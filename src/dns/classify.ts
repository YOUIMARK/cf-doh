/**
 * DNS response classification: blocked answers, NXDOMAIN, DNS-rebind
 * detection and answer TTL extraction. Used for caching decisions,
 * failover/strict-mode ranking and rebind protection.
 */

import { decodeName, readU16, readU32, writeU16, HEADER_LEN } from "./parse";

export type ResponseKind = "ok" | "nxdomain" | "blocked" | "rebind" | "error";

export interface AnswerSummary {
  /** Minimum TTL across all answer records; Infinity when no answers. */
  minTtl: number;
  /** True when any A/AAAA answer is 0.0.0.0 or :: (ad-blocking convention). */
  blocked: boolean;
  /** True when at least one A/AAAA answer record exists. */
  hasAddresses: boolean;
  /** True when every A/AAAA answer points at a private/loopback/link-local IP. */
  allPrivate: boolean;
}

/** Response code from the header (low nibble of byte 3). */
export function rcode(msg: Uint8Array): number {
  return msg.length >= 4 ? msg[3]! & 0x0f : -1;
}

function isZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}

function isPrivateV4(a: Uint8Array): boolean {
  if (a.length !== 4) return false;
  const [o0, o1] = [a[0]!, a[1]!];
  if (o0 === 0) return true; // 0.0.0.0/8
  if (o0 === 10) return true; // 10.0.0.0/8
  if (o0 === 127) return true; // 127.0.0.0/8
  if (o0 === 169 && o1 === 254) return true; // link-local
  if (o0 === 172 && o1 >= 16 && o1 <= 31) return true; // 172.16.0.0/12
  if (o0 === 192 && o1 === 168) return true; // 192.168.0.0/16
  if (o0 === 100 && o1 >= 64 && o1 <= 127) return true; // CGNAT 100.64.0.0/10
  if (o0 === 198 && (o1 === 18 || o1 === 19)) return true; // benchmarking
  if (o0 >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateV6(a: Uint8Array): boolean {
  if (a.length !== 16) return false;
  const [b0, b1] = [a[0]!, a[1]!];
  // :: and ::1
  if (isZero(a)) return true;
  if (b0 === 0 && b1 === 0) {
    if (a[2] === 0 && a[3] === 0 && a[4] === 0 && a[5] === 0 && a[6] === 0 && a[7] === 0 && a[8] === 0 && a[9] === 0 && a[10] === 0 && a[11] === 0 && a[12] === 0 && a[13] === 0 && a[14] === 0 && a[15] === 1) return true; // ::1
    return false;
  }
  if ((b0 & 0xfe) === 0xfc) return true; // fc00::/7 ULA
  if ((b0 & 0xff) === 0xfe && (b1 & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b0 === 0x20 && b1 === 0x01 && a[2] === 0x0d && a[3] === 0xb8) return true; // 2001:db8::/32 docs
  // IPv4-mapped ::ffff:x.x.x.x with a private IPv4
  if (b0 === 0 && b1 === 0 && a[2] === 0 && a[3] === 0 && a[4] === 0 && a[5] === 0 && a[6] === 0 && a[7] === 0 && a[8] === 0 && a[9] === 0 && a[10] === 0xff && a[11] === 0xff) {
    return isPrivateV4(a.slice(12, 16));
  }
  return false;
}

/**
 * Scan the answer section of a response.
 * Returns summary + the offset just past the answer section (for callers that
 * need to know where answers end).
 */
export function scanAnswers(msg: Uint8Array): AnswerSummary {
  const summary: AnswerSummary = {
    minTtl: Infinity,
    blocked: false,
    hasAddresses: false,
    allPrivate: true,
  };
  if (msg.length < HEADER_LEN) return summary;
  const qdcount = readU16(msg, 4);
  const ancount = readU16(msg, 6);
  const nscount = readU16(msg, 8);
  let off = HEADER_LEN;

  for (let i = 0; i < qdcount; i++) {
    const dn = decodeName(msg, off);
    if (!dn) return summary;
    off = dn.next + 4;
    if (off > msg.length) return summary;
  }

  let addrCount = 0;
  const total = ancount + nscount;
  for (let i = 0; i < total; i++) {
    const dn = decodeName(msg, off);
    if (!dn) return summary;
    off = dn.next;
    if (off + 10 > msg.length) return summary;
    const type = readU16(msg, off);
    const ttl = readU32(msg, off + 4);
    const rdlength = readU16(msg, off + 8);
    if (i < ancount) {
      // Only answer-section records count for TTL (authority TTLs like SOA
      // negative-cache TTLs are intentionally not used for positive caching).
      if (ttl < summary.minTtl) summary.minTtl = ttl;
    }
    const rdata = off + 10;
    if (i < ancount && (type === 1 || type === 28)) {
      const want = type === 1 ? 4 : 16;
      if (rdlength === want && rdata + want <= msg.length) {
        const addr = msg.slice(rdata, rdata + want);
        addrCount += 1;
        if (isZero(addr)) summary.blocked = true;
        else if (isPrivateV4(addr) || isPrivateV6(addr)) {
          // stays private
        } else {
          summary.allPrivate = false;
        }
      }
    }
    off += 10 + rdlength;
    if (off > msg.length) return summary;
  }
  summary.hasAddresses = addrCount > 0;
  if (addrCount === 0) summary.allPrivate = false; // no addresses → not "all private"
  return summary;
}

/**
 * Classify a response. `rebindProtection` turns the "all answers are private
 * IPs" case into "rebind". Blocked (0.0.0.0/::) is always reported, even when
 * mixed with public answers (ad-blocking semantics).
 */
export function classifyResponse(
  msg: Uint8Array,
  rebindProtection: boolean,
): ResponseKind {
  const rc = rcode(msg);
  if (rc === 3) return "nxdomain";
  if (rc !== 0) return "error";
  const s = scanAnswers(msg);
  if (s.blocked) return "blocked";
  if (rebindProtection && s.hasAddresses && s.allPrivate) return "rebind";
  return "ok";
}

/**
 * Build a synthetic NXDOMAIN response echoing the query's header + question.
 * `questionEnd` comes from parseQuestion(). Used for rebind protection and
 * synthetic blocks so clients get a deterministic, cacheable negative answer.
 */
export function buildSyntheticNxdomain(
  query: Uint8Array,
  questionEnd: number,
): Uint8Array {
  const len = Math.min(questionEnd, query.length);
  const out = query.slice(0, len);
  if (out.length < 4) return out;
  const flags = readU16(out, 2);
  writeU16(out, 2, ((flags | 0x8000) & 0xfff0) | 0x0003); // QR=1, rcode=3
  // Zero an/ns/ar counts (a query's counts are already 0; keep it explicit).
  for (const [at, ] of [[6, 0], [8, 0], [10, 0]] as const) writeU16(out, at, 0);
  return out;
}
