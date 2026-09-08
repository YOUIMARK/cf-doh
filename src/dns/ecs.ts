/**
 * EDNS Client Subnet (ECS, RFC 7871) handling — ported from vercel-doh's
 * `dns/ecs.ts` and adapted to the Cloudflare header chain.
 *
 * Correctness rules:
 *  1. A DNS message must never contain two OPT RRs (RFC 6891).
 *  2. ECS source prefix 0 is a VALID ECS meaning "don't provide client
 *     address info" — it must never be overridden with the real subnet.
 *  3. Malformed ECS options must be rejected, not silently ignored.
 */

import { countOptRrs, parseSections, toView } from "./wire";
import { parseIp } from "./encode";
import { isPrivateOrReserved, type IpAddress } from "./ip";

export const ECS_OPTION_CODE = 8;
export const OPT_RR_TYPE = 41;

const FAMILY_IPV4 = 1;
const FAMILY_IPV6 = 2;

export type EcsStatus = "absent" | "zero" | "positive" | "malformed";

/**
 * Classifies the ECS state of a message:
 *  - "absent":     no ECS option (auto-injection is allowed by policy)
 *  - "zero":       ECS with source prefix 0 (client opts out of disclosure)
 *  - "positive":   ECS with source prefix > 0 (client-provided subnet)
 *  - "malformed":  broken OPT/ECS structure (must be rejected)
 */
export function ecsStatus(msg: Uint8Array): EcsStatus {
  const parsed = parseSections(msg);
  if (!parsed) return "malformed";
  if (countOptRrs(msg) > 1) return "malformed"; // RFC 6891: at most one OPT

  const view = toView(msg);
  let sawEcs = false;
  let status: "zero" | "positive" | null = null;

  for (const opt of parsed.additional.rrs) {
    if (opt.rrType !== OPT_RR_TYPE) continue;
    // RFC 6891 §6.1.2: the OPT owner name MUST be the root domain.
    if (opt.offset - opt.nameStart !== 1 || msg[opt.nameStart] !== 0) return "malformed";
    const end = opt.rdataOffset + opt.rdLength;
    let o = opt.rdataOffset;
    while (o + 4 <= end) {
      const code = view.getUint16(o);
      const len = view.getUint16(o + 2);
      if (o + 4 + len > end) return "malformed"; // option overruns RDATA
      if (code === ECS_OPTION_CODE) {
        if (sawEcs) return "malformed"; // duplicate ECS option
        sawEcs = true;
        if (len < 4) return "malformed";
        const family = view.getUint16(o + 4);
        const sourcePrefix = view.getUint8(o + 6);
        if (family !== FAMILY_IPV4 && family !== FAMILY_IPV6) return "malformed";
        const bits = family === FAMILY_IPV4 ? 32 : 128;
        if (sourcePrefix > bits) return "malformed";
        if (len !== 4 + Math.ceil(sourcePrefix / 8)) return "malformed";
        status = sourcePrefix === 0 ? "zero" : "positive";
      }
      o += 4 + len;
    }
  }

  if (sawEcs) return status ?? "malformed";
  return "absent";
}

/** Builds the ECS option wire bytes (option code + option data). */
export function buildEcsOption(ip: IpAddress, prefixLength: number): Uint8Array {
  const bits = ip.family === FAMILY_IPV4 ? 32 : 128;
  const prefix = Math.max(0, Math.min(prefixLength, bits));
  const addrLen = Math.ceil(prefix / 8);
  const optionLength = 4 + addrLen; // FAMILY(2) + SOURCE(1) + SCOPE(1) + ADDRESS
  const out = new Uint8Array(4 + optionLength);
  const view = toView(out);
  view.setUint16(0, ECS_OPTION_CODE);
  view.setUint16(2, optionLength);
  view.setUint16(4, ip.family);
  view.setUint8(6, prefix);
  view.setUint8(7, 0); // SCOPE PREFIX-LENGTH
  out.set(ip.bytes.subarray(0, addrLen), 8);
  return out;
}

/**
 * Adds the given ECS option to the message:
 *  - merges into the existing OPT RR's RDATA when one exists (ARCOUNT unchanged);
 *  - appends a brand-new OPT RR otherwise (ARCOUNT + 1).
 * Returns the original message unchanged on malformed input.
 * Callers MUST only invoke this when ecsStatus(msg) === "absent".
 */
export function addOrMergeEcs(msg: Uint8Array, ecsOption: Uint8Array): Uint8Array {
  const parsed = parseSections(msg);
  if (!parsed) return msg;

  const opt = parsed.additional.rrs.find((rr) => rr.rrType === OPT_RR_TYPE);

  if (opt) {
    // Merge: insert the option bytes at the end of the OPT RR's RDATA.
    const rdataEnd = opt.rdataOffset + opt.rdLength;
    const out = new Uint8Array(msg.length + ecsOption.length);
    out.set(msg.subarray(0, rdataEnd), 0);
    out.set(ecsOption, rdataEnd);
    out.set(msg.subarray(rdataEnd), rdataEnd + ecsOption.length);
    toView(out).setUint16(opt.rdataOffset - 2, opt.rdLength + ecsOption.length);
    return out;
  }

  // No OPT RR: append one at the very end (RFC 6891: only one OPT allowed).
  const out = new Uint8Array(msg.length + 11 + ecsOption.length);
  out.set(msg, 0);
  let o = msg.length;
  out[o] = 0; // root name
  o += 1;
  const view = toView(out);
  view.setUint16(o, OPT_RR_TYPE);
  view.setUint16(o + 2, 4096); // UDP payload size
  view.setUint32(o + 4, 0);
  view.setUint16(o + 8, ecsOption.length);
  out.set(ecsOption, o + 10);
  view.setUint16(10, parsed.header.ar + 1); // ARCOUNT + 1
  return out;
}

/**
 * Removes any ECS option from the message (privacy: /no-ecs must STRIP a
 * client-provided subnet, not merely skip injection):
 *  - when the OPT RR still carries other options, its RDATA is rebuilt;
 *  - when the OPT RDATA becomes empty, the whole OPT RR is removed and
 *    ARCOUNT is decremented.
 * Returns the original message when there is no ECS to remove.
 */
export function removeEcsOption(msg: Uint8Array): Uint8Array {
  const parsed = parseSections(msg);
  if (!parsed) return msg;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === OPT_RR_TYPE);
  if (!opt) return msg;
  const view = toView(msg);
  const end = opt.rdataOffset + opt.rdLength;
  const kept: Uint8Array[] = [];
  let sawEcs = false;
  let o = opt.rdataOffset;
  while (o + 4 <= end) {
    const code = view.getUint16(o);
    const len = view.getUint16(o + 2);
    if (o + 4 + len > end) return msg; // malformed option → leave untouched
    if (code === ECS_OPTION_CODE) sawEcs = true;
    else kept.push(msg.subarray(o, o + 4 + len));
    o += 4 + len;
  }
  if (o !== end) return msg;
  if (!sawEcs) return msg;

  if (kept.length > 0) {
    const keptBytes = concatBytes(kept);
    const out = new Uint8Array(msg.length - opt.rdLength + keptBytes.length);
    out.set(msg.subarray(0, opt.rdataOffset), 0);
    out.set(keptBytes, opt.rdataOffset);
    out.set(msg.subarray(end), opt.rdataOffset + keptBytes.length);
    toView(out).setUint16(opt.rdataOffset - 2, keptBytes.length);
    return out;
  }

  // No options left: drop the entire OPT RR and decrement ARCOUNT.
  const rrStart = opt.nameStart;
  const out = new Uint8Array(msg.length - (end - rrStart));
  out.set(msg.subarray(0, rrStart), 0);
  out.set(msg.subarray(end), rrStart);
  toView(out).setUint16(10, parsed.header.ar - 1);
  return out;
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

/**
 * Extracts the client IP from trusted headers for ECS injection.
 * Cloudflare chain: cf-connecting-ip (set by Cloudflare, trusted) →
 * x-real-ip → x-forwarded-for (rightmost entry — the leftmost is
 * client-spoofable). Private/reserved addresses are rejected.
 */
export function parseClientIp(headers: Headers): IpAddress | null {
  for (const name of ["cf-connecting-ip", "x-real-ip"]) {
    const value = headers.get(name);
    if (!value) continue;
    const ip = firstPublic(value);
    if (ip) return ip;
  }
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    for (let i = parts.length - 1; i >= 0; i--) {
      const parsed = parseIp(parts[i]!);
      if (parsed && !isPrivateOrReserved(parsed)) return parsed;
    }
  }
  return null;
}

function firstPublic(value: string): IpAddress | null {
  for (const part of value.split(",")) {
    const parsed = parseIp(part);
    if (parsed && !isPrivateOrReserved(parsed)) return parsed;
  }
  return null;
}
