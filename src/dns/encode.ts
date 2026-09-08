/**
 * Message rewriting utilities: EDNS Client Subnet injection/stripping,
 * IP parsing/truncation, and base64url decoding for GET DoH requests.
 */

import {
  findOptRecord,
  parseEcs,
  readU16,
  readU32,
  writeU16,
  writeU32,
  type OptRecord,
} from "./parse";

const TYPE_OPT = 41;
const ECS_OPTION_CODE = 8;

function concat2(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out: Uint8Array<ArrayBufferLike> = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concat3(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const out: Uint8Array<ArrayBufferLike> = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

/** Build an EDNS Client Subnet option (RFC 7871) payload. */
export function buildEcsOption(
  family: number,
  sourcePrefix: number,
  address: Uint8Array,
): Uint8Array {
  const len = 4 + address.length;
  const out = new Uint8Array(4 + len);
  writeU16(out, 0, ECS_OPTION_CODE);
  writeU16(out, 2, len);
  writeU16(out, 4, family);
  out[6] = sourcePrefix;
  out[7] = 0; // scope prefix (0 in queries)
  out.set(address, 8);
  return out;
}

/** Build a full OPT record (name=root, type=41). */
export function buildOptRecord(
  udpPayloadSize: number,
  ttl: number,
  rdata: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(11 + rdata.length);
  out[0] = 0; // root name
  writeU16(out, 1, TYPE_OPT);
  writeU16(out, 3, udpPayloadSize);
  writeU32(out, 5, ttl);
  writeU16(out, 9, rdata.length);
  out.set(rdata, 11);
  return out;
}

/**
 * Rebuild an OPT record's rdata, dropping existing ECS options and/or
 * appending a new one. Returns { kept, droppedEcs }.
 */
function filterOptRdata(
  msg: Uint8Array,
  opt: OptRecord,
): { kept: Uint8Array; droppedEcs: boolean } {
  const chunks: Uint8Array[] = [];
  let dropped = false;
  let p = opt.rdataStart;
  const end = opt.rdataStart + opt.rdLength;
  while (p + 4 <= end) {
    const code = readU16(msg, p);
    const len = readU16(msg, p + 2);
    if (p + 4 + len > end) break; // malformed tail: keep remainder verbatim
    if (code === ECS_OPTION_CODE) {
      dropped = true;
    } else {
      chunks.push(msg.slice(p, p + 4 + len));
    }
    p += 4 + len;
  }
  if (p < end) chunks.push(msg.slice(p, end));
  let kept: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  for (const c of chunks) kept = concat2(kept, c);
  return { kept, droppedEcs: dropped };
}

/**
 * Set (replace) the ECS option in a message to a truncated subnet.
 * If the message already carries an OPT record its ECS is replaced in place;
 * otherwise a new OPT record is appended and ARCOUNT is bumped.
 */
export function setEcsInMessage(
  msg: Uint8Array,
  family: number,
  sourcePrefix: number,
  address: Uint8Array,
): Uint8Array {
  if (msg.length < 12) return msg;
  const ecsOpt = buildEcsOption(family, sourcePrefix, address);
  const opt = findOptRecord(msg);
  if (opt) {
    const { kept } = filterOptRdata(msg, opt);
    const newRecord = buildOptRecord(opt.cls, opt.ttl, concat2(kept, ecsOpt));
    return concat3(msg.slice(0, opt.start), newRecord, msg.slice(opt.end));
  }
  const newRecord = buildOptRecord(1232, 0, ecsOpt);
  const out = concat2(msg, newRecord);
  writeU16(out, 10, readU16(out, 10) + 1); // ARCOUNT++
  return out;
}

/**
 * Strip any ECS option from a message (privacy: do not leak the client's
 * subnet to upstream resolvers). Returns the same buffer when there is
 * nothing to strip.
 */
export function stripEcsFromMessage(msg: Uint8Array): Uint8Array {
  if (msg.length < 12) return msg;
  const opt = findOptRecord(msg);
  if (!opt) return msg;
  const { kept, droppedEcs } = filterOptRdata(msg, opt);
  if (!droppedEcs) return msg;
  const newRecord = buildOptRecord(opt.cls, opt.ttl, kept);
  return concat3(msg.slice(0, opt.start), newRecord, msg.slice(opt.end));
}

/** Extract the (first) ECS option from a message, if present. */
export function getEcs(msg: Uint8Array): { family: number; sourcePrefix: number; address: Uint8Array } | null {
  const opt = findOptRecord(msg);
  if (!opt) return null;
  const ecs = parseEcs(msg, opt);
  if (!ecs) return null;
  return { family: ecs.family, sourcePrefix: ecs.sourcePrefix, address: ecs.address };
}

/** Parse an IPv4 literal into 4 address bytes. */
function parseIpv4(s: string): { family: 1; bytes: Uint8Array } | null {
  const octets = s.split(".");
  if (octets.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(octets[i]!)) return null;
    const v = Number(octets[i]);
    if (v > 255) return null;
    bytes[i] = v;
  }
  return { family: 1, bytes };
}

/** Parse an IP literal into address bytes. Returns null when invalid. */
export function parseIp(ip: string): { family: 1 | 2; bytes: Uint8Array } | null {
  const s = ip.trim();
  if (!s.includes(":")) return parseIpv4(s);

  // IPv6 (may end with an embedded IPv4 literal after the last ':')
  let head = s;
  let v4Tail: Uint8Array | null = null;
  const lastColon = head.lastIndexOf(":");
  if (lastColon >= 0) {
    const tailPart = head.slice(lastColon + 1);
    if (tailPart.includes(".")) {
      const v4p = parseIpv4(tailPart);
      if (!v4p) return null;
      v4Tail = v4p.bytes;
      head = head.slice(0, lastColon);
    }
  }

  const sides = head.split("::");
  if (sides.length > 2) return null;
  const left = sides[0] ? sides[0].split(":") : [];
  const right = sides.length === 2 && sides[1] ? sides[1].split(":") : [];
  const v4Groups = v4Tail
    ? [
        (((v4Tail[0]! << 8) | v4Tail[1]!) >>> 0).toString(16),
        (((v4Tail[2]! << 8) | v4Tail[3]!) >>> 0).toString(16),
      ]
    : [];
  const used = left.length + right.length + (v4Tail ? 2 : 0);
  if (used > 8) return null;
  if (sides.length === 1 && used !== 8) return null; // full form needs 8 groups
  const mid = sides.length === 2 ? 8 - used : 0;
  const groups = [...left, ...Array<string>(mid).fill("0"), ...right, ...v4Groups];
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i]!;
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes[i * 2] = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return { family: 2, bytes };
}

/** Truncate address bytes to `bits` prefix bits (ceil(bits/8) bytes, last byte masked). */
export function truncateBytes(
  bytes: Uint8Array,
  bits: number,
  maxBits: number,
): Uint8Array {
  const b = Math.min(bits, maxBits);
  if (b <= 0) return new Uint8Array(0);
  const n = (b + 7) >> 3;
  const out = bytes.slice(0, n);
  const rem = b % 8;
  if (rem !== 0 && n > 0) out[n - 1] = out[n - 1]! & ((0xff << (8 - rem)) & 0xff);
  return out;
}

/**
 * Truncate an IP literal to `bits` prefix bits and return the address bytes
 * that should go into an ECS option (ceil(bits/8) bytes, last byte masked).
 */
export function truncateIp(ip: string, bits: number): { family: 1 | 2; bytes: Uint8Array } | null {
  const parsed = parseIp(ip);
  if (!parsed) return null;
  const maxBits = parsed.family === 1 ? 32 : 128;
  return { family: parsed.family, bytes: truncateBytes(parsed.bytes, bits, maxBits) };
}

/** Decode RFC 4648 base64url (as used by RFC 8484 GET DoH). Returns null on invalid input. */
export function base64urlToBytes(s: string): Uint8Array | null {
  if (s.length === 0 || s.length % 4 === 1) return null;
  if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) return null;
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Hex string for a byte array (used for cache keys / ECS buckets). */
export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}
