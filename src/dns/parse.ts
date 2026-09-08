/**
 * Minimal DNS wire-format helpers.
 *
 * We deliberately parse only what the worker needs:
 *  - the first question (name / qtype / qclass) for cache keys and routing,
 *  - the OPT record + EDNS Client Subnet option for ECS handling,
 *  - the answer section for TTL extraction and response classification.
 *
 * Nothing else is decoded, which keeps per-request CPU time well inside the
 * Workers free-tier budget (10 ms).
 */

export const HEADER_LEN = 12;
const TYPE_OPT = 41;
const ECS_OPTION_CODE = 8;

export function readU16(msg: Uint8Array, off: number): number {
  return ((msg[off]! << 8) | msg[off + 1]!) & 0xffff;
}

export function readU32(msg: Uint8Array, off: number): number {
  return (
    ((msg[off]! << 24) | (msg[off + 1]! << 16) | (msg[off + 2]! << 8) | msg[off + 3]!) >>> 0
  );
}

export function writeU16(msg: Uint8Array, off: number, val: number): void {
  msg[off] = (val >> 8) & 0xff;
  msg[off + 1] = val & 0xff;
}

export function writeU32(msg: Uint8Array, off: number, val: number): void {
  msg[off] = (val >>> 24) & 0xff;
  msg[off + 1] = (val >>> 16) & 0xff;
  msg[off + 2] = (val >>> 8) & 0xff;
  msg[off + 3] = val & 0xff;
}

/** Decode a possibly-compressed DNS name. Returns dotted, lowercased name and the offset just past the name field. */
export function decodeName(
  msg: Uint8Array,
  offset: number,
): { name: string; next: number } | null {
  let pos = offset;
  let out = "";
  let len = 0;
  let next = offset;
  let jumped = false;
  let jumps = 0;
  if (pos >= msg.length) return null;

  for (;;) {
    if (pos >= msg.length) return null;
    const b = msg[pos]!;
    if (b === 0) {
      pos += 1;
      if (!jumped) next = pos;
      break;
    }
    if ((b & 0xc0) === 0xc0) {
      // compression pointer
      if (pos + 1 >= msg.length) return null;
      if (jumps++ > 8) return null; // pointer-loop guard
      const ptr = ((b & 0x3f) << 8) | msg[pos + 1]!;
      if (ptr >= msg.length) return null;
      if (!jumped) {
        next = pos + 2;
        jumped = true;
      }
      pos = ptr;
      continue;
    }
    if ((b & 0xc0) !== 0) return null; // reserved label types 0x40 / 0x80
    const labLen = b;
    if (pos + 1 + labLen > msg.length) return null;
    if (len + labLen + 1 > 255) return null; // RFC 1035 255-byte name cap
    if (out.length > 0) out += ".";
    for (let i = 0; i < labLen; i++) {
      const c = msg[pos + 1 + i]!;
      // DNS names are case-insensitive; lowercase ASCII only (IDN arrives as punycode).
      out += c >= 0x41 && c <= 0x5a ? String.fromCharCode(c + 0x20) : String.fromCharCode(c);
    }
    len += labLen + 1;
    pos += 1 + labLen;
  }
  return { name: out.length === 0 ? "." : out, next };
}

export interface Question {
  name: string;
  qtype: number;
  qclass: number;
  /** Byte offset just past the question section (start of answer section). */
  questionEnd: number;
}

/** Parse the first question of a DNS message. Returns null for malformed messages. */
export function parseQuestion(msg: Uint8Array, offset = HEADER_LEN): Question | null {
  if (msg.length < HEADER_LEN + 5) return null;
  const qdcount = readU16(msg, 4);
  if (qdcount < 1) return null;
  const dn = decodeName(msg, offset);
  if (!dn) return null;
  if (dn.next + 4 > msg.length) return null;
  return {
    name: dn.name,
    qtype: readU16(msg, dn.next),
    qclass: readU16(msg, dn.next + 2),
    questionEnd: dn.next + 4,
  };
}

export interface OptRecord {
  /** Offset of the record's first byte (the root name 0x00). */
  start: number;
  /** Offset one past the record's last byte. */
  end: number;
  /** UDP payload size advertised by the client. */
  cls: number;
  ttl: number;
  rdataStart: number;
  rdLength: number;
}

/**
 * Locate the OPT (EDNS0) record in the additional section of a message.
 * Queries virtually always have ANCOUNT == NSCOUNT == 0, but we skip all
 * sections properly so the function is correct for arbitrary messages.
 */
export function findOptRecord(msg: Uint8Array): OptRecord | null {
  if (msg.length < HEADER_LEN) return null;
  const qdcount = readU16(msg, 4);
  const ancount = readU16(msg, 6);
  const nscount = readU16(msg, 8);
  const arcount = readU16(msg, 10);
  let off = HEADER_LEN;

  for (let i = 0; i < qdcount; i++) {
    const dn = decodeName(msg, off);
    if (!dn) return null;
    off = dn.next + 4;
    if (off > msg.length) return null;
  }
  for (let i = 0; i < ancount + nscount; i++) {
    const dn = decodeName(msg, off);
    if (!dn) return null;
    off = dn.next;
    if (off + 10 > msg.length) return null;
    const rdlength = readU16(msg, off + 8);
    off += 10 + rdlength;
    if (off > msg.length) return null;
  }
  for (let i = 0; i < arcount; i++) {
    const recStart = off;
    const dn = decodeName(msg, off);
    if (!dn) return null;
    off = dn.next;
    if (off + 10 > msg.length) return null;
    const type = readU16(msg, off);
    const rdlength = readU16(msg, off + 8);
    if (type === TYPE_OPT) {
      return {
        start: recStart,
        end: off + 10 + rdlength,
        cls: readU16(msg, off + 2),
        ttl: readU32(msg, off + 4),
        rdataStart: off + 10,
        rdLength: rdlength,
      };
    }
    off += 10 + rdlength;
    if (off > msg.length) return null;
  }
  return null;
}

export interface EcsOption {
  family: number; // 1 = IPv4, 2 = IPv6
  sourcePrefix: number;
  scopePrefix: number;
  /** Source-prefix address bytes (ceil(sourcePrefix/8) bytes). */
  address: Uint8Array;
}

/** Parse the EDNS Client Subnet option (code 8) out of an OPT record's rdata. */
export function parseEcs(msg: Uint8Array, opt: OptRecord): EcsOption | null {
  let p = opt.rdataStart;
  const end = opt.rdataStart + opt.rdLength;
  while (p + 4 <= end) {
    const code = readU16(msg, p);
    const len = readU16(msg, p + 2);
    if (p + 4 + len > end) return null; // malformed option list
    if (code === ECS_OPTION_CODE) {
      if (len < 4) return null;
      const family = readU16(msg, p + 4);
      const sourcePrefix = msg[p + 6]!;
      const scopePrefix = msg[p + 7]!;
      const addrLen = (sourcePrefix + 7) >> 3;
      if (4 + addrLen > len) return null;
      return {
        family,
        sourcePrefix,
        scopePrefix,
        address: msg.slice(p + 8, p + 8 + addrLen),
      };
    }
    p += 4 + len;
  }
  return null;
}
