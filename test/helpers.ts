/**
 * Test-only helpers to build DNS wire messages.
 * These deliberately mirror the wire format so tests exercise the real
 * parser rather than a parser-friendly encoding.
 */

import { writeU16, writeU32 } from "../src/dns/parse";

export function encodeName(name: string): Uint8Array {
  if (name === ".") return new Uint8Array([0]);
  const parts: number[] = [];
  for (const label of name.split(".")) {
    parts.push(label.length);
    for (let i = 0; i < label.length; i++) parts.push(label.charCodeAt(i));
  }
  parts.push(0);
  return Uint8Array.from(parts);
}

export interface QueryOpts {
  id?: number;
  flags?: number;
  qtype?: number;
  qclass?: number;
  arcount?: number;
  /** Extra bytes appended after the question (raw OPT record, etc.). */
  additional?: Uint8Array;
}

/** Build a DNS query (header + question + optional additional records). */
export function buildQuery(name: string, opts: QueryOpts = {}): Uint8Array {
  const qname = encodeName(name);
  const questionLen = qname.length + 4;
  const extra = opts.additional ?? new Uint8Array(0);
  const out = new Uint8Array(12 + questionLen + extra.length);
  writeU16(out, 0, opts.id ?? 0x1234);
  writeU16(out, 2, opts.flags ?? 0x0100); // RD
  writeU16(out, 4, 1);
  writeU16(out, 6, 0);
  writeU16(out, 8, 0);
  writeU16(out, 10, opts.arcount ?? (extra.length > 0 ? 1 : 0));
  out.set(qname, 12);
  writeU16(out, 12 + qname.length, opts.qtype ?? 1);
  writeU16(out, 12 + qname.length + 2, opts.qclass ?? 1);
  out.set(extra, 12 + questionLen);
  return out;
}

/** Build an ECS option payload (RFC 7871). */
export function buildEcsOption(
  family: number,
  sourcePrefix: number,
  address: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(8 + address.length);
  writeU16(out, 0, 8); // option code
  writeU16(out, 2, 4 + address.length);
  writeU16(out, 4, family);
  out[6] = sourcePrefix;
  out[7] = 0;
  out.set(address, 8);
  return out;
}

/** Build a raw OPT record (root name + type 41). */
export function buildOptRecord(
  udpPayloadSize: number,
  ttl: number,
  rdata: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(11 + rdata.length);
  out[0] = 0;
  writeU16(out, 1, 41);
  writeU16(out, 3, udpPayloadSize);
  writeU32(out, 5, ttl);
  writeU16(out, 9, rdata.length);
  out.set(rdata, 11);
  return out;
}

export interface AnswerSpec {
  type: number;
  ttl: number;
  rdata: Uint8Array;
}

/** Build a DNS response echoing the question with the given answer records. */
export function buildResponse(
  name: string,
  answers: AnswerSpec[],
  rcode = 0,
  id = 0x1234,
): Uint8Array {
  const qname = encodeName(name);
  const questionLen = qname.length + 4;
  const answersLen = answers.reduce((a, r) => a + 12 + r.rdata.length, 0);
  const out = new Uint8Array(12 + questionLen + answersLen);
  writeU16(out, 0, id);
  writeU16(out, 2, (0x8180 | (rcode & 0x0f)) & 0xffff); // QR RD RA + rcode
  writeU16(out, 4, 1);
  writeU16(out, 6, answers.length);
  writeU16(out, 8, 0);
  writeU16(out, 10, 0);
  out.set(qname, 12);
  writeU16(out, 12 + qname.length, 1);
  writeU16(out, 12 + qname.length + 2, 1);
  let off = 12 + questionLen;
  for (const a of answers) {
    out[off] = 0xc0;
    out[off + 1] = 0x0c; // pointer to offset 12 (the question name)
    writeU16(out, off + 2, a.type);
    writeU16(out, off + 4, 1);
    writeU32(out, off + 6, a.ttl);
    writeU16(out, off + 10, a.rdata.length);
    out.set(a.rdata, off + 12);
    off += 12 + a.rdata.length;
  }
  return out;
}

export function v4(...octets: number[]): Uint8Array {
  return Uint8Array.from(octets);
}

export function v6(...groups: number[]): Uint8Array {
  const out = new Uint8Array(16);
  groups.forEach((g, i) => {
    writeU16(out, i * 2, g);
  });
  return out;
}

/** Encode bytes as RFC 4648 base64url (for GET DoH). */
export function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
