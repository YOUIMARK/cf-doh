/**
 * DNS wire-format helpers (pure functions over Uint8Array).
 *
 * Ported from the vercel-doh project's `dns/wire.ts` (same author) and
 * adapted to the Cloudflare Workers runtime. Provides full section walking
 * used by the protocol gate and upstream response validation.
 */

export interface DnsHeader {
  id: number;
  flags: number;
  qd: number;
  an: number;
  ns: number;
  ar: number;
}

export function toView(msg: Uint8Array): DataView {
  return new DataView(msg.buffer as ArrayBuffer, msg.byteOffset, msg.byteLength);
}

export function parseHeader(msg: Uint8Array): DnsHeader | null {
  if (msg.length < 12) return null;
  const view = toView(msg);
  return {
    id: view.getUint16(0),
    flags: view.getUint16(2),
    qd: view.getUint16(4),
    an: view.getUint16(6),
    ns: view.getUint16(8),
    ar: view.getUint16(10),
  };
}

/**
 * Skips a (possibly compressed) domain name. Returns the offset after the
 * name, or -1 if malformed. Compression pointer targets are validated: they
 * must point to a prior occurrence inside the message, never into the
 * 12-byte header.
 */
export function skipName(view: DataView, offset: number): number {
  let o = offset;
  while (o < view.byteLength) {
    const len = view.getUint8(o);
    if (len === 0) return o + 1;
    if ((len & 0xc0) === 0xc0) {
      if (o + 2 > view.byteLength) return -1;
      const target = ((len & 0x3f) << 8) | view.getUint8(o + 1);
      if (target < 12 || target >= o) return -1;
      return o + 2;
    }
    if ((len & 0xc0) !== 0) return -1; // reserved label types 01/10
    if (o + 1 + len > view.byteLength) return -1;
    o += 1 + len;
  }
  return -1;
}

export interface RRInfo {
  nameStart: number;
  /** Offset of the RR's fixed fields (after the name). */
  offset: number;
  rrType: number;
  rrClass: number;
  ttl: number;
  rdLength: number;
  rdataOffset: number;
}

export interface ScanResult {
  nextOffset: number;
  rrs: RRInfo[];
}

export interface ParsedSections {
  header: DnsHeader;
  questionEnd: number;
  answers: ScanResult;
  authority: ScanResult;
  additional: ScanResult;
}

/** Scans `count` resource records starting at `offset`. Null on malformed input. */
export function scanRRs(view: DataView, offset: number, count: number): ScanResult | null {
  let o = offset;
  const rrs: RRInfo[] = [];
  for (let i = 0; i < count; i++) {
    const nameStart = o;
    const afterName = skipName(view, o);
    if (afterName === -1) return null;
    if (afterName + 10 > view.byteLength) return null;
    const rrType = view.getUint16(afterName);
    const rrClass = view.getUint16(afterName + 2);
    const ttl = view.getUint32(afterName + 4);
    const rdLength = view.getUint16(afterName + 8);
    const rdataOffset = afterName + 10;
    if (rdataOffset + rdLength > view.byteLength) return null;
    rrs.push({ nameStart, offset: afterName, rrType, rrClass, ttl, rdLength, rdataOffset });
    o = rdataOffset + rdLength;
  }
  return { nextOffset: o, rrs };
}

/** Walks header + question + all sections. Null if malformed. */
export function parseSections(msg: Uint8Array): ParsedSections | null {
  const header = parseHeader(msg);
  if (!header) return null;
  const view = toView(msg);
  let o = 12;
  for (let i = 0; i < header.qd; i++) {
    const n = skipName(view, o);
    if (n === -1) return null;
    o = n + 4;
    if (o > view.byteLength) return null;
  }
  const questionEnd = o;
  const answers = scanRRs(view, o, header.an);
  if (!answers) return null;
  const authority = scanRRs(view, answers.nextOffset, header.ns);
  if (!authority) return null;
  const additional = scanRRs(view, authority.nextOffset, header.ar);
  if (!additional) return null;
  return { header, questionEnd, answers, authority, additional };
}

/** Counts OPT RRs in the ADDITIONAL section (RFC 6891: at most one allowed). */
export function countOptRrs(msg: Uint8Array): number {
  const parsed = parseSections(msg);
  if (!parsed) return 0;
  return parsed.additional.rrs.filter((rr) => rr.rrType === 41).length;
}

/** Reads the QTYPE of the single question, or null. */
export function questionType(msg: Uint8Array): number | null {
  const header = parseHeader(msg);
  if (!header || header.qd !== 1) return null;
  const view = toView(msg);
  const nameEnd = skipName(view, 12);
  if (nameEnd === -1 || nameEnd + 4 > msg.length) return null;
  return view.getUint16(nameEnd);
}

/** Returns a copy of `msg` with the question QTYPE rewritten (v4/v6 flags). */
export function setQuestionType(msg: Uint8Array, qtype: number): Uint8Array | null {
  const header = parseHeader(msg);
  if (!header || header.qd !== 1) return null;
  const view = toView(msg);
  const nameEnd = skipName(view, 12);
  if (nameEnd === -1 || nameEnd + 4 > msg.length) return null;
  const out = msg.slice();
  toView(out).setUint16(nameEnd, qtype);
  return out;
}

/** Returns a copy of `msg` with the DNS transaction ID replaced (RFC 1035
 *  §4.1.1). Used to canonicalize cached responses (store ID 0, restore the
 *  requesting client's ID on a cache hit) so cached bytes never leak another
 *  client's transaction ID. */
export function withTransactionId(msg: Uint8Array, id: number): Uint8Array {
  const out = msg.slice();
  if (out.length >= 2) toView(out).setUint16(0, id & 0xffff);
  return out;
}

/** Full RCODE including EDNS(0) extended-rcode bits (BADVERS = 16, …). */
export function extendedRcode(msg: Uint8Array): number {
  const parsed = parseSections(msg);
  const low = parsed ? parsed.header.flags & 0x0f : 0;
  if (!parsed) return low;
  const view = toView(msg);
  for (const rr of parsed.additional.rrs) {
    if (rr.rrType !== 41) continue;
    const optTtl = view.getUint32(rr.offset + 4);
    return (((optTtl >>> 24) & 0xff) << 4) | low;
  }
  return low;
}

/**
 * Type-specific RDATA structural checks (defense in depth): fixed-length
 * types must carry exactly their wire size and name-bearing types must parse
 * to the exact end of their RDATA. Unknown types are skipped.
 */
export function checkRdataTypes(view: DataView, parsed: ParsedSections): boolean {
  const rrs = [...parsed.answers.rrs, ...parsed.authority.rrs, ...parsed.additional.rrs];
  for (const rr of rrs) {
    if (rr.rrType === 41) continue;
    const end = rr.rdataOffset + rr.rdLength;
    switch (rr.rrType) {
      case 1: // A
        if (rr.rdLength !== 4) return false;
        break;
      case 28: // AAAA
        if (rr.rdLength !== 16) return false;
        break;
      case 2: // NS
      case 5: // CNAME
      case 12: // PTR
      case 39: // DNAME
        if (skipName(view, rr.rdataOffset) !== end) return false;
        break;
      case 15: {
        // MX: 2-byte preference + a name
        if (rr.rdLength < 3) return false;
        if (skipName(view, rr.rdataOffset + 2) !== end) return false;
        break;
      }
      case 6: {
        // SOA: MNAME + RNAME + 5 × uint32
        if (rr.rdLength < 22) return false;
        const afterMname = skipName(view, rr.rdataOffset);
        if (afterMname === -1 || afterMname >= end) return false;
        const afterRname = skipName(view, afterMname);
        if (afterRname === -1 || afterRname + 20 !== end) return false;
        break;
      }
      default:
        break;
    }
  }
  return true;
}

/**
 * Whether `response` echoes `request`'s ID and question section (RFC 1035
 * §4.1.2). `request` must be the exact message sent upstream (after ECS
 * stripping / QTYPE rewrite).
 */
export function questionMatches(response: Uint8Array, request: Uint8Array): boolean {
  const rh = parseHeader(response);
  const qh = parseHeader(request);
  if (!rh || !qh) return false;
  if (rh.id !== qh.id) return false;
  if (rh.qd !== 1 || qh.qd !== 1) return false;
  const rs = parseSections(response);
  const qs = parseSections(request);
  if (!rs || !qs) return false;
  if (rs.questionEnd !== qs.questionEnd) return false;
  for (let i = 12; i < rs.questionEnd; i++) {
    if (response[i] !== request[i]) return false;
  }
  return true;
}

/**
 * Builds a minimal DNS response header + echoed question with the given
 * RCODE (used for the synthetic SERVFAIL when all upstreams fail).
 */
export function buildErrorResponse(query: Uint8Array | null, rcode: number): Uint8Array {
  const queryHeader = query ? parseHeader(query) : null;
  const id = queryHeader?.id ?? 0;
  const rd = queryHeader ? (queryHeader.flags & 0x0100) !== 0 : false;
  const flags = 0x8000 | 0x0080 | (rd ? 0x0100 : 0) | (rcode & 0x0f);

  let questionBytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  if (query && queryHeader && queryHeader.qd > 0) {
    const sections = parseSections(query);
    if (sections) questionBytes = query.subarray(12, sections.questionEnd);
  }
  const qd = questionBytes.length > 0 ? (queryHeader?.qd ?? 0) : 0;

  const out = new Uint8Array(12 + questionBytes.length);
  const view = toView(out);
  view.setUint16(0, id);
  view.setUint16(2, flags);
  view.setUint16(4, qd);
  view.setUint16(6, 0);
  view.setUint16(8, 0);
  view.setUint16(10, 0);
  out.set(questionBytes, 12);
  return out;
}
