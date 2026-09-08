/**
 * DNS protocol gate and upstream response validation (ported from
 * vercel-doh's `dns/validate.ts`).
 *
 * Query side: a proxied query must be a structurally sound standard query —
 * QDCOUNT=1, QR=0, OPCODE=0, sections parse to the exact end of the message,
 * at most one OPT RR, and a well-formed EDNS/ECS option list. Anything else
 * is rejected with 400 BEFORE touching an upstream.
 *
 * Response side: the trust boundary between upstream bytes and everything
 * downstream (caching, relaying). The response must be QR=1, structurally
 * sound, contain at most one OPT RR with a root owner name, type-consistent
 * RDATA, and — when the request is known — echo its ID and question section.
 */

import {
  checkRdataTypes,
  countOptRrs,
  extendedRcode,
  parseHeader,
  parseSections,
  questionMatches,
  toView,
  type DnsHeader,
} from "./wire";
import { ecsStatus, queryEcsScopeValid } from "./ecs";

export interface ValidatedResponse {
  header: DnsHeader;
  /** Full RCODE including EDNS(0) extended-rcode bits (e.g. BADVERS = 16). */
  rcode: number;
}

/** Validates a client query; returns null when it must be rejected with 400. */
export function validateQuery(msg: Uint8Array): boolean {
  const header = parseHeader(msg);
  if (!header || header.qd !== 1) return false;
  if ((header.flags & 0x8000) !== 0) return false; // QR must be 0 (a query)
  if (((header.flags >> 11) & 0x0f) !== 0) return false; // standard opcode only
  const sections = parseSections(msg);
  if (!sections) return false;
  if (sections.additional.nextOffset !== msg.length) return false; // trailing garbage
  if (countOptRrs(msg) > 1) return false; // RFC 6891: at most one OPT
  if (ecsStatus(msg) === "malformed") return false;
  return queryEcsScopeValid(msg); // RFC 7871: query ECS scope MUST be 0
}

/** Validates an upstream response; returns null when it cannot be trusted. */
export function validateResponse(
  msg: Uint8Array,
  request?: Uint8Array,
): ValidatedResponse | null {
  const header = parseHeader(msg);
  if (!header) return null;
  if ((header.flags & 0x8000) === 0) return null; // QR must be 1 (response)
  const opcode = (header.flags >> 11) & 0x0f;
  if (opcode !== 0) return null;
  const sections = parseSections(msg);
  if (!sections) return null;
  if (sections.additional.nextOffset !== msg.length) return null; // trailing garbage
  if (countOptRrs(msg) > 1) return null;
  const view = toView(msg);
  for (const rr of sections.additional.rrs) {
    if (rr.rrType !== 41) continue;
    // RFC 6891 §6.1.2: the OPT owner name MUST be the root domain.
    if (rr.offset - rr.nameStart !== 1 || msg[rr.nameStart] !== 0) return null;
  }
  if (!checkRdataTypes(view, sections)) return null;
  if (request && !questionMatches(msg, request)) return null; // ID + question echo
  return { header, rcode: extendedRcode(msg) };
}
