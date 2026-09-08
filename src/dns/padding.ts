/**
 * RFC 8467 response padding — ported from vercel-doh's `dns/padding.ts`.
 *
 * Pads by adding an EDNS Padding option (code 12) into the response's
 * existing OPT RR — the only RFC-correct way for a proxy that must not alter
 * the answer section. Responses WITHOUT an OPT RR get a fresh OPT RR
 * appended carrying only the padding option.
 *
 * Strategy: Random-Block-Length Padding (RFC 8467 §4.2.3) — pick a block
 * length at random from a small set, then pad to that block's multiple.
 */

import { parseSections, toView } from "./wire";

export const PADDING_OPTION_CODE = 12;
export const PADDING_BLOCK_SIZE = 128;
export const PADDING_BLOCKS = [128, 256, 512] as const;

export type Rng = () => number;

/**
 * Pads `msg` to a random block multiple by inserting an EDNS padding option
 * into the existing OPT RR. Returns the original message when it is already
 * aligned, has no OPT RR, or is malformed.
 */
export function padResponse(msg: Uint8Array, rng: Rng = Math.random): Uint8Array {
  // Already aligned to the base block → assume padded; adding more would
  // break idempotency (all chosen blocks are multiples of the base).
  if (msg.length % PADDING_BLOCK_SIZE === 0) return msg;
  const parsed = parseSections(msg);
  if (!parsed) return msg;
  const opt = parsed.additional.rrs.find((rr) => rr.rrType === 41);

  const idx = Math.min(PADDING_BLOCKS.length - 1, Math.floor(rng() * PADDING_BLOCKS.length));
  const block = PADDING_BLOCKS[idx]!;
  const overhead = opt ? 4 : 15; // 4 = option header; 15 = OPT RR header (11) + option header (4)
  const padLen = (block - ((msg.length + overhead) % block)) % block;

  const option = new Uint8Array(4 + padLen);
  const view = toView(option);
  view.setUint16(0, PADDING_OPTION_CODE);
  view.setUint16(2, padLen);

  if (!opt) {
    const out = new Uint8Array(msg.length + 11 + option.length);
    out.set(msg, 0);
    let o = msg.length;
    out[o] = 0; // root name
    o += 1;
    const outView = toView(out);
    outView.setUint16(o, 41);
    outView.setUint16(o + 2, 4096);
    outView.setUint32(o + 4, 0);
    outView.setUint16(o + 8, option.length);
    out.set(option, o + 10);
    outView.setUint16(10, parsed.header.ar + 1);
    return out;
  }

  const rdataEnd = opt.rdataOffset + opt.rdLength;
  const out = new Uint8Array(msg.length + option.length);
  out.set(msg.subarray(0, rdataEnd), 0);
  out.set(option, rdataEnd);
  out.set(msg.subarray(rdataEnd), rdataEnd + option.length);
  const outView = toView(out);
  outView.setUint16(opt.rdataOffset - 2, opt.rdLength + option.length);
  return out;
}
