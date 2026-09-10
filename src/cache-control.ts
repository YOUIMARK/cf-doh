/**
 * Cache-Control strategy (RFC 8484 §5 + RFC 2308 negative caching) — ported
 * from vercel-doh's `cache-control.ts`.
 *
 *   NOERROR + Answer            -> public, s-maxage=<min answer TTL capped>
 *   NXDOMAIN / NODATA + SOA     -> public, s-maxage=<RFC 2308 negative TTL capped>
 *   NXDOMAIN / NODATA w/o SOA   -> no-store (RFC 2308: no SOA, no safe TTL)
 *   SERVFAIL / REFUSED / other RCODE (incl. extended) -> no-store
 *   POST / ECS-sensitive / invalid response -> no-store
 *
 * Deliberately NO `stale-while-revalidate`: a DNS record's TTL is a HARD
 * expiry (RFC 1035 §3.2.1: "the time interval that the resource record may
 * be cached before it should be discarded"). Serving stale DNS past the TTL
 * would hand clients answers older than the record's own lifetime — the CDN
 * must refetch once s-maxage elapses, never extend it with a serve-stale
 * window (user-confirmed policy, mirrors vercel-doh).
 */

export interface CacheControlInput {
  method: string;
  /** Whether the upstream response passed DNS validation. */
  validResponse: boolean;
  /** Full RCODE, including EDNS(0) extended-rcode bits (BADVERS = 16, …). */
  rcode: number;
  /** True when the request carried ECS, the proxy injected ECS, or the response carries ECS. */
  ecsSensitive: boolean;
  /** Minimum ANSWER-section TTL (positive answers only). */
  minAnswerTtl: number | null;
  /** RFC 2308 negative TTL from the SOA record (NXDOMAIN/NODATA). */
  negativeTtl: number | null;
  cacheMaxAge: number;
}

export function buildCacheControl(input: CacheControlInput): string {
  if (input.method === "POST" || input.ecsSensitive || !input.validResponse) return "no-store";

  const cacheable = input.rcode === 0 || input.rcode === 3;
  if (!cacheable) return "no-store";

  let ttl: number | null = null;
  if (input.rcode === 0 && input.minAnswerTtl !== null) {
    ttl = input.minAnswerTtl;
  } else if (input.negativeTtl !== null) {
    ttl = input.negativeTtl; // RFC 2308: min(SOA TTL, SOA.MINIMUM)
  }
  if (ttl === null) return "no-store";

  const capped = Math.max(0, Math.min(ttl, input.cacheMaxAge));
  return `public, s-maxage=${capped}`;
}
