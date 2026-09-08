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
 * The serve-stale window never exceeds the entry's own TTL (bounded at 60s).
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
  const stale = Math.max(0, Math.min(60, capped));
  return `public, s-maxage=${capped}, stale-while-revalidate=${stale}`;
}
