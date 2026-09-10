/**
 * Shared response helpers: CORS, error responses that never leak internals,
 * and the DNS-message response builder that carries the cache TTL.
 */

export function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-doh-token",
    // Cache the preflight response for a day so browser CORS clients skip
    // the OPTIONS round-trip on every query (borrowed from DoHflare/DoH-vercel).
    "access-control-max-age": "86400",
  };
}

export function jsonError(status: number, message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...corsHeaders(),
    },
  });
}

export function ok204(): Response {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

/** Build a DoH response with an explicit cache lifetime. */
export function dnsResponse(
  body: Uint8Array,
  ttl: number,
  debugHeaders: Record<string, string> = {},
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/dns-message",
      "cache-control": `max-age=${Math.max(0, Math.floor(ttl))}`,
      // Service-identity header (borrowed from NextDNS-DOH): makes it obvious
      // which proxy layer produced the response when debugging multi-hop setups.
      "x-proxied-by": "cf-doh",
      ...corsHeaders(),
      ...debugHeaders,
    },
  });
}

export function jsonResponse(
  body: Uint8Array,
  ttl: number,
  debugHeaders: Record<string, string> = {},
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": "application/dns-json",
      "cache-control": `max-age=${Math.max(0, Math.floor(ttl))}`,
      "x-proxied-by": "cf-doh",
      ...corsHeaders(),
      ...debugHeaders,
    },
  });
}
