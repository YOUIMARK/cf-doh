/**
 * Shared response helpers: CORS, error responses that never leak internals,
 * and the DNS-message response builder that carries the cache TTL.
 */

export function corsHeaders(): Record<string, string> {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization, x-doh-token",
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
      ...corsHeaders(),
      ...debugHeaders,
    },
  });
}
