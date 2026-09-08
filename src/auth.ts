/**
 * Request authentication.
 *
 * The DoH endpoint path itself acts as the primary secret (a random
 * `DOH_PATH` segment is the simplest way to stop strangers from consuming
 * the free-tier quota). `AUTH_TOKEN` adds a shared-secret layer:
 * `Authorization: Bearer <token>`, `?token=<token>` or `X-DOH-Token: <token>`.
 * `ADMIN_TOKEN` protects the /config and /health endpoints.
 */

import type { Config } from "./config";

/** Constant-time string comparison (timing-safe enough for shared secrets). */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function tokenFrom(request: Request, token: string | null): string | null {
  if (!token) return null;
  const auth = request.headers.get("authorization");
  if (auth && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const q = new URL(request.url).searchParams.get("token");
  if (q) return q;
  const h = request.headers.get("x-doh-token");
  if (h) return h;
  return null;
}

export function checkAuth(request: Request, cfg: Config): boolean {
  if (!cfg.authToken) return true;
  const provided = tokenFrom(request, cfg.authToken);
  return provided !== null && safeEqual(provided, cfg.authToken);
}

export function checkAdmin(request: Request, cfg: Config): boolean {
  if (!cfg.adminToken) return true;
  const provided = tokenFrom(request, cfg.adminToken);
  return provided !== null && safeEqual(provided, cfg.adminToken);
}
