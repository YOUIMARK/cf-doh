/**
 * Configuration parsing for the DoH worker.
 *
 * Every option has a safe default and is optional. Invalid values fail fast
 * (they throw during the first request, which surfaces in Workers Logs)
 * instead of silently degrading. Environment variables come from the
 * Cloudflare dashboard or wrangler.jsonc `vars` / secrets.
 */

export type Mode = "failover" | "strict";

export interface Config {
  /** Upstream DoH providers, tried in order (failover) or in parallel (strict). */
  upstreamUrls: string[];
  /** Exact path that serves RFC 8484 DoH. Add a random segment to keep it secret. */
  dohPath: string;
  /** Optional exact path serving Google-style JSON API (dns-json). null = disabled. */
  jsonPath: string | null;
  /** Upstream used by the JSON API endpoint. */
  jsonUpstream: string | null;
  /** Optional shared token: Bearer header, `?token=` query or `X-DOH-Token`. */
  authToken: string | null;
  /** Optional token required for /config (and /health when set). */
  adminToken: string | null;
  /** Inject/truncate EDNS Client Subnet. false = strip client ECS before forwarding. */
  ecs: boolean;
  /** ECS prefix lengths for IPv4 / IPv6 when injecting or truncating. */
  ecsV4: number;
  ecsV6: number;
  /** Cache TTL clamping (seconds). */
  ttlFloor: number;
  ttlCeil: number;
  /** 0..1 jitter fraction applied to cache TTLs to avoid thundering herd. */
  ttlJitter: number;
  /** Negative-cache TTL (NXDOMAIN, synthetic blocks). */
  negTtl: number;
  /** failover = sequential, strict = parallel fan-out with most-restrictive pick. */
  mode: Mode;
  /** Replace responses whose answers are all private/loopback IPs with NXDOMAIN. */
  rebindProtection: boolean;
  /** Extra attempts per provider after a 5xx/network/timeout failure. */
  maxRetries: number;
  /** Per-provider upstream timeout in milliseconds. */
  timeoutMs: number;
  /** Maximum DNS message size accepted from clients and upstreams (bytes). */
  maxBody: number;
  /** In-memory LRU byte budget shared per isolate. */
  cacheMemBytes: number;
  /** Homepage body when `ROOT_CONTENT` is set. */
  rootContent: string | null;
  /** Redirect target for `/` when set (takes precedence over ROOT_CONTENT). */
  url302: string | null;
  /** Enable diagnostic `X-DOH-*` response headers and verbose logging. */
  debug: boolean;
}

export const DEFAULT_POSITIVE_TTL = 60;

const DEFAULT_UPSTREAMS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/dns-query",
];

function num(
  v: string | undefined,
  def: number,
  min = 0,
  max = Number.MAX_SAFE_INTEGER,
): number {
  if (v === undefined || v.trim() === "") return def;
  const n = Number(v);
  if (!Number.isFinite(n)) throw new Error(`invalid number: ${v}`);
  return Math.min(max, Math.max(min, Math.round(n)));
}

function bool(v: string | undefined, def: boolean): boolean {
  if (v === undefined || v.trim() === "") return def;
  const s = v.trim().toLowerCase();
  if (s === "1" || s === "true" || s === "on" || s === "yes") return true;
  if (s === "0" || s === "false" || s === "off" || s === "no") return false;
  throw new Error(`invalid boolean: ${v}`);
}

function pick(v: string | undefined, def: string): string {
  return v === undefined || v.trim() === "" ? def : v.trim();
}

function normPath(v: string | undefined, def: string): string {
  let p = pick(v, def);
  if (!p.startsWith("/")) p = "/" + p;
  if (p.length > 1 && p.endsWith("/")) p = p.slice(0, -1);
  return p;
}

function parseUpstreams(v: string | undefined): string[] {
  const raw = v === undefined || v.trim() === "" ? DEFAULT_UPSTREAMS : v.split(",");
  const out: string[] = [];
  for (const item of raw) {
    const s = item.trim();
    if (!s) continue;
    let u: URL;
    try {
      u = new URL(s);
    } catch {
      throw new Error(`invalid upstream URL: ${s}`);
    }
    if (u.protocol !== "https:") throw new Error(`upstream must be https: ${s}`);
    out.push(u.toString().replace(/\/$/, ""));
  }
  if (out.length === 0) throw new Error("no upstream URLs configured");
  return out;
}

function parseMemMb(v: string | undefined): number {
  return num(v, 8, 1, 64) * 1024 * 1024;
}

export function parseConfig(env: Record<string, string | undefined>): Config {
  const modeRaw = pick(env["MODE"], "failover").toLowerCase();
  if (modeRaw !== "failover" && modeRaw !== "strict") {
    throw new Error(`invalid MODE: ${modeRaw}`);
  }
  return {
    upstreamUrls: parseUpstreams(env["UPSTREAM_URLS"]),
    dohPath: normPath(env["DOH_PATH"], "/dns-query"),
    jsonPath: env["JSON_PATH"] && env["JSON_PATH"].trim() !== "" ? normPath(env["JSON_PATH"], "/dns-query.json") : null,
    jsonUpstream: env["JSON_UPSTREAM"] && env["JSON_UPSTREAM"].trim() !== "" ? pick(env["JSON_UPSTREAM"], "https://dns.google/resolve") : null,
    authToken: env["AUTH_TOKEN"] && env["AUTH_TOKEN"].trim() !== "" ? env["AUTH_TOKEN"] : null,
    adminToken: env["ADMIN_TOKEN"] && env["ADMIN_TOKEN"].trim() !== "" ? env["ADMIN_TOKEN"] : null,
    ecs: bool(env["ECS"], false),
    ecsV4: num(env["ECS_V4"], 24, 0, 32),
    ecsV6: num(env["ECS_V6"], 56, 0, 128),
    ttlFloor: num(env["TTL_FLOOR"], 0, 0, 86400 * 7),
    ttlCeil: num(env["TTL_CEIL"], 86400, 1, 86400 * 7),
    ttlJitter: Math.min(1, Math.max(0, num(env["TTL_JITTER"], 0.1, 0, 1))),
    negTtl: num(env["NEG_TTL"], 15, 0, 86400),
    mode: modeRaw as Mode,
    rebindProtection: bool(env["REBIND_PROTECTION"], false),
    maxRetries: num(env["MAX_RETRIES"], 1, 0, 10),
    timeoutMs: num(env["TIMEOUT_MS"], 3000, 100, 30000),
    maxBody: num(env["MAX_BODY"], 65536, 512, 1_048_576),
    cacheMemBytes: parseMemMb(env["CACHE_MEM"]),
    rootContent: env["ROOT_CONTENT"] && env["ROOT_CONTENT"].trim() !== "" ? env["ROOT_CONTENT"] : null,
    url302: env["URL302"] && env["URL302"].trim() !== "" ? env["URL302"] : null,
    debug: bool(env["DEBUG"], false),
  };
}
