/**
 * Configuration parsing for the DoH worker.
 *
 * Every option has a safe default and is optional. Invalid values fail fast
 * (they throw during the first request, which surfaces in Workers Logs)
 * instead of silently degrading. Environment variables come from the
 * Cloudflare dashboard or wrangler.jsonc `vars` / secrets.
 *
 * Fuses the config surface of cf-doh with vercel-doh (URL flags, provider
 * mappings, ECS pools, answer family, response padding, cache caps).
 */

import { parseIp } from "./dns/encode";

export type Mode = "failover" | "strict";
/** Answer-family preference: v4 forces the question type to A, v6 to AAAA. */
export type Family = "auto" | "v4" | "v6";

export interface DomainMapping {
  /** Upstream base for the provider. A bare hostname is normalized to https. */
  targetDomain: string;
}

export interface Config {
  /** Upstream DoH providers, tried in order (failover) or in parallel (strict). */
  upstreamUrls: string[];
  /** Upstreams used when the query carries (or we added) ECS. */
  ecsUpstreamUrls: string[];
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
  /** Global ECS behavior: "on" injects/truncates ECS, "off" strips it. URL flags override. */
  ecs: boolean;
  /** Optional fixed ECS source IP (only effective when ECS is enabled). */
  ecsOverrideIp: string | null;
  /** ECS prefix lengths for IPv4 / IPv6 when injecting or truncating. */
  ecsV4: number;
  ecsV6: number;
  /** Answer family: auto | v4 (force A) | v6 (force AAAA). URL flags override. */
  upstreamFamily: Family;
  /** Whether the frontend may display the DoH endpoint path (default: hidden). */
  showDohEndpoint: boolean;
  /** Cap for s-maxage on successful GET answers (seconds). */
  cacheMaxAge: number;
  /** Concurrently race all upstreams and take the fastest (default off). */
  raceUpstreams: boolean;
  /** RFC 8467 response padding (default off). */
  forceResponsePadding: boolean;
  /** Optional path -> upstream mapping for /dns-query/{provider}. */
  domainMappings: Record<string, DomainMapping>;
  /** Cache TTL clamping (seconds). */
  ttlFloor: number;
  ttlCeil: number;
  /** 0..1 jitter fraction applied to cache TTLs to avoid thundering herd. */
  ttlJitter: number;
  /** Negative-cache TTL (NXDOMAIN without SOA, synthetic blocks). */
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
  /** Version shown on the info page. */
  appVersion: string;
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
  // Strict integer only — "3000foo" / "24.9" must be rejected, not truncated.
  if (!/^\d+$/.test(v.trim())) throw new Error(`invalid number: ${v}`);
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

function parseUpstreams(v: string | undefined, def: string[]): string[] {
  const raw = v === undefined || v.trim() === "" ? def : v.split(",");
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

function parseDomainMappings(v: string | undefined): Record<string, DomainMapping> {
  if (v === undefined || v.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(v);
  } catch {
    throw new Error("DOMAIN_MAPPINGS must be a valid JSON object");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("DOMAIN_MAPPINGS must be a JSON object");
  }
  const out: Record<string, DomainMapping> = {};
  for (const [prefix, mapping] of Object.entries(parsed as Record<string, unknown>)) {
    if (mapping === null || typeof mapping !== "object" || Array.isArray(mapping)) {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"] must be an object`);
    }
    const m = mapping as Record<string, unknown>;
    if (typeof m.targetDomain !== "string" || m.targetDomain.length === 0) {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain must be a non-empty string`);
    }
    // Same https-only rule as the regular upstreams (SSRF guard).
    const raw = m.targetDomain.includes("://") ? m.targetDomain : `https://${m.targetDomain}`;
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain is not a valid URL`);
    }
    if (url.protocol !== "https:") {
      throw new Error(`DOMAIN_MAPPINGS["${prefix}"].targetDomain must be https`);
    }
    out[prefix] = { targetDomain: m.targetDomain };
  }
  return out;
}

function parseMemMb(v: string | undefined): number {
  return num(v, 8, 1, 64) * 1024 * 1024;
}

function parseOptionalIp(v: string | undefined): string | null {
  if (v === undefined || v.trim() === "") return null;
  const trimmed = v.trim();
  if (!parseIp(trimmed)) {
    throw new Error(`invalid ECS_OVERRIDE_IP: "${v}" (expected an IPv4 or IPv6 address)`);
  }
  return trimmed;
}

export function parseConfig(env: Record<string, string | undefined>): Config {
  const modeRaw = pick(env["MODE"], "failover").toLowerCase();
  if (modeRaw !== "failover" && modeRaw !== "strict") {
    throw new Error(`invalid MODE: ${modeRaw}`);
  }
  const familyRaw = pick(env["UPSTREAM_FAMILY"], "auto").toLowerCase();
  if (familyRaw !== "auto" && familyRaw !== "v4" && familyRaw !== "v6") {
    throw new Error(`invalid UPSTREAM_FAMILY: ${familyRaw}`);
  }
  return {
    upstreamUrls: parseUpstreams(env["UPSTREAM_URLS"], DEFAULT_UPSTREAMS),
    ecsUpstreamUrls: parseUpstreams(env["ECS_UPSTREAM_URLS"], ["https://dns.google/dns-query"]),
    dohPath: normPath(env["DOH_PATH"], "/dns-query"),
    jsonPath: env["JSON_PATH"] && env["JSON_PATH"].trim() !== "" ? normPath(env["JSON_PATH"], "/dns-query.json") : null,
    jsonUpstream: env["JSON_UPSTREAM"] && env["JSON_UPSTREAM"].trim() !== "" ? pick(env["JSON_UPSTREAM"], "https://dns.google/resolve") : null,
    authToken: env["AUTH_TOKEN"] && env["AUTH_TOKEN"].trim() !== "" ? env["AUTH_TOKEN"] : null,
    adminToken: env["ADMIN_TOKEN"] && env["ADMIN_TOKEN"].trim() !== "" ? env["ADMIN_TOKEN"] : null,
    ecs: bool(env["ECS"], false),
    ecsOverrideIp: parseOptionalIp(env["ECS_OVERRIDE_IP"]),
    ecsV4: num(env["ECS_V4"], 24, 0, 32),
    ecsV6: num(env["ECS_V6"], 56, 0, 128),
    upstreamFamily: familyRaw as Family,
    showDohEndpoint: bool(env["SHOW_DOH_ENDPOINT"], false),
    cacheMaxAge: num(env["CACHE_MAX_AGE"], 300, 0, 86400),
    raceUpstreams: bool(env["RACE_UPSTREAMS"], false),
    forceResponsePadding: bool(env["FORCE_RESPONSE_PADDING"], false),
    domainMappings: parseDomainMappings(env["DOMAIN_MAPPINGS"]),
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
    appVersion: pick(env["APP_VERSION"], "1.0.0"),
  };
}
