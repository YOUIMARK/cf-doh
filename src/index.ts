/**
 * Fused DNS-over-HTTPS proxy for Cloudflare Workers / Pages.
 *
 * Converged build: dual-layer TTL-aware caching + strict mode + auth
 * (cf-doh) × protocol gate, response validation, RFC 2308 negative caching,
 * exact media negotiation, ECS three-state handling, URL flags, provider
 * mapping, SSRF guard and RFC 8467 padding (vercel-doh) + resolver frontend
 * (borrowed and optimized from CF-Workers-DoH).
 *
 * Design constraints from Cloudflare docs (free plan): 10 ms CPU/invocation,
 * 50 subrequests/request, 6 concurrent connections/request, 128 MB isolate.
 * Cache hits still bill a request but save the upstream subrequest + CPU.
 */

import {
  parseConfig,
  type Config,
  type Family,
} from "./config";
import { DohCache, makeCacheKeyStr, makeWireCacheKey } from "./cache";
import { resolveCandidates, resolveProvider, type ResolveResult } from "./upstream";
import { parseQuestion } from "./dns/parse";
import { base64urlToBytes, getEcs, parseIp, toHex, truncateIp } from "./dns/encode";
import { buildSyntheticNxdomain, classifyResponse, scanAnswers, soaNegativeTtl } from "./dns/classify";
import { buildErrorResponse, extendedRcode, questionType, setQuestionType, withTransactionId } from "./dns/wire";
import {
  addOrMergeEcs,
  buildEcsOption,
  ecsStatus,
  parseClientIp,
  removeEcsOption,
} from "./dns/ecs";
import { formatEcsPrefix, parseCidr } from "./dns/ip";
import { validateQuery } from "./dns/validate";
import { padResponse } from "./dns/padding";
import { buildCacheControl } from "./cache-control";
import { acceptsMediaType, parseMediaType } from "./media";
import { checkAdmin, checkAuth } from "./auth";
import { corsHeaders, dnsResponse, jsonError, ok204, securityHeaders } from "./response";
import { renderHomepage } from "./frontend.js";

export interface Env {
  [key: string]: string | undefined;
}

export const DNS_MESSAGE = "application/dns-message";
export const DNS_JSON = "application/dns-json";

let cacheSingleton: DohCache | null = null;

function getCache(cfg: Config): DohCache {
  if (!cacheSingleton) cacheSingleton = new DohCache(cfg.cacheMemBytes);
  return cacheSingleton;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const cfg = parseConfig(env as Record<string, string | undefined>);
    return route(request, cfg, getCache(cfg), ctx);
  },
};

// ── URL flags: {base}/v4, /v6, /ecs, /no-ecs, /ecs-<ip>, /{provider} ──
type EcsBehavior = "default" | "force_enable" | "force_disable";

interface PathFlags {
  family: Family | null;
  behavior: EcsBehavior | null;
  ecsOverrideIp: string | null;
  provider: string | null;
}

const INVALID_PATH = "__invalid__";
const EMPTY_FLAGS: PathFlags = { family: null, behavior: null, ecsOverrideIp: null, provider: null };
const ECS_FLAGS: Record<string, EcsBehavior> = {
  ecs: "force_enable",
  auto_ecs: "force_enable",
  "no-ecs": "force_disable",
  no_ecs: "force_disable",
};

/**
 * Deterministic TTL jitter (borrowed from DoHflare's calculateDeterministicJitter):
 * the jitter fraction is derived from the cache-key hex instead of Math.random,
 * so the SAME entry gets the SAME jittered TTL on every isolate. A random
 * jitter would disagree between isolates and fragment the shared Cache API
 * entry (each isolate would store a slightly different max-age). Exported for
 * unit tests.
 */
export function deterministicJitterTtl(seed: string, ttl: number, jitter: number): number {
  const frac = (parseInt(seed.slice(-8), 16) / 0xffffffff) % 1;
  return Math.max(1, Math.round(ttl * (1 - frac * jitter)));
}

function parsePathFlags(pathname: string, basePath: string): PathFlags {
  const base = basePath.replace(/\/+$/, "");
  if (pathname === base) return { ...EMPTY_FLAGS };
  if (!pathname.startsWith(`${base}/`)) return { ...EMPTY_FLAGS };
  const segments = pathname.slice(base.length + 1).split("/").filter((s) => s.length > 0);
  const flags: PathFlags = { ...EMPTY_FLAGS };
  for (const segment of segments) {
    if (segment === "v4") flags.family = "v4";
    else if (segment === "v6") flags.family = "v6";
    else if (ECS_FLAGS[segment]) flags.behavior = ECS_FLAGS[segment]!;
    else if (segment.startsWith("ecs-")) {
      // ecs-<ip> forces ECS on with a fixed source IP. An invalid IP literal
      // is an unknown path (404), mirroring vercel-doh.
      const ip = segment.slice(4);
      if (!parseIp(ip)) {
        flags.provider = INVALID_PATH;
      } else {
        flags.ecsOverrideIp = ip;
        flags.behavior = "force_enable";
      }
    } else if (flags.provider === null) flags.provider = segment;
    else flags.provider = INVALID_PATH;
  }
  return flags;
}

async function route(
  request: Request,
  cfg: Config,
  cache: DohCache,
  ctx: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  let path = url.pathname;
  if (path.length > 1 && path.endsWith("/")) path = path.slice(0, -1);

  try {
    // DoH base path + URL flags (/v4, /ecs, /no-ecs, /ecs-<ip>, /{provider})
    if (path === cfg.dohPath || path.startsWith(cfg.dohPath + "/")) {
      return await handleDoh(request, cfg, cache, ctx, url, path);
    }
    if (cfg.jsonPath !== null && (path === cfg.jsonPath || path.startsWith(cfg.jsonPath + "/"))) {
      return await handleJson(request, cfg, cache, ctx, url);
    }
    if (path === "/ip-info") return handleIpInfo(request);
    if (path === "/health") return handleHealth(request, cfg);
    if (path === "/config") return handleConfig(request, cfg);
    // Original CF-Workers-DoH aggregate query: /?doh=&domain=&type=all
    // (the frontend queries its own origin; the worker forwards to the
    // selected DoH server with Google-style dns-json parameters).
    if (path === "/" && url.searchParams.has("doh")) {
      return await handleAggregateQuery(cfg, url);
    }
    if (path === "/") return handleRoot(cfg);
    return jsonError(404, "not found");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("doh-worker error:", msg);
    return jsonError(500, "internal error");
  }
}

/** strict mode: pick the most restrictive usable response. */
function pickMostRestrictive(candidates: ResolveResult[]): ResolveResult {
  let nx: ResolveResult | null = null;
  let zero: ResolveResult | null = null;
  let firstOk: ResolveResult | null = null;
  for (const c of candidates) {
    const kind = classifyResponse(c.body, false);
    if (kind === "blocked") return c;
    if (kind === "nxdomain") nx ??= c;
    if (c.provider === 0) zero = c;
    if (kind === "ok" && firstOk === null) firstOk = c;
  }
  return nx ?? zero ?? firstOk ?? candidates[0]!;
}

async function handleDoh(
  request: Request,
  cfg: Config,
  cache: DohCache,
  ctx: ExecutionContext,
  url: URL,
  path: string,
): Promise<Response> {
  if (request.method === "OPTIONS") return ok204();
  if (!checkAuth(request, cfg)) return jsonError(401, "unauthorized");

  const flags = parsePathFlags(path, cfg.dohPath);
  if (flags.provider === INVALID_PATH) return jsonError(404, "unknown path");

  const method = request.method;
  const accept = (request.headers.get("accept") ?? "").trim();
  const wantsJson =
    acceptsMediaType(accept, DNS_JSON) ||
    acceptsMediaType(accept, "application/json") ||
    url.searchParams.get("ct") === DNS_JSON;
  const acceptsMessage = acceptsMediaType(accept, DNS_MESSAGE);

  // Browser-style GET with no dns param → JSON query or endpoint info.
  if (method === "GET" && !url.searchParams.get("dns")) {
    if (url.searchParams.get("name") || wantsJson) {
      // Base-path JSON query (dns.google/resolve style): URL flags on the
      // DoH base path apply too, e.g. /{DOH_PATH}/v6?name=... forces AAAA.
      return handleJson(request, cfg, cache, ctx, url, {
        family: flags.family,
        behavior: flags.behavior,
        ecsOverrideIp: flags.ecsOverrideIp,
      });
    }
    if (acceptsMessage) return jsonError(400, "missing dns parameter");
    return infoText(cfg);
  }
  if (method !== "GET" && method !== "POST") {
    return jsonError(405, "method not allowed");
  }
  // RFC 8484 media negotiation: an explicit Accept that excludes
  // application/dns-message is a 406 for GET AND POST (CF-011). An absent
  // Accept (or a wildcard like */*) stays allowed — DoH clients in the wild
  // often send neither.
  if (!acceptsMessage && (method === "GET" || accept !== "")) {
    return jsonError(406, "Not Acceptable: application/dns-message required");
  }

  // ── Body acquisition with size caps ──
  let message: Uint8Array;
  if (method === "POST") {
    const declared = request.headers.get("content-length");
    if (declared && Number.parseInt(declared, 10) > cfg.maxBody) {
      return jsonError(413, "query too large");
    }
    const contentType = request.headers.get("content-type") ?? "";
    if (parseMediaType(contentType) !== DNS_MESSAGE) {
      return jsonError(415, "unsupported content type");
    }
    const raw = await request.arrayBuffer();
    if (raw.byteLength > cfg.maxBody) return jsonError(413, "query too large");
    message = new Uint8Array(raw);
  } else {
    const dnsParam = url.searchParams.get("dns") ?? "";
    // Reject by the base64url expansion ratio BEFORE decoding: an attacker
    // can otherwise force an expensive 4/3-size decode of a huge parameter
    // (each 4 chars of base64url encode 3 bytes; unpadded). Borrowed from
    // NextDNS-DOH's parseDnsRequest pre-check.
    if (dnsParam.length > Math.ceil((cfg.maxBody * 4) / 3) + 2) {
      return jsonError(413, "query too large");
    }
    // RFC 8484 §4.1: the dns= parameter MUST be unpadded base64url. Reject
    // legacy padded / standard-base64 forms ("=", "+", "/") and the
    // impossible length % 4 == 1 outright instead of tolerating them
    // (mirrors vercel-doh's strictness).
    if (!/^[A-Za-z0-9_-]+$/.test(dnsParam) || dnsParam.length % 4 === 1) {
      return jsonError(400, "invalid dns parameter (base64url, unpadded)");
    }
    const decoded = base64urlToBytes(dnsParam);
    if (!decoded) return jsonError(400, "invalid dns parameter (base64url)");
    message = decoded;
  }
  if (message.length === 0) return jsonError(400, "empty dns message");
  if (message.length > cfg.maxBody) return jsonError(413, "query too large");

  // ── Protocol gate: reject malformed queries before touching upstream ──
  if (!validateQuery(message)) return jsonError(400, "malformed dns query");

  const q = parseQuestion(message);
  if (!q) return jsonError(400, "malformed dns message");

  // ── ECS handling (three-state, ported from vercel-doh) ──
  // `cfg.ecs=false` (the default) means STRIP: a client-provided subnet must
  // never reach an upstream when the operator opted out of ECS (CF-003).
  // URL flags still override: /ecs forces enable, /no-ecs forces disable.
  const effectiveBehavior: EcsBehavior =
    flags.behavior ?? (cfg.ecs ? "force_enable" : "force_disable");

  if (effectiveBehavior === "force_disable" && ecsStatus(message) !== "absent") {
    message = removeEcsOption(message); // STRIP, not merely skip injection
  }

  const shouldAddEcs = effectiveBehavior === "force_enable";
  if (shouldAddEcs && ecsStatus(message) === "absent") {
    const overrideIp = flags.ecsOverrideIp ?? cfg.ecsOverrideIp;
    const sourceIp = overrideIp ? parseOverrideIp(overrideIp) : parseClientIp(request.headers);
    if (sourceIp) {
      const prefix = sourceIp.family === 1 ? cfg.ecsV4 : cfg.ecsV6;
      const merged = addOrMergeEcs(message, buildEcsOption(sourceIp, prefix));
      if (merged !== message) message = merged;
    }
  }

  // Sensitivity of the OUTGOING query: drives upstream pool + cache policy.
  const ecsSensitive = ecsStatus(message) !== "absent";

  // ── Answer-family flag: force question type to A (v4) / AAAA (v6) ──
  const family = flags.family ?? cfg.upstreamFamily;
  if (family !== "auto") {
    const current = questionType(message);
    if (current === 1 || current === 28 || current === 255) {
      const rewritten = setQuestionType(message, family === "v4" ? 1 : 28);
      if (rewritten) message = rewritten;
    }
  }

  // ── Cache key + dual-layer lookup (GET + non-ECS only: privacy) ──
  // Key = effective upstream bytes (post ECS / post family-rewrite) minus the
  // transaction ID, plus the provider identity, mode and ECS bucket. This
  // captures every answer-affecting dimension — RD/CD, EDNS DO/version, any
  // EDNS option, the /v4 /v6 family rewrite, the provider pool — so unrelated
  // queries can never share a cached response (CF-001). Computed lazily: only
  // GET + non-ECS requests ever read or write the cache (POST is the common
  // DoH client path and must not pay for a 64 KB hash).
  const ecs = getEcs(message);
  const bucket = ecsSensitive ? `${ecs?.family ?? 0}:${toHex(ecs?.address ?? new Uint8Array(0))}` : "none";
  const cacheable = method === "GET" && !ecsSensitive;
  let cacheKey: string | null = null;
  if (cacheable) {
    const providerKey = flags.provider
      ? (resolveProvider(cfg, flags.provider) ?? "")
      : (ecsSensitive && cfg.ecsUpstreamUrls.length > 0 ? cfg.ecsUpstreamUrls : cfg.upstreamUrls).join("|");
    cacheKey = await makeWireCacheKey(message, providerKey, cfg.mode === "strict" ? "s" : "f", bucket);
  }

  // The cached body is canonical (transaction ID 0); on a hit the current
  // request's ID is restored so client B never receives client A's ID (CF-002).
  const requestId = message.length >= 2 ? ((message[0]! << 8) | message[1]!) : 0;
  if (cacheable && cacheKey !== null) {
    const local = cache.getLocal(cacheKey);
    if (local) {
      return dnsResponse(withTransactionId(local.body, requestId), local.ttl, debugHeaders(cfg, "hit", bucket, -1, local.ttl));
    }
    const remote = await cache.getRemote(cacheKey);
    if (remote) {
      cache.putLocal(cacheKey, remote);
      return dnsResponse(withTransactionId(remote.body, requestId), remote.ttl, debugHeaders(cfg, "hit", bucket, -1, remote.ttl));
    }
  }

  // ── Upstream selection: ECS-aware pool, provider mapping ──
  let upstreamPool =
    ecsSensitive && cfg.ecsUpstreamUrls.length > 0 ? cfg.ecsUpstreamUrls : cfg.upstreamUrls;
  if (flags.provider) {
    const mapped = resolveProvider(cfg, flags.provider);
    if (!mapped) return jsonError(404, `unknown provider: ${flags.provider}`);
    upstreamPool = [mapped];
  }

  const candidates = await resolveCandidates(message, cfg, upstreamPool);
  if (candidates.length === 0) {
    // All upstreams failed → legal SERVFAIL dns-message (RFC 8484), not text.
    return dnsResponse(buildErrorResponse(message, 2), 0, { "cache-control": "no-store" });
  }

  const winner = cfg.mode === "strict" ? pickMostRestrictive(candidates) : candidates[0]!;
  const kind = classifyResponse(winner.body, cfg.rebindProtection);

  let outBody = winner.body;
  if (kind === "rebind") {
    outBody = buildSyntheticNxdomain(message, q.questionEnd);
  }

  // Full RCODE including EDNS(0) extended bits — the low nibble alone would
  // turn BADVERS (16) into NOERROR and poison cache/decision logic (CF-014).
  const rcode = extendedRcode(outBody);
  const minTtl = kind === "error" ? null : scanAnswers(winner.body).minTtl;
  const minAnswerTtl = minTtl === Infinity ? null : minTtl;
  const negTtl = soaNegativeTtl(outBody);

  // Response carries ECS (e.g. scope > 0) → client-specific, never shared.
  const responseHasEcs = ecsStatus(outBody) !== "absent";
  const cacheControl = buildCacheControl({
    method,
    validResponse: true,
    rcode,
    ecsSensitive: ecsSensitive || responseHasEcs,
    minAnswerTtl,
    negativeTtl: negTtl,
    cacheMaxAge: cfg.cacheMaxAge,
  });

  let internalTtl = 0;
  if (cacheControl !== "no-store") {
    const m = /s-maxage=(\d+)/.exec(cacheControl);
    const authoritativeTtl = m ? Number(m[1]) : 0;
    // TTL_FLOOR must never raise freshness beyond the authoritative DNS TTL
    // (CF-009): a floor above the resolver's TTL would serve stale answers
    // past the record's real expiry. Effective TTL is capped at TTL_CEIL.
    internalTtl = Math.min(cfg.ttlCeil, authoritativeTtl);
    if (internalTtl > 0 && cfg.ttlJitter > 0) {
      internalTtl = deterministicJitterTtl(cacheKey ?? toHex(outBody.subarray(0, 8)), internalTtl, cfg.ttlJitter);
    }
  }

  if (cfg.forceResponsePadding) outBody = padResponse(outBody);

  if (internalTtl > 0 && cacheKey !== null) {
    // Store the canonical response (transaction ID 0); the client-facing copy
    // keeps the requesting client's ID (CF-002).
    const entry = { body: withTransactionId(outBody, 0), status: 200, ttl: internalTtl };
    cache.putLocal(cacheKey, entry);
    ctx.waitUntil(cache.putRemote(cacheKey, entry));
  }

  return dnsResponse(outBody, internalTtl, {
    "cache-control": cacheControl,
    ...debugHeaders(cfg, "miss", bucket, winner.provider, internalTtl),
  });
}

/** Parses an override IP for ECS injection (family from the literal). */
function parseOverrideIp(ip: string): ReturnType<typeof parseClientIp> {
  const bits = ip.includes(":") ? 56 : 24;
  const t = truncateIp(ip, bits);
  return t;
}

// ── dns-json API ───────────────────────────────────────────────────────────

/** RFC 1035 §2.3.4: a domain name is at most 253 characters of text. */
const MAX_DOMAIN_TEXT = 253;
/** Text form of a domain name (letters, digits, dots, hyphen, underscore). */
const DOMAIN_CHARS = /^[a-zA-Z0-9._-]+$/;
/** Canonical boolean forms accepted for the cd/do dns-json flags. */
const BOOLEAN_FLAG = /^(0|1|true|false)$/i;
/** dns-json type whitelist (abuse/amplification guard, mirrors vercel-doh). */
const JSON_ALLOWED_TYPES = new Set([
  "ALL", "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV",
  "CAA", "HTTPS", "SVCB", "DS", "DNSKEY", "TLSA", "ANY",
]);

/** Google dns-json type names → wire type codes (JSON cache key dimension).
 *  Modern RR types (SVCB/HTTPS, DNSSEC) included so their cache keys never
 *  collapse onto unknown-type code 0 (CF-013). */
const JSON_TYPE_CODES: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33,
  DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52, SVCB: 64,
  HTTPS: 65, URI: 256, CAA: 257, ANY: 255,
};

function jsonTypeCode(type: string): number {
  const t = type.trim().toUpperCase();
  if (/^\d+$/.test(t)) return Math.min(65535, Number(t));
  return JSON_TYPE_CODES[t] ?? 0;
}

/** Minimal dns-json schema (Google resolve style) after validation. */
interface JsonResponse {
  Status?: unknown;
  Question?: unknown;
  Answer?: unknown;
  Authority?: unknown;
  Additional?: unknown;
}

/**
 * Parses and structurally validates a dns-json body (Google resolve style):
 * a JSON object with a numeric `Status` when present and array-typed
 * Question/Answer/Authority/Additional sections with object entries. Returns
 * null when the body is not trustworthy as a dns-json response (mirrors
 * vercel-doh's `validateJsonResponse`).
 */
function validateJsonResponse(body: Uint8Array): JsonResponse | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const obj = parsed as Record<string, unknown>;
  if ("Status" in obj && typeof obj.Status !== "number") return null;
  for (const key of ["Question", "Answer", "Authority", "Additional"] as const) {
    const value = obj[key];
    if (value === undefined) continue;
    if (!Array.isArray(value)) return null;
    if (value.some((entry) => entry === null || typeof entry !== "object" || Array.isArray(entry))) {
      return null;
    }
  }
  return obj as JsonResponse;
}

/** Minimum numeric TTL across a dns-json record array, or null. */
function minJsonTtl(records: unknown): number | null {
  if (!Array.isArray(records)) return null;
  let min: number | null = null;
  for (const record of records) {
    const ttl = (record as Record<string, unknown> | null)?.TTL;
    if (typeof ttl === "number" && Number.isFinite(ttl)) {
      min = min === null ? ttl : Math.min(min, ttl);
    }
  }
  return min;
}

/**
 * RFC 2308 negative TTL from a dns-json SOA record: min(SOA TTL, SOA.MINIMUM).
 * The SOA `data` string is "MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM"
 * (7 whitespace-separated fields). Returns null when no parseable SOA exists.
 */
function soaJsonNegativeTtl(authority: unknown): number | null {
  if (!Array.isArray(authority)) return null;
  for (const record of authority) {
    const rec = record as Record<string, unknown> | null;
    if (!rec || rec.type !== 6) continue; // SOA
    const ttl = rec.TTL;
    const data = rec.data;
    if (typeof ttl !== "number" || !Number.isFinite(ttl)) continue;
    if (typeof data !== "string") continue;
    const fields = data.trim().split(/\s+/);
    if (fields.length < 7) continue;
    const minimum = Number(fields[6]);
    if (!Number.isFinite(minimum) || minimum < 0) continue;
    return Math.min(ttl, minimum);
  }
  return null;
}

/**
 * JSON API URL flags, parsed from path suffixes after the JSON base path:
 *   {jsonPath}/v4           → force type=A (answer family)
 *   {jsonPath}/v6           → force type=AAAA
 *   {jsonPath}/ecs          → inject edns_client_subnet (alias /auto_ecs)
 *   {jsonPath}/ecs-<ip>     → inject with a fixed source IP
 *   {jsonPath}/no-ecs       → strip any edns_client_subnet (alias /no_ecs)
 * Unknown segments (incl. provider-style) are an unknown path (404) — the
 * JSON API has its own upstream (JSON_UPSTREAM), no provider mapping.
 */
function parseJsonFlags(pathname: string, jsonPath: string): PathFlags {
  const base = jsonPath.replace(/\/+$/, "");
  if (pathname === base) return { ...EMPTY_FLAGS };
  if (!pathname.startsWith(`${base}/`)) return { ...EMPTY_FLAGS };
  const segments = pathname.slice(base.length + 1).split("/").filter((s) => s.length > 0);
  const flags: PathFlags = { ...EMPTY_FLAGS };
  for (const segment of segments) {
    if (segment === "v4") flags.family = "v4";
    else if (segment === "v6") flags.family = "v6";
    else if (ECS_FLAGS[segment]) flags.behavior = ECS_FLAGS[segment]!;
    else if (segment.startsWith("ecs-")) {
      const ip = segment.slice(4);
      if (!parseIp(ip)) return { ...EMPTY_FLAGS, provider: INVALID_PATH };
      flags.ecsOverrideIp = ip;
      flags.behavior = "force_enable";
    } else return { ...EMPTY_FLAGS, provider: INVALID_PATH };
  }
  return flags;
}

async function handleJson(
  request: Request,
  cfg: Config,
  cache: DohCache,
  ctx: ExecutionContext,
  url: URL,
  baseFlags?: Pick<PathFlags, "family" | "behavior" | "ecsOverrideIp">,
): Promise<Response> {
  if (request.method === "OPTIONS") return ok204();
  if (!checkAuth(request, cfg)) return jsonError(401, "unauthorized");
  if (request.method !== "GET") return jsonError(405, "method not allowed");

  // URL flags: JSON-path suffix (e.g. /resolve/v4/ecs) wins over base-path
  // flags (e.g. /dns-query/v6?name=...), which win over env defaults.
  const suffixFlags = cfg.jsonPath ? parseJsonFlags(url.pathname, cfg.jsonPath) : { ...EMPTY_FLAGS };
  if (suffixFlags.provider === INVALID_PATH) return jsonError(404, "unknown path");
  const family = suffixFlags.family ?? baseFlags?.family ?? cfg.upstreamFamily;
  const behavior = suffixFlags.behavior ?? baseFlags?.behavior ?? null;
  const ecsOverrideIp = suffixFlags.ecsOverrideIp ?? baseFlags?.ecsOverrideIp ?? cfg.ecsOverrideIp;

  const name = url.searchParams.get("name");
  if (!name) return jsonError(400, "missing name parameter");

  // ── Input validation before anything is forwarded upstream (abuse /
  //    amplification guard): bounded name, whitelisted type, canonical
  //    boolean flags, valid CIDR for edns_client_subnet.
  const rawType = url.searchParams.get("type");
  const rawCidr = url.searchParams.get("edns_client_subnet");
  const rawCd = url.searchParams.get("cd");
  const rawDo = url.searchParams.get("do");
  if (name.length > MAX_DOMAIN_TEXT || !DOMAIN_CHARS.test(name)) {
    return jsonError(400, "invalid name parameter");
  }
  if (rawType !== null && rawType !== "" && !JSON_ALLOWED_TYPES.has(rawType.toUpperCase())) {
    return jsonError(400, `unsupported type: ${rawType}`);
  }
  if (rawCidr !== null && rawCidr !== "" && parseCidr(rawCidr) === null) {
    return jsonError(400, "invalid edns_client_subnet (expected ip/prefix)");
  }
  for (const flag of [rawCd, rawDo]) {
    if (flag !== null && flag !== "" && !BOOLEAN_FLAG.test(flag)) {
      return jsonError(400, "invalid cd/do flag (expected 0|1|true|false)");
    }
  }

  // Effective upstream params: start from the client's query, then apply the
  // ECS and answer-family flags on top (URL overrides env, per request).
  const params = new URLSearchParams(url.search);

  // ── ECS flag: /ecs /ecs-<ip> inject edns_client_subnet; /no-ecs strips. ──
  if (behavior === "force_disable") {
    params.delete("edns_client_subnet");
  } else if (behavior === "force_enable") {
    const sourceIp = ecsOverrideIp ? parseIp(ecsOverrideIp) : parseClientIp(request.headers);
    if (sourceIp) {
      params.set("edns_client_subnet", formatEcsPrefix(sourceIp, sourceIp.family === 1 ? cfg.ecsV4 : cfg.ecsV6));
    }
  }
  const ecsSensitive = params.has("edns_client_subnet");

  // ── Answer-family flag: force type=A (v4) / type=AAAA (v6) ──
  if (family !== "auto") {
    const current = (params.get("type") ?? "").toUpperCase();
    const target = family === "v4" ? "A" : "AAAA";
    if (current === "" || current === "A" || current === "AAAA" || current === "ANY") {
      params.set("type", target);
    }
  }
  const qtype = params.get("type") ?? "A";

  // ECS-sensitive JSON responses are client-specific — never shared-cached.
  let cacheKey: string | null = null;
  if (!ecsSensitive) {
    cacheKey = await makeCacheKeyStr({
      name: name.toLowerCase(),
      qtype: jsonTypeCode(qtype),
      qclass: 0,
      modeKey: "j",
      ecsBucket: "none",
      typeTag: qtype.trim().toLowerCase(),
    });
    const local = cache.getLocal(cacheKey);
    if (local) {
      return jsonResponse(local.body, local.ttl, debugHeaders(cfg, "hit", "none", -1, local.ttl));
    }
    const remote = await cache.getRemote(cacheKey);
    if (remote) {
      cache.putLocal(cacheKey, remote);
      return jsonResponse(remote.body, remote.ttl, debugHeaders(cfg, "hit", "none", -1, remote.ttl));
    }
  }

  const upstream = cfg.jsonUpstream ?? "https://dns.google/resolve";
  const upstreamUrl = new URL(upstream);
  upstreamUrl.search = params.toString();
  upstreamUrl.searchParams.delete("token"); // never leak our auth token upstream

  // The timeout covers fetch AND body read (CF-005) — headers arriving is not
  // the end of the attempt.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    // redirect: "manual" + 3xx check — Workers rejects "error" (SSRF guard).
    const resp = await fetch(upstreamUrl.toString(), {
      headers: { accept: DNS_JSON },
      signal: controller.signal,
      redirect: "manual",
    });
    if (resp.status >= 300 && resp.status < 400) {
      return jsonError(502, "upstream unavailable");
    }
    if (resp.status < 200 || resp.status >= 300) return jsonError(502, "upstream error");
    const body = new Uint8Array(await resp.arrayBuffer());
    if (body.byteLength > cfg.maxBody) return jsonError(502, "upstream response too large");

    // Upstream responses must parse as a valid dns-json schema; anything
    // else is treated as an upstream failure (502), never cached.
    const parsed = validateJsonResponse(body);
    if (!parsed) return jsonError(502, "upstream returned invalid dns-json");

    // TTL policy (mirrors vercel-doh's jsonCacheControl):
    //  - Status 0 with answers   → min Answer TTL
    //  - NXDOMAIN / NODATA       → RFC 2308 negative TTL: min(SOA TTL,
    //    SOA.MINIMUM) derived from the SOA record's data string; falling
    //    back to the min Authority TTL when the SOA cannot be parsed
    //  - anything else, or no usable TTL → do not cache (CF-012)
    // ECS-sensitive responses are never shared-cached.
    let ttl = 0;
    if (!ecsSensitive) {
      const status = typeof parsed.Status === "number" ? parsed.Status : -1;
      if (status === 0 || status === 3) {
        const answerTtl = minJsonTtl(parsed.Answer);
        const negativeTtl = soaJsonNegativeTtl(parsed.Authority) ?? minJsonTtl(parsed.Authority);
        if (status === 0 && answerTtl !== null) ttl = answerTtl;
        else if (negativeTtl !== null) ttl = negativeTtl;
      }
    }
    ttl = Math.min(cfg.ttlCeil, ttl);

    if (ttl > 0 && cacheKey !== null) {
      const entry = { body, status: 200, ttl };
      cache.putLocal(cacheKey, entry);
      ctx.waitUntil(cache.putRemote(cacheKey, entry));
    }
    // ECS-sensitive responses are never shared-cached: report ttl=0 → no-store.
    return jsonResponse(body, ecsSensitive ? 0 : ttl, debugHeaders(cfg, "miss", "none", -1, ttl));
  } catch {
    return jsonError(502, "upstream unavailable");
  } finally {
    clearTimeout(timer);
  }
}

function jsonResponse(
  body: Uint8Array,
  ttl: number,
  debugHeaders: Record<string, string> = {},
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      // application/json (dns.google/resolve parity): unregistered MIME types
      // like application/dns-json make browsers DOWNLOAD the response instead
      // of rendering it, so the "Get Json" button opened a file named after
      // the URL path instead of showing the JSON page.
      "content-type": "application/json; charset=utf-8",
      "cache-control": ttl > 0 ? `public, s-maxage=${ttl}` : "no-store",
      ...corsHeaders(),
      ...debugHeaders,
    },
  });
}

function debugHeaders(
  cfg: Config,
  cacheHit: "hit" | "miss",
  ecsBucket: string,
  provider: number,
  ttl: number,
): Record<string, string> {
  if (!cfg.debug) return {};
  return {
    "x-doh-cache": cacheHit,
    "x-doh-ecs": ecsBucket,
    "x-doh-upstream": String(provider),
    "x-doh-ttl": String(ttl),
  };
}

function handleHealth(request: Request, cfg: Config): Response {
  if (!checkAdmin(request, cfg)) return jsonError(401, "unauthorized");
  return new Response(JSON.stringify({ status: "ok", ts: Date.now() }), {
    headers: { "content-type": "application/json", ...corsHeaders(), ...securityHeaders() },
  });
}

function handleConfig(request: Request, cfg: Config): Response {
  if (!checkAdmin(request, cfg)) return jsonError(401, "unauthorized");
  const body = {
    upstreamUrls: cfg.upstreamUrls,
    ecsUpstreamUrls: cfg.ecsUpstreamUrls,
    dohPath: cfg.dohPath,
    jsonPath: cfg.jsonPath,
    mode: cfg.mode,
    upstreamFamily: cfg.upstreamFamily,
    ecs: cfg.ecs,
    ecsV4: cfg.ecsV4,
    ecsV6: cfg.ecsV6,
    raceUpstreams: cfg.raceUpstreams,
    forceResponsePadding: cfg.forceResponsePadding,
    cacheMaxAge: cfg.cacheMaxAge,
    ttlFloor: cfg.ttlFloor,
    ttlCeil: cfg.ttlCeil,
    ttlJitter: cfg.ttlJitter,
    rebindProtection: cfg.rebindProtection,
    maxRetries: cfg.maxRetries,
    timeoutMs: cfg.timeoutMs,
    totalTimeoutMs: cfg.totalTimeoutMs,
    aggregateAllowlist: cfg.aggregateAllowlist,
    maxBody: cfg.maxBody,
    cacheMemBytes: cfg.cacheMemBytes,
    debug: cfg.debug,
    appVersion: cfg.appVersion,
  };
  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/json", ...corsHeaders(), ...securityHeaders() },
  });
}



/**
 * Original CF-Workers-DoH aggregate resolver, ported 1:1: query the selected
 * DoH server with Google-style dns-json params (name/type), trying several
 * Accept header combinations; type=all fans out to A + AAAA + NS and merges
 * into { ipv4:{records}, ipv6:{records}, ns:{records} } for the frontend.
 * When the target is the current site, queries go through our own JSON
 * upstream instead. https-only target (SSRF guard) — otherwise behaviour
 * matches the original.
 */
async function queryDnsJson(
  dohServer: string,
  domain: string,
  type: string,
): Promise<Record<string, unknown>> {
  // Ported 1:1 from cmliu/CF-Workers-DoH `queryDns`: default fetch (follows
  // redirects, no artificial timeout — the original has neither), trying
  // several Accept header combinations.
  const dohUrl = new URL(dohServer);
  dohUrl.searchParams.set("name", domain);
  dohUrl.searchParams.set("type", type);
  const attempts: Array<Record<string, string>> = [
    { accept: "application/dns-json" },
    {},
    { accept: "application/json" },
    { accept: "application/dns-json", "user-agent": "Mozilla/5.0 DNS Client" },
  ];
  let lastError: Error | null = null;
  for (const headers of attempts) {
    try {
      const resp = await fetch(dohUrl.toString(), { headers });
      if (resp.ok) {
        const contentType = resp.headers.get("content-type") || "";
        if (contentType.includes("json") || contentType.includes("dns-json")) {
          return (await resp.json()) as Record<string, unknown>;
        }
        const text = await resp.text();
        try {
          return JSON.parse(text) as Record<string, unknown>;
        } catch {
          throw new Error("无法解析响应为JSON");
        }
      }
      const errorText = await resp.text();
      lastError = new Error(`DoH 服务器返回错误 (${resp.status}): ${errorText.substring(0, 200)}`);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }
  throw lastError ?? new Error("无法完成 DNS 查询");
}

/** Normalize dns-json Question/Answer fields: some providers (e.g. alidns)
 *  return a single object instead of an array — cmliu's original handles both
 *  (Array.isArray branch); spread-on-object would throw "is not iterable". */
function qList(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (v && typeof v === "object") return [v];
  return [];
}

/** Record types accepted by the aggregate endpoint (vercel-doh proxy parity). */
const AGGREGATE_TYPES = new Set([
  "ALL", "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV",
  "CAA", "HTTPS", "SVCB", "DS", "DNSKEY", "TLSA", "ANY",
]);

async function handleAggregateQuery(cfg: Config, url: URL): Promise<Response> {
  const domain = url.searchParams.get("domain") || url.searchParams.get("name") || "www.google.com";
  const dohParam = url.searchParams.get("doh") || "";
  const type = url.searchParams.get("type") || "all";

  // Input validation (vercel-doh /dns-query-proxy parity): bounded domain,
  // whitelisted type. The original cmliu defaults are kept for missing params.
  if (domain.length > MAX_DOMAIN_TEXT || !DOMAIN_CHARS.test(domain)) {
    return new Response(JSON.stringify({ error: "invalid domain" }, null, 2), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() },
    });
  }
  const qtype = type.toUpperCase();
  if (!AGGREGATE_TYPES.has(qtype)) {
    return new Response(JSON.stringify({ error: `unsupported type: ${type}` }, null, 2), {
      status: 400,
      headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() },
    });
  }

  const isLocal = dohParam.includes(url.host);
  // Local target → our own dns-json upstream; remote target must be https.
  let base: string;
  if (isLocal) {
    base = cfg.jsonUpstream ?? "https://dns.google/resolve";
  } else {
    try {
      const u = new URL(dohParam);
      if (u.protocol !== "https:") throw new Error("only https DoH targets are allowed");
      // Optional hostname allowlist (DOH_AGGREGATE_ALLOWLIST). When set, the
      // aggregate endpoint stops being an open HTTPS proxy: only listed hosts
      // may be queried. Empty (default) keeps the original open behaviour so
      // the frontend's custom DoH entry keeps working (CF-004).
      if (cfg.aggregateAllowlist.length > 0) {
        const host = u.hostname.toLowerCase();
        if (!cfg.aggregateAllowlist.includes(host)) {
          throw new Error(`DoH 地址不在白名单中: ${host}`);
        }
      }
      base = u.toString().replace(/\/$/, "");
    } catch (err) {
      return new Response(
        JSON.stringify({ error: `无效的 DoH 地址: ${err instanceof Error ? err.message : String(err)}` }, null, 2),
        { status: 400, headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() } },
      );
    }
  }
  try {
    if (qtype === "ALL") {
      const [a, aaaa, ns] = await Promise.all([
        queryDnsJson(base, domain, "A").catch(() => ({ Answer: [], Question: [] })),
        queryDnsJson(base, domain, "AAAA").catch(() => ({ Answer: [], Question: [] })),
        queryDnsJson(base, domain, "NS").catch(() => ({ Answer: [], Authority: [], Question: [] })),
      ]);
      const nsRecords: unknown[] = [];
      for (const r of qList(ns.Answer)) if ((r as { type?: number }).type === 2) nsRecords.push(r);
      for (const r of qList(ns.Authority)) {
        const t = (r as { type?: number }).type;
        if (t === 2 || t === 6) nsRecords.push(r);
      }
      const aRec = qList(a.Answer);
      const aaaaRec = qList(aaaa.Answer);
      const combined = {
        Status: (a as { Status?: number }).Status || (aaaa as { Status?: number }).Status || (ns as { Status?: number }).Status || 0,
        Question: [...qList(a.Question), ...qList(aaaa.Question), ...qList(ns.Question)],
        Answer: [...aRec, ...aaaaRec, ...qList(ns.Answer)],
        ipv4: { records: aRec },
        ipv6: { records: aaaaRec },
        ns: { records: nsRecords },
      };
      return new Response(JSON.stringify(combined, null, 2), {
        headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() },
      });
    }
    const result = await queryDnsJson(base, domain, qtype);
    return new Response(JSON.stringify(result, null, 2), {
      headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: `DNS 查询失败: ${err instanceof Error ? err.message : String(err)}`, doh: base, domain }, null, 2),
      { status: 500, headers: { "content-type": "application/json; charset=UTF-8", ...corsHeaders(), ...securityHeaders() } },
    );
  }
}

/** IP geolocation proxy (borrowed from CF-Workers-DoH /ip-info, adapted:
 *  CF Workers fetch cannot use http:// — ip-api free tier is http-only, so
 *  we proxy https://ipwho.is and normalize to the ip-api field shape the
 *  frontend expects: status/country/countryCode/region/city/lat/lon/isp/as). */
async function handleIpInfo(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const ip = url.searchParams.get("ip") ?? request.headers.get("cf-connecting-ip");
  if (!ip) {
    return new Response(JSON.stringify({ status: "fail", message: "IP参数未提供" }), {
      status: 400,
      headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
    });
  }
  try {
    const resp = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
      headers: { accept: "application/json" },
      redirect: "manual",
    });
    if (resp.status >= 300) throw new Error(`HTTP ${resp.status}`);
    const d = (await resp.json()) as {
      success?: boolean;
      country?: string;
      country_code?: string;
      region?: string;
      city?: string;
      latitude?: number;
      longitude?: number;
      connection?: { asn?: number; org?: string; isp?: string };
    };
    const out = {
      status: d.success ? "success" : "fail",
      country: d.country ?? "",
      countryCode: d.country_code ?? "",
      region: d.region ?? "",
      city: d.city ?? "",
      lat: d.latitude ?? 0,
      lon: d.longitude ?? 0,
      isp: d.connection?.isp ?? d.connection?.org ?? "",
      org: d.connection?.org ?? "",
      as: d.connection?.asn ? `AS${d.connection.asn} ${d.connection.org ?? ""}`.trim() : "",
      query: ip,
    };
    return new Response(JSON.stringify(out), {
      headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders(), ...securityHeaders() },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        status: "fail",
        message: `IP查询失败: ${err instanceof Error ? err.message : String(err)}`,
        query: ip,
      }),
      { status: 502, headers: { "content-type": "application/json", ...corsHeaders(), ...securityHeaders() } },
    );
  }
}

function handleRoot(cfg: Config): Response {
  if (cfg.url302 !== null) return Response.redirect(cfg.url302, 302);
  if (cfg.rootContent !== null) {
    return new Response(cfg.rootContent, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
  // Default: the resolver frontend (UI borrowed from CF-Workers-DoH).
  return renderHomepage(cfg);
}

/** Lightweight endpoint info page (path hidden unless SHOW_DOH_ENDPOINT=true). */
function infoText(cfg: Config): Response {
  const show = cfg.showDohEndpoint;
  const base = cfg.dohPath;
  const endpointLine = show
    ? `<pre>  GET  ${base}?dns=&lt;base64url&gt;        (Accept: application/dns-message)\n  POST ${base}                          (Content-Type: application/dns-message)</pre>`
    : `<p>DoH 端点路径已隐藏（部署时设置 <code>SHOW_DOH_ENDPOINT=true</code> 可在此展示）。</p>`;
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>cf-doh</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:52rem;margin:3rem auto;padding:0 1rem;line-height:1.6;background:#0f1115;color:#e6e8eb}h1{background:linear-gradient(to right,#f9ab4c,#fc673c);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}code,pre{background:#1a1e26;padding:.1rem .35rem;border-radius:6px;color:#f0a35e}pre{padding:.8rem 1rem;overflow:auto}li{margin:.3rem 0}a{color:#fc9d6b}</style>
</head>
<body>
<h1>cf-doh</h1>
<p>v${cfg.appVersion} — DNS over HTTPS 转发代理（部署于 Cloudflare Workers / Pages）。</p>
<p>这是一个 <b>DoH 端点</b>，请用支持 DoH 的客户端访问，而不是浏览器：</p>
${endpointLine}
<ul>
<li>URL flags（可与路径组合）：<code>/v4</code> 仅 A 记录 · <code>/v6</code> 仅 AAAA · <code>/ecs</code> 强制 ECS · <code>/no-ecs</code> 强制禁用（剥离已有 ECS）· <code>/ecs-&lt;ip&gt;</code> 指定 ECS 源 IP · <code>/{provider}</code> 按 <code>DOMAIN_MAPPINGS</code> 路由</li>
<li><code>${cfg.jsonPath ?? "/dns-query-json"}</code> — dns-json API（浏览器查询工具；同样支持 flag 后缀，如 <code>${cfg.jsonPath ?? "/dns-query-json"}/v4/ecs</code>；DoH 基路径也支持 <code>?name=…</code> JSON 查询，基路径 flag 同样生效）</li>
<li><code>/health</code> — 健康检查 · <code>/config</code> — 运行时配置（需 ADMIN_TOKEN）</li>
</ul>
<p>上游：已配置（隐私考虑，不在公开页面展示具体地址）</p>
</body>
</html>`;
  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, s-maxage=60",
      ...securityHeaders(),
    },
  });
}
