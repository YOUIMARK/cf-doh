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
  DEFAULT_POSITIVE_TTL,
  type Config,
  type Family,
} from "./config";
import { DohCache, makeCacheKeyStr } from "./cache";
import { resolveCandidates, resolveProvider, type ResolveResult } from "./upstream";
import { parseQuestion } from "./dns/parse";
import { base64urlToBytes, getEcs, toHex, truncateIp } from "./dns/encode";
import { buildSyntheticNxdomain, classifyResponse, scanAnswers, soaNegativeTtl } from "./dns/classify";
import { buildErrorResponse, questionType, setQuestionType } from "./dns/wire";
import {
  addOrMergeEcs,
  buildEcsOption,
  ecsStatus,
  parseClientIp,
  removeEcsOption,
} from "./dns/ecs";
import { validateQuery } from "./dns/validate";
import { padResponse } from "./dns/padding";
import { buildCacheControl } from "./cache-control";
import { acceptsMediaType, parseMediaType } from "./media";
import { checkAdmin, checkAuth } from "./auth";
import { corsHeaders, dnsResponse, jsonError, ok204 } from "./response";
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
      flags.ecsOverrideIp = segment.slice(4);
      flags.behavior = "force_enable";
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
      return handleJson(request, cfg, cache, ctx, url);
    }
    if (acceptsMessage) return jsonError(400, "missing dns parameter");
    return infoText(cfg);
  }
  if (method === "GET" && !acceptsMessage) {
    return jsonError(406, "Not Acceptable: application/dns-message required");
  }
  if (method !== "GET" && method !== "POST") {
    return jsonError(405, "method not allowed");
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
  const effectiveBehavior: EcsBehavior =
    flags.behavior ?? (cfg.ecs ? "force_enable" : "default");

  if (effectiveBehavior === "force_disable" && ecsStatus(message) !== "absent") {
    message = removeEcsOption(message); // STRIP, not merely skip injection
  }

  const shouldAddEcs =
    effectiveBehavior === "force_enable" ||
    (effectiveBehavior === "default" && cfg.ecs);
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
  const ecs = getEcs(message);
  const bucket = ecsSensitive ? `${ecs?.family ?? 0}:${toHex(ecs?.address ?? new Uint8Array(0))}` : "none";
  const cacheKey = await makeCacheKeyStr({
    name: q.name,
    qtype: q.qtype,
    qclass: q.qclass,
    modeKey: cfg.mode === "strict" ? "s" : "f",
    ecsBucket: bucket,
  });

  if (method === "GET" && !ecsSensitive) {
    const local = cache.getLocal(cacheKey);
    if (local) {
      return dnsResponse(local.body, local.ttl, debugHeaders(cfg, "hit", bucket, -1, local.ttl));
    }
    const remote = await cache.getRemote(cacheKey);
    if (remote) {
      cache.putLocal(cacheKey, remote);
      return dnsResponse(remote.body, remote.ttl, debugHeaders(cfg, "hit", bucket, -1, remote.ttl));
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

  const rcode = (outBody[3] ?? 0) & 0x0f;
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
    internalTtl = m ? Number(m[1]) : 0;
    internalTtl = Math.min(cfg.ttlCeil, Math.max(cfg.ttlFloor, internalTtl));
    if (internalTtl > 0 && cfg.ttlJitter > 0) {
      internalTtl = Math.max(1, Math.round(internalTtl * (1 - Math.random() * cfg.ttlJitter)));
    }
  }

  if (cfg.forceResponsePadding) outBody = padResponse(outBody);

  if (internalTtl > 0) {
    const entry = { body: outBody, status: 200, ttl: internalTtl };
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

/** Google dns-json type names → wire type codes (JSON cache key dimension). */
const JSON_TYPE_CODES: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, CAA: 257, ANY: 255,
};

function jsonTypeCode(type: string): number {
  const t = type.trim().toUpperCase();
  if (/^\d+$/.test(t)) return Math.min(65535, Number(t));
  return JSON_TYPE_CODES[t] ?? 0;
}

async function handleJson(
  request: Request,
  cfg: Config,
  cache: DohCache,
  ctx: ExecutionContext,
  url: URL,
): Promise<Response> {
  if (request.method === "OPTIONS") return ok204();
  if (!checkAuth(request, cfg)) return jsonError(401, "unauthorized");
  if (request.method !== "GET") return jsonError(405, "method not allowed");

  const name = url.searchParams.get("name");
  if (!name) return jsonError(400, "missing name parameter");
  const qtype = url.searchParams.get("type") ?? "A";

  const cacheKey = await makeCacheKeyStr({
    name: name.toLowerCase(),
    qtype: jsonTypeCode(qtype),
    qclass: 0,
    modeKey: "j",
    ecsBucket: "none",
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

  const upstream = cfg.jsonUpstream ?? "https://dns.google/resolve";
  const upstreamUrl = new URL(upstream);
  upstreamUrl.search = url.search;
  upstreamUrl.searchParams.delete("token"); // never leak our auth token upstream

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  let resp: Response;
  try {
    // redirect: "manual" + 3xx check — Workers rejects "error" (SSRF guard).
    resp = await fetch(upstreamUrl.toString(), {
      headers: { accept: DNS_JSON },
      signal: controller.signal,
      redirect: "manual",
    });
  } catch {
    return jsonError(502, "upstream unavailable");
  } finally {
    clearTimeout(timer);
  }
  if (resp.status >= 300 && resp.status < 400) {
    return jsonError(502, "upstream unavailable");
  }
  if (resp.status < 200 || resp.status >= 300) return jsonError(502, "upstream error");
  const body = new Uint8Array(await resp.arrayBuffer());
  if (body.byteLength > cfg.maxBody) return jsonError(502, "upstream response too large");

  let ttl = DEFAULT_POSITIVE_TTL;
  try {
    const j = JSON.parse(new TextDecoder().decode(body)) as {
      Answer?: Array<{ TTL?: number }>;
    };
    if (Array.isArray(j.Answer) && j.Answer.length > 0) {
      const ttls = j.Answer.map((a) => Number(a.TTL)).filter((n) => Number.isFinite(n) && n > 0);
      if (ttls.length > 0) ttl = Math.min(...ttls);
    } else {
      ttl = 0; // no TTL info → do not cache
    }
  } catch {
    ttl = 0; // non-JSON upstream response → do not cache
  }
  ttl = Math.min(cfg.ttlCeil, Math.max(cfg.ttlFloor, ttl));

  if (ttl > 0) {
    const entry = { body, status: 200, ttl };
    cache.putLocal(cacheKey, entry);
    ctx.waitUntil(cache.putRemote(cacheKey, entry));
  }
  return jsonResponse(body, ttl, debugHeaders(cfg, "miss", "none", -1, ttl));
}

function jsonResponse(
  body: Uint8Array,
  ttl: number,
  debugHeaders: Record<string, string> = {},
): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": DNS_JSON,
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
    headers: { "content-type": "application/json", ...corsHeaders() },
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
    negTtl: cfg.negTtl,
    rebindProtection: cfg.rebindProtection,
    maxRetries: cfg.maxRetries,
    timeoutMs: cfg.timeoutMs,
    maxBody: cfg.maxBody,
    cacheMemBytes: cfg.cacheMemBytes,
    debug: cfg.debug,
    appVersion: cfg.appVersion,
  };
  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/json", ...corsHeaders() },
  });
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
      headers: { "content-type": "application/json; charset=utf-8", ...corsHeaders() },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({
        status: "fail",
        message: `IP查询失败: ${err instanceof Error ? err.message : String(err)}`,
        query: ip,
      }),
      { status: 502, headers: { "content-type": "application/json", ...corsHeaders() } },
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
<li><code>${cfg.jsonPath ?? "/dns-query-json"}</code> — dns-json API（浏览器查询工具）</li>
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
    },
  });
}
