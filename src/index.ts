/**
 * Fused DNS-over-HTTPS proxy for Cloudflare Workers / Pages.
 *
 * Combines, from the reference projects surveyed:
 *  - streaming-friendly buffered forwarding with strict size caps
 *    (doh-cf-workers, NextDNS-DOH)
 *  - dual-layer TTL-aware caching + ECS handling (DoHflare)
 *  - ECS truncation, rebind protection, health/config endpoints,
 *    strict fan-out with most-restrictive-wins (cloudflare-doh-worker)
 *  - path-as-secret + optional token auth (cfdohpw, CF-Workers-DoH)
 *
 * Design constraints from Cloudflare docs (free plan): 10 ms CPU/invocation,
 * 50 subrequests/request, 6 concurrent connections/request, 128 MB isolate.
 * Cache hits still bill a request but save the upstream subrequest + CPU.
 */

import { parseConfig, DEFAULT_POSITIVE_TTL, type Config } from "./config";
import { DohCache, makeCacheKeyStr } from "./cache";
import { resolveCandidates, type ResolveResult } from "./upstream";
import { parseQuestion } from "./dns/parse";
import {
  base64urlToBytes,
  getEcs,
  setEcsInMessage,
  stripEcsFromMessage,
  toHex,
  truncateBytes,
  truncateIp,
} from "./dns/encode";
import { buildSyntheticNxdomain, classifyResponse, scanAnswers } from "./dns/classify";
import { checkAdmin, checkAuth } from "./auth";
import { corsHeaders, dnsResponse, jsonError, jsonResponse, ok204 } from "./response";

export interface Env {
  [key: string]: string | undefined;
}

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
    if (path === cfg.dohPath) return await handleDoh(request, cfg, cache, ctx, url);
    if (cfg.jsonPath !== null && path === cfg.jsonPath) {
      return await handleJson(request, cfg, cache, ctx, url);
    }
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

/** Apply ECS policy: strip when disabled, inject/truncate when enabled. */
function applyEcs(
  cfg: Config,
  request: Request,
  msg: Uint8Array,
): { bucket: string; out: Uint8Array } {
  if (!cfg.ecs) {
    return { bucket: "none", out: stripEcsFromMessage(msg) };
  }
  const existing = getEcs(msg);
  if (existing) {
    const maxBits = existing.family === 1 ? 32 : 128;
    const bits = existing.family === 1 ? cfg.ecsV4 : cfg.ecsV6;
    const addr = truncateBytes(existing.address, bits, maxBits);
    return {
      bucket: `${existing.family}:${toHex(addr)}`,
      out: setEcsInMessage(msg, existing.family, Math.min(bits, maxBits), addr),
    };
  }
  const ip =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (!ip) return { bucket: "none", out: msg };
  const family = ip.includes(":") ? 2 : 1;
  const bits = family === 1 ? cfg.ecsV4 : cfg.ecsV6;
  const t = truncateIp(ip, bits);
  if (!t) return { bucket: "none", out: msg };
  return {
    bucket: `${t.family}:${toHex(t.bytes)}`,
    out: setEcsInMessage(msg, t.family, bits, t.bytes),
  };
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
): Promise<Response> {
  if (request.method === "OPTIONS") return ok204();
  if (!checkAuth(request, cfg)) return jsonError(401, "unauthorized");

  let msg: Uint8Array;
  if (request.method === "GET") {
    const dnsParam = url.searchParams.get("dns");
    if (!dnsParam) return jsonError(400, "missing dns parameter");
    const decoded = base64urlToBytes(dnsParam);
    if (!decoded) return jsonError(400, "invalid dns parameter");
    if (decoded.length > cfg.maxBody) return jsonError(413, "query too large");
    msg = decoded;
  } else if (request.method === "POST") {
    const ct = (request.headers.get("content-type") ?? "").toLowerCase();
    if (!ct.includes("application/dns-message")) {
      return jsonError(415, "unsupported content type");
    }
    const raw = await request.arrayBuffer();
    if (raw.byteLength > cfg.maxBody) return jsonError(413, "query too large");
    msg = new Uint8Array(raw);
  } else {
    return jsonError(405, "method not allowed");
  }

  const q = parseQuestion(msg);
  if (!q) return jsonError(400, "malformed dns message");
  if (q.qtype === 41) return jsonError(400, "OPT in question not allowed");

  const { bucket, out } = applyEcs(cfg, request, msg);

  const modeKey = cfg.mode === "strict" ? "s" : "f";
  const cacheKey = await makeCacheKeyStr({
    name: q.name,
    qtype: q.qtype,
    qclass: q.qclass,
    modeKey,
    ecsBucket: bucket,
  });

  // Layer 1: in-memory
  const local = cache.getLocal(cacheKey);
  if (local) {
    return dnsResponse(local.body, local.ttl, debugHeaders(cfg, "hit", bucket, -1, local.ttl));
  }
  // Layer 2: Cache API
  const remote = await cache.getRemote(cacheKey);
  if (remote) {
    cache.putLocal(cacheKey, remote);
    return dnsResponse(remote.body, remote.ttl, debugHeaders(cfg, "hit", bucket, -1, remote.ttl));
  }

  const candidates = await resolveCandidates(out, cfg);
  if (candidates.length === 0) {
    return jsonError(503, "all upstreams unavailable");
  }

  const winner = cfg.mode === "strict" ? pickMostRestrictive(candidates) : candidates[0]!;
  const kind = classifyResponse(winner.body, cfg.rebindProtection);

  let outBody = winner.body;
  let ttl: number;
  if (kind === "rebind") {
    outBody = buildSyntheticNxdomain(out, q.questionEnd);
    ttl = cfg.negTtl;
  } else if (kind === "error") {
    ttl = 0; // do not cache errors
  } else if (kind === "nxdomain") {
    ttl = cfg.negTtl;
  } else {
    const s = scanAnswers(winner.body);
    ttl = s.minTtl === Infinity ? DEFAULT_POSITIVE_TTL : s.minTtl;
  }
  ttl = Math.min(cfg.ttlCeil, Math.max(cfg.ttlFloor, ttl));
  if (ttl > 0 && cfg.ttlJitter > 0) {
    ttl = Math.max(1, Math.round(ttl * (1 - Math.random() * cfg.ttlJitter)));
  }

  if (ttl > 0) {
    const entry = { body: outBody, status: 200, ttl };
    cache.putLocal(cacheKey, entry);
    ctx.waitUntil(cache.putRemote(cacheKey, entry));
  }

  return dnsResponse(outBody, ttl, debugHeaders(cfg, "miss", bucket, winner.provider, ttl));
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
    qtype: 0,
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
    resp = await fetch(upstreamUrl.toString(), {
      headers: { accept: "application/dns-json" },
      signal: controller.signal,
    });
  } catch {
    return jsonError(502, "upstream unavailable");
  } finally {
    clearTimeout(timer);
  }
  if (resp.status >= 500) return jsonError(502, "upstream error");
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
    }
  } catch {
    // non-JSON upstream response: keep default TTL
  }
  ttl = Math.min(cfg.ttlCeil, Math.max(cfg.ttlFloor, ttl));

  if (ttl > 0) {
    const entry = { body, status: 200, ttl };
    cache.putLocal(cacheKey, entry);
    ctx.waitUntil(cache.putRemote(cacheKey, entry));
  }
  return jsonResponse(body, ttl, debugHeaders(cfg, "miss", "none", -1, ttl));
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
    dohPath: cfg.dohPath,
    jsonPath: cfg.jsonPath,
    mode: cfg.mode,
    ecs: cfg.ecs,
    ecsV4: cfg.ecsV4,
    ecsV6: cfg.ecsV6,
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
  };
  return new Response(JSON.stringify(body, null, 2), {
    headers: { "content-type": "application/json", ...corsHeaders() },
  });
}

function handleRoot(cfg: Config): Response {
  if (cfg.url302 !== null) return Response.redirect(cfg.url302, 302);
  if (cfg.rootContent !== null) {
    return new Response(cfg.rootContent, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
  return jsonError(404, "not found");
}
