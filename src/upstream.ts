/**
 * Upstream DoH resolution — fuses cf-doh's failover/strict modes with
 * vercel-doh's upstream hygiene:
 *
 *  - every upstream HTTP exchange is validated INSIDE this layer: redirects
 *    are never followed (`redirect: "error"`, SSRF guard), only 2xx with the
 *    exact `application/dns-message` content type are accepted, the body is
 *    capped at MAX_BODY, and the DNS payload must pass `validateResponse`
 *    (structure + ID/question echo of the exact message sent upstream);
 *  - outbound headers are an ALLOWLIST (client Authorization/Cookie/XFF
 *    never leak to the resolver); logs redact query strings;
 *  - failover mode: round-robin start point, sequential failover;
 *    `raceUpstreams`: concurrent race, fastest validated wins;
 *    strict mode: parallel fan-out (≤6), caller picks most-restrictive.
 */

import { HEADER_LEN } from "./dns/parse";
import { rcode } from "./dns/classify";
import { parseMediaType } from "./media";
import { validateResponse } from "./dns/validate";
import type { Config } from "./config";

export interface ResolveResult {
  body: Uint8Array;
  status: number;
  provider: number;
}

const FAILOVER_RCODES = new Set([2, 5]); // SERVFAIL, REFUSED (low 4 bits)

export interface ResolveContext {
  providers: string[];
  timeoutMs: number;
  maxBody: number;
  maxRetries: number;
}

/** Error-safe URL for logs: strips query string and userinfo. */
export function redactUrl(url: string): string {
  try {
    const u = new URL(url);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.href.replace(/\/$/, "");
  } catch {
    return "(invalid url)";
  }
}

/** Resolves a path-mapped provider to an upstream URL, or null. */
export function resolveProvider(cfg: Config, provider: string): string | null {
  const mapping = cfg.domainMappings[provider];
  if (!mapping) return null;
  const target = mapping.targetDomain;
  const withScheme = target.includes("://") ? target : `https://${target}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.pathname === "" || url.pathname === "/") url.pathname = "/dns-query";
  return url.href.replace(/\/$/, "");
}

/** Outbound header ALLOWLIST — never forward client headers upstream. */
export function buildUpstreamHeaders(
  accept: string,
  userAgent: string,
  contentType?: string,
): Headers {
  const out = new Headers();
  out.set("Accept", accept);
  out.set("User-Agent", userAgent);
  if (contentType) out.set("Content-Type", contentType);
  return out;
}

/** One upstream attempt; resolves with a validated, fully-read response. */
async function tryProvider(
  providerUrl: string,
  requestMessage: Uint8Array,
  ctx: ResolveContext,
  method: "GET" | "POST",
  accept: string,
  userAgent: string,
): Promise<ResolveResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
  const headers = buildUpstreamHeaders(accept, userAgent, method === "POST" ? accept : undefined);

  let url = providerUrl;
  let init: RequestInit;
  if (method === "GET") {
    const target = new URL(providerUrl);
    target.searchParams.set("dns", encodeBase64Url(requestMessage));
    url = target.href;
    init = { method: "GET", headers, signal: controller.signal };
  } else {
    init = { method: "POST", headers, body: requestMessage, signal: controller.signal };
  }

  let resp: Response;
  try {
    // redirect: "manual" + explicit 3xx check — Workers rejects "error";
    // never follow upstream redirects (SSRF guard).
    resp = await fetch(url, { ...init, redirect: "manual" });
  } catch {
    return null; // network error / timeout
  } finally {
    clearTimeout(timer);
  }

  if (resp.status >= 300 && resp.status < 400) {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  if (resp.status < 200 || resp.status >= 300) {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  const contentType = resp.headers.get("content-type") ?? "";
  if (parseMediaType(contentType) !== "application/dns-message") {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  const declared = resp.headers.get("content-length");
  if (declared && Number.parseInt(declared, 10) > ctx.maxBody) {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  const buf = new Uint8Array(await resp.arrayBuffer());
  if (buf.byteLength < HEADER_LEN || buf.byteLength > ctx.maxBody) return null;
  // Trust boundary: the response must validate AND echo the request sent.
  const validated = validateResponse(buf, requestMessage);
  if (!validated) return null;
  if (FAILOVER_RCODES.has(rcode(buf))) return null; // SERVFAIL/REFUSED → try next
  return { body: buf, status: resp.status, provider: -1 };
}

/** Round-robin cursor (per isolate; serverless instances share nothing). */
let cursor = 0;

/**
 * Default (failover) resolution: round-robin start point, sequential
 * failover; each provider gets up to `maxRetries + 1` attempts.
 */
export async function fetchCandidates(
  requestMessage: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  if (ctx.providers.length === 0) return [];
  const attempts = Math.max(1, ctx.maxRetries + 1);
  const start = cursor % ctx.providers.length;
  cursor = (start + 1) % ctx.providers.length;
  for (let i = 0; i < ctx.providers.length; i++) {
    const pi = (start + i) % ctx.providers.length;
    for (let attempt = 0; attempt < attempts; attempt++) {
      const r = await tryProvider(
        ctx.providers[pi]!,
        requestMessage,
        ctx,
        "POST",
        "application/dns-message",
        `cf-doh/${"1.0.0"}`,
      );
      if (r) return [{ ...r, provider: pi }];
    }
  }
  return [];
}

/** Race mode: query all upstreams concurrently, take the fastest validated. */
export async function fetchCandidatesRace(
  requestMessage: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  const urls = ctx.providers.slice(0, 6);
  const attempts = urls.map(async (url, i) => {
    const r = await tryProvider(
      url,
      requestMessage,
      ctx,
      "POST",
      "application/dns-message",
      `cf-doh/${"1.0.0"}`,
    );
    if (r) return [{ ...r, provider: i }];
    return [] as ResolveResult[];
  });
  const settled = await Promise.allSettled(attempts);
  const out: ResolveResult[] = [];
  for (const s of settled) {
    if (s.status === "fulfilled" && s.value.length > 0) out.push(...s.value);
  }
  return out;
}

/**
 * Strict (fan-out) mode: query every provider concurrently (capped at 6 to
 * respect the simultaneous-connections limit) and return all validated
 * responses so the caller can apply most-restrictive-wins.
 */
export async function fetchCandidatesStrict(
  requestMessage: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  const providers = ctx.providers.slice(0, 6);
  const settled = await Promise.allSettled(
    providers.map((url, i) =>
      tryProvider(
        url,
        requestMessage,
        ctx,
        "POST",
        "application/dns-message",
        `cf-doh/${"1.0.0"}`,
      ).then((r) => (r ? [{ ...r, provider: i }] : [])),
    ),
  );
  const out: ResolveResult[] = [];
  for (const s of settled) {
    if (s.status === "fulfilled") out.push(...s.value);
  }
  return out;
}

/** Entry point chosen by index.ts based on cfg.mode / raceUpstreams. */
export async function resolveCandidates(
  requestMessage: Uint8Array,
  cfg: Config,
  upstreamPool: string[],
): Promise<ResolveResult[]> {
  const ctx: ResolveContext = {
    providers: upstreamPool,
    timeoutMs: cfg.timeoutMs,
    maxBody: cfg.maxBody,
    maxRetries: cfg.maxRetries,
  };
  if (cfg.mode === "strict") return fetchCandidatesStrict(requestMessage, ctx);
  if (cfg.raceUpstreams && ctx.providers.length > 1) {
    return fetchCandidatesRace(requestMessage, ctx);
  }
  return fetchCandidates(requestMessage, ctx);
}

function encodeBase64Url(buf: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
