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
import { parseMediaType } from "./media";
import { validateResponse } from "./dns/validate";
import type { Config } from "./config";

export interface ResolveResult {
  body: Uint8Array;
  status: number;
  provider: number;
}

/** Platform subrequest budget headroom: 50/request cap, minus cache ops. */
export const SUBREQUEST_BUDGET = 40;

/**
 * True when an upstream response should fail over to the next provider:
 * SERVFAIL (2), REFUSED (5), or any EDNS(0) extended RCODE (≥16, e.g.
 * BADVERS). Uses the FULL rcode — the low 4 bits alone would treat BADVERS
 * as NOERROR (CF-014). NXDOMAIN (3) is a valid answer, never a failure.
 */
export function isFailoverRcode(rcode: number): boolean {
  return rcode === 2 || rcode === 5 || rcode >= 16;
}

/**
 * Total attempt budget for failover resolution: `providers × (maxRetries+1)`
 * clamped to stay under the platform subrequest limit (CF-006). At least 1.
 */
export function computeAttemptBudget(providers: number, maxRetries: number): number {
  const configured = Math.max(1, providers) * (Math.max(0, maxRetries) + 1);
  return Math.max(1, Math.min(configured, SUBREQUEST_BUDGET));
}

export interface ResolveContext {
  providers: string[];
  timeoutMs: number;
  maxBody: number;
  /** Total attempts allowed across all providers (failover mode). */
  attemptBudget: number;
  /** Absolute wall-clock deadline (epoch ms) for the whole resolution. */
  deadlineMs: number;
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

/**
 * One upstream attempt; resolves with a validated, fully-read response.
 *
 * The timeout signal covers the ENTIRE attempt — fetch AND body read AND
 * DNS validation — not just the header round-trip. `fetch()` resolving only
 * means headers arrived; a slow-dripping body must not outlive the deadline
 * (CF-005). Each attempt is also bounded by the resolution's total deadline:
 * `attemptTimeout = min(timeoutMs, remaining)` (CF-007).
 */
async function tryProvider(
  providerUrl: string,
  requestMessage: Uint8Array,
  ctx: ResolveContext,
  method: "GET" | "POST",
  accept: string,
  userAgent: string,
): Promise<ResolveResult | null> {
  const remaining = ctx.deadlineMs - Date.now();
  if (remaining <= 0) return null;
  const attemptTimeout = Math.max(50, Math.min(ctx.timeoutMs, remaining));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), attemptTimeout);
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

  try {
    // redirect: "manual" + explicit 3xx check — Workers rejects "error";
    // never follow upstream redirects (SSRF guard).
    const resp = await fetch(url, { ...init, redirect: "manual" });

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
    // Body read + validation happen INSIDE the timed region.
    const buf = new Uint8Array(await resp.arrayBuffer());
    if (buf.byteLength < HEADER_LEN || buf.byteLength > ctx.maxBody) return null;
    // Trust boundary: the response must validate AND echo the request sent.
    const validated = validateResponse(buf, requestMessage);
    if (!validated) return null;
    if (isFailoverRcode(validated.rcode)) return null; // SERVFAIL/REFUSED/extended → next
    return { body: buf, status: resp.status, provider: -1 };
  } catch {
    return null; // network error / timeout (fetch or body read)
  } finally {
    clearTimeout(timer);
  }
}

/** Round-robin cursor (per isolate; serverless instances share nothing). */
let cursor = 0;

/**
 * Default (failover) resolution: round-robin start point, sequential
 * failover; the total number of attempts is capped by `ctx.attemptBudget`
 * (CF-006) and every attempt is bounded by the resolution deadline (CF-007).
 */
export async function fetchCandidates(
  requestMessage: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  if (ctx.providers.length === 0) return [];
  const start = cursor % ctx.providers.length;
  cursor = (start + 1) % ctx.providers.length;
  // Spread the attempt budget evenly across the providers actually tried so a
  // failing first provider cannot exhaust the whole budget (CF-006).
  const tryCount = Math.min(ctx.providers.length, ctx.attemptBudget);
  const perProvider = Math.max(1, Math.floor(ctx.attemptBudget / tryCount));
  let used = 0;
  for (let i = 0; i < tryCount; i++) {
    const pi = (start + i) % ctx.providers.length;
    for (let attempt = 0; attempt < perProvider && used < ctx.attemptBudget; attempt++) {
      used += 1;
      const r = await tryProvider(
        ctx.providers[pi]!,
        requestMessage,
        ctx,
        "POST",
        "application/dns-message",
        `cf-doh/${"1.0.0"}`,
      );
      if (r) return [{ ...r, provider: pi }];
      if (ctx.deadlineMs - Date.now() <= 0) return [];
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
    attemptBudget: computeAttemptBudget(upstreamPool.length, cfg.maxRetries),
    deadlineMs: Date.now() + cfg.totalTimeoutMs,
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
