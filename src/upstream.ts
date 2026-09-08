/**
 * Upstream DoH resolution.
 *
 * failover mode: try providers in order, return the first usable response.
 * strict mode:   fan out to all providers in parallel (≤ 6, matching the
 *                simultaneous-connections limit) and return every usable
 *                response so the caller can pick the most restrictive one.
 *
 * "Usable" means: fetch did not throw or time out, HTTP status < 500, body
 * within MAX_BODY, and a DNS rcode that is a real answer (not SERVFAIL /
 * REFUSED, which trigger failover).
 */

import { HEADER_LEN } from "./dns/parse";
import { rcode } from "./dns/classify";
import type { Config } from "./config";

export interface ResolveResult {
  body: Uint8Array;
  status: number;
  provider: number;
}

const FAILOVER_RCODES = new Set([2, 5]); // SERVFAIL, REFUSED

export interface ResolveContext {
  providers: string[];
  timeoutMs: number;
  maxBody: number;
  /** Extra attempts per provider on 5xx/network/timeout (failover mode). */
  maxRetries: number;
}

async function tryProvider(
  providerUrl: string,
  body: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ctx.timeoutMs);
  let resp: Response;
  try {
    resp = await fetch(providerUrl, {
      method: "POST",
      headers: {
        accept: "application/dns-message",
        "content-type": "application/dns-message",
      },
      body,
      signal: controller.signal,
    });
  } catch {
    return null; // network error / timeout
  } finally {
    clearTimeout(timer);
  }

  if (resp.status >= 500) {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  const declared = resp.headers.get("content-length");
  if (declared && Number(declared) > ctx.maxBody) {
    await resp.body?.cancel().catch(() => undefined);
    return null;
  }
  const buf = new Uint8Array(await resp.arrayBuffer());
  if (buf.byteLength > ctx.maxBody) return null;
  if (buf.byteLength < HEADER_LEN || FAILOVER_RCODES.has(rcode(buf))) return null;
  return { body: buf, status: resp.status, provider: -1 };
}

/**
 * Default (failover) resolution: try providers in order; each provider gets
 * up to `maxRetries + 1` attempts before the next one is tried.
 */
export async function fetchCandidates(
  body: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  const attempts = Math.max(1, ctx.maxRetries + 1);
  for (let pi = 0; pi < ctx.providers.length; pi++) {
    for (let attempt = 0; attempt < attempts; attempt++) {
      const r = await tryProvider(ctx.providers[pi]!, body, ctx);
      if (r) return [{ ...r, provider: pi }];
    }
  }
  return [];
}

/**
 * Strict (fan-out) mode: query every provider concurrently (capped at 6 to
 * respect the simultaneous-connections limit) and return all usable responses
 * so the caller can apply most-restrictive-wins.
 */
export async function fetchCandidatesStrict(
  body: Uint8Array,
  ctx: ResolveContext,
): Promise<ResolveResult[]> {
  const providers = ctx.providers.slice(0, 6);
  const settled = await Promise.allSettled(
    providers.map((url, i) =>
      tryProvider(url, body, ctx).then((r) => (r ? [{ ...r, provider: i }] : [])),
    ),
  );
  const out: ResolveResult[] = [];
  for (const s of settled) {
    if (s.status === "fulfilled") out.push(...s.value);
  }
  return out;
}

/** Entry point chosen by index.ts based on cfg.mode. */
export async function resolveCandidates(
  body: Uint8Array,
  cfg: Config,
): Promise<ResolveResult[]> {
  const ctx: ResolveContext = {
    providers: cfg.upstreamUrls,
    timeoutMs: cfg.timeoutMs,
    maxBody: cfg.maxBody,
    maxRetries: cfg.maxRetries,
  };
  if (cfg.mode === "strict") return fetchCandidatesStrict(body, ctx);
  return fetchCandidates(body, ctx);
}
