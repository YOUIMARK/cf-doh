/**
 * Dual-layer DNS response cache.
 *
 * Layer 1: byte-bounded in-memory LRU (per-isolate, zero subrequest cost).
 * Layer 2: Cloudflare Cache API (shared per data centre, TTL via
 * `Cache-Control: max-age`). The Cache API only accepts GET keys, so entries
 * are stored under a synthetic GET request whose URL encodes the canonical
 * cache key (official Cloudflare pattern for caching non-GET workloads).
 *
 * A cache hit still bills one request on the free plan, but avoids the
 * upstream subrequest (50/request budget) and the CPU spent re-fetching and
 * re-parsing (10 ms/invocation budget).
 */

import { toHex } from "./dns/encode";

export interface CacheEntry {
  body: Uint8Array;
  status: number;
  ttl: number; // seconds remaining; 0 = do not store
}

export interface CacheKeyInfo {
  name: string;
  qtype: number;
  qclass: number;
  /** "f" for failover mode, "s" for strict fan-out, "j" for JSON API. */
  modeKey: string;
  /** "none" when ECS is off, else the truncated subnet bucket (hex). */
  ecsBucket: string;
}

/** Canonical, deterministic cache key derived from the DNS query. */
export async function makeCacheKeyStr(info: CacheKeyInfo): Promise<string> {
  const raw = `${info.name}|${info.qtype}|${info.qclass}|${info.modeKey}|${info.ecsBucket}`;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(raw),
  );
  return toHex(new Uint8Array(digest)).slice(0, 40);
}

interface LruEntry extends CacheEntry {
  /** Absolute expiry in epoch ms. */
  expiresAt: number;
}

class ByteLru {
  private map = new Map<string, LruEntry>();
  private bytes = 0;

  constructor(private readonly maxBytes: number) {}

  get(key: string): CacheEntry | undefined {
    const e = this.map.get(key);
    if (!e) return undefined;
    if (Date.now() >= e.expiresAt) {
      this.bytes -= e.body.byteLength;
      this.map.delete(key);
      return undefined;
    }
    this.map.delete(key);
    this.map.set(key, e); // refresh recency
    return {
      body: e.body,
      status: e.status,
      ttl: Math.max(0, Math.ceil((e.expiresAt - Date.now()) / 1000)),
    };
  }

  set(key: string, entry: CacheEntry): void {
    const old = this.map.get(key);
    if (old) this.bytes -= old.body.byteLength;
    this.map.delete(key);
    const lruEntry: LruEntry = {
      body: entry.body,
      status: entry.status,
      ttl: entry.ttl,
      expiresAt: Date.now() + Math.max(0, Math.floor(entry.ttl)) * 1000,
    };
    this.map.set(key, lruEntry);
    this.bytes += lruEntry.body.byteLength;
    while (this.bytes > this.maxBytes && this.map.size > 1) {
      const oldestKey = this.map.keys().next().value;
      if (oldestKey === undefined) break;
      const oldest = this.map.get(oldestKey)!;
      this.bytes -= oldest.body.byteLength;
      this.map.delete(oldestKey);
    }
  }
}

export class DohCache {
  private lru: ByteLru;
  private readonly cacheHost: string;

  constructor(maxBytes: number, host = "doh-cache.invalid") {
    this.lru = new ByteLru(maxBytes);
    this.cacheHost = host;
  }

  /** Cache API key as a synthetic GET request (host is arbitrary to the API). */
  private cacheUrl(key: string): string {
    return `https://${this.cacheHost}/_doh/${key}`;
  }

  /** Layer 1: synchronous in-memory lookup. */
  getLocal(key: string): CacheEntry | undefined {
    const e = this.lru.get(key);
    if (!e) return undefined;
    return { body: e.body, status: e.status, ttl: e.ttl };
  }

  /** Layer 2: Cache API lookup. Returns entry or null. */
  async getRemote(key: string): Promise<CacheEntry | null> {
    try {
      const resp = await caches.default.match(this.cacheUrl(key));
      if (!resp) return null;
      const cc = resp.headers.get("cache-control") ?? "";
      const m = /max-age=(\d+)/.exec(cc);
      const ttl = m ? Math.max(0, Number(m[1])) : 0;
      const body = new Uint8Array(await resp.arrayBuffer());
      return { body, status: resp.status, ttl };
    } catch {
      // Cache API unavailable (dashboard editor / playground) → LRU only.
      return null;
    }
  }

  /** Layer 1 write (synchronous, always). */
  putLocal(key: string, entry: CacheEntry): void {
    if (entry.ttl <= 0) return;
    this.lru.set(key, { body: entry.body, status: entry.status, ttl: entry.ttl });
  }

  /** Layer 2 write (async; wrap in ctx.waitUntil at the call site). */
  async putRemote(key: string, entry: CacheEntry): Promise<void> {
    if (entry.ttl <= 0) return;
    try {
      const resp = new Response(entry.body, {
        status: entry.status,
        headers: {
          "content-type": "application/dns-message",
          "cache-control": `max-age=${Math.floor(entry.ttl)}`,
        },
      });
      await caches.default.put(this.cacheUrl(key), resp);
    } catch {
      // Non-fatal: LRU layer still covers this isolate.
    }
  }
}
