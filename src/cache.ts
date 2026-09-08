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
  /** Extra variance tag (e.g. the raw dns-json type string) — hashed in when set. */
  typeTag?: string;
}

/** Canonical, deterministic cache key derived from the DNS query. */
export async function makeCacheKeyStr(info: CacheKeyInfo): Promise<string> {
  const raw = `${info.name}|${info.qtype}|${info.qclass}|${info.modeKey}|${info.ecsBucket}${
    info.typeTag ? `|${info.typeTag}` : ""
  }`;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(raw),
  );
  return toHex(new Uint8Array(digest)).slice(0, 40);
}

/**
 * Cache key for the wire (RFC 8484) path: SHA-256 over the EXACT bytes that
 * will be sent upstream minus the 16-bit transaction ID, plus the provider
 * identity, mode and ECS bucket. Hashing the effective message bytes
 * automatically captures every DNS semantic that can change the answer:
 * RD/CD flags, EDNS version, DO bit, and any EDNS option (an unknown option
 * yields a distinct key instead of sharing a cache entry). Excluding the
 * transaction ID keeps cached responses shareable across clients (CF-002).
 * `message` MUST be the post-ECS / post-family-rewrite bytes sent upstream.
 */
export async function makeWireCacheKey(
  message: Uint8Array,
  providerKey: string,
  modeKey: string,
  ecsBucket: string,
): Promise<string> {
  const te = new TextEncoder();
  const body = message.subarray(2); // flags..end (skip transaction ID)
  const parts = [te.encode(providerKey), te.encode("|"), te.encode(modeKey), te.encode("|"), te.encode(ecsBucket), te.encode("|"), body];
  const total = parts.reduce((acc, p) => acc + p.byteLength, 0);
  const raw = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    raw.set(p, off);
    off += p.byteLength;
  }
  const digest = await crypto.subtle.digest("SHA-256", raw);
  return toHex(new Uint8Array(digest)).slice(0, 40);
}

/**
 * Remaining freshness of a Cache API entry: `max-age` is the object's
 * ORIGINAL freshness lifetime, not the time still left — the entry may have
 * sat in the cache for `Age` seconds already. Returning max-age verbatim
 * would "resurrect" nearly-expired entries (CF-008).
 */
export function remainingTtl(cacheControl: string, ageHeader: string): number {
  const m = /max-age=(\d+)/.exec(cacheControl);
  const maxAge = m ? Math.max(0, Number(m[1])) : 0;
  const age = Number(ageHeader);
  return Math.max(0, maxAge - (Number.isFinite(age) && age > 0 ? age : 0));
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
      const age = resp.headers.get("age") ?? "";
      const ttl = remainingTtl(cc, age);
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
