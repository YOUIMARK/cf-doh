/**
 * End-to-end tests: run the real worker through its fetch handler with
 * outbound upstream requests intercepted by MSW (@msw/cloudflare).
 * The cache-hit assertions count upstream calls, proving the dual-layer
 * cache serves repeat queries without spending subrequest budget.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { rcode, scanAnswers } from "../src/dns/classify";
import {
  buildQuery,
  buildResponse,
  toBase64url,
  v4,
} from "./helpers";
import { network } from "./network";

type EnvLike = Record<string, string | undefined>;

async function call(
  request: Request,
  envOverride: EnvLike = {},
): Promise<Response> {
  const ctx = createExecutionContext();
  const merged: EnvLike = { ...env, ...envOverride };
  const resp = await worker.fetch(request, merged, ctx);
  await waitOnExecutionContext(ctx);
  return resp;
}

function dnsPost(path: string, body: Uint8Array, headers: Record<string, string> = {}): Request {
  return new Request(`https://doh-worker.example${path}`, {
    method: "POST",
    headers: { "content-type": "application/dns-message", ...headers },
    body,
  });
}

function dnsGet(path: string, body: Uint8Array): Request {
  return new Request(`https://doh-worker.example${path}?dns=${toBase64url(body)}`);
}

describe("DoH endpoint", () => {
  it("resolves via POST and caches the repeat query (one upstream call)", async () => {
    const query = buildQuery("example.com", { qtype: 1 });
    const answer = buildResponse("example.com", [{ type: 1, ttl: 300, rdata: v4(1, 2, 3, 4) }]);
    let calls = 0;
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () => {
        calls += 1;
        return HttpResponse.arrayBuffer(answer.buffer as ArrayBuffer, {
          headers: { "content-type": "application/dns-message" },
        });
      }),
    );

    const first = await call(dnsPost("/dns-query", query));
    expect(first.status).toBe(200);
    expect(first.headers.get("content-type")).toBe("application/dns-message");
    const body1 = new Uint8Array(await first.arrayBuffer());
    expect(rcode(body1)).toBe(0);
    expect(scanAnswers(body1).minTtl).toBe(300);

    const second = await call(dnsPost("/dns-query", query));
    expect(second.status).toBe(200);
    const body2 = new Uint8Array(await second.arrayBuffer());
    expect(body2).toEqual(body1);
    expect(calls).toBe(1); // second query served from cache
  });

  it("resolves via GET with base64url dns parameter", async () => {
    const query = buildQuery("get.example", { qtype: 1 });
    const answer = buildResponse("get.example", [{ type: 1, ttl: 120, rdata: v4(9, 9, 9, 9) }]);
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () =>
        HttpResponse.arrayBuffer(answer.buffer as ArrayBuffer, {
          headers: { "content-type": "application/dns-message" },
        }),
      ),
    );
    const resp = await call(dnsGet("/dns-query", query));
    expect(resp.status).toBe(200);
    const body = new Uint8Array(await resp.arrayBuffer());
    expect(scanAnswers(body).minTtl).toBe(120);
  });

  it("rejects malformed messages with 400", async () => {
    const resp = await call(dnsPost("/dns-query", new Uint8Array([1, 2, 3])));
    expect(resp.status).toBe(400);
  });

  it("returns 404 on unknown paths and 415 on bad content type", async () => {
    expect((await call(new Request("https://doh-worker.example/nope"))).status).toBe(404);
    expect((await call(dnsPost("/dns-query", buildQuery("x.com"), { "content-type": "text/plain" }))).status).toBe(415);
  });

  it("requires AUTH_TOKEN when configured", async () => {
    const query = buildQuery("auth.example");
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () =>
        HttpResponse.arrayBuffer(buildResponse("auth.example", []).buffer as ArrayBuffer, {
          headers: { "content-type": "application/dns-message" },
        }),
      ),
    );
    const envAuth: EnvLike = { ...env, AUTH_TOKEN: "s3cret" };
    const denied = await call(dnsPost("/dns-query", query), envAuth);
    expect(denied.status).toBe(401);

    const allowed = await call(
      dnsPost("/dns-query", query, { authorization: "Bearer s3cret" }),
      envAuth,
    );
    expect(allowed.status).toBe(200);
  });

  it("applies rebind protection when enabled", async () => {
    const query = buildQuery("internal.example");
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () =>
        HttpResponse.arrayBuffer(
          buildResponse("internal.example", [{ type: 1, ttl: 60, rdata: v4(10, 1, 1, 1) }]).buffer as ArrayBuffer,
          { headers: { "content-type": "application/dns-message" } },
        ),
      ),
    );
    const resp = await call(dnsPost("/dns-query", query), { REBIND_PROTECTION: "true" });
    expect(resp.status).toBe(200);
    const body = new Uint8Array(await resp.arrayBuffer());
    expect(rcode(body)).toBe(3); // synthetic NXDOMAIN
  });

  it("negative-caches NXDOMAIN (no repeat upstream call)", async () => {
    const query = buildQuery("nx.example");
    let calls = 0;
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () => {
        calls += 1;
        return HttpResponse.arrayBuffer(buildResponse("nx.example", [], 3).buffer as ArrayBuffer, {
          headers: { "content-type": "application/dns-message" },
        });
      }),
    );
    const first = await call(dnsPost("/dns-query", query));
    expect(rcode(new Uint8Array(await first.arrayBuffer()))).toBe(3);
    const second = await call(dnsPost("/dns-query", query));
    expect(second.status).toBe(200);
    expect(calls).toBe(1);
  });
});

describe("strict (fan-out) mode", () => {
  it("picks the most restrictive (blocked) answer", async () => {
    const query = buildQuery("ads.example");
    network.use(
      http.post("https://cloudflare-dns.com/dns-query", () =>
        HttpResponse.arrayBuffer(
          buildResponse("ads.example", [{ type: 1, ttl: 30, rdata: v4(0, 0, 0, 0) }]).buffer as ArrayBuffer,
          { headers: { "content-type": "application/dns-message" } },
        ),
      ),
      http.post("https://dns.google/dns-query", () =>
        HttpResponse.arrayBuffer(
          buildResponse("ads.example", [{ type: 1, ttl: 30, rdata: v4(1, 2, 3, 4) }]).buffer as ArrayBuffer,
          { headers: { "content-type": "application/dns-message" } },
        ),
      ),
    );
    const resp = await call(dnsPost("/dns-query", query), { MODE: "strict" });
    expect(resp.status).toBe(200);
    const body = new Uint8Array(await resp.arrayBuffer());
    expect(scanAnswers(body).blocked).toBe(true);
  });
});

describe("JSON API endpoint", () => {
  it("forwards to dns-json upstream and caches by name", async () => {
    network.use(
      http.get("https://dns.google/resolve", () =>
        HttpResponse.json({
          Status: 0,
          Answer: [{ name: "example.com", type: 1, TTL: 120, data: "1.2.3.4" }],
        }),
      ),
    );
    const req = new Request("https://doh-worker.example/resolve?name=example.com&type=A");
    const resp = await call(req, { JSON_PATH: "/resolve" });
    expect(resp.status).toBe(200);
    expect(resp.headers.get("content-type")).toContain("application/dns-json");
    const j = (await resp.json()) as { Answer: Array<{ TTL: number }> };
    expect(j.Answer[0]!.TTL).toBe(120);
  });
});

describe("health and config", () => {
  it("serves /health", async () => {
    const resp = await call(new Request("https://doh-worker.example/health"));
    expect(resp.status).toBe(200);
  });

  it("protects /config with ADMIN_TOKEN", async () => {
    const denied = await call(new Request("https://doh-worker.example/config"), { ADMIN_TOKEN: "adm" });
    expect(denied.status).toBe(401);
    const ok = await call(new Request("https://doh-worker.example/config"), {
      ADMIN_TOKEN: "adm",
    });
    // /config requires the token even when ADMIN_TOKEN is set on this request only
    expect(ok.status).toBe(401); // token not supplied in the request itself
  });

  it("serves /config with the admin token", async () => {
    const req = new Request("https://doh-worker.example/config", {
      headers: { authorization: "Bearer adm" },
    });
    const resp = await call(req, { ADMIN_TOKEN: "adm" });
    expect(resp.status).toBe(200);
    const j = (await resp.json()) as { mode: string; dohPath: string };
    expect(j.mode).toBe("failover");
    expect(j.dohPath).toBe("/dns-query");
  });
});
