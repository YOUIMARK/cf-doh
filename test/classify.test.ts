import { describe, expect, it } from "vitest";
import {
  buildSyntheticNxdomain,
  classifyResponse,
  rcode,
  scanAnswers,
} from "../src/dns/classify";
import { parseQuestion } from "../src/dns/parse";
import { buildQuery, buildResponse, encodeName, v4, v6 } from "./helpers";

describe("scanAnswers", () => {
  it("extracts min TTL and public addresses", () => {
    const resp = buildResponse("example.com", [
      { type: 1, ttl: 300, rdata: v4(1, 2, 3, 4) },
      { type: 1, ttl: 60, rdata: v4(5, 6, 7, 8) },
    ]);
    const s = scanAnswers(resp);
    expect(s.minTtl).toBe(60);
    expect(s.blocked).toBe(false);
    expect(s.hasAddresses).toBe(true);
    expect(s.allPrivate).toBe(false);
  });

  it("detects blocked (0.0.0.0) answers", () => {
    const resp = buildResponse("ads.example", [
      { type: 1, ttl: 30, rdata: v4(0, 0, 0, 0) },
    ]);
    const s = scanAnswers(resp);
    expect(s.blocked).toBe(true);
  });

  it("detects all-private answers for rebind", () => {
    const resp = buildResponse("internal.example", [
      { type: 1, ttl: 60, rdata: v4(192, 168, 1, 1) },
      { type: 1, ttl: 60, rdata: v4(10, 0, 0, 1) },
    ]);
    const s = scanAnswers(resp);
    expect(s.allPrivate).toBe(true);
    expect(s.hasAddresses).toBe(true);
  });

  it("treats a mix of private + public as not all-private", () => {
    const resp = buildResponse("mixed.example", [
      { type: 1, ttl: 60, rdata: v4(192, 168, 1, 1) },
      { type: 1, ttl: 60, rdata: v4(8, 8, 8, 8) },
    ]);
    expect(scanAnswers(resp).allPrivate).toBe(false);
  });

  it("handles AAAA private (::1, fc00::/7, fe80::/10)", () => {
    for (const addr of [v6(0, 0, 0, 0, 0, 0, 0, 1), v6(0xfc00), v6(0xfe80, 0)]) {
      const resp = buildResponse("v6.example", [{ type: 28, ttl: 60, rdata: addr }]);
      expect(scanAnswers(resp).allPrivate).toBe(true);
    }
  });

  it("returns Infinity TTL for empty answers", () => {
    const resp = buildResponse("empty.example", [], 3); // NXDOMAIN, no answers
    expect(scanAnswers(resp).minTtl).toBe(Infinity);
  });
});

describe("classifyResponse", () => {
  it("classifies ok", () => {
    expect(classifyResponse(buildResponse("x.com", [{ type: 1, ttl: 60, rdata: v4(1, 1, 1, 1) }]), false)).toBe("ok");
  });
  it("classifies nxdomain", () => {
    expect(classifyResponse(buildResponse("x.com", [], 3), false)).toBe("nxdomain");
  });
  it("classifies servfail as error", () => {
    expect(classifyResponse(buildResponse("x.com", [], 2), false)).toBe("error");
  });
  it("classifies blocked", () => {
    expect(classifyResponse(buildResponse("x.com", [{ type: 1, ttl: 30, rdata: v4(0, 0, 0, 0) }]), false)).toBe("blocked");
  });
  it("classifies rebind only when protection is on", () => {
    const resp = buildResponse("x.com", [{ type: 1, ttl: 60, rdata: v4(10, 1, 1, 1) }]);
    expect(classifyResponse(resp, false)).toBe("ok");
    expect(classifyResponse(resp, true)).toBe("rebind");
  });
  it("rcode reads header", () => {
    expect(rcode(buildResponse("x.com", [], 3))).toBe(3);
  });
});

describe("buildSyntheticNxdomain", () => {
  it("echoes the question with rcode 3 and zero counts", () => {
    const query = buildQuery("blocked.example", { qtype: 1 });
    const q = parseQuestion(query)!;
    const out = buildSyntheticNxdomain(query, q.questionEnd);
    expect(rcode(out)).toBe(3);
    expect(out.length).toBe(q.questionEnd); // header + question only
    const echoed = parseQuestion(out)!;
    expect(echoed.name).toBe("blocked.example");
    expect(echoed.qtype).toBe(1);
  });
});
