import { describe, expect, it } from "vitest";
import {
  base64urlToBytes,
  getEcs,
  parseIp,
  setEcsInMessage,
  stripEcsFromMessage,
  truncateBytes,
  truncateIp,
} from "../src/dns/encode";
import { findOptRecord, parseEcs, readU16 } from "../src/dns/parse";
import { buildEcsOption, buildOptRecord, buildQuery, toBase64url, v4, v6 } from "./helpers";

describe("parseIp", () => {
  it("parses IPv4", () => {
    expect(parseIp("1.2.3.4")).toEqual({ family: 1, bytes: v4(1, 2, 3, 4) });
  });
  it("rejects bad IPv4", () => {
    expect(parseIp("1.2.3")).toBeNull();
    expect(parseIp("1.2.3.256")).toBeNull();
    expect(parseIp("1.2.3.a")).toBeNull();
  });
  it("parses full IPv6", () => {
    expect(parseIp("2001:db8::1")?.family).toBe(2);
    expect(parseIp("2001:db8::1")?.bytes.length).toBe(16);
  });
  it("parses ::1", () => {
    const r = parseIp("::1");
    expect(r?.bytes[15]).toBe(1);
    expect(r?.bytes[0]).toBe(0);
  });
  it("parses embedded IPv4 tail", () => {
    const r = parseIp("::ffff:1.2.3.4");
    expect(r?.bytes.slice(10, 16)).toEqual(v4(0xff, 0xff, 1, 2, 3, 4));
  });
  it("rejects garbage", () => {
    expect(parseIp("not-an-ip")).toBeNull();
    expect(parseIp("1:2:3:4:5:6:7:8:9")).toBeNull();
  });
});

describe("truncateIp / truncateBytes", () => {
  it("truncates IPv4 to /24 with masked last byte", () => {
    const r = truncateIp("1.2.3.4", 24);
    expect(r).toEqual({ family: 1, bytes: v4(1, 2, 3) });
  });
  it("truncates IPv4 to /20", () => {
    const r = truncateIp("1.2.3.4", 20);
    expect(r?.bytes.length).toBe(3);
    expect(r?.bytes[2]).toBe(3 & 0xf0); // 0x00
  });
  it("truncates IPv6 to /56", () => {
    const r = truncateIp("2001:db8:1:2:3:4:5:6", 56);
    expect(r?.bytes.length).toBe(7);
    expect(r?.bytes[4]).toBe(0x00);
    expect(r?.bytes[5]).toBe(0x01); // group "0001" spans bytes 4-5
  });
  it("clamps bits to address width", () => {
    expect(truncateIp("1.2.3.4", 128)?.bytes).toEqual(v4(1, 2, 3, 4));
    expect(truncateIp("1.2.3.4", 0)?.bytes.length).toBe(0);
  });
  it("truncateBytes masks the trailing byte", () => {
    expect(truncateBytes(v4(1, 2, 3, 4), 20, 32)).toEqual(v4(1, 2, 0));
  });
});

describe("setEcsInMessage", () => {
  it("appends an OPT record when none exists and bumps ARCOUNT", () => {
    const msg = buildQuery("example.com");
    const out = setEcsInMessage(msg, 1, 24, v4(1, 2, 3));
    expect(out.length).toBeGreaterThan(msg.length);
    expect(readU16(out, 10)).toBe(1); // ARCOUNT
    const opt = findOptRecord(out)!;
    expect(parseEcs(out, opt)).toMatchObject({ family: 1, sourcePrefix: 24 });
  });

  it("replaces an existing ECS option", () => {
    const ecs = buildEcsOption(1, 32, v4(9, 9, 9, 9));
    const msg = buildQuery("example.com", { additional: buildOptRecord(1232, 0, ecs) });
    const out = setEcsInMessage(msg, 1, 24, v4(1, 2, 3));
    expect(readU16(out, 10)).toBe(1); // ARCOUNT unchanged
    const opt = findOptRecord(out)!;
    const parsed = parseEcs(out, opt);
    expect(parsed).toMatchObject({ family: 1, sourcePrefix: 24 });
    expect(parsed?.address).toEqual(v4(1, 2, 3));
    // no other ECS remains
    let count = 0;
    let p = opt.rdataStart;
    const end = opt.rdataStart + opt.rdLength;
    while (p + 4 <= end) {
      if (readU16(out, p) === 8) count++;
      const len = readU16(out, p + 2);
      p += 4 + len;
    }
    expect(count).toBe(1);
  });

  it("keeps non-ECS options intact when replacing", () => {
    const other = new Uint8Array(8); // code 0, len 4
    const ecs = buildEcsOption(2, 56, new Uint8Array(7).fill(0xfd));
    const rdata = new Uint8Array(other.length + ecs.length);
    rdata.set(other, 0);
    rdata.set(ecs, other.length);
    const msg = buildQuery("example.com", { additional: buildOptRecord(1232, 0, rdata) });
    const out = setEcsInMessage(msg, 1, 24, v4(1, 2, 3));
    const opt = findOptRecord(out)!;
    expect(readU16(out, opt.rdataStart)).toBe(0); // first option still code 0
  });
});

describe("stripEcsFromMessage", () => {
  it("returns the same buffer when there is no ECS", () => {
    const msg = buildQuery("example.com");
    expect(stripEcsFromMessage(msg)).toBe(msg);
  });

  it("removes the ECS option but keeps the OPT record", () => {
    const ecs = buildEcsOption(1, 24, v4(1, 2, 3));
    const msg = buildQuery("example.com", { additional: buildOptRecord(1232, 0, ecs) });
    const out = stripEcsFromMessage(msg);
    expect(out).not.toBe(msg);
    expect(getEcs(out)).toBeNull();
    expect(findOptRecord(out)).not.toBeNull(); // OPT itself preserved
  });

  it("leaves the message unchanged when OPT has no ECS", () => {
    const opt = buildOptRecord(1232, 0, new Uint8Array(0));
    const msg = buildQuery("example.com", { additional: opt });
    expect(stripEcsFromMessage(msg)).toBe(msg);
  });
});

describe("getEcs", () => {
  it("returns the first ECS option", () => {
    const ecs = buildEcsOption(1, 24, v4(1, 2, 3));
    const msg = buildQuery("example.com", { additional: buildOptRecord(1232, 0, ecs) });
    expect(getEcs(msg)).toEqual({ family: 1, sourcePrefix: 24, address: v4(1, 2, 3) });
  });
  it("returns null when absent", () => {
    expect(getEcs(buildQuery("example.com"))).toBeNull();
  });
});

describe("base64urlToBytes", () => {
  it("decodes RFC 8484 base64url without padding", () => {
    const bytes = v4(1, 2, 3, 4, 5);
    expect(base64urlToBytes(toBase64url(bytes))).toEqual(bytes);
  });
  it("rejects invalid characters", () => {
    expect(base64urlToBytes("ab+cd")).toBeNull();
  });
  it("rejects wrong lengths", () => {
    expect(base64urlToBytes("a")).toBeNull();
  });
});
