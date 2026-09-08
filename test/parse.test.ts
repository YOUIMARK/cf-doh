import { describe, expect, it } from "vitest";
import {
  decodeName,
  findOptRecord,
  parseEcs,
  parseQuestion,
  readU16,
} from "../src/dns/parse";
import {
  buildEcsOption,
  buildOptRecord,
  buildQuery,
  encodeName,
  v4,
} from "./helpers";

describe("decodeName", () => {
  it("decodes a simple name", () => {
    const msg = new Uint8Array([7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x63, 0x6f, 0x6d, 0x00]);
    const r = decodeName(msg, 0);
    expect(r).toEqual({ name: "example.com", next: 13 });
  });

  it("lowercases the name", () => {
    const msg = encodeName("EXAMPLE.COM");
    const r = decodeName(msg, 0);
    expect(r?.name).toBe("example.com");
  });

  it("handles the root name", () => {
    const r = decodeName(new Uint8Array([0]), 0);
    expect(r).toEqual({ name: ".", next: 1 });
  });

  it("follows compression pointers and reports the next offset", () => {
    // name at 0: pointer to offset 14 where "example.com" lives
    const msg = new Uint8Array(30);
    msg[0] = 0xc0;
    msg[1] = 14;
    msg.set([7, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 3, 0x63, 0x6f, 0x6d, 0x00], 14);
    const r = decodeName(msg, 0);
    expect(r?.name).toBe("example.com");
    expect(r?.next).toBe(2);
  });

  it("rejects pointer loops", () => {
    const msg = new Uint8Array(4);
    msg[0] = 0xc0;
    msg[1] = 2;
    msg[2] = 0xc0;
    msg[3] = 0;
    expect(decodeName(msg, 0)).toBeNull();
  });

  it("rejects out-of-range labels", () => {
    const msg = new Uint8Array([5, 0x61]); // claims 5 bytes, has 1
    expect(decodeName(msg, 0)).toBeNull();
  });
});

describe("parseQuestion", () => {
  it("parses the first question", () => {
    const q = buildQuery("example.com", { qtype: 1, qclass: 1 });
    const r = parseQuestion(q);
    expect(r).toMatchObject({ name: "example.com", qtype: 1, qclass: 1 });
    expect(r?.questionEnd).toBe(12 + encodeName("example.com").length + 4);
  });

  it("rejects messages without a question", () => {
    const q = buildQuery("example.com");
    q[4] = 0;
    q[5] = 0;
    expect(parseQuestion(q)).toBeNull();
  });

  it("rejects messages that are too short", () => {
    expect(parseQuestion(new Uint8Array(10))).toBeNull();
  });
});

describe("findOptRecord / parseEcs", () => {
  it("locates the OPT record and parses an ECS option", () => {
    const ecs = buildEcsOption(1, 24, v4(1, 2, 3));
    const opt = buildOptRecord(1232, 0, ecs);
    const msg = buildQuery("example.com", { additional: opt });
    const found = findOptRecord(msg);
    expect(found).not.toBeNull();
    expect(found?.cls).toBe(1232);
    expect(found?.rdLength).toBe(ecs.length);
    const parsed = parseEcs(msg, found!);
    expect(parsed).toEqual({ family: 1, sourcePrefix: 24, scopePrefix: 0, address: v4(1, 2, 3) });
  });

  it("returns null when no OPT record exists", () => {
    expect(findOptRecord(buildQuery("example.com"))).toBeNull();
  });

  it("scans options past a non-ECS option", () => {
    const other = new Uint8Array(8); // option code 0, length 4
    const ecs = buildEcsOption(2, 56, new Uint8Array(7).fill(0xfd));
    const rdata = new Uint8Array(other.length + ecs.length);
    rdata.set(other, 0);
    rdata.set(ecs, other.length);
    const msg = buildQuery("example.com", { additional: buildOptRecord(1232, 0, rdata) });
    const found = findOptRecord(msg)!;
    const parsed = parseEcs(msg, found);
    expect(parsed?.family).toBe(2);
    expect(parsed?.sourcePrefix).toBe(56);
  });

  it("survives answer/authority records before the additional section", () => {
    // query with ANCOUNT=1 requires us to skip it — construct manually
    const qname = encodeName("example.com");
    const questionLen = qname.length + 4;
    const answer = new Uint8Array(12 + 4); // A record, rdata 4 bytes
    answer[0] = 0xc0;
    answer[1] = 0x0c;
    answer[2] = 0;
    answer[3] = 1; // type A
    answer[4] = 0;
    answer[5] = 1; // class IN
    // ttl 0
    answer[10] = 0;
    answer[11] = 4; // rdlength
    answer.set(v4(9, 9, 9, 9), 12);
    const opt = buildOptRecord(1232, 0, buildEcsOption(1, 32, v4(8, 8, 8, 8)));
    const msg = buildQuery("example.com");
    // rebuild with ANCOUNT=1 and answer + opt appended
    const out = new Uint8Array(msg.length + answer.length + opt.length);
    out.set(msg, 0);
    // header ANCOUNT = 1, ARCOUNT = 1
    out[6] = 0;
    out[7] = 1;
    out[10] = 0;
    out[11] = 1;
    out.set(answer, 12 + questionLen);
    out.set(opt, 12 + questionLen + answer.length);
    const found = findOptRecord(out);
    expect(found).not.toBeNull();
    const parsed = parseEcs(out, found!);
    expect(parsed?.address).toEqual(v4(8, 8, 8, 8));
  });

  it("readU16/writeU16 roundtrip", () => {
    const b = new Uint8Array(2);
    expect(readU16(b, 0)).toBe(0);
  });
});
