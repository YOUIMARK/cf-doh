/**
 * IP address parsing and private/reserved classification for ECS handling.
 * `parseIp` lives in `encode.ts`; this module adds the address sanity checks
 * needed before injecting a client subnet upstream.
 */

export interface IpAddress {
  family: 1 | 2;
  bytes: Uint8Array;
}

function isPrivateV4(a: Uint8Array): boolean {
  if (a.length !== 4) return false;
  const [o0, o1] = [a[0]!, a[1]!];
  if (o0 === 0) return true; // 0.0.0.0/8
  if (o0 === 10) return true; // 10.0.0.0/8
  if (o0 === 127) return true; // 127.0.0.0/8
  if (o0 === 169 && o1 === 254) return true; // link-local
  if (o0 === 172 && o1 >= 16 && o1 <= 31) return true; // 172.16.0.0/12
  if (o0 === 192 && o1 === 168) return true; // 192.168.0.0/16
  if (o0 === 100 && o1 >= 64 && o1 <= 127) return true; // CGNAT 100.64.0.0/10
  if (o0 === 198 && (o1 === 18 || o1 === 19)) return true; // benchmarking
  if (o0 >= 224) return true; // multicast + reserved
  return false;
}

function isPrivateV6(a: Uint8Array): boolean {
  if (a.length !== 16) return false;
  const [b0, b1] = [a[0]!, a[1]!];
  if (b0 === 0 && b1 === 0) {
    let nonzero = false;
    for (let i = 2; i < 16; i++) if (a[i] !== 0) nonzero = true;
    if (!nonzero) return true; // ::
    if (a[15] === 1 && !nonzero) return true; // ::1
    if (a[15] !== 1) return false;
    // ::1 check: bytes 2..14 all zero and byte 15 == 1
    for (let i = 2; i < 15; i++) if (a[i] !== 0) return false;
    return true;
  }
  if ((b0 & 0xfe) === 0xfc) return true; // fc00::/7 ULA
  if (b0 === 0xfe && (b1 & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b0 === 0x20 && b1 === 0x01 && a[2] === 0x0d && a[3] === 0xb8) return true; // 2001:db8::/32
  return false;
}

/** True for private, loopback, link-local, CGNAT, multicast and reserved ranges. */
export function isPrivateOrReserved(ip: IpAddress): boolean {
  if (ip.family === 1) return isPrivateV4(ip.bytes);
  return isPrivateV6(ip.bytes);
}

/**
 * Masks an IP to `prefixLen` bits and formats it as "a.b.c.d/prefix"
 * (IPv4) or "xxxx:xxxx:.../prefix" (IPv6, uncompressed) — the form used by
 * the `edns_client_subnet` query parameter of dns-json APIs (mirrors
 * vercel-doh's `formatEcsPrefix`).
 */
export function formatEcsPrefix(ip: IpAddress, prefixLen: number): string {
  const bits = ip.family === 1 ? 32 : 128;
  const prefix = Math.max(0, Math.min(prefixLen, bits));
  const bytes = Array.from(ip.bytes);
  const fullBytes = Math.floor(prefix / 8);
  const remBits = prefix % 8;
  for (let i = fullBytes; i < bytes.length; i++) bytes[i] = 0;
  if (remBits > 0 && fullBytes < bytes.length) {
    bytes[fullBytes] = (bytes[fullBytes] as number) & (0xff << (8 - remBits));
  }
  if (ip.family === 1) {
    return `${bytes.join(".")}/${prefix}`;
  }
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i] as number) << 8 | (bytes[i + 1] as number)).toString(16).padStart(4, "0"));
  }
  return `${groups.join(":")}/${prefix}`;
}
