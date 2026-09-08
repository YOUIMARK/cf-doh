/**
 * HTTP media-type / Accept negotiation helpers (RFC 7231 §3.1.1.1, §5.3.2).
 *
 * DoH (RFC 8484) relies on exact media types (`application/dns-message`,
 * `application/dns-json`), so `startsWith`/`includes` string matching is
 * wrong: `application/dns-messageevil` or a `; charset=` parameter must not
 * change the answer. These helpers parse the media type essence and respect
 * Accept q-values (`Accept: application/dns-message;q=0` = not acceptable).
 * Ported from vercel-doh's `media.ts`.
 */

/** Extracts the media type essence ("type/subtype") from a Content-Type /
 *  Accept media-range header value, lowercased and trimmed. Null for empty
 *  or structurally invalid input. */
export function parseMediaType(header: string): string | null {
  const semi = header.indexOf(";");
  const essence = (semi === -1 ? header : header.slice(0, semi)).trim().toLowerCase();
  const slash = essence.indexOf("/");
  if (slash === -1 || slash === 0 || slash === essence.length - 1) return null;
  const type = essence.slice(0, slash);
  const subtype = essence.slice(slash + 1);
  if (type === "" || subtype === "" || subtype.includes("/")) return null;
  return essence;
}

/**
 * Whether the Accept header makes `wanted` acceptable:
 *  - the most specific matching media-range wins (type/subtype beats
 *    subtype wildcard, which beats a type wildcard);
 *  - a matching range with q=0 makes the type NOT acceptable even when a
 *    wildcard with q>0 also matches;
 *  - an absent/empty Accept is treated as acceptable (RFC 8484 says SHOULD,
 *    not MUST).
 */
export function acceptsMediaType(accept: string | null | undefined, wanted: string): boolean {
  const raw = (accept ?? "").trim();
  if (raw === "") return true;
  const [wType, wSub] = splitMediaType(wanted);
  if (wType === null || wSub === null) return false;

  let bestSpecificity = -1;
  let bestQ = 0;
  for (const range of raw.split(",")) {
    const parts = range
      .split(";")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (parts.length === 0) continue;
    const [rType, rSub] = splitMediaType(parts[0]!);
    if (rType === null || rSub === null) continue;

    let q = 1;
    for (const param of parts.slice(1)) {
      const eq = param.indexOf("=");
      if (eq === -1) continue;
      const key = param.slice(0, eq).trim().toLowerCase();
      const value = param.slice(eq + 1).trim();
      if (key === "q") {
        const parsed = Number.parseFloat(value);
        if (!Number.isNaN(parsed)) q = parsed;
      }
    }

    let specificity = -1;
    if (rType === "*" && rSub === "*") specificity = 0;
    else if (rType === wType && rSub === "*") specificity = 1;
    else if (rType === wType && rSub === wSub) specificity = 2;
    if (specificity < 0) continue;

    if (specificity > bestSpecificity) {
      bestSpecificity = specificity;
      bestQ = q;
    } else if (specificity === bestSpecificity && q < bestQ) {
      bestQ = q; // same specificity → most restrictive wins
    }
  }
  return bestSpecificity >= 0 && bestQ > 0;
}

/** Splits "type/subtype" into lowercased parts; null on malformed input. */
function splitMediaType(essence: string): [string | null, string | null] {
  const slash = essence.indexOf("/");
  if (slash === -1) return [null, null];
  const type = essence.slice(0, slash).trim().toLowerCase();
  const sub = essence.slice(slash + 1).trim().toLowerCase();
  if (type === "" || sub === "") return [null, null];
  return [type, sub];
}
