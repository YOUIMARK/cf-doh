/**
 * Bounded body reads (mirrors vercel-doh's read-body hardening).
 *
 * `arrayBuffer()` buffers the whole body before any size check can run, so a
 * chunked/lying sender could push unbounded bytes into the 128 MB isolate.
 * These helpers abort the stream the moment the cap is crossed and signal
 * that with `null`; the caller owns the error mapping (413 / 502 / failover).
 */

/** Reads a stream up to `maxBytes`. Returns null (after cancelling the
 *  stream) when the body exceeds the cap. A null stream reads as empty. */
export async function readStreamBounded(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<Uint8Array | null> {
  if (!stream) return new Uint8Array(0);
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/** UTF-8 text variant (chunks are concatenated before decoding, so multi-byte
 *  sequences split across chunk boundaries decode correctly). */
export async function readTextBounded(
  stream: ReadableStream<Uint8Array> | null,
  maxBytes: number,
): Promise<string | null> {
  const bytes = await readStreamBounded(stream, maxBytes);
  if (bytes === null) return null;
  return new TextDecoder().decode(bytes);
}
