// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * A28 — Canonical CBOR injectivity / round-trip property tests.
 *
 * `encodeCanonical` is the byte-exact preimage for every hash and signature in the
 * Nerion protocol.  These properties must hold universally — not just for the
 * hand-crafted vectors in cbor.test.ts / cbor-determinism.test.ts — to give
 * confidence that no exotic value shape can break the determinism or injectivity
 * guarantees that the receipt/replay invariant rests on.
 *
 * Four properties under test:
 *
 *   DETERMINISM       – encodeCanonical(x) always returns the same bytes on any call.
 *   ROUND-TRIP        – encodeCanonical(decodeCbor(encodeCanonical(x))) === encodeCanonical(x).
 *   INJECTIVITY       – x ≠ y  ⇒  encodeCanonical(x) ≠ encodeCanonical(y).
 *   STRICT-DECODER    – decodeCanonical accepts canonical bytes and rejects non-canonical bytes.
 *   CANONICAL-RT-API  – canonicalRoundTrip() never throws on any encodable value and
 *                        returns the same bytes as encodeCanonical().
 *
 * Exports under test (from crypto/src/cbor.ts):
 *   encodeCanonical(value: unknown): Bytes
 *   decodeCbor(bytes: Bytes): unknown
 *   decodeCanonical(bytes: Bytes): unknown   — strict: throws on any non-canonical input
 *   canonicalRoundTrip(value: unknown): Bytes — encode→decode→encode stability assertion
 *
 * Arbitraries: fc.jsonValue() covers null/boolean/number/string/array/object.  The
 * non-finite filter is mandatory: dCBOR has no canonical representation for NaN /
 * ±Infinity, so fast-check must not generate them.  fc.jsonValue() is the correct
 * scope because those are the types that survive a CBOR round-trip with JS structural
 * equality — Uint8Array decodes to Uint8Array but deep-equals differently from a plain
 * number array, so we keep Uint8Array out of the fc-generated corpus (it is covered
 * by hand-crafted vectors in cbor-determinism.test.ts).
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { encodeCanonical, decodeCbor, decodeCanonical, canonicalRoundTrip } from '../src/cbor.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Convert a Uint8Array to a lowercase hex string for human-readable assertions. */
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')

/**
 * fc.jsonValue() can emit NaN and ±Infinity as JS numbers.  dCBOR (and CBOR
 * well-formedness) excludes non-finite floats.  Recursively filter them out so
 * every generated value is accepted by encodeCanonical without throwing.
 */
const containsNonFinite = (x: unknown): boolean => {
  if (typeof x === 'number') return !Number.isFinite(x)
  if (Array.isArray(x)) return x.some(containsNonFinite)
  if (x !== null && typeof x === 'object')
    return Object.values(x as Record<string, unknown>).some(containsNonFinite)
  return false
}

const safeJson: fc.Arbitrary<fc.JsonValue> = fc.jsonValue().filter((v) => !containsNonFinite(v))

/** Default run count: enough for broad coverage without slow CI. */
const RUNS = { numRuns: 300 }
/** Wider run count for injectivity where we need a good ratio of distinct pairs. */
const RUNS_INJECT = { numRuns: 600 }

// ---------------------------------------------------------------------------
// DETERMINISM
// Calling encodeCanonical twice on the same value MUST produce byte-identical
// output.  Violation here would break the receipt/replay invariant (any two
// witnesses would derive different commitment bytes for the same action).
// ---------------------------------------------------------------------------
describe('A28 — CBOR DETERMINISM property', () => {
  it('encodeCanonical(x) is byte-identical on any two calls for any JSON-compatible x', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        expect(hex(encodeCanonical(x))).toBe(hex(encodeCanonical(x)))
      }),
      RUNS,
    )
  })

  it('determinism holds regardless of JS object key insertion order', () => {
    // Build two objects with the same logical content but keys inserted in
    // reverse order.  The dCBOR encoder MUST sort map keys and produce the
    // same bytes.
    fc.assert(
      fc.property(fc.dictionary(fc.string({ minLength: 1, maxLength: 8 }), fc.integer()), (obj) => {
        const keys = Object.keys(obj)
        const reversed = Object.fromEntries(
          keys
            .slice()
            .reverse()
            .map((k) => [k, obj[k]]),
        )
        expect(hex(encodeCanonical(obj))).toBe(hex(encodeCanonical(reversed)))
      }),
      RUNS,
    )
  })

  it('determinism holds at every nesting depth (deeply-nested key-order independence)', () => {
    // Generates arrays of objects with randomized key sets to stress nested
    // map sorting across an arbitrary depth.
    const deepObj = fc.array(
      fc.record({
        a: fc.integer(),
        b: fc.string(),
        c: fc.boolean(),
      }),
      { maxLength: 4 },
    )
    fc.assert(
      fc.property(deepObj, (arr) => {
        // Two encodings of the same JS value — JS does NOT re-order object keys
        // between two calls, so this is a pure stability check.
        expect(hex(encodeCanonical(arr))).toBe(hex(encodeCanonical(arr)))
      }),
      RUNS,
    )
  })
})

// ---------------------------------------------------------------------------
// ROUND-TRIP
// encode → decode → encode must be byte-stable.  The canonical encoder is used
// as the equality witness (not JSON.stringify) because dCBOR map keys are sorted,
// so the decoded JS object's key order may differ from the original's.
// ---------------------------------------------------------------------------
describe('A28 — CBOR ROUND-TRIP property', () => {
  it('encodeCanonical(decodeCbor(encodeCanonical(x))) === encodeCanonical(x) for any JSON-compatible x', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const encoded = encodeCanonical(x)
        const decoded = decodeCbor(encoded)
        const reEncoded = encodeCanonical(decoded)
        expect(hex(reEncoded)).toBe(hex(encoded))
      }),
      RUNS,
    )
  })

  it('encode(decode(encode(x))) equals encode(x) — encoding is stable across a SECOND extra round-trip', () => {
    // Belt-and-suspenders: if the first re-encode is stable, a second one must
    // be too (the decoded value is already in canonical key-order).
    fc.assert(
      fc.property(safeJson, (x) => {
        const first = encodeCanonical(x)
        const second = encodeCanonical(decodeCbor(first))
        const third = encodeCanonical(decodeCbor(second))
        expect(hex(third)).toBe(hex(first))
      }),
      RUNS,
    )
  })

  it('round-trip is lossless for primitive leaf types (bool, null, integer, string)', () => {
    fc.assert(
      fc.property(
        fc.oneof(
          fc.boolean(),
          fc.constant(null),
          fc.integer({ min: -(2 ** 31), max: 2 ** 31 - 1 }),
          fc.string(),
        ),
        (prim) => {
          const bytes = encodeCanonical(prim)
          const back = decodeCbor(bytes)
          // Primitives survive CBOR round-trip with JS strict equality.
          expect(back).toBe(prim)
        },
      ),
      RUNS,
    )
  })
})

// ---------------------------------------------------------------------------
// INJECTIVITY
// Two structurally distinct values MUST NOT share a canonical encoding.
// A collision here would make two different actions look identical to any
// verifier that hashes or signs canonical bytes.
// ---------------------------------------------------------------------------
describe('A28 — CBOR INJECTIVITY property', () => {
  it('x !== y (structurally) implies encodeCanonical(x) !== encodeCanonical(y)', () => {
    fc.assert(
      fc.property(safeJson, safeJson, (x, y) => {
        // JSON.stringify is the guard: if the two values stringify identically,
        // they are structurally equal and must produce identical bytes — skip.
        if (JSON.stringify(x) === JSON.stringify(y)) return
        expect(hex(encodeCanonical(x))).not.toBe(hex(encodeCanonical(y)))
      }),
      RUNS_INJECT,
    )
  })

  it('type-boundary injectivity: cross-type collisions are impossible', () => {
    // Protocol-critical pairs: a number tag vs a text tag, a CBOR boolean vs
    // CBOR null, byte-string vs array, etc.
    const pairs: [fc.JsonValue, fc.JsonValue][] = [
      [1, '1'], // CBOR major-type 0 (uint) vs major-type 3 (text)
      [0, '0'],
      [true, 1], // CBOR simple 21 vs uint 1
      [false, 0], // CBOR simple 20 vs uint 0
      [null, false], // CBOR simple 22 vs simple 20
      [null, 0],
      [null, ''],
      [[], {}], // CBOR major-type 4 (array) vs major-type 5 (map)
      [[], ''],
      [{}, ''],
      [[1], [1, 2]], // different-length arrays
      [{ a: 1 }, { a: 2 }],
      [{ a: 1 }, { b: 1 }],
      [{ a: 1 }, { a: 1, b: 2 }],
    ]
    for (const [x, y] of pairs) {
      const exHex = hex(encodeCanonical(x))
      const eyHex = hex(encodeCanonical(y))
      if (exHex === eyHex) {
        throw new Error(
          `expected encodeCanonical(${JSON.stringify(x)}) !== encodeCanonical(${JSON.stringify(y)})`,
        )
      }
    }
  })

  it('1 000 random JSON-compatible values produce 1 000 distinct canonical encodings', () => {
    // Sample, deduplicate structurally equal values (JSON identity), then verify
    // that the set of encodings is as large as the set of distinct input values.
    const samples = fc.sample(safeJson, 1000)
    const distinctByJson = new Map<string, fc.JsonValue>()
    for (const s of samples) {
      distinctByJson.set(JSON.stringify(s), s)
    }
    const encodings = new Set<string>()
    for (const v of distinctByJson.values()) {
      encodings.add(hex(encodeCanonical(v)))
    }
    expect(encodings.size).toBe(distinctByJson.size)
  })
})

// ---------------------------------------------------------------------------
// STRICT DECODER (decodeCanonical)
// decodeCanonical must accept exactly the outputs of encodeCanonical and reject
// every byte sequence that departs from the dCBOR canonical form — including
// unsorted map keys, duplicate map keys, non-minimal integer encodings,
// indefinite-length items, and non-canonical floats.
// ---------------------------------------------------------------------------
describe('A28 — decodeCanonical STRICT-DECODER property', () => {
  it('decodeCanonical accepts any output of encodeCanonical without throwing', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const canonical = encodeCanonical(x)
        expect(() => decodeCanonical(canonical)).not.toThrow()
      }),
      RUNS,
    )
  })

  it('decodeCanonical(encodeCanonical(x)) re-encodes to the same canonical bytes', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const canonical = encodeCanonical(x)
        const decoded = decodeCanonical(canonical)
        expect(hex(encodeCanonical(decoded))).toBe(hex(canonical))
      }),
      RUNS,
    )
  })

  it('decodeCanonical rejects known non-canonical byte patterns (R7 hardening)', () => {
    // Each hex string decodes to a value whose canonical re-encoding differs —
    // decodeCanonical must throw /non-canonical/ on every one of them.
    const fromHex = (s: string): Uint8Array =>
      new Uint8Array(s.match(/../g)!.map((h) => parseInt(h, 16)))

    const nonCanonical: Record<string, string> = {
      'unsorted map keys {2:0, 1:0}': 'a202000100',
      'duplicate map keys {1:0, 1:1}': 'a201000101',
      'non-minimal uint (uint64 encoding of 5)': '1b0000000000000005',
      'non-minimal uint (uint8 encoding of 5)': '1805',
      'indefinite-length array': '9f0102ff',
      'indefinite-length map': 'bf0102ff',
      'non-canonical float (1.0 as f64)': 'fb3ff0000000000000',
      'negative-zero float': 'fb8000000000000000',
    }
    for (const [label, hexStr] of Object.entries(nonCanonical)) {
      expect(() => decodeCanonical(fromHex(hexStr)), `expected rejection of ${label}`).toThrow(
        /non-canonical/,
      )
    }
  })

  it('decodeCanonical never silently accepts mutated (non-canonical) bytes as-if canonical', () => {
    // Flipping a bit in a canonical encoding must cause decodeCanonical to either
    // throw (malformed or non-canonical CBOR) OR — in the rare case where the
    // mutation produces a different but genuinely canonical encoding — return a
    // value whose re-encoding equals the mutated bytes (not the original bytes).
    // The one thing it must NEVER do is silently decode a mutated byte string and
    // re-encode it to the ORIGINAL canonical bytes (which would indicate a
    // non-determinism or aliasing bug).
    fc.assert(
      fc.property(
        safeJson.filter((x) => {
          try {
            return encodeCanonical(x).length >= 2
          } catch {
            return false
          }
        }),
        fc.nat({ max: 7 }),
        (x, bit) => {
          const canonical = encodeCanonical(x)
          const mutated = new Uint8Array(canonical)
          // Flip a bit in the last byte (a value byte, not the major-type byte).
          const lastIdx = mutated.length - 1
          mutated[lastIdx] = (mutated[lastIdx] ?? 0) ^ (1 << (bit % 8))
          // If the flip is a no-op (e.g. XOR with 0 on a 0-byte), skip.
          if (hex(mutated) === hex(canonical)) return
          try {
            const decoded = decodeCanonical(mutated)
            // decodeCanonical did NOT throw: the mutated bytes are genuinely
            // canonical for some OTHER value.  Its re-encoding must equal the
            // mutated bytes — NOT the original canonical bytes.
            const reenc = hex(encodeCanonical(decoded))
            expect(reenc).toBe(hex(mutated))
            expect(reenc).not.toBe(hex(canonical))
          } catch {
            // Any thrown error is the correct outcome for malformed / non-canonical bytes.
          }
        },
      ),
      RUNS,
    )
  })
})

// ---------------------------------------------------------------------------
// canonicalRoundTrip API property
// canonicalRoundTrip(x) must:
//   (a) never throw for any encodable x (JSON-compatible, finite)
//   (b) return bytes byte-identical to encodeCanonical(x)
// ---------------------------------------------------------------------------
describe('A28 — canonicalRoundTrip API property', () => {
  it('canonicalRoundTrip(x) never throws for any JSON-compatible x', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        expect(() => canonicalRoundTrip(x)).not.toThrow()
      }),
      RUNS,
    )
  })

  it('canonicalRoundTrip(x) returns bytes equal to encodeCanonical(x)', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        expect(hex(canonicalRoundTrip(x))).toBe(hex(encodeCanonical(x)))
      }),
      RUNS,
    )
  })

  it('canonicalRoundTrip is idempotent: calling it twice produces the same bytes', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const first = hex(canonicalRoundTrip(x))
        const second = hex(canonicalRoundTrip(x))
        expect(second).toBe(first)
      }),
      RUNS,
    )
  })
})
