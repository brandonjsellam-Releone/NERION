// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { encodeCanonical, decodeCbor } from '../src/cbor.js'

/**
 * A28 — canonical CBOR injectivity / round-trip property tests.
 *
 * `encodeCanonical` is the byte-exact preimage for every hash and signature in
 * the protocol.  These four properties must hold universally — not just for the
 * hand-crafted vectors in cbor.test.ts / cbor-determinism.test.ts — to give
 * confidence that no exotic value shape can break the determinism or injectivity
 * guarantees that the receipt/replay invariant rests on:
 *
 *   DETERMINISM  – encode(x) always returns the same bytes for the same input.
 *   ROUND-TRIP   – decode(encode(x)) is structurally equal to x.
 *   INJECTIVITY  – x ≠ y  ⇒  encode(x) ≠ encode(y).
 *   NO-COLLISION – 1 000 random values yield 1 000 distinct hex encodings.
 *
 * All arbitraries use fc.jsonValue() which generates the JSON-compatible subset
 * (null, boolean, number, string, array, object) — exactly the types that survive
 * a CBOR round-trip with structural equality (no Uint8Array whose decoded form
 * is a Uint8Array, whose equality semantics differ from plain arrays).
 */

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')

/**
 * fc.jsonValue() can generate NaN and ±Infinity (as JS numbers).  dCBOR does not
 * have a canonical representation for these (CBOR well-formedness and dCBOR both
 * exclude them).  Filter them out so every generated value is encodable.
 */
const safeJson: fc.Arbitrary<fc.JsonValue> = fc.jsonValue().filter((v) => {
  const containsNonFinite = (x: unknown): boolean => {
    if (typeof x === 'number') return !Number.isFinite(x)
    if (Array.isArray(x)) return x.some(containsNonFinite)
    if (x !== null && typeof x === 'object')
      return Object.values(x as Record<string, unknown>).some(containsNonFinite)
    return false
  }
  return !containsNonFinite(v)
})

const RUNS = { numRuns: 200 }

// ---------------------------------------------------------------------------
// DETERMINISM
// ---------------------------------------------------------------------------
describe('A28 — CBOR canonical-encoding DETERMINISM property', () => {
  it('encodeCanonical(x) returns byte-identical results on repeated calls for any JSON-compatible x', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const a = hex(encodeCanonical(x))
        const b = hex(encodeCanonical(x))
        expect(a).toBe(b)
      }),
      RUNS,
    )
  })

  it('determinism holds when the same object is passed twice with different key insertion order', () => {
    // Build two objects whose property sets are the same but enumerated in
    // reversed order; the canonical encoder must produce identical bytes.
    fc.assert(
      fc.property(fc.dictionary(fc.string({ minLength: 1, maxLength: 8 }), fc.integer()), (obj) => {
        const keys = Object.keys(obj)
        // Reverse the key order by rebuilding the object in reverse key sequence.
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
})

// ---------------------------------------------------------------------------
// ROUND-TRIP
// ---------------------------------------------------------------------------
describe('A28 — CBOR canonical-encoding ROUND-TRIP property', () => {
  it('decodeCbor(encodeCanonical(x)) re-encodes to the same canonical bytes as encodeCanonical(x)', () => {
    // NOTE on equality semantics: CBOR maps are stored with keys sorted in
    // dCBOR canonical order.  When we decode back to a JS object the keys come
    // out in that sorted order, which may differ from the insertion order of the
    // original `x`.  `JSON.stringify` is therefore NOT a suitable equality
    // predicate (it is sensitive to key order).  The canonical encoder IS the
    // canonical "equality witness": if encode(decode(encode(x))) == encode(x)
    // then the decoded value is the same logical CBOR value as the original.
    // (This is exactly what `canonicalRoundTrip` in cbor.ts asserts.)
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

  it('encode(decode(encode(x))) equals encode(x) — encoding is stable across an extra round-trip', () => {
    fc.assert(
      fc.property(safeJson, (x) => {
        const first = encodeCanonical(x)
        const second = encodeCanonical(decodeCbor(first))
        expect(hex(second)).toBe(hex(first))
      }),
      RUNS,
    )
  })
})

// ---------------------------------------------------------------------------
// INJECTIVITY
// ---------------------------------------------------------------------------
describe('A28 — CBOR canonical-encoding INJECTIVITY property', () => {
  it('if x !== y (structurally) then encodeCanonical(x) !== encodeCanonical(y)', () => {
    fc.assert(
      fc.property(safeJson, safeJson, (x, y) => {
        // Only assert when x and y are genuinely distinct values.
        if (JSON.stringify(x) === JSON.stringify(y)) return
        expect(hex(encodeCanonical(x))).not.toBe(hex(encodeCanonical(y)))
      }),
      // Run more iterations so we get a good ratio of x≠y pairs.
      { numRuns: 500 },
    )
  })

  it('type-level injectivity: number vs string, boolean vs null, array vs object', () => {
    // Hardened spot-checks: fast-check's universal coverage above should catch
    // any regression here, but these anchor the most protocol-relevant collision
    // vectors (JSON integer vs CBOR text, CBOR bool vs CBOR null).
    const pairs: [fc.JsonValue, fc.JsonValue][] = [
      [1, '1'],
      [0, '0'],
      [true, 1],
      [false, 0],
      [null, false],
      [null, 0],
      [null, ''],
      [[], {}],
      [[], ''],
      [{}, ''],
    ]
    for (const [x, y] of pairs) {
      expect(hex(encodeCanonical(x))).not.toBe(hex(encodeCanonical(y)))
    }
  })
})

// ---------------------------------------------------------------------------
// NO-COLLISION across 1 000 random values
// ---------------------------------------------------------------------------
describe('A28 — CBOR canonical-encoding NO-COLLISION (1 000 samples)', () => {
  it('1 000 random JSON-compatible values produce 1 000 distinct canonical encodings', () => {
    // Generate 1 000 values in one shot using fc.sample(), then verify that
    // every encoding is unique.  Values that happen to be structurally equal
    // are deduplicated before the uniqueness check so the test is not flaky
    // when fast-check draws duplicates by chance.
    const samples = fc.sample(safeJson, 1000)

    // Deduplicate by JSON identity to get the set of structurally distinct values.
    const distinctByJson = new Map<string, fc.JsonValue>()
    for (const s of samples) {
      distinctByJson.set(JSON.stringify(s), s)
    }

    // Encode every distinct value and collect hex strings.
    const encodings = new Set<string>()
    for (const v of distinctByJson.values()) {
      encodings.add(hex(encodeCanonical(v)))
    }

    // The number of distinct encodings must equal the number of distinct values —
    // no two structurally different values may share a canonical encoding.
    expect(encodings.size).toBe(distinctByJson.size)
  })
})
