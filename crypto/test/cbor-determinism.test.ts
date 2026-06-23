// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { encodeCanonical, decodeCbor, decodeCanonical, canonicalRoundTrip } from '../src/cbor.js'

/**
 * Foundational canonical-encoder determinism + injectivity (Team Apex sweep,
 * 2026-06-21). `encodeCanonical` is THE byte-exact preimage for every hash and
 * signature in the protocol, so its determinism (same value → same bytes, at any
 * nesting depth) and injectivity (distinct values → distinct bytes) are
 * load-bearing. This exercises the edge cases the basic cbor test does not:
 * deep key-order, large/negative integers, byte strings, near-collision shapes.
 */
const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex')

describe('canonical CBOR — determinism + injectivity (foundational)', () => {
  it('deep key-order independence (maps sorted at EVERY nesting level)', () => {
    const a = { x: { c: 3, a: 1, b: 2 }, y: [{ q: 2, p: 1 }], z: 'k' }
    const b = { z: 'k', y: [{ p: 1, q: 2 }], x: { b: 2, a: 1, c: 3 } }
    expect(hex(encodeCanonical(a))).toBe(hex(encodeCanonical(b)))
  })

  it('byte-stable + round-trip-stable across a wide value set (incl. large/negative ints, bytes)', () => {
    const values: unknown[] = [
      0,
      1,
      -1,
      255,
      256,
      65535,
      Number.MAX_SAFE_INTEGER,
      -Number.MAX_SAFE_INTEGER,
      '',
      'unicode: café — ✓',
      true,
      false,
      null,
      [],
      {},
      [1, 2, 3],
      { a: [1, { b: 2 }], c: new Uint8Array([0, 127, 255]) },
      new Uint8Array(0),
      { nested: { deeply: { value: [{ k: -42 }] } } },
    ]
    for (const v of values) {
      // same value → same bytes every call
      expect(hex(encodeCanonical(v))).toBe(hex(encodeCanonical(v)))
      // encode → decode → encode is byte-identical (throws inside if not)
      expect(() => canonicalRoundTrip(v)).not.toThrow()
    }
  })

  it('injectivity: distinct logical values produce distinct bytes', () => {
    const pairs: [unknown, unknown][] = [
      [{ a: 1 }, { a: 2 }],
      [{ a: 1 }, { b: 1 }],
      [{ a: 1 }, { a: 1, b: 2 }],
      [
        [1, 2],
        [1, 2, 3],
      ],
      [1, '1'], // number vs string
      [1, true],
      [null, false],
      [{ a: { b: 1 } }, { a: { b: 2 } }],
      [new Uint8Array([1, 2]), [1, 2]], // byte string vs array
      ['', new Uint8Array(0)], // empty string vs empty bytes
    ]
    for (const [x, y] of pairs) {
      expect(hex(encodeCanonical(x))).not.toBe(hex(encodeCanonical(y)))
    }
  })

  it('numeric Map keys (COSE protected-header style) are order-independent', () => {
    const m1 = new Map<number, unknown>([
      [1, -50],
      [4, 'kid'],
    ])
    const m2 = new Map<number, unknown>([
      [4, 'kid'],
      [1, -50],
    ])
    expect(hex(encodeCanonical(m1))).toBe(hex(encodeCanonical(m2)))
  })

  it('decoded values re-encode to the original canonical bytes', () => {
    const v = { suite: 'PS-5', commit: new Uint8Array([3, 1, 4, 1, 5]), tier: 2, ok: true }
    const first = encodeCanonical(v)
    expect(hex(encodeCanonical(decodeCbor(first)))).toBe(hex(first))
  })
})

/**
 * decodeCanonical strictly enforces canonical INPUT (R7 / REPLAY-CANON-001). cbor2's permissive
 * decode() silently accepts non-canonical bytes — unsorted/duplicate map keys, non-minimal integers,
 * indefinite-length items, non-canonical floats — any of which breaks the determinism the
 * receipt/replay invariant rests on. The strict decoder re-encodes and rejects on any byte mismatch.
 */
describe('decodeCanonical — rejects non-canonical input (R7)', () => {
  const fromHex = (s: string): Uint8Array =>
    new Uint8Array(s.match(/../g)!.map((h) => parseInt(h, 16)))
  // Each hex decodes to a value whose canonical re-encoding differs from these bytes → must reject.
  const nonCanonical: Record<string, string> = {
    'unsorted map keys {2:0,1:0}': 'a202000100',
    'duplicate map keys {1:0,1:1}': 'a201000101',
    'non-minimal uint (uint64 for 5)': '1b0000000000000005',
    'non-minimal uint (uint8 for 5)': '1805',
    'indefinite-length array': '9f0102ff',
    'indefinite-length map': 'bf0102ff',
    'non-canonical float (1.0 as f64)': 'fb3ff0000000000000',
    'negative-zero float': 'fb8000000000000000',
  }
  for (const [name, hexs] of Object.entries(nonCanonical)) {
    it(`rejects ${name}`, () => {
      expect(() => decodeCanonical(fromHex(hexs))).toThrow(/non-canonical/)
    })
  }

  it('accepts genuinely canonical bytes and returns the value', () => {
    const v = { suite: 'PS-5', tier: 2, items: [1, 2, 3], ok: true }
    const canonical = encodeCanonical(v)
    expect(() => decodeCanonical(canonical)).not.toThrow()
    expect(hex(encodeCanonical(decodeCanonical(canonical)))).toBe(hex(canonical))
  })

  it('a duplicate-key map cannot smuggle a chosen value (first-vs-last ambiguity is refused)', () => {
    // {1:0,1:1}: cbor2 keeps the LAST (→ {1:1}); a first-wins decoder would see {1:0}. The bytes are
    // not canonical either way, so strict decode refuses the ambiguity outright.
    expect(() => decodeCanonical(fromHex('a201000101'))).toThrow(/non-canonical/)
  })
})
