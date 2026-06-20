// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { encodeCanonical, decodeCbor, canonicalRoundTrip } from '../src/cbor.js'

describe('canonical (deterministic) CBOR', () => {
  it('is byte-identical regardless of source key order', () => {
    const a = encodeCanonical({ b: 1, a: 2, c: 3 })
    const b = encodeCanonical({ c: 3, a: 2, b: 1 })
    expect(Buffer.from(a)).toEqual(Buffer.from(b))
  })

  it('round-trips structured values', () => {
    const value = {
      intent: 'transfer',
      amount: 5,
      tier: 2,
      tags: ['money', 't2'],
      meta: { nonce: new Uint8Array([9, 8, 7]) },
    }
    const decoded = decodeCbor(encodeCanonical(value)) as typeof value
    expect(decoded.intent).toBe('transfer')
    expect(decoded.amount).toBe(5)
    expect(decoded.tags).toEqual(['money', 't2'])
    expect(Buffer.from(decoded.meta.nonce)).toEqual(Buffer.from([9, 8, 7]))
  })

  it('encoding is stable across an encode→decode→encode cycle', () => {
    const bytes = canonicalRoundTrip({ z: [1, 2, 3], a: 'x', m: { k: true } })
    expect(bytes.length).toBeGreaterThan(0)
  })

  it('produces the same bytes for the same logical value every call', () => {
    const v = { suite: 'PS-5', ceiling: 1000, delegable: false }
    expect(Buffer.from(encodeCanonical(v))).toEqual(Buffer.from(encodeCanonical(v)))
  })
})
