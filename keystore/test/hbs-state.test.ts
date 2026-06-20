// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { SoftwareOtsStateStore, HbsKeyProvider, type HbsSignEngine } from '../src/index.js'
import { OtsKeyExhaustedError, PolicyError, type HbsParams } from '../../crypto/src/index.js'

const params = (over: Partial<HbsParams> = {}): HbsParams => ({
  family: 'LMS',
  multiTree: false,
  hash: 'SHA-256/192',
  height: 2,
  ...over,
})

function fakeEngine(p: HbsParams, failFirst = false): { engine: HbsSignEngine; calls: number[] } {
  const calls: number[] = []
  let n = 0
  const engine: HbsSignEngine = {
    getRoot: () => new Uint8Array([1, 2, 3]),
    params: () => p,
    signWithIndex: (_keyId, index, _message) => {
      calls.push(index)
      if (failFirst && n++ === 0) throw new Error('engine fault')
      return new Uint8Array([index])
    },
  }
  return { engine, calls }
}

describe('stateful-HBS state manager (reserve-before-sign)', () => {
  it('SoftwareOtsStateStore is gated (refuses without allowUnsafeSoftwareState)', () => {
    expect(() => new SoftwareOtsStateStore()).toThrow(PolicyError)
    expect(() => new SoftwareOtsStateStore(true)).not.toThrow()
  })

  it('never reuses an OTS index (strict monotonic)', () => {
    const store = new SoftwareOtsStateStore(true)
    expect(store.reserve('k', 3).index).toBe(0)
    expect(store.reserve('k', 3).index).toBe(1)
    expect(store.reserve('k', 3).index).toBe(2)
  })

  it('throws OtsKeyExhaustedError at 2^H, never wrapping to 0', () => {
    const store = new SoftwareOtsStateStore(true)
    store.reserve('k', 0) // total = 1
    expect(() => store.reserve('k', 0)).toThrow(OtsKeyExhaustedError)
  })

  it('refuses an index below an external monotonic floor (anti-rollback)', () => {
    const store = new SoftwareOtsStateStore(true)
    store.reserve('k', 3) // consumed = 1
    expect(() => store.assertMonotonicFloor('k', 5)).toThrow() // local 1 < external 5 = rolled back
    expect(() => store.assertMonotonicFloor('k', 1)).not.toThrow()
  })

  it('reserve-before-sign: a failed engine.sign burns the index (NO reuse on retry)', () => {
    const { engine, calls } = fakeEngine(params(), true)
    const provider = new HbsKeyProvider(engine, new SoftwareOtsStateStore(true))
    expect(() => provider.sign('k', new Uint8Array([9]))).toThrow() // index 0 burned by the fault
    expect(provider.sign('k', new Uint8Array([9]))).toEqual(new Uint8Array([1])) // uses index 1, not 0
    expect(calls).toEqual([0, 1]) // 0 was attempted+burned, never retried
  })

  it('refuses a multi-tree key at sign time, BEFORE reserving any index', () => {
    const store = new SoftwareOtsStateStore(true)
    const provider = new HbsKeyProvider(fakeEngine(params({ multiTree: true })).engine, store)
    expect(() => provider.sign('k', new Uint8Array([1]))).toThrow(PolicyError)
    expect(store.capacity('k').consumed).toBe(0) // no index was burned
  })

  it('remaining() counts down toward exhaustion', () => {
    const store = new SoftwareOtsStateStore(true)
    const provider = new HbsKeyProvider(fakeEngine(params({ height: 2 })).engine, store)
    provider.sign('k', new Uint8Array([1]))
    expect(provider.remaining('k')).toBe(3) // total 4, consumed 1
  })
})
