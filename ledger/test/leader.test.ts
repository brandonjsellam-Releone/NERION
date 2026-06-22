// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { prove } from '../src/vrf.js'
import { vrfAlpha, vrfLeaderEligible, vrfPriority } from '../src/leader.js'
import type { ValidatorSet } from '../src/index.js'

// Each validator has an identity pubkey (drives the stake interval) + a VRF seed.
function validators(n: number, stake: (i: number) => bigint) {
  return Array.from({ length: n }, (_, i) => ({
    pubkey: bytesToHex(new Uint8Array(32).fill(i + 1)),
    vrfSeed: new Uint8Array(32).fill(100 + i),
    stake: stake(i),
  }))
}

describe('VRF leader eligibility', () => {
  it('a single validator is always eligible (beta mod 1 = 0)', () => {
    const v = validators(1, () => 5n)[0]!
    const set: ValidatorSet = { validators: [{ pubkey: v.pubkey, stake: v.stake }] }
    for (let r = 0; r < 5; r++) {
      const beta = prove(v.vrfSeed, vrfAlpha('00'.repeat(32), r)).beta
      expect(vrfLeaderEligible(set, v.pubkey, beta)).toBe(true)
    }
  })

  it('eligibility frequency tracks stake fraction (stake-weighted self-selection)', () => {
    const vs = validators(4, (i) => (i === 0 ? 7n : 1n)) // total 10; v0 holds 70%
    const set: ValidatorSet = { validators: vs.map((v) => ({ pubkey: v.pubkey, stake: v.stake })) }
    const eligible = [0, 0, 0, 0]
    const ROUNDS = 150
    for (let r = 0; r < ROUNDS; r++) {
      vs.forEach((v, i) => {
        const beta = prove(v.vrfSeed, vrfAlpha('aa'.repeat(32), r)).beta
        if (vrfLeaderEligible(set, v.pubkey, beta)) eligible[i] = (eligible[i] as number) + 1
      })
    }
    expect((eligible[0] as number) / ROUNDS).toBeGreaterThan(0.5) // ~0.7
    expect((eligible[1] as number) / ROUNDS).toBeLessThan(0.3) // ~0.1
    const total = eligible.reduce((a, b) => a + b, 0) / ROUNDS // E[#eligible] ≈ 1
    expect(total).toBeGreaterThan(0.6)
    expect(total).toBeLessThan(1.5)
  })

  it('vrfPriority orders by beta (lower wins) for tie-breaks', () => {
    const lo = new Uint8Array(64)
    lo[0] = 1
    const hi = new Uint8Array(64)
    hi[0] = 2
    expect(vrfPriority(lo) < vrfPriority(hi)).toBe(true)
  })
})
