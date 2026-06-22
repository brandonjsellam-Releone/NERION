// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { selectLeader, totalStake, type ValidatorSet } from '../src/index.js'

/**
 * A10 (Team Apex 21-day sprint): `selectLeader` — the deterministic, verifiable,
 * stake-weighted leader draw — had ZERO direct test coverage. This exercises its four
 * load-bearing properties (determinism, membership, stake-proportionality, order/
 * permutation independence) plus the zero-stake fail-closed edge and the large-stake
 * BigInt walk (LEDGER-PRECISION-001).
 */
const s = signerFor(SUITE_IDS.PS_5)
const keys = Array.from({ length: 4 }, () => s.keygen())
const hx = keys.map((k) => bytesToHex(k.publicKey))
const set: ValidatorSet = {
  validators: [
    { pubkey: hx[0]!, stake: 10n },
    { pubkey: hx[1]!, stake: 20n },
    { pubkey: hx[2]!, stake: 30n },
    { pubkey: hx[3]!, stake: 40n },
  ],
}
// Distinct prevHash per draw (any string is fine — it is hashed into the seed).
const prevAt = (i: number): string => i.toString(16).padStart(64, '0')

describe('selectLeader — verifiable stake-weighted sortition (A10)', () => {
  it('is deterministic for a fixed (set, prevHash, round)', () => {
    expect(selectLeader(set, prevAt(7), 0)).toBe(selectLeader(set, prevAt(7), 0))
    expect(selectLeader(set, prevAt(7), 1)).toBe(selectLeader(set, prevAt(7), 1))
  })

  it('always returns a member of the set', () => {
    const members = new Set(set.validators.map((v) => v.pubkey))
    for (let r = 0; r < 60; r++) {
      expect(members.has(selectLeader(set, prevAt(r), r % 3))).toBe(true)
    }
  })

  it('is independent of validator ORDER (pubkey-sorted internally)', () => {
    const reversed: ValidatorSet = { validators: [...set.validators].reverse() }
    const rotated: ValidatorSet = {
      validators: [set.validators[2]!, set.validators[0]!, set.validators[3]!, set.validators[1]!],
    }
    for (let i = 0; i < 40; i++) {
      const leader = selectLeader(set, prevAt(i), 0)
      expect(selectLeader(reversed, prevAt(i), 0)).toBe(leader)
      expect(selectLeader(rotated, prevAt(i), 0)).toBe(leader)
    }
  })

  it('weights selection ~proportionally to stake over many draws', () => {
    const counts = new Map<string, number>()
    const N = 4000
    for (let i = 0; i < N; i++) {
      const ldr = selectLeader(set, prevAt(i), 0)
      counts.set(ldr, (counts.get(ldr) ?? 0) + 1)
    }
    const total = totalStake(set)
    for (const v of set.validators) {
      const observed = (counts.get(v.pubkey) ?? 0) / N
      const expected = Number(v.stake) / Number(total)
      // 4000 draws → per-proportion std error ≲ 0.008; 0.05 is a wide, non-flaky bound.
      expect(Math.abs(observed - expected)).toBeLessThan(0.05)
    }
  })

  it('fails closed on a zero-stake set; a single validator always leads', () => {
    expect(() => selectLeader({ validators: [] }, prevAt(1), 0)).toThrow()
    expect(() =>
      selectLeader({ validators: [{ pubkey: hx[0]!, stake: 0n }] }, prevAt(1), 0),
    ).toThrow()
    const solo: ValidatorSet = { validators: [{ pubkey: hx[0]!, stake: 5n }] }
    expect(selectLeader(solo, prevAt(9), 3)).toBe(hx[0])
  })

  it('selects exactly at large stake (LEDGER-PRECISION-001 BigInt walk, total = 2^53)', () => {
    const big: ValidatorSet = {
      validators: [
        { pubkey: hx[0]!, stake: 4_503_599_627_370_496n }, // 2^52
        { pubkey: hx[1]!, stake: 4_503_599_627_370_496n }, // 2^52 (total = 2^53)
      ],
    }
    const ldr = selectLeader(big, prevAt(123), 0)
    expect([hx[0], hx[1]]).toContain(ldr)
    expect(selectLeader(big, prevAt(123), 0)).toBe(ldr) // still deterministic at scale
  })
})
