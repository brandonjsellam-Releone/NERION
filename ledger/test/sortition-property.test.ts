// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Property-based tests for selectLeader (Nerion A10 DoD — fast-check edition).
 *
 * Four security-load-bearing invariants are verified over arbitrary generator
 * inputs so the covering space extends well beyond the hand-picked cases in
 * sortition.test.ts:
 *
 *   (1) DETERMINISM         — same (seed, validators) → same leader every call
 *   (2) MEMBERSHIP          — leader is always in the supplied validator set
 *   (3) STAKE-WEIGHTING     — higher-stake validators win more often over N draws
 *   (4) PERMUTATION STABILITY — equal-stake sets yield the same leader regardless
 *                               of the input order (pubkey-sort makes it stable)
 *
 * Each property runs numRuns:50 so the full suite stays fast in CI.
 * The STAKE-WEIGHTING property uses a fixed-seed fc.gen call to drive N=200
 * draws without additional Uint8Array generation overhead.
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { selectLeader } from '../src/sortition.js'
import type { ValidatorSet, Validator } from '../src/types.js'

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

/**
 * A hex string of exactly `byteLen` bytes (2*byteLen hex chars).
 * Used to generate prevHash values that are realistic but arbitrary.
 */
const hexString = (byteLen: number): fc.Arbitrary<string> =>
  fc.uint8Array({ minLength: byteLen, maxLength: byteLen }).map((arr) =>
    Array.from(arr)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  )

/** Arbitrary 32-byte prevHash (same width as a real block hash). */
const prevHash32 = hexString(32)

/**
 * Arbitrary non-negative bigint stake in [1, 2^20].
 * Lower bound is 1n so every validator has positive stake (total > 0).
 * Upper bound is kept small so the cumulative walk stays fast.
 */
const posStake: fc.Arbitrary<bigint> = fc.bigInt({ min: 1n, max: 1_048_576n /* 2^20 */ })

/**
 * A hex pubkey: 8 arbitrary bytes rendered as hex (short enough to be fast,
 * distinct enough that collisions are negligible across the 2-4 validators
 * used per property run).
 */
const pubkeyHex = hexString(8)

/**
 * An array of 2–5 Validator records with DISTINCT pubkeys and positive stakes.
 * Distinctness is enforced by constructing pubkeys from an index prefix.
 */
const validatorSet: fc.Arbitrary<ValidatorSet> = fc
  .array(posStake, { minLength: 2, maxLength: 5 })
  .chain((stakes) => {
    // Give each validator a deterministic prefix so pubkeys are guaranteed distinct.
    const validators: fc.Arbitrary<Validator[]> = fc.tuple(
      ...stakes.map((stake, i) =>
        pubkeyHex.map((suffix) => ({
          pubkey: i.toString(16).padStart(2, '0') + suffix,
          stake,
        })),
      ),
    )
    return validators.map((vs) => ({ validators: vs }))
  })

/**
 * A round in [0, 15] — small range keeps property execution fast while
 * still exercising the round dimension of the seed derivation.
 */
const smallRound = fc.integer({ min: 0, max: 15 })

// ---------------------------------------------------------------------------
// (1) DETERMINISM
// ---------------------------------------------------------------------------

describe('selectLeader property-based tests (A10)', () => {
  it('(1) DETERMINISM: same (set, prevHash, round) always returns the same leader', () => {
    fc.assert(
      fc.property(validatorSet, prevHash32, smallRound, (set, hash, round) => {
        const first = selectLeader(set, hash, round)
        const second = selectLeader(set, hash, round)
        expect(first).toBe(second)
      }),
      { numRuns: 50 },
    )
  })

  // ---------------------------------------------------------------------------
  // (2) MEMBERSHIP
  // ---------------------------------------------------------------------------

  it('(2) MEMBERSHIP: returned leader is always a member of the validator set', () => {
    fc.assert(
      fc.property(validatorSet, prevHash32, smallRound, (set, hash, round) => {
        const leader = selectLeader(set, hash, round)
        const pubkeys = new Set(set.validators.map((v) => v.pubkey))
        expect(pubkeys.has(leader)).toBe(true)
      }),
      { numRuns: 50 },
    )
  })

  // ---------------------------------------------------------------------------
  // (3) STAKE-WEIGHTING
  // ---------------------------------------------------------------------------

  /**
   * Generate a two-validator set where one validator has 3× the stake of the
   * other.  Over 200 draws the high-stake validator must win more than half
   * the time — a conservative bound (expected share ≈ 75 %) that is never
   * flaky at this sample size.
   */
  it('(3) STAKE-WEIGHTING: higher-stake validator wins more often over N=200 draws', () => {
    fc.assert(
      fc.property(
        posStake,
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        (baseStake, seedBytes) => {
          // Heavy validator has 3× the stake of light.
          const lightPub = '00' + 'aa'.repeat(8)
          const heavyPub = '01' + 'bb'.repeat(8)
          const set: ValidatorSet = {
            validators: [
              { pubkey: lightPub, stake: baseStake },
              { pubkey: heavyPub, stake: baseStake * 3n },
            ],
          }

          const N = 200
          let heavyWins = 0
          for (let i = 0; i < N; i++) {
            // Vary both the prevHash and round so we sample many distinct seed points.
            const hash = i.toString(16).padStart(64, '0')
            const round = i % 8
            if (selectLeader(set, hash, round) === heavyPub) heavyWins++
          }

          // Expected fraction ≈ 0.75.  A 200-draw binomial with p=0.75 has
          // std-dev ≈ 0.031; requiring > 0.50 gives a 99.999 % confidence margin.
          expect(heavyWins / N).toBeGreaterThan(0.5)
        },
      ),
      { numRuns: 50 },
    )
  })

  // ---------------------------------------------------------------------------
  // (4) PERMUTATION STABILITY
  // ---------------------------------------------------------------------------

  /**
   * When all validators share the same stake the cumulative-walk is uniform.
   * The result must be IDENTICAL regardless of the order the validators are
   * supplied — selectLeader sorts by pubkey internally, so permuting the input
   * must not change the elected leader.
   */
  it('(4) PERMUTATION STABILITY: equal-stake sets yield the same leader regardless of input order', () => {
    fc.assert(
      fc.property(
        // Generate 2-4 distinct pubkeys and a single shared stake value.
        fc.array(pubkeyHex, { minLength: 2, maxLength: 4 }).chain((suffixes) => {
          // Guarantee distinctness by prepending the index.
          const pubkeys = suffixes.map((s, i) => i.toString(16).padStart(2, '0') + s)
          return fc.tuple(fc.constant(pubkeys), posStake)
        }),
        prevHash32,
        smallRound,
        ([pubkeys, stake], hash, round) => {
          const canonical: ValidatorSet = {
            validators: pubkeys.map((pubkey) => ({ pubkey, stake })),
          }
          // Reverse the array — simplest non-trivial permutation.
          const reversed: ValidatorSet = {
            validators: [...canonical.validators].reverse(),
          }
          // Rotate by one position (different from reverse for length > 2).
          const rotated: ValidatorSet = {
            validators: [...canonical.validators.slice(1), canonical.validators[0]!],
          }

          const expected = selectLeader(canonical, hash, round)
          expect(selectLeader(reversed, hash, round)).toBe(expected)
          expect(selectLeader(rotated, hash, round)).toBe(expected)
        },
      ),
      { numRuns: 50 },
    )
  })
})
