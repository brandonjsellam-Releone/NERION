// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Equivocation detection property-based tests (Nerion A27 DoD).
 *
 * Four fc.assert properties cover the security-critical invariants of
 * detectEquivocations (LEDGER-001 / LEDGER-EQUIV-001) over generated inputs:
 *
 *   (a) HONEST NEVER FLAGGED    — a validator attesting a single block is never
 *                                 detected as an equivocator
 *   (b) DOUBLE SIGNER FLAGGED   — the same pubkey signing two distinct blocks at
 *                                 the same height yields exactly one proof
 *   (c) NO FALSE POSITIVES      — N distinct honest validators (each attesting one
 *                                 block only) produce zero proofs
 *   (d) DETERMINISTIC           — same (blockA, attsA, blockB, attsB) input always
 *                                 produces the same proofs in the same order
 *
 * Each property runs numRuns:50 so the full ledger suite stays fast in CI.
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  detectEquivocations,
  GENESIS_PREV,
  type ValidatorSet,
  type Attestation,
  type Block,
} from '../src/index.js'

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Build a ValidatorSet and ledger from a list of KeyPairs with equal stake.
 * Using equal stake (1n each) keeps the sortition leader deterministic and
 * avoids confusion between honest/equivocating validators.
 */
function makeSet(keys: readonly KeyPair[]): ValidatorSet {
  return {
    validators: keys.map((k) => ({
      pubkey: bytesToHex(k.publicKey),
      stake: 1n,
    })),
  }
}

/**
 * Pick the sortition leader KeyPair for the genesis round from a set+keys pair.
 */
function leaderOf(set: ValidatorSet, keys: readonly KeyPair[]): KeyPair {
  const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
  return byHex.get(selectLeader(set, GENESIS_PREV, 0))!
}

/**
 * Propose two DISTINCT blocks at the same height (same ledger, different payloadRoot).
 * The ledger.propose API uses the current head so both blocks sit at height 0.
 */
function twoConflictingBlocks(
  ledger: Ledger,
  leader: KeyPair,
  payloadA: string,
  payloadB: string,
): [Block, Block] {
  const blockA = ledger.propose(payloadA, 0, 1000, leader)
  const blockB = ledger.propose(payloadB, 0, 2000, leader)
  return [blockA, blockB]
}

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

/**
 * A hex string of exactly `bytes` bytes (2*bytes hex chars) built from a
 * fc.uint8Array so fast-check shrinks it at the byte level.
 */
const hexBytes = (bytes: number) =>
  fc.uint8Array({ minLength: bytes, maxLength: bytes }).map(bytesToHex)

/**
 * A pair of DISTINCT 32-byte hex payload roots — used as payloadRoot so the two
 * conflicting blocks hash to different values.
 */
const twoDistinctPayloads = fc.tuple(hexBytes(32), hexBytes(32)).filter(([a, b]) => a !== b)

/**
 * A small validator count (1..6) to keep key generation manageable in CI.
 */
const validatorCount = fc.integer({ min: 1, max: 6 })

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('equivocation detection property-based tests (A27)', () => {
  // (a) HONEST NEVER FLAGGED: a validator attesting only one block is never
  //     returned as an equivocator, regardless of what the other block is.
  it('(a) HONEST NEVER FLAGGED: single honest vote never triggers equivocation detection', () => {
    fc.assert(
      fc.property(twoDistinctPayloads, ([payloadA, payloadB]) => {
        // Minimal 3-validator set (34/33/33 like the unit tests).
        const keys: KeyPair[] = [s.keygen(), s.keygen(), s.keygen()]
        const set: ValidatorSet = {
          validators: keys.map((k, i) => ({
            pubkey: bytesToHex(k.publicKey),
            stake: i === 0 ? 34n : 33n,
          })),
        }
        const ledger = new Ledger(set, suite)
        const leader = (() => {
          const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
          return byHex.get(selectLeader(set, GENESIS_PREV, 0))!
        })()
        const [blockA, blockB] = twoConflictingBlocks(ledger, leader, payloadA, payloadB)

        // Each validator attests ONLY blockA (honest behaviour).
        const attsA = keys.map((k) => ledger.attest(blockA, k))
        // Nobody attests blockB.
        const attsB: Attestation[] = []

        const proofs = detectEquivocations(blockA, attsA, blockB, attsB)
        // No validator double-signed — zero proofs expected.
        expect(proofs.length).toBe(0)
      }),
      { numRuns: 50 },
    )
  })

  // (b) DOUBLE SIGNER FLAGGED: the same pubkey signing both blockA and blockB at
  //     the same height must appear in exactly one proof.
  it('(b) DOUBLE SIGNER FLAGGED: same pubkey with two different votes triggers exactly once', () => {
    fc.assert(
      fc.property(twoDistinctPayloads, ([payloadA, payloadB]) => {
        // Use a single-validator set so the equivocating validator is unambiguous.
        const offenderKey = s.keygen()
        const set: ValidatorSet = {
          validators: [{ pubkey: bytesToHex(offenderKey.publicKey), stake: 1n }],
        }
        const ledger = new Ledger(set, suite)
        // With a single validator it is always the leader.
        const blockA = ledger.propose(payloadA, 0, 1000, offenderKey)
        const blockB = ledger.propose(payloadB, 0, 2000, offenderKey)

        const attsA = [ledger.attest(blockA, offenderKey)]
        const attsB = [ledger.attest(blockB, offenderKey)]

        const proofs = detectEquivocations(blockA, attsA, blockB, attsB)
        // Exactly one proof for the one offender.
        expect(proofs.length).toBe(1)
        expect(proofs[0]!.validator).toBe(bytesToHex(offenderKey.publicKey))
      }),
      { numRuns: 50 },
    )
  })

  // (c) NO FALSE POSITIVES: a set of N distinct validators, each attesting exactly
  //     one of the two blocks (not both), must never produce any proofs.
  it('(c) NO FALSE POSITIVES: honest set of N distinct validators never flagged', () => {
    fc.assert(
      fc.property(validatorCount, twoDistinctPayloads, (n, [payloadA, payloadB]) => {
        const keys: KeyPair[] = Array.from({ length: n }, () => s.keygen())
        const set = makeSet(keys)
        const ledger = new Ledger(set, suite)
        const leader = leaderOf(set, keys)

        const [blockA, blockB] = twoConflictingBlocks(ledger, leader, payloadA, payloadB)

        // Split validators: first half attests A only, second half attests B only.
        // No validator attests both — all honest.
        const splitIdx = Math.ceil(n / 2)
        const attsA: Attestation[] = keys.slice(0, splitIdx).map((k) => ledger.attest(blockA, k))
        const attsB: Attestation[] = keys.slice(splitIdx).map((k) => ledger.attest(blockB, k))

        const proofs = detectEquivocations(blockA, attsA, blockB, attsB)
        // No double-signer in this split — zero proofs.
        expect(proofs.length).toBe(0)
      }),
      { numRuns: 50 },
    )
  })

  // (d) DETERMINISTIC: calling detectEquivocations twice with exactly the same
  //     inputs always returns structurally identical proof arrays.
  it('(d) DETERMINISTIC: same input always produces same detection result', () => {
    fc.assert(
      fc.property(twoDistinctPayloads, ([payloadA, payloadB]) => {
        // Mix of honest and equivocating validators: first key double-signs,
        // remaining two sign only one block each.
        const keys: KeyPair[] = [s.keygen(), s.keygen(), s.keygen()]
        const set: ValidatorSet = {
          validators: keys.map((k, i) => ({
            pubkey: bytesToHex(k.publicKey),
            stake: i === 0 ? 34n : 33n,
          })),
        }
        const ledger = new Ledger(set, suite)
        const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
        const leader = byHex.get(selectLeader(set, GENESIS_PREV, 0))!

        const [blockA, blockB] = twoConflictingBlocks(ledger, leader, payloadA, payloadB)

        // keys[0] attests both (equivocator); keys[1] attests A only; keys[2] attests B only.
        const attsA: Attestation[] = [
          ledger.attest(blockA, keys[0]!),
          ledger.attest(blockA, keys[1]!),
        ]
        const attsB: Attestation[] = [
          ledger.attest(blockB, keys[0]!),
          ledger.attest(blockB, keys[2]!),
        ]

        const proofs1 = detectEquivocations(blockA, attsA, blockB, attsB)
        const proofs2 = detectEquivocations(blockA, attsA, blockB, attsB)

        // Same count.
        expect(proofs1.length).toBe(proofs2.length)

        // Same proof content in the same order (structural equality on all fields).
        for (let i = 0; i < proofs1.length; i++) {
          const p1 = proofs1[i]!
          const p2 = proofs2[i]!
          expect(p1.validator).toBe(p2.validator)
          expect(p1.height).toBe(p2.height)
          expect(p1.blockHashA).toBe(p2.blockHashA)
          expect(p1.blockHashB).toBe(p2.blockHashB)
          expect(p1.attA.sig).toStrictEqual(p2.attA.sig)
          expect(p1.attB.sig).toStrictEqual(p2.attB.sig)
        }
      }),
      { numRuns: 50 },
    )
  })
})
