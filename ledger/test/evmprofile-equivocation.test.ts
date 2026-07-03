// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Interchain accountable safety (LEDGER-EVM-ACCT-001, AAC cycle-7): a validator that co-signs
 * conflicting EVM-profile attestations for two distinct blocks at the SAME height is caught + slashable,
 * matching the native ledger equivocation semantics (same-height double-sign; honest cross-height is
 * NOT slashable — LEDGER-EQUIV-001). No `round` is used because Nerion attestations are one-per-height.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  signEvmAttestation,
  detectEvmEquivocations,
  verifyEvmEquivocationProof,
  type EvmTarget,
} from '../src/evmprofile.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const HEIGHT = 9
const HASH_A = 'aa'.repeat(32)
const HASH_B = 'bb'.repeat(32)
const TARGET: EvmTarget = { chainId: 8888n, verifier: 'c0'.repeat(20) }

function fixture() {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: 4 }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
  }
  return { keys, set }
}

describe('EVM-profile equivocation (interchain accountable safety)', () => {
  it('detects a validator who co-signed two distinct blocks at the same height', () => {
    const { keys, set } = fixture()
    // keys[0] equivocates: signs BOTH hashA and hashB at HEIGHT. keys[1]/keys[2] each sign one.
    const attsA = [
      signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH_A, TARGET),
      signEvmAttestation(keys[1]!, set, suite, HEIGHT, HASH_A, TARGET),
    ]
    const attsB = [
      signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH_B, TARGET), // the equivocation
      signEvmAttestation(keys[2]!, set, suite, HEIGHT, HASH_B, TARGET),
    ]
    const proofs = detectEvmEquivocations(set, suite, HEIGHT, TARGET, HASH_A, attsA, HASH_B, attsB)
    expect(proofs).toHaveLength(1)
    expect(proofs[0]!.validator).toBe(bytesToHex(keys[0]!.publicKey))
    expect(verifyEvmEquivocationProof(proofs[0]!, set, suite, TARGET)).toBe(true)
  })

  it('does NOT flag an honest validator who signed only one block', () => {
    const { keys, set } = fixture()
    const attsA = [signEvmAttestation(keys[1]!, set, suite, HEIGHT, HASH_A, TARGET)]
    const attsB = [signEvmAttestation(keys[2]!, set, suite, HEIGHT, HASH_B, TARGET)]
    expect(
      detectEvmEquivocations(set, suite, HEIGHT, TARGET, HASH_A, attsA, HASH_B, attsB),
    ).toHaveLength(0)
  })

  it('verifyEvmEquivocationProof rejects a same-block proof, a non-member, and a wrong-set proof', () => {
    const { keys, set } = fixture()
    const attsA = [signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH_A, TARGET)]
    const attsB = [signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH_B, TARGET)]
    const proof = detectEvmEquivocations(
      set,
      suite,
      HEIGHT,
      TARGET,
      HASH_A,
      attsA,
      HASH_B,
      attsB,
    )[0]!
    expect(verifyEvmEquivocationProof(proof, set, suite, TARGET)).toBe(true)
    // Same block on both sides is not equivocation.
    expect(
      verifyEvmEquivocationProof({ ...proof, blockHashB: proof.blockHashA }, set, suite, TARGET),
    ).toBe(false)
    // A different set → different evmSetId → the recomputed messages differ → the sigs fail (stale
    // cross-epoch/set proofs are rejected; slashing is scoped to the set the double-sign occurred in).
    const stranger = signerFor(suite).keygen(new Uint8Array(32).fill(99))
    const otherSet: ValidatorSet = {
      validators: [...set.validators, { pubkey: bytesToHex(stranger.publicKey), stake: 1n }],
    }
    expect(verifyEvmEquivocationProof(proof, otherSet, suite, TARGET)).toBe(false)
    // A non-member validator named in the proof is rejected (no stake in the trusted set).
    expect(
      verifyEvmEquivocationProof(
        { ...proof, validator: bytesToHex(stranger.publicKey) },
        set,
        suite,
        TARGET,
      ),
    ).toBe(false)
  })

  it('does NOT flag honest cross-HEIGHT signing (each proof pins one height; LEDGER-EQUIV-001 parity)', () => {
    const { keys, set } = fixture()
    // keys[0] signs hashA at HEIGHT and hashB at HEIGHT+1 — honest one-block-per-height, not equivocation.
    const attsA = [signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH_A, TARGET)]
    const attsBnext = [signEvmAttestation(keys[0]!, set, suite, HEIGHT + 1, HASH_B, TARGET)]
    // The detector pins ONE height; the height-(H+1) attestation does not verify under HEIGHT's message.
    expect(
      detectEvmEquivocations(set, suite, HEIGHT, TARGET, HASH_A, attsA, HASH_B, attsBnext),
    ).toHaveLength(0)
  })
})
