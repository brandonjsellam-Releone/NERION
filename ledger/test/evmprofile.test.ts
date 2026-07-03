// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * EVM-native attestation profile (interchain option B). Exercises the TS reference verifier that the
 * Hyperion contract must match: a ≥2/3 ML-DSA-87 stake quorum over the keccak-reproducible message
 * finalizes; sub-quorum / tampered sig / wrong set / wrong epoch / wrong destination all fail closed
 * (because the setId, message, chainId, and verifier are RECOMPUTED / bound, not trusted from the
 * caller). The AAC-Campaign-#1 hardening cases assert verifyEvmFinality FAILS CLOSED (never throws)
 * on malformed input, that the destination binding blocks cross-chain replay, and that a
 * duplicate-pubkey set can not inflate the stake denominator.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import {
  evmSetId,
  evmAttestMessage,
  signEvmAttestation,
  verifyEvmFinality,
  type EvmTarget,
} from '../src/evmprofile.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const HEIGHT = 7
const HASH = 'cd'.repeat(32)
const TARGET: EvmTarget = { chainId: 8888n, verifier: 'c0'.repeat(20) }

function fixture(epoch?: number) {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: 4 }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
    ...(epoch !== undefined ? { epoch } : {}),
  }
  return { keys, set }
}

describe('EVM-native attestation profile (interchain option B)', () => {
  it('encodings are deterministic 32-byte commitments', () => {
    const { set } = fixture()
    const id = evmSetId(set)
    expect(id.length).toBe(32)
    expect(bytesToHex(evmSetId(set))).toBe(bytesToHex(id)) // deterministic
    expect(evmAttestMessage(suite, HEIGHT, HASH, id, TARGET).length).toBe(32)
  })

  it('a ≥2/3 stake quorum finalizes (all 4 sign)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const verdict = verifyEvmFinality(set, atts, suite, HEIGHT, HASH, TARGET)
    expect(verdict.finalized).toBe(true)
    expect(verdict.attestingStake).toBe(4n)
    expect(verdict.totalStake).toBe(4n)
  })

  it('fail-closed: a sub-2/3 quorum (only 2 of 4 sign) does not finalize', () => {
    const { keys, set } = fixture()
    const atts = keys
      .slice(0, 2)
      .map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  it('fail-closed: a tampered signature is not counted (tamper 2 of 4 → sub-quorum)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const bust = (i: number) => {
      const s = Uint8Array.from(atts[i]!.evmSig)
      s[0] = (s[0]! ^ 0xff) & 0xff
      return { ...atts[i]!, evmSig: s }
    }
    const tampered = [bust(0), bust(1), atts[2]!, atts[3]!]
    expect(verifyEvmFinality(set, tampered, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  it('fail-closed: a duplicated signer cannot inflate the quorum', () => {
    const { keys, set } = fixture()
    const one = signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH, TARGET)
    const other = signEvmAttestation(keys[1]!, set, suite, HEIGHT, HASH, TARGET)
    // same validator three times + one other = 2 distinct of 4 stake -> below 2/3
    expect(
      verifyEvmFinality(set, [one, one, one, other], suite, HEIGHT, HASH, TARGET).finalized,
    ).toBe(false)
  })

  it('fail-closed: signatures made under a DIFFERENT set do not verify (setId is recomputed)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const stranger = signerFor(suite).keygen(new Uint8Array(32).fill(99))
    const otherSet: ValidatorSet = {
      validators: [...set.validators, { pubkey: bytesToHex(stranger.publicKey), stake: 1n }],
    }
    expect(verifyEvmFinality(otherSet, atts, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  it('fail-closed: an epoch change flips the setId so prior signatures no longer verify', () => {
    const { keys, set } = fixture(0)
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const epoch1: ValidatorSet = { validators: set.validators.map((v) => ({ ...v })), epoch: 1 }
    expect(evmSetId(epoch1)).not.toEqual(evmSetId(set))
    expect(verifyEvmFinality(epoch1, atts, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  // --- AAC Campaign #1 hardening (council + adversarial review converged) ---

  it('cross-chain replay: a proof bound to chainId A does NOT finalize under chainId B', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const otherChain: EvmTarget = { chainId: 9999n, verifier: TARGET.verifier }
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, HASH, otherChain).finalized).toBe(false)
  })

  it('cross-deployment replay: a proof bound to verifier A does NOT finalize under verifier B', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const otherVerifier: EvmTarget = { chainId: TARGET.chainId, verifier: 'ab'.repeat(20) }
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, HASH, otherVerifier).finalized).toBe(false)
  })

  it('fail-closed (no throw): a non-32-byte blockHash returns finalized:false', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    expect(() => verifyEvmFinality(set, atts, suite, HEIGHT, 'cd'.repeat(31), TARGET)).not.toThrow()
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, 'cd'.repeat(31), TARGET).finalized).toBe(
      false,
    )
  })

  it('fail-closed (no throw): a non-integer / negative height returns finalized:false', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    for (const bad of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() => verifyEvmFinality(set, atts, suite, bad, HASH, TARGET)).not.toThrow()
      expect(verifyEvmFinality(set, atts, suite, bad, HASH, TARGET).finalized).toBe(false)
    }
  })

  it('fail-closed (no throw): a malformed member pubkey returns finalized:false', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const badSet: ValidatorSet = {
      validators: [...set.validators, { pubkey: 'zz', stake: 1n }], // non-hex
    }
    expect(() => verifyEvmFinality(badSet, atts, suite, HEIGHT, HASH, TARGET)).not.toThrow()
    expect(verifyEvmFinality(badSet, atts, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  it('fail-closed (no throw): a chainId ≥ 2^256 returns finalized:false (u256 overflow guard)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    const overflow: EvmTarget = { chainId: 1n << 256n, verifier: TARGET.verifier }
    expect(() => verifyEvmFinality(set, atts, suite, HEIGHT, HASH, overflow)).not.toThrow()
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, HASH, overflow).finalized).toBe(false)
  })

  it('fail-closed: a duplicate-pubkey set cannot inflate the stake denominator', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH, TARGET))
    // Duplicate an honest member: raw total would be 5, but the set is non-canonical → rejected.
    const dupSet: ValidatorSet = {
      validators: [...set.validators, { pubkey: set.validators[0]!.pubkey, stake: 1n }],
    }
    expect(() => verifyEvmFinality(dupSet, atts, suite, HEIGHT, HASH, TARGET)).not.toThrow()
    expect(verifyEvmFinality(dupSet, atts, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
    // evmSetId on the sign path throws loudly (validator misconfiguration).
    expect(() => evmSetId(dupSet)).toThrow(/duplicate pubkey/)
  })

  it('fail-closed: more than the attestation cap returns finalized:false without verifying', () => {
    const { keys, set } = fixture()
    const one = signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH, TARGET)
    const flood = Array.from({ length: 8193 }, () => one) // > MAX_ATTESTATIONS
    expect(verifyEvmFinality(set, flood, suite, HEIGHT, HASH, TARGET).finalized).toBe(false)
  })

  it('validator-set order does not matter: setId is canonical (sorted by decoded pubkey bytes)', () => {
    const { set } = fixture()
    const reversed: ValidatorSet = { validators: [...set.validators].reverse() }
    expect(bytesToHex(evmSetId(reversed))).toBe(bytesToHex(evmSetId(set)))
  })
})
