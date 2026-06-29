// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * EVM-native attestation profile (interchain option B). Exercises the TS reference verifier that the
 * Hyperion contract must match: a >2/3 ML-DSA-87 stake quorum over the keccak-reproducible message
 * finalizes; sub-quorum / tampered sig / wrong set / wrong epoch all fail closed (because the setId
 * and message are RECOMPUTED from the trusted set, not trusted from the caller).
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
} from '../src/evmprofile.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const HEIGHT = 7
const HASH = 'cd'.repeat(32)

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
    expect(evmAttestMessage(suite, HEIGHT, HASH, id).length).toBe(32)
  })

  it('a >2/3 stake quorum finalizes (all 4 sign)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH))
    const verdict = verifyEvmFinality(set, atts, suite, HEIGHT, HASH)
    expect(verdict.finalized).toBe(true)
    expect(verdict.attestingStake).toBe(4n)
    expect(verdict.totalStake).toBe(4n)
  })

  it('fail-closed: a sub-2/3 quorum (only 2 of 4 sign) does not finalize', () => {
    const { keys, set } = fixture()
    const atts = keys.slice(0, 2).map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH))
    expect(verifyEvmFinality(set, atts, suite, HEIGHT, HASH).finalized).toBe(false)
  })

  it('fail-closed: a tampered signature is not counted (3 valid of 4, tamper 2 → sub-quorum)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH))
    const bust = (i: number) => {
      const s = Uint8Array.from(atts[i]!.evmSig)
      s[0] = (s[0]! ^ 0xff) & 0xff
      return { ...atts[i]!, evmSig: s }
    }
    const tampered = [bust(0), bust(1), atts[2]!, atts[3]!]
    expect(verifyEvmFinality(set, tampered, suite, HEIGHT, HASH).finalized).toBe(false)
  })

  it('fail-closed: a duplicated signer cannot inflate the quorum', () => {
    const { keys, set } = fixture()
    const one = signEvmAttestation(keys[0]!, set, suite, HEIGHT, HASH)
    // the same validator three times + one other = 2 distinct of 4 stake -> below 2/3
    const other = signEvmAttestation(keys[1]!, set, suite, HEIGHT, HASH)
    expect(verifyEvmFinality(set, [one, one, one, other], suite, HEIGHT, HASH).finalized).toBe(
      false,
    )
  })

  it('fail-closed: signatures made under a DIFFERENT set do not verify (setId is recomputed)', () => {
    const { keys, set } = fixture()
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH))
    const stranger = signerFor(suite).keygen(new Uint8Array(32).fill(99))
    const otherSet: ValidatorSet = {
      validators: [
        ...set.validators,
        { pubkey: bytesToHex(stranger.publicKey), stake: 1n }, // changes the set -> changes evmSetId
      ],
    }
    // The attestations signed under `set` carry a message bound to set's evmSetId; verified against
    // otherSet (different evmSetId) the recomputed message differs and every signature fails.
    expect(verifyEvmFinality(otherSet, atts, suite, HEIGHT, HASH).finalized).toBe(false)
  })

  it('fail-closed: an epoch change flips the setId so prior signatures no longer verify', () => {
    const { keys, set } = fixture(0)
    const atts = keys.map((k) => signEvmAttestation(k, set, suite, HEIGHT, HASH))
    const epoch1: ValidatorSet = { validators: set.validators.map((v) => ({ ...v })), epoch: 1 }
    expect(evmSetId(epoch1)).not.toEqual(evmSetId(set))
    expect(verifyEvmFinality(epoch1, atts, suite, HEIGHT, HASH).finalized).toBe(false)
  })
})
