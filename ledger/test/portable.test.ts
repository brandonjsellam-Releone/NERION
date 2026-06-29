// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Portable PQ finality proof — the cross-chain interop primitive. A proof exported from a finalized
 * block must be verifiable by an INDEPENDENT consumer (its own trusted ValidatorSet), survive a
 * JSON serialize→deserialize round-trip (bytes preserved), and fail closed on tamper / wrong set /
 * epoch mismatch.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  exportFinalityProof,
  verifyPortableFinality,
  serializeFinalityProof,
  deserializeFinalityProof,
} from '../src/index.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5

function fixture(epoch?: number) {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: 4 }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
    ...(epoch !== undefined ? { epoch } : {}),
  }
  const builder = new Ledger(set, suite)
  const prev = builder.headHash()
  const leaderId = selectLeader(set, prev, 0)
  const leaderKey = keys.find((k) => bytesToHex(k.publicKey) === leaderId)!
  const block = builder.propose('ab'.repeat(32), 0, 1000, leaderKey)
  const atts = keys.map((k) => builder.attest(block, k)) // 4/4 stake >= 2/3
  return { keys, set, prev, block, atts }
}

describe('portable PQ finality proof (cross-chain interop primitive)', () => {
  it('an INDEPENDENT verifier (its own trusted set) accepts the exported proof as finalized', () => {
    const { set, block, atts, prev } = fixture()
    const proof = exportFinalityProof(block, atts, prev)
    const trusted: ValidatorSet = { validators: set.validators.map((v) => ({ ...v })) } // fresh object
    const verdict = verifyPortableFinality(proof, trusted)
    expect(verdict.finalized).toBe(true)
    expect(verdict.ok).toBe(true)
  })

  it('survives JSON serialize → deserialize (bytes preserved) and still verifies', () => {
    const { set, block, atts, prev } = fixture()
    const wire = serializeFinalityProof(exportFinalityProof(block, atts, prev))
    expect(typeof wire).toBe('string')
    const back = deserializeFinalityProof(wire)
    expect(back.block.proposerSig).toBeInstanceOf(Uint8Array)
    expect(back.attestations[0]!.sig).toBeInstanceOf(Uint8Array)
    expect(verifyPortableFinality(back, set).finalized).toBe(true)
  })

  it('fail-closed: a tampered block (proposer signature) is rejected — verdict.ok is false', () => {
    const { set, block, atts, prev } = fixture()
    const back = deserializeFinalityProof(
      serializeFinalityProof(exportFinalityProof(block, atts, prev)),
    )
    const sig = Uint8Array.from(back.block.proposerSig)
    sig[0] = (sig[0]! ^ 0xff) & 0xff
    const tampered = { ...back, block: { ...back.block, proposerSig: sig } }
    // A consumer gates on verdict.ok (all checks pass), not just .finalized.
    expect(verifyPortableFinality(tampered, set).ok).toBe(false)
  })

  it('fail-closed: corrupting a 3/4-quorum below 2/3 (two attestations) is not finalized', () => {
    const { set, block, atts, prev } = fixture()
    const back = deserializeFinalityProof(
      serializeFinalityProof(exportFinalityProof(block, atts, prev)),
    )
    const bust = (i: number) => {
      const s = Uint8Array.from(back.attestations[i]!.sig)
      s[0] = (s[0]! ^ 0xff) & 0xff
      return { ...back.attestations[i]!, sig: s }
    }
    const tampered = {
      ...back,
      attestations: [bust(0), bust(1), ...back.attestations.slice(2)], // 2 of 4 invalid -> 2/4 < 2/3
    }
    expect(verifyPortableFinality(tampered, set).finalized).toBe(false)
  })

  it('fail-closed: a different trusted validator set does not finalize', () => {
    const { block, atts, prev } = fixture()
    const proof = exportFinalityProof(block, atts, prev)
    const stranger = signerFor(suite).keygen(new Uint8Array(32).fill(99))
    const wrongSet: ValidatorSet = {
      validators: [{ pubkey: bytesToHex(stranger.publicKey), stake: 1n }],
    }
    expect(verifyPortableFinality(proof, wrongSet).finalized).toBe(false)
  })

  it('fail-closed: an epoch mismatch between proof and trusted set is rejected', () => {
    const { set, block, atts, prev } = fixture(0)
    const proof = exportFinalityProof(block, atts, prev, { epoch: 0 })
    const setEpoch1: ValidatorSet = { validators: set.validators.map((v) => ({ ...v })), epoch: 1 }
    const verdict = verifyPortableFinality(proof, setEpoch1)
    expect(verdict.finalized).toBe(false)
    expect(verdict.reasons.join(' ')).toContain('epoch mismatch')
  })
})
