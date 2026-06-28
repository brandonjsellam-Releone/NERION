// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  Ledger,
  verifyFinalized,
  blockHash,
  GENESIS_PREV,
  vrfPublicKey,
  vrfAlpha,
  vrfLeaderEligible,
  prove,
  viewChangeMessage,
  verifyViewChangeCert,
  consensusSetId,
} from '../src/index.js'
import type { ValidatorSet, TimeoutVote, ViewChangeCert } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)

const validator = (idSeed: number, vrfSeed: number, stake: bigint) => {
  const kp = signer.keygen(new Uint8Array(32).fill(idSeed))
  const seed = new Uint8Array(32).fill(vrfSeed)
  return {
    kp,
    seed,
    record: { pubkey: bytesToHex(kp.publicKey), vrfPubkey: bytesToHex(vrfPublicKey(seed)), stake },
  }
}

describe('VRF-mode ledger (ADR-0004)', () => {
  it('proposes, attests, and finalizes a VRF block; a light client verifies it', () => {
    const v = validator(1, 50, 1n) // single validator → always eligible (β mod 1 = 0)
    const set: ValidatorSet = { validators: [v.record] }
    const ledger = new Ledger(set, suite)
    const block = ledger.proposeVrf('deadbeefroot', 0, 1000, v.kp, v.seed)
    expect(block.vrfProof).toBeDefined()
    expect(block.header.vrfOutput).toBeDefined()
    const att = ledger.attest(block, v.kp)
    expect(ledger.submit(block, [att]).finalized).toBe(true)
    const verdict = verifyFinalized(block, [att], set, GENESIS_PREV)
    expect(verdict.ok && verdict.finalized).toBe(true)
  })

  it('rejects a wrong VRF key and a tampered vrfOutput', () => {
    const v = validator(2, 60, 1n)
    const set: ValidatorSet = { validators: [v.record] }
    const ledger = new Ledger(set, suite)
    const block = ledger.proposeVrf('caferoot', 0, 1, v.kp, v.seed)
    const att = ledger.attest(block, v.kp)

    const wrongSet: ValidatorSet = {
      validators: [
        { ...v.record, vrfPubkey: bytesToHex(vrfPublicKey(new Uint8Array(32).fill(61))) },
      ],
    }
    expect(
      verifyFinalized(block, [att], wrongSet, GENESIS_PREV).reasons.some((r) =>
        r.includes('VRF proof is invalid'),
      ),
    ).toBe(true)

    const tampered = { ...block, header: { ...block.header, vrfOutput: 'ff'.repeat(64) } }
    expect(verifyFinalized(tampered, [att], set, GENESIS_PREV).ok).toBe(false)
  })

  it('round > 0 needs a 2/3 view-change cert; a valid cert admits the block', () => {
    const v = validator(3, 70, 1n)
    const set: ValidatorSet = { validators: [v.record] }
    const ledger = new Ledger(set, suite)

    const vote: TimeoutVote = {
      height: 0,
      prevHash: GENESIS_PREV,
      round: 0,
      validator: v.record.pubkey,
      suite,
      sig: signer.sign(
        viewChangeMessage(suite, 0, GENESIS_PREV, 0, consensusSetId(set)),
        v.kp.secretKey,
      ),
    }
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, GENESIS_PREV, 0, cert)).toBe(true)

    // proposeVrf self-validates the cert for round > 0 (mirrors propose's leader check).
    expect(() => ledger.proposeVrf('aa', 1, 1, v.kp, v.seed)).toThrow(/view-change/)

    const withCert = ledger.proposeVrf('aa', 1, 1, v.kp, v.seed, cert)
    // the same block without the cert → verifyFinalized rejects (round > 0 needs one).
    const noCert = {
      header: withCert.header,
      proposerSig: withCert.proposerSig,
      suite: withCert.suite,
      vrfProof: withCert.vrfProof as Uint8Array,
    }
    expect(
      verifyFinalized(noCert, [], set, GENESIS_PREV).reasons.some((r) => r.includes('view-change')),
    ).toBe(true)
    const att = ledger.attest(withCert, v.kp)
    const verdict = verifyFinalized(withCert, [att], set, GENESIS_PREV)
    expect(verdict.ok && verdict.finalized).toBe(true)
  })

  it('an ineligible proposer cannot propose', () => {
    const low = validator(40, 90, 1n) // stake 1 of 100 → eligible only ~1% of draws
    const high = validator(41, 91, 99n)
    // β is deterministic per seed, so find a vrf seed where `low` is NOT eligible.
    let foundIneligible = false
    for (let i = 0; i < 20 && !foundIneligible; i++) {
      const seed = new Uint8Array(32).fill(200 + i)
      const set: ValidatorSet = {
        validators: [{ ...low.record, vrfPubkey: bytesToHex(vrfPublicKey(seed)) }, high.record],
      }
      const beta = prove(seed, vrfAlpha(GENESIS_PREV, 0)).beta
      if (!vrfLeaderEligible(set, low.record.pubkey, beta)) {
        foundIneligible = true
        const ledger = new Ledger(set, suite)
        expect(() => ledger.proposeVrf('x', 0, 1, low.kp, seed)).toThrow(/not VRF-eligible/)
      }
    }
    expect(foundIneligible).toBe(true)
  })

  it('rejects a downgrade: a proof-less legacy block in a VRF validator set', () => {
    const v = validator(5, 55, 1n)
    const set: ValidatorSet = { validators: [v.record] } // VRF-mode (has vrfPubkey)
    const ledger = new Ledger(set, suite)
    const legacy = ledger.propose('x', 0, 1, v.kp) // deprecated path → no vrfProof
    const att = ledger.attest(legacy, v.kp)
    const verdict = verifyFinalized(legacy, [att], set, GENESIS_PREV)
    expect(verdict.ok).toBe(false) // rejected (ok=false); submit() would throw
    expect(verdict.reasons.some((r) => r.includes('VRF-mode'))).toBe(true)
  })

  it('rejects a VRF block presented to a legacy (no-VRF-key) validator set', () => {
    const v = validator(6, 56, 1n)
    const vrfSet: ValidatorSet = { validators: [v.record] }
    const block = new Ledger(vrfSet, suite).proposeVrf('y', 0, 1, v.kp, v.seed) // has vrfProof
    const legacySet: ValidatorSet = { validators: [{ pubkey: v.record.pubkey, stake: 1n }] }
    const att = new Ledger(legacySet, suite).attest(block, v.kp)
    const verdict = verifyFinalized(block, [att], legacySet, GENESIS_PREV)
    expect(verdict.ok).toBe(false) // rejected (ok=false); submit() would throw
    expect(verdict.reasons.some((r) => r.includes('no VRF keys'))).toBe(true)
  })

  it('a VRF block and a legacy block with identical fields hash differently (β committed)', () => {
    const v = validator(7, 57, 1n)
    const vrfSet: ValidatorSet = { validators: [v.record] }
    const legacySet: ValidatorSet = { validators: [{ pubkey: v.record.pubkey, stake: 1n }] }
    const vrfBlock = new Ledger(vrfSet, suite).proposeVrf('same', 0, 5, v.kp, v.seed)
    const legacyBlock = new Ledger(legacySet, suite).propose('same', 0, 5, v.kp)
    expect(blockHash(vrfBlock.header)).not.toBe(blockHash(legacyBlock.header))
    // the legacy block still round-trips after the headerBytes schema change
    const ledger = new Ledger(legacySet, suite)
    expect(
      verifyFinalized(legacyBlock, [ledger.attest(legacyBlock, v.kp)], legacySet, GENESIS_PREV).ok,
    ).toBe(true)
  })

  it('finalizes a round>0 VRF block at a real (non-genesis) head via Ledger.submit()', () => {
    const v = validator(8, 58, 1n)
    const set: ValidatorSet = { validators: [v.record] }
    const ledger = new Ledger(set, suite)
    const b0 = ledger.proposeVrf('h0', 0, 1, v.kp, v.seed)
    ledger.submit(b0, [ledger.attest(b0, v.kp)])
    expect(ledger.height()).toBe(1)
    const head = ledger.headHash()

    const vote: TimeoutVote = {
      height: 1,
      prevHash: head,
      round: 0,
      validator: v.record.pubkey,
      suite,
      sig: signer.sign(viewChangeMessage(suite, 1, head, 0, consensusSetId(set)), v.kp.secretKey),
    }
    const b1 = ledger.proposeVrf('h1', 1, 2, v.kp, v.seed, { round: 0, votes: [vote] })
    expect(ledger.submit(b1, [ledger.attest(b1, v.kp)]).finalized).toBe(true)
    expect(ledger.height()).toBe(2)

    // a cert bound to genesis (wrong prevHash for this head) is rejected at propose.
    const wrong: TimeoutVote = {
      height: 2,
      prevHash: GENESIS_PREV,
      round: 0,
      validator: v.record.pubkey,
      suite,
      sig: signer.sign(
        viewChangeMessage(suite, 2, GENESIS_PREV, 0, consensusSetId(set)),
        v.kp.secretKey,
      ),
    }
    expect(() => ledger.proposeVrf('h2', 1, 3, v.kp, v.seed, { round: 0, votes: [wrong] })).toThrow(
      /view-change/,
    )
  })
})
