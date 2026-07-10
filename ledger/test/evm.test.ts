// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * NATIVE-profile relayer/inspection packer — packages a portable finality proof into a 0x-hex view
 * under Nerion's NATIVE (dCBOR/SHAKE256) domain. Asserts the emitted setId + per-attestation
 * messages are exactly Nerion's own consensusSetId / attestMessage, all hex is 0x-prefixed, and
 * stray attestations are filtered out.
 *
 * PARITY-002: this is NOT the encoder for contracts/NerionFinalityVerifier.sol (that contract
 * recomputes a keccak256 profile via ledger/src/evmprofile.ts, tested separately in
 * evmprofile.test.ts) — see ledger/src/evm.ts's module docstring for the full explanation.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  blockHash,
  consensusSetId,
  exportFinalityProof,
  finalityProofToEvmInput,
} from '../src/index.js'
import { attestMessage } from '../src/chain.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5

function fixture() {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: 4 }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
  }
  const builder = new Ledger(set, suite)
  const prev = builder.headHash()
  const leaderId = selectLeader(set, prev, 0)
  const leaderKey = keys.find((k) => bytesToHex(k.publicKey) === leaderId)!
  const block = builder.propose('ab'.repeat(32), 0, 1000, leaderKey)
  const atts = keys.map((k) => builder.attest(block, k))
  return { keys, set, prev, block, atts }
}

describe('EVM/QRL-Zond interchain encoder', () => {
  it('encodes the proof with setId + messages exactly matching Nerion consensusSetId / attestMessage', () => {
    const { set, block, atts, prev } = fixture()
    const input = finalityProofToEvmInput(exportFinalityProof(block, atts, prev), set)
    expect(input.tag).toBe('polarseek-attest-v2')
    expect(input.suite).toBe(suite)
    expect(input.height).toBe(0)
    expect(input.blockHash).toBe(`0x${blockHash(block.header)}`)
    expect(input.setId).toBe(`0x${consensusSetId(set)}`)
    expect(input.validators.length).toBe(4)
    expect(input.validators[0]!.stake).toBe('1')
    expect(input.attestations.length).toBe(4)
    const expectedMsg = `0x${bytesToHex(attestMessage(suite, 0, blockHash(block.header), consensusSetId(set)))}`
    for (const a of input.attestations) {
      expect(a.message).toBe(expectedMsg)
      expect(a.sig.startsWith('0x')).toBe(true)
      expect(a.validator.startsWith('0x')).toBe(true)
    }
  })

  it('all hex fields are 0x-prefixed and stripping recovers the Nerion hex', () => {
    const { set, block, atts, prev } = fixture()
    const input = finalityProofToEvmInput(exportFinalityProof(block, atts, prev), set)
    expect(input.setId.slice(2)).toBe(consensusSetId(set))
    expect(input.validators[0]!.pubkey.slice(2)).toBe(set.validators[0]!.pubkey)
  })

  it('only includes attestations for THIS block (filters stray entries)', () => {
    const { set, block, atts, prev } = fixture()
    const stray = { ...atts[0]!, blockHash: 'ff'.repeat(32) }
    const input = finalityProofToEvmInput(exportFinalityProof(block, [...atts, stray], prev), set)
    expect(input.attestations.length).toBe(4) // the stray (wrong blockHash) is excluded
  })
})
