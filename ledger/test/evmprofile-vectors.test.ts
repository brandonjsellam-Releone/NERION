// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Cross-implementation lock: the EVM-native profile encoding (ledger/src/evmprofile.ts) must keep
 * reproducing the golden vectors in contracts/test/evm-profile-vectors.json — the SAME vectors the
 * Hyperion/Solidity NerionFinalityVerifier is checked against (contracts/test/*.t.sol). If this test
 * breaks, the TS encoding changed and the Solidity contract + its vectors must be regenerated in
 * lock-step, or on-chain verification would silently diverge from off-chain.
 */

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { evmSetId, evmAttestMessage } from '../src/evmprofile.js'
import type { ValidatorSet } from '../src/index.js'

interface VecValidator {
  pubkey: string
  stake: string
  vrfPubkey: string
}
interface Vectors {
  setIdCases: { name: string; epoch: number; validators: VecValidator[]; expectedSetId: string }[]
  messageCases: {
    name: string
    suite: string
    height: number
    blockHash: string
    setId: string
    expectedMessage: string
  }[]
}

const here = dirname(fileURLToPath(import.meta.url))
const vectors = JSON.parse(
  readFileSync(join(here, '../../contracts/test/evm-profile-vectors.json'), 'utf8'),
) as Vectors

describe('EVM-profile cross-implementation golden vectors', () => {
  it('evmSetId reproduces every committed setId vector', () => {
    for (const c of vectors.setIdCases) {
      const set: ValidatorSet = {
        validators: c.validators.map((v) => ({
          pubkey: v.pubkey,
          stake: BigInt(v.stake),
          ...(v.vrfPubkey ? { vrfPubkey: v.vrfPubkey } : {}),
        })),
        epoch: c.epoch,
      }
      expect(bytesToHex(evmSetId(set))).toBe(c.expectedSetId)
    }
  })

  it('evmAttestMessage reproduces every committed message vector', () => {
    for (const c of vectors.messageCases) {
      const got = bytesToHex(evmAttestMessage(c.suite, c.height, c.blockHash, hexToBytes(c.setId)))
      expect(got).toBe(c.expectedMessage)
    }
  })
})
