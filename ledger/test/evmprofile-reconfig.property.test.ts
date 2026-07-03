// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Property test (AAC Campaign #1 hypothesis 4.4): cross-epoch / set-substitution resistance of the
 * EVM-native interchain attestation profile, under RANDOMIZED reconfigurations. Because the on-chain
 * verifier RECOMPUTES the setId (which folds members + stake + epoch) and requires each signature to
 * be over the message bound to THAT setId, an attestation gathered under validator set S(epoch e)
 * must NEVER count as finality under any set S' with a different setId — no matter how S' differs
 * (added/removed/reweighted member, or a re-epoch). This is the ADR-0020/B5 binding, fuzzed against
 * the real signing + verification path (not just the fixed cases in evmprofile.test.ts).
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { evmSetId, signEvmAttestation, verifyEvmFinality } from '../src/evmprofile.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const HEIGHT = 11
const HASH = 'ab'.repeat(32)
const signer = signerFor(suite)

// Deterministic keys by seed byte (kept in a cache so property runs don't re-keygen the same seed).
const keyCache = new Map<number, ReturnType<typeof signer.keygen>>()
function keyFor(seed: number) {
  let k = keyCache.get(seed)
  if (!k) {
    k = signer.keygen(new Uint8Array(32).fill(seed))
    keyCache.set(seed, k)
  }
  return k
}

const setIdHex = (s: ValidatorSet) => bytesToHex(evmSetId(s))

describe('EVM-profile — cross-epoch / set-substitution resistance (property)', () => {
  it('a full quorum finalizes under its OWN set, and NEVER under any differently-identified set', () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(fc.integer({ min: 1, max: 60 }), { minLength: 2, maxLength: 5 }),
        fc.integer({ min: 0, max: 6 }), // epoch of S
        fc.integer({ min: 0, max: 6 }), // epoch of S'
        fc.integer({ min: 0, max: 3 }), // mutation kind
        fc.integer({ min: 61, max: 90 }), // stranger seed (disjoint from member seeds)
        (seeds, epochS, epochSp, mut, strangerSeed) => {
          const keys = seeds.map(keyFor)
          const S: ValidatorSet = {
            validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
            epoch: epochS,
          }
          // Every member co-signs the EVM profile for this block under S.
          const atts = keys.map((k) => signEvmAttestation(k, S, suite, HEIGHT, HASH))

          // Positive control: the quorum finalizes under its own set.
          if (!verifyEvmFinality(S, atts, suite, HEIGHT, HASH).finalized) return false

          // Build S' by a reconfiguration that changes the set identity.
          let SpVals = S.validators.map((v) => ({ ...v }))
          switch (mut) {
            case 0: // add a stranger
              SpVals = [
                ...SpVals,
                { pubkey: bytesToHex(keyFor(strangerSeed).publicKey), stake: 1n },
              ]
              break
            case 1: // remove one member (only if >2 remain)
              if (SpVals.length > 2) SpVals = SpVals.slice(1)
              break
            case 2: // reweight one member
              SpVals[0] = { ...SpVals[0]!, stake: SpVals[0]!.stake + 1n }
              break
            case 3: // membership unchanged; rely on the epoch differing
              break
          }
          const Sp: ValidatorSet = { validators: SpVals, epoch: epochSp }

          // If the reconfiguration produced an identical set identity, the binding says nothing —
          // skip (a genuine no-op, e.g. mut=3 with epochSp===epochS).
          if (setIdHex(Sp) === setIdHex(S)) return true

          // The invariant: signatures bound to S's setId cannot manufacture finality under S'.
          return verifyEvmFinality(Sp, atts, suite, HEIGHT, HASH).finalized === false
        },
      ),
      { numRuns: 25 },
    )
    expect(true).toBe(true)
  })
})
