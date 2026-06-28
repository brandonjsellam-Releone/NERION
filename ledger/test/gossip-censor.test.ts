// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOSSIP-CENSOR-002 (Team Apex max sweep 2026-06-28) — a single staked validator must not be able
 * to CENSOR finalization by exhausting the attestation pool's hash-slots.
 *
 * The attack: the GOSSIP-CENSOR-001 ingress check pools only attestations a real staked validator
 * signed, but a single staked validator can still self-sign VALID attestations for many distinct
 * GARBAGE blockHashes. Before the per-validator cap, those occupied every global slot
 * (MAX_ATTESTED_HASHES), so the genuine block's hash was dropped at the global cap and never
 * finalized — censorship by a minority staked validator, network-wide. The per-validator
 * distinct-hash cap bounds any one validator's footprint, so the genuine block always gets pooled.
 *
 * (This replaces an unverified scratch repro left by a session-limited sweep; the bug it described
 * is real — confirmed empirically — and is fixed here.)
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import { GossipBus, GossipNode, Ledger, blockHash, selectLeader } from '../src/index.js'
import { attestMessage } from '../src/chain.js'
import { consensusSetId } from '../src/sortition.js'
import type { ValidatorSet, Attestation } from '../src/index.js'

const suite = SUITE_IDS.PS_5

describe('GOSSIP-CENSOR-002: one staked validator cannot censor finalization by hash-slot exhaustion', () => {
  it('the genuine block still finalizes despite a garbage-hash attestation flood from one validator', () => {
    const signer = signerFor(suite)
    const keys: KeyPair[] = Array.from({ length: 4 }, (_, i) =>
      signer.keygen(new Uint8Array(32).fill(i + 1)),
    )
    const set: ValidatorSet = {
      validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
    }
    const bus = new GossipBus()
    const node = new GossipNode(keys[0]!, set, suite, bus)

    // Attacker = one staked validator floods VALID attestations for many distinct garbage hashes at
    // the live height. 200 > the per-validator cap (2*64), so the cap bounds its pooled footprint.
    const attacker = keys[3]!
    const attackerHex = bytesToHex(attacker.publicKey)
    const setId = consensusSetId(set)
    for (let i = 0; i < 200; i++) {
      const fakeHash = i.toString(16).padStart(64, '0')
      const sig = signer.sign(attestMessage(suite, 0, fakeHash, setId), attacker.secretKey)
      const att: Attestation = {
        blockHash: fakeHash,
        height: 0,
        validator: attackerHex,
        suite,
        sig,
      }
      bus.broadcast('attacker', { kind: 'attestation', attestation: att })
    }
    bus.run()

    // The genuine block + an honest 3/4-stake quorum.
    const builder = new Ledger(set, suite)
    const leaderId = selectLeader(set, builder.headHash(), 0)
    const leaderKey = keys.find((k) => bytesToHex(k.publicKey) === leaderId)!
    const block = builder.propose('genuineroot', 0, 1000, leaderKey)
    const hash = blockHash(block.header)
    const honestAtts = keys.slice(0, 3).map((k) => builder.attest(block, k)) // 3/4 stake >= 2/3
    bus.broadcast('proposer', { kind: 'block', block })
    for (const a of honestAtts) bus.broadcast('honest', { kind: 'attestation', attestation: a })
    bus.run()

    // Not censored: the honest quorum's attestations were pooled and the block finalized.
    expect(node.hasFinalized(hash)).toBe(true)
  })
})
