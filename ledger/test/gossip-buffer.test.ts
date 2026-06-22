// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import { GossipBus, GossipNode, Ledger, blockHash, selectLeader } from '../src/index.js'
import type { ValidatorSet } from '../src/index.js'

/**
 * GOSSIP-BUFFER-001 (Team Apex, 2026-06-21). The future-block buffer caps the
 * height RANGE (+64) but previously did NOT cap the COUNT of distinct blocks an
 * adversary could flood at a single future height — each unique hash was buffered
 * (and re-flooded) without verification, an unbounded-memory / amplification vector.
 * A per-height cap (MAX_PENDING_PER_HEIGHT = 64) now bounds it; honest catch-up
 * (a few blocks/height) is unaffected.
 */
const suite = SUITE_IDS.PS_5
const N = 4
const CAP = 64 // MAX_PENDING_PER_HEIGHT in gossip.ts

function fixture() {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: N }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1n })),
  }
  return { keys, set }
}

describe('gossip future-buffer DoS bound (GOSSIP-BUFFER-001)', () => {
  it('caps distinct buffered blocks per future height, yet still catches up', () => {
    const { keys, set } = fixture()

    // Build + finalize block 0 in a builder ledger so we can mint many height-1 blocks.
    const L = new Ledger(set, suite)
    const leader0 = selectLeader(set, L.headHash(), 0)
    const leader0Key = keys.find((k) => bytesToHex(k.publicKey) === leader0)!
    const b0 = L.propose('root0', 0, 1, leader0Key)
    const atts0 = keys.map((k) => L.attest(b0, k))
    L.submit(b0, atts0) // L now at height 1
    const leader1 = selectLeader(set, blockHash(b0.header), 0)
    const leader1Key = keys.find((k) => bytesToHex(k.publicKey) === leader1)!

    // Mint CAP + 6 DISTINCT height-1 blocks (distinct payloadRoot -> distinct hash).
    const flood = Array.from({ length: CAP + 6 }, (_, i) =>
      L.propose(`flood-${i}`, 0, 1, leader1Key),
    )

    // A fresh node at height 0 is flooded with all of them (all future -> buffered).
    const bus = new GossipBus()
    const node = new GossipNode(keys[0]!, set, suite, bus)
    for (const b of flood) bus.broadcast('attacker', { kind: 'block', block: b })
    bus.run()

    expect(node.height()).toBe(0) // none applied early
    expect(node.pendingBlockCount()).toBe(CAP) // bounded, NOT CAP+6

    // Liveness preserved: delivering block 0 + its attestations lets the node finalize it.
    bus.broadcast('net', { kind: 'block', block: b0 })
    for (const a of atts0) bus.broadcast('net', { kind: 'attestation', attestation: a })
    bus.run()
    expect(node.height()).toBe(1)
    expect(node.hasFinalized(blockHash(b0.header))).toBe(true)
  })
})
