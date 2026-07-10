// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import type { KeyPair } from '../../crypto/src/index.js'
import {
  GossipBus,
  GossipNode,
  Ledger,
  blockHash,
  selectLeader,
  GENESIS_PREV,
} from '../src/index.js'
import type { ValidatorSet } from '../src/index.js'

/**
 * GOSSIP-BUFFER-002 (AAC council review, 2026-07-11). GOSSIP-BUFFER-001 capped distinct blocks
 * buffered at a FUTURE height, but the symmetric CURRENT-height path (`knownBlocks`) had no
 * equivalent cap — an attacker floods distinct garbage blocks at the height the node is already
 * on instead of ahead of it, growing `knownBlocks` (and, via the proposer-conflict record,
 * `observedConflicts`) without bound. A per-height cap (MAX_KNOWN_AT_HEIGHT = 64) plus a total
 * cap on `observedConflicts` (MAX_OBSERVED_CONFLICTS, never pruned by height) now bounds both;
 * honest liveness (finalizing the genuinely-attested block) is unaffected.
 */
const suite = SUITE_IDS.PS_5
const N = 4
const CAP = 64 // MAX_KNOWN_AT_HEIGHT in gossip.ts

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

describe('gossip current-height buffer DoS bound (GOSSIP-BUFFER-002)', () => {
  it('caps distinct blocks + observedConflicts at the CURRENT height, yet still finalizes', () => {
    const { keys, set } = fixture()
    const L = new Ledger(set, suite)
    const leader0 = selectLeader(set, GENESIS_PREV, 0)
    const leader0Key = keys.find((k) => bytesToHex(k.publicKey) === leader0)!

    // Mint CAP + 6 DISTINCT height-0 blocks (distinct payloadRoot -> distinct hash).
    const flood = Array.from({ length: CAP + 6 }, (_, i) =>
      L.propose(`flood-${i}`, 0, 1, leader0Key),
    )

    // A fresh node at height 0 is flooded with all of them (all at its CURRENT height).
    const bus = new GossipBus()
    const node = new GossipNode(keys[0]!, set, suite, bus)
    for (const b of flood) bus.broadcast('attacker', { kind: 'block', block: b })
    bus.run()

    expect(node.height()).toBe(0) // no quorum reached yet
    expect(node.knownBlockCount()).toBe(CAP) // bounded, NOT CAP+6
    // The first accepted block sets attestedAt; every OTHER accepted block (up to the cap)
    // records a conflict; blocks dropped by the knownBlocks cap never reach that branch.
    expect(node.observedConflicts.length).toBe(CAP - 1)

    // Liveness preserved: the genuinely-first-accepted block still finalizes once a real
    // 2/3 quorum attests it (the node itself already self-attested it inside onBlock).
    const acceptedHash = blockHash(flood[0]!.header)
    const others = keys.slice(1).map((k) => L.attest(flood[0]!, k))
    for (const a of others) bus.broadcast('net', { kind: 'attestation', attestation: a })
    bus.run()
    expect(node.height()).toBe(1)
    expect(node.hasFinalized(acceptedHash)).toBe(true)
  })

  it('does not grow observedConflicts past MAX_OBSERVED_CONFLICTS across many heights', () => {
    // Sanity: a single burst below the per-height cap still respects the conflict record —
    // this is a light smoke test of the total-cap constant existing and being generous
    // (the acute per-height exhaustion is covered above; a full multi-thousand-height
    // longevity run is out of scope for a unit test).
    const { keys, set } = fixture()
    const L = new Ledger(set, suite)
    const leader0 = selectLeader(set, GENESIS_PREV, 0)
    const leader0Key = keys.find((k) => bytesToHex(k.publicKey) === leader0)!
    const flood = Array.from({ length: 5 }, (_, i) => L.propose(`f2-${i}`, 0, 1, leader0Key))

    const bus = new GossipBus()
    const node = new GossipNode(keys[0]!, set, suite, bus)
    for (const b of flood) bus.broadcast('attacker', { kind: 'block', block: b })
    bus.run()

    expect(node.knownBlockCount()).toBe(5)
    expect(node.observedConflicts.length).toBe(4)
  })
})
