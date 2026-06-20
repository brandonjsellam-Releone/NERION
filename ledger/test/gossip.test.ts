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
  verifyFinalized,
  GENESIS_PREV,
  detectEquivocations,
  verifyEquivocationProof,
  slash,
} from '../src/index.js'
import type { ValidatorSet } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const N = 4

function fixture() {
  const signer = signerFor(suite)
  const keys: KeyPair[] = Array.from({ length: N }, (_, i) =>
    signer.keygen(new Uint8Array(32).fill(i + 1)),
  )
  const set: ValidatorSet = {
    validators: keys.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1 })),
  }
  const leaderId = selectLeader(set, GENESIS_PREV, 0)
  const leaderIdx = keys.findIndex((k) => bytesToHex(k.publicKey) === leaderId)
  return { keys, set, leaderId, leaderIdx }
}

describe('networked ledger — gossip convergence', () => {
  it('all honest nodes independently finalize the same block', () => {
    const { keys, set, leaderIdx } = fixture()
    const bus = new GossipBus()
    const nodes = keys.map((k) => new GossipNode(k, set, suite, bus))

    const block = nodes[leaderIdx]!.proposeIfLeader('deadbeefroot', 1000)
    expect(block).toBeDefined()
    bus.run()

    const hash = blockHash(block!.header)
    for (const n of nodes) {
      expect(n.hasFinalized(hash)).toBe(true)
      expect(n.height()).toBe(1)
      expect(n.headHash()).toBe(hash) // every node converged on the same head
    }
  })

  it('a non-leader cannot propose', () => {
    const { keys, set, leaderIdx } = fixture()
    const bus = new GossipBus()
    const nodes = keys.map((k) => new GossipNode(k, set, suite, bus))
    const nonLeader = nodes[(leaderIdx + 1) % N]!
    expect(nonLeader.proposeIfLeader('x', 1)).toBeUndefined()
  })

  it('a sub-2/3 partition finalizes nothing (no split-brain)', () => {
    const { keys, set, leaderId, leaderIdx } = fixture()
    const bus = new GossipBus()
    const nodes = keys.map((k) => new GossipNode(k, set, suite, bus))

    // Side A = leader + one peer (stake 2 of 4 < the 2/3 = ~2.67 quorum); Side B = the rest.
    const ids = keys.map((k) => bytesToHex(k.publicKey))
    const others = ids.filter((id) => id !== leaderId)
    const sideA = new Set([leaderId, others[0]!])
    bus.setReachability((from, to) => sideA.has(from) === sideA.has(to))

    const block = nodes[leaderIdx]!.proposeIfLeader('caferoot', 1000)!
    bus.run()

    const hash = blockHash(block.header)
    for (const n of nodes) {
      expect(n.hasFinalized(hash)).toBe(false)
      expect(n.height()).toBe(0)
    }
  })
})

describe('networked ledger — equivocation safety (accountable finality)', () => {
  it('an honest node attests at most one block per height', () => {
    const { keys, set, leaderId, leaderIdx } = fixture()
    const leaderKey = keys[leaderIdx]!
    const builder = new Ledger(set, suite)
    const a = builder.propose('rootA', 0, 100, leaderKey)
    const b = builder.propose('rootB', 0, 100, leaderKey) // propose() doesn't mutate the chain
    const hA = blockHash(a.header)
    const hB = blockHash(b.header)
    expect(hA).not.toBe(hB)

    const honestIdx = (leaderIdx + 1) % N
    const bus = new GossipBus()
    const honest = new GossipNode(keys[honestIdx]!, set, suite, bus)

    bus.broadcast('proposer', { kind: 'block', block: a })
    bus.run()
    bus.broadcast('proposer', { kind: 'block', block: b })
    bus.run()

    expect(honest.observedConflicts).toEqual([{ height: 0, a: hA, b: hB }])
    expect(honest.attestationsFor(hA).length).toBe(1) // it attested the first block...
    expect(honest.attestationsFor(hB).length).toBe(0) // ...and refused the conflicting one

    // The honest node's leader id matches the sortition leader it would accept.
    expect(selectLeader(set, GENESIS_PREV, 0)).toBe(leaderId)
  })

  it('a Byzantine double-signer is caught and slashable', () => {
    const { keys, set, leaderIdx } = fixture()
    const leaderKey = keys[leaderIdx]!
    const builder = new Ledger(set, suite)
    const a = builder.propose('rootA', 0, 100, leaderKey)
    const b = builder.propose('rootB', 0, 100, leaderKey)

    // A Byzantine validator signs attestations for BOTH conflicting blocks.
    const byzantine = keys[(leaderIdx + 2) % N]!
    const attA = builder.attest(a, byzantine)
    const attB = builder.attest(b, byzantine)

    const proofs = detectEquivocations(a, [attA], b, [attB])
    expect(proofs).toHaveLength(1)
    const proof = proofs[0]!
    expect(proof.validator).toBe(bytesToHex(byzantine.publicKey))
    expect(verifyEquivocationProof(proof, set)).toBe(true)

    const slashed = slash(set, [proof.validator])
    expect(slashed.validators.length).toBe(set.validators.length - 1)
    expect(slashed.validators.some((v) => v.pubkey === proof.validator)).toBe(false)
  })

  it('a Byzantine leader flooding two conflicting blocks: only one finalizes network-wide', () => {
    const { keys, set, leaderIdx } = fixture()
    const bus = new GossipBus()
    const nodes = keys.map((k) => new GossipNode(k, set, suite, bus))

    const builder = new Ledger(set, suite)
    const a = builder.propose('rootA', 0, 1, keys[leaderIdx]!)
    const b = builder.propose('rootB', 0, 1, keys[leaderIdx]!)
    const hA = blockHash(a.header)
    const hB = blockHash(b.header)
    expect(hA).not.toBe(hB)

    bus.broadcast('byz', { kind: 'block', block: a }) // deterministic FIFO: A before B
    bus.broadcast('byz', { kind: 'block', block: b })
    bus.run()

    expect(nodes.every((n) => n.hasFinalized(hA))).toBe(true) // A reached honest quorum
    expect(nodes.some((n) => n.hasFinalized(hB))).toBe(false) // B never did
    expect(nodes.every((n) => n.observedConflicts.length > 0)).toBe(true)
  })
})

describe('networked ledger — suite binding (anti cross-suite confusion)', () => {
  it('rejects a block whose suite label was swapped without re-signing', () => {
    const { keys, set, leaderIdx } = fixture()
    const L = new Ledger(set, suite) // PS-5
    const block = L.propose('root', 0, 1, keys[leaderIdx]!)
    const atts = keys.map((k) => L.attest(block, k))

    // Verifies under its true suite even without an expectedSuite pin.
    const good = verifyFinalized(block, atts, set, GENESIS_PREV)
    expect(good.ok && good.finalized).toBe(true)

    // Relabel everything PS-5 -> PS-1 (same ML-DSA-87) WITHOUT re-signing: the
    // suite is bound into the signed transcripts, so the swapped sigs are invalid.
    const relabeled = { ...block, suite: SUITE_IDS.PS_1 }
    const relabeledAtts = atts.map((a) => ({ ...a, suite: SUITE_IDS.PS_1 }))
    const bad = verifyFinalized(relabeled, relabeledAtts, set, GENESIS_PREV)
    expect(bad.finalized).toBe(false)
    expect(bad.reasons.some((r) => r.includes('proposer signature is invalid'))).toBe(true)

    // Defense-in-depth: attestations whose suite differs from the (valid) block's
    // are not counted, so attesting stake drops below quorum even with no expectedSuite.
    const mixedAtts = atts.map((a) => ({ ...a, suite: SUITE_IDS.PS_1 }))
    const mixed = verifyFinalized(block, mixedAtts, set, GENESIS_PREV)
    expect(mixed.finalized).toBe(false)
    expect(mixed.attestingStake).toBe(0)
  })
})

describe('networked ledger — multi-height liveness', () => {
  it('buffers a future-height block and applies it after catching up', () => {
    const { keys, set, leaderIdx } = fixture()

    // Build a finalizable 2-block chain out-of-band.
    const L = new Ledger(set, suite)
    const b0 = L.propose('root0', 0, 1, keys[leaderIdx]!)
    const atts0 = keys.map((k) => L.attest(b0, k))
    L.submit(b0, atts0) // advance L to height 1 so it can propose block 1
    const leader1 = selectLeader(set, blockHash(b0.header), 0)
    const leader1Key = keys.find((k) => bytesToHex(k.publicKey) === leader1)!
    const b1 = L.propose('root1', 0, 1, leader1Key)
    const atts1 = keys.map((k) => L.attest(b1, k))
    const h0 = blockHash(b0.header)
    const h1 = blockHash(b1.header)

    // A fresh node at height 0 receives block 1 (+ its attestations) FIRST.
    const bus = new GossipBus()
    const node = new GossipNode(keys[0]!, set, suite, bus)
    bus.broadcast('net', { kind: 'block', block: b1 })
    for (const a of atts1) bus.broadcast('net', { kind: 'attestation', attestation: a })
    bus.run()
    expect(node.height()).toBe(0) // block 1 buffered, not applied early
    expect(node.hasFinalized(h1)).toBe(false)

    // Now it receives block 0: it finalizes 0, then replays the buffered block 1.
    bus.broadcast('net', { kind: 'block', block: b0 })
    for (const a of atts0) bus.broadcast('net', { kind: 'attestation', attestation: a })
    bus.run()
    expect(node.height()).toBe(2)
    expect(node.hasFinalized(h0)).toBe(true)
    expect(node.hasFinalized(h1)).toBe(true)
  })
})
