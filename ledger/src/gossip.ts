// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Networked ledger — deterministic in-process gossip over the pure-PoS ledger.
 *
 * Each {@link GossipNode} runs its OWN {@link Ledger} and only ever finalizes a
 * block it has independently verified (proposer sortition + signatures + ≥2/3
 * stake). Nodes flood blocks and attestations to peers over a {@link GossipBus};
 * honest nodes attest at most one block per height (equivocation-safe), so a
 * conflicting block cannot also gather a quorum from honest stake.
 *
 * The bus is deterministic (FIFO, no clock/RNG) and exposes a reachability hook
 * for partition tests. It is an in-memory stand-in for a real transport: the
 * GossipNode logic is transport-agnostic, so swapping in sockets later is a
 * `GossipBus` implementation change, not a consensus change.
 */

import { bytesToHex } from '@noble/hashes/utils.js'
import type { KeyPair } from '../../crypto/src/index.js'
import { Ledger, blockHash } from './chain.js'
import { selectLeader, stakeOf, canonicalRound } from './sortition.js'
import type { Attestation, Block, ValidatorSet } from './types.js'

export type GossipMessage =
  | { readonly kind: 'block'; readonly block: Block }
  | { readonly kind: 'attestation'; readonly attestation: Attestation }

type Handler = (m: GossipMessage) => void

/** Don't buffer blocks more than this many heights ahead — a node needs the
 *  intermediate heights first anyway, and this bounds pendingBlocks against an
 *  adversarial flood of far-future blocks (a real transport would also expire them). */
const MAX_FUTURE_HEIGHTS = 64

/** Deterministic in-process broadcast network with optional partitions. */
export class GossipBus {
  private readonly handlers = new Map<string, Handler>()
  private readonly queue: { to: string; msg: GossipMessage }[] = []
  private reachable: (from: string, to: string) => boolean = () => true
  /** Total messages delivered over this bus's lifetime (for assertions). */
  delivered = 0

  register(id: string, handler: Handler): void {
    this.handlers.set(id, handler)
  }

  /** Partition control: a message from→to is delivered only if this returns true. */
  setReachability(fn: (from: string, to: string) => boolean): void {
    this.reachable = fn
  }

  broadcast(from: string, msg: GossipMessage): void {
    for (const to of this.handlers.keys()) {
      if (to === from || !this.reachable(from, to)) continue
      this.queue.push({ to, msg })
    }
  }

  /** Deliver queued messages FIFO until the network is quiescent. */
  run(maxDeliveries = 1_000_000): number {
    let n = 0
    while (this.queue.length > 0) {
      if (n >= maxDeliveries) throw new Error('gossip did not converge (delivery cap hit)')
      const item = this.queue.shift() as { to: string; msg: GossipMessage }
      this.handlers.get(item.to)?.(item.msg)
      n++
      this.delivered++
    }
    return n
  }
}

export class GossipNode {
  readonly id: string
  private readonly ledger: Ledger
  /** hash → block, for blocks at the node's current height. */
  private readonly knownBlocks = new Map<string, Block>()
  /** blockHash → (validator → attestation). */
  private readonly attestations = new Map<string, Map<string, Attestation>>()
  /** height → the single block hash this honest node attested there. */
  private readonly attestedAt = new Map<number, string>()
  private readonly finalizedHashes = new Set<string>()
  /** Blocks whose height is ahead of ours, held until we catch up (liveness). */
  private readonly pendingBlocks = new Map<number, Block[]>()
  /** Proposer-equivocations this node observed (it saw two blocks at one height). */
  readonly observedConflicts: { height: number; a: string; b: string }[] = []

  constructor(
    readonly key: KeyPair,
    private readonly set: ValidatorSet,
    private readonly suite: string,
    private readonly bus: GossipBus,
    private readonly finalityNum = 2,
    private readonly finalityDen = 3,
  ) {
    this.id = bytesToHex(key.publicKey)
    this.ledger = new Ledger(set, suite, finalityNum, finalityDen)
    bus.register(this.id, (m) => this.onMessage(m))
  }

  height(): number {
    return this.ledger.height()
  }
  headHash(): string {
    return this.ledger.headHash()
  }
  hasFinalized(hash: string): boolean {
    return this.finalizedHashes.has(hash)
  }
  attestationsFor(hash: string): Attestation[] {
    return [...(this.attestations.get(hash)?.values() ?? [])]
  }

  /** If this node is the canonical leader for its current head, propose + gossip. */
  proposeIfLeader(payloadRoot: string, timestamp: number): Block | undefined {
    const round = canonicalRound(this.height())
    if (selectLeader(this.set, this.headHash(), round) !== this.id) return undefined
    const block = this.ledger.propose(payloadRoot, round, timestamp, this.key)
    this.onBlock(block) // self-deliver (records, attests, queues gossip to peers)
    this.drainBuffered()
    return block
  }

  private onMessage(m: GossipMessage): void {
    if (m.kind === 'block') this.onBlock(m.block)
    else this.onAttestation(m.attestation)
    this.drainBuffered() // iteratively replay buffered blocks for any newly-reached height
  }

  private onBlock(block: Block, flood = true): void {
    const height = this.height()
    if (block.header.height < height) return // stale: already past this height
    if (block.header.height > height) {
      this.bufferFuture(block) // future: hold (and flood) until we catch up
      return
    }
    const h = blockHash(block.header)
    if (this.knownBlocks.has(h)) return // already processed this block
    this.knownBlocks.set(h, block)
    if (flood) this.bus.broadcast(this.id, { kind: 'block', block }) // flood once (skipped on replay)

    const already = this.attestedAt.get(block.header.height)
    if (already === undefined) {
      if (stakeOf(this.set, this.id) > 0) {
        this.attestedAt.set(block.header.height, h)
        this.onAttestation(this.ledger.attest(block, this.key)) // record + gossip our attestation
      }
    } else if (already !== h) {
      // The proposer sent a second, conflicting block at this height: honest nodes
      // do NOT double-attest. Record it so a slashable proof can be built.
      this.observedConflicts.push({ height: block.header.height, a: already, b: h })
    }
    this.tryFinalize(h)
  }

  /** Hold a block whose height is ahead of ours; replayed once we catch up. */
  private bufferFuture(block: Block): void {
    // Ignore blocks too far ahead: we need the intermediate heights first anyway,
    // and this bounds pendingBlocks against an adversarial far-future flood.
    if (block.header.height > this.height() + MAX_FUTURE_HEIGHTS) return
    const list = this.pendingBlocks.get(block.header.height) ?? []
    const h = blockHash(block.header)
    if (list.some((b) => blockHash(b.header) === h)) return // dedup
    list.push(block)
    this.pendingBlocks.set(block.header.height, list)
    this.bus.broadcast(this.id, { kind: 'block', block }) // still flood so peers receive it
  }

  private onAttestation(att: Attestation): void {
    let byValidator = this.attestations.get(att.blockHash)
    if (!byValidator) {
      byValidator = new Map()
      this.attestations.set(att.blockHash, byValidator)
    }
    if (byValidator.has(att.validator)) return // already have this validator's attestation
    byValidator.set(att.validator, att)
    this.bus.broadcast(this.id, { kind: 'attestation', attestation: att }) // flood once
    this.tryFinalize(att.blockHash)
  }

  private tryFinalize(hash: string): void {
    if (this.finalizedHashes.has(hash)) return
    const block = this.knownBlocks.get(hash)
    if (!block || block.header.height !== this.height()) return
    try {
      this.ledger.submit(block, this.attestationsFor(hash))
      this.finalizedHashes.add(hash)
    } catch {
      // Not yet final (insufficient stake) or invalid — wait for more attestations.
    }
  }

  /**
   * Advance the chain as far as buffered blocks allow: prune sub-head known-block
   * state and replay buffered blocks for each newly-reached height. ITERATIVE (not
   * recursive), so catching up across many heights cannot blow the stack.
   * `finalizedHashes` is retained as the finality record. Orphan attestations (for
   * blocks this node never received) are also retained — bounded in practice since
   * honest validators attest at most once per height and the bus floods each
   * message once; a real transport would add height-keyed expiry.
   */
  private drainBuffered(): void {
    for (;;) {
      const height = this.height()
      for (const k of [...this.attestedAt.keys()]) if (k < height) this.attestedAt.delete(k)
      for (const [h, b] of [...this.knownBlocks]) {
        if (b.header.height < height) {
          this.knownBlocks.delete(h)
          this.attestations.delete(h)
        }
      }
      for (const k of [...this.pendingBlocks.keys()]) if (k < height) this.pendingBlocks.delete(k)
      const due = this.pendingBlocks.get(height)
      if (!due) return
      this.pendingBlocks.delete(height)
      for (const b of due) this.onBlock(b, false) // already flooded at buffer time
      if (this.height() === height) return // nothing advanced this round → quiescent
    }
  }
}
