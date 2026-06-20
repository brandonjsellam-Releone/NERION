// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Pure proof-of-stake ledger types (P4).
 *
 * The ledger anchors PolarSeek transparency-log roots (and governance
 * enactments) into PQ-verifiable, stake-finalized blocks. All consensus
 * signatures are ML-DSA-87 so a light client verifies finality post-quantum
 * without replaying full state.
 *
 * Leader selection has two modes: legacy deterministic sortition (public,
 * grindable — deprecated) and VRF-mode (ADR-0004: private, verifiable, with
 * view-change liveness). The VRF fields are optional so both modes coexist.
 */

import type { Bytes } from '../../crypto/src/index.js'

export interface Validator {
  /** hex validator public key (ML-DSA-87 consensus identity). */
  readonly pubkey: string
  /** Non-negative integer stake weight. */
  readonly stake: number
  /**
   * hex ed25519 VRF public key (ADR-0004) — classical, SEPARATE from the ML-DSA
   * identity. Required for VRF-mode sortition; absent under legacy mode.
   */
  readonly vrfPubkey?: string
}

export interface ValidatorSet {
  readonly validators: readonly Validator[]
}

export interface BlockHeader {
  readonly height: number
  readonly prevHash: string
  readonly round: number
  readonly proposer: string
  /** hex root being anchored (e.g. a transparency-log root). */
  readonly payloadRoot: string
  readonly timestamp: number
  /** hex VRF output β (64 bytes), committed so the proposer sig + attestations
   *  bind it (VRF mode only). */
  readonly vrfOutput?: string
}

export interface Block {
  readonly header: BlockHeader
  readonly proposerSig: Bytes
  readonly suite: string
  /** 80-byte RFC 9381 ECVRF proof π proving the proposer's eligibility (VRF mode). */
  readonly vrfProof?: Bytes
  /** Justifies a round > 0: ≥2/3-stake timeout cert for the previous round (VRF mode). */
  readonly viewChangeCert?: ViewChangeCert
}

export interface Attestation {
  readonly blockHash: string
  readonly validator: string
  readonly suite: string
  readonly sig: Bytes
}

/** A signed vote that round `round` at `(height, prevHash)` timed out (ADR-0004). */
export interface TimeoutVote {
  readonly height: number
  readonly prevHash: string
  readonly round: number
  readonly validator: string
  readonly suite: string
  readonly sig: Bytes
}

/** ≥2/3-stake evidence that `round` timed out — justifies advancing to `round + 1`. */
export interface ViewChangeCert {
  readonly round: number
  readonly votes: readonly TimeoutVote[]
}

export interface FinalizedBlock {
  readonly block: Block
  readonly hash: string
  readonly attestations: readonly Attestation[]
  readonly attestingStake: number
  readonly finalized: boolean
}

export interface LightClientVerdict {
  readonly ok: boolean
  readonly finalized: boolean
  readonly attestingStake: number
  readonly totalStake: number
  readonly reasons: string[]
}
