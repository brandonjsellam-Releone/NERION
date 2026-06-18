/**
 * Pure proof-of-stake ledger types (P4).
 *
 * The ledger anchors PolarSeek transparency-log roots (and governance
 * enactments) into PQ-verifiable, stake-finalized blocks. All signatures are
 * ML-DSA-87 so a light client verifies finality post-quantum without replaying
 * full state.
 */

import type { Bytes } from '../../crypto/src/index.js'

export interface Validator {
  /** hex validator public key. */
  readonly pubkey: string
  /** Non-negative integer stake weight. */
  readonly stake: number
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
}

export interface Block {
  readonly header: BlockHeader
  readonly proposerSig: Bytes
  readonly suite: string
}

export interface Attestation {
  readonly blockHash: string
  readonly validator: string
  readonly suite: string
  readonly sig: Bytes
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
