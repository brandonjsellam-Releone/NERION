/**
 * Append-only transparency log (SCITT-style, reference implementation).
 *
 * The log operator is NOT trusted: clients verify inclusion proofs against a
 * gossiped root and verify consistency proofs to detect a rewritten history
 * (split-view / equivocation). This in-memory reference log is for the demo and
 * tests; production anchors roots to the Plane-3 ledger and mirrors operators.
 */

import type { Bytes } from '../../crypto/src/index.js'
import {
  consistencyProof,
  inclusionProof,
  merkleRoot,
  verifyConsistency,
  verifyInclusion,
} from './merkle.js'

export interface InclusionWitness {
  readonly index: number
  readonly size: number
  readonly leaf: Bytes
  readonly proof: Bytes[]
  readonly root: Bytes
}

export interface ConsistencyWitness {
  readonly from: number
  readonly to: number
  readonly proof: Bytes[]
  readonly oldRoot: Bytes
  readonly newRoot: Bytes
}

export class TransparencyLog {
  private readonly entries: Bytes[] = []

  /** Append a leaf payload; returns its index and the new signed-tree size/root. */
  append(data: Bytes): { index: number; size: number; root: Bytes } {
    const index = this.entries.length
    this.entries.push(data)
    return { index, size: this.entries.length, root: this.root() }
  }

  size(): number {
    return this.entries.length
  }

  root(): Bytes {
    return merkleRoot(this.entries)
  }

  /** Produce an inclusion witness for a previously-appended entry. */
  proveInclusion(index: number): InclusionWitness {
    const entry = this.entries[index]
    if (entry === undefined) throw new RangeError('no such log entry')
    return {
      index,
      size: this.entries.length,
      leaf: entry,
      proof: inclusionProof(this.entries, index),
      root: this.root(),
    }
  }

  /** Produce a consistency witness from an earlier size to the current size. */
  proveConsistency(fromSize: number): ConsistencyWitness {
    const to = this.entries.length
    return {
      from: fromSize,
      to,
      proof: consistencyProof(this.entries, fromSize, to),
      oldRoot: merkleRoot(this.entries.slice(0, fromSize)),
      newRoot: this.root(),
    }
  }
}

/** Verify an inclusion witness — no trust in the log operator, only the root. */
export function checkInclusion(w: InclusionWitness, gossipedRoot: Bytes): boolean {
  return verifyInclusion(w.index, w.size, w.leaf, w.proof, gossipedRoot)
}

/** Verify the log grew append-only between two gossiped roots. */
export function checkConsistency(w: ConsistencyWitness): boolean {
  return verifyConsistency(w.from, w.to, w.proof, w.oldRoot, w.newRoot)
}
