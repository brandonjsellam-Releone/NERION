/**
 * File-backed append-only transparency log.
 *
 * Leaves are persisted as hex lines so the log survives a restart and can be
 * mirrored by copying the file. Roots/proofs are computed with the same Merkle
 * primitives as the in-memory log, so witnesses are interchangeable.
 */

import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { Bytes } from '../../crypto/src/index.js'
import { inclusionProof, merkleRoot } from './merkle.js'
import { consistencyProof } from './merkle.js'
import type { InclusionWitness, ConsistencyWitness } from './log.js'

export class PersistentTransparencyLog {
  private readonly entries: Bytes[] = []

  constructor(private readonly path: string) {
    if (existsSync(path)) {
      for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
        const t = line.trim()
        if (t.length > 0) this.entries.push(hexToBytes(t))
      }
    }
  }

  append(data: Bytes): { index: number; size: number; root: Bytes } {
    const index = this.entries.length
    this.entries.push(data)
    appendFileSync(this.path, bytesToHex(data) + '\n')
    return { index, size: this.entries.length, root: this.root() }
  }

  size(): number {
    return this.entries.length
  }

  root(): Bytes {
    return merkleRoot(this.entries)
  }

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
