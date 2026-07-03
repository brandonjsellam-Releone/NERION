// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  merkleRoot,
  consistencyProof,
  verifyConsistency,
  emptyRoot,
  verifyInclusion,
  inclusionProof,
} from '../src/merkle.js'

/**
 * Consistency-proof SOUNDNESS regression — bakes in the Team Apex post-fix
 * verification round (2026-06-21). After TLOG-001/002 landed, a 4-seat council
 * panel (DeepSeek/Grok/Hermes/OpenAI) raised three TLOG findings; all THREE were
 * adjudicated FALSE POSITIVES against an exhaustive empirical cross-check. These
 * tests encode the two properties the panel probed that the base suite did not
 * already assert directly, so the refutation cannot silently regress:
 *
 *  1. For 0 < m < n the proof BINDS the new root (root2) — a forged root2 is
 *     rejected. (Refutes "root2 is never checked.")
 *  2. m = 0: the empty tree is a universal prefix, so ANY genuine newRoot is
 *     consistent with it — provided root1 is the canonical empty root (TLOG-001).
 *     (Refutes "m=0 wrongly accepts arbitrary root2": root2's authenticity is the
 *     STH signature's job; the prefix relation itself is vacuously true.)
 */
const entry = (i: number): Uint8Array => new TextEncoder().encode(`soundness-${i}`)
const tree = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => entry(i))

describe('Merkle consistency soundness (Team Apex post-fix verification, 2026-06-21)', () => {
  it('binds the new root: a forged root2 is rejected for every 0 < m < n (sizes 2..16)', () => {
    for (let n = 2; n <= 16; n++) {
      const es = tree(n)
      const realNew = merkleRoot(es)
      // A different size-n tree (last leaf altered) -> a root the log never produced.
      const forgedNew = merkleRoot([...es.slice(0, n - 1), entry(1000 + n)])
      expect(forgedNew).not.toEqual(realNew)
      for (let m = 1; m < n; m++) {
        const proof = consistencyProof(es, m, n)
        const oldRoot = merkleRoot(es.slice(0, m))
        // Genuine link verifies...
        expect(verifyConsistency(m, n, proof, oldRoot, realNew)).toBe(true)
        // ...the SAME proof against a forged new root does NOT (root2 is bound).
        expect(verifyConsistency(m, n, proof, oldRoot, forgedNew)).toBe(false)
      }
    }
  })

  it('m=0: empty tree is consistent with any genuine newRoot (sizes 1..16), only with the empty root1', () => {
    for (let n = 1; n <= 16; n++) {
      const realNew = merkleRoot(tree(n))
      expect(verifyConsistency(0, n, [], emptyRoot(), realNew)).toBe(true)
      // A non-empty claimed size-0 root is rejected (TLOG-001), and a non-empty proof is rejected.
      expect(verifyConsistency(0, n, [], merkleRoot(tree(1)), realNew)).toBe(false)
      expect(verifyConsistency(0, n, [emptyRoot()], emptyRoot(), realNew)).toBe(false)
    }
  })
})

describe('TLOG-NONFINITE-001 (AAC cycle-3): a non-finite index fails closed AND terminates', () => {
  // BLOCKING regression: a gossiped ConsistencyWitness with from = NaN / -Infinity previously reached
  // trailingZeros(m), which infinite-loops (uncatchable — no throw), permanently wedging the untrusted
  // split-view/rewrite monitor. A hang here would blow vitest's per-test timeout; a `false` return is
  // the regression signal that the entry guard rejects it before the bit-twiddling.
  it('verifyConsistency returns false for NaN / ±Infinity / non-integer m or n', () => {
    const es = tree(8)
    const realNew = merkleRoot(es)
    const proof = consistencyProof(es, 4, 8)
    const oldRoot = merkleRoot(es.slice(0, 4))
    // Positive control: the genuine link still verifies.
    expect(verifyConsistency(4, 8, proof, oldRoot, realNew)).toBe(true)
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 2.5, -1]) {
      expect(verifyConsistency(bad, 8, proof, oldRoot, realNew)).toBe(false)
      expect(verifyConsistency(4, bad, proof, oldRoot, realNew)).toBe(false)
    }
  })

  it('verifyInclusion returns false for a non-finite / non-integer index or size', () => {
    const es = tree(8)
    const root = merkleRoot(es)
    const proof = inclusionProof(es, 3)
    expect(verifyInclusion(3, 8, es[3]!, proof, root)).toBe(true) // positive control
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1, 3.5]) {
      expect(verifyInclusion(bad, 8, es[3]!, proof, root)).toBe(false)
      expect(verifyInclusion(3, bad, es[3]!, proof, root)).toBe(false)
    }
  })
})
