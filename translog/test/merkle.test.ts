// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  merkleRoot,
  inclusionProof,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
  leafHash,
  emptyRoot,
} from '../src/merkle.js'

const entry = (i: number): Uint8Array => new TextEncoder().encode(`entry-${i}`)
const tree = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => entry(i))

describe('Merkle inclusion proofs', () => {
  it('verify for every index across sizes 1..16', () => {
    for (let n = 1; n <= 16; n++) {
      const es = tree(n)
      const root = merkleRoot(es)
      for (let m = 0; m < n; m++) {
        expect(verifyInclusion(m, n, es[m]!, inclusionProof(es, m), root)).toBe(true)
      }
    }
  })

  it('rejects a tampered leaf, wrong index, and wrong root', () => {
    const es = tree(7)
    const root = merkleRoot(es)
    const m = 3
    const proof = inclusionProof(es, m)
    expect(verifyInclusion(m, 7, entry(99), proof, root)).toBe(false)
    expect(verifyInclusion(4, 7, es[m]!, proof, root)).toBe(false)
    expect(verifyInclusion(m, 7, es[m]!, proof, merkleRoot(tree(8)))).toBe(false)
  })
})

describe('Merkle consistency (append-only) proofs', () => {
  it('verify for all m <= n across sizes 1..16', () => {
    for (let n = 1; n <= 16; n++) {
      const es = tree(n)
      const newRoot = merkleRoot(es)
      for (let m = 0; m <= n; m++) {
        const proof = consistencyProof(es, m, n)
        const oldRoot = merkleRoot(es.slice(0, m))
        expect(verifyConsistency(m, n, proof, oldRoot, newRoot)).toBe(true)
      }
    }
  })

  it('rejects a rewritten history (forged old root)', () => {
    const es = tree(8)
    const newRoot = merkleRoot(es)
    const m = 5
    const proof = consistencyProof(es, m, 8)
    const forgedOld = merkleRoot([...tree(4), entry(999)])
    expect(verifyConsistency(m, 8, proof, forgedOld, newRoot)).toBe(false)
  })

  it('rejects a tampered consistency proof node', () => {
    const es = tree(8)
    const newRoot = merkleRoot(es)
    const m = 5
    const proof = consistencyProof(es, m, 8)
    const bad = [...proof]
    bad[0] = leafHash(entry(123))
    expect(verifyConsistency(m, 8, bad, merkleRoot(es.slice(0, m)), newRoot)).toBe(false)
  })
})

describe('Merkle hardening — Team Apex audit (TLOG-001/002)', () => {
  it('TLOG-001: m=0 consistency requires root1 to be the empty-tree root', () => {
    const newRoot = merkleRoot(tree(8))
    // Genesis-from-empty with the REAL empty root verifies...
    expect(verifyConsistency(0, 8, [], emptyRoot(), newRoot)).toBe(true)
    // ...but a BOGUS size-0 root is rejected: a signed size-0 STH cannot lie about genesis.
    expect(verifyConsistency(0, 8, [], leafHash(entry(1)), newRoot)).toBe(false)
  })

  it('TLOG-002: verification fails closed above the 32-bit-safe size bound', () => {
    const big = 2 ** 31 // exceeds MAX_TREE_SIZE (2^31 - 1)
    expect(verifyConsistency(0, big, [], emptyRoot(), merkleRoot(tree(4)))).toBe(false)
    // verifyInclusion swallows the range error as false (fail-closed).
    expect(verifyInclusion(0, big, entry(0), [], merkleRoot(tree(4)))).toBe(false)
  })
})
