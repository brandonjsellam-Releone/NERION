// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { merkleRoot, inclusionProof, verifyInclusion } from '../../translog/src/merkle.js'

/**
 * Property-based inclusion-proof tests for the RFC 6962-style Merkle tree
 * (Team Apex A11 sweep, 2026-06-24). The example tests in translog/test pin
 * specific known-good cases; this suite exercises RANDOMIZED trees so the five
 * core inclusion-proof properties hold over the full input space:
 *
 *  COMPLETENESS  — valid leaf + valid proof + correct root → true
 *  FORGED ROOT   — any different root (same tree) → false
 *  WRONG INDEX   — correct proof submitted with a wrong leaf index → false
 *  LEAF TAMPER   — one-byte mutation of the raw leaf payload → false
 *  PATH TAMPER   — one-byte mutation of any sibling in the audit path → false
 *
 * Run budget: 20–25 examples per property (SHA3 hashing makes 100 runs slow on
 * large trees; the coverage goal is structural breadth, not exhaustive sampling).
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Encode a number as a deterministic leaf payload. */
const entry = (i: number): Uint8Array => new TextEncoder().encode(`leaf-${i}`)

/** Build a tree of `n` leaves. */
const makeTree = (n: number): Uint8Array[] => Array.from({ length: n }, (_, i) => entry(i))

/** Return a copy of `buf` with byte at `offset` XOR'd with `mask` (defaults to 0x01). */
const flipByte = (buf: Uint8Array, offset: number, mask = 0x01): Uint8Array => {
  const copy = new Uint8Array(buf)
  const idx = offset % copy.length
  copy[idx] = (copy[idx] ?? 0) ^ mask
  return copy
}

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

/**
 * Generates (entries, leafIndex) pairs — a non-empty tree of up to 32 leaves
 * and a valid index within it.  Keeping the tree small bounds per-run hashing
 * while still exercising power-of-two, odd, and prime sizes.
 */
const treeAndIndexArb: fc.Arbitrary<{ entries: Uint8Array[]; m: number }> = fc
  .integer({ min: 1, max: 32 })
  .chain((n) =>
    fc.record({
      entries: fc.constant(makeTree(n)),
      m: fc.integer({ min: 0, max: n - 1 }),
    }),
  )

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('Merkle inclusion proof — properties (randomized, A11)', () => {
  // -------------------------------------------------------------------------
  // COMPLETENESS
  // -------------------------------------------------------------------------
  it('COMPLETENESS: valid leaf + valid proof verifies against the real root', () => {
    fc.assert(
      fc.property(treeAndIndexArb, ({ entries, m }) => {
        const root = merkleRoot(entries)
        const proof = inclusionProof(entries, m)
        expect(verifyInclusion(m, entries.length, entries[m]!, proof, root)).toBe(true)
      }),
      { numRuns: 25 },
    )
  })

  // -------------------------------------------------------------------------
  // FORGED ROOT
  // -------------------------------------------------------------------------
  it('FORGED ROOT: any different root rejects a genuine proof (same tree, same leaf, same index)', () => {
    fc.assert(
      fc.property(
        treeAndIndexArb,
        // Build a second tree of a different size (or shift one leaf) to get a different root.
        fc.integer({ min: 1, max: 32 }),
        ({ entries, m }, altSize) => {
          const root = merkleRoot(entries)

          // Build an alternative tree whose root is almost certainly different.
          // Altering the size or content guarantees this in all but degenerate cases.
          const altEntries = makeTree(altSize === entries.length ? altSize + 1 : altSize)
          const forgedRoot = merkleRoot(altEntries)

          // Only assert when the forged root actually differs (degenerate collisions are
          // theoretically impossible for SHA3 but we guard defensively).
          if (forgedRoot.length !== root.length || forgedRoot.some((b, i) => b !== root[i])) {
            const proof = inclusionProof(entries, m)
            expect(verifyInclusion(m, entries.length, entries[m]!, proof, forgedRoot)).toBe(false)
          }
        },
      ),
      { numRuns: 20 },
    )
  })

  // -------------------------------------------------------------------------
  // WRONG INDEX
  // -------------------------------------------------------------------------
  it('WRONG INDEX: a valid proof submitted with an incorrect leaf index rejects', () => {
    fc.assert(
      fc.property(
        // Require at least 2 leaves so there is always a distinct wrong index.
        fc.integer({ min: 2, max: 32 }).chain((n) =>
          fc.record({
            entries: fc.constant(makeTree(n)),
            m: fc.integer({ min: 0, max: n - 1 }),
            // wrong index: any index in [0, n) that is not m
            delta: fc.integer({ min: 1, max: n - 1 }),
          }),
        ),
        ({ entries, m, delta }) => {
          const n = entries.length
          const wrongIndex = (m + delta) % n
          const root = merkleRoot(entries)
          const proof = inclusionProof(entries, m)
          // Proof is for index m; submitting it as proof for wrongIndex must fail.
          expect(verifyInclusion(wrongIndex, n, entries[m]!, proof, root)).toBe(false)
        },
      ),
      { numRuns: 20 },
    )
  })

  // -------------------------------------------------------------------------
  // LEAF TAMPER
  // -------------------------------------------------------------------------
  it('LEAF TAMPER: a one-byte mutation of the leaf payload rejects', () => {
    fc.assert(
      fc.property(
        treeAndIndexArb,
        // Which byte within the leaf to flip (leaf payloads are at least 7 bytes).
        fc.integer({ min: 0, max: 6 }),
        ({ entries, m }, byteOffset) => {
          const root = merkleRoot(entries)
          const proof = inclusionProof(entries, m)
          const tampered = flipByte(entries[m]!, byteOffset)
          expect(verifyInclusion(m, entries.length, tampered, proof, root)).toBe(false)
        },
      ),
      { numRuns: 20 },
    )
  })

  // -------------------------------------------------------------------------
  // PATH TAMPER
  // -------------------------------------------------------------------------
  it('PATH TAMPER: a one-byte mutation of any path element rejects', () => {
    fc.assert(
      fc.property(
        // Require at least 2 leaves so the proof is non-empty.
        fc.integer({ min: 2, max: 32 }).chain((n) =>
          fc.record({
            entries: fc.constant(makeTree(n)),
            m: fc.integer({ min: 0, max: n - 1 }),
          }),
        ),
        ({ entries, m }) => {
          const root = merkleRoot(entries)
          const proof = inclusionProof(entries, m)
          if (proof.length === 0) return // n=1 produces empty proof; skip (covered by COMPLETENESS)

          // Tamper every sibling node in the audit path and verify each is rejected.
          for (let pathIdx = 0; pathIdx < proof.length; pathIdx++) {
            const tamperedProof = proof.map((node, i) => (i === pathIdx ? flipByte(node, 0) : node))
            expect(verifyInclusion(m, entries.length, entries[m]!, tamperedProof, root)).toBe(false)
          }
        },
      ),
      { numRuns: 20 },
    )
  })
})
