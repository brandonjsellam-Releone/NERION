// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * RFC 6962-style Merkle tree: leaf/node domain separation, Merkle root,
 * inclusion proofs, and consistency (append-only) proofs.
 *
 * Hashing is SHA3-256 (via the crypto suite's hash). Proof *generation* uses
 * the canonical recursive RFC 6962 algorithm; *verification* uses the
 * Trillian-style index decomposition. Both implement the same standard, so a
 * generated proof verifies — exhaustively checked in translog/test.
 *
 * This is the transparency-log primitive that lets anyone verify a receipt's
 * inclusion and the log's append-only growth WITHOUT trusting the operator.
 */

import { SHA3_SHAKE256, type Bytes } from '../../crypto/src/index.js'
import { concatBytes } from '@noble/hashes/utils.js'

const H = (b: Bytes): Bytes => SHA3_SHAKE256.digest(b)
const LEAF_PREFIX = Uint8Array.of(0x00)
const NODE_PREFIX = Uint8Array.of(0x01)

// JS bitwise ops in the verifier (chainInner `index>>i`, `1<<shift`, `m^(n-1)`) are 32-bit,
// so verification is only sound for sizes < 2^31 (TLOG-002, Team Apex 2026-06-21). The
// generator is unaffected; lifting this cap needs BigInt index arithmetic (tracked follow-up).
// Verifiers fail CLOSED above the bound rather than computing over a wrong tree shape.
const MAX_TREE_SIZE = 2 ** 31 - 1

export const emptyRoot = (): Bytes => H(new Uint8Array(0))
export const leafHash = (data: Bytes): Bytes => H(concatBytes(LEAF_PREFIX, data))
export const nodeHash = (l: Bytes, r: Bytes): Bytes => H(concatBytes(NODE_PREFIX, l, r))

export function bytesEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

// --- small bit helpers (operate on non-negative integers) ---
const bitLength = (x: number): number => {
  let n = 0
  while (x > 0) {
    n++
    x = Math.floor(x / 2)
  }
  return n
}
const popcount = (x: number): number => {
  let c = 0
  while (x > 0) {
    c += x & 1
    x = Math.floor(x / 2)
  }
  return c
}
const trailingZeros = (x: number): number => {
  // TLOG-NONFINITE-001 (AAC cycle-3): a non-integer / non-finite / non-positive x must NOT enter the
  // loop — `NaN & 1` is 0 and `NaN >> 1` is 0, so `while ((x & 1) === 0)` would spin forever (an
  // uncatchable infinite loop, not a throw). Guard defensively in addition to the entry-point checks.
  if (!Number.isInteger(x) || x <= 0) return 0
  let n = 0
  while ((x & 1) === 0) {
    n++
    x >>= 1
  }
  return n
}
/** Largest power of two strictly less than n (n >= 2). */
const splitPoint = (n: number): number => {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** Merkle Tree Hash of `entries` (each entry is the raw leaf payload). */
export function merkleRoot(entries: readonly Bytes[]): Bytes {
  const n = entries.length
  if (n === 0) return emptyRoot()
  if (n === 1) return leafHash(entries[0]!)
  const k = splitPoint(n)
  return nodeHash(merkleRoot(entries.slice(0, k)), merkleRoot(entries.slice(k)))
}

/** Audit path proving entry `m` is included in a tree over `entries`. */
export function inclusionProof(entries: readonly Bytes[], m: number): Bytes[] {
  const n = entries.length
  if (m < 0 || m >= n) throw new RangeError('index out of range')
  if (n === 1) return []
  const k = splitPoint(n)
  if (m < k) return [...inclusionProof(entries.slice(0, k), m), merkleRoot(entries.slice(k))]
  return [...inclusionProof(entries.slice(k), m - k), merkleRoot(entries.slice(0, k))]
}

const chainInner = (seed: Bytes, proof: readonly Bytes[], index: number): Bytes => {
  let acc = seed
  for (let i = 0; i < proof.length; i++) {
    acc = ((index >> i) & 1) === 0 ? nodeHash(acc, proof[i]!) : nodeHash(proof[i]!, acc)
  }
  return acc
}
const chainInnerRight = (seed: Bytes, proof: readonly Bytes[], index: number): Bytes => {
  let acc = seed
  for (let i = 0; i < proof.length; i++) {
    if (((index >> i) & 1) === 1) acc = nodeHash(proof[i]!, acc)
  }
  return acc
}
const chainBorderRight = (seed: Bytes, proof: readonly Bytes[]): Bytes => {
  let acc = seed
  for (const h of proof) acc = nodeHash(h, acc)
  return acc
}

/** Recompute the root from an inclusion proof (Trillian decomposition). */
export function rootFromInclusion(
  m: number,
  n: number,
  leaf: Bytes,
  proof: readonly Bytes[],
): Bytes {
  // TLOG-NONFINITE-001 (AAC cycle-3): reject a non-finite / non-integer / negative index or size
  // BEFORE the 32-bit bit-twiddling below (where NaN silently aliases to index 0). verifyInclusion
  // wraps this in try/catch, so a malformed witness fails CLOSED instead of being mis-decomposed.
  if (!Number.isInteger(m) || !Number.isInteger(n) || m < 0 || n < 0) {
    throw new RangeError('non-integer or negative index/size')
  }
  if (m >= n) throw new RangeError('index >= size')
  if (n > MAX_TREE_SIZE) throw new RangeError('tree size exceeds 32-bit-safe bound (TLOG-002)')
  const inner = bitLength(m ^ (n - 1))
  const border = popcount(m >> inner)
  if (proof.length !== inner + border) throw new Error('malformed inclusion proof length')
  const res = chainInner(leaf, proof.slice(0, inner), m)
  return chainBorderRight(res, proof.slice(inner))
}

/** Verify that `leaf` is the entry at index `m` of a size-`n` tree with `root`. */
export function verifyInclusion(
  m: number,
  n: number,
  leaf: Bytes,
  proof: readonly Bytes[],
  root: Bytes,
): boolean {
  try {
    return bytesEqual(rootFromInclusion(m, n, leafHash(leaf), proof), root)
  } catch {
    return false
  }
}

/** Consistency proof that a size-`m` tree is a prefix of a size-`n` tree. */
export function consistencyProof(entries: readonly Bytes[], m: number, n: number): Bytes[] {
  if (m < 0 || m > n || n > entries.length) throw new RangeError('bad consistency range')
  if (m === 0 || m === n) return []
  return subproof(entries.slice(0, n), m, true)
}

function subproof(entries: readonly Bytes[], m: number, b: boolean): Bytes[] {
  const n = entries.length
  if (m === n) return b ? [] : [merkleRoot(entries)]
  const k = splitPoint(n)
  if (m <= k) {
    return [...subproof(entries.slice(0, k), m, b), merkleRoot(entries.slice(k))]
  }
  return [...subproof(entries.slice(k), m - k, false), merkleRoot(entries.slice(0, k))]
}

/** Verify a consistency proof links `root1` (size m) to `root2` (size n). */
export function verifyConsistency(
  m: number,
  n: number,
  proof: readonly Bytes[],
  root1: Bytes,
  root2: Bytes,
): boolean {
  try {
    // TLOG-NONFINITE-001 (AAC cycle-3, BLOCKING): reject a non-finite / non-integer / negative m or n
    // FIRST. Otherwise m=NaN/-Infinity passes `m > n` (false), `m === n`, and `m === 0`, then reaches
    // `trailingZeros(m)` which infinite-loops — an UNCATCHABLE hang (no throw) that permanently wedges
    // the untrusted-gossip split-view/rewrite monitor (checkConsistency), so a real rewrite would go
    // undetected. This entry guard is the load-bearing fix; trailingZeros is also hardened defensively.
    if (!Number.isInteger(m) || !Number.isInteger(n) || m < 0 || n < 0) return false
    if (m > n) return false
    if (n > MAX_TREE_SIZE) return false // 32-bit-safe verification bound (TLOG-002)
    if (m === n) return proof.length === 0 && bytesEqual(root1, root2)
    // m === 0: the empty tree is a prefix of any tree, but root1 MUST be the empty-tree
    // root — else a signed size-0 STH with a BOGUS root would pass append-only checks
    // (TLOG-001, Team Apex audit 2026-06-21).
    if (m === 0) return proof.length === 0 && bytesEqual(root1, emptyRoot())
    let inner = bitLength((m - 1) ^ (n - 1))
    const shift = trailingZeros(m)
    inner -= shift
    if (inner < 0) return false // defensive: malformed (m, n)

    let seed: Bytes
    let start: number
    if (m === 1 << shift) {
      seed = root1
      start = 0
    } else {
      if (proof.length === 0) return false
      seed = proof[0]!
      start = 1
    }
    const p = proof.slice(start)
    const mask = (m - 1) >> shift
    // TLOG-DOS-001 (round-2 sweep): bound the proof length BEFORE the border-hash chain. A genuine
    // RFC 6962 consistency proof for size n has at most 2·bitLength(n)+1 elements (inner and border
    // are each ≤ bitLength(n), plus the optional seed); surplus elements otherwise flow into
    // borderProof and are each SHA3-hashed (chainBorderRight), making verification O(proof.length)
    // — a measured ~minute on a crafted multi-million-element proof from untrusted gossip. The
    // inclusion verifier already guards this; this brings consistency to parity (wrong-length but
    // in-bound proofs are still rejected by the root comparison below, so soundness is unchanged).
    if (proof.length > 2 * bitLength(n) + 1) return false
    const innerProof = p.slice(0, inner)
    const borderProof = p.slice(inner)

    const hash1 = chainBorderRight(chainInnerRight(seed, innerProof, mask), borderProof)
    const hash2 = chainBorderRight(chainInner(seed, innerProof, mask), borderProof)
    return bytesEqual(hash1, root1) && bytesEqual(hash2, root2)
  } catch {
    return false
  }
}
