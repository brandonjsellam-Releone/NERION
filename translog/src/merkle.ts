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
  if (x === 0) return 0
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
  if (m >= n) throw new RangeError('index >= size')
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
    if (m > n) return false
    if (m === n) return proof.length === 0 && bytesEqual(root1, root2)
    if (m === 0) return proof.length === 0
    let inner = bitLength((m - 1) ^ (n - 1))
    const shift = trailingZeros(m)
    inner -= shift

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
    const innerProof = p.slice(0, inner)
    const borderProof = p.slice(inner)

    const hash1 = chainBorderRight(chainInnerRight(seed, innerProof, mask), borderProof)
    const hash2 = chainBorderRight(chainInner(seed, innerProof, mask), borderProof)
    return bytesEqual(hash1, root1) && bytesEqual(hash2, root2)
  } catch {
    return false
  }
}
