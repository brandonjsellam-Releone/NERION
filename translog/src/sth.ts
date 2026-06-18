/**
 * Signed Tree Heads (STH) + gossip / split-view detection.
 *
 * Each log operator signs its (size, root) with a PQ signature. Clients gossip
 * STHs and detect:
 *   - EQUIVOCATION: two STHs from one operator at the same size with different
 *     roots (a split view), or
 *   - a broken APPEND-ONLY guarantee: two STHs from one operator where the
 *     larger is not consistent with the smaller.
 * This is how a malicious or compromised log operator is caught WITHOUT trusting
 * it — the multi-operator, mirrorable transparency property.
 */

import { encodeCanonical, signerFor, type Bytes, type KeyPair } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { verifyConsistency } from './merkle.js'

const STH_CONTEXT = 'polarseek-sth-v1'

export interface SignedTreeHead {
  /** hex of the operator public key. */
  readonly operator: string
  readonly size: number
  readonly rootHex: string
  readonly suite: string
  readonly sig: Bytes
}

export function signTreeHead(
  size: number,
  root: Bytes,
  suite: string,
  operator: KeyPair,
): SignedTreeHead {
  const operatorHex = bytesToHex(operator.publicKey)
  const rootHex = bytesToHex(root)
  const sig = signerFor(suite).sign(
    encodeCanonical([STH_CONTEXT, operatorHex, size, rootHex]),
    operator.secretKey,
  )
  return { operator: operatorHex, size, rootHex, suite, sig }
}

export function verifyTreeHead(sth: SignedTreeHead, operatorPublicKey: Bytes): boolean {
  if (bytesToHex(operatorPublicKey) !== sth.operator) return false
  return signerFor(sth.suite).verify(
    sth.sig,
    encodeCanonical([STH_CONTEXT, sth.operator, sth.size, sth.rootHex]),
    operatorPublicKey,
  )
}

export interface Equivocation {
  readonly operator: string
  readonly size: number
  readonly rootA: string
  readonly rootB: string
}

/**
 * Detect split-view equivocation: any operator presenting two different roots
 * for the same tree size. Returns one entry per conflicting pair found.
 */
export function detectEquivocation(sths: readonly SignedTreeHead[]): Equivocation[] {
  const seen = new Map<string, string>() // `${operator}@${size}` -> rootHex
  const out: Equivocation[] = []
  for (const sth of sths) {
    const key = `${sth.operator}@${sth.size}`
    const prior = seen.get(key)
    if (prior === undefined) seen.set(key, sth.rootHex)
    else if (prior !== sth.rootHex) {
      out.push({ operator: sth.operator, size: sth.size, rootA: prior, rootB: sth.rootHex })
    }
  }
  return out
}

/**
 * Verify an operator stayed append-only between two of its STHs, given a
 * consistency proof. `older.size <= newer.size` and both STHs must be from the
 * same operator. Returns false if the proof fails (i.e., the log was rewritten).
 */
export function checkAppendOnly(
  older: SignedTreeHead,
  newer: SignedTreeHead,
  proof: readonly Bytes[],
): boolean {
  if (older.operator !== newer.operator) return false
  if (older.size > newer.size) return false
  return verifyConsistency(
    older.size,
    newer.size,
    proof,
    hexToBytesLocal(older.rootHex),
    hexToBytesLocal(newer.rootHex),
  )
}

// Local hex decode to avoid importing more than needed.
function hexToBytesLocal(hex: string): Bytes {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
