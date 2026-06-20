// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Receipts — the durable, post-quantum, regulator-ready evidence of a decision.
 *
 * A receipt commits (by hash) to the intent, authorizing capability, policy,
 * replay input, and decision — NO payloads, NO PII — plus jurisdiction, risk
 * tier, suite, and timestamp, signed with the suite's PQ signature (ML-DSA-87).
 * The receipt body is the leaf appended to the transparency log, so anyone can
 * verify the signature (with the issuer key) AND log inclusion (against a
 * gossiped root) WITHOUT trusting the log operator or the issuer's honesty.
 */

import { encodeCanonical, SHA3_SHAKE256, signerFor, type Bytes } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { bytesEqual, checkInclusion, type InclusionWitness } from '../../translog/src/index.js'

export interface ReceiptCommitments {
  readonly intent: string
  readonly capability: string
  readonly policy: string
  readonly inputHash: string
  readonly decisionHash: string
}

export interface ReceiptBody {
  readonly v: 1
  readonly suite: string
  readonly evaluatorVersion: string
  readonly effect: string
  readonly tier: number
  readonly jurisdiction: string
  readonly timestamp: number
  readonly commitments: ReceiptCommitments
}

export interface Receipt {
  readonly body: ReceiptBody
  readonly sig: Bytes
  readonly signerPublicKey: Bytes
}

const hashHex = (v: unknown): string => bytesToHex(SHA3_SHAKE256.digest(encodeCanonical(v)))

export interface BuildReceiptParams {
  readonly suite: string
  readonly evaluatorVersion: string
  readonly effect: string
  readonly tier: number
  readonly jurisdiction: string
  readonly timestamp: number
  readonly intent: unknown
  readonly capability: unknown | null
  readonly policy: unknown
  readonly inputHash: string
  readonly decisionHash: string
  readonly issuerSecretKey: Bytes
  readonly issuerPublicKey: Bytes
}

export function buildReceipt(p: BuildReceiptParams): Receipt {
  const body: ReceiptBody = {
    v: 1,
    suite: p.suite,
    evaluatorVersion: p.evaluatorVersion,
    effect: p.effect,
    tier: p.tier,
    jurisdiction: p.jurisdiction,
    timestamp: p.timestamp,
    commitments: {
      intent: hashHex(p.intent),
      capability: p.capability === null ? 'none' : hashHex(p.capability),
      policy: hashHex(p.policy),
      inputHash: p.inputHash,
      decisionHash: p.decisionHash,
    },
  }
  const sig = signerFor(p.suite).sign(encodeCanonical(body), p.issuerSecretKey)
  return { body, sig, signerPublicKey: p.issuerPublicKey }
}

/** The canonical bytes appended to the transparency log for this receipt. */
export function receiptLeaf(r: Receipt): Bytes {
  return encodeCanonical(r.body)
}

/** Verify the receipt's PQ signature under its embedded issuer key. */
export function verifyReceipt(r: Receipt): boolean {
  return signerFor(r.body.suite).verify(r.sig, encodeCanonical(r.body), r.signerPublicKey)
}

export interface ExternalVerdict {
  readonly ok: boolean
  readonly reasons: string[]
}

/**
 * Full external verification: trust ONLY the expected issuer public key and a
 * gossiped log root. Checks signature, issuer-key match, leaf↔body binding, and
 * Merkle inclusion. No trust in the issuer's or the log operator's good behavior.
 */
export function verifyReceiptInclusion(
  r: Receipt,
  witness: InclusionWitness,
  gossipedRoot: Bytes,
  trustedIssuerKey: Bytes,
): ExternalVerdict {
  const reasons: string[] = []
  if (!verifyReceipt(r)) reasons.push('receipt signature invalid')
  if (!bytesEqual(r.signerPublicKey, trustedIssuerKey)) {
    reasons.push('receipt not signed by the expected issuer key')
  }
  if (!bytesEqual(witness.leaf, receiptLeaf(r))) {
    reasons.push('witness leaf does not match the receipt body')
  }
  if (!checkInclusion(witness, gossipedRoot)) {
    reasons.push('inclusion proof does not verify against the gossiped root')
  }
  return { ok: reasons.length === 0, reasons }
}
