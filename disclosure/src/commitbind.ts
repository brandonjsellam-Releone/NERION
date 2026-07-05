// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * v:2 structural commitment-binding (ADR-0013) — UNAUDITED REFERENCE.
 *
 * Closes the LINKAGE CONTRACT gap documented in `policyproof.ts`: a policy-
 * satisfaction proof attests a property of the COMMITTED amount, so end-to-end
 * soundness needs the issuer's Pedersen commitment to be the SAME amount the
 * kernel decided on. The fix (ADR-0013, after adversarial council review replaced
 * a heavy ZK equality circuit): hash the canonical intent SKELETON (amount omitted —
 * see CB-001) AND the compressed commitment together, so any other commitment yields a
 * different digest, while the public digest never leaks the amount.
 *
 * TRUST MODEL (read before integrating — the review panel flagged this):
 *  - The BINDER (the admission kernel / issuer, which holds the plaintext amount
 *    and the blinding) guarantees the commitment opens to the intent's own amount.
 *    `bindAmountCommitment` derives the committed value DIRECTLY from
 *    `intent.amount`, so the commitment cannot be to a different value than the
 *    intent records.
 *  - `boundIntentDigest` / `verifyBoundCommitment` prove only POINT-binding: that a
 *    given commitment point belongs to this exact intent. They do NOT by themselves
 *    prove the commitment opens to `intent.amount`.
 *  - A verifier that HOLDS the opening (the kernel, or a non-private auditor) uses
 *    `verifyBoundAmount`, which additionally checks `commit(intent.amount, opening)`
 *    equals the commitment.
 *  - A PRIVACY verifier (no amount, no opening) CAN recompute this digest from the
 *    amount-free intent skeleton + the commitment (the amount is not in the pre-image,
 *    CB-001), and relies on the binder's signature + the range / policy-satisfaction
 *    proof for the amount. Structural binding does NOT defend against a binder that is
 *    itself malicious at admission — that is the quorum / attestation model's job.
 *
 * SCOPE / STATUS: binding PRIMITIVE + verification, with tests. Wiring it into the
 * signed v:2 receipt body is a clearly-scoped follow-up. Soundness of the
 * underlying range proof remains CLASSICAL and UNAUDITED — no soundness claim until
 * external ZK audit (docs/STATUS.md, ADR-0013).
 */

import { commit, type Pt } from './zkrange.js'
import { commitAmount } from './policyproof.js'
import {
  DOMAIN_TAGS,
  encodeCanonical,
  SHA3_SHAKE256,
  constantTimeEqual,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

const DOMAIN = DOMAIN_TAGS.COMMIT_BIND

export class CommitBindError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'CommitBindError'
  }
}

/**
 * The intent's amount as a non-negative bigint. Throws if absent or not a SAFE
 * integer — `ActionIntent.amount` is a JS `number`, so values above 2^53 are not
 * exactly representable and are rejected here rather than silently rounded (a
 * soundness hazard the review panel flagged).
 */
export function intentAmount(intent: ActionIntent): bigint {
  const a = intent.amount
  if (a === undefined) throw new CommitBindError('intent carries no amount to bind')
  if (!Number.isSafeInteger(a) || a < 0) {
    throw new CommitBindError('intent.amount must be a non-negative safe integer')
  }
  return BigInt(a)
}

/**
 * Bound intent digest = SHA3-256 over the deterministic CBOR encoding of
 * {domain, intent-skeleton, commitment}, where the skeleton is the intent with its
 * `amount` OMITTED.
 *
 * CB-001 (Team Apex audit, 2026-06-21): this digest is a PUBLIC, externally-
 * recomputable receipt field. Hashing the plaintext `amount` into it would NULLIFY the
 * commitment's perfect hiding — anyone holding the receipt could brute-force the amount
 * over its small enumerable domain by recomputing the digest per candidate. The amount
 * is instead bound CRYPTOGRAPHICALLY by the commitment (and checked against
 * `intent.amount` in `verifyBoundAmount`), so it is excluded from the pre-image. Any
 * future SECRET intent field must be excluded here likewise.
 *
 * Including the compressed commitment still binds the point to this exact intent
 * skeleton; dCBOR makes the encoding unambiguous (no concatenation-splitting).
 */
export function boundIntentDigest(intent: ActionIntent, commitment: Pt): Bytes {
  // Bind every intent field EXCEPT the secret amount (CB-001). The commitment carries the
  // amount's binding; the public digest must not make it brute-forceable.
  const skeleton = Object.fromEntries(Object.entries(intent).filter(([k]) => k !== 'amount'))
  const preimage = encodeCanonical({
    domain: DOMAIN,
    intent: skeleton,
    commitment: commitment.toBytes(),
  })
  return SHA3_SHAKE256.digest(preimage)
}

/** Hex of the bound digest — a stable, externally-recomputable receipt field. */
export function boundIntentDigestHex(intent: ActionIntent, commitment: Pt): string {
  return bytesToHex(boundIntentDigest(intent, commitment))
}

/**
 * POINT-binding check ONLY: true iff `commitment` is the point bound into `digest`
 * for this intent. Does NOT prove the commitment opens to `intent.amount` — use
 * `verifyBoundAmount` when the opening is available.
 */
export function verifyBoundCommitment(
  intent: ActionIntent,
  commitment: Pt,
  digest: Bytes,
): boolean {
  return constantTimeEqual(boundIntentDigest(intent, commitment), digest)
}

/**
 * FULL check (needs the opening): the commitment is bound to this intent AND opens
 * to the intent's own amount. This is what the kernel / a non-private auditor uses.
 */
export function verifyBoundAmount(
  intent: ActionIntent,
  commitment: Pt,
  opening: bigint,
  digest: Bytes,
): boolean {
  if (!verifyBoundCommitment(intent, commitment, digest)) return false
  const expected = commit(intentAmount(intent), opening)
  return constantTimeEqual(expected.toBytes(), commitment.toBytes())
}

/** The intent's amount, committed and bound to its intent. */
export interface BoundAmount {
  readonly commitment: Pt
  /** Secret blinding; kept by the prover to build the satisfaction proof. */
  readonly opening: bigint
  /** SHA3-256 digest binding the commitment to the intent. */
  readonly digest: Bytes
}

/**
 * Commit to the intent's OWN amount (derived from `intent.amount`, not a separate
 * parameter — so the commitment cannot be to a different value than the intent
 * records) and bind it to the intent.
 */
export function bindAmountCommitment(intent: ActionIntent): BoundAmount {
  const { commitment, opening } = commitAmount(intentAmount(intent))
  return { commitment, opening, digest: boundIntentDigest(intent, commitment) }
}
