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
 * {domain, salt, intent-skeleton, commitment}, where the skeleton is the intent with
 * its `amount` OMITTED.
 *
 * CB-001 (Team Apex audit, 2026-06-21): `amount` is excluded from the pre-image for a
 * reason INDEPENDENT of brute-forceability — the design goal (stated in the module
 * TRUST MODEL above) is that a PRIVACY verifier can recompute this digest from just
 * `{intent-minus-amount, commitment}`, without ever learning the amount; the amount's
 * binding comes from the COMMITMENT itself (checked in `verifyBoundAmount`), not from
 * appearing in this preimage. Putting it back — even salted — would break that
 * recomputability-without-the-amount property. `amount` therefore stays excluded here.
 *
 * SEAM-CB-SALT-001 (AAC council review, 2026-07-11): every OTHER field — including
 * `counterparty` (types.ts: "never re-identified across calls") and arbitrary `params`
 * — WAS hashed into this digest unsalted, so a low-entropy/enumerable value among them
 * was brute-forceable from the public digest (the same CB-001 class, just left
 * unfixed on this specific pre-image). Mirroring `selective.ts`'s salted mode
 * (RCPT-001/ADR-0014), `salt` is now REQUIRED (not optional — an opt-in defense here
 * would repeat the exact mistake CUSTODY-SEAL-002 just closed elsewhere in this
 * session) and folded into the preimage. A high-entropy salt makes EVERY field in the
 * skeleton non-brute-forceable, including any field added to `ActionIntent` in the
 * future — this is a global, forward-safe fix, not a per-field allowlist that would
 * need remembering to extend. Reuse the SAME salt a caller already mints for its other
 * receipt commitments (e.g. `receipt.ts`'s `intentSalt`) — one salt per receipt, kept
 * off the public leaf, revealed only to an authorized disclosure verifier.
 *
 * Including the compressed commitment still binds the point to this exact intent
 * skeleton; dCBOR makes the encoding unambiguous (no concatenation-splitting).
 */
export function boundIntentDigest(intent: ActionIntent, commitment: Pt, salt: Bytes): Bytes {
  // Bind every intent field EXCEPT the secret amount (CB-001; see the doc comment above for
  // why amount specifically stays excluded even under salting). The commitment carries the
  // amount's binding; the public digest must not make it brute-forceable.
  const skeleton = Object.fromEntries(Object.entries(intent).filter(([k]) => k !== 'amount'))
  const preimage = encodeCanonical({
    domain: DOMAIN,
    salt,
    intent: skeleton,
    commitment: commitment.toBytes(),
  })
  return SHA3_SHAKE256.digest(preimage)
}

/** Hex of the bound digest — a stable, externally-recomputable receipt field. */
export function boundIntentDigestHex(intent: ActionIntent, commitment: Pt, salt: Bytes): string {
  return bytesToHex(boundIntentDigest(intent, commitment, salt))
}

/**
 * POINT-binding check ONLY: true iff `commitment` is the point bound into `digest`
 * for this intent (under the same `salt` the digest was built with). Does NOT prove
 * the commitment opens to `intent.amount` — use `verifyBoundAmount` when the opening
 * is available.
 */
export function verifyBoundCommitment(
  intent: ActionIntent,
  commitment: Pt,
  digest: Bytes,
  salt: Bytes,
): boolean {
  return constantTimeEqual(boundIntentDigest(intent, commitment, salt), digest)
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
  salt: Bytes,
): boolean {
  if (!verifyBoundCommitment(intent, commitment, digest, salt)) return false
  const expected = commit(intentAmount(intent), opening)
  return constantTimeEqual(expected.toBytes(), commitment.toBytes())
}

/** The intent's amount, committed and bound to its intent. */
export interface BoundAmount {
  readonly commitment: Pt
  /** Secret blinding; kept by the prover to build the satisfaction proof. */
  readonly opening: bigint
  /** SHA3-256 digest binding the commitment to the intent (salted — see SEAM-CB-SALT-001). */
  readonly digest: Bytes
}

/**
 * Commit to the intent's OWN amount (derived from `intent.amount`, not a separate
 * parameter — so the commitment cannot be to a different value than the intent
 * records) and bind it to the intent. `salt` should be the SAME high-entropy salt the
 * caller uses for its other receipt-field commitments (SEAM-CB-SALT-001) — kept off
 * the public leaf, revealed only to an authorized disclosure verifier.
 */
export function bindAmountCommitment(intent: ActionIntent, salt: Bytes): BoundAmount {
  const { commitment, opening } = commitAmount(intentAmount(intent))
  return { commitment, opening, digest: boundIntentDigest(intent, commitment, salt) }
}
