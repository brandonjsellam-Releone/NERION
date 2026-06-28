// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * v:2 structural commitment-binding (ADR-0013, hardened by ADR-0042) — UNAUDITED REFERENCE.
 *
 * Closes the LINKAGE CONTRACT gap documented in `policyproof.ts`: a policy-
 * satisfaction proof attests a property of the COMMITTED amount, so end-to-end
 * soundness needs the issuer's Pedersen commitment to be the SAME amount the
 * kernel decided on. The fix (ADR-0013, after adversarial council review replaced
 * a heavy ZK equality circuit): hash the canonical intent SKELETON (amount omitted —
 * see CB-001) AND the compressed commitment together, so any other commitment yields a
 * different digest, while the public digest never leaks the amount.
 *
 * CB-002 / ADR-0042 (ZK audit-prep 2026-06-27, dossier P6): the skeleton is built
 * from an ALLOWLIST of known-public fields (`PUBLIC_INTENT_FIELDS` = {type, resource}),
 * not a denylist that excluded only `amount`. Every OTHER non-amount field
 * (`counterparty`, `params`, and any FUTURE field) is folded in as a high-entropy
 * SALTED commitment instead of plaintext, so it stays point-bound (a malicious binder
 * still cannot vary it without changing the digest) while no longer being brute-forceable
 * from the public digest. See `boundIntentDigest` and ADR-0042 for the
 * secrecy-vs-binding-completeness tradeoff.
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
 *  - A PRIVACY verifier recomputes this digest from the amount-free intent skeleton +
 *    the commitment. For an intent that carries non-public fields it ALSO needs the
 *    binding `salt` (revealed out of band to authorized verifiers, exactly like the
 *    receipt's `intentSalt`, ADR-0014); it relies on the binder's signature + the
 *    range / policy-satisfaction proof for the amount. Structural binding does NOT
 *    defend against a binder that is itself malicious at admission — that is the
 *    quorum / attestation model's job.
 *
 * SCOPE / STATUS: binding PRIMITIVE + verification, with tests. Wiring it (and the
 * binding salt) into the signed v:2 receipt body is a clearly-scoped follow-up.
 * Soundness of the underlying range proof remains CLASSICAL and UNAUDITED — no
 * soundness claim until external ZK audit (docs/STATUS.md, ADR-0013, ADR-0042).
 */

import { commit, type Pt } from './zkrange.js'
import { commitAmount } from './policyproof.js'
import { commitField } from './selective.js'
import {
  encodeCanonical,
  SHA3_SHAKE256,
  constantTimeEqual,
  randomBytes,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

const DOMAIN = 'PolarSeek/disclosure/commit-bind/v2'

/**
 * ALLOWLIST of `ActionIntent` fields hashed into the public digest in PLAINTEXT
 * (CB-002 / ADR-0042). These are the structural, non-privacy-sensitive identity of
 * the action: a public verifier may recompute and check them without any secret.
 *
 * Anything NOT in this set (and not `amount`, which is omitted entirely — CB-001) is
 * privacy-sensitive by default and folded in as a SALTED commitment (binding kept,
 * hiding added). Adding a field here is a CONSCIOUS, council-reviewable act: a field
 * placed here becomes brute-forceable from the public digest if it is low-entropy, so
 * it must be genuinely public. Removing a field that should be public would weaken
 * point-binding completeness. The surface-lock test pins this set.
 */
export const PUBLIC_INTENT_FIELDS: readonly string[] = ['type', 'resource']

/** Field omitted from the digest entirely — bound cryptographically by the Pedersen commitment (CB-001). */
const OMITTED_FIELD = 'amount'

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

/** True iff the intent carries any non-public, non-amount field (i.e. a binding salt is required). */
export function hasSaltedFields(intent: ActionIntent): boolean {
  return Object.keys(intent).some((k) => k !== OMITTED_FIELD && !PUBLIC_INTENT_FIELDS.includes(k))
}

/**
 * Build the digest pre-image's `intent` map (CB-002 / ADR-0042). Allowlisted public
 * fields go in as PLAINTEXT; every other present field (except the omitted `amount`)
 * goes in as a SALTED commitment over `{field, value}`, so it stays point-bound but is
 * not brute-forceable. FAIL-CLOSED: a non-public field with no salt is an error — we
 * never silently fall back to plaintext (that would re-open the CB-001/CB-002 surface).
 */
function buildBoundSkeleton(intent: ActionIntent, salt?: Bytes): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(intent)) {
    if (k === OMITTED_FIELD) continue // amount: bound by the Pedersen commitment (CB-001)
    if (PUBLIC_INTENT_FIELDS.includes(k)) {
      out[k] = v // allowlisted public field: plaintext (binding + publicly recomputable)
    } else {
      if (salt === undefined) {
        throw new CommitBindError(
          `intent field '${k}' is privacy-sensitive (not in PUBLIC_INTENT_FIELDS) and requires a binding salt; ` +
            `refusing to hash it in plaintext (CB-002 / ADR-0042)`,
        )
      }
      // Salted (hiding) commitment over {field, value} — reuses the audited selective.ts
      // salted-commit primitive; the field name domain-separates one field from another.
      out[k] = commitField({ field: k, value: v }, salt)
    }
  }
  return out
}

/**
 * Bound intent digest = SHA3-256 over the deterministic CBOR encoding of
 * {domain, intent-skeleton, commitment}.
 *
 * The skeleton (CB-002 / ADR-0042) keeps the allowlisted public fields
 * (`PUBLIC_INTENT_FIELDS`) as PLAINTEXT and folds every OTHER non-`amount` field into a
 * high-entropy salted commitment; `amount` is omitted entirely (CB-001), bound instead
 * by the Pedersen `commitment` and re-checked in `verifyBoundAmount`.
 *
 * Why this shape:
 *  - SECRECY (P6 fix): hashing a low-entropy field (e.g. `counterparty`, a `params`
 *    value) in plaintext would let anyone holding the public digest + the rest of the
 *    skeleton brute-force it over its enumerable domain — the same failure CB-001 fixed
 *    for `amount`. Salting (high-entropy salt, kept off the public artifact) removes the
 *    brute-force handle.
 *  - BINDING-COMPLETENESS: salting (vs. dropping the field) keeps every field
 *    point-bound — a malicious binder still cannot vary `counterparty`/`params` without
 *    changing the digest. Dropping a legitimately-public field, by contrast, would let
 *    it vary silently; that inverse risk is why the public set is an explicit allowlist.
 *
 * `salt` is REQUIRED whenever the intent carries a non-public field; passing it for a
 * public-only intent is harmless (it is consumed only by salted fields). dCBOR (sorted
 * keys, definite lengths) makes the encoding unambiguous; the digest for an intent
 * confined to the public allowlist (+ amount) is byte-identical to the pre-ADR-0042 digest.
 */
export function boundIntentDigest(intent: ActionIntent, commitment: Pt, salt?: Bytes): Bytes {
  const skeleton = buildBoundSkeleton(intent, salt)
  const preimage = encodeCanonical({
    domain: DOMAIN,
    intent: skeleton,
    commitment: commitment.toBytes(),
  })
  return SHA3_SHAKE256.digest(preimage)
}

/** Hex of the bound digest — a stable, recomputable receipt field (needs the salt for salted fields). */
export function boundIntentDigestHex(intent: ActionIntent, commitment: Pt, salt?: Bytes): string {
  return bytesToHex(boundIntentDigest(intent, commitment, salt))
}

/**
 * POINT-binding check ONLY: true iff `commitment` is the point bound into `digest`
 * for this intent. Does NOT prove the commitment opens to `intent.amount` — use
 * `verifyBoundAmount` when the opening is available. Pass the same `salt` the digest
 * was built with (required when the intent carries salted fields).
 */
export function verifyBoundCommitment(
  intent: ActionIntent,
  commitment: Pt,
  digest: Bytes,
  salt?: Bytes,
): boolean {
  return constantTimeEqual(boundIntentDigest(intent, commitment, salt), digest)
}

/**
 * FULL check (needs the opening): the commitment is bound to this intent AND opens
 * to the intent's own amount. This is what the kernel / a non-private auditor uses.
 * Pass the same `salt` the digest was built with (required for salted fields).
 */
export function verifyBoundAmount(
  intent: ActionIntent,
  commitment: Pt,
  opening: bigint,
  digest: Bytes,
  salt?: Bytes,
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
  /** SHA3-256 digest binding the commitment to the intent. */
  readonly digest: Bytes
  /**
   * The per-binding salt that folds the intent's non-public fields into the digest
   * (CB-002 / ADR-0042). Present iff the intent carried any such field. It is a
   * disclosure secret: keep it OFF the public artifact and reveal it only to
   * authorized verifiers so they can recompute `digest` (same model as `intentSalt`).
   */
  readonly salt?: Bytes
}

/**
 * Commit to the intent's OWN amount (derived from `intent.amount`, not a separate
 * parameter — so the commitment cannot be to a different value than the intent
 * records) and bind it to the intent.
 *
 * If the intent carries any non-public field, a fresh 32-byte CSPRNG `salt` is minted
 * (unless one is supplied for determinism/testing) and returned on the result so the
 * binder can hand it to authorized verifiers; intents confined to the public allowlist
 * need no salt and produce the pre-ADR-0042 digest unchanged.
 */
export function bindAmountCommitment(intent: ActionIntent, salt?: Bytes): BoundAmount {
  const bindingSalt = salt ?? (hasSaltedFields(intent) ? randomBytes(32) : undefined)
  const { commitment, opening } = commitAmount(intentAmount(intent))
  const digest = boundIntentDigest(intent, commitment, bindingSalt)
  return bindingSalt === undefined
    ? { commitment, opening, digest }
    : { commitment, opening, digest, salt: bindingSalt }
}
