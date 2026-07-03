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
 *
 * The intent commitment is SALTED so it is HIDING, not merely binding (RCPT‑001,
 * Team Apex 2026‑06‑21; ADR‑0014): a high‑entropy per‑receipt salt is folded into
 * `commitments.intent` so a low‑entropy field (e.g. `amount`) cannot be
 * brute‑forced from the PUBLIC leaf. The salt is carried on the `Receipt` wrapper
 * (`intentSalt`) and is DELIBERATELY NOT part of `ReceiptBody` / the leaf; it is
 * revealed only to authorized verifiers for selective disclosure.
 */

import {
  activeSuiteIds,
  encodeCanonical,
  SHA3_SHAKE256,
  signerFor,
  randomBytes,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { bytesEqual, checkInclusion, type InclusionWitness } from '../../translog/src/index.js'
import { commitField, verifyDisclosure } from '../../disclosure/src/selective.js'

/** Salt length for the hiding intent commitment — 256‑bit CSPRNG (ADR‑0014). */
export const INTENT_SALT_BYTES = 32

export interface ReceiptCommitments {
  /**
   * SALTED, HIDING commitment to the full intent: `SHA3(canonical({domain, salt,
   * intent}))` with a high‑entropy per‑receipt salt (ADR‑0014). The salt lives on
   * the `Receipt` wrapper, never here — so this published value does NOT leak
   * low‑entropy intent fields (e.g. `amount`) to a log observer (RCPT‑001).
   */
  readonly intent: string
  readonly capability: string
  readonly policy: string
  /**
   * SALTED, HIDING commitment to the replay input hash — `commitField(replayInputHash,
   * salt)`. The raw replay hash is SHA3 over the whole KernelInput (which holds the
   * low-entropy `amount`), so publishing it raw would re-leak the amount from the
   * public leaf even though `intent` is salted (RCPT-002). The salt is off-leaf.
   */
  readonly inputHash: string
  /** SALTED, HIDING commitment to the replay decision hash (`commitField(receiptHash,
   *  salt)`); raw it transitively re-leaks the amount via the embedded input hash
   *  (RCPT-002). Off-leaf salt. */
  readonly decisionHash: string
}

/**
 * The signed receipt body — and the EXACT bytes of the transparency‑log leaf
 * (`receiptLeaf`). It contains only hash commitments and metadata; in particular
 * it carries NO salt (the intent salt is on `Receipt`, out of the leaf — ADR‑0014).
 */
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
  /**
   * High‑entropy salt that makes `body.commitments.intent` hiding (ADR‑0014).
   * NOT part of `body` / the log leaf — held out of band by the issuer/holder and
   * disclosed only to authorized verifiers (`verifyIntentDisclosure`). Fresh per
   * receipt: two receipts for the same intent get different commitments.
   */
  readonly intentSalt: Bytes
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
  /**
   * Optional override for the intent‑commitment salt (ADR‑0014). Omit in
   * production — a fresh 256‑bit CSPRNG salt is generated. Supply one only for
   * deterministic tests/KATs. Reusing a salt across receipts weakens hiding.
   */
  readonly intentSalt?: Bytes
}

export function buildReceipt(p: BuildReceiptParams): Receipt {
  // Hiding intent commitment (RCPT‑001 / ADR‑0014): a fresh high‑entropy salt makes
  // commitments.intent non‑brute‑forceable from the public leaf. The salt rides on
  // the Receipt wrapper, never in the body/leaf.
  const intentSalt = p.intentSalt ?? randomBytes(INTENT_SALT_BYTES)
  const body: ReceiptBody = {
    v: 1,
    suite: p.suite,
    evaluatorVersion: p.evaluatorVersion,
    effect: p.effect,
    tier: p.tier,
    jurisdiction: p.jurisdiction,
    timestamp: p.timestamp,
    commitments: {
      intent: commitField(p.intent, intentSalt),
      capability: p.capability === null ? 'none' : hashHex(p.capability),
      policy: hashHex(p.policy),
      // The replay input/decision hashes are SHA3 over the full KernelInput, which
      // contains the low-entropy `amount`. Published RAW, they re-leak the amount
      // from the PUBLIC leaf by brute-force — bypassing the salted `intent`
      // commitment (RCPT-002, Team Apex 2026-06-21). Salt them with the same
      // off-leaf intentSalt so the WHOLE leaf is hiding; an authorized auditor with
      // the salt + replay bundle recomputes commitField(replay().inputHash, salt).
      inputHash: commitField(p.inputHash, intentSalt),
      decisionHash: commitField(p.decisionHash, intentSalt),
    },
  }
  const sig = signerFor(p.suite).sign(encodeCanonical(body), p.issuerSecretKey)
  return { body, sig, signerPublicKey: p.issuerPublicKey, intentSalt }
}

/**
 * The canonical bytes appended to the transparency log for this receipt — exactly
 * `encodeCanonical(r.body)`. The intent salt (`r.intentSalt`) is NOT in the body,
 * so it is never published in the leaf (ADR‑0014); a log observer sees only the
 * salted, hiding `commitments.intent`.
 */
export function receiptLeaf(r: Receipt): Bytes {
  return encodeCanonical(r.body)
}

/** Verify the receipt's PQ signature under its embedded issuer key. Fail-closed: a receipt is
 *  "regulator-ready evidence anyone can verify", so `r.body.suite` is attacker-transportable. Reject an
 *  inactive/unknown suite and swallow any signer throw, so verifying a batch of gossiped receipts
 *  never crashes on one poisoned receipt (RECEIPT-SUITE-THROW-001, AAC cycle-5 completeness sweep —
 *  the sole verify-side signerFor dispatch that lacked this guard). The suite is bound into the signed
 *  body, so a swapped label already fails the signature; this only converts a crash into a clean false. */
export function verifyReceipt(r: Receipt): boolean {
  if (!activeSuiteIds().includes(r.body.suite)) return false
  try {
    return signerFor(r.body.suite).verify(r.sig, encodeCanonical(r.body), r.signerPublicKey)
  } catch {
    return false
  }
}

/**
 * Authorized selective disclosure of the receipt's intent (ADR‑0014). Recomputes
 * the salted, hiding `commitments.intent` from `revealedIntent` + the receipt's
 * `intentSalt` and matches it. The salt is the disclosure secret: a verifier
 * WITHOUT it cannot recompute (nor brute‑force) the commitment from the public
 * leaf — that is the RCPT‑001 fix. Returns false on a mismatch (wrong intent,
 * tampered amount, or wrong salt).
 */
export function verifyIntentDisclosure(r: Receipt, revealedIntent: unknown): boolean {
  return verifyDisclosure(r.body.commitments.intent, revealedIntent, r.intentSalt)
}

export interface ExternalVerdict {
  readonly ok: boolean
  readonly reasons: string[]
}

/**
 * Full external verification: trust ONLY the expected issuer public key and a
 * gossiped log root. Checks signature, issuer-key match, leaf↔body binding, and
 * Merkle inclusion. No trust in the issuer's or the log operator's good behavior.
 *
 * Operates purely on `r.body` — it neither needs nor reads `r.intentSalt`, so
 * inclusion/signature verification is unchanged by the hiding intent commitment
 * (ADR‑0014). Disclosing the intent is a separate, authorized step
 * (`verifyIntentDisclosure`), which is the only path that consumes the salt.
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
