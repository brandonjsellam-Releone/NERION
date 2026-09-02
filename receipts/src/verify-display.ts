// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Displayed-vs-signed gate for the standalone receipt CLI (G3).
 *
 * `verifyReceiptInclusion` already trusts only `r.body` (the signed ReceiptBody).
 * The portable bundle also carries an UNSIGNED convenience wrapper `decision`
 * `{effect, tier, …}`. Painting that wrapper next to VERIFIED is a
 * displayed-vs-signed fail: swapping `decision.effect` in JSON would still
 * print VERIFIED. This module never returns wrapper fields as the verified
 * paint, and fail-closes when the wrapper disagrees with the signed body.
 *
 * Software-only: no signer, no ML-DSA, no primitives. Tests construct JSON
 * fixtures and call these functions directly.
 */

export interface SignedDisplayFields {
  readonly effect: string
  readonly tier: number
  readonly suite: string
  readonly jurisdiction: string
}

export interface DisplayVerdict {
  readonly ok: boolean
  readonly reasons: string[]
  /**
   * Signature-covered fields taken ONLY from `receipt.body`. Never from
   * `bundle.decision`. Populated when the body is well-formed so FAIL reasons
   * can cite the signed values; the CLI must not print VERIFIED unless `ok`.
   */
  readonly signed: SignedDisplayFields | null
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/**
 * Extract the fields a verifier may associate with VERIFIED, and fail-close
 * if an unsigned wrapper `decision` diverges from the signed ReceiptBody.
 */
export function signedDisplayFields(bundle: unknown): DisplayVerdict {
  if (!isRecord(bundle)) {
    return { ok: false, reasons: ['bundle is not a JSON object'], signed: null }
  }
  const receipt = bundle.receipt
  if (!isRecord(receipt)) {
    return { ok: false, reasons: ['bundle.receipt missing'], signed: null }
  }
  const body = receipt.body
  if (!isRecord(body)) {
    return { ok: false, reasons: ['signed ReceiptBody missing'], signed: null }
  }
  const effect = body.effect
  const tier = body.tier
  if (typeof effect !== 'string' || effect.length === 0) {
    return { ok: false, reasons: ['signed ReceiptBody.effect missing'], signed: null }
  }
  if (typeof tier !== 'number' || !Number.isFinite(tier)) {
    return { ok: false, reasons: ['signed ReceiptBody.tier missing'], signed: null }
  }
  const signed: SignedDisplayFields = {
    effect,
    tier,
    suite: typeof body.suite === 'string' ? body.suite : '',
    jurisdiction: typeof body.jurisdiction === 'string' ? body.jurisdiction : '',
  }

  if (bundle.decision === undefined) {
    return { ok: true, reasons: [], signed }
  }
  if (!isRecord(bundle.decision)) {
    return {
      ok: false,
      reasons: ['unsigned wrapper decision is not an object'],
      signed,
    }
  }
  const reasons: string[] = []
  if (bundle.decision.effect !== effect) {
    reasons.push(
      `unsigned wrapper decision.effect ${JSON.stringify(bundle.decision.effect)} diverges from signed ReceiptBody.effect ${JSON.stringify(effect)}`,
    )
  }
  if (bundle.decision.tier !== tier) {
    reasons.push(
      `unsigned wrapper decision.tier ${JSON.stringify(bundle.decision.tier)} diverges from signed ReceiptBody.tier ${JSON.stringify(tier)}`,
    )
  }
  return { ok: reasons.length === 0, reasons, signed }
}

/**
 * Fields the CLI may print beside VERIFIED. Null forbids VERIFIED — including
 * when the unsigned wrapper `decision.effect`/`tier` disagrees with the body.
 */
export function verifiedPaint(bundle: unknown): SignedDisplayFields | null {
  const verdict = signedDisplayFields(bundle)
  return verdict.ok ? verdict.signed : null
}
