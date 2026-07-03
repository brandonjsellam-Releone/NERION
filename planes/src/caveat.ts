// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Permit caveats — OFFLINE, holder-side, least-privilege attenuation of a Plane-1 PermitToken
 * (macaroon-style first-party caveats; Team Apex R&D council 2026-06-28).
 *
 * WHAT IT ADDS. A capability holder that received a kernel-issued PermitToken can NARROW it further
 * and hand the narrowed permit to a sub-agent / tool, WITHOUT a kernel round-trip and WITHOUT the
 * audience MAC key. The resource (which holds the audience key) recomputes the chain and enforces
 * the base claims AND every caveat conjunctively, so a caveat can only ever RESTRICT. This is
 * decentralized, offline, third-party-verifiable least-privilege delegation for agent workflows —
 * the categorical move a central-permission gatekeeper cannot make.
 *
 * HOW (standard macaroon chaining over the EXISTING permit MAC; no new crypto primitive):
 *   M0 = HMAC-SHA-384(audienceKey, toBeMaced(suite, body))      // the kernel-issued permit's root MAC
 *   M_i = HMAC-SHA-384(M_{i-1}, caveatChainMessage(caveat_i))    // each holder-added caveat
 * A forwarded {@link AttenuatedPermit} carries ONLY (suite, body, caveats, mac=M_n) — crucially NOT
 * M0. The holder folds a caveat with the MAC it currently holds (M0 from its own base permit, or
 * M_{n-1}); the recipient sub-agent gets only M_n and so CANNOT strip caveats (it cannot reverse
 * HMAC to recover M_{k<n}) and CANNOT fall back to the un-attenuated permit (it never receives M0).
 * The resource recomputes M0 from its audience key (it never trusts a transmitted M0), re-folds the
 * caveats, and constant-time compares to M_n.
 *
 * SECURITY / HONESTY. Soundness reduces to the same HMAC-SHA-384 the PermitToken already relies on
 * (macaroon EUF security): without M_{i-1} you cannot extend the chain, and you cannot drop a caveat
 * without invalidating the MAC. Caveats are FIRST-PARTY only (predicates the resource evaluates from
 * the request it already has) — no third-party/discharge caveats. Attenuation is monotone by
 * construction: the resource enforces the base permit PLUS the conjunction of all caveats, so a
 * caveat cannot broaden authority. UNAUDITED reference, like the rest of the disclosure/SDK layer.
 *
 * SCOPE (honest). A Nerion PermitToken is bound to the EXACT action via `actionHash(intent)`, so
 * amount / counterparty / action-type are already point-fixed by the base permit. The genuinely
 * NON-REDUNDANT, value-adding caveat today is therefore `expiresAtMost` — offline shortening of a
 * forwarded permit's lifetime (the base `exp` is a range `now ≤ exp`), e.g. handing a sub-agent a
 * 5-second permit derived from a 5-minute one without a kernel round-trip. The `amountAtMost` /
 * `counterpartyIs` / `actionPrefix` caveats are mechanically sound and never broaden, but for an
 * exact-action permit they are redundant with the `actionHash` binding (they can only further forbid
 * the one action the permit is already for); they are retained as defense-in-depth and as
 * forward-compatibility for any future action-FAMILY permit. The macaroon mechanism itself — offline,
 * unforgeable, third-party-verifiable, monotone attenuation — is the categorical contribution.
 */

import {
  HMAC_SHA384,
  constantTimeEqual,
  encodeCanonical,
  permitMac,
  type Bytes,
  type PermitToken,
} from '../../crypto/src/index.js'
import {
  verifyPermitForAction,
  MAX_PERMIT_BODY_BYTES,
  MAX_PERMIT_SUITE_LEN,
  type PermitCheck,
  type PermitVerdict,
} from './permit.js'

/** Domain separator for the caveat MAC chain (separates it from the base permit MAC transcript). */
const CAVEAT_CONTEXT = 'Nerion/permit-caveat/v1'

/** Bound the attacker-supplied caveat count before the HMAC chain runs (decode-side DoS guard).
 *  Honest attenuation chains are short (a handful of narrowings); reject beyond this fail-closed. */
const MAX_CAVEATS = 16

/**
 * A first-party caveat: a monotone RESTRICTION the resource enforces from the request it already
 * has. Each can only narrow the base permit.
 *  - `expiresAtMost`  — the action time `now` must be ≤ `value` (tighter than the base exp).
 *  - `amountAtMost`   — `intent.amount` must be ≤ `value`.
 *  - `counterpartyIs` — `intent.counterparty` must equal `value`.
 *  - `actionPrefix`   — `intent.type` must be `value` or a dotted-namespace child of it.
 */
export type Caveat =
  | { readonly kind: 'expiresAtMost'; readonly value: number }
  | { readonly kind: 'amountAtMost'; readonly value: number }
  | { readonly kind: 'counterpartyIs'; readonly value: string }
  | { readonly kind: 'actionPrefix'; readonly value: string }

/**
 * A forwarded attenuated permit: the base permit's IDENTIFIER (suite + body) plus holder-added
 * caveats and the macaroon chain MAC M_n. It deliberately does NOT carry the root MAC M0, so a
 * recipient cannot strip caveats or fall back to the un-attenuated permit.
 */
export interface AttenuatedPermit {
  readonly suite: string
  /** Canonical CBOR bytes of the base permit claims (the macaroon "identifier"). */
  readonly body: Bytes
  /** Holder-added caveats, in chain order. */
  readonly caveats: readonly Caveat[]
  /** HMAC-SHA-384 chain MAC M_n (root M0 is never transmitted). */
  readonly mac: Bytes
}

/** Canonical, domain-separated chain message for one caveat (length-prefixed dCBOR — unambiguous). */
function caveatChainMessage(c: Caveat): Bytes {
  return encodeCanonical([CAVEAT_CONTEXT, c.kind, c.value])
}

/** Fold `caveats` over `rootMac` to produce the macaroon chain MAC. */
function chainMac(rootMac: Bytes, caveats: readonly Caveat[]): Bytes {
  let acc = rootMac
  for (const c of caveats) acc = HMAC_SHA384.compute(acc, caveatChainMessage(c))
  return acc
}

/**
 * OFFLINE, holder-side: add a caveat to a permit (or an already-attenuated permit), narrowing it.
 * Needs only the permit's current MAC (`permit.mac` — M0 for a base permit, M_{n-1} for an
 * already-attenuated one) — never the audience key — so a holder can attenuate before forwarding to
 * a sub-agent without contacting the kernel. The root MAC M0 is not retained in the result.
 */
export function attenuate(
  permit: PermitToken | AttenuatedPermit,
  caveat: Caveat,
): AttenuatedPermit {
  const isAttenuated = 'caveats' in permit
  const caveats = isAttenuated ? [...permit.caveats, caveat] : [caveat]
  const mac = HMAC_SHA384.compute(permit.mac, caveatChainMessage(caveat))
  return { suite: permit.suite, body: permit.body, caveats, mac }
}

/** Enforce one caveat against the action being checked. Returns a reason string on violation, else null. */
function enforceCaveat(c: Caveat, check: PermitCheck): string | null {
  switch (c.kind) {
    case 'expiresAtMost':
      if (!Number.isSafeInteger(c.value)) return 'caveat expiresAtMost is malformed'
      return check.now <= c.value ? null : 'caveat expiry exceeded'
    case 'amountAtMost': {
      if (!Number.isSafeInteger(c.value) || c.value < 0) return 'caveat amountAtMost is malformed'
      const amount = check.intent.amount ?? 0
      if (!Number.isSafeInteger(amount) || amount < 0) return 'intent amount is malformed'
      return amount <= c.value ? null : 'caveat amount ceiling exceeded'
    }
    case 'counterpartyIs':
      return check.intent.counterparty === c.value ? null : 'caveat counterparty mismatch'
    case 'actionPrefix': {
      const t = check.intent.type
      const boundary = c.value.endsWith('.') ? c.value : c.value + '.'
      return t === c.value || t.startsWith(boundary) ? null : 'caveat action-prefix mismatch'
    }
    default:
      // A runtime-malformed (off-type) caveat from the wire: fail closed.
      return `unknown caveat kind: ${String((c as { kind?: unknown }).kind)}`
  }
}

/**
 * Resource-side: verify an attenuated permit and enforce the base claims AND every caveat.
 * Fail-closed on a bad base permit, an invalid caveat chain (tamper/forge/reorder/drop), an
 * over-long chain, or any violated caveat. The root MAC M0 is recomputed from `audienceKey` — a
 * transmitted M0 is never trusted (none is carried).
 */
export function verifyAttenuatedPermit(
  ap: AttenuatedPermit,
  audienceKey: Bytes,
  check: PermitCheck,
): PermitVerdict {
  // AAC cycle-4 — two use-time bypasses on this newer attenuated path:
  //  (1) Shape: `caveats` (and body/suite) are attacker-controlled wire fields. A non-array `caveats`
  //      would throw `.length` below (throw-instead-of-fail-closed); guard the shape first.
  //  (2) F5 size cap: the non-attenuated verifyPermitForAction caps body/suite BEFORE its HMAC, but
  //      it runs AFTER permitMac here — so without an equal pre-check an attacker forces a full
  //      canonical-encode + HMAC-SHA-384 over an UNAUTHENTICATED multi-MB `ap.body` (pre-auth work-
  //      amplification DoS). Enforce the identical cap before permitMac.
  const w = ap as unknown as { body?: unknown; suite?: unknown; caveats?: unknown }
  if (!(w.body instanceof Uint8Array) || typeof w.suite !== 'string' || !Array.isArray(w.caveats)) {
    return { ok: false, reasons: ['attenuated permit is malformed (body/suite/caveats)'] }
  }
  if (ap.body.length > MAX_PERMIT_BODY_BYTES || ap.suite.length > MAX_PERMIT_SUITE_LEN) {
    return { ok: false, reasons: ['permit token exceeds size bound'] }
  }
  if (ap.caveats.length > MAX_CAVEATS) {
    return { ok: false, reasons: [`too many caveats (> ${MAX_CAVEATS})`] }
  }
  // Recompute the root MAC M0 from the audience key (never trust a transmitted M0 — none is carried).
  const m0 = permitMac({ suite: ap.suite, body: ap.body }, audienceKey)
  // 1. The base must be a genuine kernel-issued permit for this audience + bound to this action.
  //    Reconstruct the base token with the recomputed M0 and run the full base enforcement (MAC,
  //    audience, actionHash, exp, effect, size cap). A wrong audience key yields a wrong M0 → reject.
  const base: PermitToken = { suite: ap.suite, body: ap.body, mac: m0 }
  const baseVerdict = verifyPermitForAction(base, audienceKey, check)
  if (!baseVerdict.ok) return baseVerdict
  // 2. The caveat chain must reconstruct from M0: any added/removed/reordered/tampered caveat
  //    changes the chain. Constant-time compare.
  if (!constantTimeEqual(chainMac(m0, ap.caveats), ap.mac)) {
    return {
      ok: false,
      reasons: ['attenuated permit caveat chain is invalid (tampered or forged)'],
    }
  }
  // 3. Enforce every caveat conjunctively — caveats only ever narrow the base grant.
  const reasons: string[] = []
  for (const c of ap.caveats) {
    const r = enforceCaveat(c, check)
    if (r !== null) reasons.push(r)
  }
  return { ok: reasons.length === 0, reasons }
}
