// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CB-001 / CB-002 exposure-surface lock (audit-prep 2026-06-27 — ZK dossier P6,
 * docs/council/zk-audit-prep-2026-06-27.md; decision recorded in ADR-0042).
 *
 * `boundIntentDigest` builds its PUBLIC, recomputable pre-image from an ALLOWLIST of
 * known-public fields (`PUBLIC_INTENT_FIELDS` = {type, resource}) — NOT the old
 * denylist that excluded only `amount` (CB-001). These tests LOCK that partition so any
 * change to it is a CONSCIOUS one reconciled with ADR-0042:
 *
 *   - `amount` is OMITTED entirely (bound by the Pedersen commitment, CB-001);
 *   - the allowlisted public fields {type, resource} are hashed in PLAINTEXT — they
 *     bind and are recomputable by anyone, with no salt;
 *   - every OTHER non-amount field — the privacy-sensitive `counterparty` ("never
 *     re-identified across calls", types.ts:26-27) and arbitrary `params` — is folded
 *     in as a high-entropy SALTED commitment (CB-002). It STAYS point-bound (changing
 *     it changes the digest, so binding-completeness holds), but is NOT brute-forceable
 *     from the public digest, and is recomputable only by a holder of the salt.
 *
 * If a maintainer moves a field between the public allowlist and the salted set, or
 * accidentally re-includes `amount`, a test here breaks — forcing reconciliation with
 * the allowlist-vs-denylist decision in ADR-0042.
 */

import { describe, it, expect } from 'vitest'
import { boundIntentDigestHex, PUBLIC_INTENT_FIELDS, CommitBindError } from '../src/commitbind.js'
import { commitAmount } from '../src/policyproof.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

describe('CB-002 public-digest exposure surface (ADR-0042 allowlist lock)', () => {
  // One FIXED commitment so the ONLY variable across comparisons is the intent skeleton.
  const C = commitAmount(500n).commitment
  // Fixed salts so a comparison isolates the field under test (in production the binder
  // mints a fresh CSPRNG salt per binding — see bindAmountCommitment).
  const SALT = new Uint8Array(32).fill(7)
  const SALT2 = new Uint8Array(32).fill(9)

  const base: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    counterparty: 'cp-001',
    amount: 500,
    params: { memo: 'q3' },
  }
  const digest = (i: ActionIntent, salt: Uint8Array = SALT): string =>
    boundIntentDigestHex(i, C, salt)

  it('ALLOWLIST: the public (plaintext) field set is exactly {type, resource}', () => {
    expect([...PUBLIC_INTENT_FIELDS].sort()).toEqual(['resource', 'type'])
  })

  it('EXCLUDES amount: changing only amount leaves the public digest unchanged (CB-001 hiding)', () => {
    expect(digest({ ...base, amount: 999_999 })).toBe(digest(base))
    expect(digest({ ...base, amount: 0 })).toBe(digest(base))
  })

  it('PUBLIC fields bind and need NO salt: digest is byte-identical with or without a salt', () => {
    const pub: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 500 }
    // A public-only intent is recomputable by anyone (no salt); passing a salt does not
    // change the digest because the salt is consumed only by salted fields.
    expect(boundIntentDigestHex(pub, C)).toBe(boundIntentDigestHex(pub, C, SALT))
    // ...and the allowlisted fields still bind:
    expect(boundIntentDigestHex({ ...pub, type: 'infra.deploy' }, C)).not.toBe(
      boundIntentDigestHex(pub, C),
    )
    expect(boundIntentDigestHex({ ...pub, resource: 'vendor-other' }, C)).not.toBe(
      boundIntentDigestHex(pub, C),
    )
  })

  it('BINDING PRESERVED: counterparty/params still change the digest (point-binding completeness)', () => {
    // Salted-not-dropped: a malicious binder cannot vary these silently.
    expect(digest({ ...base, counterparty: 'cp-002' })).not.toBe(digest(base))
    expect(digest({ ...base, params: { memo: 'q4' } })).not.toBe(digest(base))
  })

  it('SECRECY: a salt-less party cannot recompute a salted-field digest — FAIL CLOSED', () => {
    // No silent fallback to plaintext (that would re-open the CB-001/CB-002 surface).
    expect(() => boundIntentDigestHex(base, C)).toThrow(CommitBindError)
    expect(() => boundIntentDigestHex({ type: 't', resource: 'r', counterparty: 'cp' }, C)).toThrow(
      CommitBindError,
    )
  })

  it('SECRECY: a different salt yields a different digest for the same intent (hiding / unlinkable)', () => {
    expect(digest(base, SALT2)).not.toBe(digest(base, SALT))
  })

  it('LOCK: amount is the only PLAINTEXT-excluded field; counterparty/params are SALTED, not dropped', () => {
    // If this set ever changes, update it deliberately and reconcile with ADR-0042.
    // Every non-amount field still affects the digest (nothing dropped → binding-complete):
    const mustAffectDigest: Array<Partial<ActionIntent>> = [
      { type: 'x.y' },
      { resource: 'r2' },
      { counterparty: 'cpX' },
      { params: { k: 'v' } },
    ]
    for (const delta of mustAffectDigest) {
      expect(digest({ ...base, ...delta })).not.toBe(digest(base))
    }
    // ...and amount must NOT affect it:
    expect(digest({ ...base, amount: 123 })).toBe(digest(base))
  })
})
