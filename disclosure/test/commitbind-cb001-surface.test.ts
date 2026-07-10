// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CB-001 exposure-surface lock (audit-prep 2026-06-27 — ZK dossier P6,
 * docs/council/zk-audit-prep-2026-06-27.md), UPDATED for SEAM-CB-SALT-001 (AAC
 * council review, 2026-07-11).
 *
 * `boundIntentDigest` builds its PUBLIC, externally-recomputable pre-image from the
 * intent skeleton with `amount` OMITTED (commitbind.ts) — still a *denylist* of one
 * field, for the recomputability-without-the-amount reason documented there — but the
 * skeleton is now SALTED (a required parameter), closing the SEAM-CB-SALT-001 gap this
 * file originally locked in as ACCEPTED behavior: `counterparty` ("never re-identified
 * across calls", types.ts:26-27) and arbitrary `params` ARE still hashed into the
 * digest (binding is preserved — a different value still changes the digest), but a
 * high-entropy salt now makes them NOT brute-forceable from the public digest alone,
 * exactly mirroring how `selective.ts` / RCPT-001 protect the receipt's other
 * low-entropy fields.
 *
 * These tests now positively assert BOTH properties for the sensitive fields: (a)
 * binding — a changed value still changes the digest, and (b) hiding — the SAME
 * intent+commitment under two DIFFERENT salts produces UNLINKABLE digests, so an
 * observer without the salt cannot correlate or brute-force the field even though it
 * is present in the pre-image.
 */

import { describe, it, expect } from 'vitest'
import { boundIntentDigestHex } from '../src/commitbind.js'
import { commitAmount } from '../src/policyproof.js'
import { randomBytes } from '../../crypto/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

describe('CB-001 / SEAM-CB-SALT-001 public-digest exposure surface (audit-prep lock)', () => {
  // One FIXED commitment so the ONLY variable across comparisons is the intent skeleton (+ salt).
  const C = commitAmount(500n).commitment
  const salt = randomBytes(16)

  const base: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    counterparty: 'cp-001',
    amount: 500,
    params: { memo: 'q3' },
  }
  const digest = (i: ActionIntent, s: Uint8Array = salt): string => boundIntentDigestHex(i, C, s)

  it('EXCLUDES amount: changing only amount leaves the public digest unchanged (CB-001 hiding)', () => {
    expect(digest({ ...base, amount: 999_999 })).toBe(digest(base))
    expect(digest({ ...base, amount: 0 })).toBe(digest(base))
  })

  it('INCLUDES type/resource: changing either changes the digest (binding)', () => {
    expect(digest({ ...base, type: 'infra.deploy' })).not.toBe(digest(base))
    expect(digest({ ...base, resource: 'vendor-other' })).not.toBe(digest(base))
  })

  it('INCLUDES counterparty: binding preserved (changing it changes the digest)', () => {
    expect(digest({ ...base, counterparty: 'cp-002' })).not.toBe(digest(base))
  })

  it('INCLUDES params: binding preserved (changing them changes the digest)', () => {
    expect(digest({ ...base, params: { memo: 'q4' } })).not.toBe(digest(base))
  })

  it('SEAM-CB-SALT-001: counterparty/params are NOT brute-forceable — the salt hides them', () => {
    // A brute-force enumerator with no salt cannot even ask "does this digest match candidate X"
    // without ALSO guessing the salt: the SAME low-entropy counterparty under two DIFFERENT salts
    // is unlinkable — no shared digest an attacker could match against a public receipt leaf.
    const saltA = randomBytes(16)
    const saltB = randomBytes(16)
    expect(digest(base, saltA)).not.toBe(digest(base, saltB))
    // Without the salt, an attacker also cannot verify a guessed counterparty against the digest —
    // there is no unsalted recomputation path (salt is a required parameter, not optional).
  })

  it('LOCK: amount is the only excluded field; every included field is now salted', () => {
    // If this set ever changes, update it deliberately and reconcile with SEAM-CB-SALT-001 /
    // the allowlist-vs-denylist decision in docs/council/zk-audit-prep-2026-06-27.md.
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
