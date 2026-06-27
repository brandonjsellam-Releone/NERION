// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CB-001 exposure-surface lock (audit-prep 2026-06-27 — ZK dossier P6,
 * docs/council/zk-audit-prep-2026-06-27.md).
 *
 * `boundIntentDigest` builds its PUBLIC, externally-recomputable pre-image from the
 * intent skeleton with `amount` OMITTED (commitbind.ts:91-101) — a *denylist*. These
 * tests LOCK that surface so any change to the excluded-field set is a CONSCIOUS one:
 *
 *   - they assert `amount` is the ONLY excluded field (the CB-001 hiding fix), and
 *   - they make explicit that every OTHER field — including the privacy-sensitive
 *     `counterparty` ("never re-identified across calls", types.ts:26-27) and arbitrary
 *     `params` — IS hashed into the public digest. If such a value is low-entropy /
 *     enumerable it is brute-forceable from a single public digest (the commitment and
 *     the rest of the skeleton are public), exactly as the amount was pre-CB-001.
 *
 * If a maintainer excludes another field, or accidentally includes `amount`, a test
 * here breaks — forcing reconciliation with the allowlist-vs-denylist decision recorded
 * in the ZK audit-prep dossier.
 */

import { describe, it, expect } from 'vitest'
import { boundIntentDigestHex } from '../src/commitbind.js'
import { commitAmount } from '../src/policyproof.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

describe('CB-001 public-digest exposure surface (audit-prep lock)', () => {
  // One FIXED commitment so the ONLY variable across comparisons is the intent skeleton.
  const C = commitAmount(500n).commitment

  const base: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    counterparty: 'cp-001',
    amount: 500,
    params: { memo: 'q3' },
  }
  const digest = (i: ActionIntent): string => boundIntentDigestHex(i, C)

  it('EXCLUDES amount: changing only amount leaves the public digest unchanged (CB-001 hiding)', () => {
    expect(digest({ ...base, amount: 999_999 })).toBe(digest(base))
    expect(digest({ ...base, amount: 0 })).toBe(digest(base))
  })

  it('INCLUDES type/resource: changing either changes the digest (binding)', () => {
    expect(digest({ ...base, type: 'infra.deploy' })).not.toBe(digest(base))
    expect(digest({ ...base, resource: 'vendor-other' })).not.toBe(digest(base))
  })

  it('INCLUDES counterparty: it is in the public pre-image (brute-forceable if low-entropy)', () => {
    expect(digest({ ...base, counterparty: 'cp-002' })).not.toBe(digest(base))
  })

  it('INCLUDES params: arbitrary param values are in the public pre-image', () => {
    expect(digest({ ...base, params: { memo: 'q4' } })).not.toBe(digest(base))
  })

  it('LOCK: amount is the only excluded field — any change here is a conscious decision', () => {
    // If this set ever changes, update it deliberately and reconcile with the
    // allowlist-vs-denylist decision in docs/council/zk-audit-prep-2026-06-27.md.
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
