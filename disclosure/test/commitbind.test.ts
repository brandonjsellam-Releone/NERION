// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  bindAmountCommitment,
  boundIntentDigest,
  verifyBoundCommitment,
  verifyBoundAmount,
  intentAmount,
  CommitBindError,
} from '../src/commitbind.js'
import { commitAmount } from '../src/policyproof.js'
import { randomBytes } from '../../crypto/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

describe('v:2 structural commitment-binding (ADR-0013, UNAUDITED)', () => {
  const intent: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    amount: 500,
  }
  const salt = randomBytes(16)

  it('binds the intent-amount commitment and full-verifies (binding + opening)', () => {
    const bound = bindAmountCommitment(intent, salt)
    expect(verifyBoundCommitment(intent, bound.commitment, bound.digest, salt)).toBe(true)
    expect(verifyBoundAmount(intent, bound.commitment, bound.opening, bound.digest, salt)).toBe(
      true,
    )
  })

  it('rejects a substituted commitment — closes the point-substitution gap', () => {
    const bound = bindAmountCommitment(intent, salt)
    const forged = commitAmount(1n).commitment // commitment to a DIFFERENT amount
    expect(verifyBoundCommitment(intent, forged, bound.digest, salt)).toBe(false)
  })

  it('verifyBoundAmount rejects an opening that does not open C to intent.amount', () => {
    const bound = bindAmountCommitment(intent, salt)
    expect(
      verifyBoundAmount(intent, bound.commitment, bound.opening + 1n, bound.digest, salt),
    ).toBe(false)
  })

  it('rejects the right commitment against a tampered intent', () => {
    const bound = bindAmountCommitment(intent, salt)
    const tampered: ActionIntent = { ...intent, resource: 'attacker' }
    expect(verifyBoundCommitment(tampered, bound.commitment, bound.digest, salt)).toBe(false)
  })

  it('refuses to bind an intent with no amount or an unsafe amount', () => {
    expect(() => bindAmountCommitment({ type: 'x', resource: 'y' }, salt)).toThrow(CommitBindError)
    expect(() =>
      intentAmount({ type: 'x', resource: 'y', amount: Number.MAX_SAFE_INTEGER + 1 }),
    ).toThrow(CommitBindError)
  })

  it('is deterministic for a fixed intent + commitment + salt', () => {
    const { commitment } = commitAmount(42n)
    expect(boundIntentDigest(intent, commitment, salt)).toEqual(
      boundIntentDigest(intent, commitment, salt),
    )
  })

  it('CB-001 (Team Apex): the public digest does NOT bind the plaintext amount', () => {
    const { commitment } = commitAmount(42n)
    // Two intents identical except for the amount must yield the SAME digest — the amount is
    // bound by the (perfectly-hiding) commitment, not the public preimage. Were it in the
    // preimage, an attacker could brute-force it over its small enumerable domain.
    const a: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 500 }
    const b: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 999999 }
    expect(boundIntentDigest(a, commitment, salt)).toEqual(boundIntentDigest(b, commitment, salt))
    // ...while a different NON-secret field still changes the digest (skeleton binding intact).
    const c: ActionIntent = { type: 'payment.transfer', resource: 'vendor-evil', amount: 500 }
    expect(boundIntentDigest(a, commitment, salt)).not.toEqual(
      boundIntentDigest(c, commitment, salt),
    )
  })

  it('SEAM-CB-SALT-001: a DIFFERENT salt for the SAME intent+commitment yields a DIFFERENT digest', () => {
    const { commitment } = commitAmount(42n)
    const saltA = randomBytes(16)
    const saltB = randomBytes(16)
    expect(boundIntentDigest(intent, commitment, saltA)).not.toEqual(
      boundIntentDigest(intent, commitment, saltB),
    )
    // ...and the digest is verifiable only under the SAME salt it was built with.
    const digest = boundIntentDigest(intent, commitment, saltA)
    expect(verifyBoundCommitment(intent, commitment, digest, saltA)).toBe(true)
    expect(verifyBoundCommitment(intent, commitment, digest, saltB)).toBe(false)
  })
})
