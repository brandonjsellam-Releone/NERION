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
import type { ActionIntent } from '../../capabilities/src/index.js'

describe('v:2 structural commitment-binding (ADR-0013, UNAUDITED)', () => {
  const intent: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    amount: 500,
  }

  it('binds the intent-amount commitment and full-verifies (binding + opening)', () => {
    const bound = bindAmountCommitment(intent)
    expect(verifyBoundCommitment(intent, bound.commitment, bound.digest)).toBe(true)
    expect(verifyBoundAmount(intent, bound.commitment, bound.opening, bound.digest)).toBe(true)
  })

  it('rejects a substituted commitment — closes the point-substitution gap', () => {
    const bound = bindAmountCommitment(intent)
    const forged = commitAmount(1n).commitment // commitment to a DIFFERENT amount
    expect(verifyBoundCommitment(intent, forged, bound.digest)).toBe(false)
  })

  it('verifyBoundAmount rejects an opening that does not open C to intent.amount', () => {
    const bound = bindAmountCommitment(intent)
    expect(verifyBoundAmount(intent, bound.commitment, bound.opening + 1n, bound.digest)).toBe(
      false,
    )
  })

  it('rejects the right commitment against a tampered intent', () => {
    const bound = bindAmountCommitment(intent)
    const tampered: ActionIntent = { ...intent, resource: 'attacker' }
    expect(verifyBoundCommitment(tampered, bound.commitment, bound.digest)).toBe(false)
  })

  it('refuses to bind an intent with no amount or an unsafe amount', () => {
    expect(() => bindAmountCommitment({ type: 'x', resource: 'y' })).toThrow(CommitBindError)
    expect(() =>
      intentAmount({ type: 'x', resource: 'y', amount: Number.MAX_SAFE_INTEGER + 1 }),
    ).toThrow(CommitBindError)
  })

  it('is deterministic for a fixed intent + commitment', () => {
    const { commitment } = commitAmount(42n)
    expect(boundIntentDigest(intent, commitment)).toEqual(boundIntentDigest(intent, commitment))
  })
})
