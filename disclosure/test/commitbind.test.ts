// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  bindAmountCommitment,
  boundIntentDigest,
  boundIntentDigestHex,
  verifyBoundCommitment,
  verifyBoundAmount,
  intentAmount,
  hasSaltedFields,
  CommitBindError,
} from '../src/commitbind.js'
import { commitAmount } from '../src/policyproof.js'
import { commit } from '../src/zkrange.js'
import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
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

  it('CB-001 (Team Apex): the public digest does NOT bind the plaintext amount', () => {
    const { commitment } = commitAmount(42n)
    // Two intents identical except for the amount must yield the SAME digest — the amount is
    // bound by the (perfectly-hiding) commitment, not the public preimage. Were it in the
    // preimage, an attacker could brute-force it over its small enumerable domain.
    const a: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 500 }
    const b: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 999999 }
    expect(boundIntentDigest(a, commitment)).toEqual(boundIntentDigest(b, commitment))
    // ...while a different NON-secret field still changes the digest (skeleton binding intact).
    const c: ActionIntent = { type: 'payment.transfer', resource: 'vendor-evil', amount: 500 }
    expect(boundIntentDigest(a, commitment)).not.toEqual(boundIntentDigest(c, commitment))
  })
})

describe('CB-002 / ADR-0042: salted binding of non-public intent fields (UNAUDITED)', () => {
  // An intent carrying privacy-sensitive fields (counterparty, params) beyond the
  // public allowlist {type, resource}.
  const intent: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    counterparty: 'cp-001',
    amount: 500,
    params: { memo: 'q3' },
  }

  it('bindAmountCommitment mints a salt only when the intent carries non-public fields', () => {
    expect(hasSaltedFields(intent)).toBe(true)
    const bound = bindAmountCommitment(intent)
    expect(bound.salt).toBeInstanceOf(Uint8Array)
    expect(bound.salt?.length).toBe(32)

    const publicOnly: ActionIntent = {
      type: 'payment.transfer',
      resource: 'vendor-acme',
      amount: 500,
    }
    expect(hasSaltedFields(publicOnly)).toBe(false)
    expect(bindAmountCommitment(publicOnly).salt).toBeUndefined()
  })

  it('full round-trip verifies when the salt is supplied to the verifier', () => {
    const bound = bindAmountCommitment(intent)
    expect(verifyBoundCommitment(intent, bound.commitment, bound.digest, bound.salt)).toBe(true)
    expect(
      verifyBoundAmount(intent, bound.commitment, bound.opening, bound.digest, bound.salt),
    ).toBe(true)
  })

  it('binding-completeness: tampering a salted field is rejected under the same salt', () => {
    const bound = bindAmountCommitment(intent)
    const tamperedCp: ActionIntent = { ...intent, counterparty: 'attacker' }
    const tamperedParams: ActionIntent = { ...intent, params: { memo: 'forged' } }
    expect(verifyBoundCommitment(tamperedCp, bound.commitment, bound.digest, bound.salt)).toBe(
      false,
    )
    expect(verifyBoundCommitment(tamperedParams, bound.commitment, bound.digest, bound.salt)).toBe(
      false,
    )
  })

  it('secrecy: a verifier without the salt cannot recompute the digest — fail-closed', () => {
    const bound = bindAmountCommitment(intent)
    // No salt → buildBoundSkeleton refuses to hash the sensitive fields in plaintext.
    expect(() => verifyBoundCommitment(intent, bound.commitment, bound.digest)).toThrow(
      CommitBindError,
    )
    // A WRONG salt recomputes a different digest → rejects (does not throw).
    const wrong = new Uint8Array(32).fill(1)
    expect(verifyBoundCommitment(intent, bound.commitment, bound.digest, wrong)).toBe(false)
  })

  it('amount is still omitted even with salted fields present (CB-001 preserved)', () => {
    const bound = bindAmountCommitment(intent)
    // Same salt, same commitment, different amount → identical digest (amount not in preimage).
    const otherAmount: ActionIntent = { ...intent, amount: 999_999 }
    expect(boundIntentDigest(otherAmount, bound.commitment, bound.salt)).toEqual(
      boundIntentDigest(intent, bound.commitment, bound.salt),
    )
  })

  it('a caller-supplied salt makes bindAmountCommitment deterministic', () => {
    const salt = new Uint8Array(32).fill(5)
    const a = bindAmountCommitment(intent, salt)
    // Recompute the digest directly with the same salt + the SAME commitment a produced.
    expect(boundIntentDigest(intent, a.commitment, salt)).toEqual(a.digest)
  })
})

describe('CB-002 / ADR-0042: digest byte-stability KATs (council-requested)', () => {
  // Deterministic commitment + fixed salt so these vectors are reproducible. Pinning the
  // exact bytes (1) PROVES the backward-compat claim — the public-only digest is identical
  // to the pre-ADR-0042 denylist algorithm — and (2) locks the salted encoding, so any
  // silent change to the reused selective.ts commitField primitive or the dCBOR layer breaks
  // a test rather than silently shifting a protocol digest.
  const C = commit(500n, 7n)
  const SALT = new Uint8Array(32).fill(7)

  const pub: ActionIntent = { type: 'payment.transfer', resource: 'vendor-acme', amount: 500 }
  const full: ActionIntent = {
    type: 'payment.transfer',
    resource: 'vendor-acme',
    counterparty: 'cp-001',
    amount: 500,
    params: { memo: 'q3' },
  }

  // The pre-ADR-0042 denylist algorithm, reconstructed inline: skeleton = every field except
  // amount, all PLAINTEXT, same domain string. Self-validating backward-compat oracle.
  const legacyDenylistDigestHex = (i: ActionIntent): string => {
    const skeleton = Object.fromEntries(Object.entries(i).filter(([k]) => k !== 'amount'))
    const preimage = encodeCanonical({
      domain: 'PolarSeek/disclosure/commit-bind/v2',
      intent: skeleton,
      commitment: C.toBytes(),
    })
    return bytesToHex(SHA3_SHAKE256.digest(preimage))
  }

  it('PUBLIC-ONLY digest is byte-identical to the pre-ADR-0042 denylist algorithm', () => {
    expect(boundIntentDigestHex(pub, C)).toBe(legacyDenylistDigestHex(pub))
  })

  it('PUBLIC-ONLY digest matches the pinned KAT vector', () => {
    expect(boundIntentDigestHex(pub, C)).toBe(
      'b4f316a704d12f66adee3180570a91279783d29ca462ea4ae0a38e8f46d42afc',
    )
  })

  it('SALTED (full-intent) digest matches the pinned KAT vector and DIFFERS from the legacy plaintext digest', () => {
    expect(boundIntentDigestHex(full, C, SALT)).toBe(
      'a2927de53d5302532d5becfa1cfa5a4d39ab625fe68c0fa6ce4ad9b43c2f668a',
    )
    // The whole point of CB-002: the salted encoding is NOT the legacy plaintext one.
    expect(boundIntentDigestHex(full, C, SALT)).not.toBe(legacyDenylistDigestHex(full))
  })
})
