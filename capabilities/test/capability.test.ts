// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, encodeCanonical } from '../../crypto/src/index.js'
import { issueRoot, attenuate, verifyChain, resolve, AttenuationError } from '../src/index.js'
import type { ActionIntent, Capability, EvalContext } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const delegatee = signer.keygen()
const trustedRoots = [authority.publicKey]
const holderHex = bytesToHex(holder.publicKey)
const delegateeHex = bytesToHex(delegatee.publicKey)

const root = issueRoot(
  {
    subject: holderHex,
    actions: ['payment.transfer'],
    perActionCeiling: 1000,
    aggregateCap: 5000,
    counterparties: ['alice'],
    maxTier: 2,
    notBefore: 0,
    notAfter: 10_000_000_000,
    delegable: true,
  },
  suite,
  authority,
)

const baseCtx = (over: Partial<EvalContext> = {}): EvalContext => ({
  now: 1000,
  tier: 2,
  observedAggregate: 0,
  holder: holderHex,
  ...over,
})
const pay = (amount: number, counterparty = 'alice'): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty,
  amount,
})

describe('capability issuance & verification', () => {
  it('a root capability verifies against its trusted authority', () => {
    expect(verifyChain(root, trustedRoots)).toBe(true)
  })
  it('rejects an untrusted root authority', () => {
    expect(verifyChain(root, [delegatee.publicKey])).toBe(false)
  })
  it('rejects a tampered signature', () => {
    const link0 = root.chain[0]!
    const badSig = Uint8Array.from(link0.sig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    const tampered: Capability = { chain: [{ ...link0, sig: badSig }] }
    expect(verifyChain(tampered, trustedRoots)).toBe(false)
  })
})

describe('default-deny resolver', () => {
  it('authorizes an in-policy action', () => {
    const r = resolve(pay(500), [root], trustedRoots, baseCtx())
    expect(r.authorized).toBe(true)
  })
  it('denies when there is no capability at all (default-deny)', () => {
    expect(resolve(pay(500), [], trustedRoots, baseCtx()).authorized).toBe(false)
  })
  it('denies over the per-action ceiling', () => {
    expect(resolve(pay(2000), [root], trustedRoots, baseCtx()).authorized).toBe(false)
  })
  it('denies a disallowed counterparty', () => {
    expect(resolve(pay(500, 'bob'), [root], trustedRoots, baseCtx()).authorized).toBe(false)
  })
  it('denies above the tier ceiling', () => {
    expect(resolve(pay(500), [root], trustedRoots, baseCtx({ tier: 3 })).authorized).toBe(false)
  })
  it('denies an unknown action type', () => {
    const r = resolve({ type: 'x.y', resource: 'r' }, [root], trustedRoots, baseCtx())
    expect(r.authorized).toBe(false)
  })
  it('enforces the rolling aggregate via the signed scalar', () => {
    expect(
      resolve(pay(500), [root], trustedRoots, baseCtx({ observedAggregate: 4800 })).authorized,
    ).toBe(false)
    expect(
      resolve(pay(500), [root], trustedRoots, baseCtx({ observedAggregate: 4000 })).authorized,
    ).toBe(true)
  })
  it('denies when the requester is not the capability holder', () => {
    expect(
      resolve(pay(500), [root], trustedRoots, baseCtx({ holder: delegateeHex })).authorized,
    ).toBe(false)
  })

  it('denies non-finite / non-integer / negative amounts (PS-CAP-01/02 fail-closed)', () => {
    expect(resolve(pay(Number.NaN), [root], trustedRoots, baseCtx()).authorized).toBe(false)
    expect(resolve(pay(Number.POSITIVE_INFINITY), [root], trustedRoots, baseCtx()).authorized).toBe(
      false,
    )
    expect(resolve(pay(-100), [root], trustedRoots, baseCtx()).authorized).toBe(false)
    expect(resolve(pay(1.5), [root], trustedRoots, baseCtx()).authorized).toBe(false)
  })

  it('denies when no holder identity is supplied (PS-CAP-03)', () => {
    const noHolder: EvalContext = { now: 1000, tier: 2, observedAggregate: 0 }
    expect(resolve(pay(500), [root], trustedRoots, noHolder).authorized).toBe(false)
  })
})

describe('attenuating delegation', () => {
  const child = attenuate(root, { perActionCeiling: 200 }, delegateeHex, holder)

  it('a delegated capability verifies and is held by the delegatee', () => {
    expect(verifyChain(child, trustedRoots)).toBe(true)
    expect(child.chain.length).toBe(2)
  })
  it('the delegated ceiling binds even though the root allowed more', () => {
    const ctx = baseCtx({ holder: delegateeHex })
    expect(resolve(pay(100), [child], trustedRoots, ctx).authorized).toBe(true)
    expect(resolve(pay(500), [child], trustedRoots, ctx).authorized).toBe(false)
  })
  it('a non-holder cannot delegate', () => {
    expect(() => attenuate(root, {}, delegateeHex, delegatee)).toThrow(AttenuationError)
  })
  it('rejects a forged broadening delegation', () => {
    // Craft a child grant that BROADENS the ceiling, validly signed by the holder.
    const link0 = root.chain[0]!
    const forgedGrant = {
      ...link0.grant,
      id: 'forged',
      issuer: link0.grant.subject,
      subject: delegateeHex,
      perActionCeiling: 1_000_000,
    }
    const sig = signer.sign(encodeCanonical(forgedGrant), holder.secretKey)
    const forged: Capability = {
      chain: [link0, { grant: forgedGrant, suite, signerPublicKey: holder.publicKey, sig }],
    }
    // Signature is valid, but it broadens authority -> chain verification rejects it.
    expect(verifyChain(forged, trustedRoots)).toBe(false)
  })
})
