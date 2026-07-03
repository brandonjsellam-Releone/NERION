// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { issueRoot, attenuate, verifyChain, resolve, AttenuationError } from '../src/index.js'
import type { ActionIntent, Capability, EvalContext, RiskTier } from '../src/index.js'

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

  it('CAP-SUITE-PIN-001: an unknown/inactive suite fails closed WITHOUT throwing', () => {
    // A link whose suite is not an active suite must be rejected before signerFor() (which would
    // throw UnknownSuiteError) — so a poisoned candidate can not abort admission by exception.
    const bogus: Capability = { chain: [{ ...root.chain[0]!, suite: 'PS-BOGUS' }] }
    expect(() => verifyChain(bogus, trustedRoots)).not.toThrow()
    expect(verifyChain(bogus, trustedRoots)).toBe(false)
  })

  it('CAP-RESOLVE-ROBUST-001: a poisoned candidate does not deny a request a valid one authorizes', () => {
    const bogus: Capability = { chain: [{ ...root.chain[0]!, suite: 'PS-BOGUS' }] }
    // bogus first, valid root second — resolve() must skip the bad one and authorize via root.
    expect(resolve(pay(500), [bogus, root], trustedRoots, baseCtx()).authorized).toBe(true)
  })

  it('CAP-SUITE-PIN-001: a chain that switches to a different active suite between links is rejected', () => {
    const child = attenuate(root, { perActionCeiling: 200 }, delegateeHex, holder)
    // Re-label the delegation link with a DIFFERENT active suite than the root; the pin check runs
    // before the signature check, so the chain is rejected on the suite switch itself.
    const mixed: Capability = {
      chain: [child.chain[0]!, { ...child.chain[1]!, suite: SUITE_IDS.PS_1 }],
    }
    expect(verifyChain(mixed, trustedRoots)).toBe(false)
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
  it('DOS-VERIFY-003: denies an over-large candidate array (caps hot-path verify cost)', () => {
    const flood = new Array(65).fill(root) // > MAX_CANDIDATES (64)
    const r = resolve(pay(500), flood, trustedRoots, baseCtx())
    expect(r.authorized).toBe(false)
    expect(r.reason).toMatch(/too many candidate/)
    // a within-bound array of the same valid capability still authorizes
    expect(resolve(pay(500), new Array(64).fill(root), trustedRoots, baseCtx()).authorized).toBe(
      true,
    )
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

  it('a non-finite `now` cannot bypass the validity window (KERNEL-TIME-001 fail-closed)', () => {
    // A capability whose validity window has already expired at a normal clock.
    const expired = issueRoot(
      {
        subject: holderHex,
        actions: ['payment.transfer'],
        perActionCeiling: 1000,
        aggregateCap: 5000,
        counterparties: ['alice'],
        maxTier: 2,
        notBefore: 0,
        notAfter: 500,
        delegable: true,
      },
      suite,
      authority,
    )
    // Sanity: a finite clock past notAfter denies.
    expect(resolve(pay(500), [expired], trustedRoots, baseCtx({ now: 1000 })).authorized).toBe(
      false,
    )
    // A non-finite clock (NaN / ±Infinity) makes both `<`/`>` window comparisons
    // false; it must NOT slip past the expiry — fail closed.
    expect(
      resolve(pay(500), [expired], trustedRoots, baseCtx({ now: Number.NaN })).authorized,
    ).toBe(false)
    expect(
      resolve(pay(500), [expired], trustedRoots, baseCtx({ now: Number.POSITIVE_INFINITY }))
        .authorized,
    ).toBe(false)
    // And a non-finite clock denies even an otherwise-valid, non-expired grant.
    expect(resolve(pay(500), [root], trustedRoots, baseCtx({ now: Number.NaN })).authorized).toBe(
      false,
    )
  })
})

describe('attenuating delegation', () => {
  const child = attenuate(root, { perActionCeiling: 200 }, delegateeHex, holder)

  it('a delegated capability verifies and is held by the delegatee', () => {
    expect(verifyChain(child, trustedRoots)).toBe(true)
    expect(child.chain.length).toBe(2)
  })
  it('DOS-VERIFY-002: rejects a chain longer than the bound, before the per-link verify loop', () => {
    // verifyChain does one PQ verify per link; an over-long (attacker-extended) chain is rejected on
    // length BEFORE verifying, bounding hot-path work. A legit chain is a root + a few delegations.
    const link = root.chain[0]!
    const overLong: Capability = { chain: Array.from({ length: 40 }, () => link) }
    expect(verifyChain(overLong, trustedRoots)).toBe(false)
    expect(verifyChain(root, trustedRoots)).toBe(true) // genuine short chain still verifies
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

  it('rejects an onward delegation from a NON-delegable parent (CAP-DELEG-001)', () => {
    // Replicate the module's private id derivation + suite-bound signing message so
    // the forged child has a CORRECT content-hash id and a valid signature — the
    // only thing wrong with it is that its parent forbade onward delegation.
    const CAP_CONTEXT = 'polarseek/capability/grant/v2'
    const deriveId = (body: object): string =>
      bytesToHex(SHA3_SHAKE256.digest(encodeCanonical(body))).slice(0, 24)
    const selfSign = (parentSubject: string): Capability['chain'][number] => {
      const childBody = {
        issuer: parentSubject, // = holder
        subject: delegateeHex,
        actions: ['payment.transfer'],
        perActionCeiling: 200, // strictly narrower
        aggregateCap: 5000,
        counterparties: ['alice'],
        maxTier: 2 as RiskTier,
        notBefore: 0,
        notAfter: 10_000_000_000,
        delegable: false,
      }
      const grant = { id: deriveId(childBody), ...childBody }
      const sig = signer.sign(encodeCanonical([CAP_CONTEXT, suite, grant]), holder.secretKey)
      return { grant, suite, signerPublicKey: holder.publicKey, sig }
    }

    // Issue a root the holder may USE but NOT delegate.
    const nonDelegable = issueRoot(
      {
        subject: holderHex,
        actions: ['payment.transfer'],
        perActionCeiling: 1000,
        aggregateCap: 5000,
        counterparties: ['alice'],
        maxTier: 2,
        notBefore: 0,
        notAfter: 10_000_000_000,
        delegable: false,
      },
      suite,
      authority,
    )
    expect(verifyChain(nonDelegable, trustedRoots)).toBe(true)

    const forged: Capability = {
      chain: [nonDelegable.chain[0]!, selfSign(nonDelegable.chain[0]!.grant.subject)],
    }
    // Strict attenuation, valid id + signature, but the parent is non-delegable.
    expect(verifyChain(forged, trustedRoots)).toBe(false)

    // Control: the IDENTICAL construction under a DELEGABLE parent verifies, proving
    // the rejection is specifically the delegable-flag enforcement, not a bad id/sig.
    const ctrl: Capability = {
      chain: [root.chain[0]!, selfSign(root.chain[0]!.grant.subject)],
    }
    expect(verifyChain(ctrl, trustedRoots)).toBe(true)
  })
})

describe('CAP-001 hardening — Team Apex audit', () => {
  it('a grant signature binds the suite + domain tag (an unbound sig is rejected)', () => {
    const link0 = root.chain[0]!
    // A signature over the bare grant (pre-CAP-001 format, no suite/context binding)...
    const unboundSig = signer.sign(encodeCanonical(link0.grant), authority.secretKey)
    const spoofed: Capability = { chain: [{ ...link0, sig: unboundSig }] }
    // ...is rejected: verifyChain now binds the suite + domain tag into the signed message.
    expect(verifyChain(spoofed, trustedRoots)).toBe(false)
  })

  it('a tampered grant id is rejected (id must be the body content-hash)', () => {
    const link0 = root.chain[0]!
    const tamperedId: Capability = {
      chain: [{ ...link0, grant: { ...link0.grant, id: 'deadbeefdeadbeefdeadbeef' } }],
    }
    expect(verifyChain(tamperedId, trustedRoots)).toBe(false)
  })

  it('an invalid (negative / non-integer) tier fails closed', () => {
    expect(
      resolve(pay(500), [root], trustedRoots, baseCtx({ tier: -1 as RiskTier })).authorized,
    ).toBe(false)
    expect(
      resolve(pay(500), [root], trustedRoots, baseCtx({ tier: 1.5 as RiskTier })).authorized,
    ).toBe(false)
  })
})

describe('capability revocation enforcement (REVOKE-ENFORCE-001 / REVOKE-CHILD-002)', () => {
  const revChild = attenuate(root, { perActionCeiling: 200 }, delegateeHex, holder)
  const rootId = root.chain[0]!.grant.id
  const childId = revChild.chain[revChild.chain.length - 1]!.grant.id

  it('a revoked capability no longer authorizes (closes the admission fail-open)', () => {
    // Not revoked -> authorized.
    expect(resolve(pay(500), [root], trustedRoots, baseCtx()).authorized).toBe(true)
    // Revoked (id in the explicit revoked set) -> denied.
    expect(resolve(pay(500), [root], trustedRoots, baseCtx(), new Set([rootId])).authorized).toBe(
      false,
    )
  })

  it('revoking a ROOT also revokes its delegated children, and re-delegation cannot outrun it', () => {
    const ctx = baseCtx({ holder: delegateeHex })
    // The delegated child authorizes normally...
    expect(resolve(pay(100), [revChild], trustedRoots, ctx).authorized).toBe(true)
    // ...but revoking the ROOT id denies the child too (the root id is in its chain).
    expect(resolve(pay(100), [revChild], trustedRoots, ctx, new Set([rootId])).authorized).toBe(
      false,
    )
    // Revoking only the child id denies the child but not independent use of the root.
    expect(resolve(pay(100), [revChild], trustedRoots, ctx, new Set([childId])).authorized).toBe(
      false,
    )
    expect(resolve(pay(500), [root], trustedRoots, baseCtx(), new Set([childId])).authorized).toBe(
      true,
    )
  })
})
