// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Capability issuance, attenuating delegation, and chain verification.
 *
 * Each grant is signed with the suite's PQ signature scheme (ML-DSA-87) over its
 * canonical CBOR encoding. A delegation link is valid only if it (a) is signed
 * by the holder of the parent's subject key and (b) is a strict attenuation of
 * the parent grant. Verification trusts only an explicit set of root authority
 * public keys — no ambient authority.
 */

import { bytesToHex } from '@noble/hashes/utils.js'
import {
  encodeCanonical,
  SHA3_SHAKE256,
  signerFor,
  type Bytes,
  type KeyPair,
} from '../../crypto/src/index.js'
import type { Attenuation } from './grant.js'
import { isAttenuationOf, narrow } from './grant.js'
import type { Capability, CapabilityGrant, RiskTier } from './types.js'

export class AttenuationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'AttenuationError'
  }
}

type GrantBody = Omit<CapabilityGrant, 'id'>

/** Deterministic capability id: truncated SHA3-256 over the canonical grant body. */
function deriveId(body: GrantBody): string {
  return bytesToHex(SHA3_SHAKE256.digest(encodeCanonical(body))).slice(0, 24)
}

export interface RootGrantSpec {
  /** hex of the holder/delegatee public key. */
  readonly subject: string
  readonly actions: readonly string[]
  readonly perActionCeiling?: number | null
  readonly aggregateCap?: number | null
  readonly counterparties?: readonly string[] | null
  readonly maxTier: RiskTier
  readonly notBefore: number
  readonly notAfter: number
  readonly delegable: boolean
}

/** Issue a root capability signed by a trusted authority. */
export function issueRoot(spec: RootGrantSpec, suite: string, authority: KeyPair): Capability {
  const body: GrantBody = {
    issuer: bytesToHex(authority.publicKey),
    subject: spec.subject,
    actions: [...spec.actions],
    perActionCeiling: spec.perActionCeiling ?? null,
    aggregateCap: spec.aggregateCap ?? null,
    counterparties: spec.counterparties === undefined ? null : spec.counterparties,
    maxTier: spec.maxTier,
    notBefore: spec.notBefore,
    notAfter: spec.notAfter,
    delegable: spec.delegable,
  }
  const grant: CapabilityGrant = { id: deriveId(body), ...body }
  const sig = signerFor(suite).sign(encodeCanonical(grant), authority.secretKey)
  return { chain: [{ grant, suite, signerPublicKey: authority.publicKey, sig }] }
}

function tail(cap: Capability): { grant: CapabilityGrant; suite: string } {
  const link = cap.chain[cap.chain.length - 1]
  if (link === undefined) throw new AttenuationError('empty capability chain')
  return link
}

/**
 * Delegate a (narrowed) capability to a new subject. The delegator must hold the
 * current tail's subject key. Throws {@link AttenuationError} if the result would
 * broaden authority or the parent is not delegable.
 */
export function attenuate(
  parent: Capability,
  restriction: Attenuation,
  newSubject: string,
  delegator: KeyPair,
): Capability {
  const parentTail = tail(parent)
  if (!parentTail.grant.delegable) throw new AttenuationError('parent grant is not delegable')
  if (bytesToHex(delegator.publicKey) !== parentTail.grant.subject) {
    throw new AttenuationError('delegator does not hold the parent subject key')
  }

  const provisional = narrow(parentTail.grant, restriction, {
    id: '',
    issuer: parentTail.grant.subject,
    subject: newSubject,
  })
  const { id: _drop, ...body } = provisional
  const grant: CapabilityGrant = { id: deriveId(body), ...body }

  if (!isAttenuationOf(grant, parentTail.grant)) {
    throw new AttenuationError('refusing to issue: child grant would broaden authority')
  }

  const suite = parentTail.suite
  const sig = signerFor(suite).sign(encodeCanonical(grant), delegator.secretKey)
  return { chain: [...parent.chain, { grant, suite, signerPublicKey: delegator.publicKey, sig }] }
}

/** Verify the full chain against an explicit set of trusted root public keys. */
export function verifyChain(cap: Capability, trustedRoots: readonly Bytes[]): boolean {
  if (cap.chain.length === 0) return false
  const trusted = new Set(trustedRoots.map((k) => bytesToHex(k)))

  for (let i = 0; i < cap.chain.length; i++) {
    const link = cap.chain[i]
    if (link === undefined) return false
    const signerHex = bytesToHex(link.signerPublicKey)

    // The grant's issuer must be the key that signed this link.
    if (link.grant.issuer !== signerHex) return false
    if (
      !signerFor(link.suite).verify(link.sig, encodeCanonical(link.grant), link.signerPublicKey)
    ) {
      return false
    }

    if (i === 0) {
      if (!trusted.has(signerHex)) return false // root must be a trusted authority
    } else {
      const prev = cap.chain[i - 1]
      if (prev === undefined) return false
      // The delegator must hold the previous link's subject key…
      if (signerHex !== prev.grant.subject) return false
      // …and the grant must strictly attenuate its parent.
      if (!isAttenuationOf(link.grant, prev.grant)) return false
    }
  }
  return true
}

/** The effective (most-restrictive) grant: the chain tail. */
export function effectiveGrant(cap: Capability): CapabilityGrant {
  return tail(cap).grant
}
