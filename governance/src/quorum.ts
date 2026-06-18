/**
 * M-of-N quorum approval, revocation registry, and the local kill switch.
 *
 * Each approval is an independent PQ signature (ML-DSA-87) over the canonical
 * proposal. Enactment counts DISTINCT valid member signatures and requires at
 * least `threshold`. This is an independent-signature quorum — NOT single-key
 * threshold-MPC crypto (which would need a threshold signature scheme; tracked
 * as future work). No single member can veto.
 */

import {
  encodeCanonical,
  signerFor,
  SHA3_SHAKE256,
  type KeyPair,
  type Bytes,
} from '../../crypto/src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import type { Approval, EnactmentResult, Proposal, Quorum } from './types.js'

const GOV_CONTEXT = 'polarseek-gov-v1'

function proposalBytes(p: Proposal): Bytes {
  return encodeCanonical([
    GOV_CONTEXT,
    p.id,
    p.kind,
    p.target,
    p.payload,
    p.notBefore,
    p.notAfter,
    p.nonce,
  ])
}

/** Deterministic proposal id from its content (excluding the id itself). */
export function proposalId(p: Omit<Proposal, 'id'>): string {
  const h = SHA3_SHAKE256.digest(
    encodeCanonical([GOV_CONTEXT, p.kind, p.target, p.payload, p.notBefore, p.notAfter, p.nonce]),
  )
  return bytesToHex(h).slice(0, 24)
}

export function approve(p: Proposal, suite: string, member: KeyPair): Approval {
  const sig = signerFor(suite).sign(proposalBytes(p), member.secretKey)
  return { proposalId: p.id, signer: bytesToHex(member.publicKey), suite, sig }
}

export function verifyApproval(p: Proposal, a: Approval): boolean {
  if (a.proposalId !== p.id) return false
  try {
    return signerFor(a.suite).verify(a.sig, proposalBytes(p), hexToBytes(a.signer))
  } catch {
    return false
  }
}

/** Count distinct valid member approvals; enact iff >= threshold and in-window. */
export function enact(
  p: Proposal,
  approvals: readonly Approval[],
  quorum: Quorum,
  now: number,
): EnactmentResult {
  const reasons: string[] = []
  if (now < p.notBefore || now > p.notAfter) reasons.push('proposal is outside its validity window')

  const members = new Set(quorum.members)
  const distinctValid = new Set<string>()
  for (const a of approvals) {
    if (!members.has(a.signer)) continue
    if (verifyApproval(p, a)) distinctValid.add(a.signer)
  }
  const n = distinctValid.size
  if (n < quorum.threshold) reasons.push(`need ${quorum.threshold} approvals, have ${n}`)
  return { enacted: reasons.length === 0, validApprovals: n, reasons }
}

/** In-memory revocation registry driven by enacted `revoke` proposals. */
export class RevocationRegistry {
  private readonly revoked = new Set<string>()

  enactRevocation(
    p: Proposal,
    approvals: readonly Approval[],
    quorum: Quorum,
    now: number,
  ): EnactmentResult {
    if (p.kind !== 'revoke') {
      return { enacted: false, validApprovals: 0, reasons: ['proposal is not a revocation'] }
    }
    const r = enact(p, approvals, quorum, now)
    if (r.enacted) this.revoked.add(p.target)
    return r
  }

  isRevoked(target: string): boolean {
    return this.revoked.has(target)
  }
}

/**
 * Customer-held LOCAL kill switch — a sovereign override that denies everything
 * regardless of quorum. Complements (does not replace) threshold global
 * revocation.
 */
export class LocalKillSwitch {
  private killed = false
  engage(): void {
    this.killed = true
  }
  release(): void {
    this.killed = false
  }
  get engaged(): boolean {
    return this.killed
  }
}
