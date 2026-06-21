// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

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

/**
 * Stable identity of a quorum CONFIGURATION = SHA3 over its sorted members +
 * threshold. Bound into every approval signature so a signature gathered under
 * one committee cannot be re-counted under a DIFFERENT committee that merely
 * lists the same operator — cross-quorum / set-substitution consent transfer
 * (GOV-QUORUM-001, Team Apex 2026-06-21). This mirrors the validator-set binding
 * ADR-0005 added to receipts/quorum.ts; governance previously carried only the
 * k>0 fail-closed back-port, not the set-binding.
 */
function quorumId(quorum: Quorum): string {
  const sortedMembers = [...quorum.members].sort()
  const h = SHA3_SHAKE256.digest(
    encodeCanonical([GOV_CONTEXT, 'quorum', sortedMembers, quorum.threshold]),
  )
  // Full-length (no truncation): quorumId is the SECURITY binding that isolates one committee's
  // consent from another's, so a 96-bit truncation invited a ~2^48 cross-quorum collision
  // (GOV-QID-001, Team Apex 2026-06-21). The short proposal id is fine; this binding must not be.
  return bytesToHex(h)
}

function proposalBytes(p: Proposal, qid: string, suite: string): Bytes {
  return encodeCanonical([
    GOV_CONTEXT,
    p.id,
    p.kind,
    p.target,
    p.payload,
    p.notBefore,
    p.notAfter,
    p.nonce,
    qid,
    // Bind the signature suite (GOV-SUITE-001, Team Apex 2026-06-21): without it an approval is
    // not tied to the algorithm it was made under (cross-suite/downgrade confusion, the CAP-001
    // class). Changing the approval's `suite` now changes the signed bytes and fails verification.
    suite,
  ])
}

/** Deterministic proposal id from its content (excluding the id itself). */
export function proposalId(p: Omit<Proposal, 'id'>): string {
  const h = SHA3_SHAKE256.digest(
    encodeCanonical([GOV_CONTEXT, p.kind, p.target, p.payload, p.notBefore, p.notAfter, p.nonce]),
  )
  return bytesToHex(h).slice(0, 24)
}

export function approve(p: Proposal, suite: string, member: KeyPair, quorum: Quorum): Approval {
  const sig = signerFor(suite).sign(proposalBytes(p, quorumId(quorum), suite), member.secretKey)
  return { proposalId: p.id, signer: bytesToHex(member.publicKey), suite, sig }
}

export function verifyApproval(p: Proposal, a: Approval, quorum: Quorum): boolean {
  if (a.proposalId !== p.id) return false
  try {
    return signerFor(a.suite).verify(
      a.sig,
      proposalBytes(p, quorumId(quorum), a.suite),
      hexToBytes(a.signer),
    )
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
  // Fail-closed on a non-finite clock: a NaN/Infinity `now` makes BOTH window comparisons false,
  // silently skipping the validity-window gate so an out-of-window proposal would enact
  // (GOV-TIME-001 — the KERNEL-TIME-001 / ATTEST-TIME-001 class, missed in governance). `now` is
  // the caller's clock; governance reads no clock of its own.
  if (!Number.isSafeInteger(now)) {
    reasons.push('enactment clock is non-finite or unsafe')
  } else if (now < p.notBefore || now > p.notAfter) {
    reasons.push('proposal is outside its validity window')
  }
  // Fail-closed on a non-positive threshold: threshold=0 would otherwise enact a
  // proposal with ZERO approvals (`0 < 0` is false). Surfaced by the re-audit.
  if (!Number.isInteger(quorum.threshold) || quorum.threshold < 1) {
    reasons.push('quorum threshold must be a positive integer')
  }

  const members = new Set(quorum.members)
  const distinctValid = new Set<string>()
  for (const a of approvals) {
    if (!members.has(a.signer)) continue
    if (verifyApproval(p, a, quorum)) distinctValid.add(a.signer)
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

  /**
   * The enacted revoked capability ids. Pass to admission as the explicit `revoked`
   * input (`node.admit({ ..., revoked: registry.revokedIds() })`) so a capability
   * whose chain contains any of these is denied — wiring quorum revocation into the
   * stateless kernel's enforcement path (REVOKE-ENFORCE-001, Team Apex 2026-06-21).
   */
  revokedIds(): string[] {
    return [...this.revoked]
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
