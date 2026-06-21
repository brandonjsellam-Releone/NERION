// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  proposalId,
  approve,
  enact,
  RevocationRegistry,
  LocalKillSwitch,
  type Proposal,
  type Quorum,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const m1 = s.keygen()
const m2 = s.keygen()
const m3 = s.keygen()
const outsider = s.keygen()
const NOW = 1000

const quorum: Quorum = {
  members: [m1, m2, m3].map((k) => bytesToHex(k.publicKey)),
  threshold: 2,
}

function revokeProposal(target: string): Proposal {
  const base = {
    kind: 'revoke' as const,
    target,
    payload: '',
    notBefore: 0,
    notAfter: NOW + 1000,
    nonce: 'n1',
  }
  return { id: proposalId(base), ...base }
}

describe('M-of-N quorum', () => {
  const p = revokeProposal('cap-123')

  it('enacts with threshold distinct valid approvals', () => {
    const r = enact(p, [approve(p, suite, m1, quorum), approve(p, suite, m2, quorum)], quorum, NOW)
    expect(r.enacted).toBe(true)
    expect(r.validApprovals).toBe(2)
  })

  it('does not enact below threshold', () => {
    expect(enact(p, [approve(p, suite, m1, quorum)], quorum, NOW).enacted).toBe(false)
  })

  it('fails closed on a non-positive threshold (zero cannot enact with no approvals)', () => {
    const zeroQuorum: Quorum = { members: quorum.members, threshold: 0 }
    expect(enact(p, [], zeroQuorum, NOW).enacted).toBe(false)
  })

  it('counts a duplicate signer only once', () => {
    const r = enact(p, [approve(p, suite, m1, quorum), approve(p, suite, m1, quorum)], quorum, NOW)
    expect(r.validApprovals).toBe(1)
    expect(r.enacted).toBe(false)
  })

  it('ignores non-member and invalid approvals', () => {
    const r = enact(
      p,
      [approve(p, suite, outsider, quorum), approve(p, suite, m1, quorum)],
      quorum,
      NOW,
    )
    expect(r.validApprovals).toBe(1)
  })

  it('rejects approvals for a different proposal', () => {
    const other = revokeProposal('cap-999')
    const r = enact(
      p,
      [approve(other, suite, m1, quorum), approve(other, suite, m2, quorum)],
      quorum,
      NOW,
    )
    expect(r.enacted).toBe(false)
  })

  it('does not enact outside the validity window', () => {
    const r = enact(
      p,
      [approve(p, suite, m1, quorum), approve(p, suite, m2, quorum)],
      quorum,
      NOW + 100000,
    )
    expect(r.enacted).toBe(false)
  })

  it('an approval does not transfer across quorums (GOV-QUORUM-001)', () => {
    // m1+m2 approve under the strict 2-of-3 committee `quorum`.
    const a1 = approve(p, suite, m1, quorum)
    const a2 = approve(p, suite, m2, quorum)

    // A DIFFERENT committee (different roster) must NOT count those approvals —
    // each signature is scoped to the exact quorum it was gathered under.
    const otherRoster: Quorum = {
      members: [m1, m2].map((k) => bytesToHex(k.publicKey)),
      threshold: 2,
    }
    const crossRoster = enact(p, [a1, a2], otherRoster, NOW)
    expect(crossRoster.validApprovals).toBe(0)
    expect(crossRoster.enacted).toBe(false)

    // The insidious case — SAME roster, LOWERED threshold — also must not count.
    const lowered: Quorum = { members: quorum.members, threshold: 1 }
    expect(enact(p, [a1], lowered, NOW).validApprovals).toBe(0)

    // Sanity: re-signed under the other roster, they DO reach its threshold.
    const reSigned = enact(
      p,
      [approve(p, suite, m1, otherRoster), approve(p, suite, m2, otherRoster)],
      otherRoster,
      NOW,
    )
    expect(reSigned.enacted).toBe(true)
  })

  it('GOV-TIME-001: a non-finite clock fails closed (cannot skip the validity window)', () => {
    const aps = [approve(p, suite, m1, quorum), approve(p, suite, m2, quorum)]
    expect(enact(p, aps, quorum, Number.NaN).enacted).toBe(false)
    expect(enact(p, aps, quorum, Number.POSITIVE_INFINITY).enacted).toBe(false)
  })

  it('GOV-SUITE-001: an approval is bound to its signature suite (relabel rejected)', () => {
    // PS-1 and PS-5 share ML-DSA-87, so without binding the suite into the signed bytes a PS-5
    // approval would verify as PS-1. The suite is now in proposalBytes, so a relabel fails.
    const a1 = approve(p, suite, m1, quorum)
    const relabeled = { ...a1, suite: SUITE_IDS.PS_1 }
    const r = enact(p, [relabeled, approve(p, suite, m2, quorum)], quorum, NOW)
    expect(r.validApprovals).toBe(1) // the relabeled m1 approval no longer counts
    expect(r.enacted).toBe(false)
  })
})

describe('revocation registry & kill switch', () => {
  it('revokes a target once a quorum enacts it', () => {
    const reg = new RevocationRegistry()
    const p = revokeProposal('cap-abc')
    expect(reg.isRevoked('cap-abc')).toBe(false)
    reg.enactRevocation(
      p,
      [approve(p, suite, m1, quorum), approve(p, suite, m2, quorum)],
      quorum,
      NOW,
    )
    expect(reg.isRevoked('cap-abc')).toBe(true)
  })

  it('does not revoke without quorum', () => {
    const reg = new RevocationRegistry()
    const p = revokeProposal('cap-xyz')
    reg.enactRevocation(p, [approve(p, suite, m1, quorum)], quorum, NOW)
    expect(reg.isRevoked('cap-xyz')).toBe(false)
  })

  it('local kill switch engages and releases', () => {
    const k = new LocalKillSwitch()
    expect(k.engaged).toBe(false)
    k.engage()
    expect(k.engaged).toBe(true)
    k.release()
    expect(k.engaged).toBe(false)
  })
})
