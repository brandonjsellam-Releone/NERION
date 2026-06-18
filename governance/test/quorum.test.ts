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
    const r = enact(p, [approve(p, suite, m1), approve(p, suite, m2)], quorum, NOW)
    expect(r.enacted).toBe(true)
    expect(r.validApprovals).toBe(2)
  })

  it('does not enact below threshold', () => {
    expect(enact(p, [approve(p, suite, m1)], quorum, NOW).enacted).toBe(false)
  })

  it('counts a duplicate signer only once', () => {
    const r = enact(p, [approve(p, suite, m1), approve(p, suite, m1)], quorum, NOW)
    expect(r.validApprovals).toBe(1)
    expect(r.enacted).toBe(false)
  })

  it('ignores non-member and invalid approvals', () => {
    const r = enact(p, [approve(p, suite, outsider), approve(p, suite, m1)], quorum, NOW)
    expect(r.validApprovals).toBe(1)
  })

  it('rejects approvals for a different proposal', () => {
    const other = revokeProposal('cap-999')
    const r = enact(p, [approve(other, suite, m1), approve(other, suite, m2)], quorum, NOW)
    expect(r.enacted).toBe(false)
  })

  it('does not enact outside the validity window', () => {
    const r = enact(p, [approve(p, suite, m1), approve(p, suite, m2)], quorum, NOW + 100000)
    expect(r.enacted).toBe(false)
  })
})

describe('revocation registry & kill switch', () => {
  it('revokes a target once a quorum enacts it', () => {
    const reg = new RevocationRegistry()
    const p = revokeProposal('cap-abc')
    expect(reg.isRevoked('cap-abc')).toBe(false)
    reg.enactRevocation(p, [approve(p, suite, m1), approve(p, suite, m2)], quorum, NOW)
    expect(reg.isRevoked('cap-abc')).toBe(true)
  })

  it('does not revoke without quorum', () => {
    const reg = new RevocationRegistry()
    const p = revokeProposal('cap-xyz')
    reg.enactRevocation(p, [approve(p, suite, m1)], quorum, NOW)
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
