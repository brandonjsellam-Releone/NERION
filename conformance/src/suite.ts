/**
 * PolarSeek conformance suite — the certification moat.
 *
 * A portable set of checks that exercise every public guarantee end-to-end. Any
 * implementation (the TS reference, a future Rust port, a third-party build)
 * must pass all of these to claim conformance. Each check is self-contained.
 */

import { bytesToHex } from '@noble/hashes/utils.js'
import {
  signerFor,
  SUITE_IDS,
  negotiate,
  activeSuiteIds,
  encodeCanonical,
  kemFor,
} from '../../crypto/src/index.js'
import {
  issueRoot,
  attenuate,
  authorizesIntent,
  type ActionIntent,
} from '../../capabilities/src/index.js'
import {
  decide,
  buildReplayBundle,
  replay,
  DEFAULT_POLICY,
  type KernelInput,
} from '../../kernel/src/index.js'
import { TransparencyLog, checkConsistency, detectEquivocation } from '../../translog/src/index.js'
import { buildReceipt, receiptLeaf, verifyReceiptInclusion } from '../../receipts/src/index.js'
import { SoftwareAttester } from '../../attest/src/index.js'
import { PolarSeekNode, verifyPermitForAction, type Session } from '../../planes/src/index.js'
import {
  proposalId,
  approve,
  enact,
  type Proposal,
  type Quorum,
} from '../../governance/src/index.js'
import { commit, proveBelow, verifyBelow, randomScalar } from '../../disclosure/src/index.js'

export interface ConformanceResult {
  readonly id: string
  readonly name: string
  readonly passed: boolean
  readonly detail: string
}
export interface ConformanceReport {
  readonly ok: boolean
  readonly passed: number
  readonly total: number
  readonly results: ConformanceResult[]
}

const SUITE = SUITE_IDS.PS_5
const NOW = 1_750_000_000

function check(id: string, name: string, fn: () => boolean): ConformanceResult {
  try {
    const passed = fn()
    return { id, name, passed, detail: passed ? 'ok' : 'assertion returned false' }
  } catch (e) {
    return { id, name, passed: false, detail: `threw: ${(e as Error).message}` }
  }
}

const CHECKS: Array<() => ConformanceResult> = [
  () =>
    check('C1', 'SuiteID negotiation prefers Cat-5 and excludes pending', () => {
      const n = negotiate([SUITE_IDS.PS_1, SUITE_IDS.PS_5], [SUITE_IDS.PS_5, SUITE_IDS.PS_1])
      return n === SUITE_IDS.PS_5 && !activeSuiteIds().includes(SUITE_IDS.PS_5_HQC)
    }),

  () =>
    check('C2', 'Hybrid KEM round-trips', () => {
      const kem = kemFor(SUITE)
      const { publicKey, secretKey } = kem.keygen()
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
      return bytesToHex(kem.decapsulate(cipherText, secretKey)) === bytesToHex(sharedSecret)
    }),

  () =>
    check('C3', 'ML-DSA signatures verify and reject tampering', () => {
      const s = signerFor(SUITE)
      const { publicKey, secretKey } = s.keygen()
      const msg = new TextEncoder().encode('conformance')
      const sig = s.sign(msg, secretKey)
      const bad = Uint8Array.from(msg)
      bad[0] = (bad[0] as number) ^ 1
      return s.verify(sig, msg, publicKey) && !s.verify(sig, bad, publicKey)
    }),

  () =>
    check('C4', 'Canonical CBOR is key-order independent', () => {
      return (
        bytesToHex(encodeCanonical({ a: 1, b: 2 })) === bytesToHex(encodeCanonical({ b: 2, a: 1 }))
      )
    }),

  () =>
    check('C5', 'Capability attenuation never amplifies', () => {
      const s = signerFor(SUITE)
      const authority = s.keygen()
      const holder = s.keygen()
      const delegatee = s.keygen()
      const root = issueRoot(
        {
          subject: bytesToHex(holder.publicKey),
          actions: ['payment.transfer'],
          perActionCeiling: 1000,
          aggregateCap: null,
          counterparties: null,
          maxTier: 2,
          notBefore: 0,
          notAfter: NOW + 1000,
          delegable: true,
        },
        SUITE,
        authority,
      )
      const child = attenuate(
        root,
        { perActionCeiling: 100 },
        bytesToHex(delegatee.publicKey),
        holder,
      )
      const intent: ActionIntent = { type: 'payment.transfer', resource: 'r', amount: 500 }
      const ctx = { now: NOW, tier: 2 as const, observedAggregate: 0 }
      // Child denies 500 (ceiling 100) while parent allows it -> child ⊆ parent.
      return (
        authorizesIntent(root.chain[0]!.grant, intent, ctx) &&
        !authorizesIntent(child.chain[1]!.grant, intent, ctx)
      )
    }),

  () =>
    check('C6', 'Kernel default-denies and replays byte-identically', () => {
      const s = signerFor(SUITE)
      const authority = s.keygen()
      const agent = s.keygen()
      const cap = issueRoot(
        {
          subject: bytesToHex(agent.publicKey),
          actions: ['payment.transfer'],
          perActionCeiling: 1000,
          aggregateCap: null,
          counterparties: null,
          maxTier: 2,
          notBefore: 0,
          notAfter: NOW + 1000,
          delegable: false,
        },
        SUITE,
        authority,
      )
      const input: KernelInput = {
        intent: { type: 'payment.transfer', resource: 'r', amount: 500 },
        capabilities: [cap],
        policy: DEFAULT_POLICY,
        trustedRoots: [authority.publicKey],
        now: NOW,
        observedAggregate: 0,
        holder: bytesToHex(agent.publicKey),
      }
      const denyNoCap = decide({ ...input, capabilities: [] }).effect === 'deny'
      const b = buildReplayBundle(input)
      const det = replay(b).receiptHash === replay(b).receiptHash
      return denyNoCap && det && decide(input).effect === 'allow'
    }),

  () =>
    check('C7', 'Receipt verifies externally and rejects tampering', () => {
      const s = signerFor(SUITE)
      const issuer = s.keygen()
      const log = new TransparencyLog()
      const receipt = buildReceipt({
        suite: SUITE,
        evaluatorVersion: 'v',
        effect: 'allow',
        tier: 2,
        jurisdiction: 'US',
        timestamp: NOW,
        intent: { type: 'payment.transfer' },
        capability: null,
        policy: DEFAULT_POLICY,
        inputHash: 'aa',
        decisionHash: 'bb',
        issuerSecretKey: issuer.secretKey,
        issuerPublicKey: issuer.publicKey,
      })
      const { index } = log.append(receiptLeaf(receipt))
      const w = log.proveInclusion(index)
      const good = verifyReceiptInclusion(receipt, w, log.root(), issuer.publicKey).ok
      const other = s.keygen()
      const bad = verifyReceiptInclusion(receipt, w, log.root(), other.publicKey).ok
      return good && !bad
    }),

  () =>
    check('C8', 'PermitToken is action-bound (replay rejected)', () => {
      const s = signerFor(SUITE)
      const authority = s.keygen()
      const agent = s.keygen()
      const issuer = s.keygen()
      const attesterKey = s.keygen()
      const agentHex = bytesToHex(agent.publicKey)
      const ev = new SoftwareAttester(SUITE, attesterKey).produce('s', agentHex, 'n', NOW + 300)
      const session: Session = {
        sessionId: 's',
        sessionKey: new Uint8Array(48).fill(7),
        claims: ev.claims,
      }
      const cap = issueRoot(
        {
          subject: agentHex,
          actions: ['payment.transfer'],
          perActionCeiling: 1000,
          aggregateCap: null,
          counterparties: null,
          maxTier: 2,
          notBefore: 0,
          notAfter: NOW + 1000,
          delegable: false,
        },
        SUITE,
        authority,
      )
      const node = new PolarSeekNode({
        suite: SUITE,
        policy: DEFAULT_POLICY,
        trustedRoots: [authority.publicKey],
        issuer,
        log: new TransparencyLog(),
        jurisdiction: 'US',
        permitTtlSeconds: 30,
      })
      const intent: ActionIntent = { type: 'payment.transfer', resource: 'acct://x', amount: 500 }
      const out = node.admit({
        intent,
        capabilities: [cap],
        session,
        audience: 'acct://x',
        now: NOW,
        observedAggregate: 0,
      })
      if (out.permit === null) return false
      const ok = verifyPermitForAction(out.permit, session.sessionKey, {
        audience: 'acct://x',
        intent,
        now: NOW + 1,
      }).ok
      const replayDifferent = verifyPermitForAction(out.permit, session.sessionKey, {
        audience: 'acct://x',
        intent: { ...intent, amount: 600 },
        now: NOW + 1,
      }).ok
      return ok && !replayDifferent
    }),

  () =>
    check('C9', 'Governance enacts at threshold, not below', () => {
      const s = signerFor(SUITE)
      const members = [s.keygen(), s.keygen(), s.keygen()]
      const quorum: Quorum = { members: members.map((m) => bytesToHex(m.publicKey)), threshold: 2 }
      const base = {
        kind: 'revoke' as const,
        target: 'cap-x',
        payload: '',
        notBefore: 0,
        notAfter: NOW + 1000,
        nonce: 'n',
      }
      const p: Proposal = { id: proposalId(base), ...base }
      const two = enact(
        p,
        [approve(p, SUITE, members[0]!), approve(p, SUITE, members[1]!)],
        quorum,
        NOW,
      ).enacted
      const one = enact(p, [approve(p, SUITE, members[0]!)], quorum, NOW).enacted
      return two && !one
    }),

  () =>
    check('C10', 'Transparency consistency proof verifies; equivocation detected', () => {
      const log = new TransparencyLog()
      for (let i = 0; i < 3; i++) log.append(new TextEncoder().encode(`r${i}`))
      const from = log.size()
      for (let i = 3; i < 8; i++) log.append(new TextEncoder().encode(`r${i}`))
      const consistent = checkConsistency(log.proveConsistency(from))
      const eq = detectEquivocation([
        { operator: 'op', size: 4, rootHex: 'aa', suite: SUITE, sig: new Uint8Array() },
        { operator: 'op', size: 4, rootHex: 'bb', suite: SUITE, sig: new Uint8Array() },
      ])
      return consistent && eq.length === 1
    }),

  () =>
    check('C11', 'ZK range proof hides amount and binds to threshold', () => {
      const r = randomScalar()
      const C = commit(40n, r)
      const proof = proveBelow(40n, r, 100n)
      return verifyBelow(C, 100n, proof) && !verifyBelow(C, 50n, proof)
    }),
]

export function runConformance(): ConformanceReport {
  const results = CHECKS.map((c) => c())
  const passed = results.filter((r) => r.passed).length
  return { ok: passed === results.length, passed, total: results.length, results }
}
