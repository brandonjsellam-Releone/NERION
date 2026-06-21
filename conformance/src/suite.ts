// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

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
  getSuite,
  assessCnsa20,
  coseSign1,
  coseSign1Verify,
  encodeCoseSign1,
  decodeCoseSign1,
  signEatResult,
  COSE_ALG,
  issuePermit,
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
import {
  TransparencyLog,
  checkConsistency,
  checkInclusion,
  detectEquivocation,
} from '../../translog/src/index.js'
import {
  buildReceipt,
  receiptLeaf,
  verifyReceiptInclusion,
  buildQuorumReceipt,
  verifyQuorumReceipt,
} from '../../receipts/src/index.js'
import { SoftwareAttester } from '../../attest/src/index.js'
import {
  PolarSeekNode,
  verifyPermitForAction,
  deriveAudiencePermitKey,
  actionHash,
  type Session,
} from '../../planes/src/index.js'
import {
  proposalId,
  approve,
  enact,
  type Proposal,
  type Quorum,
} from '../../governance/src/index.js'
import {
  commit,
  commitField,
  verifyDisclosure,
  proveBelow,
  verifyBelow,
  randomScalar,
  commitAmount,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
  bindAmountCommitment,
  verifyBoundCommitment,
  verifyBoundAmount,
} from '../../disclosure/src/index.js'
import { runNegativeOracle } from './negative.js'
import { assertCnsa, signCnsaVerdict, verifyCnsaVerdict, cnsaVerdictLeaf } from './cnsa-oracle.js'
import { buildCbom, signCbom, verifyCbom, cbomLeaf } from './cbom.js'
import {
  SoftwareOtsStateStore,
  HbsKeyProvider,
  type HbsSignEngine,
} from '../../keystore/src/index.js'
import {
  buildSbom,
  buildSlsaProvenance,
  signSupplyChainStatement,
  verifySupplyChainStatement,
  supplyChainLeaf,
} from './supplychain.js'

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
      // The resource is provisioned with ONLY its audience-scoped key (ADR-0015).
      const audienceKey = deriveAudiencePermitKey(session.sessionKey, 'acct://x')
      const ok = verifyPermitForAction(out.permit, audienceKey, {
        audience: 'acct://x',
        intent,
        now: NOW + 1,
      }).ok
      const replayDifferent = verifyPermitForAction(out.permit, audienceKey, {
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

  () =>
    check('C12', 'Quorum receipt finalizes at k (not below); rejects set substitution', () => {
      const s = signerFor(SUITE)
      const v = [s.keygen(), s.keygen(), s.keygen()]
      const set = { validators: v.map((kp) => ({ pubkey: bytesToHex(kp.publicKey), stake: 1 })) }
      const body = {
        v: 1 as const,
        suite: SUITE,
        evaluatorVersion: 'v',
        effect: 'allow',
        tier: 2,
        jurisdiction: 'US',
        timestamp: NOW,
        commitments: {
          intent: 'aa',
          capability: 'none',
          policy: 'bb',
          inputHash: 'cc',
          decisionHash: 'dd',
        },
      }
      const k = 2
      const epoch = 1
      const two = verifyQuorumReceipt(
        buildQuorumReceipt(body, set, k, epoch, [v[0]!, v[1]!], SUITE),
        set,
        k,
        epoch,
      ).ok
      const one = verifyQuorumReceipt(
        buildQuorumReceipt(body, set, k, epoch, [v[0]!], SUITE),
        set,
        k,
        epoch,
      ).ok
      // Permissive-set substitution: a receipt bound to an attacker set (where an
      // attacker key is a "validator") is rejected against the real trusted set.
      const atk = s.keygen()
      const atkSet = {
        validators: [
          { pubkey: bytesToHex(v[0]!.publicKey), stake: 1 },
          { pubkey: bytesToHex(atk.publicKey), stake: 1 },
        ],
      }
      const substituted = verifyQuorumReceipt(
        buildQuorumReceipt(body, atkSet, 2, epoch, [v[0]!, atk], SUITE),
        set,
        k,
        epoch,
      ).ok
      return two && !one && !substituted
    }),

  () =>
    check(
      'C13',
      'Policy-satisfaction proof verifies in-bound amount, hides it, rejects out-of-bound',
      () => {
        const { commitment, opening } = commitAmount(40n)
        const bounds = { perActionCeiling: 100n }
        const proof = provePolicySatisfaction(40n, opening, bounds)
        const good = verifyPolicySatisfaction(commitment, bounds, proof)
        // the proof is bound to its ceiling: it does not verify against a tighter one
        const tighter = !verifyPolicySatisfaction(commitment, { perActionCeiling: 30n }, proof)
        // a prover cannot prove an amount above the ceiling
        let cannotForge = false
        try {
          provePolicySatisfaction(150n, opening, bounds)
        } catch {
          cannotForge = true
        }
        return good && tighter && cannotForge
      },
    ),

  () =>
    check('C14', 'Govern the verb: the decision is invariant to perception-shaped inputs', () => {
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
        intent: { type: 'payment.transfer', resource: 'acct://x', amount: 500 },
        capabilities: [cap],
        policy: DEFAULT_POLICY,
        trustedRoots: [authority.publicKey],
        now: NOW,
        observedAggregate: 0,
        holder: bytesToHex(agent.publicKey),
      }
      return runNegativeOracle(input).invariant
    }),

  () =>
    check(
      'C15',
      'CNSA 2.0 oracle: PS-5 is conformant (ML-DSA-87/ML-KEM-1024/AES-256/SHA-384); PS-1 is not',
      () => {
        const ps5 = assessCnsa20(getSuite(SUITE_IDS.PS_5))
        const ps1 = assessCnsa20(getSuite(SUITE_IDS.PS_1))
        // PS-5 conformant but transitional (hybrid KEM + SHA3); PS-1 fails (ML-KEM-768).
        return ps5.conformant && !ps5.pureCnsa && !ps1.conformant
      },
    ),

  () =>
    check(
      'C16',
      'CNSA 2.0 signed verdict: PS-5 conformant-transitional, signed+anchored+verified; PS-1 rejected',
      () => {
        const s = signerFor(SUITE)
        const issuer = s.keygen()
        const v = assertCnsa(SUITE_IDS.PS_5)
        if (!(v.conformant && v.level === 'CNSA-2.0-Cat5-transitional')) return false
        const env = signCnsaVerdict(v, SUITE, issuer.secretKey)
        const verified =
          verifyCnsaVerdict(env, issuer.publicKey) && !verifyCnsaVerdict(env, s.keygen().publicKey)
        const log = new TransparencyLog()
        const { index } = log.append(cnsaVerdictLeaf(env))
        const anchored = checkInclusion(log.proveInclusion(index), log.root())
        return verified && anchored && !assertCnsa(SUITE_IDS.PS_1).conformant
      },
    ),

  () =>
    check(
      'C17',
      'CBOM inventories active suites, flags quantum-vulnerable legs (P-384/X25519), signs+anchors+verifies',
      () => {
        const s = signerFor(SUITE)
        const issuer = s.keygen()
        const cbom = buildCbom(NOW)
        if (!cbom.quantumVulnerable.includes('P-384') || !cbom.quantumVulnerable.includes('X25519'))
          return false
        if (cbom.quantumVulnerable.includes('ML-KEM-1024')) return false
        const env = signCbom(cbom, SUITE, issuer.secretKey)
        const verified = verifyCbom(env, issuer.publicKey) && !verifyCbom(env, s.keygen().publicKey)
        const log = new TransparencyLog()
        const { index } = log.append(cbomLeaf(env))
        return verified && checkInclusion(log.proveInclusion(index), log.root())
      },
    ),

  () =>
    check(
      'C18',
      'CNSA 2.0 code-signing: single-tree LMS conformant / HSS multi-tree excluded; reserve-before-sign never reuses an OTS index',
      () => {
        const base = getSuite(SUITE_IDS.PS_5)
        const sigStatus = (id: string): string =>
          assessCnsa20({ ...base, sigId: id }).findings.find((f) => f.component === 'signature')!
            .status
        const lmsOk = sigStatus('LMS-SHA256-M24') === 'conformant'
        const mtBad = sigStatus('XMSSMT-SHA2_20-2_256') === 'non-conformant'
        // reserve-before-sign: a fault burns the index; the retry uses a fresh one (no reuse).
        const engine: HbsSignEngine = {
          getRoot: () => new Uint8Array([1]),
          params: () => ({ family: 'LMS', multiTree: false, hash: 'SHA-256/192', height: 2 }),
          signWithIndex: (_k, index) => {
            if (index === 0) throw new Error('fault')
            return new Uint8Array([index])
          },
        }
        const provider = new HbsKeyProvider(engine, new SoftwareOtsStateStore(true))
        let threw = false
        try {
          provider.sign('k', new Uint8Array([1]))
        } catch {
          threw = true
        }
        const sig2 = provider.sign('k', new Uint8Array([1])) // must be index 1, not 0
        return lmsOk && mtBad && threw && sig2[0] === 1
      },
    ),

  () =>
    check(
      'C19',
      'COSE_Sign1 (RFC 9052) over ML-DSA-87 verifies, binds alg, rejects tamper; RATS/EAT result round-trips',
      () => {
        const s = signerFor(SUITE)
        const kp = s.keygen()
        const enc = new TextEncoder()
        const msg = coseSign1(enc.encode('m'), SUITE, kp.secretKey, COSE_ALG.ML_DSA_87)
        const ok = coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)
        const badKey = !coseSign1Verify(msg, SUITE, s.keygen().publicKey, COSE_ALG.ML_DSA_87)
        const badAlg = !coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_65)
        const eat = signEatResult(enc.encode('n'), { result: 'affirming' }, SUITE, kp.secretKey)
        const eatOk = coseSign1Verify(
          decodeCoseSign1(encodeCoseSign1(eat)),
          SUITE,
          kp.publicKey,
          COSE_ALG.ML_DSA_87,
        )
        return ok && badKey && badAlg && eatOk
      },
    ),

  () =>
    check(
      'C20',
      'Signed SBOM + SLSA provenance (COSE_Sign1) verify and anchor; wrong key rejected',
      () => {
        const s = signerFor(SUITE)
        const kp = s.keygen()
        const sbomSig = signSupplyChainStatement(buildSbom(undefined, NOW), SUITE, kp.secretKey)
        const prov = buildSlsaProvenance({
          subjectName: 'polarseek',
          subjectSha256: 'ab'.repeat(32),
          buildType: 'https://polarseek/bt/v1',
          builderId: 'https://polarseek/builder',
          now: NOW,
        })
        const provSig = signSupplyChainStatement(prov, SUITE, kp.secretKey)
        const ok =
          verifySupplyChainStatement(sbomSig, SUITE, kp.publicKey) &&
          verifySupplyChainStatement(provSig, SUITE, kp.publicKey)
        const badKey = !verifySupplyChainStatement(sbomSig, SUITE, s.keygen().publicKey)
        const log = new TransparencyLog()
        const { index } = log.append(supplyChainLeaf(provSig))
        return ok && badKey && checkInclusion(log.proveInclusion(index), log.root())
      },
    ),

  () =>
    check(
      'C21',
      'v:2 structural binding ties the amount commitment to its intent (rejects substitution + wrong opening)',
      () => {
        const intent: ActionIntent = {
          type: 'payment.transfer',
          resource: 'vendor-acme',
          amount: 500,
        }
        const bound = bindAmountCommitment(intent)
        const good = verifyBoundCommitment(intent, bound.commitment, bound.digest)
        const full = verifyBoundAmount(intent, bound.commitment, bound.opening, bound.digest)
        // a malicious issuer substituting a commitment to a different amount is rejected
        const rejectsSub = !verifyBoundCommitment(intent, commitAmount(1n).commitment, bound.digest)
        // a wrong opening (C does not open to the intent's amount) is rejected by the full check
        const rejectsBadOpening = !verifyBoundAmount(
          intent,
          bound.commitment,
          bound.opening + 1n,
          bound.digest,
        )
        return good && full && rejectsSub && rejectsBadOpening
      },
    ),

  () =>
    check(
      'C22',
      'Plane-1 permits are per-audience key-bound (cross-audience forgery rejected)',
      () => {
        const s = signerFor(SUITE)
        const authority = s.keygen()
        const agent = s.keygen()
        const issuer = s.keygen()
        const attesterKey = s.keygen()
        const agentHex = bytesToHex(agent.publicKey)
        const ev = new SoftwareAttester(SUITE, attesterKey).produce('s', agentHex, 'n', NOW + 300)
        const session: Session = {
          sessionId: 's',
          sessionKey: new Uint8Array(48).fill(9),
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
        const intent: ActionIntent = { type: 'payment.transfer', resource: 'acct://A', amount: 500 }
        const out = node.admit({
          intent,
          capabilities: [cap],
          session,
          audience: 'acct://A',
          now: NOW,
          observedAggregate: 0,
        })
        if (out.permit === null) return false

        // Each resource holds ONLY its own derived key; distinct audiences differ.
        const keyA = deriveAudiencePermitKey(session.sessionKey, 'acct://A')
        const keyB = deriveAudiencePermitKey(session.sessionKey, 'acct://B')
        const distinct = bytesToHex(keyA) !== bytesToHex(keyB)
        const okA = verifyPermitForAction(out.permit, keyA, {
          audience: 'acct://A',
          intent,
          now: NOW + 1,
        }).ok
        // B's resource cannot verify A's permit (the MAC binds the audience).
        const rejectedUnderB = !verifyPermitForAction(out.permit, keyB, {
          audience: 'acct://B',
          intent,
          now: NOW + 1,
        }).ok

        // PERMIT-001 attacker holds ONLY keyB and re-MACs a permit claiming
        // audience A; A's resource (keyA) rejects the forgery.
        const forged = issuePermit(
          {
            sessionId: 's',
            nonce: ev.claims.nonce,
            audience: 'acct://A',
            actionHash: actionHash(intent),
            tier: out.decision.tier,
            exp: NOW + 30,
            evaluator: out.decision.evaluatorVersion,
            effect: out.decision.effect,
          },
          SUITE,
          keyB,
        )
        const forgeryRejected = !verifyPermitForAction(forged, keyA, {
          audience: 'acct://A',
          intent,
          now: NOW + 1,
        }).ok

        return distinct && okA && rejectedUnderB && forgeryRejected
      },
    ),

  () =>
    check(
      'C23',
      'v:1 intent commitment is salted/hiding (low-entropy fields not brute-forceable from the leaf)',
      () => {
        const intent: ActionIntent = {
          type: 'payment.transfer',
          resource: 'acct://A',
          amount: 500,
        }
        const salt = new Uint8Array(16).fill(0x5a)
        const salted = commitField(intent, salt)
        const unsalted = commitField(intent) // legacy, binding-only
        // Salting changes the digest, so the public commitment is no longer the
        // brute-forceable unsalted hash of the same (low-entropy) intent (RCPT-001 / ADR-0014).
        const hides = salted !== unsalted
        const discloses = verifyDisclosure(salted, intent, salt) // authorized verifier with the salt
        const needsSalt = !verifyDisclosure(salted, intent) // attacker without the salt fails
        const wrongSalt = !verifyDisclosure(salted, intent, new Uint8Array(16).fill(0x6b))
        return hides && discloses && needsSalt && wrongSalt
      },
    ),
]

export function runConformance(): ConformanceReport {
  const results = CHECKS.map((c) => c())
  const passed = results.filter((r) => r.passed).length
  return { ok: passed === results.length, passed, total: results.length, results }
}
