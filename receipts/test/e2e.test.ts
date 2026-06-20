// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  signerFor,
  SUITE_IDS,
  issuePermit,
  verifyPermit,
  randomBytes,
} from '../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../capabilities/src/index.js'
import {
  decide,
  buildReplayBundle,
  replay,
  DEFAULT_POLICY,
  type KernelInput,
} from '../../kernel/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import { buildReceipt, receiptLeaf, verifyReceiptInclusion } from '../src/index.js'

/**
 * End-to-end "governed money-movement" (Tier-2) demo, exercised as a test.
 * Run as a readable trace with:  npm run demo
 *
 *   intent -> admission decision -> PermitToken (hot) -> PQ receipt (nearline)
 *          -> transparency-log inclusion -> INDEPENDENT external verification
 */
describe('end-to-end T2 governed payment', () => {
  it('admits, receipts, anchors, and verifies with no trust in the issuer or operator', () => {
    const log: string[] = []
    const say = (s: string) => log.push(s)

    const NOW = 1_750_000_000
    const suite = SUITE_IDS.PS_5
    const signer = signerFor(suite)

    // Parties.
    const authority = signer.keygen() // capability-issuing authority (root of trust)
    const agent = signer.keygen() // the AI agent acting (capability holder)
    const issuer = signer.keygen() // the PolarSeek node that signs receipts
    const sessionKey = randomBytes(48) // hot-path PermitToken MAC key
    const trustedRoots = [authority.publicKey]

    say(`suite=${suite}  (CNSA 2.0 Cat-5: ML-KEM-1024+P-384 / ML-DSA-87)`)

    // 1) Authority grants the agent a narrow treasury capability.
    const cap = issueRoot(
      {
        subject: bytesToHex(agent.publicKey),
        actions: ['payment.transfer'],
        perActionCeiling: 1000,
        aggregateCap: 5000,
        counterparties: ['vendor-acme'],
        maxTier: 2,
        notBefore: 0,
        notAfter: NOW + 86_400,
        delegable: true,
      },
      suite,
      authority,
    )
    say('capability: payment.transfer ≤ 1000 to {vendor-acme}, aggregate ≤ 5000, tier ≤ 2')

    // 2) Agent proposes a typed ACTION intent (the verb — never perception).
    const intent: ActionIntent = {
      type: 'payment.transfer',
      resource: 'acct://treasury/ops',
      counterparty: 'vendor-acme',
      amount: 500,
    }
    say(`intent: transfer ${intent.amount} to ${intent.counterparty}`)

    const input: KernelInput = {
      intent,
      capabilities: [cap],
      policy: DEFAULT_POLICY,
      trustedRoots,
      now: NOW,
      observedAggregate: 1500, // a signed scalar from the nearline plane, not in-kernel state
      holder: bytesToHex(agent.publicKey),
    }

    // 3) Plane 1 — stateless admission decision.
    const decision = decide(input)
    say(
      `decision: ${decision.effect.toUpperCase()} tier=${decision.tier} obligations=[${decision.obligations.join(', ')}]`,
    )
    expect(decision.effect).toBe('allow')
    expect(decision.tier).toBe(2)
    expect(decision.obligations).toContain('nearline-receipt')

    // 3b) Plane 1 — issue a short-lived PermitToken (HMAC, no PQ on the hot path).
    const permit = issuePermit(
      { intent, tier: decision.tier, exp: NOW + 30, evaluator: decision.evaluatorVersion },
      suite,
      sessionKey,
    )
    expect(verifyPermit(permit, sessionKey)).toBe(true)
    say('permit: issued + verified (HMAC-SHA-384, session-scoped)')

    // 4) Plane 2 — deterministic replay + PQ receipt.
    const bundle = buildReplayBundle(input)
    const r1 = replay(bundle)
    const r2 = replay(bundle)
    expect(r1.receiptHash).toBe(r2.receiptHash) // byte-identical determinism
    say(`replay: deterministic (receiptHash=${r1.receiptHash.slice(0, 16)}…)`)

    const receipt = buildReceipt({
      suite,
      evaluatorVersion: decision.evaluatorVersion,
      effect: decision.effect,
      tier: decision.tier,
      jurisdiction: 'US',
      timestamp: NOW,
      intent,
      capability: cap,
      policy: DEFAULT_POLICY,
      inputHash: r1.inputHash,
      decisionHash: r1.receiptHash,
      issuerSecretKey: issuer.secretKey,
      issuerPublicKey: issuer.publicKey,
    })
    say('receipt: built + signed (ML-DSA-87) — commitments only, no PII/payload')

    // 5) Plane 2 — anchor the receipt into the transparency log (amongst others).
    const tlog = new TransparencyLog()
    tlog.append(new TextEncoder().encode('prior-entry'))
    const { index } = tlog.append(receiptLeaf(receipt))
    tlog.append(new TextEncoder().encode('later-entry'))
    const gossipedRoot = tlog.root()
    const witness = tlog.proveInclusion(index)
    say(
      `anchored: leaf #${index} of ${tlog.size()}, root=${bytesToHex(gossipedRoot).slice(0, 16)}…`,
    )

    // 6) INDEPENDENT verification — trust only the issuer key + gossiped root.
    const verdict = verifyReceiptInclusion(receipt, witness, gossipedRoot, issuer.publicKey)
    say(`EXTERNAL VERIFY: ${verdict.ok ? 'PASS' : 'FAIL — ' + verdict.reasons.join('; ')}`)
    expect(verdict.ok).toBe(true)

    // 7) Counter-example: an over-ceiling transfer is denied.
    const denied = decide({ ...input, intent: { ...intent, amount: 5000 } })
    expect(denied.effect).toBe('deny')
    say(`control: transfer 5000 (> ceiling) -> ${denied.effect.toUpperCase()}`)

    // eslint-disable-next-line no-console
    console.log(
      '\n=== PolarSeek T2 governed-payment demo ===\n' + log.map((l) => '  ' + l).join('\n') + '\n',
    )
  })
})
