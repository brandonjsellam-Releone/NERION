#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs a Tier-2 governed-payment admission through a PolarSeekNode and writes a
 * PORTABLE, self-contained receipt bundle (JSON, hex-encoded) to disk, so the
 * standalone verifier (tools/verify-receipt.mjs) — or any third party — can
 * verify the receipt's signature + transparency-log inclusion with no trust in
 * the issuer or the log operator.
 *
 * Prereq: `npm run build`.  Usage: `npm run bundle`.
 */
import { writeFileSync } from 'node:fs'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes } from '../dist/crypto/src/index.js'
import { issueRoot } from '../dist/capabilities/src/index.js'
import { DEFAULT_POLICY } from '../dist/kernel/src/index.js'
import { TransparencyLog } from '../dist/translog/src/index.js'
import { receiptLeaf } from '../dist/receipts/src/index.js'
import { SoftwareAttester, appraise } from '../dist/attest/src/index.js'
import { PolarSeekNode } from '../dist/planes/src/index.js'
import { loadEnv } from '../dist/ops/src/index.js'

loadEnv()

const NOW = 1_750_000_000
const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const authority = s.keygen()
const agent = s.keygen()
const issuer = s.keygen()
const attesterKey = s.keygen()
const attester = new SoftwareAttester(suite, attesterKey)
const agentHex = bytesToHex(agent.publicKey)

const evidence = attester.produce('sess-bundle', agentHex, 'a1b2c3d4', NOW + 300)
const appraised = appraise(evidence, {
  expectedNonce: 'a1b2c3d4',
  now: NOW,
  trustedAttesters: [attesterKey.publicKey],
  acceptedFormats: ['software-dev'],
})
if (!appraised.valid) throw new Error('attestation failed: ' + appraised.reasons.join('; '))

const cap = issueRoot(
  {
    subject: agentHex,
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

const node = new PolarSeekNode({
  suite,
  policy: DEFAULT_POLICY,
  trustedRoots: [authority.publicKey],
  issuer,
  log: new TransparencyLog(),
  jurisdiction: 'US',
  permitTtlSeconds: 30,
})

const out = node.admit({
  intent: { type: 'payment.transfer', resource: 'acct://treasury/ops', counterparty: 'vendor-acme', amount: 500 },
  capabilities: [cap],
  session: { sessionId: 'sess-bundle', sessionKey: randomBytes(48), claims: evidence.claims },
  audience: 'acct://treasury/ops',
  now: NOW,
  observedAggregate: 1500,
})

if (out.decision.effect !== 'allow' || !out.receipt || !out.inclusion) {
  throw new Error('expected an allow with a receipt; got ' + out.decision.effect)
}

const bundle = {
  description: 'PolarSeek portable receipt bundle — verify with: npm run verify:cli',
  decision: { effect: out.decision.effect, tier: out.decision.tier, obligations: out.decision.obligations },
  receipt: {
    body: out.receipt.body,
    sigHex: bytesToHex(out.receipt.sig),
    signerPublicKeyHex: bytesToHex(out.receipt.signerPublicKey),
  },
  witness: {
    index: out.inclusion.index,
    size: out.inclusion.size,
    leafHex: bytesToHex(out.inclusion.leaf),
    proofHex: out.inclusion.proof.map((h) => bytesToHex(h)),
    rootHex: bytesToHex(out.inclusion.root),
  },
  gossipedRootHex: bytesToHex(out.logRoot),
  issuerPublicKeyHex: bytesToHex(issuer.publicKey),
}

// Sanity: the appended leaf must equal the receipt's canonical body.
if (bundle.witness.leafHex !== bytesToHex(receiptLeaf(out.receipt))) {
  throw new Error('internal error: witness leaf != receipt body')
}

const path = new URL('../polarseek-receipt-bundle.json', import.meta.url)
writeFileSync(path, JSON.stringify(bundle, null, 2) + '\n')
console.log('wrote portable receipt bundle ->', path.pathname)
console.log(`decision=${out.decision.effect} tier=${out.decision.tier} logRoot=${bundle.gossipedRootHex.slice(0, 16)}…`)
console.log('verify it independently with:  npm run verify:cli')
