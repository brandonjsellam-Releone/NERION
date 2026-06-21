#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Standalone EXTERNAL verifier for a PolarSeek receipt bundle.
 *
 * "Zero trust in the operator" REQUIRES the two trust anchors to be supplied
 * OUT OF BAND — NOT read from the bundle under verification:
 *   - the expected ISSUER public key (from the issuer's independently-published key);
 *   - the gossiped LOG ROOT (from an independent gossip/witness of the log).
 * Reading them from the bundle would be circular trust: a forged, attacker-signed,
 * self-rooted bundle would "verify" (VERIFY-CLI-001, Team Apex 2026-06-21). This
 * CLI therefore REFUSES to verify unless both anchors are given out of band.
 *
 * Prereq: `npm run build` (+ `npm run bundle` to produce a sample, which prints the
 * exact out-of-band command).
 * Usage:
 *   NERION_ISSUER_PK=<hex> NERION_LOG_ROOT=<hex> npm run verify:cli [bundle.json]
 *   node tools/verify-receipt.mjs <bundle.json> <issuerPkHex> <logRootHex>
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { hexToBytes } from '@noble/hashes/utils.js'
import { verifyReceiptInclusion } from '../dist/receipts/src/index.js'
import { loadEnv } from '../dist/ops/src/index.js'

loadEnv()

const defaultPath = fileURLToPath(new URL('../polarseek-receipt-bundle.json', import.meta.url))
const path = process.argv[2] ?? defaultPath
const b = JSON.parse(readFileSync(path, 'utf8'))

// The trust anchors MUST come from OUTSIDE the bundle (VERIFY-CLI-001). Never fall
// back to b.issuerPublicKeyHex / b.gossipedRootHex — those are attacker-controlled.
const issuerHex = process.env.NERION_ISSUER_PK ?? process.argv[3]
const rootHex = process.env.NERION_LOG_ROOT ?? process.argv[4]
if (!issuerHex || !rootHex) {
  console.error('PolarSeek external receipt verification — REFUSING TO VERIFY')
  console.error('  The trusted issuer public key and the gossiped log root MUST be supplied OUT OF')
  console.error('  BAND — not taken from the bundle being verified. Otherwise a forged, attacker-')
  console.error('  signed, self-rooted bundle would "verify" (circular trust, VERIFY-CLI-001).')
  console.error('  Supply them:')
  console.error('    NERION_ISSUER_PK=<hex> NERION_LOG_ROOT=<hex> npm run verify:cli [bundle.json]')
  console.error('    node tools/verify-receipt.mjs <bundle.json> <issuerPkHex> <logRootHex>')
  process.exit(2)
}

const receipt = {
  body: b.receipt.body,
  sig: hexToBytes(b.receipt.sigHex),
  signerPublicKey: hexToBytes(b.receipt.signerPublicKeyHex),
}
const witness = {
  index: b.witness.index,
  size: b.witness.size,
  leaf: hexToBytes(b.witness.leafHex),
  proof: b.witness.proofHex.map((h) => hexToBytes(h)),
  root: hexToBytes(b.witness.rootHex),
}
// OUT-OF-BAND anchors — deliberately NOT b.gossipedRootHex / b.issuerPublicKeyHex.
const gossipedRoot = hexToBytes(rootHex)
const issuerKey = hexToBytes(issuerHex)

const verdict = verifyReceiptInclusion(receipt, witness, gossipedRoot, issuerKey)

console.log('PolarSeek external receipt verification')
console.log('  file         :', path)
console.log('  effect/tier  :', b.decision?.effect, '/', b.decision?.tier)
console.log('  suite        :', receipt.body.suite)
console.log('  jurisdiction :', receipt.body.jurisdiction)
console.log('  pinned issuer:', issuerHex.slice(0, 24) + '…  (out-of-band)')
console.log('  pinned root  :', rootHex.slice(0, 24) + '…  (out-of-band)')
console.log('  intent commit:', receipt.body.commitments.intent.slice(0, 24) + '…')
// Surface a divergence between the bundle's self-claim and the pinned anchors — a
// forged/foreign bundle typically self-declares a different issuer/root.
if (b.issuerPublicKeyHex && b.issuerPublicKeyHex !== issuerHex)
  console.log('  NOTE: bundle self-declares a DIFFERENT issuer than the pinned one (expected if forged/foreign).')
if (b.gossipedRootHex && b.gossipedRootHex !== rootHex)
  console.log('  NOTE: bundle self-declares a DIFFERENT log root than the pinned one (expected if forged/foreign).')
if (verdict.ok) {
  console.log('\n  RESULT: ✔ VERIFIED (signature + log inclusion under the OUT-OF-BAND issuer key + root)')
  process.exit(0)
} else {
  console.log('\n  RESULT: x FAILED')
  for (const r of verdict.reasons) console.log('   -', r)
  process.exit(1)
}
