#!/usr/bin/env node
/**
 * Standalone EXTERNAL verifier for a PolarSeek receipt bundle.
 *
 * Trusts ONLY the issuer public key and the gossiped log root embedded in the
 * bundle — never the issuer's or the log operator's good behavior. Re-derives
 * the Merkle root from the inclusion proof and verifies the ML-DSA-87 signature.
 *
 * Prereq: `npm run build` (+ `npm run bundle` to produce a sample).
 * Usage: `npm run verify:cli [path-to-bundle.json]`
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { hexToBytes } from '@noble/hashes/utils.js'
import { verifyReceiptInclusion } from '../dist/receipts/src/index.js'

const defaultPath = fileURLToPath(new URL('../polarseek-receipt-bundle.json', import.meta.url))
const path = process.argv[2] ?? defaultPath
const b = JSON.parse(readFileSync(path, 'utf8'))

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
const gossipedRoot = hexToBytes(b.gossipedRootHex)
const issuerKey = hexToBytes(b.issuerPublicKeyHex)

const verdict = verifyReceiptInclusion(receipt, witness, gossipedRoot, issuerKey)

console.log('PolarSeek external receipt verification')
console.log('  file        :', path)
console.log('  effect/tier :', b.decision?.effect, '/', b.decision?.tier)
console.log('  suite       :', receipt.body.suite)
console.log('  jurisdiction:', receipt.body.jurisdiction)
console.log('  log root    :', b.gossipedRootHex.slice(0, 24) + '…')
console.log('  intent commit:', receipt.body.commitments.intent.slice(0, 24) + '…')
if (verdict.ok) {
  console.log('\n  RESULT: ✔ VERIFIED (signature + log inclusion, no operator trust)')
  process.exit(0)
} else {
  console.log('\n  RESULT: x FAILED')
  for (const r of verdict.reasons) console.log('   -', r)
  process.exit(1)
}
