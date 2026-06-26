// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * BENCH-01 (real-path) — measures Nerion's ACTUAL Plane-1 govern-the-verb code,
 * not a model. It drives the real `issueBoundPermit` / `verifyPermitForAction`
 * (planes/src/permit.ts) over the real audience-bound permit-key derivation,
 * HMAC-SHA-384 MAC, and SHA3/SHAKE256 action commitment, imported from the built
 * `dist/`. Run `npm run build` first.
 *
 * This realizes the first BENCH-01 roadmap item (bench/README.md): replace the
 * modelled verb path with the real protocol APIs. The primitive harness
 * (bench/run.mjs) still measures ML-DSA-87 / SHA3 / HKDF directly; this one
 * measures the assembled permit logic + its defenses.
 *
 * Adversarial corpus over the REAL verifier (each MUST yield verdict.ok=false):
 *   wrongAudienceKey  — another resource's derived key       (PERMIT-001 / ADR-0015 MAC binding)
 *   tamperedIntent    — intent mutated after issuance        (action-hash binding)
 *   audienceMismatch  — permit presented at the wrong resource
 *   expired           — now > exp                            (fail-closed expiry, PS-PLANE-05)
 *   effectMismatch    — bound effect != expected effect      (no silent downgrade)
 *   sessionMismatch   — wrong session id
 *   tamperedToken     — a flipped MAC byte
 * Valid traces MUST yield verdict.ok=true. A violation exits non-zero.
 *
 * Deterministic: fixed session key + claims => reproducible sizes + verdicts.
 * Timings are advisory. UNAUDITED / pre-FTO; no FIPS/production/non-infringement claim.
 *
 * Usage: node bench/run-permit.mjs [--update-baseline] [--permits=512]
 */
import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { SUITE_IDS, encodeCanonical, deriveAudiencePermitKey } from '../dist/crypto/src/index.js'
import { issueBoundPermit, verifyPermitForAction, actionHash } from '../dist/planes/src/permit.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = join(HERE, '..')
const SUITE = SUITE_IDS.PS_5
const NOW = 1_900_000_000 // fixed clock for determinism
const HARNESS_VERSION = '0.1.0'

const args = process.argv.slice(2)
const UPDATE_BASELINE = args.includes('--update-baseline')
const PERMITS = Number((args.find((a) => a.startsWith('--permits=')) || '').split('=')[1]) || 512
const AUDIENCES = 64
const REVOKED_FRACTION = 0.1

// deterministic byte helpers
const det = (label, n = 32) => {
  let out = new Uint8Array(0)
  let i = 0
  while (out.length < n) {
    const blk = new Uint8Array(createHash('sha3-256').update(`${label}/${i++}`).digest())
    const merged = new Uint8Array(out.length + blk.length)
    merged.set(out)
    merged.set(blk, out.length)
    out = merged
  }
  return out.slice(0, n)
}
const round = (x) => Math.round(x * 1000) / 1000
function stats(samples) {
  if (!samples.length) return { avg: 0, p50: 0, p95: 0, max: 0 }
  const s = [...samples].sort((a, b) => a - b)
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))]
  return {
    avg: round(s.reduce((a, b) => a + b, 0) / s.length),
    p50: round(at(0.5)),
    p95: round(at(0.95)),
    max: round(s[s.length - 1]),
  }
}

const sessionKey = det('nerion-bench/permit/session', 48)
const pay = (amount, audience) => ({ type: 'payment.transfer', resource: audience, amount })

const revoked = new Set()
for (let a = 0; a < AUDIENCES; a++) if (a / AUDIENCES < REVOKED_FRACTION) revoked.add(`acct://aud-${a}`)

const t = { issue: [], verify: [], derive: [] }
const wallStart = performance.now()

let validIssued = 0
let validOk = 0
let revokedRejected = 0
const adv = {
  wrongAudienceKey: { n: 0, rejected: 0 },
  tamperedIntent: { n: 0, rejected: 0 },
  audienceMismatch: { n: 0, rejected: 0 },
  expired: { n: 0, rejected: 0 },
  effectMismatch: { n: 0, rejected: 0 },
  sessionMismatch: { n: 0, rejected: 0 },
  tamperedToken: { n: 0, rejected: 0 },
}
let firstToken = null

const verify = (token, key, check) => {
  const v0 = performance.now()
  const verdict = verifyPermitForAction(token, key, check)
  t.verify.push(performance.now() - v0)
  return verdict
}

for (let i = 0; i < PERMITS; i++) {
  const audience = `acct://aud-${i % AUDIENCES}`
  const intent = pay(100 + i, audience)
  const claims = {
    sessionId: 'bench-sess',
    nonce: `n-${i}`,
    audience,
    actionHash: actionHash(intent),
    tier: 1,
    exp: NOW + 3600,
    evaluator: 'bench-eval@1',
    effect: 'allow',
  }

  const i0 = performance.now()
  const token = issueBoundPermit(claims, SUITE, sessionKey)
  t.issue.push(performance.now() - i0)
  if (!firstToken) firstToken = token

  if (revoked.has(audience)) {
    revokedRejected++ // resource refuses revoked audiences before any crypto
    continue
  }

  const d0 = performance.now()
  const audienceKey = deriveAudiencePermitKey(sessionKey, audience)
  t.derive.push(performance.now() - d0)
  const okCheck = { audience, intent, now: NOW + 5, sessionId: 'bench-sess', expectedEffect: 'allow' }

  // ---- valid trace ----
  validIssued++
  if (verify(token, audienceKey, okCheck).ok) validOk++

  // ---- adversarial traces (sampled) ----
  if (i % 4 === 0) {
    const otherAud = `acct://aud-${(i + 1) % AUDIENCES}`

    adv.wrongAudienceKey.n++
    if (!verify(token, deriveAudiencePermitKey(sessionKey, otherAud), okCheck).ok) adv.wrongAudienceKey.rejected++

    adv.tamperedIntent.n++
    if (!verify(token, audienceKey, { ...okCheck, intent: pay(100 + i + 1, audience) }).ok) adv.tamperedIntent.rejected++

    adv.audienceMismatch.n++
    if (!verify(token, audienceKey, { ...okCheck, audience: otherAud }).ok) adv.audienceMismatch.rejected++

    adv.expired.n++
    if (!verify(token, audienceKey, { ...okCheck, now: NOW + 100000 }).ok) adv.expired.rejected++

    adv.effectMismatch.n++
    if (!verify(token, audienceKey, { ...okCheck, expectedEffect: 'transform' }).ok) adv.effectMismatch.rejected++

    adv.sessionMismatch.n++
    if (!verify(token, audienceKey, { ...okCheck, sessionId: 'wrong-sess' }).ok) adv.sessionMismatch.rejected++

    adv.tamperedToken.n++
    const bad = { suite: token.suite, body: token.body, mac: token.mac.slice() }
    bad.mac[0] ^= 0x01
    if (!verify(bad, audienceKey, okCheck).ok) adv.tamperedToken.rejected++
  }
}

const allValidOk = validOk === validIssued && validIssued > 0
const allAdversarialRejected = Object.values(adv).every((c) => c.n > 0 && c.rejected === c.n)

const sizes = {
  permitBodyBytes: firstToken.body.length,
  permitMacBytes: firstToken.mac.length,
  permitTokenCanonicalBytes: encodeCanonical(firstToken).length,
}

const report = {
  meta: {
    harness: 'BENCH-01-permit',
    version: HARNESS_VERSION,
    target: 'real planes/src/permit.ts (issueBoundPermit / verifyPermitForAction) via dist/',
    suite: SUITE,
    mac: 'HMAC-SHA-384',
    commitment: 'SHA3/SHAKE256 actionHash',
    kdf: 'HKDF-SHA-384 audience permit key',
    node: process.version,
    workload: { permits: PERMITS, audiences: AUDIENCES, revokedFraction: REVOKED_FRACTION },
    note: 'UNAUDITED / pre-FTO. Measures real Nerion Plane-1 permit code. No FIPS/production/non-infringement claim.',
  },
  correctness: {
    validIssued,
    validOk,
    revokedRejected,
    adversarial: adv,
    allValidOk,
    allAdversarialRejected,
  },
  sizes,
  timings_ms: {
    issue: stats(t.issue),
    verify: stats(t.verify),
    deriveAudienceKey: stats(t.derive),
    totalWall: round(performance.now() - wallStart),
  },
  throughput: {
    permitsIssuedPerSec: round(PERMITS / (t.issue.reduce((a, b) => a + b, 0) / 1000)),
    verificationsPerSec: round(t.verify.length / (t.verify.reduce((a, b) => a + b, 0) / 1000)),
  },
}

writeFileSync(join(REPO, 'bench', 'report-permit.json'), JSON.stringify(report, null, 2) + '\n')

if (UPDATE_BASELINE) {
  const baseline = {
    _note: 'BENCH-01 real-path regression baseline. Deterministic fields only. Regenerate with `npm run bench:permit -- --update-baseline`.',
    primitive: report.meta.suite, // gate keys on this; PS-5 permit suite
    workload: report.meta.workload,
    sizes: report.sizes,
    correctness: report.correctness,
  }
  writeFileSync(join(REPO, 'bench', 'baseline-permit.json'), JSON.stringify(baseline, null, 2) + '\n')
}

console.log(`BENCH-01-permit  target=real planes/permit.ts  suite=${SUITE}  node=${process.version}`)
console.log(`  workload       : ${PERMITS} permits, ${AUDIENCES} audiences, ${Math.round(REVOKED_FRACTION * 100)}% revoked`)
console.log(`  valid ok       : ${validOk}/${validIssued}    revoked rejected: ${revokedRejected}`)
console.log(
  `  adversarial    : ` +
    Object.entries(adv)
      .map(([k, v]) => `${k} ${v.rejected}/${v.n}`)
      .join('  '),
)
console.log(`  sizes (bytes)  : body=${sizes.permitBodyBytes} mac=${sizes.permitMacBytes} token=${sizes.permitTokenCanonicalBytes}`)
console.log(`  issue p95/avg  : ${report.timings_ms.issue.p95}/${report.timings_ms.issue.avg} ms    verify p95/avg: ${report.timings_ms.verify.p95}/${report.timings_ms.verify.avg} ms`)
console.log(`  throughput     : issue=${report.throughput.permitsIssuedPerSec}/s verify=${report.throughput.verificationsPerSec}/s`)
console.log(`  report         : bench/report-permit.json${UPDATE_BASELINE ? '  (baseline updated)' : ''}`)

if (!allValidOk || !allAdversarialRejected) {
  console.error('BENCH-01-permit SECURITY INVARIANT VIOLATED — a valid permit was rejected or an attack permit was accepted.')
  process.exit(1)
}
console.log('BENCH-01-permit OK — all valid permits accepted, all adversarial permits rejected (real verifier).')
