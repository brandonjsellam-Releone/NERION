#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * BENCH-01 regression gate.
 *
 * Compares the latest `bench/report.json` (produced by `npm run bench`) against
 * the committed `bench/baseline.json`. HARD-fails (exit 1) on any regression in
 * the DETERMINISTIC, security-meaningful invariants:
 *   - signature scheme / primitive changed
 *   - workload shape changed
 *   - any cryptographic artifact size changed
 *   - a valid trace stopped being accepted
 *   - an adversarial trace started being accepted  (security regression)
 *   - the Merkle inclusion proof stopped verifying
 *
 * Timings are machine-dependent and are NOT gated here by default (a same-runner
 * timing budget can be layered on in CI; see bench/README.md). This keeps the
 * gate strict where it matters and non-flaky where it doesn't.
 *
 * Usage:  npm run bench && npm run bench:gate
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..')
const reportPath = join(REPO, 'bench', 'report.json')
const baselinePath = join(REPO, 'bench', 'baseline.json')

function load(path, what) {
  if (!existsSync(path)) {
    console.error(`BENCH-GATE: missing ${what} (${path}). Run \`npm run bench\` first.`)
    process.exit(1)
  }
  return JSON.parse(readFileSync(path, 'utf8'))
}

const report = load(reportPath, 'report')
const baseline = load(baselinePath, 'baseline')
const fail = []

// primitive + workload
if (report.meta.primitive !== baseline.primitive)
  fail.push(`primitive changed: ${baseline.primitive} -> ${report.meta.primitive}`)
for (const k of Object.keys(baseline.workload)) {
  if (report.meta.workload[k] !== baseline.workload[k])
    fail.push(`workload.${k} changed: ${baseline.workload[k]} -> ${report.meta.workload[k]}`)
}

// sizes (deterministic)
for (const k of Object.keys(baseline.sizes)) {
  if (report.sizes[k] !== baseline.sizes[k])
    fail.push(`sizes.${k} changed: ${baseline.sizes[k]} -> ${report.sizes[k]}`)
}

// correctness — valid acceptance must not regress
const rc = report.correctness
const bc = baseline.correctness
if (!rc.allValidAccepted) fail.push('a valid trace was REJECTED (allValidAccepted=false)')
if (rc.validAccepted < bc.validAccepted)
  fail.push(`validAccepted regressed: ${bc.validAccepted} -> ${rc.validAccepted}`)
if (rc.revokedRejected !== bc.revokedRejected)
  fail.push(`revokedRejected changed: ${bc.revokedRejected} -> ${rc.revokedRejected}`)
if (!rc.inclusionProofOk) fail.push('Merkle inclusion proof FAILED to verify')

// correctness — every adversarial class must still reject 100%
if (!rc.allAdversarialRejected) fail.push('an adversarial trace was ACCEPTED (allAdversarialRejected=false)')
for (const cls of Object.keys(bc.adversarial)) {
  const r = rc.adversarial[cls]
  if (!r) {
    fail.push(`adversarial class "${cls}" missing from report`)
    continue
  }
  if (r.n === 0) fail.push(`adversarial class "${cls}" ran 0 cases`)
  if (r.rejected < r.n) fail.push(`adversarial class "${cls}" ACCEPTED an attack: rejected ${r.rejected}/${r.n}`)
}

if (fail.length) {
  console.error('BENCH-GATE: FAIL')
  for (const f of fail) console.error(`  - ${f}`)
  process.exit(1)
}
console.log(`BENCH-GATE: PASS  (${report.meta.primitive}; ${rc.validAccepted} valid accepted, all adversarial classes rejected, sizes stable)`)
