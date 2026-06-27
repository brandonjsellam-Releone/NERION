#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * BENCH-01 regression gate.
 *
 * Compares a bench report against its committed baseline and HARD-fails (exit 1)
 * on any regression in the DETERMINISTIC, security-meaningful invariants:
 *   - signature scheme / suite changed
 *   - workload shape changed
 *   - any cryptographic artifact size changed
 *   - a valid trace stopped being accepted
 *   - an adversarial trace started being accepted  (security regression)
 *   - the Merkle inclusion proof stopped verifying (primitive harness only)
 *
 * Works for both harnesses (shape-tolerant):
 *   primitive : bench/report.json        vs bench/baseline.json        (default)
 *   real-path : bench/report-permit.json vs bench/baseline-permit.json
 * Override via env BENCH_REPORT / BENCH_BASELINE.
 *
 * Timings are machine-dependent and are NOT gated here by default.
 */
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..')
const reportPath = join(REPO, process.argv[2] || process.env.BENCH_REPORT || 'bench/report.json')
const baselinePath = join(REPO, process.argv[3] || process.env.BENCH_BASELINE || 'bench/baseline.json')

function load(path, what) {
  if (!existsSync(path)) {
    console.error(`BENCH-GATE: missing ${what} (${path}). Run the matching \`npm run bench*\` first.`)
    process.exit(1)
  }
  return JSON.parse(readFileSync(path, 'utf8'))
}

const report = load(reportPath, 'report')
const baseline = load(baselinePath, 'baseline')
const fail = []

// Shape-tolerant accessors (primitive vs real-path reports differ slightly).
const reportPrimitive = report.meta.primitive ?? report.meta.suite
const rc = report.correctness
const bc = baseline.correctness
const validAccepted = rc.validAccepted ?? rc.validOk
const baseValidAccepted = bc.validAccepted ?? bc.validOk
const allValid = rc.allValidAccepted ?? rc.allValidOk
const hasInclusion = rc.inclusionProofOk !== undefined

// primitive/suite + workload
if (reportPrimitive !== baseline.primitive)
  fail.push(`primitive/suite changed: ${baseline.primitive} -> ${reportPrimitive}`)
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
if (!allValid) fail.push('a valid trace was REJECTED (allValid=false)')
if (validAccepted < baseValidAccepted)
  fail.push(`valid accepted regressed: ${baseValidAccepted} -> ${validAccepted}`)
if (rc.revokedRejected !== bc.revokedRejected)
  fail.push(`revokedRejected changed: ${bc.revokedRejected} -> ${rc.revokedRejected}`)
if (hasInclusion && !rc.inclusionProofOk) fail.push('Merkle inclusion proof FAILED to verify')

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
  console.error(`BENCH-GATE: FAIL  (${report.meta.harness})`)
  for (const f of fail) console.error(`  - ${f}`)
  process.exit(1)
}
console.log(`BENCH-GATE: PASS  (${report.meta.harness}; ${reportPrimitive}; ${validAccepted} valid accepted, all adversarial classes rejected, sizes stable)`)
