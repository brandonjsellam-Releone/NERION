#!/usr/bin/env node

// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Runs the PolarSeek conformance suite and prints a certification report.
 * Prereq: `npm run build`.  Usage: `npm run conformance`.
 */
import { runConformance } from '../dist/conformance/src/index.js'
import { loadEnv } from '../dist/ops/src/index.js'

loadEnv() // load .env if present (no-op otherwise)

const report = runConformance()
console.log('PolarSeek conformance report')
for (const r of report.results) {
  console.log(`  ${r.passed ? 'PASS' : 'FAIL'}  ${r.id}  ${r.name}${r.passed ? '' : '  -> ' + r.detail}`)
}
console.log(`\n  ${report.passed}/${report.total} checks passed`)
if (report.ok) {
  console.log('  RESULT: ✔ CONFORMANT')
  process.exit(0)
} else {
  console.log('  RESULT: x NON-CONFORMANT')
  process.exit(1)
}
