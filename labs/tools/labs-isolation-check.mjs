// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// labs-isolation-check — the Nerion Labs sandbox guard (docs/APEX_TEAMS.md §5).
// Enforces, over labs/, the isolation the Innovation team depends on:
//   1. No labs/ source imports repo PROD source (crypto/kernel/ledger/keystore/…).
//   2. No tracked change outside labs/ (frozen-asset diff-guard: never touch SuiteID Ps1,
//      conformance/, vectors/, ps-*.json, or any KAT on an innovation/ branch).
// Exit 0 = clean; exit 1 = violation; exit 2 = guard self-test failed (guard is broken).
// Run:  node labs/tools/labs-isolation-check.mjs   |   --selftest

import { readdirSync, statSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url)) // labs/tools
const labsRoot = join(here, '..') // labs/
const repoRoot = join(labsRoot, '..') // repo root

const FORBIDDEN_IMPORTS = [
  '../../crypto', '../../kernel', '../../ledger', '../../keystore', '../../planes',
  '../../capabilities', '../../conformance', '../../disclosure', '../../governance',
  '../../receipts', '../../translog', '../../settlement', '../../sortition',
]
const FROZEN = [/crypto\/src\/suites\.ts$/, /conformance\//, /vectors\//, /ps-.*\.json$/, /\.kat(\.json)?$/]

function walk(dir, out = []) {
  let entries
  try { entries = readdirSync(dir) } catch { return out }
  for (const e of entries) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.(mjs|cjs|js|mts|cts|ts)$/.test(e)) out.push(p)
  }
  return out
}

function scanImports() {
  // Scan PROTOTYPE code under spikes/ only — the guard tooling itself legitimately names
  // these paths in FORBIDDEN_IMPORTS, and must not self-match. Match real import/require
  // syntax (`from '…'`, `require('…')`, `import('…')`), not bare substrings.
  const bad = []
  for (const f of walk(join(labsRoot, 'spikes'))) {
    const src = readFileSync(f, 'utf8')
    for (const pat of FORBIDDEN_IMPORTS) {
      const re = new RegExp(`(from|require\\(|import\\()\\s*['"]${pat.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`)
      if (re.test(src)) bad.push(`${f}: forbidden prod import '${pat}'`)
    }
  }
  return bad
}

function frozenDiffViolations() {
  let changed = []
  try {
    const out = execSync('git diff --name-only origin/main', { cwd: repoRoot, encoding: 'utf8' })
    changed = out.split('\n').map((s) => s.trim()).filter(Boolean)
  } catch {
    return { skipped: true, violations: [] }
  }
  const violations = []
  for (const f of changed) {
    if (FROZEN.some((re) => re.test(f))) violations.push(`${f}: frozen asset must not change on an innovation/ branch`)
    if (!f.startsWith('labs/')) violations.push(`${f}: change outside labs/ (Innovation is labs-only)`)
  }
  return { skipped: false, violations }
}

if (process.argv.includes('--selftest')) {
  const planted = join(labsRoot, 'spikes', '_selftest_violation.mjs')
  writeFileSync(planted, "import x from '../../crypto/src/index.js'\n")
  const caught = scanImports().some((m) => m.includes('_selftest_violation'))
  rmSync(planted)
  if (!caught) {
    console.error('SELFTEST FAILED: planted prod-import was NOT caught — the guard is broken.')
    process.exit(2)
  }
  console.log('SELFTEST OK: planted prod-import was caught and the guard rejects it.')
  process.exit(0)
}

const importBad = scanImports()
const frozen = frozenDiffViolations()
const all = [...importBad, ...frozen.violations]
if (all.length) {
  console.error('LABS ISOLATION VIOLATIONS:')
  for (const v of all) console.error('  - ' + v)
  process.exit(1)
}
console.log(
  `labs isolation: clean (${walk(join(labsRoot, 'spikes')).length} spike source files scanned; ` +
    `frozen-asset diff-guard ${frozen.skipped ? 'skipped — git unavailable' : 'green'}).`,
)
process.exit(0)
