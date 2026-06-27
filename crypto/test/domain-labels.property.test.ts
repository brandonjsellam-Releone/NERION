// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PQC-1 — conformance gate for the domain-separation label registry. Proves the namespace is:
 *  - UNIQUE        (no label string reused for two purposes — would merge trust domains)
 *  - PREFIX-FREE   (no label is a string-prefix of another — no cross-context confusion under
 *                   raw-string / HKDF-info concatenation)
 *  - COVERED       (every registered label actually appears in its claimed source module)
 *  - ESCAPE-FREE   (every domain-separation literal in the source tree is registered or explicitly
 *                   excluded — a NEW unregistered label fails this test)
 *  - INJECTIVE     (distinct labels ⇒ distinct canonical encodings under encodeCanonical)
 */

import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToHex } from '@noble/hashes/utils.js'
import { encodeCanonical } from '../src/index.js'
import {
  DOMAIN_LABELS,
  DOMAIN_LABEL_SET,
  NON_LABEL_LITERALS,
  isRegisteredLabel,
  isExcludedLiteral,
} from '../src/domain-labels.js'

// Module directories whose src/ trees carry protocol domain-separation labels.
const SRC_ROOTS = [
  'crypto',
  'capabilities',
  'kernel',
  'receipts',
  'translog',
  'attest',
  'planes',
  'governance',
  'conformance',
  'disclosure',
  'ledger',
  'settlement',
  'keystore',
  'ops',
]

// The registry file itself (its prose examples are not real labels) and test files are not scanned.
const SCAN_SKIP = (path: string): boolean =>
  path.replace(/\\/g, '/').endsWith('crypto/src/domain-labels.ts') || path.endsWith('.test.ts')

function tsFilesUnder(dir: string): string[] {
  const out: string[] = []
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return out
  }
  for (const e of entries) {
    const p = join(dir, e)
    if (statSync(p).isDirectory()) {
      if (e !== 'node_modules') out.push(...tsFilesUnder(p))
    } else if (e.endsWith('.ts') && !SCAN_SKIP(p)) {
      out.push(p)
    }
  }
  return out
}

const SOURCE_FILES = SRC_ROOTS.flatMap((r) => tsFilesUnder(join(r, 'src')))

// Extract every single/double/backtick string literal; the drift check then flags any whose CONTENT
// carries a domain-separation prefix family anywhere but is not registered/excluded. Catches
// mid-string embeddings and concatenation fragments (e.g. 'polarseek-' + x), and parameterized
// templates (their static stem is matched via isRegisteredLabel). NOT sound against a label assembled
// entirely from non-matching fragments — see the honesty note below.
const STRING_LITERAL = /'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`/g
const CARRIES_LABEL = /(?:polarseek|PolarSeek)[/-]/

describe('PQC-1 — domain-separation registry: uniqueness & prefix-freeness', () => {
  it('all labels are unique', () => {
    expect(DOMAIN_LABEL_SET.size).toBe(DOMAIN_LABELS.length)
  })

  it('no label is a string-prefix of another (prefix-free)', () => {
    const labels = DOMAIN_LABELS.map((d) => d.label)
    const offenders: string[] = []
    for (const a of labels) {
      for (const b of labels) {
        if (a !== b && b.startsWith(a)) offenders.push(`"${a}" is a prefix of "${b}"`)
      }
    }
    expect(offenders, offenders.join('; ')).toEqual([])
  })

  it('registry and exclusion sets are disjoint', () => {
    for (const x of NON_LABEL_LITERALS) {
      expect(DOMAIN_LABEL_SET.has(x.literal), `${x.literal} is both registered and excluded`).toBe(
        false,
      )
    }
  })
})

describe('PQC-1 — coverage: every registered label exists in its claimed source module', () => {
  it.each(DOMAIN_LABELS.map((d) => [d.label, d.module] as const))(
    '%s is present in %s',
    (label, module) => {
      const content = readFileSync(module, 'utf8')
      expect(content.includes(label)).toBe(true)
    },
  )
})

describe('PQC-1 — drift detector (best-effort static scan; NOT sound enforcement — see note)', () => {
  // HONESTY: this scan reduces, but does not eliminate, the chance of an unregistered label. It
  // catches inline literals (including mid-string and the 'polarseek-' + x concatenation fragment)
  // and parameterized templates, but CANNOT catch a label assembled entirely from non-matching
  // fragments or built at runtime from variables. The only SOUND enforcement is import-only labels
  // (every module imports its label from domain-labels.ts; the gate then forbids ANY domain-sep
  // literal outside the registry) — a byte-identical, conformance-gated follow-up, deferred here to
  // avoid a 15-module refactor while concurrent sessions edit those files. Treat 0 violations as
  // "no drift detected", NOT proof of coverage.
  it('every source string literal carrying a domain-sep prefix is registered or explicitly excluded', () => {
    expect(SOURCE_FILES.length).toBeGreaterThan(20) // sanity: the walk actually found the tree
    const violations: Array<{ literal: string; file: string }> = []
    for (const file of SOURCE_FILES) {
      const content = readFileSync(file, 'utf8')
      for (const m of content.matchAll(STRING_LITERAL)) {
        const inner = m[0]!.slice(1, -1) // strip the surrounding quotes/backticks
        if (!CARRIES_LABEL.test(inner)) continue
        if (!isRegisteredLabel(inner) && !isExcludedLiteral(inner)) {
          violations.push({ literal: inner, file: file.replace(/\\/g, '/') })
        }
      }
    }
    expect(
      violations,
      `unregistered domain-separation literals:\n${JSON.stringify(violations, null, 2)}`,
    ).toEqual([])
  })
})

describe('PQC-1 — injectivity: distinct labels give distinct canonical encodings', () => {
  it('encodeCanonical([label, ...]) never collides across labels', () => {
    const labels = DOMAIN_LABELS.map((d) => d.label)
    const encoded = labels.map((l) => bytesToHex(encodeCanonical([l, 'fixed-field', 1])))
    expect(new Set(encoded).size).toBe(labels.length)
  })
})
