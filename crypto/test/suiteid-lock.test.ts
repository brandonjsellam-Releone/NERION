// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * SUITEID-LOCK (AAC cycle-7, completeness-critic ADV-005): a MECHANICAL freeze gate on the SuiteID
 * registry (crypto/src/suites.ts). The KAT diff gate only catches registry edits that PERTURB a
 * committed vector; an OUTPUT-NEUTRAL edit — adding a SuiteID, renaming a label, or changing a suite's
 * category / kem / sig / aead / mac / hash id in a way that doesn't move a KAT — was previously caught
 * only by CODEOWNERS convention. This test hashes the load-bearing registry fields and pins the digest,
 * so ANY registry change turns the gate red and forces an EXPLICIT, reviewed lock bump. It does NOT
 * read/modify suites.ts source — it reads the exported registry, so the frozen file is untouched.
 */

import { describe, it, expect } from 'vitest'
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils.js'
import { SUITE_IDS, allSuites, SHA3_SHAKE256 } from '../src/index.js'

/**
 * Canonical projection of the registry's LOAD-BEARING fields only (prose `description` / `standards`
 * are intentionally excluded — editing them must NOT trip the gate). Deterministic + sorted.
 */
function suiteIdLockDigest(): string {
  const ids = Object.entries(SUITE_IDS)
    .map(([k, v]) => `${k}=${v}`)
    .sort()
    .join('\n')
  const suites = allSuites()
    .map((s) =>
      [
        s.id,
        s.status,
        s.category,
        s.preference,
        s.kemId,
        s.sigId,
        s.aeadId,
        s.macId,
        s.hashId,
      ].join('|'),
    )
    .sort()
    .join('\n')
  return bytesToHex(SHA3_SHAKE256.digest(utf8ToBytes(`${ids}\n---\n${suites}`)))
}

// The pinned lock. Bumping this is a DELIBERATE act: it means the SuiteID registry changed, and the
// change must be reviewed (CODEOWNERS owns /crypto/). If this test fails, do NOT blindly re-pin —
// confirm the registry change is intended, then update the digest in the SAME reviewed commit.
const SUITEID_LOCK = '4eca753f0723ca47b3124cbd0f1ffa482f08517c16a9d309d99a3638f00e6b1a'

describe('SUITEID-LOCK — mechanical freeze of the SuiteID registry', () => {
  it('the load-bearing SuiteID registry matches the pinned lock digest', () => {
    // Digest over {SUITE_IDS entries} + {each active/registered suite's id|status|category|preference|
    // kemId|sigId|aeadId|macId|hashId}. Prose fields are excluded. A mismatch means the registry
    // changed — confirm it is intended, then re-pin SUITEID_LOCK in the SAME reviewed (CODEOWNERS) commit.
    expect(suiteIdLockDigest()).toBe(SUITEID_LOCK)
  })
})
