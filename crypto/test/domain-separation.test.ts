// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * DS-REGISTRY-001 (AAC cycle-8 domain-separation audit): the message-space registry
 * (crypto/src/domains.ts) is the single source of truth for every signed / MAC'd / sealed / committed
 * message space's domain tag. This gate makes global disjointness MACHINE-CHECKED rather than verified
 * by structural coincidence: a new signed message can not silently collide with an existing space.
 */

import { describe, it, expect } from 'vitest'
import {
  allDomainTags,
  DOMAIN_TAGS,
  DOMAIN_TAGS_V2,
  DOMAIN_TAGS_V3,
  PROTOCOL_TAG_GENERATION,
} from '../src/index.js'

describe('DS-REGISTRY-001 — message-space domain-tag registry', () => {
  it('every registered domain tag is UNIQUE within each generation (no two message spaces collide)', () => {
    for (const gen of [DOMAIN_TAGS_V2, DOMAIN_TAGS_V3]) {
      const tags = Object.values(gen)
      expect(new Set(tags).size).toBe(tags.length)
    }
  })

  it('every registered tag is a non-empty string (both generations)', () => {
    for (const t of [...Object.values(DOMAIN_TAGS_V2), ...Object.values(DOMAIN_TAGS_V3)]) {
      expect(typeof t).toBe('string')
      expect(t.length).toBeGreaterThan(0)
    }
  })

  it('the receipt space is registered (RCPT-DS-002 — the previously-untagged signed message)', () => {
    expect(DOMAIN_TAGS.RECEIPT).toBe('nerion-receipt-v1')
    expect(allDomainTags()).toContain(DOMAIN_TAGS.RECEIPT)
  })
})

describe('ADR-0042 — v2/v3 tag generations', () => {
  it('the active generation is v2 and DOMAIN_TAGS resolves to the FROZEN v2 set (byte-identity pin)', () => {
    // Flipping this is a PROTOCOL BREAK gated by ADR-0042 (v3 KATs + negotiation). If this test
    // fails, someone flipped PROTOCOL_TAG_GENERATION outside that gated migration — do not re-pin
    // without the full ADR-0042 §c vector/conformance work landing in the SAME reviewed commit.
    expect(PROTOCOL_TAG_GENERATION).toBe('v2')
    expect(DOMAIN_TAGS).toBe(DOMAIN_TAGS_V2)
  })

  it('both generations register exactly the same message spaces (same keys)', () => {
    expect(Object.keys(DOMAIN_TAGS_V3).sort()).toEqual(Object.keys(DOMAIN_TAGS_V2).sort())
  })

  it('no v3 value collides with the v2 value of a DIFFERENT space (cross-generation ambiguity)', () => {
    // Same-key equality is ALLOWED (already-Nerion tags + the two PINNED exceptions keep their v2
    // value — same message space, same bytes). What must never happen is a v3 tag equalling the v2
    // tag of ANOTHER space: that would let a v3 message verify inside a different v2 message space.
    const v2ByValue = new Map(Object.entries(DOMAIN_TAGS_V2).map(([k, v]) => [v as string, k]))
    for (const [key, value] of Object.entries(DOMAIN_TAGS_V3)) {
      const v2Owner = v2ByValue.get(value as string)
      if (v2Owner !== undefined) expect(v2Owner).toBe(key)
    }
  })

  it('every MIGRATED v3 tag is Nerion-branded and DIFFERS from its v2 predecessor', () => {
    // The two pinned exceptions (frozen suites.ts literal; ADR-0016 generator-H provenance) are the
    // only spaces allowed to stay polarseek/PolarSeek-branded in v3.
    const PINNED = new Set([
      'SUITE_NEGOTIATION',
      'ZK_GENERATOR_H',
      'ZK_STMT_PREFIX',
      'ZK_BIT_PREFIX',
    ])
    for (const [key, v3] of Object.entries(DOMAIN_TAGS_V3)) {
      const v2 = (DOMAIN_TAGS_V2 as Record<string, string>)[key]!
      if (PINNED.has(key)) {
        expect(v3).toBe(v2) // pinned: identical by design
      } else if (v3 !== v2) {
        // migrated: must be Nerion-branded and mutually unverifiable with its v2 predecessor
        expect((v3 as string).startsWith('Nerion/')).toBe(true)
      } else {
        // unchanged: was already Nerion-branded before the generations split
        expect(/^(Nerion\/|nerion-)/.test(v3 as string)).toBe(true)
      }
    }
  })
})
