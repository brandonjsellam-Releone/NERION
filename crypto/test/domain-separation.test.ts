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
import { allDomainTags, DOMAIN_TAGS } from '../src/index.js'

describe('DS-REGISTRY-001 — message-space domain-tag registry', () => {
  it('every registered domain tag is globally UNIQUE (no two message spaces collide)', () => {
    const tags = allDomainTags()
    expect(new Set(tags).size).toBe(tags.length)
  })

  it('every registered tag is a non-empty string', () => {
    for (const t of allDomainTags()) {
      expect(typeof t).toBe('string')
      expect(t.length).toBeGreaterThan(0)
    }
  })

  it('the receipt space is registered (RCPT-DS-002 — the previously-untagged signed message)', () => {
    expect(DOMAIN_TAGS.RECEIPT).toBe('nerion-receipt-v1')
    expect(allDomainTags()).toContain(DOMAIN_TAGS.RECEIPT)
  })
})
