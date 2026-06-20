// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { TransparencyLog, checkInclusion, checkConsistency } from '../src/index.js'

const data = (s: string): Uint8Array => new TextEncoder().encode(s)

describe('TransparencyLog', () => {
  it('appends, grows, and proves inclusion against the gossiped root', () => {
    const log = new TransparencyLog()
    const roots: Uint8Array[] = []
    for (let i = 0; i < 6; i++) roots.push(log.append(data(`receipt-${i}`)).root)
    expect(log.size()).toBe(6)

    const w = log.proveInclusion(2)
    expect(checkInclusion(w, log.root())).toBe(true)
    // Wrong root must fail.
    expect(checkInclusion(w, roots[0]!)).toBe(false)
  })

  it('detects a tampered inclusion witness', () => {
    const log = new TransparencyLog()
    for (let i = 0; i < 5; i++) log.append(data(`r${i}`))
    const w = log.proveInclusion(1)
    const bad = { ...w, leaf: data('forged') }
    expect(checkInclusion(bad, log.root())).toBe(false)
  })

  it('proves append-only consistency between two sizes', () => {
    const log = new TransparencyLog()
    for (let i = 0; i < 3; i++) log.append(data(`r${i}`))
    const fromSize = log.size()
    for (let i = 3; i < 9; i++) log.append(data(`r${i}`))
    expect(checkConsistency(log.proveConsistency(fromSize))).toBe(true)
  })
})
