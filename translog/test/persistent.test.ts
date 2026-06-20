// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, afterEach } from 'vitest'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { rmSync, existsSync } from 'node:fs'
import { PersistentTransparencyLog, TransparencyLog, checkInclusion } from '../src/index.js'

const data = (s: string): Uint8Array => new TextEncoder().encode(s)
let path = ''
afterEach(() => {
  if (path && existsSync(path)) rmSync(path)
})

describe('PersistentTransparencyLog', () => {
  it('persists leaves and reloads to the same root + verifiable inclusion', () => {
    path = join(tmpdir(), `polarseek-ptl-${Date.now()}-${process.pid}.log`)
    const a = new PersistentTransparencyLog(path)
    for (let i = 0; i < 5; i++) a.append(data(`r${i}`))
    const rootBefore = Buffer.from(a.root()).toString('hex')

    // Reload from disk in a fresh instance.
    const b = new PersistentTransparencyLog(path)
    expect(b.size()).toBe(5)
    expect(Buffer.from(b.root()).toString('hex')).toBe(rootBefore)

    const w = b.proveInclusion(2)
    expect(checkInclusion(w, b.root())).toBe(true)
  })

  it('agrees with the in-memory log for the same entries', () => {
    path = join(tmpdir(), `polarseek-ptl2-${Date.now()}-${process.pid}.log`)
    const p = new PersistentTransparencyLog(path)
    const mem = new TransparencyLog()
    for (let i = 0; i < 6; i++) {
      p.append(data(`x${i}`))
      mem.append(data(`x${i}`))
    }
    expect(Buffer.from(p.root())).toEqual(Buffer.from(mem.root()))
  })
})
