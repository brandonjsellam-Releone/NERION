// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, afterEach } from 'vitest'
import { getEnv, requireEnv, hasEnv, loadEnv, MissingEnvError } from '../src/index.js'

const KEY = 'POLARSEEK_TEST_VAR_XYZ'
afterEach(() => {
  delete process.env[KEY]
})

describe('ops env accessors', () => {
  it('getEnv returns the value when set, fallback otherwise', () => {
    expect(getEnv(KEY, 'fb')).toBe('fb')
    process.env[KEY] = 'v'
    expect(getEnv(KEY)).toBe('v')
  })

  it('treats empty string as unset', () => {
    process.env[KEY] = ''
    expect(getEnv(KEY, 'fb')).toBe('fb')
    expect(hasEnv(KEY)).toBe(false)
  })

  it('requireEnv throws MissingEnvError when unset', () => {
    expect(() => requireEnv(KEY)).toThrow(MissingEnvError)
    process.env[KEY] = 'present'
    expect(requireEnv(KEY)).toBe('present')
    expect(hasEnv(KEY)).toBe(true)
  })

  it('loadEnv returns false for a missing file', () => {
    expect(loadEnv('definitely-not-a-real-file.env')).toBe(false)
  })
})
