import { describe, it, expect } from 'vitest'
import { commitField, verifyDisclosure } from '../src/index.js'

describe('selective disclosure', () => {
  it('verifies a revealed field against its commitment', () => {
    const intent = { type: 'payment.transfer', amount: 500, counterparty: 'vendor-acme' }
    const commitment = commitField(intent)
    expect(verifyDisclosure(commitment, intent)).toBe(true)
  })

  it('rejects a different value', () => {
    const intent = { type: 'payment.transfer', amount: 500 }
    const commitment = commitField(intent)
    expect(verifyDisclosure(commitment, { type: 'payment.transfer', amount: 501 })).toBe(false)
  })

  it('is key-order independent (canonical encoding)', () => {
    expect(commitField({ a: 1, b: 2 })).toBe(commitField({ b: 2, a: 1 }))
  })
})
