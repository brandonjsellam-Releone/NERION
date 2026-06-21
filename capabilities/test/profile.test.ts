// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import {
  manifestDigest,
  isNamespacedVerb,
  ActionManifestError,
  base58btcEncode,
  base58btcDecode,
  didKeyFromPublicKey,
  toVerifiableCredential,
} from '../src/profile.js'
import type { ActionManifest } from '../src/profile.js'

const baseManifest: ActionManifest = {
  verbId: 'fin.payment.transfer',
  authorityScope: 'acct://treasury',
  riskClass: 'T2',
  policyHash: 'ab'.repeat(16),
  replayDomain: 'sess-1',
  expiry: 1_750_000_300,
}

describe('Action Manifest (ADR-0025 Phase A)', () => {
  it('digest is deterministic', () => {
    expect(bytesToHex(manifestDigest(baseManifest))).toBe(
      bytesToHex(manifestDigest({ ...baseManifest })),
    )
  })
  it('distinct verb => distinct digest (anti semantic-laundering)', () => {
    const a = bytesToHex(manifestDigest(baseManifest))
    const b = bytesToHex(manifestDigest({ ...baseManifest, verbId: 'msg.email.send' }))
    expect(a).not.toBe(b)
  })
  it('rejects a non-namespaced verb', () => {
    expect(isNamespacedVerb('transfer')).toBe(false)
    expect(isNamespacedVerb('fin.payment.transfer')).toBe(true)
    expect(() => manifestDigest({ ...baseManifest, verbId: 'transfer' })).toThrow(
      ActionManifestError,
    )
  })
})

describe('base58btc', () => {
  it('matches the canonical "Hello World!" vector and round-trips', () => {
    expect(base58btcEncode(utf8ToBytes('Hello World!'))).toBe('2NEpo7TZRRrLZSi2U')
    const rnd = Uint8Array.from({ length: 40 }, (_, i) => (i * 37 + 11) & 0xff)
    expect(bytesToHex(base58btcDecode(base58btcEncode(rnd)))).toBe(bytesToHex(rnd))
  })
  it('preserves leading zero bytes', () => {
    const z = Uint8Array.from([0, 0, 1, 2, 3])
    expect(base58btcEncode(z).startsWith('11')).toBe(true)
    expect(bytesToHex(base58btcDecode(base58btcEncode(z)))).toBe(bytesToHex(z))
  })
})

describe('did:key', () => {
  it('is did:key:z... and recovers the pubkey (caller supplies the multicodec)', () => {
    const pk = Uint8Array.from({ length: 32 }, (_, i) => (i + 1) & 0xff)
    const did = didKeyFromPublicKey(0x1234, pk)
    expect(did.startsWith('did:key:z')).toBe(true)
    const decoded = base58btcDecode(did.slice('did:key:z'.length))
    expect(bytesToHex(decoded.slice(decoded.length - 32))).toBe(bytesToHex(pk))
  })
})

describe('W3C VC projection', () => {
  it('renders a VC 2.0 object binding the manifest digest', () => {
    const vc = toVerifiableCredential({
      issuerDid: 'did:key:zIssuer',
      subjectDid: 'did:key:zAgent',
      manifest: baseManifest,
      validFrom: '2026-06-22T00:00:00Z',
    })
    expect((vc['@context'] as string[])[0]).toBe('https://www.w3.org/ns/credentials/v2')
    expect((vc['type'] as string[]).includes('VerifiableCredential')).toBe(true)
    expect(vc['issuer']).toBe('did:key:zIssuer')
    const cs = vc['credentialSubject'] as Record<string, unknown>
    expect(cs['id']).toBe('did:key:zAgent')
    expect(cs['manifestDigest']).toBe(bytesToHex(manifestDigest(baseManifest)))
  })
})
