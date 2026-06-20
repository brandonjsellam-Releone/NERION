// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  AwsKmsSealer,
  AwsKmsKeyProvider,
  awsKmsSealerFromEnv,
  deriveSigningKey,
} from '../src/aws-kms.js'

const suite = SUITE_IDS.PS_5
const MSG = new TextEncoder().encode('seal the verb in KMS')

// AWS's own documented signing-key example (the canonical SigV4 test credential).
const AWS_DOC_SECRET = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'

/**
 * Mock KMS endpoint: identity Encrypt/Decrypt (CiphertextBlob == Plaintext, both
 * base64) so wrap→unwrap round-trips, while letting us assert the request was
 * SigV4-signed and correctly targeted. No network, no real key.
 */
function mockKms() {
  const calls: { target: string; authorization: string; signedHeaders: string }[] = []
  const impl = (async (_url: string | URL, init?: RequestInit) => {
    const headers = (init?.headers ?? {}) as Record<string, string>
    const target = headers['x-amz-target'] ?? ''
    const authorization = headers['authorization'] ?? ''
    calls.push({ target, authorization, signedHeaders: authorization })
    const body = JSON.parse(String(init?.body)) as Record<string, string>
    if (target === 'TrentService.Encrypt') {
      return new Response(
        JSON.stringify({ KeyId: body['KeyId'], CiphertextBlob: body['Plaintext'] }),
        {
          status: 200,
        },
      )
    }
    if (target === 'TrentService.Decrypt') {
      return new Response(
        JSON.stringify({ KeyId: body['KeyId'], Plaintext: body['CiphertextBlob'] }),
        {
          status: 200,
        },
      )
    }
    return new Response(JSON.stringify({ __type: 'UnknownOperationException' }), { status: 400 })
  }) as unknown as typeof fetch
  return { impl, calls }
}

function sealerWith(impl: typeof fetch): AwsKmsSealer {
  return new AwsKmsSealer({
    region: 'us-east-2',
    accessKeyId: 'AKIDEXAMPLE',
    secretAccessKey: AWS_DOC_SECRET,
    keyId: 'alias/polarseek-seal-kek',
    fetchImpl: impl,
    clock: () => new Date('2020-01-01T00:00:00Z'),
  })
}

describe('AWS SigV4 signing-key derivation (KAT vs AWS docs)', () => {
  it('reproduces AWS"s documented kSigning hex', () => {
    // From AWS "Examples of how to derive a signing key for SigV4".
    const kSigning = deriveSigningKey(AWS_DOC_SECRET, '20150830', 'us-east-1', 'iam')
    expect(bytesToHex(kSigning)).toBe(
      'c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9',
    )
  })
})

describe('AwsKmsSealer (KMS Encrypt/Decrypt as wrap/unwrap, SigV4 over REST)', () => {
  it('round-trips a seed and signs the request', async () => {
    const { impl, calls } = mockKms()
    const sealer = sealerWith(impl)
    const seed = new Uint8Array([0, 1, 2, 3, 250, 251, 252, 255])
    const back = await sealer.unwrap(await sealer.wrap(seed))
    expect(Array.from(back)).toEqual(Array.from(seed))

    const enc = calls.find((c) => c.target === 'TrentService.Encrypt')
    expect(enc).toBeDefined()
    expect(enc?.authorization.startsWith('AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/')).toBe(true)
    expect(enc?.authorization).toContain('SignedHeaders=content-type;host;x-amz-date;x-amz-target')
    expect(enc?.authorization).toContain('/us-east-2/kms/aws4_request')
  })

  it('throws on missing required config', () => {
    expect(
      () =>
        new AwsKmsSealer({
          region: 'us-east-2',
          accessKeyId: 'a',
          secretAccessKey: 's',
          keyId: '',
        }),
    ).toThrow(/missing config "keyId"/)
  })

  it('awsKmsSealerFromEnv requires the core vars', () => {
    expect(() => awsKmsSealerFromEnv({})).toThrow(/missing config "region"/)
    const s = awsKmsSealerFromEnv({
      AWS_REGION: 'us-east-2',
      AWS_ACCESS_KEY_ID: 'a',
      AWS_SECRET_ACCESS_KEY: 's',
      AWS_KMS_KEY_ID: 'k',
    })
    expect(s).toBeInstanceOf(AwsKmsSealer)
  })
})

describe('SigV4 full-request regression KAT', () => {
  it('pins the entire Authorization (canonical request + StringToSign), not just the signing key', async () => {
    const auths: string[] = []
    const impl = (async (_url: string | URL, init?: RequestInit) => {
      const headers = (init?.headers ?? {}) as Record<string, string>
      auths.push(headers['authorization'] ?? '')
      const body = JSON.parse(String(init?.body)) as Record<string, string>
      return new Response(
        JSON.stringify({ KeyId: body['KeyId'], CiphertextBlob: body['Plaintext'] }),
        {
          status: 200,
        },
      )
    }) as unknown as typeof fetch

    const sealer = new AwsKmsSealer({
      region: 'us-east-2',
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: AWS_DOC_SECRET,
      keyId: 'alias/polarseek-seal-kek',
      endpoint: 'https://kms.us-east-2.amazonaws.com',
      fetchImpl: impl,
      clock: () => new Date('2020-01-02T03:04:05Z'),
    })
    await sealer.wrap(new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7]))

    // Frozen full Authorization for this EXACT request — pins the whole canonical
    // request + StringToSign path. Regenerate ONLY on a deliberate SigV4 change.
    expect(auths[0]).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20200102/us-east-2/kms/aws4_request, ' +
        'SignedHeaders=content-type;host;x-amz-date;x-amz-target, ' +
        'Signature=9a381a33cd96558d9b6b9ec6aef974b73e1c34c9005919a6e132728858039390',
    )
  })
})

describe('AwsKmsKeyProvider (model B via KMS)', () => {
  it('provisions, seals via KMS, and a cold load reproduces the keypair', async () => {
    const { impl } = mockKms()
    const provider = new AwsKmsKeyProvider(sealerWith(impl))
    const { ref, publicKey, sealed } = await provider.provision(suite, 'issuer')
    expect(ref.provider).toBe('aws-kms')
    expect(signerFor(suite).verify(provider.sign(ref, suite, MSG), MSG, publicKey)).toBe(true)

    const cold = new AwsKmsKeyProvider(sealerWith(impl))
    const ref2 = await cold.load(sealed)
    expect(cold.getPublicKey(ref2)).toEqual(publicKey)
    expect(signerFor(suite).verify(cold.sign(ref2, suite, MSG), MSG, publicKey)).toBe(true)
  })
})
