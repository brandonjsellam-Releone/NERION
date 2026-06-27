// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * AWS KMS sealing — a symmetric KMS key as a wrapping KEK (model B):
 * wrap = kms:Encrypt(seed), unwrap = kms:Decrypt(blob). The KMS key never leaves
 * AWS and PolarSeek's PQC private key is never sent there.
 *
 * Self-contained: SigV4 request signing is implemented over `@noble/hashes`
 * (sha256 + hmac), so there is no `@aws-sdk` dependency tree — the custody path
 * stays small and auditable, like the Azure REST sealer. The error-prone core
 * (the SigV4 signing-key derivation) is pinned by a known-answer test against
 * AWS's own documented example (see keystore/test/aws-kms.test.ts). The live KMS
 * round-trip needs network and is the final check on a real deployment.
 */

import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import { NotImplementedError } from '../../crypto/src/index.js'
import type { Bytes } from '../../crypto/src/index.js'
import { SealingKeyProvider } from './sealing-provider.js'
import type { SeedSealer } from './sealing-provider.js'

type Json = Record<string, unknown>

const b64Encode = (b: Bytes): string => Buffer.from(b).toString('base64')
const b64Decode = (s: string): Bytes => new Uint8Array(Buffer.from(s, 'base64'))
const sha256hex = (data: Bytes): string => bytesToHex(sha256(data))
const hmacRaw = (key: Bytes, msg: string | Bytes): Bytes =>
  hmac(sha256, key, typeof msg === 'string' ? utf8ToBytes(msg) : msg)

/**
 * Derive the SigV4 signing key: HMAC chain over date → region → service →
 * 'aws4_request', starting from 'AWS4'+secret. Exported for the KAT.
 */
export function deriveSigningKey(
  secret: string,
  dateStamp: string,
  region: string,
  service: string,
): Bytes {
  const kDate = hmacRaw(utf8ToBytes('AWS4' + secret), dateStamp)
  const kRegion = hmacRaw(kDate, region)
  const kService = hmacRaw(kRegion, service)
  return hmacRaw(kService, 'aws4_request')
}

interface SigV4Input {
  host: string
  region: string
  service: string
  target: string
  body: string
  accessKeyId: string
  secretAccessKey: string
  sessionToken: string | undefined
  amzDate: string // e.g. 20150830T123600Z
}

/** Build SigV4-signed headers for a POST to an AWS JSON (x-amz-json-1.1) API. */
function signedHeadersFor(input: SigV4Input): Record<string, string> {
  const dateStamp = input.amzDate.slice(0, 8)
  const contentType = 'application/x-amz-json-1.1'
  const payloadHash = sha256hex(utf8ToBytes(input.body))

  const headerMap: Record<string, string> = {
    'content-type': contentType,
    host: input.host,
    'x-amz-date': input.amzDate,
    'x-amz-target': input.target,
  }
  if (input.sessionToken) headerMap['x-amz-security-token'] = input.sessionToken

  const names = Object.keys(headerMap).sort()
  const canonicalHeaders = names.map((n) => `${n}:${headerMap[n] ?? ''}\n`).join('')
  const signedHeaders = names.join(';')
  const canonicalRequest = ['POST', '/', '', canonicalHeaders, signedHeaders, payloadHash].join(
    '\n',
  )

  const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    input.amzDate,
    scope,
    sha256hex(utf8ToBytes(canonicalRequest)),
  ].join('\n')

  const signature = bytesToHex(
    hmacRaw(
      deriveSigningKey(input.secretAccessKey, dateStamp, input.region, input.service),
      stringToSign,
    ),
  )
  const authorization = `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`

  const headers: Record<string, string> = {
    'content-type': contentType,
    'x-amz-date': input.amzDate,
    'x-amz-target': input.target,
    authorization,
  }
  if (input.sessionToken) headers['x-amz-security-token'] = input.sessionToken
  return headers
}

function amzDate(d: Date): string {
  // 2015-08-30T12:36:00.000Z -> 20150830T123600Z
  return d.toISOString().replace(/[:-]|\.\d{3}/g, '')
}

/** Pull only the AWS error type for messages — never echo a response body that could carry the seed. */
function safeAwsError(json: Json): string {
  const t = json['__type']
  return typeof t === 'string' ? t : '(no __type in response)'
}

export interface AwsKmsConfig {
  readonly region: string
  readonly accessKeyId: string
  readonly secretAccessKey: string
  /** Key id, ARN, or alias of a SYMMETRIC (ENCRYPT_DECRYPT) KMS key. */
  readonly keyId: string
  readonly sessionToken?: string
  /** Override the endpoint (default https://kms.<region>.amazonaws.com). */
  readonly endpoint?: string
  /** Injectable fetch (defaults to global fetch) — for tests. */
  readonly fetchImpl?: typeof fetch
  /** Injectable clock (defaults to () => new Date()) — for deterministic tests. */
  readonly clock?: () => Date
}

/** A {@link SeedSealer} backed by AWS KMS Encrypt/Decrypt over signed REST. */
export class AwsKmsSealer implements SeedSealer {
  private readonly region: string
  private readonly accessKeyId: string
  private readonly secretAccessKey: string
  private readonly keyId: string
  private readonly sessionToken: string | undefined
  private readonly endpoint: string
  private readonly host: string
  private readonly fetchImpl: typeof fetch
  private readonly clock: () => Date

  constructor(config: AwsKmsConfig) {
    for (const k of ['region', 'accessKeyId', 'secretAccessKey', 'keyId'] as const) {
      if (!config[k]) throw new Error(`AwsKmsSealer: missing config "${k}"`)
    }
    const fetchImpl = config.fetchImpl ?? globalThis.fetch
    if (typeof fetchImpl !== 'function') {
      throw new NotImplementedError(
        'AWS KMS sealer',
        'a global fetch (Node >= 20) or an injected fetchImpl',
      )
    }
    this.region = config.region
    this.accessKeyId = config.accessKeyId
    this.secretAccessKey = config.secretAccessKey
    this.keyId = config.keyId
    this.sessionToken = config.sessionToken
    this.endpoint = (config.endpoint ?? `https://kms.${config.region}.amazonaws.com`).replace(
      /\/+$/,
      '',
    )
    this.host = new URL(this.endpoint).host
    this.fetchImpl = fetchImpl
    this.clock = config.clock ?? (() => new Date())
  }

  /**
   * AAD binding the wrapped seed to THIS KEK + a fixed purpose. KMS requires the
   * Decrypt EncryptionContext to match the Encrypt one byte-for-byte, so a valid
   * ciphertext cannot be swapped across keys / tenants / purposes — an online
   * cross-id swap the symmetric path was otherwise open to (CUSTODY-AWS-AAD-001,
   * Team Apex 2026-06-21; complements the offline-forgery defense in sealing-provider).
   *
   * When the caller supplies per-blob `aad` (the {@link SealingKeyProvider} passes
   * the canonical id/suite/sigId binding — CUSTODY-SEAL-AAD-001), it is added as an
   * extra context entry so the same ciphertext additionally cannot be relabeled or
   * swapped across keys sealed under THIS KEK. Omitting `aad` preserves the exact
   * legacy context (and therefore the pinned SigV4 request KAT) byte-for-byte.
   */
  private encryptionContext(aad?: Bytes): Record<string, string> {
    const ctx: Record<string, string> = { purpose: 'polarseek-seed-seal-v1', keyId: this.keyId }
    if (aad !== undefined) ctx['binding'] = b64Encode(aad)
    return ctx
  }

  async wrap(seed: Bytes, aad?: Bytes): Promise<Bytes> {
    const json = await this.call('TrentService.Encrypt', {
      KeyId: this.keyId,
      Plaintext: b64Encode(seed),
      EncryptionContext: this.encryptionContext(aad),
    })
    const ct = json['CiphertextBlob']
    if (typeof ct !== 'string') throw new Error('AWS KMS Encrypt: no CiphertextBlob in response')
    return b64Decode(ct)
  }

  async unwrap(blob: Bytes, aad?: Bytes): Promise<Bytes> {
    const json = await this.call('TrentService.Decrypt', {
      KeyId: this.keyId,
      CiphertextBlob: b64Encode(blob),
      EncryptionContext: this.encryptionContext(aad),
    })
    const pt = json['Plaintext']
    if (typeof pt !== 'string') throw new Error('AWS KMS Decrypt: no Plaintext in response')
    return b64Decode(pt)
  }

  private async call(target: string, payload: Json): Promise<Json> {
    const body = JSON.stringify(payload)
    const headers = signedHeadersFor({
      host: this.host,
      region: this.region,
      service: 'kms',
      target,
      body,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
      sessionToken: this.sessionToken,
      amzDate: amzDate(this.clock()),
    })
    const res = await this.fetchImpl(this.endpoint, { method: 'POST', headers, body })
    const json = (await res.json()) as Json
    if (!res.ok) {
      throw new Error(`AWS KMS ${target} failed (${res.status}): ${safeAwsError(json)}`)
    }
    return json
  }
}

/** AWS KMS key provider (model B; PQC seed sealed by a symmetric KMS key). */
export class AwsKmsKeyProvider extends SealingKeyProvider {
  constructor(sealer: SeedSealer, name = 'aws-kms') {
    super(sealer, name)
  }
}

/** Build an {@link AwsKmsSealer} from environment variables. */
export function awsKmsSealerFromEnv(env: {
  AWS_REGION?: string
  AWS_ACCESS_KEY_ID?: string
  AWS_SECRET_ACCESS_KEY?: string
  AWS_KMS_KEY_ID?: string
  AWS_SESSION_TOKEN?: string
}): AwsKmsSealer {
  const config: AwsKmsConfig = {
    region: env.AWS_REGION ?? '',
    accessKeyId: env.AWS_ACCESS_KEY_ID ?? '',
    secretAccessKey: env.AWS_SECRET_ACCESS_KEY ?? '',
    keyId: env.AWS_KMS_KEY_ID ?? '',
    ...(env.AWS_SESSION_TOKEN ? { sessionToken: env.AWS_SESSION_TOKEN } : {}),
  }
  return new AwsKmsSealer(config)
}
