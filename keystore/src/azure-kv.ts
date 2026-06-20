// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Minimal Azure Key Vault data-plane client for SEALING secret seeds at rest.
 *
 * PolarSeek is post-quantum-native, but no mainstream cloud KMS — Azure Key
 * Vault included — can hold or operate ML-DSA / ML-KEM keys yet; they do RSA/EC
 * only. So Key Vault is used here purely as a *wrapping KEK*: a classical RSA
 * key in the vault wraps (RSA-OAEP-256) PolarSeek's small PQC keygen *seed*, and
 * the resulting blob is the only at-rest representation of the secret. The PQC
 * keypair is re-derived from the unwrapped seed and all PQC signing happens in
 * PolarSeek's own code — the vault never sees a post-quantum private key.
 *
 * Transport is plain REST over Node's built-in `fetch` (no `@azure/*` SDK tree)
 * so the whole custody path stays small and auditable. Real wrap/unwrap require
 * outbound network to Azure; the {@link SeedSealer} seam is injectable so the
 * provider can be exercised offline with a fake sealer.
 */

import { NotImplementedError } from '../../crypto/src/index.js'
import type { Bytes } from '../../crypto/src/index.js'
import type { SeedSealer } from './sealing-provider.js'

export interface AzureKeyVaultConfig {
  readonly tenantId: string
  readonly clientId: string
  readonly clientSecret: string
  /** e.g. https://<your-vault>.vault.azure.net/ */
  readonly vaultUrl: string
  /** Name of the RSA wrapping key inside the vault. */
  readonly keyName: string
  /** Data-plane API version. Default '7.4'. */
  readonly apiVersion?: string
  /** AAD login host. Default 'https://login.microsoftonline.com'. */
  readonly authHost?: string
  /** Injectable fetch (defaults to global fetch) — for tests / custom agents. */
  readonly fetchImpl?: typeof fetch
}

interface ResolvedConfig {
  tenantId: string
  clientId: string
  clientSecret: string
  vaultUrl: string
  keyName: string
  apiVersion: string
  authHost: string
  fetchImpl: typeof fetch
}

type Json = Record<string, unknown>

const b64uEncode = (b: Bytes): string => Buffer.from(b).toString('base64url')
const b64uDecode = (s: string): Bytes => new Uint8Array(Buffer.from(s, 'base64url'))

/**
 * Extract only non-sensitive identifiers from a backend error body. Never
 * serialize the whole response: a non-2xx (or a misbehaving / compromised
 * endpoint) could echo the wrapped/unwrapped `value` — i.e. the seed — which
 * must never reach logs.
 */
function safeError(json: Json): string {
  const parts: string[] = []
  const err = json['error']
  if (typeof err === 'string')
    parts.push(err) // AAD: error code (e.g. invalid_client)
  else if (err && typeof err === 'object') {
    const code = (err as Json)['code']
    if (typeof code === 'string') parts.push(code) // Key Vault: error.code
  }
  const corr = json['correlation_id'] ?? json['x-ms-request-id']
  if (typeof corr === 'string') parts.push(`req=${corr}`)
  return parts.length > 0 ? parts.join(' ') : '(no error code in response)'
}

/**
 * Azure Key Vault RSA-OAEP-256 wrap/unwrap over REST (client-credentials auth).
 * Tokens and the resolved key version (kid) are cached for the client's life.
 */
export class AzureKeyVaultSealer implements SeedSealer {
  private readonly cfg: ResolvedConfig
  private token: { value: string; expiresAt: number } | undefined
  private kid: string | undefined

  constructor(config: AzureKeyVaultConfig) {
    const fetchImpl = config.fetchImpl ?? globalThis.fetch
    if (typeof fetchImpl !== 'function') {
      throw new NotImplementedError(
        'Azure Key Vault sealer',
        'a global fetch (Node >= 20) or an injected fetchImpl',
      )
    }
    for (const k of ['tenantId', 'clientId', 'clientSecret', 'vaultUrl', 'keyName'] as const) {
      if (!config[k]) throw new Error(`AzureKeyVaultSealer: missing config "${k}"`)
    }
    this.cfg = {
      tenantId: config.tenantId,
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      vaultUrl: config.vaultUrl.replace(/\/+$/, ''),
      keyName: config.keyName,
      apiVersion: config.apiVersion ?? '7.4',
      authHost: (config.authHost ?? 'https://login.microsoftonline.com').replace(/\/+$/, ''),
      fetchImpl,
    }
  }

  async wrap(seed: Bytes): Promise<Bytes> {
    return (await this.op('wrapkey', seed)).value
  }

  async unwrap(sealed: Bytes): Promise<Bytes> {
    return (await this.op('unwrapkey', sealed)).value
  }

  // ── internals ──────────────────────────────────────────────────────────────

  private async accessToken(nowMs: number): Promise<string> {
    if (this.token && this.token.expiresAt > nowMs + 60_000) return this.token.value
    const url = `${this.cfg.authHost}/${this.cfg.tenantId}/oauth2/v2.0/token`
    const body = new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: this.cfg.clientId,
      client_secret: this.cfg.clientSecret,
      scope: 'https://vault.azure.net/.default',
    })
    const res = await this.cfg.fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    const json = (await res.json()) as Json
    if (!res.ok) throw new Error(`Azure AAD token failed (${res.status}): ${safeError(json)}`)
    const access = json['access_token']
    if (typeof access !== 'string') throw new Error('Azure AAD token: no access_token in response')
    const expiresIn = Number(json['expires_in'] ?? 3000)
    this.token = { value: access, expiresAt: nowMs + expiresIn * 1000 }
    return access
  }

  /**
   * Resolve the full key identifier (kid; includes the key VERSION) once, cached.
   * NOTE (KEK rotation): the kid pins the current version, and op() targets it for
   * BOTH wrap and unwrap. RSA-OAEP ciphertext cannot cross versions, so if the
   * vault's wrapping key is rotated, seeds sealed under the prior version must be
   * re-sealed (unwrap with a sealer constructed before rotation, then re-provision).
   * AWS KMS, by contrast, resolves the backing version internally and survives
   * rotation; a future Azure upgrade can embed the wrapping kid in the blob.
   */
  private async keyId(): Promise<string> {
    if (this.kid) return this.kid
    const url = `${this.cfg.vaultUrl}/keys/${this.cfg.keyName}?api-version=${this.cfg.apiVersion}`
    const json = await this.send(url, undefined, 'GET')
    const key = json['key'] as Json | undefined
    const kid = key?.['kid']
    if (typeof kid !== 'string') {
      throw new Error(`Azure Key Vault: key "${this.cfg.keyName}" has no kid (does it exist?)`)
    }
    this.kid = kid
    return kid
  }

  private async op(kind: 'wrapkey' | 'unwrapkey', input: Bytes): Promise<{ value: Bytes }> {
    const kid = await this.keyId()
    const url = `${kid}/${kind}?api-version=${this.cfg.apiVersion}`
    const json = await this.send(url, { alg: 'RSA-OAEP-256', value: b64uEncode(input) }, 'POST')
    const value = json['value']
    if (typeof value !== 'string') throw new Error(`Azure Key Vault ${kind}: no value in response`)
    return { value: b64uDecode(value) }
  }

  private async send(url: string, body: Json | undefined, method: 'GET' | 'POST'): Promise<Json> {
    const token = await this.accessToken(Date.now())
    const res = await this.cfg.fetchImpl(url, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    })
    const json = (await res.json()) as Json
    if (!res.ok) {
      throw new Error(`Azure Key Vault ${method} ${url} failed (${res.status}): ${safeError(json)}`)
    }
    return json
  }
}

/** Build an {@link AzureKeyVaultSealer} from environment variables. */
export function azureSealerFromEnv(env: {
  AZURE_TENANT_ID?: string
  AZURE_CLIENT_ID?: string
  AZURE_CLIENT_SECRET?: string
  AZURE_KEY_VAULT_URL?: string
  AZURE_KEY_VAULT_KEK_NAME?: string
}): AzureKeyVaultSealer {
  return new AzureKeyVaultSealer({
    tenantId: env.AZURE_TENANT_ID ?? '',
    clientId: env.AZURE_CLIENT_ID ?? '',
    clientSecret: env.AZURE_CLIENT_SECRET ?? '',
    vaultUrl: env.AZURE_KEY_VAULT_URL ?? '',
    keyName: env.AZURE_KEY_VAULT_KEK_NAME ?? 'polarseek-seal-kek',
  })
}
