// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Azure Key Vault key provider — a {@link SealingKeyProvider} whose backend is
 * Azure Key Vault (model B: the vault's RSA key wraps PolarSeek's PQC seed; the
 * vault never holds a post-quantum private key). The sealing mechanics live in
 * sealing-provider.ts; this just names the provider and binds the Azure sealer.
 */

import { SealingKeyProvider } from './sealing-provider.js'
import type { SeedSealer, SealedKey } from './sealing-provider.js'
import type { Bytes } from '../../crypto/src/index.js'
import type { KeyRef } from './types.js'

export class AzureKeyVaultKeyProvider extends SealingKeyProvider {
  constructor(sealer: SeedSealer, name = 'azure-kv') {
    super(sealer, name)
  }

  /**
   * CUSTODY-SEAL-002 (AAC council review, 2026-07-11): this provider names the ONE backend
   * (Azure Key Vault RSA-OAEP) the CUSTODY-SEAL-001 substitution attack targets, so it REQUIRES
   * `opts.trustedPublicKey` UNCONDITIONALLY — regardless of whether the constructor-supplied
   * sealer instance itself declares `isPublicKeyWrap` (the generic gate in
   * `SealingKeyProvider.load()` is defense-in-depth; this override closes the gap even for a
   * caller-supplied sealer/fake that omits the flag). Source `trustedPublicKey` from a channel
   * INDEPENDENT of the at-rest blob store — never by reading it back from the same store the
   * blob itself lives in, which would defeat the check.
   */
  override async load(sealed: SealedKey, opts: { trustedPublicKey?: Bytes } = {}): Promise<KeyRef> {
    if (opts.trustedPublicKey === undefined) {
      throw new Error(
        `sealed key "${sealed.id}" requires opts.trustedPublicKey: AzureKeyVaultKeyProvider ` +
          'wraps with a public-key (RSA-OAEP) backend and is offline-forgeable without it ' +
          '(CUSTODY-SEAL-002).',
      )
    }
    return super.load(sealed, opts)
  }
}
