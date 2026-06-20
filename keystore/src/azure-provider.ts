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
import type { SeedSealer } from './sealing-provider.js'

export class AzureKeyVaultKeyProvider extends SealingKeyProvider {
  constructor(sealer: SeedSealer, name = 'azure-kv') {
    super(sealer, name)
  }
}
