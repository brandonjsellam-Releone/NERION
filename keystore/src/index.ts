// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/keystore — key custody.
 *
 * - SoftwareKeyProvider: in-process keys (dev / Local-Private).
 * - SealingKeyProvider: generic "KMS/HSM as a wrapping KEK" (model B). PolarSeek's
 *   PQC seed is wrapped at rest by a backend key; signing happens in-process.
 *   Concrete backends: AzureKeyVaultKeyProvider, AwsKmsKeyProvider, Pkcs11KeyProvider.
 * - CloudKmsKeyProvider: honest stub for GCP KMS only (pending SDK).
 */

export type { KeyRef, KeyProvider } from './types.js'
export {
  SoftwareKeyProvider,
  CloudKmsKeyProvider,
  KeyProviderRegistry,
  signEnvelopeViaProvider,
} from './providers.js'
export { SealingKeyProvider, sealedKeyAad } from './sealing-provider.js'
export type { SealedKey, SeedSealer } from './sealing-provider.js'
export { AzureKeyVaultKeyProvider } from './azure-provider.js'
export { AzureKeyVaultSealer, azureSealerFromEnv } from './azure-kv.js'
export type { AzureKeyVaultConfig } from './azure-kv.js'
export { Pkcs11KeyProvider, Pkcs11Sealer, pkcs11SealerFromEnv } from './pkcs11.js'
export type { Pkcs11WrapEngine, Pkcs11Config } from './pkcs11.js'
export { AwsKmsKeyProvider, AwsKmsSealer, awsKmsSealerFromEnv } from './aws-kms.js'
export type { AwsKmsConfig } from './aws-kms.js'
export { SoftwareOtsStateStore, HbsKeyProvider } from './hbs-state.js'
export type { OtsStateStore, OtsCapacity, HbsSignEngine } from './hbs-state.js'
