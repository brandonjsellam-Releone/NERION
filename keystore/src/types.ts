// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Key-custody abstraction.
 *
 * Signing keys are never handled directly by protocol logic — they live behind
 * a {@link KeyProvider}. The software provider holds keys in process (dev /
 * Local-Private); HSM and cloud-KMS providers are honest stubs until real
 * hardware/credentials are wired (the "HSM/KMS" production gap). Swapping
 * providers is a config change, not a code change.
 */

import type { Bytes } from '../../crypto/src/index.js'

/** An opaque handle to a key held by a provider. */
export interface KeyRef {
  readonly provider: string
  readonly id: string
}

export interface KeyProvider {
  readonly name: string
  /** Create a new key under `id` and return its handle + public key. */
  generate(suite: string, id: string): { ref: KeyRef; publicKey: Bytes }
  getPublicKey(ref: KeyRef): Bytes
  /** Sign `message` with the referenced key under `suite`. */
  sign(ref: KeyRef, suite: string, message: Bytes): Bytes
}
