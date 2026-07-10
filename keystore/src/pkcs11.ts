// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PKCS#11 HSM sealing — turns a token-resident RSA/AES key into a SeedSealer so
 * the generic {@link SealingKeyProvider} can seal PolarSeek's PQC seed in
 * SoftHSM / Luna / CloudHSM (model B; the token never holds a PQC private key).
 *
 * PolarSeek ships NO native PKCS#11 binding: that requires `node-gyp` + a C
 * toolchain and a vendor module (`.so`/`.dll`), which is a deploy-environment
 * concern, not a protocol one. Instead you supply a tiny {@link Pkcs11WrapEngine}
 * adapter — typically a thin wrapper over `pkcs11js` bound to your
 * `PKCS11_MODULE_PATH` + `PKCS11_PIN` and a wrapping-key label — and PolarSeek
 * does the rest. This keeps the custody seam auditable and lets the provider be
 * fully tested offline with a fake engine (see keystore/test/pkcs11.test.ts).
 */

import { NotImplementedError } from '../../crypto/src/index.js'
import type { Bytes } from '../../crypto/src/index.js'
import { SealingKeyProvider } from './sealing-provider.js'
import type { SeedSealer } from './sealing-provider.js'

/** The wrap/unwrap capability PolarSeek needs from a PKCS#11 token. */
export interface Pkcs11WrapEngine {
  /** Wrap (encrypt) the seed with the token's wrapping key. */
  wrap(seed: Bytes): Promise<Bytes>
  /** Unwrap (decrypt) the sealed blob with the token's wrapping key. */
  unwrap(blob: Bytes): Promise<Bytes>
}

export interface Pkcs11Config {
  /** Path to the vendor PKCS#11 module (`.so`/`.dll`), e.g. libsofthsm2. */
  readonly modulePath: string
  /** Token PIN used to log in. */
  readonly pin: string
  /** Label/id of the wrapping key inside the token. */
  readonly wrapKeyLabel?: string
}

/** A {@link SeedSealer} backed by a PKCS#11 token via a user-supplied engine. */
export class Pkcs11Sealer implements SeedSealer {
  private readonly engine: Pkcs11WrapEngine
  /**
   * CUSTODY-SEAL-002 (AAC council review, 2026-07-11): PKCS#11 wrap-key mechanisms vary by
   * deployment — RSA-OAEP is a public-key wrap (offline-forgeable, CUSTODY-SEAL-001), an
   * AES-based mechanism is not — and {@link Pkcs11WrapEngine} doesn't expose which. Defaults
   * CONSERVATIVELY to `true` (fail closed / require `trustedPublicKey` in `load()`); pass
   * `isPublicKeyWrap: false` only when you are CERTAIN the underlying mechanism is symmetric AEAD.
   */
  readonly isPublicKeyWrap: boolean
  constructor(engine: Pkcs11WrapEngine, isPublicKeyWrap = true) {
    this.engine = engine
    this.isPublicKeyWrap = isPublicKeyWrap
  }
  wrap(seed: Bytes): Promise<Bytes> {
    return this.engine.wrap(seed)
  }
  unwrap(blob: Bytes): Promise<Bytes> {
    return this.engine.unwrap(blob)
  }
}

/** PKCS#11 HSM key provider (model B; PQC seed sealed by a token-resident key). */
export class Pkcs11KeyProvider extends SealingKeyProvider {
  constructor(sealer: SeedSealer, name = 'pkcs11') {
    super(sealer, name)
  }
}

/**
 * Build a {@link Pkcs11Sealer} from environment variables plus a native engine
 * factory. PolarSeek has no built-in PKCS#11 binding, so `engineFactory` is
 * required — wire it to `pkcs11js` (`npm i pkcs11js`; needs node-gyp + a C
 * toolchain) bound to your module and PIN. Without it this throws a clear
 * pointer rather than pretending a token is connected.
 */
export function pkcs11SealerFromEnv(
  env: { PKCS11_MODULE_PATH?: string; PKCS11_PIN?: string; PKCS11_WRAP_KEY_LABEL?: string },
  engineFactory?: (config: Pkcs11Config) => Pkcs11WrapEngine,
): Pkcs11Sealer {
  const modulePath = env.PKCS11_MODULE_PATH ?? ''
  const pin = env.PKCS11_PIN ?? ''
  if (!modulePath || !pin) {
    throw new Error('pkcs11SealerFromEnv: PKCS11_MODULE_PATH and PKCS11_PIN must both be set')
  }
  if (!engineFactory) {
    throw new NotImplementedError(
      'a native PKCS#11 engine',
      'pass engineFactory wired to `pkcs11js` (npm i pkcs11js; needs node-gyp + a C toolchain) bound to PKCS11_MODULE_PATH + PKCS11_PIN',
    )
  }
  const config: Pkcs11Config = env.PKCS11_WRAP_KEY_LABEL
    ? { modulePath, pin, wrapKeyLabel: env.PKCS11_WRAP_KEY_LABEL }
    : { modulePath, pin }
  return new Pkcs11Sealer(engineFactory(config))
}
