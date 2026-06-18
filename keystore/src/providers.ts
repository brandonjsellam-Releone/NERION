/**
 * Key providers: a working software backend, HSM/KMS stubs, a routing registry,
 * and an envelope-signing helper that keeps secret keys behind the provider.
 */

import {
  signerFor,
  signEnvelopeWith,
  NotImplementedError,
  type Bytes,
  type KeyPair,
  type SignedEnvelope,
} from '../../crypto/src/index.js'
import type { KeyProvider, KeyRef } from './types.js'

/** In-process software key custody (dev / Local-Private). */
export class SoftwareKeyProvider implements KeyProvider {
  readonly name = 'software'
  private readonly keys = new Map<string, KeyPair>()

  generate(suite: string, id: string): { ref: KeyRef; publicKey: Bytes } {
    const kp = signerFor(suite).keygen()
    this.keys.set(id, kp)
    return { ref: { provider: this.name, id }, publicKey: kp.publicKey }
  }

  /** Adopt an existing keypair (e.g. a pre-provisioned issuer key). */
  importKeyPair(id: string, kp: KeyPair): KeyRef {
    this.keys.set(id, kp)
    return { provider: this.name, id }
  }

  getPublicKey(ref: KeyRef): Bytes {
    return this.require(ref).publicKey
  }

  sign(ref: KeyRef, suite: string, message: Bytes): Bytes {
    return signerFor(suite).sign(message, this.require(ref).secretKey)
  }

  private require(ref: KeyRef): KeyPair {
    const kp = this.keys.get(ref.id)
    if (!kp) throw new Error(`software keystore has no key "${ref.id}"`)
    return kp
  }
}

/** Base for hardware/cloud providers that are registered but not yet wired. */
abstract class StubKeyProvider implements KeyProvider {
  abstract readonly name: string
  protected abstract readonly connect: string
  private fail(): never {
    throw new NotImplementedError(`${this.name} key provider`, this.connect)
  }
  generate(_suite: string, _id: string): { ref: KeyRef; publicKey: Bytes } {
    this.fail()
  }
  getPublicKey(_ref: KeyRef): Bytes {
    this.fail()
  }
  sign(_ref: KeyRef, _suite: string, _message: Bytes): Bytes {
    this.fail()
  }
}

/** PKCS#11 HSM (SoftHSM / Luna / CloudHSM) — pending bindings + module. */
export class Pkcs11KeyProvider extends StubKeyProvider {
  readonly name = 'pkcs11'
  protected readonly connect = 'a PKCS#11 module + pkcs11 bindings (SoftHSM/Luna/CloudHSM)'
}

/** Cloud KMS (AWS KMS / Azure Key Vault / GCP KMS) — pending credentials + SDK. */
export class CloudKmsKeyProvider extends StubKeyProvider {
  readonly name = 'cloud-kms'
  protected readonly connect = 'cloud KMS credentials + SDK (AWS KMS / Azure Key Vault / GCP KMS)'
}

/** Routes key operations to the provider named in each KeyRef. */
export class KeyProviderRegistry {
  private readonly providers = new Map<string, KeyProvider>()

  register(p: KeyProvider): this {
    this.providers.set(p.name, p)
    return this
  }
  resolve(ref: KeyRef): KeyProvider {
    const p = this.providers.get(ref.provider)
    if (!p) throw new Error(`no key provider named "${ref.provider}"`)
    return p
  }
  getPublicKey(ref: KeyRef): Bytes {
    return this.resolve(ref).getPublicKey(ref)
  }
  sign(ref: KeyRef, suite: string, message: Bytes): Bytes {
    return this.resolve(ref).sign(ref, suite, message)
  }
}

/** Sign an envelope with a key held behind a provider (secret never leaves it). */
export function signEnvelopeViaProvider(
  payload: unknown,
  suite: string,
  provider: KeyProvider,
  ref: KeyRef,
  context = '',
): SignedEnvelope {
  return signEnvelopeWith(payload, suite, (tbs) => provider.sign(ref, suite, tbs), context)
}
