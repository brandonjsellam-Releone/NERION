// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Sealing key provider — model B: a cloud KMS / HSM used as a *wrapping KEK*.
 *
 * No mainstream KMS/HSM (Azure Key Vault, AWS KMS, PKCS#11 SoftHSM / Luna /
 * CloudHSM) can hold or operate ML-DSA / ML-KEM keys yet — they do RSA/EC only.
 * So rather than signing in the backend, PolarSeek generates a PQC key from a
 * small random *seed*, wraps only that seed with the backend's key, and persists
 * just the wrapped blob ({@link SealedKey}). To sign, the blob is unwrapped (one
 * async round-trip), the PQC keypair is deterministically re-derived, and signing
 * runs in-process. The backend never holds a post-quantum private key.
 *
 * Backends differ only in how they wrap/unwrap — captured by {@link SeedSealer}.
 * Azure Key Vault, a PKCS#11 token, and AWS KMS are all just SeedSealers, so they
 * share this one provider (see AzureKeyVaultKeyProvider / Pkcs11KeyProvider).
 *
 * Wrap/unwrap are async but {@link KeyProvider} is sync, so callers must
 * `provision()` or `load()` (async) before the sync `sign()` / `getPublicKey()`
 * work. That mirrors reality: at rest the secret exists only in the sealed blob.
 *
 * Secret hygiene: the transient seed is zeroized on every path (including errors),
 * replacing an unlocked id zeroizes the superseded secret key, `provision()`
 * verifies the seal round-trips before persisting (so a non-decryptable blob fails
 * loudly at creation), and `load()` re-derives the public key from the unwrapped
 * seed and checks it.
 *
 * INTEGRITY vs AUTHENTICITY (CUSTODY-SEAL-001, Team Apex 2026-06-21). The
 * `load()` re-derived-key check against `sealed.publicKey` detects a CORRUPTED /
 * wrong-key-unwrapped blob, but it does NOT by itself detect a consistent
 * SUBSTITUTION: both the wrapped seed and the public key come from the same
 * (possibly attacker-controlled) at-rest blob. With a PUBLIC-KEY wrap — e.g. Azure
 * Key Vault RSA-OAEP — anyone who knows the (public) KEK can craft a valid
 * `wrappedSeed` for a chosen seed OFFLINE, set `publicKey` to match, and overwrite
 * a replicated blob to substitute a chosen signing key under any id. (A SYMMETRIC
 * AEAD wrap like AWS KMS Encrypt is not forgeable without the Encrypt grant, so it
 * is not exposed to the offline variant.) Defense: when the at-rest store is not
 * integrity-trusted, pass `load(sealed, { trustedPublicKey })` with the key's
 * out-of-band-trusted public key (e.g. the value `provision()` returned, kept in an
 * integrity-protected record) — `load()` then rejects any blob whose re-derived key
 * differs. Use an authenticated/symmetric wrap and an integrity-protected store too.
 */

import {
  signerFor,
  randomBytes,
  constantTimeEqual,
  NotImplementedError,
} from '../../crypto/src/index.js'
import type { Bytes, KeyPair, SignatureScheme } from '../../crypto/src/index.js'
import type { KeyProvider, KeyRef } from './types.js'

/**
 * The one capability the sealing provider needs from a custody backend.
 *
 * `aad` (Associated Data) binds the wrapped blob to its at-rest metadata
 * (`id`/`suite`/`sigId`) so a blob cannot be relabeled or swapped across keys
 * sealed under the same KEK (CUSTODY-SEAL-AAD-001). The provider derives `aad`
 * from {@link SealedKey} via {@link sealedKeyAad} and passes the SAME value to
 * `wrap` (at provision) and `unwrap` (at load); a backend with AEAD AAD support
 * (e.g. AWS KMS EncryptionContext) then enforces the binding cryptographically —
 * an `unwrap` whose `aad` differs from the `wrap`'s fails to decrypt.
 *
 * The parameter is OPTIONAL for backward compatibility: a caller (or a backend
 * fake) that omits it gets the legacy behavior. IMPORTANT enforcement caveat:
 * AAD is only cryptographically enforced by backends whose primitive carries
 * AEAD associated data (AWS KMS / a symmetric-AEAD HSM mechanism). RSA-OAEP
 * backends (Azure Key Vault wrapkey, RSA-based PKCS#11) CANNOT bind AAD — for
 * those, the `id`/`suite`/`sigId` relabel surface is reduced (not eliminated) by
 * the publicKey self-check in `load()` (which binds suite/sigId to the secret)
 * plus the `trustedPublicKey` authenticity check (CUSTODY-SEAL-001). Do not
 * assume AAD enforcement on an RSA-OAEP backend.
 */
export interface SeedSealer {
  /** Wrap (encrypt) a small secret seed; returns the opaque sealed blob. */
  wrap(seed: Bytes, aad?: Bytes): Promise<Bytes>
  /** Unwrap (decrypt) a sealed blob back to the original seed. */
  unwrap(sealed: Bytes, aad?: Bytes): Promise<Bytes>
}

/**
 * Canonical Associated Data binding a sealed blob to its at-rest metadata.
 * Versioned (`v1`) so the encoding can evolve without ambiguity, and field
 * lengths are prefixed so distinct (id, suite, sigId) triples can never collide
 * onto the same byte string. Exported so a custom backend can fold it into its
 * own AEAD context identically to {@link AwsKmsSealer}.
 */
export function sealedKeyAad(meta: { id: string; suite: string; sigId: string }): Bytes {
  const enc = new TextEncoder()
  const field = (s: string): string => `${enc.encode(s).length}:${s}`
  return enc.encode(
    `polarseek-seed-seal-aad-v1|${field(meta.id)}|${field(meta.suite)}|${field(meta.sigId)}`,
  )
}

/** At-rest custody artifact: safe to persist/replicate — carries NO secret. */
export interface SealedKey {
  readonly id: string
  readonly suite: string
  readonly sigId: string
  /** Backend-wrapped keygen seed — the only at-rest form of the secret. */
  readonly wrappedSeed: Bytes
  /** The derived PQC public key — bound to the seed and checked on load(). */
  readonly publicKey: Bytes
}

export class SealingKeyProvider implements KeyProvider {
  readonly name: string
  private readonly sealer: SeedSealer
  private readonly unlocked = new Map<string, { suite: string; kp: KeyPair }>()

  constructor(sealer: SeedSealer, name = 'sealing-kms') {
    this.sealer = sealer
    this.name = name
  }

  /** Generate a PQC key, seal its seed in the backend, and unlock it for use. */
  async provision(
    suite: string,
    id: string,
  ): Promise<{ ref: KeyRef; publicKey: Bytes; sealed: SealedKey }> {
    const scheme = signerFor(suite)
    const seed = randomBytes(seedLengthFor(scheme))
    // Bind the at-rest metadata (id/suite/sigId) into the wrap as AEAD AAD so the
    // blob cannot later be relabeled / cross-key swapped under the same KEK
    // (CUSTODY-SEAL-AAD-001). The SAME aad is passed to load()'s unwrap.
    const aad = sealedKeyAad({ id, suite, sigId: scheme.id })
    try {
      const kp = scheme.keygen(seed)
      try {
        const wrappedSeed = await this.sealer.wrap(seed, aad)
        // Verify the seal round-trips NOW — catch a wrong-key/garbled blob or a
        // missing decrypt permission at provisioning, not at a later load() after
        // the only plaintext copy of the seed has been zeroized. Unwrapping with
        // the same aad also proves the AAD binding round-trips on AEAD backends.
        const check = await this.sealer.unwrap(wrappedSeed, aad)
        const roundTrips = constantTimeEqual(check, seed)
        check.fill(0)
        if (!roundTrips) {
          throw new Error(
            `seal round-trip failed for "${id}": backend did not unwrap the wrapped seed to the original`,
          )
        }
        this.lock(id) // zeroize any key previously held under this id
        this.unlocked.set(id, { suite, kp })
        const sealed: SealedKey = {
          id,
          suite,
          sigId: scheme.id,
          wrappedSeed,
          publicKey: kp.publicKey,
        }
        return { ref: { provider: this.name, id }, publicKey: kp.publicKey, sealed }
      } catch (e) {
        // The derived secret never reached the unlocked store (wrap/unwrap threw
        // or the round-trip failed): zeroize it before unwinding. Mirrors load().
        kp.secretKey.fill(0)
        throw e
      }
    } finally {
      seed.fill(0)
    }
  }

  /**
   * Unwrap a previously sealed key (async; hits the backend) and unlock it.
   *
   * Pass `opts.trustedPublicKey` (the key's out-of-band-trusted public key, e.g. the
   * value `provision()` returned, kept in an integrity-protected record) whenever the
   * at-rest blob store is not integrity-trusted — it is the defense against a
   * substituted blob under a public-key wrap (CUSTODY-SEAL-001).
   */
  async load(sealed: SealedKey, opts: { trustedPublicKey?: Bytes } = {}): Promise<KeyRef> {
    const scheme = signerFor(sealed.suite)
    // Metadata self-consistency (backend-agnostic; holds even on non-AEAD wraps
    // that cannot enforce AAD): sigId is plaintext metadata that nothing else
    // re-derives, so a relabel to an arbitrary sigId would otherwise pass. The
    // suite already fixes the scheme, so sigId MUST equal the scheme's own id.
    if (sealed.sigId !== scheme.id) {
      throw new Error(
        `sealed key "${sealed.id}" failed metadata check: sigId "${sealed.sigId}" does not match ` +
          `suite "${sealed.suite}" (scheme "${scheme.id}")`,
      )
    }
    // Verify the at-rest metadata is the SAME that was sealed: pass the blob's
    // claimed id/suite/sigId as AAD. On an AEAD backend (AWS KMS), a relabeled /
    // cross-key-swapped blob has mismatched AAD and fails to decrypt here — the
    // primary CUSTODY-SEAL-AAD-001 defense. (sigId is taken from the blob and is
    // independently re-checked below against the scheme; see metadata check.)
    const aad = sealedKeyAad({ id: sealed.id, suite: sealed.suite, sigId: sealed.sigId })
    const seed = await this.sealer.unwrap(sealed.wrappedSeed, aad)
    try {
      const kp = scheme.keygen(seed)
      // (1) Corruption check: re-derived key must match the blob's own field. Catches a garbled
      // blob / wrong-key unwrap — but NOT a consistent substitution (both values are from the
      // attacker-controllable blob). See CUSTODY-SEAL-001 in the module docstring.
      if (!constantTimeEqual(kp.publicKey, sealed.publicKey)) {
        kp.secretKey.fill(0)
        throw new Error(
          `sealed key "${sealed.id}" failed integrity check: re-derived public key does not match sealed.publicKey`,
        )
      }
      // (2) Authenticity check (CUSTODY-SEAL-001 fix): if the caller supplies the out-of-band
      // trusted public key, the re-derived key MUST equal it — this rejects a substituted blob
      // that a public-key (e.g. Azure RSA-OAEP) wrap would otherwise admit.
      if (
        opts.trustedPublicKey !== undefined &&
        !constantTimeEqual(kp.publicKey, opts.trustedPublicKey)
      ) {
        kp.secretKey.fill(0)
        throw new Error(
          `sealed key "${sealed.id}" failed authenticity check: re-derived public key does not match ` +
            'the trusted public key (possible blob substitution — CUSTODY-SEAL-001)',
        )
      }
      this.lock(sealed.id) // zeroize any key previously held under this id
      this.unlocked.set(sealed.id, { suite: sealed.suite, kp })
      return { provider: this.name, id: sealed.id }
    } finally {
      seed.fill(0)
    }
  }

  /** Drop an unlocked key from memory (zeroing the secret). */
  lock(id: string): void {
    const e = this.unlocked.get(id)
    if (e) e.kp.secretKey.fill(0)
    this.unlocked.delete(id)
  }

  generate(_suite: string, _id: string): { ref: KeyRef; publicKey: Bytes } {
    throw new NotImplementedError(
      `synchronous generate() on the ${this.name} provider`,
      'use the async provision(suite, id) — wrapping the seed is a network/HSM round-trip',
    )
  }

  getPublicKey(ref: KeyRef): Bytes {
    return this.require(ref.id).kp.publicKey
  }

  sign(ref: KeyRef, suite: string, message: Bytes): Bytes {
    const e = this.require(ref.id)
    if (e.suite !== suite) throw new Error(`key "${ref.id}" is suite ${e.suite}, not ${suite}`)
    return signerFor(suite).sign(message, e.kp.secretKey)
  }

  private require(id: string): { suite: string; kp: KeyPair } {
    const e = this.unlocked.get(id)
    if (!e) {
      throw new Error(`key "${id}" is not unlocked — call provision()/load() (async) first`)
    }
    return e
  }
}

/** Keygen seed length, read from the scheme itself (no duplicate table to drift). */
function seedLengthFor(scheme: SignatureScheme): number {
  const n = scheme.lengths.seed
  if (typeof n !== 'number' || n <= 0) {
    throw new NotImplementedError(
      `sealed seeds for signature scheme "${scheme.id}"`,
      'the scheme does not expose a keygen seed length via scheme.lengths.seed',
    )
  }
  return n
}
