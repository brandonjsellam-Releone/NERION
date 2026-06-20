// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * One-time-key HBS STATE MANAGER + custody adapter — the heart of safe
 * CNSA 2.0 LMS/XMSS code signing. The single rule: no one-time-key (OTS) index is
 * ever used twice — a single reuse is a total, unrecoverable forgery (SP 800-208
 * §9.1).
 *
 * `HbsKeyProvider` orchestrates RESERVE-BEFORE-SIGN: it durably burns the
 * OTS index in the store BEFORE asking the engine to sign, and never retries a
 * burned index — a failed sign wastes a leaf rather than risk reuse. The raw
 * LMS/XMSS primitive is delegated to an injected `HbsSignEngine` (a vetted FIPS
 * 140-3 L3+ module via PKCS#11), never home-rolled — exactly like the existing HSM
 * custody adapters.
 *
 * ┌────────────────────────────────────────────────────────────────────────────┐
 * │ `SoftwareOtsStateStore` is a DEV / LOCAL-PRIVATE REFERENCE for the reserve- │
 * │ before-sign LOGIC ONLY. It is NOT an SP 800-208-conformant signer: a        │
 * │ consistent restore-from-backup moves the monotonic floor backward           │
 * │ undetectably, and software fsync is unverifiable on virtual/network disks —  │
 * │ either path reuses an OTS index = total forgery. Production REQUIRES a       │
 * │ hardware monotonic counter inside the FIPS module boundary. Construction is  │
 * │ hard-gated behind `allowUnsafeSoftwareState`.                                │
 * └────────────────────────────────────────────────────────────────────────────┘
 */

import {
  PolicyError,
  OtsKeyExhaustedError,
  OtsStateRollbackError,
  assertSingleTree,
  type Bytes,
  type HbsParams,
} from '../../crypto/src/index.js'

export interface OtsCapacity {
  readonly height: number
  readonly total: number
  readonly consumed: number
}

export interface OtsStateStore {
  /** Reserve (durably burn) the next one-time-key index for `keyId`. */
  reserve(keyId: string, height: number): { index: number }
  capacity(keyId: string): OtsCapacity
}

/**
 * In-memory reference store enforcing the reserve-before-sign invariants. DEV ONLY
 * (gated). Demonstrates I2 (no-reuse / strict monotonic), I5 (exhaustion), and the
 * I4 monotonic-floor anti-rollback check. The durability (I1) and anti-clone (I3)
 * invariants require non-volatile / hardware backing and are documented, not
 * simulated, here.
 */
export class SoftwareOtsStateStore implements OtsStateStore {
  private readonly keys = new Map<string, { height: number; total: number; next: number }>()

  constructor(allowUnsafeSoftwareState = false) {
    if (!allowUnsafeSoftwareState) {
      throw new PolicyError(
        'E_OTS_SOFTWARE_UNSAFE',
        'SoftwareOtsStateStore is a dev/Local-Private reference and is NOT an SP 800-208-conformant ' +
          'signer (restore-from-backup can silently reuse an OTS index = total forgery). Pass ' +
          'allowUnsafeSoftwareState=true for testing only; production one-time-key HBS signing requires a ' +
          'FIPS 140-3 L3+ hardware monotonic counter.',
      )
    }
  }

  private state(keyId: string, height: number): { height: number; total: number; next: number } {
    let s = this.keys.get(keyId)
    if (s === undefined) {
      if (!Number.isInteger(height) || height < 0 || height > 32) {
        throw new PolicyError('E_OTS_BAD_HEIGHT', `invalid single-tree height ${height}`)
      }
      s = { height, total: 2 ** height, next: 0 }
      this.keys.set(keyId, s)
    } else if (s.height !== height) {
      throw new PolicyError(
        'E_OTS_HEIGHT_MISMATCH',
        `height for ${keyId} changed ${s.height} -> ${height}`,
      )
    }
    return s
  }

  reserve(keyId: string, height: number): { index: number } {
    const s = this.state(keyId, height)
    if (s.next >= s.total) throw new OtsKeyExhaustedError(keyId) // I5
    const index = s.next
    s.next = index + 1 // I1/I2: burn-before-return, strict monotonic (HW: a monotonic counter)
    return { index }
  }

  capacity(keyId: string): OtsCapacity {
    const s = this.keys.get(keyId)
    if (s === undefined) return { height: 0, total: 0, consumed: 0 }
    return { height: s.height, total: s.total, consumed: s.next }
  }

  /** I4 anti-rollback: refuse if persisted state is below an external monotonic floor. */
  assertMonotonicFloor(keyId: string, externalFloor: number): void {
    const s = this.keys.get(keyId)
    if (s !== undefined && s.next < externalFloor) throw new OtsStateRollbackError(keyId)
  }
}

/** The raw LMS/XMSS primitive, adapter-provided (a vetted FIPS module via PKCS#11). */
export interface HbsSignEngine {
  getRoot(keyId: string): Bytes
  /** Sign with the OTS leaf at `index`. The engine is TOLD the index; it never picks one. */
  signWithIndex(keyId: string, index: number, message: Bytes): Bytes
  params(keyId: string): HbsParams
}

/**
 * Custody adapter that owns reserve-before-sign + single-tree policy and delegates
 * the raw primitive to `engine`. It deliberately does NOT implement the stateless
 * `KeyProvider.sign` so an HBS code-signing key can never be routed through the seed-sealing
 * path (the clone bug).
 */
export class HbsKeyProvider {
  constructor(
    private readonly engine: HbsSignEngine,
    private readonly store: OtsStateStore,
    readonly name = 'hbs',
  ) {}

  getPublicKey(keyId: string): Bytes {
    return this.engine.getRoot(keyId)
  }

  /**
   * RESERVE-BEFORE-SIGN: enforce single-tree, durably burn the next OTS index, THEN
   * sign. A failed `signWithIndex` leaves the index burned (never retried) — a wasted
   * leaf is safe; a reused leaf forges.
   */
  sign(keyId: string, message: Bytes): Bytes {
    const params = this.engine.params(keyId)
    assertSingleTree(params, keyId) // policy BEFORE any state mutation
    const { index } = this.store.reserve(keyId, params.height)
    return this.engine.signWithIndex(keyId, index, message)
  }

  remaining(keyId: string): number {
    const c = this.store.capacity(keyId)
    return c.total - c.consumed
  }
}
