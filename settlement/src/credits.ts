// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Non-transferable metering credits (settlement, P4).
 *
 * Credits are granted (issuer-signed) to an account and can only be METERED
 * DOWN as governed actions consume them. There is intentionally **no transfer
 * operation** — credits are non-transferable by construction. A fungible /
 * transferable token is deliberately deferred pending counsel (MiCA / MTL), per
 * the build spec. Costs scale with the action's risk tier.
 */

import { encodeCanonical, signerFor, type Bytes, type KeyPair } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'

export class SettlementError extends Error {
  constructor(m: string) {
    super(m)
    this.name = 'SettlementError'
  }
}

export interface CreditGrant {
  readonly account: string
  readonly amount: number
  readonly issuer: string
  readonly nonce: string
  readonly suite: string
  readonly sig: Bytes
}

export interface MeterRecord {
  readonly account: string
  readonly cost: number
  /** Reference to the metered decision/receipt (e.g. a decision hash). */
  readonly ref: string
}

/** Metering cost per risk tier (T0..T3). */
export function tierCost(tier: number): number {
  const COSTS = [1, 2, 5, 20]
  return COSTS[tier] ?? 20
}

const GRANT_CONTEXT = 'polarseek-credit-grant-v1'

export class MeteringLedger {
  private readonly balances = new Map<string, number>()
  /**
   * (account, nonce) pairs already granted — one-shot, so the same signed
   * CreditGrant cannot be replayed to credit twice (SETTLE-001, Team Apex
   * 2026-06-21).
   */
  private readonly consumedNonces = new Set<string>()
  /**
   * (account, ref) pairs already metered. `ref` identifies the metered
   * decision/receipt, so a given action is metered AT MOST once — a replayed
   * Plane-1 permit (threat R2) cannot double-charge / drain the account
   * (SETTLE-METER-001, Team Apex 2026-06-21). Mirrors the grant-side replay set.
   */
  private readonly meteredRefs = new Set<string>()

  constructor(
    private readonly suite: string,
    private readonly issuer: KeyPair,
  ) {}

  /** Issue non-transferable credits to an account (issuer-signed). */
  grant(account: string, amount: number, nonce: string): CreditGrant {
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new SettlementError('grant amount must be a positive integer')
    }
    // Replay protection (SETTLE-001): a given (account, nonce) may be granted at
    // most once, so the same signed CreditGrant cannot double-credit. The key is
    // JSON-encoded so there is no separator aliasing between account and nonce.
    const nonceKey = JSON.stringify([account, nonce])
    if (this.consumedNonces.has(nonceKey)) {
      throw new SettlementError('grant nonce already used for this account (replay rejected)')
    }
    this.consumedNonces.add(nonceKey)
    this.balances.set(account, this.balance(account) + amount)
    const sig = signerFor(this.suite).sign(
      encodeCanonical([GRANT_CONTEXT, account, amount, nonce]),
      this.issuer.secretKey,
    )
    return {
      account,
      amount,
      issuer: bytesToHex(this.issuer.publicKey),
      nonce,
      suite: this.suite,
      sig,
    }
  }

  balance(account: string): number {
    return this.balances.get(account) ?? 0
  }

  /** Meter (consume) credits for a metered action; throws if insufficient. */
  meter(account: string, cost: number, ref: string): MeterRecord {
    if (!Number.isInteger(cost) || cost < 0)
      throw new SettlementError('cost must be a non-negative integer')
    // Idempotency on `ref` (SETTLE-METER-001): a given (account, ref) is metered
    // at most once, so a replayed permit cannot decrement the balance repeatedly
    // and drain the account. JSON-encoded key — no separator aliasing.
    const refKey = JSON.stringify([account, ref])
    if (this.meteredRefs.has(refKey)) {
      throw new SettlementError('ref already metered for this account (replay rejected)')
    }
    const bal = this.balance(account)
    if (bal < cost) throw new SettlementError('insufficient metering credits')
    // Mark only after the balance check, so a failed (insufficient) meter is retryable.
    this.meteredRefs.add(refKey)
    this.balances.set(account, bal - cost)
    return { account, cost, ref }
  }

  /**
   * Verify a grant's issuer signature. Pass `trustedIssuer` (hex public key) to
   * BIND the grant to a known issuer: without it, this only proves the grant is
   * self-consistently signed by whoever `g.issuer` names — NOT that the issuer is
   * trusted (anyone can self-sign a grant under their own key). Authorizing credit
   * MUST pass the trusted issuer key (SETTLE-002, Team Apex 2026-06-21) — mirrors
   * `verifyReceiptInclusion`'s `trustedIssuerKey`.
   */
  verifyGrant(g: CreditGrant, trustedIssuer?: string): boolean {
    if (trustedIssuer !== undefined && g.issuer !== trustedIssuer) return false
    try {
      return signerFor(g.suite).verify(
        g.sig,
        encodeCanonical([GRANT_CONTEXT, g.account, g.amount, g.nonce]),
        hexToBytesLocal(g.issuer),
      )
    } catch {
      return false
    }
  }
}

function hexToBytesLocal(hex: string): Bytes {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
