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

import {
  activeSuiteIds,
  DOMAIN_TAGS,
  encodeCanonical,
  signerFor,
  type Bytes,
  type KeyPair,
} from '../../crypto/src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

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

const GRANT_CONTEXT = DOMAIN_TAGS.CREDIT_GRANT

/**
 * In-memory metering ledger for ONE issuer (`this.issuer`).
 *
 * SCOPE (SETTLE-REPLAY-SCOPE-001, AAC cycle-3): the replay defenses (`consumedNonces`,
 * `meteredRefs`) and `balances` are PROCESS-LOCAL and non-durable — they dedup within a single live
 * instance only. A signed `CreditGrant` replayed to a SEPARATE instance (a replica, a restarted
 * process, or a re-instantiated ledger) is NOT caught here. Any multi-instance or persistent
 * deployment MUST back grant-nonce and meter-ref dedup with a durable, shared store keyed by
 * (issuer, account, nonce) / (issuer, account, ref). Dedup is issuer-scoped by construction (one
 * ledger binds one issuer), so the in-key issuer is implicit; a shared store must make it explicit.
 */
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
    // F8 (Team Apex max sweep 2026-06-28): Number.isInteger accepts integer-valued floats at/above
    // 2^53, where `balance + amount` loses unit precision (2^53 + 1 === 2^53) — enabling silent
    // under-charge / un-drainable inflated balances. Require a SAFE integer (matches ADR-0018's
    // amount domain [0, 2^53-1] and grant.ts / quorum.ts), not merely an integer.
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new SettlementError('grant amount must be a positive safe integer')
    }
    // Replay protection (SETTLE-001): a given (account, nonce) may be granted at
    // most once, so the same signed CreditGrant cannot double-credit. The key is
    // JSON-encoded so there is no separator aliasing between account and nonce.
    const nonceKey = JSON.stringify([account, nonce])
    if (this.consumedNonces.has(nonceKey)) {
      throw new SettlementError('grant nonce already used for this account (replay rejected)')
    }
    // Cap the cumulative balance so repeated valid grants can never walk it across 2^53 into the
    // lossy range (the overflow check is exact: both operands are safe integers). F8.
    if (this.balance(account) > Number.MAX_SAFE_INTEGER - amount) {
      throw new SettlementError('grant would overflow the safe-integer balance range')
    }
    this.consumedNonces.add(nonceKey)
    this.balances.set(account, this.balance(account) + amount)
    // SETTLE-SUITE-BIND-001 (AAC cycle-3): bind `suite` INTO the signed message. Previously the
    // signature covered only [context, account, amount, nonce] while verifyGrant dispatched on the
    // attacker-transportable `g.suite` field — an algorithm-substitution gap (a swapped suite label
    // was signature-preserving among suites sharing a sigId, and would become load-bearing the moment
    // a suite with a different/weaker sigId is activated). Binding the suite makes any swap break the
    // signature. (Same class as CAP-SUITE-PIN-001.)
    const sig = signerFor(this.suite).sign(
      encodeCanonical([GRANT_CONTEXT, this.suite, account, amount, nonce]),
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
    if (!Number.isSafeInteger(cost) || cost < 0)
      throw new SettlementError('cost must be a non-negative safe integer')
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
    // SETTLE-VERIFY-DOMAIN-001 (AAC cycle-3): re-validate the amount at USE time. The F8 safe-integer
    // guard lived only in grant() (the issue path); a CreditGrant is a signed, transportable credential
    // (its whole purpose), so a foreign grant crossing this trust boundary must be re-checked here — or
    // a downstream consumer could credit an amount in the lossy >= 2^53 range this ledger cannot
    // represent (ADR-0018's canonical u64 domain exceeds JS-number safety; a JS-number ledger must
    // reject what it cannot represent). Fail-closed.
    if (!Number.isSafeInteger(g.amount) || g.amount <= 0) return false
    // Reject a grant whose advertised suite is not currently active (defense-in-depth beyond the suite
    // now being bound into the signature by grant() — SETTLE-SUITE-BIND-001).
    if (!activeSuiteIds().includes(g.suite)) return false
    try {
      return signerFor(g.suite).verify(
        g.sig,
        encodeCanonical([GRANT_CONTEXT, g.suite, g.account, g.amount, g.nonce]),
        hexToBytes(g.issuer),
      )
    } catch {
      return false
    }
  }
}
