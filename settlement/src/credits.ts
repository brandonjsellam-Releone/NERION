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

  constructor(
    private readonly suite: string,
    private readonly issuer: KeyPair,
  ) {}

  /** Issue non-transferable credits to an account (issuer-signed). */
  grant(account: string, amount: number, nonce: string): CreditGrant {
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new SettlementError('grant amount must be a positive integer')
    }
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
    const bal = this.balance(account)
    if (bal < cost) throw new SettlementError('insufficient metering credits')
    this.balances.set(account, bal - cost)
    return { account, cost, ref }
  }

  /** Verify a grant's issuer signature. */
  verifyGrant(g: CreditGrant): boolean {
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
