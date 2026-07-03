// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Central message-space registry (DS-REGISTRY-001 — AAC cycle-8 domain-separation audit).
 *
 * Single source of truth for the domain-separation TAG of every signed / MAC'd / sealed / committed
 * message space in Nerion. The cross-cutting audit confirmed no two message spaces currently collide,
 * but for a few surfaces disjointness held by STRUCTURAL COINCIDENCE (CBOR major-type, message length,
 * key-role) rather than by an explicit tag both sides check. This registry makes the property
 * machine-checkable: `crypto/test/domain-separation.test.ts` asserts every registered tag is globally
 * UNIQUE, so a new signed message can not silently reuse (collide with) an existing space.
 *
 * MIGRATION (incremental): consumers SHOULD import their tag from here rather than hard-coding a
 * literal. `receipts/src/receipt.ts` is the first migrated consumer (it also CLOSES RCPT-DS-002 — the
 * receipt was previously the ONLY signed message with no domain tag). The remaining literals below are
 * the AUTHORITATIVE INVENTORY of the existing tags; migrating each module to import from here is a
 * tracked follow-up. RULE: adding any new signed/MAC'd/sealed/committed message REQUIRES adding its tag
 * here first (the uniqueness test then guarantees no collision with an existing space).
 */

/** Every domain-separation tag, keyed by message space. Values MUST be globally unique. */
export const DOMAIN_TAGS = {
  // ── ML-DSA-87 signatures ───────────────────────────────────────────────────────────────────────
  /** crypto/envelope.ts — generic signed envelope. */
  ENVELOPE_SIGNED: 'PolarSeek-Signed-v1',
  /** capabilities/capability.ts — capability grant link. */
  CAPABILITY_GRANT: 'polarseek/capability/grant/v2',
  /** governance/quorum.ts — governance proposal. */
  GOVERNANCE_PROPOSAL: 'polarseek-gov-v1',
  /** receipts/receipt.ts — the transparency-log receipt (MIGRATED; was previously UNTAGGED). */
  RECEIPT: 'nerion-receipt-v1',
  /** receipts/quorum.ts — decentralized quorum receipt. */
  QUORUM_RECEIPT: 'polarseek-quorum-receipt-v1',
  /** translog/sth.ts — signed tree head. */
  STH: 'polarseek-sth-v1',
  /** attest/software.ts — attestation evidence. */
  ATTEST_EVIDENCE: 'polarseek/attest/evidence/v1',
  /** settlement/credits.ts — metering credit grant. */
  CREDIT_GRANT: 'polarseek-credit-grant-v1',
  /** ledger/chain.ts — block proposer signature. */
  BLOCK_SIG: 'polarseek-block-sig-v1',
  /** ledger/chain.ts — native consensus attestation. */
  ATTESTATION: 'polarseek-attest-v2',
  /** ledger/leader.ts — view-change / timeout vote. */
  TIMEOUT: 'polarseek-timeout-v2',
  /** ledger/evmprofile.ts — EVM-native interchain attestation (keccak preimage; SAME validator key). */
  EVM_ATTEST: 'Nerion/evm-attest/v1',

  // ── MACs (HMAC-SHA-384) ────────────────────────────────────────────────────────────────────────
  /** crypto/envelope.ts — hot-path permit MAC. */
  PERMIT_MAC: 'PolarSeek-Permit-v1',
  /** crypto/envelope.ts — per-audience permit-key HKDF info. */
  PERMIT_AUDIENCE_KDF: 'PolarSeek-Permit-AudienceKDF-v1',
  /** planes/caveat.ts — macaroon caveat chain MAC. */
  PERMIT_CAVEAT: 'Nerion/permit-caveat/v1',

  // ── AEAD seals / KEM (ADR-0028) ────────────────────────────────────────────────────────────────
  /** crypto/seal.ts — hybrid-KEM AEAD seal AAD/HKDF. */
  KEM_SEAL: 'polarseek/kem-seal',

  // ── hash commitments / set ids ─────────────────────────────────────────────────────────────────
  /** disclosure/selective.ts — salted receipt-field commitment. */
  SALTED_COMMIT: 'Nerion/disclosure/salted-commit/v1',
  /** disclosure/commitbind.ts — v:2 commitment-to-intent binding. */
  COMMIT_BIND: 'PolarSeek/disclosure/commit-bind/v2',
  /** ledger/evmprofile.ts — EVM validator-set id fold. */
  EVM_CONSENSUS_SET: 'Nerion/evm-consensus-set/v1',
} as const

export type DomainTag = (typeof DOMAIN_TAGS)[keyof typeof DOMAIN_TAGS]

/** All registered tags (used by the uniqueness gate). */
export function allDomainTags(): string[] {
  return Object.values(DOMAIN_TAGS)
}
