// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Central message-space registry (DS-REGISTRY-001 — AAC cycle-8 domain-separation audit) +
 * versioned tag GENERATIONS (ADR-0042).
 *
 * Single source of truth for the domain-separation TAG of every signed / MAC'd / sealed / committed
 * message space in Nerion. `crypto/test/domain-separation.test.ts` asserts every registered tag is
 * UNIQUE within its generation, so a new signed message can not silently reuse (collide with) an
 * existing space. RULE: adding any new signed/MAC'd/sealed/committed message REQUIRES adding its tag
 * here first (to BOTH generations).
 *
 * GENERATIONS (ADR-0042 — the polarseek->Nerion tag-VALUE migration as a versioned v2->v3 bump):
 *  - `DOMAIN_TAGS_V2` is the FROZEN pre-rename tag set — the source of the frozen KAT vectors
 *    (`conformance/vectors/ps-kat.json`, `crypto/vectors/deterministic-kat.json`). No value in it
 *    ever changes.
 *  - `DOMAIN_TAGS_V3` is the Nerion/* generation: every migrated tag adopts the Nerion naming AND
 *    bumps its embedded version suffix, so a v3 tag is a DIFFERENT string from its v2 predecessor
 *    (mutually unverifiable by construction — domain separation working as designed). Tags that were
 *    already Nerion-branded keep their value (same message space, no bump needed).
 *  - `PROTOCOL_TAG_GENERATION` selects the ACTIVE generation consumers resolve through
 *    `DOMAIN_TAGS`. It is 'v2' (the wire-compatible default): flipping it to 'v3' is a PROTOCOL
 *    BREAK — it rehashes every migrated signed message, requires the additive v3 KAT/conformance
 *    vectors (ADR-0042 §c, not yet generated) and generation negotiation (ADR-0029; never
 *    dual-accept). Do NOT flip it outside that gated migration.
 *
 * PINNED-IN-V3 EXCEPTIONS (kept at their v2 value in BOTH generations, deliberately):
 *  - `SUITE_NEGOTIATION`: the live literal is hard-coded in crypto/src/suites.ts, which is FROZEN
 *    (suiteid-lock). Renaming it here without unfreezing suites.ts would silently desync the
 *    registry from the code. Migrates only with a deliberate suites.ts change.
 *  - `ZK_GENERATOR_H`: ADR-0016 pins the NUMS generator-H PROVENANCE. This string is hashed to
 *    derive the Pedersen generator H itself — changing it mints a DIFFERENT generator (a
 *    commitment-scheme migration invalidating every existing commitment), not a rename.
 *  - The zkrange dynamic Fiat-Shamir prefixes ('PolarSeek/disclosure/stmt/v2',
 *    'PolarSeek/disclosure/bit/{amount|diff}/{i}') remain hard-coded in zkrange.ts with dynamic
 *    suffixes; they migrate with the ZK layer (same audit surface as ADR-0022), not here.
 *  - kernel/policy.ts 'polarseek-kernel/0.1.0' is an evaluator VERSION label riding inside signed
 *    decisions/receipts — a version string, not a domain-separation tag; it is versioned by the
 *    kernel's own scheme.
 */

/** Which tag generation consumers resolve through `DOMAIN_TAGS`. */
export type TagGeneration = 'v2' | 'v3'

/**
 * The ACTIVE generation. 'v2' = byte-identical to the frozen KATs. Flipping to 'v3' is a gated
 * protocol migration (ADR-0042) — see the module docblock. Not a runtime knob: it is a build-time
 * constant so the emitted bytes of a given build are deterministic.
 */
export const PROTOCOL_TAG_GENERATION: TagGeneration = 'v2'

/** The FROZEN v2 (pre-rename) tag set — source of the frozen KAT vectors. Never edit a value. */
export const DOMAIN_TAGS_V2 = {
  // ── ML-DSA-87 signatures ───────────────────────────────────────────────────────────────────────
  /** crypto/envelope.ts — generic signed envelope. */
  ENVELOPE_SIGNED: 'PolarSeek-Signed-v1',
  /** capabilities/capability.ts — capability grant link. */
  CAPABILITY_GRANT: 'polarseek/capability/grant/v2',
  /** governance/quorum.ts — governance proposal. */
  GOVERNANCE_PROPOSAL: 'polarseek-gov-v1',
  /** receipts/receipt.ts — the transparency-log receipt (was previously UNTAGGED; RCPT-DS-002). */
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

  // ── COSE_Sign1 profiles (RFC 9052, crypto/cose.ts) — externalAad domain tags ─────────────────────
  /** EAT attestation-result COSE profile. */
  COSE_EAT: 'polarseek/cose/eat-result/v1',
  /** CycloneDX SBOM/CBOM COSE profile. */
  COSE_SBOM: 'polarseek/cose/cyclonedx-sbom/v1',
  /** SLSA provenance COSE profile. */
  COSE_SLSA: 'polarseek/cose/slsa-provenance/v1',

  // ── HKDF / negotiation labels ────────────────────────────────────────────────────────────────────
  /** crypto/suites.ts — suite-negotiation transcript (literal lives in the FROZEN suites.ts). */
  SUITE_NEGOTIATION: 'polarseek/suite-negotiation',
  /** planes/node.ts — attested-session key HKDF. */
  SESSION_KDF: 'polarseek/session-key/v1',

  // ── AEAD seals / KEM (ADR-0028) ────────────────────────────────────────────────────────────────
  /** crypto/seal.ts — hybrid-KEM AEAD seal AAD/HKDF. */
  KEM_SEAL: 'polarseek/kem-seal',

  // ── hash commitments / set ids ─────────────────────────────────────────────────────────────────
  /** disclosure/selective.ts — salted receipt-field commitment. */
  SALTED_COMMIT: 'Nerion/disclosure/salted-commit/v1',
  /** disclosure/commitbind.ts — v:2 commitment-to-intent binding. */
  COMMIT_BIND: 'PolarSeek/disclosure/commit-bind/v2',
  /** disclosure/setmembership.ts — set-membership Fiat-Shamir challenge (base; suffixed by k). */
  SET_MEMBERSHIP: 'Nerion/disclosure/set-membership/v1',
  /** disclosure/setmembership.ts — membership-proof digest (transparency-log-anchored). Registered in
   *  the ADR-0042 completeness pass: a live committed message space that was missing from the inventory. */
  SET_MEMBERSHIP_DIGEST: 'nerion-setmembership-v1',
  /** disclosure/policyproof.ts — policy-satisfaction proof digest. */
  POLICY_PROOF: 'polarseek-psp-v1',
  /** disclosure/zkrange.ts — NUMS generator-H derivation (nothing-up-my-sleeve; ADR-0016 pins it). */
  ZK_GENERATOR_H: 'PolarSeek/disclosure/generator-H/v1',
  /** disclosure/zkrange.ts — range-proof STATEMENT Fiat-Shamir prefix (suffixed |n=..|thr=..). */
  ZK_STMT_PREFIX: 'PolarSeek/disclosure/stmt/v2',
  /** disclosure/zkrange.ts — per-BIT Fiat-Shamir prefix (suffixed /{amount|diff}/{i}). */
  ZK_BIT_PREFIX: 'PolarSeek/disclosure/bit',
  /** ledger/chain.ts — native block hash. */
  BLOCK_HASH: 'polarseek-block-v1',
  /** ledger/leader.ts — VRF alpha / seed. */
  VRF: 'polarseek-vrf-v1',
  /** ledger/sortition.ts — native consensus-set id (DISTINCT from EVM_CONSENSUS_SET). */
  NATIVE_CONSENSUS_SET: 'polarseek-consensus-set/v1',
  /** ledger/sortition.ts — leader sortition seed. */
  SORTITION: 'polarseek-sortition-v1',
  /** ledger/evmprofile.ts — EVM validator-set id fold. */
  EVM_CONSENSUS_SET: 'Nerion/evm-consensus-set/v1',

  // ── conformance-layer signed contexts (registered in the ADR-0042 completeness pass) ────────────
  /** conformance/cnsa-oracle.ts — signed CNSA 2.0 verdict envelope (ADR-0008). */
  CNSA_VERDICT: 'PolarSeek-CNSA-Verdict-v1',
  /** conformance/cbom.ts — signed CBOM statement (ADR-0009). */
  CBOM: 'PolarSeek-CBOM-v1',
} as const

/**
 * The v3 (Nerion/*) generation — ADR-0042. Every MIGRATED tag is a NEW string (Nerion naming +
 * bumped version suffix), so v2 and v3 messages are mutually unverifiable by construction. Tags that
 * were already Nerion-branded, and the PINNED exceptions (see module docblock), keep their v2 value.
 * INACTIVE until `PROTOCOL_TAG_GENERATION` flips under the gated ADR-0042 migration (additive v3
 * KATs + conformance check + ADR-0029 negotiation).
 */
export const DOMAIN_TAGS_V3 = {
  // ── ML-DSA-87 signatures ───────────────────────────────────────────────────────────────────────
  ENVELOPE_SIGNED: 'Nerion/envelope/signed/v2',
  CAPABILITY_GRANT: 'Nerion/capability/grant/v3',
  GOVERNANCE_PROPOSAL: 'Nerion/governance/proposal/v2',
  RECEIPT: 'nerion-receipt-v1', // already Nerion — unchanged
  QUORUM_RECEIPT: 'Nerion/receipts/quorum/v2',
  STH: 'Nerion/translog/sth/v2',
  ATTEST_EVIDENCE: 'Nerion/attest/evidence/v2',
  CREDIT_GRANT: 'Nerion/settlement/credit-grant/v2',
  BLOCK_SIG: 'Nerion/ledger/block-sig/v2',
  ATTESTATION: 'Nerion/consensus/attest/v3',
  TIMEOUT: 'Nerion/consensus/timeout/v3',
  EVM_ATTEST: 'Nerion/evm-attest/v1', // already Nerion — unchanged

  // ── MACs (HMAC-SHA-384) ────────────────────────────────────────────────────────────────────────
  PERMIT_MAC: 'Nerion/permit/mac/v2',
  PERMIT_AUDIENCE_KDF: 'Nerion/permit/audience-kdf/v2',
  PERMIT_CAVEAT: 'Nerion/permit-caveat/v1', // already Nerion — unchanged

  // ── COSE_Sign1 profiles ────────────────────────────────────────────────────────────────────────
  COSE_EAT: 'Nerion/cose/eat-result/v2',
  COSE_SBOM: 'Nerion/cose/cyclonedx-sbom/v2',
  COSE_SLSA: 'Nerion/cose/slsa-provenance/v2',

  // ── HKDF / negotiation labels ──────────────────────────────────────────────────────────────────
  SUITE_NEGOTIATION: 'polarseek/suite-negotiation', // PINNED — literal lives in FROZEN suites.ts
  SESSION_KDF: 'Nerion/planes/session-key/v2',

  // ── AEAD seals / KEM ───────────────────────────────────────────────────────────────────────────
  KEM_SEAL: 'Nerion/crypto/kem-seal/v2',

  // ── hash commitments / set ids ─────────────────────────────────────────────────────────────────
  SALTED_COMMIT: 'Nerion/disclosure/salted-commit/v1', // already Nerion — unchanged
  COMMIT_BIND: 'Nerion/disclosure/commit-bind/v3',
  SET_MEMBERSHIP: 'Nerion/disclosure/set-membership/v1', // already Nerion — unchanged
  SET_MEMBERSHIP_DIGEST: 'nerion-setmembership-v1', // already Nerion — unchanged
  POLICY_PROOF: 'Nerion/disclosure/psp/v2',
  ZK_GENERATOR_H: 'PolarSeek/disclosure/generator-H/v1', // PINNED — ADR-0016 generator provenance
  ZK_STMT_PREFIX: 'PolarSeek/disclosure/stmt/v2', // PINNED — ZK layer migrates with ADR-0022, not here
  ZK_BIT_PREFIX: 'PolarSeek/disclosure/bit', // PINNED — ZK layer migrates with ADR-0022, not here
  BLOCK_HASH: 'Nerion/ledger/block/v2',
  VRF: 'Nerion/ledger/vrf/v2',
  NATIVE_CONSENSUS_SET: 'Nerion/consensus/set/v2',
  SORTITION: 'Nerion/ledger/sortition/v2',
  EVM_CONSENSUS_SET: 'Nerion/evm-consensus-set/v1', // already Nerion — unchanged

  // ── conformance-layer signed contexts ──────────────────────────────────────────────────────────
  CNSA_VERDICT: 'Nerion/conformance/cnsa-verdict/v2',
  CBOM: 'Nerion/conformance/cbom/v2',
} as const

/** The ACTIVE tag set — what every consumer imports. v2 today (byte-identical to the frozen KATs). */
export const DOMAIN_TAGS: typeof DOMAIN_TAGS_V2 | typeof DOMAIN_TAGS_V3 =
  PROTOCOL_TAG_GENERATION === 'v2' ? DOMAIN_TAGS_V2 : DOMAIN_TAGS_V3

export type DomainTag = (typeof DOMAIN_TAGS)[keyof typeof DOMAIN_TAGS]

/** The tag set of a specific generation (tests / tooling / future negotiation). */
export function domainTagsFor(gen: TagGeneration): Record<string, string> {
  return gen === 'v2' ? DOMAIN_TAGS_V2 : DOMAIN_TAGS_V3
}

/** All tags of the ACTIVE generation (used by the uniqueness gate). */
export function allDomainTags(): string[] {
  return Object.values(DOMAIN_TAGS)
}
