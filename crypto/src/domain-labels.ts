// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PQC-1 — the single source-of-truth registry of every domain-separation label used across the
 * protocol surface (HKDF info, signing/permit contexts, COSE type tags, commitment domains,
 * consensus preimages, hash-to-curve domains, …). Domain separation is what stops a signature,
 * MAC, KDF output, or commitment minted for one purpose from ever validating in another; a
 * COLLISION or accidental REUSE of a label silently merges two trust domains.
 *
 * Today these labels are scattered across ~15 modules in FOUR different naming conventions
 * (`polarseek/x/v1`, `PolarSeek/x/v1`, `PolarSeek-X-v1`, `polarseek-x-v1`) — ADR-0026 fixed one
 * cross-profile substitution reactively, which is exactly the symptom of an un-audited namespace.
 * This registry + its conformance test (crypto/test/domain-labels.property.test.ts) make the
 * namespace CHECKABLE: global uniqueness, prefix-freeness, source-coverage, no-inline-escape, and
 * canonical-encoding injectivity.
 *
 * Additive: this is a registry + a gate. It does NOT change any label's bytes or wire format (no
 * `Ps1` / `ps-*.json` touch). Wiring each module to IMPORT its label from here (so the registry is
 * load-bearing, not just authoritative-by-test) is a byte-identical follow-up, gated by conformance.
 */

export interface DomainLabel {
  /** The exact label string as it appears in source (for parameterized labels, the static stem). */
  readonly label: string
  /** What the label domain-separates. */
  readonly purpose: string
  /** Module the label is defined in (relative to repo root). */
  readonly module: string
  /** True when the label is a static STEM that runtime code extends (e.g. with `|n=..` or `/${i}`). */
  readonly parameterized?: boolean
}

/**
 * Every genuine domain-separation label in the protocol. Keep this in sync with source — the
 * conformance test fails if a label here is missing from source (stale) or if a domain-separation
 * literal appears in source that is not registered here (escape).
 */
export const DOMAIN_LABELS: readonly DomainLabel[] = [
  // --- crypto core ---
  { label: 'polarseek/kem-seal', purpose: 'KEM seal HKDF domain', module: 'crypto/src/seal.ts' },
  {
    label: 'polarseek/suite-negotiation',
    purpose: 'suite-negotiation transcript domain',
    module: 'crypto/src/suites.ts',
  },
  {
    label: 'PolarSeek-Signed-v1',
    purpose: 'generic signed-envelope context',
    module: 'crypto/src/envelope.ts',
  },
  {
    label: 'PolarSeek-Permit-v1',
    purpose: 'permit-token signing context',
    module: 'crypto/src/envelope.ts',
  },
  {
    label: 'PolarSeek-Permit-AudienceKDF-v1',
    purpose: 'per-audience permit-key HKDF context (ADR-0015)',
    module: 'crypto/src/envelope.ts',
  },
  {
    label: 'polarseek/cose/eat-result/v1',
    purpose: 'COSE EAT attestation-result type',
    module: 'crypto/src/cose.ts',
  },
  {
    label: 'polarseek/cose/cyclonedx-sbom/v1',
    purpose: 'COSE CycloneDX SBOM type',
    module: 'crypto/src/cose.ts',
  },
  {
    label: 'polarseek/cose/slsa-provenance/v1',
    purpose: 'COSE SLSA provenance type',
    module: 'crypto/src/cose.ts',
  },
  // --- capabilities / kernel-adjacent ---
  {
    label: 'polarseek/capability/grant/v2',
    purpose: 'capability-grant signing context',
    module: 'capabilities/src/capability.ts',
  },
  // --- disclosure / ZK ---
  {
    label: 'PolarSeek/disclosure/generator-H/v1',
    purpose: 'Pedersen generator-H hash-to-curve domain (ADR-0016)',
    module: 'disclosure/src/zkrange.ts',
  },
  {
    label: 'PolarSeek/disclosure/stmt/v2',
    purpose: 'range-proof statement transcript stem (extended with |n=..|thr=..)',
    module: 'disclosure/src/zkrange.ts',
    parameterized: true,
  },
  {
    label: 'PolarSeek/disclosure/bit/',
    purpose: 'per-bit OR-proof transcript stem (extended with /${prefix}/${i})',
    module: 'disclosure/src/zkrange.ts',
    parameterized: true,
  },
  {
    label: 'PolarSeek/disclosure/commit-bind/v2',
    purpose: 'salted intent-commitment domain (ADR-0014)',
    module: 'disclosure/src/commitbind.ts',
  },
  {
    label: 'polarseek-psp-v1',
    purpose: 'policy-satisfaction-proof domain',
    module: 'disclosure/src/policyproof.ts',
  },
  // --- governance / consensus / ledger ---
  {
    label: 'polarseek-gov-v1',
    purpose: 'governance quorum context',
    module: 'governance/src/quorum.ts',
  },
  {
    label: 'polarseek-quorum-receipt-v1',
    purpose: 'quorum-receipt domain',
    module: 'receipts/src/quorum.ts',
  },
  {
    label: 'polarseek-block-v1',
    purpose: 'block-hash preimage domain',
    module: 'ledger/src/chain.ts',
  },
  {
    label: 'polarseek-block-sig-v1',
    purpose: 'block-signature preimage domain',
    module: 'ledger/src/chain.ts',
  },
  {
    label: 'polarseek-attest-v1',
    purpose: 'checkpoint-attestation preimage domain',
    module: 'ledger/src/chain.ts',
  },
  {
    label: 'polarseek-vrf-v1',
    purpose: 'VRF input domain (sortition)',
    module: 'ledger/src/leader.ts',
  },
  {
    label: 'polarseek-timeout-v1',
    purpose: 'view-change timeout preimage domain',
    module: 'ledger/src/leader.ts',
  },
  {
    label: 'polarseek-sortition-v1',
    purpose: 'sortition seed domain',
    module: 'ledger/src/sortition.ts',
  },
  // --- transparency / attestation / planes / settlement ---
  { label: 'polarseek-sth-v1', purpose: 'signed-tree-head domain', module: 'translog/src/sth.ts' },
  {
    label: 'polarseek/attest/evidence/v1',
    purpose: 'software-attestation evidence domain',
    module: 'attest/src/software.ts',
  },
  {
    label: 'polarseek/session-key/v1',
    purpose: 'plane session-key HKDF context',
    module: 'planes/src/node.ts',
  },
  {
    label: 'polarseek-credit-grant-v1',
    purpose: 'settlement credit-grant domain',
    module: 'settlement/src/credits.ts',
  },
  {
    label: 'polarseek-seed-seal-v1',
    purpose: 'KMS seed-seal purpose binding',
    module: 'keystore/src/aws-kms.ts',
  },
  // --- conformance oracles ---
  {
    label: 'PolarSeek-CNSA-Verdict-v1',
    purpose: 'CNSA-verdict attestation context',
    module: 'conformance/src/cnsa-oracle.ts',
  },
  {
    label: 'PolarSeek-CBOM-v1',
    purpose: 'CBOM signing context',
    module: 'conformance/src/cbom.ts',
  },
]

/** The exact label strings, for O(1) membership and the no-escape reconciliation. */
export const DOMAIN_LABEL_SET: ReadonlySet<string> = new Set(DOMAIN_LABELS.map((d) => d.label))

/**
 * Source literals that MATCH the domain-separation naming pattern but are NOT protocol
 * domain-separation contexts — each with the reason it is excluded. Kept explicit so the no-escape
 * scan stays sound (no silent allowlisting) and an auditor can see every judgement call.
 */
export const NON_LABEL_LITERALS: ReadonlyArray<{
  readonly literal: string
  readonly reason: string
}> = [
  {
    literal: 'polarseek-kernel/0.1.0',
    reason: 'kernel VERSION string (KERNEL_VERSION), not a domain-separation context',
  },
  {
    literal: 'polarseek-seal-kek',
    reason: 'Azure Key Vault key NAME (infra resource id), not a protocol label',
  },
  {
    literal: 'PolarSeek-CBOM',
    reason: 'CBOM bomFormat FIELD value (format tag); the signing context is PolarSeek-CBOM-v1',
  },
]

const NON_LABEL_SET: ReadonlySet<string> = new Set(NON_LABEL_LITERALS.map((x) => x.literal))

/** True if `s` is a registered domain-separation label (exact, or a parameterized stem prefix). */
export function isRegisteredLabel(s: string): boolean {
  if (DOMAIN_LABEL_SET.has(s)) return true
  for (const d of DOMAIN_LABELS) {
    if (d.parameterized && s.startsWith(d.label)) return true
  }
  return false
}

/** True if `s` is an explicitly-excluded non-label literal (version/infra/format tag). */
export function isExcludedLiteral(s: string): boolean {
  return NON_LABEL_SET.has(s)
}
