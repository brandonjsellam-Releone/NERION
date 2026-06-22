// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Supply-chain provenance — a CycloneDX-style SBOM and an in-toto / SLSA Provenance
 * v1 build-provenance statement, signed as COSE_Sign1 (ADR-0011) and anchorable in
 * the transparency log. These are the EO 14028 / NIST SSDF (SP 800-218) / SLSA Build
 * Track artifacts a federal procurement gate asks for — produced from PolarSeek's
 * real dependency set, PQ-signed, and externally verifiable.
 *
 * HONEST SCOPE: this emits + signs the standard SHAPES. A COMPLETE SBOM enumerates
 * the full transitive dependency graph (from the lockfile); SLSA L2/L3 requires a
 * hardened hosted build platform to PRODUCE the provenance — those are CI/ops
 * concerns, not closed here. This is the conformant artifact format + the
 * post-quantum signing/anchoring layer that those pipelines feed.
 */

import {
  coseSign1,
  coseSign1Verify,
  encodeCoseSign1,
  encodeCanonical,
  COSE_ALG,
  COSE_PROFILE,
  coseProfileAad,
  type Bytes,
  type CoseSign1,
} from '../../crypto/src/index.js'

export interface SbomComponent {
  readonly name: string
  readonly version: string
  readonly type: 'library' | 'framework' | 'application'
  readonly license: string
}

export interface Sbom {
  readonly bomFormat: 'CycloneDX'
  readonly specVersion: '1.6'
  readonly subject: string
  readonly generatedAt: number
  readonly components: readonly SbomComponent[]
}

/** PolarSeek's direct runtime dependencies (from package.json). */
export const POLARSEEK_DEPENDENCIES: readonly SbomComponent[] = [
  { name: '@noble/ciphers', version: '2.0.0', type: 'library', license: 'MIT' },
  { name: '@noble/curves', version: '2.2.0', type: 'library', license: 'MIT' },
  { name: '@noble/hashes', version: '2.0.0', type: 'library', license: 'MIT' },
  { name: '@noble/post-quantum', version: '0.6.1', type: 'library', license: 'MIT' },
  { name: 'cbor2', version: '2.3.0', type: 'library', license: 'MIT' },
]

/** Build a deterministic CycloneDX-style SBOM (components sorted by name). */
export function buildSbom(
  components: readonly SbomComponent[] = POLARSEEK_DEPENDENCIES,
  now = 0,
  subject = 'PolarSeek',
): Sbom {
  const sorted = [...components].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    subject,
    generatedAt: now,
    components: sorted,
  }
}

export interface SlsaProvenance {
  readonly _type: 'https://in-toto.io/Statement/v1'
  readonly subject: ReadonlyArray<{
    readonly name: string
    readonly digest: Readonly<Record<string, string>>
  }>
  readonly predicateType: 'https://slsa.dev/provenance/v1'
  readonly predicate: {
    readonly buildDefinition: {
      readonly buildType: string
      readonly resolvedDependencies: ReadonlyArray<{
        readonly name: string
        readonly version: string
      }>
    }
    readonly runDetails: {
      readonly builder: { readonly id: string }
      readonly metadata: { readonly startedOn: number }
    }
  }
}

/** Build an in-toto / SLSA Provenance v1 statement for a built artifact. */
export function buildSlsaProvenance(opts: {
  readonly subjectName: string
  readonly subjectSha256: string
  readonly buildType: string
  readonly builderId: string
  readonly dependencies?: readonly SbomComponent[]
  readonly now?: number
}): SlsaProvenance {
  const deps = (opts.dependencies ?? POLARSEEK_DEPENDENCIES).map((d) => ({
    name: d.name,
    version: d.version,
  }))
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: opts.subjectName, digest: { sha256: opts.subjectSha256 } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: { buildType: opts.buildType, resolvedDependencies: deps },
      runDetails: { builder: { id: opts.builderId }, metadata: { startedOn: opts.now ?? 0 } },
    },
  }
}

/**
 * The COSE profile (ADR-0026 domain separator) for a supply-chain statement, by its shape: a
 * CycloneDX SBOM (`bomFormat`) vs an in-toto/SLSA provenance (`_type`). Bound as external_aad so an
 * SBOM signature cannot verify as a provenance (or as an EAT result) under a shared key.
 */
function statementProfile(statement: unknown): string {
  const s = statement as Record<string, unknown> | null
  const isSbom = !!s && s['bomFormat'] === 'CycloneDX'
  const isProv = !!s && s['_type'] === 'https://in-toto.io/Statement/v1'
  // Fail closed on ambiguity / unknown shape (council ADR-0026 hardening): NEVER sign under a
  // guessed or fallback profile. An ambiguous (both-shapes) or unrecognized statement is refused,
  // so the bound profile is always exactly one registered COSE_PROFILE value — no latent vector.
  if (isSbom && isProv) {
    throw new Error('ambiguous supply-chain statement: both SBOM and provenance shape')
  }
  if (isSbom) return COSE_PROFILE.CYCLONEDX_SBOM
  if (isProv) return COSE_PROFILE.SLSA_PROVENANCE
  throw new Error('unrecognized supply-chain statement shape — refusing to sign without a profile')
}

/** Sign an SBOM or provenance statement as a COSE_Sign1 (ML-DSA-87), bound to its profile. */
export function signSupplyChainStatement(
  statement: unknown,
  suite: string,
  secretKey: Bytes,
): CoseSign1 {
  return coseSign1(
    encodeCanonical(statement),
    suite,
    secretKey,
    COSE_ALG.ML_DSA_87,
    coseProfileAad(statementProfile(statement)),
  )
}

/**
 * Verify a supply-chain statement. The relying party MUST declare the `expectedProfile`
 * (COSE_PROFILE.CYCLONEDX_SBOM or .SLSA_PROVENANCE) — a signature minted under a different profile
 * (e.g. an EAT result, or the wrong supply-chain type) fails (ADR-0026 domain separation).
 */
export function verifySupplyChainStatement(
  msg: CoseSign1,
  suite: string,
  publicKey: Bytes,
  expectedProfile: string,
): boolean {
  return coseSign1Verify(msg, suite, publicKey, COSE_ALG.ML_DSA_87, coseProfileAad(expectedProfile))
}

/** Canonical bytes to anchor a signed supply-chain statement as a transparency-log leaf. */
export function supplyChainLeaf(msg: CoseSign1): Bytes {
  return encodeCoseSign1(msg)
}
