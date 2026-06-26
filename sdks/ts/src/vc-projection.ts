// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * B12 Phase-A — presentation-layer projection of Nerion's native permit/receipt
 * data into W3C Verifiable Credentials 2.0 and an eIDAS-2.0 electronic-attestation
 * shape, for external standards-speaking consumers (SSI wallets, eIDAS verifiers).
 *
 * ADDITIVE & PURELY PRESENTATIONAL. This module performs NO cryptography and does
 * NOT change how Nerion signs or verifies anything. It imports no signing or
 * verification function, reads no clock, and defines its own minimal *structural*
 * input types (mirroring `PermitClaims` in `planes/src/permit.ts` and
 * `ActionIntent` in `capabilities/src/types.ts`) so it is a zero-coupling leaf.
 * The canonical proof always remains the native Nerion PermitToken / Receipt
 * ML-DSA-87 signature — the VC `proof` block only *references* it. Timestamps are
 * passed in by the caller (no ambient clock), keeping projection deterministic.
 *
 * Lives in the SDK (client/presentation) layer, not the crypto cleanroom. See
 * docs/adr/ADR-0019-standards-binding-profile.md.
 */

const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2'
/** Placeholder Nerion JSON-LD context; to be published at a stable URL. */
const NERION_CONTEXT = 'https://nerion.dev/contexts/v1'

/** Fields this projection reads from a Nerion `PermitClaims` (structural mirror). */
export interface PermitView {
  readonly audience: string
  readonly actionHash: string
  readonly tier: number
  /** Raw expiry value as carried in the permit; unit-agnostic (not interpreted here). */
  readonly exp: number
  readonly effect: string
  readonly evaluator: string
}

/** Fields this projection reads from a Nerion `ActionIntent` (structural mirror). */
export interface IntentView {
  readonly type: string
  readonly resource: string
  readonly counterparty?: string
  readonly amount?: number
}

/** Fields this projection reads from a Nerion receipt (structural mirror). */
export interface ReceiptView {
  readonly action: string
  readonly tier: number
  readonly effect: string
  readonly evaluatorVersion: string
  readonly merkleRoot?: string
}

/** A minimal W3C Verifiable Credential 2.0 document (presentation view). */
export interface W3CVerifiableCredential {
  readonly '@context': readonly string[]
  readonly type: readonly string[]
  readonly issuer: string
  readonly validFrom: string
  readonly validUntil?: string
  readonly credentialSubject: Readonly<Record<string, unknown>>
  readonly proof: Readonly<Record<string, unknown>>
}

/** A minimal W3C Verifiable Presentation 2.0 document (presentation view). */
export interface W3CVerifiablePresentation {
  readonly '@context': readonly string[]
  readonly type: readonly string[]
  readonly holder: string
  readonly verifiableCredential?: readonly W3CVerifiableCredential[]
  readonly nerionReceipt: Readonly<Record<string, unknown>>
}

/**
 * Project a Nerion permit (its claims + the action it authorizes) into a W3C-VC
 * 2.0 credential. The `proof` block references Nerion's native ML-DSA-87 signature;
 * it does not re-sign. The caller (holder of the canonical signed PermitToken)
 * supplies `issuerDid`, `validFromIso`, and optionally the base64url `proofValue`
 * and a `validUntilIso` (computed by the caller, which knows the `exp` unit).
 */
export function permitToVerifiableCredential(
  permit: PermitView,
  intent: IntentView,
  opts: {
    readonly issuerDid: string
    readonly validFromIso: string
    readonly validUntilIso?: string
    readonly proofValueB64Url?: string
  },
): W3CVerifiableCredential {
  const credentialSubject: Record<string, unknown> = {
    id: opts.issuerDid,
    nerionProtocol: 'v1',
    action: intent.type,
    resource: intent.resource,
    audience: permit.audience,
    tier: permit.tier,
    effect: permit.effect,
    actionHash: permit.actionHash,
    evaluator: permit.evaluator,
    expiresAtRaw: permit.exp,
  }
  if (intent.counterparty !== undefined) credentialSubject.counterparty = intent.counterparty
  if (intent.amount !== undefined) credentialSubject.amount = intent.amount

  const proof: Record<string, unknown> = {
    type: 'NerionMLDSA87Signature2026',
    cryptosuite: 'nerion-ml-dsa-87',
    proofPurpose: 'assertionMethod',
    verificationMethod: `${opts.issuerDid}#nerion-key`,
    note: 'Presentation view. The canonical proof is the native Nerion PermitToken ML-DSA-87 signature.',
  }
  if (opts.proofValueB64Url !== undefined) proof.proofValue = opts.proofValueB64Url

  return {
    '@context': [VC_CONTEXT_V2, NERION_CONTEXT],
    type: ['VerifiableCredential', 'NerionPermitCredential'],
    issuer: opts.issuerDid,
    validFrom: opts.validFromIso,
    ...(opts.validUntilIso !== undefined ? { validUntil: opts.validUntilIso } : {}),
    credentialSubject,
    proof,
  }
}

/**
 * Project a Nerion receipt into a W3C Verifiable Presentation. Optionally embeds
 * the permit credential. Purely presentational; the canonical audit evidence is
 * the Merkle-anchored native receipt.
 */
export function receiptToVerifiablePresentation(
  receipt: ReceiptView,
  holderDid: string,
  embeddedCredentials?: readonly W3CVerifiableCredential[],
): W3CVerifiablePresentation {
  const nerionReceipt: Record<string, unknown> = {
    action: receipt.action,
    tier: receipt.tier,
    effect: receipt.effect,
    evaluatorVersion: receipt.evaluatorVersion,
  }
  if (receipt.merkleRoot !== undefined) nerionReceipt.merkleRoot = receipt.merkleRoot

  return {
    '@context': [VC_CONTEXT_V2, NERION_CONTEXT],
    type: ['VerifiablePresentation', 'NerionActionReceiptPresentation'],
    holder: holderDid,
    ...(embeddedCredentials !== undefined ? { verifiableCredential: embeddedCredentials } : {}),
    nerionReceipt,
  }
}

/**
 * Project a Nerion permit into a simplified eIDAS-2.0 electronic-attestation
 * structure (Phase-A shape; qualified-signature alignment is Phase-B and requires
 * an accredited module — out of scope here).
 */
export function permitToEidasAttestation(
  permit: PermitView,
  intent: IntentView,
  opts: { readonly organizationIdentifier: string; readonly country: string },
): Readonly<Record<string, unknown>> {
  return {
    eidasAttestationType: 'NerionAgentCapabilityAttestation',
    issuer: { organizationIdentifier: opts.organizationIdentifier, country: opts.country },
    subject: { agentAudience: permit.audience },
    attributes: {
      permittedAction: intent.type,
      permittedResource: intent.resource,
      tier: permit.tier,
      effect: permit.effect,
      cryptographicAlgorithm: 'ML-DSA-87 (FIPS 204)',
    },
  }
}
