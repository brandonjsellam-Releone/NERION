// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * vc-projection.ts — Phase-A Standards-Binding Projection Layer (ADR-0036 / ADR-0025).
 *
 * Pure presentation/serialization module. Projects a verified Nerion PermitToken +
 * PermitClaims + ActionIntent into three external credential formats:
 *   1. W3C Verifiable Credentials Data Model 1.1 JSON-LD envelope (VcProjection)
 *   2. eIDAS-2.0 / EUDI-VC descriptor (EidasDescriptor)
 *   3. IETF agent-auth-token descriptor (AgentAuthDescriptor)
 *
 * HARD CONSTRAINTS (enforced by code structure, not runtime guards):
 *   - This module imports NOTHING from crypto/src/ — no issuePermit, verifyPermit,
 *     signEnvelope, or any cryptographic primitive.
 *   - It NEVER mutates PermitToken.body, .mac, or .suite.
 *   - It NEVER touches SuiteID Ps1 or conformance/vectors/ps-*.json.
 *   - It is a pure function: given the same inputs it returns the same outputs.
 *
 * Callers MUST have already verified the PermitToken before projecting it. This
 * module does not verify — it only serializes what the caller asserts is valid.
 *
 * Standards targets (see ADR-0036 for alignment notes):
 *   - W3C VC Data Model 2.0 (https://www.w3.org/TR/vc-data-model-2.0/)
 *   - W3C DID Core 1.0 / did:key method
 *   - EUDI ARF v1.4 SD-JWT VC profile (planning-level, pending ratification)
 *   - draft-klrc-aiagent-auth (IETF agent-authorization, working draft)
 *
 * Phase-A note: VC `proof` field is intentionally absent. The PermitToken
 * HMAC-SHA-384 MAC is the cryptographic binding. Relying parties MUST verify
 * the MAC independently before trusting projected fields.
 *
 * No legal conformity claim is made. "Technically interoperable" only.
 */

import { didKeyFromPublicKey } from '../../capabilities/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import type { PermitToken } from '../../crypto/src/index.js'
import type { PermitClaims } from './permit.js'

// ---------------------------------------------------------------------------
// DID construction helpers (pure, no crypto)
// ---------------------------------------------------------------------------

/**
 * Multicodec code for ML-DSA-87 (Dilithium5) keys used in did:key construction.
 *
 * NOTE: 0xed follows the community convention for ML-DSA-87 in the did:key context.
 * As an unsigned LEB128 varint it serializes to the bytes 0xed 0x01 — the exact
 * multicodec prefix this layer used historically — so the prefixed payload is unchanged;
 * only the (now injective) multibase encoding differs. ML-DSA-87 is NOT yet in the
 * canonical IANA multicodec registry as of June 2026; this value is provisional and must
 * be treated as such. See ADR-0036.
 */
const MLDSA87_MULTICODEC_CODE = 0xed

/**
 * Construct a did:key DID from raw ML-DSA-87 public key bytes.
 *
 * Format: did:key:z<base58btc(varint(multicodec) || publicKeyBytes)> — the canonical
 * did:key encoding (multibase 'z' = base58btc).
 *
 * Regression #1: this delegates to capabilities' didKeyFromPublicKey — the single
 * already-correct, INJECTIVE DID function — so distinct public keys can never collapse to
 * the same DID. The previous hand-rolled base64url encoder DROPPED the final base64 char
 * for inputs where length % 3 != 0, which was non-injective and aliased distinct ML-DSA-87
 * public keys to the same did:key. That encoder and its divergent did:key:u path have been
 * removed in favour of the canonical base58btc encoding.
 *
 * Reference: https://w3c-ccg.github.io/did-method-key/ (ML-DSA-87 provisional)
 */
export function buildDidKey(publicKeyBytes: Uint8Array): string {
  return didKeyFromPublicKey(MLDSA87_MULTICODEC_CODE, publicKeyBytes)
}

// ---------------------------------------------------------------------------
// W3C VC Data Model 1.1 projection types
// ---------------------------------------------------------------------------

/** W3C VC 1.1 credentialSubject embedding the ActionIntent + permit metadata. */
export interface NerionCredentialSubject {
  /** The DID of the agent holding the permit (did:key over ML-DSA-87, provisional). */
  readonly id: string
  /** Nerion action type, e.g. 'payment.transfer'. */
  readonly actionType: string
  /** Opaque resource identifier the action targets. */
  readonly resource: string
  /** Optional counterparty reference. */
  readonly counterparty?: string
  /** Optional amount in minor units. */
  readonly amount?: number
  /** Optional typed parameters. */
  readonly params?: Readonly<Record<string, unknown>>
  /** Permit audience (resource endpoint identifier). */
  readonly audience: string
  /** Permit session binding. */
  readonly sessionId: string
  /** Risk tier from the admission decision. */
  readonly tier: number
  /** Kernel decision effect ('allow' | 'transform'). */
  readonly effect: string
  /** Hex-encoded SHA3/SHAKE256 commitment to the exact ActionIntent. */
  readonly actionHash: string
}

/**
 * W3C Verifiable Credentials Data Model 1.1 JSON-LD projection of a Nerion PermitToken.
 *
 * This is a PRESENTATION envelope only. The `proof` field is intentionally absent:
 * the Nerion PermitToken's HMAC-SHA-384 MAC is the cryptographic binding; the VC
 * envelope is for external ecosystem interoperability (did:key, VC wallets, EUDI).
 * An issuer wishing to add a VC-native proof MUST do so outside this module using
 * their own signing infrastructure.
 */
export interface VcProjection {
  readonly '@context': readonly string[]
  readonly id: string
  readonly type: readonly ['VerifiableCredential', 'NerionPermitCredential']
  /** did:key of the admission authority (issuer of the permit). */
  readonly issuer: string
  /**
   * ISO-8601 issuance timestamp. Callers should supply this from the actual
   * issuance time. If omitted, the projection sets 'unknown' rather than
   * approximating from exp, which would be semantically misleading.
   */
  readonly validFrom: string
  /** ISO-8601 expiry derived from permit exp. */
  readonly expirationDate: string
  readonly credentialSubject: NerionCredentialSubject
  /**
   * Nerion-specific extension: the raw PermitToken suite tag for audit purposes.
   * Consumers MUST NOT rely on this for security decisions.
   */
  readonly nerionPermitSuite: string
  /**
   * Phase marker: 'A-unsigned' indicates no VC proof field is present.
   * Phase-B will add a DataIntegrityProof (ML-DSA-87) after external audit.
   */
  readonly _nerionPhase: 'A-unsigned'
}

// ---------------------------------------------------------------------------
// eIDAS-2.0 / EUDI-VC descriptor
// ---------------------------------------------------------------------------

/**
 * eIDAS-2.0 / EUDI Wallet Architecture and Reference Framework (ARF v1.4) SD-JWT VC
 * style descriptor. Not a legal conformity claim; technically interoperable with
 * ARF v1.4 SD-JWT VC profile. See ADR-0036.
 */
export interface EidasDescriptor {
  /**
   * Verifiable Credential Type URI. Maps Nerion permits into the EUDI namespace.
   * Provisional — not a registered type URI.
   */
  readonly vct: 'https://nerion.trelyan.com/credentials/permit/v1'
  readonly iss: string
  readonly sub: string
  readonly aud: string
  readonly exp: number
  readonly iat: number
  readonly claims: {
    readonly actionType: string
    readonly resource: string
    readonly counterparty?: string
    readonly amount?: number
    readonly tier: number
    readonly effect: string
    readonly actionHash: string
    readonly sessionId: string
  }
  /** Raw PermitToken suite tag for interop diagnostics. */
  readonly nerionSuite: string
}

// ---------------------------------------------------------------------------
// IETF agent-auth-token descriptor
// ---------------------------------------------------------------------------

/**
 * IETF agent-authorization descriptor aligned with the emerging
 * draft-klrc-aiagent-auth / OAuth transaction tokens for AI agents work.
 *
 * Not a submission-ready claim. Field names follow the OAuth/JWT convention
 * (sub, aud, exp, iat) for ecosystem interoperability.
 */
export interface AgentAuthDescriptor {
  /** JWT-style subject: the agent DID. */
  readonly sub: string
  /** Audience: the permit audience (resource endpoint). */
  readonly aud: string
  /** Expiry (unix seconds). */
  readonly exp: number
  /** Approximate issuance (unix seconds). Same as exp - 300 by convention unless caller supplies iat. */
  readonly iat: number
  /** Nerion-specific action binding. */
  readonly action: string
  readonly resource: string
  readonly counterparty?: string
  readonly amount?: number
  readonly tier: number
  readonly effect: string
  /** Hex-encoded SHAKE256 commitment to the exact ActionIntent. */
  readonly actionHash: string
  readonly sessionId: string
  /** Nerion protocol identifier for agent-auth consumers. */
  readonly nerionProtocol: 'nerion/permit/v1'
}

// ---------------------------------------------------------------------------
// Bundled projection output
// ---------------------------------------------------------------------------

export interface PermitProjection {
  readonly vc: VcProjection
  readonly eidas: EidasDescriptor
  readonly agentAuth: AgentAuthDescriptor
}

/**
 * Maximum unix-seconds value whose ×1000 milliseconds is still a representable
 * ECMAScript time value. The Date time range is ±8.64e15 ms (±100,000,000 days
 * around the epoch); anything outside makes Date#toISOString throw a RangeError.
 */
const MAX_SAFE_UNIX_SECONDS = 8.64e15 / 1000 // = 8.64e12

/** True iff `unixSeconds * 1000` yields a valid (non-NaN, in-range) Date. */
function isProjectableUnixSeconds(unixSeconds: number): boolean {
  return (
    typeof unixSeconds === 'number' &&
    Number.isFinite(unixSeconds) &&
    Math.abs(unixSeconds) <= MAX_SAFE_UNIX_SECONDS
  )
}

/**
 * Thrown by {@link projectPermit} when the permit's time fields cannot be safely
 * serialized to ISO-8601 (non-finite or out-of-Date-range `exp` / `issuedAtUnixSec`).
 *
 * This is a controlled, descriptive failure that REPLACES the opaque RangeError that
 * `new Date(x * 1000).toISOString()` would otherwise throw for such inputs. Callers
 * that want a non-throwing deny result should use {@link tryProjectPermit}, which
 * converts this into `{ ok: false, error }` and never throws on bad time inputs.
 */
export class PermitProjectionError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PermitProjectionError'
  }
}

/** Deny-shaped (non-throwing) result of a projection attempt. */
export type PermitProjectionResult =
  | { readonly ok: true; readonly projection: PermitProjection }
  | { readonly ok: false; readonly error: string }

// ---------------------------------------------------------------------------
// Projection function
// ---------------------------------------------------------------------------

/**
 * Project a verified Nerion PermitToken + its decoded PermitClaims + the ActionIntent
 * into W3C VC 1.1, eIDAS-2.0 EUDI, and IETF agent-auth descriptors.
 *
 * @param token - The PermitToken (caller must have already verified it).
 * @param claims - The decoded PermitClaims (caller must have read via readPermit).
 * @param intent - The ActionIntent the permit is bound to.
 * @param issuerPublicKeyBytes - Raw ML-DSA-87 public key bytes of the admission authority.
 * @param agentPublicKeyBytes - Raw ML-DSA-87 public key bytes of the agent (subject).
 * @param opts - Optional: issuedAtUnixSec (actual issuance time); nonce for credential ID.
 *   If issuedAtUnixSec is omitted, validFrom / iat are set to 'unknown' / 0 to avoid
 *   semantically misleading approximations from exp.
 * @throws {PermitProjectionError} if `claims.exp` (or a supplied `issuedAtUnixSec`) is
 *   not a finite, in-range unix-seconds value. This is a controlled, descriptive error
 *   that REPLACES the opaque RangeError `new Date(x * 1000).toISOString()` would throw —
 *   the validation happens BEFORE any Date is constructed. Callers that want a
 *   non-throwing deny result should use {@link tryProjectPermit} instead.
 */
export function projectPermit(
  token: PermitToken,
  claims: PermitClaims,
  intent: ActionIntent,
  issuerPublicKeyBytes: Uint8Array,
  agentPublicKeyBytes: Uint8Array,
  opts?: { nonce?: string; issuedAtUnixSec?: number },
): PermitProjection {
  // Validate time inputs BEFORE constructing any Date — new Date(x*1000).toISOString()
  // throws an opaque RangeError for non-finite / out-of-range values. Surface a clear,
  // typed error instead (or, via tryProjectPermit, a deny-shaped result).
  if (!isProjectableUnixSeconds(claims.exp)) {
    throw new PermitProjectionError(
      `invalid permit exp: expected a finite unix-seconds value in representable Date range, got ${String(claims.exp)}`,
    )
  }
  if (opts?.issuedAtUnixSec !== undefined && !isProjectableUnixSeconds(opts.issuedAtUnixSec)) {
    throw new PermitProjectionError(
      `invalid issuedAtUnixSec: expected a finite unix-seconds value in representable Date range, got ${String(opts.issuedAtUnixSec)}`,
    )
  }

  const issuerDid = buildDidKey(issuerPublicKeyBytes)
  const agentDid = buildDidKey(agentPublicKeyBytes)

  const credentialId = `urn:nerion:permit:${opts?.nonce ?? `${claims.sessionId}:${claims.nonce}`}`

  // ISO-8601 helpers (pure arithmetic, no Date manipulation beyond toISOString).
  // exp / issuedAtUnixSec were validated above, so these Date constructions cannot throw.
  const expiryDate = new Date(claims.exp * 1000).toISOString()
  // Use caller-supplied issuedAt if available; do not approximate from exp.
  const validFrom =
    opts?.issuedAtUnixSec !== undefined
      ? new Date(opts.issuedAtUnixSec * 1000).toISOString()
      : 'unknown'
  const iatApprox = opts?.issuedAtUnixSec ?? 0

  const credentialSubject: NerionCredentialSubject = {
    id: agentDid,
    actionType: intent.type,
    resource: intent.resource,
    ...(intent.counterparty !== undefined ? { counterparty: intent.counterparty } : {}),
    ...(intent.amount !== undefined ? { amount: intent.amount } : {}),
    ...(intent.params !== undefined ? { params: intent.params } : {}),
    audience: claims.audience,
    sessionId: claims.sessionId,
    tier: claims.tier,
    effect: claims.effect,
    actionHash: claims.actionHash,
  }

  const vc: VcProjection = {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://nerion.trelyan.com/contexts/permit/v1',
    ],
    id: credentialId,
    type: ['VerifiableCredential', 'NerionPermitCredential'],
    issuer: issuerDid,
    validFrom,
    expirationDate: expiryDate,
    credentialSubject,
    nerionPermitSuite: token.suite,
    _nerionPhase: 'A-unsigned',
  }

  const eidas: EidasDescriptor = {
    vct: 'https://nerion.trelyan.com/credentials/permit/v1',
    iss: issuerDid,
    sub: agentDid,
    aud: claims.audience,
    exp: claims.exp,
    iat: iatApprox,
    claims: {
      actionType: intent.type,
      resource: intent.resource,
      ...(intent.counterparty !== undefined ? { counterparty: intent.counterparty } : {}),
      ...(intent.amount !== undefined ? { amount: intent.amount } : {}),
      tier: claims.tier,
      effect: claims.effect,
      actionHash: claims.actionHash,
      sessionId: claims.sessionId,
    },
    nerionSuite: token.suite,
  }

  const agentAuth: AgentAuthDescriptor = {
    sub: agentDid,
    aud: claims.audience,
    exp: claims.exp,
    iat: iatApprox,
    action: intent.type,
    resource: intent.resource,
    ...(intent.counterparty !== undefined ? { counterparty: intent.counterparty } : {}),
    ...(intent.amount !== undefined ? { amount: intent.amount } : {}),
    tier: claims.tier,
    effect: claims.effect,
    actionHash: claims.actionHash,
    sessionId: claims.sessionId,
    nerionProtocol: 'nerion/permit/v1',
  }

  return { vc, eidas, agentAuth }
}

/**
 * Non-throwing variant of {@link projectPermit}. Validates the permit's time fields
 * and returns a deny-shaped {@link PermitProjectionResult} (`{ ok: false, error }`)
 * instead of throwing when `claims.exp` / `opts.issuedAtUnixSec` is non-finite or out of
 * the representable Date range. On success it returns `{ ok: true, projection }`.
 *
 * Use this on any path that must FAIL CLOSED on bad inputs rather than surface an
 * exception (regression guard for #3: out-of-range exp must not throw a RangeError).
 */
export function tryProjectPermit(
  token: PermitToken,
  claims: PermitClaims,
  intent: ActionIntent,
  issuerPublicKeyBytes: Uint8Array,
  agentPublicKeyBytes: Uint8Array,
  opts?: { nonce?: string; issuedAtUnixSec?: number },
): PermitProjectionResult {
  try {
    return {
      ok: true,
      projection: projectPermit(
        token,
        claims,
        intent,
        issuerPublicKeyBytes,
        agentPublicKeyBytes,
        opts,
      ),
    }
  } catch (err) {
    if (err instanceof PermitProjectionError) {
      return { ok: false, error: err.message }
    }
    throw err
  }
}
