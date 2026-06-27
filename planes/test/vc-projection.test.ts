// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * vc-projection.test.ts — F2 regression suite for the Phase-A standards-binding
 * projection layer (planes/src/vc-projection.ts).
 *
 * Covers three properties, two of which are explicit regression tests:
 *   (a) did:key construction is INJECTIVE at the real ML-DSA-87 public-key size
 *       (2592 bytes raw → 2594 bytes after the 2-byte multicodec prefix). This is
 *       the regression test for the DID/base-encoding aliasing bug (#1): it PASSES
 *       only once the encoder is a proper bijection over the trailing bytes. The
 *       pre-fix hand-rolled base64url path dropped the final char when the input
 *       length % 3 != 0, which could alias distinct ML-DSA-87 public keys to the
 *       same did:key. The fix makes the encoder injective. (Format-agnostic: the
 *       sweeps below assert distinctness regardless of base64url/base58btc.)
 *   (b) projectPermit happy path — the three descriptors are produced and carry
 *       the bound fields straight through from the verified PermitToken/claims.
 *   (c) A non-finite permit `exp` must NOT throw on the resource verify path; it
 *       fails CLOSED with a deny verdict (regression for #3, fail-open-on-bad-exp).
 *
 * This module imports the real exported API only. It never touches crypto suite
 * vectors or conformance fixtures.
 */

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, randomBytes } from '../../crypto/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import {
  buildDidKey,
  projectPermit,
  tryProjectPermit,
  PermitProjectionError,
} from '../src/vc-projection.js'
import {
  actionHash,
  issueBoundPermit,
  verifyPermitForAction,
  deriveAudiencePermitKey,
  type PermitClaims,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)

// Real ML-DSA-87 (FIPS 204, Cat-5) keypairs — the genuine sizes the projection
// layer must handle, not a synthetic stand-in.
const issuerKp = s.keygen()
const agentKp = s.keygen()

/** ML-DSA-87 raw public-key length in bytes (FIPS 204, Category 5). */
const MLDSA87_PK_LEN = 2592

const NOW = 1_750_000_000

const pay = (amount: number): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty: 'vendor-acme',
  amount,
})

function claimsFor(intent: ActionIntent, exp: number): PermitClaims {
  return {
    sessionId: 'sess-vc',
    nonce: 'feedface',
    audience: 'acct://treasury',
    actionHash: actionHash(intent),
    tier: 2,
    exp,
    evaluator: 'kernel/test',
    effect: 'allow',
  }
}

// ---------------------------------------------------------------------------
// (a) base64url / did:key parity + INJECTIVITY at the real ML-DSA-87 PK size.
// ---------------------------------------------------------------------------

describe('buildDidKey — base64url/DID construction', () => {
  it('emits a well-formed multibase did:key with no non-url-safe / padding chars', () => {
    // Post-fix the encoder is injective; the surviving format is multibase did:key.
    // Accept either valid post-fix encoding: 'u' (base64url) or 'z' (base58btc) —
    // both are canonical and injective. Whichever is emitted, the body must use
    // only that base's alphabet and never +, /, or = (no standard-base64 padding).
    const did = buildDidKey(agentKp.publicKey)
    expect(did).toMatch(/^did:key:[uz]/)
    const prefix = did.charAt('did:key:'.length) // 'u' or 'z'
    const body = did.slice('did:key:'.length + 1)
    expect(body.length).toBeGreaterThan(3000)
    if (prefix === 'u') {
      // base64url alphabet only (RFC 4648 §5): A-Za-z0-9-_.
      expect(body).toMatch(/^[A-Za-z0-9_-]+$/)
    } else {
      // base58btc (Bitcoin) alphabet: no 0, O, I, l.
      expect(body).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/)
    }
    expect(body).not.toContain('+')
    expect(body).not.toContain('/')
    expect(body).not.toContain('=')
  })

  it('the signer really yields a 2592-byte ML-DSA-87 public key (grounds the test)', () => {
    expect(agentKp.publicKey.length).toBe(MLDSA87_PK_LEN)
    expect(issuerKp.publicKey.length).toBe(MLDSA87_PK_LEN)
  })

  it('is INJECTIVE over the trailing byte at the real ML-DSA-87 PK size (regression #1)', () => {
    // Fix all but the last byte; vary the final byte over 0..255. A correct
    // base encoder is a bijection on byte strings, so all 256 prefixed keys
    // (2594 bytes each) MUST map to 256 DISTINCT did:key strings.
    // The pre-fix encoder dropped the final base64 char for inputs where
    // length % 3 != 0 and collided some of these — so this assertion FAILS
    // before the #1 fix and PASSES after (it asserts post-fix behavior).
    const base = new Uint8Array(MLDSA87_PK_LEN)
    // Fill with a non-trivial fixed pattern so the variation is genuinely at the
    // boundary, not masked by a run of zeros elsewhere.
    for (let i = 0; i < base.length; i++) base[i] = (i * 31 + 7) & 0xff

    const dids = new Set<string>()
    for (let v = 0; v <= 255; v++) {
      const pk = Uint8Array.from(base)
      pk[pk.length - 1] = v
      dids.add(buildDidKey(pk))
    }
    expect(dids.size).toBe(256)
  })

  it('is also injective over the second-to-last byte (covers the other tail lane)', () => {
    // Varying the penultimate byte exercises a different position of the input
    // than the last-byte sweep above — any non-injective tail handling shows here.
    const base = new Uint8Array(MLDSA87_PK_LEN)
    for (let i = 0; i < base.length; i++) base[i] = (i * 17 + 3) & 0xff

    const dids = new Set<string>()
    for (let v = 0; v <= 255; v++) {
      const pk = Uint8Array.from(base)
      pk[pk.length - 2] = v
      dids.add(buildDidKey(pk))
    }
    expect(dids.size).toBe(256)
  })

  it('round-trips structurally: distinct public keys yield distinct DIDs', () => {
    const a = buildDidKey(agentKp.publicKey)
    const b = buildDidKey(issuerKp.publicKey)
    expect(a).not.toBe(b)
    // Same key in → same DID out (pure/deterministic).
    expect(buildDidKey(agentKp.publicKey)).toBe(a)
  })
})

// ---------------------------------------------------------------------------
// (b) projectPermit happy path.
// ---------------------------------------------------------------------------

describe('projectPermit — happy path', () => {
  it('projects a verified permit into VC / eIDAS / agent-auth descriptors', () => {
    const intent = pay(500)
    const claims = claimsFor(intent, NOW + 30)
    const sessionKey = randomBytes(48)
    const token = issueBoundPermit(claims, suite, sessionKey)

    // Sanity: the permit verifies for the exact action under the audience key,
    // i.e. it is a genuinely-bound token before we project it.
    const audienceKey = deriveAudiencePermitKey(sessionKey, claims.audience)
    expect(
      verifyPermitForAction(token, audienceKey, {
        audience: claims.audience,
        intent,
        now: NOW + 5,
      }).ok,
    ).toBe(true)

    const out = projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
      issuedAtUnixSec: NOW,
    })

    const issuerDid = buildDidKey(issuerKp.publicKey)
    const agentDid = buildDidKey(agentKp.publicKey)

    // --- W3C VC 1.1 envelope ---
    expect(out.vc.type).toEqual(['VerifiableCredential', 'NerionPermitCredential'])
    expect(out.vc.issuer).toBe(issuerDid)
    expect(out.vc.credentialSubject.id).toBe(agentDid)
    expect(out.vc.credentialSubject.actionType).toBe('payment.transfer')
    expect(out.vc.credentialSubject.resource).toBe('acct://treasury')
    expect(out.vc.credentialSubject.counterparty).toBe('vendor-acme')
    expect(out.vc.credentialSubject.amount).toBe(500)
    expect(out.vc.credentialSubject.audience).toBe('acct://treasury')
    expect(out.vc.credentialSubject.tier).toBe(2)
    expect(out.vc.credentialSubject.effect).toBe('allow')
    expect(out.vc.credentialSubject.actionHash).toBe(actionHash(intent))
    expect(out.vc.nerionPermitSuite).toBe(token.suite)
    expect(out.vc._nerionPhase).toBe('A-unsigned')
    expect(out.vc.validFrom).toBe(new Date(NOW * 1000).toISOString())
    expect(out.vc.expirationDate).toBe(new Date((NOW + 30) * 1000).toISOString())
    // No VC-native proof in Phase A.
    expect('proof' in out.vc).toBe(false)

    // --- eIDAS / EUDI descriptor ---
    expect(out.eidas.vct).toBe('https://nerion.trelyan.com/credentials/permit/v1')
    expect(out.eidas.iss).toBe(issuerDid)
    expect(out.eidas.sub).toBe(agentDid)
    expect(out.eidas.aud).toBe('acct://treasury')
    expect(out.eidas.exp).toBe(NOW + 30)
    expect(out.eidas.iat).toBe(NOW)
    expect(out.eidas.claims.actionType).toBe('payment.transfer')
    expect(out.eidas.claims.amount).toBe(500)
    expect(out.eidas.claims.actionHash).toBe(actionHash(intent))
    expect(out.eidas.nerionSuite).toBe(token.suite)

    // --- IETF agent-auth descriptor ---
    expect(out.agentAuth.sub).toBe(agentDid)
    expect(out.agentAuth.aud).toBe('acct://treasury')
    expect(out.agentAuth.exp).toBe(NOW + 30)
    expect(out.agentAuth.iat).toBe(NOW)
    expect(out.agentAuth.action).toBe('payment.transfer')
    expect(out.agentAuth.resource).toBe('acct://treasury')
    expect(out.agentAuth.counterparty).toBe('vendor-acme')
    expect(out.agentAuth.amount).toBe(500)
    expect(out.agentAuth.tier).toBe(2)
    expect(out.agentAuth.effect).toBe('allow')
    expect(out.agentAuth.actionHash).toBe(actionHash(intent))
    expect(out.agentAuth.nerionProtocol).toBe('nerion/permit/v1')
  })

  it('is pure: identical inputs yield deeply-equal projections', () => {
    const intent = pay(250)
    const claims = claimsFor(intent, NOW + 30)
    const token = issueBoundPermit(claims, suite, randomBytes(48))
    const a = projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
      issuedAtUnixSec: NOW,
    })
    const b = projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
      issuedAtUnixSec: NOW,
    })
    expect(a).toEqual(b)
  })

  it('omits validFrom/iat sensibly when issuedAt is not supplied', () => {
    const intent = pay(100)
    const claims = claimsFor(intent, NOW + 30)
    const token = issueBoundPermit(claims, suite, randomBytes(48))
    const out = projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey)
    // Source contract: do not approximate validFrom from exp.
    expect(out.vc.validFrom).toBe('unknown')
    expect(out.eidas.iat).toBe(0)
    expect(out.agentAuth.iat).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// (c) Non-finite exp must NOT throw — it fails CLOSED (regression #3).
// ---------------------------------------------------------------------------

describe('non-finite exp fails closed (regression #3)', () => {
  it('verifyPermitForAction returns a deny verdict (does not throw) for a non-finite exp', () => {
    const intent = pay(500)
    const sessionKey = randomBytes(48)
    const audienceKey = deriveAudiencePermitKey(sessionKey, 'acct://treasury')

    for (const badExp of [Infinity, -Infinity, NaN]) {
      const claims = claimsFor(intent, badExp as number)
      const token = issueBoundPermit(claims, suite, sessionKey)

      let verdict: { ok: boolean; reasons: string[] } | undefined
      // The fail-closed contract: this MUST NOT throw.
      expect(() => {
        verdict = verifyPermitForAction(token, audienceKey, {
          audience: 'acct://treasury',
          intent,
          now: NOW + 5,
        })
      }).not.toThrow()

      expect(verdict).toBeDefined()
      // A non-finite/absent expiry must never be treated as non-expiring.
      expect(verdict!.ok).toBe(false)
      expect(verdict!.reasons.join(' ')).toMatch(/expir|expiry/i)
    }
  })

  it('a finite-but-past exp also denies (sanity: the deny path is the expiry, not a crash)', () => {
    const intent = pay(500)
    const sessionKey = randomBytes(48)
    const audienceKey = deriveAudiencePermitKey(sessionKey, 'acct://treasury')
    const claims = claimsFor(intent, NOW - 1)
    const token = issueBoundPermit(claims, suite, sessionKey)
    const verdict = verifyPermitForAction(token, audienceKey, {
      audience: 'acct://treasury',
      intent,
      now: NOW + 5,
    })
    expect(verdict.ok).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// (d) Direct coverage of the F3 exp guard at its OWN call site.
//
// The (c) suite above exercises verifyPermitForAction (permit.ts). The F3 fix
// also added a non-finite/out-of-range exp guard inside projectPermit /
// tryProjectPermit (vc-projection.ts). This block tests THAT guard directly so
// the shipped behaviour change is covered where it lives:
//   - projectPermit THROWS PermitProjectionError on a bad exp (controlled,
//     typed error replacing the opaque Date RangeError), and
//   - tryProjectPermit FAILS CLOSED ({ ok: false }) on the same input.
// ---------------------------------------------------------------------------

describe('projectPermit / tryProjectPermit — bad exp guard (regression #3, own call site)', () => {
  const intent = pay(500)
  const token = issueBoundPermit(claimsFor(intent, NOW + 30), suite, randomBytes(48))

  for (const badExp of [Infinity, -Infinity, NaN, 8.64e12 + 1, -(8.64e12 + 1)]) {
    it(`projectPermit throws PermitProjectionError for exp=${String(badExp)}`, () => {
      const claims = claimsFor(intent, badExp as number)
      expect(() =>
        projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
          issuedAtUnixSec: NOW,
        }),
      ).toThrow(PermitProjectionError)
    })

    it(`tryProjectPermit fails closed (ok=false) for exp=${String(badExp)}`, () => {
      const claims = claimsFor(intent, badExp as number)
      const res = tryProjectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
        issuedAtUnixSec: NOW,
      })
      expect(res.ok).toBe(false)
      if (!res.ok) expect(res.error).toMatch(/exp/i)
    })
  }

  it('projectPermit also guards a non-finite issuedAtUnixSec', () => {
    const claims = claimsFor(intent, NOW + 30)
    expect(() =>
      projectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
        issuedAtUnixSec: Infinity,
      }),
    ).toThrow(PermitProjectionError)
  })

  it('a valid exp still projects cleanly through tryProjectPermit (guard is not over-broad)', () => {
    const claims = claimsFor(intent, NOW + 30)
    const res = tryProjectPermit(token, claims, intent, issuerKp.publicKey, agentKp.publicKey, {
      issuedAtUnixSec: NOW,
    })
    expect(res.ok).toBe(true)
    if (res.ok) expect(res.projection.eidas.exp).toBe(NOW + 30)
  })
})
