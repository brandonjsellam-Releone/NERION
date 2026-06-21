<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0015: Per-audience PermitToken keys (close PERMIT-001 cross-audience forgery)

**Status:** Accepted — finding PERMIT-001 raised by the Team Apex multi-model audit (2026-06-21,
[council/team-apex-zkrange-2026-06-21.md](../council/team-apex-zkrange-2026-06-21.md)); fix designed,
implemented, and conformance-checked (C22). Closes the last open architectural item on the
"Action enforcement" row of [ASSURANCE.md](../ASSURANCE.md).

## Context

Plane-1 `PermitToken`s are the hot-path authorization artifact: a denied action never executes, and an
allowed one is bound to a specific `{action, audience, session, exp, effect}` so a stolen token cannot be
replayed for a different action or at a different resource. To keep Plane 1 fast — **no per-action PQ
signature and no network round-trip**, exactly as the three-plane spec mandates — the token is a symmetric
MAC (`HMAC-SHA-384`) rather than a signature ([envelope.ts](../../crypto/src/envelope.ts),
[permit.ts](../../planes/src/permit.ts)).

The MAC key was the per-session `sessionKey`, **shared between the issuer (kernel/node) and the resource**.
The `audience` claim is MAC-bound, so a *non-key-holder* cannot change it. But a symmetric MAC gives the
verifier the same power as the issuer:

> **PERMIT-001 (architectural).** A key-holding — i.e. malicious or compromised — resource can re-MAC a
> permit for a **different** `audience` and present it elsewhere. The `audience` binding is only as strong
> as "nobody who can verify can also forge," which a shared symmetric key violates by construction.

This is exploitable only when one `sessionKey` spans **multiple mutually-distrusting resources** (the
intended multi-resource deployment). It is not exploitable in single-process Local mode, but the design did
not *enforce* per-audience keys, so it was a latent escalation path that grows with deployment scope.

## Decision

**Derive a per-`(session, audience)` MAC key and provision each resource with only its own derived key —
never the raw session secret.**

```
audienceKey = HKDF-SHA-384(
    IKM  = sessionKey,                                   # the session secret (issuer-held)
    salt = "" (empty; RFC 5869 §2.2),
    info = canonicalCBOR(["PolarSeek-Permit-AudienceKDF-v1", audience]),
    L    = 48 bytes)                                      # = HMAC-SHA-384 key width
```

- **Issuer (kernel/node)** holds the session secret. `issueBoundPermit` derives `audienceKey` from
  `claims.audience` and MACs under it. The session secret never leaves the issuer.
- **Resource** is provisioned, during session/attestation key distribution, with **only**
  `deriveAudiencePermitKey(sessionKey, itsAudience)`. `verifyPermitForAction` verifies under that derived
  key directly — it neither holds nor re-derives from the session secret.

New crypto surface (audited `@noble` primitives only, zero hand-rolled crypto):

- `HKDF_SHA384` (`crypto/src/symmetric.ts`) — the `Kdf` interface over `@noble/hashes` HKDF (RFC 5869).
- `deriveAudiencePermitKey(sessionKey, audience)` (`crypto/src/envelope.ts`) — the domain-separated,
  audience-bound derivation above.

### Why this closes the forgery (the load-bearing argument)

HKDF is a PRF: its output (`audienceKey`) is **one-way** with respect to the input keying material and
**independent** across distinct `info` values. A resource for audience *B* holds only `K_B`. To forge a
permit a *different* resource *A* will accept, it needs `K_A = HKDF(sessionKey, A)`. From `K_B` it can
recover **neither** `sessionKey` (one-wayness) **nor** `K_A` (PRF independence). The only permits *B* can
mint are permits MAC'd under `K_B` — i.e. permits for audience *B itself*, which is not an escalation: *B*
is the enforcement point for *B* and could always choose to act on its own. Cross-audience forgery is
therefore removed, not merely detected.

The `claims.audience === check.audience` equality check is **kept** as defense-in-depth (it catches a
misprovisioned resource and keeps the failure reason legible), but correctness no longer depends on it — the
**key** now enforces the audience binding. Domain separation via the canonical-CBOR `info` (length-prefixed,
key-order-independent) prevents any cross-context or audience-string-ambiguity confusion, mirroring the
existing `toBeMaced`/`toBeSigned` transcript discipline.

### Distribution flow (attest/ + planes/)

Session establishment is unchanged through attestation ([attest/](../../attest/src/index.ts)): attest the
agent, mint the short-lived `sessionKey`. The change is **what each resource receives**:

- **Before:** resources received `sessionKey` (the master) and verified directly under it.
- **After:** for each resource the issuer computes `deriveAudiencePermitKey(sessionKey, audience)` and
  provisions **that** out-of-band. The SDK's `GuardContext` now carries an optional `audienceKey` for a
  standalone resource that was provisioned this way; in single-process Local mode (one trust domain)
  `checkPermit` derives it on the fly from the in-process session for convenience. Either path verifies
  under the audience key, never the raw secret.

## Alternative considered — asymmetric issuer signatures

The panel's second option was to make Plane-1 permits **PQ signatures** (e.g. ML-DSA-87) verified with the
issuer's *public* key. This is strictly stronger: resources hold no secret at all, so even self-audience
fabrication is impossible and permits become non-repudiable. We **rejected it as the Plane-1 default** on the
hot-path performance grounds the whole plane exists to satisfy:

| | Per-audience HKDF + HMAC (**chosen**) | Asymmetric (ML-DSA-87) |
|---|---|---|
| Issue cost | 1 HKDF (≈2 HMAC) + 1 HMAC ≈ **µs** | ML-DSA sign — **~1–2 orders slower** |
| Verify cost | 1 HMAC, constant-time ≈ **µs** | ML-DSA verify — heavier |
| Token size | 48-byte tag | **~4.6 KB** ML-DSA-87 signature |
| Resource holds | its derived MAC key (a secret) | nothing (public key only) |
| Closes PERMIT-001 | **Yes** (cross-audience) | Yes (cross- **and** self-audience) |
| Non-repudiation | No | Yes |

HKDF adds ~2 HMAC compressions per issuance and **zero** to the size or network profile — Plane 1 stays a
pure symmetric hot path. The asymmetric construction already exists in the codebase
(`signEnvelope`/`verifyEnvelope`, the same path Plane-2 receipts use) and remains available for a resource
that genuinely needs non-repudiation or a zero-secret posture; such a resource can demand a signed envelope
instead of a permit. We keep that as an **opt-in per-resource upgrade**, not the hot-path default. If a
future deployment needs non-repudiation by default, that is a follow-up ADR (a `suite`-selected permit
algorithm), not a reason to tax every Plane-1 admission today.

Derived keys may be cached per `(session, audience)` to amortize even the ~2-HMAC HKDF cost; the reference
implementation derives per call for simplicity, which is already negligible.

## Consequences — honest caveats (binding)

- **Trust boundary, not a panacea.** Per-audience keys stop a resource from forging *across* audiences. They
  do not (and cannot, symmetrically) stop a resource from acting within its own authority — that is the
  resource's own decision and outside Plane 1's threat model. A deployment that needs to stop *self*-minting
  must use the asymmetric opt-in above.
- **Correct distribution is now load-bearing.** The security property holds **iff** resources are
  provisioned with derived keys and never the raw `sessionKey`. Handing a resource the session secret
  re-opens PERMIT-001. This is a deployment obligation, documented in [DEPLOY.md](../DEPLOY.md).
- **Additive + fail-closed.** The raw-MAC primitives (`issuePermit`/`verifyPermit`) are unchanged; only the
  Plane-1 binding layer derives. A resource that mistakenly verifies under the wrong key simply fails closed.
- **No new cryptographic primitive.** HKDF-SHA-384 (RFC 5869) over the same audited `@noble` SHA-384 already
  used for the MAC. No bespoke construction; the composition itself is still **not externally audited**.
- **FTO still required** before any public claim — design-around is engineering intent, not a legal opinion
  ([FTO_TODO.md](../FTO_TODO.md)).

## Conformance

**C22** asserts the property end-to-end: distinct audiences derive distinct keys; a permit issued for
audience *A* verifies under *A*'s key and is **rejected** under *B*'s key; and a permit re-MAC'd by a holder
of only *B*'s key (the PERMIT-001 attacker) is **rejected** by *A*'s resource. This fix adds **C22**; with the
concurrently-landed salted-intent check **C23** (RCPT-001 / ADR-0014), the conformance suite stands at
**23/23**.

## Credits

Team Apex multi-model audit (DeepSeek · Grok · Hermes panel on the enforcement boundary) surfaced PERMIT-001
and converged on per-audience HKDF derivation vs. asymmetric signatures as the two fixes. This ADR adopts the
HKDF path to preserve the Plane-1 hot-path rationale and records the asymmetric option as an opt-in upgrade.
