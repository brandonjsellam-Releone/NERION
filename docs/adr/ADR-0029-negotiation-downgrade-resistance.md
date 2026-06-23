<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0029: suite-negotiation downgrade resistance (R3)

**Status:** Accepted — transcript primitive IMPLEMENTED 2026-06-23 (`negotiationTranscript` /
`verifyNegotiationTranscript` in `crypto/src/suites.ts`); the handshake message that carries the
signed transcript is a forward requirement (no live negotiation handshake exists yet).

## Context

`negotiate(local, remote)` returns the most-preferred *active* suite both peers support. Every signed
or encrypted Nerion object also carries its SuiteID, which is bound into the signed bytes — so a
downgrade of an object **at rest** is already detected (a relabelled object fails its signature).

The gap (auditor-dossier **R3**) is the **live negotiation exchange itself**. The offered suite lists
are sent peer-to-peer; if that exchange rides an **unauthenticated** channel, a MITM can **strip** the
stronger suites from one peer's offered list, so `negotiate` — which faithfully picks the best of what
it is *given* — settles on a weaker common suite. `negotiate` cannot detect this; nothing binds the
*offered lists* to the authenticated session.

## Decision

Add a **negotiation transcript** committing a fresh session binder + both peer identities + both
peers' full offered lists + the chosen suite:

```
negotiationTranscript({ sessionId, initiatorId, responderId,
                        initiatorOffered, responderOffered, chosen })
  = SHA3-256( canonicalCBOR([ "polarseek/suite-negotiation", 1,
                              sessionId, initiatorId, responderId,
                              initiatorOffered, responderOffered, chosen ]) )
```

- Lists are bound **as-offered** (never sorted) and **role-labelled** (initiator vs responder), so a
  strip (a removal) or a reorder changes the hash, and both peers compute the same value from their
  own view.
- **`sessionId`** is a FRESH per-session binder (e.g. SHA3 of both peers' handshake nonces); it makes
  a PRIOR session's signed transcript un-replayable (council R3 review — cross-session replay).
- **`initiatorId` / `responderId`** (long-term public-key identities) bind the transcript to this
  exact peer pair, defeating cross-peer signature replay (council R3 review).
- **Requirement:** the first authenticated handshake message MUST be signed over (or include) this
  transcript. Each peer, **after** verifying the peer's signature, recomputes the transcript from its
  own view and constant-time-compares via `verifyNegotiationTranscript`. A mismatch ⇒ the offered
  lists seen by the two peers differ ⇒ a MITM downgrade ⇒ **abort**. This is the TLS-1.3
  "Finished over the full handshake transcript" defense.

## Consequences

- Closes the negotiation-layer downgrade **once the handshake binds the transcript**. The primitive
  and its binding property are implemented and adversarially tested now (a stripped/reordered offer
  and a swapped chosen suite are all rejected; the silent `negotiate` downgrade is shown to be caught
  by the cross-check); the handshake message that transmits the signed transcript is future wiring —
  the same staging used for the KEM-seal (ADR-0028).
- **No wire/KAT change**: new functions only; `SuiteID Ps1` + `conformance/vectors/ps-*.json` are
  untouched.
- `verifyNegotiationTranscript` does **not** verify the signature — the caller must verify the
  peer's signature over the transcript independently; this function only detects the downgrade once
  that signature is confirmed authentic.
