<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Permit caveats — offline, holder-side least-privilege attenuation

**Status:** UNAUDITED reference (Team Apex R&D council, 2026-06-28). New capability, additive. Code:
[`planes/src/caveat.ts`](../planes/src/caveat.ts) · tests: `planes/test/caveat.test.ts`. (Design note,
not yet an ADR — ADR numbering is reconciled separately.)

## What it adds

A capability holder that received a kernel-issued **PermitToken** can **narrow it further and hand
the narrowed permit to a sub-agent / tool — offline, without a kernel round-trip, and without the
audience MAC key.** The resource (which holds the audience key) verifies the result and enforces the
base permit's claims **and every caveat conjunctively**, so a caveat can only ever **restrict**.

This is the decentralized, offline, third-party-verifiable least-privilege delegation an agent swarm
needs, and it is the categorical move a central-permission gatekeeper cannot make: in a closed system
every narrowing is another call to the trusted gatekeeper; here the holder narrows locally and the
narrowing is cryptographically enforced by the resource with no new trust.

## How (macaroon chaining over the existing permit MAC — no new primitive)

```
M0  = HMAC-SHA-384(audienceKey, toBeMaced(suite, body))   // the kernel-issued permit's root MAC
M_i = HMAC-SHA-384(M_{i-1}, caveatChainMessage(caveat_i))  // each holder-added caveat
```

- `attenuate(permit, caveat)` (holder-side, **no audience key**): folds a caveat using the MAC the
  holder currently has (`M0` from its base permit, or `M_{n-1}`). Returns
  `{ suite, body, caveats, mac: M_n }` — **crucially NOT `M0`**.
- `verifyAttenuatedPermit(ap, audienceKey, check)` (resource-side): **recomputes `M0` from its
  audience key** (never trusts a transmitted `M0` — none is carried), re-folds the caveats, and
  constant-time compares to `M_n`; then runs the full base-permit enforcement (MAC, audience,
  `actionHash`, expiry, effect, size cap) and enforces every caveat.

Because the forwarded artifact carries only `M_n` (not `M0`), a recipient sub-agent **cannot strip
caveats** (it cannot reverse HMAC to recover `M_{k<n}`) and **cannot fall back to the un-attenuated
permit** (it never receives `M0`, and `M_n ≠ M0`).

## Caveat kinds

| kind             | restriction                                | status                                                 |
| ---------------- | ------------------------------------------ | ------------------------------------------------------ |
| `expiresAtMost`  | action time `now ≤ value`                  | **primary, non-redundant** — offline expiry tightening |
| `amountAtMost`   | `intent.amount ≤ value`                    | sound; redundant with `actionHash` today (see Scope)   |
| `counterpartyIs` | `intent.counterparty === value`            | sound; redundant today                                 |
| `actionPrefix`   | `intent.type` is `value` or a dotted child | sound; redundant today                                 |

## Scope & honesty

A Nerion PermitToken is bound to the **exact** action via `actionHash(intent)`, so amount /
counterparty / action-type are already point-fixed by the base permit. The genuinely
**non-redundant, value-adding** caveat today is therefore **`expiresAtMost`** — e.g. handing a
sub-agent a 5-second permit derived from a 5-minute one, offline. The other caveat kinds are
mechanically sound and **never broaden** (enforcement is conjunctive), but for an exact-action permit
they can only further forbid the one action the permit is already for; they are retained as
defense-in-depth and forward-compatibility for any future action-**family** permit. **The macaroon
mechanism itself — offline, unforgeable, third-party-verifiable, monotone attenuation — is the
categorical contribution.**

## Security

- **Soundness** reduces to the same HMAC-SHA-384 the PermitToken already uses (macaroon EUF): you
  cannot extend the chain without `M_{i-1}`, nor drop/reorder/tamper a caveat without invalidating
  `M_n`. First-party caveats only (no third-party/discharge caveats).
- **Monotone by construction:** the resource always enforces the base permit **plus** the
  conjunction of all caveats — a caveat cannot broaden authority.
- **Fail-closed:** bad base permit, invalid chain, over-long chain (`> MAX_CAVEATS`), or any violated
  / malformed caveat → reject. Caveat numeric values must be safe integers.
- **UNAUDITED** reference, like the rest of the disclosure/SDK layer. Pinned by
  `planes/test/caveat.test.ts` (offline tightening, strip-resistance, tamper/drop rejection,
  conjunctive stacking, wrong-key rejection, DoS bound).

## Threat model note

Caveats bind **only when the verifier checks them** (`verifyAttenuatedPermit`). The intended flow is:
a holder attenuates and forwards **only** the attenuated permit (`{suite, body, caveats, M_n}`) to a
less-trusted sub-agent. The holder, which legitimately possesses its own base permit, can of course
still use that base permit directly — caveats restrict what the **sub-agent** receives, not what the
holder already holds.
