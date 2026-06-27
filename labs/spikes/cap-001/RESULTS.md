<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# CAP-001 — RESULTS (premise corrected; a real council-validated hybrid upside)

> **TOY / MOCK — UNAUDITED, pre-FTO.** No novelty/non-infringement claim. © TRELYAN.
> (Spike id CAP-001 — unrelated to the code's "CAP-001" suite-binding audit comment.)

## Premise correction (read-only intake)
`capabilities/src/capability.ts`: Nerion **already** has offline-attenuable delegation — via ML-DSA-87
**signature-chains** (each delegation link is a separate PQ signature by the holder of the parent subject
key; `attenuate()` is offline; `verifyChain()` checks each link against a **trusted root PUBLIC key**).
So "Macaroons *add* attenuation Nerion lacks" is **false**. The real question is the **architecture
tradeoff**: signature-chain (Nerion) vs HMAC-chain (Macaroon).

## Measured (HMAC-chain Macaroon, node:crypto HMAC-SHA-384)
- Offline attenuation verifies ✓; a removed caveat and a forged caveat are both rejected ✓.
- **Macaroon:** tiny (64–241 B at depth 1–16), fast (verify 9–57 µs = d HMACs).
- **Nerion sig-chain:** d × ~7.4 KB (d=1 → 7.4 KB; d=16 → 119 KB), 116–493× larger; verify = d ML-DSA-87
  verifies (≫ HMAC).

| depth d | macaroon | sig-chain | **hybrid (signed-root + HMAC caveats)** |
|---|---|---|---|
| 1 | 64 B | 7.4 KB | 7.4 KB (1×) |
| 4 | 97 B | 29.7 KB | **7.6 KB (3.9× smaller)** |
| 16 | 241 B | 119 KB | **~8.1 KB (~14.6× smaller)** |

## Council adjudication
- **DeepSeek (ship):** the **"Macaroons can't do decentralized verification" claim is correct** — HMAC-chain
  verify needs the root secret; **third-party caveats / discharge macaroons do NOT remove that requirement**
  (they only shift *condition evaluation* to another secret-holder; the primary chain's integrity still
  needs the root secret). The pure-HMAC intra-domain fast-path carries **key-distribution / blast-radius**
  risk (any verifier's compromise leaks the secret → chain-wide forgery). Prefer the phrase "public
  verifiability *without shared secrets*."
- **Grok (a real hybrid upside; size cost is more material than I first allowed):** a **signed-root + HMAC
  caveat hybrid** — one ML-DSA signature over the root grant (publicly verifiable vs the trusted PK) then
  HMAC-chained first-party caveats — **keeps public verifiability AND shrinks attenuation** (measured: 3.9×
  at d=4, ~14.6× at d=16; savings appear at depth ≥3–4). And the sig-chain size *does* matter even at depth
  1–3 (7–15 KB tokens in mTLS/AuthZ headers, mobile/IoT, audit logs, revocable-token storage) — "not
  gossiped" under-reached.

## Verdict — pure sig-chain stays the safe DEFAULT; GRADUATE a genuine hybrid optimization
- **No kill.** Nerion's signature-chain is correct and is the **simplest safe default**: publicly verifiable
  without shared secrets (decentralized validators), delegate identity + non-repudiation. Macaroons' pure
  HMAC-chain **cannot** do decentralized verification — a dealbreaker here — confirmed by council.
- **Genuine upside (council-validated, measured) → GRADUATE to R&D:** a **signed-root + HMAC-caveat hybrid**
  that preserves public verifiability while cutting deep-delegation token size **3.9–14.6×** (depth ≥3–4).
  Caveats to weigh: HMAC caveats are **first-party only** (third-party caveats / revocation need more);
  careful **root-key binding** to prevent extraction; and it adds implementation surface. Ties to LED-001
  (ML-DSA-87's 4627-byte signatures dominate size across the protocol).

## Honesty caveats
Macaroon size/speed are real measurements; sig-chain and hybrid sizes use the real FIPS-204 ML-DSA-87
constant (4627 B) + an approximate grant body; verify-time contrast is qualitative (Macaroon measured,
ML-DSA verify not run here). No competitiveness/audit/novelty/FTO claim.
