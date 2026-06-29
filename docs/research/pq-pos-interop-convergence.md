<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion convergence note — QRL-Zond × Algorand × PQCryptoLib × cross-chain interoperability

**Status:** research / design direction (NOT implemented; no FIPS or production claim). 2026-06-30.
**Inputs:** PQShield *PQCryptoLib-SDK* Product Brief v3.0 (Mar 2026); *Blockchain interoperability*
(Marshall, Butterworths JIBFL, Jul/Aug 2022); [theQRL](https://github.com/theQRL) (QRL Zond).

> Honesty banner: this maps where Nerion's ledger already sits relative to QRL-Zond and Algorand,
> and identifies concrete, *buildable* increments. It makes no claim that Nerion is FIPS-validated,
> audited, or production-ready — those remain open (see ASSURANCE.md). "FIPS path" means a route to
> validation, not a validation.

## 1. Where Nerion already sits (the convergence is mostly already true)

| Property | **QRL Zond** | **Algorand** | **Nerion today** |
|---|---|---|---|
| Signatures | post-quantum (ML-DSA/Dilithium via `go-qrllib`; XMSS heritage) | classical Ed25519 | **ML-DSA-87 (FIPS-204 alg) + SLH-DSA-SHAKE-256f available** (CNSA 2.0) |
| Consensus | Ethereum-style PoS (Casper-FFG finality, via `qrysm` = Prysm fork) | pure PoS + VRF cryptographic sortition, immediate finality, no forking | **PoS + VRF sortition (Algorand-style) + Casper-style accountable finality** |
| Finality property | accountable (Casper slashing) | immediate, player-replaceable | **AccountableSafety machine-checked in TLA⁺** (`docs/formal/`) |
| Set/epoch binding | beacon-chain epochs | — | **`consensusSetId` folds members+stake+epoch into every signed message (ADR-0020/B5)** |
| Execution | EVM-compatible (`qrl-contracts`, `web3.js`) | AVM (TEAL) | **none — Nerion governs the *verb*, it is not a smart-contract VM** |

**Reading:** Nerion is already the intersection the request asks for — **QRL-Zond's post-quantum +
accountable-PoS** crossed with **Algorand's VRF sortition + immediate finality**. It is *not* a
general L1/EVM; it is an execution-**governance** layer. So "merge QRL + Algorand" for Nerion is not
"rebuild the chain" — it is **adopt the specific strengths each has that Nerion still lacks**, below.

## 2. What to adopt from each input

### 2.1 From QRL / PQCryptoLib (PQShield) — the FIPS-validation + hybrid path
PQCryptoLib-SDK is a **FIPS 140-3 CAVP/CMVP-ready** OpenSSL 3.x provider for ML-DSA, ML-KEM, Falcon,
SLH-DSA, and **hybrid EC+ML-KEM TLS** (`draft-ietf-tls-ecdhe-mlkem`). Nerion today delegates crypto
to `@noble/post-quantum` (audited, but **not** FIPS-validated). Concrete increments:
- **A crypto-provider seam** so the same `SuiteID` can be backed by either `@noble` (default, today)
  or a **FIPS-validated provider** (PQCryptoLib-SDK / an OpenSSL PQC provider) for deployments that
  need CAVP/CMVP — without changing the protocol or the frozen vectors. This is the honest route
  from "CNSA-2.0 *aligned*" to "CNSA-2.0 *validated*" the gov/SBIR track needs.
- **Hybrid PQ/T transport**: adopt EC+ML-KEM hybrid for the session/transport layer (defense-in-depth
  during the transition), matching the TLS draft PQShield ships.
- **Hash-based conservative option** (QRL's original hallmark): SLH-DSA-SHAKE-256f (already a Nerion
  suite) as the *settlement-anchor* signature for the highest-assurance tier — hash-based security
  rests on no new number-theoretic assumption, the most conservative PQ choice for long-lived anchors.

### 2.2 From Algorand — already in; harden the finality story
Nerion has VRF sortition (`selectLeader`/`vrfLeaderEligible`) and accountable finality. The recent
`consensusSetId`+epoch binding and the per-validator gossip caps (GOSSIP-CENSOR-002) close the
set-substitution and censorship gaps. Remaining Algorand-flavored items already tracked: immediate
single-shot finality formalization and the round-skip fairness caveat (`docs/CONSENSUS-CAVEATS.md`).

### 2.3 From the interoperability paper — the headline synthesis
The paper's core security lesson: **trusted-multisig bridges are the weak point** — Wormhole ($320M)
+ Ronin ($625M) ≈ **$1B** lost — and the durable path is **light-client verification + cryptographic
finality proofs** (the Polkadot/Cosmos "network-of-networks" model; Chainlink CCIP as a candidate
TCP/IP-for-chains). **Nerion already has the two primitives a secure interop anchor needs:**
1. `verifyFinalized` — a **stateless light-client verifier** (block + attestations → finalized?),
2. **k-of-n ML-DSA-87 quorum receipts + RFC-6962 Merkle inclusion** — externally verifiable, no
   operator trust.

So the strongest "QRL × Algorand × interop" synthesis for Nerion is a **post-quantum cross-chain
finality-attestation primitive**: a portable, self-contained, ML-DSA-signed proof that "Nerion
finalized action/decision X under validator-set/epoch E", verifiable **offline by a bridge or another
chain** — categorically stronger than the multisig bridges that lost $1B, because the trust root is a
**post-quantum threshold signature over a transparency-logged decision**, not a small custodial
committee. This is the "PQ interchain on-ramp" the paper says TradFi will need.

## 3. Concrete, buildable increments (roadmap)

1. **Portable PQ finality proof** (next build) — a self-contained `{header, consensusSetId, epoch,
   attestations}` bundle + an offline `verifyPortableFinality()` wrapping the hardened
   `verifyFinalized`, with a stable serialization a non-Nerion verifier can consume. *This is the
   interop primitive; it reuses code Nerion already has and is self-contained.*
2. **EVM/web3 verifier sketch** — since QRL-Zond and most TradFi rails are EVM, specify (later) a
   Solidity/precompile verifier for the portable proof so an EVM chain can check Nerion finality
   on-chain (the bridge "destination" side). Forward-looking; not built.
3. **FIPS crypto-provider seam** (§2.1) — interface so a CAVP/CMVP provider can back the SuiteIDs.
4. **Hybrid PQ/T transport** + **SLH-DSA settlement-anchor option** (§2.1).

## 4. What this is NOT
Not a pivot to an EVM L1, not a token, not a bridge operator. Nerion stays the **govern-the-verb**
execution-governance layer; the interop work makes its **finality + decision receipts portable and
externally verifiable** so other chains/bridges/TradFi rails can *consume* Nerion's guarantees. All
FIPS/audit items remain open and honestly caveated.

## 5. Team
Council seat **Qwen2.5-Coder** (`qwen2.5-coder-32b-instruct`) added 2026-06-30 as a coding/review
specialist (wiring: DashScope / OpenRouter / HuggingFace — see council roster). Both source PDFs are
recorded here as design inputs.
