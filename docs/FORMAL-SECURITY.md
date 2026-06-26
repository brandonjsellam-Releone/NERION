<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Formal Security Analysis

**Version:** 0.1.0-draft  
**Date:** 2026-06-24  
**Authors:** Senior Cryptographer review, TRELYAN  
**Status:** DRAFT — not audited, not production-ready  
**Scope:** Cryptographic properties of the Nerion protocol stack as implemented in the
TypeScript reference (`crypto/`, `kernel/`, `receipts/`, `planes/`, `disclosure/`,
`translog/`) and the accompanying ADR corpus. This memo covers the theoretical security
basis; it does **not** certify the implementation against any external standard.

---

> **Universal disclaimer, binding on this entire document.**  
> Nerion is **UNAUDITED**, **not FIPS-validated**, and is at **Local/Private dev maturity**.
> No claim in this document constitutes a legal non-infringement opinion (FTO review is
> pending — see `FTO_TODO.md`). No claim is a FIPS CMVP or NSA validation statement. Claims
> are marked `PROVEN`, `CONJECTURED`, or `OPEN` per the taxonomy in §0. Where "PROVEN" is
> used, the underlying standard result is cited; the *application* of that result to Nerion's
> specific code paths is at most `CONJECTURED` until external audit confirms the
> implementation matches the assumed model. "PROVEN" never means "proven in this codebase" —
> it means there exists a peer-reviewed result that would cover Nerion's usage *if* the
> implementation faithfully realizes the abstraction.

---

## §0. Claim taxonomy

Every substantive security claim below carries one of three labels:

| Label | Meaning |
|---|---|
| **PROVEN** | A peer-reviewed result (cited) establishes the property under a stated model and assumption. Nerion's code is designed to instantiate that model; correctness of the instantiation is confirmed only by implementation review and testing, not by formal verification. |
| **CONJECTURED** | The property is plausible, follows standard cryptographic practice, and is consistent with the threat model and ADR corpus, but no peer-reviewed result has been directly applied to Nerion's exact construction, or the construction is bespoke and UNAUDITED. |
| **OPEN** | A known gap: either the property has not been established, or it is explicitly awaiting external audit, formal verification, or a future standard result. |

---

## §1. ML-DSA-87 Usage Analysis

### §1.1 How Nerion uses ML-DSA-87 (FIPS 204)

ML-DSA-87 is Nerion's **nearline-plane (Plane 2) signature scheme**. It appears at three
distinct layers.

**Receipt signing (`receipts/src/receipt.ts`, `crypto/src/envelope.ts`).** Every
`ReceiptBody` — the exact bytes that form the transparency-log leaf — is signed under
ML-DSA-87 via `signerFor(suite).sign(encodeCanonical(body), issuerSecretKey)`. The
`signerFor` dispatch is suite-identified: the `suite` field (e.g. `"PS-1"` or `"PS-5"`)
is resolved at call-time through the `REGISTRY` in `crypto/src/suites.ts`, which maps it
to `ml_dsa87` from `@noble/post-quantum`. The signed payload is not the raw body object
but its deterministic CBOR encoding (`encodeCanonical`), so the signed bytes are canonical
and implementation-independent.

**Signed envelopes (`crypto/src/envelope.ts`, `signEnvelope` / `verifyEnvelope`).** The
envelope layer is used for nearline-plane capabilities, attestation results, and any
object that needs non-repudiation. The to-be-signed structure is:

```
TBS = encodeCanonical(["PolarSeek-Signed-v1", suite, context, payload])
sig = ML-DSA-87.sign(TBS, secretKey)
```

The `"PolarSeek-Signed-v1"` string and the `context` parameter together form a
**domain separator** binding the signature to its usage context. An envelope signature
cannot be transferred to a different protocol layer without breaking verification, because
the signed transcript differs.

**Long-lived root-of-trust signing (`crypto/src/sign.ts`, SLH-DSA-SHAKE-256f).** For
long-term or root-of-trust keys (e.g. governance, release signing — per ADR-0010),
`SLH_DSA_SHAKE_256F` is registered alongside `ML_DSA_87`. SLH-DSA provides hash-based,
stateless, quantum-conservative signatures (FIPS 205) and is used where key rotation is
infrequent. This section focuses on ML-DSA-87; SLH-DSA's properties are analogous at
their respective security levels.

**Permit tokens are NOT signed with ML-DSA-87.** Plane 1 PermitTokens use
`HMAC-SHA-384` — a deliberate design choice for hot-path latency. The asymmetric
alternative (ML-DSA-87 permits) was considered and rejected for the default path in
ADR-0015 due to throughput constraints. Non-repudiation of admission decisions lives
exclusively in Plane 2 receipts.

### §1.2 Formal security properties: EUF-CMA

**Standard result (PROVEN under ML-DSA parameter set).** FIPS 204 (ML-DSA) is based on
the **Module Learning With Errors (MLWE)** and **Module Short Integer Solution (MSIS)**
problems. Ducas et al. (Crystals-Dilithium, TCHES 2018) and the NIST FIPS 204 security
analysis establish that ML-DSA achieves **existential unforgeability under adaptive
chosen-message attack (EUF-CMA)** in the random-oracle model (ROM), reducible to MLWE
and MSIS. For ML-DSA-87 (parameter set III), the claimed security level is NIST Level 5
(≥ 256-bit classical, ≥ 128-bit quantum against best-known attacks).

The formal reduction shows: an adversary that can forge a ML-DSA-87 signature on a
message not previously signed, given access to a signing oracle, can be turned into a
solver for MLWE or MSIS with probability negligibly larger than that of breaking the
underlying hard problem. The MLWE/MSIS problems are believed to be **hard for quantum
computers** (no known quantum speedup beyond Grover's quadratic reduction on the generic
lattice-sieving algorithms, which does not break the 128-bit PQ floor at Level-5
parameters). **PROVEN** (Ducas et al. TCHES 2018; NIST FIPS 204 §3; see also Bai and
Galbraith 2014 for the reduction framework).

**Nerion's instantiation.** The `ml_dsa87` object from `@noble/post-quantum` implements
FIPS 204. The library produces deterministic signatures (the signing algorithm is
randomized via an internal seed but the API wraps it to produce deterministic output per
keypair+message, consistent with the "deterministic ML-DSA" variant described in FIPS
204). Deterministic signing eliminates the class of attacks where a bad RNG exposes the
secret key (cf. the ECDSA-RNG disaster class). Whether `@noble/post-quantum`'s ML-DSA-87
faithfully implements FIPS 204 byte-for-byte has not been independently audited by
TRELYAN. **CONJECTURED** (Nerion's usage is consistent with the EUF-CMA model; fidelity
of `@noble` to FIPS 204 is a library audit item).

### §1.3 Nerion-specific usage guarantees

**Domain separation.** The `signEnvelope` path embeds `["PolarSeek-Signed-v1", suite,
context, payload]` into the signed transcript. The `suite` field prevents cross-suite
signature transfer. The `context` field (e.g., `""` for receipts, custom strings for
capabilities) prevents cross-context reuse. The `receipt.ts` path signs
`encodeCanonical(body)` directly rather than via `signEnvelope`, but the receipt body
contains the `suite` identifier and `v: 1` version tag, providing implicit domain
separation. **CONJECTURED** (pattern follows standard domain-separation practice; no
formal collision analysis has been performed across all Nerion context strings).

**Message binding.** The to-be-signed bytes are the canonical dCBOR encoding of the
structured payload. The dCBOR encoder (`crypto/src/cbor.ts`) enforces sorted map keys,
shortest-form integers, definite-length items, and canonical floats. This closes the
serialization-ambiguity threat (T-SER-1 in the threat model): two distinct logical values
produce distinct byte encodings. The receipt body itself binds `{v, suite, evaluatorVersion,
effect, tier, jurisdiction, timestamp, commitments}`, and the commitments are SHA3 hashes
of the intent, capability, policy, input hash, and decision hash. A valid receipt signature
therefore non-repudiably attests to all of these fields simultaneously. **PROVEN** for the
binding property of digital signatures (standard result); **CONJECTURED** for dCBOR
injectivity in Nerion's exact encoder (tested by `cbor-determinism.test.ts` but not
formally verified).

**No key reuse across planes.** The threat model (§3 of `THREAT_MODEL.md`) mandates plane
key isolation: Plane 1 HMAC keys, Plane 2 ML-DSA-87 keys, and Plane 3 threshold/MPC keys
are distinct. The source enforces this structurally — `envelope.ts` calls `signerFor(suite)`
which dispatches through `suites.ts`; the HMAC path (`symmetric.ts`) is entirely separate.
**CONJECTURED** (structural separation is present in code; that no deployment code
accidentally shares keys across planes has not been formally verified).

**Issuer-key binding in external verification.** `verifyReceiptInclusion` (in
`receipts/receipt.ts`) explicitly checks `bytesEqual(r.signerPublicKey, trustedIssuerKey)`,
so a receipt signed by an unexpected key is rejected even if the signature itself verifies.
This prevents a cross-issuer substitution attack. **CONJECTURED** (correct as coded; no
formal analysis of the trust anchor distribution mechanism).

### §1.4 Residual risks

**Deterministic signing (positive).** ML-DSA-87 deterministic signing is used via the
`@noble` API. Determinism eliminates entropy-dependent side-channel and RNG-failure attacks.
No residual risk from this property; it is strictly preferable to randomized signing in an
adversarial environment. **CONJECTURED** (consistent with FIPS 204's deterministic mode).

**Nonce handling.** ML-DSA does not use per-signature nonces in the same sense as ECDSA.
The security parameter is the seed provided to key generation. No residual nonce risk
specific to ML-DSA-87 is identified beyond standard key-management obligations. **OPEN**
(pending library-level audit of `@noble/post-quantum` to confirm determinism properties).

**Side channels.** The `@noble` libraries advertise constant-time operations. TRELYAN has
not independently measured or verified constant-time execution of ML-DSA-87 operations on
the target hardware. Side-channel attacks against lattice-based schemes (cache timing,
power analysis) are an active research area. `ASSURANCE.md` explicitly records: "side-
channel resistance unassessed." **OPEN** (residual R9 from threat model; designated for
review before production).

**Library trust.** The implementation relies entirely on `@noble/post-quantum` for ML-DSA-87
correctness. A bug in that library — even one conformant to FIPS 204 on test vectors —
could exhibit exploitable behavior under adversarially crafted inputs. An independent audit
of the `@noble` ML-DSA-87 implementation against FIPS 204 is not on file. **OPEN**.

---

## §2. ML-KEM-1024 Key Encapsulation Analysis

### §2.1 Session key derivation and HKDF-SHA-384 binding

Nerion uses **hybrid KEMs**, not raw ML-KEM-1024. Two hybrid constructions are
registered (ADR-0001, ADR-0002, `crypto/src/kem.ts`):

- **PS-1 (general tier):** `XWING-MLKEM768-X25519` — the X-Wing construction
  (IETF draft), combining X25519 and ML-KEM-768. Security level: NIST Cat-3 classical /
  Cat-3 PQ (floor set by ML-KEM-768).
- **PS-5 (regulated, CNSA 2.0 Cat-5 tier):** `MLKEM1024-P384` — ML-KEM-1024 combined
  with ECDH P-384. Security level: NIST Cat-5 classical / Cat-5 PQ (ML-KEM-1024).

Both are sourced from `@noble/post-quantum/hybrid` — vetted library combiners, not
hand-assembled. The decision explicitly prohibits rolling a custom KEM combiner
(ADR-0001 guardrail: "never roll our own primitive").

**HKDF-SHA-384 audience binding (ADR-0015).** Plane 1 PermitToken MAC keys are not
derived directly from a shared session secret. Instead, `deriveAudiencePermitKey` applies
HKDF-SHA-384 with a domain-separated `info` field:

```
audienceKey = HKDF-SHA-384(
    IKM  = sessionKey,
    salt = "" (RFC 5869 §2.2 empty-salt),
    info = encodeCanonical(["PolarSeek-Permit-AudienceKDF-v1", audience]),
    L    = 48 bytes)
```

This is implemented in `crypto/src/envelope.ts` `deriveAudiencePermitKey` and uses
`HKDF_SHA384` from `crypto/src/symmetric.ts` (wrapping `@noble/hashes` HKDF, RFC 5869).
The canonical CBOR `info` encoding is length-prefixed and key-order-independent, so
distinct audience strings produce distinct, non-colliding `info` bytes. Each resource is
provisioned with only its derived `audienceKey`; the session secret never leaves the
issuer.

### §2.2 IND-CCA2 property and how Nerion preserves it

**Standard result (PROVEN).** FIPS 203 (ML-KEM) is based on the CRYSTALS-Kyber
construction (Bos et al., EURO S&P 2018; Schwabe et al. IACR 2021). The ML-KEM-1024
encapsulation mechanism achieves **IND-CCA2 (indistinguishability under adaptive
chosen-ciphertext attack)** in the quantum random-oracle model (QROM), reducible to
the Module-LWE (MLWE) problem — which is believed hard for quantum computers. This is
the gold standard for KEM security: an adversary cannot distinguish the encapsulated
key from a random key even with access to a decapsulation oracle for all ciphertexts
except the challenge. **PROVEN** (Hofheinz, Hövelmanns, Kiltz 2017 for the Kyber
IND-CCA transform; NIST FIPS 203 §3 for the ML-KEM-1024 instantiation; QROM security
in Jiang et al. CRYPTO 2018).

**Hybrid combiner security.** In X-Wing and MLKEM1024-P384, the shared secret is
combined from both legs via an internal KDF. The security argument for such hybrid
constructions is: the combined shared secret is indistinguishable from random as long as
*at least one* leg is secure. A classical adversary breaking ECDH does not help if
ML-KEM is secure; a quantum adversary breaking ML-KEM-1024 does not help if the
classical leg remains (though the classical leg falls to Shor's algorithm for a CRQC).
**PROVEN** for the combiner security property (Bindel et al. PQCrypto 2019; X-Wing
formal analysis, Barbosa et al. 2024); **CONJECTURED** for `@noble`'s specific combiner
implementation matching the proven construction.

**IND-CCA2 preservation in Nerion.** Nerion uses the KEM only through the library
interface: `encapsulate(publicKey) → {cipherText, sharedSecret}` and
`decapsulate(cipherText, secretKey) → sharedSecret`. No direct manipulation of the
ciphertext or shared secret outside the KEM primitive occurs. The `sharedSecret` feeds
into higher-level key derivation (HKDF) without modification. **CONJECTURED** (the
usage pattern is consistent with IND-CCA2 preservation; no formal analysis of the
full key-establishment flow including the session establishment handshake has been
performed).

### §2.3 Audience-bound permit key isolation (per-audience HKDF, ADR-0015)

**Security property addressed.** PERMIT-001, surfaced by Team Apex audit 2026-06-21:
a resource holding the raw `sessionKey` could re-MAC a permit for a *different*
audience's resource, because HMAC-SHA-384 over the same key grants the verifier the
same forgery power as the issuer.

**Construction.** HKDF is a **pseudorandom function** (PRF) family (Krawczyk 2010; IETF
RFC 5869). The one-wayness of HKDF means: given `K_B = HKDF(sessionKey, B)`, it is
computationally infeasible to recover `sessionKey` or to derive `K_A = HKDF(sessionKey, A)`
for `A ≠ B` without the session secret. The independence of outputs under distinct `info`
values follows from the PRF property of the underlying HMAC construction. ADR-0015
documents this argument explicitly: "From `K_B` it can recover neither `sessionKey` (one-
wayness) nor `K_A` (PRF independence)." **PROVEN** for HKDF-PRF property (Krawczyk 2010,
"Cryptographic Extraction and Key Derivation: The HKDF Scheme"); **CONJECTURED** for
the specific `info` encoding's collision-freeness (canonical CBOR is injective by
construction; no formal proof on record for this specific encoding applied to Nerion's
audience domain).

**Residual.** Per-audience keys do not prevent a resource from acting *within its own
authority* — a resource holding `K_A` can freely issue MAC-valid tokens for audience A
to itself. This is noted as a deployment obligation in ADR-0015: "correct key distribution
(derived keys only, never the raw session secret) is a deployment obligation." A
deployment that needs to prevent self-minting must use the asymmetric opt-in
(`signEnvelope` + ML-DSA-87). **OPEN** (the deployment obligation is documented but
not mechanically enforced in the current codebase).

---

## §3. VRF Pseudorandomness and Uniqueness

### §3.1 RFC 9381 ECVRF properties in Nerion's context

Nerion's Plane 3 / P4 ledger uses a VRF for private leader sortition (ADR-0004).
The chosen ciphersuite is **ECVRF-EDWARDS25519-SHA512-ELL2** from RFC 9381 §5.1,
implemented over `@noble/curves` ed25519.

A VRF (Verifiable Random Function, Micali, Rabin, Vadhan 1999) provides two
fundamental properties for any (key, message) pair:

1. **Pseudorandomness.** The output `beta = VRF_proof_to_hash(pi)` is
   computationally indistinguishable from a random value by any party that does not
   hold the secret key, even given the public key and the message. This is the property
   that makes leader election unpredictable before the elected leader reveals their proof.

2. **Verifiability / uniqueness.** Given `(public_key, message, proof pi)`, any party
   can verify that `beta` is the unique correct output. "Unique" means: for a given
   `(key, message)`, there is exactly one valid `beta`, and no prover — even a
   malicious one — can produce two distinct valid outputs for the same input. This
   prevents equivocation in the leader protocol.

**Standard result (PROVEN).** RFC 9381 §3 defines the required VRF properties
(pseudorandomness and uniqueness) and proves that the ECVRF constructions satisfy them
under the decisional Diffie-Hellman (DDH) assumption on the underlying elliptic-curve
group, in the random-oracle model. For ECVRF-EDWARDS25519-SHA512-ELL2, the security
reduces to DDH on Curve25519 / Edwards25519. This is a **classical** assumption — see
§3.3 for the quantum discussion. **PROVEN** (RFC 9381 §3; Dodis, Yampolskiy 2005 for
the foundational VRF framework; Goldberg et al. 2020 "Verifiable Random Functions (VRFs)
on Elliptic Curves").

### §3.2 Uniqueness proof: why H ≠ G is necessary (link to ADR-0032)

The ECVRF's uniqueness (also called "trusted uniqueness" in RFC 9381 §3.2) relies on
the **Decisional Diffie-Hellman (DDH)** assumption on the group. Uniqueness is proven
via the "DLEQ proof" inside the VRF: the prover demonstrates, in zero knowledge, that
the VRF output and the auxiliary point are computed under the same discrete log as the
public key. For this proof to be sound, the auxiliary generator `H` used in the DLEQ
proof must be:

- **Distinct from the base point G** (otherwise the DLEQ relation collapses to a scalar
  multiple of G and the proof leaks the secret key).
- **A point whose discrete log with respect to G is unknown** (the nothing-up-my-sleeve
  / NUMS requirement). If an adversary knew `dlog_G(H)`, they could forge DLEQ proofs.

ADR-0032 addresses this for Nerion's Pedersen commitment generators (which share the
same structural requirement), prescribing:

```
H = hash_to_ristretto255("PolarSeek/disclosure/generator-H/v1")
```

using `@noble/curves` `ristretto255_hasher.hashToCurve` (RFC 9380 §5.3, expand_message_xmd
with SHA-512). The NUMS argument: `H` is the image of a fixed human-readable domain-
separation seed under a hash-to-curve map; no party selected `H`'s bits by choosing an
algebraically convenient value. **CONJECTURED** that `dlog_G(H)` is unknown (the NUMS
argument is a heuristic under ROM; it is not unconditionally proven). The ADR also
specifies runtime invariants — `H ≠ G`, `H ≠ identity`, `H` has prime order,
`H` matches the pinned bytes — to close the *trivial* forgery classes.

For the VRF ciphersuite proper (ECVRF-EDWARDS25519), the `H` derivation follows
RFC 9381's `ECVRF_encode_to_try_and_increment` procedure, which is a different (but
structurally similar) NUMS derivation defined by the RFC. **PROVEN** for the RFC-defined
ciphersuite (RFC 9381 §5.1 normative); **CONJECTURED** for Nerion's correct instantiation
of that ciphersuite through `@noble/curves`.

### §3.3 Pseudorandomness under the DLEQ assumption

RFC 9381 proves VRF pseudorandomness under the decisional Diffie-Hellman (DDH)
assumption: an adversary cannot distinguish the VRF output from a random bit string
without the secret key, even given the public key and oracle access. In the
leader-sortition context, this means: until the elected validator reveals their VRF
proof, no other party can predict which validator will win the draw — providing
**private, grind-resistant leader election**.

The chained-VRF beacon design in ADR-0004 is critical here: the seed for round `h` is
`VRF_beta` of round `h-1`'s finalized leader, not the block hash. As ADR-0004 notes,
block-hash seeding is grindable (a proposer shapes block content to bias the next draw).
Chaining the prior leader's VRF output removes this surface: the proposer must commit to
the proof that *is* the next seed, and changing it changes their own eligibility.
**CONJECTURED** (the anti-grinding argument is standard and sound for chained VRF beacons;
no formal proof of the specific Nerion chaining construction has been written).

**Post-quantum honesty note.** ECVRF-EDWARDS25519 security rests on DDH on Curve25519,
which is broken by Shor's algorithm on a cryptographically relevant quantum computer
(CRQC). A quantum adversary with a CRQC could predict the leader schedule — enabling
targeted denial-of-service. However, as ADR-0004 explicitly states: "Safety is post-
quantum; only liveness/unpredictability rests on a classical assumption." Block
finalization uses ML-DSA-87 (PQ), so a quantum adversary that predicts the leader cannot
*forge blocks or finality*. No standardized post-quantum VRF exists as of June 2026
(lattice VRFs are research-stage with prohibitive proof sizes and no NIST track).
**OPEN** (replacing ECVRF with a PQ-VRF is a designated future-work item; the gap is
documented and accepted).

---

## §4. Formal Gaps and Open Items

### §4.1 QROM vs ROM: where Nerion makes ROM assumptions

Several of Nerion's constructions are proven or argued only in the **classical** random-
oracle model (ROM), not the quantum random-oracle model (QROM). The distinction matters:
a quantum adversary can query a ROM in superposition, which breaks some ROM-based proofs
that do not hold in the QROM.

| Construction | Model claimed | QROM status |
|---|---|---|
| ML-DSA-87 (FIPS 204) | ROM (classical) and QROM (NIST security analysis covers quantum adversaries at Level-5 parameters) | **PROVEN** in QROM (FIPS 204 security analysis; Kiltz, Lyubashevsky, Schaffner 2018) |
| ML-KEM-1024 (FIPS 203) | QROM | **PROVEN** in QROM (Jiang et al. CRYPTO 2018; FIPS 203 security analysis) |
| HKDF-SHA-384 (permit key derivation, ADR-0015) | ROM (standard PRF argument for HMAC/HKDF) | QROM treatment exists for HKDF generically (Zhandry 2012); not applied specifically to Nerion's `info` structure. **CONJECTURED** |
| ZK range proof / dual-range OR-proof (`disclosure/zkrange.ts`, ADR-0033) | **Classical ROM only** | **OPEN** — no QROM argument. Fiat-Shamir soundness in the QROM is a separate, stronger claim (Unruh 2015; Don et al. 2019). The soundness/binding is a *classical* property (discrete-log over ristretto255). |
| ZK policy-satisfaction proof (`disclosure/policyproof.ts`, ADR-0006) | Classical ROM only | **OPEN** — same as above; the PSP composes the range proof. |
| Salted intent commitment (ADR-0014) | Classical ROM | QROM: the hiding property under a 256-bit salt is information-theoretic for the salt-keeper; the binding is SHA3-based and a quantum adversary does not gain a preimage advantage that breaks binding. **CONJECTURED** that hiding is practically sound in QROM given the salt entropy; formal analysis not on record. |
| ECVRF-EDWARDS25519-SHA512-ELL2 (ADR-0004) | Classical ROM / DDH | **OPEN** — broken by Shor's algorithm; no PQ-VRF is available. Accepted gap. |

**Implication.** The most significant QROM gap is the ZK disclosure layer. An adversary
with a quantum computer and access to the protocol could, in principle, exploit the
Fiat-Shamir transform's weaknesses in the QROM to forge range proofs or policy-satisfaction
proofs — allowing a false claim of "amount within bounds" to appear valid. This would not
break the ML-DSA-87 receipt signature (which is QROM-secure) but would undermine the
zero-knowledge *soundness* guarantee that the protocol layer provides on top of it. Amount
*confidentiality* (hiding) remains information-theoretic and is unaffected by any quantum
attack. **OPEN** — designated for the external ZK/crypto audit.

### §4.2 Lack of formal verification

Nerion has no mechanically verified proofs (TLA+ model checking, Coq/Rocq formalization,
EasyCrypt protocol proofs, or ProVerif symbolic analysis). All formal claims rest on:

1. Standard literature results applied by analogy to Nerion's construction.
2. Property-based testing (`fast-check`) over randomized input spaces.
3. KAT vectors pinned against Nerion's own spec.
4. Multi-model adversarial review (Team Apex council).

None of these is a substitute for formal verification. Specific gaps:

- **TLA+/Alloy for the three-plane protocol.** The interaction between Plane 1 admission,
  Plane 2 receipt anchoring, and Plane 3 settlement has not been modeled in a state-space
  tool. The "nearline gap" (T-P2-1), the fail-closed / fail-open boundary (T-P1-9), and
  cross-plane key isolation have not been verified as invariants in a formal model. **OPEN**.

- **EasyCrypt/CryptoVerif for the signing protocol.** The domain-separation argument
  for `signEnvelope` (that the `["PolarSeek-Signed-v1", suite, context, payload]`
  transcript prevents cross-context forgery) and the receipt non-repudiation chain have
  not been mechanically proven in a cryptographic game-playing framework. **OPEN**.

- **ProVerif/Tamarin for session establishment.** The session key establishment,
  PermitToken issuance, and audience-key derivation flow has not been analyzed by a
  symbolic protocol verifier. PERMIT-001 was caught by human (multi-model) review, not
  by a model checker. **OPEN**.

- **Coq proof of dCBOR injectivity.** The canonical CBOR encoder's injectivity
  (distinct logical values → distinct byte encodings) underpins signature binding. It
  is tested but not formally proven. **OPEN**.

These are designated as a **research track** — items for a future formal-methods
engagement, separate from the current external security audit scope.

### §4.3 External audit gaps

The ASSURANCE.md matrix records: "Independent security/ZK audit: Not done. OSTIF +
OTF Security Lab #22493 (→ Radically Open Security) submitted, not yet accepted/scoped."

As of the date of this document, no completed external audit exists. Specific gaps:

- **ZK construction audit (priority).** The bespoke disclosure layer (`disclosure/zkrange.ts`,
  `disclosure/policyproof.ts`, `disclosure/commitbind.ts`) is UNAUDITED. The soundness of
  the Fiat-Shamir-wrapped Chaum-Pedersen OR-proof (ADR-0033), the dual-range proof
  composition, and the `n ≤ 251` no-wraparound argument (ZKRANGE-002) are priority audit
  items. One off-by-one (ZKRANGE-002) was found by internal review at `n=252` — the
  `n ≤ 251` fix is correct and in production use (n=32 throughout), but the audit should
  confirm no further integer-range issues exist.

- **`@noble` library audit.** Nerion's cryptographic security reduces entirely to the
  correctness of `@noble/post-quantum` (ML-DSA-87, ML-KEM-1024), `@noble/curves`
  (ristretto255, ed25519), and `@noble/hashes` (SHA-384, SHA3, HKDF, HMAC). These
  libraries have had community review but Nerion has not commissioned or reviewed
  the output of a formal code audit of these libraries in the versions pinned by the
  repo. **OPEN**.

- **Transparency-log gossip and consistency proof.** The SCITT-style log
  (`translog/`) provides Merkle inclusion and consistency proofs. The threat model
  identifies split-view / equivocation (T-P2-3) as a known risk. Whether the
  current gossip/witness mechanism fully closes this threat for multi-operator
  deployments has not been externally reviewed. **OPEN**.

- **MPC/threshold governance key management.** Plane 3 threshold signatures
  (`governance/`) have not been audited for correctness of the quorum ceremony,
  share custody, or liveness fallback. **OPEN**.

---

## §5. EU AI Act and NIST AI RMF Alignment

> **Scope clarification (binding).** Nerion is **infrastructure / a protocol**, not an
> "AI system" as defined under the EU AI Act. Nerion governs whether an AI action is
> *admitted* and produces evidence about admissions; it does not make AI inferences,
> process training data, or produce outputs that constitute an AI system's functional
> output. It is **complementary to** the Act's accountability and transparency goals,
> not an entity regulated by or certifiable under the Act. The analysis below describes
> how Nerion's cryptographic properties *support* operators building AI systems that are
> subject to the Act — it is not a compliance certification claim.

### §5.1 EU AI Act — Article 13 (Transparency) and Article 17 (Quality Management)

**Article 13 (Transparency for high-risk AI systems)** requires that high-risk AI
systems be designed to enable natural persons to understand the system's output and
its basis. Article 13(1) requires "sufficient transparency" to enable meaningful human
oversight; Article 13(3)(b) requires "the degree of accuracy, robustness and
cybersecurity of the high-risk AI system."

Nerion's cryptographic accountability mechanism supports Article 13 in the following
ways:

1. **Non-repudiable action record.** Every admission decision at Plane 2 produces a
   ML-DSA-87–signed `ReceiptBody` anchored in the transparency log. The receipt
   binds `{action hash, capability, policy version, evaluator version, effect, tier,
   jurisdiction, timestamp}` under a PQ signature. This provides a
   tamper-evident, non-repudiable record that a specific admission decision was made
   by a known policy version at a known time — an objective audit trace for human
   reviewers. The EUF-CMA property of ML-DSA-87 means the receipt cannot be forged
   after the fact (see §1.2). **CONJECTURED** (the record is non-repudiable under
   ML-DSA-87's EUF-CMA; whether this satisfies Art. 13 for a specific AI deployment
   is a legal question outside the scope of this memo).

2. **Merkle inclusion proofs.** Any auditor or regulator can independently verify, given
   a gossiped Merkle root, that a specific receipt is included in the log and that the
   log's history has not been rewritten (append-only consistency proof). This supports
   the "sufficiency of transparency" requirement without requiring trust in the log
   operator. **PROVEN** for Merkle inclusion correctness (standard result; see SCITT /
   RFC 9162 / CT RFC 6962); **CONJECTURED** for the adequacy of this evidence for EU AI
   Act purposes.

3. **Govern-the-verb invariance (C14 / ADR-0007).** The admission kernel's decision is
   invariant to perception-shaped data in intent parameters. This architectural property
   means the governance record attests to *what action was admitted under what policy*,
   not to the content or origin of the underlying perception — which limits the surface
   area of what the AI-Act-regulated AI system must disclose through the Nerion receipt.

**Article 17 (Quality management systems)** requires technical documentation, risk
management, data governance, and post-market monitoring for high-risk AI systems.

1. **Policy version binding in receipts.** Every receipt commits to the `evaluatorVersion`
   — a deterministic hash of the policy in force at admission time. This enables an
   auditor to reconstruct exactly which policy was active for any historical decision,
   supporting Article 17's documentation and post-market monitoring requirements.
   **CONJECTURED** (correctness of the binding; legal adequacy is out of scope).

2. **Risk-tier obligations.** The kernel's `obligationsForTier` function attaches
   verifiable obligation sets to decisions: Tier 2 requires `nearline-receipt` and
   `step-up-approval`; Tier 3 requires `nearline-receipt`, `n-of-m-attestation`,
   `dual-control`, and `all-planes`. These obligations become part of the signed receipt
   and are therefore included in the evidence record. For high-risk AI Act categories,
   operators can configure Tier 3 admission requiring multi-party attestation before
   an irreversible action is admitted — producing a receipt trail that satisfies Art.
   17 audit requirements. **CONJECTURED** (design intent matches Art. 17 requirements;
   no legal review has been performed).

3. **Fail-closed admission (C8).** The kernel's `decide()` function has no fail-open
   path — any unexpected condition results in a Tier-3 deny. This supports the "robust"
   and "safe" requirements of Art. 17(1)(e) (risk management system that "ensures"
   appropriate handling of foreseeable risk). **CONJECTURED**.

### §5.2 NIST AI RMF alignment

The NIST AI Risk Management Framework (NIST AI 100-1, January 2023) defines four core
functions: GOVERN, MAP, MEASURE, MANAGE.

**GOVERN.** Nerion's three-plane architecture provides a programmable policy layer
(Plane 1 kernel) governed by a quorum (Plane 3 settlement) with a cryptographically
accountable evidence trail (Plane 2). The GOVERN function requires "establishing policies,
processes, and accountability for AI risk." Nerion's cryptographic evidence trail
supports the accountability component by producing non-repudiable records of governance
decisions. **CONJECTURED**.

**MAP.** AI RMF MAP includes categorizing AI systems and their risk contexts. Nerion's
risk-tier system (T0–T3) and the `tierOf` function in `kernel/src/policy.ts` implement
a programmatic risk categorization that can be aligned with AI RMF impact tiers.
**CONJECTURED**.

**MEASURE.** AI RMF MEASURE includes monitoring and evaluation of AI risks. The
transparency log (Plane 2) provides a measurable, timestamped record of all admitted
actions indexed by policy version, jurisdiction, and tier. Post-hoc analysis of the
log supports the MEASURE function. The Merkle consistency proofs ensure the log
cannot be retroactively edited, supporting evidence integrity for measurement.
**CONJECTURED**.

**MANAGE.** AI RMF MANAGE includes response and recovery. Nerion's Plane 3
threshold/MPC governance layer is designed for revocation, key rotation, and dispute
resolution. The quorum design (requiring threshold ≥ k of n signers) prevents a single
operator from unilaterally altering governance. **CONJECTURED** (design is consistent
with MANAGE requirements; the governance layer is not yet fully audited).

### §5.3 Non-repudiation chain as evidence for audits

The Nerion non-repudiation chain, as constructed, consists of the following links:

```
Admission intent
    └─ kernel.decide(input) → Decision (deterministic, fail-closed)
        └─ buildReceipt(params) → ReceiptBody (canonical CBOR)
            └─ ML-DSA-87.sign(encodeCanonical(body), issuerKey) → sig
                └─ translog.append(receiptLeaf(receipt))
                    └─ STH signed over Merkle root
                        └─ inclusion proof available to any verifier
```

Each link in this chain has a cryptographic property:

1. **Determinism of `decide()`.** Given the same `KernelInput`, the kernel produces the
   identical `Decision` object. This means a receipt unambiguously attests to the
   outcome of a specific kernel invocation; no "the kernel might have produced a
   different result" ambiguity exists. **CONJECTURED** (tested by C8; not formally verified).

2. **Binding of `ReceiptBody` to the decision.** The `effect` field in the body is the
   decision outcome; `commitments.intent` is the salted hiding commitment to the
   admitted intent; `commitments.capability`, `commitments.policy`, `commitments.inputHash`,
   `commitments.decisionHash` are the other commitment fields. All fields are canonical
   CBOR and therefore unambiguous. **CONJECTURED** (injectivity of dCBOR encoder; tested
   but not formally verified).

3. **ML-DSA-87 non-repudiation.** EUF-CMA means the issuer cannot later deny issuing
   the receipt — only the holder of `issuerSecretKey` could have produced a valid
   signature under `issuerPublicKey`. This is non-repudiation in the cryptographic
   sense (one-party: the issuer cannot deny; the symmetric PermitToken path does NOT
   provide non-repudiation and this is explicitly documented in the threat model's §6
   "EVIDENCE vs. PROOF" section). **PROVEN** for EUF-CMA (see §1.2); **CONJECTURED**
   for the legal sufficiency of this property as audit evidence.

4. **Log inclusion proof integrity.** `verifyReceiptInclusion` verifies the ML-DSA-87
   signature, issuer key match, leaf–body consistency, and Merkle inclusion proof against
   a gossiped root. An auditor with a gossiped root and a receipt can independently
   verify all four links without trusting the issuer or the log operator. **PROVEN** for
   Merkle tree security (standard result; collision resistance of SHA3/SHAKE256 used for
   the Merkle tree). **CONJECTURED** for the end-to-end verification path in Nerion's
   implementation.

**Regulatory evidence posture.** The chain supports the following audit assertion:
"Receipt `R` with signature `s` under public key `pk` was included in transparency log
at position `i`, under root `root`, at time `t`, by a kernel running policy version
`ev`, admitting intent commitment `c_intent` at tier `tier`." Every element of this
assertion is cryptographically verifiable from the receipt, the inclusion proof, and
a gossiped root — without trusting any single operator. For EU AI Act Article 13/17
and NIST AI RMF MAP/MEASURE functions, this chain provides the strongest available
cryptographic evidence basis. **CONJECTURED** (legal/regulatory adequacy is out of
scope for this technical memo).

---

## Appendix A: Notation and standard references

| Symbol / term | Meaning |
|---|---|
| EUF-CMA | Existential Unforgeability under Adaptive Chosen-Message Attack |
| IND-CCA2 | Indistinguishability under Adaptive Chosen-Ciphertext Attack |
| MLWE | Module Learning With Errors |
| MSIS | Module Short Integer Solution |
| DDH | Decisional Diffie-Hellman |
| DLEQ | Discrete Logarithm Equality (Chaum-Pedersen proof) |
| ROM | Random Oracle Model |
| QROM | Quantum Random Oracle Model |
| HVZK | Honest-Verifier Zero Knowledge |
| KEM | Key Encapsulation Mechanism |
| VRF | Verifiable Random Function |
| PRF | Pseudorandom Function |
| NUMS | Nothing-Up-My-Sleeve (generator derivation) |
| HKDF | HMAC-based Key Derivation Function (RFC 5869) |
| dCBOR | Deterministic / Canonical CBOR |
| CRQC | Cryptographically Relevant Quantum Computer |

**Primary standards cited:**

- FIPS 203 (ML-KEM, 2024-08-13), FIPS 204 (ML-DSA, 2024-08-13), FIPS 205 (SLH-DSA, 2024-08-13) — NIST
- RFC 5869 — HKDF (Krawczyk, Eronen)
- RFC 9381 — Verifiable Random Functions (VRFs) over Elliptic Curves
- RFC 6962 / SCITT — Certificate Transparency / Supply Chain Integrity, Transparency, and Trust
- NIST AI 100-1 (January 2023) — AI Risk Management Framework
- EU AI Act (Regulation (EU) 2024/1689), Articles 13, 17

**Key literature (informational):**

- Ducas et al., "CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme," TCHES 2018
- Bos et al., "CRYSTALS — Kyber: A CCA-Secure Module-Lattice-Based KEM," EURO S&P 2018
- Jiang et al., "IND-CCA-Secure Key Encapsulation Mechanism in the Quantum Random Oracle Model," CRYPTO 2018
- Hofheinz, Hövelmanns, Kiltz, "A Modular Analysis of the Fujisaki-Okamoto Transformation," TCC 2017
- Krawczyk, "Cryptographic Extraction and Key Derivation: The HKDF Scheme," CRYPTO 2010
- Micali, Rabin, Vadhan, "Verifiable Random Functions," FOCS 1999
- Cramer, Damgård, Schoenmakers, "Proofs of Partial Knowledge," CRYPTO 1994 (CDS OR-proof)
- Fiat, Shamir, "How to Prove Yourself," CRYPTO 1986 (Fiat-Shamir transform)
- Unruh, "Non-Interactive Zero-Knowledge Proofs in the Quantum Random Oracle Model," EUROCRYPT 2015
- Bindel et al., "Hybrid Key Encapsulation Mechanisms and Authenticated Key Exchange," PQCrypto 2019
- Barbosa et al., "X-Wing: The Hybrid KEM You've Been Looking For," IACR ePrint 2024

---

## Appendix B: Open items summary

| # | Item | Status | Dependency |
|---|---|---|---|
| O-1 | ZK layer: Fiat-Shamir soundness in QROM | **OPEN** | External ZK/crypto audit |
| O-2 | `@noble` library audit (ML-DSA, ML-KEM, ristretto255) | **OPEN** | External library audit |
| O-3 | dCBOR encoder formal injectivity proof | **OPEN** | Formal methods engagement |
| O-4 | TLA+/EasyCrypt three-plane protocol verification | **OPEN** | Research track |
| O-5 | ProVerif/Tamarin session establishment analysis | **OPEN** | Research track |
| O-6 | PQ-VRF replacement for ECVRF-EDWARDS25519 | **OPEN** | Future NIST standard |
| O-7 | Transparency log gossip / split-view audit | **OPEN** | External audit |
| O-8 | Threshold/MPC governance key management audit | **OPEN** | External audit |
| O-9 | Side-channel resistance of ML-DSA-87 hot paths | **OPEN** | Hardware measurement |
| O-10 | HKDF audience binding QROM analysis | **OPEN** | Academic / formal methods |
| O-11 | ADR-0032 H-generator pinning implementation | **OPEN** | Implementing PR (design proposed) |
| O-12 | ADR-0033 transcript-binding tightening audit ratification | **OPEN** | External ZK/crypto audit |
| O-13 | Correct key distribution enforcement (deployment obligation) | **OPEN** | Operational / deployment tooling |
| O-14 | Legal / FTO review | **OPEN** | Counsel engagement (FTO_TODO.md) |

---

*This document is a technical memo, not an audit report, not a FIPS validation, and not a legal
opinion. It is subject to revision as the codebase, ADR corpus, and external audit findings evolve.*
