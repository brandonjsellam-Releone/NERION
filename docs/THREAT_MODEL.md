# Post-Quant PolarSeek — Threat Model

> **Status: P0 — crypto implemented & tested; everything else scaffolding.** As of 2026-06-17
> `crypto/` is built in TypeScript (SuiteID registry, hybrid KEMs, ML-DSA-87 + SLH-DSA,
> AES-256-GCM/HMAC-SHA-384/SHAKE, deterministic CBOR, signed envelopes + PermitToken) with
> **51 passing tests** and a clean-room CI linter (`tools/cleanroom-lint.mjs`). The remaining
> implementation directories (`kernel/`, `attest/`, `capabilities/`, `planes/`, `receipts/`,
> `translog/`, `ledger/`, `settlement/`, `governance/`, `conformance/`, `sdks/`) are
> **empty/unbuilt**. This document models the *intended* design and is explicit about what is
> unbuilt. Treat every "Mitigation" outside `crypto/` as a **requirement to implement and
> test**, not as a property the system currently has.
>
> This is a security engineering document. It is **not** a legal opinion and does **not** make
> any patent non-infringement claim — see `FTO_TODO.md`, which governs all public claims.

## 0. Scope, method, and what PolarSeek is

PolarSeek is a 3-plane execution-governance protocol for **AI/agent ACTIONS** ("govern the verb,
never the eye"). It governs whether an action is *admitted* and produces durable, auditable
evidence about admitted actions. It does **not** govern perception, model weights, or content
moderation, and it is **not** a sandbox: an admitted action still executes in some downstream
system (the *resource*), which PolarSeek does not itself confine.

- **Plane 1 — Hot Admission.** Synchronous, stateless, deterministic kernel. On each action it
  evaluates policy and, if admitted, issues a short-lived **PermitToken** authenticated with a
  symmetric MAC (HMAC-SHA-384) bound to a fresh attestation. **No per-action PQ signature, no
  network round-trip, no sequence/nonce-history tracking** by design (latency budget). This is
  the most security-sensitive plane precisely because it deliberately omits the cheapest
  classical anti-replay tools.
- **Plane 2 — Nearline Assurance.** Asynchronous, batched **ML-DSA-87** receipts over admitted
  actions, Merkle-anchored to a **SCITT-style append-only transparency log**. This is where
  non-repudiation and post-quantum durability live.
- **Plane 3 — Offline Settlement.** Pure proof-of-stake ledger with threshold/MPC governance for
  slow, high-consequence, irreversible decisions (revocation, key rotation, dispute resolution).
- **Risk tiers T0–T3.** T0 = trivial/reversible; T3 = high-consequence/irreversible. Tier
  selects *how much assurance is required before/around an action* (e.g., T3 may require Plane 2
  confirmation or Plane 3 co-signature before the resource executes; T0 may admit on Plane 1
  alone). Tier assignment is itself a security-relevant decision (see T-CAP-3).

**Cryptographic inventory (confirmed available via dependencies, not yet wired in):**
`@noble/post-quantum` provides ML-KEM-1024, ML-DSA-87, SLH-DSA; `@noble/curves` provides
x25519/ed25519; `@noble/hashes` provides SHA-2 (incl. SHA-384), SHA-3/SHAKE, HMAC;
`@noble/ciphers` provides AES. `_introspect.mjs` confirms ML-KEM-1024 encapsulate/decapsulate,
ML-DSA-87 sign/verify, and x25519 round-trip work with these versions. **None of this is
integrated** — it is library availability only.

---

## 1. Assets to protect

| # | Asset | Why it matters | Primary plane |
|---|-------|----------------|---------------|
| A1 | **Kernel admission decisions** (the verb-level allow/deny) | The protocol's whole purpose; a wrong "allow" is the core failure | P1 |
| A2 | **PermitToken integrity & confidentiality of its authority** | A forged/replayed/stolen token authorizes an action the policy did not | P1 |
| A3 | **HMAC-SHA-384 PermitToken signing key(s)** | Compromise = mint arbitrary valid PermitTokens; symmetric, so any holder can forge | P1 |
| A4 | **Attestation material** (the fresh attestation the token is bound to) | If forgeable, binding is meaningless; replayed attestations enable replayed permits | P1 |
| A5 | **Kernel policy + capability definitions** | Over-broad or tampered policy silently widens authority | P1/P3 |
| A6 | **ML-DSA-87 receipt signing keys** | Compromise = forge non-repudiable history; backdate/insert receipts | P2 |
| A7 | **Transparency-log integrity & consistency** (Merkle root, append-only, no equivocation) | The audit ground-truth; split-view destroys accountability | P2 |
| A8 | **Receipts themselves** (the durable record of what was admitted) | Evidence for dispute, forensic, and settlement | P2 |
| A9 | **PoS ledger state & threshold/MPC governance keys** | Controls revocation, rotation, dispute outcome; ledger rewrite = catastrophic | P3 |
| A10 | **MPC key shares** | Threshold compromise = full governance takeover | P3 |
| A11 | **Long-lived secrets at rest** (any) vs. a future quantum adversary (HNDL target) | Harvest-now-decrypt-later exposure | all |
| A12 | **Build/release supply chain** (deps, signing keys, CI) | One poisoned artifact bypasses every plane | cross-cutting |
| A13 | **Availability of the admission path** | If P1 is down, agents either stall (DoS) or fail-open (catastrophic) | P1 |
| A14 | **Determinism of the kernel** | Non-determinism breaks both reproducibility and the audit's meaning | P1 |
| A15 | **Identity/provenance binding** (which agent/principal acted) | Without it, receipts attribute nothing | all |

Explicitly **out of scope as protected assets**: model weights, prompt content, "intent," and the
correctness of the downstream resource's own execution. PolarSeek attests *that an action was
admitted under policy*; it does not guarantee the action's real-world outcome.

---

## 2. Adversaries

| ID | Adversary | Capability | Goal |
|----|-----------|------------|------|
| ADV-1 | **Malicious/compromised agent** | Can call the admission API arbitrarily; may be fully controlled by an attacker; sees its own PermitTokens | Get an out-of-policy action admitted; replay/escalate |
| ADV-2 | **Compromised resource / downstream service** | Receives PermitTokens; can attempt replay against other resources | Use a token outside its intended audience/scope |
| ADV-3 | **Network adversary (MITM)** | Observes/modifies traffic between agent, kernel, resource, log | Steal/replay tokens; HNDL capture; tamper attestations |
| ADV-4 | **Malicious kernel operator / insider** | Runs kernel or holds keys | Mint permits, suppress/alter receipts, equivocate log |
| ADV-5 | **Malicious log operator** | Runs the transparency log | Split-view / equivocation; omit or reorder entries |
| ADV-6 | **Governance-quorum subset** | Holds < threshold MPC shares (or up to threshold−1) | Stall, bias, or (at threshold) seize governance |
| ADV-7 | **Supply-chain attacker** | Can poison a dependency, build, or signing key | Backdoor any plane invisibly |
| ADV-8 | **Quantum adversary (CRQC)** | Future cryptographically-relevant quantum computer; breaks ECC/RSA, weakens (not breaks) symmetric via Grover | Forge classical signatures; decrypt harvested traffic |
| ADV-9 | **HNDL adversary (record now)** | A *present-day* passive collector storing ciphertext/transcripts for future quantum decryption | Future confidentiality break of today's data |

**On the quantum adversary, honestly:** ML-DSA-87 (P2) and ML-KEM-1024 (key establishment) are
the PQ answers and are dependency-available. **But the P1 PermitToken's security rests on
HMAC-SHA-384**, a symmetric MAC. Grover gives at most a quadratic speedup against symmetric
primitives, so SHA-384's preimage/forgery resistance remains comfortably > 128-bit
post-quantum — **the PermitToken MAC is *not* the quantum-weak link.** The quantum-weak links are
(a) any classical-only key establishment or transport (x25519/TLS) used to carry tokens or
attestations, and (b) any long-lived ECC signatures. The "Post-Quant" name is **earned only at
P2/P3 once ML-DSA/ML-KEM are actually wired in**; today the name describes intent, and P1's
quantum-resistance is incidental (it comes from using a symmetric MAC, not from a PQ design).

---

## 3. Trust boundaries per plane

```
[ Agent ]── action request ──►(TB-1)──► [ P1 Hot-Admission Kernel ] ──issues──► PermitToken
     │                                          │ holds A3 (HMAC key), A4 attestation root
     │◄──────────── PermitToken ────────────────┘
     │
     └── action + PermitToken ──►(TB-2)──► [ Resource / downstream executor ]
                                                │
   (async)                                      ▼
[ P1 batch ] ──►(TB-3)──► [ P2 Assurance: ML-DSA-87 receipts ] ──►(TB-4)──► [ Transparency Log (SCITT) ]
                                                                                  │ Merkle root
[ P3 Settlement: PoS ledger + threshold/MPC ] ◄──(TB-5)── anchors/disputes ───────┘
```

- **TB-1 (Agent ↔ Kernel):** The kernel must treat *all* agent input as hostile and untrusted.
  This is the primary admission boundary. Statelessness means the kernel cannot rely on any
  remembered context about this agent — every request is judged on its face plus the bound
  attestation.
- **TB-2 (Agent/Resource ↔ PermitToken):** The token crosses an untrusted hop. The resource
  trusts the token *only* via MAC verification against a shared/derived key and binding checks.
  The agent is assumed able to read and attempt to misuse its own token.
- **TB-3 (P1 → P2):** Batching boundary. A delay window exists here (the "nearline" gap) during
  which an admitted action has executed but is **not yet** in the durable PQ-signed record.
- **TB-4 (P2 → Log):** The log operator is a *separate trust domain* and is assumed potentially
  hostile (ADV-5). P2 must not trust the log to be honest; it must be able to *prove*
  inclusion/consistency.
- **TB-5 (P2/P3):** Governance boundary. Crossing into P3 means a quorum, not a single operator,
  and slow irreversible authority.

Critical boundary property: **a compromise contained in one plane must not silently grant
authority in another.** P1 key theft must not let you rewrite P2 history; P2 forgery must not let
you change P3 settlement. Whether this holds depends entirely on key separation and
cross-plane verification — both **unimplemented**.

---

## 4. Threats per plane

### Plane 1 — Hot Admission (highest concentration of risk)

| ID | Threat | Notes |
|----|--------|-------|
| T-P1-1 | **PermitToken replay** | No sequence/nonce tracking and no network round-trip by design. A captured token is replayable for its full validity window against any resource that accepts it. **This is the headline P1 risk.** |
| T-P1-2 | **PermitToken theft / exfiltration** | Stolen from a compromised agent (ADV-1), resource (ADV-2), or wire (ADV-3). MAC validity is preserved; theft ≠ forgery but yields the same effect within scope/lifetime. |
| T-P1-3 | **HMAC key compromise (A3)** | Symmetric: anyone with the key mints unlimited valid tokens. If the same key is shared with verifying resources, the blast radius includes every such resource. |
| T-P1-4 | **Attestation forgery / replay (A4)** | If the "fresh attestation" can be forged or replayed, binding is theater. Freshness must be cryptographically enforced (challenge/clock), not asserted. |
| T-P1-5 | **Token scope/audience over-broadening** | A token valid for resource X accepted by resource Y; or a coarse scope that authorizes more verbs than intended. |
| T-P1-6 | **Kernel non-determinism (A14)** | Any wall-clock, RNG, map-iteration-order, float, locale, or unpinned-dependency nondeterminism makes two kernels disagree on admit/deny and makes receipts unreproducible. Determinism is a *security* property here. |
| T-P1-7 | **Clock skew / lifetime abuse** | Short-lived tokens depend on synchronized time. Skew either rejects valid tokens (DoS) or extends the replay window. |
| T-P1-8 | **Policy-evaluation DoS / algorithmic complexity** | Crafted inputs that blow up evaluation cost stall the synchronous hot path (A13). |
| T-P1-9 | **Fail-open vs fail-closed ambiguity** | If the kernel or its attestation source is unavailable, does the system stall (safe, DoS) or admit anyway (catastrophic)? Must be explicit per tier. |
| T-P1-10 | **Confused-deputy via capability** | Agent induces the kernel to admit using authority that belongs to another principal. |

### Plane 2 — Nearline Assurance

| ID | Threat | Notes |
|----|--------|-------|
| T-P2-1 | **Receipt suppression in the nearline gap (TB-3)** | An action admitted at P1 executes before its receipt is anchored. A malicious kernel operator (ADV-4) can crash/withhold before anchoring, leaving no durable record. The gap is inherent to batching. |
| T-P2-2 | **ML-DSA-87 receipt key compromise (A6)** | Forge non-repudiable receipts; backdate or insert. |
| T-P2-3 | **Log split-view / equivocation (A7, ADV-5)** | Log shows different roots/inclusion to different verifiers — the classic transparency-log attack. Defeated only by gossip/witness/consistency-proof checking, not by trusting the log. |
| T-P2-4 | **Merkle inclusion/consistency proof gaps** | If verifiers accept a root without checking append-only consistency against prior roots, history can be rewritten. |
| T-P2-5 | **Batch-boundary manipulation** | Reordering or dropping entries within/between batches; ambiguous batch membership. |
| T-P2-6 | **Receipt ↔ action binding weakness** | A receipt that doesn't cryptographically bind the *exact* admitted action, attestation, and principal proves nothing useful. |

### Plane 3 — Offline Settlement

| ID | Threat | Notes |
|----|--------|-------|
| T-P3-1 | **Threshold/MPC governance capture (A10, ADV-6)** | Reaching the signing threshold seizes revocation/rotation/dispute authority. |
| T-P3-2 | **Sub-threshold griefing / liveness attack** | Withholding shares stalls revocation and rotation — a denial-of-governance, often easier than capture. |
| T-P3-3 | **PoS-specific attacks** | Stake grinding, long-range/nothing-at-stake, validator collusion, weak-subjectivity bootstrapping. |
| T-P3-4 | **Slow-path latency exploited** | Because P3 is deliberately slow, an attacker races irreversible damage ahead of revocation taking effect. |
| T-P3-5 | **Governance/ledger key HNDL or classical exposure** | If any P3 key uses classical-only crypto, ADV-8/ADV-9 apply to the highest-value keys in the system. |

### Cross-cutting

| ID | Threat | Notes |
|----|--------|-------|
| T-CAP-1 | **Capability over-broadening** | Broad/wildcard capabilities, additive grants that never shrink, or transitive delegation that loses attenuation. |
| T-CAP-2 | **Capability confused-deputy / delegation forgery** | Forged or improperly-attenuated delegation chains. |
| T-CAP-3 | **Risk-tier downgrade** | Adversary gets a T3 action classified as T0 to skip P2/P3 assurance. Tiering logic is an attack surface. |
| T-SC-1 | **Supply chain (ADV-7)** | Dependency poisoning (`@noble/*`, `cbor2`), build/CI compromise, release-signing key theft, typosquatting, unpinned versions. |
| T-CR-1 | **HNDL on transport (ADV-9)** | Tokens/attestations carried over classical-only key exchange are harvestable now, decryptable later. |
| T-CR-2 | **Algorithm-agility failure** | No clean way to rotate primitives if ML-DSA/ML-KEM parameters are deprecated; no crypto version negotiation. |
| T-ID-1 | **Identity spoofing / weak provenance (A15)** | Receipts attribute to a principal the system cannot actually authenticate. |
| T-SER-1 | **Serialization ambiguity (CBOR)** | Non-canonical CBOR enables signature/MAC malleability and parser-differential attacks across SDKs (TS/Go/Python). |

---

## 5. Mitigations (REQUIREMENTS — none implemented yet)

**Plane 1**
- **M-P1-1 (replay):** Bind the token to a fresh, single-use attestation challenge and a tight
  expiry; bind to a specific **audience (resource id)** and **action hash** so the token is only
  valid for *that* verb at *that* resource. Statelessness forbids server-side nonce caches, so
  replay resistance must live in *binding + short lifetime*, and the design must state plainly:
  **within the validity window, against the bound audience, replay is possible** unless the
  resource itself enforces idempotency. Resources handling T2/T3 actions MUST enforce
  idempotency keys.
- **M-P1-2 (theft):** Minimize lifetime; consider channel binding (token usable only over the
  TLS/exporter context it was issued for); never log tokens; treat them as bearer secrets.
- **M-P1-3 (HMAC key):** Per-resource derived keys (HKDF) so a single resource compromise does
  not yield a universal forgery key; key in HSM/KMS; rotation procedure defined; **document that
  HMAC is symmetric and confers no non-repudiation** — that is P2's job.
- **M-P1-4 (attestation):** Cryptographically-fresh attestation (verifier-supplied nonce or
  bounded clock), with the attestation evidence itself verified, not trusted on assertion.
- **M-P1-6 (determinism):** Forbid wall-clock, RNG, ambient I/O, and unordered iteration inside
  the decision function; pin all deps; pass time/entropy as explicit inputs; ship a deterministic
  conformance harness (`conformance/`, empty today) with cross-SDK test vectors.
- **M-P1-9 (fail mode):** **Fail closed by default.** Per-tier explicit policy; T0 MAY have a
  documented degraded mode, T3 MUST fail closed.
- **M-P1-8 (DoS):** Bounded-time policy evaluation; input size limits; no unbounded recursion.

**Plane 2**
- **M-P2-1 (gap):** Make the nearline window *bounded and measured*; for T3, require receipt
  anchoring (or P3 co-sign) **before** the resource is allowed to execute — i.e., high tiers are
  not "nearline." Persist a write-ahead intent at admission so an action cannot vanish.
- **M-P2-2/6 (receipts):** ML-DSA-87 over a canonical encoding binding {action hash, attestation,
  principal, tier, kernel policy version, timestamp}. Keys in HSM; rotation + revocation via P3.
- **M-P2-3/4 (log):** SCITT-style append-only log with **mandatory consistency-proof checking**
  and **witness/gossip** so a split view is detectable; verifiers MUST reject a root not proven
  consistent with the last-seen root. Do not trust the log operator.

**Plane 3**
- **M-P3-1/2:** Threshold chosen against a stated fault model; published quorum; key-share
  custody separation; liveness fallback so sub-threshold griefing cannot permanently block
  revocation.
- **M-P3-3:** Use a reviewed PoS construction; document weak-subjectivity checkpoints.
- **M-P3-5:** PQ (ML-DSA) for governance signatures; PQ or hybrid for any P3 key exchange.

**Cross-cutting**
- **M-CAP:** Capabilities default-deny, least-privilege, attenuating-only delegation, explicit
  expiry; tier assignment is server-side and auditable, never client-asserted (M for T-CAP-3).
- **M-SC:** Lockfile-pinned deps with hash verification; reproducible builds; signed releases
  (consider SLH-DSA for long-lived release signatures, ML-DSA otherwise); SBOM; the `FTO_TODO.md`
  export-control item (d) must be closed before distribution.
- **M-CR (HNDL):** Carry all tokens/attestations over **PQ or hybrid (x25519+ML-KEM-1024)** key
  establishment, not classical-only TLS — otherwise A11/T-CR-1 stands. Build **crypto agility**
  (versioned algorithm identifiers in every signed/MAC'd structure) from day one.
- **M-SER:** Mandate **canonical/deterministic CBOR**; cross-SDK byte-exactness tests in
  `conformance/`.
- **M-ID:** Strong principal authentication feeding attestation; no receipt without an
  authenticated principal.

---

## 6. Evidence vs. Proof (no security theater)

This section is normative. Misusing one for the other is a security defect.

**PROOF (cryptographic, verifiable, adversary-resistant) — relied upon for authorization:**
- A valid **HMAC-SHA-384** over a PermitToken proves the token was minted by a holder of the key
  (integrity + key-possession). It is **proof of MAC validity, not of non-repudiation** (anyone
  with the symmetric key could mint it) and **not proof of liveness/non-replay**.
- A valid **ML-DSA-87** receipt signature proves origin authenticity and non-repudiation of the
  receipt under the PQ assumption.
- A **Merkle inclusion proof + verified consistency proof** proves an entry is in a log whose
  history was not rewritten *relative to roots you have witnessed*.
- A **threshold/MPC signature** proves a quorum authorized a governance action.

**EVIDENCE (corroborating signals — informative, attacker-influenceable, MUST NOT gate
authorization on its own):**
- **Geo-location / IP geolocation** is **EVIDENCE, not proof.** It is trivially spoofable (VPN,
  proxy, residential botnet, GPS spoofing, datacenter egress) and MUST NOT be a security control.
  It may be *recorded in receipts as a labeled signal* and used for risk scoring/anomaly
  flagging, never for admission or attribution.
- **Device fingerprints, user-agent strings, ASN/reputation, timing/heuristics, "intent"
  classifications** — all EVIDENCE. Spoofable or probabilistic; record-and-flag only.
- **Self-asserted attestation claims** that are not cryptographically verified are EVIDENCE, not
  proof. An attestation is proof only to the extent its evidence is independently verified
  (M-P1-4).

**Rules:**
1. No T-tier may be *lowered*, and no action *admitted*, on the strength of EVIDENCE alone.
2. EVIDENCE may be stored in receipts but MUST be labeled `evidence:` and never silently
   promoted to a basis for trust.
3. If a control cannot be stated as a verifiable PROOF above, it does not gate authorization.
   Calling geolocation a "security check" would be theater; we explicitly refuse to.

---

## 7. Residual risks we are NOT mitigating yet (and why)

> Honesty clause: the single largest residual risk is that **nothing in §5 is implemented.** The
> codebase is empty scaffolding plus an introspection script. The list below assumes the intended
> design were built; on top of it sits the meta-risk that it currently is not.

| # | Residual risk | Why not mitigated yet / accepted |
|---|---------------|----------------------------------|
| R1 | **Entire protocol is unbuilt (stubbed).** | P0 stage. No kernel, crypto wiring, receipts, log, ledger, SDKs, or conformance vectors exist. Until built, PolarSeek provides **zero** real assurance. Highest-priority residual risk by far. |
| R2 | **In-window PermitToken replay against the bound audience.** | A deliberate design trade: statelessness + no round-trip + no sequence tracking means we *cannot* prevent replay within the validity window server-side. Pushed to short lifetimes, audience/action binding, and resource-side idempotency — but for non-idempotent resources that don't cooperate, a bounded replay window is **accepted**. |
| R3 | **Nearline gap (action executes before durable receipt).** | Inherent to async batching for latency. Mitigated only by bounding the window and forcing high tiers off the nearline path; for T0/T1 a small unrecorded-action window is accepted. |
| R4 | **Insider kernel operator (ADV-4) within a single deployment.** | A single honest-but-curious or malicious operator holding the HMAC key can mint/permit during their window before P2/P3 detect divergence. Cross-plane detection is *detective, not preventive*; we accept detection-after-the-fact for P1 operator abuse. |
| R5 | **HNDL on any classical-only transport that ships before hybrid KEM is wired.** | If a deployment carries tokens over plain x25519/TLS prior to M-CR landing, today's transcripts are harvestable. Accepted only until hybrid (x25519+ML-KEM-1024) transport is mandatory; flagged as must-fix-before-prod. |
| R6 | **Downstream resource behavior.** | PolarSeek governs admission, not execution. A resource that ignores token scope, fails to verify the MAC, or mis-executes an admitted action is outside our control. We provide the proof; the resource must honor it. Not mitigated by design scope. |
| R7 | **Quantum break of the symmetric MAC.** | Accepted as negligible: Grover leaves SHA-384 > 128-bit PQ security. We are *not* spending effort hardening P1's MAC against quantum. |
| R8 | **Governance liveness (sub-threshold griefing).** | A fallback path to keep revocation live under share-withholding is designed-but-unbuilt; until then, denial-of-governance is an accepted residual. |
| R9 | **Side channels in crypto primitives.** | We rely on `@noble/*` constant-time properties; we are not independently auditing them at P0. Accepted with intent to review before prod. |
| R10 | **Supply chain beyond pinning.** | Reproducible builds, SBOM, and signed releases are planned, not done. Until then a dependency/CI compromise (ADV-7) is an accepted, monitored residual. |
| R11 | **Legal / FTO and export-control.** | Out of scope for *this* document and explicitly gated by `FTO_TODO.md`. No public non-infringement or "post-quantum-safe" claim may be made until counsel/classification work is on file. Tracked, not resolved here. |

**Bottom line:** treat this threat model as a build checklist. The protocol's eventual security
depends on §5 being implemented and on §6 being enforced without exception; today its real-world
assurance is that of an empty repository, and this document says so on purpose.
