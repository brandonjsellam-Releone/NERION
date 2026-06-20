# Nerion — NLnet Restack Application (RESEARCH DOSSIER — not paste‑ready; the maintainer writes the final proposal himself, see 🚨)

**Programme:** Open Internet Stack **"Restack"** (the EU‑Horizon‑funded successor to the NGI Zero Commons
Fund; €7M to 2030). **Status (verified 2026‑06‑20):** Restack is *"currently being set up — coming soon,"*
opening ≈ **September 2026** ("after the summer"), then **continuous open calls** until the budget is
allocated (~early 2027). Submit at <https://nlnet.nl/propose/> when the call is live; watch the Restack page
+ NGI Zero newsletter for the exact date.
**Requested:** EUR 45,000 — within Restack's **hard €50k cap on a *first* proposal** (a larger grant, up to
€150k, is only possible *after* a first Restack/NGI project completes successfully; max €500k per party over
the programme). **Contact:** brandon.sellam@gmail.com.

> 🚨 **NLnet forbids AI‑written proposals.** Restack FAQ (verified 2026‑06‑20): *"Can I use generative AI to
> write parts of my proposal — the short answer is: no… please grant us the courtesy of writing the proposal
> yourself. If you do use generative AI… please put this in the text and explain why… Failure to do so is
> likely to result in the proposal being rejected, and tarnishing your reputation."* **Treat this file as a
> research dossier / fact‑base — Brandon must write the submitted text in his own words** (or disclose AI use +
> justify it). Do NOT paste it verbatim.
>
> Every claim below is honest and **pre‑audit by design** — that is precisely what this grant funds.
> ⚠️ Pre‑submission checklist in [GRANT_TARGETS.md](./GRANT_TARGETS.md): confirm the live call; publish the
> public repo; reconcile doc numbers; get one auditor quote; **apply as an individual** (no legal entity needed —
> FAQ); **timeline ≤ 12 months** (NLnet default; programme ends May 2030); milestones must be *future* work
> (NLnet cannot fund already‑completed effort); F&A/overhead ≤ 25% and generally ineligible.

## 1. Project name
Nerion — an open, post‑quantum, decentralized execution‑governance protocol for AI/agent actions.

## 2. Project summary
Nerion governs what an autonomous AI agent is allowed to **do** — typed actions such as tool‑calls,
API requests, and transaction intents — rather than what it perceives. Design principle: **"govern the
verb, never the eye"** — it never touches perception (no camera frames, no object tracking, no zone
occupancy). Three planes: (1) a stateless deterministic **Hot‑Admission kernel** issuing short‑lived,
action‑bound PermitTokens; (2) **Nearline Assurance** batching post‑quantum (ML‑DSA‑87) receipts into a
Merkle / SCITT‑style transparency log; (3) **Offline Settlement** on a pure proof‑of‑stake ledger with
k‑of‑n quorum governance and PQ long‑term roots. Post‑quantum‑native (ML‑DSA‑87 / ML‑KEM‑1024 / SLH‑DSA), with **hybrid KEMs (ML‑KEM‑1024 + P‑384)** for
crypto‑agility, CNSA 2.0‑aligned, and a **signed CycloneDX CBOM** crypto‑inventory (a build‑transparency
artifact — CNSA 2.0 does not itself define a CBOM format); the open Apache‑2.0 alternative to centralized,
classical, single‑visibility commercial designs that must see every action payload to attest it.

The P0–P4 software build is complete and passes **297 test assertions** with a **20/20 conformance
report** (`npm run conformance` → 20/20 CONFORMANT) — all reproducible from the public Apache‑2.0 repo,
published before submission so reviewers verify rather than take it on trust. The novel cryptographic compositions Nerion
layered **on top of** already‑audited primitives (`@noble`) are, however, **UNAUDITED**. This grant funds
the R&D to harden and externally validate those compositions; an independent cryptography/ZK security
audit — which NGI0 bundles as free practical support — is the central bundled deliverable, sequenced
highest‑risk‑first.

## 3. Team, human accountability, and process credibility
**Named accountable lead:** Brandon Sellam (brandon.sellam@gmail.com) — maintainer; **French (EU) citizen**
(Paris residence; currently also working from New York); owns audit‑remediation and post‑grant maintenance.

> **[TODO — Brandon writes 2–3 sentences of real background here:** prior cryptography / security / protocol /
> open‑source work, roles, or public contributions that show ability to execute. NLnet Stage‑2 explicitly weighs
> "can you execute" — do not leave this blank, and do **not** let AI invent credentials. This is the one place
> the dossier cannot fill for you.**]**

**AI‑assisted authorship, disclosed up front:** Nerion is built with heavy AI assistance under direct
human review. Our "council" is an explicit multi‑agent, multi‑model **adversarial review** process —
independent model lineages that critique and attempt to break each design — **not** an autonomous author.
The council produces candidate critiques; the named human maintainer adjudicates, accepts/rejects, and is
accountable. We treat this transparency as a strength: the process is evidence‑producing, captured in‑repo
as 12 ADRs and council verdicts.

This process found and forced fixes for **real bugs before any external review**: (a) a PermitToken replay
vulnerability (fixed: action‑bound permits); (b) a validator‑set‑binding flaw in quorum receipts (caught
in review, fixed); (c) a `k=0` fail‑open in quorum verification (re‑audit caught it; now fails closed,
`k≥1`); and (d) a soundness gap in the v:2 policy‑satisfaction receipt where a malicious issuer could
carry two unlinked amount commitments — we **deferred shipping** rather than ship an unsound claim. The
same discipline produced auditor‑ and counsel‑ready packages ([AUDIT_PACKAGE.md](../AUDIT_PACKAGE.md),
[FTO_PACKAGE.md](../FTO_PACKAGE.md), [THREAT_MODEL.md](../THREAT_MODEL.md)) that pre‑scope the external
work. We surface our own residual gaps in writing rather than hide them.

## 4. Why it matters / impact / NGI fit
Three converging public‑interest needs in one protocol, mapping onto NGI's privacy, trust‑enhancing, and
decentralization priorities. **First — post‑quantum readiness now:** agent‑action governance + its audit
evidence are deployed today and must survive a CRQC; Nerion is PQ‑native, with a signed CBOM that
machine‑flags the remaining quantum‑vulnerable legs. **Second — provable least‑privilege AI‑action
governance:** as agents proliferate, the unsolved problem is provable, auditable, independently verifiable
bounds on what they can **do** — a denied tool‑call never executes; receipts are externally verifiable
with no operator in the loop. **Third — an open standard vs. a single‑visibility commercial design:**
Nerion's decentralized k‑of‑n quorum receipts (no single host can mint a receipt) and zero‑knowledge
policy‑satisfaction proofs (prove compliance while revealing nothing about the action) are **not available
to** a central‑visibility design that must see every payload to attest it — a property the independent audit
is scoped to confirm. *(We keep this contrast technical, not legal — Nerion is
itself pre‑FTO and makes no legal characterization of any third party's IP; see §7.)*

No adoption requirement; all outputs open‑access; Apache‑2.0 — exactly the novel, emerging, pre‑adoption
R&D NGI0 exists to seed. We are honest there are **no external adopters yet**: this is net‑new research
where R&D is the primary objective.

**European Dimension (Restack hard‑criterion).** The named maintainer is a **French (EU) citizen** maintaining
a **Paris residence** (currently also working from New York). The EU anchor is French citizenship plus an EU
residence; **tax‑residency documentation can be provided on request**, and we intend to add an **EU‑based
co‑maintainer** to deepen EU substance and reduce single‑maintainer risk. Beyond the applicant, Nerion's
*substance* is squarely European: an open, vendor‑neutral, post‑quantum building block for the EU's **Open
Internet Stack / Tech‑Sovereignty** agenda and European digital autonomy. Its most on‑point regulatory hook is
the **EU AI Act** — Nerion delivers auditable, least‑privilege governance and transparency over what
high‑risk AI systems are permitted to *do*, the very accountability the Act targets. On the cryptographic side
Nerion already ships **hybrid KEMs (ML‑KEM‑1024 + P‑384)**, matching **ENISA's hybrid PQC‑migration**
guidance rather than a pure‑PQ leap. Outputs are Apache‑2.0 European commons; standardisation will be pursued
through IETF/W3C/ETSI/OASIS (incl. an intended work‑item on the "govern‑the‑verb" profile) and presented at
European venues (FOSDEM, IETF, RIPE).

**Eligible‑activity mapping (Restack's list, verbatim).** The funded work maps one‑to‑one onto Restack's
named eligible activities: *scientific research* (ZK soundness), *design/development of FOSS*, *formal
security proofs + security audits + test/CI setup* (the core deliverable), *standardisation activities
including membership fees of standards bodies* (the "govern‑the‑verb" profile + COSE/RATS codepoints),
*documentation*, and *packaging for deployability*.

**Sustainability (Stage‑2 anticipates this).** Nerion is built to outlast the grant: an open Apache‑2.0
**standard**, not a hosted service with running costs; reproducible verification anyone can run; and a clear
path to follow‑on Restack grants (≤€150k after a first project completes) plus EU public‑sector / enterprise
adoption as the agent‑governance need matures. The named maintainer owns post‑grant maintenance.

## 5. The R&D + audit work — tiered scope, ZK‑first (core deliverable)
Harden + prove the **five novel compositions** over audited `@noble` primitives, with an independent
ToB/NCC/Cure53‑grade cryptographic‑protocol audit as the bundled validation deliverable. Scope is
**tiered** so a reviewer sees a deep, fundable engagement on the highest‑risk crypto:

**FUNDED CORE (Tier 1):**
- **(A) ZK range proof — HIGHEST RISK, audit first** (`disclosure/zkrange.ts`): Pedersen/ristretto255 +
  bit‑decomposition + Chaum‑Pedersen OR‑proofs, SHAKE256 Fiat‑Shamir, dual‑range, n≤252 cap. Verify
  soundness, OR‑proof simulation/special‑soundness, generator‑H provenance, and strong (transcript‑binding)
  Fiat‑Shamir for Frozen‑Heart resistance — all to be **confirmed by the audit, not asserted**. Every privacy
  claim rests on this → sequenced first.
- **(B) ZK policy‑satisfaction composition** (`disclosure/policyproof.ts`): hidden‑amount `≤ ceiling` /
  `aggregate+amount ≤ cap`. Confirm via the audit that it preserves Pedersen perfect‑hiding and that soundness
  reduces to discrete‑log — intended properties **to be established by the auditor, not pre‑asserted**.
  **Includes designing + implementing the v:2 Pedersen↔SHA3 commitment‑to‑intent equality proof** — deferred
  from the build *precisely because it is the new cryptographic R&D this grant funds* (residual gap 1) — and
  re‑verifying it. This is the primary R&D deliverable, not a previously‑promised feature. A design decision
  record (**ADR‑0013**), sharpened by adversarial council review, specifies a **structural commitment‑binding**
  approach (embed the Pedersen commitment in the hashed intent, reuse the existing opening/range proofs) that
  **avoids a heavy ZK circuit entirely** — scoped, and materially lower‑risk than first thought.

**SECONDARY / STRETCH (Tier 2 — kept *within* the €50k first‑grant cap; covered by M5 if the audit quote
leaves room, otherwise explicitly deferred to a follow‑on Restack grant after this project completes —
**never** scaled beyond €50k on a first proposal, per Restack's rules):**
(C) ECVRF (`ledger/vrf.ts`) blast‑radius + malleability; (D) k‑of‑n quorum receipts (`receipts/quorum.ts`)
safety/binding/fail‑closed; (E) COSE_Sign1 + RATS/EAT (`crypto/cose.ts`) canonicalization + alg binding.

**Three known residual gaps** for the auditor to confirm + rate: (1) v:2 Pedersen↔SHA3 equality gap
(funded Tier‑1 remediation under B); (2) ≥2/3 view‑change round‑skip (LEDGER‑007, stated fairness‑only);
(3) software OTS‑state reuse‑under‑restore (hard‑gated dev‑only). Patent FTO is **out of audit scope** — a
separate counsel gate we are **not** asking NGI0 to fund.

**Milestone budget (NLnet pays per completed milestone — EUR 45,000):**
| M | Deliverable | EUR |
|---|---|---|
| M1 | Audit scope‑freeze + threat‑model walkthrough + auditor onboarding pack (future prep; repo publication itself is unbilled pre‑work) | 4,000 |
| M2 | ZK range‑proof + OR‑proof audit findings (component A) | 16,000 |
| M3 | Policy‑satisfaction findings + Pedersen↔SHA3 equality‑proof **design** (B + gap 1) | 9,000 |
| M4 | Equality‑proof **implementation** + re‑verification (core dev deliverable) | 9,000 |
| M5 | Public audit report + remediated release (+ C–E / gaps 2–3 as budget covers) | 7,000 |

**Basis & money‑flow.** Figures are rate‑based (~€90–110/h: one senior maintainer + a contracted ZK
specialist for the audit interface). **The independent ZK/crypto audit is sourced through NLnet's in‑kind
audit support** (Restack lists "security audits" as programme support); the €45k milestones therefore fund the
**R&D, the new dev (the Pedersen↔SHA3 equality proof), remediation, and audit‑interface work — not the audit
firm's fee.** If NLnet's audit support does not fully cover a ZK‑specialist review (~€25k–40k for A–B), M2/M5
co‑fund the gap and Tier‑2 (C–E) defers. **The v:2 commitment‑binding (M3–M4)** was first scoped as a
novel ZK equality proof, but adversarial council review (ADR‑0013) replaced it with a **structural** binding —
embed the Pedersen commitment in the hashed intent and reuse the existing opening/range proofs — which removes
the heavy‑ZK‑circuit risk; a general‑purpose SNARK remains only a documented last resort.
**Hours basis (≈€100/h):** M1 ≈40h · M2 ≈160h · M3 ≈90h (design) · M4 ≈90h (implementation + re‑verify) ·
M5 ≈70h → ~450h over ≤12 months. **Audit independence:** the review is performed by an **independent
third‑party firm** (Trail of Bits / NCC / Cure53); NLnet only *sources/funds* it, so independence is preserved
and the proof *design* (ADR‑0013) stays separate from its *verification*.
*Get one indicative auditor quote before submission so M2–M5 rest on a real figure, not an estimate.*

## 6. Open‑source proof
**License: Apache‑2.0** (in `package.json` AND a root `LICENSE` file). All outputs open‑access. Built on
public standards: RFC 9381 (ECVRF, with KATs), RFC 6962 (Merkle log), RFC 9052 (COSE), RATS/EAT, SCITT‑
style transparency, NIST FIPS 203/204/205, NSA CNSA 2.0 (machine‑checkable oracle in‑repo). **Plan: publish
the public Apache‑2.0 repo BEFORE submitting** (LICENSE + code are ready; publication is near‑zero cost) so
open‑source evidence exists at review time. Reproducible checks ship with it (`npm run gate`,
`npm run conformance`, external receipt‑verification CLI).

## 7. Current status — the honest status (non‑negotiable; this candor is the credibility edge)
The P0–P4 build is complete: **297 test assertions pass, 20/20 CONFORMANT**, and a Rust hot‑path foundation
compiles. That is the entirety of what code alone can close. **The protocol compositions are UNAUDITED and
the project is PRE‑FTO.** Every security property the project asserts is a **claim, not an established
fact**, until an external firm's report exists; passing the vectors is **KAT conformance only**, not
protocol security. We make **no** claim that Nerion is audited, production‑ready, FIPS‑validated, or
non‑infringing, and we make **no** legal characterization of any competitor's IP. Four external gates stand
between code‑complete and any public claim — FTO (counsel), **this audit**, FIPS hardware, FIPS CMVP
validation — **none closable by the project alone**, all prepared, none closed. *Conformant is not
validated; built is not audited; provisioned is not in‑use; design‑around is not a legal opinion. Nerion
is pre‑audit — which is exactly why it needs this grant.*

## 8. Differentiation (Stage 2)
Unlike a centralized, classical, single‑visibility commercial commit‑point gate — which depends on seeing
every payload — Nerion is open, post‑quantum, decentralized, and zero‑knowledge: no single host can mint
a receipt, and compliance is provable without revealing the action. Unlike audit‑only programmes that need
established, widely‑depended‑upon infrastructure, Nerion is **novel pre‑adoption R&D** where R&D is the
primary objective — NGI0's target profile — with the audit as a bundled validation deliverable, not a
request to rubber‑stamp finished code. The funded dev work (implementing the deferred Pedersen↔SHA3
equality proof) is genuine new cryptographic engineering.

**vs. existing open efforts (Stage‑2: "how do you differ from projects U, V, W?").** Nerion is
complementary to — and distinct from — today's building blocks: policy engines (OPA/Rego) decide
allow/deny but are classical and emit no post‑quantum, externally‑verifiable receipt; capability systems
(UCAN, macaroons, SPIFFE/SPIRE) convey *authority* but do not prove *policy satisfaction in zero‑knowledge*;
supply‑chain transparency (in‑toto, SCITT, SLSA) attests *artifacts*, not *runtime agent actions*. Nerion
composes these ideas into a PQ‑native, decentralized, zero‑knowledge runtime fence for what an agent may
**do**, and deliberately *reuses* their standards (COSE, SCITT‑style logs, RATS/EAT) rather than reinventing
them — interoperability over lock‑in, exactly Restack's thesis.
