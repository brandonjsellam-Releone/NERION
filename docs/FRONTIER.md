# Nerion — Frontier directions ("beyond the backlog")

> Output of a **TRELYAN AI Council frontier scan** (8 model lineages + live-web Scout, 2026-06-21).
> This is a **RESEARCH COMPASS, not a commitment and not a claim of completion.** Every direction is
> tiered (buildable-now / research-bet / speculative) and names its hardest open problem. **Nothing here
> is implemented or audited.** The honesty discipline is non-negotiable: *conformant is not validated;
> built is not audited; a design-around is not freedom-to-operate.* The funded path stays: harden +
> independently audit the existing ZK/PQ compositions first (see [AUDIT_PACKAGE.md](./AUDIT_PACKAGE.md));
> the frontier informs *direction*, not premature claims. Near-term funded work: [APEX_SPRINT_BACKLOG.md](./grants/../APEX_SPRINT_BACKLOG.md).

## The convergent #1 frontier: PQ, ZK-provable *capability verbs* bound to agent-identity standards
Independently surfaced by four seats (ChatGPT, DeepSeek, Hermes, Mistral). Evolve PermitTokens from
per-action permits into **delegatable, attenuable, zero-knowledge capability tokens** that:
1. carry a **formal, machine-checkable Action Manifest** ("policy-carrying verbs": type, authority scope,
   preconditions, expected effects, risk class, policy hash, tool/model provenance, replay domain);
2. **bind to standardized agent identities** — W3C Verifiable Credentials / DIDs, **eIDAS 2.0 / EUDI
   wallet**, and the emerging IETF agent-authorization work (`draft-klrc-aiagent-auth`, OAuth
   "transaction tokens for agents", AAuth);
3. prove the **delegation chain in zero-knowledge** without revealing it (PQ macaroon/attenuation style).

- **Tier:** buildable-now incrementally; full ZK-attenuation = research-bet.
- **Why frontier:** makes "govern the verb" *portable and standards-native* — an action carries its own
  authorization envelope, provenance, and audit semantics, interoperable with the identity rails the EU is
  actually deploying. A real design-around moat that is *not* perception-monitoring.
- **Grant leverage:** direct **eIDAS 2.0 / EU AI Act** hook → deepens the NLnet European-Dimension story.
- **Hardest open problems:** a ZK-friendly **capability/attenuation language** with witness size linear in
  attenuation depth (not the whole authority tree), PQ-safe signature verification inside the circuit
  (DeepSeek); and an **action ontology** precise enough to enforce yet general enough to prevent
  **"semantic laundering"** — relabeling a dangerous verb as a harmless one (ChatGPT).

## Tiered frontier map
**Buildable now (engineering; no new crypto assumptions):**
- Formal **Action Manifest** (canonical CBOR) bound into the PermitToken digest. *(ChatGPT)*
- **Standards profile:** PermitToken <-> W3C VC / eIDAS-VC / agent-auth-token mapping. *(Mistral, DeepSeek, Scout)*
- **PQ DIDs** for agent identity (`did:key` over SLH-DSA / ML-DSA). *(DeepSeek)*
- Multi-signature **quorum receipts** as the conservative precursor to threshold-PQ. *(ChatGPT)*

**Research bets (new constructions / maturing primitives):**
- **PQ-succinct ZK** (FRI/STARK with PQ hashes, or lattice functional commitments) for *whole-trace* policy
  proofs. Hardest: a practical (<100 ms prover, <10 KB proof) **trusted-setup-free PQ-SNARK** under
  CNSA-2.0; STARKs are PQ but proofs are ~100-200 KB. *(DeepSeek)*
- **Threshold post-quantum signatures** for private multi-authority admission (DKG, proactive refresh,
  accountable aborts) — **not yet standardized/audited for ML-DSA**; stage conservatively. *(ChatGPT)*
- **Intent->action witnessing** for tool-use (MCP / A2A): prove an executed tool call satisfies the permit's
  schema predicates. Hardest: a sound intent->predicate mapping that **survives prompt injection / model
  updates**. *(Hermes, ChatGPT)*
- **PQ-native SCITT** for AI supply-chain integrity (CRA / RoPA). Hardest: ML-DSA signature size at high
  action frequency -> aggregation. *(Mistral)*

**Speculative (multi-year / partly non-cryptographic):**
- **Programmable recourse** — permits backed by stake / insurance / dispute rights; receipts become the
  substrate for slashing / claims / arbitration. Defensible only for *digitally-verifiable* actions; the
  off-chain harm-adjudication oracle problem dominates for physical/social harms. *(ChatGPT)*
- **Inter-domain governed composability** — one aggregated proof that a workflow satisfied *each* domain's
  policy across heterogeneous governance domains (proof-carrying data / folding). Hardest: cross-domain
  *semantic* agreement without a shared root of trust. *(DeepSeek)*
- **Reflexive self-governance** — validator-set / view-change changes as ordinary governed verbs. Hardest:
  the circularity of the to-be-removed set validating its own removal. *(Grok)*
- **Decentralized AI-action certification** recognized as an EU AI Act conformity path. Hardest: legal
  recognition + liability — a multi-year regulatory battle. *(Mistral)*

## Recommended first frontier build
The **standards-binding profile** (PermitToken <-> W3C VC + eIDAS-VC + agent-auth-token, plus the Action
Manifest schema) is the highest-leverage *buildable-now* step: an ADR + a profile doc + an additive
encoding, needing **no unaudited new crypto**, and the strongest single grant differentiator. Proposed as
the next Track-B ADR.

---
*Council seats engaged 2026-06-21: ChatGPT, Grok, DeepSeek, Mistral, Watsonx, Hermes, Claude. Gemini
errored (network). Perplexity/Scout supplied the live-standards source set: IETF agent-auth +
OAuth-transaction-tokens-for-agents drafts, eIDAS 2.0 / EUDI, W3C VC/DID 2.x, BBS signatures, PQ anonymous
credentials, SCITT architecture, Google Merkle-Tree-Certs, succinct/STARK proving.*
