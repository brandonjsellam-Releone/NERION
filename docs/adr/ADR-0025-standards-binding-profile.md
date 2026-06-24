# ADR-0025: Standards-binding profile -- PermitToken as a PQ, ZK-attenuable capability credential

## Status
**Accepted — Phase-A implemented (2026-06-24).** Layers (1) and (2) are shipped in
`planes/src/vc-projection.ts`; see ADR-0030 for implementation decisions and completion record.
The ZK-attenuation proof (layer 3) remains a flagged research-bet behind `allowUnauditedZk`,
unimplemented and audit-gated. UNAUDITED; pre-FTO. No legal/conformity claim is made.

## Context
The 8-model TRELYAN council frontier scan (2026-06-21) converged on binding Nerion's "govern the verb"
model to the agent-identity standards now being defined:
- **W3C Verifiable Credentials 2.x + DIDs** -- portable signed claims + decentralized identifiers.
- **eIDAS 2.0 / EUDI wallet** -- the EU's deploying identity rail (a direct EU AI Act hook).
- **IETF agent-authorization (emerging):** `draft-klrc-aiagent-auth`, OAuth "transaction tokens for
  agents", AAuth -- classical and mostly centralized today.
- **BBS / PQ anonymous credentials, SCITT** -- selective disclosure + transparency.

Today's agent-auth is classical and centralized. Nerion can be the **open, post-quantum, zero-knowledge,
decentralized** profile -- arriving before the standards solidify. The current PermitToken (HMAC-SHA-384,
action-bound, audience-scoped) already does the hard part (binding authorization to a typed action); it
lacks a *portable credential envelope* and a *formal action schema*.

## Decision
An additive **standards-binding profile** in three layers:

**(1) Action Manifest (buildable-now).** A canonical (dCBOR) schema bound into the PermitToken/receipt
digest: `{ verb, authorityScope, preconditions[], expectedEffects[], riskClass, policyHash,
provenance{tool,model,software}, replayDomain, expiry }`. The kernel admits against the manifest; the
receipt commits to its digest. This makes the verb self-describing and audit-legible -- and is the
structural defense the council flagged against **semantic laundering**: a `verbId` + `policyHash`
namespace, not free-text labels.

**(2) Credential / identity binding (buildable-now).** Map the PermitToken to a **W3C VC**
(`credentialSubject` = the Action Manifest; `issuer` = the admission authority's DID) and the agent to a
**PQ DID** (`did:key` over ML-DSA-87 / SLH-DSA). Provide **eIDAS-2.0 / EUDI-VC** and **IETF
agent-auth-token** renderings of the same token, so a Nerion permit is consumable by those rails. All
additive -- the wire-frozen v:1 token (SuiteID `Ps1`) is unchanged; the profile is a *projection*.

**(3) ZK delegation-chain attenuation (research-bet -- flagged, gated).** Prove in zero-knowledge that a
possessed capability chain authorizes the current action *without revealing the chain* (PQ
macaroon/attenuation style), reusing the disclosure ZK stack. Fenced behind `allowUnauditedZk`; routes to
the external audit. NOT part of the buildable-now core.

## Soundness / security argument
- Layers (1)+(2) introduce **no new cryptographic assumptions** -- canonical encoding + existing
  ML-DSA/SLH-DSA signatures + standard VC/DID serialization. Soundness = the existing
  PermitToken/receipt binding (ADR-0013/0016/0018) plus signature security of the issuer DID.
- Layer (3) is genuinely hard and UNAUDITED. Hardest open problems (council): a ZK-friendly
  **attenuation language** whose witness size is linear in *attenuation depth*, not the whole authority
  tree; PQ-safe signature verification inside the circuit; and an **action ontology** precise enough to
  enforce yet general enough to avoid semantic laundering. These are the audit's scope, not assertions.
- **No claim** of eIDAS "qualified" status or legal conformity -- the profile is *technically
  interoperable*; legal recognition is explicitly out of scope.

## Implementation plan
- **Phase A (buildable-now, additive):** Action Manifest dCBOR schema + kernel admission against it +
  receipt commitment; a PQ `did:key` encoder; a VC / eIDAS / agent-auth-token projection module. Behind a
  `standardsProfile` capability flag; v:1 unchanged. New conformance check + additive KAT vectors (do NOT
  touch `conformance/vectors/ps-*.json` v:1 freeze or SuiteID `Ps1`; add a profile section to gen-kat).
- **Phase B (research-bet, gated):** the ZK delegation-chain proof, behind `allowUnauditedZk`, audited
  before any default-on.
- Keep `npm run gate` + `npm run conformance` green; additive only.

## Alternatives considered
- Classical OAuth / macaroons + standard VCs (not PQ, not ZK, not decentralized -- loses the thesis).
- Pure-VC without action-binding (loses "govern the verb").
- A bespoke identity format (loses interop and the EU hook -- the point is to ride the standards).

## Consequences
- **+** Strongest grant differentiator: a direct EU AI Act / eIDAS 2.0 hook -> deepens the NLnet
  European-Dimension; first-mover open PQ+ZK agent-auth profile.
- **+** Interop with the rails the EU + IETF are deploying; portable, audit-legible verbs.
- **-** Schema/ontology governance burden (the verb namespace); the ZK-attenuation is a real research bet,
  not a quick win -- it must stay flagged and audit-gated.

## References
[../FRONTIER.md](../FRONTIER.md) - ADR-0013 (v:2 receipt) - ADR-0016 (generator-H) - ADR-0018 (amount
domain) - W3C VC 2.x / DID - eIDAS 2.0 / EUDI - IETF draft-klrc-aiagent-auth, OAuth
transaction-tokens-for-agents - BBS (draft-irtf-cfrg-bbs-signatures) - SCITT (draft-ietf-scitt-architecture).
