# PolarSeek — Freedom-to-Operate (FTO) Reminder

> ============================================================================
> 🚩 BANNER — DO NOT REMOVE. RE-EMIT IN EVERY RELEASE NOTES FILE. 🚩
> This reminder MUST be copied verbatim (or linked + summarized) into every
> release notes / CHANGELOG entry until a patent-counsel FTO opinion is on file.
> No public non-infringement claim, marketing statement, or launch may proceed
> without that opinion. If you are reading release notes and do not see this
> banner, STOP and restore it.
> ============================================================================

## What this document is — and is NOT

PolarSeek's architectural choices — most notably **"govern the verb, never the eye"**
and the **stateless-kernel architecture** — are **ENGINEERING INTENT**. They were
chosen, in part, to design *around* the patent family described below.

- This is **ENGINEERING INTENT to avoid that patent family**.
- This is **NOT a legal opinion.**
- This is **NOT a non-infringement guarantee.**
- Design intent does not establish non-infringement. Only qualified patent
  counsel, reading the actual issued claims against our actual implementation,
  can opine on that — and even then, an opinion manages risk; it does not
  eliminate it.

Nobody on the engineering, product, marketing, or leadership team may state or
imply publicly that PolarSeek "does not infringe," "is clear of," "designs
around," or "is unaffected by" these patents until a written FTO opinion from
qualified patent counsel is on file.

## The patent family at issue

The **SIGA / "Sovereign OS" / "Commit-Point Gate"** family. Known/asserted scope
(to be verified by counsel — treat these as inputs, not findings):

- Claimed **45 granted patents** in the family.
- Claimed **priority date of 2012**.
- Claimed coverage across **20 jurisdictions**.
- Claimed subject matter spans **both AI perception AND governance** — i.e., it
  is not limited to one layer of the stack.

Because the claimed scope reaches both perception and governance, our
"govern the verb, not the eye" boundary is a *hypothesis* about where their
claims stop, not a verified fact. Counsel must test that boundary.

## ACTION REQUIRED — before any public non-infringement claim or launch

**Obtain a written freedom-to-operate (FTO) opinion from qualified patent
counsel BEFORE** any of the following: public non-infringement statements,
marketing/positioning that references these patents or "designing around" them,
investor/customer assurances, or general-availability launch.

### What counsel must concretely review

**(a) The specific SIGA patents and claims.**
   - Enumerate the actual patent numbers in the family (verify the "45 granted").
   - For each relevant patent: the specific **independent and dependent claims**,
     the **priority date(s)** (verify "2012"), and the **jurisdictions** where
     granted/pending (verify "20").
   - Identify which claims read on perception vs. governance.

**(b) PolarSeek's admission-path design vs. those claims.**
   - Map our admission path (how an action is proposed, evaluated, and admitted
     or rejected) element-by-element against the claim limitations.
   - Confirm whether "govern the verb, never the eye" actually places our
     implementation outside the asserted claims, or merely outside *some* of them.
   - Stateless-kernel architecture: confirm whether the absence of retained
     state distinguishes us from claims that presume a stateful/sovereign
     control layer.

**(c) The "commit-point gate" terminology.**
   - Determine whether continued internal/external use of the phrase
     **"commit-point gate"** (which mirrors the patent family name) creates
     willfulness, marking, or estoppel risk.
   - Advise whether to **avoid this term in all public-facing materials**
     (docs, marketing, talks, code comments shipped to users, API names).

**(d) Export-control / dual-use crypto considerations.**
   - Review any cryptography in PolarSeek for export-control / dual-use
     classification (e.g., EAR/ECCN, Wassenaar) and whether our distribution
     model triggers filing or licensing obligations across target jurisdictions.

**(e) The accountable-operator legal entity.**
   - Identify which legal entity is the **accountable operator** for PolarSeek
     and bears infringement / export / liability exposure.
   - Confirm the FTO opinion is addressed to and relied upon by that entity, and
     that indemnification and insurance posture match the launch footprint.

## Checklist (must be 100% complete before public non-infringement claim or launch)

- [ ] Full SIGA patent list enumerated and verified (count, numbers).
- [ ] Priority date(s) verified for each relevant patent.
- [ ] Jurisdiction coverage verified for each relevant patent.
- [ ] Relevant independent/dependent claims identified and charted.
- [ ] Admission-path design mapped element-by-element against claims (item b).
- [ ] "Govern the verb, never the eye" boundary tested by counsel against claims.
- [ ] Stateless-kernel distinction assessed against stateful-control claims.
- [ ] "Commit-point gate" terminology risk assessed; public-use guidance issued.
- [ ] Public/marketing materials scrubbed per counsel's terminology guidance.
- [ ] Export-control / dual-use crypto classification completed (item d).
- [ ] Accountable-operator legal entity identified and named in the opinion (item e).
- [ ] Written FTO opinion received, on file, and addressed to the accountable entity.
- [ ] Leadership sign-off recorded that no public non-infringement claim or launch
      proceeds ahead of the opinion.
- [ ] This banner confirmed present in the current release notes file.

## Reminder

Until every box above is checked and the written FTO opinion is on file: do not
launch, and do not make any public non-infringement claim. Re-emit the banner at
the top of this document in **every** release notes file.
