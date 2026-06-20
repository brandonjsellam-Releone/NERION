# FTO Recon — US 9,607,214 B2 Claim Chart (ENGINEERING LITERAL‑SCOPE ONLY, NOT A LEGAL OPINION)

> **This is an engineering literal‑scope comparison of one patent's independent claim 1, on its face.**
> It expresses **no legal opinion** on infringement (literal or under the doctrine of equivalents),
> validity, or enforceability. Full claim construction, doctrine‑of‑equivalents analysis, the dependent
> claims, the prosecution history, and review of the broader (claimed, **unverified**) ~45‑patent
> family are all **deferred to qualified patent counsel.** This note exists to *accelerate and cheapen*
> counsel's work — it is **not** a finding that PolarSeek does not infringe anything.

## What the anchor patent actually is

- **Patent:** US 9,607,214 B2 — **Title: "Tracking at least one object."**
- **Abstract:** camera/image‑based tracking of objects. *(A prior transcription here quoting a
  parking‑space abstract matched a sibling family member and is flagged for re‑verification; the **claims
  below were re‑verified verbatim from Google Patents on 2026‑06‑20** and are authoritative for scope.)*
- **It is a camera‑based vehicle/parking‑tracking patent.** The SIGA Feb‑2026 deck re‑characterizes this
  *same* patent as a "Sovereign OS / Commit‑Point Gate" governing "every machine action / inference /
  tool‑call / transaction." That characterization is **far broader than the actual claim language**
  (council‑confirmed: "the gap is enormous"). Stated here only as a juxtaposition for counsel — **not** a
  conclusion. (Counsel must also check whether the deck's "governance" assertions rest on *other*
  patents in the unverified family.)

## Independent claims (re‑verified verbatim from Google Patents, 2026‑06‑20)

US 9,607,214 B2 has **three independent claims — 1 (method), 29 (system), 30 (pedestrian method)** — and 27
dependents. **A prior transcription in this file recited a "destination location / identification camera /
database" claim; that matched a *sibling* family member (≈ US 9,036,027), not this patent, and is corrected
below.** The correction makes the design‑around *stronger*, not weaker.

### Independent claim 1 — "A method of tracking at least one object, the method comprising:"
- **[E1]** "receiving **four or more first images** showing a first object";
- **[E2]** "determining, based on … the four or more first images, a **first/second static characteristic**"
  of the object (static characteristic = **color, outline, size, dimension** — cl. 7);
- **[E3]** "determining, based on two … of the four or more first images, a **first/second dynamic
  characteristic**" (dynamic characteristic = **a speed of travel and/or a direction of travel**);
- **[E4]** "**comparing** the second static characteristic to the first static characteristic" + a result;
- **[E5]** "**comparing** the second dynamic characteristic to the first dynamic characteristic" + a result;
- **[E6]** "determining, in response to the **approximate equivalence** between the second and first static
  (and dynamic) characteristics, [that the images track the same object]"; "the steps of receiving,
  determining and comparing are performed by one or more processors."

### Independent claim 29 — system version
"A system for tracking at least one object, comprising one or more processors configured to" perform the
same receive‑images / static + dynamic characteristic / compare steps as claim 1. **Same image‑receipt core.**

### Independent claim 30 — pedestrian method
"A method of tracking at least one pedestrian" — "receiving four or more first images showing a first
**pedestrian, a first vehicle, and a payment station**…" then the same characteristic‑comparison steps.
(Explicitly parking‑enforcement.)

**Every independent claim is anchored on "receiving four or more images" of a physical object and deriving
visual static/dynamic characteristics from them.** Dependents confirm the field: roadways/parking lots
(cl. 2), cameras (cl. 3–4), real‑time tracking to **law enforcement** (cl. 5–6), **license plates** (cl.
19–20), a **drone** second camera (cl. 24), a **third‑party parking‑payment station** (cl. 25–27).

## Literal‑scope comparison (on its face — the all‑elements rule)

A claim is literally infringed only if **every** element is present. PolarSeek's admission kernel
receives **typed digital action intents** (canonical‑CBOR tool‑calls / API / transactions) and has **no
camera, no image, no video, no vehicle, no cross‑frame tracking, and no perception input of any kind.**

| Claim element (all 3 independents share [E1]) | PolarSeek (as built) | Practiced on its face? |
|---|---|---|
| **[E1]** receive **four or more images** of a physical object | kernel input is a single typed CBOR action intent; **no image, no camera, no object** exists in the system | **No** |
| **[E2]** **static visual characteristics** (color/outline/size/dimension) from images | no images; no visual feature extraction of anything | **No** |
| **[E3]** **dynamic characteristics** (speed / direction of travel) from images | no images; nothing in the system has a speed or direction of travel | **No** |
| **[E4]/[E5]** **compare** static/dynamic characteristics across images | authorization is PQ‑signature verification of a capability token, not cross‑image comparison | **No** |
| **[E6]** determine sameness via **approximate equivalence** of visual characteristics | decisions are exact deterministic policy evaluation over typed fields — not approximate visual matching | **No** |
| cl. 29 system "to track at least one object" / cl. 30 pedestrian + vehicle + payment station | no objects, pedestrians, vehicles, or payment stations anywhere in PolarSeek | **No** |

**Engineering observation (not a legal conclusion):** on the literal language of claim 1, a system with
no perception input cannot meet [E1] ("receiving a plurality of vehicle images captured by a plurality
of cameras") or any of the determinations that depend on those images. This is the literal‑scope basis
of the "govern the verb, never the eye" design‑around **for this anchor patent only.**

## Patent‑family reconnaissance (head start for counsel — engineering, not legal)

The searchable **CloudParc Inc.** granted portfolio (inventors **Steven D. Nerayoff + Thompson S. Wong**,
priority **2012‑08‑06**; the anchor expires ~2032‑11‑27) — every title is parking‑camera:

| Patent | Title |
|---|---|
| US 8,817,100 | Controlling use of parking spaces using cameras |
| US 8,830,322 | Controlling use of a single multi‑vehicle parking space … using multiple cameras |
| US 8,836,788 | Controlling use of parking spaces and restricted locations using multiple cameras |
| US 8,982,213 | Controlling use of parking spaces using cameras and smart sensors |
| US 9,036,027 | Tracking the use of at least one destination location |
| **US 9,607,214** (anchor) | Tracking at least one object |
| US 2016/0078299 (app) | Imaging a Parking Display Ticket |

**Engineering observation (not a legal conclusion):** the granted family SIGA's deck re‑characterizes as
"Sovereign OS / Commit‑Point Gate governing every machine action" is, by its actual titles + assignee, a
**parking‑enforcement camera portfolio** in a different field from PolarSeek's digital‑action governance.

**THE OPEN RISK counsel MUST resolve (do not treat the above as clearance):** SIGA's deck claims **~45
granted patents** and **~500 provisionals filed 2026** across **~20 jurisdictions.** The searchable
granted family is only ~7 patents — so either the "~45/~500" figures are inflated/counting foreign
counterparts + provisionals, **or** there are patents/applications not surfaced here. Critically, the
**claimed ~500 provisionals (2026) are UNPUBLISHED and not searchable** — they could recite anything,
including governance claims, and continuation/submarine claims can be tailored later. The granted family
being parking‑cameras does **not** clear the unpublished pipeline. Counsel must obtain the full, verified
estate.

## What counsel must still do (this note does NOT do)

1. Construe the claims (claim construction / *Markman*) and review the prosecution history.
2. Construe the **three independent claims now identified — 1 (method), 29 (system), 30 (pedestrian)** —
   plus the 27 dependents and the prosecution history.
3. Perform the **doctrine‑of‑equivalents** analysis — could a camera/vehicle/parking claim be argued to
   reach a digital‑action governor? (On its face the fields and functions differ greatly, but DOE is
   counsel's call, not engineering's.)
4. **Enumerate and verify the actual SIGA patent family** (the ~45‑granted / ~500‑provisional / 2012 /
   ~20‑jurisdiction figures are unverified deck inputs) and clear each relevant patent + jurisdiction.
5. Deliver a **written, jurisdiction‑specific FTO opinion** before any public non‑infringement claim.

## Why this is useful (cost impact)

Because the anchor patent is, on its face, a **parking‑camera method** and PolarSeek has **no perception
input at all**, a scoped single‑patent FTO opinion (per [FTO_PACKAGE.md](./FTO_PACKAGE.md)) is a clean,
fast read for counsel — a camera‑vehicle claim against a no‑camera digital protocol. This recon does not
replace that opinion; it makes it cheaper and faster, and tells counsel exactly where to look.

*Sources: **all 30 claims re‑verified verbatim from Google Patents (US9607214B2/en) on 2026‑06‑20** — 3
independent (1 / 29 / 30), 27 dependent; this corrected a prior transcription that matched a sibling family
member's "destination location" claim. Earlier council cross‑check (DeepSeek/Grok) retained. The abstract was
not re‑pulled this pass — flagged for re‑verification.*
