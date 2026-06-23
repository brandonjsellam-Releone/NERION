// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// CAP-001 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
// (Spike id CAP-001; unrelated to the code's "CAP-001" suite-binding audit comment.)
//
// Read-only intake (capabilities/src/capability.ts): Nerion ALREADY has offline-attenuable
// delegation — but via ML-DSA-87 SIGNATURE-CHAINS (each delegation link is a separate PQ signature
// by the holder of the parent's subject key; attenuate() is offline; verifyChain() checks each link
// against a TRUSTED ROOT PUBLIC KEY). So the premise "Macaroons add attenuation Nerion lacks" is FALSE.
//
// Real question: SIGNATURE-chain (Nerion) vs HMAC-chain (Macaroon) capabilities — the architecture
// tradeoff. We build a Macaroon-style HMAC-chained capability (PQ: HMAC-SHA-384), measure size/speed,
// and contrast with the signature-chain's real cost (ML-DSA-87 sig = 4627 B/link, FIPS-204). The catch
// the council should sharpen: HMAC-chain verify needs the ROOT SECRET → only shared-secret verifiers,
// NO public/decentralized verification, no delegate identity. node:crypto only; no repo imports.
// ─────────────────────────────────────────────────────────────────────────────

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'

const HMAC = (key, msg) => createHmac('sha384', key).update(msg).digest() // 48-byte tag (PQ-safe)

// ── Macaroon-style HMAC-chained capability ──
function mint(rootKey, identifier, caveats) {
  let tag = HMAC(rootKey, Buffer.from(identifier))
  for (const c of caveats) tag = HMAC(tag, Buffer.from(c))
  return { identifier, caveats: [...caveats], tag }
}
// OFFLINE attenuation — appends a caveat, re-HMACs with the previous TAG as key. No rootKey needed.
function attenuate(m, caveat) {
  return { identifier: m.identifier, caveats: [...m.caveats, caveat], tag: HMAC(m.tag, Buffer.from(caveat)) }
}
// Verify — REQUIRES the rootKey (symmetric). Replays the chain + checks each first-party caveat.
function verify(rootKey, m, satisfies) {
  let tag = HMAC(rootKey, Buffer.from(m.identifier))
  for (const c of m.caveats) {
    if (!satisfies(c)) return false
    tag = HMAC(tag, Buffer.from(c))
  }
  return tag.length === m.tag.length && timingSafeEqual(tag, m.tag)
}
const macaroonBytes = (m) => Buffer.byteLength(m.identifier) + m.caveats.reduce((a, c) => a + Buffer.byteLength(c), 0) + m.tag.length

// ── signature-chain (Nerion's actual model) cost reference ──
const MLDSA87_SIG = 4627 // FIPS-204 (real); each delegation link carries one
const MLDSA87_PK = 2592
const GRANT_BODY = 200 // approx canonical-CBOR grant body bytes/link (issuer/subject/actions/limits/window)

// ── run ──
console.log('CAP-001 — HMAC-chain (Macaroon) vs SIGNATURE-chain (Nerion) attenuable capabilities')
console.log('Nerion already has offline attenuation via ML-DSA-87 signature-chains; this measures the tradeoff.\n')

// correctness + offline-attenuation + tamper rejection
const rootKey = randomBytes(32)
const base = mint(rootKey, 'cap:agent-42', ['action=transfer', 'amount<=100'])
const deleg = attenuate(base, 'counterparty=acme') // OFFLINE — rootKey not in scope of attenuate()
const ctx = { 'action=transfer': true, 'amount<=100': true, 'counterparty=acme': true }
const okHonest = verify(rootKey, deleg, (c) => ctx[c] === true)
// forged caveat removed → tag mismatch
const stripped = { ...deleg, caveats: deleg.caveats.slice(0, 1) }
const removedRejected = !verify(rootKey, stripped, () => true)
// added caveat without re-HMAC (forgery) → mismatch
const forged = { ...deleg, caveats: [...deleg.caveats, 'amount<=999999'] }
const forgeRejected = !verify(rootKey, forged, () => true)
console.log(JSON.stringify({ offline_attenuation_verifies: okHonest, removed_caveat_rejected: removedRejected, forged_caveat_rejected: forgeRejected }))

// size + speed vs depth d (caveats / delegation links)
console.log('\nsize + speed vs depth d (HMAC-chain caveats ≈ signature-chain delegation links):')
for (const d of [1, 4, 16]) {
  const caveats = Array.from({ length: d }, (_, i) => `caveat-${i}=v${i}`)
  let t = performance.now()
  let m = mint(rootKey, 'cap:x', [caveats[0]])
  for (let i = 1; i < d; i++) m = attenuate(m, caveats[i])
  const buildUs = ((performance.now() - t) / 1) * 1000
  t = performance.now()
  for (let k = 0; k < 5000; k++) verify(rootKey, m, () => true)
  const verifyUs = ((performance.now() - t) / 5000) * 1000
  const linkBytes = MLDSA87_SIG + MLDSA87_PK + GRANT_BODY
  const sigChainBytes = d * linkBytes
  // HYBRID (council/Grok): ONE signed root (publicly verifiable vs trusted PK) + HMAC-chained caveats.
  const hybridBytes = linkBytes + (d - 1) * 48
  console.log(
    JSON.stringify({
      depth_d: d,
      macaroon_bytes: macaroonBytes(m),
      sigchain_bytes: sigChainBytes,
      hybrid_signedroot_plus_hmac_bytes: hybridBytes,
      hybrid_vs_sigchain: +(sigChainBytes / hybridBytes).toFixed(1) + 'x smaller, keeps PUBLIC verifiability',
      macaroon_verify_us: +verifyUs.toFixed(1),
    }),
  )
}

console.log(
  '\n' +
    JSON.stringify({
      macaroon_gains: 'tiny tokens (~100× smaller) + fast verify (d HMACs vs d ML-DSA-87 verifies); offline first-party attenuation',
      decisive_catch: 'HMAC-chain verify REQUIRES the ROOT SECRET (symmetric) → only shared-secret verifiers; NO public / decentralized verification, NO delegate identity / non-repudiation, NO trusted-root-pubkey anchoring',
      nerion_sigchain_buys: 'PUBLIC verifiability against a trusted ROOT PUBLIC key (decentralized verifiers who share no secret), delegate identity + non-repudiation — at d×4627 B + d ML-DSA verifies',
      verdict: 'for a DECENTRALIZED protocol (validators verify capabilities without sharing the issuer secret), signature-chains are REQUIRED; Macaroons cannot do decentralized verification. Nerion s choice is justified; the size/speed cost is real (ties to LED-001 ML-DSA bloat).',
      possible_upside: 'an HMAC fast-path for INTRA-trust-domain sub-delegation (verifier shares the secret) — a hybrid worth a narrow look; third-party caveats / revocation / confidentiality are extra limits to weigh',
    }),
)
