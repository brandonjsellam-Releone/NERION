// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * BENCH-01 — reproducible adversarial measurement harness for Nerion.
 *
 * Council mandate (TRELYAN apex council, 9/10 seats incl. seat #11 Moonshot):
 * "measurement is the moat" — turn unaudited claims into reproducible, signed,
 * machine-readable evidence. The strongest seats (OpenAI/DeepSeek/Grok) steered
 * this at ADVERSARIAL CORRECTNESS first, not a perf dashboard: a seeded corpus
 * of valid + attack traces with hard accept/reject verdicts, plus primitive
 * cost metrics, wired to a CI regression gate (tools/bench-gate.mjs).
 *
 * What it measures (the "govern the verb" path, modelled over real primitives):
 *   1. audience-bound permit-key derivation   (HKDF-SHA-384)
 *   2. salted intent commitment               (SHA3-256)
 *   3. permit signing / verification          (ML-DSA-87)
 *   4. revocation check                        (set membership)
 *   5. Merkle-anchored quorum receipt          (SHA3-256 tree)
 *
 * Adversarial corpus (each case MUST be rejected): wrong-audience, tampered
 * intent, forged signature, suite downgrade, wrong issuer key. Valid traces
 * MUST be accepted. A security invariant violation exits non-zero immediately;
 * the gate additionally enforces no regression vs bench/baseline.json.
 *
 * Determinism: seeds/salts are derived by SHA3-256 of fixed labels and ML-DSA-87
 * keygen is seeded, so sizes + verdicts are reproducible across machines.
 * Timings are inherently machine-dependent and are treated as advisory.
 *
 * Usage:  node bench/run.mjs [--update-baseline] [--permits=512]
 *         BENCH_ADAPTER=noble-real (default)
 *
 * UNAUDITED / pre-FTO. No audited/FIPS/production/non-infringement claim implied.
 */
import { createHash } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = join(HERE, '..')
const SUITE_ID = 'Ps1' // wire-frozen v:1 suite id (modelled label)
const HARNESS_VERSION = '0.1.0'

// ---- args -----------------------------------------------------------------
const args = process.argv.slice(2)
const UPDATE_BASELINE = args.includes('--update-baseline')
const PERMITS = Number((args.find((a) => a.startsWith('--permits=')) || '').split('=')[1]) || 512
const REVOKED_FRACTION = 0.1
const AUDIENCES = 64
const ADAPTER_NAME = process.env.BENCH_ADAPTER || 'noble-real'

// ---- helpers --------------------------------------------------------------
const utf8 = (s) => new TextEncoder().encode(s)
const hex = (u8) => Buffer.from(u8).toString('hex')

/** Deterministic 32-byte value from a label (seeds, salts, session keys). */
const det = (label) => new Uint8Array(createHash('sha3-256').update(label).digest())
const sha3 = (u8) => new Uint8Array(createHash('sha3-256').update(u8).digest())

function concat(...parts) {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** Canonical bytes for the modelled permit/intent: JSON with sorted keys. */
function canonical(obj) {
  const sort = (v) =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.keys(v)
          .sort()
          .reduce((a, k) => ((a[k] = sort(v[k])), a), {})
      : v
  return utf8(JSON.stringify(sort(obj)))
}

function stats(samples) {
  if (samples.length === 0) return { avg: 0, p50: 0, p95: 0, max: 0 }
  const s = [...samples].sort((a, b) => a - b)
  const at = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))]
  const avg = s.reduce((a, b) => a + b, 0) / s.length
  return { avg: round(avg), p50: round(at(0.5)), p95: round(at(0.95)), max: round(s[s.length - 1]) }
}
const round = (x) => Math.round(x * 1000) / 1000

// ---- modelled verb path ---------------------------------------------------
/** Build the canonical permit message that the issuer signs over. */
function permitMessage(adapter, sessionKey, suite, action, audience, intent, salt) {
  const audienceKey = adapter.hkdfSha384(
    sessionKey,
    utf8('nerion-bench/permit-audience-salt/v1'),
    utf8(`nerion-bench/permit-audience-kdf/v1|${audience}`),
    32,
  )
  const intentCommitment = adapter.sha3_256(concat(salt, canonical(intent)))
  const msg = canonical({
    v: 1,
    suite,
    action,
    audience,
    audTag: hex(audienceKey.slice(0, 16)),
    ic: hex(intentCommitment),
  })
  return { msg, audienceKey, intentCommitment }
}

// ---- main -----------------------------------------------------------------
const wallStart = performance.now()
const { createAdapter } = await import(`./adapters/${ADAPTER_NAME}.mjs`)
const adapter = createAdapter()

const t = {
  keygen: [],
  derive: [],
  commit: [],
  sign: [],
  verify: [],
  revocation: [],
}

// issuer + a distinct "wrong" issuer for the wrong-key attack
let s = performance.now()
const issuer = adapter.keygen(det('nerion-bench/issuer/0'))
t.keygen.push(performance.now() - s)
const wrongIssuer = adapter.keygen(det('nerion-bench/issuer/wrong'))
const sessionKey = det('nerion-bench/session/0')

// revocation set: ~REVOKED_FRACTION of audiences are revoked
const revoked = new Set()
for (let a = 0; a < AUDIENCES; a++) {
  if (a / AUDIENCES < REVOKED_FRACTION) revoked.add(`aud-${a}`)
}

const permits = []
for (let i = 0; i < PERMITS; i++) {
  const audience = `aud-${i % AUDIENCES}`
  const action = 'transfer'
  const intent = { action, amount: i, audience, nonce: i }
  const salt = det(`nerion-bench/salt/${i}`)

  let d = performance.now()
  const audienceKey = adapter.hkdfSha384(
    sessionKey,
    utf8('nerion-bench/permit-audience-salt/v1'),
    utf8(`nerion-bench/permit-audience-kdf/v1|${audience}`),
    32,
  )
  t.derive.push(performance.now() - d)

  let c = performance.now()
  const intentCommitment = adapter.sha3_256(concat(salt, canonical(intent)))
  t.commit.push(performance.now() - c)

  const msg = canonical({
    v: 1,
    suite: SUITE_ID,
    action,
    audience,
    audTag: hex(audienceKey.slice(0, 16)),
    ic: hex(intentCommitment),
  })

  let g = performance.now()
  const sig = adapter.sign(msg, issuer.secretKey)
  t.sign.push(performance.now() - g)

  permits.push({ audience, action, intent, salt, msg, sig })
}

// ---- verification + adversarial corpus ------------------------------------
let validIssued = 0
let validAccepted = 0
let revokedRejected = 0
const adv = {
  wrongAudience: { n: 0, rejected: 0 },
  tamperedIntent: { n: 0, rejected: 0 },
  forgedSignature: { n: 0, rejected: 0 },
  suiteDowngrade: { n: 0, rejected: 0 },
  wrongKey: { n: 0, rejected: 0 },
}

const verifyPermit = (sig, msg, pk) => {
  const v0 = performance.now()
  const ok = adapter.verify(sig, msg, pk)
  t.verify.push(performance.now() - v0)
  return ok
}

for (let i = 0; i < permits.length; i++) {
  const p = permits[i]

  // revocation gate (cheap set lookup, measured)
  const r0 = performance.now()
  const isRevoked = revoked.has(p.audience)
  t.revocation.push(performance.now() - r0)
  if (isRevoked) {
    revokedRejected++ // revoked permits are rejected before any signature check
    continue
  }

  // ---- valid trace: recompute message honestly, must ACCEPT ----
  validIssued++
  const honest = permitMessage(adapter, sessionKey, SUITE_ID, p.action, p.audience, p.intent, p.salt)
  if (verifyPermit(p.sig, honest.msg, issuer.publicKey)) validAccepted++

  // ---- adversarial traces (sampled to keep runtime bounded) ----
  if (i % 4 === 0) {
    // (a) wrong-audience: verifier presented a different audience
    adv.wrongAudience.n++
    const wrongAud = permitMessage(adapter, sessionKey, SUITE_ID, p.action, `aud-${(i + 1) % AUDIENCES}`, p.intent, p.salt)
    if (!verifyPermit(p.sig, wrongAud.msg, issuer.publicKey)) adv.wrongAudience.rejected++

    // (b) tampered intent: amount mutated -> commitment changes
    adv.tamperedIntent.n++
    const tampered = permitMessage(adapter, sessionKey, SUITE_ID, p.action, p.audience, { ...p.intent, amount: p.intent.amount + 1 }, p.salt)
    if (!verifyPermit(p.sig, tampered.msg, issuer.publicKey)) adv.tamperedIntent.rejected++

    // (c) forged signature: flip a byte
    adv.forgedSignature.n++
    const bad = p.sig.slice()
    bad[0] ^= 0x01
    if (!verifyPermit(bad, honest.msg, issuer.publicKey)) adv.forgedSignature.rejected++

    // (d) suite downgrade: verifier presented a different suite id
    adv.suiteDowngrade.n++
    const downgrade = permitMessage(adapter, sessionKey, 'Ps0', p.action, p.audience, p.intent, p.salt)
    if (!verifyPermit(p.sig, downgrade.msg, issuer.publicKey)) adv.suiteDowngrade.rejected++

    // (e) wrong issuer key
    adv.wrongKey.n++
    if (!verifyPermit(p.sig, honest.msg, wrongIssuer.publicKey)) adv.wrongKey.rejected++
  }
}

// ---- Merkle-anchored quorum receipt over the valid permit signatures ------
function merkleLeaves(sigs) {
  return sigs.map((sig) => sha3(concat(Uint8Array.of(0x00), sig)))
}
function merkleRoot(leaves) {
  if (leaves.length === 0) return new Uint8Array(32)
  let level = leaves
  while (level.length > 1) {
    const next = []
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i]
      const r = i + 1 < level.length ? level[i + 1] : level[i]
      next.push(sha3(concat(Uint8Array.of(0x01), l, r)))
    }
    level = next
  }
  return level[0]
}
function merkleProof(leaves, index) {
  const proof = []
  let idx = index
  let level = leaves
  while (level.length > 1) {
    const sib = idx ^ 1
    proof.push(sib < level.length ? level[sib] : level[idx])
    const next = []
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i]
      const r = i + 1 < level.length ? level[i + 1] : level[i]
      next.push(sha3(concat(Uint8Array.of(0x01), l, r)))
    }
    level = next
    idx = idx >> 1
  }
  return proof
}
function merkleVerify(leaf, index, proof, root) {
  let h = leaf
  let idx = index
  for (const sib of proof) {
    h = idx & 1 ? sha3(concat(Uint8Array.of(0x01), sib, h)) : sha3(concat(Uint8Array.of(0x01), h, sib))
    idx = idx >> 1
  }
  return hex(h) === hex(root)
}

const validSigs = permits.filter((p) => !revoked.has(p.audience)).map((p) => p.sig)
let mb = performance.now()
const leaves = merkleLeaves(validSigs)
const root = merkleRoot(leaves)
const merkleBuildMs = performance.now() - mb
let mv = performance.now()
const proof = merkleProof(leaves, 0)
const inclusionOk = merkleVerify(leaves[0], 0, proof, root)
const merkleVerifyMs = performance.now() - mv

// ---- report ---------------------------------------------------------------
const allValidAccepted = validAccepted === validIssued && validIssued > 0
const allAdversarialRejected = Object.values(adv).every((c) => c.n > 0 && c.rejected === c.n)
const totalWallMs = performance.now() - wallStart

const sizes = {
  publicKeyBytes: issuer.publicKey.length,
  secretKeyBytes: issuer.secretKey.length,
  signatureBytes: permits[0].sig.length,
  permitMessageBytes: permits[0].msg.length,
  intentCommitmentBytes: 32,
  merkleRootBytes: root.length,
}

const report = {
  meta: {
    harness: 'BENCH-01',
    version: HARNESS_VERSION,
    adapter: adapter.name,
    primitive: adapter.primitive,
    hash: adapter.hash,
    kdf: adapter.kdf,
    isProxy: adapter.isProxy,
    node: process.version,
    workload: { permits: PERMITS, audiences: AUDIENCES, revokedFraction: REVOKED_FRACTION },
    note: 'UNAUDITED / pre-FTO. Modelled measurement of the govern-the-verb path; not the production kernel. No FIPS/production/non-infringement claim.',
  },
  correctness: {
    validIssued,
    validAccepted,
    revokedRejected,
    adversarial: adv,
    inclusionProofOk: inclusionOk,
    allValidAccepted,
    allAdversarialRejected,
  },
  sizes,
  timings_ms: {
    keygen: stats(t.keygen),
    deriveAudienceKey: stats(t.derive),
    commitIntent: stats(t.commit),
    sign: stats(t.sign),
    verify: stats(t.verify),
    revocationCheck: stats(t.revocation),
    merkleBuild: round(merkleBuildMs),
    merkleVerify: round(merkleVerifyMs),
    totalWall: round(totalWallMs),
  },
  throughput: {
    permitsIssuedPerSec: round(PERMITS / (t.sign.reduce((a, b) => a + b, 0) / 1000)),
    verificationsPerSec: round(t.verify.length / (t.verify.reduce((a, b) => a + b, 0) / 1000)),
  },
}

writeFileSync(join(REPO, 'bench', 'report.json'), JSON.stringify(report, null, 2) + '\n')

if (UPDATE_BASELINE) {
  // Deterministic fields only — timings are advisory and excluded.
  const baseline = {
    _note: 'BENCH-01 regression baseline. Deterministic fields only (sizes, correctness, workload). Regenerate with `npm run bench -- --update-baseline`.',
    primitive: report.meta.primitive,
    workload: report.meta.workload,
    sizes: report.sizes,
    correctness: {
      validIssued: report.correctness.validIssued,
      validAccepted: report.correctness.validAccepted,
      revokedRejected: report.correctness.revokedRejected,
      adversarial: report.correctness.adversarial,
      inclusionProofOk: report.correctness.inclusionProofOk,
      allValidAccepted: report.correctness.allValidAccepted,
      allAdversarialRejected: report.correctness.allAdversarialRejected,
    },
  }
  writeFileSync(join(REPO, 'bench', 'baseline.json'), JSON.stringify(baseline, null, 2) + '\n')
}

// ---- console summary ------------------------------------------------------
const pq = report.sizes.signatureBytes
console.log(`BENCH-01  adapter=${report.meta.adapter}  primitive=${report.meta.primitive}  node=${report.meta.node}`)
console.log(`  workload         : ${PERMITS} permits, ${AUDIENCES} audiences, ${Math.round(REVOKED_FRACTION * 100)}% revoked`)
console.log(`  valid accepted   : ${validAccepted}/${validIssued}   revoked rejected: ${revokedRejected}`)
console.log(
  `  adversarial      : ` +
    Object.entries(adv)
      .map(([k, v]) => `${k} ${v.rejected}/${v.n}`)
      .join('  '),
)
console.log(`  sizes (bytes)    : pk=${sizes.publicKeyBytes} sk=${sizes.secretKeyBytes} sig=${pq} permitMsg=${sizes.permitMessageBytes}`)
console.log(`  sign p95/avg ms  : ${report.timings_ms.sign.p95}/${report.timings_ms.sign.avg}    verify p95/avg ms: ${report.timings_ms.verify.p95}/${report.timings_ms.verify.avg}`)
console.log(`  merkle quorum    : build=${report.timings_ms.merkleBuild}ms verify=${report.timings_ms.merkleVerify}ms inclusion=${inclusionOk}`)
console.log(`  throughput       : issue=${report.throughput.permitsIssuedPerSec}/s verify=${report.throughput.verificationsPerSec}/s`)
console.log(`  report           : bench/report.json${UPDATE_BASELINE ? '  (baseline updated)' : ''}`)

if (!allValidAccepted || !allAdversarialRejected || !inclusionOk) {
  console.error('BENCH-01 SECURITY INVARIANT VIOLATED — a valid trace was rejected or an attack trace was accepted.')
  process.exit(1)
}
console.log('BENCH-01 OK — all valid accepted, all adversarial rejected, inclusion proof verified.')
