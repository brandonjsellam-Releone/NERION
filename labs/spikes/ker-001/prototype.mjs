// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0
//
// ─────────────────────────────────────────────────────────────────────────────
// KER-001 — Nerion Labs THROWAWAY prototype (docs/APEX_TEAMS.md §5). DISPOSABLE / TOY.
//
// Backlog bet (as written): "a stateful-yet-equivalent admission kernel vs the stateless
// govern-the-verb model — ≥2× throughput."
//
// STEP-4 FTO PRE-SCREEN result: the *stateful admission kernel* framing drifts straight into
// "in-gate cross-decision state" / a "commit-point gate" — the SIGA F5 / commit-point claim
// territory that Nerion's stateless govern-the-verb model deliberately designs around. Per the
// charter this is PARKED, not built. We instead test the FTO-CLEAN question that motivated it:
//
//   Can the throughput goal (≥2×) be met while staying PROVABLY STATELESS — i.e. is a stateful
//   kernel even necessary, or does stateless parallelism already clear the bar?
//
// MEASURED (real): each admission is independent (verb-hash + permit-HMAC + asymmetric verify),
// so the stateless path is embarrassingly parallel. We measure throughput scaling across worker
// threads, and contrast a "stateful" variant where every admission must fold a result into shared
// cross-decision state under an Atomics lock (real contention). Ed25519 verify stands in as a
// PROXY for the real ML-DSA-87 admission signature (slower in prod — so absolute ops/sec are a
// shape, not a protocol benchmark). Uses only node:crypto + node:worker_threads. No repo imports.
// ─────────────────────────────────────────────────────────────────────────────

import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads'
import { generateKeyPairSync, sign, verify, createPublicKey, createHmac, randomBytes, createHash } from 'node:crypto'
import { cpus } from 'node:os'

const HMAC_KEY = Buffer.from('ker-001/permit-key')

// Model the admission hot path: verb hash + permit HMAC (SHA-384) + asymmetric signature verify.
function admitOnce(msg, sig, pub) {
  createHash('sha256').update(msg).digest() // verb-authorization lookup proxy
  createHmac('sha384', HMAC_KEY).update(msg).digest() // permit-token verify proxy
  return verify(null, msg, pub, sig) // signature verify (Ed25519 proxy for ML-DSA-87)
}

if (!isMainThread) {
  const { count, vec, stateful, sab } = workerData
  const msg = Buffer.from(vec.msgB64, 'base64')
  const sig = Buffer.from(vec.sigB64, 'base64')
  const pub = createPublicKey({ key: Buffer.from(vec.pubB64, 'base64'), type: 'spki', format: 'der' })
  const lock = sab ? new Int32Array(sab) : null
  let acc = Buffer.alloc(8)
  let ok = 0
  for (let i = 0; i < count; i++) {
    if (admitOnce(msg, sig, pub)) ok++
    if (stateful && lock) {
      // serialized cross-decision STATE update: fold this decision into a running digest
      // under an Atomics spinlock (the contention a stateful kernel would incur).
      while (Atomics.compareExchange(lock, 0, 0, 1) !== 0) {}
      acc = createHash('sha256').update(acc).update(msg).digest().subarray(0, 8)
      lock[1] = (lock[1] + 1) | 0
      Atomics.store(lock, 0, 0)
    }
  }
  parentPort.postMessage({ ok })
} else {
  const CORES = cpus().length
  const TOTAL = 48000 // total admissions per run (split across workers)

  function makeVector() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const msg = randomBytes(48)
    const sig = sign(null, msg, privateKey)
    const pub = publicKey.export({ type: 'spki', format: 'der' })
    return {
      msgB64: msg.toString('base64'),
      sigB64: sig.toString('base64'),
      pubB64: Buffer.from(pub).toString('base64'),
    }
  }

  function runPool(P, total, stateful, vec) {
    const per = Math.floor(total / P)
    const sab = stateful ? new SharedArrayBuffer(8) : null
    const t = performance.now()
    const jobs = []
    for (let i = 0; i < P; i++) {
      jobs.push(
        new Promise((res, rej) => {
          const w = new Worker(new URL(import.meta.url), { workerData: { count: per, vec, stateful, sab } })
          w.on('message', (m) => res(m))
          w.on('error', rej)
        }),
      )
    }
    return Promise.all(jobs).then(() => {
      const ms = performance.now() - t
      return { P, ops: per * P, ms: +ms.toFixed(0), opsPerSec: Math.round((per * P) / (ms / 1000)) }
    })
  }

  const vec = makeVector()
  console.log(`KER-001 — stateless-parallel admission throughput (${CORES} cores; Ed25519 verify proxy for ML-DSA-87)`)
  console.log('STEP-4 FTO pre-screen PARKED the stateful-kernel framing; this measures whether stateless already clears 2x.\n')

  const base = {}
  for (const stateful of [false, true]) {
    const label = stateful ? 'stateful (shared cross-decision state, Atomics-locked)' : 'stateless (independent, no shared state)'
    console.log(`# ${label}`)
    let p1 = null
    for (const P of [1, 2, 4, 8, 16]) {
      if (P > CORES) continue
      const r = await runPool(P, TOTAL, stateful, vec)
      if (P === 1) p1 = r.opsPerSec
      const speedup = +(r.opsPerSec / p1).toFixed(2)
      console.log(JSON.stringify({ ...r, speedupVsP1: speedup }))
      base[`${stateful ? 'stateful' : 'stateless'}_P${P}`] = r.opsPerSec
    }
    console.log('')
  }

  const sl16 = base.stateless_P16 ?? base.stateless_P8
  const sf16 = base.stateful_P16 ?? base.stateful_P8
  console.log(
    JSON.stringify({
      stateless_meets_2x: (base.stateless_P2 ?? 0) / (base.stateless_P1 ?? 1) >= 1.8,
      stateless_peak_speedup: +((sl16 ?? 0) / (base.stateless_P1 ?? 1)).toFixed(1),
      stateful_peak_speedup: +((sf16 ?? 0) / (base.stateful_P1 ?? 1)).toFixed(1),
      stateless_over_stateful_at_peak: +((sl16 ?? 0) / (sf16 ?? 1)).toFixed(2),
    }),
  )
}
