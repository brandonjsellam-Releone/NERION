// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Generator pinning (audit-prep 2026-06-27 — ZK dossier P4,
 * docs/council/zk-audit-prep-2026-06-27.md).
 *
 * The Pedersen generators are security-critical constants. `G` is the ristretto255
 * base; `H = hashToCurve("PolarSeek/disclosure/generator-H/v1")` (zkrange.ts:37) is a
 * nothing-up-my-sleeve second generator with unknown `dlog_G(H)` — the assumption that
 * makes the commitment binding while perfectly hiding. `H` is derived at import time
 * from `@noble`'s ristretto255 hash-to-curve, so it can move SILENTLY if `@noble`'s map
 * changes or the domain string is edited. A silent move invalidates every existing
 * proof/commitment and — if `H` were ever swapped for a point with known `dlog_G` —
 * would collapse the binding⇄hiding separation.
 *
 * These tests PIN both generators through the PUBLIC `commit` API (no internal access):
 *   commit(1,0) = G^1·H^0 = G   and   commit(0,1) = G^0·H^1 = H.
 * So any change to the actual generators used by the protocol — including a domain-string
 * edit during the PolarSeek→Nerion rename — fails here and becomes a CONSCIOUS, reviewed
 * change (it is a breaking protocol change requiring a version bump + fresh KATs).
 */

import { describe, it, expect } from 'vitest'
import { commit } from '../src/zkrange.js'
import { bytesToHex } from '@noble/hashes/utils.js'

// Pinned 2026-06-27 against the @noble/curves ristretto255 in package-lock.json.
// G is the canonical RFC-9496 ristretto255 base point.
const G_HEX = 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'
const H_HEX = 'c0ec23401b116b32d76d762a6b95936afe412769729c55c50cb325ceb759a546'

describe('disclosure Pedersen generators are pinned (audit-prep, ZK dossier P4)', () => {
  it('G = commit(1,0) is the canonical ristretto255 base point', () => {
    expect(bytesToHex(commit(1n, 0n).toBytes())).toBe(G_HEX)
  })

  it('H = commit(0,1) is the pinned nothing-up-my-sleeve generator', () => {
    expect(bytesToHex(commit(0n, 1n).toBytes())).toBe(H_HEX)
  })

  it('H ≠ G (independent generators — binding⇄hiding separation)', () => {
    expect(H_HEX).not.toBe(G_HEX)
    expect(commit(0n, 1n).equals(commit(1n, 0n))).toBe(false)
  })

  it('the commitment is additively homomorphic over both generators', () => {
    // commit(a,b) = G^a·H^b = commit(a,0) + commit(0,b); a cheap structural sanity check
    // that the pinned generators are the ones actually composed by `commit`.
    const a = 7n
    const b = 11n
    const lhs = commit(a, b)
    const rhs = commit(a, 0n).add(commit(0n, b))
    expect(lhs.equals(rhs)).toBe(true)
  })
})
