// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, COSE_PROFILE } from '../../crypto/src/index.js'
import { TransparencyLog, checkInclusion } from '../../translog/src/index.js'
import {
  buildSbom,
  buildSlsaProvenance,
  signSupplyChainStatement,
  verifySupplyChainStatement,
  supplyChainLeaf,
} from '../src/index.js'

const SUITE = SUITE_IDS.PS_5
const s = signerFor(SUITE)

describe('supply-chain provenance (SBOM + SLSA, COSE-signed)', () => {
  it('SBOM lists PolarSeek deps (incl. the PQ libs), sorted + deterministic', () => {
    const a = buildSbom(undefined, 1)
    expect(a.bomFormat).toBe('CycloneDX')
    expect(a.components.map((c) => c.name)).toContain('@noble/post-quantum')
    expect(JSON.stringify(buildSbom(undefined, 1))).toBe(JSON.stringify(a)) // deterministic
  })

  it('SLSA provenance has the in-toto + slsa v1 shape with a subject digest', () => {
    const p = buildSlsaProvenance({
      subjectName: 'polarseek',
      subjectSha256: 'ab'.repeat(32),
      buildType: 'https://polarseek/bt/v1',
      builderId: 'https://polarseek/builder',
      now: 5,
    })
    expect(p._type).toBe('https://in-toto.io/Statement/v1')
    expect(p.predicateType).toBe('https://slsa.dev/provenance/v1')
    expect(p.subject[0]!.digest.sha256).toBe('ab'.repeat(32))
  })

  it('signs as COSE_Sign1, verifies under its profile, rejects a wrong key AND a wrong profile', () => {
    const kp = s.keygen()
    const sig = signSupplyChainStatement(buildSbom(), SUITE, kp.secretKey)
    expect(verifySupplyChainStatement(sig, SUITE, kp.publicKey, COSE_PROFILE.CYCLONEDX_SBOM)).toBe(
      true,
    )
    expect(
      verifySupplyChainStatement(sig, SUITE, s.keygen().publicKey, COSE_PROFILE.CYCLONEDX_SBOM),
    ).toBe(false)
    // ADR-0026 domain separation: an SBOM signature does NOT verify under the provenance profile.
    expect(verifySupplyChainStatement(sig, SUITE, kp.publicKey, COSE_PROFILE.SLSA_PROVENANCE)).toBe(
      false,
    )
  })

  it('anchors a signed provenance statement in the transparency log', () => {
    const kp = s.keygen()
    const prov = buildSlsaProvenance({
      subjectName: 'a',
      subjectSha256: 'cd'.repeat(32),
      buildType: 'bt',
      builderId: 'b',
      now: 1,
    })
    const sig = signSupplyChainStatement(prov, SUITE, kp.secretKey)
    expect(verifySupplyChainStatement(sig, SUITE, kp.publicKey, COSE_PROFILE.SLSA_PROVENANCE)).toBe(
      true,
    )
    const log = new TransparencyLog()
    const { index } = log.append(supplyChainLeaf(sig))
    expect(checkInclusion(log.proveInclusion(index), log.root())).toBe(true)
  })
})
