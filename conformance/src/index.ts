// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/conformance — the certification suite (the moat).
 */

export { runConformance } from './suite.js'
export type { ConformanceResult, ConformanceReport } from './suite.js'
export { runNegativeOracle, loadPerceptionVectors } from './negative.js'
export type { NegativeVerdict } from './negative.js'
export { assertCnsa, signCnsaVerdict, verifyCnsaVerdict, cnsaVerdictLeaf } from './cnsa-oracle.js'
export type { CnsaVerdict, CnsaLevel, CnsaVerdictFinding } from './cnsa-oracle.js'
export { buildCbom, signCbom, verifyCbom, cbomLeaf } from './cbom.js'
export type { Cbom, CryptoAsset, CbomSuiteEntry, QuantumClass } from './cbom.js'
export {
  buildSbom,
  buildSlsaProvenance,
  signSupplyChainStatement,
  verifySupplyChainStatement,
  supplyChainLeaf,
  POLARSEEK_DEPENDENCIES,
} from './supplychain.js'
export type { Sbom, SbomComponent, SlsaProvenance } from './supplychain.js'
