// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/translog — SCITT-style append-only transparency log.
 */

export {
  emptyRoot,
  leafHash,
  nodeHash,
  bytesEqual,
  merkleRoot,
  inclusionProof,
  rootFromInclusion,
  verifyInclusion,
  consistencyProof,
  verifyConsistency,
} from './merkle.js'
export { TransparencyLog, checkInclusion, checkConsistency } from './log.js'
export type { InclusionWitness, ConsistencyWitness } from './log.js'
export { PersistentTransparencyLog } from './persistent.js'
export { signTreeHead, verifyTreeHead, detectEquivocation, checkAppendOnly } from './sth.js'
export type { SignedTreeHead, Equivocation } from './sth.js'
