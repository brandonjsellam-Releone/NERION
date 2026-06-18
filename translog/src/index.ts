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
