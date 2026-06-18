/**
 * @polarseek/disclosure — selective disclosure + zero-knowledge range proof.
 *
 * NOTE: the ZK range proof (zkrange) is an UNAUDITED reference built on the
 * audited ristretto255 group; the protocol composition needs external review
 * before production reliance. Selective disclosure (selective) uses only the
 * receipt's existing hash commitments and is sound.
 */

export { commitField, verifyDisclosure } from './selective.js'
export { commit, proveBelow, verifyBelow, RangeProofError, randomScalar } from './zkrange.js'
export type { RangeProof } from './zkrange.js'
