// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Threshold governance types.
 *
 * Governance actions (revocation, key rotation, upgrades, parameter changes)
 * require an **M-of-N** quorum of independent operators. There is NO single
 * veto: a withholding member cannot block an action others can reach threshold
 * on. Customers additionally hold a LOCAL kill switch (sovereign override).
 */

import type { Bytes } from '../../crypto/src/index.js'

export type ProposalKind = 'revoke' | 'rotate' | 'upgrade' | 'param'

export interface Proposal {
  readonly id: string
  readonly kind: ProposalKind
  /** What the proposal acts on: a capability id, key hex, param name, etc. */
  readonly target: string
  /** Canonical detail (e.g. the new value / new key). */
  readonly payload: string
  readonly notBefore: number
  readonly notAfter: number
  readonly nonce: string
}

export interface Quorum {
  /** hex member public keys (independent operators). */
  readonly members: readonly string[]
  /** Approvals required to enact (M of N). */
  readonly threshold: number
}

export interface Approval {
  readonly proposalId: string
  readonly signer: string
  readonly suite: string
  readonly sig: Bytes
}

export interface EnactmentResult {
  readonly enacted: boolean
  readonly validApprovals: number
  readonly reasons: string[]
}
