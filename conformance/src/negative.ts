// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Govern-the-verb negative oracle — a RUNTIME certification fence for PolarSeek's
 * core thesis "govern the verb, never the eye."
 *
 * It loads perception-shaped side-data from conformance/vectors/ps-negative.json
 * and asserts that injecting ANY of it into `intent.params` leaves the kernel's
 * Decision BYTE-IDENTICAL. A conforming implementation governs the typed ACTION
 * (type / amount / counterparty) and is provably INVARIANT to accompanying
 * perception data — the machine-checked inverse of SIGA's "owns AI perception."
 *
 * This source file names NO forbidden term: it reads the perception primitives as
 * DATA from the lint-skipped vectors file, so it passes the clean-room lint itself
 * (the lint skips dirs named `vectors`). Promotes the build-time grep
 * (tools/cleanroom-lint.mjs) to a portable runtime oracle any implementer must pass.
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToHex } from '@noble/hashes/utils.js'
import { encodeCanonical } from '../../crypto/src/index.js'
import { decide, type Decision, type KernelInput } from '../../kernel/src/index.js'

export interface NegativeVerdict {
  readonly invariant: boolean
  readonly fieldsTested: number
  /** Fields under which the decision changed (a govern-the-eye leak). Empty when clean. */
  readonly divergences: ReadonlyArray<{ field: string; got: string }>
}

const VECTOR_PATH = 'conformance/vectors/ps-negative.json'

/** Load the perception-shaped side-data vector (name -> sample value). */
export function loadPerceptionVectors(): Record<string, unknown> {
  const raw = readFileSync(join(process.cwd(), VECTOR_PATH), 'utf8')
  const parsed = JSON.parse(raw) as { fields?: Record<string, unknown> }
  return parsed.fields ?? {}
}

/** Byte-identical fingerprint of the full decision (every field that matters). */
function fingerprint(d: Decision): string {
  return bytesToHex(
    encodeCanonical([d.effect, d.tier, [...d.reasons], [...d.obligations], d.evaluatorVersion]),
  )
}

function inject(base: KernelInput, extra: Record<string, unknown>): KernelInput {
  return {
    ...base,
    intent: { ...base.intent, params: { ...(base.intent.params ?? {}), ...extra } },
  }
}

/**
 * Run the oracle against a baseline input: the Decision must be invariant under
 * every perception field (individually AND all at once). `decideFn` is injectable
 * so a test can prove the oracle CATCHES a kernel that peeks at perception (i.e.
 * the oracle is not vacuous); it defaults to the real kernel `decide`.
 */
export function runNegativeOracle(
  base: KernelInput,
  decideFn: (i: KernelInput) => Decision = decide,
  fields: Record<string, unknown> = loadPerceptionVectors(),
): NegativeVerdict {
  const baseline = fingerprint(decideFn(base))
  const divergences: Array<{ field: string; got: string }> = []
  for (const [name, value] of Object.entries(fields)) {
    const got = fingerprint(decideFn(inject(base, { [name]: value })))
    if (got !== baseline) divergences.push({ field: name, got })
  }
  const all = fingerprint(decideFn(inject(base, fields)))
  if (all !== baseline) divergences.push({ field: '<all-fields>', got: all })
  return {
    invariant: divergences.length === 0,
    fieldsTested: Object.keys(fields).length + 1,
    divergences,
  }
}
