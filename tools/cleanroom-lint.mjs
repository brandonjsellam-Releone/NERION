#!/usr/bin/env node
/**
 * Clean-room / non-infringement linter.
 *
 * Fails the build if any SIGA forbidden-element signal (CLEANROOM.md F1–F8)
 * appears in the admission-path source. The admission kernel must govern typed
 * ACTIONS, never perception, and must hold no cross-decision state. See
 * docs/CLEANROOM.md.  Run: `node tools/cleanroom-lint.mjs` (npm run lint:cleanroom).
 *
 * Scope: source directories only. This file and docs/ are excluded (they
 * legitimately *name* the forbidden terms to forbid them).
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join, extname } from 'node:path'

const FORBIDDEN = [
  { id: 'F1', re: /\b(camera|frame_ingest|videoFrame|image_input|pixel_buffer|sensor_frame|rawSensor)\b/i },
  { id: 'F2', re: /(static[_-]?dynamic|staticFeature|dynamicFeature|sequential_frames|frameSequence|cognitive_loop|decompose_frames)/i },
  { id: 'F3', re: /(object_identity|identity_continuity|track_object|reidentif|object_persistence|crossFrameId|maintain_track)/i },
  { id: 'F4', re: /(zone_occupancy|polygon|field_of_view|fov_zone|dwell_time|destination_location|zone_entry|geofence|occupancy_over_time)/i },
  { id: 'F5', re: /(kernel_state|mutable_state|prev_decision|last_seen|stateful|state_change_trigger|in_kernel_counter)/i },
  { id: 'F6', re: /(commit[_-]?point|commitPointGate|commit_gate|gate_at_state_change|sovereign_gate)/i },
  { id: 'F7', re: /(perceive_decompose|perception_to_receipt|enforce_on_track|record_on_state_change)/i },
  { id: 'F8', re: /(tensor_decompose|attention_as_decomposition|inference_loop_gate|real_time_tensor_gate)/i },
]

// Admission-path source dirs (only those that exist are scanned).
const SCAN_DIRS = [
  'crypto/src',
  'kernel',
  'capabilities',
  'receipts',
  'translog',
  'attest',
  'planes',
  'sdks',
]
const CODE_EXT = new Set(['.ts', '.rs', '.go', '.py', '.rego'])
const SKIP_DIR = new Set(['node_modules', 'dist', 'spec', 'test', 'vectors'])

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIR.has(name)) continue
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) yield* walk(p)
    else if (CODE_EXT.has(extname(p))) yield p
  }
}

const findings = []
for (const dir of SCAN_DIRS) {
  if (!existsSync(dir)) continue
  for (const file of walk(dir)) {
    const lines = readFileSync(file, 'utf8').split(/\r?\n/)
    lines.forEach((line, i) => {
      for (const { id, re } of FORBIDDEN) {
        const m = re.exec(line)
        if (m) findings.push({ file, line: i + 1, id, match: m[0], text: line.trim().slice(0, 100) })
      }
    })
  }
}

if (findings.length > 0) {
  console.error('✗ clean-room lint FAILED — forbidden SIGA elements in the admission path:\n')
  for (const f of findings) {
    console.error(`  ${f.file}:${f.line}  [${f.id}] "${f.match}"  ->  ${f.text}`)
  }
  console.error('\nSee docs/CLEANROOM.md. Govern the verb, never the eye.')
  process.exit(1)
}
console.log('✓ clean-room lint passed: no forbidden perception/stateful signals in the admission path.')
