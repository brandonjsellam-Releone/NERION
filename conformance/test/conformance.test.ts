import { describe, it, expect } from 'vitest'
import { runConformance } from '../src/index.js'

describe('PolarSeek conformance suite', () => {
  it('passes every conformance check', () => {
    const report = runConformance()
    const failures = report.results.filter((r) => !r.passed)
    if (failures.length > 0) {
      // Surface which checks failed and why.
      console.error(failures.map((f) => `${f.id} ${f.name}: ${f.detail}`).join('\n'))
    }
    expect(report.ok).toBe(true)
    expect(report.passed).toBe(report.total)
    expect(report.total).toBeGreaterThanOrEqual(11)
  })
})
