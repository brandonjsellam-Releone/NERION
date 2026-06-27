# Mutation Testing

## Purpose
Stryker mutation testing verifies that our test suite actually detects defects — not just achieves line coverage.

## Running
```bash
npx stryker run
```
Results land in `reports/mutation/html/`. This is **non-gating** (opt-in). The gate (`npm run gate`) does **NOT** run mutation testing.

## Target Modules
- `crypto/src/` — cryptographic primitives: kem, sign, seal, symmetric, envelope, cnsa, cbor, cose, code-sign
- `kernel/src/` — governance kernel (`decide()` function)
- `disclosure/src/` — disclosure logic
- `receipts/src/` — receipt construction and verification
- `ledger/src/` — ledger operations
- `settlement/src/` — settlement logic

## Excluded Files (Hard Constraints)
| File | Reason |
|---|---|
| `crypto/src/suites.ts` | Suite registry — mutations invalidate KAT vectors |
| `crypto/src/types.ts` | Type-only, no executable logic |
| `crypto/src/errors.ts` | Error constants only |
| `crypto/src/index.ts` | Re-exports only |
| `conformance/vectors/ps-*.json` | KAT vectors — must never be altered |

## Baseline
First run establishes the baseline mutation score. Track results here:

| Module | Mutation Score | Date | Notes |
|---|---|---|---|
| (run to establish baseline) | — | — | — |

## Interpreting Results
| Score | Rating |
|---|---|
| > 80 % | Excellent — high test quality |
| 60 – 80 % | Good |
| < 60 % | Review test coverage for that module |

## Thresholds (stryker.config.mjs)
```
high: 80   → green in HTML report
low:  60   → yellow in HTML report
break: null → CI is NEVER broken by mutation score (non-gating)
```

## Installing Stryker
```bash
npm install --save-dev @stryker-mutator/core @stryker-mutator/vitest-runner
```
Then run:
```bash
npx stryker run
```
