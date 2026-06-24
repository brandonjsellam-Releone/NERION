// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0
// Stryker mutation testing — opt-in, non-gating. Run: npx stryker run
export default {
  packageManager: 'npm',
  reporters: ['html', 'clear-text', 'progress'],
  testRunner: 'vitest',
  coverageAnalysis: 'perTest',
  mutate: [
    // ── crypto/src (13 files verified; suites.ts excluded per hard constraint) ──
    'crypto/src/cbor.ts',
    'crypto/src/cnsa.ts',
    'crypto/src/code-sign.ts',
    'crypto/src/cose.ts',
    'crypto/src/envelope.ts',
    'crypto/src/errors.ts',
    'crypto/src/index.ts',
    'crypto/src/kem.ts',
    'crypto/src/seal.ts',
    'crypto/src/sign.ts',
    'crypto/src/symmetric.ts',
    'crypto/src/types.ts',
    // crypto/src/suites.ts intentionally omitted — frozen invariant, hard constraint

    // ── kernel/src (5 files verified) ──
    'kernel/src/index.ts',
    'kernel/src/kernel.ts',
    'kernel/src/policy.ts',
    'kernel/src/replay.ts',
    'kernel/src/types.ts',

    // ── disclosure/src (5 files verified) ──
    'disclosure/src/commitbind.ts',
    'disclosure/src/index.ts',
    'disclosure/src/policyproof.ts',
    'disclosure/src/selective.ts',
    'disclosure/src/zkrange.ts',

    // ── attest/src (4 files verified) ──
    'attest/src/index.ts',
    'attest/src/software.ts',
    'attest/src/types.ts',
    'attest/src/verifiers.ts',

    // ── capabilities/src (6 files verified) ──
    'capabilities/src/capability.ts',
    'capabilities/src/grant.ts',
    'capabilities/src/index.ts',
    'capabilities/src/profile.ts',
    'capabilities/src/resolver.ts',
    'capabilities/src/types.ts',

    // ── governance/src (3 files verified) ──
    'governance/src/index.ts',
    'governance/src/quorum.ts',
    'governance/src/types.ts',

    // ── ledger/src (8 files verified) ──
    'ledger/src/chain.ts',
    'ledger/src/equivocation.ts',
    'ledger/src/gossip.ts',
    'ledger/src/index.ts',
    'ledger/src/leader.ts',
    'ledger/src/sortition.ts',
    'ledger/src/types.ts',
    'ledger/src/vrf.ts',

    // ── receipts/src (3 files verified) ──
    'receipts/src/index.ts',
    'receipts/src/quorum.ts',
    'receipts/src/receipt.ts',

    // ── planes/src (3 files verified) ──
    'planes/src/index.ts',
    'planes/src/node.ts',
    'planes/src/permit.ts',

    // ── settlement/src (2 files verified) ──
    'settlement/src/credits.ts',
    'settlement/src/index.ts',

    // ── translog/src (5 files verified) ──
    'translog/src/index.ts',
    'translog/src/log.ts',
    'translog/src/merkle.ts',
    'translog/src/persistent.ts',
    'translog/src/sth.ts',

    // ── ops/src (2 files verified) ──
    'ops/src/env.ts',
    'ops/src/index.ts',

    // ── keystore/src (9 files verified) ──
    'keystore/src/aws-kms.ts',
    'keystore/src/azure-kv.ts',
    'keystore/src/azure-provider.ts',
    'keystore/src/hbs-state.ts',
    'keystore/src/index.ts',
    'keystore/src/pkcs11.ts',
    'keystore/src/providers.ts',
    'keystore/src/sealing-provider.ts',
    'keystore/src/types.ts',

    // ── sdks/ts/src (3 files verified) ──
    'sdks/ts/src/client.ts',
    'sdks/ts/src/index.ts',
    'sdks/ts/src/mcp.ts',

    // ── Global exclusions ──
    '!**/*.test.ts',
    '!**/*.spec.ts',
    '!**/node_modules/**',
    '!conformance/vectors/**',   // KAT vectors — must never be mutated
    '!crypto/src/suites.ts',     // hard constraint: frozen invariant, never mutate
  ],
  thresholds: { high: 80, low: 60, break: null },
  timeoutMS: 60000,
  timeoutFactor: 2.5,
  disableBail: true,
}
