#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 TRELYAN
#
# SPDX-License-Identifier: Apache-2.0

"""PolarSeek conformance — an independent, **stdlib-only** check that a third
implementation (Python) reproduces the frozen Known-Answer Test vectors in
``conformance/vectors/ps-kat.json`` for the primitives Python's standard library
provides: SHA3-256, SHAKE256, and HMAC-SHA-384. Together with the TypeScript
reference and the Rust hot-path crate (``rust/`` ``ts_kat_vectors_reproduce``),
this gives three independent languages agreeing on the same byte-exact contract.

Out of stdlib scope (so deliberately not checked here): AES-256-GCM and the
post-quantum ML-DSA-87 keygen — those need a third-party crypto/PQC library, not
the standard library. Full receipt-signature verification belongs in a richer SDK
build that takes those dependencies.

Usage:  python sdks/python/polarseek_conformance.py
Exits non-zero if any vector fails to reproduce.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance" / "vectors" / "ps-kat.json"


def main() -> int:
    if not VECTORS.exists():
        print(f"missing {VECTORS} — run `npm run kat` first", file=sys.stderr)
        return 2

    kat = json.loads(VECTORS.read_text(encoding="utf-8"))
    if kat.get("version") != "PS-KAT-1":
        print(f"unexpected KAT version: {kat.get('version')!r}", file=sys.stderr)
        return 2

    checks = 0
    fails: list[tuple[str, str, str, str]] = []

    for v in kat["hash"]["sha3_256"]:
        got = hashlib.sha3_256(v["msgUtf8"].encode("utf-8")).hexdigest()
        checks += 1
        if got != v["digestHex"]:
            fails.append(("sha3_256", v["msgUtf8"], got, v["digestHex"]))

    for v in kat["hash"]["shake256"]:
        got = hashlib.shake_256(v["msgUtf8"].encode("utf-8")).hexdigest(v["outLen"])
        checks += 1
        if got != v["outHex"]:
            fails.append(("shake256", v["msgUtf8"], got, v["outHex"]))

    for v in kat["mac"]["hmac_sha384"]:
        key = bytes.fromhex(v["keyHex"])
        got = hmac.new(key, v["msgUtf8"].encode("utf-8"), hashlib.sha384).hexdigest()
        checks += 1
        if got != v["tagHex"]:
            fails.append(("hmac_sha384", v["msgUtf8"], got, v["tagHex"]))

    if fails:
        for name, label, got, exp in fails:
            print(f"FAIL {name} [{label!r}]: got {got[:24]}… expected {exp[:24]}…")
        print(f"\n{len(fails)}/{checks} KAT checks FAILED")
        return 1

    print(
        f"PolarSeek conformance: all {checks} KAT checks passed "
        f"(SHA3-256, SHAKE256, HMAC-SHA-384) against {VECTORS.name}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
