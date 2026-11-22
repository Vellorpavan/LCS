#!/usr/bin/env python3
"""
Cryptographic Checksum Invariance Verification
==============================================
Validates bit-for-bit SHA-256 integrity of all five frozen core modules
and four database schema files. Exits with code 0 on success, 1 on failure.
"""

import sys
import os
import hashlib

FROZEN_DIGESTS = {
    # Five Frozen Core Modules
    "capability_retrieval_v1.py": "b7d476236d2f5addd6619f619a6f1145bf407a6917d20493e4d85afd0ca843b4",
    "capability_retrieval_v1_1.py": "2a29c3dcec1e792021a63707fec9a92c3a6505080b0c05a63e377c69ce272e12",
    "capability_parameter_v1.py": "469b743cf6af1f6807544f2182dee12a4708ceb5512dd32185c4e5986a524c00",
    "capability_planning_v1.py": "eb81b3255d58958d73689b99cb8506647f8c781d30d93cea1c90dfd435d070e4",
    "governance_policy_v1.py": "5273f17e83d1c90cd5f935b815841db711a3523a08d1d180f2a4d67bcad44252",
    # Four SQL Migration & Database Schemas
    os.path.join("lcs", "schemas", "lcs_schema_m3_migration.sql"): "65652fa722ddb4fe1334071cd01369cb13e11923a3dd55d313008f73bdefb652",
    os.path.join("lcs", "schemas", "lcs_schema_m4_migration.sql"): "6644e0ead9752ba2c136c5414a6dde72a8ad5eed126ceebe246e7f84ab1817dc",
    os.path.join("lcs", "schemas", "lcs_schema_m5_sqlite_compat.sql"): "88d13292f7888fe7148785c935f4854d8acfca700f0777e1334190f8f750b620",
    os.path.join("lcs", "schemas", "lcs_schema_v2b.sql"): "49ee7ff523e6740f01d52ba279da77055047f1ea0325a7042614befb7401e421",
}


def main() -> int:
    failed = False
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    print("Verifying cryptographic checksums for frozen core modules and schemas...")

    for rel_path, expected_hash in FROZEN_DIGESTS.items():
        abs_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(abs_path):
            print(f"FAILED: File not found: {rel_path}")
            failed = True
            continue

        with open(abs_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        if actual_hash != expected_hash:
            print(f"FAILED: Hash mismatch for {rel_path}!")
            print(f"  Expected: {expected_hash}")
            print(f"  Actual:   {actual_hash}")
            failed = True
        else:
            print(f"  [OK] {rel_path} -> {actual_hash[:16]}...")

    if failed:
        print("\nERROR: Frozen baseline invariance check failed!")
        return 1

    print("\nSUCCESS: All frozen core modules and schemas are verified bit-for-bit identical.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
