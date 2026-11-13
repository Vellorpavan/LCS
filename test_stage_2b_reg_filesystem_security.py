#!/usr/bin/env python3
"""
LCS Stage 2A.26 Filesystem Security & Root Initialization Defense Test Suite
=============================================================================
Directly tests SecureCASStorageEngine and SecureCASDirectoryWalker against:
  1. Root symlink replacement attacks (O_NOFOLLOW on CAS root itself)
  2. Parent directory swap after root descriptor pinning
  3. Ancestor directory replacement races
  4. Intermediate component symlink attacks
  5. Final component symlink attacks
  6. Staging directory replacement attacks
  7. Cross-filesystem (EXDEV) device boundary breakouts
  8. Destination tampering and descriptor integrity across unlinks
  9. External cleanup boundary safety
  10. Inode type invariant verification (rejects non-directory root)
"""

import os
import sys
import errno
import stat
import shutil
import hashlib
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from cas_storage_engine_v2b import (
    SecureCASStorageEngine,
    SecureCASDirectoryWalker,
    CASSecurityViolationError,
    CASDeviceBoundaryViolationError,
    CASDestinationCorruptionError
)

# ============================================================================
# ROOT INITIALIZATION & ANCESTOR DEFENSE TESTS
# ============================================================================

def test_01_root_symlink_replacement_defense():
    print("--- Test 01: Root Symlink Replacement Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        outside_trap = os.path.join(tmp_dir, "outside_victim")
        os.makedirs(outside_trap, exist_ok=True)
        
        cas_root_symlink = os.path.join(tmp_dir, "cas_symlink_root")
        os.symlink(outside_trap, cas_root_symlink)
        
        # Initialization must strictly reject root if it is a symbolic link!
        caught_root_symlink = False
        try:
            SecureCASDirectoryWalker(cas_root_symlink)
        except (CASSecurityViolationError, OSError) as e:
            caught_root_symlink = True
            print(f"  Guarded: Root directory resolution strictly rejected root symlink: {e}")
        assert caught_root_symlink, "Security failure: CAS directory walker accepted a root symlink!"
        
        assert len(os.listdir(outside_trap)) == 0, "Victim directory was contaminated!"
        print("PASS: Test 01 - Root symlink replacement attack defeated.\n")


def test_02_parent_directory_swap_defense():
    print("--- Test 02: Parent Directory Swap Defense (Root Descriptor Pinning) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        outside_trap = os.path.join(tmp_dir, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        
        base_dir = os.path.join(tmp_dir, "base")
        cas_root = os.path.join(base_dir, "cas")
        os.makedirs(cas_root, exist_ok=True)
        
        # Initialize storage engine, pinning root_fd and staging_dir_fd
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        # Adversary swaps the entire parent directory 'base' with a symlink to outside_trap
        base_renamed = os.path.join(tmp_dir, "base_renamed")
        os.rename(base_dir, base_renamed)
        os.symlink(outside_trap, base_dir)
        
        # Engine writes payload descriptor-relative through pinned descriptors
        payload = b"Payload written after parent directory was swapped by adversary"
        digest = hashlib.sha256(payload).hexdigest()
        
        tmp_name, written, _ = engine.write_payload_to_staging("pub_parent", "tok_parent", digest, payload)
        
        # Verify data landed inside the original pinned inode (in base_renamed/cas/staging)
        assert os.path.exists(os.path.join(base_renamed, "cas", "staging", tmp_name))
        
        # Verify outside_trap remained 100% empty
        assert len(os.listdir(outside_trap)) == 0, "Security failure: File leaked into outside trap!"
        print("  Verified: Operations remained strictly bound to kernel-pinned root descriptor.")
        
        engine.close()
        print("PASS: Test 02 - Parent directory swap defeated by descriptor pinning.\n")


def test_03_ancestor_directory_replacement_pinning():
    print("--- Test 03: Ancestor Directory Replacement Race (Kernel Inode Pinning) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        outside_trap = os.path.join(tmp_dir, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        # Adversary swaps staging directory with a symlink to outside_trap
        staging_orig = os.path.join(cas_root, "staging")
        staging_orphaned = os.path.join(cas_root, "staging_orphaned")
        os.rename(staging_orig, staging_orphaned)
        os.symlink(outside_trap, staging_orig)
        
        payload = b"Protected data written through pinned directory descriptor"
        digest = hashlib.sha256(payload).hexdigest()
        
        tmp_name, written, _ = engine.write_payload_to_staging("pub_pin", "tok_pin", digest, payload)
        
        assert os.path.exists(os.path.join(staging_orphaned, tmp_name))
        assert len(os.listdir(outside_trap)) == 0, "Security failure: outside trap received file write!"
        print("  Verified: Data wrote strictly to kernel-pinned inode; outside trap remained 100% empty.")
        
        engine.close()
        print("PASS: Test 03 - Ancestor Directory Replacement Race defeated.\n")


def test_04_intermediate_component_symlink_attack():
    print("--- Test 04: Intermediate Component Symlink Attack Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        outside_trap = os.path.join(tmp_dir, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        os.makedirs(cas_root, exist_ok=True)
        
        # Adversary creates cas/objects as a symlink pointing to outside_trap
        os.symlink(outside_trap, os.path.join(cas_root, "objects"))
        
        caught_symlink = False
        try:
            engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
            engine.get_shard_dir_descriptor("ab")
        except (CASSecurityViolationError, OSError) as e:
            caught_symlink = True
            print(f"  Guarded: Traversal rejected intermediate symlink component: {e}")
        assert caught_symlink, "Intermediate symlink was followed by directory walker!"
        
        assert len(os.listdir(outside_trap)) == 0
        print("PASS: Test 04 - Intermediate Component Symlink defeated.\n")


def test_05_final_component_symlink_attack():
    print("--- Test 05: Final Component Symlink Attack Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        outside_trap = os.path.join(tmp_dir, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        payload = b"Authentic content intended for CAS in Stage 2A.26"
        digest = hashlib.sha256(payload).hexdigest()
        shard = digest[:2]
        
        shard_dir = os.path.join(cas_root, "objects", shard)
        os.makedirs(shard_dir, exist_ok=True)
        
        # Adversary creates destination file as a symlink pointing to an outside victim file
        target_outside_file = os.path.join(outside_trap, "victim_file.txt")
        with open(target_outside_file, "wb") as f:
            f.write(b"ORIGINAL SECRET CONTENT")
            
        dest_symlink = os.path.join(shard_dir, digest)
        os.symlink(target_outside_file, dest_symlink)
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_sym", "tok_sym", digest, payload)
        
        caught_symlink_tampering = False
        try:
            engine.publish_staging_to_cas(tmp_name, digest)
        except (CASDestinationCorruptionError, CASSecurityViolationError, OSError) as e:
            caught_symlink_tampering = True
            print(f"  Guarded: Publication rejected destination symlink attack: {e}")
        assert caught_symlink_tampering, "Engine overwrote through destination symlink!"
        
        with open(target_outside_file, "rb") as f:
            assert f.read() == b"ORIGINAL SECRET CONTENT"
            
        engine.close()
        print("PASS: Test 05 - Final Component Symlink Attack defeated.\n")


def test_06_staging_directory_replacement_attack():
    print("--- Test 06: Staging Directory Replacement Attack Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        outside_trap = os.path.join(tmp_dir, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        os.makedirs(cas_root, exist_ok=True)
        
        os.symlink(outside_trap, os.path.join(cas_root, "staging"))
        
        caught_staging_symlink = False
        try:
            walker = SecureCASDirectoryWalker(cas_root)
            walker.open_subpath_descriptor("staging")
        except (CASSecurityViolationError, OSError) as e:
            caught_staging_symlink = True
            print(f"  Guarded: O_NOFOLLOW strictly rejected symlinked staging directory: {e}")
        assert caught_staging_symlink
        
        assert len(os.listdir(outside_trap)) == 0
        print("PASS: Test 06 - Staging Directory Replacement defeated.\n")


def test_07_cross_filesystem_device_boundary_protection():
    print("--- Test 07: Cross-Filesystem (EXDEV) Device Boundary Protection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        mount_point = os.path.join(cas_root, "mount_point")
        os.makedirs(mount_point, exist_ok=True)
        
        walker = SecureCASDirectoryWalker(cas_root)
        root_dev = walker.dev
        assert root_dev > 0
        
        # Simulate cross-device mount point mismatch
        walker.dev = root_dev + 8888
        caught_dev_mismatch = False
        try:
            walker.open_subpath_descriptor("mount_point")
        except CASDeviceBoundaryViolationError as e:
            caught_dev_mismatch = True
            print(f"  Guarded: Cross-device breakout check caught device mismatch: {e}")
        assert caught_dev_mismatch
        
        walker.close()
        print("PASS: Test 07 - Cross-Filesystem Breakout defeated.\n")


def test_08_destination_tampering_and_descriptor_integrity():
    print("--- Test 08: Destination Tampering Defense & Descriptor Integrity ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        payload = b"Immutable CAS descriptor integrity test for Stage 2A.26"
        digest = hashlib.sha256(payload).hexdigest()
        
        tmp_name, _, _ = engine.write_payload_to_staging("pub_tamp", "tok_tamp", digest, payload)
        engine.publish_staging_to_cas(tmp_name, digest)
        
        shard = digest[:2]
        shard_fd = engine.get_shard_dir_descriptor(shard)
        blob_fd = os.open(digest, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=shard_fd)
        
        content = os.read(blob_fd, 1024)
        assert content == payload
        
        os.unlink(digest, dir_fd=shard_fd)
        
        os.lseek(blob_fd, 0, os.SEEK_SET)
        assert os.read(blob_fd, 1024) == payload
        
        os.close(blob_fd)
        os.close(shard_fd)
        engine.close()
        print("  Verified: Open descriptor remains intact and consistent even across directory unlink.")
        print("PASS: Test 08 - Descriptor Integrity defeated tampering.\n")


def test_09_cleanup_boundary_safety():
    print("--- Test 09: Cleanup Boundary Safety (Zero External File Deletion) ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        cas_root = os.path.join(tmp_dir, "cas")
        outside_dir = os.path.join(tmp_dir, "outside_user_data")
        os.makedirs(outside_dir, exist_ok=True)
        
        user_file = os.path.join(outside_dir, "important_doc.pdf")
        with open(user_file, "wb") as f:
            f.write(b"CRITICAL USER DATA - DO NOT DELETE")
            
        engine = SecureCASStorageEngine(cas_root, trusted_anchor=os.path.realpath(tmp_dir))
        
        caught_traversal = False
        try:
            engine.delete_cas_blob_descriptor_relative("../../outside_user_data/important_doc.pdf")
        except (CASSecurityViolationError, FileNotFoundError, OSError) as e:
            caught_traversal = True
            print(f"  Guarded: Traversal outside CAS root prevented during deletion: {e}")
        assert caught_traversal
        
        assert os.path.exists(user_file)
        with open(user_file, "rb") as f:
            assert f.read() == b"CRITICAL USER DATA - DO NOT DELETE"
            
        engine.close()
        print("PASS: Test 09 - Cleanup Boundary Safety verified.\n")


def test_10_directory_descriptor_inode_type_invariant():
    print("--- Test 10: Directory Descriptor Inode Type Invariant Verification ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = os.path.join(tmp_dir, "regular_file.txt")
        with open(file_path, "wb") as f:
            f.write(b"not a directory")
            
        caught_not_dir = False
        try:
            SecureCASDirectoryWalker(file_path)
        except (NotADirectoryError, CASSecurityViolationError) as e:
            caught_not_dir = True
            print(f"  Guarded: Walker rejected non-directory root path: {e}")
        assert caught_not_dir
        print("PASS: Test 10 - Directory Descriptor Type Invariant verified.\n")


# ============================================================================
# TEST 11: Trusted Anchor Root Creation & Ancestor Symlink Rejection
# ============================================================================
def test_11_trusted_anchor_root_creation_and_ancestor_symlink_rejection():
    print("--- Test 11: Trusted Anchor Root Creation & Ancestor Symlink Rejection ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        trusted_anchor = os.path.join(os.path.realpath(tmp_dir), "trusted_anchor")
        os.makedirs(trusted_anchor, exist_ok=True)
        outside_trap = os.path.join(os.path.realpath(tmp_dir), "outside_victim_trap")
        os.makedirs(outside_trap, exist_ok=True)
        
        # Scenario A: Clean root initialization from trusted anchor down to subdirectories
        clean_cas_root = os.path.join(trusted_anchor, "deep", "nested", "cas_root")
        engine = SecureCASStorageEngine(clean_cas_root, trusted_anchor=trusted_anchor)
        assert os.path.isdir(os.path.join(clean_cas_root, "staging"))
        assert os.path.isdir(os.path.join(clean_cas_root, "objects"))
        engine.close()
        print("  Verified: Clean root created descriptor-relative starting from trusted anchor.")
        
        # Scenario B: Adversary places a symlink in an ancestor component pointing to outside_trap
        adversary_base = os.path.join(trusted_anchor, "adversary")
        os.makedirs(adversary_base, exist_ok=True)
        symlink_comp = os.path.join(adversary_base, "rogue_link")
        os.symlink(outside_trap, symlink_comp)
        
        target_under_symlink = os.path.join(symlink_comp, "cas_sub")
        caught_anchor_symlink = False
        try:
            SecureCASStorageEngine(target_under_symlink, trusted_anchor=trusted_anchor)
        except (CASSecurityViolationError, OSError) as e:
            caught_anchor_symlink = True
            print(f"  Guarded: Traversal from trusted anchor strictly rejected ancestor symlink: {e}")
        assert caught_anchor_symlink, "Security violation: Engine followed ancestor symlink from trusted anchor!"
        assert len(os.listdir(outside_trap)) == 0, "Victim directory was contaminated!"
        print("  Verified: Outside victim trap remained 100% empty.")
        
        print("PASS: Test 11 - Trusted anchor root creation and ancestor symlink rejection verified.\n")

# ============================================================================
# TEST 12: Concurrent Root Initialization Safety
# ============================================================================
def test_12_concurrent_root_initialization():
    print("--- Test 12: Concurrent Root Initialization Safety ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        trusted_anchor = os.path.join(os.path.realpath(tmp_dir), "anchor")
        os.makedirs(trusted_anchor, exist_ok=True)
        shared_cas_root = os.path.join(trusted_anchor, "shared_team_cas")
        
        import threading
        barrier = threading.Barrier(2)
        engines = []
        errors = []
        
        def worker(w_id: int):
            try:
                barrier.wait()
                eng = SecureCASStorageEngine(shared_cas_root, trusted_anchor=trusted_anchor)
                engines.append((w_id, eng))
            except Exception as e:
                errors.append((w_id, e))
                
        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        
        assert len(errors) == 0, f"Concurrent root initialization produced errors: {errors}"
        assert len(engines) == 2, "Expected 2 successfully initialized engines"
        
        # Verify both engines share the exact same root inode and device
        ino1 = engines[0][1].walker.root_ino
        ino2 = engines[1][1].walker.root_ino
        assert ino1 == ino2, f"Inodes do not match: {ino1} != {ino2}"
        print(f"  Verified: Both concurrent workers safely initialized CAS root at inode {ino1}.")
        
        for _, eng in engines:
            eng.close()
            
        print("PASS: Test 12 - Concurrent root initialization verified.\n")


# ============================================================================
# TEST 13: Complete Multi-Level Ancestor Trust Boundary Verification
# ============================================================================
def test_13_complete_multi_level_ancestor_trust_boundary():
    print("--- Test 13: Complete Multi-Level Ancestor Trust Boundary Verification ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        trusted_anchor = os.path.join(os.path.realpath(tmp_dir), "operator_trusted_anchor")
        os.makedirs(trusted_anchor, exist_ok=True)
        outside_trap = os.path.join(os.path.realpath(tmp_dir), "outside_victim_trap")
        os.makedirs(outside_trap, exist_ok=True)
        
        # Test symlink attacks at every intermediate depth level between anchor and root:
        # Level 1: anchor/sub1
        # Level 2: anchor/sub1/sub2
        # Level 3: anchor/sub1/sub2/sub3
        levels = ["sub1", "sub1/sub2", "sub1/sub2/sub3"]
        for target_level in levels:
            # Clean directory tree under anchor
            clean_anchor = os.path.join(os.path.realpath(tmp_dir), f"anchor_for_{target_level.replace('/', '_')}")
            os.makedirs(clean_anchor, exist_ok=True)
            
            # Create parents up to target_level
            parent = os.path.dirname(os.path.join(clean_anchor, target_level))
            os.makedirs(parent, exist_ok=True)
            
            # Place symlink at target_level pointing to outside_trap
            target_path = os.path.join(clean_anchor, target_level)
            os.symlink(outside_trap, target_path)
            
            full_cas_root = os.path.join(target_path, "cas_store")
            caught_ancestor_symlink = False
            try:
                SecureCASStorageEngine(full_cas_root, trusted_anchor=clean_anchor)
            except (CASSecurityViolationError, OSError) as e:
                caught_ancestor_symlink = True
                print(f"  Guarded: Intermediate ancestor symlink at level '{target_level}' strictly rejected: {e}")
            assert caught_ancestor_symlink, f"Security failure: Engine traversed ancestor symlink at {target_level}!"
            assert len(os.listdir(outside_trap)) == 0, f"Victim directory contaminated at level {target_level}!"
            
        print("  Verified: Complete ancestor chain verified; zero victim directory contamination across all depths.")
        print("PASS: Test 13 - Complete multi-level ancestor trust boundary verified.\n")



# ============================================================================
# TEST 14: Explicit Trusted Anchor Mandate & Symlink Above Anchor Defense
# ============================================================================
def test_14_explicit_trusted_anchor_mandate_and_symlink_above_anchor():
    print("--- Test 14: Explicit Trusted Anchor Mandate & Symlink Above Anchor Defense ---")
    with tempfile.TemporaryDirectory() as tmp_dir:
        real_tmp = os.path.realpath(tmp_dir)
        cas_root = os.path.join(real_tmp, "cas_store")
        
        # 1. Omitting trusted_anchor (trusted_anchor=None) MUST strictly raise CASSecurityViolationError
        caught_none = False
        try:
            SecureCASStorageEngine(cas_root, trusted_anchor=None)
        except CASSecurityViolationError as e:
            caught_none = True
            print(f"  Guarded: Omitting trusted_anchor strictly rejected: {e}")
        assert caught_none, "Security violation: Engine allowed initialization without explicit trusted_anchor!"
        
        # 2. Supplying non-absolute path for trusted_anchor MUST strictly raise CASSecurityViolationError
        caught_non_abs = False
        try:
            SecureCASStorageEngine(cas_root, trusted_anchor="relative/path/anchor")
        except CASSecurityViolationError as e:
            caught_non_abs = True
            print(f"  Guarded: Non-absolute trusted_anchor strictly rejected: {e}")
        assert caught_non_abs, "Security violation: Engine allowed non-absolute trusted_anchor!"
        
        # 3. Supplying a symlink AS the trusted_anchor itself MUST strictly raise CASSecurityViolationError
        outside_trap = os.path.join(real_tmp, "outside_trap")
        os.makedirs(outside_trap, exist_ok=True)
        symlink_anchor = os.path.join(real_tmp, "symlink_as_anchor")
        os.symlink(outside_trap, symlink_anchor)
        
        caught_sym_anchor = False
        try:
            target_cas = os.path.join(symlink_anchor, "cas_store")
            SecureCASStorageEngine(target_cas, trusted_anchor=symlink_anchor)
        except CASSecurityViolationError as e:
            caught_sym_anchor = True
            print(f"  Guarded: Symlink as trusted_anchor strictly rejected: {e}")
        assert caught_sym_anchor, "Security violation: Engine accepted symlink as trusted_anchor!"
        
        # 4. Supplying a trusted_anchor where an ancestor directory ABOVE the anchor is a symlink
        # Hierarchy: real_tmp/ancestor_real/actual_anchor
        # Symlink: real_tmp/ancestor_symlink -> real_tmp/ancestor_real
        # Proposed anchor: real_tmp/ancestor_symlink/actual_anchor
        ancestor_real = os.path.join(real_tmp, "ancestor_real")
        actual_anchor = os.path.join(ancestor_real, "actual_anchor")
        os.makedirs(actual_anchor, exist_ok=True)
        
        ancestor_symlink = os.path.join(real_tmp, "ancestor_symlink")
        os.symlink(ancestor_real, ancestor_symlink)
        
        tainted_anchor_path = os.path.join(ancestor_symlink, "actual_anchor")
        tainted_cas_root = os.path.join(tainted_anchor_path, "cas_store")
        
        caught_above_sym = False
        try:
            SecureCASStorageEngine(tainted_cas_root, trusted_anchor=tainted_anchor_path)
        except CASSecurityViolationError as e:
            caught_above_sym = True
            print(f"  Guarded: Ancestor symlink above proposed anchor strictly detected and rejected: {e}")
        assert caught_above_sym, "Security violation: Engine accepted anchor with symlink in ancestor hierarchy!"
        
        # 5. Legitimate anchor with genuine directory ancestry succeeds
        valid_cas_root = os.path.join(actual_anchor, "cas_store")
        valid_engine = SecureCASStorageEngine(valid_cas_root, trusted_anchor=actual_anchor)
        assert os.path.isdir(os.path.join(valid_cas_root, "staging"))
        valid_engine.close()
        print("  Verified: Legitimate trusted anchor with authentic non-symlink ancestry succeeds.")
        
        print("PASS: Test 14 - Explicit trusted anchor mandate and symlink above anchor defense verified.\n")

def main():
    print("=" * 76)
    print("RUNNING LCS STAGE 2A.28 FILESYSTEM SECURITY VERIFICATION SUITE")
    print("=" * 76)
    test_01_root_symlink_replacement_defense()
    test_02_parent_directory_swap_defense()
    test_03_ancestor_directory_replacement_pinning()
    test_04_intermediate_component_symlink_attack()
    test_05_final_component_symlink_attack()
    test_06_staging_directory_replacement_attack()
    test_07_cross_filesystem_device_boundary_protection()
    test_08_destination_tampering_and_descriptor_integrity()
    test_09_cleanup_boundary_safety()
    test_10_directory_descriptor_inode_type_invariant()
    test_11_trusted_anchor_root_creation_and_ancestor_symlink_rejection()
    test_12_concurrent_root_initialization()
    test_13_complete_multi_level_ancestor_trust_boundary()
    test_14_explicit_trusted_anchor_mandate_and_symlink_above_anchor()
    print("=" * 76)
    print("ALL 14 FILESYSTEM SECURITY TESTS PASSED (100% GREEN)")
    print("=" * 76)

if __name__ == "__main__":
    main()
