#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail-closed tests for paired synthetic and live shadow resource evidence."""

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import run_shadow_resource_production_gate as live_runner
import run_shadow_resource_synthetic_gate as synthetic_runner
import verify_shadow_resource_production_evidence as verifier
import generate_resource_benchmark_evidence as resource_model


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTRACT_PATH = HERE / "shadow_resource_production_contract.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def synthetic_phase(database_bytes: int = 150_000_000_000) -> dict:
    return {
        "wall_seconds": 1.0,
        "peak_rss_bytes": 2_000_000_000,
        "peak_database_bytes": database_bytes,
        "peak_sst_bytes": database_bytes - 1_001_100_000,
        "peak_wal_bytes": 1_000_000_000,
        "peak_manifest_bytes": 1_000_000,
        "peak_other_bytes": 100_000,
        "sample_count": 2,
        "maximum_sample_seconds": 0.1,
        "maximum_sample_gap_seconds": 0.2,
    }


def live_phase(height: int, block_hash: str,
               chainstate_bytes: int = 4_000_000_000) -> dict:
    return {
        "wall_seconds": 1.0,
        "peak_rss_bytes": 2_000_000_000,
        "peak_chainstate_bytes": chainstate_bytes,
        "peak_sst_bytes": chainstate_bytes - 1_001_100_000,
        "peak_wal_bytes": 1_000_000_000,
        "peak_manifest_bytes": 1_000_000,
        "peak_other_bytes": 100_000,
        "completed_height": height,
        "completed_hash": block_hash,
        "sample_count": 2,
        "maximum_sample_seconds": 0.1,
        "maximum_sample_gap_seconds": 0.2,
    }


def snapshot(total: int) -> dict:
    wal = 1_000_000_000
    manifest = 1_000_000
    other = 100_000
    return {
        "total_bytes": total,
        "sst_bytes": total - wal - manifest - other,
        "wal_bytes": wal,
        "manifest_bytes": manifest,
        "other_bytes": other,
        "file_count": 100,
    }


def measurement_environment() -> dict:
    return {
        "schema": 1,
        "system": "Linux",
        "machine": "x86_64",
        "kernel_release": "test-kernel",
        "cpu_model": "test-cpu",
        "logical_cpu_count": 8,
        "memory_bytes": 32_000_000_000,
        "page_size_bytes": 4096,
        "filesystem_type": "ext4",
        "filesystem_source": "/dev/test",
        "mount_options": "rw",
        "device_major": 8,
        "device_minor": 1,
        "rotational": False,
        "compiler": "g++ test",
        "python_version": "3.11.0",
        "page_cache_policy": "os-managed-observed-no-eviction",
    }


class ShadowResourceProductionTest(unittest.TestCase):
    def setUp(self):
        self.contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        verifier.verify_contract(self.contract)

    def test_contract_exact_arithmetic_and_point_lookup_envelope(self):
        fixture = self.contract["synthetic_fixture"]
        self.assertEqual(fixture["issued_claims"], 179_771_400)
        self.assertEqual(
            fixture["claim_family_records"], 3 * fixture["issued_claims"]
        )
        self.assertEqual(
            fixture["authentication_sequential_records"],
            2 * fixture["total_records"],
        )
        self.assertEqual(
            fixture["authentication_point_lookups"],
            (
                fixture["payout_point_lookups"]
                + fixture["attestation_point_lookups"]
                + fixture["logical_proof_bucket_point_lookups"]
            ),
        )
        self.assertEqual(
            fixture["authentication_point_lookups"], 372_327_984
        )

    def test_logical_proof_bucket_serialization_footprint(self):
        expected = {
            0: (38, 50, 61, 98),
            1: (70, 82, 93, 130),
            64: (2_086, 2_100, 2_112, 2_150),
        }
        for proof_ids, sizes in expected.items():
            footprint = resource_model.logical_proof_bucket_storage(proof_ids)
            self.assertEqual(
                (
                    footprint["payload_bytes"],
                    footprint["script_bytes"],
                    footprint["coin_value_bytes"],
                    footprint["batch_payload_bytes"],
                ),
                sizes,
            )
        self.assertEqual(199_800 * 2_150, 429_570_000)

    def test_chainstate_file_categories_are_physical(self):
        with tempfile.TemporaryDirectory() as temporary:
            chainstate = Path(temporary)
            (chainstate / "000001.ldb").write_bytes(b"s" * 11)
            (chainstate / "000002.log").write_bytes(b"w" * 7)
            (chainstate / "MANIFEST-000003").write_bytes(b"m" * 5)
            (chainstate / "CURRENT").write_bytes(b"o" * 3)
            measured = live_runner.chainstate_snapshot(chainstate)
        self.assertEqual(
            measured,
            {
                "total_bytes": 26,
                "sst_bytes": 11,
                "wal_bytes": 7,
                "manifest_bytes": 5,
                "other_bytes": 3,
                "file_count": 4,
            },
        )

    def test_periodic_physical_samples_tolerate_leveldb_file_churn(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            chainstate = temporary / "chainstate"
            database = temporary / "synthetic"
            chainstate.mkdir()
            database.mkdir()
            for root in (chainstate, database):
                (root / "000001.ldb").write_bytes(b"stable")
                (root / "000002.log").write_bytes(b"vanishing")

            original_scandir = os.scandir

            class RacingEntry:
                def __init__(self, entry):
                    self.entry = entry
                    self.name = entry.name
                    self.path = entry.path

                def stat(self, follow_symlinks=False):
                    if self.name == "000002.log":
                        raise FileNotFoundError(self.path)
                    return self.entry.stat(follow_symlinks=follow_symlinks)

            class RacingDirectory:
                def __init__(self, path):
                    with original_scandir(path) as entries:
                        self.entries = [RacingEntry(entry) for entry in entries]

                def __enter__(self):
                    return iter(self.entries)

                def __exit__(self, _exc_type, _exc_value, _traceback):
                    return False

            with mock.patch.object(os, "scandir", RacingDirectory):
                live = live_runner.chainstate_snapshot(
                    chainstate, tolerate_churn=True
                )
                synthetic = synthetic_runner.database_snapshot(
                    database, tolerate_churn=True
                )
                with self.assertRaisesRegex(RuntimeError, "disappeared"):
                    live_runner.chainstate_snapshot(chainstate)
                with self.assertRaisesRegex(RuntimeError, "disappeared"):
                    synthetic_runner.database_snapshot(database)

            self.assertEqual(live["total_bytes"], len(b"stable"))
            self.assertEqual(synthetic["total_bytes"], len(b"stable"))

    def test_archive_extraction_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            archive = temporary / "bad.tar"
            payload = b"outside"
            with tarfile.open(archive, "w") as bundle:
                member = tarfile.TarInfo("../outside")
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            with self.assertRaisesRegex(
                    RuntimeError, "unsafe fixture archive member"):
                live_runner.safe_extract(
                    archive, temporary / "extract", "datadir"
                )
            self.assertFalse((temporary / "outside").exists())

    def test_extract_reauthenticates_archive_after_use(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            archive = temporary / "fixture.tar"
            archive.write_bytes(b"authenticated archive")
            manifest = {
                "archive_root": "datadir",
                "archive_sha256": sha256(archive),
                "archive_size_bytes": archive.stat().st_size,
            }
            gate = live_runner.ProductionGate.__new__(
                live_runner.ProductionGate
            )
            gate.args = SimpleNamespace(fixture_archive=archive)
            gate.manifest = manifest
            gate.work = temporary / "work"
            gate.work.mkdir()
            gate.datadir = gate.work / "fixture" / "datadir"
            gate.chainstate = gate.datadir / "chainstate"
            gate.require_datadir_unowned = mock.Mock()

            def replace_during_extract(source, destination, expected_root):
                del source, expected_root
                datadir = destination / "datadir"
                (datadir / "blocks").mkdir(parents=True)
                (datadir / "chainstate").mkdir()
                archive.write_bytes(b"unauthenticated bytes")

            with mock.patch.object(
                    live_runner, "safe_extract", replace_during_extract):
                with self.assertRaisesRegex(
                        RuntimeError, "archive SHA256 differs"):
                    gate.extract_fresh()

    def test_work_directory_symlink_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            target = temporary / "target"
            target.mkdir()
            link = temporary / "redirect"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, "symbolic-link"):
                synthetic_runner.reject_symlink_components(
                    link / "candidate", "work directory"
                )
            with self.assertRaisesRegex(RuntimeError, "symbolic-link"):
                live_runner.reject_symlink_components(
                    link / "candidate", "work directory"
                )

    def test_interrupted_synthetic_mutations_restore_exact_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            database = temporary / "synthetic-leveldb"
            database.mkdir()
            sstable = database / "000001.ldb"
            log = database / "000002.log"
            sstable.write_bytes(b"immutable-sstable")
            log.write_bytes(b"mutable-log")

            gate = object.__new__(synthetic_runner.SyntheticGate)
            gate.args = SimpleNamespace(work_dir=temporary)
            gate.database = database
            gate.snapshot_root = temporary / "synthetic-predecessor"
            gate.snapshot_marker = temporary / "synthetic-predecessor.json"
            gate.binding = {"target_sha": "a" * 40}
            marker = gate.create_snapshot("undo")
            self.assertEqual(
                sstable.stat().st_ino,
                (gate.snapshot_root / sstable.name).stat().st_ino,
            )
            self.assertNotEqual(
                log.stat().st_ino,
                (gate.snapshot_root / log.name).stat().st_ino,
            )

            sstable.unlink()
            log.write_bytes(b"partial-mutation")
            (database / "partial.ldb").write_bytes(b"partial")
            gate.restore_snapshot("undo")
            self.assertEqual(sstable.read_bytes(), b"immutable-sstable")
            self.assertEqual(log.read_bytes(), b"mutable-log")
            self.assertFalse((database / "partial.ldb").exists())
            self.assertEqual(
                synthetic_runner.database_snapshot(
                    database, include_files=True
                ),
                marker["snapshot"],
            )

    def test_interrupted_synthetic_read_restores_exact_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            gate = synthetic_runner.SyntheticGate(
                SimpleNamespace(work_dir=temporary),
                {"budgets": {"read_timeout": 5}},
                {"target_sha": "a" * 40},
            )
            try:
                gate.database.mkdir()
                immutable = gate.database / "000001.ldb"
                mutable = gate.database / "000002.log"
                immutable.write_bytes(b"immutable")
                mutable.write_bytes(b"predecessor")
                gate.begin("read")
                marker = gate.create_snapshot("read")
                immutable.unlink()
                mutable.write_bytes(b"partial-cleanup")

                def invoke(command, timeout):
                    self.assertEqual(command, "open")
                    self.assertEqual(timeout, 5)
                    self.assertEqual(immutable.read_bytes(), b"immutable")
                    self.assertEqual(mutable.read_bytes(), b"predecessor")
                    return {
                        "peak_rss_bytes": 1,
                        "peak_database_bytes": 1,
                        "peak_sst_bytes": 0,
                        "peak_wal_bytes": 0,
                        "peak_manifest_bytes": 0,
                        "peak_other_bytes": 0,
                        "wall_seconds": 1.0,
                        "sample_count": 2,
                        "maximum_sample_seconds": 0.1,
                        "maximum_sample_gap_seconds": 0.2,
                    }, "complete"

                gate.invoke = invoke
                resources, output = gate.phase(
                    "read", "open", "read_timeout"
                )
                self.assertEqual(output, "complete")
                self.assertEqual(
                    resources["peak_database_bytes"],
                    marker["snapshot"]["total_bytes"],
                )
                self.assertFalse(gate.snapshot_root.exists())
            finally:
                gate.close()

    def test_measured_synthetic_child_starts_behind_rss_barrier(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            fixture = temporary / "fixture.py"
            fixture.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "assert sys.argv[3] == '--measurement-barriers'\n"
                "assert sys.stdin.read(1) == '\\n'\n"
                "database = pathlib.Path(sys.argv[2])\n"
                "database.mkdir(exist_ok=True)\n"
                "(database / 'CURRENT').write_bytes(b'x')\n"
                "print('{\\\"schema\\\":1}', flush=True)\n"
                "assert sys.stdin.read(1) == '\\n'\n",
                encoding="utf-8",
            )
            fixture.chmod(0o700)
            args = SimpleNamespace(
                work_dir=temporary,
                fixture_binary=fixture,
            )
            contract = {"measurement": {"sample_interval_seconds": 1}}
            gate = synthetic_runner.SyntheticGate(
                args, contract, {"target_sha": "a" * 40}
            )
            try:
                live_samples = 0

                def live_rss(pid):
                    nonlocal live_samples
                    try:
                        os.kill(pid, 0)
                    except ProcessLookupError:
                        return 0
                    live_samples += 1
                    return 4096 if live_samples == 1 else 8192

                with mock.patch.object(
                    synthetic_runner, "process_rss_bytes",
                    side_effect=live_rss,
                ):
                    resources, output = gate.invoke("open", 5)
                self.assertEqual(resources["peak_rss_bytes"], 8192)
                self.assertEqual(json.loads(output), {"schema": 1})
            finally:
                gate.close()

    def test_phase_journal_marks_interruption_until_atomic_completion(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            gate = object.__new__(synthetic_runner.SyntheticGate)
            gate.journal_path = temporary / "journal.json"
            gate.journal = {
                "schema": 2,
                "binding": {"target_sha": "a" * 40},
                "active_phase": None,
                "completed": {},
            }
            self.assertFalse(gate.begin("full_undo"))
            persisted = json.loads(gate.journal_path.read_text())
            self.assertEqual(persisted["active_phase"], "full_undo")
            self.assertTrue(gate.begin("full_undo"))
            gate.save("full_undo", {"resources": {}})
            persisted = json.loads(gate.journal_path.read_text())
            self.assertIsNone(persisted["active_phase"])
            self.assertIn("full_undo", persisted["completed"])

    def test_restart_cannot_relabel_completed_phases_to_a_new_host(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            args = SimpleNamespace(work_dir=temporary)
            first_binding = {
                "target_sha": "a" * 40,
                "measurement_environment": {"kernel": "first"},
            }
            gate = synthetic_runner.SyntheticGate(args, {}, first_binding)
            gate.begin("full_apply")
            gate.close()
            changed_binding = copy.deepcopy(first_binding)
            changed_binding["measurement_environment"]["kernel"] = "changed"
            with self.assertRaisesRegex(RuntimeError, "different inputs"):
                synthetic_runner.SyntheticGate(args, {}, changed_binding)

    def test_live_snapshot_restores_chainstate_and_block_index(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            datadir = temporary / "fixture" / "datadir"
            chainstate = datadir / "chainstate"
            block_index = datadir / "blocks" / "index"
            chainstate.mkdir(parents=True)
            block_index.mkdir(parents=True)
            (chainstate / "000001.ldb").write_bytes(b"coins")
            (chainstate / "CURRENT").write_bytes(b"manifest")
            (block_index / "000002.ldb").write_bytes(b"blocks")
            (block_index / "CURRENT").write_bytes(b"index-manifest")

            gate = object.__new__(live_runner.ProductionGate)
            gate.work = temporary
            gate.datadir = datadir
            gate.chainstate = chainstate
            gate.snapshot_root = temporary / "live-predecessor"
            gate.snapshot_marker = temporary / "live-predecessor.json"
            gate.binding = {"target_sha": "a" * 40}
            marker = gate.create_snapshot("live_reorg_undo")

            shutil.rmtree(chainstate)
            shutil.rmtree(block_index)
            chainstate.mkdir()
            block_index.mkdir()
            (chainstate / "partial.ldb").write_bytes(b"partial")
            (block_index / "partial.ldb").write_bytes(b"partial")
            gate.restore_snapshot("live_reorg_undo")

            self.assertEqual(
                gate.snapshot_inventory(temporary / "live-predecessor"),
                marker["snapshot"],
            )
            self.assertEqual(
                live_runner.chainstate_snapshot(
                    chainstate, include_files=True
                ),
                marker["snapshot"]["chainstate"],
            )
            self.assertEqual(
                live_runner.chainstate_snapshot(
                    block_index, include_files=True
                ),
                marker["snapshot"]["block_index"],
            )

    def test_inherited_gate_lock_blocks_retry_until_child_exits(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            args = SimpleNamespace(work_dir=temporary)
            binding = {"target_sha": "a" * 40}
            gate = synthetic_runner.SyntheticGate(args, {}, binding)
            child = subprocess.Popen(
                ["sleep", "30"], pass_fds=(gate.lock_fd,)
            )
            gate.close()
            try:
                with self.assertRaisesRegex(RuntimeError, "surviving child"):
                    synthetic_runner.SyntheticGate(args, {}, binding)
            finally:
                child.terminate()
                child.wait(timeout=10)
            replacement = synthetic_runner.SyntheticGate(args, {}, binding)
            replacement.close()

    def make_repo(self, temporary: Path):
        repo = temporary / "repo"
        repo.mkdir()
        for relative in self.contract["source_files"]:
            destination = repo / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        contract_destination = (
            repo / "ci/release/shadow_resource_production_contract.json"
        )
        contract_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CONTRACT_PATH, contract_destination)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "Blackcoin-Dev"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email",
             "298119138+Blackcoin-Dev@users.noreply.github.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(repo), "remote", "add", "origin",
             "https://github.com/Blackcoin-Dev/Blackcoin.git"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        target_sha = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        contract_path = repo / "ci/release/shadow_resource_production_contract.json"
        hashes = {
            relative: sha256(repo / relative)
            for relative in self.contract["source_files"]
        }
        return repo, target_sha, contract_path, hashes

    def make_executable(self, path: Path) -> Path:
        path.write_bytes(b"executable-test-input")
        path.chmod(0o700)
        return path

    def test_current_hashes_cannot_mask_epoch_source_model_drift(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, _, _, hashes = self.make_repo(temporary)
            cache_source = repo / "src/node/caches.cpp"
            source = cache_source.read_text(encoding="utf-8")
            source = source.replace(
                "sizes.coins_db = std::min(sizes.coins_db, "
                "nMaxCoinsDBCache << 20);",
                "sizes.coins_db = nTotalCache;",
            )
            cache_source.write_text(source, encoding="utf-8")
            hashes["src/node/caches.cpp"] = sha256(cache_source)
            with self.assertRaisesRegex(
                    RuntimeError, "epoch-bound source contract changed"):
                verifier.verify_sources(
                    repo, {"source_files": hashes}, self.contract
                )

    def test_current_hashes_cannot_mask_logical_bucket_window_drift(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, _, _, hashes = self.make_repo(temporary)
            shadow_header = repo / "src/shadow.h"
            source = shadow_header.read_text(encoding="utf-8")
            source = source.replace(
                "static constexpr uint32_t SHADOW_POW_LATE_ORIGIN_WINDOW = 64;",
                "static constexpr uint32_t SHADOW_POW_LATE_ORIGIN_WINDOW = 65;",
            )
            shadow_header.write_text(source, encoding="utf-8")
            hashes["src/shadow.h"] = sha256(shadow_header)
            with self.assertRaisesRegex(
                    RuntimeError, "epoch-bound source contract changed"):
                verifier.verify_sources(
                    repo, {"source_files": hashes}, self.contract
                )

    def exact_scan(self, phase_name: str) -> dict:
        fixture = self.contract["synthetic_fixture"]
        return {
            "schema": 1,
            "contract_id": self.contract["contract_id"],
            "phase": phase_name,
            "height": fixture["reward_end_height"],
            "records": fixture["total_records"],
            "claims": fixture["issued_claims"],
            "payouts": fixture["issued_claims"],
            "provenance": fixture["issued_claims"],
            "logical_proof_buckets": fixture[
                "logical_proof_bucket_records"
            ],
            "logical_bytes": fixture["retained_logical_batch_payload_bytes"],
        }

    def exact_authentication(self) -> dict:
        fixture = self.contract["synthetic_fixture"]
        return {
            "schema": 1,
            "contract_id": self.contract["contract_id"],
            "phase": "applied",
            "height": fixture["reward_end_height"],
            "sequential_records": fixture["authentication_sequential_records"],
            "provenance_records": fixture["issued_claims"],
            "payout_candidates": fixture["issued_claims"],
            "payout_authenticated": fixture["issued_claims"],
            "attestation_candidates": fixture["issued_claims"],
            "attestation_lookup_hits": fixture["issued_claims"],
            "logical_proof_bucket_lookups": fixture[
                "logical_proof_bucket_point_lookups"
            ],
            "point_lookups": fixture["authentication_point_lookups"],
        }

    def make_synthetic_evidence(self, target_sha: str, contract_path: Path,
                                hashes: dict, binary: Path) -> dict:
        logical = self.contract["synthetic_fixture"][
            "retained_logical_batch_payload_bytes"
        ]
        steady = snapshot(120_000_000_000)
        compacted = snapshot(115_000_000_000)
        phases = {
            "full_apply": synthetic_phase(),
            "full_scan": synthetic_phase(),
            "full_authentication": synthetic_phase(),
            "clean_startups": [synthetic_phase() for _ in range(3)],
            "full_undo": synthetic_phase(),
            "undo_scan": synthetic_phase(),
            "full_reapply": synthetic_phase(),
            "reapply_scan": synthetic_phase(),
            "forced_compaction": synthetic_phase(),
            "compaction_scan": synthetic_phase(),
        }
        reclaimed = steady["total_bytes"] - compacted["total_bytes"]
        return {
            "schema": 2,
            "status": "complete",
            "evidence_kind": "deterministic_synthetic_full_epoch",
            "not_live_chain_evidence": True,
            "repository": self.contract["repository"],
            "target_sha": target_sha,
            "tree_clean": True,
            "measurement_environment": measurement_environment(),
            "qualification_scope": self.contract["qualification_scope"],
            "contract_sha256": sha256(contract_path),
            "source_files": hashes,
            "fixture_binary": {
                "sha256": sha256(binary),
                "size_bytes": binary.stat().st_size,
            },
            "fixture": self.exact_scan("applied"),
            "authentication": self.exact_authentication(),
            "post_reapply_fixture": self.exact_scan("reapplied"),
            "post_compaction_fixture": self.exact_scan("reapplied"),
            "phases": phases,
            "leveldb": {
                "steady_snapshot": steady,
                "compacted_snapshot": compacted,
                "maximum_observed_bytes": 150_000_000_000,
                "obsolete_file_bytes": 1_000_000_000,
                "post_apply_cleanup_obsolete_bytes": 1_000_000_000,
                "post_reapply_cleanup_obsolete_bytes": 500_000_000,
                "forced_compaction_reclaimed_bytes": reclaimed,
                "steady_physical_to_logical_ratio":
                    steady["total_bytes"] / logical,
                "maximum_observed_physical_to_logical_ratio":
                    150_000_000_000 / logical,
                "obsolete_file_to_logical_ratio": 1_000_000_000 / logical,
                "forced_compaction_reclaim_ratio":
                    reclaimed / steady["total_bytes"],
            },
            "maximum_peak_rss_bytes": 2_000_000_000,
        }

    def make_live_evidence(self, target_sha: str, contract_path: Path,
                           hashes: dict, blackcoind: Path,
                           blackcoin_cli: Path) -> dict:
        live = self.contract["live_partial_snapshot"]
        height = live["minimum_height"] + 100
        end_hash = "a" * 64
        pre_hash = "b" * 64
        first_hash = "c" * 64
        steady = snapshot(3_000_000_000)
        compacted = snapshot(2_900_000_000)
        phases = {
            "live_full_replay": live_phase(height, end_hash),
            "live_lifecycle_scan": live_phase(height, end_hash),
            "clean_startups": [live_phase(height, end_hash) for _ in range(3)],
            "live_partial_epoch_undo": live_phase(
                self.contract["synthetic_fixture"]["reward_start_height"] - 1,
                pre_hash,
            ),
            "live_partial_epoch_reapply": live_phase(height, end_hash),
            "live_reorg_cleanup": live_phase(height, end_hash),
            "forced_compaction": live_phase(height, end_hash),
        }
        return {
            "schema": 2,
            "status": "complete",
            "evidence_kind": "current_live_partial_epoch",
            "completed_epoch": False,
            "repository": self.contract["repository"],
            "target_sha": target_sha,
            "tree_clean": True,
            "measurement_environment": measurement_environment(),
            "qualification_scope": self.contract["qualification_scope"],
            "contract_sha256": sha256(contract_path),
            "source_files": hashes,
            "binaries": {
                "blackcoind": {
                    "sha256": sha256(blackcoind),
                    "size_bytes": blackcoind.stat().st_size,
                },
                "blackcoin_cli": {
                    "sha256": sha256(blackcoin_cli),
                    "size_bytes": blackcoin_cli.stat().st_size,
                },
            },
            "fixture": {
                "evidence_kind": "current_live_partial_epoch",
                "fixture_manifest_sha256": "1" * 64,
                "archive_sha256": "2" * 64,
                "archive_size_bytes": 100,
                "network": "main",
                "target_sha": target_sha,
                "captured_at_unix": int(time.time()),
                "capture_attestation":
                    "protected_operator_confirmed_connected_mainnet_tip",
                "capture_rpc": {
                    "chain": "main",
                    "blocks": height,
                    "headers": height,
                    "bestblockhash": end_hash,
                    "initialblockdownload": False,
                    "connections": 8,
                },
                "end_height": height,
                "end_hash": end_hash,
                "pre_gold_rush_hash": pre_hash,
                "first_gold_rush_hash": first_hash,
                "issued_claims": 100,
                "spent_claims": 10,
                "unspent_claims": 90,
            },
            "phases": phases,
            "leveldb": {
                "steady_snapshot": steady,
                "compacted_snapshot": compacted,
                "maximum_observed_bytes": 4_000_000_000,
                "observed_file_churn_bytes": 1_000_000,
                "forced_compaction_reclaimed_bytes": 100_000_000,
            },
            "maximum_peak_rss_bytes": 2_000_000_000,
        }

    def write_json(self, path: Path, value: dict) -> Path:
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def write_live_manifest(self, path: Path, evidence: dict,
                            contract_path: Path) -> tuple[Path, str]:
        fixture = evidence["fixture"]
        manifest = {
            "schema": 2,
            "evidence_kind": fixture["evidence_kind"],
            "contract_sha256": sha256(contract_path),
            "target_sha": fixture["target_sha"],
            "network": fixture["network"],
            "archive_sha256": fixture["archive_sha256"],
            "archive_size_bytes": fixture["archive_size_bytes"],
            "archive_root": "datadir",
            "captured_at_unix": fixture["captured_at_unix"],
            "capture_attestation": fixture["capture_attestation"],
            "capture_rpc": fixture["capture_rpc"],
            "end_height": fixture["end_height"],
            "end_hash": fixture["end_hash"],
            "pre_gold_rush_hash": fixture["pre_gold_rush_hash"],
            "first_gold_rush_hash": fixture["first_gold_rush_hash"],
            "issued_claims": fixture["issued_claims"],
            "spent_claims": fixture["spent_claims"],
            "unspent_claims": fixture["unspent_claims"],
        }
        self.write_json(path, manifest)
        digest = sha256(path)
        fixture["fixture_manifest_sha256"] = digest
        return path, digest

    def test_paired_evidence_verifies_and_scaled_or_mislabeled_fails(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, target_sha, contract_path, hashes = self.make_repo(temporary)
            fixture_binary = self.make_executable(temporary / "fixture")
            blackcoind = self.make_executable(temporary / "blackcoind")
            blackcoin_cli = self.make_executable(temporary / "blackcoin-cli")
            synthetic = self.make_synthetic_evidence(
                target_sha, contract_path, hashes, fixture_binary
            )
            live = self.make_live_evidence(
                target_sha, contract_path, hashes, blackcoind, blackcoin_cli
            )
            synthetic_path = self.write_json(
                temporary / "synthetic.json", synthetic
            )
            manifest_path, manifest_sha = self.write_live_manifest(
                temporary / "manifest.json", live, contract_path
            )
            live_path = self.write_json(temporary / "live.json", live)

            verifier.verify_synthetic(
                repo, contract_path, synthetic_path, fixture_binary, target_sha
            )
            verifier.verify_live(
                repo, contract_path, live_path, manifest_path,
                blackcoind, blackcoin_cli, target_sha, manifest_sha,
            )

            scaled = copy.deepcopy(synthetic)
            scaled["authentication"]["point_lookups"] -= 1
            scaled_path = self.write_json(temporary / "scaled.json", scaled)
            with self.assertRaisesRegex(RuntimeError, "point-lookup envelope"):
                verifier.verify_synthetic(
                    repo, contract_path, scaled_path, fixture_binary, target_sha
                )

            mislabeled = copy.deepcopy(synthetic)
            mislabeled["evidence_kind"] = "current_live_partial_epoch"
            mislabeled_path = self.write_json(
                temporary / "mislabeled.json", mislabeled
            )
            with self.assertRaisesRegex(RuntimeError, "identity or status"):
                verifier.verify_synthetic(
                    repo, contract_path, mislabeled_path,
                    fixture_binary, target_sha,
                )

            completed_too_early = copy.deepcopy(live)
            completed_too_early["completed_epoch"] = True
            completed_path = self.write_json(
                temporary / "completed-too-early.json", completed_too_early
            )
            with self.assertRaisesRegex(RuntimeError, "completed_epoch"):
                verifier.verify_live(
                    repo, contract_path, completed_path, manifest_path,
                    blackcoind, blackcoin_cli, target_sha, manifest_sha,
                )

            mismatched_fixture = copy.deepcopy(live)
            mismatched_fixture["fixture"]["archive_size_bytes"] += 1
            mismatched_path = self.write_json(
                temporary / "mismatched-fixture.json", mismatched_fixture
            )
            with self.assertRaisesRegex(RuntimeError, "differs from its manifest"):
                verifier.verify_live(
                    repo, contract_path, mismatched_path, manifest_path,
                    blackcoind, blackcoin_cli, target_sha, manifest_sha,
                )

    def test_authentication_time_and_compaction_threshold_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, target_sha, contract_path, hashes = self.make_repo(temporary)
            binary = self.make_executable(temporary / "fixture")
            evidence = self.make_synthetic_evidence(
                target_sha, contract_path, hashes, binary
            )
            evidence["phases"]["full_authentication"]["wall_seconds"] = (
                self.contract["budgets"][
                    "maximum_full_authentication_seconds"
                ] + 1
            )
            slow_path = self.write_json(temporary / "slow.json", evidence)
            with self.assertRaisesRegex(RuntimeError, "full_authentication"):
                verifier.verify_synthetic(
                    repo, contract_path, slow_path, binary, target_sha
                )

            evidence = self.make_synthetic_evidence(
                target_sha, contract_path, hashes, binary
            )
            steady_total = evidence["leveldb"]["steady_snapshot"]["total_bytes"]
            compacted_total = 100_000_000_000
            evidence["leveldb"]["compacted_snapshot"] = snapshot(compacted_total)
            evidence["leveldb"]["forced_compaction_reclaimed_bytes"] = (
                steady_total - compacted_total
            )
            evidence["leveldb"]["forced_compaction_reclaim_ratio"] = (
                (steady_total - compacted_total) / steady_total
            )
            compact_path = self.write_json(
                temporary / "compaction.json", evidence
            )
            with self.assertRaisesRegex(
                    RuntimeError, "requires authenticated compaction"):
                verifier.verify_synthetic(
                    repo, contract_path, compact_path, binary, target_sha
                )

    def test_endpoint_snapshots_cannot_exceed_sampled_peaks(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, target_sha, contract_path, hashes = self.make_repo(temporary)
            binary = self.make_executable(temporary / "fixture")
            evidence = self.make_synthetic_evidence(
                target_sha, contract_path, hashes, binary
            )
            phases = evidence["phases"]
            samples = [
                phases[name] for name in phases if name != "clean_startups"
            ] + phases["clean_startups"]
            for phase in samples:
                phase["peak_database_bytes"] = 1
                phase["peak_sst_bytes"] = 0
                phase["peak_wal_bytes"] = 0
                phase["peak_manifest_bytes"] = 0
                phase["peak_other_bytes"] = 0
            evidence["leveldb"]["maximum_observed_bytes"] = 1
            logical = self.contract["synthetic_fixture"][
                "retained_logical_batch_payload_bytes"
            ]
            evidence["leveldb"][
                "maximum_observed_physical_to_logical_ratio"
            ] = 1 / logical
            path = self.write_json(temporary / "underreported.json", evidence)
            with self.assertRaisesRegex(RuntimeError, "below an endpoint"):
                verifier.verify_synthetic(
                    repo, contract_path, path, binary, target_sha
                )

    def test_release_verifier_rejects_stale_live_evidence(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            repo, target_sha, contract_path, hashes = self.make_repo(temporary)
            blackcoind = self.make_executable(temporary / "blackcoind")
            blackcoin_cli = self.make_executable(temporary / "blackcoin-cli")
            evidence = self.make_live_evidence(
                target_sha, contract_path, hashes, blackcoind, blackcoin_cli
            )
            evidence["fixture"]["captured_at_unix"] = 1
            manifest_path, manifest_sha = self.write_live_manifest(
                temporary / "stale-manifest.json", evidence, contract_path
            )
            path = self.write_json(temporary / "stale-live.json", evidence)
            with self.assertRaisesRegex(RuntimeError, "older"):
                verifier.verify_live(
                    repo, contract_path, path, manifest_path,
                    blackcoind, blackcoin_cli, target_sha, manifest_sha,
                )

    def test_live_manifest_age_is_enforced_at_capture(self):
        with tempfile.TemporaryDirectory() as temporary_raw:
            temporary = Path(temporary_raw)
            archive = temporary / "fixture.tar"
            with tarfile.open(archive, "w") as bundle:
                member = tarfile.TarInfo("datadir/blocks/placeholder")
                payload = b"fixture"
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))
            target_sha = "a" * 40
            contract_sha = sha256(CONTRACT_PATH)
            manifest = {
                "schema": 2,
                "evidence_kind": "current_live_partial_epoch",
                "contract_sha256": contract_sha,
                "target_sha": target_sha,
                "network": "main",
                "archive_sha256": sha256(archive),
                "archive_size_bytes": archive.stat().st_size,
                "archive_root": "datadir",
                "captured_at_unix": int(time.time()),
                "capture_attestation":
                    "protected_operator_confirmed_connected_mainnet_tip",
                "capture_rpc": {
                    "chain": "main",
                    "blocks": 5_950_100,
                    "headers": 5_950_100,
                    "bestblockhash": "b" * 64,
                    "initialblockdownload": False,
                    "connections": 8,
                },
                "end_height": 5_950_100,
                "end_hash": "b" * 64,
                "pre_gold_rush_hash": "c" * 64,
                "first_gold_rush_hash": "d" * 64,
                "issued_claims": 100,
                "spent_claims": 10,
                "unspent_claims": 90,
            }
            live_runner.verify_fixture_manifest(
                manifest, self.contract, contract_sha, target_sha, archive
            )
            manifest["captured_at_unix"] -= (
                self.contract["live_partial_snapshot"][
                    "maximum_capture_age_seconds"
                ] + 1
            )
            with self.assertRaisesRegex(RuntimeError, "older"):
                live_runner.verify_fixture_manifest(
                    manifest, self.contract, contract_sha,
                    target_sha, archive,
                )


if __name__ == "__main__":
    unittest.main()
