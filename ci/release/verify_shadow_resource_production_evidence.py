#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify paired scoped synthetic and current-live shadow resource evidence."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys
import time

from generate_resource_benchmark_evidence import verify_epoch_source_contract


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BLOCK_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
CONTRACT_ID = "blackcoin.qq.shadow.synthetic-full-epoch.leveldb.v3"
REQUIRED_SOURCE_FILES = {
    ".github/actionlint.yaml",
    ".github/workflows/build.yml",
    ".github/workflows/pr-gate.yml",
    ".github/workflows/shadow-resource-production.yml",
    "src/bench/quantum_crypto.cpp",
    "src/coins.cpp",
    "src/coins.h",
    "src/compressor.cpp",
    "src/compressor.h",
    "src/consensus/amount.h",
    "src/consensus/consensus.h",
    "src/consensus/demurrage.cpp",
    "src/consensus/demurrage.h",
    "src/consensus/quantum_witness.h",
    "src/dbwrapper.cpp",
    "src/dbwrapper.h",
    "src/kernel/chainparams.cpp",
    "src/node/caches.cpp",
    "src/script/script.h",
    "src/serialize.h",
    "src/shadow.cpp",
    "src/shadow.h",
    "src/txdb.cpp",
    "src/txdb.h",
    "src/validation.cpp",
    "src/rpc/blockchain.cpp",
    "src/rpc/shadow.cpp",
    "src/test/coins_tests.cpp",
    "src/test/demurrage_tests.cpp",
    "src/test/quantum_pool_tests.cpp",
    "src/test/shadow_tests.cpp",
    "test/functional/feature_goldrush_coinstatsindex.py",
    "ci/release/generate_resource_benchmark_evidence.py",
    "ci/release/shadow_resource_leveldb_fixture.cpp",
    "ci/release/run_shadow_resource_synthetic_gate.py",
    "ci/release/run_shadow_resource_production_gate.py",
    "ci/release/test_shadow_resource_production.py",
    "ci/release/verify_shadow_resource_production_evidence.py",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(16 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def require_keys(value: dict, expected: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != expected:
        actual = set(value) if isinstance(value, dict) else set()
        raise RuntimeError(
            f"{label} fields differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def integer(value, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise RuntimeError(f"{label} must be an integer >= {minimum}")
    return value


def finite(value, label: str, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result <= 0):
        raise RuntimeError(f"{label} must be finite and {'positive' if positive else 'nonnegative'}")
    return result


def printable(value, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise RuntimeError(f"{label} must be non-empty printable text")
    return value


MEASUREMENT_ENVIRONMENT_KEYS = {
    "schema", "system", "machine", "kernel_release", "cpu_model",
    "logical_cpu_count", "memory_bytes", "page_size_bytes",
    "filesystem_type", "filesystem_source", "mount_options",
    "device_major", "device_minor", "rotational", "compiler",
    "python_version", "page_cache_policy",
}


def _mount_field(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def collect_measurement_environment(repo: Path, work: Path) -> dict:
    target = work.resolve()
    mount = None
    for line in Path("/proc/self/mountinfo").read_text(
            encoding="utf-8").splitlines():
        before, separator, after = line.partition(" - ")
        fields = before.split()
        trailing = after.split()
        if not separator or len(fields) < 6 or len(trailing) < 2:
            continue
        mountpoint = Path(_mount_field(fields[4]))
        try:
            target.relative_to(mountpoint)
        except ValueError:
            continue
        if mount is None or len(mountpoint.parts) > len(mount[0].parts):
            mount = (
                mountpoint, trailing[0], _mount_field(trailing[1]), fields[5]
            )
    if mount is None:
        raise RuntimeError("measurement filesystem mount is unavailable")
    memory_bytes = 0
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemTotal:"):
            _, raw, unit = line.split()
            if unit != "kB":
                raise RuntimeError("unexpected measurement memory unit")
            memory_bytes = int(raw) * 1024
            break
    if memory_bytes <= 0:
        raise RuntimeError("measurement host memory is unavailable")
    cpu_model = "unknown"
    for line in Path("/proc/cpuinfo").read_text(
            encoding="utf-8", errors="replace").splitlines():
        if line.startswith(("model name", "Hardware", "Processor")):
            _, _, value = line.partition(":")
            if value.strip():
                cpu_model = value.strip()
                break
    compiler_command = "c++"
    makefile = repo / "src/Makefile"
    if makefile.is_file():
        for line in makefile.read_text(
                encoding="utf-8", errors="replace").splitlines():
            if line.startswith("CXX = "):
                parsed = shlex.split(line[len("CXX = "):])
                if parsed:
                    compiler_command = parsed[0]
                break
    compiler_result = subprocess.run(
        [compiler_command, "--version"], capture_output=True, text=True,
        check=False,
    )
    compiler = (compiler_result.stdout or compiler_result.stderr).splitlines()
    if compiler_result.returncode or not compiler:
        raise RuntimeError("measurement compiler identity is unavailable")
    device = target.stat().st_dev
    major = os.major(device)
    minor = os.minor(device)
    rotational_path = Path(f"/sys/dev/block/{major}:{minor}/queue/rotational")
    rotational = None
    if rotational_path.is_file():
        raw = rotational_path.read_text(encoding="ascii").strip()
        if raw not in {"0", "1"}:
            raise RuntimeError("measurement storage rotational flag is invalid")
        rotational = raw == "1"
    return {
        "schema": 1,
        "system": platform.system(),
        "machine": platform.machine(),
        "kernel_release": platform.release(),
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "memory_bytes": memory_bytes,
        "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
        "filesystem_type": mount[1],
        "filesystem_source": mount[2],
        "mount_options": mount[3],
        "device_major": major,
        "device_minor": minor,
        "rotational": rotational,
        "compiler": compiler[0],
        "python_version": platform.python_version(),
        "page_cache_policy": "os-managed-observed-no-eviction",
    }


def verify_measurement_environment(value: dict, label: str) -> None:
    require_keys(value, MEASUREMENT_ENVIRONMENT_KEYS, label)
    if value["schema"] != 1 or value["system"] != "Linux" or value[
        "machine"
    ] != "x86_64":
        raise RuntimeError(f"{label} is not the required Linux x86-64 host")
    for key in (
        "kernel_release", "cpu_model", "filesystem_type",
        "filesystem_source", "mount_options", "compiler", "python_version",
    ):
        printable(value[key], f"{label}.{key}")
    for key in (
        "logical_cpu_count", "memory_bytes", "page_size_bytes",
    ):
        integer(value[key], f"{label}.{key}", 1)
    for key in ("device_major", "device_minor"):
        integer(value[key], f"{label}.{key}")
    if value["rotational"] is not None and not isinstance(
            value["rotational"], bool):
        raise RuntimeError(f"{label}.rotational must be boolean or null")
    if value["page_cache_policy"] != "os-managed-observed-no-eviction":
        raise RuntimeError(f"{label} page-cache policy differs")


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def normalize_repository_url(value: str) -> str:
    value = value.strip().removesuffix(".git").removesuffix("/")
    for prefix in ("https://github.com/", "ssh://git@github.com/", "git@github.com:"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value


PINNED_SYNTHETIC = {
    "schema": 1,
    "contract_id": CONTRACT_ID,
    "reward_start_height": 5_950_000,
    "competing_claims_activation_height": 5_993_200,
    "reward_end_height": 6_192_999,
    "gold_rush_blocks": 243_000,
    "authenticated_whitelist_entries": 687,
    "issued_claims": 179_771_400,
    "claim_family_records": 539_314_200,
    "logical_proof_bucket_records": 199_800,
    "total_records": 541_701_000,
    "retained_logical_batch_payload_bytes": 103_622_484_600,
    "authentication_sequential_records": 1_083_402_000,
    "payout_point_lookups": 179_771_400,
    "attestation_point_lookups": 179_771_400,
    "logical_proof_bucket_point_lookups": 12_785_184,
    "authentication_point_lookups": 372_327_984,
    "leveldb_cache_bytes": 4_194_304,
    "leveldb_write_buffer_bytes": 2_097_152,
}

PINNED_MEASUREMENT = {
    "database": "leveldb",
    "sample_interval_seconds": 5,
    "clean_startup_runs": 3,
    "validation_threads": 2,
    "dbcache_mib": 512,
    "require_full_synthetic_apply": True,
    "require_full_synthetic_scan": True,
    "require_full_synthetic_authentication": True,
    "require_full_synthetic_undo": True,
    "require_full_synthetic_reapply": True,
    "require_forced_compaction_comparison": True,
    "require_clean_close_between_phases": True,
}

PINNED_BUDGETS = {
    "maximum_steady_physical_to_logical_ratio": 2.0,
    "maximum_observed_physical_to_logical_ratio": 3.0,
    "maximum_obsolete_file_to_logical_ratio": 0.1,
    "compaction_required_reclaim_ratio": 0.1,
    "maximum_wal_bytes": 4_294_967_296,
    "maximum_peak_rss_bytes": 17_179_869_184,
    "maximum_sampler_sweep_seconds": 1,
    "maximum_sampler_gap_seconds": 7,
    "maximum_clean_startup_seconds": 600,
    "maximum_full_apply_seconds": 345_600,
    "maximum_full_scan_seconds": 86_400,
    "maximum_full_authentication_seconds": 86_400,
    "maximum_full_undo_seconds": 345_600,
    "maximum_full_reapply_seconds": 345_600,
    "maximum_forced_compaction_seconds": 345_600,
    "maximum_live_replay_seconds": 345_600,
    "maximum_live_lifecycle_scan_seconds": 86_400,
}

PINNED_QUALIFICATION_SCOPE = {
    "synthetic": (
        "Isolated incremental Gold Rush shadow-family LevelDB layout and "
        "I/O-shaped fixture operations, including one maximum-size 64-ID "
        "QQPROOFS bucket for every post-5,993,200 height. It excludes "
        "pre-existing and ordinary base UTXOs, ordinary or migration quantum "
        "outputs, production Coin and marker decoding/classification CPU, and "
        "terminal combined-chainstate effects."
    ),
    "live": (
        "Current captured partial-mainnet combined chainstate using production "
        "blackcoind and getcirculatingsupply at the protected "
        "operator-attested tip. It does not project the terminal Gold Rush "
        "height."
    ),
    "unproved": (
        "Terminal combined-chainstate physical amplification and "
        "full-cardinality production getcirculatingsupply wall time remain "
        "unproved until terminal-live evidence or a separately reviewed "
        "conservative background model exists."
    ),
}

PINNED_PRODUCTION_RELEASE_AUTHORIZATION = {
    "scoped_pair_sufficient": False,
    "remaining_gate": (
        "Final production publication requires terminal-live "
        "combined-chainstate and full-cardinality production "
        "getcirculatingsupply qualification, or a separately reviewed "
        "conservative equivalent."
    ),
}

PINNED_RETENTION = {
    "authenticated_compaction_implemented": False,
    "rule": (
        "Compaction is required when exact synthetic steady or "
        "maximum-observed physical amplification, obsolete-file retention, "
        "or measured forced-compaction reclaim crosses its pinned budget. "
        "Periodic sampling is not asserted as an unseen transient upper "
        "bound. The release gate fails when compaction is required but no "
        "separately authenticated compaction protocol is implemented."
    ),
}


def verify_contract(contract: dict) -> None:
    require_keys(
        contract,
        {"schema", "contract_id", "repository", "qualification_scope",
         "production_release_authorization",
         "synthetic_fixture",
         "live_partial_snapshot", "measurement", "budgets", "retention",
         "source_files"},
        "contract",
    )
    if contract["schema"] != 2 or contract["contract_id"] != CONTRACT_ID:
        raise RuntimeError("unsupported production resource contract")
    if contract["repository"] != "Blackcoin-Dev/Blackcoin":
        raise RuntimeError("production resource repository changed")
    if contract["qualification_scope"] != PINNED_QUALIFICATION_SCOPE:
        raise RuntimeError("production resource qualification scope changed")
    if contract["production_release_authorization"] != (
            PINNED_PRODUCTION_RELEASE_AUTHORIZATION):
        raise RuntimeError("production release authorization changed")
    if contract["synthetic_fixture"] != PINNED_SYNTHETIC:
        raise RuntimeError("synthetic full-epoch contract changed without schema review")
    live = contract["live_partial_snapshot"]
    require_keys(
        live,
        {"network", "minimum_height", "maximum_height",
         "require_protected_operator_tip_attestation",
         "require_full_chainstate_replay", "require_authenticated_lifecycle_scan",
         "require_positive_issued_claim_count",
         "completed_epoch_equivalence_required_when_available",
         "maximum_capture_age_seconds", "scope"},
        "contract.live_partial_snapshot",
    )
    if {key: live[key] for key in live if key != "scope"} != {
        "network": "main",
        "minimum_height": 5_950_000,
        "maximum_height": 6_192_999,
        "require_protected_operator_tip_attestation": True,
        "require_full_chainstate_replay": True,
        "require_authenticated_lifecycle_scan": True,
        "require_positive_issued_claim_count": True,
        "completed_epoch_equivalence_required_when_available": True,
        "maximum_capture_age_seconds": 604_800,
    }:
        raise RuntimeError("live partial-epoch contract changed without schema review")
    printable(live["scope"], "contract.live_partial_snapshot.scope")
    if contract["measurement"] != PINNED_MEASUREMENT:
        raise RuntimeError("measurement contract changed without schema review")
    if contract["budgets"] != PINNED_BUDGETS:
        raise RuntimeError("resource budgets changed without schema review")
    retention = contract["retention"]
    require_keys(retention, {"authenticated_compaction_implemented", "rule"}, "contract.retention")
    if retention != PINNED_RETENTION:
        raise RuntimeError("retention policy changed without schema review")
    source_files = contract["source_files"]
    if not isinstance(source_files, list) or len(source_files) != len(set(source_files)):
        raise RuntimeError("contract source_files must be a unique list")
    if set(source_files) != REQUIRED_SOURCE_FILES:
        raise RuntimeError("resource evidence source-file coverage changed")
    for relative in source_files:
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise RuntimeError(f"unsafe source path: {relative}")


def verify_repository(repo: Path, target_sha: str, contract: dict) -> None:
    if not GIT_SHA_RE.fullmatch(target_sha):
        raise RuntimeError("target SHA must be full lowercase hexadecimal")
    if git_output(repo, "rev-parse", "HEAD") != target_sha:
        raise RuntimeError("checked-out HEAD differs from target SHA")
    if normalize_repository_url(git_output(repo, "remote", "get-url", "origin")) != contract["repository"]:
        raise RuntimeError("checked-out origin differs from the contract")
    if git_output(repo, "status", "--porcelain"):
        raise RuntimeError("resource evidence verification requires a clean tree")


def verify_sources(repo: Path, evidence: dict, contract: dict) -> None:
    epoch_sources = verify_epoch_source_contract(repo)
    hashes = evidence.get("source_files")
    if not isinstance(hashes, dict) or set(hashes) != set(contract["source_files"]):
        raise RuntimeError("evidence source coverage differs from the contract")
    for relative in contract["source_files"]:
        path = repo / relative
        if not path.is_file() or hashes[relative] != sha256_file(path):
            raise RuntimeError(f"evidence source hash differs for {relative}")
    if not set(epoch_sources).issubset(hashes):
        raise RuntimeError("epoch source contract is not fully evidence-bound")


SNAPSHOT_KEYS = {
    "total_bytes", "sst_bytes", "wal_bytes", "manifest_bytes",
    "other_bytes", "file_count",
}


def verify_snapshot(value: dict, label: str) -> None:
    require_keys(value, SNAPSHOT_KEYS, label)
    for key in SNAPSHOT_KEYS:
        integer(value[key], f"{label}.{key}")
    if value["total_bytes"] != sum(
        value[key] for key in ("sst_bytes", "wal_bytes", "manifest_bytes", "other_bytes")
    ):
        raise RuntimeError(f"{label} byte categories do not sum")
    if value["total_bytes"] == 0 or value["file_count"] == 0:
        raise RuntimeError(f"{label} is empty")


SYNTHETIC_PHASE_KEYS = {
    "wall_seconds", "peak_rss_bytes", "peak_database_bytes",
    "peak_sst_bytes", "peak_wal_bytes", "peak_manifest_bytes",
    "peak_other_bytes", "sample_count", "maximum_sample_seconds",
    "maximum_sample_gap_seconds",
}


def verify_synthetic_phase(value: dict, label: str) -> None:
    require_keys(value, SYNTHETIC_PHASE_KEYS, label)
    finite(value["wall_seconds"], f"{label}.wall_seconds", positive=True)
    for key in SYNTHETIC_PHASE_KEYS - {
        "wall_seconds", "maximum_sample_seconds",
        "maximum_sample_gap_seconds",
    }:
        integer(value[key], f"{label}.{key}")
    integer(value["sample_count"], f"{label}.sample_count", 2)
    finite(
        value["maximum_sample_seconds"],
        f"{label}.maximum_sample_seconds", positive=True,
    )
    finite(
        value["maximum_sample_gap_seconds"],
        f"{label}.maximum_sample_gap_seconds",
    )
    integer(value["peak_rss_bytes"], f"{label}.peak_rss_bytes", 1)
    database_peak = integer(
        value["peak_database_bytes"], f"{label}.peak_database_bytes", 1
    )
    for key in (
        "peak_sst_bytes", "peak_wal_bytes", "peak_manifest_bytes",
        "peak_other_bytes",
    ):
        if value[key] > database_peak:
            raise RuntimeError(f"{label}.{key} exceeds the database peak")


def verify_binary(value: dict, path: Path, label: str) -> None:
    require_keys(value, {"sha256", "size_bytes"}, label)
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"{label} executable is missing")
    if value["sha256"] != sha256_file(path):
        raise RuntimeError(f"{label} digest differs")
    if integer(value["size_bytes"], f"{label}.size_bytes", 1) != path.stat().st_size:
        raise RuntimeError(f"{label} size differs")


LIVE_MANIFEST_KEYS = {
    "schema", "evidence_kind", "contract_sha256", "target_sha",
    "network", "archive_sha256", "archive_size_bytes", "archive_root",
    "captured_at_unix", "capture_attestation", "capture_rpc",
    "end_height", "end_hash", "pre_gold_rush_hash",
    "first_gold_rush_hash", "issued_claims", "spent_claims",
    "unspent_claims",
}


def verify_live_manifest(path: Path, contract: dict, contract_sha: str,
                         target_sha: str, expected_sha: str) -> tuple[dict, str]:
    if not SHA256_RE.fullmatch(expected_sha):
        raise RuntimeError("live manifest SHA256 is invalid")
    actual_sha = sha256_file(path)
    if actual_sha != expected_sha:
        raise RuntimeError("live manifest digest differs")
    manifest = load_json(path, "live fixture manifest")
    require_keys(manifest, LIVE_MANIFEST_KEYS, "live fixture manifest")
    live = contract["live_partial_snapshot"]
    if (
        manifest["schema"] != 2
        or manifest["evidence_kind"] != "current_live_partial_epoch"
        or manifest["contract_sha256"] != contract_sha
        or manifest["target_sha"] != target_sha
        or manifest["network"] != live["network"]
    ):
        raise RuntimeError("live fixture manifest identity differs")
    captured_at = integer(
        manifest["captured_at_unix"], "live manifest capture time", 1
    )
    capture_age = int(time.time()) - captured_at
    if capture_age < -300:
        raise RuntimeError("live fixture manifest capture time is in the future")
    if capture_age > live["maximum_capture_age_seconds"]:
        raise RuntimeError("live fixture manifest is older than the contracted window")
    height = integer(manifest["end_height"], "live manifest height")
    if not live["minimum_height"] <= height <= live["maximum_height"]:
        raise RuntimeError("live fixture manifest height is outside the contract")
    for key in ("end_hash", "pre_gold_rush_hash", "first_gold_rush_hash"):
        if (
            not isinstance(manifest[key], str)
            or not BLOCK_HASH_RE.fullmatch(manifest[key])
        ):
            raise RuntimeError(f"live fixture manifest {key} is invalid")
    if manifest["capture_attestation"] != (
        "protected_operator_confirmed_connected_mainnet_tip"
    ):
        raise RuntimeError("live fixture manifest lacks the protected attestation")
    capture_rpc = manifest["capture_rpc"]
    require_keys(
        capture_rpc,
        {"chain", "blocks", "headers", "bestblockhash",
         "initialblockdownload", "connections"},
        "live fixture manifest capture RPC",
    )
    if (
        capture_rpc["chain"] != "main"
        or capture_rpc["blocks"] != height
        or capture_rpc["headers"] != height
        or capture_rpc["bestblockhash"] != manifest["end_hash"]
        or capture_rpc["initialblockdownload"] is not False
        or integer(
            capture_rpc["connections"],
            "live fixture manifest capture RPC connections", 1,
        ) < 1
    ):
        raise RuntimeError("live fixture manifest capture RPC differs")
    if not SHA256_RE.fullmatch(str(manifest["archive_sha256"])):
        raise RuntimeError("live fixture manifest archive digest is invalid")
    integer(manifest["archive_size_bytes"], "live manifest archive size", 1)
    archive_root = manifest["archive_root"]
    if not isinstance(archive_root, str) or not archive_root:
        raise RuntimeError("live fixture manifest archive root is invalid")
    root = Path(archive_root)
    if root.is_absolute() or ".." in root.parts or len(root.parts) != 1:
        raise RuntimeError("live fixture manifest archive root is unsafe")
    issued = integer(manifest["issued_claims"], "live manifest issued claims", 1)
    spent = integer(manifest["spent_claims"], "live manifest spent claims")
    unspent = integer(manifest["unspent_claims"], "live manifest unspent claims")
    if spent > issued or unspent != issued - spent:
        raise RuntimeError("live fixture manifest claim inventory differs")
    return manifest, actual_sha


def _verify_fixture_scan(value: dict, label: str) -> None:
    require_keys(
        value,
        {"schema", "contract_id", "phase", "height", "records", "claims",
         "payouts", "provenance", "logical_proof_buckets",
         "logical_bytes"},
        label,
    )
    if value != {
        "schema": 1,
        "contract_id": CONTRACT_ID,
        "phase": value["phase"],
        "height": 6_192_999,
        "records": 541_701_000,
        "claims": 179_771_400,
        "payouts": 179_771_400,
        "provenance": 179_771_400,
        "logical_proof_buckets": 199_800,
        "logical_bytes": 103_622_484_600,
    } or value["phase"] not in {"applied", "reapplied"}:
        raise RuntimeError(f"{label} is not the exact completed synthetic envelope")


def recompute_decision(evidence: dict, contract: dict) -> tuple[bool, list[str], list[str]]:
    budgets = contract["budgets"]
    leveldb = evidence["leveldb"]
    phases = evidence["phases"]
    reasons = []
    if leveldb["steady_physical_to_logical_ratio"] > budgets["maximum_steady_physical_to_logical_ratio"]:
        reasons.append("steady-physical-amplification")
    if leveldb["maximum_observed_physical_to_logical_ratio"] > budgets["maximum_observed_physical_to_logical_ratio"]:
        reasons.append("observed-physical-amplification")
    if leveldb["obsolete_file_to_logical_ratio"] > budgets["maximum_obsolete_file_to_logical_ratio"]:
        reasons.append("obsolete-file-retention")
    if leveldb["forced_compaction_reclaim_ratio"] >= budgets["compaction_required_reclaim_ratio"]:
        reasons.append("forced-compaction-material-reclaim")

    all_phases = [
        phases["full_apply"], phases["full_scan"],
        phases["full_authentication"], phases["full_undo"],
        phases["undo_scan"], phases["full_reapply"], phases["reapply_scan"],
        phases["forced_compaction"], phases["compaction_scan"],
        *phases["clean_startups"],
    ]
    failed = []
    if max(item["peak_wal_bytes"] for item in all_phases) > budgets["maximum_wal_bytes"]:
        failed.append("peak-wal-bytes")
    if evidence["maximum_peak_rss_bytes"] > budgets["maximum_peak_rss_bytes"]:
        failed.append("peak-rss-bytes")
    if max(item["maximum_sample_seconds"] for item in all_phases) > budgets[
        "maximum_sampler_sweep_seconds"
    ]:
        failed.append("sampler-sweep-time")
    if max(item["maximum_sample_gap_seconds"] for item in all_phases) > budgets[
        "maximum_sampler_gap_seconds"
    ]:
        failed.append("sampler-gap-time")
    for phase_name, budget_name in (
        ("full_apply", "maximum_full_apply_seconds"),
        ("full_scan", "maximum_full_scan_seconds"),
        ("full_authentication", "maximum_full_authentication_seconds"),
        ("full_undo", "maximum_full_undo_seconds"),
        ("undo_scan", "maximum_full_scan_seconds"),
        ("full_reapply", "maximum_full_reapply_seconds"),
        ("reapply_scan", "maximum_full_scan_seconds"),
        ("forced_compaction", "maximum_forced_compaction_seconds"),
        ("compaction_scan", "maximum_full_scan_seconds"),
    ):
        if phases[phase_name]["wall_seconds"] > budgets[budget_name]:
            failed.append(f"{phase_name}-wall-time")
    if max(item["wall_seconds"] for item in phases["clean_startups"]) > budgets["maximum_clean_startup_seconds"]:
        failed.append("clean-startup-wall-time")
    failed.extend(reasons)
    return bool(reasons), reasons, failed


def verify_synthetic(repo: Path, contract_path: Path, evidence_path: Path,
                     fixture_binary: Path, target_sha: str) -> dict:
    contract = load_json(contract_path, "production resource contract")
    verify_contract(contract)
    verify_repository(repo, target_sha, contract)
    evidence = load_json(evidence_path, "synthetic resource evidence")
    require_keys(
        evidence,
        {"schema", "status", "evidence_kind", "not_live_chain_evidence",
         "repository", "target_sha", "tree_clean", "contract_sha256",
         "measurement_environment", "qualification_scope",
         "source_files", "fixture_binary", "fixture", "post_reapply_fixture",
         "post_compaction_fixture", "authentication", "phases", "leveldb",
         "maximum_peak_rss_bytes"},
        "synthetic evidence",
    )
    if (evidence["schema"], evidence["status"], evidence["evidence_kind"],
            evidence["not_live_chain_evidence"]) != (
                2, "complete", "deterministic_synthetic_full_epoch", True):
        raise RuntimeError("synthetic evidence identity or status differs")
    if evidence["repository"] != contract["repository"] or evidence["target_sha"] != target_sha or evidence["tree_clean"] is not True:
        raise RuntimeError("synthetic evidence is not bound to the clean target")
    if evidence["contract_sha256"] != sha256_file(contract_path):
        raise RuntimeError("synthetic evidence contract digest differs")
    if evidence["qualification_scope"] != contract["qualification_scope"]:
        raise RuntimeError("synthetic evidence qualification scope differs")
    verify_measurement_environment(
        evidence["measurement_environment"], "synthetic measurement environment"
    )
    verify_sources(repo, evidence, contract)
    verify_binary(evidence["fixture_binary"], fixture_binary, "fixture_binary")
    _verify_fixture_scan(evidence["fixture"], "fixture")
    _verify_fixture_scan(evidence["post_reapply_fixture"], "post_reapply_fixture")
    _verify_fixture_scan(evidence["post_compaction_fixture"], "post_compaction_fixture")
    if evidence["fixture"]["phase"] != "applied" or evidence["post_reapply_fixture"]["phase"] != "reapplied" or evidence["post_compaction_fixture"]["phase"] != "reapplied":
        raise RuntimeError("synthetic fixture phase sequence differs")
    expected_authentication = {
        "schema": 1,
        "contract_id": CONTRACT_ID,
        "phase": "applied",
        "height": PINNED_SYNTHETIC["reward_end_height"],
        "sequential_records": PINNED_SYNTHETIC[
            "authentication_sequential_records"
        ],
        "provenance_records": PINNED_SYNTHETIC["issued_claims"],
        "payout_candidates": PINNED_SYNTHETIC["issued_claims"],
        "payout_authenticated": PINNED_SYNTHETIC["issued_claims"],
        "attestation_candidates": PINNED_SYNTHETIC["issued_claims"],
        "attestation_lookup_hits": PINNED_SYNTHETIC["issued_claims"],
        "logical_proof_bucket_lookups": PINNED_SYNTHETIC[
            "logical_proof_bucket_point_lookups"
        ],
        "point_lookups": PINNED_SYNTHETIC["authentication_point_lookups"],
    }
    if evidence["authentication"] != expected_authentication:
        raise RuntimeError(
            "synthetic authentication differs from the exact terminal "
            "point-lookup envelope"
        )

    phases = evidence["phases"]
    require_keys(
        phases,
        {"full_apply", "full_scan", "full_authentication",
         "clean_startups", "full_undo",
         "undo_scan", "full_reapply", "reapply_scan", "forced_compaction",
         "compaction_scan"},
        "synthetic phases",
    )
    if not isinstance(phases["clean_startups"], list) or len(phases["clean_startups"]) != 3:
        raise RuntimeError("synthetic evidence lacks three clean startups")
    for name in phases:
        if name == "clean_startups":
            for index, phase in enumerate(phases[name]):
                verify_synthetic_phase(phase, f"clean_startups[{index}]")
        else:
            verify_synthetic_phase(phases[name], f"phases.{name}")

    leveldb = evidence["leveldb"]
    require_keys(
        leveldb,
        {"steady_snapshot", "compacted_snapshot", "maximum_observed_bytes",
         "obsolete_file_bytes", "post_apply_cleanup_obsolete_bytes",
         "post_reapply_cleanup_obsolete_bytes",
         "forced_compaction_reclaimed_bytes",
         "steady_physical_to_logical_ratio",
         "maximum_observed_physical_to_logical_ratio",
         "obsolete_file_to_logical_ratio", "forced_compaction_reclaim_ratio"},
        "synthetic leveldb",
    )
    verify_snapshot(leveldb["steady_snapshot"], "steady_snapshot")
    verify_snapshot(leveldb["compacted_snapshot"], "compacted_snapshot")
    logical = PINNED_SYNTHETIC["retained_logical_batch_payload_bytes"]
    transient = integer(leveldb["maximum_observed_bytes"], "maximum_observed_bytes")
    obsolete = integer(leveldb["obsolete_file_bytes"], "obsolete_file_bytes")
    post_apply_obsolete = integer(
        leveldb["post_apply_cleanup_obsolete_bytes"],
        "post_apply_cleanup_obsolete_bytes",
    )
    post_reapply_obsolete = integer(
        leveldb["post_reapply_cleanup_obsolete_bytes"],
        "post_reapply_cleanup_obsolete_bytes",
    )
    if obsolete != max(post_apply_obsolete, post_reapply_obsolete):
        raise RuntimeError("synthetic obsolete-file summary differs")
    reclaimed = integer(leveldb["forced_compaction_reclaimed_bytes"], "reclaimed_bytes")
    expected_reclaimed = max(
        0,
        (
            leveldb["steady_snapshot"]["total_bytes"]
            - leveldb["compacted_snapshot"]["total_bytes"]
        ),
    )
    if reclaimed != expected_reclaimed:
        raise RuntimeError("synthetic reclaimed-byte calculation differs")
    observed_transient = max(
        item["peak_database_bytes"] for item in [
            phases["full_apply"], phases["full_scan"],
            phases["full_authentication"], phases["full_undo"],
            phases["undo_scan"], phases["full_reapply"],
            phases["reapply_scan"],
            phases["forced_compaction"], phases["compaction_scan"],
            *phases["clean_startups"],
        ]
    )
    if transient != observed_transient:
        raise RuntimeError("synthetic maximum-observed-byte summary differs")
    endpoint_snapshots = [
        leveldb["steady_snapshot"], leveldb["compacted_snapshot"],
    ]
    if transient < max(item["total_bytes"] for item in endpoint_snapshots):
        raise RuntimeError("synthetic maximum-observed bytes are below an endpoint")
    all_phases = [
        phases["full_apply"], phases["full_scan"],
        phases["full_authentication"], phases["full_undo"],
        phases["undo_scan"], phases["full_reapply"], phases["reapply_scan"],
        phases["forced_compaction"], phases["compaction_scan"],
        *phases["clean_startups"],
    ]
    for endpoint_key, peak_key in (
        ("sst_bytes", "peak_sst_bytes"),
        ("wal_bytes", "peak_wal_bytes"),
        ("manifest_bytes", "peak_manifest_bytes"),
        ("other_bytes", "peak_other_bytes"),
    ):
        if max(item[peak_key] for item in all_phases) < max(
            item[endpoint_key] for item in endpoint_snapshots
        ):
            raise RuntimeError(
                f"synthetic sampled {endpoint_key} is below an endpoint"
            )
    if max(item["wal_bytes"] for item in endpoint_snapshots) > contract[
        "budgets"
    ]["maximum_wal_bytes"]:
        raise RuntimeError("synthetic endpoint WAL exceeded its budget")
    expected_ratios = {
        "steady_physical_to_logical_ratio": leveldb["steady_snapshot"]["total_bytes"] / logical,
        "maximum_observed_physical_to_logical_ratio": transient / logical,
        "obsolete_file_to_logical_ratio": obsolete / logical,
        "forced_compaction_reclaim_ratio": reclaimed / leveldb["steady_snapshot"]["total_bytes"],
    }
    for key, expected in expected_ratios.items():
        actual = finite(leveldb[key], f"leveldb.{key}")
        if not math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-15):
            raise RuntimeError(f"synthetic {key} was not reproducibly calculated")
    peak_rss = integer(evidence["maximum_peak_rss_bytes"], "maximum_peak_rss_bytes")
    observed_peak = max(
        item["peak_rss_bytes"] for item in [
            phases["full_apply"], phases["full_scan"],
            phases["full_authentication"], phases["full_undo"],
            phases["undo_scan"], phases["full_reapply"],
            phases["reapply_scan"],
            phases["forced_compaction"], phases["compaction_scan"],
            *phases["clean_startups"],
        ]
    )
    if peak_rss != observed_peak:
        raise RuntimeError("synthetic peak RSS summary differs")
    required, reasons, failed = recompute_decision(evidence, contract)
    if required and not contract["retention"]["authenticated_compaction_implemented"]:
        raise RuntimeError(
            "synthetic evidence requires authenticated compaction, but none is implemented"
        )
    if failed:
        raise RuntimeError(f"synthetic resource budgets failed: {', '.join(failed)}")
    return {
        "compaction_required": required,
        "reasons": reasons,
        "measurement_environment": evidence["measurement_environment"],
    }


LIVE_PHASE_KEYS = {
    "wall_seconds", "peak_rss_bytes", "peak_chainstate_bytes",
    "peak_sst_bytes", "peak_wal_bytes", "peak_manifest_bytes",
    "peak_other_bytes", "completed_height", "completed_hash",
    "sample_count", "maximum_sample_seconds",
    "maximum_sample_gap_seconds",
}


def verify_live_phase(value: dict, label: str, height: int, block_hash: str) -> None:
    require_keys(value, LIVE_PHASE_KEYS, label)
    finite(value["wall_seconds"], f"{label}.wall_seconds", positive=True)
    for key in LIVE_PHASE_KEYS - {
        "wall_seconds", "completed_hash", "maximum_sample_seconds",
        "maximum_sample_gap_seconds",
    }:
        integer(value[key], f"{label}.{key}")
    integer(value["sample_count"], f"{label}.sample_count", 2)
    finite(
        value["maximum_sample_seconds"],
        f"{label}.maximum_sample_seconds", positive=True,
    )
    finite(
        value["maximum_sample_gap_seconds"],
        f"{label}.maximum_sample_gap_seconds",
    )
    integer(value["peak_rss_bytes"], f"{label}.peak_rss_bytes", 1)
    chainstate_peak = integer(
        value["peak_chainstate_bytes"],
        f"{label}.peak_chainstate_bytes",
        1,
    )
    for key in (
        "peak_sst_bytes", "peak_wal_bytes", "peak_manifest_bytes",
        "peak_other_bytes",
    ):
        if value[key] > chainstate_peak:
            raise RuntimeError(f"{label}.{key} exceeds the chainstate peak")
    if value["completed_height"] != height or value["completed_hash"] != block_hash:
        raise RuntimeError(f"{label} completed at a different live anchor")


def verify_live(repo: Path, contract_path: Path, evidence_path: Path,
                manifest_path: Path, blackcoind: Path,
                blackcoin_cli: Path, target_sha: str,
                manifest_sha: str) -> dict:
    contract = load_json(contract_path, "production resource contract")
    verify_contract(contract)
    verify_repository(repo, target_sha, contract)
    contract_sha = sha256_file(contract_path)
    manifest, manifest_sha = verify_live_manifest(
        manifest_path, contract, contract_sha, target_sha, manifest_sha
    )
    evidence = load_json(evidence_path, "live partial resource evidence")
    require_keys(
        evidence,
        {"schema", "status", "evidence_kind", "completed_epoch", "repository",
         "target_sha", "tree_clean", "contract_sha256", "source_files",
         "measurement_environment", "qualification_scope",
         "binaries", "fixture", "phases", "leveldb",
         "maximum_peak_rss_bytes"},
        "live evidence",
    )
    if (evidence["schema"], evidence["status"], evidence["evidence_kind"]) != (
            2, "complete", "current_live_partial_epoch"):
        raise RuntimeError("live evidence identity or status differs")
    if evidence["repository"] != contract["repository"] or evidence["target_sha"] != target_sha or evidence["tree_clean"] is not True:
        raise RuntimeError("live evidence is not bound to the clean target")
    if evidence["contract_sha256"] != contract_sha:
        raise RuntimeError("live evidence contract digest differs")
    if evidence["qualification_scope"] != contract["qualification_scope"]:
        raise RuntimeError("live evidence qualification scope differs")
    verify_measurement_environment(
        evidence["measurement_environment"], "live measurement environment"
    )
    verify_sources(repo, evidence, contract)
    binaries = evidence["binaries"]
    require_keys(binaries, {"blackcoind", "blackcoin_cli"}, "live binaries")
    verify_binary(binaries["blackcoind"], blackcoind, "blackcoind")
    verify_binary(binaries["blackcoin_cli"], blackcoin_cli, "blackcoin_cli")

    fixture = evidence["fixture"]
    require_keys(
        fixture,
        {"evidence_kind", "fixture_manifest_sha256", "archive_sha256",
         "archive_size_bytes", "network", "target_sha", "captured_at_unix",
         "capture_attestation", "capture_rpc",
         "end_height", "end_hash", "pre_gold_rush_hash",
         "first_gold_rush_hash", "issued_claims", "spent_claims",
         "unspent_claims"},
        "live fixture",
    )
    manifest_projection = {
        "evidence_kind": manifest["evidence_kind"],
        "fixture_manifest_sha256": manifest_sha,
        "archive_sha256": manifest["archive_sha256"],
        "archive_size_bytes": manifest["archive_size_bytes"],
        "network": manifest["network"],
        "target_sha": manifest["target_sha"],
        "captured_at_unix": manifest["captured_at_unix"],
        "capture_attestation": manifest["capture_attestation"],
        "capture_rpc": manifest["capture_rpc"],
        "end_height": manifest["end_height"],
        "end_hash": manifest["end_hash"],
        "pre_gold_rush_hash": manifest["pre_gold_rush_hash"],
        "first_gold_rush_hash": manifest["first_gold_rush_hash"],
        "issued_claims": manifest["issued_claims"],
        "spent_claims": manifest["spent_claims"],
        "unspent_claims": manifest["unspent_claims"],
    }
    if fixture != manifest_projection:
        raise RuntimeError("live evidence fixture differs from its manifest")
    if fixture["evidence_kind"] != "current_live_partial_epoch" or fixture["fixture_manifest_sha256"] != manifest_sha or fixture["network"] != "main" or fixture["target_sha"] != target_sha:
        raise RuntimeError("live fixture identity differs")
    if fixture["capture_attestation"] != (
        "protected_operator_confirmed_connected_mainnet_tip"
    ):
        raise RuntimeError("live fixture lacks the protected tip attestation")
    if not SHA256_RE.fullmatch(fixture["archive_sha256"]):
        raise RuntimeError("live fixture archive digest is invalid")
    live_contract = contract["live_partial_snapshot"]
    integer(fixture["archive_size_bytes"], "live fixture archive size", 1)
    captured_at = integer(
        fixture["captured_at_unix"], "live fixture capture time", 1
    )
    capture_age = int(time.time()) - captured_at
    if capture_age < -300:
        raise RuntimeError("live fixture capture time is in the future")
    if capture_age > live_contract["maximum_capture_age_seconds"]:
        raise RuntimeError("live fixture is older than the contracted window")
    height = integer(fixture["end_height"], "live fixture height")
    if not live_contract["minimum_height"] <= height <= live_contract["maximum_height"]:
        raise RuntimeError("live fixture height is outside the contracted interval")
    for key in ("end_hash", "pre_gold_rush_hash", "first_gold_rush_hash"):
        if not isinstance(fixture[key], str) or not BLOCK_HASH_RE.fullmatch(fixture[key]):
            raise RuntimeError(f"live fixture {key} is invalid")
    capture_rpc = fixture["capture_rpc"]
    require_keys(
        capture_rpc,
        {"chain", "blocks", "headers", "bestblockhash",
         "initialblockdownload", "connections"},
        "live fixture capture RPC",
    )
    if (
        capture_rpc["chain"] != "main"
        or capture_rpc["blocks"] != height
        or capture_rpc["headers"] != height
        or capture_rpc["bestblockhash"] != fixture["end_hash"]
        or capture_rpc["initialblockdownload"] is not False
        or integer(
            capture_rpc["connections"],
            "live fixture capture RPC connections",
            1,
        ) < 1
    ):
        raise RuntimeError("live fixture capture RPC does not match its tip")
    issued = integer(fixture["issued_claims"], "live issued claims", 1)
    spent = integer(fixture["spent_claims"], "live spent claims")
    unspent = integer(fixture["unspent_claims"], "live unspent claims")
    if spent > issued or unspent != issued - spent:
        raise RuntimeError("live claim inventory is inconsistent")
    if evidence["completed_epoch"] is not (height == live_contract["maximum_height"]):
        raise RuntimeError("live completed_epoch label differs from height")

    phases = evidence["phases"]
    require_keys(
        phases,
        {"live_full_replay", "live_lifecycle_scan", "clean_startups",
         "live_partial_epoch_undo", "live_partial_epoch_reapply",
         "live_reorg_cleanup", "forced_compaction"},
        "live phases",
    )
    startups = phases["clean_startups"]
    if not isinstance(startups, list) or len(startups) != 3:
        raise RuntimeError("live evidence lacks three clean startups")
    for name in ("live_full_replay", "live_lifecycle_scan",
                 "live_partial_epoch_reapply", "live_reorg_cleanup",
                 "forced_compaction"):
        verify_live_phase(phases[name], f"phases.{name}", height, fixture["end_hash"])
    for index, phase in enumerate(startups):
        verify_live_phase(phase, f"clean_startups[{index}]", height, fixture["end_hash"])
    verify_live_phase(
        phases["live_partial_epoch_undo"], "phases.live_partial_epoch_undo",
        PINNED_SYNTHETIC["reward_start_height"] - 1,
        fixture["pre_gold_rush_hash"],
    )
    leveldb = evidence["leveldb"]
    require_keys(
        leveldb,
        {"steady_snapshot", "compacted_snapshot", "maximum_observed_bytes",
         "observed_file_churn_bytes", "forced_compaction_reclaimed_bytes"},
        "live leveldb",
    )
    verify_snapshot(leveldb["steady_snapshot"], "live steady snapshot")
    verify_snapshot(leveldb["compacted_snapshot"], "live compacted snapshot")
    transient = integer(leveldb["maximum_observed_bytes"], "live maximum-observed bytes")
    integer(leveldb["observed_file_churn_bytes"], "live file churn bytes")
    reclaimed = integer(leveldb["forced_compaction_reclaimed_bytes"], "live reclaimed bytes")
    if reclaimed != max(0, leveldb["steady_snapshot"]["total_bytes"] - leveldb["compacted_snapshot"]["total_bytes"]):
        raise RuntimeError("live reclaimed-byte calculation differs")
    all_phases = [
        phases["live_full_replay"], phases["live_lifecycle_scan"],
        phases["live_partial_epoch_undo"], phases["live_partial_epoch_reapply"],
        phases["live_reorg_cleanup"], phases["forced_compaction"], *startups,
    ]
    if transient != max(item["peak_chainstate_bytes"] for item in all_phases):
        raise RuntimeError("live maximum-observed-byte summary differs")
    endpoint_snapshots = [
        leveldb["steady_snapshot"], leveldb["compacted_snapshot"],
    ]
    if transient < max(item["total_bytes"] for item in endpoint_snapshots):
        raise RuntimeError("live maximum-observed bytes are below an endpoint")
    for endpoint_key, peak_key in (
        ("sst_bytes", "peak_sst_bytes"),
        ("wal_bytes", "peak_wal_bytes"),
        ("manifest_bytes", "peak_manifest_bytes"),
        ("other_bytes", "peak_other_bytes"),
    ):
        if max(item[peak_key] for item in all_phases) < max(
            item[endpoint_key] for item in endpoint_snapshots
        ):
            raise RuntimeError(
                f"live sampled {endpoint_key} is below an endpoint"
            )
    peak_rss = integer(evidence["maximum_peak_rss_bytes"], "live peak RSS")
    if peak_rss != max(item["peak_rss_bytes"] for item in all_phases) or peak_rss > contract["budgets"]["maximum_peak_rss_bytes"]:
        raise RuntimeError("live peak RSS summary or budget differs")
    if phases["live_full_replay"]["wall_seconds"] > contract["budgets"]["maximum_live_replay_seconds"]:
        raise RuntimeError("live replay exceeded its budget")
    if phases["live_lifecycle_scan"]["wall_seconds"] > contract["budgets"]["maximum_live_lifecycle_scan_seconds"]:
        raise RuntimeError("live lifecycle scan exceeded its budget")
    if phases["live_partial_epoch_undo"]["wall_seconds"] > contract["budgets"]["maximum_full_undo_seconds"]:
        raise RuntimeError("live partial-epoch undo exceeded its budget")
    if phases["live_partial_epoch_reapply"]["wall_seconds"] > contract["budgets"]["maximum_full_reapply_seconds"]:
        raise RuntimeError("live partial-epoch reapply exceeded its budget")
    if phases["live_reorg_cleanup"]["wall_seconds"] > contract["budgets"]["maximum_clean_startup_seconds"]:
        raise RuntimeError("live reorg cleanup exceeded its budget")
    if phases["forced_compaction"]["wall_seconds"] > contract["budgets"]["maximum_forced_compaction_seconds"]:
        raise RuntimeError("live forced compaction exceeded its budget")
    if max(item["wall_seconds"] for item in startups) > contract["budgets"]["maximum_clean_startup_seconds"]:
        raise RuntimeError("live startup exceeded its budget")
    if max(item["maximum_sample_seconds"] for item in all_phases) > contract[
        "budgets"
    ]["maximum_sampler_sweep_seconds"]:
        raise RuntimeError("live sampler sweep exceeded its budget")
    if max(item["maximum_sample_gap_seconds"] for item in all_phases) > contract[
        "budgets"
    ]["maximum_sampler_gap_seconds"]:
        raise RuntimeError("live sampler gap exceeded its budget")
    if max(
        max(item["peak_wal_bytes"] for item in all_phases),
        max(item["wal_bytes"] for item in endpoint_snapshots),
    ) > contract["budgets"]["maximum_wal_bytes"]:
        raise RuntimeError("live WAL exceeded its budget")
    return evidence["measurement_environment"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--synthetic-evidence", type=Path, required=True)
    parser.add_argument("--synthetic-binary", type=Path, required=True)
    parser.add_argument("--live-evidence", type=Path, required=True)
    parser.add_argument("--live-manifest", type=Path, required=True)
    parser.add_argument("--live-manifest-sha256", required=True)
    parser.add_argument("--blackcoind", type=Path, required=True)
    parser.add_argument("--blackcoin-cli", type=Path, required=True)
    parser.add_argument("--target-sha", required=True)
    args = parser.parse_args()
    try:
        repo = args.repo_root.resolve()
        contract = args.contract.resolve()
        decision = verify_synthetic(
            repo, contract, args.synthetic_evidence.resolve(),
            args.synthetic_binary.resolve(), args.target_sha,
        )
        live_environment = verify_live(
            repo, contract, args.live_evidence.resolve(),
            args.live_manifest.resolve(), args.blackcoind.resolve(),
            args.blackcoin_cli.resolve(), args.target_sha,
            args.live_manifest_sha256,
        )
        if live_environment != decision["measurement_environment"]:
            raise RuntimeError(
                "paired evidence was measured on different host environments"
            )
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        "Scoped synthetic full-epoch and current live partial-epoch resource "
        f"evidence pass; compaction_required={decision['compaction_required']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
