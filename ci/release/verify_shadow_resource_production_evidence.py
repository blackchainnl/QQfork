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
    "doc/v30.1.1-release-gate.md",
    "doc/v30.1.1-shadow-resource-bounds.md",
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
    "src/Makefile.am",
    "src/Makefile.test.include",
    "src/init.cpp",
    "src/node/caches.cpp",
    "src/node/shadow_resource_monitor.cpp",
    "src/node/shadow_resource_monitor.h",
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
    "src/test/shadow_resource_monitor_tests.cpp",
    "src/test/shadow_tests.cpp",
    "src/warnings.cpp",
    "src/warnings.h",
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
        "blackcoind, getshadowresourceinfo, and the single-flight production "
        "getcirculatingsupply path at protected operator-attested anchors. "
        "Multi-window slopes remain empirical operating assumptions, not "
        "consensus limits."
    ),
    "unproved": (
        "Consensus permits chainstate growth far above this operating model. "
        "Universal consensus-bounded resource safety, indefinite post-horizon "
        "growth, and cross-platform performance equivalence remain unproved. "
        "The verifier may authorize only the declared fixed-height RPC "
        "operating envelope."
    ),
}

PINNED_AUTHORIZATION_POLICY = {
    "result_source": "verifier_derived_not_contract_boolean",
    "authorized_mode": "scoped_operational",
    "authorized_scope": "optional_getcirculatingsupply_capacity_and_fail_closed_runtime_controls_on_the_recorded_linux_reference_environment_through_the_fixed_height_horizon_without_a_future_completion_latency_guarantee",
    "provisional_mode": "provisional_scoped_operational",
    "universal_consensus_bound": False,
    "minimum_observation_span_blocks": 10_000,
    "minimum_observation_span_seconds": 604_800,
    "maximum_observation_end_age_seconds": 86_400,
    "required_growth_windows_blocks": [1, 64, 1_024, 10_000],
    "growth_safety_multiplier": 4,
    "require_exact_sha_source_and_binaries": True,
    "require_combined_production_scan": True,
    "require_runtime_single_flight_and_progress": True,
    "require_non_consensus_failure_isolation": True,
    "requalify_on_height_horizon_or_source_change": True,
}

PINNED_OPERATIONAL_ENVELOPE = {
    "model_class": "scoped_operational",
    "universal_consensus_bound": False,
    "support_through_height": 6_192_999,
    "modeled_shadow_logical_bytes": 103_622_484_600,
    "policy_disk_amplification_factor": 3,
    "modeled_shadow_physical_reserve_bytes": 310_867_453_800,
    "maximum_modeled_shadow_logical_bytes_per_block": 432_613,
    "maximum_modeled_shadow_physical_bytes_per_block": 1_297_839,
    "modeled_legacy_shadow_logical_bytes_per_block": 398_396,
    "current_chainstate_estimate_allowance_bytes": 68_719_476_736,
    "current_background_records": 16_777_216,
    "background_physical_reserve_bytes_per_block": 262_144,
    "background_growth_records_per_block": 1_024,
    "maximum_synthetic_records": 541_701_000,
    "maximum_modeled_shadow_records_per_block": 2_263,
    "modeled_legacy_shadow_records_per_block": 2_073,
    "minimum_free_bytes": 68_719_476_736,
    "immediate_scan_free_bytes": 68_719_476_736,
    "critical_free_bytes": 52_428_800,
    "maximum_estimated_chainstate_bytes": 443_287_922_536,
    "maximum_records_per_cursor": 807_310_216,
    "maximum_sequential_visits": 1_614_620_432,
    "maximum_point_seeks": 1_614_620_432,
    "absolute_records_per_cursor": 1_614_620_432,
    "absolute_point_seeks": 3_229_240_864,
    "warning_numerator": 5,
    "warning_denominator": 4,
}

PINNED_RETENTION = {
    "authenticated_compaction_implemented": False,
    "rule": (
        "Compaction is required when exact synthetic steady or "
        "maximum-observed physical amplification, obsolete-file retention, "
        "or measured forced-compaction reclaim crosses its pinned budget. "
        "Periodic sampling is not asserted as an unseen transient upper "
        "bound. Optional evidence qualification fails when compaction is "
        "required but no separately authenticated compaction protocol is "
        "implemented."
    ),
}


def verify_contract(contract: dict) -> None:
    require_keys(
        contract,
        {"schema", "contract_id", "repository", "qualification_scope",
         "authorization_policy", "operational_envelope",
         "synthetic_fixture",
         "live_partial_snapshot", "measurement", "budgets", "retention",
         "source_files"},
        "contract",
    )
    if contract["schema"] != 3 or contract["contract_id"] != CONTRACT_ID:
        raise RuntimeError("unsupported production resource contract")
    if contract["repository"] != "Blackcoin-Dev/Blackcoin":
        raise RuntimeError("production resource repository changed")
    if contract["qualification_scope"] != PINNED_QUALIFICATION_SCOPE:
        raise RuntimeError("production resource qualification scope changed")
    if contract["authorization_policy"] != PINNED_AUTHORIZATION_POLICY:
        raise RuntimeError("production authorization policy changed")
    if contract["operational_envelope"] != PINNED_OPERATIONAL_ENVELOPE:
        raise RuntimeError("operational envelope changed without schema review")
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
    verify_runtime_operational_envelope(repo, contract)


RUNTIME_ENVELOPE_CONSTANTS = {
    "support_through_height": "SHADOW_RESOURCE_SUPPORT_THROUGH_HEIGHT",
    "modeled_shadow_logical_bytes": "SHADOW_RESOURCE_MODELED_SHADOW_LOGICAL_BYTES",
    "policy_disk_amplification_factor": "SHADOW_RESOURCE_POLICY_DISK_AMPLIFICATION_FACTOR",
    "modeled_shadow_physical_reserve_bytes": "SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES",
    "maximum_modeled_shadow_logical_bytes_per_block": "SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK",
    "maximum_modeled_shadow_physical_bytes_per_block": "SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK",
    "modeled_legacy_shadow_logical_bytes_per_block": "SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_LOGICAL_BYTES_PER_BLOCK",
    "current_chainstate_estimate_allowance_bytes": "SHADOW_RESOURCE_CURRENT_CHAINSTATE_ESTIMATE_ALLOWANCE_BYTES",
    "current_background_records": "SHADOW_RESOURCE_CURRENT_BACKGROUND_RECORDS",
    "background_physical_reserve_bytes_per_block": "SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK",
    "background_growth_records_per_block": "SHADOW_RESOURCE_BACKGROUND_GROWTH_RECORDS_PER_BLOCK",
    "maximum_synthetic_records": "SHADOW_RESOURCE_MAX_SYNTHETIC_RECORDS",
    "maximum_modeled_shadow_records_per_block": "SHADOW_RESOURCE_MAX_MODELED_SHADOW_RECORDS_PER_BLOCK",
    "modeled_legacy_shadow_records_per_block": "SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_RECORDS_PER_BLOCK",
    "minimum_free_bytes": "SHADOW_RESOURCE_MINIMUM_FREE_BYTES",
    "immediate_scan_free_bytes": "SHADOW_RESOURCE_IMMEDIATE_SCAN_FREE_BYTES",
    "critical_free_bytes": "SHADOW_RESOURCE_CRITICAL_FREE_BYTES",
    "maximum_estimated_chainstate_bytes": "SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES",
    "maximum_records_per_cursor": "SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR",
    "maximum_sequential_visits": "SHADOW_RESOURCE_MAX_SEQUENTIAL_VISITS",
    "maximum_point_seeks": "SHADOW_RESOURCE_MAX_POINT_SEEKS",
    "absolute_records_per_cursor": "SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR",
    "absolute_point_seeks": "SHADOW_RESOURCE_ABSOLUTE_POINT_SEEKS",
    "warning_numerator": "SHADOW_RESOURCE_WARNING_NUMERATOR",
    "warning_denominator": "SHADOW_RESOURCE_WARNING_DENOMINATOR",
}


def verify_runtime_operational_envelope(repo: Path, contract: dict) -> None:
    header = (repo / "src/node/shadow_resource_monitor.h").read_text(
        encoding="utf-8"
    )
    envelope = contract["operational_envelope"]
    for field, constant in RUNTIME_ENVELOPE_CONSTANTS.items():
        match = re.search(
            rf"inline constexpr (?:int|uint64_t) {constant}\{{([0-9]+)(?:ULL)?\}};",
            header,
        )
        if match is None:
            raise RuntimeError(
                f"runtime operational constant is not a literal: {constant}"
            )
        if int(match.group(1)) != envelope[field]:
            raise RuntimeError(
                f"runtime operational constant differs: {constant}"
            )

    blockchain = (repo / "src/rpc/blockchain.cpp").read_text(encoding="utf-8")
    runtime_requirements = (
        "allow_unqualified_resource_scan",
        "TryBeginShadowSupplyScan",
        "abortcirculatingsupplyscan",
        "active_coin_batch_payload_bytes_scanned",
        "authenticated_shadow_batch_payload_bytes_scanned",
        "IsModeledShadowResourceMarkerOutpoint",
        "SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR",
        "SHADOW_RESOURCE_ABSOLUTE_POINT_SEEKS",
        "consensus_behavior_changed\", false",
        "no partial monetary result was returned",
    )
    for requirement in runtime_requirements:
        if requirement not in blockchain:
            raise RuntimeError(
                f"production resource RPC protection is missing: {requirement}"
            )
    monitor = (repo / "src/node/shadow_resource_monitor.cpp").read_text(
        encoding="utf-8"
    )
    for requirement in (
        "Base-chain validation, networking, staking, mining, and consensus rules remain unchanged",
        "GetShadowSupplyScanProgress",
        "SetShadowResourceWarning",
    ):
        if requirement not in monitor:
            raise RuntimeError(
                f"resource monitor failure isolation is missing: {requirement}"
            )


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
        "fixture_binary": evidence["fixture_binary"],
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


OPERATIONAL_OBSERVATION_KEYS = {
    "schema", "height", "bestblock", "block_mediantime", "txouts",
    "marker_records_scanned", "utxo_records_scanned",
    "active_coin_batch_payload_bytes_scanned",
    "authenticated_shadow_records_scanned",
    "authenticated_shadow_batch_payload_bytes_scanned",
    "provenance_point_seeks", "demurrage_point_seeks",
    "chainstate_estimated_bytes", "filesystem_available_bytes",
    "required_free_bytes", "resource_status", "within_supported_height",
    "within_chainstate_size", "within_immediate_scan_free_space",
    "within_projected_free_space", "operational_envelope_satisfied",
    "rpc_responsive_after_scan",
}


def verify_operational_observations(value, fixture: dict,
                                    contract: dict) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise RuntimeError("live evidence lacks operational observations")
    policy = contract["authorization_policy"]
    synthetic = contract["synthetic_fixture"]
    pre_height = synthetic["reward_start_height"] - 1
    end_height = fixture["end_height"]
    expected_heights = {pre_height, end_height}
    for window in policy["required_growth_windows_blocks"]:
        target = end_height - window
        if target >= synthetic["reward_start_height"]:
            expected_heights.add(target)

    observations = []
    for index, observation in enumerate(value):
        label = f"operational_observations[{index}]"
        require_keys(observation, OPERATIONAL_OBSERVATION_KEYS, label)
        if observation["schema"] != 1:
            raise RuntimeError(f"{label} schema differs")
        height = integer(observation["height"], f"{label}.height")
        block_hash = observation["bestblock"]
        if not isinstance(block_hash, str) or not BLOCK_HASH_RE.fullmatch(block_hash):
            raise RuntimeError(f"{label}.bestblock is invalid")
        for key in (
            "block_mediantime", "txouts", "marker_records_scanned",
            "utxo_records_scanned",
            "active_coin_batch_payload_bytes_scanned",
            "authenticated_shadow_records_scanned",
            "authenticated_shadow_batch_payload_bytes_scanned",
            "provenance_point_seeks",
            "demurrage_point_seeks", "chainstate_estimated_bytes",
            "filesystem_available_bytes", "required_free_bytes",
        ):
            integer(observation[key], f"{label}.{key}")
        if observation["resource_status"] not in {
            "healthy", "warning", "outside_operational_envelope"
        }:
            raise RuntimeError(f"{label}.resource_status differs")
        for key in (
            "within_supported_height", "within_chainstate_size",
            "within_immediate_scan_free_space",
            "within_projected_free_space",
            "operational_envelope_satisfied",
            "rpc_responsive_after_scan",
        ):
            if not isinstance(observation[key], bool):
                raise RuntimeError(f"{label}.{key} must be boolean")
        if observation["marker_records_scanned"] != observation[
                "utxo_records_scanned"]:
            raise RuntimeError(f"{label} immutable cursor counts differ")
        if observation["txouts"] > observation["utxo_records_scanned"]:
            raise RuntimeError(f"{label} UTXO count exceeds streamed records")
        if observation["authenticated_shadow_records_scanned"] > observation[
                "utxo_records_scanned"]:
            raise RuntimeError(
                f"{label} authenticated shadow records exceed active records"
            )
        if observation[
                "authenticated_shadow_batch_payload_bytes_scanned"] > observation[
                    "active_coin_batch_payload_bytes_scanned"]:
            raise RuntimeError(
                f"{label} authenticated shadow payload exceeds active payload"
            )
        if (
            observation["provenance_point_seeks"]
            + observation["demurrage_point_seeks"]
            > contract["operational_envelope"]["absolute_point_seeks"]
        ):
            raise RuntimeError(f"{label} exceeds the absolute seek protection")
        if observation["marker_records_scanned"] > contract[
                "operational_envelope"]["absolute_records_per_cursor"]:
            raise RuntimeError(f"{label} exceeds the absolute cursor protection")
        if observation["within_supported_height"] is not (
            height <= contract["operational_envelope"]["support_through_height"]
        ):
            raise RuntimeError(f"{label} support-horizon status differs")
        envelope = contract["operational_envelope"]
        expected_size = (
            observation["chainstate_estimated_bytes"]
            <= envelope["maximum_estimated_chainstate_bytes"]
        )
        expected_immediate = (
            observation["filesystem_available_bytes"]
            >= envelope["immediate_scan_free_bytes"]
        )
        expected_projected = (
            observation["filesystem_available_bytes"]
            >= observation["required_free_bytes"]
        )
        first_unmeasured = max(
            height + 1, synthetic["reward_start_height"]
        )
        remaining = max(
            0, synthetic["reward_end_height"] - first_unmeasured + 1
        )
        expected_required = (
            envelope["minimum_free_bytes"]
            + remaining
            * envelope["maximum_modeled_shadow_physical_bytes_per_block"]
            + remaining
            * envelope["background_physical_reserve_bytes_per_block"]
        )
        if observation["required_free_bytes"] != expected_required:
            raise RuntimeError(f"{label} projected free-space formula differs")
        if observation["within_chainstate_size"] is not expected_size:
            raise RuntimeError(f"{label} chainstate-size status differs")
        if observation["within_immediate_scan_free_space"] is not expected_immediate:
            raise RuntimeError(f"{label} immediate-space status differs")
        if observation["within_projected_free_space"] is not expected_projected:
            raise RuntimeError(f"{label} projected-space status differs")
        expected_envelope = (
            observation["within_supported_height"]
            and expected_size and expected_projected
        )
        if observation["operational_envelope_satisfied"] is not expected_envelope:
            raise RuntimeError(f"{label} operating-envelope status differs")
        if observation["rpc_responsive_after_scan"] is not True:
            raise RuntimeError(f"{label} did not prove post-scan RPC responsiveness")
        observations.append(observation)

    heights = [item["height"] for item in observations]
    if heights != sorted(heights) or len(heights) != len(set(heights)):
        raise RuntimeError("operational observations must have unique sorted heights")
    if set(heights) != expected_heights:
        raise RuntimeError("operational observation anchors differ from policy")
    by_height = {item["height"]: item for item in observations}
    if by_height[pre_height]["bestblock"] != fixture["pre_gold_rush_hash"]:
        raise RuntimeError("pre-Gold-Rush operational anchor differs")
    if by_height[end_height]["bestblock"] != fixture["end_hash"]:
        raise RuntimeError("current operational anchor differs")
    return observations


def derive_operational_authorization(live_evidence: dict, contract: dict,
                                     target_sha: str,
                                     contract_sha: str,
                                     synthetic_fixture_binary=None) -> dict:
    """Derive a deterministic result; the contract contains no approval bit."""
    fixture = live_evidence["fixture"]
    observations = live_evidence["operational_observations"]
    by_height = {item["height"]: item for item in observations}
    end_height = fixture["end_height"]
    current = by_height[end_height]
    pre_height = contract["synthetic_fixture"]["reward_start_height"] - 1
    baseline = by_height[pre_height]
    policy = contract["authorization_policy"]
    envelope = contract["operational_envelope"]
    blockers = []
    observations_report = []

    def modeled_shadow_growth(prior_height: int,
                              current_height: int) -> tuple[int, int]:
        """Return the exact regime-aware maximum active shadow growth."""
        synthetic = contract["synthetic_fixture"]
        reward_start = synthetic["reward_start_height"]
        reward_end = synthetic["reward_end_height"]
        canonical_start = synthetic["competing_claims_activation_height"]

        def blocks(first: int, last: int) -> int:
            return max(0, last - first + 1)

        legacy_blocks = blocks(
            max(prior_height + 1, reward_start),
            min(current_height, canonical_start - 1, reward_end),
        )
        canonical_blocks = blocks(
            max(prior_height + 1, canonical_start, reward_start),
            min(current_height, reward_end),
        )
        maximum_records = (
            legacy_blocks
            * envelope["modeled_legacy_shadow_records_per_block"]
            + canonical_blocks
            * envelope["maximum_modeled_shadow_records_per_block"]
        )
        maximum_logical_bytes = (
            legacy_blocks
            * envelope["modeled_legacy_shadow_logical_bytes_per_block"]
            + canonical_blocks
            * envelope[
                "maximum_modeled_shadow_logical_bytes_per_block"
            ]
        )
        return maximum_records, maximum_logical_bytes

    def block(reason: str) -> None:
        if reason not in blockers:
            blockers.append(reason)

    if end_height > envelope["support_through_height"]:
        block("height_horizon_exceeded")
    if end_height - pre_height < policy["minimum_observation_span_blocks"]:
        block("minimum_block_span_unavailable")
    if current["block_mediantime"] - baseline["block_mediantime"] < policy[
            "minimum_observation_span_seconds"]:
        block("minimum_time_span_unavailable")
    if baseline["chainstate_estimated_bytes"] > envelope[
            "current_chainstate_estimate_allowance_bytes"]:
        block("baseline_chainstate_exceeds_allowance")
    baseline_background_records = (
        baseline["marker_records_scanned"]
        - baseline["authenticated_shadow_records_scanned"]
    )
    if baseline_background_records > envelope["current_background_records"]:
        block("baseline_records_exceed_allowance")
    if current["chainstate_estimated_bytes"] > envelope[
            "maximum_estimated_chainstate_bytes"]:
        block("current_chainstate_exceeds_envelope")
    if current["marker_records_scanned"] > envelope[
            "maximum_records_per_cursor"]:
        block("current_cursor_records_exceed_envelope")
    if (
        current["provenance_point_seeks"]
        + current["demurrage_point_seeks"]
        > envelope["maximum_point_seeks"]
    ):
        block("current_point_seeks_exceed_envelope")
    if not current["within_immediate_scan_free_space"]:
        block("immediate_scan_free_space_below_envelope")
    if not current["within_projected_free_space"]:
        block("projected_free_space_below_envelope")
    if not current["operational_envelope_satisfied"]:
        block("runtime_operational_envelope_not_satisfied")

    record_limit = (
        envelope["background_growth_records_per_block"]
        // policy["growth_safety_multiplier"]
    )
    logical_byte_limit = (
        envelope["background_physical_reserve_bytes_per_block"]
        // (
            envelope["policy_disk_amplification_factor"]
            * policy["growth_safety_multiplier"]
        )
    )

    cumulative_shadow_record_delta = max(
        0,
        current["authenticated_shadow_records_scanned"]
        - baseline["authenticated_shadow_records_scanned"],
    )
    cumulative_shadow_logical_byte_delta = max(
        0,
        current["authenticated_shadow_batch_payload_bytes_scanned"]
        - baseline["authenticated_shadow_batch_payload_bytes_scanned"],
    )
    (cumulative_shadow_record_maximum,
     cumulative_shadow_logical_byte_maximum) = modeled_shadow_growth(
        pre_height, end_height
    )
    if cumulative_shadow_record_delta > cumulative_shadow_record_maximum:
        block("cumulative_shadow_records_exceed_model")
    if (
        cumulative_shadow_logical_byte_delta
        > cumulative_shadow_logical_byte_maximum
    ):
        block("cumulative_shadow_logical_bytes_exceed_model")
    cumulative_background_record_delta = max(
        0,
        (
            current["marker_records_scanned"]
            - current["authenticated_shadow_records_scanned"]
        )
        - (
            baseline["marker_records_scanned"]
            - baseline["authenticated_shadow_records_scanned"]
        ),
    )
    cumulative_background_logical_byte_delta = max(
        0,
        (
            current["active_coin_batch_payload_bytes_scanned"]
            - current["authenticated_shadow_batch_payload_bytes_scanned"]
        )
        - (
            baseline["active_coin_batch_payload_bytes_scanned"]
            - baseline[
                "authenticated_shadow_batch_payload_bytes_scanned"
            ]
        ),
    )
    cumulative_blocks = max(0, end_height - pre_height)
    cumulative_background_record_maximum = cumulative_blocks * record_limit
    cumulative_background_logical_byte_maximum = (
        cumulative_blocks * logical_byte_limit
    )
    if (
        cumulative_background_record_delta
        > cumulative_background_record_maximum
    ):
        block("cumulative_background_records_exceed_assumption")
    if (
        cumulative_background_logical_byte_delta
        > cumulative_background_logical_byte_maximum
    ):
        block("cumulative_background_logical_bytes_exceed_assumption")

    for window in policy["required_growth_windows_blocks"]:
        prior = by_height.get(end_height - window)
        if prior is None:
            block(f"growth_window_{window}_unavailable")
            continue
        current_background_records = (
            current["marker_records_scanned"]
            - current["authenticated_shadow_records_scanned"]
        )
        prior_background_records = (
            prior["marker_records_scanned"]
            - prior["authenticated_shadow_records_scanned"]
        )
        current_background_logical_bytes = (
            current["active_coin_batch_payload_bytes_scanned"]
            - current["authenticated_shadow_batch_payload_bytes_scanned"]
        )
        prior_background_logical_bytes = (
            prior["active_coin_batch_payload_bytes_scanned"]
            - prior["authenticated_shadow_batch_payload_bytes_scanned"]
        )
        background_record_delta = max(
            0, current_background_records - prior_background_records
        )
        background_logical_byte_delta = max(
            0,
            current_background_logical_bytes
            - prior_background_logical_bytes,
        )
        record_rate = (
            background_record_delta + window - 1
        ) // window
        logical_byte_rate = (
            background_logical_byte_delta + window - 1
        ) // window
        authenticated_shadow_record_delta = max(
            0,
            current["authenticated_shadow_records_scanned"]
            - prior["authenticated_shadow_records_scanned"],
        )
        authenticated_shadow_logical_byte_delta = max(
            0,
            current["authenticated_shadow_batch_payload_bytes_scanned"]
            - prior[
                "authenticated_shadow_batch_payload_bytes_scanned"
            ],
        )
        (maximum_shadow_records,
         maximum_shadow_logical_bytes) = modeled_shadow_growth(
            prior["height"], current["height"]
        )
        shadow_within = (
            authenticated_shadow_record_delta <= maximum_shadow_records
            and authenticated_shadow_logical_byte_delta
            <= maximum_shadow_logical_bytes
        )
        within = (
            shadow_within
            and record_rate <= record_limit
            and logical_byte_rate <= logical_byte_limit
        )
        observations_report.append({
            "window_blocks": window,
            "active_record_delta": (
                current["marker_records_scanned"]
                - prior["marker_records_scanned"]
            ),
            "authenticated_shadow_record_delta": (
                current["authenticated_shadow_records_scanned"]
                - prior["authenticated_shadow_records_scanned"]
            ),
            "authenticated_shadow_record_growth_ceiling":
                authenticated_shadow_record_delta,
            "modeled_shadow_record_growth_maximum": maximum_shadow_records,
            "background_record_growth_per_block_ceiling": record_rate,
            "background_record_growth_per_block_limit": record_limit,
            "active_logical_byte_delta": (
                current["active_coin_batch_payload_bytes_scanned"]
                - prior["active_coin_batch_payload_bytes_scanned"]
            ),
            "authenticated_shadow_logical_byte_delta": (
                current[
                    "authenticated_shadow_batch_payload_bytes_scanned"
                ]
                - prior[
                    "authenticated_shadow_batch_payload_bytes_scanned"
                ]
            ),
            "authenticated_shadow_logical_byte_growth_ceiling":
                authenticated_shadow_logical_byte_delta,
            "modeled_shadow_logical_byte_growth_maximum":
                maximum_shadow_logical_bytes,
            "background_logical_byte_growth_per_block_ceiling":
                logical_byte_rate,
            "background_logical_byte_growth_per_block_limit":
                logical_byte_limit,
            "within_operating_assumption": within,
        })
        if authenticated_shadow_record_delta > maximum_shadow_records:
            block(f"growth_window_{window}_shadow_records_exceed_model")
        if (
            authenticated_shadow_logical_byte_delta
            > maximum_shadow_logical_bytes
        ):
            block(
                f"growth_window_{window}_shadow_logical_bytes_exceed_model"
            )
        if record_rate > record_limit:
            block(f"growth_window_{window}_records_exceed_assumption")
        if logical_byte_rate > logical_byte_limit:
            block(
                f"growth_window_{window}_logical_bytes_exceed_assumption"
            )

    provisional_blockers = {
        reason for reason in blockers
        if reason not in {
            "minimum_block_span_unavailable",
            "minimum_time_span_unavailable",
        } and not (
            reason.startswith("growth_window_")
            and reason.endswith("_unavailable")
        )
    }
    source_manifest_sha256 = hashlib.sha256(json.dumps(
        live_evidence["source_files"], separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")).hexdigest()
    return {
        "schema": 1,
        "target_sha": target_sha,
        "contract_sha256": contract_sha,
        "source_manifest_sha256": source_manifest_sha256,
        "binaries": {
            "blackcoind": live_evidence["binaries"]["blackcoind"],
            "blackcoin_cli": live_evidence["binaries"]["blackcoin_cli"],
            "synthetic_fixture": synthetic_fixture_binary,
        },
        "measurement_environment": live_evidence["measurement_environment"],
        "live_fixture_binding": {
            "fixture_manifest_sha256": fixture[
                "fixture_manifest_sha256"
            ],
            "archive_sha256": fixture["archive_sha256"],
            "archive_size_bytes": fixture["archive_size_bytes"],
        },
        "mode": policy["authorized_mode"],
        "authorized_scope": policy["authorized_scope"],
        "authorized": not blockers,
        "provisional_mode": policy["provisional_mode"],
        "provisional_authorized": not provisional_blockers,
        "universal_consensus_bound": False,
        "support_through_height": envelope["support_through_height"],
        "evidence_end_height": end_height,
        "evidence_end_hash": fixture["end_hash"],
        "evidence_end_mediantime": current["block_mediantime"],
        "observation_span_blocks": end_height - pre_height,
        "observation_span_mediantime_seconds": (
            current["block_mediantime"] - baseline["block_mediantime"]
        ),
        "evidence_captured_at_unix": fixture["captured_at_unix"],
        "authorization_expires_at_unix": (
            fixture["captured_at_unix"]
            + policy["maximum_observation_end_age_seconds"]
        ),
        "required_growth_windows_blocks": policy[
            "required_growth_windows_blocks"
        ],
        "growth_safety_multiplier": policy["growth_safety_multiplier"],
        "policy_disk_amplification_factor": envelope[
            "policy_disk_amplification_factor"
        ],
        "background_physical_reserve_bytes_per_block": envelope[
            "background_physical_reserve_bytes_per_block"
        ],
        "cumulative_authenticated_shadow_growth": {
            "record_growth_ceiling": cumulative_shadow_record_delta,
            "modeled_record_growth_maximum":
                cumulative_shadow_record_maximum,
            "logical_byte_growth_ceiling":
                cumulative_shadow_logical_byte_delta,
            "modeled_logical_byte_growth_maximum":
                cumulative_shadow_logical_byte_maximum,
        },
        "cumulative_background_growth": {
            "record_growth_ceiling": cumulative_background_record_delta,
            "record_growth_maximum":
                cumulative_background_record_maximum,
            "logical_byte_growth_ceiling":
                cumulative_background_logical_byte_delta,
            "logical_byte_growth_maximum":
                cumulative_background_logical_byte_maximum,
        },
        "growth_windows": observations_report,
        "blockers": blockers,
        "scope": contract["qualification_scope"],
    }


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
         "operational_observations",
         "maximum_peak_rss_bytes"},
        "live evidence",
    )
    if (evidence["schema"], evidence["status"], evidence["evidence_kind"]) != (
            3, "complete", "current_live_partial_epoch"):
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
    verify_operational_observations(
        evidence["operational_observations"], fixture, contract
    )

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
    return {
        "measurement_environment": evidence["measurement_environment"],
        "evidence": evidence,
        "contract_sha256": contract_sha,
    }


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
    parser.add_argument("--authorization-output", type=Path)
    parser.add_argument("--require-production-authorization",
                        action="store_true")
    args = parser.parse_args()
    try:
        repo = args.repo_root.resolve()
        contract = args.contract.resolve()
        decision = verify_synthetic(
            repo, contract, args.synthetic_evidence.resolve(),
            args.synthetic_binary.resolve(), args.target_sha,
        )
        live_result = verify_live(
            repo, contract, args.live_evidence.resolve(),
            args.live_manifest.resolve(), args.blackcoind.resolve(),
            args.blackcoin_cli.resolve(), args.target_sha,
            args.live_manifest_sha256,
        )
        if live_result["measurement_environment"] != decision[
                "measurement_environment"]:
            raise RuntimeError(
                "paired evidence was measured on different host environments"
            )
        contract_value = load_json(contract, "production resource contract")
        authorization = derive_operational_authorization(
            live_result["evidence"], contract_value, args.target_sha,
            live_result["contract_sha256"], decision["fixture_binary"],
        )
        if args.authorization_output:
            output = args.authorization_output.resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(authorization, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if args.require_production_authorization:
            if not authorization["authorized"]:
                raise RuntimeError(
                    "scoped operational authorization blockers: "
                    + ", ".join(authorization["blockers"])
                )
            if int(time.time()) > authorization[
                    "authorization_expires_at_unix"]:
                raise RuntimeError(
                    "scoped operational authorization evidence is stale"
                )
    except RuntimeError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(
        "Scoped synthetic full-epoch and current live partial-epoch resource "
        "evidence pass; "
        f"mode={authorization['mode']}; authorized={authorization['authorized']}; "
        f"provisional_authorized={authorization['provisional_authorized']}; "
        f"compaction_required={decision['compaction_required']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
