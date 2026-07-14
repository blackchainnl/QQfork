#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Validate nanobench output and emit source-bound release evidence."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform as host_platform
import re
import statistics
import struct
import subprocess
import sys


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
MAX_SHADOW_POW_EVALS_PER_BLOCK = 64
MIN_QUANTUM_INPUT_WEIGHT = 3903
MAX_WEIGHT_BOUND_QUANTUM_INPUTS = 8198
MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK = 16
MAX_BLOCK_MLDSA_VERIFICATIONS = 8215
V4_MAX_BLOCK_WEIGHT = 32_000_000
V4_MAX_BLOCK_SERIALIZED_SIZE = 32_000_000
MAXIMUM_QUANTUM_BENCHMARK_BLOCK_WEIGHT = 31_997_596
MAXIMUM_QUANTUM_BENCHMARK_SERIALIZED_SIZE = 30_988_642
# Mainnet permanently authenticated this count in the snapshot manifest at the
# protocol-pinned whitelist height. The benchmark independently reconstructs
# and authenticates the same count before deriving its 687 + 64 claim bound.
MAINNET_SHADOW_WHITELIST_HEIGHT = 5_945_000
MAINNET_AUTHENTICATED_WHITELIST_ENTRIES = 687
MAXIMUM_MAINNET_SYNTHETIC_CLAIMS = (
    MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + MAX_SHADOW_POW_EVALS_PER_BLOCK
)
MAXIMUM_MAINNET_SYNTHETIC_CLAIM_FAMILY_COINS = (
    MAXIMUM_MAINNET_SYNTHETIC_CLAIMS * 3
)
MAXIMUM_MAINNET_SYNTHETIC_MUHASH_INSERTIONS = (
    MAXIMUM_MAINNET_SYNTHETIC_CLAIMS * 2
)
# The source-bound Apple-silicon baseline is documented alongside the
# benchmark. Two seconds leaves a substantial cross-run/platform margin while
# still bounding the complete apply+checkpoint+undo+rewind transition to less
# than 1/32 of Blackcoin's 64-second target spacing.
MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS = 2.0
MAINNET_SHADOW_REWARD_START_HEIGHT = 5_950_000
MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT = 5_993_200
MAINNET_SHADOW_REWARD_END_HEIGHT = 6_192_999
MAINNET_SHADOW_GOLD_RUSH_BLOCKS = 243_000
LEGACY_POW_CLAIMS_PER_BLOCK = 1
MIN_TRANSACTION_WEIGHT = 4 * 60
MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK = (
    V4_MAX_BLOCK_WEIGHT // MIN_TRANSACTION_WEIGHT
) + 2
MAX_SHADOW_STATE_MARKER_BYTES = 0x02000000 - 1024
MAX_SHADOW_SHARD_DATA_BYTES = 8000
DIRECT_QUANTUM_SCRIPT_BYTES = 34
CANONICAL_P2PKH_SCRIPT_BYTES = 25
POOL_V2_BYTES = 49
SHADOW_MAX_EMISSION_SATOSHIS = 51_437_700 * 100_000_000

NATIVE_PLATFORMS = {
    "linux": "linux",
    "darwin": "macos",
    "windows": "windows",
}
NATIVE_ARCHITECTURES = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "arm64": "arm64",
}
BINARY_FORMATS = {
    "linux": "elf",
    "macos": "mach-o",
    "windows": "pe",
}
ELF_MACHINES = {62: "x86_64", 183: "arm64"}
MACHO_MACHINES = {0x01000007: "x86_64", 0x0100000c: "arm64"}
PE_MACHINES = {0x8664: "x86_64", 0xaa64: "arm64"}

DOMAIN_BENCHMARKS = {
    "crypto": {
        "QuantumArgon2id1MiB": ("op", 1),
        "QuantumArgon2id64ClaimBlock": (
            "proof", MAX_SHADOW_POW_EVALS_PER_BLOCK
        ),
        "QuantumMLDSA44Verify": ("op", 1),
        "QuantumMLDSA44MaxWeightBlock": (
            "signature", MAX_BLOCK_MLDSA_VERIFICATIONS
        ),
    },
    "large-block": {"QuantumLargeBlockValidation32MiB": ("block", 1)},
    # This name remains reserved so production fails closed until the
    # maximum-marker apply/undo benchmark lands.
    "synthetic-state": {
        "QuantumSyntheticStateApplyUndoMaxMarkers": ("state-transition", 1)
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_epoch_source_contract(repo_root: Path) -> dict[str, str]:
    """Bind epoch arithmetic to the exact serializers and mainnet schedule."""
    required = {
        "src/shadow.h": (
            "static constexpr int MAINNET_SHADOW_REWARD_START_HEIGHT = 5950000;",
            "static constexpr int MAINNET_SHADOW_GOLD_RUSH_BLOCKS = (180 * 24 * 60 * 60) / 64;",
            "static constexpr int MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS = 43200;",
            "static_assert(MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT == 5993200);",
            "static_assert(MAINNET_SHADOW_REWARD_END_HEIGHT == 6192999);",
            "static constexpr unsigned int MAX_SHADOW_POW_EVALS_PER_BLOCK = 64;",
            "static constexpr CAmount SHADOW_MAX_EMISSION = 51437700 * COIN;",
        ),
        "src/shadow.cpp": (
            "static constexpr size_t POOL_V2_SIZE = 49;",
            "static constexpr size_t MAX_SHADOW_STATE_MARKER_BYTES = MAX_SIZE - 1024;",
            "static constexpr size_t MAX_SHADOW_SHARD_DATA_BYTES = 8000;",
            "static constexpr uint32_t MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK = (V4_MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) + 2;",
            "static constexpr size_t HEADER_SIZE = 1 + uint256::size() + 3 * sizeof(uint32_t);",
            "static constexpr size_t SIZE = 2 + 3 * sizeof(uint32_t) + 6 * uint256::size() + POOL_V2_SIZE;",
            "static_assert(2 + QUANTUM_MIGRATION_PROGRAM_SIZE == 34);",
        ),
        "src/serialize.h": (
            "static constexpr uint64_t MAX_SIZE = 0x02000000;",
        ),
        "src/consensus/consensus.h": (
            "static const unsigned int V4_MAX_BLOCK_WEIGHT = 32000000;",
            "static const int WITNESS_SCALE_FACTOR = 4;",
            "static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60;",
        ),
        "src/consensus/quantum_witness.h": (
            "static constexpr unsigned int QUANTUM_MIGRATION_PROGRAM_SIZE = 32;",
        ),
        "src/consensus/amount.h": (
            "static constexpr CAmount COIN = 100000000;",
        ),
        "src/coins.h": (
            "uint32_t code = nHeight * uint32_t{4} + (fCoinBase ? 1 : 0) + (fCoinStake ? 2 : 0);",
            "::Serialize(s, VARINT(code));",
            "::Serialize(s, VARINT(nTime));",
            "::Serialize(s, Using<TxOutCompression>(out));",
        ),
        "src/txdb.cpp": (
            "SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }",
        ),
        "src/compressor.h": (
            "static const unsigned int nSpecialScripts = 6;",
            "unsigned int nSize = script.size() + nSpecialScripts;",
            "READWRITE(Using<AmountCompression>(obj.nValue), Using<ScriptCompression>(obj.scriptPubKey))",
        ),
        "src/compressor.cpp": (
            "uint64_t CompressAmount(uint64_t n)",
            "return 1 + (n*9 + d - 1)*10 + e;",
            "return 1 + (n - 1)*10 + 9;",
        ),
        "src/kernel/chainparams.cpp": (
            "consensus.nShadowCompetingClaimsActivationHeight =\n            MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT;",
        ),
        "src/bench/quantum_crypto.cpp": (
            "constexpr uint32_t MAINNET_AUTHENTICATED_WHITELIST_ENTRIES{687};",
            "static_assert(MAXIMUM_MAINNET_SYNTHETIC_CLAIMS == 751);",
        ),
        "src/dbwrapper.cpp": (
            "options.compression = leveldb::kNoCompression;",
        ),
    }
    hashes = {}
    for relative, fragments in required.items():
        path = repo_root / relative
        if not path.is_file():
            raise RuntimeError(f"epoch-bound source file is missing: {relative}")
        source = path.read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            raise RuntimeError(
                f"epoch-bound source contract changed in {relative}: {missing[0]}"
            )
        hashes[relative] = sha256_file(path)
    return hashes


def varint_size(value: int) -> int:
    if value < 0:
        raise RuntimeError("VARINT input must be nonnegative")
    size = 1
    while value > 0x7F:
        value = (value >> 7) - 1
        size += 1
    return size


def compress_amount(value: int) -> int:
    if value < 0:
        raise RuntimeError("compressed amount must be nonnegative")
    if value == 0:
        return 0
    exponent = 0
    while value % 10 == 0 and exponent < 9:
        value //= 10
        exponent += 1
    if exponent < 9:
        digit = value % 10
        value //= 10
        return 1 + (value * 9 + digit - 1) * 10 + exponent
    return 1 + (value - 1) * 10 + 9


def script_push_size(payload_bytes: int) -> int:
    if payload_bytes < 0:
        raise RuntimeError("script payload size must be nonnegative")
    if payload_bytes <= 75:
        return 1
    if payload_bytes <= 0xFF:
        return 2
    if payload_bytes <= 0xFFFF:
        return 3
    return 5


def marker_script_size(tag_bytes: int, payload_bytes: int) -> int:
    return (
        2 + script_push_size(tag_bytes) + tag_bytes +
        script_push_size(payload_bytes) + payload_bytes
    )


def coin_value_size(script_bytes: int, compressed_amount_varint_bytes: int = 1) -> int:
    # Every Gold Rush height uses a four-byte height-code VARINT. A uint32
    # block time needs at most five bytes. Marker scripts are not one of the
    # six special CTxOutCompressor templates.
    return (
        4 + 5 + compressed_amount_varint_bytes +
        varint_size(script_bytes + 6) + script_bytes
    )


def leveldb_batch_put_size(value_bytes: int) -> int:
    # CoinEntry is 'C' + uint256 + VARINT(0): 34 bytes. CDBBatch::WriteImpl
    # adds a type byte and key/value length VARINTs. These are serialized batch
    # payload bytes, not an SSTable or compaction-amplification bound.
    key_bytes = 34
    return 3 + key_bytes + (1 if value_bytes > 127 else 0) + value_bytes


def active_undo_batch_payload(blob_bytes: int) -> dict:
    if blob_bytes <= 0 or blob_bytes > MAX_SHADOW_STATE_MARKER_BYTES:
        raise RuntimeError("active undo blob is outside the source marker bound")
    shard_count = (
        blob_bytes + MAX_SHADOW_SHARD_DATA_BYTES - 1
    ) // MAX_SHADOW_SHARD_DATA_BYTES
    manifest_payload = 1 + 2 * 32 + 2 * 4 + 32
    manifest_script = marker_script_size(6, manifest_payload)
    total = leveldb_batch_put_size(coin_value_size(manifest_script))
    remaining = blob_bytes
    for _ in range(shard_count):
        data_bytes = min(MAX_SHADOW_SHARD_DATA_BYTES, remaining)
        remaining -= data_bytes
        shard_payload = 1 + 32 + 3 * 4 + data_bytes
        shard_script = marker_script_size(6, shard_payload)
        total += leveldb_batch_put_size(coin_value_size(shard_script))
    if remaining != 0:
        raise RuntimeError("active undo shard accounting did not consume the blob")
    return {"blob_bytes": blob_bytes, "shards": shard_count,
            "batch_payload_bytes": total}


def calculate_full_epoch_bounds() -> dict:
    legacy_blocks = (
        MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT -
        MAINNET_SHADOW_REWARD_START_HEIGHT
    )
    canonical_blocks = MAINNET_SHADOW_GOLD_RUSH_BLOCKS - legacy_blocks
    if (legacy_blocks != 43_200 or canonical_blocks != 199_800 or
            MAINNET_SHADOW_REWARD_END_HEIGHT -
            MAINNET_SHADOW_REWARD_START_HEIGHT + 1 !=
            MAINNET_SHADOW_GOLD_RUSH_BLOCKS):
        raise RuntimeError("mainnet Gold Rush phase arithmetic changed")

    legacy_claims_per_block = (
        MAINNET_AUTHENTICATED_WHITELIST_ENTRIES +
        LEGACY_POW_CLAIMS_PER_BLOCK
    )
    canonical_claims_per_block = MAXIMUM_MAINNET_SYNTHETIC_CLAIMS
    maximum_claims = (
        legacy_blocks * legacy_claims_per_block +
        canonical_blocks * canonical_claims_per_block
    )
    protocol_maximum_claims = (
        MAINNET_SHADOW_GOLD_RUSH_BLOCKS *
        MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK
    )

    claim_payload = 4 + 8 + 1 + POOL_V2_BYTES + 2 + DIRECT_QUANTUM_SCRIPT_BYTES
    claim_envelope = 4 + 4 + 32 + 4 + claim_payload
    claim_marker_script = marker_script_size(8, claim_envelope)
    claim_marker_bytes = leveldb_batch_put_size(
        coin_value_size(claim_marker_script)
    )

    # A claim cannot exceed the entire scheduled emission. The largest
    # non-multiple of ten below that cap maximizes CompressAmount over the
    # interval and therefore bounds every claim's amount VARINT.
    maximum_claim_amount_varint_bytes = varint_size(
        compress_amount(SHADOW_MAX_EMISSION_SATOSHIS - 1)
    )
    if maximum_claim_amount_varint_bytes != 8:
        raise RuntimeError("maximum claim amount compression changed")
    payout_bytes = leveldb_batch_put_size(
        coin_value_size(DIRECT_QUANTUM_SCRIPT_BYTES,
                        compressed_amount_varint_bytes=
                        maximum_claim_amount_varint_bytes)
    )
    payout_record_payload = (
        1 + 4 + 32 + 4 + 36 + 8 + 1 + 32 +
        1 + DIRECT_QUANTUM_SCRIPT_BYTES
    )
    payout_marker_script = marker_script_size(7, payout_record_payload)
    payout_marker_bytes = leveldb_batch_put_size(
        coin_value_size(payout_marker_script)
    )
    claim_family_bytes = claim_marker_bytes + payout_bytes + payout_marker_bytes
    if (claim_marker_bytes, payout_bytes, payout_marker_bytes,
            claim_family_bytes) != (205, 89, 215, 509):
        raise RuntimeError("claim-family serialization arithmetic changed")

    pool_undo_payload = 2 + 3 * 4 + 6 * 32 + POOL_V2_BYTES
    pool_undo_script = marker_script_size(6, pool_undo_payload)
    pool_undo_bytes = leveldb_batch_put_size(coin_value_size(pool_undo_script))
    solver_script = marker_script_size(7, 1 + 32)
    solver_bytes = leveldb_batch_put_size(coin_value_size(solver_script))
    if (pool_undo_bytes, solver_bytes) != (316, 92):
        raise RuntimeError("fixed marker serialization arithmetic changed")

    p2pkh_whitelist_blob = (
        1 + 4 + MAINNET_AUTHENTICATED_WHITELIST_ENTRIES *
        (2 + CANONICAL_P2PKH_SCRIPT_BYTES)
    )
    p2pkh_active_state = (
        p2pkh_whitelist_blob + 32 +
        40 * MAINNET_AUTHENTICATED_WHITELIST_ENTRIES
    )
    p2pkh_active_undo = (
        p2pkh_whitelist_blob + 169 +
        41 * MAINNET_AUTHENTICATED_WHITELIST_ENTRIES
    )
    p2pkh_undo_storage = active_undo_batch_payload(p2pkh_active_undo)
    protocol_undo_storage = active_undo_batch_payload(
        MAX_SHADOW_STATE_MARKER_BYTES
    )
    if (p2pkh_whitelist_blob, p2pkh_active_state, p2pkh_active_undo,
            p2pkh_undo_storage["batch_payload_bytes"],
            protocol_undo_storage["batch_payload_bytes"]) != (
                18_554, 46_066, 46_890, 47_696, 34_002_437):
        raise RuntimeError("active-state serialization arithmetic changed")

    fixed_per_block = pool_undo_bytes + solver_bytes
    p2pkh_retained_payload_bytes = (
        maximum_claims * claim_family_bytes +
        MAINNET_SHADOW_GOLD_RUSH_BLOCKS *
        (p2pkh_undo_storage["batch_payload_bytes"] + fixed_per_block)
    )
    protocol_retained_payload_bytes = (
        protocol_maximum_claims * claim_family_bytes +
        MAINNET_SHADOW_GOLD_RUSH_BLOCKS *
        (protocol_undo_storage["batch_payload_bytes"] + fixed_per_block)
    )

    return {
        "schedule": {
            "start_height": MAINNET_SHADOW_REWARD_START_HEIGHT,
            "competing_claims_activation_height":
                MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT,
            "end_height": MAINNET_SHADOW_REWARD_END_HEIGHT,
            "blocks": MAINNET_SHADOW_GOLD_RUSH_BLOCKS,
            "legacy_allocation_blocks": legacy_blocks,
            "canonical_reimbursement_blocks": canonical_blocks,
        },
        "claim_operations": {
            "canonical_687_entry_fixture": {
                "authenticated_whitelist_entries":
                    MAINNET_AUTHENTICATED_WHITELIST_ENTRIES,
                "legacy_claims_per_block": legacy_claims_per_block,
                "canonical_claims_per_block": canonical_claims_per_block,
                "maximum_claims": maximum_claims,
                "maximum_claim_family_records": maximum_claims * 3,
                "maximum_muhash_insertions": maximum_claims * 2,
            },
            "protocol_source_envelope": {
                "maximum_claims_per_block":
                    MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK,
                "maximum_claims": protocol_maximum_claims,
                "maximum_claim_family_records": protocol_maximum_claims * 3,
                "maximum_muhash_insertions": protocol_maximum_claims * 2,
            },
        },
        "serialized_chainstate_batch_payload": {
            "claim_marker_bytes": claim_marker_bytes,
            "payout_coin_bytes": payout_bytes,
            "payout_provenance_bytes": payout_marker_bytes,
            "claim_family_bytes": claim_family_bytes,
            "pool_undo_bytes_per_block": pool_undo_bytes,
            "solver_bytes_per_block": solver_bytes,
            "canonical_p2pkh_fixture": {
                "whitelist_blob_bytes": p2pkh_whitelist_blob,
                "maximum_active_state_bytes": p2pkh_active_state,
                "maximum_active_undo": p2pkh_undo_storage,
                "full_epoch_retained_append_only_payload_bytes":
                    p2pkh_retained_payload_bytes,
            },
            "protocol_source_envelope": {
                "maximum_active_undo": protocol_undo_storage,
                "full_epoch_retained_append_only_payload_bytes":
                    protocol_retained_payload_bytes,
            },
            "scope": (
                "serialized retained append-only claim-family, undo and solver "
                "CoinEntry "
                "payloads plus CDBBatch framing; excludes pre-existing base "
                "UTXOs, rolling checkpoint puts/deletes, SSTable/index/filter/"
                "WAL overhead, obsolete files and compaction amplification"
            ),
            "physical_leveldb_disk_bound_established": False,
        },
        "startup": {
            "full_epoch_claim_scan_required_by_application": False,
            "maximum_active_state_shards_canonical_p2pkh_fixture": 6,
            "maximum_active_state_shards_protocol_source_envelope": 4_195,
            "leveldb_open_wall_clock_bound_established": False,
        },
        "replay": {
            "canonical_687_entry_fixture_maximum_claim_applications":
                maximum_claims,
            "canonical_687_entry_fixture_maximum_muhash_insertions":
                maximum_claims * 2,
            "protocol_source_envelope_maximum_claim_applications":
                protocol_maximum_claims,
            "protocol_source_envelope_maximum_muhash_insertions":
                protocol_maximum_claims * 2,
            "sum_of_per_block_apply_undo_thresholds_seconds":
                MAINNET_SHADOW_GOLD_RUSH_BLOCKS *
                MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS,
            "full_replay_wall_clock_bound_established": False,
        },
        "retention": {
            "authenticated_compaction_implemented": False,
            "decision": (
                "unresolved until exact snapshot dimensions, physical "
                "LevelDB amplification, and full-epoch replay are qualified"
            ),
        },
        "issue_13_disposition": "partial",
    }


def finite_positive(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} is not numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise RuntimeError(f"{label} must be finite and positive")
    return numeric


def checked_line(value: str, label: str) -> str:
    value = value.strip()
    if not value or any(ord(character) < 32 for character in value):
        raise RuntimeError(f"{label} must be non-empty printable single-line text")
    return value


def native_runner_identity() -> tuple[str, str, str, str]:
    reported_platform = checked_line(host_platform.system(), "native platform")
    reported_architecture = checked_line(
        host_platform.machine(), "native architecture"
    )
    normalized_platform = NATIVE_PLATFORMS.get(reported_platform.lower())
    normalized_architecture = NATIVE_ARCHITECTURES.get(
        reported_architecture.lower()
    )
    if normalized_platform is None:
        raise RuntimeError(
            f"unsupported native benchmark platform: {reported_platform}"
        )
    if normalized_architecture is None:
        raise RuntimeError(
            f"unsupported native benchmark architecture: {reported_architecture}"
        )
    return (
        normalized_platform,
        normalized_architecture,
        reported_platform,
        reported_architecture,
    )


def verify_native_runner(
    requested_platform: str, requested_architecture: str
) -> tuple[str, str]:
    (
        native_platform,
        native_architecture,
        reported_platform,
        reported_architecture,
    ) = native_runner_identity()
    if (requested_platform != native_platform or
            requested_architecture != native_architecture):
        raise RuntimeError(
            "benchmark identity is not native: "
            f"requested {requested_platform}/{requested_architecture}, "
            f"runner reports {reported_platform}/{reported_architecture}"
        )
    return reported_platform, reported_architecture


def verify_process_not_translated(native_platform: str) -> str:
    if native_platform != "macos":
        return "not-applicable"
    result = subprocess.run(
        ["sysctl", "-in", "sysctl.proc_translated"],
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    if result.returncode == 0 and value == "1":
        raise RuntimeError("native benchmark process is running under Rosetta translation")
    if result.returncode == 0 and value != "0":
        raise RuntimeError(f"unexpected macOS process translation status: {value!r}")
    return "not-translated"


def native_binary_identity(binary: Path) -> tuple[str, str]:
    try:
        size = binary.stat().st_size
        with binary.open("rb") as executable:
            header = executable.read(64)
            if header.startswith(b"\x7fELF"):
                if len(header) < 20 or header[4:6] != b"\x02\x01":
                    raise RuntimeError("benchmark ELF must be 64-bit little-endian")
                machine = struct.unpack_from("<H", header, 18)[0]
                architecture = ELF_MACHINES.get(machine)
                if architecture is None:
                    raise RuntimeError(f"unsupported benchmark ELF machine: {machine:#x}")
                return "elf", architecture

            if header[:4] == b"\xcf\xfa\xed\xfe":
                if len(header) < 8:
                    raise RuntimeError("truncated benchmark Mach-O header")
                machine = struct.unpack_from("<I", header, 4)[0]
                architecture = MACHO_MACHINES.get(machine)
                if architecture is None:
                    raise RuntimeError(f"unsupported benchmark Mach-O machine: {machine:#x}")
                return "mach-o", architecture

            if header[:2] == b"MZ":
                if len(header) < 64:
                    raise RuntimeError("truncated benchmark DOS header")
                pe_offset = struct.unpack_from("<I", header, 0x3c)[0]
                if pe_offset > size - 6:
                    raise RuntimeError("benchmark PE header offset is out of bounds")
                executable.seek(pe_offset)
                pe_header = executable.read(6)
                if pe_header[:4] != b"PE\0\0":
                    raise RuntimeError("benchmark PE signature is invalid")
                machine = struct.unpack_from("<H", pe_header, 4)[0]
                architecture = PE_MACHINES.get(machine)
                if architecture is None:
                    raise RuntimeError(f"unsupported benchmark PE machine: {machine:#x}")
                return "pe", architecture
    except OSError as error:
        raise RuntimeError(f"cannot inspect benchmark binary: {error}") from error
    raise RuntimeError("benchmark binary format is not ELF, Mach-O, or PE")


def verify_native_binary(binary: Path, requested_platform: str,
                         requested_architecture: str) -> tuple[str, str]:
    binary_format, binary_architecture = native_binary_identity(binary)
    expected_format = BINARY_FORMATS[requested_platform]
    if (binary_format != expected_format or
            binary_architecture != requested_architecture):
        raise RuntimeError(
            "benchmark binary is not native for the requested runner: "
            f"requested {requested_platform}/{requested_architecture}, "
            f"binary is {binary_format}/{binary_architecture}"
        )
    if os.name != "nt" and not os.access(binary, os.X_OK):
        raise RuntimeError("benchmark binary is not executable")
    return binary_format, binary_architecture


def verify_source_checkout(repo_root: Path, repository: str,
                           source_sha: str,
                           allowed_untracked: tuple[Path, ...] = ()) -> None:
    if repository != EXPECTED_REPOSITORY:
        raise RuntimeError(
            f"source repository must be exactly {EXPECTED_REPOSITORY}, got {repository}"
        )
    try:
        actual = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        tracked_status = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--quiet", "HEAD", "--"],
            check=False,
        ).returncode
        untracked_output = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--others",
             "--exclude-standard", "-z"],
            check=True,
            capture_output=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"cannot verify benchmark source checkout: {error}") from error
    if actual != source_sha:
        raise RuntimeError(
            f"benchmark source commit mismatch: checkout is {actual}, expected {source_sha}"
        )
    if tracked_status not in (0, 1):
        raise RuntimeError("cannot inspect tracked benchmark source state")
    if tracked_status == 1:
        raise RuntimeError("benchmark source checkout has tracked changes")

    root = repo_root.resolve()
    allowed = set()
    for path in allowed_untracked:
        candidate = path if path.is_absolute() else repo_root / path
        try:
            allowed.add(candidate.resolve().relative_to(root).as_posix())
        except ValueError:
            continue
    untracked = {
        entry.decode("utf-8")
        for entry in untracked_output.split(b"\0") if entry
    }
    unexpected = sorted(untracked - allowed)
    if unexpected:
        raise RuntimeError(
            "benchmark source checkout has unexpected untracked files: " +
            ", ".join(unexpected)
        )


def expected_benchmarks(required_domains: set[str]) -> dict:
    if not required_domains:
        raise RuntimeError("at least one required benchmark domain is mandatory")
    unknown = sorted(required_domains - set(DOMAIN_BENCHMARKS))
    if unknown:
        raise RuntimeError("unknown required benchmark domain(s): " + ", ".join(unknown))
    return {
        name: specification
        for domain in sorted(required_domains)
        for name, specification in DOMAIN_BENCHMARKS[domain].items()
    }


def parse_measurements(path: Path, required_domains: set[str],
                       minimum_runtime_ms: int) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    results = document.get("results")
    if not isinstance(results, list) or not results:
        raise RuntimeError("nanobench document has no results")

    expected = expected_benchmarks(required_domains)
    by_name = {}
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("name"), str):
            raise RuntimeError("nanobench result has no valid name")
        name = result["name"]
        if name in by_name:
            raise RuntimeError(f"duplicate nanobench result: {name}")
        by_name[name] = result
    actual_names = set(by_name)
    expected_names = set(expected)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise RuntimeError(
            "benchmark set mismatch for required domains "
            f"{sorted(required_domains)}: missing={missing}, unexpected={unexpected}"
        )

    if (isinstance(minimum_runtime_ms, bool) or
            not isinstance(minimum_runtime_ms, int) or
            minimum_runtime_ms <= 0):
        raise RuntimeError("minimum benchmark runtime must be a positive integer")
    expected_runtime_seconds = minimum_runtime_ms / 1000.0
    measurements = {}
    for name in sorted(expected):
        result = by_name[name]
        expected_unit, expected_batch = expected[name]
        if result.get("unit") != expected_unit:
            raise RuntimeError(
                f"unexpected unit for {name}: expected {expected_unit}, got {result.get('unit')!r}"
            )
        batch = result.get("batch")
        if (isinstance(batch, bool) or not isinstance(batch, int) or
                batch != expected_batch):
            raise RuntimeError(
                f"unexpected batch for {name}: expected {expected_batch}, got {batch!r}"
            )
        epochs = result.get("epochs")
        if isinstance(epochs, bool) or not isinstance(epochs, int) or epochs < 5:
            raise RuntimeError(f"insufficient benchmark epochs for {name}")
        min_epoch_time = finite_positive(result.get("minEpochTime"),
                                         f"{name} configured runtime")
        if not math.isclose(min_epoch_time * epochs, expected_runtime_seconds,
                            rel_tol=1e-6, abs_tol=1e-9):
            raise RuntimeError(
                f"{name} configured runtime does not match {minimum_runtime_ms} ms"
            )
        raw_measurements = result.get("measurements")
        if not isinstance(raw_measurements, list) or len(raw_measurements) != epochs:
            raise RuntimeError(f"{name} measurements must contain exactly {epochs} epochs")
        normalized_measurements = []
        elapsed_values = []
        for measurement in raw_measurements:
            if not isinstance(measurement, dict):
                raise RuntimeError(f"{name} epoch measurement is not an object")
            iterations = measurement.get("iterations")
            if (isinstance(iterations, bool) or
                    not isinstance(iterations, int) or iterations <= 0):
                raise RuntimeError(f"{name} epoch iterations must be positive integers")
            elapsed = finite_positive(measurement.get("elapsed"),
                                      f"{name} epoch elapsed time")
            elapsed_values.append(elapsed)
            normalized_measurements.append({
                "iterations": iterations,
                "elapsed_seconds_per_batch": elapsed,
            })
        median = finite_positive(result.get("median(elapsed)"), f"{name} median")
        total = finite_positive(result.get("totalTime"), f"{name} total time")
        computed_median = statistics.median(elapsed_values)
        computed_total = sum(
            measurement["iterations"] * measurement["elapsed_seconds_per_batch"]
            for measurement in normalized_measurements
        )
        if not math.isclose(median, computed_median, rel_tol=1e-12, abs_tol=1e-15):
            raise RuntimeError(f"{name} median does not match epoch measurements")
        if not math.isclose(total, computed_total, rel_tol=1e-9, abs_tol=1e-12):
            raise RuntimeError(f"{name} total time does not match epoch measurements")
        error = result.get("medianAbsolutePercentError(elapsed)")
        if isinstance(error, bool) or not isinstance(error, (int, float)):
            raise RuntimeError(f"{name} error estimate is not numeric")
        error = float(error)
        if not math.isfinite(error) or error < 0:
            raise RuntimeError(f"{name} error estimate is invalid")
        measurements[name] = {
            "unit": expected_unit,
            "batch": expected_batch,
            "epochs": epochs,
            "median_seconds": median,
            "median_seconds_per_batch": median,
            "median_seconds_per_operation": median / expected_batch,
            "minimum_seconds_per_batch": min(elapsed_values),
            "maximum_seconds_per_batch": max(elapsed_values),
            "median_absolute_fractional_error": error,
            "total_seconds": total,
            "measurements": normalized_measurements,
        }
    return measurements


def generate_evidence(*, nanobench_json: Path, binary: Path, source_sha: str,
                      repo_root: Path, repository: str,
                      platform: str, architecture: str, toolchain: str,
                      compiler_flags: str, build_profile: str,
                      minimum_runtime_ms: int, provenance_manifest: Path,
                      required_domains: set[str]) -> dict:
    if not SHA1_RE.fullmatch(source_sha):
        raise RuntimeError("source SHA must be a full lowercase commit identifier")
    verify_source_checkout(
        repo_root, repository, source_sha,
        allowed_untracked=(nanobench_json,),
    )
    epoch_source_contract = verify_epoch_source_contract(repo_root)
    if not LABEL_RE.fullmatch(platform) or not LABEL_RE.fullmatch(architecture):
        raise RuntimeError("platform and architecture must be simple stable labels")
    reported_platform, reported_architecture = verify_native_runner(
        platform, architecture
    )
    translation_status = verify_process_not_translated(platform)
    toolchain = checked_line(toolchain, "toolchain")
    compiler_flags = checked_line(compiler_flags, "compiler flags")
    build_profile = checked_line(build_profile, "build profile")
    if not binary.is_file():
        raise RuntimeError(f"benchmark binary does not exist: {binary}")
    binary_format, binary_architecture = verify_native_binary(
        binary, platform, architecture
    )
    if not provenance_manifest.is_file():
        raise RuntimeError(f"provenance manifest does not exist: {provenance_manifest}")
    provenance = json.loads(provenance_manifest.read_text(encoding="utf-8"))
    if not isinstance(provenance, dict) or provenance.get("schema") != 1 or not all(
        isinstance(provenance.get(component), dict)
        for component in ("liboqs", "argon2", "wycheproof")
    ):
        raise RuntimeError("unsupported quantum cryptography provenance manifest")

    measurements = parse_measurements(
        nanobench_json, required_domains, minimum_runtime_ms
    )
    coverage = {
        domain: all(name in measurements for name in benchmarks)
        for domain, benchmarks in DOMAIN_BENCHMARKS.items()
    }
    missing = sorted(domain for domain in required_domains if not coverage[domain])
    if missing:
        raise RuntimeError(
            "required benchmark domain(s) are incomplete: " + ", ".join(missing)
        )

    derived = {}
    if coverage["crypto"]:
        argon_single = measurements["QuantumArgon2id1MiB"]["median_seconds"]
        argon_block = measurements["QuantumArgon2id64ClaimBlock"]["median_seconds"]
        mldsa_single = measurements["QuantumMLDSA44Verify"]["median_seconds"]
        mldsa_block = measurements["QuantumMLDSA44MaxWeightBlock"]["median_seconds"]
        derived = {
            "shadow_pow_argon2_block": {
                "maximum_evaluations": MAX_SHADOW_POW_EVALS_PER_BLOCK,
                "single_operation_projection_seconds":
                    argon_single * MAX_SHADOW_POW_EVALS_PER_BLOCK,
                "measured_seconds": argon_block,
                "matrix_traffic_mib": MAX_SHADOW_POW_EVALS_PER_BLOCK,
            },
            "quantum_mldsa_block": {
                "maximum_verifications": MAX_BLOCK_MLDSA_VERIFICATIONS,
                "single_operation_projection_seconds":
                    mldsa_single * MAX_BLOCK_MLDSA_VERIFICATIONS,
                "measured_seconds": mldsa_block,
            },
        }
    if coverage["large-block"]:
        derived["large_block_validation"] = {
            "maximum_weight": V4_MAX_BLOCK_WEIGHT,
            "maximum_serialized_size": V4_MAX_BLOCK_SERIALIZED_SIZE,
            "measured_fixture_weight":
                MAXIMUM_QUANTUM_BENCHMARK_BLOCK_WEIGHT,
            "measured_fixture_serialized_size":
                MAXIMUM_QUANTUM_BENCHMARK_SERIALIZED_SIZE,
            "measured_fixture_quantum_inputs":
                MAX_WEIGHT_BOUND_QUANTUM_INPUTS,
            "measured_seconds": measurements[
                "QuantumLargeBlockValidation32MiB"
            ]["median_seconds"],
        }
    if coverage["synthetic-state"]:
        synthetic_measurement = measurements[
            "QuantumSyntheticStateApplyUndoMaxMarkers"
        ]
        synthetic_seconds = synthetic_measurement["median_seconds"]
        synthetic_maximum_seconds = synthetic_measurement[
            "maximum_seconds_per_batch"
        ]
        if synthetic_maximum_seconds > MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS:
            raise RuntimeError(
                "QuantumSyntheticStateApplyUndoMaxMarkers maximum epoch "
                f"{synthetic_maximum_seconds:.9f}s exceeds the enforced "
                f"{MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS:.9f}s threshold"
            )
        derived["synthetic_state_apply_undo"] = {
            "authenticated_whitelist_snapshot_height":
                MAINNET_SHADOW_WHITELIST_HEIGHT,
            "authenticated_whitelist_entries":
                MAINNET_AUTHENTICATED_WHITELIST_ENTRIES,
            "maximum_pow_claims": MAX_SHADOW_POW_EVALS_PER_BLOCK,
            "maximum_synthetic_claims": MAXIMUM_MAINNET_SYNTHETIC_CLAIMS,
            "maximum_claim_family_coins":
                MAXIMUM_MAINNET_SYNTHETIC_CLAIM_FAMILY_COINS,
            "maximum_muhash_insertions":
                MAXIMUM_MAINNET_SYNTHETIC_MUHASH_INSERTIONS,
            "measured_seconds": synthetic_seconds,
            "measured_median_seconds": synthetic_seconds,
            "measured_maximum_epoch_seconds": synthetic_maximum_seconds,
            "maximum_allowed_seconds":
                MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS,
            "maximum_fraction_of_target_spacing":
                MAXIMUM_SYNTHETIC_STATE_APPLY_UNDO_SECONDS / 64.0,
        }
        derived["full_gold_rush_epoch"] = calculate_full_epoch_bounds()

    return {
        "schema": 1,
        "source": {"repository": repository, "commit": source_sha},
        "runner": {
            "platform": platform,
            "architecture": architecture,
            "reported_platform": reported_platform,
            "reported_architecture": reported_architecture,
            "native_execution_verified": True,
            "binary_format": binary_format,
            "binary_architecture": binary_architecture,
            "process_translation": translation_status,
            "endianness": sys.byteorder,
            "toolchain": toolchain,
        },
        "build": {
            "profile": build_profile,
            "compiler_flags": compiler_flags,
            "minimum_benchmark_runtime_ms": minimum_runtime_ms,
        },
        "inputs": {
            "benchmark_binary_sha256": sha256_file(binary),
            "nanobench_json_sha256": sha256_file(nanobench_json),
            "quantum_crypto_provenance_manifest_sha256":
                sha256_file(provenance_manifest),
            "epoch_source_contract_sha256": epoch_source_contract,
        },
        "consensus_limits": {
            "minimum_quantum_input_weight": MIN_QUANTUM_INPUT_WEIGHT,
            "maximum_quantum_inputs_by_weight": MAX_WEIGHT_BOUND_QUANTUM_INPUTS,
            "demurrage_attestations_per_block":
                MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK,
            "pos_block_signatures_per_block": 1,
            "maximum_mldsa_verifications_per_block":
                MAX_BLOCK_MLDSA_VERIFICATIONS,
            "maximum_shadow_argon2_evaluations_per_block":
                MAX_SHADOW_POW_EVALS_PER_BLOCK,
            "v4_maximum_block_weight": V4_MAX_BLOCK_WEIGHT,
            "v4_maximum_block_serialized_size":
                V4_MAX_BLOCK_SERIALIZED_SIZE,
            "maximum_quantum_benchmark_block_weight":
                MAXIMUM_QUANTUM_BENCHMARK_BLOCK_WEIGHT,
            "maximum_quantum_benchmark_serialized_size":
                MAXIMUM_QUANTUM_BENCHMARK_SERIALIZED_SIZE,
        },
        "coverage": coverage,
        "release_resource_evidence_complete": all(coverage.values()),
        "measurements": measurements,
        "derived_upper_bounds": derived,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nanobench-json", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--platform", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--toolchain", required=True)
    parser.add_argument("--compiler-flags", required=True)
    parser.add_argument("--build-profile", required=True)
    parser.add_argument("--minimum-runtime-ms", required=True, type=int)
    parser.add_argument(
        "--provenance-manifest", type=Path,
        default=Path(__file__).resolve().parents[2] /
        "contrib" / "devtools" / "quantum-crypto-provenance.json",
    )
    parser.add_argument(
        "--require-domain", action="append", default=[],
        choices=tuple(DOMAIN_BENCHMARKS),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    evidence = generate_evidence(
        nanobench_json=args.nanobench_json,
        binary=args.binary,
        source_sha=args.source_sha,
        repo_root=args.repo_root,
        repository=args.repository,
        platform=args.platform,
        architecture=args.architecture,
        toolchain=args.toolchain,
        compiler_flags=args.compiler_flags,
        build_profile=args.build_profile,
        minimum_runtime_ms=args.minimum_runtime_ms,
        provenance_manifest=args.provenance_manifest,
        required_domains=set(args.require_domain),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote resource benchmark evidence to {args.output}")


if __name__ == "__main__":
    main()
