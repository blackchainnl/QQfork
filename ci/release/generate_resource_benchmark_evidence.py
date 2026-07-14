#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Validate nanobench output and emit source-bound release evidence."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
MAX_SHADOW_POW_EVALS_PER_BLOCK = 64
MAX_BLOCK_MLDSA_VERIFICATIONS = 8215

DOMAIN_BENCHMARKS = {
    "crypto": {
        "QuantumArgon2id1MiB": "op",
        "QuantumArgon2id64ClaimBlock": "block",
        "QuantumMLDSA44Verify": "op",
        "QuantumMLDSA44MaxWeightBlock": "block",
    },
    # These names are reserved so production fails closed until dedicated
    # 32 MiB block-validation and maximum-marker apply/undo benches land.
    "large-block": {"QuantumLargeBlockValidation32MiB": "block"},
    "synthetic-state": {
        "QuantumSyntheticStateApplyUndoMaxMarkers": "state-transition"
    },
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def finite_positive(value, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} is not numeric")
    numeric = float(value)
    if not math.isfinite(numeric) or numeric <= 0:
        raise RuntimeError(f"{label} must be finite and positive")
    return numeric


def parse_measurements(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    results = document.get("results")
    if not isinstance(results, list) or not results:
        raise RuntimeError("nanobench document has no results")

    expected = {
        name: unit
        for domain in DOMAIN_BENCHMARKS.values()
        for name, unit in domain.items()
    }
    measurements = {}
    seen = set()
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("name"), str):
            raise RuntimeError("nanobench result has no valid name")
        name = result["name"]
        if name in seen:
            raise RuntimeError(f"duplicate nanobench result: {name}")
        seen.add(name)
        if name not in expected:
            continue
        if result.get("unit") != expected[name] or result.get("batch") != 1:
            raise RuntimeError(f"unexpected unit or batch for {name}")
        epochs = result.get("epochs")
        if isinstance(epochs, bool) or not isinstance(epochs, int) or epochs < 5:
            raise RuntimeError(f"insufficient benchmark epochs for {name}")
        median = finite_positive(result.get("median(elapsed)"), f"{name} median")
        total = finite_positive(result.get("totalTime"), f"{name} total time")
        error = result.get("medianAbsolutePercentError(elapsed)")
        if isinstance(error, bool) or not isinstance(error, (int, float)):
            raise RuntimeError(f"{name} error estimate is not numeric")
        error = float(error)
        if not math.isfinite(error) or error < 0:
            raise RuntimeError(f"{name} error estimate is invalid")
        measurements[name] = {
            "unit": expected[name],
            "epochs": epochs,
            "median_seconds": median,
            "median_absolute_fractional_error": error,
            "total_seconds": total,
        }
    return measurements


def generate_evidence(*, nanobench_json: Path, binary: Path, source_sha: str,
                      platform: str, architecture: str, toolchain: str,
                      required_domains: set[str]) -> dict:
    if not SHA1_RE.fullmatch(source_sha):
        raise RuntimeError("source SHA must be a full lowercase commit identifier")
    if not LABEL_RE.fullmatch(platform) or not LABEL_RE.fullmatch(architecture):
        raise RuntimeError("platform and architecture must be simple stable labels")
    if not toolchain.strip() or "\n" in toolchain or "\r" in toolchain:
        raise RuntimeError("toolchain must be a non-empty single-line description")
    if not binary.is_file():
        raise RuntimeError(f"benchmark binary does not exist: {binary}")

    measurements = parse_measurements(nanobench_json)
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

    return {
        "schema": 1,
        "source": {"commit": source_sha},
        "runner": {
            "platform": platform,
            "architecture": architecture,
            "toolchain": toolchain,
        },
        "inputs": {
            "benchmark_binary_sha256": sha256_file(binary),
            "nanobench_json_sha256": sha256_file(nanobench_json),
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
    parser.add_argument("--platform", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--toolchain", required=True)
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
        platform=args.platform,
        architecture=args.architecture,
        toolchain=args.toolchain,
        required_domains=set(args.require_domain),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"Wrote resource benchmark evidence to {args.output}")


if __name__ == "__main__":
    main()
