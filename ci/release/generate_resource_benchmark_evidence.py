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
import statistics
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
    # These names are reserved so production fails closed until dedicated
    # 32 MiB block-validation and maximum-marker apply/undo benches land.
    "large-block": {"QuantumLargeBlockValidation32MiB": ("block", 1)},
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


def verify_source_checkout(repo_root: Path, repository: str,
                           source_sha: str) -> None:
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
    except (OSError, subprocess.CalledProcessError) as error:
        raise RuntimeError(f"cannot verify benchmark source checkout: {error}") from error
    if actual != source_sha:
        raise RuntimeError(
            f"benchmark source commit mismatch: checkout is {actual}, expected {source_sha}"
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
    verify_source_checkout(repo_root, repository, source_sha)
    if not LABEL_RE.fullmatch(platform) or not LABEL_RE.fullmatch(architecture):
        raise RuntimeError("platform and architecture must be simple stable labels")
    toolchain = checked_line(toolchain, "toolchain")
    compiler_flags = checked_line(compiler_flags, "compiler flags")
    build_profile = checked_line(build_profile, "build profile")
    if not binary.is_file():
        raise RuntimeError(f"benchmark binary does not exist: {binary}")
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

    return {
        "schema": 1,
        "source": {"repository": repository, "commit": source_sha},
        "runner": {
            "platform": platform,
            "architecture": architecture,
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
