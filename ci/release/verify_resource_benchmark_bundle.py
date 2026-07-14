#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify the exact native resource-evidence bundle for a release."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_RUNNERS = {
    "linux-x86_64": ("linux", "x86_64"),
    "linux-arm64": ("linux", "arm64"),
    "windows-x86_64": ("windows", "x86_64"),
    "macos-x86_64": ("macos", "x86_64"),
    "macos-arm64": ("macos", "arm64"),
}
NORMALIZED_PLATFORMS = {
    "linux": "linux",
    "darwin": "macos",
    "windows": "windows",
}
NORMALIZED_ARCHITECTURES = {
    "amd64": "x86_64",
    "x86_64": "x86_64",
    "aarch64": "arm64",
    "arm64": "arm64",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def expected_filenames() -> set[str]:
    return {
        f"quantum-resource-{runner}-{suffix}.json"
        for runner in EXPECTED_RUNNERS
        for suffix in ("evidence", "nanobench")
    }


def verify_bundle(directory: Path, source_sha: str, repository: str,
                  provenance_manifest: Path) -> None:
    require(SHA1_RE.fullmatch(source_sha) is not None,
            "source SHA must be a full lowercase commit identifier")
    require(repository == EXPECTED_REPOSITORY,
            f"repository must be exactly {EXPECTED_REPOSITORY}")
    require(directory.is_dir(), f"resource evidence directory is missing: {directory}")
    require(provenance_manifest.is_file(),
            f"quantum crypto provenance manifest is missing: {provenance_manifest}")

    actual = {
        path.name for path in directory.iterdir()
        if path.is_file()
    }
    expected = expected_filenames()
    require(actual == expected,
            "resource evidence inventory differs: "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}")
    require(not any(path.is_dir() for path in directory.iterdir()),
            "resource evidence bundle contains an unexpected directory")

    manifest_sha256 = sha256_file(provenance_manifest)
    for runner, (expected_platform, expected_architecture) in EXPECTED_RUNNERS.items():
        evidence_path = directory / f"quantum-resource-{runner}-evidence.json"
        raw_path = directory / f"quantum-resource-{runner}-nanobench.json"
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError(f"invalid resource evidence {evidence_path.name}: {error}") from error

        require(isinstance(evidence, dict) and evidence.get("schema") == 1,
                f"unsupported resource evidence schema: {evidence_path.name}")
        require(evidence.get("source") == {
                    "repository": repository,
                    "commit": source_sha,
                }, f"resource evidence source mismatch: {evidence_path.name}")

        runner_record = evidence.get("runner")
        require(isinstance(runner_record, dict),
                f"resource evidence runner is missing: {evidence_path.name}")
        require(runner_record.get("platform") == expected_platform and
                runner_record.get("architecture") == expected_architecture,
                f"resource evidence runner mismatch: {evidence_path.name}")
        require(runner_record.get("native_execution_verified") is True,
                f"native execution is not verified: {evidence_path.name}")
        reported_platform = runner_record.get("reported_platform")
        reported_architecture = runner_record.get("reported_architecture")
        require(isinstance(reported_platform, str) and
                NORMALIZED_PLATFORMS.get(reported_platform.lower()) == expected_platform,
                f"reported platform mismatch: {evidence_path.name}")
        require(isinstance(reported_architecture, str) and
                NORMALIZED_ARCHITECTURES.get(reported_architecture.lower()) ==
                expected_architecture,
                f"reported architecture mismatch: {evidence_path.name}")

        inputs = evidence.get("inputs")
        require(isinstance(inputs, dict),
                f"resource evidence inputs are missing: {evidence_path.name}")
        require(inputs.get("nanobench_json_sha256") == sha256_file(raw_path),
                f"nanobench input hash mismatch: {evidence_path.name}")
        require(inputs.get("quantum_crypto_provenance_manifest_sha256") ==
                manifest_sha256,
                f"quantum crypto provenance hash mismatch: {evidence_path.name}")
        require(SHA256_RE.fullmatch(inputs.get("benchmark_binary_sha256", ""))
                is not None,
                f"benchmark binary hash is invalid: {evidence_path.name}")

        coverage = evidence.get("coverage")
        require(isinstance(coverage, dict) and
                set(coverage) == {"crypto", "large-block", "synthetic-state"} and
                all(value is True for value in coverage.values()),
                f"resource evidence coverage is incomplete: {evidence_path.name}")
        require(evidence.get("release_resource_evidence_complete") is True,
                f"resource evidence is not release-complete: {evidence_path.name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument(
        "--provenance-manifest", required=True, type=Path,
    )
    args = parser.parse_args()
    verify_bundle(
        args.directory.resolve(),
        args.source_sha,
        args.repository,
        args.provenance_manifest.resolve(),
    )
    print("Exact native resource benchmark bundle verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"Resource benchmark bundle verification failed: {error}", file=sys.stderr)
        sys.exit(1)
