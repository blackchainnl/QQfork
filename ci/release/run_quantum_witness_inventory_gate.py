#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Run the protected exact-source mainnet quantum-witness inventory gate."""

import argparse
import fcntl
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import run_shadow_resource_production_gate as resource_gate


GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def run(command):
    result = subprocess.run(
        [str(item) for item in command], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"command failed ({result.returncode}): {command[0]}: {detail}"
        )
    return result.stdout


def safe_remove_tree(path, parent):
    if not path.exists():
        return
    if path.is_symlink() or path.parent != parent:
        raise RuntimeError("refusing to remove an unsafe witness fixture path")
    shutil.rmtree(path)


def verify_dispositions_input(path, expected_sha256):
    """Bind the optional protected disposition file to its dispatch input."""
    if path is None:
        if expected_sha256:
            raise RuntimeError(
                "a dispositions digest was supplied without a dispositions file"
            )
        return
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("dispositions file is missing or unsafe")
    if not SHA256_RE.fullmatch(expected_sha256):
        raise RuntimeError("dispositions SHA256 must be lowercase hexadecimal")
    if resource_gate.sha256_file(path) != expected_sha256:
        raise RuntimeError(
            "dispositions file differs from the immutable requested digest"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--fixture-manifest", type=Path, required=True)
    parser.add_argument("--fixture-manifest-sha256", required=True)
    parser.add_argument("--fixture-archive", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--blackcoind", type=Path, required=True)
    parser.add_argument("--blackcoin-cli", type=Path, required=True)
    parser.add_argument("--dispositions", type=Path)
    parser.add_argument("--dispositions-sha256", default="")
    parser.add_argument("--evidence-output", type=Path, required=True)
    parser.add_argument("--authorization-output", type=Path, required=True)
    args = parser.parse_args()

    lock_descriptor = None
    fixture_destination = None
    try:
        for path, label in (
            (args.work_dir, "work directory"),
            (args.fixture_manifest, "fixture manifest"),
            (args.fixture_archive, "fixture archive"),
        ):
            resource_gate.reject_symlink_components(path, label)
        args.repo_root = args.repo_root.resolve()
        args.contract = args.contract.resolve()
        args.fixture_manifest = args.fixture_manifest.resolve()
        args.fixture_archive = args.fixture_archive.resolve()
        args.work_dir = args.work_dir.resolve()
        args.blackcoind = args.blackcoind.resolve()
        args.blackcoin_cli = args.blackcoin_cli.resolve()
        args.evidence_output = args.evidence_output.resolve()
        args.authorization_output = args.authorization_output.resolve()
        if args.dispositions is not None:
            resource_gate.reject_symlink_components(args.dispositions, "dispositions file")
            args.dispositions = args.dispositions.resolve()

        if sys.platform != "linux" or not Path("/proc/self/status").is_file():
            raise RuntimeError("production witness evidence requires native Linux /proc")
        if not GIT_SHA_RE.fullmatch(args.target_sha):
            raise RuntimeError("target SHA must be a full lowercase Git commit")
        if not SHA256_RE.fullmatch(args.fixture_manifest_sha256):
            raise RuntimeError("fixture manifest SHA256 must be lowercase hexadecimal")
        if args.work_dir in (Path("/"), args.repo_root) or args.repo_root in args.work_dir.parents:
            raise RuntimeError("witness work directory must be external to the source checkout")
        for output in (args.evidence_output, args.authorization_output):
            if output == args.work_dir or args.work_dir not in output.parents:
                raise RuntimeError("witness outputs must be inside the dedicated work directory")
        if resource_gate.git_output(args.repo_root, "rev-parse", "HEAD") != args.target_sha:
            raise RuntimeError("checked-out HEAD differs from target SHA")
        if resource_gate.evidence_verifier.normalize_repository_url(
            resource_gate.git_output(args.repo_root, "remote", "get-url", "origin")
        ) != "Blackcoin-Dev/Blackcoin":
            raise RuntimeError("checked-out origin is not Blackcoin-Dev/Blackcoin")
        if resource_gate.git_output(args.repo_root, "status", "--porcelain"):
            raise RuntimeError("production witness runner requires a clean source tree")
        for binary, label in (
            (args.blackcoind, "blackcoind"),
            (args.blackcoin_cli, "blackcoin-cli"),
        ):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"exact {label} executable is missing")
        if not args.fixture_manifest.is_file() or args.fixture_manifest.is_symlink():
            raise RuntimeError("fixture manifest is missing or unsafe")
        if not args.fixture_archive.is_file() or args.fixture_archive.is_symlink():
            raise RuntimeError("fixture archive is missing or unsafe")

        contract = resource_gate.load_json(args.contract, "production resource contract")
        resource_gate.evidence_verifier.verify_contract(contract)
        contract_sha = resource_gate.sha256_file(args.contract)
        manifest_sha = resource_gate.sha256_file(args.fixture_manifest)
        if manifest_sha != args.fixture_manifest_sha256:
            raise RuntimeError("fixture manifest differs from the immutable requested digest")
        manifest = resource_gate.load_json(args.fixture_manifest, "fixture manifest")
        resource_gate.verify_fixture_manifest(
            manifest, contract, contract_sha, args.target_sha, args.fixture_archive,
        )

        verify_dispositions_input(args.dispositions, args.dispositions_sha256)

        args.work_dir.mkdir(parents=True, exist_ok=True)
        lock_path = args.work_dir / ".quantum-witness-gate.lock"
        if lock_path.is_symlink():
            raise RuntimeError("witness gate lock is unsafe")
        lock_descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another witness inventory gate owns this work directory") from error

        fixture_destination = args.work_dir / "fixture"
        safe_remove_tree(fixture_destination, args.work_dir)
        resource_gate.verify_fixture_archive(args.fixture_archive, manifest)
        resource_gate.safe_extract(
            args.fixture_archive, fixture_destination, manifest["archive_root"],
        )
        resource_gate.verify_fixture_archive(args.fixture_archive, manifest)
        datadir = fixture_destination / manifest["archive_root"]
        if not (datadir / "blocks").is_dir() or not (datadir / "chainstate").is_dir():
            raise RuntimeError("extracted witness fixture is not an archival datadir")
        for lock, label in (
            (datadir / ".lock", "blackcoind datadir"),
            (datadir / "blocks" / "index" / "LOCK", "block-index LevelDB"),
            (datadir / "chainstate" / "LOCK", "chainstate LevelDB"),
        ):
            resource_gate.require_unowned_lock(lock, label)

        audit_command = [
            sys.executable,
            args.repo_root / "contrib" / "devtools" / "quantum_witness_inventory_audit.py",
            "--source-root", args.repo_root,
            "--source-sha", args.target_sha,
            "--blackcoin-cli", args.blackcoin_cli,
            "--blackcoind", args.blackcoind,
            "--datadir", datadir,
            "--daemon-arg=-dbcache=4096",
            "--page-size=1000",
            "--max-records=100000",
            "--output", args.evidence_output,
        ]
        if args.dispositions is not None:
            audit_command.extend(("--dispositions", args.dispositions))
        run(audit_command)

        evidence_verifier = (
            args.repo_root / "ci" / "release" /
            "verify_quantum_witness_inventory_evidence.py"
        )
        run([
            sys.executable,
            evidence_verifier,
            "--repo-root", args.repo_root,
            "--target-sha", args.target_sha,
            "--evidence", args.evidence_output,
            "--capture-manifest", args.fixture_manifest,
            "--capture-manifest-sha256", args.fixture_manifest_sha256,
            "--contract", args.contract,
            "--blackcoind", args.blackcoind,
            "--blackcoin-cli", args.blackcoin_cli,
            "--authorization-output", args.authorization_output,
        ])
        # The protected paths can be refreshed independently of this process.
        # Recheck the optional decision file after both readers complete and
        # require the verifier-derived authorization to retain the dispatch
        # digest. This closes an ordinary pathname-replacement race.
        verify_dispositions_input(args.dispositions, args.dispositions_sha256)
        authorization = resource_gate.load_json(
            args.authorization_output, "witness authorization",
        )
        expected_dispositions_sha = args.dispositions_sha256 or None
        bridge_review = authorization.get("bridge_review")
        if (
            not isinstance(bridge_review, dict)
            or bridge_review.get("dispositions_file_sha256") !=
                expected_dispositions_sha
        ):
            raise RuntimeError(
                "witness authorization differs from the dispatch dispositions"
            )
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if fixture_destination is not None:
            try:
                safe_remove_tree(fixture_destination, args.work_dir)
            except (RuntimeError, OSError) as cleanup_error:
                print(f"cleanup error: {cleanup_error}", file=sys.stderr)
        if lock_descriptor is not None:
            os.close(lock_descriptor)
    print(f"Witness inventory evidence written to {args.evidence_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
