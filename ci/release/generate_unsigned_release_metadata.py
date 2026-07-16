#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate fail-closed metadata for the publisher-unsigned final release."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
EXPECTED_ACKNOWLEDGEMENT = (
    "I_ACKNOWLEDGE_V30_1_1_FINAL_ARTIFACTS_HAVE_NO_PUBLISHER_SIGNATURES"
)
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _inventory(artifacts, excluded):
    subjects = []
    for path in sorted(artifacts.iterdir()):
        if path in excluded:
            continue
        _require(not path.is_symlink() and path.is_file(),
                 f"release artifact must be a regular file: {path}")
        _require(not path.name.endswith(".asc"),
                 f"detached signature is forbidden by the unsigned policy: {path.name}")
        _require("RELEASE-KEY" not in path.name,
                 f"release-key artifact is forbidden by the unsigned policy: {path.name}")
        subjects.append({
            "name": path.name,
            "sha256": sha256(path),
            "size": path.stat().st_size,
        })
    _require(subjects, "no release artifacts were found")
    return subjects


def generate_metadata(
    *,
    artifacts,
    version,
    source_sha,
    tag,
    workflow_run_id,
    acknowledgement,
    notice,
    manifest,
    macos_adhoc_signed,
):
    _require(artifacts.is_dir(), "artifact directory does not exist")
    _require(VERSION_RE.fullmatch(version) is not None,
             "version must have major.minor.patch form")
    _require(FULL_SHA_RE.fullmatch(source_sha) is not None,
             "source-sha must be a full lowercase commit identifier")
    _require(tag == f"v{version}", "tag and version do not match")
    _require(re.fullmatch(r"[0-9]+", workflow_run_id) is not None,
             "workflow-run-id must be numeric")
    _require(acknowledgement == EXPECTED_ACKNOWLEDGEMENT,
             "explicit unsigned-final acknowledgement does not match")
    _require(isinstance(macos_adhoc_signed, bool),
             "macos-adhoc-signed must be a boolean")

    expected_notice = artifacts / f"Blackcoin-{version}-UNSIGNED-PRODUCTION.txt"
    expected_manifest = artifacts / f"Blackcoin-{version}-UNSIGNED-PRODUCTION.json"
    _require(notice.resolve() == expected_notice.resolve(),
             f"notice filename must be {expected_notice.name}")
    _require(manifest.resolve() == expected_manifest.resolve(),
             f"manifest filename must be {expected_manifest.name}")
    for output in (notice, manifest):
        _require(output.parent.resolve() == artifacts.resolve(),
                 "metadata outputs must be inside the artifact directory")
        _require(not output.exists() and not output.is_symlink(),
                 f"metadata output already exists: {output.name}")

    source_marker = artifacts / "SOURCE_COMMIT.txt"
    _require(source_marker.is_file() and not source_marker.is_symlink(),
             "SOURCE_COMMIT.txt is missing")
    _require(source_marker.read_text(encoding="utf-8").strip() == source_sha,
             "SOURCE_COMMIT.txt does not match source-sha")

    reproducibility = artifacts / f"Blackcoin-{version}-REPRODUCIBILITY.txt"
    _require(reproducibility.is_file() and not reproducibility.is_symlink(),
             "reproducibility report is missing")
    reproducibility_text = reproducibility.read_text(encoding="utf-8")
    for required in (
        f"package_label={version}",
        "prerelease_channel=production",
        f"source_commit={source_sha}",
    ):
        _require(required in reproducibility_text,
                 f"reproducibility report is missing required text: {required}")

    required_assets = {
        f"Blackcoin-{version}-Linux-x86_64.tar.gz",
        f"Blackcoin-{version}-Linux-ARM64.tar.gz",
        f"Blackcoin-{version}-Windows-x86_64-Portable.zip",
        f"Blackcoin-{version}-Windows-x86_64-Installer.exe",
        f"Blackcoin-{version}-macOS-Intel-x86_64-Qt-app.tar.gz",
        f"Blackcoin-{version}-macOS-Intel-x86_64-Qt-app.zip",
        f"Blackcoin-{version}-macOS-Apple-Silicon-ARM64-Qt-app.tar.gz",
        f"Blackcoin-{version}-macOS-Apple-Silicon-ARM64-Qt-app.zip",
        f"Blackcoin-{version}-SBOM.spdx.json",
        f"Blackcoin-{version}-provenance.intoto.json",
    }
    missing_assets = sorted(
        name for name in required_assets
        if not (artifacts / name).is_file() or (artifacts / name).is_symlink()
    )
    _require(not missing_assets,
             "required final artifacts are missing: " + ", ".join(missing_assets))
    _require(macos_adhoc_signed,
             "final macOS application bundles must retain native-verified ad-hoc signatures")

    acknowledgement_sha256 = hashlib.sha256(
        EXPECTED_ACKNOWLEDGEMENT.encode("ascii")
    ).hexdigest()
    notice.write_text(
        "PUBLISHER-UNSIGNED BLACKCOIN CORE PRODUCTION RELEASE\n"
        "\n"
        f"version={version}\n"
        f"tag={tag}\n"
        f"source_commit={source_sha}\n"
        f"workflow_run_id={workflow_run_id}\n"
        "signed=false\n"
        "publisher_signed=false\n"
        "source_commit_openpgp_signed=false\n"
        "tag_openpgp_signed=false\n"
        "checksums_openpgp_signed=false\n"
        "provenance_openpgp_signed=false\n"
        "authenticode_signed=false\n"
        "developer_id_signed=false\n"
        "macos_adhoc_signed=true\n"
        "notarized=false\n"
        "github_build_provenance_attestation=true\n"
        "github_sbom_attestation=true\n"
        f"unsigned_final_acknowledgement_sha256={acknowledgement_sha256}\n"
        "\n"
        "The project has no release-signing certificates for v30.1.1. Windows "
        "packages have no Authenticode signature. macOS applications carry only "
        "identity-free ad-hoc launch signatures and are not notarized. The source "
        "commit, annotated tag, checksums, and in-toto statement have no "
        "Blackcoin-Dev OpenPGP signature. Verify SHA256SUMS.txt, the exact source "
        "commit, two-builder reproducibility report, SBOM, provenance, and GitHub "
        "OIDC attestations before installing.\n",
        encoding="utf-8",
    )

    subjects = _inventory(artifacts, {manifest})
    document = {
        "schema": 1,
        "classification": "PUBLISHER_UNSIGNED_PRODUCTION_RELEASE",
        "source": {
            "repository": EXPECTED_REPOSITORY,
            "commit": source_sha,
            "tag": tag,
            "tag_type": "annotated-unsigned",
        },
        "workflow": {
            "event": "push",
            "run_id": workflow_run_id,
            "protected_environment": "production-release",
        },
        "authorization": {
            "mechanism": "protected-environment-exact-value-acknowledgement",
            "acknowledged": True,
            "acknowledgement_sha256": acknowledgement_sha256,
            "protected_environment_gate_required": True,
            "independent_environment_review_required": False,
        },
        "release": {
            "version": version,
            "published": True,
            "signed": False,
            "publisher_signed": False,
            "source_commit_openpgp_signed": False,
            "tag_openpgp_signed": False,
            "checksums_openpgp_signed": False,
            "provenance_openpgp_signed": False,
            "authenticode_signed": False,
            "developer_id_signed": False,
            "macos_adhoc_signed": True,
            "notarized": False,
        },
        "integrity": {
            "checksum_manifest": "SHA256SUMS.txt",
            "reproducibility": "two-isolated-builds-byte-identical",
            "sbom": f"Blackcoin-{version}-SBOM.spdx.json",
            "provenance": f"Blackcoin-{version}-provenance.intoto.json",
            "github_build_provenance_attestation": True,
            "github_sbom_attestation": True,
        },
        "notice": notice.name,
        "artifacts_before_manifest_and_checksums": subjects,
    }
    manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--acknowledgement", required=True)
    parser.add_argument("--notice", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--macos-adhoc-signed", action="store_true")
    args = parser.parse_args()

    document = generate_metadata(
        artifacts=args.artifacts,
        version=args.version,
        source_sha=args.source_sha,
        tag=args.tag,
        workflow_run_id=args.workflow_run_id,
        acknowledgement=args.acknowledgement,
        notice=args.notice,
        manifest=args.manifest,
        macos_adhoc_signed=args.macos_adhoc_signed,
    )
    print(
        "Wrote publisher-unsigned final metadata for "
        f"{len(document['artifacts_before_manifest_and_checksums'])} artifact(s)"
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"unsigned release metadata generation failed: {error}", file=sys.stderr)
        sys.exit(1)
