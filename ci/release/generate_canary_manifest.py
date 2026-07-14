#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate fail-closed metadata for an unpublished exact-SHA alpha bundle."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SEMANTIC_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
ALPHA_LABEL_RE = re.compile(
    r"^(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-alpha(?P<rc>[1-9][0-9]*)$"
)


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def generate_manifest(
    *,
    artifacts,
    package_label,
    source_version,
    configured_version,
    source_sha,
    release_candidate,
    workflow_run_id,
    output,
):
    label_match = ALPHA_LABEL_RE.fullmatch(package_label)
    if label_match is None:
        raise RuntimeError("package-label must have major.minor.patch-alphaN form")
    if not SEMANTIC_VERSION_RE.fullmatch(source_version):
        raise RuntimeError("source-version must have major.minor.patch form")
    if label_match.group("version") != source_version:
        raise RuntimeError("package-label and source-version do not match")
    if not re.fullmatch(r"[1-9][0-9]*", release_candidate):
        raise RuntimeError("release-candidate must be a positive integer")
    if label_match.group("rc") != release_candidate:
        raise RuntimeError("package-label alpha number and release-candidate do not match")
    if configured_version != f"{source_version}rc{release_candidate}":
        raise RuntimeError("configured-version does not match source-version and release-candidate")
    if not FULL_SHA_RE.fullmatch(source_sha):
        raise RuntimeError("source-sha must be a full lowercase commit identifier")
    if not re.fullmatch(r"[0-9]+", workflow_run_id):
        raise RuntimeError("workflow-run-id must be numeric")
    if not artifacts.is_dir():
        raise RuntimeError("artifact directory does not exist")
    if output.parent.resolve() != artifacts.resolve():
        raise RuntimeError("manifest output must be inside the artifact directory")

    expected_prefix = f"Blackcoin-{package_label}-{source_sha}-"
    expected_output = f"{expected_prefix}MANIFEST-UNSIGNED.json"
    if output.name != expected_output:
        raise RuntimeError(f"manifest filename must be {expected_output}")
    if output.exists() or output.is_symlink():
        raise RuntimeError("manifest output already exists")

    subjects = []
    marker = None
    reproducibility = None
    for path in sorted(artifacts.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"canary artifact must be a regular file: {path}")
        if not path.name.startswith(expected_prefix):
            raise RuntimeError(
                "every canary artifact filename must contain the package label and exact source SHA: "
                f"{path.name}"
            )
        if path.name.endswith("-UNSIGNED-CANARY.txt"):
            if marker is not None:
                raise RuntimeError("canary bundle contains more than one unsigned marker")
            marker = path
        if path.name.endswith("-REPRODUCIBILITY.txt"):
            if reproducibility is not None:
                raise RuntimeError("canary bundle contains more than one reproducibility report")
            reproducibility = path
        if path.name.endswith("-SOURCE_COMMIT.txt"):
            if path.read_text(encoding="utf-8").strip() != source_sha:
                raise RuntimeError(f"source commit marker does not match: {path.name}")
        subjects.append(
            {
                "name": path.name,
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )

    if marker is None:
        raise RuntimeError("unsigned canary marker is missing")
    if reproducibility is None:
        raise RuntimeError("reproducibility report is missing")
    marker_text = marker.read_text(encoding="utf-8")
    reproducibility_text = reproducibility.read_text(encoding="utf-8")
    required_marker_text = (
        "UNSIGNED CANARY ARTIFACTS - NOT A PRODUCTION RELEASE",
        f"package_label={package_label}",
        f"configured_version={configured_version}",
        f"source_commit={source_sha}",
        f"workflow_run_id={workflow_run_id}",
        "signed=false",
        "notarized=false",
        "published=false",
    )
    for required in required_marker_text:
        if required not in marker_text:
            raise RuntimeError(f"unsigned canary marker is missing required text: {required}")
    required_reproducibility_text = (
        f"package_label={package_label}",
        f"configured_version={configured_version}",
        f"source_commit={source_sha}",
    )
    for required in required_reproducibility_text:
        if required not in reproducibility_text:
            raise RuntimeError(f"reproducibility report is missing required text: {required}")
    if not subjects:
        raise RuntimeError("no canary artifacts were found")

    manifest = {
        "schema": 1,
        "classification": "UNSIGNED_CANARY_NOT_FOR_PRODUCTION",
        "package_label": package_label,
        "source_version": source_version,
        "configured_version": configured_version,
        "release_candidate": int(release_candidate),
        "source": {
            "repository": EXPECTED_REPOSITORY,
            "commit": source_sha,
        },
        "workflow": {
            "event": "workflow_dispatch",
            "run_id": workflow_run_id,
        },
        "release": {
            "published": False,
            "signed": False,
            "notarized": False,
            "tag": None,
        },
        "reproducibility": {
            "method": "two-isolated-builds-byte-identical",
            "report": reproducibility.name,
        },
        "artifacts": subjects,
    }
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--package-label", required=True)
    parser.add_argument("--source-version", required=True)
    parser.add_argument("--configured-version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--release-candidate", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    manifest = generate_manifest(
        artifacts=args.artifacts,
        package_label=args.package_label,
        source_version=args.source_version,
        configured_version=args.configured_version,
        source_sha=args.source_sha,
        release_candidate=args.release_candidate,
        workflow_run_id=args.workflow_run_id,
        output=args.output,
    )
    print(f"Wrote unsigned canary manifest for {len(manifest['artifacts'])} artifact(s) to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"canary manifest generation failed: {error}", file=sys.stderr)
        sys.exit(1)
