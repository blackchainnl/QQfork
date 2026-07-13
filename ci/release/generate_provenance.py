#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate an in-toto SLSA v1 provenance statement for exact release artifacts."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if args.repository != EXPECTED_REPOSITORY:
        raise RuntimeError(f"repository must be {EXPECTED_REPOSITORY}")
    if not FULL_SHA_RE.fullmatch(args.source_sha):
        raise RuntimeError("source-sha must be a full lowercase commit identifier")
    if args.tag != f"v{args.version}":
        raise RuntimeError("tag and version do not match")
    if not re.fullmatch(r"[0-9]+", args.workflow_run_id):
        raise RuntimeError("workflow-run-id must be numeric")

    subjects = []
    for path in sorted(args.artifacts.iterdir()):
        if path == args.output or path.name.endswith("-provenance.intoto.json"):
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"release artifact must be a regular file: {path}")
        subjects.append({"name": path.name, "digest": {"sha256": sha256(path)}})
    if not subjects:
        raise RuntimeError("no release subjects were found")

    repository_uri = f"git+https://github.com/{args.repository}.git"
    workflow_uri = (
        f"https://github.com/{args.repository}/.github/workflows/build.yml@{args.source_sha}"
    )
    run_uri = f"https://github.com/{args.repository}/actions/runs/{args.workflow_run_id}"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": workflow_uri,
                "externalParameters": {
                    "source": {
                        "uri": repository_uri,
                        "digest": {"gitCommit": args.source_sha},
                    },
                    "version": args.version,
                    "tag": args.tag,
                },
                "internalParameters": {
                    "workflowRunId": args.workflow_run_id,
                    "reproducibilityGate": "two-isolated-builds-byte-identical",
                },
                "resolvedDependencies": [
                    {"uri": repository_uri, "digest": {"gitCommit": args.source_sha}}
                ],
            },
            "runDetails": {
                "builder": {"id": run_uri},
                "metadata": {"invocationId": run_uri},
            },
        },
    }
    args.output.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote provenance for {len(subjects)} release subject(s) to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"provenance generation failed: {error}", file=sys.stderr)
        sys.exit(1)
