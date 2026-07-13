#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Require two isolated release builds to produce byte-identical artifacts."""

import argparse
import hashlib
from pathlib import Path
import sys


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def inventory(root):
    root = root.resolve(strict=True)
    result = {}
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        if entry.is_symlink():
            raise RuntimeError(f"release artifact must not be a symbolic link: {relative}")
        if entry.is_dir():
            continue
        if not entry.is_file():
            raise RuntimeError(f"unsupported release artifact type: {relative}")
        result[relative] = (entry.stat().st_size, digest(entry))
    if not result:
        raise RuntimeError(f"release artifact directory is empty: {root}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primary", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    args = parser.parse_args()

    primary = inventory(args.primary)
    verifier = inventory(args.verifier)
    if primary.keys() != verifier.keys():
        missing = sorted(primary.keys() - verifier.keys())
        unexpected = sorted(verifier.keys() - primary.keys())
        if missing:
            print(f"missing from verifier build: {', '.join(missing)}", file=sys.stderr)
        if unexpected:
            print(f"unexpected in verifier build: {', '.join(unexpected)}", file=sys.stderr)
        return 1

    mismatches = [name for name in primary if primary[name] != verifier[name]]
    if mismatches:
        for name in mismatches:
            primary_size, primary_hash = primary[name]
            verifier_size, verifier_hash = verifier[name]
            print(
                f"non-reproducible artifact {name}: "
                f"primary={primary_size}:{primary_hash} verifier={verifier_size}:{verifier_hash}",
                file=sys.stderr,
            )
        return 1

    print(f"Verified {len(primary)} byte-identical release artifact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
