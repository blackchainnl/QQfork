#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify the exact executable payload used by Windows release packages."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile


EXPECTED_EXECUTABLES = (
    "blackcoin-cli.exe",
    "blackcoin-qt.exe",
    "blackcoin-tx.exe",
    "blackcoin-util.exe",
    "blackcoin-wallet.exe",
    "blackcoind.exe",
)
FORBIDDEN_EXECUTABLES = frozenset({"test_blackcoin.exe"})


def _require_exact_names(names, context):
    names = list(names)
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise RuntimeError(f"{context} contains duplicate entries: {', '.join(duplicates)}")

    actual = set(names)
    expected = set(EXPECTED_EXECUTABLES)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        raise RuntimeError(f"{context} is missing required executables: {', '.join(missing)}")
    if unexpected:
        raise RuntimeError(f"{context} contains unexpected entries: {', '.join(unexpected)}")


def verify_directory(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"portable payload is not a directory: {root}")

    names = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError(f"portable payload entry must be a regular file: {entry.name}")
        names.append(entry.name)
    _require_exact_names(names, "portable payload directory")
    return tuple(root / name for name in EXPECTED_EXECUTABLES)


def verify_archive(archive):
    archive = Path(archive).resolve(strict=True)
    with zipfile.ZipFile(archive) as zipped:
        names = []
        for entry in zipped.infolist():
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if entry.is_dir() or stat.S_ISLNK(mode):
                raise RuntimeError(f"portable archive entry must be a regular file: {entry.filename}")
            if path.is_absolute() or len(path.parts) != 1 or path.name != entry.filename:
                raise RuntimeError(f"portable archive entry must be a flat filename: {entry.filename}")
            names.append(entry.filename)
    _require_exact_names(names, "portable archive")
    return tuple(EXPECTED_EXECUTABLES)


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_installer_extraction(extracted_root, portable_root):
    extracted_root = Path(extracted_root).resolve(strict=True)
    portable_root = Path(portable_root).resolve(strict=True)
    portable_paths = {path.name: path for path in verify_directory(portable_root)}

    found = {}
    for entry in sorted(extracted_root.rglob("*")):
        if entry.is_symlink():
            raise RuntimeError(f"installer extraction contains a symbolic link: {entry}")
        if not entry.is_file():
            continue
        lower_name = entry.name.lower()
        if lower_name in FORBIDDEN_EXECUTABLES:
            raise RuntimeError(f"installer contains forbidden test executable: {entry}")
        if lower_name not in EXPECTED_EXECUTABLES:
            if lower_name.startswith("blackcoin") and lower_name.endswith(".exe"):
                raise RuntimeError(f"installer contains unexpected Blackcoin executable: {entry}")
            continue
        if entry.name != lower_name:
            raise RuntimeError(f"installer executable has unexpected case: {entry}")
        if lower_name in found:
            raise RuntimeError(f"installer contains duplicate executable {lower_name}")
        found[lower_name] = entry

    _require_exact_names(found, "installer payload")
    for name in EXPECTED_EXECUTABLES:
        portable = portable_paths[name]
        installed = found[name]
        if portable.stat().st_size != installed.stat().st_size or _sha256(portable) != _sha256(installed):
            raise RuntimeError(f"installer payload differs from signed portable executable: {name}")
    return tuple(found[name] for name in EXPECTED_EXECUTABLES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("names", help="print the required portable executable names")
    directory = subparsers.add_parser("directory", help="verify an extracted portable payload")
    directory.add_argument("path", type=Path)
    archive = subparsers.add_parser("archive", help="verify a portable zip inventory")
    archive.add_argument("path", type=Path)
    installer = subparsers.add_parser("installer", help="verify extracted installer payload bytes")
    installer.add_argument("path", type=Path)
    installer.add_argument("--portable-dir", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "names":
        print("\n".join(EXPECTED_EXECUTABLES))
    elif args.command == "directory":
        verify_directory(args.path)
        print(f"Verified {len(EXPECTED_EXECUTABLES)} portable executable(s)")
    elif args.command == "archive":
        verify_archive(args.path)
        print(f"Verified {len(EXPECTED_EXECUTABLES)} portable archive member(s)")
    else:
        print("\n".join(str(path) for path in verify_installer_extraction(args.path, args.portable_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
