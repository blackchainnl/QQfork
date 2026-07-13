#!/usr/bin/env python3
"""Verify pinned quantum-cryptography source archives and local vendored files."""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def check_hash(label: str, actual: str, expected: str) -> None:
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected}, got {actual}")


def verify_archive(path: Path, component: dict) -> None:
    check_hash(str(path), sha256_file(path), component["archive_sha256"])
    with tarfile.open(path, "r:gz") as archive:
        regular_files = {
            member.name: member for member in archive.getmembers() if member.isfile()
        }
        for relative, expected in component["upstream_files"].items():
            matches = [name for name in regular_files if name.endswith("/" + relative)]
            if len(matches) != 1:
                raise SystemExit(f"{path}: expected one archive member ending in {relative}, got {matches}")
            extracted = archive.extractfile(regular_files[matches[0]])
            if extracted is None:
                raise SystemExit(f"{path}: cannot read {matches[0]}")
            check_hash(f"{path}:{relative}", sha256_bytes(extracted.read()), expected)


def verify_local_files(root: Path, component: dict) -> None:
    for relative, expected in component.get("local_files", {}).items():
        path = root / relative
        if not path.is_file():
            raise SystemExit(f"missing local provenance file: {path}")
        check_hash(str(path), sha256_file(path), expected)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).with_name("quantum-crypto-provenance.json"))
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--liboqs-archive", type=Path)
    parser.add_argument("--argon2-archive", type=Path)
    parser.add_argument("--wycheproof-json", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1:
        raise SystemExit("unsupported provenance manifest schema")

    verify_local_files(args.repo_root, manifest["argon2"])
    verify_local_files(args.repo_root, manifest["wycheproof"])
    if args.liboqs_archive:
        verify_archive(args.liboqs_archive, manifest["liboqs"])
    if args.argon2_archive:
        verify_archive(args.argon2_archive, manifest["argon2"])
    if args.wycheproof_json:
        check_hash(str(args.wycheproof_json), sha256_file(args.wycheproof_json),
                   manifest["wycheproof"]["source_sha256"])

    print("quantum cryptography source provenance verified")


if __name__ == "__main__":
    main()
