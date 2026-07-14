#!/usr/bin/env python3
"""Verify pinned quantum-cryptography source archives and local vendored files."""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path
import re
import urllib.parse
import urllib.request


ALLOWED_UPSTREAM_HOSTS = {"codeload.github.com", "raw.githubusercontent.com"}
MAX_UPSTREAM_BYTES = 128 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def check_hash(label: str, actual: str, expected: str) -> None:
    if not SHA256_RE.fullmatch(expected):
        raise SystemExit(f"{label}: invalid expected SHA-256")
    if actual != expected:
        raise SystemExit(f"{label}: expected {expected}, got {actual}")


def verify_archive(path: Path, component: dict) -> dict:
    archive_sha256 = sha256_file(path)
    check_hash(str(path), archive_sha256, component["archive_sha256"])
    verified_files = {}
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
            actual = sha256_bytes(extracted.read())
            check_hash(f"{path}:{relative}", actual, expected)
            verified_files[relative] = actual
    return {"archive_sha256": archive_sha256, "files": verified_files}


def verify_local_files(root: Path, component: dict) -> dict:
    verified = {}
    for relative, expected in component.get("local_files", {}).items():
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            raise SystemExit(f"unsafe local provenance path: {relative}")
        path = root / relative_path
        if not path.is_file():
            raise SystemExit(f"missing local provenance file: {path}")
        actual = sha256_file(path)
        check_hash(str(path), actual, expected)
        verified[relative] = actual
    return verified


def download_pinned(url: str, expected_sha256: str, destination: Path) -> Path:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_UPSTREAM_HOSTS:
        raise SystemExit(f"untrusted upstream URL: {url}")
    check_hash(url, expected_sha256, expected_sha256)

    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(destination.name + ".part")
    partial.unlink(missing_ok=True)
    request = urllib.request.Request(
        url, headers={"User-Agent": "Blackcoin-v30.1.1-crypto-provenance"}
    )
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=120) as response, partial.open("wb") as output:
            final_url = urllib.parse.urlparse(response.geturl())
            if final_url.scheme != "https" or final_url.hostname not in ALLOWED_UPSTREAM_HOSTS:
                raise SystemExit(f"upstream redirected to an untrusted URL: {response.geturl()}")
            declared_size = response.headers.get("Content-Length")
            if declared_size is not None and int(declared_size) > MAX_UPSTREAM_BYTES:
                raise SystemExit(f"upstream object exceeds {MAX_UPSTREAM_BYTES} bytes: {url}")
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPSTREAM_BYTES:
                    raise SystemExit(f"upstream object exceeds {MAX_UPSTREAM_BYTES} bytes: {url}")
                digest.update(chunk)
                output.write(chunk)
        check_hash(url, digest.hexdigest(), expected_sha256)
        partial.replace(destination)
    finally:
        partial.unlink(missing_ok=True)
    return destination


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schema") != 1:
        raise SystemExit("unsupported provenance manifest schema")
    for name in ("liboqs", "argon2", "wycheproof"):
        if not isinstance(manifest.get(name), dict):
            raise SystemExit(f"missing provenance component: {name}")
    for name in ("liboqs", "argon2"):
        component = manifest[name]
        if not component.get("archive_url") or not component.get("upstream_files"):
            raise SystemExit(f"incomplete archive provenance component: {name}")
        if not SHA256_RE.fullmatch(component.get("archive_sha256", "")):
            raise SystemExit(f"{name} archive: invalid expected SHA-256")
    wycheproof = manifest["wycheproof"]
    if not wycheproof.get("source_url"):
        raise SystemExit("incomplete source provenance component: wycheproof")
    if not SHA256_RE.fullmatch(wycheproof.get("source_sha256", "")):
        raise SystemExit("wycheproof source: invalid expected SHA-256")


def write_evidence(path: Path, manifest_path: Path, repo_root: Path,
                   local: dict, upstream: dict) -> None:
    try:
        recorded_manifest = str(manifest_path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        recorded_manifest = manifest_path.name
    evidence = {
        "schema": 1,
        "manifest": {
            "path": recorded_manifest,
            "sha256": sha256_file(manifest_path),
        },
        "local": local,
        "upstream": upstream,
        "complete": set(upstream) == {"liboqs", "argon2", "wycheproof"},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path,
                        default=Path(__file__).with_name("quantum-crypto-provenance.json"))
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[2])
    parser.add_argument("--liboqs-archive", type=Path)
    parser.add_argument("--argon2-archive", type=Path)
    parser.add_argument("--wycheproof-json", type=Path)
    parser.add_argument("--fetch-upstream", type=Path,
                        help="download all three pinned upstream objects into this directory")
    parser.add_argument("--require-upstream", action="store_true",
                        help="fail unless all three upstream objects are verified")
    parser.add_argument("--evidence", type=Path,
                        help="write a machine-readable verification record")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validate_manifest(manifest)

    explicit = (args.liboqs_archive, args.argon2_archive, args.wycheproof_json)
    if args.fetch_upstream and any(explicit):
        raise SystemExit("--fetch-upstream cannot be combined with explicit upstream paths")
    if args.fetch_upstream:
        args.liboqs_archive = download_pinned(
            manifest["liboqs"]["archive_url"],
            manifest["liboqs"]["archive_sha256"],
            args.fetch_upstream / "liboqs.tar.gz",
        )
        args.argon2_archive = download_pinned(
            manifest["argon2"]["archive_url"],
            manifest["argon2"]["archive_sha256"],
            args.fetch_upstream / "argon2.tar.gz",
        )
        args.wycheproof_json = download_pinned(
            manifest["wycheproof"]["source_url"],
            manifest["wycheproof"]["source_sha256"],
            args.fetch_upstream / "mldsa_44_verify_test.json",
        )

    local = {
        "argon2": verify_local_files(args.repo_root, manifest["argon2"]),
        "wycheproof": verify_local_files(args.repo_root, manifest["wycheproof"]),
    }
    upstream = {}
    if args.liboqs_archive:
        upstream["liboqs"] = verify_archive(args.liboqs_archive, manifest["liboqs"])
    if args.argon2_archive:
        upstream["argon2"] = verify_archive(args.argon2_archive, manifest["argon2"])
    if args.wycheproof_json:
        actual = sha256_file(args.wycheproof_json)
        check_hash(str(args.wycheproof_json), actual,
                   manifest["wycheproof"]["source_sha256"])
        upstream["wycheproof"] = {"source_sha256": actual}
    if args.require_upstream and set(upstream) != {"liboqs", "argon2", "wycheproof"}:
        raise SystemExit("complete liboqs, Argon2, and Wycheproof provenance is required")
    if args.evidence:
        write_evidence(args.evidence, args.manifest, args.repo_root, local, upstream)

    print("quantum cryptography source provenance verified")


if __name__ == "__main__":
    main()
