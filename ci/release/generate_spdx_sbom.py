#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate a deterministic SPDX 2.3 SBOM for release artifacts and depends inputs."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys


FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def sha256(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def spdx_id(kind, value):
    safe = re.sub(r"[^A-Za-z0-9.-]", "-", value).strip("-.") or "item"
    suffix = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-{kind}-{safe[:80]}-{suffix}"


def make_package(name, package_id, version, download_location, checksums=None, license_declared="NOASSERTION"):
    package = {
        "SPDXID": package_id,
        "name": name,
        "versionInfo": version,
        "downloadLocation": download_location,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": license_declared,
        "copyrightText": "NOASSERTION",
    }
    if checksums:
        package["checksums"] = checksums
    return package


def parse_depends_package(path):
    values = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"package\s*=\s*([^\s#]+)", line)
        if match:
            values["name"] = match.group(1)
            continue
        match = re.fullmatch(r"\$\(package\)_version\s*=\s*([^\s#]+)", line)
        if match:
            values["version"] = match.group(1)
            continue
        match = re.fullmatch(r"\$\(package\)_sha256_hash\s*=\s*([0-9a-fA-F]{64})", line)
        if match:
            values["sha256"] = match.group(1).lower()
    if "name" not in values:
        return None
    version = values.get("version", "NOASSERTION")
    if "$" in version:
        version = "NOASSERTION"
    checksum = values.get("sha256")
    checksums = [{"algorithm": "SHA256", "checksumValue": checksum}] if checksum else None
    package_id = spdx_id("Dependency", f"{values['name']}@{version}")
    return make_package(
        name=values["name"],
        package_id=package_id,
        version=version,
        download_location="NOASSERTION",
        checksums=checksums,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--depends-packages", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    if not FULL_SHA_RE.fullmatch(args.source_sha):
        raise RuntimeError("source-sha must be a full lowercase commit identifier")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        raise RuntimeError("version must have major.minor.patch form")
    if not args.artifacts.is_dir() or not args.depends_packages.is_dir():
        raise RuntimeError("artifact and depends package directories must exist")

    created = datetime.fromtimestamp(args.source_date_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    namespace = (
        f"https://github.com/Blackcoin-Dev/Blackcoin/releases/download/v{args.version}/"
        f"spdx-{args.source_sha}"
    )
    root_id = spdx_id("Package", f"Blackcoin-Core-{args.version}-{args.source_sha}")
    packages = [
        make_package(
            name="Blackcoin Core",
            package_id=root_id,
            version=args.version,
            download_location=f"https://github.com/Blackcoin-Dev/Blackcoin/tree/{args.source_sha}",
            checksums=None,
            license_declared="MIT",
        )
    ]
    relationships = []

    artifact_paths = []
    for path in sorted(args.artifacts.iterdir()):
        if path == args.output or (
            path.name.startswith("Blackcoin-") and path.name.endswith("-SBOM.spdx.json")
        ):
            continue
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"release artifact must be a regular file: {path}")
        artifact_paths.append(path)
    if not artifact_paths:
        raise RuntimeError("no release artifacts were found for the SBOM")

    for path in artifact_paths:
        checksum = sha256(path)
        if not SHA256_RE.fullmatch(checksum):
            raise RuntimeError(f"invalid artifact checksum for {path.name}")
        artifact_id = spdx_id("Artifact", path.name)
        packages.append(
            make_package(
                name=path.name,
                package_id=artifact_id,
                version=args.version,
                download_location=(
                    f"https://github.com/Blackcoin-Dev/Blackcoin/releases/download/"
                    f"v{args.version}/{path.name}"
                ),
                checksums=[{"algorithm": "SHA256", "checksumValue": checksum}],
            )
        )
        relationships.append(
            {"spdxElementId": root_id, "relationshipType": "CONTAINS", "relatedSpdxElement": artifact_id}
        )

    seen_dependencies = set()
    for path in sorted(args.depends_packages.glob("*.mk")):
        package = parse_depends_package(path)
        if package is None or package["SPDXID"] in seen_dependencies:
            continue
        seen_dependencies.add(package["SPDXID"])
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package["SPDXID"],
            }
        )

    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"Blackcoin-Core-{args.version}-release-SBOM",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": created,
            "creators": ["Organization: Blackcoin-Dev"],
        },
        "documentDescribes": [root_id],
        "packages": packages,
        "relationships": relationships,
    }
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote SPDX SBOM with {len(packages)} package record(s) to {args.output}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"SBOM generation failed: {error}", file=sys.stderr)
        sys.exit(1)
