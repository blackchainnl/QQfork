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


def load_dependency_manifest(path, depends_packages):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot load dependency manifest: {error}") from error
    if document.get("schema") != 1:
        raise RuntimeError("dependency manifest schema must be 1")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise RuntimeError("dependency manifest has no dependency records")

    by_name = {}
    expected_recipes = set()
    for dependency in dependencies:
        name = dependency.get("package")
        version = dependency.get("version")
        recipe = dependency.get("recipe")
        if not isinstance(name, str) or not name or name in by_name:
            raise RuntimeError("dependency manifest package names must be unique")
        if not isinstance(version, str) or not version or "$" in version:
            raise RuntimeError(f"dependency {name} has an unresolved version")
        if not isinstance(recipe, str) or Path(recipe).parent.name != "packages":
            raise RuntimeError(f"dependency {name} has an invalid recipe path")
        if not (depends_packages / Path(recipe).name).is_file():
            raise RuntimeError(f"dependency {name} recipe does not exist")
        sources = dependency.get("sources")
        if not isinstance(sources, list):
            raise RuntimeError(f"dependency {name} sources must be a list")
        for source in sources:
            if not isinstance(source.get("url"), str) or not source["url"].startswith("https://"):
                raise RuntimeError(f"dependency {name} source URL must use HTTPS")
            if not SHA256_RE.fullmatch(source.get("sha256", "")):
                raise RuntimeError(f"dependency {name} source checksum is invalid")
        by_name[name] = dependency
        expected_recipes.add(Path(recipe).name)

    actual_recipes = {path.name for path in depends_packages.glob("*.mk") if path.name != "packages.mk"}
    if actual_recipes != expected_recipes:
        raise RuntimeError("dependency manifest recipe inventory is incomplete")
    for name, dependency in by_name.items():
        alias = dependency.get("source_alias")
        if alias is None:
            if not dependency["sources"]:
                raise RuntimeError(f"dependency {name} has no source archive")
            continue
        if alias not in by_name or by_name[alias].get("source_alias") is not None:
            raise RuntimeError(f"dependency {name} has an invalid source alias")
        if dependency["version"] != by_name[alias]["version"]:
            raise RuntimeError(f"dependency {name} alias version differs from {alias}")
    return dependencies, by_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--depends-packages", required=True, type=Path)
    parser.add_argument("--dependency-manifest", required=True, type=Path)
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

    dependencies, dependencies_by_name = load_dependency_manifest(
        args.dependency_manifest, args.depends_packages
    )
    for dependency in sorted(dependencies, key=lambda record: record["package"]):
        name = dependency["package"]
        version = dependency["version"]
        source_owner = dependencies_by_name[dependency.get("source_alias", name)]
        sources = source_owner["sources"]
        primary = sources[0]
        package_id = spdx_id("Dependency", f"{name}@{version}")
        package = make_package(
            name=name,
            package_id=package_id,
            version=version,
            download_location=primary["url"],
            checksums=[{"algorithm": "SHA256", "checksumValue": primary["sha256"]}],
        )
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
        for position, source in enumerate(sources[1:], start=2):
            source_name = f"{name} source archive {position}: {Path(source['url']).name}"
            source_id = spdx_id("DependencySource", f"{name}@{version}:{source['url']}")
            packages.append(
                make_package(
                    name=source_name,
                    package_id=source_id,
                    version=version,
                    download_location=source["url"],
                    checksums=[{"algorithm": "SHA256", "checksumValue": source["sha256"]}],
                )
            )
            relationships.append(
                {
                    "spdxElementId": package_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": source_id,
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
