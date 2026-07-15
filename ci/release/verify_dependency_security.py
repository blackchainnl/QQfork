#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail closed when dependency, advisory, capability, or provenance evidence drifts."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_DISPOSITIONS = {"mitigated", "not-built", "not-applicable", "deferred"}
ALLOWED_LEGACY_DISPOSITIONS = {"ported", "equivalent", "incompatible", "deferred"}
EXPECTED_BASELINES = {
    "v30_1_0": "f647dc75c9479c03e81414f145a8d233b60959c7",
    "v30_1_1_audit_base": "7fde566f5f564e43f4c2d76502bd7e43c819e35f",
    "legacy_v26_2_0": "b54edb619b0d42df4b3a73a29b02d9eb885516d5",
    "active_legacy_v28_4_0": "c2455cdd6f43756fbca137a83d9d168dae4eb442",
}
CRC32C_ARM64_BACKPORT = "d3d60ac6e0f16780bcfcc825385e1d338801a558"
CRC32C_ARM64_BACKPORT_FILES = {
    "src/crc32c/src/crc32c_arm64.cc",
    "src/crc32c/src/crc32c_read_le.h",
    "src/crc32c/src/crc32c_read_le_unittest.cc",
}


def fail(message):
    raise RuntimeError(message)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        fail(message)


def load_document(path):
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot load dependency security manifest {path}: {error}")
    require(document.get("schema") == 1, "dependency security manifest schema must be 1")
    return document


def tracked_tree_sha256(root, prefix):
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", prefix],
        check=True,
        stdout=subprocess.PIPE,
    )
    digest = hashlib.sha256()
    paths = sorted(path.decode("utf-8") for path in result.stdout.split(b"\0") if path)
    require(paths, f"vendored component has no tracked files: {prefix}")
    for relative in paths:
        content = (root / relative).read_bytes()
        digest.update(relative.encode("utf-8") + b"\0" + hashlib.sha256(content).digest())
    return digest.hexdigest()


def verify_sources(root, document):
    dependencies = document.get("dependencies")
    require(isinstance(dependencies, list) and dependencies, "dependencies must be a non-empty list")
    by_name = {}
    recipes = set()
    for dependency in dependencies:
        name = dependency.get("package")
        require(isinstance(name, str) and name, "every dependency needs a package name")
        require(name not in by_name, f"duplicate dependency package: {name}")
        by_name[name] = dependency

        recipe = dependency.get("recipe")
        require(isinstance(recipe, str) and recipe.startswith("depends/packages/"),
                f"{name}: invalid recipe path")
        require(recipe not in recipes, f"duplicate dependency recipe: {recipe}")
        recipes.add(recipe)
        recipe_path = root / recipe
        require(recipe_path.is_file(), f"{name}: missing recipe {recipe}")
        expected_recipe_hash = dependency.get("recipe_sha256")
        require(SHA256_RE.fullmatch(expected_recipe_hash or "") is not None,
                f"{name}: recipe_sha256 must be a full lowercase SHA-256")
        require(sha256(recipe_path) == expected_recipe_hash,
                f"{name}: recipe changed without a manifest review")

        version = dependency.get("version")
        require(isinstance(version, str) and version and "$" not in version,
                f"{name}: unresolved version")
        recipe_text = recipe_path.read_text(encoding="utf-8")
        require(re.search(rf"^package={re.escape(name)}$", recipe_text, re.MULTILINE) is not None,
                f"{name}: recipe package assignment does not match")

        alias = dependency.get("source_alias")
        sources = dependency.get("sources")
        require(isinstance(sources, list), f"{name}: sources must be a list")
        if alias is None:
            require(sources, f"{name}: dependency source is not pinned")
            require(
                re.search(
                    rf"^\$\(package\)_version\s*=\s*{re.escape(version)}$",
                    recipe_text,
                    re.MULTILINE,
                ) is not None,
                f"{name}: manifest version does not match recipe",
            )
        else:
            require(not sources, f"{name}: aliased source must not duplicate source records")
            require(isinstance(alias, str) and alias, f"{name}: invalid source alias")

        source_hashes = set()
        for source in sources:
            url = source.get("url")
            checksum = source.get("sha256")
            require(isinstance(url, str) and url.startswith("https://") and " " not in url,
                    f"{name}: source URL must use HTTPS")
            require(SHA256_RE.fullmatch(checksum or "") is not None,
                    f"{name}: source needs a full lowercase SHA-256")
            require(checksum not in source_hashes, f"{name}: duplicate source checksum")
            source_hashes.add(checksum)

        literal_recipe_hashes = set(
            re.findall(r"^\$\(package\)_[A-Za-z0-9_]*sha256_hash\s*=\s*([0-9a-f]{64})$",
                       recipe_text, re.MULTILINE)
        )
        if alias is None:
            require(literal_recipe_hashes == source_hashes,
                    f"{name}: manifest source hashes do not exactly match recipe hashes")
        else:
            require(not literal_recipe_hashes,
                    f"{name}: alias recipe unexpectedly contains a literal source hash")

    for name, dependency in by_name.items():
        alias = dependency.get("source_alias")
        if alias is None:
            continue
        require(alias in by_name, f"{name}: source alias does not exist: {alias}")
        require(by_name[alias].get("source_alias") is None,
                f"{name}: chained source aliases are forbidden")
        require(dependency["version"] == by_name[alias]["version"],
                f"{name}: alias version differs from {alias}")

    package_index = document.get("package_index_recipe", {})
    index_path = package_index.get("path")
    index_hash = package_index.get("sha256")
    require(index_path == "depends/packages/packages.mk", "unexpected package index recipe")
    require(SHA256_RE.fullmatch(index_hash or "") is not None,
            "package index needs a full lowercase SHA-256")
    require(sha256(root / index_path) == index_hash,
            "package index changed without a manifest review")

    actual_recipes = {
        path.relative_to(root).as_posix()
        for path in (root / "depends/packages").glob("*.mk")
    }
    expected_recipes = recipes | {index_path}
    require(actual_recipes == expected_recipes,
            "depends recipe inventory differs from the dependency security manifest")
    return by_name


def verify_constraints(root, document):
    constraints = document.get("build_constraints", {})
    for package in ("liboqs", "qt"):
        recipe_text = (root / f"depends/packages/{package}.mk").read_text(encoding="utf-8")
        package_constraints = constraints.get(package, {})
        required = package_constraints.get("required")
        require(isinstance(required, list) and required,
                f"{package}: required build constraints are missing")
        for fragment in required:
            require(recipe_text.count(fragment) >= 1,
                    f"{package}: required build constraint is missing: {fragment}")
        for fragment in package_constraints.get("forbidden", []):
            require(fragment not in recipe_text,
                    f"{package}: forbidden algorithm entered the recipe: {fragment}")

    qt_constraints = constraints["qt"]
    qt_sources = document["dependencies"][[d["package"] for d in document["dependencies"]].index("qt")]["sources"]
    source_modules = {Path(source["url"]).name.split("-everywhere", 1)[0] for source in qt_sources}
    require(source_modules == set(qt_constraints.get("allowed_source_modules", [])),
            "Qt source module inventory differs from the reviewed set")
    for module in qt_constraints.get("forbidden_source_modules", []):
        require(module not in source_modules, f"forbidden Qt source module is present: {module}")


def verify_dispositions(root, document, dependency_names):
    for section in ("dependency_advisories", "bitcoin_core_advisories"):
        records = document.get(section)
        require(isinstance(records, list) and records, f"{section} must be a non-empty list")
        seen = set()
        for record in records:
            identifier = record.get("id")
            require(isinstance(identifier, str) and identifier,
                    f"{section}: advisory identifier is missing")
            require(identifier not in seen, f"{section}: duplicate advisory identifier {identifier}")
            seen.add(identifier)
            disposition = record.get("disposition")
            require(disposition in ALLOWED_DISPOSITIONS,
                    f"{identifier}: invalid advisory disposition")
            require(isinstance(record.get("reason"), str) and record["reason"],
                    f"{identifier}: advisory reason is missing")
            require(isinstance(record.get("source"), str) and record["source"].startswith("https://"),
                    f"{identifier}: primary source URL is missing")
            if section == "dependency_advisories":
                require(record.get("package") in dependency_names,
                        f"{identifier}: dependency advisory package is not inventoried")
            if disposition == "deferred":
                for field in ("risk", "owner", "target"):
                    require(isinstance(record.get(field), str) and record[field],
                            f"{identifier}: deferred advisory lacks {field}")

    legacy = document.get("legacy_delta_dispositions")
    require(isinstance(legacy, list) and legacy, "legacy delta dispositions are missing")
    seen_commits = set()
    for record in legacy:
        commit = record.get("commit")
        require(COMMIT_RE.fullmatch(commit or "") is not None,
                "legacy delta commit must be a full lowercase identifier")
        require(commit not in seen_commits, f"duplicate legacy delta commit: {commit}")
        seen_commits.add(commit)
        disposition = record.get("disposition")
        require(disposition in ALLOWED_LEGACY_DISPOSITIONS,
                f"{commit}: invalid legacy disposition")
        require(isinstance(record.get("risk"), str) and record["risk"],
                f"{commit}: risk statement is missing")
        evidence = record.get("evidence")
        require(isinstance(evidence, list) and evidence,
                f"{commit}: evidence is missing")
        for relative in evidence:
            require((root / relative).is_file(), f"{commit}: evidence path does not exist: {relative}")
        if disposition == "deferred":
            for field in ("owner", "target"):
                require(isinstance(record.get(field), str) and record[field],
                        f"{commit}: deferred legacy delta lacks {field}")


def verify_delta_and_vendored(root, document, dependencies):
    delta = document.get("dependency_delta")
    require(isinstance(delta, list), "dependency delta must be a list")
    delta_packages = [record.get("package") for record in delta]
    require(len(delta_packages) == len(set(delta_packages)),
            "dependency delta contains duplicate packages")
    require(set(delta_packages) == set(dependencies),
            "dependency delta must compare every candidate dependency")
    comparisons = {record["package"]: record for record in delta}
    for record in delta:
        package = record["package"]
        require(record.get("candidate") == dependencies[package]["version"],
                f"{package}: candidate delta does not match inventory")
        require(isinstance(record.get("v30_1_0"), str) and record["v30_1_0"],
                f"{package}: v30_1_0 version is missing")
        active_legacy = record.get("active_legacy")
        require(active_legacy is None or (isinstance(active_legacy, str) and active_legacy),
                f"{package}: active_legacy version must be a version or null")

    for package, dependency in dependencies.items():
        alias = dependency.get("source_alias")
        if alias is None:
            continue
        for baseline in ("v30_1_0", "active_legacy"):
            require(comparisons[package][baseline] == comparisons[alias][baseline],
                    f"{package}: {baseline} alias version differs from {alias}")

    lagging_active_legacy = {
        package
        for package, record in comparisons.items()
        if record["active_legacy"] is not None
        and record["candidate"] == record["v30_1_0"]
        and record["candidate"] != record["active_legacy"]
    }
    update_dispositions = document.get("dependency_update_dispositions")
    require(isinstance(update_dispositions, list),
            "dependency update dispositions must be a list")
    covered = set()
    for record in update_dispositions:
        package = record.get("package")
        require(package in dependencies, "dependency update disposition package is unknown")
        covers = record.get("covers")
        require(isinstance(covers, list), f"{package}: covers must be a list")
        names = {package, *covers}
        require(names <= set(dependencies), f"{package}: disposition covers an unknown package")
        require(not (covered & names), f"{package}: dependency update disposition overlaps")
        covered |= names
        require(record.get("disposition") == "deferred",
                f"{package}: unresolved active-legacy delta must be deferred")
        for field in ("risk", "owner", "target"):
            require(isinstance(record.get(field), str) and record[field],
                    f"{package}: dependency update disposition lacks {field}")
        require(isinstance(record.get("source"), str) and record["source"].startswith("https://"),
                f"{package}: dependency update disposition lacks a primary comparison URL")
    require(covered == lagging_active_legacy,
            "active-legacy dependency deltas lack exact dispositions")

    vendored = document.get("vendored_components")
    require(isinstance(vendored, list) and vendored, "vendored component review is missing")
    vendored_by_name = {component.get("package"): component for component in vendored}
    require(len(vendored_by_name) == len(vendored),
            "vendored component review contains duplicate packages")
    require(set(vendored_by_name) == {"secp256k1", "crc32c"},
            "vendored component inventory must contain secp256k1 and crc32c")

    secp256k1 = vendored_by_name["secp256k1"]
    expected_hash = secp256k1.get("tracked_tree_sha256")
    require(SHA256_RE.fullmatch(expected_hash or "") is not None,
            "secp256k1 tracked tree hash is invalid")
    require(tracked_tree_sha256(root, "src/secp256k1/") == expected_hash,
            "vendored secp256k1 tree changed without a manifest review")
    require(secp256k1.get("disposition") == "deferred",
            "secp256k1 0.5.1 delta must retain an explicit disposition")
    for field in ("risk", "owner", "target"):
        require(isinstance(secp256k1.get(field), str) and secp256k1[field],
                f"secp256k1 disposition lacks {field}")

    crc32c = vendored_by_name["crc32c"]
    require(crc32c.get("upstream_commit") == CRC32C_ARM64_BACKPORT,
            "crc32c ARM64 backport commit differs from the reviewed upstream fix")
    require(crc32c.get("source") ==
            f"https://github.com/google/crc32c/commit/{CRC32C_ARM64_BACKPORT}",
            "crc32c ARM64 backport must link the exact upstream commit")
    require(crc32c.get("disposition") == "backported",
            "crc32c ARM64 alignment fix must remain an explicit backport")
    require(isinstance(crc32c.get("reason"), str) and crc32c["reason"],
            "crc32c ARM64 backport reason is missing")
    tracked_files = crc32c.get("tracked_files")
    require(isinstance(tracked_files, list),
            "crc32c ARM64 backport tracked-file inventory is missing")
    by_path = {record.get("path"): record for record in tracked_files}
    require(len(by_path) == len(tracked_files),
            "crc32c ARM64 backport contains duplicate tracked files")
    require(set(by_path) == CRC32C_ARM64_BACKPORT_FILES,
            "crc32c ARM64 backport tracked-file inventory differs")
    for relative, record in by_path.items():
        expected_file_hash = record.get("sha256")
        require(SHA256_RE.fullmatch(expected_file_hash or "") is not None,
                f"crc32c ARM64 backport hash is invalid: {relative}")
        require(sha256(root / relative) == expected_file_hash,
                f"crc32c ARM64 backport file changed without review: {relative}")


def verify_capability_and_lifetime(root):
    required_fragments = {
        "src/protocol.h": ["NODE_QUANTUM_QUASAR = (1ULL << 24)"],
        "src/protocol.cpp": ['case NODE_QUANTUM_QUASAR:  return "QUANTUM_QUASAR";'],
        "src/init.cpp": ["NODE_WITNESS | NODE_QUANTUM_QUASAR"],
        "test/functional/test_framework/messages.py": ["NODE_QUANTUM_QUASAR = (1 << 24)"],
        "test/functional/rpc_net.py": [
            "legacy_services = test_framework.messages.NODE_NETWORK",
            "quantum_services = legacy_services | test_framework.messages.NODE_QUANTUM_QUASAR",
        ],
        "src/test/netbase_tests.cpp": ["NODE_NETWORK | NODE_QUANTUM_QUASAR"],
    }
    for relative, fragments in required_fragments.items():
        text = (root / relative).read_text(encoding="utf-8")
        for fragment in fragments:
            require(fragment in text, f"capability evidence missing from {relative}: {fragment}")

    validation = (root / "src/validation.cpp").read_text(encoding="utf-8")
    connect_start = validation.find("bool Chainstate::ConnectBlock(")
    require(connect_start >= 0, "ConnectBlock definition is missing")
    txdata = validation.find("std::vector<PrecomputedTransactionData> txsdata(block.vtx.size());", connect_start)
    control = validation.find("CCheckQueueControl<CScriptCheck> control(", connect_start)
    require(connect_start < txdata < control,
            "CVE-2024-52911 mitigation drift: txsdata must be constructed before control")
    require("preallocate the vector size" in validation[connect_start:control],
            "CVE-2024-52911 lifetime rationale is missing")


def verify_provenance(root, document):
    record = document.get("provenance", {})
    path = root / record.get("manifest", "")
    require(path.is_file(), "copyright provenance manifest is missing")
    require(SHA256_RE.fullmatch(record.get("sha256", "")) is not None,
            "copyright provenance SHA-256 is invalid")
    require(sha256(path) == record["sha256"],
            "copyright provenance manifest changed without review")
    provenance = json.loads(path.read_text(encoding="utf-8"))
    for field in ("schema", "current_revision", "legacy_revision"):
        require(provenance.get(field) == record.get(field),
                f"copyright provenance {field} differs from review")
    for manifest_field, expected_field in (
        ("restored", "restored_count"),
        ("excluded", "excluded_count"),
        ("ambiguous", "ambiguous_count"),
    ):
        require(len(provenance.get(manifest_field, [])) == record.get(expected_field),
                f"copyright provenance {manifest_field} count differs from review")


def verify_documentation(root):
    audit = (root / "doc/v30.1.1-dependency-security-audit.md").read_text(encoding="utf-8")
    release_notes = (root / "doc/release-notes.md").read_text(encoding="utf-8")
    manifest_path = "ci/release/dependency-security-manifest.json"
    require(manifest_path in audit, "dependency audit does not link the enforced manifest")
    require("v30.1.1-dependency-security-audit.md" in release_notes,
            "release notes do not link the dependency audit")
    for marker in (
        "CVE-2024-52911",
        "CVE-2026-44518",
        "CVE-2026-46344",
        "all 31 candidate recipes",
        "libnatpmp",
        "bitcoin-core/libmultiprocess",
        CRC32C_ARM64_BACKPORT,
    ):
        require(marker in audit, f"dependency audit is missing {marker}")


def verify(root, manifest_path):
    document = load_document(manifest_path)
    require(document.get("baselines") == EXPECTED_BASELINES,
            "dependency audit baselines differ from the immutable review revisions")
    dependencies = verify_sources(root, document)
    verify_constraints(root, document)
    verify_delta_and_vendored(root, document, dependencies)
    verify_dispositions(root, document, set(dependencies))
    verify_capability_and_lifetime(root)
    verify_provenance(root, document)
    verify_documentation(root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest or root / "ci/release/dependency-security-manifest.json"
    verify(root, manifest.resolve())
    print("Dependency, advisory, capability, and provenance evidence verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Dependency security verification failed: {error}", file=sys.stderr)
        sys.exit(1)
