#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Build exact, provenance-checked binaries for mixed-version tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request


BINARIES = ("blackcoind", "blackcoin-cli")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")


def run(command, *, cwd=None, capture=False):
    print("+", " ".join(str(part) for part in command), flush=True)
    completed = subprocess.run(
        [str(part) for part in command],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout if capture else None


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path):
    data = json.loads(path.read_text(encoding="utf8"))
    if data.get("schema") != 1 or not data.get("sources"):
        raise ValueError("unsupported or empty mixed-version source manifest")
    required = {
        "version", "install_dir", "repository", "source_ref",
        "ref_object", "commit", "tag_kind", "source_daemon", "source_cli",
    }
    for source in data["sources"]:
        missing = required.difference(source)
        if missing:
            raise ValueError(f"{source.get('version', '<unknown>')} missing {sorted(missing)}")
        if not SHA1_RE.fullmatch(source["ref_object"]) or not SHA1_RE.fullmatch(source["commit"]):
            raise ValueError(f"{source['version']} contains a non-commit object identifier")
        install_dir = Path(source["install_dir"])
        if install_dir.is_absolute() or ".." in install_dir.parts:
            raise ValueError(f"unsafe install directory for {source['version']}")
        for binary_key in ("source_daemon", "source_cli"):
            binary_name = Path(source[binary_key])
            if binary_name.is_absolute() or len(binary_name.parts) != 1:
                raise ValueError(f"unsafe {binary_key} for {source['version']}")
        asset = source.get("release_asset")
        if asset is not None:
            asset_required = {
                "host", "url", "sha256", "daemon_member", "daemon_sha256",
                "cli_member", "cli_sha256",
            }
            missing_asset = asset_required.difference(asset)
            if missing_asset:
                raise ValueError(
                    f"{source['version']} release asset missing {sorted(missing_asset)}"
                )
            for digest_key in ("sha256", "daemon_sha256", "cli_sha256"):
                if not re.fullmatch(r"[0-9a-f]{64}", asset[digest_key]):
                    raise ValueError(
                        f"{source['version']} release asset has invalid {digest_key}"
                    )
            for member_key in ("daemon_member", "cli_member"):
                member = Path(asset[member_key])
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError(
                        f"{source['version']} release asset has unsafe {member_key}"
                    )
    return data


def remote_objects(source):
    ref = source["source_ref"]
    output = run(
        ["git", "ls-remote", source["repository"], ref, f"{ref}^{{}}"],
        capture=True,
    )
    objects = {}
    for line in output.splitlines():
        object_id, object_ref = line.split(maxsplit=1)
        objects[object_ref] = object_id
    if objects.get(ref) != source["ref_object"]:
        raise RuntimeError(
            f"{source['version']} provenance changed: {ref} is "
            f"{objects.get(ref, '<missing>')}, expected {source['ref_object']}"
        )
    peeled = objects.get(f"{ref}^{{}}", objects[ref])
    if peeled != source["commit"]:
        raise RuntimeError(
            f"{source['version']} resolves to {peeled}, expected {source['commit']}"
        )
    if source["tag_kind"] == "annotated" and f"{ref}^{{}}" not in objects:
        raise RuntimeError(f"{source['version']} is no longer an annotated tag")
    if source["tag_kind"] == "lightweight" and source["ref_object"] != source["commit"]:
        raise RuntimeError(f"{source['version']} lightweight tag does not point to its pinned commit")


def source_version(source_dir):
    configure = (source_dir / "configure.ac").read_text(encoding="utf8")
    values = {}
    for component in ("MAJOR", "MINOR", "BUILD"):
        match = re.search(rf"^define\(_CLIENT_VERSION_{component}, ([0-9]+)\)$", configure, re.MULTILINE)
        if match is None:
            raise RuntimeError(f"cannot read {component.lower()} version from {source_dir / 'configure.ac'}")
        values[component] = match.group(1)
    return f"v{values['MAJOR']}.{values['MINOR']}.{values['BUILD']}"


def cached_provenance_is_valid(output_dir, manifest_digest, sources):
    provenance_path = output_dir / "provenance.json"
    if not provenance_path.is_file():
        return False
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf8"))
    except (OSError, ValueError):
        return False
    if provenance.get("manifest_sha256") != manifest_digest:
        return False
    built = {item.get("version"): item for item in provenance.get("sources", [])}
    for source in sources:
        item = built.get(source["version"])
        if item is None or item.get("commit") != source["commit"]:
            return False
        for binary in BINARIES:
            path = output_dir / source["install_dir"] / "bin" / binary
            if not path.is_file() or file_sha256(path) != item.get("binaries", {}).get(binary):
                return False
    return True


def clone_exact_source(source, destination):
    run(["git", "init", "--quiet", destination])
    run(["git", "remote", "add", "origin", source["repository"]], cwd=destination)
    run(["git", "fetch", "--quiet", "--depth=1", "origin", source["commit"]], cwd=destination)
    run(["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=destination)
    checked_out = run(["git", "rev-parse", "HEAD"], cwd=destination, capture=True).strip()
    if checked_out != source["commit"]:
        raise RuntimeError(f"checked out {checked_out}, expected {source['commit']}")


def download_exact_release(source, *, output_dir, build_root, host):
    """Install an immutable, digest-pinned upstream release asset.

    The functional framework expects Blackcoin's current executable names, so
    legacy `blackmored`/`blackmore-cli` members are deliberately normalized at
    install time. The archive and each extracted executable are independently
    pinned. No archive path is extracted to disk.
    """
    asset = source.get("release_asset")
    if asset is None or asset["host"] != host:
        return None

    archive = build_root / f"{source['install_dir']}-release.tar.gz"
    request = urllib.request.Request(
        asset["url"],
        headers={"User-Agent": "Blackcoin-v30.1.1-mixed-version-gate"},
    )
    with urllib.request.urlopen(request) as response, archive.open("wb") as destination:
        shutil.copyfileobj(response, destination)
    if file_sha256(archive) != asset["sha256"]:
        raise RuntimeError(f"{source['version']} release archive digest mismatch")

    destination = output_dir / source["install_dir"] / "bin"
    destination.mkdir(parents=True, exist_ok=True)
    installed = {}
    hashes = {}
    with tarfile.open(archive, mode="r:gz") as bundle:
        for installed_name, member_key, digest_key in (
            ("blackcoind", "daemon_member", "daemon_sha256"),
            ("blackcoin-cli", "cli_member", "cli_sha256"),
        ):
            member_name = asset[member_key]
            try:
                member = bundle.getmember(member_name)
            except KeyError as error:
                raise RuntimeError(
                    f"{source['version']} release archive is missing {member_name}"
                ) from error
            if not member.isfile():
                raise RuntimeError(
                    f"{source['version']} release member is not a regular file: {member_name}"
                )
            source_file = bundle.extractfile(member)
            if source_file is None:
                raise RuntimeError(f"cannot read {member_name}")
            installed_path = destination / installed_name
            with installed_path.open("wb") as output:
                shutil.copyfileobj(source_file, output)
            installed_path.chmod(0o755)
            digest = file_sha256(installed_path)
            if digest != asset[digest_key]:
                raise RuntimeError(
                    f"{source['version']} release member digest mismatch: {member_name}"
                )
            installed[installed_name] = installed_path
            hashes[installed_name] = digest

    reported_versions = {}
    for installed_name, installed_path in installed.items():
        reported = run([installed_path, "--version"], capture=True).splitlines()[0]
        if source["version"].removeprefix("v") not in reported:
            raise RuntimeError(f"{installed_path} reports unexpected version: {reported}")
        reported_versions[installed_name] = reported
    return {
        "version": source["version"],
        "install_dir": source["install_dir"],
        "repository": source["repository"],
        "source_ref": source["source_ref"],
        "ref_object": source["ref_object"],
        "commit": source["commit"],
        "tag_kind": source["tag_kind"],
        "host": host,
        "origin": "digest-pinned-release-asset",
        "release_asset_url": asset["url"],
        "release_asset_sha256": asset["sha256"],
        "binaries": hashes,
        "reported_versions": reported_versions,
    }


def build_source(source, *, build_root, output_dir, host, jobs):
    source_dir = build_root / source["install_dir"]
    clone_exact_source(source, source_dir)
    actual_version = source_version(source_dir)
    if actual_version != source["version"]:
        raise RuntimeError(
            f"{source['commit']} declares {actual_version}, expected {source['version']}"
        )

    run([
        "make", f"-j{jobs}", "-C", "depends", f"HOST={host}",
        "NO_QT=1", "NO_UPNP=1", "NO_NATPMP=1",
    ], cwd=source_dir)
    run(["./autogen.sh"], cwd=source_dir)
    prefix = source_dir / "depends" / host
    run([
        "./configure", f"--prefix={prefix}", "--with-gui=no",
        "--disable-tests", "--disable-bench", "--disable-zmq",
    ], cwd=source_dir)
    run(["make", f"-j{jobs}"], cwd=source_dir)

    destination = output_dir / source["install_dir"] / "bin"
    destination.mkdir(parents=True, exist_ok=True)
    hashes = {}
    reported_versions = {}
    source_names = {
        "blackcoind": source["source_daemon"],
        "blackcoin-cli": source["source_cli"],
    }
    for binary in BINARIES:
        built_binary = source_dir / "src" / source_names[binary]
        if not built_binary.is_file():
            raise RuntimeError(f"missing {built_binary}")
        installed_binary = destination / binary
        shutil.copy2(built_binary, installed_binary)
        installed_binary.chmod(0o755)
        reported = run([installed_binary, "--version"], capture=True).splitlines()[0]
        if source["version"].removeprefix("v") not in reported:
            raise RuntimeError(f"{installed_binary} reports unexpected version: {reported}")
        hashes[binary] = file_sha256(installed_binary)
        reported_versions[binary] = reported
    return {
        "version": source["version"],
        "install_dir": source["install_dir"],
        "repository": source["repository"],
        "source_ref": source["source_ref"],
        "ref_object": source["ref_object"],
        "commit": source["commit"],
        "tag_kind": source["tag_kind"],
        "host": host,
        "origin": "source-build",
        "binaries": hashes,
        "reported_versions": reported_versions,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).with_name("sources.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--host", default="x86_64-pc-linux-gnu")
    parser.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    output_dir = args.output.resolve()
    build_root = args.build_root.resolve()
    if output_dir == Path("/") or build_root == Path("/") or output_dir == build_root:
        parser.error("unsafe output/build-root path")
    manifest = load_manifest(manifest_path)
    manifest_digest = file_sha256(manifest_path)

    for source in manifest["sources"]:
        remote_objects(source)

    if cached_provenance_is_valid(output_dir, manifest_digest, manifest["sources"]):
        print(f"Reusing verified mixed-version binaries in {output_dir}")
        return 0

    shutil.rmtree(output_dir, ignore_errors=True)
    shutil.rmtree(build_root, ignore_errors=True)
    output_dir.mkdir(parents=True)
    build_root.mkdir(parents=True)
    built = []
    try:
        for source in manifest["sources"]:
            exact_release = download_exact_release(
                source,
                output_dir=output_dir,
                build_root=build_root,
                host=args.host,
            )
            built.append(exact_release or build_source(
                source,
                build_root=build_root,
                output_dir=output_dir,
                host=args.host,
                jobs=args.jobs,
            ))
    finally:
        shutil.rmtree(build_root, ignore_errors=True)

    provenance = {
        "schema": 1,
        "manifest_sha256": manifest_digest,
        "sources": built,
    }
    (output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf8",
    )
    print(json.dumps(provenance, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
