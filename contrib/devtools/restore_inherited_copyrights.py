#!/usr/bin/env python3
# Copyright (c) 2026 Quantum Quasar Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Restore demonstrably inherited Bitcoin Core copyright notices.

This tool intentionally uses two immutable git trees for classification. It
does not infer provenance from filenames alone. A notice is restorable only
when the active legacy tree has the same path and notice, the current baseline
has an inherited Blackcoin-family header, and the non-copyright bodies are
either identical or highly similar. Vendored, generated, binary, translation,
and patch artifacts are never changed.

The working tree is only modified with --write. The JSON manifest records all
restored, excluded, and ambiguous candidates so the decision is reviewable.
"""

import argparse
import difflib
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile


BITCOIN_HOLDER = "The Bitcoin Core developers"
BITCOIN_NOTICE_RE = re.compile(r"^.*Copyright(?: \(c\))?.*The Bitcoin Core developers\s*$")
BLACKCOIN_FAMILY_RE = re.compile(
    r"^.*Copyright(?: \(c\))?.*(?:Blackcoin Core Developers|"
    r"Blackcoin More Developers|Blackcoin Developers)\s*$"
)
COPYRIGHT_RE = re.compile(r"^.*Copyright(?: \(c\))?.*$")

FIRST_PARTY_ROOTS = {
    ".github",
    "build-aux",
    "build_msvc",
    "ci",
    "contrib",
    "depends",
    "src",
    "test",
}

VENDORED_PREFIXES = (
    "src/crc32c/",
    "src/crypto/argon2/",
    "src/crypto/ctaes/",
    "src/leveldb/",
    "src/minisketch/",
    "src/secp256k1/",
    "src/univalue/",
)

GENERATED_OR_DATA_PREFIXES = (
    "src/bench/data/",
    "src/qt/locale/",
    "src/test/data/",
    "test/functional/data/",
)

GENERATED_FILES = {
    "src/chainparamsseeds.h",
    "src/qt/bitcoinstrings.cpp",
}

SOURCE_BUILD_SUFFIXES = {
    ".ac",
    ".am",
    ".awk",
    ".bash",
    ".c",
    ".cc",
    ".cmake",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".in",
    ".l",
    ".ll",
    ".m",
    ".m4",
    ".mk",
    ".mm",
    ".pl",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".y",
    ".yaml",
    ".yml",
    ".yy",
    ".zsh",
}

TOP_LEVEL_BUILD_FILES = {
    "Makefile.am",
    "autogen.sh",
    "configure.ac",
}


def git(repo, *args, text=True):
    command = ["git", "-C", str(repo), *args]
    return subprocess.check_output(command, text=text)


def git_root(path):
    return Path(git(path, "rev-parse", "--show-toplevel").strip())


def resolve_ref(repo, ref):
    return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").strip()


def load_tree(repo, ref):
    """Load a git tree with one deterministic archive invocation."""
    archive = git(repo, "archive", "--format=tar", ref, text=False)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tree:
        for member in tree.getmembers():
            if not member.isfile():
                continue
            file_object = tree.extractfile(member)
            if file_object is None:
                continue
            files[member.name] = file_object.read()
    return files


def decode_text(data):
    if b"\0" in data:
        raise UnicodeError("NUL byte")
    return data.decode("utf-8")


def header_lines(text, limit=80):
    return text.splitlines()[:limit]


def bitcoin_notices(text):
    return [line for line in header_lines(text) if BITCOIN_NOTICE_RE.match(line)]


def has_blackcoin_family_header(text):
    return any(BLACKCOIN_FAMILY_RE.match(line) for line in header_lines(text))


def normalize_body(text):
    lines = []
    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if COPYRIGHT_RE.match(line):
            continue
        lines.append(line.rstrip())
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(lines)


def body_similarity(current, legacy):
    current_body = normalize_body(current)
    legacy_body = normalize_body(legacy)
    current_hash = hashlib.sha256(current_body.encode("utf-8")).hexdigest()
    legacy_hash = hashlib.sha256(legacy_body.encode("utf-8")).hexdigest()
    if current_hash == legacy_hash:
        return 1.0, "normalized-identical"
    ratio = difflib.SequenceMatcher(
        None,
        current_body.splitlines(),
        legacy_body.splitlines(),
        autojunk=False,
    ).ratio()
    return ratio, "high-body-similarity"


def exclusion_reason(path, current_bytes):
    posix = PurePosixPath(path)
    if path in GENERATED_FILES:
        return "generated-file"
    if path.startswith(VENDORED_PREFIXES):
        return "vendored-subtree"
    if path.startswith(GENERATED_OR_DATA_PREFIXES):
        return "generated-translation-or-test-data"
    if path.startswith("depends/patches/") or posix.suffix == ".patch":
        return "upstream-patch-artifact"
    if posix.parts and posix.parts[0] not in FIRST_PARTY_ROOTS:
        if path not in TOP_LEVEL_BUILD_FILES:
            return "outside-first-party-source-test-build-scope"
    if b"\0" in current_bytes:
        return "binary-file"
    if (
        posix.suffix.lower() not in SOURCE_BUILD_SUFFIXES
        and posix.name not in TOP_LEVEL_BUILD_FILES
        and not posix.name.startswith("Makefile")
        and not current_bytes.startswith(b"#!")
    ):
        return "non-source-build-file-type"
    return None


def choose_insertion_index(current_lines, legacy_lines, legacy_notice_index):
    # Prefer the closest inherited header line before the notice in the legacy
    # file, then the closest one after it. This preserves established ordering.
    for legacy_index in range(legacy_notice_index - 1, -1, -1):
        line = legacy_lines[legacy_index].rstrip("\r\n")
        if not COPYRIGHT_RE.match(line):
            continue
        for current_index, current_line in enumerate(current_lines[:80]):
            if current_line.rstrip("\r\n") == line:
                return current_index + 1
    for legacy_index in range(legacy_notice_index + 1, min(len(legacy_lines), 80)):
        line = legacy_lines[legacy_index].rstrip("\r\n")
        if not COPYRIGHT_RE.match(line):
            continue
        for current_index, current_line in enumerate(current_lines[:80]):
            if current_line.rstrip("\r\n") == line:
                return current_index
    for current_index, current_line in enumerate(current_lines[:80]):
        if BLACKCOIN_FAMILY_RE.match(current_line.rstrip("\r\n")):
            return current_index
    raise ValueError("working file no longer has an inherited Blackcoin-family header")


def restore_notice(repo, path, legacy_text, notice):
    file_path = repo / path
    with file_path.open("r", encoding="utf-8", newline="") as file_object:
        current_text = file_object.read()
    if BITCOIN_HOLDER in current_text:
        return False

    current_lines = current_text.splitlines(keepends=True)
    legacy_lines = legacy_text.splitlines(keepends=True)
    notice_indexes = [
        index
        for index, line in enumerate(legacy_lines[:80])
        if line.rstrip("\r\n") == notice
    ]
    if len(notice_indexes) != 1:
        raise ValueError("legacy notice is not unique in the header")

    insertion_index = choose_insertion_index(
        current_lines, legacy_lines, notice_indexes[0]
    )
    newline = "\r\n" if "\r\n" in current_text else "\n"
    current_lines.insert(insertion_index, notice + newline)
    with file_path.open("w", encoding="utf-8", newline="") as file_object:
        file_object.write("".join(current_lines))
    return True


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--legacy-tree",
        required=True,
        help="path to the active legacy repository checkout",
    )
    parser.add_argument("--current-ref", default="HEAD")
    parser.add_argument("--legacy-ref", default="HEAD")
    parser.add_argument("--similarity-threshold", type=float, default=0.95)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument(
        "--write",
        action="store_true",
        help="restore eligible notices in the current working tree",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not 0.0 <= args.similarity_threshold <= 1.0:
        raise SystemExit("similarity threshold must be between 0 and 1")

    current_repo = git_root(Path.cwd())
    legacy_repo = git_root(Path(args.legacy_tree))
    current_revision = resolve_ref(current_repo, args.current_ref)
    legacy_revision = resolve_ref(legacy_repo, args.legacy_ref)

    current_tree = load_tree(current_repo, current_revision)
    legacy_tree = load_tree(legacy_repo, legacy_revision)

    restored = []
    excluded = []
    ambiguous = []

    for path in sorted(current_tree.keys() & legacy_tree.keys()):
        current_bytes = current_tree[path]
        legacy_bytes = legacy_tree[path]
        try:
            legacy_text = decode_text(legacy_bytes)
        except UnicodeError:
            continue
        notices = bitcoin_notices(legacy_text)
        if not notices:
            continue

        try:
            current_text = decode_text(current_bytes)
        except UnicodeError:
            excluded.append({"path": path, "reason": "binary-file"})
            continue
        if bitcoin_notices(current_text):
            continue

        reason = exclusion_reason(path, current_bytes)
        if reason:
            excluded.append({"path": path, "reason": reason})
            continue
        if len(notices) != 1:
            ambiguous.append({"path": path, "reason": "multiple-legacy-notices"})
            continue
        if not has_blackcoin_family_header(current_text):
            ambiguous.append(
                {"path": path, "reason": "missing-inherited-Blackcoin-family-header"}
            )
            continue

        similarity, basis = body_similarity(current_text, legacy_text)
        rounded_similarity = round(similarity, 6)
        if similarity < args.similarity_threshold:
            ambiguous.append(
                {
                    "path": path,
                    "reason": "body-similarity-below-threshold",
                    "similarity": rounded_similarity,
                }
            )
            continue

        entry = {
            "path": path,
            "basis": basis,
            "similarity": rounded_similarity,
            "notice": notices[0],
        }
        if args.write:
            try:
                restore_notice(current_repo, path, legacy_text, notices[0])
            except (OSError, UnicodeError, ValueError) as error:
                ambiguous.append(
                    {
                        "path": path,
                        "reason": "working-tree-restore-failed",
                        "detail": str(error),
                        "similarity": rounded_similarity,
                    }
                )
                continue
        restored.append(entry)

    manifest = {
        "schema": 1,
        "current_revision": current_revision,
        "legacy_revision": legacy_revision,
        "similarity_threshold": args.similarity_threshold,
        "write_applied": args.write,
        "restored": restored,
        "excluded": excluded,
        "ambiguous": ambiguous,
    }
    manifest_path = args.manifest
    if not manifest_path.is_absolute():
        manifest_path = current_repo / manifest_path
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(
        "provenance audit: "
        f"restored={len(restored)} excluded={len(excluded)} "
        f"ambiguous={len(ambiguous)}"
    )
    if ambiguous:
        print("ambiguous files were left unchanged", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
