#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail-closed preflight for the pinned external script test vectors."""

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Iterable, NamedTuple


PINNED_TOTAL = 2_244
PINNED_INCOMPATIBLE = 1_161
PINNED_COMPATIBLE = 1_083
_HEX_RE = re.compile(r"[0-9a-fA-F]+\Z")


class CorpusError(ValueError):
    """The external corpus does not match the reviewed Blackcoin gate."""


class CorpusCounts(NamedTuple):
    total: int
    incompatible: int
    compatible: int


def transaction_version(tx_hex: str, index: int) -> int:
    """Return the signed little-endian int32 at the start of a transaction."""
    if not isinstance(tx_hex, str):
        raise CorpusError(f"vector {index}: tx must be a string")
    if len(tx_hex) < 8:
        raise CorpusError(f"vector {index}: tx is shorter than its int32 version")
    if len(tx_hex) % 2 != 0 or _HEX_RE.fullmatch(tx_hex) is None:
        raise CorpusError(f"vector {index}: tx is not strict even-length hex")
    return int.from_bytes(bytes.fromhex(tx_hex[:8]), byteorder="little", signed=True)


def verify_vectors(
    vectors: Iterable[object],
    *,
    expected_total: int = PINNED_TOTAL,
    expected_incompatible: int = PINNED_INCOMPATIBLE,
    expected_compatible: int = PINNED_COMPATIBLE,
) -> CorpusCounts:
    if not isinstance(vectors, list):
        raise CorpusError("corpus root must be a JSON array")

    incompatible = 0
    compatible = 0
    for index, vector in enumerate(vectors):
        if not isinstance(vector, dict):
            raise CorpusError(f"vector {index}: entry must be an object")
        if "tx" not in vector:
            raise CorpusError(f"vector {index}: missing tx")
        version = transaction_version(vector["tx"], index)
        if version < 2:
            incompatible += 1
        else:
            compatible += 1

    counts = CorpusCounts(len(vectors), incompatible, compatible)
    expected = CorpusCounts(
        expected_total,
        expected_incompatible,
        expected_compatible,
    )
    if counts != expected:
        raise CorpusError(
            "pinned corpus classification changed: "
            f"got total={counts.total}, incompatible={counts.incompatible}, "
            f"compatible={counts.compatible}; expected total={expected.total}, "
            f"incompatible={expected.incompatible}, compatible={expected.compatible}"
        )
    return counts


def verify_file(path: Path) -> CorpusCounts:
    try:
        with path.open("r", encoding="utf-8") as corpus_file:
            vectors = json.load(corpus_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CorpusError(f"cannot read corpus {path}: {error}") from error
    return verify_vectors(vectors)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify the exact pinned script corpus and its Blackcoin transaction "
            "version split"
        )
    )
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()

    try:
        counts = verify_file(args.corpus)
    except CorpusError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    print(
        "verified pinned script corpus: "
        f"total={counts.total} incompatible-version-lt-2={counts.incompatible} "
        f"blackcoin-compatible={counts.compatible}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
