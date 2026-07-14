#!/usr/bin/env python3
#
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check stable Quantum Quasar documentation invariants against source."""

import hashlib
import re
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WHITEPAPER = ROOT / "doc" / "whitepaper-quantum-quasar.md"
PDF = ROOT / "doc" / "whitepaper-quantum-quasar.pdf"
PDF_GENERATOR = ROOT / "contrib" / "devtools" / "gen-whitepaper-pdf.py"
RELEASE_GATE = ROOT / "doc" / "v30.1.1-release-gate.md"


def source_integer(path, name, braced=False):
    text = path.read_text(encoding="utf-8")
    separator = r"\s*\{" if braced else r"\s*=\s*"
    suffix = r"\}" if braced else ""
    match = re.search(rf"\b{re.escape(name)}{separator}(\d+){suffix}", text)
    if not match:
        raise ValueError(f"cannot find integer {name} in {path.relative_to(ROOT)}")
    return int(match.group(1))


def appendix_integers():
    rows = {}
    for line in WHITEPAPER.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\| `([^`]+)` \| ([^|]+) \|", line)
        if not match:
            continue
        number = re.search(r"\d[\d,]*", match.group(2))
        if number:
            rows[match.group(1)] = int(number.group(0).replace(",", ""))
    return rows


def check_source_constants(failures):
    witness_header = ROOT / "src" / "consensus" / "quantum_witness.h"
    address_header = ROOT / "src" / "addresstype.h"
    redelegation_header = ROOT / "src" / "wallet" / "redelegation.h"
    expected = {
        "QUANTUM_MIGRATION_PROGRAM_SIZE": source_integer(
            witness_header, "QUANTUM_MIGRATION_PROGRAM_SIZE"
        ),
        "QUANTUM_TIERED_PROGRAM_SIZE": source_integer(
            witness_header, "QUANTUM_TIERED_PROGRAM_SIZE"
        ),
        "QUANTUM_COLDSTAKE_PROGRAM_SIZE": source_integer(
            witness_header, "QUANTUM_COLDSTAKE_PROGRAM_SIZE"
        ),
        "EUTXO_PROGRAM_SIZE": source_integer(address_header, "EUTXO_PROGRAM_SIZE"),
    }
    for member in (
        "trigger_multiplier",
        "min_trigger_blocks",
        "max_patience_blocks",
        "rate_limit_blocks",
        "probation_blocks",
        "stampede_jitter_blocks",
        "liveness_improvement_blocks",
    ):
        expected[f"QuantumRedelegationPolicy::{member}"] = source_integer(
            redelegation_header, member, braced=True
        )

    documented = appendix_integers()
    for symbol, source_value in expected.items():
        if symbol not in documented:
            failures.append(f"whitepaper Appendix A has no row for {symbol}")
        elif documented[symbol] != source_value:
            failures.append(
                f"whitepaper {symbol} is {documented[symbol]}, source is {source_value}"
            )


def check_release_status(failures):
    text = RELEASE_GATE.read_text(encoding="utf-8")
    match = re.search(
        r"^\| #19 specification and documentation \| [^|]+ \| ([^|]+) \|",
        text,
        re.MULTILINE,
    )
    if not match:
        failures.append("release gate has no roadmap row for issue #19")
    elif match.group(1).strip() != "Partial":
        failures.append(
            f"issue #19 must remain Partial until its full evidence matrix passes; "
            f"found {match.group(1).strip()}"
        )


def check_pdf_provenance(failures):
    generator_bytes = PDF_GENERATOR.read_bytes()
    generator_text = generator_bytes.decode("utf-8")
    expected_creator = "Blackcoin gen-whitepaper-pdf.py (ReportLab)"
    expected_producer = "pypdf"

    creator = re.search(r'^DOC_CREATOR = "([^"]+)"$', generator_text, re.MULTILINE)
    producer = re.search(r'^DOC_PRODUCER = "([^"]+)"$', generator_text, re.MULTILINE)
    if not creator or creator.group(1) != expected_creator:
        failures.append("PDF generator Creator does not identify the ReportLab generator")
    if not producer or producer.group(1) != expected_producer:
        failures.append("PDF generator Producer does not identify pypdf")
    pdf_bytes = PDF.read_bytes()
    source_bytes = WHITEPAPER.read_bytes()
    revision_digest = hashlib.sha256(
        source_bytes + b"\0" + generator_bytes
    ).hexdigest()
    expected_instance = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"blackcoin-quantum-quasar-whitepaper:{revision_digest}",
        )
    )
    required = (
        f"<xmp:CreatorTool>{expected_creator}</xmp:CreatorTool>".encode(),
        f"<pdf:Producer>{expected_producer}</pdf:Producer>".encode(),
        b'x:xmptk="pypdf"',
        f"<xmpMM:InstanceID>uuid:{expected_instance}</xmpMM:InstanceID>".encode(),
    )
    for fragment in required:
        if fragment not in pdf_bytes:
            failures.append(
                "generated PDF metadata is stale or missing: "
                + fragment.decode("utf-8")
            )


def main():
    failures = []
    try:
        check_source_constants(failures)
        check_release_status(failures)
        check_pdf_provenance(failures)
    except (OSError, ValueError) as error:
        failures.append(str(error))

    if failures:
        for failure in failures:
            print(f"quantum documentation invariant: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
