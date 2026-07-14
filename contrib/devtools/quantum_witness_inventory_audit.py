#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate fail-closed, source-bound quantum witness inventory evidence."""

import argparse
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


INVENTORY_SCHEMA = "blackcoin.quantum.witness_inventory.v1"
EVIDENCE_SCHEMA = "blackcoin.quantum.witness_inventory.acceptance.v1"
DISPOSITIONS_SCHEMA = "blackcoin.quantum.witness_bridge_dispositions.v1"
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
PLACEHOLDERS = {"", "n/a", "none", "tbd", "todo", "unknown"}


class AuditError(RuntimeError):
    """An acceptance invariant was not proved."""


def _json_ready(value):
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value


def canonical_bytes(value):
    return (json.dumps(
        _json_ready(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ) + "\n").encode("utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command, *, cwd=None):
    try:
        result = subprocess.run(
            [str(item) for item in command], cwd=cwd, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=3600,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AuditError(f"command failed: {command[0]}: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise AuditError(f"command failed ({result.returncode}): {' '.join(map(str, command))}: {detail}")
    return result.stdout


def verify_source_checkout(root, expected_sha):
    root = Path(root).resolve()
    if not FULL_SHA_RE.fullmatch(expected_sha):
        raise AuditError("--source-sha must be a full lowercase 40-character commit SHA")
    head = _run(["git", "-C", root, "rev-parse", "HEAD"]).strip()
    if head != expected_sha:
        raise AuditError(f"source checkout is {head}, expected {expected_sha}")
    status = _run([
        "git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all",
    ])
    if status:
        raise AuditError("source checkout is not clean; exact-source evidence was not generated")
    repository = _run(["git", "-C", root, "config", "--get", "remote.origin.url"]).strip()
    if not repository:
        raise AuditError("source checkout has no remote.origin.url")
    return {"repository": repository, "commit": head, "clean": True}


def verify_binary(path, source_sha, label, *, isolated_datadir=False):
    path = Path(path).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise AuditError(f"{label} is not an executable file: {path}")
    if isolated_datadir:
        with tempfile.TemporaryDirectory(prefix="blackcoin-version-") as datadir:
            version = _run([path, f"-datadir={datadir}", "-version"]).strip()
    else:
        version = _run([path, "-version"]).strip()
    build_marker = source_sha[:12]
    if build_marker not in version or f"{build_marker}-dirty" in version:
        raise AuditError(
            f"{label} does not identify clean source commit {source_sha}; "
            f"expected build marker {build_marker}"
        )
    return {
        "sha256": file_sha256(path),
        "version": version,
        "source_commit_marker": build_marker,
    }


def _cli_argument(value):
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value)


class BlackcoinCLI:
    def __init__(self, binary, options):
        self.binary = str(Path(binary).resolve())
        self.options = list(options)

    def __call__(self, method, *params):
        output = _run([
            self.binary, *self.options, method,
            *(_cli_argument(param) for param in params),
        ])
        try:
            return json.loads(output, parse_float=Decimal)
        except json.JSONDecodeError as error:
            # bitcoin-cli intentionally prints top-level JSON strings without
            # surrounding quotes. Keep that exception narrow so malformed
            # object/array responses cannot be mistaken for usable evidence.
            if method == "getblockhash" and output.strip() == output.rstrip("\n"):
                return output.strip()
            raise AuditError(f"{method} returned invalid JSON") from error


def _require(condition, message):
    if not condition:
        raise AuditError(message)


def _outpoint_key(record):
    txid = record.get("txid")
    vout = record.get("vout")
    _require(isinstance(txid, str) and HASH_RE.fullmatch(txid), "inventory record has an invalid txid")
    _require(isinstance(vout, int) and 0 <= vout <= 0xffffffff, "inventory record has an invalid vout")
    return f"{txid}:{vout}"


def review_class(record):
    """Return the bridge-review class, or None for an exact native v14/v16."""
    version = record.get("witness_version")
    version_class = record.get("version_class")
    handling = record.get("bridge_handling")
    expected_class = {14: "v14", 15: "v15", 16: "v16"}.get(version, "unknown")
    _require(version_class == expected_class, f"{_outpoint_key(record)} has inconsistent version classification")

    if version == 14:
        _require(
            handling in {
                "recognized_quantum_cold_stake",
                "unknown_or_malformed_witness_program_requires_explicit_review",
            },
            f"{_outpoint_key(record)} has an unknown v14 handling class",
        )
        return None if handling == "recognized_quantum_cold_stake" else "malformed_v14"
    if version == 15:
        _require(
            handling in {
                "recognized_eutxo",
                "unknown_or_malformed_witness_program_requires_explicit_review",
            },
            f"{_outpoint_key(record)} has an unknown v15 handling class",
        )
        return "v15_unsupported" if handling == "recognized_eutxo" else "malformed_v15"
    if version == 16:
        _require(
            handling in {
                "recognized_direct_quantum",
                "unknown_or_malformed_witness_program_requires_explicit_review",
            },
            f"{_outpoint_key(record)} has an unknown v16 handling class",
        )
        return None if handling == "recognized_direct_quantum" else "malformed_v16"

    _require(
        isinstance(version, int) and 2 <= version <= 16 and
        handling == "unknown_or_malformed_witness_program_requires_explicit_review",
        f"{_outpoint_key(record)} has an inconsistent unknown-witness classification",
    )
    return "unknown_witness_version"


def _snapshot(page):
    snapshot = page.get("utxo_snapshot")
    _require(isinstance(snapshot, dict), "inventory response has no UTXO snapshot identity")
    _require(snapshot.get("algorithm") == "muhash3072", "inventory UTXO commitment is not MuHash3072")
    commitment = snapshot.get("commitment")
    _require(isinstance(commitment, str) and HASH_RE.fullmatch(commitment), "inventory UTXO commitment is invalid")
    txouts = snapshot.get("txouts")
    _require(isinstance(txouts, int) and txouts >= 0, "inventory UTXO count is invalid")
    _require(
        snapshot.get("excludes_authenticated_zero_value_protocol_markers") is True,
        "inventory UTXO commitment does not state the protocol-marker exclusion",
    )
    return {
        "height": page.get("height"),
        "bestblock": page.get("bestblock"),
        "muhash": commitment,
        "txouts": txouts,
    }


def collect_inventory(rpc, *, page_size=1000, max_records=100000, max_pages=10000):
    _require(1 <= page_size <= 1000, "page size must be between 1 and 1000")
    _require(max_records >= 0 and max_pages >= 1, "record and page bounds are invalid")
    offset = 0
    records = []
    identity = None
    total_records = None
    invariant_summary = None

    for _ in range(max_pages):
        page = rpc("getquantumwitnessinventory", "utxos", offset, page_size, 1)
        _require(isinstance(page, dict) and page.get("schema") == INVENTORY_SCHEMA,
                 "unexpected witness inventory schema")
        _require(page.get("view") == "utxos" and page.get("offset") == offset,
                 "inventory page does not match the requested UTXO offset")
        coverage = page.get("coverage")
        _require(isinstance(coverage, dict), "inventory response has no coverage contract")
        for field in (
            "snapshot_current_utxos_exact",
            "snapshot_tip_still_active",
            "snapshot_utxo_commitment_exact",
        ):
            _require(coverage.get(field) is True, f"inventory coverage is incomplete: {field}")
        _require(coverage.get("snapshot_includes_mempool") is False,
                 "inventory unexpectedly includes mempool outputs")

        page_identity = _snapshot(page)
        _require(isinstance(page_identity["height"], int) and page_identity["height"] >= 0,
                 "inventory height is invalid")
        _require(isinstance(page_identity["bestblock"], str) and
                 HASH_RE.fullmatch(page_identity["bestblock"]), "inventory tip hash is invalid")
        if identity is None:
            identity = page_identity
        else:
            _require(page_identity == identity, "tip or UTXO snapshot changed between inventory pages")

        page_total = page.get("total_records")
        _require(isinstance(page_total, int) and page_total >= 0,
                 "inventory total_records is incomplete")
        if total_records is None:
            total_records = page_total
            _require(total_records <= max_records,
                     f"inventory has {total_records} records, above the acceptance bound {max_records}")
        else:
            _require(page_total == total_records, "inventory total changed between pages")

        page_records = page.get("records")
        _require(isinstance(page_records, list), "inventory records page is invalid")
        _require(page.get("count") == len(page_records), "inventory page count is inconsistent")
        summary = {
            "classification": page.get("classification"),
            "current_utxos": page.get("current_utxos"),
            "coverage": coverage,
        }
        if invariant_summary is None:
            invariant_summary = summary
        else:
            _require(summary == invariant_summary, "inventory aggregates changed between pages")

        for record in page_records:
            _require(isinstance(record, dict), "inventory contains a non-object record")
            _outpoint_key(record)
            review_class(record)
            records.append(record)

        page_end = offset + len(page_records)
        next_offset = page.get("next_offset")
        if next_offset is None:
            _require(page_end == total_records,
                     "inventory ended before every declared record was returned")
            break
        _require(isinstance(next_offset, int) and next_offset == page_end and next_offset > offset,
                 "inventory pagination is non-contiguous or non-progressing")
        _require(next_offset <= total_records, "inventory next_offset exceeds total_records")
        offset = next_offset
    else:
        raise AuditError("inventory exceeded the maximum page bound")

    _require(len(records) == total_records, "inventory record enumeration is incomplete")
    keys = [_outpoint_key(record) for record in records]
    _require(len(keys) == len(set(keys)), "inventory contains duplicate outpoints")
    total_bucket = invariant_summary["current_utxos"].get("total")
    _require(isinstance(total_bucket, dict) and total_bucket.get("count") == total_records,
             "inventory aggregate count does not reconcile with enumerated records")
    return {
        "snapshot": identity,
        "classification": invariant_summary["classification"],
        "current_utxos": invariant_summary["current_utxos"],
        "coverage": invariant_summary["coverage"],
        "records": sorted(records, key=lambda item: (item["txid"], item["vout"])),
    }


def _load_dispositions(path):
    if path is None:
        return None, None
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditError(f"unable to read bridge dispositions: {error}") from error
    return document, file_sha256(path)


def apply_dispositions(records, *, dispositions, source_sha, network, snapshot):
    review_records = []
    native_records = []
    for record in records:
        record_class = review_class(record)
        selected = {
            key: record[key] for key in (
                "txid", "vout", "amount", "scriptPubKey", "witness_version",
                "version_class", "bridge_handling", "origin_height",
                "origin_blockhash", "origin_phase", "origin_group",
            ) if key in record
        }
        if record_class is None:
            selected["disposition"] = "native_quantum_format_no_bridge_required"
            native_records.append(selected)
        else:
            selected["review_class"] = record_class
            review_records.append(selected)

    if not review_records:
        _require(dispositions is None,
                 "a zero-result inventory must not carry a dispositions file")
        return {
            "scope": ["unknown_witness_version", "v15", "malformed_v14", "malformed_v16"],
            "result": "zero_relevant_outpoints",
            "count": 0,
            "records": [],
        }, native_records

    _require(isinstance(dispositions, dict),
             "relevant witness outpoints exist; a snapshot-bound dispositions file is required")
    _require(dispositions.get("schema") == DISPOSITIONS_SCHEMA,
             "bridge dispositions schema is invalid")
    _require(dispositions.get("source_commit") == source_sha,
             "bridge dispositions are not bound to this source commit")
    _require(dispositions.get("network") == network,
             "bridge dispositions are not bound to this network")
    expected_snapshot = {
        "height": snapshot["height"],
        "bestblock": snapshot["bestblock"],
        "utxo_muhash": snapshot["muhash"],
    }
    _require(dispositions.get("snapshot") == expected_snapshot,
             "bridge dispositions are stale or bound to another UTXO snapshot")
    outpoints = dispositions.get("outpoints")
    _require(isinstance(outpoints, dict), "bridge dispositions outpoints must be an object")
    expected_keys = {_outpoint_key(record) for record in review_records}
    _require(set(outpoints) == expected_keys,
             "bridge dispositions must cover exactly every relevant inventory outpoint")

    for record in review_records:
        key = _outpoint_key(record)
        disposition = outpoints[key]
        _require(isinstance(disposition, dict), f"{key} disposition must be an object")
        for field in ("action", "rationale", "approval_ref"):
            value = disposition.get(field)
            _require(isinstance(value, str) and value.strip().lower() not in PLACEHOLDERS,
                     f"{key} disposition requires a non-placeholder {field}")
        record["disposition"] = {
            "action": disposition["action"].strip(),
            "rationale": disposition["rationale"].strip(),
            "approval_ref": disposition["approval_ref"].strip(),
        }

    return {
        "scope": ["unknown_witness_version", "v15", "malformed_v14", "malformed_v16"],
        "result": "explicit_per_outpoint_dispositions",
        "count": len(review_records),
        "records": review_records,
    }, native_records


def generate_evidence(rpc, *, source, binaries, source_sha, dispositions=None,
                      dispositions_sha256=None, page_size=1000, max_records=100000):
    chain_before = rpc("getblockchaininfo")
    network_info = rpc("getnetworkinfo")
    phase = rpc("getquantumquasarinfo")
    genesis_hash = rpc("getblockhash", 0)
    inventory = collect_inventory(
        rpc, page_size=page_size, max_records=max_records,
    )
    snapshot = inventory["snapshot"]

    stats = rpc("gettxoutsetinfo", "muhash")
    chain_after = rpc("getblockchaininfo")
    block_header = rpc("getblockheader", snapshot["bestblock"])
    chain = chain_before.get("chain")
    _require(isinstance(chain, str) and chain, "node did not report a network")
    _require(isinstance(genesis_hash, str) and HASH_RE.fullmatch(genesis_hash),
             "node returned an invalid genesis hash")
    for observed in (chain_before, chain_after):
        _require(observed.get("chain") == chain, "network changed during inventory acceptance")
        _require(observed.get("blocks") == snapshot["height"],
                 "active height changed during inventory acceptance")
        _require(observed.get("bestblockhash") == snapshot["bestblock"],
                 "active tip changed during inventory acceptance")
        _require(observed.get("initialblockdownload") is False,
                 "inventory acceptance requires a synchronized node")
    _require(stats.get("height") == snapshot["height"] and
             stats.get("bestblock") == snapshot["bestblock"],
             "independent UTXO scan is bound to another tip")
    _require(stats.get("muhash") == snapshot["muhash"],
             "independent gettxoutsetinfo MuHash does not match the inventory snapshot")
    _require(stats.get("txouts") == snapshot["txouts"],
             "independent gettxoutsetinfo count does not match the inventory snapshot")
    _require(block_header.get("height") == snapshot["height"] and
             block_header.get("hash") == snapshot["bestblock"] and
             block_header.get("confirmations", 0) > 0,
             "inventory tip is not the active-chain block at the recorded height")

    bridge_review, native_records = apply_dispositions(
        inventory["records"], dispositions=dispositions, source_sha=source_sha,
        network=chain, snapshot=snapshot,
    )
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "source": source,
        "binaries": binaries,
        "network": {
            "chain": chain,
            "genesis_hash": genesis_hash,
            "protocol_version": network_info.get("protocolversion"),
            "subversion": network_info.get("subversion"),
        },
        "snapshot": {
            "height": snapshot["height"],
            "bestblock": snapshot["bestblock"],
            "block_time": block_header.get("time"),
            "utxo_muhash": snapshot["muhash"],
            "utxo_txouts": snapshot["txouts"],
            "independent_gettxoutsetinfo_match": True,
        },
        "phase_schedule": {
            key: phase.get(key) for key in (
                "phase", "active_tip_phase", "next_block_phase",
                "active_tip_height", "next_block_height",
                "gold_rush_end_height", "quantum_migration_end_height",
                "height_boundaries_authoritative", "quantum_spend_enforcement_active",
                "legacy_addresses_accepted", "quantum_address_required",
            )
        },
        "inventory": {
            "classification": inventory["classification"],
            "coverage": inventory["coverage"],
            "current_utxos": inventory["current_utxos"],
            "total_records": len(inventory["records"]),
            "records": inventory["records"],
        },
        "bridge_review": bridge_review,
        "native_quantum_formats": {
            "count": len(native_records),
            "records": native_records,
        },
        "acceptance": {
            "tip_unchanged_across_all_calls": True,
            "all_inventory_pages_same_snapshot": True,
            "all_declared_records_enumerated_once": True,
            "utxo_commitment_independently_reconciled": True,
            "bridge_review_complete": True,
            "dispositions_file_sha256": dispositions_sha256,
        },
    }
    evidence["evidence_payload_sha256"] = hashlib.sha256(canonical_bytes(evidence)).hexdigest()
    return evidence


def write_evidence(path, evidence):
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(_json_ready(evidence), sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=destination.parent,
            prefix=f".{destination.name}.", delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--blackcoin-cli", type=Path, required=True)
    parser.add_argument("--blackcoind", type=Path, required=True)
    parser.add_argument("--cli-arg", action="append", default=[],
                        help="blackcoin-cli option; use --cli-arg=-datadir=/path for leading dashes")
    parser.add_argument("--dispositions", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--page-size", type=int, default=1000)
    parser.add_argument("--max-records", type=int, default=100000)
    args = parser.parse_args()

    try:
        source = verify_source_checkout(args.source_root, args.source_sha)
        binaries = {
            "blackcoind": verify_binary(
                args.blackcoind, args.source_sha, "blackcoind",
                isolated_datadir=True,
            ),
            "blackcoin_cli": verify_binary(args.blackcoin_cli, args.source_sha, "blackcoin-cli"),
        }
        dispositions, dispositions_sha256 = _load_dispositions(args.dispositions)
        evidence = generate_evidence(
            BlackcoinCLI(args.blackcoin_cli, args.cli_arg),
            source=source,
            binaries=binaries,
            source_sha=args.source_sha,
            dispositions=dispositions,
            dispositions_sha256=dispositions_sha256,
            page_size=args.page_size,
            max_records=args.max_records,
        )
        write_evidence(args.output, evidence)
    except AuditError as error:
        parser.exit(1, f"witness inventory acceptance failed: {error}\n")

    print(f"wrote {args.output}")
    print(f"evidence_payload_sha256={evidence['evidence_payload_sha256']}")


if __name__ == "__main__":
    main()
