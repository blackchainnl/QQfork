#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Verify optional exact-source mainnet quantum-witness evidence offline."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
DEVTOOLS = ROOT / "contrib" / "devtools"
for module_root in (str(DEVTOOLS), str(Path(__file__).resolve().parent)):
    if module_root not in sys.path:
        sys.path.insert(0, module_root)

import quantum_witness_inventory_audit as audit  # noqa: E402
import verify_shadow_resource_production_evidence as resource_verifier  # noqa: E402


AUTHORIZATION_SCHEMA = "blackcoin.quantum.witness_inventory.authorization.v1"
AUTHORIZED_MODE = "exact_final_mainnet_witness_inventory"
MAXIMUM_CAPTURE_AGE_SECONDS = 86_400
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """The evidence does not satisfy optional live qualification."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def require_keys(value, expected, label):
    require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    require(actual == set(expected),
            f"{label} fields differ: missing={sorted(set(expected) - actual)}, "
            f"extra={sorted(actual - set(expected))}")


def load_json(path, label):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot read {label}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def sha256_file(path):
    digest = hashlib.sha256()
    try:
        with Path(path).open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise VerificationError(f"cannot hash {path}: {error}") from error
    return digest.hexdigest()


def verify_capture_manifest(manifest, contract, *, contract_sha256,
                            manifest_sha256, target_sha, now=None,
                            maximum_age_seconds=MAXIMUM_CAPTURE_AGE_SECONDS):
    require_keys(
        manifest,
        {
            "schema", "evidence_kind", "contract_sha256", "target_sha",
            "network", "archive_sha256", "archive_size_bytes", "archive_root",
            "captured_at_unix", "capture_attestation", "capture_rpc",
            "end_height", "end_hash", "pre_gold_rush_hash",
            "first_gold_rush_hash", "issued_claims", "spent_claims",
            "unspent_claims",
        },
        "capture manifest",
    )
    require(isinstance(contract, dict), "production resource contract is invalid")
    expected = contract.get("live_partial_snapshot")
    require(isinstance(expected, dict), "production resource contract has no live snapshot policy")
    require(manifest["schema"] == 2, "unsupported capture manifest schema")
    require(manifest["evidence_kind"] == "current_live_partial_epoch",
            "capture is not labeled current live partial-epoch evidence")
    require(manifest["contract_sha256"] == contract_sha256,
            "capture manifest is bound to another production contract")
    require(manifest["target_sha"] == target_sha,
            "capture manifest is bound to another source commit")
    require(manifest["network"] == "main" == expected.get("network"),
            "capture manifest is not Blackcoin mainnet evidence")
    require(SHA256_RE.fullmatch(manifest_sha256) is not None,
            "capture manifest SHA256 is invalid")
    captured_at = manifest["captured_at_unix"]
    require(isinstance(captured_at, int) and not isinstance(captured_at, bool) and
            captured_at > 0, "capture time is invalid")
    current_time = int(time.time()) if now is None else int(now)
    age = current_time - captured_at
    require(age >= -300, "capture time is more than five minutes in the future")
    require(isinstance(maximum_age_seconds, int) and maximum_age_seconds > 0,
            "maximum capture age is invalid")
    require(age <= maximum_age_seconds,
            "mainnet witness inventory capture is stale for live qualification")

    height = manifest["end_height"]
    require(isinstance(height, int) and not isinstance(height, bool) and
            expected.get("minimum_height") <= height <= expected.get("maximum_height"),
            "capture height is outside the live Gold Rush interval")
    require(manifest["capture_attestation"] ==
            "protected_operator_confirmed_connected_mainnet_tip",
            "capture lacks the protected connected-tip attestation")
    rpc = manifest["capture_rpc"]
    require_keys(
        rpc,
        {"chain", "blocks", "headers", "bestblockhash",
         "initialblockdownload", "connections"},
        "capture RPC",
    )
    require(
        rpc["chain"] == "main" and rpc["blocks"] == height and
        rpc["headers"] == height and rpc["bestblockhash"] == manifest["end_hash"] and
        rpc["initialblockdownload"] is False and
        isinstance(rpc["connections"], int) and not isinstance(rpc["connections"], bool) and
        rpc["connections"] >= 1,
        "capture RPC does not attest a connected synchronized exact tip",
    )
    for key in ("end_hash", "pre_gold_rush_hash", "first_gold_rush_hash",
                "archive_sha256"):
        require(isinstance(manifest[key], str) and SHA256_RE.fullmatch(manifest[key]),
                f"capture manifest {key} is invalid")
    root = manifest["archive_root"]
    require(isinstance(root, str) and root and not Path(root).is_absolute() and
            ".." not in Path(root).parts and len(Path(root).parts) == 1,
            "capture archive_root is unsafe")
    require(isinstance(manifest["archive_size_bytes"], int) and
            not isinstance(manifest["archive_size_bytes"], bool) and
            manifest["archive_size_bytes"] > 0,
            "capture archive size is invalid")
    for key in ("issued_claims", "spent_claims", "unspent_claims"):
        require(isinstance(manifest[key], int) and not isinstance(manifest[key], bool) and
                manifest[key] >= 0, f"capture manifest {key} is invalid")
    require(manifest["issued_claims"] > 0 and
            manifest["spent_claims"] <= manifest["issued_claims"] and
            manifest["unspent_claims"] ==
            manifest["issued_claims"] - manifest["spent_claims"],
            "capture claim inventory does not reconcile")


def selected_record(record):
    return {
        key: record[key] for key in (
            "txid", "vout", "amount", "scriptPubKey", "witness_version",
            "version_class", "bridge_handling", "origin_height",
            "origin_blockhash", "origin_phase", "origin_group",
        ) if key in record
    }


def verify_inventory(evidence, capture_manifest):
    inventory = evidence.get("inventory")
    require_keys(
        inventory,
        {"classification", "coverage", "current_utxos", "total_records", "records"},
        "inventory",
    )
    records = inventory.get("records")
    require(isinstance(records, list), "inventory records are invalid")
    require(inventory.get("classification") == audit.INVENTORY_CLASSIFICATION,
            "inventory classification contract is unexpected")
    require(inventory.get("total_records") == len(records),
            "inventory record count does not reconcile")
    expected_order = sorted(records, key=lambda item: (item.get("txid", ""), item.get("vout", -1)))
    require(records == expected_order, "inventory records are not canonically ordered")
    snapshot = evidence["snapshot"]
    keys = []
    total_atomic = 0
    for record in records:
        total_atomic += audit._validate_inventory_record(record, snapshot["height"])
        keys.append(audit._outpoint_key(record))
    require(len(keys) == len(set(keys)), "inventory contains duplicate outpoints")

    current = inventory.get("current_utxos")
    require(isinstance(current, dict), "inventory aggregates are missing")
    require(audit._inventory_bucket(current.get("total"), "total") ==
            (len(records), total_atomic), "inventory total does not reconcile")
    for field, aggregate in (
        ("version_class", "by_version"),
        ("origin_group", "by_origin_group"),
        ("origin_phase", "by_origin_phase"),
        ("bridge_handling", "by_bridge_handling"),
    ):
        audit._require_partition(
            current.get(aggregate), audit._expected_partition(records, field), aggregate,
        )
    audit._require_partition(
        current.get("by_version_and_origin"),
        audit._expected_partition(records, "version_class", cross_field="origin_group"),
        "by_version_and_origin",
    )
    coverage = inventory.get("coverage")
    require(isinstance(coverage, dict), "inventory coverage is missing")
    for field in (
        "snapshot_current_utxos_exact", "snapshot_tip_still_active",
        "snapshot_utxo_commitment_exact",
    ):
        require(coverage.get(field) is True, f"inventory coverage is incomplete: {field}")
    require(coverage.get("snapshot_includes_mempool") is False and
            coverage.get("snapshot_includes_synthetic_shadow_outputs") is False,
            "inventory coverage does not exclude transient or synthetic outputs")

    review_base = []
    native_expected = []
    for record in records:
        item = selected_record(record)
        classification = audit.review_class(record)
        if classification is None:
            item["disposition"] = "native_quantum_format_no_bridge_required"
            native_expected.append(item)
        else:
            item["review_class"] = classification
            review_base.append(item)

    native = evidence.get("native_quantum_formats")
    require(native == {"count": len(native_expected), "records": native_expected},
            "native quantum format inventory does not reconcile")
    review = evidence.get("bridge_review")
    require_keys(review, {"scope", "result", "count", "records"}, "bridge review")
    require(review.get("scope") == [
        "unknown_witness_version", "v15", "malformed_v14",
        "malformed_v16", "pre_migration_v14", "pre_migration_v16",
    ], "bridge-review scope is invalid")
    acceptance = evidence.get("acceptance")
    require_keys(
        acceptance,
        {
            "tip_unchanged_across_all_calls",
            "all_inventory_pages_same_snapshot",
            "all_declared_records_enumerated_once",
            "utxo_commitment_independently_reconciled",
            "bridge_review_complete",
            "mainnet_identity_and_schedule_exact",
            "rpc_server_exact_binary_bound",
            "live_shadow_inventory_reconciled",
            "dispositions_file_sha256",
        },
        "acceptance",
    )
    dispositions_sha = acceptance.get("dispositions_file_sha256")
    if not review_base:
        require(review.get("result") == "zero_relevant_outpoints" and
                review.get("count") == 0 and review.get("records") == [] and
                dispositions_sha is None,
                "zero bridge-review result is not explicit and disposition-free")
    else:
        require(review.get("result") == "explicit_per_outpoint_dispositions" and
                review.get("count") == len(review_base) and
                isinstance(review.get("records"), list) and
                len(review["records"]) == len(review_base) and
                isinstance(dispositions_sha, str) and SHA256_RE.fullmatch(dispositions_sha),
                "bridge-review dispositions are incomplete")
        actual = review["records"]
        for base, record in zip(review_base, actual):
            require(isinstance(record, dict), "bridge-review record is invalid")
            disposition = record.get("disposition")
            require_keys(
                disposition,
                {"action", "rationale", "approval_ref"},
                "bridge-review disposition",
            )
            for field in ("action", "rationale", "approval_ref"):
                value = disposition.get(field)
                require(isinstance(value, str) and
                        value.strip().lower() not in audit.PLACEHOLDERS,
                        f"bridge-review disposition has invalid {field}")
            expected = dict(base)
            expected["disposition"] = disposition
            require(record == expected, "bridge-review record differs from the inventory")

    live = evidence.get("live_shadow_reconciliation")
    require_keys(
        live,
        {
            "issued_count", "issued_amount_atomic",
            "spent_count", "spent_amount_atomic",
            "unspent_count", "unspent_amount_atomic",
            "witness_exclusion_matches_authenticated_inventory",
            "supply_lifecycle_buckets_match_authenticated_inventory",
        },
        "live shadow reconciliation",
    )
    for key in ("issued_count", "spent_count", "unspent_count"):
        require(live.get(key) == capture_manifest[key.replace("_count", "_claims")],
                f"live shadow {key} differs from the connected capture")
    require(live["issued_count"] - live["spent_count"] == live["unspent_count"],
            "live shadow claim counts do not reconcile")
    for key in ("issued_amount_atomic", "spent_amount_atomic", "unspent_amount_atomic"):
        require(isinstance(live.get(key), str) and live[key].isdigit(),
                f"live shadow {key} is invalid")
    require(int(live["issued_amount_atomic"]) - int(live["spent_amount_atomic"]) ==
            int(live["unspent_amount_atomic"]),
            "live shadow amounts do not reconcile")
    require(live["issued_count"] > 0 and live["spent_count"] == 0 and
            int(live["issued_amount_atomic"]) > 0 and
            int(live["spent_amount_atomic"]) == 0,
            "live Gold Rush witness inventory is not issuance-only")
    require(live.get("witness_exclusion_matches_authenticated_inventory") is True and
            live.get("supply_lifecycle_buckets_match_authenticated_inventory") is True,
            "live shadow inventory reconciliation is incomplete")
    excluded = current.get("excluded_synthetic_shadow")
    require(audit._inventory_bucket(excluded, "excluded synthetic shadow") ==
            (live["unspent_count"], int(live["unspent_amount_atomic"])),
            "inventory synthetic exclusion differs from live shadow state")
    return review


def verify_evidence_document(evidence, capture_manifest, contract, *,
                             target_sha, manifest_sha256, contract_sha256,
                             actual_binaries=None, now=None,
                             maximum_age_seconds=MAXIMUM_CAPTURE_AGE_SECONDS):
    try:
        resource_verifier.verify_contract(contract)
    except RuntimeError as error:
        raise VerificationError(
            f"production resource contract is invalid: {error}"
        ) from error
    require_keys(
        evidence,
        {
            "schema", "source", "binaries", "rpc_server", "network",
            "snapshot", "phase_schedule", "inventory",
            "live_shadow_reconciliation", "bridge_review",
            "native_quantum_formats", "acceptance",
            "evidence_payload_sha256",
        },
        "witness evidence",
    )
    claimed_payload = evidence.get("evidence_payload_sha256")
    require(isinstance(claimed_payload, str) and SHA256_RE.fullmatch(claimed_payload),
            "witness evidence payload SHA256 is invalid")
    unhashed = copy.deepcopy(evidence)
    unhashed.pop("evidence_payload_sha256", None)
    computed_payload = hashlib.sha256(audit.canonical_bytes(unhashed)).hexdigest()
    require(computed_payload == claimed_payload,
            "witness evidence payload SHA256 does not match its contents")
    require(evidence.get("schema") == audit.EVIDENCE_SCHEMA,
            "unexpected witness evidence schema")
    require(audit.FULL_SHA_RE.fullmatch(target_sha) is not None,
            "target SHA must be a full lowercase Git commit")

    verify_capture_manifest(
        capture_manifest, contract, contract_sha256=contract_sha256,
        manifest_sha256=manifest_sha256, target_sha=target_sha, now=now,
        maximum_age_seconds=maximum_age_seconds,
    )
    source = evidence.get("source")
    require_keys(source, {"repository", "commit", "clean"}, "witness source")
    require(source.get("commit") == target_sha and source.get("clean") is True and
            isinstance(source.get("repository"), str) and
            resource_verifier.normalize_repository_url(source["repository"]) ==
            "Blackcoin-Dev/Blackcoin",
            "witness evidence source identity is not the clean final candidate")
    binaries = evidence.get("binaries")
    require(isinstance(binaries, dict) and set(binaries) ==
            {"blackcoind", "blackcoin_cli"}, "witness binary inventory is incomplete")
    if actual_binaries is not None:
        require(binaries == actual_binaries,
                "bundled witness binaries differ from the evidence binary inventory")
    for label, identity in binaries.items():
        require_keys(
            identity,
            {"sha256", "version", "source_commit", "source_dirty"},
            f"{label} identity",
        )
        require(identity.get("source_commit") == target_sha and
                identity.get("source_dirty") is False and
                isinstance(identity.get("sha256"), str) and
                SHA256_RE.fullmatch(identity["sha256"]) and
                f"Source commit: {target_sha}" in identity.get("version", "").splitlines(),
                f"{label} is not bound to the clean final source")

    server = evidence.get("rpc_server")
    require_keys(
        server,
        {
            "launched_by_acceptance_verifier", "non_daemonized_process",
            "pid", "executable", "executable_sha256",
            "process_image_binding", "rpc_endpoint", "rpc_authentication",
            "rpc_reported_build", "rpc_reported_source_commit",
            "rpc_reported_source_dirty", "wallet_disabled",
            "staking_disabled", "pow_mining_disabled",
            "network_frozen_during_snapshot",
        },
        "witness RPC server",
    )
    require(server.get("launched_by_acceptance_verifier") is True and
            server.get("non_daemonized_process") is True and
            server.get("executable_sha256") == binaries["blackcoind"]["sha256"] and
            server.get("rpc_reported_source_commit") == target_sha and
            server.get("rpc_reported_source_dirty") is False and
            server.get("wallet_disabled") is True and
            server.get("staking_disabled") is True and
            server.get("pow_mining_disabled") is True and
            server.get("network_frozen_during_snapshot") is True,
            "witness RPC server is not bound to an isolated exact candidate")
    process_image = server.get("process_image_binding")
    auth = server.get("rpc_authentication")
    require_keys(
        process_image, {"mechanism", "observed_path", "sha256"},
        "witness process image",
    )
    require(process_image.get("mechanism") == "linux_proc_pid_exe" and
            process_image.get("sha256") == binaries["blackcoind"]["sha256"],
            "witness RPC process image is not bound to the candidate daemon")
    require_keys(
        auth,
        {"mechanism", "private_directory_mode", "cookie_path", "secret_recorded"},
        "witness RPC authentication",
    )
    require(auth.get("mechanism") ==
            "verifier_owned_cookie" and auth.get("private_directory_mode") == "0700" and
            auth.get("secret_recorded") is False,
            "witness RPC authentication was not verifier-owned")
    require(isinstance(server.get("pid"), int) and server["pid"] > 0 and
            isinstance(server.get("rpc_reported_build"), str) and
            server["rpc_reported_build"] in binaries["blackcoind"]["version"],
            "witness RPC runtime identity is incomplete")

    network = evidence.get("network")
    require_keys(
        network,
        {"chain", "genesis_hash", "protocol_version", "subversion"},
        "witness network",
    )
    require(network.get("chain") == "main" and
            network.get("genesis_hash") == audit.MAINNET_GENESIS_HASH,
            "witness evidence is not Blackcoin mainnet")
    snapshot = evidence.get("snapshot")
    require_keys(
        snapshot,
        {
            "height", "bestblock", "block_time", "utxo_muhash",
            "utxo_txouts", "independent_gettxoutsetinfo_match",
        },
        "witness snapshot",
    )
    require(snapshot.get("height") == capture_manifest["end_height"] and
            snapshot.get("bestblock") == capture_manifest["end_hash"] and
            isinstance(snapshot.get("utxo_muhash"), str) and
            SHA256_RE.fullmatch(snapshot["utxo_muhash"]) and
            isinstance(snapshot.get("utxo_txouts"), int) and
            snapshot["utxo_txouts"] >= 0 and
            snapshot.get("independent_gettxoutsetinfo_match") is True,
            "witness UTXO snapshot differs from the protected capture")
    phase = evidence.get("phase_schedule")
    require_keys(
        phase,
        {
            "phase", "phase_context", "active_tip_phase", "next_block_phase",
            "active_tip_height", "next_block_height",
            "lifecycle_schedule_valid", "v4_activation_height",
            "gold_rush_end_height", "quantum_migration_end_height",
            "height_boundaries_authoritative", "time_boundaries_are_estimates",
            "shadow_reward_start_height", "shadow_reward_end_height",
            "shadow_reward_next_height", "shadow_merge_mining_active",
            "shadow_reward_height_active", "qqp4_activation_disabled",
            "qqp4_activation_height", "qqp4_active_at_tip",
            "qqp4_active_next_block", "qqp4_exact_input_required_next_block",
            "quantum_spend_enforcement_active",
            "quantum_migration_outputs_fundable", "legacy_addresses_accepted",
            "quantum_address_required",
        },
        "witness phase schedule",
    )
    next_height = snapshot["height"] + 1
    active_phase = audit._mainnet_phase(snapshot["height"])
    next_phase = audit._mainnet_phase(next_height)
    next_quantum_active = next_phase in {"migration", "final_lockout"}
    next_final = next_phase == "final_lockout"
    require(phase.get("phase_context") == "next_block" and
            phase.get("phase") == next_phase and
            phase.get("active_tip_phase") == active_phase and
            phase.get("next_block_phase") == next_phase and
            phase.get("active_tip_height") == snapshot["height"] and
            phase.get("next_block_height") == next_height and
            phase.get("lifecycle_schedule_valid") is True and
            phase.get("height_boundaries_authoritative") is True and
            phase.get("time_boundaries_are_estimates") is True and
            phase.get("v4_activation_height") == audit.MAINNET_V4_HEIGHT and
            phase.get("gold_rush_end_height") == audit.MAINNET_GOLD_RUSH_END_HEIGHT and
            phase.get("quantum_migration_end_height") == audit.MAINNET_MIGRATION_END_HEIGHT and
            phase.get("shadow_reward_start_height") == audit.MAINNET_V4_HEIGHT and
            phase.get("shadow_reward_end_height") == audit.MAINNET_GOLD_RUSH_END_HEIGHT and
            phase.get("shadow_reward_next_height") == next_height and
            phase.get("shadow_merge_mining_active") is True and
            phase.get("shadow_reward_height_active") is
                (next_height <= audit.MAINNET_GOLD_RUSH_END_HEIGHT) and
            phase.get("quantum_spend_enforcement_active") is next_quantum_active and
            phase.get("quantum_migration_outputs_fundable") is next_quantum_active and
            phase.get("legacy_addresses_accepted") is (not next_final) and
            phase.get("quantum_address_required") is next_final and
            phase.get("qqp4_activation_disabled") is True and
            phase.get("qqp4_activation_height") == 0 and
            phase.get("qqp4_active_at_tip") is False and
            phase.get("qqp4_active_next_block") is False and
            phase.get("qqp4_exact_input_required_next_block") is False,
            "witness lifecycle schedule differs from the final mainnet contract")

    review = verify_inventory(evidence, capture_manifest)
    acceptance = evidence.get("acceptance")
    for field in (
        "tip_unchanged_across_all_calls", "all_inventory_pages_same_snapshot",
        "all_declared_records_enumerated_once",
        "utxo_commitment_independently_reconciled", "bridge_review_complete",
        "mainnet_identity_and_schedule_exact", "rpc_server_exact_binary_bound",
        "live_shadow_inventory_reconciled",
    ):
        require(acceptance.get(field) is True, f"witness acceptance is incomplete: {field}")

    return {
        "schema": AUTHORIZATION_SCHEMA,
        "authorized": True,
        "mode": AUTHORIZED_MODE,
        "target_sha": target_sha,
        "network": "main",
        "capture_manifest_sha256": manifest_sha256,
        "production_contract_sha256": contract_sha256,
        "evidence_payload_sha256": claimed_payload,
        "snapshot": {
            "height": snapshot["height"],
            "bestblock": snapshot["bestblock"],
            "utxo_muhash": snapshot["utxo_muhash"],
            "utxo_txouts": snapshot["utxo_txouts"],
            "captured_at_unix": capture_manifest["captured_at_unix"],
        },
        "bridge_review": {
            "result": review["result"],
            "count": review["count"],
            "dispositions_file_sha256": acceptance.get("dispositions_file_sha256"),
        },
        "binaries": {
            "blackcoind_sha256": binaries["blackcoind"]["sha256"],
            "blackcoin_cli_sha256": binaries["blackcoin_cli"]["sha256"],
        },
        "scope": (
            "exact connected-tip mainnet value-bearing witness-v2-through-v16 "
            "UTXO inventory with same-tip MuHash and live shadow reconciliation"
        ),
    }


def write_json(path, value):
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
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
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--capture-manifest", type=Path, required=True)
    parser.add_argument("--capture-manifest-sha256", required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--blackcoind", type=Path, required=True)
    parser.add_argument("--blackcoin-cli", type=Path, required=True)
    parser.add_argument("--authorization-output", type=Path, required=True)
    parser.add_argument("--maximum-age-seconds", type=int,
                        default=MAXIMUM_CAPTURE_AGE_SECONDS)
    args = parser.parse_args()
    try:
        repo = args.repo_root.resolve()
        source = audit.verify_source_checkout(repo, args.target_sha)
        require(resource_verifier.normalize_repository_url(source["repository"]) ==
                "Blackcoin-Dev/Blackcoin", "checked-out origin is not Blackcoin-Dev/Blackcoin")
        evidence = load_json(args.evidence, "witness evidence")
        manifest = load_json(args.capture_manifest, "capture manifest")
        contract = load_json(args.contract, "production resource contract")
        actual_manifest_sha = sha256_file(args.capture_manifest)
        require(actual_manifest_sha == args.capture_manifest_sha256,
                "capture manifest bytes differ from the requested digest")
        contract_sha = sha256_file(args.contract)
        actual_binaries = {
            "blackcoind": audit.verify_binary(
                args.blackcoind, args.target_sha, "blackcoind", isolated_datadir=True,
            ),
            "blackcoin_cli": audit.verify_binary(
                args.blackcoin_cli, args.target_sha, "blackcoin-cli",
            ),
        }
        authorization = verify_evidence_document(
            evidence, manifest, contract, target_sha=args.target_sha,
            manifest_sha256=actual_manifest_sha, contract_sha256=contract_sha,
            actual_binaries=actual_binaries,
            maximum_age_seconds=args.maximum_age_seconds,
        )
        write_json(args.authorization_output, authorization)
    except (audit.AuditError, VerificationError, OSError) as error:
        parser.exit(1, f"quantum witness evidence verification failed: {error}\n")
    print(f"wrote {args.authorization_output}")


if __name__ == "__main__":
    main()
