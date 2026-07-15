#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Generate fail-closed, source-bound quantum witness inventory evidence."""

import argparse
from contextlib import AbstractContextManager
from decimal import Decimal
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time


INVENTORY_SCHEMA = "blackcoin.quantum.witness_inventory.v1"
INVENTORY_CLASSIFICATION = (
    "native value-bearing witness versions >1; "
    "exact v14/v15/v16/unknown and active-chain origin phase"
)
EVIDENCE_SCHEMA = "blackcoin.quantum.witness_inventory.acceptance.v1"
DISPOSITIONS_SCHEMA = "blackcoin.quantum.witness_bridge_dispositions.v1"
FULL_SHA_RE = re.compile(r"[0-9a-f]{40}")
HASH_RE = re.compile(r"[0-9a-f]{64}")
PLACEHOLDERS = {"", "n/a", "none", "tbd", "todo", "unknown"}
MAINNET_GENESIS_HASH = "000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563"
MAINNET_V4_HEIGHT = 5_950_000
MAINNET_GOLD_RUSH_END_HEIGHT = 6_192_999
MAINNET_MIGRATION_END_HEIGHT = 6_921_999
ATOMIC_UNITS = Decimal(100_000_000)


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


def _run(command, *, cwd=None, timeout=3600):
    try:
        result = subprocess.run(
            [str(item) for item in command], cwd=cwd, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout,
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
    source_identity = f"Source commit: {source_sha}"
    if source_identity not in version.splitlines():
        raise AuditError(
            f"{label} does not identify clean source commit {source_sha}; "
            "the full immutable source identity is absent or dirty"
        )
    return {
        "sha256": file_sha256(path),
        "version": version,
        "source_commit": source_sha,
        "source_dirty": False,
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


def _reserve_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _argument_name(argument):
    name = argument.lstrip("-").split("=", 1)[0].lower()
    # ArgsManager accepts -nofoo and -nofoo=0 as aliases that can invert foo.
    # Normalize those aliases before checking verifier-owned settings.
    if name.startswith("no") and name[2:] in VerifierOwnedDaemon.CONTROLLED_ARGUMENTS:
        return name[2:]
    return name


def _proc_process_image_identity(pid, expected_sha256, *, proc_root=Path("/proc")):
    """Hash the executable inode held by a running Linux process."""
    executable_link = Path(proc_root) / str(pid) / "exe"
    try:
        observed_path = os.readlink(executable_link)
        observed_sha256 = file_sha256(executable_link)
    except OSError as error:
        raise AuditError(
            f"unable to bind RPC server PID {pid} through {executable_link}: {error}"
        ) from error
    _require(observed_sha256 == expected_sha256,
             "running blackcoind process image differs from the verified candidate binary")
    return {
        "mechanism": "linux_proc_pid_exe",
        "observed_path": observed_path,
        "sha256": observed_sha256,
    }


class VerifierOwnedDaemon(AbstractContextManager):
    """Launch the exact candidate daemon on a private RPC endpoint.

    The process is deliberately not daemonized. The Popen PID therefore names
    the executable passed to this verifier, while the private random RPC port
    and source-bearing RPC build identity prevent an unrelated resident node
    from supplying evidence.
    """

    CONTROLLED_ARGUMENTS = {
        "datadir", "daemon", "daemonwait", "server", "disablewallet", "wallet",
        "staking", "powmining", "networkactive", "listen", "testnet",
        "regtest", "signet", "rpcbind", "rpcallowip", "rpcconnect",
        "rpcport", "rpcuser", "rpcpassword", "rpcauth", "rpccookiefile",
        "chain",
    }

    def __init__(self, daemon, cli, datadir, daemon_args, *, startup_timeout=900):
        self.daemon = str(Path(daemon).resolve())
        self.cli = str(Path(cli).resolve())
        self.datadir = str(Path(datadir).resolve())
        self.daemon_args = list(daemon_args)
        self.startup_timeout = startup_timeout
        self.process = None
        self.temporary = None
        self.log_file = None
        self.rpc_port = None
        self.cli_options = None
        self.cookie_path = None

    def _log_tail(self):
        if self.log_file is None:
            return ""
        self.log_file.flush()
        try:
            text = Path(self.log_file.name).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return text[-4000:]

    def __enter__(self):
        datadir = Path(self.datadir)
        if not datadir.is_dir():
            raise AuditError(f"mainnet datadir does not exist: {datadir}")
        for argument in self.daemon_args:
            if not isinstance(argument, str) or not argument.startswith("-"):
                raise AuditError("every --daemon-arg must be a single option beginning with '-'")
            if _argument_name(argument) in self.CONTROLLED_ARGUMENTS:
                raise AuditError(
                    f"--daemon-arg may not override verifier-controlled option: {argument}"
                )

        self.temporary = tempfile.TemporaryDirectory(prefix="blackcoin-witness-daemon-")
        os.chmod(self.temporary.name, 0o700)
        self.log_file = tempfile.NamedTemporaryFile(
            mode="w+", encoding="utf-8", dir=self.temporary.name,
            prefix="blackcoind-", suffix=".log", delete=False,
        )
        self.rpc_port = _reserve_loopback_port()
        self.cookie_path = str(Path(self.temporary.name) / "rpc-auth.cookie")
        command = [
            self.daemon,
            *self.daemon_args,
            f"-datadir={self.datadir}",
            "-daemon=0",
            "-server=1",
            "-disablewallet=1",
            "-staking=0",
            "-powmining=0",
            "-networkactive=0",
            "-listen=0",
            "-testnet=0",
            "-regtest=0",
            "-signet=0",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            f"-rpcport={self.rpc_port}",
            f"-rpccookiefile={self.cookie_path}",
        ]
        self.cli_options = [
            f"-datadir={self.datadir}",
            "-rpcconnect=127.0.0.1",
            f"-rpcport={self.rpc_port}",
            f"-rpccookiefile={self.cookie_path}",
        ]
        try:
            try:
                self.process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=self.log_file,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            except OSError as error:
                raise AuditError(
                    f"unable to launch exact candidate blackcoind: {error}"
                ) from error

            deadline = time.monotonic() + self.startup_timeout
            while time.monotonic() < deadline:
                returncode = self.process.poll()
                if returncode is not None:
                    raise AuditError(
                        f"exact candidate blackcoind exited during startup ({returncode}): "
                        f"{self._log_tail()}"
                    )
                try:
                    _run(
                        [self.cli, *self.cli_options, "getnetworkinfo"],
                        timeout=15,
                    )
                    return self
                except AuditError:
                    time.sleep(1)
            raise AuditError(
                f"exact candidate blackcoind did not become RPC-ready within "
                f"{self.startup_timeout}s: {self._log_tail()}"
            )
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def identity(self, source_sha, daemon_sha256, network_info):
        _require(self.process is not None and self.process.poll() is None,
                 "verifier-owned blackcoind is no longer running")
        _require(sys.platform.startswith("linux"),
                 "production witness evidence requires Linux /proc process-image binding")
        process_image = _proc_process_image_identity(
            self.process.pid, daemon_sha256,
        )
        rpc_build = network_info.get("build")
        _require(isinstance(rpc_build, str) and rpc_build and
                 network_info.get("source_commit") == source_sha and
                 network_info.get("source_dirty") is False,
                 "RPC server build is not bound to the clean candidate source")
        return {
            "launched_by_acceptance_verifier": True,
            "non_daemonized_process": True,
            "pid": self.process.pid,
            "executable": self.daemon,
            "executable_sha256": daemon_sha256,
            "process_image_binding": process_image,
            "rpc_endpoint": f"127.0.0.1:{self.rpc_port}",
            "rpc_authentication": {
                "mechanism": "verifier_owned_cookie",
                "private_directory_mode": "0700",
                "cookie_path": self.cookie_path,
                "secret_recorded": False,
            },
            "rpc_reported_build": rpc_build,
            "rpc_reported_source_commit": source_sha,
            "rpc_reported_source_dirty": False,
            "wallet_disabled": True,
            "staking_disabled": True,
            "pow_mining_disabled": True,
            "network_frozen_during_snapshot": True,
        }

    def __exit__(self, exc_type, _exc_value, _traceback):
        shutdown_error = None
        if self.process is not None and self.process.poll() is None:
            try:
                subprocess.run(
                    [self.cli, *self.cli_options, "stop"],
                    check=False, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=30,
                )
                self.process.wait(timeout=120)
            except (OSError, subprocess.TimeoutExpired) as error:
                shutdown_error = error
                self.process.terminate()
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=30)
        if self.log_file is not None:
            self.log_file.close()
        if self.temporary is not None:
            self.temporary.cleanup()
        if exc_type is None and shutdown_error is not None:
            raise AuditError(f"exact candidate blackcoind did not stop cleanly: {shutdown_error}")
        return False


def _require(condition, message):
    if not condition:
        raise AuditError(message)


def _outpoint_key(record):
    txid = record.get("txid")
    vout = record.get("vout")
    _require(isinstance(txid, str) and HASH_RE.fullmatch(txid), "inventory record has an invalid txid")
    _require(isinstance(vout, int) and 0 <= vout <= 0xffffffff, "inventory record has an invalid vout")
    return f"{txid}:{vout}"


def _amount_atomic(value, label):
    try:
        amount = Decimal(value)
    except Exception as error:
        raise AuditError(f"{label} is not a decimal amount") from error
    atomic = amount * ATOMIC_UNITS
    _require(amount.is_finite() and amount >= 0 and atomic == atomic.to_integral_value(),
             f"{label} is not a non-negative 8-decimal amount")
    return int(atomic)


def _inventory_bucket(bucket, label):
    _require(isinstance(bucket, dict), f"{label} inventory bucket is missing")
    count = bucket.get("count")
    atomic_text = bucket.get("amount_atomic")
    _require(isinstance(count, int) and count >= 0,
             f"{label} inventory count is invalid")
    _require(isinstance(atomic_text, str) and atomic_text.isdigit(),
             f"{label} inventory atomic amount is invalid")
    atomic = int(atomic_text)
    _require(_amount_atomic(bucket.get("amount"), f"{label} inventory amount") == atomic,
             f"{label} inventory display and atomic amounts disagree")
    return count, atomic


def review_class(record):
    """Return the bridge-review class, or None for a safely originated native format."""
    version = record.get("witness_version")
    version_class = record.get("version_class")
    handling = record.get("bridge_handling")
    origin_group = record.get("origin_group")
    expected_class = {14: "v14", 15: "v15", 16: "v16"}.get(version, "unknown")
    _require(version_class == expected_class, f"{_outpoint_key(record)} has inconsistent version classification")
    _require(
        origin_group in {"pre_migration_window", "migration_or_later"},
        f"{_outpoint_key(record)} has an invalid origin group",
    )

    if version == 14:
        _require(
            handling in {
                "recognized_quantum_cold_stake",
                "unknown_or_malformed_witness_program_requires_explicit_review",
            },
            f"{_outpoint_key(record)} has an unknown v14 handling class",
        )
        if handling != "recognized_quantum_cold_stake":
            return "malformed_v14"
        return None if origin_group == "migration_or_later" else "pre_migration_v14"
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
        if handling != "recognized_direct_quantum":
            return "malformed_v16"
        return None if origin_group == "migration_or_later" else "pre_migration_v16"

    _require(
        isinstance(version, int) and 2 <= version <= 16 and
        handling == "unknown_or_malformed_witness_program_requires_explicit_review",
        f"{_outpoint_key(record)} has an inconsistent unknown-witness classification",
    )
    return "unknown_witness_version"


def _validate_inventory_record(record, snapshot_height):
    _require(isinstance(record, dict), "inventory contains a non-object record")
    key = _outpoint_key(record)
    amount_atomic = _amount_atomic(record.get("amount"), f"{key} amount")
    _require(amount_atomic > 0, f"{key} is not value-bearing")
    version = record.get("witness_version")
    script_hex = record.get("scriptPubKey")
    _require(isinstance(version, int) and 2 <= version <= 16,
             f"{key} has an invalid witness version")
    _require(isinstance(script_hex, str) and len(script_hex) % 2 == 0 and
             re.fullmatch(r"[0-9a-f]+", script_hex) is not None,
             f"{key} has an invalid scriptPubKey")
    script = bytes.fromhex(script_hex)
    expected_opcode = 0x50 + version
    _require(4 <= len(script) <= 42 and script[0] == expected_opcode and
             script[1] == len(script) - 2 and 2 <= script[1] <= 40,
             f"{key} scriptPubKey does not encode its declared witness version")
    origin_height = record.get("origin_height")
    origin_hash = record.get("origin_blockhash")
    origin_phase = record.get("origin_phase")
    origin_group = record.get("origin_group")
    _require(isinstance(origin_height, int) and 0 <= origin_height <= snapshot_height,
             f"{key} has an invalid origin height")
    _require(isinstance(origin_hash, str) and HASH_RE.fullmatch(origin_hash),
             f"{key} has an invalid origin block hash")
    expected_group = {
        "pre_v4": "pre_migration_window",
        "gold_rush": "pre_migration_window",
        "migration": "migration_or_later",
        "final": "migration_or_later",
    }.get(origin_phase)
    _require(expected_group is not None and origin_group == expected_group,
             f"{key} has inconsistent origin phase and group")
    _require(isinstance(record.get("origin_block_time"), int) and
             isinstance(record.get("coin_time"), int),
             f"{key} has incomplete origin time provenance")
    _require(isinstance(record.get("coinbase"), bool) and
             isinstance(record.get("coinstake"), bool),
             f"{key} has invalid generation flags")
    review_class(record)
    return amount_atomic


def _expected_partition(records, field, *, cross_field=None):
    expected = {}
    for record in records:
        key = record[field]
        if cross_field is not None:
            key = f"{key}/{record[cross_field]}"
        count, amount = expected.get(key, (0, 0))
        expected[key] = (count + 1, amount + _amount_atomic(
            record["amount"], f"{_outpoint_key(record)} amount",
        ))
    return expected


def _require_partition(actual, expected, label):
    _require(isinstance(actual, dict) and set(actual) == set(expected),
             f"{label} inventory keys do not reconcile with enumerated records")
    for key, expected_bucket in expected.items():
        _require(_inventory_bucket(actual[key], f"{label}/{key}") == expected_bucket,
                 f"{label}/{key} inventory bucket does not reconcile")


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
        _require(coverage.get("snapshot_includes_synthetic_shadow_outputs") is False,
                 "inventory does not explicitly exclude synthetic shadow outputs")

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

        _require(summary["classification"] == INVENTORY_CLASSIFICATION,
                 "inventory classification contract is unexpected")
        for record in page_records:
            _validate_inventory_record(record, page_identity["height"])
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
    current = invariant_summary["current_utxos"]
    _require(isinstance(current, dict), "inventory current-UTXO aggregates are missing")
    total_expected = (
        total_records,
        sum(_amount_atomic(record["amount"], f"{_outpoint_key(record)} amount")
            for record in records),
    )
    _require(_inventory_bucket(current.get("total"), "total") == total_expected,
             "inventory total does not reconcile with enumerated records")
    for field, aggregate in (
        ("version_class", "by_version"),
        ("origin_group", "by_origin_group"),
        ("origin_phase", "by_origin_phase"),
        ("bridge_handling", "by_bridge_handling"),
    ):
        _require_partition(
            current.get(aggregate), _expected_partition(records, field), aggregate,
        )
    _require_partition(
        current.get("by_version_and_origin"),
        _expected_partition(records, "version_class", cross_field="origin_group"),
        "by_version_and_origin",
    )
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
            "scope": [
                "unknown_witness_version", "v15", "malformed_v14",
                "malformed_v16", "pre_migration_v14", "pre_migration_v16",
            ],
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
        "scope": [
            "unknown_witness_version", "v15", "malformed_v14",
            "malformed_v16", "pre_migration_v14", "pre_migration_v16",
        ],
        "result": "explicit_per_outpoint_dispositions",
        "count": len(review_records),
        "records": review_records,
    }, native_records


def _mainnet_phase(height):
    if height < MAINNET_V4_HEIGHT:
        return "legacy"
    if height <= MAINNET_GOLD_RUSH_END_HEIGHT:
        return "gold_rush"
    if height <= MAINNET_MIGRATION_END_HEIGHT:
        return "migration"
    return "final_lockout"


def validate_mainnet_identity(chain, network_info, phase, genesis_hash,
                              snapshot, source_sha):
    _require(chain == "main", "release witness evidence must be generated on mainnet")
    _require(genesis_hash == MAINNET_GENESIS_HASH,
             "RPC server does not have the immutable Blackcoin mainnet genesis")
    rpc_build = network_info.get("build")
    _require(isinstance(rpc_build, str) and rpc_build and
             network_info.get("source_commit") == source_sha and
             network_info.get("source_dirty") is False,
             "RPC server does not report the clean exact candidate source build")
    _require(network_info.get("networkactive") is False,
             "verifier-owned daemon must keep P2P frozen during the immutable scan")

    height = snapshot["height"]
    next_height = height + 1
    _require(MAINNET_V4_HEIGHT <= height <= MAINNET_GOLD_RUSH_END_HEIGHT,
             "release witness evidence must be captured during the live mainnet Gold Rush")
    exact_schedule = {
        "v4_activation_height": MAINNET_V4_HEIGHT,
        "gold_rush_end_height": MAINNET_GOLD_RUSH_END_HEIGHT,
        "quantum_migration_end_height": MAINNET_MIGRATION_END_HEIGHT,
        "shadow_reward_start_height": MAINNET_V4_HEIGHT,
        "shadow_reward_end_height": MAINNET_GOLD_RUSH_END_HEIGHT,
    }
    for field, expected in exact_schedule.items():
        _require(phase.get(field) == expected,
                 f"RPC lifecycle schedule has an unexpected {field}")
    _require(phase.get("lifecycle_schedule_valid") is True and
             phase.get("height_boundaries_authoritative") is True and
             phase.get("time_boundaries_are_estimates") is True,
             "RPC lifecycle schedule is not valid and height-authoritative")
    _require(phase.get("phase_context") == "next_block" and
             phase.get("active_tip_height") == height and
             phase.get("next_block_height") == next_height,
             "RPC lifecycle status is not bound to the inventory snapshot height")
    _require(phase.get("active_tip_phase") == _mainnet_phase(height) and
             phase.get("next_block_phase") == _mainnet_phase(next_height) and
             phase.get("phase") == _mainnet_phase(next_height),
             "RPC lifecycle phase does not match the immutable mainnet heights")
    next_quantum_active = _mainnet_phase(next_height) in {"migration", "final_lockout"}
    next_final = _mainnet_phase(next_height) == "final_lockout"
    _require(phase.get("quantum_spend_enforcement_active") is next_quantum_active and
             phase.get("quantum_migration_outputs_fundable") is next_quantum_active and
             phase.get("legacy_addresses_accepted") is (not next_final) and
             phase.get("quantum_address_required") is next_final,
             "RPC funding/spending fields do not derive from the next-block phase")
    _require(phase.get("shadow_merge_mining_active") is True and
             phase.get("shadow_reward_height_active") is
                 (next_height <= MAINNET_GOLD_RUSH_END_HEIGHT) and
             phase.get("shadow_reward_next_height") == next_height,
             "RPC Gold Rush activity fields do not match the reward-height window")
    _require(phase.get("qqp4_activation_disabled") is True and
             phase.get("qqp4_activation_height") == 0 and
             phase.get("qqp4_active_at_tip") is False and
             phase.get("qqp4_active_next_block") is False and
             phase.get("qqp4_exact_input_required_next_block") is False,
             "RPC unexpectedly reports the separately scheduled QQP4 rules active")
    return rpc_build


def reconcile_live_shadow_inventory(inventory, supply, snapshot, stats):
    _require(isinstance(supply, dict) and
             supply.get("schema") == "blackcoin.supply.lifecycle.v2",
             "unexpected circulating-supply schema")
    _require(supply.get("height") == snapshot["height"] and
             supply.get("bestblock") == snapshot["bestblock"] and
             supply.get("evaluation_height") == snapshot["height"] + 1,
             "shadow supply scan is not bound to the witness-inventory snapshot")
    _require(supply.get("height_boundaries_authoritative") is True,
             "shadow supply scan is not height-authoritative")
    _require(supply.get("txouts") == snapshot["txouts"],
             "shadow supply and witness scans disagree on UTXO count")
    _require(_amount_atomic(supply.get("nominal_amount"), "supply nominal amount") ==
             _amount_atomic(stats.get("total_amount"), "gettxoutsetinfo total amount"),
             "shadow supply and independent UTXO stats disagree on nominal value")

    excluded = inventory["current_utxos"].get("excluded_synthetic_shadow")
    shadow = supply.get("shadow")
    _require(isinstance(excluded, dict) and isinstance(shadow, dict),
             "synthetic shadow reconciliation fields are missing")
    _require(shadow.get("synthetic") is True and shadow.get("merkle_included") is False,
             "shadow supply does not identify non-Merkle synthetic issuance")
    issued_count = shadow.get("issued_count")
    spent_count = shadow.get("spent_count")
    unspent_count = shadow.get("unspent_count")
    _require(all(isinstance(value, int) and value >= 0
                 for value in (issued_count, spent_count, unspent_count)) and
             issued_count > 0 and spent_count == 0 and
             issued_count - spent_count == unspent_count,
             "live Gold Rush issued/spent/unspent counts do not reconcile")
    issued_atomic = _amount_atomic(
        shadow.get("issued_nominal_amount"), "issued shadow amount")
    spent_atomic = _amount_atomic(
        shadow.get("spent_nominal_amount"), "spent shadow amount")
    unspent_atomic = _amount_atomic(
        shadow.get("unspent_nominal_amount"), "unspent shadow amount")
    _require(issued_atomic > 0 and spent_atomic == 0 and
             issued_atomic - spent_atomic == unspent_atomic,
             "live Gold Rush issued/spent/unspent values do not reconcile")
    excluded_atomic = excluded.get("amount_atomic")
    _require(isinstance(excluded.get("count"), int) and
             isinstance(excluded_atomic, str) and excluded_atomic.isdigit() and
             excluded["count"] == unspent_count and
             int(excluded_atomic) == unspent_atomic,
             "witness scan does not exactly exclude the authenticated live shadow inventory")
    _require(_amount_atomic(
        supply.get("synthetic_non_merkle_nominal_amount"),
        "synthetic non-Merkle amount",
    ) == unspent_atomic,
             "supply scan does not reconcile its synthetic non-Merkle amount")
    immature_count = supply.get("goldrush_synthetic_immature_txouts")
    locked_payout_count = supply.get("goldrush_locked_payout_txouts")
    _require(isinstance(immature_count, int) and immature_count >= 0 and
             isinstance(locked_payout_count, int) and locked_payout_count >= 0,
             "Gold Rush lifecycle bucket counts are invalid")
    locked_count = immature_count + locked_payout_count
    locked_atomic = _amount_atomic(
        supply.get("goldrush_synthetic_immature_amount"),
        "immature synthetic amount",
    ) + _amount_atomic(
        supply.get("goldrush_locked_payout_amount"),
        "locked synthetic amount",
    )
    _require(locked_count == unspent_count and locked_atomic == unspent_atomic,
             "Gold Rush locked/immature lifecycle buckets do not cover every synthetic payout")
    _require(shadow.get("claimable_next_block") is True,
             "current Gold Rush reward pool is not reported claimable for the next block")
    return {
        "issued_count": issued_count,
        "issued_amount_atomic": str(issued_atomic),
        "spent_count": spent_count,
        "spent_amount_atomic": str(spent_atomic),
        "unspent_count": unspent_count,
        "unspent_amount_atomic": str(unspent_atomic),
        "witness_exclusion_matches_authenticated_inventory": True,
        "supply_lifecycle_buckets_match_authenticated_inventory": True,
    }


def generate_evidence(rpc, *, source, binaries, source_sha, server=None,
                      dispositions=None, dispositions_sha256=None,
                      page_size=1000, max_records=100000):
    chain_before = rpc("getblockchaininfo")
    network_info = rpc("getnetworkinfo")
    phase = rpc("getquantumquasarinfo")
    genesis_hash = rpc("getblockhash", 0)
    inventory = collect_inventory(
        rpc, page_size=page_size, max_records=max_records,
    )
    snapshot = inventory["snapshot"]

    supply = rpc("getcirculatingsupply")
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
    _require(chain_before.get("pruned") is False and chain_after.get("pruned") is False,
             "release witness evidence requires an unpruned archival node")
    _require(chain_before.get("headers") == snapshot["height"] and
             chain_after.get("headers") == snapshot["height"],
             "archival node has headers beyond its fully validated snapshot")
    rpc_build = validate_mainnet_identity(
        chain, network_info, phase, genesis_hash, snapshot, source_sha,
    )
    _require(isinstance(server, dict) and
             server.get("launched_by_acceptance_verifier") is True and
             server.get("executable_sha256") == binaries["blackcoind"]["sha256"] and
             isinstance(server.get("process_image_binding"), dict) and
             server["process_image_binding"].get("mechanism") == "linux_proc_pid_exe" and
             server["process_image_binding"].get("sha256") ==
                 binaries["blackcoind"]["sha256"] and
             isinstance(server.get("rpc_authentication"), dict) and
             server["rpc_authentication"].get("mechanism") ==
                 "verifier_owned_cookie" and
             server["rpc_authentication"].get("private_directory_mode") == "0700" and
             server["rpc_authentication"].get("secret_recorded") is False and
             server.get("rpc_reported_build") == rpc_build and
             server.get("rpc_reported_source_commit") == source_sha and
             server.get("rpc_reported_source_dirty") is False,
             "RPC server process is not bound to the exact verified blackcoind")
    _require(rpc_build in binaries["blackcoind"].get("version", ""),
             "RPC server build does not match the verified blackcoind version")
    shadow_reconciliation = reconcile_live_shadow_inventory(
        inventory, supply, snapshot, stats,
    )

    bridge_review, native_records = apply_dispositions(
        inventory["records"], dispositions=dispositions, source_sha=source_sha,
        network=chain, snapshot=snapshot,
    )
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "source": source,
        "binaries": binaries,
        "rpc_server": server,
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
                "quantum_migration_outputs_fundable",
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
        "live_shadow_reconciliation": shadow_reconciliation,
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
            "mainnet_identity_and_schedule_exact": True,
            "rpc_server_exact_binary_bound": True,
            "live_shadow_inventory_reconciled": True,
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
    parser.add_argument("--datadir", type=Path, required=True,
                        help="Cold or snapshotted unpruned mainnet datadir; no other node may use it")
    parser.add_argument("--daemon-arg", action="append", default=[],
                        help="Additional non-identity daemon option; use --daemon-arg=-dbcache=4096")
    parser.add_argument("--startup-timeout", type=int, default=900)
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
        _require(1 <= args.startup_timeout <= 3600,
                 "--startup-timeout must be between 1 and 3600 seconds")
        dispositions, dispositions_sha256 = _load_dispositions(args.dispositions)
        with VerifierOwnedDaemon(
            args.blackcoind, args.blackcoin_cli, args.datadir,
            args.daemon_arg, startup_timeout=args.startup_timeout,
        ) as daemon:
            rpc = BlackcoinCLI(args.blackcoin_cli, daemon.cli_options)
            network_info = rpc("getnetworkinfo")
            server = daemon.identity(
                args.source_sha, binaries["blackcoind"]["sha256"], network_info,
            )
            evidence = generate_evidence(
                rpc,
                source=source,
                binaries=binaries,
                source_sha=args.source_sha,
                server=server,
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
