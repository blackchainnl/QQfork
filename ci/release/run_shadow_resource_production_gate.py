#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the restart-safe current-live partial-epoch resource gate.

The external archive is a recent mainnet snapshot captured after Gold Rush
activation. It proves real blackcoind replay, lifecycle accounting, startup,
reorg, and compaction behavior at the current partial epoch. It never claims
that live mainnet already reached the future completed-epoch envelope; the
separate deterministic synthetic gate measures that exact maximum now.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time

from generate_resource_benchmark_evidence import verify_epoch_source_contract
import verify_shadow_resource_production_evidence as evidence_verifier


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def reject_symlink_components(path: Path, label: str) -> None:
    current = path.absolute()
    for candidate in (current, *current.parents):
        if candidate.exists() and candidate.is_symlink():
            raise RuntimeError(f"{label} contains a symbolic-link component")


def require_unowned_lock(path: Path, label: str) -> None:
    if not path.exists():
        return
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} lock path is unsafe")
    descriptor = os.open(path, os.O_RDWR)
    try:
        try:
            fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"{label} is owned by another process") from error
        fcntl.lockf(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(16 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    if sys.platform == "linux":
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)


def require_keys(value: dict, expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise RuntimeError(
            f"{label} fields differ: missing={sorted(expected - set(value))}, "
            f"extra={sorted(set(value) - expected)}"
        )


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def verify_fixture_manifest(manifest: dict, contract: dict, contract_sha: str,
                            target_sha: str, archive: Path) -> None:
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
        "fixture manifest",
    )
    expected = contract["live_partial_snapshot"]
    if manifest["schema"] != 2:
        raise RuntimeError("unsupported fixture manifest schema")
    if manifest["evidence_kind"] != "current_live_partial_epoch":
        raise RuntimeError("fixture is not labeled as current live partial-epoch evidence")
    if manifest["contract_sha256"] != contract_sha:
        raise RuntimeError("fixture was not generated for the exact production contract")
    if manifest["target_sha"] != target_sha:
        raise RuntimeError("fixture source commit differs from the target commit")
    if manifest["network"] != expected["network"]:
        raise RuntimeError("fixture network differs from the production contract")
    if not isinstance(manifest["captured_at_unix"], int) or isinstance(manifest["captured_at_unix"], bool) or manifest["captured_at_unix"] <= 0:
        raise RuntimeError("fixture capture time is invalid")
    capture_age = int(time.time()) - manifest["captured_at_unix"]
    if capture_age < -300:
        raise RuntimeError("fixture capture time is more than five minutes in the future")
    if capture_age > expected["maximum_capture_age_seconds"]:
        raise RuntimeError("fixture is older than the contracted live-evidence window")
    if not isinstance(manifest["end_height"], int) or isinstance(manifest["end_height"], bool):
        raise RuntimeError("fixture end_height is invalid")
    if not expected["minimum_height"] <= manifest["end_height"] <= expected["maximum_height"]:
        raise RuntimeError("live fixture tip is outside the Gold Rush interval")
    if manifest["capture_attestation"] != (
        "protected_operator_confirmed_connected_mainnet_tip"
    ):
        raise RuntimeError("fixture lacks the protected operator tip attestation")
    capture_rpc = manifest["capture_rpc"]
    require_keys(
        capture_rpc,
        {"chain", "blocks", "headers", "bestblockhash",
         "initialblockdownload", "connections"},
        "fixture capture RPC",
    )
    if (
        capture_rpc["chain"] != expected["network"]
        or capture_rpc["blocks"] != manifest["end_height"]
        or capture_rpc["headers"] != manifest["end_height"]
        or capture_rpc["bestblockhash"] != manifest["end_hash"]
        or capture_rpc["initialblockdownload"] is not False
        or not isinstance(capture_rpc["connections"], int)
        or isinstance(capture_rpc["connections"], bool)
        or capture_rpc["connections"] < 1
    ):
        raise RuntimeError("fixture capture RPC does not attest a connected exact tip")
    for key in ("end_hash", "pre_gold_rush_hash", "first_gold_rush_hash"):
        if not isinstance(manifest[key], str) or not HASH_RE.fullmatch(manifest[key]):
            raise RuntimeError(f"fixture {key} must be a full lowercase block hash")
    for key in ("issued_claims", "spent_claims", "unspent_claims"):
        if not isinstance(manifest[key], int) or isinstance(manifest[key], bool) or manifest[key] < 0:
            raise RuntimeError(f"fixture {key} is invalid")
    if manifest["issued_claims"] <= 0 or manifest["spent_claims"] > manifest["issued_claims"] or manifest["unspent_claims"] != manifest["issued_claims"] - manifest["spent_claims"]:
        raise RuntimeError("live fixture claim inventory is inconsistent")
    if not isinstance(manifest["archive_root"], str) or not manifest["archive_root"]:
        raise RuntimeError("fixture archive_root must be non-empty")
    root = Path(manifest["archive_root"])
    if root.is_absolute() or ".." in root.parts or len(root.parts) != 1:
        raise RuntimeError("fixture archive_root must be one safe relative directory")
    if not SHA256_RE.fullmatch(str(manifest["archive_sha256"])):
        raise RuntimeError("fixture archive SHA256 is invalid")
    if not isinstance(manifest["archive_size_bytes"], int) or isinstance(manifest["archive_size_bytes"], bool) or manifest["archive_size_bytes"] <= 0:
        raise RuntimeError("fixture archive size is invalid")
    verify_fixture_archive(archive, manifest)


def verify_fixture_archive(archive: Path, manifest: dict) -> None:
    """Authenticate the exact archive pathname used by extraction.

    The protected runner can live for several days. Rechecking immediately
    around extraction prevents an ordinary capture refresh or atomic pathname
    replacement from making the evidence attest one archive while replaying
    another. The protected-runner trust boundary still excludes a malicious
    exact ABA replacement.
    """
    if not archive.is_file() or archive.is_symlink():
        raise RuntimeError("fixture archive is missing or not a regular file")
    if archive.stat().st_size != manifest["archive_size_bytes"]:
        raise RuntimeError("fixture archive size differs from the manifest")
    actual_archive_sha = sha256_file(archive)
    if actual_archive_sha != manifest["archive_sha256"]:
        raise RuntimeError("fixture archive SHA256 differs from the manifest")


def safe_extract(archive: Path, destination: Path, expected_root: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members = bundle.getmembers()
            if not members:
                raise RuntimeError("fixture archive is empty")
            seen = set()
            for member in members:
                path = Path(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not path.parts
                    or path.parts[0] != expected_root
                    or member.issym()
                    or member.islnk()
                    or member.isdev()
                ):
                    raise RuntimeError(f"unsafe fixture archive member: {member.name}")
                if member.name in seen:
                    raise RuntimeError(f"duplicate fixture archive member: {member.name}")
                seen.add(member.name)
            # The data filter also normalizes permissions and rejects platform-
            # specific special files on Python versions that support it.
            try:
                bundle.extractall(destination, members=members, filter="data")
            except TypeError:
                bundle.extractall(destination, members=members)
    except (OSError, tarfile.TarError) as error:
        raise RuntimeError(f"cannot extract fixture archive: {error}") from error


def chainstate_snapshot(
        chainstate: Path, *, include_files: bool = False,
        tolerate_churn: bool = False) -> dict:
    totals = {
        "total_bytes": 0,
        "sst_bytes": 0,
        "wal_bytes": 0,
        "manifest_bytes": 0,
        "other_bytes": 0,
        "file_count": 0,
    }
    files = {}
    if not chainstate.is_dir():
        if tolerate_churn:
            return totals
        raise RuntimeError(f"chainstate directory is missing: {chainstate}")
    pending = [chainstate]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                    except FileNotFoundError as error:
                        if tolerate_churn:
                            continue
                        raise RuntimeError(
                            f"chainstate file disappeared: {entry.path}"
                        ) from error
                    if stat.S_ISLNK(metadata.st_mode):
                        raise RuntimeError(
                            f"chainstate contains a symbolic link: {entry.path}"
                        )
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(Path(entry.path))
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        continue
                    path = Path(entry.path)
                    size = metadata.st_size
                    relative = str(path.relative_to(chainstate))
                    files[relative] = size
                    totals["total_bytes"] += size
                    totals["file_count"] += 1
                    name = entry.name
                    if path.suffix in (".ldb", ".sst"):
                        totals["sst_bytes"] += size
                    elif path.suffix == ".log" and path.stem.isdigit():
                        totals["wal_bytes"] += size
                    elif name.startswith("MANIFEST-"):
                        totals["manifest_bytes"] += size
                    else:
                        totals["other_bytes"] += size
        except FileNotFoundError as error:
            if tolerate_churn:
                continue
            raise RuntimeError(
                f"chainstate directory disappeared: {directory}"
            ) from error
    if include_files:
        totals["_files"] = files
    return totals


def public_snapshot(snapshot: dict) -> dict:
    return {key: value for key, value in snapshot.items() if key != "_files"}


def disappeared_bytes(before: dict, after: dict) -> int:
    prior = before.get("_files", {})
    current = after.get("_files", {})
    return sum(size for name, size in prior.items() if name not in current)


def process_rss_bytes(pid: int) -> int:
    status = Path(f"/proc/{pid}/status")
    try:
        lines = status.read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        return 0
    except OSError as error:
        raise RuntimeError(f"cannot read Linux process resource data: {error}") from error
    values = {}
    for line in lines:
        if line.startswith(("VmRSS:", "VmHWM:")):
            name, raw, unit = line.split()
            if unit != "kB":
                raise RuntimeError(f"unexpected /proc memory unit: {unit}")
            values[name[:-1]] = int(raw) * 1024
    if not values:
        raise RuntimeError("Linux process RSS/HWM fields are missing")
    return max(values.values())


class PhaseSampler:
    def __init__(self, pid: int, chainstate: Path, interval: int):
        self.pid = pid
        self.chainstate = chainstate
        self.interval = interval
        self.stop_event = threading.Event()
        self.failure = None
        self.sample_count = 0
        self.maximum_sample_seconds = 0.0
        self.maximum_sample_gap_seconds = 0.0
        self.last_sample_started = None
        self.peak = {
            "peak_rss_bytes": 0,
            "peak_chainstate_bytes": 0,
            "peak_sst_bytes": 0,
            "peak_wal_bytes": 0,
            "peak_manifest_bytes": 0,
            "peak_other_bytes": 0,
        }
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _sample(self) -> None:
        started = time.monotonic()
        if self.last_sample_started is not None:
            self.maximum_sample_gap_seconds = max(
                self.maximum_sample_gap_seconds,
                started - self.last_sample_started,
            )
        self.last_sample_started = started
        rss = process_rss_bytes(self.pid)
        try:
            snapshot = chainstate_snapshot(
                self.chainstate, tolerate_churn=True
            )
        except RuntimeError:
            # Symbolic links and unsupported entries remain fatal even for a
            # periodic sample. Only ordinary LevelDB rename/delete churn is
            # tolerated; closed-database endpoints remain strict.
            raise
        self.peak["peak_rss_bytes"] = max(self.peak["peak_rss_bytes"], rss)
        for source, target in (
            ("total_bytes", "peak_chainstate_bytes"),
            ("sst_bytes", "peak_sst_bytes"),
            ("wal_bytes", "peak_wal_bytes"),
            ("manifest_bytes", "peak_manifest_bytes"),
            ("other_bytes", "peak_other_bytes"),
        ):
            self.peak[target] = max(self.peak[target], snapshot[source])
        self.sample_count += 1
        self.maximum_sample_seconds = max(
            self.maximum_sample_seconds, time.monotonic() - started
        )

    def _run(self) -> None:
        try:
            while not self.stop_event.wait(self.interval):
                self._sample()
        except Exception as error:  # propagated by finish()
            self.failure = error

    def start(self) -> None:
        self._sample()
        self.thread.start()

    def finish(self) -> dict:
        self.stop_event.set()
        self.thread.join()
        if self.failure is not None:
            raise RuntimeError(f"resource sampler failed: {self.failure}") from self.failure
        self._sample()
        result = dict(self.peak)
        result.update(
            sample_count=self.sample_count,
            maximum_sample_seconds=self.maximum_sample_seconds,
            maximum_sample_gap_seconds=self.maximum_sample_gap_seconds,
        )
        return result


class Daemon:
    def __init__(self, process: subprocess.Popen, log_handle, log_path: Path):
        self.process = process
        self.log_handle = log_handle
        self.log_path = log_path

    def close_log(self) -> None:
        self.log_handle.close()


class ProductionGate:
    def __init__(self, args, contract: dict, manifest: dict, binding: dict):
        self.args = args
        self.contract = contract
        self.manifest = manifest
        self.binding = binding
        self.work = args.work_dir
        self.datadir = self.work / "fixture" / manifest["archive_root"]
        self.chainstate = self.datadir / "chainstate"
        self.journal_path = self.work / "journal.json"
        self.snapshot_root = self.work / "live-predecessor"
        self.snapshot_marker = self.work / "live-predecessor.json"
        self.logs = self.work / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)
        self.lock_fd = os.open(
            self.work / ".shadow-resource.lock",
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self.lock_fd)
            raise RuntimeError(
                "another live gate or surviving daemon owns this work directory"
            ) from error
        self.interval = contract["measurement"]["sample_interval_seconds"]
        self.network_args = ["-chain=main"]
        self.current_daemon = None
        try:
            self.journal = self._load_journal()
        except BaseException:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise

    def _load_journal(self) -> dict:
        if not self.journal_path.exists():
            return {
                "schema": 2,
                "binding": self.binding,
                "active_phase": None,
                "completed": {},
            }
        journal = load_json(self.journal_path, "resource gate journal")
        require_keys(
            journal,
            {"schema", "binding", "active_phase", "completed"},
            "journal",
        )
        if journal["schema"] != 2 or journal["binding"] != self.binding:
            raise RuntimeError(
                "existing work directory belongs to a different source, binary, contract, or fixture"
            )
        if (
            journal["active_phase"] is not None
            and not isinstance(journal["active_phase"], str)
        ):
            raise RuntimeError("resource gate journal active phase is invalid")
        if not isinstance(journal["completed"], dict):
            raise RuntimeError("resource gate journal completion map is invalid")
        return journal

    def save_stage(self, name: str, value) -> None:
        active = self.journal["active_phase"]
        if active is not None and active != name:
            raise RuntimeError(
                f"cannot complete resource stage {name} while {active} is active"
            )
        self.journal["completed"][name] = value
        self.journal["active_phase"] = None
        atomic_json(self.journal_path, self.journal)

    def begin_stage(self, name: str) -> bool:
        active = self.journal["active_phase"]
        if active is not None and active != name:
            raise RuntimeError(
                f"resource gate journal has interrupted {active} while "
                f"starting {name}"
            )
        interrupted = active == name
        self.journal["active_phase"] = name
        atomic_json(self.journal_path, self.journal)
        return interrupted

    def cli(self, *command: str, timeout=None):
        invocation = [
            str(self.args.blackcoin_cli),
            f"-datadir={self.datadir}",
            f"-conf={self.work / 'empty.conf'}",
            "-nosettings",
            "-rpcclienttimeout=0",
            *self.network_args,
            *command,
        ]
        result = subprocess.run(
            invocation, capture_output=True, text=True, check=False,
            timeout=timeout,
        )
        if result.returncode:
            raise RuntimeError(
                f"RPC {' '.join(command)} failed: {result.stderr.strip() or result.stdout.strip()}"
            )
        output = result.stdout.strip()
        if not output:
            return None
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            if command[0] in {"getblockhash", "stop"} and "\n" not in output:
                return output
            raise RuntimeError(f"RPC {' '.join(command)} returned invalid JSON") from error

    def launch(self, stage: str, *extra: str) -> Daemon:
        if self.current_daemon is not None:
            raise RuntimeError("a prior measured daemon is still active")
        log_path = self.logs / f"{stage}.log"
        log_handle = log_path.open("a", encoding="utf-8")
        invocation = [
            str(self.args.blackcoind),
            f"-datadir={self.datadir}",
            f"-conf={self.work / 'empty.conf'}",
            "-nosettings",
            "-server=1",
            "-disablewallet=1",
            "-listen=0",
            "-dnsseed=0",
            "-discover=0",
            "-upnp=0",
            "-natpmp=0",
            "-connect=0",
            "-persistmempool=0",
            f"-par={self.contract['measurement']['validation_threads']}",
            f"-dbcache={self.contract['measurement']['dbcache_mib']}",
            "-daemon=0",
            "-printtoconsole=1",
            *self.network_args,
            *extra,
        ]
        process = subprocess.Popen(
            invocation,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            pass_fds=(self.lock_fd,),
        )
        daemon = Daemon(process, log_handle, log_path)
        self.current_daemon = daemon
        return daemon

    def wait_for_tip(self, daemon: Daemon, height: int, block_hash: str,
                     timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        last_error = "RPC not ready"
        while time.monotonic() < deadline:
            if daemon.process.poll() is not None:
                daemon.close_log()
                tail = ""
                try:
                    tail = "\n".join(daemon.log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-40:])
                except OSError:
                    pass
                raise RuntimeError(
                    f"blackcoind exited before {height}/{block_hash}:\n{tail}"
                )
            try:
                info = self.cli("getblockchaininfo", timeout=60)
                last_error = f"current tip {info.get('blocks')}/{info.get('bestblockhash')}"
                if (
                    info.get("blocks") == height
                    and info.get("bestblockhash") == block_hash
                    and info.get("initialblockdownload") is False
                ):
                    return info
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                last_error = str(error)
            time.sleep(10)
        raise RuntimeError(f"timed out waiting for exact tip: {last_error}")

    def wait_for_rpc(self, daemon: Daemon, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        last_error = "RPC not ready"
        while time.monotonic() < deadline:
            if daemon.process.poll() is not None:
                daemon.close_log()
                tail = ""
                try:
                    tail = "\n".join(
                        daemon.log_path.read_text(
                            encoding="utf-8", errors="replace"
                        ).splitlines()[-40:]
                    )
                except OSError:
                    pass
                raise RuntimeError(
                    f"blackcoind exited before RPC became ready:\n{tail}"
                )
            try:
                return self.cli("getblockchaininfo", timeout=60)
            except (RuntimeError, subprocess.TimeoutExpired) as error:
                last_error = str(error)
            time.sleep(10)
        raise RuntimeError(f"timed out waiting for RPC: {last_error}")

    def restore_manifest_tip(self, daemon: Daemon, timeout: float) -> None:
        """Restore an interrupted reorg to the immutable captured tip."""
        info = self.wait_for_rpc(daemon, min(timeout, 600))
        if (
            info.get("blocks") != self.manifest["end_height"]
            or info.get("bestblockhash") != self.manifest["end_hash"]
            or info.get("initialblockdownload") is not False
        ):
            self.cli(
                "reconsiderblock",
                self.manifest["first_gold_rush_hash"],
                timeout=timeout,
            )
            self.wait_for_tip(
                daemon,
                self.manifest["end_height"],
                self.manifest["end_hash"],
                timeout,
            )
        first_hash = self.cli(
            "getblockhash",
            str(self.contract["synthetic_fixture"]["reward_start_height"]),
            timeout=60,
        )
        if first_hash != self.manifest["first_gold_rush_hash"]:
            raise RuntimeError(
                "fixture first Gold Rush block hash differs from the manifest"
            )

    def stop(self, daemon: Daemon) -> None:
        try:
            self.cli("stop", timeout=120)
            daemon.process.wait(timeout=600)
        except (RuntimeError, subprocess.TimeoutExpired) as error:
            raise RuntimeError("blackcoind did not complete the required clean shutdown") from error
        finally:
            daemon.close_log()
        if daemon.process.returncode != 0:
            raise RuntimeError(f"blackcoind clean-shutdown exit code was {daemon.process.returncode}")
        self.current_daemon = None

    def abort_current(self) -> None:
        daemon = self.current_daemon
        if daemon is None:
            return
        try:
            if daemon.process.poll() is None:
                try:
                    self.cli("stop", timeout=120)
                    daemon.process.wait(timeout=300)
                except Exception:
                    # SIGTERM enters the daemon's normal shutdown path.  This
                    # phase remains unjournaled and therefore cannot count as
                    # evidence even if cancellation required this fallback.
                    daemon.process.terminate()
                    daemon.process.wait(timeout=300)
        except Exception:
            pass
        finally:
            daemon.close_log()
            self.current_daemon = None

    def close(self) -> None:
        self.abort_current()
        lock_fd = getattr(self, "lock_fd", None)
        if lock_fd is not None:
            # A surviving daemon inherits this open-file description. Closing
            # only the runner's copy keeps the retry lock held by that daemon.
            os.close(lock_fd)
            self.lock_fd = None

    def phase(self, daemon: Daemon, started: float, height: int, block_hash: str,
              sampler: PhaseSampler) -> dict:
        result = sampler.finish()
        result.update(
            wall_seconds=time.monotonic() - started,
            completed_height=height,
            completed_hash=block_hash,
        )
        return result

    def operational_observation(self, supply: dict) -> dict:
        """Bind one production scan and cheap resource sample to one anchor."""
        height = supply.get("height")
        block_hash = supply.get("bestblock")
        operational = supply.get("operational_resource", {})
        resource = self.cli("getshadowresourceinfo", timeout=120)
        chain = self.cli("getblockchaininfo", timeout=120)
        header = self.cli("getblockheader", block_hash, timeout=120)
        if (
            resource.get("schema")
            != "blackcoin.shadow.resource_operational.v1"
            or resource.get("model_class") != "scoped_operational"
            or resource.get("universal_consensus_bound") is not False
            or resource.get("height") != height
            or resource.get("bestblock") != block_hash
            or resource.get("measurements_available") is not True
            or chain.get("blocks") != height
            or chain.get("bestblockhash") != block_hash
            or chain.get("initialblockdownload") is not False
            or header.get("hash") != block_hash
            or operational.get("scan_id")
            != resource.get("supply_scan", {}).get("scan_id")
            or resource.get("supply_scan", {}).get("active") is not False
            or resource.get("supply_scan", {}).get("last_outcome")
            != "complete"
        ):
            raise RuntimeError(
                "operational observation is not bound to one completed production scan"
            )
        return {
            "schema": 1,
            "height": height,
            "bestblock": block_hash,
            "block_mediantime": header.get("mediantime"),
            "txouts": supply.get("txouts"),
            "marker_records_scanned": operational.get(
                "marker_records_scanned"
            ),
            "utxo_records_scanned": operational.get("utxo_records_scanned"),
            "active_coin_batch_payload_bytes_scanned": operational.get(
                "active_coin_batch_payload_bytes_scanned"
            ),
            "authenticated_shadow_records_scanned": operational.get(
                "authenticated_shadow_records_scanned"
            ),
            "authenticated_shadow_batch_payload_bytes_scanned": (
                operational.get(
                    "authenticated_shadow_batch_payload_bytes_scanned"
                )
            ),
            "provenance_point_seeks": operational.get(
                "provenance_point_seeks"
            ),
            "demurrage_point_seeks": operational.get(
                "demurrage_point_seeks"
            ),
            "chainstate_estimated_bytes": resource.get(
                "chainstate_estimated_bytes"
            ),
            "filesystem_available_bytes": resource.get(
                "filesystem_available_bytes"
            ),
            "required_free_bytes": resource.get("required_free_bytes"),
            "resource_status": resource.get("status"),
            "within_supported_height": resource.get(
                "within_supported_height"
            ),
            "within_chainstate_size": resource.get("within_chainstate_size"),
            "within_immediate_scan_free_space": resource.get(
                "within_immediate_scan_free_space"
            ),
            "within_projected_free_space": resource.get(
                "within_projected_free_space"
            ),
            "operational_envelope_satisfied": resource.get(
                "operational_envelope_satisfied"
            ),
            "rpc_responsive_after_scan": True,
        }

    def discard_sampler(self, sampler: PhaseSampler) -> None:
        if sampler.thread.is_alive():
            try:
                sampler.finish()
            except RuntimeError:
                # The measured phase remains active and unjournaled. Preserve
                # the primary daemon/RPC failure for diagnostics.
                pass

    def require_datadir_unowned(self) -> None:
        for path, label in (
            (self.datadir / ".lock", "blackcoind datadir"),
            (self.chainstate / "LOCK", "chainstate LevelDB"),
            (self.datadir / "blocks" / "index" / "LOCK", "block-index LevelDB"),
        ):
            require_unowned_lock(path, label)

    def extract_fresh(self) -> None:
        fixture_directory = self.work / "fixture"
        if fixture_directory.exists():
            if fixture_directory.is_symlink() or fixture_directory.parent != self.work:
                raise RuntimeError("unsafe fixture extraction directory")
            self.require_datadir_unowned()
            shutil.rmtree(fixture_directory)
        # The archive was authenticated before the gate object was created,
        # but the protected run can remain resumable for days. Authenticate
        # the exact pathname immediately before and after extraction so a
        # concurrent capture refresh cannot enter the measured replay.
        verify_fixture_archive(self.args.fixture_archive, self.manifest)
        safe_extract(
            self.args.fixture_archive, fixture_directory,
            self.manifest["archive_root"],
        )
        verify_fixture_archive(self.args.fixture_archive, self.manifest)
        if not (self.datadir / "blocks").is_dir() or not self.chainstate.is_dir():
            raise RuntimeError("fixture archive lacks blocks or chainstate")
        for name in (".cookie", "blackcoind.pid", "settings.json", "mempool.dat"):
            path = self.datadir / name
            if path.exists():
                path.unlink()
        (self.work / "empty.conf").write_text("\n", encoding="utf-8")

    def extract(self) -> None:
        if "extract" in self.journal["completed"]:
            if not (self.datadir / "blocks").is_dir():
                raise RuntimeError(
                    "journal says extraction completed but fixture blocks are missing"
                )
            return
        self.begin_stage("extract")
        # An interrupted extraction has no authenticated completion marker.
        # Restart from the immutable archive so stale files cannot enter the
        # measured snapshot.
        self.extract_fresh()
        self.save_stage("extract", True)

    def copy_tree(self, source: Path, destination: Path) -> None:
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("live snapshot destination already exists")
        destination.mkdir(parents=True, mode=0o700)
        for path in source.rglob("*"):
            if path.is_symlink():
                raise RuntimeError(f"live database contains a symlink: {path}")
            relative = path.relative_to(source)
            target = destination / relative
            if path.is_dir():
                target.mkdir(mode=0o700)
                continue
            if not path.is_file():
                raise RuntimeError(
                    f"live database has an unsupported entry: {path}"
                )
            if path.suffix in {".ldb", ".sst"}:
                os.link(path, target)
            else:
                shutil.copy2(path, target)
                with target.open("rb") as copied:
                    os.fsync(copied.fileno())
        if sys.platform == "linux":
            for directory_path in (destination, *(
                path for path in destination.rglob("*") if path.is_dir()
            )):
                directory = os.open(
                    directory_path, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)

    def snapshot_inventory(self, root: Path) -> dict:
        return {
            "chainstate": chainstate_snapshot(
                root / "chainstate", include_files=True
            ),
            "block_index": chainstate_snapshot(
                root / "block-index", include_files=True
            ),
        }

    def remove_snapshot(self, expected_phase: str = "") -> None:
        if expected_phase and self.snapshot_marker.exists():
            marker = load_json(self.snapshot_marker, "live predecessor marker")
            if marker.get("phase") != expected_phase:
                return
        if self.snapshot_marker.exists():
            if self.snapshot_marker.is_symlink():
                raise RuntimeError("live predecessor marker is a symlink")
            self.snapshot_marker.unlink()
        if self.snapshot_root.exists():
            if (
                self.snapshot_root.is_symlink()
                or self.snapshot_root.parent != self.work
            ):
                raise RuntimeError("unsafe live predecessor directory")
            shutil.rmtree(self.snapshot_root)

    def load_snapshot(self, name: str):
        if not self.snapshot_marker.exists():
            return None
        marker = load_json(self.snapshot_marker, "live predecessor marker")
        require_keys(
            marker, {"schema", "binding", "phase", "snapshot"},
            "live predecessor marker",
        )
        if (
            marker["schema"] != 1
            or marker["binding"] != self.binding
            or marker["phase"] != name
            or not self.snapshot_root.is_dir()
            or self.snapshot_root.is_symlink()
            or marker["snapshot"] != self.snapshot_inventory(self.snapshot_root)
        ):
            raise RuntimeError("live predecessor identity differs")
        return marker

    def create_snapshot(self, name: str) -> dict:
        existing = self.load_snapshot(name)
        if existing is not None:
            return existing
        if self.snapshot_root.exists() or self.snapshot_marker.exists():
            self.remove_snapshot()
        sources = {
            "chainstate": self.chainstate,
            "block-index": self.datadir / "blocks" / "index",
        }
        for label, source in sources.items():
            if not source.is_dir() or source.is_symlink():
                raise RuntimeError(f"live {label} predecessor is missing")
        temporary = self.snapshot_root.with_name(
            self.snapshot_root.name + ".tmp"
        )
        if temporary.exists() or temporary.is_symlink():
            if temporary.is_symlink() or temporary.parent != self.work:
                raise RuntimeError("unsafe temporary live predecessor")
            shutil.rmtree(temporary)
        temporary.mkdir(mode=0o700)
        for label, source in sources.items():
            self.copy_tree(source, temporary / label)
        snapshot = self.snapshot_inventory(temporary)
        os.replace(temporary, self.snapshot_root)
        marker = {
            "schema": 1,
            "binding": self.binding,
            "phase": name,
            "snapshot": snapshot,
        }
        atomic_json(self.snapshot_marker, marker)
        return marker

    def restore_snapshot(self, name: str) -> None:
        marker = self.load_snapshot(name)
        if marker is None:
            raise RuntimeError(f"live {name} predecessor is missing")
        targets = {
            "chainstate": self.chainstate,
            "block-index": self.datadir / "blocks" / "index",
        }
        self.require_datadir_unowned()
        for target in targets.values():
            if target.exists():
                if target.is_symlink() or self.datadir not in target.parents:
                    raise RuntimeError("unsafe live database restore target")
                shutil.rmtree(target)
        for label, target in targets.items():
            self.copy_tree(self.snapshot_root / label, target)
        restored = {
            "chainstate": chainstate_snapshot(
                self.chainstate, include_files=True
            ),
            "block_index": chainstate_snapshot(
                self.datadir / "blocks" / "index", include_files=True
            ),
        }
        if restored != marker["snapshot"]:
            raise RuntimeError("restored live predecessor differs")

    def include_snapshot_peak(self, resources: dict, snapshot: dict) -> None:
        for source, target in (
            ("total_bytes", "peak_chainstate_bytes"),
            ("sst_bytes", "peak_sst_bytes"),
            ("wal_bytes", "peak_wal_bytes"),
            ("manifest_bytes", "peak_manifest_bytes"),
            ("other_bytes", "peak_other_bytes"),
        ):
            resources[target] = max(resources[target], snapshot[source])

    def run_full_replay(self) -> dict:
        if "full_replay" in self.journal["completed"]:
            return self.journal["completed"]["full_replay"]
        interrupted = self.journal["active_phase"] == "full_replay"
        if interrupted:
            # -reindex-chainstate resumes internal progress. That is correct
            # for a node, but the remaining suffix is not a measurement of a
            # complete replay. Restore the immutable archive and rerun all of
            # it instead.
            self.extract_fresh()
        self.begin_stage("full_replay")
        predecessor = chainstate_snapshot(self.chainstate)
        daemon = self.launch("full-replay", "-reindex-chainstate=1")
        sampler = PhaseSampler(daemon.process.pid, self.chainstate, self.interval)
        started = time.monotonic()
        sampler.start()
        try:
            self.wait_for_tip(
                daemon, self.manifest["end_height"], self.manifest["end_hash"],
                self.contract["budgets"]["maximum_live_replay_seconds"],
            )
            result = self.phase(
                daemon, started, self.manifest["end_height"],
                self.manifest["end_hash"], sampler,
            )
            self.include_snapshot_peak(result, predecessor)
            self.stop(daemon)
        except BaseException:
            self.discard_sampler(sampler)
            raise
        self.save_stage("full_replay", result)
        return result

    def run_lifecycle_scan(self) -> dict:
        if "lifecycle_scan" in self.journal["completed"]:
            self.remove_snapshot("lifecycle_scan")
            return self.journal["completed"]["lifecycle_scan"]
        interrupted = self.journal["active_phase"] == "lifecycle_scan"
        self.begin_stage("lifecycle_scan")
        marker = self.create_snapshot("lifecycle_scan")
        if interrupted:
            self.restore_snapshot("lifecycle_scan")
        daemon = self.launch("lifecycle-scan")
        self.wait_for_tip(daemon, self.manifest["end_height"], self.manifest["end_hash"], 600)
        sampler = PhaseSampler(daemon.process.pid, self.chainstate, self.interval)
        started = time.monotonic()
        sampler.start()
        try:
            supply = self.cli(
                "getcirculatingsupply",
                timeout=self.contract["budgets"][
                    "maximum_live_lifecycle_scan_seconds"
                ],
            )
            shadow = supply.get("shadow", {})
            if (
                supply.get("height") != self.manifest["end_height"]
                or supply.get("bestblock") != self.manifest["end_hash"]
                or shadow.get("issued_count") != self.manifest["issued_claims"]
                or shadow.get("spent_count") != self.manifest["spent_claims"]
                or shadow.get("unspent_count") != self.manifest["unspent_claims"]
            ):
                raise RuntimeError(
                    "full lifecycle scan does not authenticate the exact fixture inventory"
                )
            result = self.phase(
                daemon, started, self.manifest["end_height"],
                self.manifest["end_hash"], sampler,
            )
            self.include_snapshot_peak(
                result, marker["snapshot"]["chainstate"]
            )
            self.stop(daemon)
        except BaseException:
            self.discard_sampler(sampler)
            raise
        self.save_stage("lifecycle_scan", result)
        self.remove_snapshot("lifecycle_scan")
        return result

    def run_clean_startups(self) -> tuple[list[dict], int]:
        if "clean_startups" in self.journal["completed"]:
            value = self.journal["completed"]["clean_startups"]
            self.remove_snapshot("clean_startups")
            return value["phases"], value["obsolete_file_bytes"]
        interrupted = self.journal["active_phase"] == "clean_startups"
        self.begin_stage("clean_startups")
        marker = self.create_snapshot("clean_startups")
        if interrupted:
            # Re-run the complete sequence from its byte-exact closed-DB
            # predecessor. An unmeasured recovery open would consume the WAL
            # recovery and obsolete-file cleanup this gate must measure.
            self.restore_snapshot("clean_startups")
        phases = []
        obsolete = 0
        prior = marker["snapshot"]["chainstate"]
        for index in range(self.contract["measurement"]["clean_startup_runs"]):
            daemon = self.launch(f"clean-startup-{index + 1}")
            sampler = PhaseSampler(daemon.process.pid, self.chainstate, self.interval)
            started = time.monotonic()
            sampler.start()
            try:
                self.wait_for_tip(
                    daemon, self.manifest["end_height"],
                    self.manifest["end_hash"],
                    self.contract["budgets"][
                        "maximum_clean_startup_seconds"
                    ],
                )
                result = self.phase(
                    daemon, started, self.manifest["end_height"],
                    self.manifest["end_hash"], sampler,
                )
                self.include_snapshot_peak(result, prior)
                self.stop(daemon)
                current = chainstate_snapshot(
                    self.chainstate, include_files=True
                )
                self.include_snapshot_peak(result, current)
            except BaseException:
                self.discard_sampler(sampler)
                raise
            obsolete = max(obsolete, disappeared_bytes(prior, current))
            prior = current
            phases.append(result)
        value = {"phases": phases, "obsolete_file_bytes": obsolete}
        self.save_stage("clean_startups", value)
        self.remove_snapshot("clean_startups")
        return phases, obsolete

    def run_full_reorg(self) -> tuple[dict, dict, dict, int]:
        completed = self.journal["completed"]
        first_hash = self.manifest["first_gold_rush_hash"]
        pre_height = (
            self.contract["synthetic_fixture"]["reward_start_height"] - 1
        )

        if "live_reorg_undo" in completed:
            undo_value = completed["live_reorg_undo"]
            if set(undo_value) != {"phase", "operational_observations"}:
                raise RuntimeError("completed live reorg undo fields differ")
            undo = undo_value["phase"]
            undo_observations = undo_value["operational_observations"]
            self.remove_snapshot("live_reorg_undo")
        else:
            interrupted = self.journal["active_phase"] == "live_reorg_undo"
            self.begin_stage("live_reorg_undo")
            marker = self.create_snapshot("live_reorg_undo")
            if interrupted:
                self.restore_snapshot("live_reorg_undo")
            daemon = self.launch("full-epoch-undo")
            self.restore_manifest_tip(
                daemon,
                self.contract["budgets"]["maximum_full_reapply_seconds"],
            )
            undo_sampler = PhaseSampler(
                daemon.process.pid, self.chainstate, self.interval
            )
            undo_started = time.monotonic()
            undo_sampler.start()
            try:
                end_height = self.manifest["end_height"]
                target_heights = {pre_height}
                for window in self.contract["authorization_policy"][
                    "required_growth_windows_blocks"
                ]:
                    target = end_height - window
                    if target >= self.contract["synthetic_fixture"][
                        "reward_start_height"
                    ]:
                        target_heights.add(target)
                anchors = {}
                for target in sorted(target_heights, reverse=True):
                    anchors[target] = {
                        "bestblock": self.cli(
                            "getblockhash", str(target), timeout=120
                        ),
                        "invalidate": self.cli(
                            "getblockhash", str(target + 1), timeout=120
                        ),
                    }
                if anchors[pre_height]["bestblock"] != self.manifest[
                    "pre_gold_rush_hash"
                ] or anchors[pre_height]["invalidate"] != first_hash:
                    raise RuntimeError(
                        "operational observation anchors differ from the live manifest"
                    )

                undo_observations = []
                for target in sorted(target_heights, reverse=True):
                    self.cli(
                        "invalidateblock",
                        anchors[target]["invalidate"],
                        timeout=self.contract["budgets"][
                            "maximum_full_undo_seconds"
                        ],
                    )
                    self.wait_for_tip(
                        daemon,
                        target,
                        anchors[target]["bestblock"],
                        self.contract["budgets"][
                            "maximum_full_undo_seconds"
                        ],
                    )
                    rollback_supply = self.cli(
                        "getcirculatingsupply",
                        timeout=self.contract["budgets"][
                            "maximum_live_lifecycle_scan_seconds"
                        ],
                    )
                    if (
                        rollback_supply.get("height") != target
                        or rollback_supply.get("bestblock")
                        != anchors[target]["bestblock"]
                    ):
                        raise RuntimeError(
                            "growth-window scan differs from its exact anchor"
                        )
                    if target == pre_height:
                        rollback_shadow = rollback_supply.get("shadow", {})
                        if (
                            rollback_shadow.get("issued_count") != 0
                            or rollback_shadow.get("spent_count") != 0
                            or rollback_shadow.get("unspent_count") != 0
                        ):
                            raise RuntimeError(
                                "full-epoch undo did not restore the exact pre-Gold-Rush inventory"
                            )
                    undo_observations.append(
                        self.operational_observation(rollback_supply)
                    )
                undo = self.phase(
                    daemon,
                    undo_started,
                    pre_height,
                    self.manifest["pre_gold_rush_hash"],
                    undo_sampler,
                )
                self.include_snapshot_peak(
                    undo, marker["snapshot"]["chainstate"]
                )
                self.stop(daemon)
            except BaseException:
                self.discard_sampler(undo_sampler)
                raise
            self.save_stage("live_reorg_undo", {
                "phase": undo,
                "operational_observations": undo_observations,
            })
            self.remove_snapshot("live_reorg_undo")

        if "live_reorg_reapply" in completed:
            reapply_value = completed["live_reorg_reapply"]
            if set(reapply_value) != {"phase", "operational_observation"}:
                raise RuntimeError("completed live reorg reapply fields differ")
            reapply = reapply_value["phase"]
            reapply_observation = reapply_value[
                "operational_observation"
            ]
            self.remove_snapshot("live_reorg_reapply")
        else:
            interrupted = (
                self.journal["active_phase"] == "live_reorg_reapply"
            )
            self.begin_stage("live_reorg_reapply")
            marker = self.create_snapshot("live_reorg_reapply")
            if interrupted:
                self.restore_snapshot("live_reorg_reapply")
            daemon = self.launch("full-epoch-reapply")
            self.wait_for_tip(
                daemon,
                pre_height,
                self.manifest["pre_gold_rush_hash"],
                600,
            )
            reapply_sampler = PhaseSampler(
                daemon.process.pid, self.chainstate, self.interval
            )
            reapply_started = time.monotonic()
            reapply_sampler.start()
            try:
                self.cli(
                    "reconsiderblock",
                    first_hash,
                    timeout=self.contract["budgets"][
                        "maximum_full_reapply_seconds"
                    ],
                )
                self.wait_for_tip(
                    daemon,
                    self.manifest["end_height"],
                    self.manifest["end_hash"],
                    self.contract["budgets"][
                        "maximum_full_reapply_seconds"
                    ],
                )
                reapply_supply = self.cli(
                    "getcirculatingsupply",
                    timeout=self.contract["budgets"][
                        "maximum_live_lifecycle_scan_seconds"
                    ],
                )
                shadow = reapply_supply.get("shadow", {})
                if (
                    reapply_supply.get("height")
                    != self.manifest["end_height"]
                    or reapply_supply.get("bestblock")
                    != self.manifest["end_hash"]
                    or shadow.get("issued_count")
                    != self.manifest["issued_claims"]
                    or shadow.get("spent_count")
                    != self.manifest["spent_claims"]
                    or shadow.get("unspent_count")
                    != self.manifest["unspent_claims"]
                ):
                    raise RuntimeError(
                        "full-epoch reapply did not restore the exact live inventory"
                    )
                reapply_observation = self.operational_observation(
                    reapply_supply
                )
                reapply = self.phase(
                    daemon,
                    reapply_started,
                    self.manifest["end_height"],
                    self.manifest["end_hash"],
                    reapply_sampler,
                )
                self.include_snapshot_peak(
                    reapply, marker["snapshot"]["chainstate"]
                )
                self.stop(daemon)
            except BaseException:
                self.discard_sampler(reapply_sampler)
                raise
            self.save_stage("live_reorg_reapply", {
                "phase": reapply,
                "operational_observation": reapply_observation,
            })
            self.remove_snapshot("live_reorg_reapply")

        if "live_reorg_cleanup" in completed:
            cleanup_value = completed["live_reorg_cleanup"]
            if set(cleanup_value) != {"phase", "obsolete_file_bytes"}:
                raise RuntimeError("completed live reorg cleanup fields differ")
            cleanup_phase = cleanup_value["phase"]
            obsolete = cleanup_value["obsolete_file_bytes"]
            self.remove_snapshot("live_reorg_cleanup")
        else:
            interrupted = (
                self.journal["active_phase"] == "live_reorg_cleanup"
            )
            self.begin_stage("live_reorg_cleanup")
            marker = self.create_snapshot("live_reorg_cleanup")
            if interrupted:
                self.restore_snapshot("live_reorg_cleanup")
            before_cleanup = marker["snapshot"]["chainstate"]
            cleanup_started = time.monotonic()
            cleanup = self.launch("post-reorg-clean-open")
            cleanup_sampler = PhaseSampler(
                cleanup.process.pid, self.chainstate, self.interval
            )
            cleanup_sampler.start()
            try:
                self.restore_manifest_tip(cleanup, 600)
                cleanup_phase = self.phase(
                    cleanup,
                    cleanup_started,
                    self.manifest["end_height"],
                    self.manifest["end_hash"],
                    cleanup_sampler,
                )
                self.include_snapshot_peak(cleanup_phase, before_cleanup)
                self.stop(cleanup)
                after_cleanup = chainstate_snapshot(
                    self.chainstate, include_files=True
                )
                self.include_snapshot_peak(cleanup_phase, after_cleanup)
            except BaseException:
                self.discard_sampler(cleanup_sampler)
                raise
            obsolete = disappeared_bytes(before_cleanup, after_cleanup)
            self.save_stage("live_reorg_cleanup", {
                "phase": cleanup_phase,
                "obsolete_file_bytes": obsolete,
            })
            self.remove_snapshot("live_reorg_cleanup")
        observations = sorted(
            [*undo_observations, reapply_observation],
            key=lambda item: item["height"],
        )
        return undo, reapply, cleanup_phase, obsolete, observations

    def run_forced_compaction(self) -> tuple[dict, dict, dict]:
        if "forced_compaction" in self.journal["completed"]:
            value = self.journal["completed"]["forced_compaction"]
            self.remove_snapshot("forced_compaction")
            return value["phase"], value["steady_snapshot"], value["compacted_snapshot"]
        interrupted = self.journal["active_phase"] == "forced_compaction"
        self.begin_stage("forced_compaction")
        marker = self.create_snapshot("forced_compaction")
        if interrupted:
            self.restore_snapshot("forced_compaction")
        steady = public_snapshot(marker["snapshot"]["chainstate"])
        daemon = self.launch("forced-compaction", "-forcecompactdb=1")
        sampler = PhaseSampler(daemon.process.pid, self.chainstate, self.interval)
        started = time.monotonic()
        sampler.start()
        try:
            self.wait_for_tip(
                daemon, self.manifest["end_height"], self.manifest["end_hash"],
                self.contract["budgets"]["maximum_forced_compaction_seconds"],
            )
            compacted_supply = self.cli(
                "getcirculatingsupply",
                timeout=self.contract["budgets"][
                    "maximum_live_lifecycle_scan_seconds"
                ],
            )
            compacted_shadow = compacted_supply.get("shadow", {})
            if (
                compacted_supply.get("height")
                != self.manifest["end_height"]
                or compacted_supply.get("bestblock")
                != self.manifest["end_hash"]
                or compacted_shadow.get("issued_count")
                != self.manifest["issued_claims"]
                or compacted_shadow.get("spent_count")
                != self.manifest["spent_claims"]
                or compacted_shadow.get("unspent_count")
                != self.manifest["unspent_claims"]
            ):
                raise RuntimeError(
                    "forced compaction changed the authenticated fixture inventory"
                )
            phase = self.phase(
                daemon, started, self.manifest["end_height"],
                self.manifest["end_hash"], sampler,
            )
            self.include_snapshot_peak(phase, steady)
            self.stop(daemon)
        except BaseException:
            self.discard_sampler(sampler)
            raise
        compacted = chainstate_snapshot(self.chainstate)
        value = {
            "phase": phase,
            "steady_snapshot": steady,
            "compacted_snapshot": compacted,
        }
        self.save_stage("forced_compaction", value)
        self.remove_snapshot("forced_compaction")
        return phase, steady, compacted

    def run(self) -> dict:
        self.extract()
        replay = self.run_full_replay()
        lifecycle = self.run_lifecycle_scan()
        startups, startup_obsolete = self.run_clean_startups()
        (undo, reapply, reorg_cleanup, reorg_obsolete,
         operational_observations) = self.run_full_reorg()
        compact_phase, steady, compacted = self.run_forced_compaction()

        reclaimed = max(0, steady["total_bytes"] - compacted["total_bytes"])
        phases = {
            "live_full_replay": replay,
            "live_lifecycle_scan": lifecycle,
            "clean_startups": startups,
            "live_partial_epoch_undo": undo,
            "live_partial_epoch_reapply": reapply,
            "live_reorg_cleanup": reorg_cleanup,
            "forced_compaction": compact_phase,
        }
        transient_peak = max(
            phase["peak_chainstate_bytes"]
            for phase in [
                replay, lifecycle, undo, reapply, reorg_cleanup,
                compact_phase, *startups,
            ]
        )
        leveldb = {
            "steady_snapshot": steady,
            "compacted_snapshot": compacted,
            "maximum_observed_bytes": transient_peak,
            "observed_file_churn_bytes": max(
                startup_obsolete, reorg_obsolete
            ),
            "forced_compaction_reclaimed_bytes": reclaimed,
        }
        evidence = {
            "schema": 3,
            "status": "complete",
            "evidence_kind": "current_live_partial_epoch",
            "completed_epoch": (
                self.manifest["end_height"]
                == self.contract["live_partial_snapshot"]["maximum_height"]
            ),
            "repository": self.contract["repository"],
            "target_sha": self.args.target_sha,
            "tree_clean": True,
            "measurement_environment": self.binding[
                "measurement_environment"
            ],
            "qualification_scope": self.contract["qualification_scope"],
            "contract_sha256": self.binding["contract_sha256"],
            "source_files": {
                relative: sha256_file(self.args.repo_root / relative)
                for relative in self.contract["source_files"]
            },
            "binaries": {
                "blackcoind": {
                    "sha256": self.binding["blackcoind_sha256"],
                    "size_bytes": self.args.blackcoind.stat().st_size,
                },
                "blackcoin_cli": {
                    "sha256": self.binding["blackcoin_cli_sha256"],
                    "size_bytes": self.args.blackcoin_cli.stat().st_size,
                },
            },
            "fixture": {
                "evidence_kind": self.manifest["evidence_kind"],
                "fixture_manifest_sha256": self.binding["fixture_manifest_sha256"],
                "archive_sha256": self.manifest["archive_sha256"],
                "archive_size_bytes": self.manifest["archive_size_bytes"],
                "network": self.manifest["network"],
                "target_sha": self.manifest["target_sha"],
                "captured_at_unix": self.manifest["captured_at_unix"],
                "capture_attestation": self.manifest["capture_attestation"],
                "capture_rpc": self.manifest["capture_rpc"],
                "end_height": self.manifest["end_height"],
                "end_hash": self.manifest["end_hash"],
                "pre_gold_rush_hash": self.manifest["pre_gold_rush_hash"],
                "first_gold_rush_hash": self.manifest["first_gold_rush_hash"],
                "issued_claims": self.manifest["issued_claims"],
                "spent_claims": self.manifest["spent_claims"],
                "unspent_claims": self.manifest["unspent_claims"],
            },
            "phases": phases,
            "leveldb": leveldb,
            "operational_observations": operational_observations,
            "maximum_peak_rss_bytes": max(
                phase["peak_rss_bytes"]
                for phase in [replay, lifecycle, undo, reapply, reorg_cleanup,
                              compact_phase, *startups]
            ),
        }
        return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--fixture-manifest", type=Path, required=True)
    parser.add_argument("--fixture-manifest-sha256", required=True)
    parser.add_argument("--fixture-archive", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--blackcoind", type=Path, required=True)
    parser.add_argument("--blackcoin-cli", type=Path, required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    gate = None
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_shutdown(signum, frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        reject_symlink_components(args.work_dir, "work directory")
        reject_symlink_components(args.fixture_manifest, "fixture manifest")
        reject_symlink_components(args.fixture_archive, "fixture archive")
        args.repo_root = args.repo_root.resolve()
        args.contract = args.contract.resolve()
        args.fixture_manifest = args.fixture_manifest.resolve()
        args.fixture_archive = args.fixture_archive.resolve()
        args.work_dir = args.work_dir.resolve()
        args.blackcoind = args.blackcoind.resolve()
        args.blackcoin_cli = args.blackcoin_cli.resolve()
        args.output = args.output.resolve()
        if args.work_dir == Path("/") or args.work_dir == args.repo_root or args.repo_root in args.work_dir.parents:
            raise RuntimeError("work directory must be an external dedicated path")
        if args.output == args.work_dir or args.work_dir not in args.output.parents:
            raise RuntimeError("live evidence output must be inside work directory")
        fixture_destination = args.work_dir / "fixture"
        if fixture_destination == args.fixture_archive or fixture_destination in args.fixture_archive.parents:
            raise RuntimeError("fixture archive cannot be stored inside the disposable extraction directory")
        if sys.platform != "linux" or not Path("/proc/self/status").is_file():
            raise RuntimeError("physical production resource measurement requires native Linux /proc")
        if not GIT_SHA_RE.fullmatch(args.target_sha):
            raise RuntimeError("target SHA must be a full lowercase Git commit")
        if not SHA256_RE.fullmatch(args.fixture_manifest_sha256):
            raise RuntimeError("fixture manifest SHA256 must be lowercase hexadecimal")
        if git_output(args.repo_root, "rev-parse", "HEAD") != args.target_sha:
            raise RuntimeError("checked-out HEAD differs from target SHA")
        if evidence_verifier.normalize_repository_url(
            git_output(args.repo_root, "remote", "get-url", "origin")
        ) != "Blackcoin-Dev/Blackcoin":
            raise RuntimeError("checked-out origin is not Blackcoin-Dev/Blackcoin")
        if git_output(args.repo_root, "status", "--porcelain"):
            raise RuntimeError("production resource runner requires a clean source tree")
        if not args.blackcoind.is_file() or not os.access(args.blackcoind, os.X_OK):
            raise RuntimeError("exact blackcoind executable is missing")
        if not args.blackcoin_cli.is_file() or not os.access(args.blackcoin_cli, os.X_OK):
            raise RuntimeError("exact blackcoin-cli executable is missing")
        if not args.fixture_archive.is_file():
            raise RuntimeError("fixture archive is missing")
        contract = load_json(args.contract, "production resource contract")
        evidence_verifier.verify_contract(contract)
        verify_epoch_source_contract(args.repo_root)
        contract_sha = sha256_file(args.contract)
        manifest_sha = sha256_file(args.fixture_manifest)
        if manifest_sha != args.fixture_manifest_sha256:
            raise RuntimeError("fixture manifest SHA256 differs from the immutable requested digest")
        manifest = load_json(args.fixture_manifest, "fixture manifest")
        verify_fixture_manifest(manifest, contract, contract_sha, args.target_sha, args.fixture_archive)
        args.work_dir.mkdir(parents=True, exist_ok=True)
        binding = {
            "target_sha": args.target_sha,
            "contract_sha256": contract_sha,
            "fixture_manifest_sha256": manifest_sha,
            "archive_sha256": manifest["archive_sha256"],
            "blackcoind_sha256": sha256_file(args.blackcoind),
            "blackcoin_cli_sha256": sha256_file(args.blackcoin_cli),
            "measurement_environment": (
                evidence_verifier.collect_measurement_environment(
                    args.repo_root, args.work_dir
                )
            ),
        }
        gate = ProductionGate(args, contract, manifest, binding)
        evidence = gate.run()
        atomic_json(args.output, evidence)
        evidence_verifier.verify_live(
            args.repo_root, args.contract, args.output,
            args.fixture_manifest, args.blackcoind, args.blackcoin_cli,
            args.target_sha,
            args.fixture_manifest_sha256,
        )
    except (RuntimeError, OSError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    finally:
        if gate is not None:
            gate.close()
        signal.signal(signal.SIGTERM, previous_sigterm)
    print(f"Current live partial-epoch resource evidence written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
