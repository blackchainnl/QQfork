#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the restart-safe full-epoch synthetic shadow-family LevelDB gate.

This gate measures the completed 243,000-block incremental shadow-family
workload now. It is not a terminal combined-chainstate or production-RPC
maximum. A separate live-partial gate replays the current mainnet shadow ledger
through blackcoind and measures the current combined database.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from generate_resource_benchmark_evidence import verify_epoch_source_contract
import verify_shadow_resource_production_evidence as evidence_verifier


GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_CONTRACT_ID = "blackcoin.qq.shadow.synthetic-full-epoch.leveldb.v3"


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


def git_output(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def normalize_origin(value: str) -> str:
    value = value.strip().removesuffix(".git").removesuffix("/")
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value[len("git@github.com:"):]
    if value.startswith("ssh://git@github.com/"):
        value = "https://github.com/" + value[len("ssh://git@github.com/"):]
    return value


def database_snapshot(
        database: Path, include_files: bool = False,
        tolerate_churn: bool = False) -> dict:
    result = {
        "total_bytes": 0,
        "sst_bytes": 0,
        "wal_bytes": 0,
        "manifest_bytes": 0,
        "other_bytes": 0,
        "file_count": 0,
    }
    files = {}
    if not database.is_dir():
        if tolerate_churn:
            return result
        raise RuntimeError(
            f"synthetic LevelDB directory is missing: {database}"
        )
    try:
        with os.scandir(database) as entries:
            for entry in entries:
                try:
                    metadata = entry.stat(follow_symlinks=False)
                except FileNotFoundError as error:
                    if tolerate_churn:
                        continue
                    raise RuntimeError(
                        f"synthetic LevelDB file disappeared: {entry.path}"
                    ) from error
                if stat.S_ISLNK(metadata.st_mode):
                    raise RuntimeError(
                        f"synthetic LevelDB contains a symlink: {entry.path}"
                    )
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                size = metadata.st_size
                name = entry.name
                suffix = Path(name).suffix
                stem = Path(name).stem
                files[name] = size
                result["total_bytes"] += size
                result["file_count"] += 1
                if suffix in (".ldb", ".sst"):
                    result["sst_bytes"] += size
                elif suffix == ".log" and stem.isdigit():
                    result["wal_bytes"] += size
                elif name.startswith("MANIFEST-"):
                    result["manifest_bytes"] += size
                else:
                    result["other_bytes"] += size
    except FileNotFoundError as error:
        if tolerate_churn:
            return result
        raise RuntimeError(
            f"synthetic LevelDB directory disappeared: {database}"
        ) from error
    if include_files:
        result["_files"] = files
    return result


def public_snapshot(value: dict) -> dict:
    return {key: item for key, item in value.items() if key != "_files"}


def disappeared_bytes(before: dict, after: dict) -> int:
    return sum(
        size for name, size in before.get("_files", {}).items()
        if name not in after.get("_files", {})
    )


def process_rss_bytes(pid: int) -> int:
    values = []
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    except FileNotFoundError:
        # Very short clean-open probes may exit before the sampler thread gets
        # its first timeslice. Long apply/scan/authentication phases remain
        # sampled normally and dominate the process-wide peak summary.
        return 0
    except OSError as error:
        raise RuntimeError(f"cannot read Linux process resource data: {error}") from error
    for line in lines:
        if line.startswith(("VmRSS:", "VmHWM:")):
            _, raw, unit = line.split()
            if unit != "kB":
                raise RuntimeError(f"unexpected /proc memory unit: {unit}")
            values.append(int(raw) * 1024)
    if not values:
        raise RuntimeError("Linux process RSS/HWM fields are missing")
    return max(values)


class Sampler:
    def __init__(self, pid: int, database: Path, interval: int):
        self.pid = pid
        self.database = database
        self.interval = interval
        self.stop_event = threading.Event()
        self.failure = None
        self.sample_count = 0
        self.maximum_sample_seconds = 0.0
        self.maximum_sample_gap_seconds = 0.0
        self.last_sample_started = None
        self.peak = {
            "peak_rss_bytes": 0,
            "peak_database_bytes": 0,
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
        snapshot = database_snapshot(
            self.database, tolerate_churn=True
        )
        self.peak["peak_rss_bytes"] = max(self.peak["peak_rss_bytes"], rss)
        for source, target in (
            ("total_bytes", "peak_database_bytes"),
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
        except Exception as error:  # propagated by finish
            self.failure = error

    def start(self) -> None:
        self._sample()
        self.thread.start()

    def finish(self) -> dict:
        self.stop_event.set()
        self.thread.join()
        if self.failure:
            raise RuntimeError(f"resource sampler failed: {self.failure}") from self.failure
        # Pin every phase to its endpoint even when it completes between
        # periodic samples. A missing exited process contributes zero RSS, but
        # the final physical database state is always observed.
        self._sample()
        result = dict(self.peak)
        result.update(
            sample_count=self.sample_count,
            maximum_sample_seconds=self.maximum_sample_seconds,
            maximum_sample_gap_seconds=self.maximum_sample_gap_seconds,
        )
        return result


class SyntheticGate:
    def __init__(self, args, contract: dict, binding: dict):
        self.args = args
        self.contract = contract
        self.binding = binding
        self.database = args.work_dir / "synthetic-leveldb"
        self.journal_path = args.work_dir / "synthetic-journal.json"
        self.snapshot_root = args.work_dir / "synthetic-predecessor"
        self.snapshot_marker = args.work_dir / "synthetic-predecessor.json"
        self.current_process = None
        self.current_sampler = None
        args.work_dir.mkdir(parents=True, exist_ok=True)
        self.lock_fd = os.open(
            args.work_dir / ".shadow-resource.lock",
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self.lock_fd)
            raise RuntimeError(
                "another synthetic gate or surviving child owns this work directory"
            ) from error
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
        journal = load_json(self.journal_path, "synthetic gate journal")
        if set(journal) != {
            "schema", "binding", "active_phase", "completed",
        }:
            raise RuntimeError("synthetic gate journal fields differ")
        if journal["schema"] != 2 or journal["binding"] != self.binding:
            raise RuntimeError("synthetic gate journal belongs to different inputs")
        if (
            journal["active_phase"] is not None
            and not isinstance(journal["active_phase"], str)
        ):
            raise RuntimeError("synthetic gate journal active phase is invalid")
        if not isinstance(journal["completed"], dict):
            raise RuntimeError("synthetic gate journal completion map is invalid")
        return journal

    def save(self, name: str, value) -> None:
        active = self.journal["active_phase"]
        if active is not None and active != name:
            raise RuntimeError(
                f"cannot complete synthetic {name} while {active} is active"
            )
        self.journal["completed"][name] = value
        self.journal["active_phase"] = None
        atomic_json(self.journal_path, self.journal)

    def begin(self, name: str) -> bool:
        active = self.journal["active_phase"]
        if active is not None and active != name:
            raise RuntimeError(
                f"synthetic gate journal has interrupted {active} while "
                f"starting {name}"
            )
        interrupted = active == name
        self.journal["active_phase"] = name
        atomic_json(self.journal_path, self.journal)
        return interrupted

    def parse_state(self, output: str) -> dict:
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise RuntimeError("synthetic fixture state is not JSON") from error
        if (
            set(value) != {"schema", "phase", "height"}
            or value["schema"] != 1
            or value["phase"] not in {
                "empty", "applying", "applied", "undoing", "undone",
                "reapplying", "reapplied",
            }
            or not isinstance(value["height"], int)
            or isinstance(value["height"], bool)
        ):
            raise RuntimeError("synthetic fixture state is invalid")
        return value

    def reset_database(self) -> None:
        expected = self.args.work_dir / "synthetic-leveldb"
        if self.database != expected or self.database == Path("/"):
            raise RuntimeError(
                "refusing to reset an unexpected synthetic database path"
            )
        if self.database.is_symlink():
            raise RuntimeError(
                "refusing to reset a symbolic-link synthetic database"
            )
        if self.database.exists():
            require_unowned_lock(
                self.database / "LOCK", "synthetic LevelDB"
            )
            shutil.rmtree(self.database)

    def copy_database(self, source: Path, destination: Path) -> None:
        if destination.exists() or destination.is_symlink():
            raise RuntimeError("synthetic snapshot destination already exists")
        destination.mkdir(mode=0o700)
        for path in source.iterdir():
            if path.is_symlink() or not path.is_file():
                raise RuntimeError(
                    f"synthetic database has an unsupported entry: {path}"
                )
            target = destination / path.name
            if path.suffix in {".ldb", ".sst"}:
                # SSTables are immutable. A same-filesystem hard link creates
                # a byte-exact predecessor without duplicating 100+ GiB.
                os.link(path, target)
            else:
                shutil.copy2(path, target)
                with target.open("rb") as copied:
                    os.fsync(copied.fileno())
        if sys.platform == "linux":
            directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def remove_snapshot(self, expected_phase: str = "") -> None:
        if expected_phase and self.snapshot_marker.exists():
            marker = load_json(
                self.snapshot_marker, "synthetic predecessor marker"
            )
            if marker.get("phase") != expected_phase:
                return
        if self.snapshot_marker.exists():
            if self.snapshot_marker.is_symlink():
                raise RuntimeError("synthetic predecessor marker is a symlink")
            self.snapshot_marker.unlink()
        if self.snapshot_root.exists():
            if (
                self.snapshot_root.is_symlink()
                or self.snapshot_root.parent != self.args.work_dir
            ):
                raise RuntimeError("unsafe synthetic predecessor directory")
            shutil.rmtree(self.snapshot_root)

    def load_snapshot(self, name: str):
        if not self.snapshot_marker.exists():
            return None
        marker = load_json(
            self.snapshot_marker, "synthetic predecessor marker"
        )
        if set(marker) != {"schema", "binding", "phase", "snapshot"}:
            raise RuntimeError("synthetic predecessor marker fields differ")
        if (
            marker["schema"] != 1
            or marker["binding"] != self.binding
            or marker["phase"] != name
            or not self.snapshot_root.is_dir()
            or self.snapshot_root.is_symlink()
        ):
            raise RuntimeError("synthetic predecessor identity differs")
        actual = database_snapshot(self.snapshot_root, include_files=True)
        if marker["snapshot"] != actual:
            raise RuntimeError("synthetic predecessor snapshot differs")
        return marker

    def create_snapshot(self, name: str) -> dict:
        existing = self.load_snapshot(name)
        if existing is not None:
            return existing
        if self.snapshot_root.exists() or self.snapshot_marker.exists():
            self.remove_snapshot()
        temporary = self.snapshot_root.with_name(
            self.snapshot_root.name + ".tmp"
        )
        if temporary.exists() or temporary.is_symlink():
            if temporary.is_symlink() or temporary.parent != self.args.work_dir:
                raise RuntimeError("unsafe temporary predecessor directory")
            shutil.rmtree(temporary)
        self.copy_database(self.database, temporary)
        snapshot = database_snapshot(temporary, include_files=True)
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
            raise RuntimeError(f"synthetic {name} predecessor is missing")
        self.reset_database()
        self.copy_database(self.snapshot_root, self.database)
        if database_snapshot(self.database, include_files=True) != marker["snapshot"]:
            raise RuntimeError("restored synthetic predecessor differs")

    def include_snapshot_peak(self, resources: dict, snapshot: dict) -> None:
        for source, target in (
            ("total_bytes", "peak_database_bytes"),
            ("sst_bytes", "peak_sst_bytes"),
            ("wal_bytes", "peak_wal_bytes"),
            ("manifest_bytes", "peak_manifest_bytes"),
            ("other_bytes", "peak_other_bytes"),
        ):
            resources[target] = max(resources[target], snapshot[source])

    def invoke(self, command: str, timeout: int) -> tuple[dict, str]:
        if self.current_process is not None:
            raise RuntimeError("a prior synthetic fixture process is active")
        process = subprocess.Popen(
            [
                str(self.args.fixture_binary), command, str(self.database),
                "--measurement-barriers",
            ],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
            pass_fds=(self.lock_fd,),
        )
        sampler = Sampler(
            process.pid, self.database,
            self.contract["measurement"]["sample_interval_seconds"],
        )
        self.current_process = process
        self.current_sampler = sampler
        started = time.monotonic()
        try:
            # The fixture blocks before opening LevelDB. Sampling the live
            # child first removes the Popen/thread race for short clean-open
            # phases without weakening the positive-RSS evidence invariant.
            sampler.start()
            if process.stdin is None:
                raise RuntimeError("synthetic start barrier is unavailable")
            process.stdin.write("\n")
            process.stdin.flush()
            if process.stdout is None:
                raise RuntimeError("synthetic measured output pipe is unavailable")
            ready, _, _ = select.select(
                [process.stdout], [], [], timeout
            )
            if not ready:
                raise subprocess.TimeoutExpired(process.args, timeout)
            first_line = process.stdout.readline()
            if not first_line:
                # EOF means the child failed before reaching its completion
                # barrier. Reap it and preserve its diagnostic.
                _, stderr = process.communicate(timeout=60)
                self.discard_sampler(sampler)
                self.current_sampler = None
                self.current_process = None
                raise RuntimeError(
                    f"synthetic {command} failed before measured output: "
                    f"{stderr.strip() or process.returncode}"
                )
            # The child has completed the LevelDB operation but remains alive
            # at its second barrier. This live /proc sample includes VmHWM for
            # the operation, including sub-interval clean opens.
            resources = sampler.finish()
            self.current_sampler = None
            process.stdin.write("\n")
            process.stdin.flush()
            process.stdin.close()
            process.stdin = None
            remaining = max(1.0, timeout - (time.monotonic() - started))
            stdout_tail, stderr = process.communicate(timeout=remaining)
            stdout = first_line + stdout_tail
        except subprocess.TimeoutExpired:
            self.abort_current()
            raise RuntimeError(f"synthetic {command} exceeded its pinned timeout")
        except BaseException:
            self.abort_current()
            raise
        self.current_process = None
        if process.returncode:
            raise RuntimeError(
                f"synthetic {command} failed: {stderr.strip() or stdout.strip()}"
            )
        resources["wall_seconds"] = time.monotonic() - started
        return resources, stdout.strip()

    def abort_current(self) -> None:
        process = self.current_process
        sampler = self.current_sampler
        try:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=300)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process is not None and process.stdin is not None:
                process.stdin.close()
                process.stdin = None
            if sampler is not None and sampler.thread.is_alive():
                try:
                    sampler.finish()
                except RuntimeError:
                    pass
        finally:
            self.current_sampler = None
            self.current_process = None

    def discard_sampler(self, sampler: Sampler) -> None:
        if sampler.thread.is_alive():
            try:
                sampler.finish()
            except RuntimeError:
                pass

    def close(self) -> None:
        self.abort_current()
        lock_fd = getattr(self, "lock_fd", None)
        if lock_fd is not None:
            # Do not explicitly unlock: a surviving child inherits this same
            # open-file description and must continue to exclude a retry.
            os.close(lock_fd)
            self.lock_fd = None

    def phase(self, name: str, command: str, timeout_key: str) -> tuple[dict, str]:
        if name in self.journal["completed"]:
            saved = self.journal["completed"][name]
            self.remove_snapshot(name)
            return saved["resources"], saved.get("output", "")
        interrupted = self.begin(name)
        marker = self.create_snapshot(name)
        if interrupted:
            self.restore_snapshot(name)
        resources, output = self.invoke(
            command, self.contract["budgets"][timeout_key],
        )
        self.include_snapshot_peak(resources, marker["snapshot"])
        value = {"resources": resources, "output": output}
        self.save(name, value)
        self.remove_snapshot(name)
        return resources, output

    def measured_apply(self) -> tuple[dict, dict]:
        if "apply" in self.journal["completed"]:
            saved = self.journal["completed"]["apply"]
            if set(saved) != {"resources", "output", "post_snapshot"}:
                raise RuntimeError(
                    "completed synthetic apply lacks its exact snapshot"
                )
            return saved["resources"], saved["post_snapshot"]
        interrupted = self.begin("apply")
        if interrupted or self.database.exists():
            # A complete apply has no journal until its post-state snapshot is
            # durable. Any database present here is partial or unauthenticated
            # and therefore cannot shorten the measured full apply.
            self.reset_database()
        resources, output = self.invoke(
            "apply", self.contract["budgets"]["maximum_full_apply_seconds"],
        )
        post_snapshot = database_snapshot(self.database, include_files=True)
        expected = self.contract["synthetic_fixture"]
        if self.parse_state(output) != {
            "schema": 1,
            "phase": "applied",
            "height": expected["reward_end_height"],
        }:
            raise RuntimeError(
                "measured synthetic apply did not reach the exact end"
            )
        self.save("apply", {
            "resources": resources,
            "output": output,
            "post_snapshot": post_snapshot,
        })
        return resources, post_snapshot

    def measured_undo(self) -> dict:
        if "undo" in self.journal["completed"]:
            self.remove_snapshot("undo")
            return self.journal["completed"]["undo"]["resources"]
        interrupted = self.journal["active_phase"] == "undo"
        self.begin("undo")
        marker = self.create_snapshot("undo")
        if interrupted:
            self.restore_snapshot("undo")
        resources, output = self.invoke(
            "undo", self.contract["budgets"]["maximum_full_undo_seconds"],
        )
        self.include_snapshot_peak(resources, marker["snapshot"])
        expected_height = (
            self.contract["synthetic_fixture"]["reward_start_height"] - 1
        )
        if self.parse_state(output) != {
            "schema": 1,
            "phase": "undone",
            "height": expected_height,
        }:
            raise RuntimeError(
                "measured synthetic undo did not reach the exact start"
            )
        self.save("undo", {"resources": resources, "output": output})
        self.remove_snapshot("undo")
        return resources

    def measured_reapply(self) -> tuple[dict, dict]:
        if "reapply" in self.journal["completed"]:
            saved = self.journal["completed"]["reapply"]
            if set(saved) != {"resources", "output", "post_snapshot"}:
                raise RuntimeError(
                    "completed synthetic reapply lacks its exact snapshot"
                )
            self.remove_snapshot("reapply")
            return saved["resources"], saved["post_snapshot"]
        interrupted = self.journal["active_phase"] == "reapply"
        self.begin("reapply")
        marker = self.create_snapshot("reapply")
        if interrupted:
            self.restore_snapshot("reapply")
        resources, output = self.invoke(
            "reapply",
            self.contract["budgets"]["maximum_full_reapply_seconds"],
        )
        self.include_snapshot_peak(resources, marker["snapshot"])
        post_snapshot = database_snapshot(self.database, include_files=True)
        expected = self.contract["synthetic_fixture"]
        if self.parse_state(output) != {
            "schema": 1,
            "phase": "reapplied",
            "height": expected["reward_end_height"],
        }:
            raise RuntimeError(
                "measured synthetic reapply did not reach the exact end"
            )
        self.save("reapply", {
            "resources": resources,
            "output": output,
            "post_snapshot": post_snapshot,
        })
        self.remove_snapshot("reapply")
        return resources, post_snapshot

    def measured_compaction(self) -> tuple[dict, dict, dict]:
        if "compact" in self.journal["completed"]:
            saved = self.journal["completed"]["compact"]
            if set(saved) != {
                "resources", "output", "steady_snapshot",
                "compacted_snapshot",
            }:
                raise RuntimeError("completed compaction lacks bound snapshots")
            self.remove_snapshot("compact")
            return (
                saved["resources"],
                saved["steady_snapshot"],
                saved["compacted_snapshot"],
            )
        interrupted = self.journal["active_phase"] == "compact"
        self.begin("compact")
        expected = self.contract["synthetic_fixture"]
        predecessor = {
            "schema": 1,
            "phase": "reapplied",
            "height": expected["reward_end_height"],
        }
        marker = self.create_snapshot("compact")
        if interrupted:
            self.restore_snapshot("compact")
        steady = marker["snapshot"]
        resources, output = self.invoke(
            "compact",
            self.contract["budgets"]["maximum_forced_compaction_seconds"],
        )
        if self.parse_state(output) != predecessor:
            raise RuntimeError("synthetic compaction changed fixture state")
        self.include_snapshot_peak(resources, steady)
        compacted = database_snapshot(self.database, include_files=True)
        self.save("compact", {
            "resources": resources,
            "output": output,
            "steady_snapshot": steady,
            "compacted_snapshot": compacted,
        })
        self.remove_snapshot("compact")
        return resources, steady, compacted

    def parse_scan(self, output: str, phase: str, exact: bool) -> dict:
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise RuntimeError("synthetic scan returned invalid JSON") from error
        expected = self.contract["synthetic_fixture"]
        if value.get("schema") != 1 or value.get("contract_id") != EXPECTED_CONTRACT_ID:
            raise RuntimeError("synthetic scan contract identity differs")
        if value.get("phase") != phase:
            raise RuntimeError(f"synthetic scan phase is {value.get('phase')}, expected {phase}")
        if exact:
            checks = {
                "height": expected["reward_end_height"],
                "records": expected["total_records"],
                "claims": expected["issued_claims"],
                "payouts": expected["issued_claims"],
                "provenance": expected["issued_claims"],
                "logical_proof_buckets": expected[
                    "logical_proof_bucket_records"
                ],
                "logical_bytes": expected["retained_logical_batch_payload_bytes"],
            }
        else:
            checks = {
                "height": expected["reward_start_height"] - 1,
                "records": 0,
                "claims": 0,
                "payouts": 0,
                "provenance": 0,
                "logical_proof_buckets": 0,
                "logical_bytes": 0,
            }
        for key, expected_value in checks.items():
            if value.get(key) != expected_value:
                raise RuntimeError(
                    f"synthetic scan {key}={value.get(key)}, expected {expected_value}"
                )
        return value

    def parse_authentication(self, output: str) -> dict:
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "synthetic authentication returned invalid JSON"
            ) from error
        expected = self.contract["synthetic_fixture"]
        exact = {
            "schema": 1,
            "contract_id": EXPECTED_CONTRACT_ID,
            "phase": "applied",
            "height": expected["reward_end_height"],
            "sequential_records": expected[
                "authentication_sequential_records"
            ],
            "provenance_records": expected["issued_claims"],
            "payout_candidates": expected["issued_claims"],
            "payout_authenticated": expected["issued_claims"],
            "attestation_candidates": expected["issued_claims"],
            "attestation_lookup_hits": expected["issued_claims"],
            "logical_proof_bucket_lookups": expected[
                "logical_proof_bucket_point_lookups"
            ],
            "point_lookups": expected["authentication_point_lookups"],
        }
        if value != exact:
            raise RuntimeError(
                "synthetic authentication did not execute the exact "
                "completed-epoch point-lookup envelope"
            )
        return value

    def run(self) -> dict:
        apply, post_apply_before_scan = self.measured_apply()
        apply_scan_resources, apply_scan_raw = self.phase(
            "apply_scan", "scan", "maximum_full_scan_seconds",
        )
        apply_scan = self.parse_scan(apply_scan_raw, "applied", True)
        authentication_resources, authentication_raw = self.phase(
            "authentication", "authenticate",
            "maximum_full_authentication_seconds",
        )
        authentication = self.parse_authentication(authentication_raw)

        startups = []
        for index in range(self.contract["measurement"]["clean_startup_runs"]):
            resources, output = self.phase(
                f"startup_{index + 1}", "open", "maximum_clean_startup_seconds",
            )
            opened = json.loads(output)
            if opened != {
                "schema": 1, "phase": "applied",
                "height": self.contract["synthetic_fixture"]["reward_end_height"],
            }:
                raise RuntimeError("clean synthetic startup opened unexpected state")
            startups.append(resources)

        if "post_apply_cleanup" in self.journal["completed"]:
            post_apply_obsolete = self.journal["completed"][
                "post_apply_cleanup"
            ]
        else:
            post_apply_clean = database_snapshot(
                self.database, include_files=True
            )
            post_apply_obsolete = disappeared_bytes(
                post_apply_before_scan, post_apply_clean
            )
            self.save("post_apply_cleanup", post_apply_obsolete)

        undo = self.measured_undo()
        undo_scan_resources, undo_scan_raw = self.phase(
            "undo_scan", "scan", "maximum_full_scan_seconds",
        )
        self.parse_scan(undo_scan_raw, "undone", False)
        reapply, post_reapply_before_scan = self.measured_reapply()
        reapply_scan_resources, reapply_scan_raw = self.phase(
            "reapply_scan", "scan", "maximum_full_scan_seconds",
        )
        reapply_scan = self.parse_scan(reapply_scan_raw, "reapplied", True)
        if "post_reapply_cleanup" in self.journal["completed"]:
            post_reapply_obsolete = self.journal["completed"][
                "post_reapply_cleanup"
            ]
        else:
            post_reapply_clean = database_snapshot(
                self.database, include_files=True
            )
            post_reapply_obsolete = disappeared_bytes(
                post_reapply_before_scan, post_reapply_clean
            )
            self.save("post_reapply_cleanup", post_reapply_obsolete)

        compact, steady, compacted = self.measured_compaction()
        compact_scan_resources, compact_scan_raw = self.phase(
            "compact_scan", "scan", "maximum_full_scan_seconds",
        )
        compact_scan = self.parse_scan(compact_scan_raw, "reapplied", True)

        logical = self.contract["synthetic_fixture"][
            "retained_logical_batch_payload_bytes"
        ]
        all_phases = [
            apply, apply_scan_resources, authentication_resources, undo,
            undo_scan_resources, reapply, reapply_scan_resources, compact,
            compact_scan_resources, *startups,
        ]
        transient = max(item["peak_database_bytes"] for item in all_phases)
        peak_rss = max(item["peak_rss_bytes"] for item in all_phases)
        reclaimed = max(0, steady["total_bytes"] - compacted["total_bytes"])
        obsolete = max(post_apply_obsolete, post_reapply_obsolete)
        evidence = {
            "schema": 2,
            "status": "complete",
            "evidence_kind": "deterministic_synthetic_full_epoch",
            "not_live_chain_evidence": True,
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
            "fixture_binary": {
                "sha256": self.binding["fixture_binary_sha256"],
                "size_bytes": self.args.fixture_binary.stat().st_size,
            },
            "fixture": apply_scan,
            "authentication": authentication,
            "post_reapply_fixture": reapply_scan,
            "post_compaction_fixture": compact_scan,
            "phases": {
                "full_apply": apply,
                "full_scan": apply_scan_resources,
                "full_authentication": authentication_resources,
                "clean_startups": startups,
                "full_undo": undo,
                "undo_scan": undo_scan_resources,
                "full_reapply": reapply,
                "reapply_scan": reapply_scan_resources,
                "forced_compaction": compact,
                "compaction_scan": compact_scan_resources,
            },
            "leveldb": {
                "steady_snapshot": public_snapshot(steady),
                "compacted_snapshot": public_snapshot(compacted),
                "maximum_observed_bytes": transient,
                "obsolete_file_bytes": obsolete,
                "post_apply_cleanup_obsolete_bytes": post_apply_obsolete,
                "post_reapply_cleanup_obsolete_bytes": post_reapply_obsolete,
                "forced_compaction_reclaimed_bytes": reclaimed,
                "steady_physical_to_logical_ratio": steady["total_bytes"] / logical,
                "maximum_observed_physical_to_logical_ratio": transient / logical,
                "obsolete_file_to_logical_ratio": obsolete / logical,
                "forced_compaction_reclaim_ratio": (
                    reclaimed / steady["total_bytes"]
                    if steady["total_bytes"] else 0
                ),
            },
            "maximum_peak_rss_bytes": peak_rss,
        }
        atomic_json(self.args.output, evidence)
        return evidence


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--fixture-binary", type=Path, required=True)
    parser.add_argument("--target-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    gate = None
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_shutdown(signum, frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    signal.signal(signal.SIGTERM, request_shutdown)
    try:
        reject_symlink_components(args.work_dir, "work directory")
        args.repo_root = args.repo_root.resolve(strict=True)
        args.contract = args.contract.resolve(strict=True)
        args.fixture_binary = args.fixture_binary.resolve(strict=True)
        args.work_dir = args.work_dir.resolve()
        args.output = args.output.resolve()
        if (
            args.work_dir == Path("/")
            or args.work_dir == args.repo_root
            or args.repo_root in args.work_dir.parents
        ):
            raise RuntimeError(
                "work directory must be external to the source repository"
            )
        if args.output == args.work_dir or args.work_dir not in args.output.parents:
            raise RuntimeError("synthetic evidence output must be inside work directory")
        if not GIT_SHA_RE.fullmatch(args.target_sha):
            raise RuntimeError("target SHA must be full lowercase 40-character hex")
        if os.name != "posix" or not Path("/proc/self/status").is_file():
            raise RuntimeError("exact synthetic resource sampling requires Linux /proc")
        if not os.access(args.fixture_binary, os.X_OK):
            raise RuntimeError("fixture binary is not executable")
        if git_output(args.repo_root, "rev-parse", "HEAD") != args.target_sha:
            raise RuntimeError("source checkout differs from target SHA")
        if git_output(args.repo_root, "status", "--porcelain"):
            raise RuntimeError("source checkout has tracked or untracked changes")
        origin = normalize_origin(git_output(args.repo_root, "remote", "get-url", "origin"))
        if origin != "https://github.com/Blackcoin-Dev/Blackcoin":
            raise RuntimeError("source origin is not Blackcoin-Dev/Blackcoin")
        contract = load_json(args.contract, "resource contract")
        evidence_verifier.verify_contract(contract)
        verify_epoch_source_contract(args.repo_root)
        tool_contract = subprocess.run(
            [str(args.fixture_binary), "contract"], capture_output=True,
            text=True, check=True,
        )
        if json.loads(tool_contract.stdout) != contract["synthetic_fixture"]:
            raise RuntimeError("fixture binary contract differs from checked-in contract")
        args.work_dir.mkdir(parents=True, exist_ok=True)
        binding = {
            "target_sha": args.target_sha,
            "contract_sha256": sha256_file(args.contract),
            "fixture_binary_sha256": sha256_file(args.fixture_binary),
            "measurement_environment": (
                evidence_verifier.collect_measurement_environment(
                    args.repo_root, args.work_dir
                )
            ),
        }
        gate = SyntheticGate(args, contract, binding)
        gate.run()
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError, KeyboardInterrupt) as error:
        print(f"shadow synthetic resource gate: {error}", file=sys.stderr)
        return 1
    finally:
        if gate is not None:
            gate.close()
        signal.signal(signal.SIGTERM, previous_sigterm)


if __name__ == "__main__":
    raise SystemExit(main())
