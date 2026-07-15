#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test protected chainstate rebuild service isolation and recovery.

The first ``-reindex-chainstate`` process is intentionally not a node. It
must commit the rebuilt chainstate, exit successfully, and leave normal
services for a separate verification restart. This test reserves the exact
RPC, P2P, and ZMQ endpoints while that first process runs. A successful exit
therefore proves that it did not initialize those services. It also exercises
the real startup, block, and shutdown notification commands, then verifies
that interrupted BUILDING/PREPARED/ROLLING_BACK journals recover before normal
service initialization, CLEANUP_READY recovery completes before services, and
malformed journals fail closed.
"""

import errno
import shlex
import socket
import sys
import time
from pathlib import Path

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port, rpc_port


ZERO_HASH = "0" * 64


class ChainstateRebuildLifecycleTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoind_zmq()

    def setup_network(self):
        self.marker_dir = Path(self.options.tmpdir) / "chainstate-rebuild-markers"
        self.marker_dir.mkdir()
        self.startup_marker = self.marker_dir / "startup"
        self.block_marker = self.marker_dir / "block"
        self.shutdown_marker = self.marker_dir / "shutdown"
        self.p2p_listen_port = p2p_port(0)
        self.rpc_listen_port = rpc_port(0)
        # This test only starts node 0. Reserve a second framework-assigned
        # P2P port for ZMQ so concurrent functional-test workers cannot collide.
        self.zmq_listen_port = p2p_port(self.num_nodes + 1)
        self.zmq_address = f"tcp://127.0.0.1:{self.zmq_listen_port}"
        super().setup_network()

    def service_args(self):
        startup_marker = shlex.quote(str(self.startup_marker))
        block_marker = shlex.quote(str(self.block_marker))
        shutdown_marker = shlex.quote(str(self.shutdown_marker))
        return [
            "-autostartstaking=0",
            "-server=1",
            "-listen=1",
            f"-port={self.p2p_listen_port}",
            f"-rpcport={self.rpc_listen_port}",
            f"-rpcbind=127.0.0.1:{self.rpc_listen_port}",
            "-rpcallowip=127.0.0.1",
            f"-zmqpubhashblock={self.zmq_address}",
            f"-startupnotify=printf startup > {startup_marker}",
            f"-blocknotify=printf block > {block_marker}",
            f"-shutdownnotify=printf shutdown > {shutdown_marker}",
            "-debug=rpc",
            "-debug=http",
            "-debug=net",
            "-debug=zmq",
        ]

    @staticmethod
    def reserve_closed_port(port):
        """Reserve a TCP address without listening on it.

        A connection to this socket is refused while the reservation prevents
        Blackcoin from binding the same endpoint. It gives the test both an
        active listener-isolation probe and a deterministic startup guard.
        """
        deadline = time.monotonic() + 10
        while True:
            reserved = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                reserved.bind(("127.0.0.1", port))
                return reserved
            except OSError as error:
                reserved.close()
                if error.errno != errno.EADDRINUSE or time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    @staticmethod
    def port_refuses_connections(port):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.1)
        try:
            return probe.connect_ex(("127.0.0.1", port)) != 0
        finally:
            probe.close()

    @staticmethod
    def port_accepts_connections(port):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.1)
        try:
            return probe.connect_ex(("127.0.0.1", port)) == 0
        finally:
            probe.close()

    def reserve_service_ports(self):
        return [
            self.reserve_closed_port(self.p2p_listen_port),
            self.reserve_closed_port(self.rpc_listen_port),
            self.reserve_closed_port(self.zmq_listen_port),
        ]

    def assert_service_ports_refused(self):
        for port in (
            self.p2p_listen_port,
            self.rpc_listen_port,
            self.zmq_listen_port,
        ):
            assert self.port_refuses_connections(port), f"service unexpectedly accepted TCP on {port}"

    def clear_markers(self):
        for marker in (self.startup_marker, self.block_marker, self.shutdown_marker):
            marker.unlink(missing_ok=True)

    @staticmethod
    def journal_has_phase(journal, phase):
        try:
            return f"phase={phase}\n" in journal.read_text(encoding="utf-8")
        except OSError:
            return False

    @staticmethod
    def write_interrupted_journal(journal, phase):
        journal.write_text(
            "blackcoin-chainstate-rebuild-v2\n"
            f"phase={phase}\n"
            "base=1\n"
            "snapshot=0\n"
            "commitment=0\n"
            f"tip={ZERO_HASH}\n"
            "coins=0\n"
            f"full_coin_hash={ZERO_HASH}\n",
            encoding="utf-8",
        )

    @staticmethod
    def replace_journal_phase(journal, old_phase, new_phase):
        contents = journal.read_text(encoding="utf-8")
        old_line = f"phase={old_phase}\n"
        assert contents.count(old_line) == 1, f"missing or duplicate journal phase {old_phase}"
        journal.write_text(contents.replace(old_line, f"phase={new_phase}\n", 1), encoding="utf-8")

    @staticmethod
    def log_delta(node, offset):
        return node.debug_log_path.read_bytes()[offset:].decode("utf-8", errors="replace")

    @staticmethod
    def kill_node_process(node):
        """Kill without RPC shutdown and reset the framework's process state."""
        node.process.kill()
        node.process.wait(timeout=node.rpc_timeout)
        node.stdout.close()
        node.stderr.close()
        node.running = False
        node.process = None
        node.rpc_connected = False
        node.rpc = None

    def kill_after_durable_rebuild_transition(self, phase, *, reindex_chainstate):
        """Use the production journal path, then send a real process kill."""
        node = self.nodes[0]
        marker = node.chain_path / "chainstate-rebuild-test-pause"
        journal = node.chain_path / "chainstate-rebuild.journal"
        marker.unlink(missing_ok=True)
        extra_args = [f"-testchainstaterebuildpauseafter={phase}"]
        if reindex_chainstate:
            extra_args.append("-reindex-chainstate")
        node.start(extra_args=extra_args)
        self.wait_until(lambda: marker.exists(), timeout=60)
        assert_equal(marker.read_text(encoding="utf-8"), f"{phase}\n")
        assert self.journal_has_phase(journal, phase)
        self.kill_node_process(node)
        marker.unlink()

    def verify_recovered_tip(self, expected_height, expected_tip):
        node = self.nodes[0]
        self.start_node(0)
        assert_equal(node.getblockcount(), expected_height)
        assert_equal(node.getbestblockhash(), expected_tip)
        self.stop_node(0)

    def exhaust_process_file_writes_during_reconstruction(self, expected_height, expected_tip):
        """Apply a real POSIX file-size quota after BUILDING is durable."""
        node = self.nodes[0]
        journal = node.chain_path / "chainstate-rebuild.journal"
        backup = node.chain_path / "chainstate.rebuild-backup"
        node.start(extra_args=[
            "-reindex-chainstate",
            "-testchainstaterebuildfilesizelimit=1",
        ])
        return_code = node.process.wait(timeout=60)
        assert return_code != 0, "reconstruction unexpectedly succeeded under a one-byte file quota"
        node.stdout.close()
        node.stderr.close()
        node.running = False
        node.process = None
        node.rpc_connected = False
        node.rpc = None
        assert self.journal_has_phase(journal, "building")
        assert backup.is_dir()
        self.verify_recovered_tip(expected_height, expected_tip)

    def assert_log_before(self, text, first, second):
        first_offset = text.find(first)
        second_offset = text.find(second)
        assert first_offset >= 0, f"missing log marker: {first}"
        assert second_offset >= 0, f"missing log marker: {second}"
        assert first_offset < second_offset, f"{second} preceded {first}"

    def run_first_pass_with_reserved_services(self):
        node = self.nodes[0]
        journal = node.chain_path / "chainstate-rebuild.journal"
        backup = node.chain_path / "chainstate.rebuild-backup"
        self.clear_markers()
        log_offset = node.debug_log_size()
        reservations = self.reserve_service_ports()
        committed = False
        try:
            node.start(extra_args=[*self.service_args(), "-reindex-chainstate"])
            deadline = time.monotonic() + 60
            while node.process.poll() is None:
                self.assert_service_ports_refused()
                committed = committed or self.journal_has_phase(journal, "commit-ready")
                if time.monotonic() >= deadline:
                    raise AssertionError("protected chainstate rebuild did not exit within 60 seconds")
                time.sleep(0.01)
            node.wait_until_stopped()
            self.assert_service_ports_refused()
        finally:
            for reservation in reservations:
                reservation.close()

        committed = committed or self.journal_has_phase(journal, "commit-ready")
        assert committed, "first rebuild pass never reached durable COMMIT_READY"
        assert journal.is_file()
        assert backup.is_dir()
        assert not self.startup_marker.exists()
        assert not self.block_marker.exists()
        assert not self.shutdown_marker.exists()

        first_pass_log = self.log_delta(node, log_offset)
        for service_marker in (
            "Binding RPC on address",
            "Notifier pubhashblock",
            "Done loading",
            "Starting initial sync",
            "Loading wallet",
        ):
            assert service_marker not in first_pass_log, (
                f"first rebuild pass initialized normal service: {service_marker}"
            )
        assert "Skipping -shutdownnotify for planned chainstate rebuild restart" in first_pass_log

    def verify_restart_enables_services(self, expected_height, expected_tip):
        node = self.nodes[0]
        journal = node.chain_path / "chainstate-rebuild.journal"
        backup = node.chain_path / "chainstate.rebuild-backup"
        log_offset = node.debug_log_size()
        self.start_node(0, extra_args=self.service_args())

        assert not journal.exists()
        assert not backup.exists()
        verification_log = self.log_delta(node, log_offset)
        cleanup_marker = "Verified the rebuilt chainstate after restart and retired preserved databases"
        self.assert_log_before(verification_log, cleanup_marker, "Binding RPC on address")
        self.assert_log_before(verification_log, cleanup_marker, "Notifier pubhashblock ready")
        assert_equal(node.getblockcount(), expected_height)
        assert_equal(node.getbestblockhash(), expected_tip)

        for port in (
            self.p2p_listen_port,
            self.rpc_listen_port,
            self.zmq_listen_port,
        ):
            self.wait_until(lambda port=port: self.port_accepts_connections(port), timeout=10)
        assert_equal(node.getzmqnotifications(), [
            {"type": "pubhashblock", "address": self.zmq_address, "hwm": 1000},
        ])
        self.wait_until(lambda: self.startup_marker.exists(), timeout=10)

    def assert_interrupted_recovery_precedes_services(self, phase, expected_height, expected_tip):
        node = self.nodes[0]
        chainstate = node.chain_path / "chainstate"
        backup = node.chain_path / "chainstate.rebuild-backup"
        journal = node.chain_path / "chainstate-rebuild.journal"
        assert chainstate.is_dir()
        assert not backup.exists()
        chainstate.rename(backup)
        self.write_interrupted_journal(journal, phase)
        self.clear_markers()
        log_offset = node.debug_log_size()
        reservations = self.reserve_service_ports()
        try:
            node.assert_start_raises_init_error(
                extra_args=self.service_args(),
                expected_msg=r"Error: Unable to start HTTP server\. See debug log for details\.",
                match=ErrorMatch.PARTIAL_REGEX,
            )
            self.assert_service_ports_refused()
        finally:
            for reservation in reservations:
                reservation.close()

        assert chainstate.is_dir()
        assert not backup.exists()
        assert not journal.exists()
        recovery_log = self.log_delta(node, log_offset)
        self.assert_log_before(
            recovery_log,
            "Restored the original chainstate after an interrupted staged rebuild",
            "Binding RPC on address",
        )
        assert "Notifier pubhashblock" not in recovery_log
        assert not self.startup_marker.exists()
        assert not self.block_marker.exists()

        self.start_node(0, extra_args=self.service_args())
        assert_equal(node.getblockcount(), expected_height)
        assert_equal(node.getbestblockhash(), expected_tip)
        self.stop_node(0)

    def assert_cleanup_ready_recovery_precedes_services(self, expected_height, expected_tip):
        """Exercise a crash after durable CLEANUP_READY but before backup removal."""
        node = self.nodes[0]
        journal = node.chain_path / "chainstate-rebuild.journal"
        backup = node.chain_path / "chainstate.rebuild-backup"
        assert journal.is_file()
        assert backup.is_dir()
        self.replace_journal_phase(journal, "commit-ready", "cleanup-ready")
        self.clear_markers()
        log_offset = node.debug_log_size()
        reservations = self.reserve_service_ports()
        try:
            node.assert_start_raises_init_error(
                extra_args=self.service_args(),
                expected_msg=r"Error: Unable to start HTTP server\. See debug log for details\.",
                match=ErrorMatch.PARTIAL_REGEX,
            )
            self.assert_service_ports_refused()
        finally:
            for reservation in reservations:
                reservation.close()

        assert not journal.exists()
        assert not backup.exists()
        recovery_log = self.log_delta(node, log_offset)
        self.assert_log_before(
            recovery_log,
            "Recovered verified chainstate rebuild cleanup before normal service initialization",
            "Binding RPC on address",
        )
        assert "Notifier pubhashblock" not in recovery_log
        assert not self.startup_marker.exists()
        assert not self.block_marker.exists()

        self.start_node(0, extra_args=self.service_args())
        assert_equal(node.getblockcount(), expected_height)
        assert_equal(node.getbestblockhash(), expected_tip)
        self.stop_node(0)

    def assert_malformed_journal_fails_closed(self):
        node = self.nodes[0]
        journal = node.chain_path / "chainstate-rebuild.journal"
        self.clear_markers()
        journal.write_text("this is not a chainstate rebuild journal\n", encoding="utf-8")
        log_offset = node.debug_log_size()
        reservations = self.reserve_service_ports()
        try:
            node.assert_start_raises_init_error(
                extra_args=self.service_args(),
                expected_msg=r"Error: The chainstate rebuild journal is unreadable or malformed",
                match=ErrorMatch.PARTIAL_REGEX,
            )
            self.assert_service_ports_refused()
        finally:
            for reservation in reservations:
                reservation.close()

        assert journal.is_file()
        malformed_log = self.log_delta(node, log_offset)
        for service_marker in ("Binding RPC on address", "Notifier pubhashblock", "Done loading"):
            assert service_marker not in malformed_log, (
                f"malformed rebuild journal initialized normal service: {service_marker}"
            )
        assert not self.startup_marker.exists()
        assert not self.block_marker.exists()

        journal.unlink()

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Build a persistent chainstate for protected rebuild testing")
        self.generatetoaddress(node, 6, node.get_deterministic_priv_key().address)
        expected_height = node.getblockcount()
        expected_tip = node.getbestblockhash()
        self.stop_node(0)

        self.log.info("Commit the isolated first rebuild pass without opening service endpoints")
        self.run_first_pass_with_reserved_services()

        self.log.info("Verify the committed replacement before normal services become available")
        self.verify_restart_enables_services(expected_height, expected_tip)
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address)
        self.wait_until(lambda: self.block_marker.exists(), timeout=10)
        expected_height = node.getblockcount()
        expected_tip = node.getbestblockhash()
        self.stop_node(0)
        self.wait_until(lambda: self.shutdown_marker.exists(), timeout=10)

        for phase in ("building", "prepared", "rolling-back"):
            self.log.info(f"Recover interrupted {phase.upper()} rebuild before normal services")
            self.assert_interrupted_recovery_precedes_services(
                phase, expected_height, expected_tip)

        self.log.info("Commit another rebuild, then recover durable CLEANUP_READY before services")
        self.run_first_pass_with_reserved_services()
        self.assert_cleanup_ready_recovery_precedes_services(expected_height, expected_tip)

        self.log.info("Fail closed on a malformed rebuild journal before normal services")
        self.assert_malformed_journal_fails_closed()
        self.start_node(0, extra_args=self.service_args())
        assert_equal(node.getblockcount(), expected_height)
        assert_equal(node.getbestblockhash(), expected_tip)
        self.stop_node(0)

        for phase in ("prepared", "building"):
            self.log.info(f"Kill the daemon after durable {phase.upper()} and recover the original chainstate")
            self.kill_after_durable_rebuild_transition(
                phase, reindex_chainstate=True)
            self.verify_recovered_tip(expected_height, expected_tip)

        self.log.info("Kill rollback itself after durable ROLLING_BACK, then resume it on another start")
        self.kill_after_durable_rebuild_transition(
            "building", reindex_chainstate=True)
        self.kill_after_durable_rebuild_transition(
            "rolling-back", reindex_chainstate=False)
        self.verify_recovered_tip(expected_height, expected_tip)

        self.log.info("Kill after durable COMMIT_READY, then verify and retire the backup on restart")
        self.kill_after_durable_rebuild_transition(
            "commit-ready", reindex_chainstate=True)
        self.verify_recovered_tip(expected_height, expected_tip)

        self.log.info("Kill after durable CLEANUP_READY, then finish retryable backup cleanup")
        self.run_first_pass_with_reserved_services()
        self.kill_after_durable_rebuild_transition(
            "cleanup-ready", reindex_chainstate=False)
        self.verify_recovered_tip(expected_height, expected_tip)

        if sys.platform != "win32":
            self.log.info("Exhaust real process file writes during reconstruction and recover the preserved source")
            self.exhaust_process_file_writes_during_reconstruction(
                expected_height, expected_tip)


if __name__ == "__main__":
    ChainstateRebuildLifecycleTest().main()
