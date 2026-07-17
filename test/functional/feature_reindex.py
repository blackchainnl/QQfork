#!/usr/bin/env python3
# Copyright (c) 2014-2021 Blackcoin Core Developers
# Copyright (c) 2014-2021 Blackcoin More Developers
# Copyright (c) 2014-2021 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with -reindex and -reindex-chainstate options.

- Start a single node and generate 3 blocks.
- Stop the node and restart it with -reindex. Verify that the node has reindexed up to block 3.
- Stop the node and restart it with -reindex-chainstate. Verify that the node has reindexed up to block 3.
- Verify that out-of-order blocks are correctly processed, see LoadExternalBlockFile()
"""

import socket
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.p2p import MAGIC_BYTES
from test_framework.util import assert_equal, p2p_port, rpc_port


class ReindexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def reindex(self, justchainstate=False):
        self.generatetoaddress(self.nodes[0], 3, self.nodes[0].get_deterministic_priv_key().address)
        blockcount = self.nodes[0].getblockcount()
        self.stop_nodes()
        if justchainstate:
            node = self.nodes[0]
            journal = node.chain_path / "chainstate-rebuild.journal"
            backup = node.chain_path / "chainstate.rebuild-backup"
            self.run_chainstate_rebuild_first_pass(node, ["-reindex-chainstate"])
            assert journal.is_file()
            assert backup.is_dir()
            self.restart_after_chainstate_rebuild(0)
            assert_equal(node.getblockcount(), blockcount)
        else:
            self.start_nodes([["-reindex"]])
            assert_equal(self.nodes[0].getblockcount(), blockcount)  # start_node is blocking on reindex
        self.log.info("Success")

    @staticmethod
    def _port_is_open(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            return sock.connect_ex(("127.0.0.1", port)) == 0

    def _assert_services_quiesced(self, node):
        for service, port in (("RPC/HTTP", rpc_port(node.index)),
                              ("P2P", p2p_port(node.index))):
            assert not self._port_is_open(port), \
                f"{service} listener was active during protected chainstate rebuild"

    def _wait_for_rebuild_exit_with_services_quiesced(self, node):
        deadline = time.monotonic() + 60 * self.options.timeout_factor
        saw_running = False
        while node.process.poll() is None:
            saw_running = True
            self._assert_services_quiesced(node)
            if time.monotonic() > deadline:
                raise AssertionError("protected chainstate rebuild did not exit")
            time.sleep(0.01)
        self._assert_services_quiesced(node)
        assert saw_running, "protected chainstate rebuild exited before service state could be checked"
        node.wait_until_stopped()

    def _wait_for_verification_marker_with_services_quiesced(self, node, offset):
        marker = "Verified the rebuilt chainstate after restart and retired preserved databases"
        deadline = time.monotonic() + 60 * self.options.timeout_factor
        while node.process.poll() is None:
            with node.debug_log_path.open("rb") as debug_log:
                debug_log.seek(offset)
                verification_log = debug_log.read().decode("utf8", errors="replace")
                marker_offset = verification_log.find(marker)
                if marker_offset >= 0:
                    # Normal RPC startup is allowed only after the replacement
                    # has been verified and its preserved source retired. Check
                    # ordering as well as live ports so a fast transition cannot
                    # hide an endpoint that bound during verification.
                    for rpc_marker in ("Binding RPC on address", "Starting HTTP RPC server"):
                        rpc_offset = verification_log.find(rpc_marker)
                        assert rpc_offset < 0 or rpc_offset > marker_offset, \
                            f"{rpc_marker} occurred before protected verification completed"
                    return
            self._assert_services_quiesced(node)
            if time.monotonic() > deadline:
                raise AssertionError("protected chainstate verification did not complete")
            time.sleep(0.01)
        raise AssertionError("protected chainstate verification exited before completion")

    def protected_rebuild_services(self):
        """The two protected passes must not bind RPC/HTTP or P2P listeners."""
        node = self.nodes[0]
        self.log.info("Check that a protected chainstate rebuild defers services")
        self.generatetoaddress(node, 100, node.get_deterministic_priv_key().address)
        blockcount = node.getblockcount()
        self.stop_node(0)

        node.start(["-reindex-chainstate"])
        self._wait_for_rebuild_exit_with_services_quiesced(node)

        journal = node.chain_path / "chainstate-rebuild.journal"
        assert journal.exists()
        assert "phase=commit-ready\n" in journal.read_text(encoding="utf8")

        log_offset = node.debug_log_size(mode="rb")
        node.start([])
        self._wait_for_verification_marker_with_services_quiesced(node, log_offset)
        node.wait_for_rpc_connection()
        assert_equal(node.getblockcount(), blockcount)

    # Check that blocks can be processed out of order
    def out_of_order(self):
        # The previous test created 12 blocks
        assert_equal(self.nodes[0].getblockcount(), 12)
        self.stop_nodes()

        # In this test environment, blocks will always be in order (since
        # we're generating them rather than getting them from peers), so to
        # test out-of-order handling, swap blocks 1 and 2 on disk.
        blk0 = self.nodes[0].blocks_path / "blk00000.dat"
        with open(blk0, 'r+b') as bf:
            # Read at least the first few blocks (including genesis)
            b = bf.read(2000)

            # Find the offsets of blocks 2, 3, and 4 (the first 3 blocks beyond genesis)
            # by searching for the regtest marker bytes (see pchMessageStart).
            def find_block(b, start):
                return b.find(MAGIC_BYTES["regtest"], start)+4

            genesis_start = find_block(b, 0)
            assert_equal(genesis_start, 4)
            b2_start = find_block(b, genesis_start)
            b3_start = find_block(b, b2_start)
            b4_start = find_block(b, b3_start)

            # Blocks 2 and 3 should be the same size.
            assert_equal(b3_start-b2_start, b4_start-b3_start)

            # Swap the second and third blocks (don't disturb the genesis block).
            bf.seek(b2_start)
            bf.write(b[b3_start:b4_start])
            bf.write(b[b2_start:b3_start])

        # The reindexing code should detect and accommodate out of order blocks.
        with self.nodes[0].assert_debug_log([
            'LoadExternalBlockFile: Out of order block',
            'LoadExternalBlockFile: Processing out of order child',
        ]):
            extra_args = [["-reindex"]]
            self.start_nodes(extra_args)

        # All blocks should be accepted and processed.
        assert_equal(self.nodes[0].getblockcount(), 12)

    def run_test(self):
        self.reindex(False)
        self.reindex(True)
        self.reindex(False)
        self.reindex(True)

        self.out_of_order()
        self.protected_rebuild_services()


if __name__ == '__main__':
    ReindexTest().main()
