#!/usr/bin/env python3
"""Exercise the exact Migration -> Final -> demurrage height boundary.

This is intentionally independent of the time-only demurrage test. It checks
the activation sentinel at A-1/A, restart behavior, a disconnect/reconnect,
and chainstate replay at the first active height.
"""

import http.client

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class QuantumDemurrageHeightBoundaryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=2",
            "-shadowgoldrushblocks=2",
            "-qqgoldrushendheight=4",
            "-qqmigrationendheight=6",
            "-qqdemurrageheight=7",
            "-qqdemurrageblockspermonth=4",
            "-minimumchainwork=0x00",
            "-assumevalid=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        wallet.staking(False)
        address = wallet.getnewaddress("boundary", "legacy")
        quantum_address = wallet.getnewquantumaddress()["address"]

        self.log.info("Mine to A-2 and verify Migration remains active")
        self.generatetoaddress(node, 4, address)
        assert_equal(node.getblockcount(), 4)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 4)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")

        self.log.info("Mine A-1 and verify the Final boundary is deterministic")
        self.generatetoaddress(node, 2, address)
        assert_equal(node.getblockcount(), 6)
        info = node.getquantumquasarinfo()
        assert_equal(info["phase"], "final_lockout")
        supply = node.getcirculatingsupply()
        assert_equal(supply["demurrage_active"], True)
        assert_equal(supply["demurrage_height_guard_satisfied"], True)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], True)
        self.log.info("Restart on A-1 with the authenticated empty sentinel")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 6)
        assert_equal(node.getcirculatingsupply()["demurrage_active"], True)

        self.log.info("Connect A and verify the activation sentinel survives a reorg")
        activation_hash = self.generatetoaddress(node, 1, quantum_address)[0]
        assert_equal(node.getblockcount(), 7)
        active_supply = node.getcirculatingsupply()
        assert_equal(active_supply["demurrage_active"], True)
        self.log.info("Restart on A with the v4 rolling inventory")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 7)
        assert_equal(node.getcirculatingsupply()["demurrage_active"], True)
        node.invalidateblock(activation_hash)
        assert_equal(node.getblockcount(), 6)
        node.reconsiderblock(activation_hash)
        assert_equal(node.getblockcount(), 7)
        assert_equal(node.getbestblockhash(), activation_hash)

        self.log.info("Replay the active boundary from block files")
        self.stop_node(0)
        self.start_node(0, extra_args=self.extra_args[0] + ["-reindex-chainstate"])
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 7)
        replay_supply = node.getcirculatingsupply()
        assert_equal(replay_supply["demurrage_active"], True)
        assert_equal(replay_supply["bestblock"], node.getbestblockhash())

        self.log.info("Fail closed on an interrupted multi-batch Final chainstate flush")
        crash_args = self.extra_args[0] + ["-dbbatchsize=100", "-dbcrashratio=1"]
        self.restart_node(0, extra_args=crash_args)
        node = self.nodes[0]
        self.generatetoaddress(node, 1, quantum_address)
        try:
            # gettxoutsetinfo forces a chainstate flush. With a tiny batch and
            # crash ratio 1, the node exits after committing the first partial
            # LevelDB batch and leaves DB_HEAD_BLOCKS for startup recovery.
            node.gettxoutsetinfo()
        except (http.client.CannotSendRequest,
                http.client.RemoteDisconnected,
                OSError):
            pass
        else:
            raise AssertionError("expected simulated partial-flush crash")
        node.wait_until_stopped()

        failure = (
            "ReplayBlocks(): interrupted multi-batch flush crossed "
            "authenticated Quantum Quasar state; restart with -reindex-chainstate"
        )
        with node.assert_debug_log([failure]):
            node.assert_start_raises_init_error(extra_args=self.extra_args[0])

        self.start_node(0, extra_args=self.extra_args[0] + ["-reindex-chainstate"])
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 8)
        assert_equal(node.getcirculatingsupply()["demurrage_active"], True)


if __name__ == "__main__":
    QuantumDemurrageHeightBoundaryTest().main()
