#!/usr/bin/env python3
"""Exercise the exact Migration -> Final/demurrage height boundary.

This is intentionally independent of the time-only demurrage test. It checks
automatic activation without a separate demurrage-height option, the sentinel
at A-1/A, restart behavior on both sides of that sentinel, disconnect/reconnect,
and chainstate replay at the first active height.
"""

import http.client

from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


LAST_GOLD_RUSH_HEIGHT = 4
LAST_MIGRATION_HEIGHT = 6
FIRST_FINAL_HEIGHT = LAST_MIGRATION_HEIGHT + 1


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
            f"-qqgoldrushendheight={LAST_GOLD_RUSH_HEIGHT}",
            f"-qqmigrationendheight={LAST_MIGRATION_HEIGHT}",
            "-qqdemurrageblockspermonth=4",
            "-minimumchainwork=0x00",
            "-assumevalid=0",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def assert_lifecycle(self, node, tip_phase, next_phase, demurrage_active):
        height = node.getblockcount()
        info = node.getquantumquasarinfo()
        assert_equal(info["phase_context"], "next_block")
        assert_equal(info["active_tip_height"], height)
        assert_equal(info["active_tip_phase"], tip_phase)
        assert_equal(info["next_block_height"], height + 1)
        assert_equal(info["next_block_phase"], next_phase)
        assert_equal(info["phase"], next_phase)
        assert_equal(info["height_boundaries_authoritative"], True)

        supply = node.getcirculatingsupply()
        assert_equal(supply["height"], height)
        assert_equal(supply["evaluation_height"], height + 1)
        assert_equal(supply["demurrage_activation_height"], FIRST_FINAL_HEIGHT)
        assert_equal(supply["demurrage_effective_activation_height"], FIRST_FINAL_HEIGHT)
        assert_equal(supply["quantum_migration_end_height"], LAST_MIGRATION_HEIGHT)
        assert_equal(supply["height_boundaries_authoritative"], True)
        assert_equal(supply["demurrage_active"], demurrage_active)
        assert_equal(supply["demurrage_height_guard_satisfied"], demurrage_active)
        assert_equal(supply["demurrage_post_migration_guard_satisfied"], demurrage_active)
        return supply

    def state_fingerprint(self, node):
        txoutset = node.gettxoutsetinfo("muhash")
        supply = node.getcirculatingsupply()
        return {
            "height": txoutset["height"],
            "bestblock": txoutset["bestblock"],
            "txouts": txoutset["txouts"],
            "total_amount": txoutset["total_amount"],
            "muhash": txoutset["muhash"],
            "circulating_amount": supply["circulating_amount"],
            "decayed_amount": supply["decayed_amount"],
            "locked_txouts": supply["locked_txouts"],
        }

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        wallet.staking(False)
        address = wallet.getnewaddress("boundary", "legacy")
        quantum_address = wallet.getnewquantumaddress()["address"]

        self.log.info("Mine the last Gold Rush block; the next block enters Migration")
        self.generatetoaddress(node, LAST_GOLD_RUSH_HEIGHT, address)
        assert_equal(node.getblockcount(), LAST_GOLD_RUSH_HEIGHT)
        self.assert_lifecycle(node, "gold_rush", "migration", False)
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), LAST_GOLD_RUSH_HEIGHT)
        self.assert_lifecycle(node, "gold_rush", "migration", False)

        self.log.info("Mine the last Migration block; next-block demurrage activates with Final")
        migration_hashes = self.generatetoaddress(
            node, LAST_MIGRATION_HEIGHT - LAST_GOLD_RUSH_HEIGHT, address
        )
        last_migration_hash = migration_hashes[-1]
        assert_equal(node.getblockcount(), LAST_MIGRATION_HEIGHT)
        self.assert_lifecycle(node, "migration", "final_lockout", True)
        self.log.info("Restart on the last Migration block with the authenticated empty sentinel")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), LAST_MIGRATION_HEIGHT)
        self.assert_lifecycle(node, "migration", "final_lockout", True)

        self.log.info("Connect the first Final block and verify zero-boundary activation")
        activation_hash = self.generatetoaddress(node, 1, quantum_address)[0]
        assert_equal(node.getblockcount(), FIRST_FINAL_HEIGHT)
        self.assert_lifecycle(node, "final_lockout", "final_lockout", True)
        self.log.info("Restart on the first Final block with the v4 rolling inventory")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), FIRST_FINAL_HEIGHT)
        self.assert_lifecycle(node, "final_lockout", "final_lockout", True)

        self.log.info("Disconnect Final, then the sentinel block, and restart below the boundary")
        node.invalidateblock(activation_hash)
        assert_equal(node.getblockcount(), LAST_MIGRATION_HEIGHT)
        self.assert_lifecycle(node, "migration", "final_lockout", True)
        node.invalidateblock(last_migration_hash)
        assert_equal(node.getblockcount(), LAST_MIGRATION_HEIGHT - 1)
        self.assert_lifecycle(node, "migration", "migration", False)
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockcount(), LAST_MIGRATION_HEIGHT - 1)
        self.assert_lifecycle(node, "migration", "migration", False)

        self.log.info("Reconsider the sentinel ancestor and deterministically reapply Final")
        node.reconsiderblock(last_migration_hash)
        assert_equal(node.getblockcount(), FIRST_FINAL_HEIGHT)
        assert_equal(node.getbestblockhash(), activation_hash)
        self.assert_lifecycle(node, "final_lockout", "final_lockout", True)

        self.log.info("Replay the active boundary from block files")
        self.stop_node(0)
        self.run_chainstate_rebuild_first_pass(
            node, self.extra_args[0] + ["-reindex-chainstate"])
        self.restart_after_chainstate_rebuild(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        assert_equal(node.getblockcount(), FIRST_FINAL_HEIGHT)
        replay_supply = node.getcirculatingsupply()
        assert_equal(replay_supply["demurrage_active"], True)
        assert_equal(replay_supply["bestblock"], node.getbestblockhash())
        self.assert_lifecycle(node, "final_lockout", "final_lockout", True)

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

        self.run_chainstate_rebuild_first_pass(
            node, self.extra_args[0] + ["-reindex-chainstate"])
        self.restart_after_chainstate_rebuild(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 8)
        assert_equal(node.getcirculatingsupply()["demurrage_active"], True)

        self.log.info("Commit the repaired state and reject repair without required block history")
        self.restart_node(0)
        node = self.nodes[0]
        expected_state = self.state_fingerprint(node)
        self.stop_node(0)
        block_file = node.blocks_path / "blk00000.dat"
        missing_block_file = block_file.with_suffix(".dat.boundary-test-backup")
        block_file.rename(missing_block_file)
        try:
            node.assert_start_raises_init_error(
                extra_args=self.extra_args[0] + ["-reindex-chainstate"],
                expected_msg=r"Error: Error loading block database",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        finally:
            missing_block_file.rename(block_file)

        assert not (node.chain_path / "chainstate-rebuild.journal").exists()
        assert not (node.chain_path / "chainstate.rebuild-backup").exists()
        assert (node.chain_path / "chainstate").is_dir()
        self.start_node(0)
        node = self.nodes[0]
        assert_equal(self.state_fingerprint(node), expected_state)

        self.log.info("A full block reindex reproduces the same Final state")
        self.restart_node(0, extra_args=self.extra_args[0] + ["-reindex"])
        node = self.nodes[0]
        assert_equal(self.state_fingerprint(node), expected_state)
        self.assert_lifecycle(node, "final_lockout", "final_lockout", True)


if __name__ == "__main__":
    QuantumDemurrageHeightBoundaryTest().main()
