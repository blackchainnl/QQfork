#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Keep local mining RPCs from bypassing the Gold Rush output policy."""

from test_framework.address import program_to_witness
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


SHADOW_REWARD_END_HEIGHT = 3
GOLD_RUSH_END_HEIGHT = 5
MIGRATION_END_HEIGHT = 10
FUTURE_COINBASE_ERROR = "Future-witness coinbase outputs are disabled during the Gold Rush epoch"


class GoldRushLocalMiningPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=2",
            f"-shadowgoldrushendheight={SHADOW_REWARD_END_HEIGHT}",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
        ]]

    def _assert_gold_rush_reject(self, rpc, *args, **kwargs):
        assert_raises_rpc_error(-8, FUTURE_COINBASE_ERROR, rpc, *args, **kwargs)

    def run_test(self):
        node = self.nodes[0]
        legacy_address = node.get_deterministic_priv_key().address
        quantum_address = program_to_witness(16, bytes([16]) * 32)
        unknown_future_address = program_to_witness(2, bytes([2]) * 32)
        quantum_descriptor = f"addr({quantum_address})"

        self.log.info("Rejecting direct future-witness coinbase outputs in every local mining RPC")
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        self._assert_gold_rush_reject(
            node.generatetoaddress, 1, quantum_address, invalid_call=False)
        self._assert_gold_rush_reject(
            node.generatetoaddress, 1, unknown_future_address, invalid_call=False)
        self._assert_gold_rush_reject(
            node.generatetodescriptor, 1, quantum_descriptor, invalid_call=False)
        self._assert_gold_rush_reject(
            node.generateblock, quantum_address, [], invalid_call=False)
        self._assert_gold_rush_reject(
            node.generateblock, quantum_descriptor, [], False, invalid_call=False)
        assert_equal(node.getblockcount(), 0)

        self.log.info("Keeping the guard active through the post-reward Gold Rush tail")
        self.generatetoaddress(
            node, SHADOW_REWARD_END_HEIGHT, legacy_address, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), SHADOW_REWARD_END_HEIGHT)
        phase = node.getquantumquasarinfo()
        assert_equal(phase["phase"], "gold_rush")
        assert_equal(phase["shadow_reward_height_active"], False)
        self._assert_gold_rush_reject(
            node.generatetoaddress, 1, quantum_address, invalid_call=False)
        assert_equal(node.getblockcount(), SHADOW_REWARD_END_HEIGHT)

        self.log.info("Allowing a recognized quantum coinbase once Migration begins")
        self.generatetoaddress(
            node,
            GOLD_RUSH_END_HEIGHT - SHADOW_REWARD_END_HEIGHT,
            legacy_address,
            sync_fun=self.no_op,
        )
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT)
        phase = node.getquantumquasarinfo()
        assert_equal(phase["active_tip_phase"], "gold_rush")
        assert_equal(phase["phase"], "migration")
        block_hash = self.generatetoaddress(
            node, 1, quantum_address, sync_fun=self.no_op)[0]
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT + 1)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")
        coinbase = node.getblock(block_hash, 2)["tx"][0]
        assert_equal(coinbase["vout"][0]["scriptPubKey"]["address"], quantum_address)


if __name__ == "__main__":
    GoldRushLocalMiningPolicyTest().main()
