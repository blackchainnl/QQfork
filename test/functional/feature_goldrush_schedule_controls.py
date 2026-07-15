#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the dedicated testnet Gold Rush schedule controls.

This file is intentionally branch-only. The public release line keeps the
production schedule fixed; this testnet branch exposes guarded schedule knobs
so live testnet wallets can exercise the whitelist and Gold Rush paths without
waiting for mainnet heights.
"""

from decimal import Decimal
import os
import subprocess

from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript, OP_16
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, assert_raises_rpc_error


class GoldRushScheduleControlsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "testnet3"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Rejecting malformed schedule controls before startup")
        node.assert_start_raises_init_error(
            extra_args=[
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=100",
                "-shadowgoldrushblocks=10",
            ],
            expected_msg="-shadowgoldrushstartheight must be greater than -shadowwhitelistheight",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Rejecting the compressed competing-claim boundary outside regtest")
        node.assert_start_raises_init_error(
            extra_args=["-shadowcompetingclaimsheight=110"],
            expected_msg="-shadowcompetingclaimsheight is only supported on regtest",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Rejecting schedule controls on mainnet")
        mainnet_datadir = os.path.join(self.options.tmpdir, "mainnet_schedule_guard")
        os.makedirs(mainnet_datadir, exist_ok=True)
        mainnet_result = subprocess.run(
            [
                self.options.bitcoind,
                f"-datadir={mainnet_datadir}",
                "-chain=main",
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=110",
                "-shadowgoldrushblocks=10",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        assert mainnet_result.returncode != 0
        assert "only supported on testnet/regtest" in (mainnet_result.stdout + mainnet_result.stderr)

        self.log.info("Rejecting -shadowgoldrushendheight combined with -shadowgoldrushblocks")
        node.assert_start_raises_init_error(
            extra_args=[
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=110",
                "-shadowgoldrushblocks=10",
                "-shadowgoldrushendheight=119",
            ],
            expected_msg="-shadowgoldrushendheight cannot be combined with -shadowgoldrushblocks",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Rejecting a migration end height at or below the Gold Rush end height")
        node.assert_start_raises_init_error(
            extra_args=[
                "-qqgoldrushendheight=200",
                "-qqmigrationendheight=200",
            ],
            expected_msg="-qqmigrationendheight must be greater than -qqgoldrushendheight",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Rejecting a Gold Rush phase end height below the reward window end")
        node.assert_start_raises_init_error(
            extra_args=[
                "-shadowwhitelistheight=100",
                "-shadowgoldrushstartheight=110",
                "-shadowgoldrushendheight=119",
                "-qqgoldrushendheight=115",
                "-qqmigrationendheight=215",
            ],
            expected_msg="must not be below the shadow reward end height",
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.log.info("Starting testnet with an explicit whitelist/start/end schedule")
        self.start_node(0, [
            "-shadowwhitelistheight=100",
            "-shadowgoldrushstartheight=110",
            "-shadowgoldrushblocks=10",
        ])

        info = node.getquantumquasarinfo()
        assert_equal(info["shadow_reward_start_height"], 110)
        assert_equal(info["shadow_reward_end_height"], 119)
        assert_equal(info["shadow_reward_next_height"], 1)
        assert_equal(info["shadow_reward_height_active"], False)
        # A shadow-window override without separate phase controls derives a
        # complete height-authoritative lifecycle from that reward window.
        assert_equal(info["gold_rush_end_height"], 119)
        assert info["quantum_migration_end_height"] > info["gold_rush_end_height"]
        assert_equal(info["height_boundaries_authoritative"], True)
        self.stop_node(0)

        self.log.info("Starting testnet with the height-based phase boundaries")
        self.start_node(0, [
            "-shadowwhitelistheight=100",
            "-shadowgoldrushstartheight=110",
            "-shadowgoldrushendheight=119",
            "-qqgoldrushendheight=119",
            "-qqmigrationendheight=219",
        ])

        info = node.getquantumquasarinfo()
        assert_equal(info["shadow_reward_start_height"], 110)
        assert_equal(info["shadow_reward_end_height"], 119)
        assert_equal(info["gold_rush_end_height"], 119)
        assert_equal(info["quantum_migration_end_height"], 219)
        assert_equal(info["phase"], "gold_rush")

        self.log.info("Rejecting raw generateblock transaction injection outside regtest")
        address = node.get_deterministic_priv_key().address
        raw_tx = node.createrawtransaction(
            [{"txid": "00" * 32, "vout": 0}],
            [{address: Decimal("1")}],
        )
        assert_raises_rpc_error(
            -8,
            "Raw transaction injection through generateblock is only available on regtest",
            node.generateblock,
            address,
            [raw_tx],
            False,
            invalid_call=False,
        )

        self.log.info("Rejecting a known-parent future-witness coinbase through submitblock")
        tip = node.getbestblockhash()
        coinbase = create_coinbase(
            node.getblockcount() + 1,
            script_pubkey=CScript([OP_16, bytes([16]) * 32]),
        )
        block = create_block(
            int(tip, 16),
            coinbase,
            node.getblockheader(tip)["time"] + 1,
        )
        assert_equal(
            node.submitblock(block.serialize().hex()),
            "goldrush-future-witness-coinbase",
        )


if __name__ == "__main__":
    GoldRushScheduleControlsTest().main()
