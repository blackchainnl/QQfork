#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Prove Gold Rush ordinary PoS remains unrestricted in a mixed wallet.

The deterministic whitelist controls shadow PoS reward eligibility only. A
wallet containing both whitelisted and non-whitelisted mature legacy outputs
must still search the non-whitelisted outputs for an ordinary base-chain PoS
kernel.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


GOLD_RUSH_END_TIME = 2_000_000_000
WALLET_NAME = "goldrush_mixed_pos"


class GoldRushPosUnrestrictedTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=3000",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xf) + 16)

    @staticmethod
    def _kernel_inputs(utxos):
        return [{"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in utxos]

    def _find_non_whitelisted_only_kernel_time(self, wallet, whitelist_inputs, non_whitelist_inputs):
        for _ in range(5000):
            self._bump_mocktime(16)
            non_whitelist_kernel = wallet.checkkernel(non_whitelist_inputs)
            whitelist_kernel = wallet.checkkernel(whitelist_inputs)
            if non_whitelist_kernel["found"] and not whitelist_kernel["found"]:
                return non_whitelist_kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a non-whitelisted-only PoS kernel")

    def _find_kernel_time(self, wallet, inputs):
        for _ in range(5000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a PoS kernel")

    def _mine_at_kernel(self, wallet, kernel_time):
        node = self.nodes[0]
        start_height = node.getblockcount()
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=30)
        finally:
            wallet.staking(False)
        return node.getblock(node.getbestblockhash(), 2)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)

        self.log.info("Creating the whitelist snapshot with one mixed-wallet address")
        whitelist_address = wallet.getnewaddress("whitelisted", "legacy")
        whitelist_script = wallet.getaddressinfo(whitelist_address)["scriptPubKey"]
        funding_address = default_wallet.getnewaddress("funding", "legacy")
        self.generatetoaddress(node, 1, whitelist_address, sync_fun=self.no_op)

        self.log.info("Creating a pure non-whitelisted wallet after the snapshot")
        node.createwallet(wallet_name="goldrush_pure_nonwhitelist")
        pure_wallet = node.get_wallet_rpc("goldrush_pure_nonwhitelist")
        pure_wallet.staking(False)
        pure_address = pure_wallet.getnewaddress("pure-non-whitelisted", "legacy")
        pure_script = pure_wallet.getaddressinfo(pure_address)["scriptPubKey"]

        self.generatetoaddress(node, COINBASE_MATURITY + 8, funding_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Funding a second address after the snapshot so it is not whitelisted")
        non_whitelist_address = wallet.getnewaddress("non-whitelisted", "legacy")
        non_whitelist_script = wallet.getaddressinfo(non_whitelist_address)["scriptPubKey"]
        funding_txid = default_wallet.sendtoaddress(non_whitelist_address, Decimal("5000"))
        pure_funding_txid = default_wallet.sendtoaddress(pure_address, Decimal("10000"))
        funding_block = self.generatetoaddress(node, 1, funding_address, sync_fun=self.no_op)[0]
        assert funding_txid in node.getblock(funding_block)["tx"]
        assert pure_funding_txid in node.getblock(funding_block)["tx"]
        self.generatetoaddress(node, COINBASE_MATURITY, funding_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()

        wallet_scripts = {entry["address"]: entry for entry in wallet.getgoldrushinfo()["wallet_scripts"]}
        assert_equal(wallet_scripts[whitelist_address]["whitelisted"], True)
        assert_equal(wallet_scripts[non_whitelist_address]["whitelisted"], False)

        mature = wallet.listunspent(COINBASE_MATURITY, 9999999)
        whitelist_utxos = [utxo for utxo in mature if utxo["scriptPubKey"] == whitelist_script]
        non_whitelist_utxos = [utxo for utxo in mature if utxo["scriptPubKey"] == non_whitelist_script]
        assert_equal(len(whitelist_utxos), 1)
        assert_equal(len(non_whitelist_utxos), 1)
        pure_utxos = [utxo for utxo in pure_wallet.listunspent(COINBASE_MATURITY, 9999999) if utxo["scriptPubKey"] == pure_script]
        assert_equal(len(pure_utxos), 1)

        self.log.info("Selecting a timestamp where only the non-whitelisted output has a valid kernel")
        kernel_time = self._find_non_whitelisted_only_kernel_time(
            wallet,
            self._kernel_inputs(whitelist_utxos),
            self._kernel_inputs(non_whitelist_utxos),
        )

        self.log.info("The mixed wallet must produce the ordinary PoS block with that kernel")
        block = self._mine_at_kernel(wallet, kernel_time)
        assert "proof-of-stake" in block["flags"]
        kernel_input = block["tx"][1]["vin"][0]
        assert_equal(kernel_input["txid"], non_whitelist_utxos[0]["txid"])
        assert_equal(kernel_input["vout"], non_whitelist_utxos[0]["vout"])
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("A pure non-whitelisted wallet also stakes, without a shadow reward")
        shadow_before = node.getgoldrushstate()
        pure_kernel_time = self._find_kernel_time(pure_wallet, self._kernel_inputs(pure_utxos))
        pure_block = self._mine_at_kernel(pure_wallet, pure_kernel_time)
        pure_kernel = pure_block["tx"][1]["vin"][0]
        assert_equal(pure_kernel["txid"], pure_utxos[0]["txid"])
        assert_equal(pure_kernel["vout"], pure_utxos[0]["vout"])
        shadow_after = node.getgoldrushstate()
        assert_equal(shadow_after["pos_count"], shadow_before["pos_count"])
        assert_equal(shadow_after["claimed_amount"], shadow_before["claimed_amount"])
        assert_equal(pure_wallet.getgoldrushinfo()["wallet_recent_solve_qualified"], False)


if __name__ == "__main__":
    GoldRushPosUnrestrictedTest().main()
