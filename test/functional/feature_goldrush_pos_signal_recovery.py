#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise terminal QQSIGNAL cleanup at the Gold Rush boundary.

An unconfirmed wallet signal can be absent from the mempool after restart or
eviction. Once Gold Rush ends it is terminally invalid and must be abandoned so
its otherwise-live legacy input becomes spendable again.
"""

import time
from threading import Thread

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy


GOLD_RUSH_END_TIME = 2_000_000_000
WALLET_NAME = "goldrush_signal_recovery"


class GoldRushPosSignalRecoveryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-staketimio=25",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=300",
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
    def _staking_inputs(wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block(self, wallet):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
        finally:
            wallet.staking(False)
        block_hash = node.getbestblockhash()
        assert "proof-of-stake" in node.getblock(block_hash)["flags"]
        return block_hash

    @staticmethod
    def _is_abandoned(wallet, txid):
        return any(detail.get("abandoned", False) for detail in wallet.gettransaction(txid)["details"])

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        node.get_wallet_rpc(self.default_wallet_name).staking(False)

        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)
        signal_address = wallet.getnewaddress("signal-target", "legacy")
        funding_address = node.get_wallet_rpc(self.default_wallet_name).getnewaddress("funding", "legacy")

        self.log.info("Creating a whitelisted target with more than one mature legacy input")
        self.generatetoaddress(node, 2, signal_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 8, funding_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Solving one PoS block and publishing a signal that remains unconfirmed")
        solve_hash = self._mine_pos_block(wallet)
        solve_height = node.getblock(solve_hash)["height"]
        payout_address = wallet.getnewquantumaddress("stale-pos-payout")["address"]
        first_signal = wallet.sendshadowsignal(signal_address, solve_height, solve_hash, payout_address)
        decoded = node.decoderawtransaction(first_signal["hex"])
        signal_input = decoded["vin"][0]
        signal_outpoint = {"txid": signal_input["txid"], "vout": signal_input["vout"]}
        assert first_signal["txid"] in node.getrawmempool()

        self.log.info("A valid non-broadcast signal releases its input only after the bounded retry ceiling")
        restart_args = self.extra_args[0] + [
            "-persistmempool=0",
            "-walletbroadcast=0",
            "-autostartstaking=0",
            "-qqshadowsignalmaxretryfailures=2",
            "-qqshadowsignalretrybasemillis=2000",
            f"-mocktime={self.mock_time}",
        ]
        self.restart_node(0, restart_args)
        node = self.nodes[0]
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        assert first_signal["txid"] not in node.getrawmempool()
        assert node.gettxout(signal_outpoint["txid"], signal_outpoint["vout"], False) is not None
        assert_equal(self._is_abandoned(wallet, first_signal["txid"]), False)

        with node.assert_debug_log(
            expected_msgs=["retry in 2000ms after valid pending signal could not be resubmitted"],
            timeout=10,
        ):
            wallet.staking(True)
        assert_equal(self._is_abandoned(wallet, first_signal["txid"]), False)
        with node.assert_debug_log(
            expected_msgs=["after 2 failed resubmissions and released its inputs"],
            timeout=10,
        ):
            self.wait_until(lambda: self._is_abandoned(wallet, first_signal["txid"]), timeout=10)
        wallet.staking(False)
        assert any(
            utxo["txid"] == signal_outpoint["txid"] and utxo["vout"] == signal_outpoint["vout"]
            for utxo in wallet.listunspent(1, 9999999)
        ), "retry-exhausted QQSIGNAL must release its legacy input"

        self.log.info("Creating a second pending signal for the peer-relay/cleanup race regression")
        self.restart_node(0, self.extra_args[0] + ["-persistmempool=0", "-autostartstaking=0", f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        second_payout_address = wallet.getnewquantumaddress("stale-pos-payout-race")["address"]
        second_signal = wallet.sendshadowsignal(signal_address, solve_height, solve_hash, second_payout_address)
        second_decoded = node.decoderawtransaction(second_signal["hex"])
        second_input = second_decoded["vin"][0]
        second_outpoint = {"txid": second_input["txid"], "vout": second_input["vout"]}
        assert second_signal["txid"] in node.getrawmempool()

        self.log.info("A peer insertion at the cleanup barrier prevents abandonment of the now-live transaction")
        race_args = self.extra_args[0] + [
            "-persistmempool=0",
            "-walletbroadcast=0",
            "-autostartstaking=0",
            "-qqshadowsignalmaxretryfailures=1",
            "-qqshadowsignalretrybasemillis=10",
            "-qqshadowsignalcleanupdelaymillis=2000",
            f"-mocktime={self.mock_time}",
        ]
        self.restart_node(0, race_args)
        node = self.nodes[0]
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        assert second_signal["txid"] not in node.getrawmempool()
        barrier_offset = node.debug_log_size(encoding="utf-8")
        race_errors = []

        def relay_at_cleanup_barrier():
            deadline = time.time() + 10
            while time.time() < deadline:
                with open(node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
                    debug_log.seek(barrier_offset)
                    if "cleanup race barrier reached" in debug_log.read():
                        break
                time.sleep(0.01)
            else:
                race_errors.append("cleanup race barrier was not reached")
                return
            try:
                rpc = get_rpc_proxy(node.url, 91, timeout=10, coveragedir=node.coverage_dir)
                rpc.sendrawtransaction(second_signal["hex"])
            except Exception as error:
                race_errors.append(str(error))

        relay_thread = Thread(target=relay_at_cleanup_barrier, name="qqsignal-cleanup-race", daemon=True)
        relay_thread.start()
        wallet.staking(True)
        relay_thread.join(timeout=15)
        assert not relay_thread.is_alive(), "peer relay did not complete at the cleanup barrier"
        assert_equal(race_errors, [])
        self.wait_until(lambda: second_signal["txid"] in node.getrawmempool(), timeout=10)
        assert_equal(self._is_abandoned(wallet, second_signal["txid"]), False)
        wallet.staking(False)

        self.log.info("Advancing past Gold Rush makes the old QQSIGNAL terminal and releases its input")
        # Drop the peer-relayed transaction and preserve only its inactive
        # wallet record, then cross the phase boundary.
        self.restart_node(0, self.extra_args[0] + [
            "-persistmempool=0",
            "-walletbroadcast=0",
            "-autostartstaking=0",
            "-minstakingamount=1000000",
            f"-mocktime={self.mock_time}",
        ])
        node = self.nodes[0]
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        assert second_signal["txid"] not in node.getrawmempool()
        assert_equal(self._is_abandoned(wallet, second_signal["txid"]), False)
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        generated = 0
        while node.getquantumquasarinfo()["phase"] == "gold_rush":
            self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            generated += 1
            assert generated < 400
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")

        wallet.staking(True)
        try:
            self.wait_until(lambda: self._is_abandoned(wallet, second_signal["txid"]), timeout=15)
        finally:
            wallet.staking(False)

        assert_equal(self._is_abandoned(wallet, second_signal["txid"]), True)
        assert second_signal["txid"] not in node.getrawmempool()
        spendable = wallet.listunspent(1, 9999999)
        assert any(
            utxo["txid"] == second_outpoint["txid"] and utxo["vout"] == second_outpoint["vout"]
            for utxo in spendable
        ), "terminal QQSIGNAL must not keep its legacy input reserved"


if __name__ == "__main__":
    GoldRushPosSignalRecoveryTest().main()
