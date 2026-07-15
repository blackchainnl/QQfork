#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Core Developers
# Copyright (c) 2026 Blackcoin More Developers
# Copyright (c) 2026 Quantum Quasar Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Exercise canonical next-block time selection for v2 transactions and PoS.

A v2 transaction has no serialized nTime. A v1 mempool parent can therefore
have an output timestamp later than the old floor-to-mask PoS template time.
The child must be accepted by next-block policy and then selected and mined by
the aligned PoS template at the same candidate timestamp.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import tx_from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


FEE = Decimal("0.01")
WALLET_NAME = "pos_v2_template_time"


class WalletPoSV2TemplateTimeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-autostartstaking=0",
            "-staketimio=50",
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

    def _find_next_kernel_time(self, wallet, inputs=None):
        if inputs is None:
            inputs = self._staking_inputs(wallet)
        assert inputs, "funded wallet must have mature staking inputs"
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    @staticmethod
    def _spendable_utxo(wallet):
        return next(utxo for utxo in wallet.listunspent(1, 9999999)
                    if utxo["confirmations"] > 1)

    def _signed_raw_spend(self, wallet, source, destination, amount):
        raw = self.nodes[0].createrawtransaction(
            [{"txid": source["txid"], "vout": source["vout"]}],
            [{destination: amount}],
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        return signed["hex"]

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        node.get_wallet_rpc(self.default_wallet_name).staking(False)

        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)
        stake_address = wallet.getnewaddress("stake", "legacy")

        self.log.info("Creating multiple mature legacy inputs for staking and a v1 parent")
        self.generatetoaddress(node, COINBASE_MATURITY + 3, stake_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()

        self.log.info("Finding an aligned kernel and admitting a v1-parent/v2-child package one second before it")
        kernel_time = self._find_next_kernel_time(wallet)

        # A successful checkkernel template must use the exact kernel it
        # reports. In particular, it must not substitute a different wallet
        # UTXO after the caller has decided which proof to sign.
        kernel_template = wallet.checkkernel(self._staking_inputs(wallet), True)
        assert_equal(kernel_template["found"], True)
        assert_equal(kernel_template["kernel"]["time"], kernel_time)
        assert "blocktemplate" in kernel_template
        assert "blocktemplatefees" in kernel_template
        assert "blocktemplatesignkey" in kernel_template

        source = self._spendable_utxo(wallet)
        # Constructing a template records that interval as searched, which is
        # correct for a caller that will sign and submit it. Advance to a fresh
        # aligned interval before asking the automatic staker to produce a
        # block in the independent package-selection portion of this test.
        # Exclude the package's funding input from the kernel search: spending
        # the exact UTXO selected by checkkernel would make the advertised
        # kernel unavailable before the automatic staker can use it.
        kernel_inputs = [
            entry for entry in self._staking_inputs(wallet)
            if (entry["txid"], entry["vout"]) !=
            (source["txid"], source["vout"])
        ]
        kernel_time = self._find_next_kernel_time(wallet, kernel_inputs)
        self._set_mocktime(kernel_time - 1)

        parent_destination = wallet.getnewaddress("v1-parent", "legacy")
        parent_amount = Decimal(str(source["amount"])) - FEE
        parent_raw = node.createrawtransaction(
            [{"txid": source["txid"], "vout": source["vout"]}],
            [{parent_destination: parent_amount}],
        )
        parent = tx_from_hex(parent_raw)
        parent.nVersion = 1
        parent.nTime = kernel_time - 1
        parent_signed = wallet.signrawtransactionwithwallet(parent.serialize().hex())
        assert_equal(parent_signed["complete"], True)
        parent_tx = tx_from_hex(parent_signed["hex"])
        assert_equal(parent_tx.nVersion, 1)
        assert_equal(parent_tx.nTime, kernel_time - 1)
        parent_txid = node.sendrawtransaction(parent_signed["hex"])

        child_destination = wallet.getnewaddress("v2-child", "legacy")
        child_hex = self._signed_raw_spend(
            wallet,
            {"txid": parent_txid, "vout": 0},
            child_destination,
            parent_amount - FEE,
        )
        child_tx = tx_from_hex(child_hex)
        assert_equal(child_tx.nVersion, 2)
        child_policy = node.testmempoolaccept([child_hex])[0]
        assert_equal(child_policy["allowed"], True)
        child_txid = node.sendrawtransaction(child_hex)
        assert_equal(set(node.getrawmempool()), {parent_txid, child_txid})

        self.log.info("The aligned PoS template must select and mine the policy-accepted v2 child")
        start_height = node.getblockcount()
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            # At K-1 the old floor-to-mask template used K-16 and omitted the
            # package. The canonical ceiling-aligned template uses K.
            self._set_mocktime(kernel_time - 1)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
        finally:
            wallet.staking(False)

        block = node.getblock(node.getbestblockhash(), 2)
        assert "proof-of-stake" in block["flags"]
        assert_equal(block["time"], kernel_time)
        txids = [tx["txid"] for tx in block["tx"]]
        assert parent_txid in txids[2:]
        assert child_txid in txids[2:]

        self.log.info("Keep a v2-parent/older-v1-child package out of an aligned PoS block")
        self._sync_mocktime_to_tip()
        second_source = self._spendable_utxo(wallet)
        second_kernel_inputs = [
            entry for entry in self._staking_inputs(wallet)
            if (entry["txid"], entry["vout"]) !=
            (second_source["txid"], second_source["vout"])
        ]
        second_kernel_time = self._find_next_kernel_time(wallet,
                                                          second_kernel_inputs)
        self._set_mocktime(second_kernel_time - 1)

        v2_parent_destination = wallet.getnewaddress("v2-parent", "legacy")
        v2_parent_amount = Decimal(str(second_source["amount"])) - FEE
        v2_parent_hex = self._signed_raw_spend(
            wallet,
            second_source,
            v2_parent_destination,
            v2_parent_amount,
        )
        v2_parent = tx_from_hex(v2_parent_hex)
        assert_equal(v2_parent.nVersion, 2)
        v2_parent_txid = node.sendrawtransaction(v2_parent_hex)

        v1_child_destination = wallet.getnewaddress("v1-child", "legacy")
        v1_child_raw = node.createrawtransaction(
            [{"txid": v2_parent_txid, "vout": 0}],
            [{v1_child_destination: v2_parent_amount - FEE}],
        )
        v1_child = tx_from_hex(v1_child_raw)
        v1_child.nVersion = 1
        v1_child.nTime = second_kernel_time - 1
        v1_child_signed = wallet.signrawtransactionwithwallet(
            v1_child.serialize().hex())
        assert_equal(v1_child_signed["complete"], True)
        v1_child_txid = node.sendrawtransaction(v1_child_signed["hex"])

        # The generic next-header template at K-1 can include both: its v2
        # parent receives K-1 and the legacy child also serializes K-1.
        # This is a template-policy candidate, not a statement about current
        # mainnet base-block PoW production.
        generic_template = node.getblocktemplate({"rules": ["segwit"]})
        generic_txids = {entry["txid"] for entry in generic_template["transactions"]}
        assert v2_parent_txid in generic_txids
        assert v1_child_txid in generic_txids

        # At aligned K the v2 parent acquires K, while the legacy child remains
        # K-1. The actual PoS template must reject that package without a
        # throw or invalid block selection; it may include the parent alone.
        second_start_height = node.getblockcount()
        wallet.staking(True)
        try:
            self._set_mocktime(second_kernel_time)
            self.wait_until(lambda: node.getblockcount() > second_start_height,
                            timeout=20)
        finally:
            wallet.staking(False)

        second_block = node.getblock(node.getbestblockhash(), 2)
        assert "proof-of-stake" in second_block["flags"]
        assert_equal(second_block["time"], second_kernel_time)
        second_block_txids = [tx["txid"] for tx in second_block["tx"]]
        assert v1_child_txid not in second_block_txids

        self.log.info("Reject a v2 spend when MTP leaves no legal aligned PoS header time")
        mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        # Regtest's pre-PoS future-drift allowance is 24 hours. Set adjusted
        # time exactly one allowance behind MTP, so MTP+1 cannot be a legal
        # header time even before the additional ceiling-to-mask step.
        self._set_mocktime(mtp - 24 * 60 * 60)
        unavailable_kernel = wallet.checkkernel(self._staking_inputs(wallet))
        assert_equal(unavailable_kernel["found"], False)
        assert "kernel" not in unavailable_kernel
        blocked_source = self._spendable_utxo(wallet)
        blocked_hex = self._signed_raw_spend(
            wallet,
            blocked_source,
            wallet.getnewaddress("unavailable", "legacy"),
            Decimal(str(blocked_source["amount"])) - FEE,
        )
        blocked_policy = node.testmempoolaccept([blocked_hex])[0]
        assert_equal(blocked_policy["allowed"], False)
        assert_equal(blocked_policy["reject-reason"], "next-block-time-unavailable")


if __name__ == "__main__":
    WalletPoSV2TemplateTimeTest().main()
