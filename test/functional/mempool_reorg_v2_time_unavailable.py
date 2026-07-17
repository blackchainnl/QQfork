#!/usr/bin/env python3
# Copyright (c) 2026 Blackcoin Core Developers
# Copyright (c) 2026 Blackcoin More Developers
# Copyright (c) 2026 Quantum Quasar Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.
"""Recheck v2 mempool entries safely when no next header time exists.

An adjusted clock more than the regtest future-drift allowance behind tip MTP
must not evict an otherwise valid, already-admitted v2 transaction during
reorg cleanup. Independent validity still applies: a coinbase spend made
immature by the same reorg must be removed, and new v2 admission must remain
closed until a real next-block header time is available.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_raises_rpc_error,
)
from test_framework.wallet import MiniWallet


FUTURE_DRIFT = 24 * 60 * 60


class MempoolReorgV2TimeUnavailableTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    @staticmethod
    def _coinbase_txid(node, block_hash):
        return node.getblock(block_hash)["tx"][0]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.log.info("Create a coinbase that is mature only for the current next block")
        maturity_blocks = wallet.generate(COINBASE_MATURITY)
        just_mature_utxo = wallet.get_utxo(
            txid=self._coinbase_txid(node, maturity_blocks[0]))
        assert_equal(just_mature_utxo["confirmations"], COINBASE_MATURITY)

        stable_utxo = wallet.get_utxo(
            txid=self._coinbase_txid(node, node.getblockhash(76)))
        blocked_utxo = wallet.get_utxo(
            txid=self._coinbase_txid(node, node.getblockhash(77)))

        stable_spend = wallet.create_self_transfer(utxo_to_spend=stable_utxo)
        just_mature_spend = wallet.create_self_transfer(
            utxo_to_spend=just_mature_utxo)
        blocked_spend = wallet.create_self_transfer(utxo_to_spend=blocked_utxo)
        assert_equal(stable_spend["tx"].nVersion, 2)
        assert_equal(just_mature_spend["tx"].nVersion, 2)
        assert_equal(blocked_spend["tx"].nVersion, 2)

        stable_txid = node.sendrawtransaction(stable_spend["hex"])
        immature_txid = node.sendrawtransaction(just_mature_spend["hex"])
        assert_equal(set(node.getrawmempool()), {stable_txid, immature_txid})

        tip_hash = node.getbestblockhash()
        parent_hash = node.getblockheader(tip_hash)["previousblockhash"]
        parent_mtp = node.getblockheader(parent_hash)["mediantime"]
        node.setmocktime(parent_mtp - FUTURE_DRIFT)

        self.log.info("Prove the local clock leaves no legal next-block header")
        assert_raises_rpc_error(
            -32603,
            "No legal next-block header time is currently available",
            node.getblocktemplate,
            {"rules": ["segwit"]},
        )

        self.log.info("Invoke actual reorg cleanup while no candidate header exists")
        node.invalidateblock(tip_hash)
        assert_equal(node.getbestblockhash(), parent_hash)

        # The stable spend still passes input existence, value, maturity,
        # lifecycle, and script checks. The exact-boundary coinbase spend no
        # longer passes maturity after the one-block disconnect.
        assert_equal(node.getrawmempool(), [stable_txid])

        self.log.info("Keep new v2 admission closed without a real header time")
        blocked_policy = node.testmempoolaccept([blocked_spend["hex"]])[0]
        assert_equal(blocked_policy["allowed"], False)
        assert_equal(blocked_policy["reject-reason"],
                     "next-block-time-unavailable")


if __name__ == "__main__":
    MempoolReorgV2TimeUnavailableTest().main()
