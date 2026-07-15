#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test safe getblocktemplate refresh across a candidate-header time change.

A version-2 transaction receives the candidate block header's time when it is
connected. A version-1 child serializes its own time. Therefore, a cached
template containing a v2 parent and an equally timed v1 child cannot simply
advance its header time: the child would then precede its input. The daemon
must rebuild its package at the newer candidate time, and it must not advertise
that time is externally mutable while the mixed-version dependency remains.
"""

from test_framework.blocktools import COINBASE_MATURITY, NORMAL_GBT_REQUEST_PARAMS
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet, MiniWalletMode


class GetBlockTemplateCachedTimeTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    @staticmethod
    def template_txids(template):
        return {entry["txid"] for entry in template["transactions"]}

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node, mode=MiniWalletMode.RAW_P2PK)

        self.log.info("Create a mature v2 parent source on the regtest candidate chain")
        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 1)
        self.generate(wallet, COINBASE_MATURITY + 1)

        node.setmocktime(node.getblockheader(node.getbestblockhash())["time"] + 16)
        parent = wallet.create_self_transfer(confirmed_only=True)
        assert_equal(parent["tx"].nVersion, 2)
        parent_txid = wallet.sendrawtransaction(from_node=node, tx_hex=parent["hex"])

        self.log.info("Cache a v2-only template, where time remains externally mutable")
        parent_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert parent_txid in self.template_txids(parent_template)
        assert "time" in parent_template["mutable"]

        # Move mock time beyond the ordinary five-second mempool-template
        # throttle before admitting the child. The following GBT call will
        # build a package at this exact candidate header time.
        package_time = parent_template["curtime"] + 6
        node.setmocktime(package_time)
        child = wallet.create_self_transfer(utxo_to_spend=parent["new_utxo"])["tx"]
        child.nVersion = 1
        child.nTime = package_time
        wallet.sign_tx(child)
        child_txid = node.sendrawtransaction(child.serialize().hex(), maxfeerate=0)

        self.log.info("Select the valid v2-parent/v1-child package at its original header time")
        cached_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        assert_equal(cached_template["curtime"], package_time)
        assert {parent_txid, child_txid}.issubset(self.template_txids(cached_template))
        assert "time" not in cached_template["mutable"]
        assert "transactions" in cached_template["mutable"]
        assert "prevblock" in cached_template["mutable"]

        self.log.info("Advance only candidate time: GBT must rebuild, not mutate the cached package")
        node.setmocktime(package_time + 1)
        refreshed_template = node.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        refreshed_txids = self.template_txids(refreshed_template)
        assert_equal(refreshed_template["curtime"], package_time + 1)
        assert parent_txid in refreshed_txids
        assert child_txid not in refreshed_txids
        # With the dependent v1 child absent, time becomes safe to advertise
        # again for the remaining v2-only template.
        assert "time" in refreshed_template["mutable"]
        assert_equal(set(node.getrawmempool()), {parent_txid, child_txid})


if __name__ == "__main__":
    GetBlockTemplateCachedTimeTest().main()
