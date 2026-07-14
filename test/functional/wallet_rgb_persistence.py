#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet persistence for RGB metadata and EUTXO fail-closed policy."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletRGBPersistenceTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _assert_wallet_state(self, node, contract_id, assignment_txid):
        assets = node.listrgbassets()
        assert_equal(len(assets), 1)
        assert_equal(assets[0]["contract_id"], contract_id)
        assert_equal(assets[0]["ticker"], "QQT")
        assert_equal(assets[0]["name"], "Blackcoin Test Asset")
        assert_equal(assets[0]["total_supply"], 1000)
        assert_equal(assets[0]["balance"], 1000)
        assert_equal(assets[0]["proof_available"], False)
        assert_equal(assets[0]["proof_transition_count"], 0)
        assert_equal(len(assets[0]["assignments"]), 1)
        assert_equal(assets[0]["assignments"][0]["txid"], assignment_txid)
        assert_equal(assets[0]["assignments"][0]["vout"], 0)
        assert_equal(assets[0]["assignments"][0]["amount"], 1000)
        assert_equal(assets[0]["assignments"][0]["spent"], False)

        assert_equal(node.listeutxostates(), [])

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Importing RGB contract and owned assignment metadata")
        contract_id = "11" * 32
        assignment_txid = "22" * 32
        imported_contract = node.importrgbcontract({
            "contract_id": contract_id,
            "ticker": "QQT",
            "name": "Blackcoin Test Asset",
            "total_supply": 1000,
            "timestamp": 123,
        })
        assert_equal(imported_contract["contract_id"], contract_id)

        imported_assignment = node.importrgbassignment({
            "contract_id": contract_id,
            "txid": assignment_txid,
            "vout": 0,
            "amount": 1000,
            "timestamp": 124,
        })
        assert_equal(imported_assignment["contract_id"], contract_id)
        assert_equal(imported_assignment["txid"], assignment_txid)
        assert_raises_rpc_error(
            -4,
            "RGB proof graph is not available",
            node.exportrgbconsignment,
            contract_id,
        )

        self.log.info("Rejecting inconsistent RGB import metadata")
        assert_raises_rpc_error(
            -4,
            "Failed to import RGB contract metadata",
            node.importrgbcontract,
            {
                "contract_id": contract_id,
                "ticker": "BAD",
                "name": "Blackcoin Test Asset",
                "total_supply": 1000,
            },
        )
        assert_raises_rpc_error(
            -4,
            "Failed to import RGB assignment",
            node.importrgbassignment,
            {
                "contract_id": "33" * 32,
                "txid": assignment_txid,
                "vout": 1,
                "amount": 1000,
            },
        )

        self.log.info("Rejecting EUTXO v15 construction without quantum ownership authorization")
        assert_raises_rpc_error(
            -8,
            "EUTXO v15 is disabled in v30.1.1 because it has no quantum ownership authorization",
            node.createrawtransaction,
            [],
            [{"eutxo": {"amount": 1, "datum": "01", "validator": "52885187"}}],
        )
        self._assert_wallet_state(node, contract_id, assignment_txid)

        self.log.info("Restarting node and verifying RGB wallet metadata reload")
        self.restart_node(0, extra_args=self.extra_args[0])
        node = self.nodes[0]
        self._assert_wallet_state(node, contract_id, assignment_txid)


if __name__ == "__main__":
    WalletRGBPersistenceTest().main()
