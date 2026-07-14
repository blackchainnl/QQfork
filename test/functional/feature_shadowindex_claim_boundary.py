#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise shadowindex across the historical/canonical QQSPROOF boundary.

Mainnet paid the v30.1.0 first-valid QQSPROOF rule before height 5,993,200.
Those authenticated payouts must remain indexable without inventing canonical
claim provenance.  From the activation height onward, every credited PoW
payout must retain its exact canonical source record.  This test compresses
that boundary on regtest and verifies both sides across restart, reorg, and a
full reindex.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


CLAIM_ACTIVATION_HEIGHT = 40


class ShadowIndexClaimBoundaryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.node_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-shadowindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=20",
            "-shadowgoldrushblocks=100",
            f"-shadowcompetingclaimsheight={CLAIM_ACTIVATION_HEIGHT}",
        ]
        self.extra_args = [self.node_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(
            self.nodes[0].getbestblockhash()
        )["time"]
        self._set_mocktime((tip_time & ~0xF) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9_999_999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(1000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block_with_claim(self, wallet, claim_txid):
        node = self.nodes[0]
        last_error = None
        for _ in range(4):
            start_height = node.getblockcount()
            kernel_time = self._find_next_kernel_time(wallet)
            self._set_mocktime(kernel_time - 16)
            wallet.staking(True)
            try:
                self._set_mocktime(kernel_time)
                self.wait_until(
                    lambda: node.getblockcount() > start_height, timeout=20
                )
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:]
                return block_hash
            except AssertionError as error:
                last_error = error
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _wait_index_synced(self):
        node = self.nodes[0]

        def synced_to_tip():
            status = node.getindexinfo().get("shadowindex", {})
            return (
                status.get("synced", False)
                and status.get("best_block_height", node.getblockcount())
                == node.getblockcount()
            )

        self.wait_until(synced_to_tip, timeout=60)

    def _wait_for_quantum_utxo(self, wallet, address):
        def outputs():
            return wallet.listunspent(
                0,
                9_999_999,
                [address],
                True,
                {"include_immature_coinbase": True},
            )

        self.wait_until(lambda: len(outputs()) == 1, timeout=30)
        return outputs()[0]

    def _assert_historical_payout(self, block_hash, claim_txid, payout_txid):
        node = self.nodes[0]
        page = node.getshadowblock(block_hash, 0, 10, 0, 10)
        assert_equal(page["total_payouts"], 1)
        assert_equal(page["payouts"][0]["synthetic_txid"], payout_txid)
        assert_equal(page["observed_pow_claim_txids"], [claim_txid])
        assert Decimal(str(page["pow_payout_total"])) > 0
        accounting = page["pow_claim_accounting"]
        assert_equal(accounting["active"], False)
        assert_equal(accounting["total_records"], 0)
        assert_equal(accounting["observed_count"], 0)
        assert_equal(accounting["evaluated_count"], 0)
        assert_equal(accounting["winner_count"], 0)
        assert_equal(accounting["reimbursed_loser_count"], 0)
        assert_equal(accounting["rejected_count"], 0)
        assert_equal(accounting["credited_total"], Decimal("0.00000000"))
        assert_equal(accounting["accounting_commitment"], None)
        assert_equal(accounting["records"], [])
        assert_equal(accounting["next_offset"], None)

        payout = node.getshadowtransaction(payout_txid)
        assert_equal(payout["mode"], "pow")
        assert_equal(payout["base_anchor"]["blockhash"], block_hash)
        assert_equal(payout["pow_claim_source"], None)

    def _assert_canonical_payout(self, block_hash, claim_txid, payout_txid):
        node = self.nodes[0]
        page = node.getshadowblock(block_hash, 0, 10, 0, 10)
        accounting = page["pow_claim_accounting"]
        assert_equal(accounting["active"], True)
        assert_equal(accounting["total_records"], 1)
        assert_equal(accounting["observed_count"], 1)
        assert_equal(accounting["evaluated_count"], 1)
        assert_equal(accounting["winner_count"], 1)
        assert_equal(accounting["reimbursed_loser_count"], 0)
        assert_equal(accounting["rejected_count"], 0)
        assert len(accounting["accounting_commitment"]) == 64
        assert_equal(accounting["records"][0]["txid"], claim_txid)
        assert_equal(accounting["records"][0]["disposition"], "winner")
        assert_equal(accounting["records"][0]["synthetic_txid"], payout_txid)
        assert_equal(
            Decimal(str(accounting["credited_total"])),
            Decimal(str(page["pow_payout_total"])),
        )

        payout = node.getshadowtransaction(payout_txid)
        assert_equal(payout["mode"], "pow")
        assert_equal(payout["base_anchor"]["blockhash"], block_hash)
        assert_equal(payout["pow_claim_source"]["txid"], claim_txid)
        assert_equal(payout["pow_claim_source"]["disposition"], "winner")
        return page

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xF) + 16)
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name="claim_boundary", load_on_startup=True)
        wallet = node.get_wallet_rpc("claim_boundary")
        wallet.staking(False)

        staking_address = wallet.getnewaddress("stake", "legacy")
        historical_claim_address = wallet.getnewaddress("historical", "legacy")
        canonical_claim_address = wallet.getnewaddress("canonical", "legacy")

        self.generatetoaddress(node, 1, staking_address)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address)
        self.generatetoaddress(
            node, COINBASE_MATURITY + 2, historical_claim_address
        )
        self._sync_mocktime_to_tip()
        self._wait_index_synced()
        info = node.getgoldrushstate()
        assert_equal(
            info["competing_claim_rule_activation_height"],
            CLAIM_ACTIVATION_HEIGHT,
        )
        assert_equal(info["competing_claim_rule_active_next_block"], False)

        self.log.info("Indexing a paid preactivation QQSPROOF without invented provenance")
        historical_payout_address = wallet.getnewquantumaddress()["address"]
        historical_claim = wallet.sendshadowpowclaim(
            historical_claim_address, historical_payout_address, 500_000
        )
        historical_block = self._mine_pos_block_with_claim(
            wallet, historical_claim["txid"]
        )
        historical_height = node.getblockcount()
        assert historical_height < CLAIM_ACTIVATION_HEIGHT
        self._wait_index_synced()
        historical_utxo = self._wait_for_quantum_utxo(
            wallet, historical_payout_address
        )
        self._assert_historical_payout(
            historical_block, historical_claim["txid"], historical_utxo["txid"]
        )
        assert_equal(node.getshadowsupply()["issued_count"], 1)

        self.log.info("Rewinding and reconnecting the historical payout preserves null provenance")
        historical_parent = node.getblockheader(historical_block)["previousblockhash"]
        node.invalidateblock(historical_block)
        node.syncwithvalidationinterfacequeue()
        self._wait_index_synced()
        assert_equal(node.getbestblockhash(), historical_parent)
        assert_raises_rpc_error(
            -5,
            "not found",
            node.getshadowtransaction,
            historical_utxo["txid"],
        )
        node.reconsiderblock(historical_block)
        node.syncwithvalidationinterfacequeue()
        self._wait_index_synced()
        assert_equal(node.getbestblockhash(), historical_block)
        self._assert_historical_payout(
            historical_block, historical_claim["txid"], historical_utxo["txid"]
        )

        self.log.info("Crossing the boundary and requiring canonical source provenance")
        blocks_to_activation_parent = CLAIM_ACTIVATION_HEIGHT - 1 - node.getblockcount()
        assert blocks_to_activation_parent >= COINBASE_MATURITY
        self.generatetoaddress(
            node, blocks_to_activation_parent, canonical_claim_address
        )
        self._sync_mocktime_to_tip()
        self._wait_index_synced()
        assert_equal(node.getblockcount(), CLAIM_ACTIVATION_HEIGHT - 1)
        assert_equal(
            node.getgoldrushstate()["competing_claim_rule_active_next_block"],
            True,
        )

        canonical_payout_address = wallet.getnewquantumaddress()["address"]
        canonical_claim = wallet.sendshadowpowclaim(
            canonical_claim_address, canonical_payout_address, 500_000
        )
        canonical_block = self._mine_pos_block_with_claim(
            wallet, canonical_claim["txid"]
        )
        assert_equal(node.getblockcount(), CLAIM_ACTIVATION_HEIGHT)
        self._wait_index_synced()
        canonical_utxo = self._wait_for_quantum_utxo(wallet, canonical_payout_address)
        canonical_page = self._assert_canonical_payout(
            canonical_block, canonical_claim["txid"], canonical_utxo["txid"]
        )
        expected_issued_count = 1 + canonical_page["total_payouts"]
        assert_equal(node.getshadowsupply()["issued_count"], expected_issued_count)

        self.log.info("Restart and full reindex reproduce both sides of the boundary")
        for restart_args in (
            self.node_args,
            self.node_args + ["-reindex"],
        ):
            self.restart_node(
                0, extra_args=restart_args + [f"-mocktime={self.mock_time}"]
            )
            node.setmocktime(self.mock_time)
            self._wait_index_synced()
            self._assert_historical_payout(
                historical_block,
                historical_claim["txid"],
                historical_utxo["txid"],
            )
            self._assert_canonical_payout(
                canonical_block, canonical_claim["txid"], canonical_utxo["txid"]
            )
            assert_equal(
                node.getshadowsupply()["issued_count"], expected_issued_count
            )


if __name__ == "__main__":
    ShadowIndexClaimBoundaryTest().main()
