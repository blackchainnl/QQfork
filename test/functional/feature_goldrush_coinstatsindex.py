#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check Gold Rush payouts against coinstatsindex and the explorer index.

Gold Rush reward credits are synthetic quantum UTXOs created by upgraded nodes
after connecting otherwise legacy-compatible PoS blocks. This test verifies that
two upgraded nodes converge on the same UTXO commitment and that a node running
coinstatsindex plus shadowindex reports the same state across apply, spend,
restart, rebuild, and reorg. The block-page loop is a reference explorer
ingestion flow: enumerate active-chain anchors, follow next_offset, and
reconcile every observed credit against getshadowsupply.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
QUANTUM_SPEND_FEE = Decimal("0.01")
STATS_KEYS = ["height", "bestblock", "txouts", "bogosize", "muhash", "total_amount"]
ZERO_AMOUNT = Decimal("0E-8")


class GoldRushCoinStatsIndexTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=20",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]
        self.extra_args = [
            common_args,
            common_args + ["-coinstatsindex", "-shadowindex=1"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        for node in self.nodes:
            node.setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        )
        self._set_mocktime((tip_time & ~0xf) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(300):
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
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:], "QQSPROOF claim must be a fee-paying transaction"
                # Node 0 validates the in-memory block object produced by its
                # wallet. Node 1 validates the network-serialized copy, where
                # version-2 transaction nTime is absent. Both must derive the
                # stake input time from the source block and accept the exact
                # same PoS block.
                self.sync_blocks()
                assert_equal(self.nodes[1].getbestblockhash(), block_hash)
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _wait_index_synced(self):
        index_node = self.nodes[1]

        def synced_to_tip():
            indexes = index_node.getindexinfo()
            return all(
                indexes[name]["synced"]
                and indexes[name].get("best_block_height", index_node.getblockcount()) == index_node.getblockcount()
                for name in ("coinstatsindex", "shadowindex")
            )

        self.wait_until(synced_to_tip, timeout=60)

    def _stats_fingerprint(self, stats):
        return {key: stats[key] for key in STATS_KEYS}

    def _live_stats(self, node):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=None, use_index=False))

    def _indexed_stats(self, node):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=None, use_index=True))

    def _indexed_stats_at(self, node, block_hash_or_height):
        return self._stats_fingerprint(node.gettxoutsetinfo(hash_type="muhash", hash_or_height=block_hash_or_height, use_index=True))

    def _indexed_full_stats_at(self, node, block_hash_or_height):
        return node.gettxoutsetinfo(hash_type="muhash", hash_or_height=block_hash_or_height, use_index=True)

    def _amount(self, value):
        return Decimal(str(value))

    def _ingest_shadow_reward_window(self):
        """Reference explorer loop with bounded pages and supply reconciliation."""
        node = self.nodes[1]
        observed = []
        last_reward_height = min(node.getblockcount(), 29)
        for height in range(20, last_reward_height + 1):
            offset = 0
            while True:
                page = node.getshadowblock(height, offset, 2)
                assert_equal(page["schema"], "blackcoin.shadow.block.v2")
                assert_equal(page["synthetic"], True)
                assert_equal(page["merkle_included"], False)
                observed.extend(page["payouts"])
                if page["next_offset"] is None:
                    break
                offset = page["next_offset"]

        supply = node.getshadowsupply()
        assert_equal(supply["schema"], "blackcoin.shadow.supply.v1")
        assert_equal(len(observed), supply["issued_count"])
        assert_equal(
            sum((self._amount(item["nominal_amount"]) for item in observed), ZERO_AMOUNT),
            self._amount(supply["issued_nominal_amount"]),
        )
        return observed, supply

    def _assert_cross_node_live_stats_match(self):
        assert_equal(self._live_stats(self.nodes[0]), self._live_stats(self.nodes[1]))

    def _assert_index_matches_live(self):
        assert_equal(self._indexed_stats(self.nodes[1]), self._live_stats(self.nodes[1]))

    def _get_quantum_utxos(self, wallet, address):
        return wallet.listunspent(0, 9999999, [address], True, {"include_immature_coinbase": True})

    def _witness_inventory(self, view="utxos"):
        inventory = self.nodes[1].getquantumwitnessinventory(view, 0, 100, 1_000_000)
        assert_equal(inventory["schema"], "blackcoin.quantum.witness_inventory.v1")
        assert_equal(inventory["coverage"]["snapshot_current_utxos_exact"], True)
        assert_equal(inventory["coverage"]["history_snapshot_tip_covered"], True)
        assert_equal(inventory["coverage"]["history_scan_complete"], True)
        assert_equal(inventory["coverage"]["history_aggregates_exact"], True)
        assert_equal(inventory["coverage"]["history_reconciles_current_utxos"], True)
        return inventory

    def _wait_for_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address)[0]

    def _advance_to_migration_window(self):
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        for _ in range(12):
            self.generatetoaddress(self.nodes[0], 1, self.nodes[0].get_deterministic_priv_key().address)
            self._bump_mocktime(16)
        self._wait_index_synced()
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "migration")
        assert_equal(self.nodes[1].getquantumquasarinfo()["phase"], "migration")

    def _build_quantum_spend(self, wallet, utxo, destination):
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        assert spend_amount > 0
        raw = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        return self.nodes[0].signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )

    def run_test(self):
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Preparing a wallet with mature staking and QQSPROOF funding coins")
        for node in self.nodes:
            node.get_wallet_rpc(self.default_wallet_name).staking(False)
        self.nodes[0].createwallet(wallet_name="goldrush_coinstats")
        wallet = self.nodes[0].get_wallet_rpc("goldrush_coinstats")
        wallet.staking(False)
        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")

        self.generatetoaddress(self.nodes[0], 1, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, staking_address)
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, claim_address)
        self._sync_mocktime_to_tip()
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "gold_rush")
        self._wait_index_synced()
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()

        parent_hash = self.nodes[0].getbestblockhash()
        parent_height = self.nodes[0].getblockcount()
        parent_stats = self._live_stats(self.nodes[1])
        parent_indexed_full = self._indexed_full_stats_at(self.nodes[1], parent_hash)

        self.log.info("Mining a PoS block with a fee-paying QQSPROOF claim")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        assert claim["txid"] in self.nodes[0].getrawmempool()
        claim_block_hash = self._mine_pos_block_with_claim(wallet, claim["txid"])
        claim_block_height = self.nodes[0].getblockcount()
        self._wait_index_synced()

        self.log.info("Checking cross-node UTXO commitments include the synthetic quantum payout")
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert Decimal(str(payout_utxo["amount"])) > 0
        assert self.nodes[0].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        claim_stats = self._live_stats(self.nodes[1])
        claim_indexed_full = self._indexed_full_stats_at(self.nodes[1], claim_block_hash)
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()
        assert_equal(self._indexed_stats_at(self.nodes[1], parent_hash), parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], parent_height), parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], claim_block_hash), claim_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], claim_block_height), claim_stats)
        assert_equal(self._amount(claim_indexed_full["block_info"]["coinbase"]), self._amount(payout_utxo["amount"]))
        assert_equal(self._amount(claim_indexed_full["block_info"]["unspendable"]), ZERO_AMOUNT)
        assert_equal(self._amount(claim_indexed_full["block_info"]["unspendables"]["unclaimed_rewards"]), ZERO_AMOUNT)
        assert_equal(claim_indexed_full["total_unspendable_amount"], parent_indexed_full["total_unspendable_amount"])

        self.log.info("Enumerating explorer pages and reconciling indexed shadow supply")
        claim_shadow = self.nodes[1].getshadowblock(claim_block_hash, 0, 1, 0, 1)
        assert_equal(claim_shadow["total_payouts"], 1)
        assert_equal(claim_shadow["count"], 1)
        assert_equal(claim_shadow["payouts"][0]["synthetic_txid"], payout_utxo["txid"])
        assert_equal(claim_shadow["payouts"][0]["synthetic"], True)
        assert_equal(claim_shadow["payouts"][0]["merkle_included"], False)
        claim_accounting = claim_shadow["pow_claim_accounting"]
        assert_equal(claim_accounting["active"], True)
        assert_equal(claim_accounting["total_records"], 1)
        assert_equal(claim_accounting["winner_count"], 1)
        assert_equal(claim_accounting["reimbursed_loser_count"], 0)
        assert_equal(claim_accounting["rejected_count"], 0)
        assert_equal(claim_accounting["next_offset"], None)
        assert_equal(claim_accounting["records"][0]["txid"], claim["txid"])
        assert_equal(claim_accounting["records"][0]["disposition"], "winner")
        assert_equal(claim_accounting["records"][0]["synthetic_txid"], payout_utxo["txid"])
        assert_equal(
            self._amount(claim_accounting["credited_total"]),
            self._amount(claim_shadow["pow_payout_total"]),
        )
        payout_record = self.nodes[1].getshadowtransaction(payout_utxo["txid"])
        assert_equal(payout_record["schema"], "blackcoin.shadow.transaction.v1")
        assert_equal(payout_record["status"], "gold_rush_locked")
        assert_equal(payout_record["base_anchor"]["blockhash"], claim_block_hash)
        assert_equal(payout_record["pow_claim_source"]["txid"], claim["txid"])
        assert_equal(payout_record["pow_claim_source"]["disposition"], "winner")
        address_history = self.nodes[1].getshadowaddress(payout_address)
        assert_equal(address_history["schema"], "blackcoin.shadow.address.v1")
        assert_equal(address_history["address"], payout_address)
        assert_equal(address_history["count"], 1)
        assert_equal(address_history["records"][0]["synthetic_txid"], payout_utxo["txid"])
        payout_script = address_history["scriptPubKey"]
        script_history = self.nodes[1].getshadowscript(payout_script)
        assert_equal(script_history["schema"], "blackcoin.shadow.script.v1")
        assert_equal(script_history["scriptPubKey"], payout_script)
        assert_equal(script_history["address"], payout_address)
        assert_equal(script_history["synthetic"], True)
        assert_equal(script_history["merkle_included"], False)
        assert_equal(script_history["count"], 1)
        assert_equal(script_history["records"][0]["synthetic_txid"], payout_utxo["txid"])
        payout_outpoint = self.nodes[1].getshadowoutpoint(payout_utxo["txid"], payout_utxo["vout"])
        assert_equal(payout_outpoint["schema"], "blackcoin.shadow.outpoint.v1")
        assert_equal(payout_outpoint["lookup_index"], "synthetic_transaction")
        assert_equal(payout_outpoint["status"], "gold_rush_locked")
        assert_equal(payout_outpoint["synthetic"], True)
        assert_equal(payout_outpoint["merkle_included"], False)
        assert_raises_rpc_error(
            -5, "not found", self.nodes[1].getshadowoutpoint, payout_utxo["txid"], payout_utxo["vout"] + 1
        )
        observed, shadow_supply = self._ingest_shadow_reward_window()
        assert_equal([item["synthetic_txid"] for item in observed], [payout_utxo["txid"]])
        assert_equal(shadow_supply["unspent_count"], 1)
        assert_equal(self._amount(shadow_supply["unspent_nominal_amount"]), self._amount(payout_utxo["amount"]))
        assert_equal(shadow_supply["lifecycle_schema"], "blackcoin.shadow.supply.lifecycle.v1")
        assert_equal(shadow_supply["accounting_scope"], "synthetic_gold_rush_payouts_only")
        assert_equal(shadow_supply["synthetic"], True)
        assert_equal(shadow_supply["merkle_included"], False)
        assert_equal(shadow_supply["lifecycle"]["classification_exact"], True)
        assert_equal(shadow_supply["lifecycle"]["locked_count"], 1)
        assert_equal(shadow_supply["lifecycle"]["spendable_count"], 0)
        assert_equal(shadow_supply["lifecycle"]["expired_payout_count"], 0)
        assert_equal(shadow_supply["legacy"]["included"], False)
        assert_equal(shadow_supply["legacy"]["spendable_amount"], None)
        assert_equal(
            self._amount(shadow_supply["schedule"]["accrued_amount"]),
            self._amount(shadow_supply["issued_nominal_amount"])
            + self._amount(shadow_supply["pool"]["amount"]),
        )
        assert_equal(
            self._amount(shadow_supply["pool"]["amount"]),
            self._amount(shadow_supply["pool"]["pow_amount"])
            + self._amount(shadow_supply["pool"]["pos_amount"]),
        )
        payout_inventory = self._witness_inventory()
        assert_equal(payout_inventory["current_utxos"]["total"]["count"], 0)
        assert_equal(payout_inventory["current_utxos"]["excluded_synthetic_shadow"]["count"], 1)
        assert_equal(payout_inventory["history"]["created"]["count"], 0)

        self.log.info("Invalidating the claim block on the index node rewinds indexed shadow payouts")
        self.nodes[1].invalidateblock(claim_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == parent_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        assert_raises_rpc_error(-5, "not in the active chain", self.nodes[1].getshadowblock, claim_block_hash)
        assert_raises_rpc_error(-5, "not found", self.nodes[1].getshadowtransaction, payout_utxo["txid"])
        assert_raises_rpc_error(
            -5, "not found", self.nodes[1].getshadowoutpoint, payout_utxo["txid"], payout_utxo["vout"]
        )
        assert_equal(self.nodes[1].getshadowscript(payout_script)["count"], 0)
        assert_equal(self._live_stats(self.nodes[1]), parent_stats)
        self._assert_index_matches_live()

        self.log.info("Reconsidering the claim block restores the indexed synthetic payout")
        self.nodes[1].reconsiderblock(claim_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == claim_block_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None
        assert_equal(self.nodes[1].getshadowtransaction(payout_utxo["txid"])["status"], "gold_rush_locked")
        assert_equal(self.nodes[1].getshadowscript(payout_script)["count"], 1)
        assert_equal(self._live_stats(self.nodes[1]), claim_stats)
        self._assert_index_matches_live()
        self._assert_cross_node_live_stats_match()

        self.log.info("Spending the synthetic payout and checking the index tracks the spend/undo path")
        self.generatetoaddress(self.nodes[0], COINBASE_MATURITY, self.nodes[0].get_deterministic_priv_key().address)
        self._sync_mocktime_to_tip()
        matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
        assert matured_utxo["confirmations"] > COINBASE_MATURITY

        self._advance_to_migration_window()
        migration_parent_hash = self.nodes[0].getbestblockhash()
        migration_parent_height = self.nodes[0].getblockcount()
        migration_parent_stats = self._live_stats(self.nodes[1])
        migration_parent_indexed_full = self._indexed_full_stats_at(self.nodes[1], migration_parent_hash)
        next_quantum = wallet.getnewquantumaddress()["address"]
        signed = self._build_quantum_spend(wallet, matured_utxo, next_quantum)
        assert_equal(signed["complete"], True)
        spend_txid = self.nodes[0].sendrawtransaction(signed["hex"])
        spend_block_hash = self.generatetoaddress(self.nodes[0], 1, self.nodes[0].get_deterministic_priv_key().address)[0]
        spend_block_height = self.nodes[0].getblockcount()
        self._wait_index_synced()
        assert spend_txid in self.nodes[0].getblock(spend_block_hash)["tx"]
        assert self.nodes[0].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        spend_stats = self._live_stats(self.nodes[1])
        spend_indexed_full = self._indexed_full_stats_at(self.nodes[1], spend_block_hash)
        self._assert_cross_node_live_stats_match()
        self._assert_index_matches_live()
        assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_hash), migration_parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_height), migration_parent_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_hash), spend_stats)
        assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_height), spend_stats)
        assert_equal(self._amount(spend_indexed_full["block_info"]["prevout_spent"]), self._amount(matured_utxo["amount"]))
        assert_equal(self._amount(spend_indexed_full["block_info"]["unspendable"]), ZERO_AMOUNT)
        assert_equal(self._amount(spend_indexed_full["block_info"]["unspendables"]["unclaimed_rewards"]), ZERO_AMOUNT)
        assert_equal(spend_indexed_full["total_unspendable_amount"], migration_parent_indexed_full["total_unspendable_amount"])
        spent_record = self.nodes[1].getshadowtransaction(payout_utxo["txid"])
        assert_equal(spent_record["status"], "spent")
        assert_equal(spent_record["spend"]["txid"], spend_txid)
        assert_equal(spent_record["spend"]["blockhash"], spend_block_hash)
        spent_outpoint = self.nodes[1].getshadowoutpoint(payout_utxo["txid"], payout_utxo["vout"])
        assert_equal(spent_outpoint["lookup_index"], "spent_outpoint")
        assert_equal(spent_outpoint["status"], "spent")
        assert_equal(spent_outpoint["spend"]["txid"], spend_txid)
        spent_script_history = self.nodes[1].getshadowscript(payout_script)
        assert_equal(spent_script_history["count"], 1)
        assert_equal(spent_script_history["records"][0]["status"], "spent")
        spent_supply = self.nodes[1].getshadowsupply()
        assert_equal(spent_supply["spent_count"], 1)
        assert_equal(spent_supply["unspent_count"], 0)
        assert_equal(self._amount(spent_supply["spent_nominal_amount"]), self._amount(payout_utxo["amount"]))
        assert_equal(spent_supply["lifecycle"]["classification_exact"], True)
        assert_equal(spent_supply["lifecycle"]["locked_count"], 0)
        assert_equal(spent_supply["lifecycle"]["spendable_count"], 0)
        assert_equal(
            self._amount(spent_supply["burn"]["realized_amount"]),
            self._amount(spent_supply["spent_burned_amount"]),
        )
        witness_inventory = self._witness_inventory()
        assert_equal(witness_inventory["current_utxos"]["total"]["count"], 1)
        assert_equal(witness_inventory["current_utxos"]["by_version"]["v16"]["count"], 1)
        assert_equal(witness_inventory["current_utxos"]["by_origin_group"]["migration_or_later"]["count"], 1)
        assert_equal(witness_inventory["current_utxos"]["by_bridge_handling"]["recognized_direct_quantum"]["count"], 1)
        assert_equal(witness_inventory["current_utxos"]["excluded_synthetic_shadow"]["count"], 0)
        assert_equal(witness_inventory["history"]["created"]["count"], 1)
        assert_equal(witness_inventory["history"]["spent"]["count"], 0)
        assert_equal(witness_inventory["history"]["unspent"]["count"], 1)
        assert_equal(witness_inventory["records"][0]["txid"], spend_txid)
        history_inventory = self._witness_inventory("history")
        assert_equal(history_inventory["records"][0]["txid"], spend_txid)
        assert_equal(history_inventory["records"][0]["spent"], False)

        self.log.info("Invalidating the spend block restores the synthetic payout in indexed chainstate")
        self.nodes[1].invalidateblock(spend_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == migration_parent_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is not None
        assert_equal(self.nodes[1].getshadowtransaction(payout_utxo["txid"])["status"], "unspent")
        rewound_outpoint = self.nodes[1].getshadowoutpoint(payout_utxo["txid"], payout_utxo["vout"])
        assert_equal(rewound_outpoint["lookup_index"], "synthetic_transaction")
        assert_equal(rewound_outpoint["status"], "unspent")
        assert_equal(self.nodes[1].getshadowscript(payout_script)["records"][0]["status"], "unspent")
        rewound_supply = self.nodes[1].getshadowsupply()
        assert_equal(rewound_supply["lifecycle"]["classification_exact"], True)
        assert_equal(rewound_supply["lifecycle"]["locked_count"], 0)
        assert_equal(rewound_supply["lifecycle"]["spendable_count"], 1)
        rewound_inventory = self._witness_inventory()
        assert_equal(rewound_inventory["current_utxos"]["total"]["count"], 0)
        assert_equal(rewound_inventory["current_utxos"]["excluded_synthetic_shadow"]["count"], 1)
        assert_equal(rewound_inventory["history"]["created"]["count"], 0)
        assert_equal(self._live_stats(self.nodes[1]), migration_parent_stats)
        self._assert_index_matches_live()

        self.log.info("Reconsidering the spend block removes the payout from indexed chainstate again")
        self.nodes[1].reconsiderblock(spend_block_hash)
        self.wait_until(lambda: self.nodes[1].getbestblockhash() == spend_block_hash, timeout=30)
        self._wait_index_synced()
        assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
        assert_equal(self._witness_inventory()["history"]["created"]["count"], 1)
        assert_equal(self._live_stats(self.nodes[1]), spend_stats)
        self._assert_index_matches_live()
        self._assert_cross_node_live_stats_match()

        self.log.info("Restarting and rebuilding coinstatsindex preserves synthetic payout spend state")
        final_stats = self._live_stats(self.nodes[1])
        for restart_args in (
            self.extra_args[1],
            self.extra_args[1] + ["-reindex"],
            self.extra_args[1] + ["-reindex-chainstate"],
        ):
            self.restart_node(1, extra_args=restart_args + [f"-mocktime={self.mock_time}"])
            self.nodes[1].setmocktime(self.mock_time)
            self.connect_nodes(0, 1)
            self.sync_blocks()
            self._wait_index_synced()
            assert_equal(self.nodes[1].getbestblockhash(), spend_block_hash)
            assert self.nodes[1].gettxout(matured_utxo["txid"], matured_utxo["vout"], False) is None
            rebuilt_record = self.nodes[1].getshadowtransaction(payout_utxo["txid"])
            assert_equal(rebuilt_record["status"], "spent")
            assert_equal(rebuilt_record["spend"]["txid"], spend_txid)
            rebuilt_outpoint = self.nodes[1].getshadowoutpoint(payout_utxo["txid"], payout_utxo["vout"])
            assert_equal(rebuilt_outpoint["lookup_index"], "spent_outpoint")
            assert_equal(rebuilt_outpoint["status"], "spent")
            rebuilt_script = self.nodes[1].getshadowscript(payout_script)
            assert_equal(rebuilt_script["count"], 1)
            assert_equal(rebuilt_script["records"][0]["status"], "spent")
            rebuilt_claim = self.nodes[1].getshadowblock(claim_block_hash, 0, 1, 0, 1)["pow_claim_accounting"]
            assert_equal(rebuilt_claim["records"][0]["txid"], claim["txid"])
            assert_equal(rebuilt_claim["records"][0]["disposition"], "winner")
            assert_equal(rebuilt_claim["records"][0]["synthetic_txid"], payout_utxo["txid"])
            rebuilt_supply = self.nodes[1].getshadowsupply()
            assert_equal(rebuilt_supply["spent_count"], 1)
            assert_equal(rebuilt_supply["unspent_count"], 0)
            assert_equal(rebuilt_supply["lifecycle"]["classification_exact"], True)
            assert_equal(rebuilt_supply["lifecycle"]["locked_count"], 0)
            assert_equal(rebuilt_supply["lifecycle"]["spendable_count"], 0)
            rebuilt_inventory = self._witness_inventory()
            assert_equal(rebuilt_inventory["current_utxos"]["total"]["count"], 1)
            assert_equal(rebuilt_inventory["history"]["created"]["count"], 1)
            assert_equal(self._live_stats(self.nodes[1]), final_stats)
            self._assert_index_matches_live()
            assert_equal(self._indexed_stats_at(self.nodes[1], migration_parent_hash), migration_parent_stats)
            assert_equal(self._indexed_stats_at(self.nodes[1], spend_block_hash), spend_stats)
            self._assert_cross_node_live_stats_match()


if __name__ == "__main__":
    GoldRushCoinStatsIndexTest().main()
