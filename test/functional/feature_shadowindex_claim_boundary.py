#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise shadowindex across the historical/QQP3/QQP4 boundaries.

Mainnet paid the v30.1.0 first-valid QQSPROOF rule before height 5,993,200.
The canonical QQP3 boundary intentionally still accepts valid QQP2 carriers,
and adds bounded late QQP3 reimbursement. QQP4 is a separate future fork. This
test pins QQP2 plus QQP3 source records, reorg behavior, and full reindex while
the chain remains strictly before the QQP4 activation height.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


CLAIM_ACTIVATION_HEIGHT = 40
QQP4_ACTIVATION_HEIGHT = 43


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
            f"-shadowqqp4height={QQP4_ACTIVATION_HEIGHT}",
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

    def _mine_pos_block_with_claims(self, wallet, claim_txids):
        node = self.nodes[0]
        expected_txids = set(claim_txids)
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
                assert expected_txids.issubset(set(txids[2:]))
                return block_hash
            except AssertionError as error:
                last_error = error
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _mine_pos_block_with_claim(self, wallet, claim_txid):
        return self._mine_pos_block_with_claims(wallet, [claim_txid])

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

    @staticmethod
    def _downgrade_qqp3_to_qqp2(proof_hex):
        proof = bytearray.fromhex(proof_hex)
        prefix = b"QQSPROOF"
        proof_header_size = 13  # magic(4) | mode(1) | nonce(8)
        qqp3_origin_size = 36  # height(4) | parent hash(32)
        assert proof.startswith(prefix)
        assert proof[len(prefix):len(prefix) + 4] == b"QQP3"
        header_end = len(prefix) + proof_header_size
        return (
            proof[:len(prefix)]
            + b"QQP2"
            + proof[len(prefix) + 4:header_end]
            + proof[header_end + qqp3_origin_size:]
        ).hex()

    def _submit_qqp2_carrier(self, wallet, address, q3_proof_hex):
        node = self.nodes[0]
        q2_proof_hex = self._downgrade_qqp3_to_qqp2(q3_proof_hex)
        utxos = wallet.listunspent(1, 9_999_999, [address])
        assert utxos, "need an unspent second input for the QQP2 carrier"
        utxo = utxos[0]
        fee = Decimal("0.0005")
        assert Decimal(str(utxo["amount"])) > fee
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{address: Decimal(str(utxo["amount"])) - fee},
             {"data": q2_proof_hex}],
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        txid = node.sendrawtransaction(signed["hex"])
        assert txid in node.getrawmempool()
        return txid

    @staticmethod
    def _assert_qqp2_source(source):
        assert_equal(source["proof_version"], 2)
        assert_equal(source["origin_bound"], False)
        assert_equal(source["input_bound"], False)
        assert_equal(source["claim_outpoint"], None)

    @staticmethod
    def _assert_qqp3_source(source):
        assert_equal(source["proof_version"], 3)
        assert_equal(source["origin_bound"], True)
        assert_equal(source["input_bound"], False)
        assert_equal(source["claim_outpoint"], None)

    def _assert_qqp2_and_qqp3_current_payouts(
        self,
        block_hash,
        qqp2_claim,
        qqp3_claim,
        payout_address,
        synthetic_by_claim=None,
    ):
        node = self.nodes[0]
        page = node.getshadowblock(block_hash, 0, 10, 0, 10)
        accounting = page["pow_claim_accounting"]
        assert_equal(accounting["active"], True)
        assert_equal(accounting["total_records"], 2)
        assert_equal(accounting["observed_count"], 2)
        assert_equal(accounting["evaluated_count"], 2)
        assert_equal(accounting["winner_count"], 1)
        assert_equal(accounting["reimbursed_loser_count"], 1)
        assert_equal(accounting["rejected_count"], 0)
        assert len(accounting["accounting_commitment"]) == 64

        records = {record["txid"]: record for record in accounting["records"]}
        assert_equal(set(records), {qqp2_claim, qqp3_claim})
        assert_equal(
            {record["disposition"] for record in records.values()},
            {"winner", "reimbursed_loser"},
        )
        self._assert_qqp2_source(records[qqp2_claim])
        self._assert_qqp3_source(records[qqp3_claim])
        assert_equal(
            Decimal(str(accounting["credited_total"])),
            Decimal(str(page["pow_payout_total"])),
        )

        for txid, record in records.items():
            assert_equal(record["base_fee_known"], True)
            assert_equal(record["payout_address"], payout_address)
            assert record["synthetic_txid"] is not None
            if synthetic_by_claim is not None:
                assert_equal(record["synthetic_txid"], synthetic_by_claim[txid])
            payout = node.getshadowtransaction(record["synthetic_txid"])
            assert_equal(payout["mode"], "pow")
            assert_equal(payout["base_anchor"]["blockhash"], block_hash)
            assert_equal(payout["pow_claim_source"]["txid"], txid)
            assert_equal(
                payout["pow_claim_source"]["disposition"],
                record["disposition"],
            )
            if txid == qqp2_claim:
                self._assert_qqp2_source(payout["pow_claim_source"])
            else:
                self._assert_qqp3_source(payout["pow_claim_source"])
        return page, {
            txid: record["synthetic_txid"] for txid, record in records.items()
        }

    def _assert_mixed_qqp3_payouts(
        self,
        block_hash,
        late_claim,
        current_claim,
        payout_by_claim,
        synthetic_by_claim=None,
    ):
        node = self.nodes[0]
        page = node.getshadowblock(block_hash, 0, 10, 0, 10)
        accounting = page["pow_claim_accounting"]
        assert_equal(accounting["active"], True)
        assert_equal(accounting["total_records"], 2)
        assert_equal(accounting["observed_count"], 2)
        assert_equal(accounting["evaluated_count"], 2)
        assert_equal(accounting["winner_count"], 1)
        assert_equal(accounting["reimbursed_loser_count"], 0)
        assert_equal(accounting["reimbursed_late_count"], 1)
        assert_equal(accounting["origin_mismatch_count"], 0)
        assert_equal(accounting["origin_expired_count"], 0)
        assert_equal(accounting["rejected_count"], 0)
        assert len(accounting["accounting_commitment"]) == 64

        records = {record["txid"]: record for record in accounting["records"]}
        assert_equal(set(records), {late_claim, current_claim})
        late = records[late_claim]
        current = records[current_claim]
        inclusion_height = node.getblockheader(block_hash)["height"]
        assert_equal(late["disposition"], "reimbursed_late")
        assert_equal(current["disposition"], "winner")
        self._assert_qqp3_source(late)
        self._assert_qqp3_source(current)
        assert_equal(late["origin_height"], inclusion_height - 1)
        assert_equal(late["inclusion_height"], inclusion_height)
        assert_equal(late["origin_age"], 1)
        assert_equal(current["origin_height"], inclusion_height)
        assert_equal(current["inclusion_height"], inclusion_height)
        assert_equal(current["origin_age"], 0)
        for txid, record in records.items():
            assert_equal(record["base_fee_known"], True)
            assert_equal(record["payout_address"], payout_by_claim[txid])
            assert record["synthetic_txid"] is not None
            self._assert_qqp3_source(record)
            if synthetic_by_claim is not None:
                assert_equal(record["synthetic_txid"], synthetic_by_claim[txid])
            payout = node.getshadowtransaction(record["synthetic_txid"])
            assert_equal(payout["pow_claim_source"]["txid"], txid)
            assert_equal(
                payout["pow_claim_source"]["disposition"],
                record["disposition"],
            )
            assert_equal(
                payout["pow_claim_source"]["origin_height"],
                record["origin_height"],
            )
            self._assert_qqp3_source(payout["pow_claim_source"])

        late_fee = min(Decimal(str(late["base_fee"])), Decimal("0.01"))
        assert_equal(Decimal(str(late["credited_amount"])), late_fee)
        assert_equal(
            Decimal(str(current["credited_amount"])) + late_fee,
            Decimal(str(accounting["credited_total"])),
        )
        assert_equal(
            Decimal(str(accounting["credited_total"])),
            Decimal(str(page["pow_payout_total"])),
        )
        return page, {
            txid: record["synthetic_txid"] for txid, record in records.items()
        }

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

        self.log.info("Crossing the QQP3 boundary with both valid QQP2 and QQP3 carriers")
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
        assert_equal(node.getgoldrushstate()["qqp4_active_next_block"], False)

        q3_current_payout_address = wallet.getnewquantumaddress()["address"]
        q3_current_claim = wallet.sendshadowpowclaim(
            canonical_claim_address, q3_current_payout_address, 500_000
        )
        assert q3_current_claim["txid"] in node.getrawmempool()
        q2_current_txid = self._submit_qqp2_carrier(
            wallet, canonical_claim_address, q3_current_claim["proof"]
        )
        assert_equal(
            set(node.getrawmempool()),
            {q2_current_txid, q3_current_claim["txid"]},
        )

        qqp2_qqp3_block = self._mine_pos_block_with_claims(
            wallet, [q2_current_txid, q3_current_claim["txid"]]
        )
        assert_equal(node.getblockcount(), CLAIM_ACTIVATION_HEIGHT)
        self._wait_index_synced()
        qqp2_qqp3_page, qqp2_qqp3_synthetic = (
            self._assert_qqp2_and_qqp3_current_payouts(
                qqp2_qqp3_block,
                q2_current_txid,
                q3_current_claim["txid"],
                q3_current_payout_address,
            )
        )

        self.log.info("A QQP3 claim remains eligible for its one-block late window")
        late_payout_address = wallet.getnewquantumaddress()["address"]
        late_claim = wallet.sendshadowpowclaim(
            canonical_claim_address, late_payout_address, 500_000
        )
        assert late_claim["txid"] in node.getrawmempool()
        self.generateblock(node, output=staking_address, transactions=[])
        assert_equal(node.getblockcount(), CLAIM_ACTIVATION_HEIGHT + 1)
        self.wait_until(
            lambda: late_claim["txid"] in node.getrawmempool(), timeout=20
        )
        assert_equal(node.getgoldrushstate()["qqp4_active_next_block"], False)

        current_payout_address = wallet.getnewquantumaddress()["address"]
        current_claim = wallet.sendshadowpowclaim(
            canonical_claim_address, current_payout_address, 500_000
        )
        assert_equal(
            set(node.getrawmempool()),
            {late_claim["txid"], current_claim["txid"]},
        )
        qqp3_late_block = self._mine_pos_block_with_claims(
            wallet, [late_claim["txid"], current_claim["txid"]]
        )
        assert_equal(node.getblockcount(), CLAIM_ACTIVATION_HEIGHT + 2)
        assert_equal(node.getgoldrushstate()["qqp4_active"], False)
        self._wait_index_synced()
        qqp3_late_page, qqp3_late_synthetic = self._assert_mixed_qqp3_payouts(
            qqp3_late_block,
            late_claim["txid"],
            current_claim["txid"],
            {
                late_claim["txid"]: late_payout_address,
                current_claim["txid"]: current_payout_address,
            },
        )
        expected_issued_count = (
            1
            + qqp2_qqp3_page["total_payouts"]
            + qqp3_late_page["total_payouts"]
        )
        assert_equal(node.getshadowsupply()["issued_count"], expected_issued_count)

        self.log.info("Reorg removes and restores the late QQP3 synthetic payouts")
        qqp3_late_parent = node.getblockheader(qqp3_late_block)["previousblockhash"]
        node.invalidateblock(qqp3_late_block)
        node.syncwithvalidationinterfacequeue()
        self._wait_index_synced()
        assert_equal(node.getbestblockhash(), qqp3_late_parent)
        for synthetic_txid in qqp3_late_synthetic.values():
            assert_raises_rpc_error(
                -5, "not found", node.getshadowtransaction, synthetic_txid
            )
        node.reconsiderblock(qqp3_late_block)
        node.syncwithvalidationinterfacequeue()
        self._wait_index_synced()
        assert_equal(node.getbestblockhash(), qqp3_late_block)
        self._assert_qqp2_and_qqp3_current_payouts(
            qqp2_qqp3_block,
            q2_current_txid,
            q3_current_claim["txid"],
            q3_current_payout_address,
            qqp2_qqp3_synthetic,
        )
        self._assert_mixed_qqp3_payouts(
            qqp3_late_block,
            late_claim["txid"],
            current_claim["txid"],
            {
                late_claim["txid"]: late_payout_address,
                current_claim["txid"]: current_payout_address,
            },
            qqp3_late_synthetic,
        )

        self.log.info("Restart and full reindex reproduce QQP2 and QQP3 provenance")
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
            self._assert_qqp2_and_qqp3_current_payouts(
                qqp2_qqp3_block,
                q2_current_txid,
                q3_current_claim["txid"],
                q3_current_payout_address,
                qqp2_qqp3_synthetic,
            )
            self._assert_mixed_qqp3_payouts(
                qqp3_late_block,
                late_claim["txid"],
                current_claim["txid"],
                {
                    late_claim["txid"]: late_payout_address,
                    current_claim["txid"]: current_payout_address,
                },
                qqp3_late_synthetic,
            )
            assert_equal(
                node.getshadowsupply()["issued_count"], expected_issued_count
            )


if __name__ == "__main__":
    ShadowIndexClaimBoundaryTest().main()
