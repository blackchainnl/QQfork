#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise QQP3 logical-proof deduplication through a live node.

Policy must reject a second carrier for one decoded QQP3 proof.  A peer can
still put both otherwise-valid transactions in a direct PoS block, so shadow
accounting must choose one deterministic fee carrier, evaluate and credit the
logical proof once, and preserve base-block validity.  A later direct-block
replay of the same proof must remain base-valid while receiving zero credit.
Reorg, restart, and reindex must reproduce those decisions exactly.
"""

from decimal import Decimal
import time

from test_framework.address import base58_to_byte
from test_framework.blocktools import (
    COINBASE_MATURITY,
    WITNESS_COMMITMENT_HEADER,
    get_witness_script,
)
from test_framework.key import ECKey
from test_framework.messages import (
    CBlock,
    CTransaction,
    CTxInWitness,
    from_hex,
    ser_uint256,
    tx_from_hex,
)
from test_framework.p2p import P2PDataStore
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class GoldRushQQP3DuplicateClaimsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.node_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-shadowindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=2",
            "-shadowgoldrushblocks=1000",
            "-shadowcompetingclaimsheight=2",
            # This is a QQP3 carrier-identity test. QQP4 has a separate,
            # exact-input-bound activation and regression suite.
            "-shadowqqp4height=1001",
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

    @staticmethod
    def _amount(value):
        return Decimal(str(value))

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9_999_999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "staking wallet must have a mature input"
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _capture_pos_template(self, wallet, expected_claim_txids):
        node = self.nodes[0]
        expected = set(expected_claim_txids)
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
                txids = {tx["txid"] for tx in block["tx"][2:]}
                assert expected.issubset(txids)
                return block_hash, node.getblock(block_hash, 0)
            except AssertionError as error:
                last_error = error
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to capture a PoS template")

    @staticmethod
    def _legacy_key_from_wif(wif):
        payload, version = base58_to_byte(wif)
        assert_equal(version, 239)
        compressed = len(payload) == 33 and payload[-1] == 1
        assert len(payload) == (33 if compressed else 32)
        key = ECKey()
        key.set(payload[:32], compressed)
        return key

    def _ordered_signed_pos_block(self, template_hex, ordered_raw, signing_wif):
        block = from_hex(CBlock(), template_hex)
        inserted_txids = {
            self.nodes[0].decoderawtransaction(raw)["txid"]
            for raw in ordered_raw
        }
        extras = []
        for tx in block.vtx[2:]:
            tx.rehash()
            if tx.hash not in inserted_txids:
                extras.append(tx)
        block.vtx = block.vtx[:2] + [tx_from_hex(raw) for raw in ordered_raw] + extras

        # Reordering witness transaction ids changes the witness commitment.
        coinbase = CTransaction(block.vtx[0])
        coinbase.wit.vtxinwit = [CTxInWitness() for _ in coinbase.vin]
        coinbase.wit.vtxinwit[0].scriptWitness.stack = [b"\x00" * 32]
        block.vtx[0] = coinbase
        witness_script = get_witness_script(block.calc_witness_merkle_root(), 0)
        for txout in reversed(block.vtx[0].vout):
            if bytes(txout.scriptPubKey).startswith(
                b"\x6a\x24" + WITNESS_COMMITMENT_HEADER
            ):
                txout.scriptPubKey = witness_script
                break
        else:
            raise AssertionError("PoS template is missing its witness commitment")

        block.vtx[0].rehash()
        block.hashMerkleRoot = block.calc_merkle_root()
        block.sha256 = None
        block.hash = None
        block.vchBlockSig = b""
        block.rehash()
        block.vchBlockSig = self._legacy_key_from_wif(signing_wif).sign_ecdsa(
            ser_uint256(block.sha256), rfc6979=True
        )
        block.nFlags = 1
        block.rehash()
        return block

    def _raw_carrier(self, wallet, target_address, proof_hex, fee):
        node = self.nodes[0]
        utxos = wallet.listunspent(1, 9_999_999, [target_address])
        assert utxos, "duplicate carrier needs an independent mature input"
        utxo = utxos[0]
        amount = self._amount(utxo["amount"])
        assert amount > fee
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [
                {target_address: amount - fee},
                {"data": proof_hex},
            ],
        )
        signed = wallet.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        txid = node.decoderawtransaction(signed["hex"])["txid"]
        return txid, signed["hex"]

    def _wait_shadowindex(self):
        node = self.nodes[0]

        def synced():
            status = node.getindexinfo().get("shadowindex", {})
            return (
                status.get("synced", False)
                and status.get("best_block_height", node.getblockcount())
                == node.getblockcount()
            )

        self.wait_until(synced, timeout=60)

    @staticmethod
    def _accounting_fingerprint(page):
        accounting = page["pow_claim_accounting"]
        return {
            "total_payouts": page["total_payouts"],
            "pow_payout_total": page["pow_payout_total"],
            "observed_pow_claim_txids": page["observed_pow_claim_txids"],
            "total_records": accounting["total_records"],
            "observed_count": accounting["observed_count"],
            "evaluated_count": accounting["evaluated_count"],
            "duplicate_logical_proof_count": accounting[
                "duplicate_logical_proof_count"
            ],
            "already_accounted_count": accounting["already_accounted_count"],
            "winner_count": accounting["winner_count"],
            "reimbursed_loser_count": accounting["reimbursed_loser_count"],
            "rejected_count": accounting["rejected_count"],
            "credited_total": accounting["credited_total"],
            "accounting_commitment": accounting["accounting_commitment"],
            "records": accounting["records"],
        }

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xF) + 16)
        peer = node.add_p2p_connection(P2PDataStore())
        staker = node.get_wallet_rpc(self.default_wallet_name)
        staker.staking(False)
        node.createwallet(wallet_name="qqp3_claimants", load_on_startup=True)
        claimant = node.get_wallet_rpc("qqp3_claimants")
        claimant.staking(False)

        staking_address = node.get_deterministic_priv_key().address
        target_address = claimant.getnewaddress("qqp3-target", "legacy")
        self.log.info("Creating independent mature staking and claim inputs")
        self.generatetoaddress(node, 1, staking_address)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address)
        self.generatetoaddress(node, COINBASE_MATURITY + 8, target_address)
        self._sync_mocktime_to_tip()
        self._wait_shadowindex()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        state = node.getgoldrushstate()
        assert_equal(state["competing_claim_rule_active_next_block"], True)
        assert_equal(state["qqp4_active_next_block"], False)

        payout_a = claimant.getnewquantumaddress()["address"]
        payout_b = claimant.getnewquantumaddress()["address"]
        claim_a = claimant.sendshadowpowclaim(
            target_address, payout_a, 500_000
        )
        claim_b = claimant.sendshadowpowclaim(
            target_address, payout_b, 500_000
        )
        raw_a = node.getrawtransaction(claim_a["txid"])
        raw_b = node.getrawtransaction(claim_b["txid"])

        duplicate_fee = Decimal("0.005")
        duplicate_txid, duplicate_raw = self._raw_carrier(
            claimant, target_address, claim_a["proof"], duplicate_fee
        )
        duplicate_policy = node.testmempoolaccept([duplicate_raw])[0]
        assert_equal(duplicate_policy["allowed"], False)
        assert_equal(
            duplicate_policy["reject-reason"], "shadow-proof-mempool-duplicate"
        )

        parent_hash = node.getbestblockhash()
        parent_supply = node.getshadowsupply()
        expected_pool = self._amount(claimant.getgoldrushinfo()["pow_jackpot"])
        self.log.info("Injecting two carriers for one QQP3 proof in a direct PoS block")
        template_hash, template_hex = self._capture_pos_template(
            staker, [claim_a["txid"], claim_b["txid"]]
        )
        node.invalidateblock(template_hash)
        self.wait_until(lambda: node.getbestblockhash() == parent_hash, timeout=30)
        self.wait_until(
            lambda: {claim_a["txid"], claim_b["txid"]}.issubset(
                set(node.getrawmempool())
            ),
            timeout=30,
        )
        duplicate_block = self._ordered_signed_pos_block(
            template_hex,
            [raw_a, duplicate_raw, raw_b],
            node.get_deterministic_priv_key().key,
        )
        peer.send_blocks_and_test(
            [duplicate_block], node, success=True, force_send=True
        )
        self._wait_shadowindex()
        assert_equal(node.getbestblockhash(), duplicate_block.hash)

        duplicate_page = node.getshadowblock(duplicate_block.hash, 0, 10, 0, 10)
        duplicate_accounting = duplicate_page["pow_claim_accounting"]
        assert_equal(duplicate_page["total_payouts"], 2)
        assert_equal(self._amount(duplicate_page["pow_payout_total"]), expected_pool)
        assert_equal(duplicate_accounting["total_records"], 2)
        assert_equal(duplicate_accounting["observed_count"], 3)
        assert_equal(duplicate_accounting["evaluated_count"], 2)
        assert_equal(duplicate_accounting["duplicate_logical_proof_count"], 1)
        assert_equal(duplicate_accounting["already_accounted_count"], 0)
        assert_equal(duplicate_accounting["winner_count"], 1)
        assert_equal(duplicate_accounting["reimbursed_loser_count"], 1)
        assert_equal(duplicate_accounting["rejected_count"], 1)
        assert_equal(
            self._amount(duplicate_accounting["credited_total"]), expected_pool
        )
        assert_equal(
            duplicate_page["observed_pow_claim_txids"],
            [claim_a["txid"], duplicate_txid, claim_b["txid"]],
        )

        records = duplicate_accounting["records"]
        assert_equal(len({record["logical_proof_id"] for record in records}), 2)
        record_by_txid = {record["txid"]: record for record in records}
        assert duplicate_txid in record_by_txid
        assert claim_a["txid"] not in record_by_txid
        assert claim_b["txid"] in record_by_txid
        duplicate_record = record_by_txid[duplicate_txid]
        assert_equal(self._amount(duplicate_record["base_fee"]), duplicate_fee)
        assert_equal(duplicate_record["base_fee_known"], True)
        duplicated_logical_id = duplicate_record["logical_proof_id"]
        assert_equal(node.getshadowsupply()["issued_count"], parent_supply["issued_count"] + 2)

        self.log.info("Rejecting policy replay while preserving a direct replay block")
        replay_txid, replay_raw = self._raw_carrier(
            claimant, target_address, claim_a["proof"], Decimal("0.004")
        )
        replay_policy = node.testmempoolaccept([replay_raw])[0]
        assert_equal(replay_policy["allowed"], False)
        assert_equal(
            replay_policy["reject-reason"], "shadow-proof-already-accounted"
        )

        replay_parent = node.getbestblockhash()
        replay_supply = node.getshadowsupply()
        replay_template_hash, replay_template_hex = self._capture_pos_template(
            staker, []
        )
        node.invalidateblock(replay_template_hash)
        self.wait_until(lambda: node.getbestblockhash() == replay_parent, timeout=30)
        replay_block = self._ordered_signed_pos_block(
            replay_template_hex,
            [replay_raw],
            node.get_deterministic_priv_key().key,
        )
        peer.send_blocks_and_test(
            [replay_block], node, success=True, force_send=True
        )
        self._wait_shadowindex()
        assert_equal(node.getbestblockhash(), replay_block.hash)

        replay_page = node.getshadowblock(replay_block.hash, 0, 10, 0, 10)
        replay_accounting = replay_page["pow_claim_accounting"]
        assert_equal(replay_page["total_payouts"], 0)
        assert_equal(self._amount(replay_page["pow_payout_total"]), Decimal(0))
        assert_equal(replay_accounting["total_records"], 1)
        assert_equal(replay_accounting["observed_count"], 1)
        assert_equal(replay_accounting["evaluated_count"], 1)
        assert_equal(replay_accounting["duplicate_logical_proof_count"], 0)
        assert_equal(replay_accounting["already_accounted_count"], 1)
        assert_equal(replay_accounting["winner_count"], 0)
        assert_equal(replay_accounting["reimbursed_loser_count"], 0)
        assert_equal(replay_accounting["credited_total"], Decimal("0.00000000"))
        assert_equal(replay_accounting["records"][0]["txid"], replay_txid)
        assert_equal(
            replay_accounting["records"][0]["logical_proof_id"],
            duplicated_logical_id,
        )
        assert_equal(
            replay_accounting["records"][0]["disposition"], "already_accounted"
        )
        supply_after_replay = node.getshadowsupply()
        assert_equal(
            supply_after_replay["issued_count"], replay_supply["issued_count"]
        )
        assert_equal(
            supply_after_replay["issued_nominal_amount"],
            replay_supply["issued_nominal_amount"],
        )

        duplicate_fingerprint = self._accounting_fingerprint(duplicate_page)
        replay_fingerprint = self._accounting_fingerprint(replay_page)
        # The unmodified PoS template remains a valid sibling in block files.
        # Extend the custom replay branch so a full reindex deterministically
        # selects it without relying on the runtime invalidation marker used
        # while replacing the captured template.
        final_tip = self.generatetoaddress(node, 1, staking_address)[0]
        self._wait_shadowindex()
        assert_equal(node.getbestblockhash(), final_tip)
        final_supply = node.getshadowsupply()
        self.log.info("Disconnecting and reconsidering removes and restores exact credit")
        node.invalidateblock(duplicate_block.hash)
        node.syncwithvalidationinterfacequeue()
        self._wait_shadowindex()
        assert_equal(node.getbestblockhash(), parent_hash)
        assert_equal(node.getshadowsupply(), parent_supply)
        node.reconsiderblock(final_tip)
        node.syncwithvalidationinterfacequeue()
        self._wait_shadowindex()
        assert_equal(node.getbestblockhash(), final_tip)
        assert_equal(
            self._accounting_fingerprint(
                node.getshadowblock(duplicate_block.hash, 0, 10, 0, 10)
            ),
            duplicate_fingerprint,
        )
        assert_equal(
            self._accounting_fingerprint(
                node.getshadowblock(replay_block.hash, 0, 10, 0, 10)
            ),
            replay_fingerprint,
        )
        assert_equal(node.getshadowsupply(), final_supply)

        self.log.info("Restart and reindex reproduce logical-proof accounting")
        for restart_args in (
            self.node_args + ["-staking=0"],
            self.node_args + ["-staking=0", "-reindex"],
        ):
            self.restart_node(
                0, extra_args=restart_args + [f"-mocktime={self.mock_time}"]
            )
            node.setmocktime(self.mock_time)
            self._wait_shadowindex()
            assert_equal(node.getbestblockhash(), final_tip)
            assert_equal(
                self._accounting_fingerprint(
                    node.getshadowblock(duplicate_block.hash, 0, 10, 0, 10)
                ),
                duplicate_fingerprint,
            )
            assert_equal(
                self._accounting_fingerprint(
                    node.getshadowblock(replay_block.hash, 0, 10, 0, 10)
                ),
                replay_fingerprint,
            )
            assert_equal(node.getshadowsupply(), final_supply)


if __name__ == "__main__":
    GoldRushQQP3DuplicateClaimsTest().main()
