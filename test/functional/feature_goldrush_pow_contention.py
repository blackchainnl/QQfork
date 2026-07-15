#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise post-activation competing QQSPROOF accounting through live nodes.

Policy admits up to the same bounded 64 QQSPROOF evaluations used by block
accounting after activation. Consensus classifies independently received
claims deterministically: transaction order cannot choose the winner, valid
losers recover their bounded base fee from the same fixed PoW pool, and replay
must reconstruct the same source provenance and synthetic payouts.
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
from test_framework.util import assert_equal, assert_raises_rpc_error


MAX_REIMBURSEMENT = Decimal("0.01")


class GoldRushPowContentionTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        common_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-shadowindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=2",
            "-shadowgoldrushblocks=1000",
            # Pin both transitions for this exact-input contention vector.
            "-shadowcompetingclaimsheight=2",
            "-shadowqqp4height=2",
        ]
        self.extra_args = [common_args, common_args]

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
        self._set_mocktime((tip_time & ~0xF) + 16)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "staking wallet must have mature inputs"
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_template(self, wallet, claim_txid):
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
                assert_equal(txids[2:], [claim_txid])
                return block_hash, node.getblock(block_hash, 0)
            except AssertionError as error:
                last_error = error
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mint deterministic PoS template")

    @staticmethod
    def _legacy_key_from_wif(wif):
        payload, version = base58_to_byte(wif)
        assert_equal(version, 239)
        compressed = len(payload) == 33 and payload[-1] == 1
        assert len(payload) == (33 if compressed else 32)
        key = ECKey()
        key.set(payload[:32], compressed)
        return key

    def _ordered_signed_pos_block(self, template_hex, ordered_claim_hex, signing_wif):
        block = from_hex(CBlock(), template_hex)
        claim_txids = {
            self.nodes[0].decoderawtransaction(raw)["txid"]
            for raw in ordered_claim_hex
        }
        extras = []
        for tx in block.vtx[2:]:
            tx.rehash()
            if tx.hash not in claim_txids:
                extras.append(tx)
        block.vtx = (
            block.vtx[:2]
            + [tx_from_hex(raw) for raw in ordered_claim_hex]
            + extras
        )

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
        return block

    def _wait_shadowindex(self, node):
        self.wait_until(
            lambda: node.getindexinfo()["shadowindex"]["synced"]
            and node.getindexinfo()["shadowindex"].get(
                "best_block_height", node.getblockcount()
            )
            == node.getblockcount(),
            timeout=60,
        )

    @staticmethod
    def _amount(value):
        return Decimal(str(value))

    @staticmethod
    def _is_abandoned(wallet, txid):
        return any(
            detail.get("abandoned", False)
            for detail in wallet.gettransaction(txid)["details"]
        )

    def _quantum_utxos(self, wallet, address):
        return wallet.listunspent(
            0,
            9999999,
            [address],
            True,
            {"include_immature_coinbase": True},
        )

    def _wait_one_quantum_utxo(self, wallet, address):
        self.wait_until(lambda: len(self._quantum_utxos(wallet, address)) == 1, timeout=30)
        return self._quantum_utxos(wallet, address)[0]

    @staticmethod
    def _normalized_accounting(summary):
        return {
            "total_records": summary["total_records"],
            "winner_count": summary["winner_count"],
            "reimbursed_loser_count": summary["reimbursed_loser_count"],
            "reimbursed_late_count": summary["reimbursed_late_count"],
            "origin_mismatch_count": summary["origin_mismatch_count"],
            "origin_expired_count": summary["origin_expired_count"],
            "rejected_count": summary["rejected_count"],
            "credited_total": summary["credited_total"],
            "winner_credited_total": summary["winner_credited_total"],
            "reimbursed_credited_total": summary["reimbursed_credited_total"],
            "records": [
                {
                    key: record[key]
                    for key in (
                        "txid",
                        "vout",
                        "canonical_rank",
                        "disposition",
                        "base_fee_known",
                        "base_fee",
                        "origin_bound",
                        "origin_height",
                        "origin_previous_block_hash",
                        "inclusion_height",
                        "origin_age",
                        "credited_amount",
                        "payout_scriptPubKey",
                        "payout_address",
                    )
                }
                for record in summary["records"]
            ],
        }

    def _assert_competing_accounting(
        self, node, block_hash, expected_pool, claims, payout_by_txid
    ):
        assert_raises_rpc_error(
            -8,
            "claim_count must be between 1 and 64",
            node.getshadowblock,
            block_hash,
            0,
            10,
            0,
            65,
        )
        page = node.getshadowblock(block_hash, 0, 10, 0, 10)
        assert_equal(page["schema"], "blackcoin.shadow.block.v3")
        assert_equal(page["total_payouts"], 2)
        assert_equal(page["count"], 2)
        assert_equal(self._amount(page["pow_payout_total"]), expected_pool)
        summary = page["pow_claim_accounting"]
        assert_equal(summary["active"], True)
        assert_equal(summary["total_records"], 2)
        assert_equal(summary["observed_count"], 2)
        assert_equal(summary["evaluated_count"], 2)
        assert_equal(summary["winner_count"], 1)
        assert_equal(summary["reimbursed_loser_count"], 1)
        assert_equal(summary["reimbursed_late_count"], 0)
        assert_equal(summary["origin_mismatch_count"], 0)
        assert_equal(summary["origin_expired_count"], 0)
        assert_equal(summary["rejected_count"], 0)
        assert len(summary["accounting_commitment"]) == 64
        assert_equal(self._amount(summary["credited_total"]), expected_pool)
        assert_equal(summary["next_offset"], None)

        records = {record["txid"]: record for record in summary["records"]}
        assert_equal(set(records), set(claims))
        winner = next(
            record for record in records.values() if record["disposition"] == "winner"
        )
        loser = next(
            record
            for record in records.values()
            if record["disposition"] == "reimbursed_loser"
        )
        # Records are serialized in the consensus uint256 rank order.  The
        # RPC hex form reverses the internal byte order, so lexical comparison
        # of the displayed strings would not reproduce uint256::operator<.
        assert_equal(summary["records"][0]["txid"], winner["txid"])
        assert_equal(summary["records"][1]["txid"], loser["txid"])
        inclusion_height = node.getblock(block_hash)["height"]
        for txid, record in records.items():
            assert_equal(record["base_fee_known"], True)
            assert self._amount(record["base_fee"]) > 0
            assert_equal(record["origin_bound"], True)
            assert_equal(record["origin_height"], inclusion_height)
            assert_equal(record["inclusion_height"], inclusion_height)
            assert_equal(record["origin_age"], 0)
            assert_equal(record["payout_address"], payout_by_txid[txid])
            assert record["synthetic_txid"] is not None

        loser_reimbursement = min(self._amount(loser["base_fee"]), MAX_REIMBURSEMENT)
        assert_equal(self._amount(loser["credited_amount"]), loser_reimbursement)
        assert_equal(
            self._amount(winner["credited_amount"]),
            expected_pool - loser_reimbursement,
        )
        assert_equal(
            self._amount(winner["credited_amount"])
            + self._amount(loser["credited_amount"]),
            expected_pool,
        )

        for source_txid, record in records.items():
            synthetic = node.getshadowtransaction(record["synthetic_txid"])
            assert_equal(synthetic["base_anchor"]["blockhash"], block_hash)
            assert_equal(synthetic["pow_claim_source"]["txid"], source_txid)
            assert_equal(
                synthetic["pow_claim_source"]["disposition"],
                record["disposition"],
            )
            history = node.getshadowaddress(record["payout_address"])
            assert_equal(history["count"], 1)
            assert_equal(
                history["records"][0]["synthetic_txid"], record["synthetic_txid"]
            )

        supply = node.getshadowsupply()
        assert_equal(supply["issued_count"], 2)
        assert_equal(self._amount(supply["issued_nominal_amount"]), expected_pool)
        return page, records

    def _assert_wallet_claim(self, node, wallet, claim_txid, payout_address, synthetic_txid):
        self.wait_until(lambda: wallet.gettransaction(claim_txid)["confirmations"] > 0, timeout=30)
        assert_equal(self._is_abandoned(wallet, claim_txid), False)
        assert claim_txid not in node.getrawmempool()
        utxo = self._wait_one_quantum_utxo(wallet, payout_address)
        assert_equal(utxo["txid"], synthetic_txid)
        assert node.gettxout(utxo["txid"], utxo["vout"], False) is not None
        return utxo

    def run_test(self):
        self._set_mocktime((int(time.time()) & ~0xF) + 16)
        for node in self.nodes:
            node.get_wallet_rpc(self.default_wallet_name).staking(False)
        block_peers = [
            node.add_p2p_connection(P2PDataStore()) for node in self.nodes
        ]

        self.nodes[0].createwallet(wallet_name="contention_a", load_on_startup=True)
        self.nodes[1].createwallet(wallet_name="contention_b", load_on_startup=True)
        staker = self.nodes[0].get_wallet_rpc(self.default_wallet_name)
        claimant_a = self.nodes[0].get_wallet_rpc("contention_a")
        claimant_b = self.nodes[1].get_wallet_rpc("contention_b")
        for wallet in (staker, claimant_a, claimant_b):
            wallet.staking(False)

        staking_address = self.nodes[0].get_deterministic_priv_key().address
        claim_address_a = claimant_a.getnewaddress("claim-a", "legacy")
        claim_address_b = claimant_b.getnewaddress("claim-b", "legacy")

        self.log.info("Building a shared post-activation parent with three mature wallets")
        self.generatetoaddress(
            self.nodes[0],
            1,
            self.nodes[1].get_deterministic_priv_key().address,
        )
        for address in (staking_address, claim_address_a, claim_address_b):
            self.generatetoaddress(self.nodes[0], COINBASE_MATURITY + 2, address)
        self.sync_blocks()
        self._sync_mocktime_to_tip()
        parent_hash = self.nodes[0].getbestblockhash()
        parent_height = self.nodes[0].getblockcount()
        assert_equal(self.nodes[1].getbestblockhash(), parent_hash)
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "gold_rush")
        assert_equal(
            claimant_a.getgoldrushinfo()["competing_claim_rule_active_next_block"],
            True,
        )

        payout_a = claimant_a.getnewquantumaddress()["address"]
        payout_b = claimant_b.getnewquantumaddress()["address"]
        self.disconnect_nodes(0, 1)
        claim_a = claimant_a.sendshadowpowclaim(claim_address_a, payout_a, 500000)
        claim_b = claimant_b.sendshadowpowclaim(claim_address_b, payout_b, 500000)
        raw_a = self.nodes[0].getrawtransaction(claim_a["txid"])
        raw_b = self.nodes[1].getrawtransaction(claim_b["txid"])
        assert_equal(self.nodes[0].getrawmempool(), [claim_a["txid"]])
        assert_equal(self.nodes[1].getrawmempool(), [claim_b["txid"]])

        self.log.info("Confirming post-activation relay admits bounded competing claims")
        reject_b = self.nodes[0].testmempoolaccept([raw_b])[0]
        reject_a = self.nodes[1].testmempoolaccept([raw_a])[0]
        assert_equal(reject_b["allowed"], True)
        assert_equal(reject_a["allowed"], True)

        self.log.info("Direct PoW placement remains base data and earns no synthetic credit")
        pow_case = self.generateblock(
            self.nodes[0], staking_address, [claim_a["txid"]], sync_fun=self.no_op
        )
        pow_hash = pow_case["hash"]
        assert "proof-of-work" in self.nodes[0].getblock(pow_hash)["flags"]
        self._wait_shadowindex(self.nodes[0])
        pow_page = self.nodes[0].getshadowblock(pow_hash, 0, 10, 0, 10)
        assert_equal(pow_page["observed_pow_claim_txids"], [claim_a["txid"]])
        assert_equal(pow_page["total_payouts"], 0)
        assert_equal(self._amount(pow_page["pow_payout_total"]), Decimal(0))
        pow_summary = pow_page["pow_claim_accounting"]
        assert_equal(pow_summary["total_records"], 0)
        assert_equal(pow_summary["observed_count"], 1)
        assert_equal(pow_summary["evaluated_count"], 0)
        assert_equal(pow_summary["invalid_location_count"], 1)
        assert_equal(pow_summary["rejected_count"], 1)
        assert_equal(pow_summary["records"], [])
        assert_equal(self._quantum_utxos(claimant_a, payout_a), [])
        self.nodes[0].invalidateblock(pow_hash)
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == parent_hash, timeout=30)
        self.wait_until(lambda: claim_a["txid"] in self.nodes[0].getrawmempool(), timeout=30)
        assert_equal(self._is_abandoned(claimant_a, claim_a["txid"]), False)

        expected_pool = self._amount(claimant_a.getgoldrushinfo()["pow_jackpot"])
        assert expected_pool > MAX_REIMBURSEMENT
        self.log.info("Capturing a valid PoS template and constructing AB/BA competitors")
        template_hash, template_hex = self._mine_pos_template(staker, claim_a["txid"])
        template = self.nodes[0].getblock(template_hash, 2)
        assert_equal(template["height"], parent_height + 1)
        self.nodes[0].invalidateblock(template_hash)
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == parent_hash, timeout=30)
        self.wait_until(lambda: claim_a["txid"] in self.nodes[0].getrawmempool(), timeout=30)

        signing_wif = self.nodes[0].get_deterministic_priv_key().key
        block_ab = self._ordered_signed_pos_block(
            template_hex, [raw_a, raw_b], signing_wif
        )
        block_ba = self._ordered_signed_pos_block(
            template_hex, [raw_b, raw_a], signing_wif
        )
        block_ab.rehash()
        block_ba.rehash()
        block_ab.nFlags = 1
        block_ba.nFlags = 1
        assert block_ab.hash != block_ba.hash
        for candidate in (block_ab, block_ba):
            assert candidate.vtx[1].vin
            assert candidate.vtx[1].vout
            assert_equal(candidate.vtx[1].vout[0].nValue, 0)
            assert_equal(bytes(candidate.vtx[1].vout[0].scriptPubKey), b"")
            roundtrip = from_hex(CBlock(), candidate.serialize().hex())
            assert_equal(roundtrip.calc_merkle_root(), roundtrip.hashMerkleRoot)
            assert roundtrip.vtx[1].vin
            assert_equal(roundtrip.vtx[1].vout[0].nValue, 0)
            assert_equal(bytes(roundtrip.vtx[1].vout[0].scriptPubKey), b"")
        assert_equal([tx.hash for tx in block_ab.vtx[2:4]], [claim_a["txid"], claim_b["txid"]])
        assert_equal([tx.hash for tx in block_ba.vtx[2:4]], [claim_b["txid"], claim_a["txid"]])

        # PoS identity is carried in the negotiated block-message marker, so
        # inject the custom candidates through the ordinary P2P block path.
        block_peers[0].send_blocks_and_test(
            [block_ab], self.nodes[0], success=True, force_send=True
        )
        block_peers[1].send_blocks_and_test(
            [block_ba], self.nodes[1], success=True, force_send=True
        )
        self._wait_shadowindex(self.nodes[0])
        self._wait_shadowindex(self.nodes[1])
        assert_equal(self.nodes[0].getbestblockhash(), block_ab.hash)
        assert_equal(self.nodes[1].getbestblockhash(), block_ba.hash)

        claims = {claim_a["txid"], claim_b["txid"]}
        payouts = {claim_a["txid"]: payout_a, claim_b["txid"]: payout_b}
        page_ab, records_ab = self._assert_competing_accounting(
            self.nodes[0], block_ab.hash, expected_pool, claims, payouts
        )
        page_ba, records_ba = self._assert_competing_accounting(
            self.nodes[1], block_ba.hash, expected_pool, claims, payouts
        )
        assert_equal(
            page_ab["observed_pow_claim_txids"],
            [claim_a["txid"], claim_b["txid"]],
        )
        assert_equal(
            page_ba["observed_pow_claim_txids"],
            [claim_b["txid"], claim_a["txid"]],
        )
        assert_equal(
            self._normalized_accounting(page_ab["pow_claim_accounting"]),
            self._normalized_accounting(page_ba["pow_claim_accounting"]),
        )
        assert (
            page_ab["pow_claim_accounting"]["accounting_commitment"]
            != page_ba["pow_claim_accounting"]["accounting_commitment"]
        ), "ordered-note commitment must distinguish transaction permutations"

        utxo_ab_a = self._assert_wallet_claim(
            self.nodes[0],
            claimant_a,
            claim_a["txid"],
            payout_a,
            records_ab[claim_a["txid"]]["synthetic_txid"],
        )
        self._assert_wallet_claim(
            self.nodes[1],
            claimant_b,
            claim_b["txid"],
            payout_b,
            records_ba[claim_b["txid"]]["synthetic_txid"],
        )

        self.log.info("Extending BA forces both nodes onto one deterministic allocation")
        child_hash = self.generatetoaddress(
            self.nodes[1],
            1,
            self.nodes[1].get_deterministic_priv_key().address,
            sync_fun=self.no_op,
        )[0]
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=60)
        assert_equal(self.nodes[0].getbestblockhash(), child_hash)
        assert_equal(self.nodes[1].getbestblockhash(), child_hash)
        self._wait_shadowindex(self.nodes[0])
        self._wait_shadowindex(self.nodes[1])
        replay_page, replay_records = self._assert_competing_accounting(
            self.nodes[0], block_ba.hash, expected_pool, claims, payouts
        )
        assert_equal(
            self._normalized_accounting(replay_page["pow_claim_accounting"]),
            self._normalized_accounting(page_ab["pow_claim_accounting"]),
        )
        assert self.nodes[0].gettxout(utxo_ab_a["txid"], utxo_ab_a["vout"], False) is None
        utxo_ba_a = self._assert_wallet_claim(
            self.nodes[0],
            claimant_a,
            claim_a["txid"],
            payout_a,
            replay_records[claim_a["txid"]]["synthetic_txid"],
        )
        assert utxo_ba_a["txid"] != utxo_ab_a["txid"]
        self._assert_wallet_claim(
            self.nodes[1],
            claimant_b,
            claim_b["txid"],
            payout_b,
            replay_records[claim_b["txid"]]["synthetic_txid"],
        )

        self.log.info("Disconnect/reconsider restores AB, then BA, without duplicate wallet state")
        self.disconnect_nodes(0, 1)
        self.nodes[0].invalidateblock(block_ba.hash)
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == block_ab.hash, timeout=30)
        self._wait_shadowindex(self.nodes[0])
        restored_ab = self._wait_one_quantum_utxo(claimant_a, payout_a)
        assert_equal(restored_ab["txid"], records_ab[claim_a["txid"]]["synthetic_txid"])
        assert self.nodes[0].gettxout(utxo_ba_a["txid"], utxo_ba_a["vout"], False) is None
        self.nodes[0].reconsiderblock(block_ba.hash)
        self.wait_until(lambda: self.nodes[0].getbestblockhash() == child_hash, timeout=30)
        self._wait_shadowindex(self.nodes[0])
        restored_ba = self._wait_one_quantum_utxo(claimant_a, payout_a)
        assert_equal(restored_ba["txid"], utxo_ba_a["txid"])
        assert self.nodes[0].gettxout(utxo_ab_a["txid"], utxo_ab_a["vout"], False) is None
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=60)

        self.log.info("Restart and full reindex reproduce the same tip, records, and wallet claims")
        self.restart_node(
            0,
            extra_args=self.extra_args[0] + [f"-mocktime={self.mock_time}"],
        )
        self.restart_node(
            1,
            extra_args=self.extra_args[1]
            + ["-reindex", f"-mocktime={self.mock_time}"],
        )
        self.connect_nodes(0, 1)
        self.sync_blocks(timeout=120)
        self._wait_shadowindex(self.nodes[0])
        self._wait_shadowindex(self.nodes[1])
        assert_equal(self.nodes[0].getbestblockhash(), child_hash)
        assert_equal(self.nodes[1].getbestblockhash(), child_hash)
        assert_equal(
            self.nodes[0].getgoldrushstate()["replay_state"]["valid_for_tip"],
            True,
        )
        assert_equal(
            self.nodes[1].getgoldrushstate()["replay_state"]["valid_for_tip"],
            True,
        )
        final_page_0, final_records_0 = self._assert_competing_accounting(
            self.nodes[0], block_ba.hash, expected_pool, claims, payouts
        )
        final_page_1, final_records_1 = self._assert_competing_accounting(
            self.nodes[1], block_ba.hash, expected_pool, claims, payouts
        )
        assert_equal(
            self._normalized_accounting(final_page_0["pow_claim_accounting"]),
            self._normalized_accounting(final_page_1["pow_claim_accounting"]),
        )
        assert_equal(final_records_0, final_records_1)
        self._assert_wallet_claim(
            self.nodes[0],
            self.nodes[0].get_wallet_rpc("contention_a"),
            claim_a["txid"],
            payout_a,
            final_records_0[claim_a["txid"]]["synthetic_txid"],
        )
        self._assert_wallet_claim(
            self.nodes[1],
            self.nodes[1].get_wallet_rpc("contention_b"),
            claim_b["txid"],
            payout_b,
            final_records_1[claim_b["txid"]]["synthetic_txid"],
        )


if __name__ == "__main__":
    GoldRushPowContentionTest().main()
