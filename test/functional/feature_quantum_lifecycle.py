#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Drive one node through the Blackcoin 24-month lifecycle.

This test exercises the live height-authoritative phase boundaries instead of booting separate
phase-pinned nodes. It proves Gold Rush payouts stay locked through Gold Rush,
become ordinary quantum UTXOs after normal maturity, and remain spendable at
Final Lockout. It also proves legacy inputs are disabled after the deadline.
"""

from decimal import Decimal
import hashlib
import struct
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


SHADOW_WHITELIST_HEIGHT = 1
SHADOW_GOLD_RUSH_BLOCKS = 500
GOLD_RUSH_END_HEIGHT = SHADOW_WHITELIST_HEIGHT + SHADOW_GOLD_RUSH_BLOCKS
MIGRATION_END_HEIGHT = GOLD_RUSH_END_HEIGHT + 2
QUANTUM_SPEND_FEE = Decimal("0.01")
LEGACY_SPEND_FEE = Decimal("0.01")
GOLD_RUSH_PAYOUT_MARKER_DOMAIN = b"Quantum Quasar Direct Gold Rush Payout"


class QuantumLifecycleTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-staketimio=50",
            f"-shadowwhitelistheight={SHADOW_WHITELIST_HEIGHT}",
            f"-shadowgoldrushblocks={SHADOW_GOLD_RUSH_BLOCKS}",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
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

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
            if utxo.get("spendable", True)
            and utxo.get("confirmations", 0) > COINBASE_MATURITY
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
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:], "QQSPROOF claim must be a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _mine_until_phase(self, phase, address):
        node = self.nodes[0]
        for _ in range(1000):
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            info = node.getquantumquasarinfo()
            if info["phase"] == phase and (phase != "migration" or info["quantum_spend_enforcement_active"]):
                return
        raise AssertionError(f"timed out waiting for phase {phase}")

    def _get_quantum_utxos(self, wallet, address, *, min_conf=0):
        options = {"include_immature_coinbase": True}
        return wallet.listunspent(min_conf, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address, min_conf=min_conf)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address, min_conf=min_conf)[0]

    def _build_quantum_spend(self, wallet, utxo, destination):
        node = self.nodes[0]
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        assert spend_amount > 0
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        return raw, signed

    def _build_legacy_spend(self, wallet, utxo, destination):
        node = self.nodes[0]
        spend_amount = Decimal(str(utxo["amount"])) - LEGACY_SPEND_FEE
        assert spend_amount > 0
        return node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )

    def _compact_size(self, size):
        if size < 253:
            return bytes([size])
        if size <= 0xffff:
            return b"\xfd" + struct.pack("<H", size)
        if size <= 0xffffffff:
            return b"\xfe" + struct.pack("<I", size)
        return b"\xff" + struct.pack("<Q", size)

    def _goldrush_marker_outpoint(self, payout_utxo):
        serialized = (
            self._compact_size(len(GOLD_RUSH_PAYOUT_MARKER_DOMAIN))
            + GOLD_RUSH_PAYOUT_MARKER_DOMAIN
            + bytes.fromhex(payout_utxo["txid"])[::-1]
            + struct.pack("<I", payout_utxo["vout"])
        )
        digest = hashlib.sha256(hashlib.sha256(serialized).digest()).digest()
        return digest[::-1].hex(), 0

    def _assert_goldrush_marker_exists(self, payout_utxo):
        marker_txid, marker_vout = self._goldrush_marker_outpoint(payout_utxo)
        marker = self.nodes[0].gettxout(marker_txid, marker_vout, False)
        if marker is None:
            raise AssertionError(f"missing Gold Rush companion marker for {payout_utxo['txid']}:{payout_utxo['vout']}")
        assert_equal(marker["value"], 0)

    def _assert_output_lifecycle(self, wallet, utxo, state, *, synthetic,
                                 merkle_included, mature, spendable,
                                 permanently_locked=False):
        matches = [
            output for output in wallet.listunspent(
                0, 9999999, [], True, {"include_immature_coinbase": True})
            if output["txid"] == utxo["txid"] and output["vout"] == utxo["vout"]
        ]
        assert_equal(len(matches), 1)
        output = matches[0]
        assert_equal(output["spendability_state"], state)
        assert_equal(output["synthetic"], synthetic)
        assert_equal(output["merkle_included"], merkle_included)
        assert_equal(output["mature"], mature)
        assert_equal(output["ordinary_spendable"], spendable)
        assert_equal(output["spendable"], spendable and output["wallet_signable"])
        assert_equal(output["permanently_locked"], permanently_locked)
        assert_equal(Decimal(output["nominal_amount"]), Decimal(output["amount"]))
        assert_equal(
            Decimal(output["effective_amount"]) + Decimal(output["burned_amount"]),
            Decimal(output["nominal_amount"]),
        )
        return output

    def _assert_wallet_lifecycle_consistent(self, wallet, category, minimum_count):
        balances = wallet.getbalances()
        wallet_info = wallet.getwalletinfo()
        assert_equal(balances["mine"]["trusted"], balances["mine"]["lifecycle"]["ordinary_available"])
        assert_equal(wallet_info["balance"], wallet_info["lifecycle"]["ordinary_available"])
        assert_equal(wallet_info["balance"], balances["mine"]["trusted"])
        assert balances["mine"]["lifecycle"]["categories"][category]["count"] >= minimum_count
        assert wallet_info["lifecycle"]["categories"][category]["count"] >= minimum_count

    def _assert_phase_status(self, wallet, phase, *, quantum_spends_active, deadline_passed):
        node = self.nodes[0]
        info = node.getquantumquasarinfo()
        status = wallet.getmigrationstatus()
        assert_equal(info["height_boundaries_authoritative"], True)
        assert_equal(info["phase"], phase)
        assert_equal(status["phase"], phase)
        assert_equal(status["quantum_spends_active"], quantum_spends_active)
        # Retained compatibility field now means optional consolidation is available.
        assert_equal(status["goldrush_remigration_active"], quantum_spends_active)
        assert_equal(status["deadline_passed"], deadline_passed)

    def _assert_generateblock_rejects(self, rawtx, output_address, reject_reason):
        assert_raises_rpc_error(
            -25,
            f"TestBlockValidity failed: {reject_reason}",
            self.generateblock,
            self.nodes[0],
            output=output_address,
            transactions=[rawtx],
        )

    def _reconsider_tip(self, block_hash):
        node = self.nodes[0]
        node.reconsiderblock(block_hash)
        self.wait_until(lambda: node.getbestblockhash() == block_hash, timeout=30)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating mature legacy staking, claim, and lockout-test coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name="quantum_lifecycle")
        node.createwallet(wallet_name="quantum_lifecycle_staker_b")
        wallet = node.get_wallet_rpc("quantum_lifecycle")
        staker_b = node.get_wallet_rpc("quantum_lifecycle_staker_b")
        wallet.staking(False)
        staker_b.staking(False)

        staking_address = wallet.getnewaddress("", "legacy")
        staking_address_b = staker_b.getnewaddress("", "legacy")
        claim_address_a = wallet.getnewaddress("", "legacy")
        claim_address_b = wallet.getnewaddress("", "legacy")
        legacy_lockout_address = wallet.getnewaddress("", "legacy")

        self.generatetoaddress(node, 1, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, staking_address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, claim_address_a, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, claim_address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, legacy_lockout_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address_b, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        self._assert_phase_status(wallet, "gold_rush", quantum_spends_active=False, deadline_passed=False)

        legacy_lockout_utxo = wallet.listunspent(1, 9999999, [legacy_lockout_address])[0]
        claim_b_funding_utxo = wallet.listunspent(1, 9999999, [claim_address_b])[0]
        wallet.lockunspent(False, [{"txid": legacy_lockout_utxo["txid"], "vout": legacy_lockout_utxo["vout"]}])
        wallet.lockunspent(False, [{"txid": claim_b_funding_utxo["txid"], "vout": claim_b_funding_utxo["vout"]}])

        self.log.info("Mining two independent QQSPROOF payouts before Gold Rush ends")
        payout_address_a = wallet.getnewquantumaddress()["address"]
        claim_a = wallet.sendshadowpowclaim(claim_address_a, payout_address_a, 500000)
        self._mine_pos_block_with_claim(wallet, claim_a["txid"])
        payout_utxo_a = self._wait_for_quantum_utxo(wallet, payout_address_a)
        self._assert_goldrush_marker_exists(payout_utxo_a)
        immature_a = self._assert_output_lifecycle(
            wallet, payout_utxo_a, "gold_rush_synthetic_immature",
            synthetic=True, merkle_included=False, mature=False, spendable=False,
        )
        assert immature_a["earliest_spend_height"] > node.getblockcount()
        self._assert_wallet_lifecycle_consistent(wallet, "gold_rush_synthetic_immature", 1)

        payout_address_b = wallet.getnewquantumaddress()["address"]
        wallet.lockunspent(True, [{"txid": claim_b_funding_utxo["txid"], "vout": claim_b_funding_utxo["vout"]}])
        claim_b = wallet.sendshadowpowclaim(claim_address_b, payout_address_b, 500000)
        self._mine_pos_block_with_claim(staker_b, claim_b["txid"])
        payout_utxo_b = self._wait_for_quantum_utxo(wallet, payout_address_b)
        self._assert_goldrush_marker_exists(payout_utxo_b)

        self.log.info("Maturing both synthetic payouts while Gold Rush is still active")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo_a = self._wait_for_quantum_utxo(wallet, payout_address_a, min_conf=COINBASE_MATURITY + 1)
        payout_utxo_b = self._wait_for_quantum_utxo(wallet, payout_address_b, min_conf=COINBASE_MATURITY + 1)
        self._assert_phase_status(wallet, "gold_rush", quantum_spends_active=False, deadline_passed=False)
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 2)
        mature_locked_a = self._assert_output_lifecycle(
            wallet, payout_utxo_a, "gold_rush_synthetic_mature_locked",
            synthetic=True, merkle_included=False, mature=True, spendable=False,
        )
        assert mature_locked_a["earliest_spend_height"] > node.getblockcount()
        self._assert_output_lifecycle(
            wallet, payout_utxo_b, "gold_rush_synthetic_mature_locked",
            synthetic=True, merkle_included=False, mature=True, spendable=False,
        )
        self._assert_wallet_lifecycle_consistent(wallet, "gold_rush_synthetic_mature_locked", 2)
        migration_status = wallet.getmigrationstatus()
        assert_equal(migration_status["categories"]["gold_rush_synthetic_mature_locked"]["count"], 2)

        self.log.info("Gold Rush payout spends stay disabled during the legacy-compatible Gold Rush")
        migration_destination_a = wallet.getnewquantumaddress()["address"]
        _, same_goldrush_signed = self._build_quantum_spend(wallet, payout_utxo_a, payout_address_a)
        assert_equal(same_goldrush_signed["complete"], False)
        _, valid_goldrush_signed = self._build_quantum_spend(wallet, payout_utxo_a, migration_destination_a)
        assert_equal(valid_goldrush_signed["complete"], False)

        self.log.info("Crossing the Gold Rush end boundary into the migration window")
        # Use a legacy coinbase destination for the final Gold Rush blocks.
        migration_mining_address = wallet.getnewaddress("", "legacy")
        self._mine_until_phase("migration", migration_mining_address)
        self._assert_phase_status(wallet, "migration", quantum_spends_active=True, deadline_passed=False)
        assert_equal(node.getgoldrushstate()["replay_state"]["valid_for_tip"], True)

        self.log.info("Gold Rush payouts are ordinary quantum UTXOs during migration")
        migration_payout_a = self._assert_output_lifecycle(
            wallet, payout_utxo_a, "migration_spendable_direct_quantum",
            synthetic=True, merkle_included=False, mature=True, spendable=True,
        )
        assert_equal(migration_payout_a["earliest_spend_height"], node.getblockcount() + 1)
        self._assert_output_lifecycle(
            wallet, payout_utxo_b, "migration_spendable_direct_quantum",
            synthetic=True, merkle_included=False, mature=True, spendable=True,
        )
        self._assert_wallet_lifecycle_consistent(wallet, "migration_spendable_direct_quantum", 2)
        valid_raw, valid_signed = self._build_quantum_spend(wallet, payout_utxo_a, migration_destination_a)
        assert_equal(valid_signed["complete"], True)
        valid_accept = node.testmempoolaccept([valid_signed["hex"]])[0]
        if not valid_accept["allowed"]:
            raise AssertionError(f"ordinary Gold Rush payout spend rejected: {valid_accept}")
        spend_txid = node.sendrawtransaction(valid_signed["hex"])
        spend_block_hash = self.generatetoaddress(node, 1, migration_mining_address, sync_fun=self.no_op)[0]
        assert spend_txid in node.getblock(spend_block_hash)["tx"]
        assert node.gettxout(payout_utxo_a["txid"], payout_utxo_a["vout"], False) is None
        assert node.gettxout(payout_utxo_b["txid"], payout_utxo_b["vout"], False) is not None
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 0)
        assert_equal([
            output for output in wallet.listunspent(
                0, 9999999, [], True, {"include_immature_coinbase": True})
            if output["txid"] == payout_utxo_a["txid"] and output["vout"] == payout_utxo_a["vout"]
        ], [])

        self.log.info("Same-address payout spends are valid; no remigration covenant exists")
        _, same_signed = self._build_quantum_spend(wallet, payout_utxo_b, payout_address_b)
        assert_equal(same_signed["complete"], True)
        same_accept = node.testmempoolaccept([same_signed["hex"]])[0]
        if not same_accept["allowed"]:
            raise AssertionError(f"same-address payout spend rejected: {same_accept}")

        self.log.info("Crossing the migration deadline into final lockout")
        final_mining_address = wallet.getnewquantumaddress()["address"]
        self._mine_until_phase("final_lockout", final_mining_address)
        final_tip = node.getbestblockhash()
        self._assert_phase_status(wallet, "final_lockout", quantum_spends_active=True, deadline_passed=True)
        assert_equal(node.getgoldrushstate()["replay_state"]["valid_for_tip"], True)
        wallet.lockunspent(True, [{"txid": legacy_lockout_utxo["txid"], "vout": legacy_lockout_utxo["vout"]}])
        self._assert_output_lifecycle(
            wallet, legacy_lockout_utxo, "final_locked_legacy",
            synthetic=False, merkle_included=True, mature=True, spendable=False,
            permanently_locked=True,
        )
        self._assert_wallet_lifecycle_consistent(wallet, "final_locked_legacy", 1)

        self.log.info("Reorging below the deadline preserves ordinary payout spendability")
        node.invalidateblock(final_tip)
        self._assert_phase_status(wallet, "migration", quantum_spends_active=True, deadline_passed=False)
        assert_equal(node.getgoldrushstate()["replay_state"]["valid_for_tip"], True)
        self._assert_output_lifecycle(
            wallet, legacy_lockout_utxo, "spendable_legacy",
            synthetic=False, merkle_included=True, mature=True, spendable=True,
        )
        reorg_migration_destination = wallet.getnewquantumaddress()["address"]
        _, reorg_migration_signed = self._build_quantum_spend(wallet, payout_utxo_b, reorg_migration_destination)
        assert_equal(reorg_migration_signed["complete"], True)
        reorg_migration_accept = node.testmempoolaccept([reorg_migration_signed["hex"]])[0]
        if not reorg_migration_accept["allowed"]:
            raise AssertionError(f"ordinary payout spend rejected after deadline reorg: {reorg_migration_accept}")
        self._reconsider_tip(final_tip)
        self._assert_phase_status(wallet, "final_lockout", quantum_spends_active=True, deadline_passed=True)
        assert_equal(node.getgoldrushstate()["replay_state"]["valid_for_tip"], True)
        self._assert_output_lifecycle(
            wallet, legacy_lockout_utxo, "final_locked_legacy",
            synthetic=False, merkle_included=True, mature=True, spendable=False,
            permanently_locked=True,
        )

        self.log.info("Lifecycle classification survives wallet restart")
        restart_time = self.mock_time + 32
        self.restart_node(0, extra_args=self.extra_args[0] + [f"-mocktime={restart_time}", "-staking=0"])
        node = self.nodes[0]
        node.loadwallet("quantum_lifecycle")
        wallet = node.get_wallet_rpc("quantum_lifecycle")
        self._set_mocktime(restart_time)
        self._assert_phase_status(wallet, "final_lockout", quantum_spends_active=True, deadline_passed=True)
        assert_equal(node.getgoldrushstate()["replay_state"]["valid_for_tip"], True)
        self._assert_output_lifecycle(
            wallet, legacy_lockout_utxo, "final_locked_legacy",
            synthetic=False, merkle_included=True, mature=True, spendable=False,
            permanently_locked=True,
        )
        self._assert_output_lifecycle(
            wallet, payout_utxo_b, "migration_spendable_direct_quantum",
            synthetic=True, merkle_included=False, mature=True, spendable=True,
        )

        self.log.info("Legacy inputs are rejected after final lockout")
        legacy_destination = wallet.getnewquantumaddress()["address"]
        legacy_hex = self._build_legacy_spend(wallet, legacy_lockout_utxo, legacy_destination)
        legacy_accept = node.testmempoolaccept([legacy_hex])[0]
        assert_equal(legacy_accept["allowed"], False)
        assert_equal(legacy_accept["reject-reason"], "legacy-spend-disabled")
        self._assert_generateblock_rejects(legacy_hex, final_mining_address, "legacy-spend-disabled")

        self.log.info("An untouched Gold Rush payout remains spendable after Final Lockout")
        final_destination = wallet.getnewquantumaddress()["address"]
        _, final_signed = self._build_quantum_spend(wallet, payout_utxo_b, final_destination)
        assert_equal(final_signed["complete"], True)
        final_accept = node.testmempoolaccept([final_signed["hex"]])[0]
        if not final_accept["allowed"]:
            raise AssertionError(f"Gold Rush payout rejected after Final Lockout: {final_accept}")
        final_spend_txid = node.sendrawtransaction(final_signed["hex"])
        final_spend_block = self.generatetoaddress(node, 1, final_mining_address, sync_fun=self.no_op)[0]
        assert final_spend_txid in node.getblock(final_spend_block)["tx"]


if __name__ == "__main__":
    QuantumLifecycleTest().main()
