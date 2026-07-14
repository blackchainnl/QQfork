#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Prove future-witness behavior on both sides of the Gold Rush boundary."""

from decimal import Decimal

from test_framework.address import key_to_p2pkh, program_to_witness
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair
from test_framework.script_util import key_to_p2pkh_script


GOLD_RUSH_END_HEIGHT = COINBASE_MATURITY + 5
MIGRATION_END_HEIGHT = GOLD_RUSH_END_HEIGHT + 50
SPLIT_AMOUNT = Decimal("0.1")
FUTURE_AMOUNT = Decimal("0.02")
FEE = Decimal("0.001")


class QuantumActivationBoundaryTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=2",
            "-vbparams=taproot:-2:0",
            f"-shadowgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _signed_witness_creation(self, wallet, utxo, version, program, outputs=1,
                                 quantum_only=False):
        node = self.nodes[0]
        destination = program_to_witness(version, program)
        value = Decimal(str(utxo["amount"]))
        if quantum_only:
            witness_amount = value - FEE
            result_outputs = [{destination: witness_amount}]
        else:
            witness_amount = FUTURE_AMOUNT * outputs
            change = value - witness_amount - FEE
            assert change > 0
            result_outputs = [
                {destination: witness_amount},
                {wallet.getnewaddress("change", "legacy"): change},
            ]
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            result_outputs,
        )
        # Bypass wallet output policy only for this consensus-boundary fixture;
        # the legacy input itself remains normally signed and fully valid.
        signed = node.signrawtransactionwithkey(
            raw,
            [utxo["privkey"]],
            [{"txid": utxo["txid"], "vout": utxo["vout"],
              "scriptPubKey": utxo["scriptPubKey"], "amount": utxo["amount"]}],
        )
        assert_equal(signed["complete"], True)
        decoded = node.decoderawtransaction(signed["hex"])
        witness_vouts = [
            vout for vout in decoded["vout"]
            if vout["scriptPubKey"].get("address") == destination
        ]
        assert_equal(len(witness_vouts), 1)
        return signed["hex"], decoded["txid"], witness_vouts, destination

    def _future_spend(self, txid, vout, destination, remainder_destination=None):
        outputs = [{destination: FUTURE_AMOUNT - FEE}]
        if remainder_destination is not None:
            outputs.append({remainder_destination: FUTURE_AMOUNT})
        return self.nodes[0].createrawtransaction(
            [{"txid": txid, "vout": vout}],
            outputs,
        )

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        wallet.staking(False)
        mining_address = wallet.getnewaddress("mining", "legacy")

        self.generatetoaddress(node, COINBASE_MATURITY + 1, mining_address, sync_fun=self.no_op)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Creating independent legacy inputs for boundary fixtures")
        split_keys = [generate_keypair(wif=True) for _ in range(20)]
        split_addresses = [key_to_p2pkh(pubkey) for _, pubkey in split_keys]
        split_txid = wallet.sendmany("", {address: SPLIT_AMOUNT for address in split_addresses})
        split_block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        assert split_txid in node.getblock(split_block)["tx"]
        while node.getblockcount() < GOLD_RUSH_END_HEIGHT - 1:
            self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT - 1)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        split_tx = next(tx for tx in node.getblock(split_block, 2)["tx"] if tx["txid"] == split_txid)
        key_by_address = {
            address: (privkey, pubkey)
            for address, (privkey, pubkey) in zip(split_addresses, split_keys)
        }
        split_utxos = []
        for vout in split_tx["vout"]:
            address = vout["scriptPubKey"].get("address")
            if address not in key_by_address:
                continue
            privkey, pubkey = key_by_address[address]
            split_utxos.append({
                "txid": split_txid,
                "vout": vout["n"],
                "amount": vout["value"],
                "privkey": privkey,
                "scriptPubKey": key_to_p2pkh_script(pubkey).hex(),
            })
        assert len(split_utxos) >= 18

        self.log.info("The last Gold Rush block preserves legacy acceptance of future witness outputs")
        pre_g_transactions = []
        pre_g_cases = (
            (1, bytes([1]) * 32),
            (2, bytes([2]) * 32),
            (13, bytes([13]) * 32),
            (14, bytes([14]) * 32),
            (15, bytes([15]) * 32),
            (16, bytes([16]) * 32),
            (14, bytes([14]) * 33),
            (16, bytes([16]) * 33),
        )
        for utxo, (version, program) in zip(split_utxos[:8], pre_g_cases):
            parent_hex, _, _, _ = self._signed_witness_creation(wallet, utxo, version, program)
            policy = node.testmempoolaccept([parent_hex])[0]
            if version == 1:
                assert_equal(policy["allowed"], True)
            else:
                assert_equal(policy["allowed"], False)
                assert_equal(policy["reject-reason"], "quantum-output-premature")
            pre_g_transactions.append(parent_hex)

        final_goldrush = self.generateblock(node, mining_address, pre_g_transactions)["hash"]
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT)
        assert_equal(node.getbestblockhash(), final_goldrush)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")

        self.log.info("The immutable inventory classifies every last-G witness outpoint")
        records = []
        offset = 0
        inventory_identity = None
        while True:
            page = node.getquantumwitnessinventory("utxos", offset, 2, 1)
            assert_equal(page["schema"], "blackcoin.quantum.witness_inventory.v1")
            assert_equal(page["bestblock"], final_goldrush)
            assert_equal(page["height"], GOLD_RUSH_END_HEIGHT)
            assert_equal(page["coverage"]["snapshot_current_utxos_exact"], True)
            assert_equal(page["coverage"]["snapshot_tip_still_active"], True)
            assert_equal(page["coverage"]["snapshot_utxo_commitment_exact"], True)
            identity = (
                page["height"], page["bestblock"],
                page["utxo_snapshot"]["commitment"],
                page["utxo_snapshot"]["txouts"],
            )
            if inventory_identity is None:
                inventory_identity = identity
                assert_equal(page["total_records"], 7)
                assert_equal(page["current_utxos"]["total"]["count"], 7)
            else:
                assert_equal(identity, inventory_identity)
            records.extend(page["records"])
            if page["next_offset"] is None:
                break
            assert_equal(page["next_offset"], offset + len(page["records"]))
            offset = page["next_offset"]

        assert_equal(len(records), 7)
        assert_equal(len({(record["txid"], record["vout"]) for record in records}), 7)
        assert_equal({record["origin_phase"] for record in records}, {"gold_rush"})
        assert_equal({record["origin_group"] for record in records}, {"pre_migration_window"})
        classifications = sorted(
            (record["witness_version"], record["bridge_handling"])
            for record in records
        )
        assert_equal(classifications, sorted([
            (2, "unknown_or_malformed_witness_program_requires_explicit_review"),
            (13, "unknown_or_malformed_witness_program_requires_explicit_review"),
            (14, "recognized_quantum_cold_stake"),
            (14, "unknown_or_malformed_witness_program_requires_explicit_review"),
            (15, "recognized_eutxo"),
            (16, "recognized_direct_quantum"),
            (16, "unknown_or_malformed_witness_program_requires_explicit_review"),
        ]))
        txoutset = node.gettxoutsetinfo("muhash")
        assert_equal(txoutset["height"], inventory_identity[0])
        assert_equal(txoutset["bestblock"], inventory_identity[1])
        assert_equal(txoutset["muhash"], inventory_identity[2])
        assert_equal(txoutset["txouts"], inventory_identity[3])

        self.log.info("G+1 accepts exact v14/v16 outputs and keeps v15 disabled")
        active_exact = []
        for utxo, version in zip(split_utxos[8:10], (14, 16)):
            tx_hex, _, _, _ = self._signed_witness_creation(wallet, utxo, version, bytes([0x44 + version]) * 32)
            policy = node.testmempoolaccept([tx_hex])[0]
            assert_equal(policy["allowed"], True)
            active_exact.append(tx_hex)

        v15_hex, _, _, _ = self._signed_witness_creation(
            wallet, split_utxos[10], 15, bytes([0x53]) * 32
        )
        v15_policy = node.testmempoolaccept([v15_hex])[0]
        assert_equal(v15_policy["allowed"], False)
        assert_equal(v15_policy["reject-reason"], "eutxo-output-disabled")
        assert_raises_rpc_error(
            -25,
            "eutxo-output-disabled",
            self.generateblock,
            node,
            mining_address,
            [v15_hex],
        )

        active_invalid = [
            (2, bytes([2]) * 32),
            (13, bytes([13]) * 32),
            (14, bytes([14]) * 33),
            (15, bytes([15]) * 31),
            (16, bytes([16]) * 33),
        ]
        for utxo, (version, program) in zip(split_utxos[11:16], active_invalid):
            tx_hex, _, _, _ = self._signed_witness_creation(wallet, utxo, version, program)
            policy = node.testmempoolaccept([tx_hex])[0]
            assert_equal(policy["allowed"], False)
            assert_equal(policy["reject-reason"], "unknown-quantum-witness-output")
            assert_raises_rpc_error(
                -25,
                "unknown-quantum-witness-output",
                self.generateblock,
                node,
                mining_address,
                [tx_hex],
            )

        first_migration = self.generateblock(node, mining_address, active_exact)["hash"]
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT + 1)
        assert_equal(node.getbestblockhash(), first_migration)

        self.log.info("Height M is the last block that can fund v16 from a legacy input")
        while node.getblockcount() < MIGRATION_END_HEIGHT - 1:
            self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")
        last_migration_hex, _, _, _ = self._signed_witness_creation(
            wallet, split_utxos[16], 16, bytes([0x61]) * 32,
            quantum_only=True,
        )
        last_migration_policy = node.testmempoolaccept([last_migration_hex])[0]
        assert_equal(last_migration_policy["allowed"], True)
        last_migration = self.generateblock(
            node, mining_address, [last_migration_hex]
        )["hash"]
        assert_equal(node.getblockcount(), MIGRATION_END_HEIGHT)
        assert_equal(node.getbestblockhash(), last_migration)
        assert_equal(node.getquantumquasarinfo()["phase"], "final_lockout")

        self.log.info("Height M+1 rejects the same legacy-to-v16 funding path")
        post_migration_hex, _, _, _ = self._signed_witness_creation(
            wallet, split_utxos[17], 16, bytes([0x62]) * 32,
            quantum_only=True,
        )
        post_migration_policy = node.testmempoolaccept([post_migration_hex])[0]
        assert_equal(post_migration_policy["allowed"], False)
        assert_equal(post_migration_policy["reject-reason"], "legacy-spend-disabled")
        first_final_address = wallet.getnewquantumaddress()["address"]
        assert_raises_rpc_error(
            -25,
            "legacy-spend-disabled",
            self.generateblock,
            node,
            first_final_address,
            [post_migration_hex],
        )
        first_final = self.generateblock(node, first_final_address, [])["hash"]
        assert_equal(node.getblockcount(), MIGRATION_END_HEIGHT + 1)
        assert_equal(node.getbestblockhash(), first_final)
        assert_equal(node.getquantumquasarinfo()["phase"], "final_lockout")

        self.log.info("A reorg across the boundary flips the same rules in both directions")
        node.invalidateblock(final_goldrush)
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT - 1)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        node.reconsiderblock(final_goldrush)
        assert_equal(node.getbestblockhash(), first_final)
        assert_equal(node.getquantumquasarinfo()["phase"], "final_lockout")


if __name__ == "__main__":
    QuantumActivationBoundaryTest().main()
