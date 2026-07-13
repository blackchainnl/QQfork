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

    def _signed_witness_creation(self, wallet, utxo, version, program, outputs=1):
        node = self.nodes[0]
        destination = program_to_witness(version, program)
        value = Decimal(str(utxo["amount"]))
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

        self.log.info("The last Gold Rush block preserves legacy acceptance of unknown witness outputs")
        pre_g_transactions = []
        for utxo, version in zip(split_utxos[:6], (1, 2, 13, 14, 15, 16)):
            program = bytes([version]) * 32
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

        self.log.info("G+1 accepts exact v14/v16 outputs and keeps v15 disabled")
        active_exact = []
        for utxo, version in zip(split_utxos[6:8], (14, 16)):
            tx_hex, _, _, _ = self._signed_witness_creation(wallet, utxo, version, bytes([0x44 + version]) * 32)
            active_exact.append(tx_hex)

        v15_hex, _, _, _ = self._signed_witness_creation(
            wallet, split_utxos[8], 15, bytes([0x53]) * 32
        )
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
        for utxo, (version, program) in zip(split_utxos[8:13], active_invalid):
            tx_hex, _, _, _ = self._signed_witness_creation(wallet, utxo, version, program)
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

        self.log.info("A reorg across the boundary flips the same rules in both directions")
        node.invalidateblock(final_goldrush)
        assert_equal(node.getblockcount(), GOLD_RUSH_END_HEIGHT - 1)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        node.reconsiderblock(final_goldrush)
        assert_equal(node.getbestblockhash(), first_migration)
        assert_equal(node.getquantumquasarinfo()["phase"], "migration")


if __name__ == "__main__":
    QuantumActivationBoundaryTest().main()
