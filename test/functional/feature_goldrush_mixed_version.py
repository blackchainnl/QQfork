#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run the designated v26 reference and the v30.1.1 candidate together.

v28.4.0 and v30.1.0 are started and version-checked as diagnostic builds, but
they are not compatibility authorities: both contain known consensus changes
that the v30.1.1 Gold Rush bridge deliberately removes. The normative pair is
the exact v26.2.0 reference and the candidate. It relays adversarial,
legacy-valid blocks in both directions, reorganizes both directions, and
persists the common tip across restart.
"""

from decimal import Decimal

from test_framework.address import address_to_scriptpubkey
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.key import ECKey
from test_framework.messages import COIN, COutPoint, CTransaction, CTxIn, CTxOut, from_hex
from test_framework.script import (
    CScript,
    OP_0,
    OP_DEPTH,
    OP_EQUAL,
    OP_FALSE,
    OP_NOP4,
    OP_RETURN,
    sign_input_legacy,
)
from test_framework.script_util import key_to_p2pk_script, program_to_witness_script, script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


VERSIONS = [260200, 280400, 300100, None]
EXPECTED_RPC_VERSIONS = [260200, 280400, 300100, 300101]
REFERENCE = 0
CANDIDATE = 3
GOLD_RUSH_ARGS = [
    "-shadowwhitelistheight=1",
    "-shadowgoldrushstartheight=2",
    "-shadowgoldrushblocks=500",
    "-qqgoldrushendheight=600",
    "-qqmigrationendheight=800",
]
FEE = COIN // 100
QQSPROOF = b"QQSPROOF"


class GoldRushMixedVersionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        base_args = ["-minimumchainwork=0x00", "-assumevalid=0"]
        self.extra_args = [
            list(base_args),
            list(base_args),
            base_args + GOLD_RUSH_ARGS,
            base_args + GOLD_RUSH_ARGS,
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_nodes(self):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args, versions=VERSIONS)
        self.start_nodes()

    def setup_network(self):
        self.setup_nodes()
        # Keep a direct normative link. Diagnostic nodes receive the ordinary
        # bootstrap chain, then stop before fixtures they are known to reject.
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.connect_nodes(1, REFERENCE)
        self.connect_nodes(2, REFERENCE)
        self.sync_blocks(self.nodes)

    @property
    def normative_nodes(self):
        return [self.nodes[REFERENCE], self.nodes[CANDIDATE]]

    def assert_normative_tip(self):
        tips = [node.getbestblockhash() for node in self.normative_nodes]
        assert_equal(len(set(tips)), 1)
        heights = [node.getblockcount() for node in self.normative_nodes]
        assert_equal(len(set(heights)), 1)

    def mine_and_sync(self, miner, blocks=1, nodes=None):
        address = self.nodes[CANDIDATE].get_deterministic_priv_key().address
        self.generatetoaddress(miner, blocks, address, sync_fun=self.no_op)
        self.sync_blocks(nodes or self.normative_nodes, timeout=120)

    def generate_raw_block(self, producer, transactions):
        address = self.nodes[CANDIDATE].get_deterministic_priv_key().address
        result = self.generateblock(producer, address, transactions, sync_fun=self.no_op)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        return result["hash"]

    def coinbase_utxo(self, block_hash):
        coinbase = self.nodes[CANDIDATE].getblock(block_hash, 2)["tx"][0]
        output = coinbase["vout"][0]
        return {
            "txid": coinbase["txid"],
            "vout": 0,
            "value": int(Decimal(str(output["value"])) * COIN),
            "amount": output["value"],
            "script": output["scriptPubKey"]["hex"],
        }

    def signed_coin_spend(self, coin, outputs):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]
        tx.vout = list(outputs)
        signed = self.nodes[CANDIDATE].signrawtransactionwithkey(
            tx.serialize().hex(),
            [self.nodes[CANDIDATE].get_deterministic_priv_key().key],
            [{
                "txid": coin["txid"],
                "vout": coin["vout"],
                "scriptPubKey": coin["script"],
                "amount": coin["amount"],
            }],
        )
        assert_equal(signed["complete"], True)
        return signed["hex"]

    @staticmethod
    def tx_from_outputs(prev_txid, prev_vout, prev_value, outputs, script_sig=b""):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(prev_txid, 16), prev_vout), script_sig)]
        tx.vout = list(outputs)
        assert sum(output.nValue for output in tx.vout) <= prev_value - FEE
        tx.rehash()
        return tx

    def exercise_nop4_both_directions(self, coins, change_script):
        # This script succeeds only when opcode 0xb3 retains the reference
        # client's NOP4 semantics. Reinterpreting it as OP_ISCOINSTAKE pushes
        # an extra stack item and makes OP_DEPTH 0 EQUAL false.
        redeem = CScript([OP_NOP4, OP_DEPTH, OP_0, OP_EQUAL])
        p2sh = script_to_p2sh_script(redeem)
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            funding_hex = self.signed_coin_spend(coin, [
                CTxOut(COIN, p2sh),
                CTxOut(coin["value"] - COIN - FEE, change_script),
            ])
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = self.tx_from_outputs(
                funding.hash, 0, COIN,
                [CTxOut(COIN - FEE, change_script)],
                CScript([bytes(redeem)]),
            )
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_non_strict_sighash_both_directions(self, coins, change_script):
        key = ECKey()
        key.set(b"\x11" * 32, True)
        p2pk = key_to_p2pk_script(key.get_pubkey().get_bytes())
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            funding_hex = self.signed_coin_spend(coin, [
                CTxOut(COIN, p2pk),
                CTxOut(coin["value"] - COIN - FEE, change_script),
            ])
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = self.tx_from_outputs(
                funding.hash, 0, COIN,
                [CTxOut(COIN - FEE, change_script)],
            )
            # Base type 4 uses the reference client's ALL-like legacy digest,
            # but STRICTENC rejects the otherwise valid DER signature.
            sign_input_legacy(spend, 0, p2pk, key, sighash_type=4)
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_future_witness_both_directions(self, coins, change_script):
        versions = (2, 13, 14, 15, 16)
        scripts = [program_to_witness_script(v, bytes([v]) * 32) for v in versions]
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            outputs = [CTxOut(COIN, script) for script in scripts]
            outputs.append(CTxOut(coin["value"] - len(scripts) * COIN - FEE, change_script))
            funding_hex = self.signed_coin_spend(coin, outputs)
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = CTransaction()
            spend.vin = [CTxIn(COutPoint(int(funding.hash, 16), n)) for n in range(len(scripts))]
            spend.vout = [CTxOut(len(scripts) * COIN - FEE, change_script)]
            spend.rehash()
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_shadow_lookalikes_both_directions(self, coins, change_script):
        marker = CScript([OP_FALSE, OP_RETURN, b"QQPOOL"])
        malformed = CScript([OP_RETURN, QQSPROOF + b"\x00"])
        oversized = CScript([OP_RETURN, QQSPROOF + b"\x00" * 600])
        excess = [CScript([OP_RETURN, QQSPROOF + bytes([i])]) for i in range(65)]
        scripts = [marker, malformed, malformed, oversized, *excess]
        for coin, producer in (
            (coins.pop(), self.nodes[REFERENCE]),
            (coins.pop(), self.nodes[CANDIDATE]),
        ):
            outputs = [CTxOut(0, script) for script in scripts]
            outputs.append(CTxOut(coin["value"] - FEE, change_script))
            tx_hex = self.signed_coin_spend(coin, outputs)
            self.generate_raw_block(producer, [tx_hex])

    def run_test(self):
        self.log.info("Verifying every daemon is the pinned historical/candidate build")
        for node, expected in zip(self.nodes, EXPECTED_RPC_VERSIONS):
            assert_equal(node.getnetworkinfo()["version"], expected)

        self.log.info("Bootstrapping spendable reference-produced outputs on all four builds")
        mined = self.generatetoaddress(
            self.nodes[REFERENCE],
            COINBASE_MATURITY + 20,
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            sync_fun=self.no_op,
        )
        self.sync_blocks(self.nodes, timeout=180)
        for legacy_node in self.nodes[:3]:
            self.mine_and_sync(legacy_node, nodes=self.nodes)
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=2, nodes=self.nodes)
        assert_equal(len({node.getbestblockhash() for node in self.nodes}), 1)
        assert_equal(self.nodes[2].getquantumquasarinfo()["phase"], "gold_rush")
        assert_equal(self.nodes[3].getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Stopping diagnostic builds before known split-path fixtures")
        self.stop_node(1)
        self.stop_node(2)
        coins = [self.coinbase_utxo(block_hash) for block_hash in mined[:12]]
        change_script = address_to_scriptpubkey(
            self.nodes[CANDIDATE].get_deterministic_priv_key().address
        )

        self.log.info("Crossing NOP4 discriminator blocks in both directions")
        self.exercise_nop4_both_directions(coins, change_script)
        self.log.info("Crossing legacy-valid undefined-hashtype blocks in both directions")
        self.exercise_non_strict_sighash_both_directions(coins, change_script)
        self.log.info("Creating and spending witness v2/v13/v14/v15/v16 in both directions")
        self.exercise_future_witness_both_directions(coins, change_script)
        self.log.info("Crossing marker, malformed, duplicate, oversized, and excess QQ notes")
        self.exercise_shadow_lookalikes_both_directions(coins, change_script)

        self.log.info("A longer reference branch reorganizes the candidate")
        self.disconnect_nodes(CANDIDATE, REFERENCE)
        self.mine_and_sync(self.nodes[REFERENCE], blocks=3, nodes=[self.nodes[REFERENCE]])
        reference_tip = self.nodes[REFERENCE].getbestblockhash()
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=1, nodes=[self.nodes[CANDIDATE]])
        assert self.nodes[CANDIDATE].getbestblockhash() != reference_tip
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[CANDIDATE].getbestblockhash(), reference_tip)

        self.log.info("A longer candidate branch reorganizes the reference")
        self.disconnect_nodes(CANDIDATE, REFERENCE)
        self.mine_and_sync(self.nodes[REFERENCE], blocks=1, nodes=[self.nodes[REFERENCE]])
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=3, nodes=[self.nodes[CANDIDATE]])
        candidate_tip = self.nodes[CANDIDATE].getbestblockhash()
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[REFERENCE].getbestblockhash(), candidate_tip)

        self.log.info("Restarting both normative generations preserves the common tip")
        for index in (REFERENCE, CANDIDATE):
            self.restart_node(index)
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[REFERENCE].getbestblockhash(), candidate_tip)


if __name__ == "__main__":
    GoldRushMixedVersionTest().main()
