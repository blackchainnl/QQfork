#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Gold Rush base-block compatibility regression coverage.

Internal shadow markers intentionally use legacy-valid OP_RETURN shapes. Local
policy must reject user lookalikes, while consensus must continue accepting a
base block containing one and must not treat it as internal shadow state.
"""

from decimal import Decimal
import time

from test_framework.address import key_to_p2pkh, program_to_witness
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import CTransaction, from_hex
from test_framework.script import CScript, OP_FALSE, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet_util import generate_keypair
from test_framework.script_util import key_to_p2pkh_script


GOLD_RUSH_END_TIME = 2_000_000_000
MARKER_POOL_HEX = "5151504f4f4c"  # QQPOOL


class GoldRushLegacyCompatTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(self.default_wallet_name)
        wallet.staking(False)
        mocktime = (int(time.time()) & ~0xf) + 16
        node.setmocktime(mocktime)

        mining_address = wallet.getnewaddress("mining", "legacy")
        change_address = wallet.getnewaddress("marker-change", "legacy")
        witness_fixtures = {}
        for version in (2, 13, 14, 15, 16):
            witness_privkey, witness_pubkey = generate_keypair(wif=True)
            witness_address = key_to_p2pkh(witness_pubkey)
            witness_block = self.generatetoaddress(node, 1, witness_address, sync_fun=self.no_op)[0]
            witness_txid = node.getblock(witness_block)["tx"][0]
            witness_value = node.getblock(witness_block, 2)["tx"][0]["vout"][0]["value"]
            witness_fixtures[version] = {
                "privkey": witness_privkey,
                "txid": witness_txid,
                "value": witness_value,
                "script": key_to_p2pkh_script(witness_pubkey).hex(),
            }
        self.generatetoaddress(node, COINBASE_MATURITY + 2, mining_address, sync_fun=self.no_op)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        utxos = wallet.listunspent(COINBASE_MATURITY, 9999999)
        marker_utxo = utxos[0]
        self.log.info("Policy gates every witness version above v1 during Gold Rush")
        witness_transactions = {}
        for version in (2, 13, 14, 15, 16):
            fixture = witness_fixtures[version]
            destination = program_to_witness(version, bytes([version]) * 32)
            witness_change = Decimal(str(fixture["value"])) - Decimal("1.01")
            witness_raw = node.createrawtransaction(
                [{"txid": fixture["txid"], "vout": 0}],
                [{destination: Decimal("1")}, {change_address: witness_change}],
            )
            # The wallet intentionally refuses to sign premature future-witness
            # outputs. Use the explicit legacy input key so this fixture reaches
            # direct-block consensus without weakening wallet safeguards.
            witness_signed = node.signrawtransactionwithkey(
                witness_raw,
                [fixture["privkey"]],
                [{"txid": fixture["txid"], "vout": 0, "scriptPubKey": fixture["script"], "amount": fixture["value"]}],
            )
            assert_equal(witness_signed["complete"], True)
            witness_accept = node.testmempoolaccept([witness_signed["hex"]])[0]
            assert_equal(witness_accept["allowed"], False)
            assert_equal(witness_accept["reject-reason"], "quantum-output-premature")
            witness_transactions[version] = witness_signed["hex"]

        self.log.info("Direct blocks preserve legacy unknown-witness acceptance through Gold Rush")
        for version, witness_hex in witness_transactions.items():
            block_hash = self.generateblock(node, mining_address, [witness_hex])["hash"]
            block = node.getblock(block_hash, 2)
            assert_equal(witness_transactions[version], node.getrawtransaction(block["tx"][1]))

        change = Decimal(str(marker_utxo["amount"])) - Decimal("0.01")
        raw = node.createrawtransaction(
            [{"txid": marker_utxo["txid"], "vout": marker_utxo["vout"]}],
            [{"data": MARKER_POOL_HEX}, {change_address: change}],
        )
        marker_tx = from_hex(CTransaction(), raw)
        marker_tx.vout[0].scriptPubKey = CScript([OP_FALSE, OP_RETURN, bytes.fromhex(MARKER_POOL_HEX)])
        signed = wallet.signrawtransactionwithwallet(marker_tx.serialize().hex())
        assert_equal(signed["complete"], True)
        marker_txid = node.decoderawtransaction(signed["hex"])["txid"]

        self.log.info("Policy rejects a user-created internal-marker lookalike")
        mempool = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(mempool["allowed"], False)
        assert_equal(mempool["reject-reason"], "shadow-marker-output")

        self.log.info("Gold Rush consensus still accepts the legacy-valid base block")
        block_hash = self.generateblock(node, mining_address, [signed["hex"]])["hash"]
        block = node.getblock(block_hash, 2)
        assert marker_txid in [tx["txid"] for tx in block["tx"]]
        assert_equal(node.getbestblockhash(), block_hash)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")


if __name__ == "__main__":
    GoldRushLegacyCompatTest().main()
