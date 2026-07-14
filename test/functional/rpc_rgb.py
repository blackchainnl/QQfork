#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.messages import CTransaction

class RGBRPCTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-qqgoldrushendtime=1"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _seal(self, tag, amount=None):
        seal = {"txid": f"{tag:064x}", "vout": 0}
        if amount is not None:
            seal["amount"] = amount
        return seal

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Testing decodergbcommitment...")

        # Test empty transaction (has no outputs, so no RGB commitments)
        tx = CTransaction()
        tx_hex = tx.serialize().hex()
        assert_equal(node.decodergbcommitment(tx_hex), [])

        state_hash = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        raw_rgb = node.createrawtransaction([], [{"rgb_commitment": state_hash}])
        decoded_rgb = node.decoderawtransaction(raw_rgb)
        script_pub_key = decoded_rgb["vout"][0]["scriptPubKey"]
        assert_equal(script_pub_key["type"], "rgb_commitment")
        assert_equal(script_pub_key["rgb_state_hash"], state_hash)
        decoded_commitment = node.decodergbcommitment(script_pub_key["hex"])
        assert_equal(decoded_commitment["state_hash"], state_hash)

        self.log.info("Testing verifyrgbconsignment fixed-supply validation...")
        consignment = {
            "genesis": {
                "ticker": "QQT",
                "name": "Blackcoin Test Asset",
                "total_supply": 1000,
                "allocations": [self._seal(1, 1000)],
            },
            "transitions": [{
                "inputs": [self._seal(1)],
                "outputs": [self._seal(2, 400), self._seal(3, 600)],
            }],
        }
        rgb_validation = node.verifyrgbconsignment(consignment)
        assert_equal(rgb_validation["valid"], True)
        assert_equal(rgb_validation["current_supply"], 1000)
        assert_equal(rgb_validation["unspent_assignments"], 2)
        assert_equal(rgb_validation["errors"], [])
        assert_equal(len(rgb_validation["transition_ids"]), 1)

        raw_anchor = node.createrawtransaction([], [{"rgb_commitment": rgb_validation["anchor_commitment"]}])
        decoded_anchor = node.decoderawtransaction(raw_anchor)
        anchor_spk = decoded_anchor["vout"][0]["scriptPubKey"]
        assert_equal(anchor_spk["rgb_state_hash"], rgb_validation["anchor_commitment"])
        assert_equal(node.decodergbcommitment(anchor_spk["hex"])["state_hash"], rgb_validation["anchor_commitment"])

        self.log.info("Testing wallet funding preserves RGB commitment anchors...")
        self.generatetoaddress(node, 101, node.getnewaddress(), sync_fun=self.no_op)
        funded_anchor = node.fundrawtransaction(raw_anchor)
        funded_decoded = node.decoderawtransaction(funded_anchor["hex"])
        funded_rgb_outputs = [
            out for out in funded_decoded["vout"]
            if out["scriptPubKey"]["type"] == "rgb_commitment"
        ]
        assert_equal(len(funded_rgb_outputs), 1)
        assert_equal(funded_rgb_outputs[0]["scriptPubKey"]["rgb_state_hash"], rgb_validation["anchor_commitment"])
        signed_anchor = node.signrawtransactionwithwallet(funded_anchor["hex"])
        assert_equal(signed_anchor["complete"], True)
        assert_equal(node.testmempoolaccept([signed_anchor["hex"]])[0]["allowed"], True)

        self.log.info("Testing scoped RGB transfer-anchor commitments...")
        full_history = {
            "genesis": {
                "ticker": "RQS",
                "name": "Blackcoin Scoped Anchor",
                "total_supply": 300,
                "allocations": [self._seal(10, 100), self._seal(20, 200)],
            },
            "transitions": [
                {
                    "inputs": [self._seal(20)],
                    "outputs": [self._seal(40, 200)],
                },
                {
                    "inputs": [self._seal(10)],
                    "outputs": [self._seal(30, 100)],
                },
            ],
        }
        full_history_validation = node.verifyrgbconsignment(full_history)
        assert_equal(full_history_validation["valid"], True)
        assert_equal(len(full_history_validation["transition_ids"]), 2)
        assert_equal(full_history_validation["anchor_commitment"], full_history_validation["consignment_anchor_commitment"])
        scoped_transition_id = full_history_validation["transition_ids"][1]
        scoped_history_validation = node.verifyrgbconsignment(full_history, [scoped_transition_id])
        assert_equal(scoped_history_validation["valid"], True)
        assert_equal(scoped_history_validation["anchor_commitment"], full_history_validation["anchor_commitment"])
        assert_equal(scoped_history_validation["consignment_anchor_commitment"], full_history_validation["anchor_commitment"])
        assert_equal(scoped_history_validation["anchor_transition_ids"], [scoped_transition_id])
        assert scoped_history_validation["transfer_anchor_commitment"] != full_history_validation["anchor_commitment"]
        scoped_anchor = node.createrawtransaction([], [{"rgb_commitment": scoped_history_validation["transfer_anchor_commitment"]}])
        scoped_anchor_spk = node.decoderawtransaction(scoped_anchor)["vout"][0]["scriptPubKey"]
        assert_equal(scoped_anchor_spk["rgb_state_hash"], scoped_history_validation["transfer_anchor_commitment"])

        inflated = {
            "genesis": consignment["genesis"],
            "transitions": [{
                "inputs": [self._seal(1)],
                "outputs": [self._seal(2, 1001)],
            }],
        }
        inflated_validation = node.verifyrgbconsignment(inflated)
        assert_equal(inflated_validation["valid"], False)
        assert "transition input and output amounts do not balance" in inflated_validation["errors"]

        # Test malformed hex
        assert_raises_rpc_error(-22, "TX decode failed", node.decodergbcommitment, "zzz")

        self.log.info("Testing decodeeutxospend...")
        # Test empty transaction (has no inputs, so no EUTXO spends)
        assert_equal(node.decodeeutxospend(tx_hex), [])

        # Test malformed hex
        assert_raises_rpc_error(-22, "TX decode failed", node.decodeeutxospend, "zzz")

        self.log.info("Testing EUTXO v15 construction fails closed...")
        disabled_message = "EUTXO v15 is disabled in v30.1.1 because it has no quantum ownership authorization"
        commitment = {
            "txid": "00" * 32,
            "vout": 0,
            "datum": "01",
            "validator": "52885187",
        }
        assert_raises_rpc_error(
            -8,
            disabled_message,
            node.createrawtransaction,
            [],
            [{"eutxo": {"amount": 1, "datum": "01", "validator": "52885187"}}],
        )
        assert_raises_rpc_error(
            -8,
            disabled_message,
            node.createeutxospend,
            {**commitment, "redeemer": "02"},
            [{node.getnewaddress(): 1}],
        )
        assert_raises_rpc_error(
            -8,
            disabled_message,
            node.createeutxotransition,
            commitment,
            {"amount": 1, "datum": "0b0c", "validator": "52885187"},
        )

        self.log.info("Tests successful!")

if __name__ == '__main__':
    RGBRPCTest().main()
