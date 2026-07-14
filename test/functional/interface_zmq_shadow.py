#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test deterministic shadow-ledger ZMQ deltas across restart and reorg."""

from copy import deepcopy
from decimal import Decimal
import json
import struct
import time

from test_framework.blockfilter import bip158_relevant_scriptpubkeys
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, p2p_port


try:
    import zmq
except ImportError:
    pass


GOLD_RUSH_END_TIME = 2_000_000_000
QUANTUM_SPEND_FEE = Decimal("0.01")


class ShadowSubscriber:
    def __init__(self, context, address):
        self.socket = context.socket(zmq.SUB)
        self.socket.setsockopt(zmq.SUBSCRIBE, b"shadow")
        self.socket.setsockopt(zmq.RCVTIMEO, 5_000)
        self.socket.connect(address)
        self.next_sequence = None

    def reset_sequence(self):
        self.next_sequence = None

    def receive(self):
        topic, body, sequence = self.socket.recv_multipart()
        assert_equal(topic, b"shadow")
        assert_equal(len(sequence), 4)
        current_sequence = struct.unpack("<I", sequence)[0]
        if self.next_sequence is not None:
            assert_equal(current_sequence, self.next_sequence)
        self.next_sequence = current_sequence + 1
        return json.loads(body.decode("utf-8"))

    def receive_until(self, blockhash, event_name="shadow.block.connected"):
        while True:
            event = self.receive()
            if event["blockhash"] == blockhash and event["event"] == event_name:
                return event

    def assert_empty(self, timeout_ms=500):
        previous_timeout = self.socket.getsockopt(zmq.RCVTIMEO)
        self.socket.setsockopt(zmq.RCVTIMEO, timeout_ms)
        try:
            self.socket.recv_multipart()
        except zmq.error.Again:
            return
        finally:
            self.socket.setsockopt(zmq.RCVTIMEO, previous_timeout)
        raise AssertionError("unexpected shadow notification")


class ShadowZMQTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.zmq_address = f"tcp://127.0.0.1:{p2p_port(self.num_nodes + 1)}"
        self.common_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushstartheight=20",
            "-shadowgoldrushblocks=10",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]
        self.shadow_args = self.common_args + [
            "-shadowindex=1",
            "-blockfilterindex=1",
            f"-zmqpubshadow={self.zmq_address}",
        ]
        self.extra_args = [self.shadow_args]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_py3_zmq()
        self.skip_if_no_bitcoind_zmq()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds=16):
        self._set_mocktime(self.mock_time + seconds)

    def _sync_mocktime_to_tip(self):
        tip_time = self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["time"]
        self._set_mocktime((tip_time & ~0xF) + 16)

    def _wait_index_synced(self):
        node = self.nodes[0]

        def synced():
            index = node.getindexinfo().get("shadowindex", {})
            return (
                index.get("synced", False)
                and index.get("best_block_height", node.getblockcount()) == node.getblockcount()
            )

        self.wait_until(synced, timeout=60)

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9_999_999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs
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
                blockhash = node.getbestblockhash()
                block = node.getblock(blockhash, 2)
                assert "proof-of-stake" in block["flags"]
                assert claim_txid in [tx["txid"] for tx in block["tx"]][2:]
                return blockhash
            except AssertionError as error:
                last_error = error
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _wait_for_quantum_utxo(self, wallet, address):
        def outputs():
            return wallet.listunspent(
                0, 9_999_999, [address], True, {"include_immature_coinbase": True}
            )

        self.wait_until(lambda: len(outputs()) == 1, timeout=30)
        return outputs()[0]

    def _advance_to_migration(self):
        self._set_mocktime(GOLD_RUSH_END_TIME + 16)
        for _ in range(12):
            self.generatetoaddress(
                self.nodes[0], 1, self.nodes[0].get_deterministic_priv_key().address
            )
            self._bump_mocktime(16)
        self._wait_index_synced()
        assert_equal(self.nodes[0].getquantumquasarinfo()["phase"], "migration")

    def _build_quantum_spend(self, wallet, utxo, destination):
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        raw = self.nodes[0].createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        return self.nodes[0].signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )

    @staticmethod
    def _without_direction(event):
        comparable = deepcopy(event)
        comparable.pop("event")
        return comparable

    def _assert_event_envelope(self, event, blockhash):
        assert_equal(event["schema"], "blackcoin.shadow.event.v1")
        assert_equal(event["blockhash"], blockhash)
        assert_equal(event["synthetic"], True)
        assert_equal(event["merkle_included"], False)
        assert_equal(event["units"]["display"], "BLK")
        assert_equal(event["units"]["atomic"], "satoshi")
        assert_equal(event["units"]["atomic_encoding"], "base-10 string")
        assert event["credit_count"] + event["spend_count"] <= 4096
        assert len(json.dumps(event, separators=(",", ":")).encode("utf-8")) <= 16 * 1024 * 1024

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Rejecting shadow notifications without the persisted shadow index")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=self.common_args + [f"-zmqpubshadow={self.zmq_address}"],
            expected_msg="-zmqpubshadow requires -shadowindex=1",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(0, self.shadow_args)
        node = self.nodes[0]

        context = zmq.Context()
        subscriber = ShadowSubscriber(context, self.zmq_address)
        try:
            self._set_mocktime((int(time.time()) & ~0xF) + 16)
            time.sleep(0.2)

            node.get_wallet_rpc(self.default_wallet_name).staking(False)
            node.createwallet(wallet_name="shadow_zmq")
            wallet = node.get_wallet_rpc("shadow_zmq")
            wallet.staking(False)
            staking_address = wallet.getnewaddress("", "legacy")
            claim_address = wallet.getnewaddress("", "legacy")

            self.generatetoaddress(node, 1, staking_address)
            self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address)
            self.generatetoaddress(node, COINBASE_MATURITY + 2, claim_address)
            self._sync_mocktime_to_tip()
            self._wait_index_synced()
            subscriber.receive_until(node.getbestblockhash())
            assert_equal(node.getzmqnotifications(), [
                {"type": "pubshadow", "address": self.zmq_address, "hwm": 1000}
            ])

            self.log.info("Receiving an exact synthetic-credit block delta")
            payout_address = wallet.getnewquantumaddress()["address"]
            claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500_000)
            claim_blockhash = self._mine_pos_block_with_claim(wallet, claim["txid"])
            self._wait_index_synced()
            claim_event = subscriber.receive_until(claim_blockhash)
            self._assert_event_envelope(claim_event, claim_blockhash)
            assert_equal(claim_event["event"], "shadow.block.connected")
            assert_equal(claim_event["previousblockhash"], node.getblockheader(claim_blockhash)["previousblockhash"])
            assert_equal(claim_event["credit_count"], 1)
            assert_equal(claim_event["spend_count"], 0)

            payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
            credit = claim_event["credits"][0]
            assert_equal(credit["synthetic_txid"], payout_utxo["txid"])
            assert_equal(credit["vout"], payout_utxo["vout"])
            assert_equal(credit["address"], payout_address)
            assert_equal(credit["mode"], "pow")
            assert_equal(credit["pow_claim_source"]["txid"], claim["txid"])
            assert_equal(credit["pow_claim_source"]["disposition"], "winner")
            expected_atomic = str(int(Decimal(str(payout_utxo["amount"])) * 100_000_000))
            assert_equal(credit["nominal_amount_atomic"], expected_atomic)
            assert payout_utxo["txid"] not in node.getblock(claim_blockhash)["tx"]
            assert bytes.fromhex(credit["scriptPubKey"]) not in bip158_relevant_scriptpubkeys(
                node, claim_blockhash
            )
            node.syncwithvalidationinterfacequeue()
            assert node.getblockfilter(claim_blockhash, "basic")["filter"]

            self.log.info("Disconnecting and reconnecting a credit produces exact inverse deltas")
            node.invalidateblock(claim_blockhash)
            disconnected_claim = subscriber.receive_until(
                claim_blockhash, "shadow.block.disconnected"
            )
            assert_equal(
                self._without_direction(disconnected_claim),
                self._without_direction(claim_event),
            )
            node.reconsiderblock(claim_blockhash)
            reconnected_claim = subscriber.receive_until(claim_blockhash)
            assert_equal(
                self._without_direction(reconnected_claim),
                self._without_direction(claim_event),
            )

            self.log.info("Receiving an exact synthetic-spend block delta")
            self.generatetoaddress(
                node, COINBASE_MATURITY, node.get_deterministic_priv_key().address
            )
            self._sync_mocktime_to_tip()
            matured_utxo = self._wait_for_quantum_utxo(wallet, payout_address)
            self._advance_to_migration()
            next_quantum = wallet.getnewquantumaddress()["address"]
            signed = self._build_quantum_spend(wallet, matured_utxo, next_quantum)
            assert_equal(signed["complete"], True)
            spend_txid = node.sendrawtransaction(signed["hex"])
            spend_blockhash = self.generatetoaddress(
                node, 1, node.get_deterministic_priv_key().address
            )[0]
            self._wait_index_synced()
            spend_event = subscriber.receive_until(spend_blockhash)
            self._assert_event_envelope(spend_event, spend_blockhash)
            assert_equal(spend_event["credit_count"], 0)
            assert_equal(spend_event["spend_count"], 1)
            spend = spend_event["spends"][0]
            assert_equal(spend["synthetic_txid"], payout_utxo["txid"])
            assert_equal(spend["vout"], payout_utxo["vout"])
            assert_equal(spend["spending_txid"], spend_txid)
            assert_equal(spend["address"], payout_address)
            assert_equal(spend["nominal_amount_atomic"], expected_atomic)

            self.log.info("Restarting emits no historical replay and preserves reorg deltas")
            self.restart_node(0, extra_args=self.shadow_args + [f"-mocktime={self.mock_time}"])
            node = self.nodes[0]
            subscriber.reset_sequence()
            self._wait_index_synced()
            subscriber.assert_empty()
            restarted_supply = node.getshadowsupply()
            assert_equal(restarted_supply["bestblock"], spend_blockhash)
            assert_equal(restarted_supply["spent_count"], 1)
            assert_equal(restarted_supply["unspent_count"], 0)
            time.sleep(0.2)

            child_hashes = []
            for _ in range(3):
                child_hash = self.generatetoaddress(
                    node, 1, node.get_deterministic_priv_key().address
                )[0]
                child_hashes.append(child_hash)
                try:
                    subscriber.receive_until(child_hash)
                    break
                except zmq.error.Again:
                    continue
            else:
                raise AssertionError("shadow publisher did not recover after restart")
            self._wait_index_synced()

            node.invalidateblock(spend_blockhash)
            disconnected_events = [
                subscriber.receive()
                for _ in range(len(child_hashes) + 1)
            ]
            assert_equal(
                [event["event"] for event in disconnected_events],
                ["shadow.block.disconnected"] * (len(child_hashes) + 1),
            )
            assert_equal(
                [event["blockhash"] for event in disconnected_events],
                list(reversed(child_hashes)) + [spend_blockhash],
            )
            assert_equal(
                self._without_direction(disconnected_events[-1]),
                self._without_direction(spend_event),
            )
            assert node.getbestblockhash() != spend_blockhash

            node.reconsiderblock(spend_blockhash)
            reconnected = [subscriber.receive() for _ in range(len(child_hashes) + 1)]
            assert_equal(
                [event["event"] for event in reconnected],
                ["shadow.block.connected"] * (len(child_hashes) + 1),
            )
            assert_equal(
                [event["blockhash"] for event in reconnected],
                [spend_blockhash] + child_hashes,
            )
            assert_equal(
                self._without_direction(reconnected[0]),
                self._without_direction(spend_event),
            )
        finally:
            context.destroy(linger=None)


if __name__ == "__main__":
    ShadowZMQTest().main()
