#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet QQSPROOF single-flight and exceptional broadcast cleanup.

Two concurrent sendshadowpowclaim callers must produce one wallet transaction.
If broadcast throws after wallet persistence, both the RPC and built-in miner
must abandon the inactive claim, release its input, and clear single-flight so
the same process can immediately attempt another claim.
"""

from decimal import Decimal
from threading import Thread
import time
from urllib.parse import quote

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


GOLD_RUSH_END_TIME = 2_000_000_000
QQSPROOF_HEX = "51515350524f4f46"
MANUAL_WALLET = "pow_claim_manual"
BUILTIN_WALLET = "pow_claim_builtin"


class GoldRushPowClaimSingleFlightTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
        ]
        self.extra_args = [[
            *self.base_args,
            "-qqshadowpowclaimsubmissiondelaymillis=1500",
        ]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def _set_mocktime(self, timestamp):
        self.mock_time = timestamp
        self.nodes[0].setmocktime(timestamp)

    def _bump_mocktime(self, seconds):
        self._set_mocktime(self.mock_time + seconds)

    def _load_wallet(self, name):
        node = self.nodes[0]
        if name not in node.listwallets():
            node.loadwallet(name)
        return node.get_wallet_rpc(name)

    @staticmethod
    def _is_abandoned(wallet, txid):
        return any(detail.get("abandoned", False) for detail in wallet.gettransaction(txid)["details"])

    def _claim_txids(self, wallet):
        return {
            entry["txid"]
            for entry in wallet.listtransactions("*", 1000, 0, True)
            if entry.get("comment") == "PoW Claim"
        }

    def _abandoned_claim_txids(self, wallet):
        return {txid for txid in self._claim_txids(wallet) if self._is_abandoned(wallet, txid)}

    def _extract_proof(self, wallet, txid):
        decoded = self.nodes[0].decoderawtransaction(wallet.gettransaction(txid)["hex"])
        for output in decoded["vout"]:
            parts = output["scriptPubKey"].get("asm", "").split()
            if len(parts) >= 2 and parts[0] == "OP_RETURN" and parts[1].lower().startswith(QQSPROOF_HEX.lower()):
                return parts[1]
        raise AssertionError(f"wallet claim {txid} has no decodable QQSPROOF payload")

    def _wait_for_new_abandoned_claim(self, wallet, before, timeout=180):
        self.wait_until(lambda: len(self._abandoned_claim_txids(wallet) - before) > 0, timeout=timeout)
        return sorted(self._abandoned_claim_txids(wallet) - before)[0]

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)

        node.createwallet(wallet_name=MANUAL_WALLET)
        node.createwallet(wallet_name=BUILTIN_WALLET)
        manual = node.get_wallet_rpc(MANUAL_WALLET)
        builtin = node.get_wallet_rpc(BUILTIN_WALLET)
        manual.staking(False)
        builtin.staking(False)
        manual_address = manual.getnewaddress("claim-input", "legacy")
        builtin_address = builtin.getnewaddress("claim-input", "legacy")
        funding_address = default_wallet.getnewaddress("claim-test-funding", "legacy")

        self.log.info("Funding independent manual and built-in claim wallets")
        self.generatetoaddress(node, 1, manual_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, builtin_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 5, funding_address, sync_fun=self.no_op)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 1)

        self.log.info("Two concurrent RPC callers create at most one claim")
        manual_payout = manual.getnewquantumaddress("single-flight-payout")["address"]
        first_results = []
        first_errors = []

        def submit_first_claim():
            wallet_url = f"{node.url}/wallet/{quote(MANUAL_WALLET, safe='')}"
            rpc = get_rpc_proxy(wallet_url, 91, timeout=300, coveragedir=node.coverage_dir)
            try:
                first_results.append(rpc.sendshadowpowclaim(manual_address, manual_payout, 500000))
            except Exception as error:
                first_errors.append(str(error))

        first_thread = Thread(target=submit_first_claim, name="first-pow-claim", daemon=True)
        with node.wait_for_debug_log([b"Gold Rush PoW claim submission test barrier reached"], timeout=20):
            first_thread.start()
        assert_raises_rpc_error(
            -4,
            "Another Gold Rush PoW claim submission is already in progress for this wallet",
            manual.sendshadowpowclaim,
            manual_address,
            manual_payout,
            1,
        )
        first_thread.join(timeout=300)
        assert not first_thread.is_alive(), "first sendshadowpowclaim caller did not finish"
        assert_equal(first_errors, [])
        assert_equal(len(first_results), 1)
        first_txid = first_results[0]["txid"]
        assert first_txid in node.getrawmempool()
        assert_equal(self._claim_txids(manual), {first_txid})

        self.log.info("Advancing the parent expires the one live claim and releases its input")
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: self._is_abandoned(manual, first_txid), timeout=20)
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)

        self.log.info("An injected RPC broadcast exception abandons the persisted claim")
        fault_args = [*self.base_args, "-qqshadowpowbroadcastthrow=1", f"-mocktime={self.mock_time}"]
        self.restart_node(0, extra_args=fault_args)
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        manual = self._load_wallet(MANUAL_WALLET)
        builtin = self._load_wallet(BUILTIN_WALLET)

        manual_fault_payout = manual.getnewquantumaddress("fault-payout")["address"]
        before_manual_fault = self._abandoned_claim_txids(manual)
        assert_raises_rpc_error(
            -4,
            "PoW Claim transaction broadcast raised an exception: injected Gold Rush PoW broadcast exception",
            manual.sendshadowpowclaim,
            manual_address,
            manual_fault_payout,
            500000,
        )
        first_fault_txid = self._wait_for_new_abandoned_claim(manual, before_manual_fault)
        first_fault_proof = self._extract_proof(manual, first_fault_txid)
        assert first_fault_txid not in node.getrawmempool()
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)

        self.log.info("The RPC exception releases single-flight without a restart")
        self._bump_mocktime(1)
        before_second_fault = self._abandoned_claim_txids(manual)
        assert_raises_rpc_error(
            -4,
            "PoW Claim transaction broadcast raised an exception: injected Gold Rush PoW broadcast exception",
            manual.sendshadowpowclaim,
            manual_address,
            manual_fault_payout,
            1,
            101,
            first_fault_proof,
        )
        self._wait_for_new_abandoned_claim(manual, before_second_fault)
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)

        self.log.info("The built-in miner uses the same guard and exception cleanup")
        before_builtin_fault = self._abandoned_claim_txids(builtin)
        started = builtin.setpowmining(True, 1, 100)
        builtin_payout = started["payout_address"]
        try:
            builtin_fault_txid = self._wait_for_new_abandoned_claim(builtin, before_builtin_fault)
        finally:
            builtin.setpowmining(False)
        assert_equal(builtin.getpowmininginfo()["claims_submitted"], 0)
        assert builtin_fault_txid not in node.getrawmempool()
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 1)

        self.log.info("A manual caller can enter immediately after the built-in exception")
        builtin_fault_proof = self._extract_proof(builtin, builtin_fault_txid)
        self._bump_mocktime(1)
        before_builtin_manual_fault = self._abandoned_claim_txids(builtin)
        assert_raises_rpc_error(
            -4,
            "PoW Claim transaction broadcast raised an exception: injected Gold Rush PoW broadcast exception",
            builtin.sendshadowpowclaim,
            builtin_address,
            builtin_payout,
            1,
            101,
            builtin_fault_proof,
        )
        self._wait_for_new_abandoned_claim(builtin, before_builtin_manual_fault)
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 1)

        self.log.info("Removing the fault hook lets the same input and proof submit normally")
        self.restart_node(0, extra_args=[*self.base_args, f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        manual = self._load_wallet(MANUAL_WALLET)
        self._bump_mocktime(1)
        recovered = manual.sendshadowpowclaim(
            manual_address,
            manual_fault_payout,
            1,
            102,
            first_fault_proof,
        )
        assert recovered["txid"] in node.getrawmempool()
        assert_equal(self._is_abandoned(manual, recovered["txid"]), False)

        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: self._is_abandoned(manual, recovered["txid"]), timeout=20)
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)
        assert_equal(Decimal(str(manual.getbalances()["mine"]["trusted"])), Decimal("10000"))


if __name__ == "__main__":
    GoldRushPowClaimSingleFlightTest().main()
