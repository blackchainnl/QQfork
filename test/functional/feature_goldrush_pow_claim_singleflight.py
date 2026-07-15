#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise wallet QQSPROOF single-flight and exceptional broadcast quarantine.

Two concurrent sendshadowpowclaim callers must produce one wallet transaction.
If a claim leaves the mempool or broadcast throws after wallet persistence,
the wallet must quarantine it and keep its input reserved because a peer copy
can still confirm. Generic manual abandonment is deliberately refused, and the
wallet must not create an automatic fee-paying conflicting self-spend.
"""

from decimal import Decimal
from threading import Thread
import time
from urllib.parse import quote

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy


GOLD_RUSH_END_TIME = 2_000_000_000
MANUAL_WALLET = "pow_claim_manual"
BUILTIN_WALLET = "pow_claim_builtin"
POLICY_WALLET = "pow_claim_policy"
POLICY_LOCK_WALLET = "pow_claim_policy_lock"
BUILTIN_RACE_WALLET = "pow_claim_builtin_race"
TIE_WALLET = "pow_claim_tie"
FAULT_WALLET = "pow_claim_fault"
BOUNDARY_WALLET = "pow_claim_boundary"
LIVE_FEE_VALUES = (Decimal("0.991"), Decimal("501.747137"), Decimal("969.818832"))


class GoldRushPowClaimSingleFlightTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            "-allowunsafequantumkeyrpc=1",
            # This fixture exercises PoW-claim wallet serialization. Keep
            # background PoS from advancing the tip while a boundary claim is
            # deliberately paused across restart.
            "-staking=0",
            "-txindex=1",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            # Keep this focused on historical QQP2 single-flight behavior,
            # but use a reachable boundary inside the compressed Gold Rush.
            # Post-boundary QQP4 behavior is exercised by the contention and
            # index-boundary tests.
            "-shadowcompetingclaimsheight=501",
            "-shadowqqp4height=501",
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

    def _quarantined_claim_txids(self, wallet):
        mempool = set(self.nodes[0].getrawmempool())
        return {
            txid
            for txid in self._claim_txids(wallet)
            if txid not in mempool and not self._is_abandoned(wallet, txid)
        }

    def _claim_input(self, txid):
        decoded = self.nodes[0].decoderawtransaction(self.nodes[0].getrawtransaction(txid))
        assert_equal(len(decoded["vin"]), 1)
        return {"txid": decoded["vin"][0]["txid"], "vout": decoded["vin"][0]["vout"]}

    def _fund_live_fee_inputs(self, source_wallet, target_wallet, target_address, funding_address):
        for amount in LIVE_FEE_VALUES:
            source_wallet.sendtoaddress(target_address, amount)
        self.generatetoaddress(self.nodes[0], 1, funding_address, sync_fun=self.no_op)
        utxos = target_wallet.listunspent(1, 9999999, [target_address])
        assert_equal(sorted(Decimal(str(utxo["amount"])) for utxo in utxos), sorted(LIVE_FEE_VALUES))
        return {
            Decimal(str(utxo["amount"])): {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in utxos
        }

    def _wait_for_new_quarantined_claim(self, wallet, before, timeout=180):
        self.wait_until(
            lambda: len(self._quarantined_claim_txids(wallet) - before) > 0,
            timeout=timeout,
        )
        return sorted(self._quarantined_claim_txids(wallet) - before)[0]

    def _assert_generic_abandon_rejected(self, wallet, txid):
        assert_equal(self._is_abandoned(wallet, txid), False)
        assert_raises_rpc_error(
            -5,
            "Transaction not eligible for abandonment",
            wallet.abandontransaction,
            txid,
        )
        assert_equal(self._is_abandoned(wallet, txid), False)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)

        node.createwallet(wallet_name=MANUAL_WALLET)
        node.createwallet(wallet_name=BUILTIN_WALLET)
        node.createwallet(wallet_name=POLICY_WALLET)
        node.createwallet(wallet_name=POLICY_LOCK_WALLET)
        node.createwallet(wallet_name=BUILTIN_RACE_WALLET)
        node.createwallet(wallet_name=TIE_WALLET)
        node.createwallet(wallet_name=FAULT_WALLET)
        node.createwallet(wallet_name=BOUNDARY_WALLET)
        manual = node.get_wallet_rpc(MANUAL_WALLET)
        builtin = node.get_wallet_rpc(BUILTIN_WALLET)
        policy = node.get_wallet_rpc(POLICY_WALLET)
        policy_lock = node.get_wallet_rpc(POLICY_LOCK_WALLET)
        builtin_race = node.get_wallet_rpc(BUILTIN_RACE_WALLET)
        tie_wallet = node.get_wallet_rpc(TIE_WALLET)
        fault = node.get_wallet_rpc(FAULT_WALLET)
        boundary = node.get_wallet_rpc(BOUNDARY_WALLET)
        for wallet in (manual, builtin, policy, policy_lock, builtin_race, tie_wallet, fault, boundary):
            wallet.staking(False)
        manual_address = manual.getnewaddress("claim-input", "legacy")
        builtin_address = builtin.getnewaddress("claim-input", "legacy")
        policy_address = policy.getnewaddress("claim-input", "legacy")
        policy_lock_address = policy_lock.getnewaddress("claim-input", "legacy")
        builtin_race_address = builtin_race.getnewaddress("claim-input", "legacy")
        tie_address = tie_wallet.getnewaddress("claim-input", "legacy")
        fault_address = fault.getnewaddress("claim-input", "legacy")
        boundary_address = boundary.getnewaddress("claim-input", "legacy")
        funding_address = default_wallet.getnewaddress("claim-test-funding", "legacy")

        self.log.info("Funding independent manual and built-in claim wallets")
        self.generatetoaddress(node, 1, manual_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, builtin_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, fault_address, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, boundary_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 5, funding_address, sync_fun=self.no_op)
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 1)
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 1)

        self.log.info("Funding a second confirmed boundary-wallet fee input for quarantine-gate coverage")
        default_wallet.sendtoaddress(boundary_address, Decimal("1.25000000"))
        self.generatetoaddress(node, 1, funding_address, sync_fun=self.no_op)

        self.log.info("Funding live-scale same-script fee inputs for deterministic policy coverage")
        policy_inputs = self._fund_live_fee_inputs(default_wallet, policy, policy_address, funding_address)
        policy_lock_inputs = self._fund_live_fee_inputs(default_wallet, policy_lock, policy_lock_address, funding_address)
        builtin_race_inputs = self._fund_live_fee_inputs(default_wallet, builtin_race, builtin_race_address, funding_address)

        self.log.info("Manual claims choose the smallest sufficient same-script input")
        policy_payout = policy.getnewquantumaddress("policy-payout")["address"]
        policy_claim = policy.sendshadowpowclaim(policy_address, policy_payout, 500000)
        assert_equal(self._claim_input(policy_claim["txid"]), policy_inputs[LIVE_FEE_VALUES[0]])
        # The live claim creates an unconfirmed same-script change output. It
        # must never become the next claim's fee input: claim chains can be
        # invalidated with their parent and bypass the confirmed-input rule.
        assert any(
            utxo["txid"] == policy_claim["txid"] and utxo["vout"] == 0
            for utxo in policy.listunspent(0, 9999999, [policy_address])
        )

        self.log.info("A selected input locked at the test barrier cannot fall back to a larger coin")
        policy_before_race = self._claim_txids(policy)
        expected_policy_race_input = policy_inputs[LIVE_FEE_VALUES[1]]
        policy_race_errors = []

        def submit_policy_race():
            wallet_url = f"{node.url}/wallet/{quote(POLICY_WALLET, safe='')}"
            rpc = get_rpc_proxy(wallet_url, 92, timeout=300, coveragedir=node.coverage_dir)
            try:
                rpc.sendshadowpowclaim(policy_address, policy_payout, 500000)
            except Exception as error:
                policy_race_errors.append(str(error))

        policy_race_thread = Thread(target=submit_policy_race, name="policy-input-race", daemon=True)
        with node.wait_for_debug_log([b"Gold Rush PoW claim submission test barrier reached"], timeout=20):
            policy_race_thread.start()
        assert_equal(policy.lockunspent(False, [policy_inputs[LIVE_FEE_VALUES[1]]]), True)
        policy_race_thread.join(timeout=300)
        assert not policy_race_thread.is_alive(), "policy input race caller did not finish"
        assert_equal(len(policy_race_errors), 1)
        assert "Selected Gold Rush PoW claim input" in policy_race_errors[0]
        assert (
            f"COutPoint({expected_policy_race_input['txid'][:10]}, "
            f"{expected_policy_race_input['vout']})" in policy_race_errors[0]
        )
        assert "changed while grinding" in policy_race_errors[0]
        assert_equal(self._claim_txids(policy), policy_before_race)
        assert_equal(policy.lockunspent(True, [policy_inputs[LIVE_FEE_VALUES[1]]]), True)

        # Historical QQP2 policy permits one live proof in the global mempool.
        # Clear that slot explicitly before exercising the independent
        # pre-locked-input wallet, and prove the expired policy claim remains
        # quarantined rather than being abandoned or spending its input again.
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: policy_claim["txid"] not in node.getrawmempool(), timeout=20)
        self.wait_until(lambda: policy_claim["txid"] in self._quarantined_claim_txids(policy), timeout=20)
        self._assert_generic_abandon_rejected(policy, policy_claim["txid"])

        self.log.info("A coin already locked before selection is skipped deterministically")
        policy_lock_payout = policy_lock.getnewquantumaddress("policy-lock-payout")["address"]
        assert_equal(policy_lock.lockunspent(False, [policy_lock_inputs[LIVE_FEE_VALUES[0]]]), True)
        locked_small_claim = policy_lock.sendshadowpowclaim(
            policy_lock_address, policy_lock_payout, 500000
        )
        assert_equal(
            self._claim_input(locked_small_claim["txid"]),
            policy_lock_inputs[LIVE_FEE_VALUES[1]],
        )
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: locked_small_claim["txid"] not in node.getrawmempool(), timeout=20)
        self._assert_generic_abandon_rejected(policy_lock, locked_small_claim["txid"])
        assert_equal(policy_lock.lockunspent(True, [policy_lock_inputs[LIVE_FEE_VALUES[0]]]), True)

        self.log.info("Equal-value candidates use stable COutPoint ordering")
        tie_value = Decimal("1.25000000")
        default_wallet.sendtoaddress(tie_address, tie_value)
        default_wallet.sendtoaddress(tie_address, tie_value)
        self.generatetoaddress(node, 1, funding_address, sync_fun=self.no_op)
        tie_inputs = tie_wallet.listunspent(1, 9999999, [tie_address])
        assert_equal(len(tie_inputs), 2)
        expected_tie_input = min(
            ({"txid": utxo["txid"], "vout": utxo["vout"]} for utxo in tie_inputs),
            key=lambda outpoint: (bytes.fromhex(outpoint["txid"])[::-1], outpoint["vout"]),
        )
        tie_payout = tie_wallet.getnewquantumaddress("tie-payout")["address"]
        tie_claim = tie_wallet.sendshadowpowclaim(tie_address, tie_payout, 500000)
        assert_equal(self._claim_input(tie_claim["txid"]), expected_tie_input)
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: tie_claim["txid"] not in node.getrawmempool(), timeout=20)
        self._assert_generic_abandon_rejected(tie_wallet, tie_claim["txid"])

        self.log.info("The built-in miner waits for a new tip after its exact input becomes unavailable")
        builtin_race_before = self._claim_txids(builtin_race)
        with node.wait_for_debug_log([b"Gold Rush PoW claim submission test barrier reached"], timeout=180):
            started = builtin_race.setpowmining(True, 1, 100, True)
            assert started["created_payout_key"]
        with node.wait_for_debug_log([b"is no longer spendable; retry after the next tip"], timeout=20):
            assert_equal(builtin_race.lockunspent(False, [builtin_race_inputs[LIVE_FEE_VALUES[0]]]), True)
        try:
            self.wait_until(lambda: builtin_race.getpowmininginfo()["state"] == "ready", timeout=10)
            time.sleep(2)
            assert_equal(self._claim_txids(builtin_race), builtin_race_before)
            assert_equal(builtin_race.getpowmininginfo()["claims_submitted"], 0)
        finally:
            builtin_race.setpowmining(False)
        assert_equal(builtin_race.lockunspent(True, [builtin_race_inputs[LIVE_FEE_VALUES[0]]]), True)

        self.generateblock(node, output=funding_address, transactions=[])
        builtin_race.setpowmining(True, 1, 100)
        try:
            self.wait_until(lambda: len(self._claim_txids(builtin_race) - builtin_race_before) == 1, timeout=180)
            builtin_race_claim = sorted(self._claim_txids(builtin_race) - builtin_race_before)[0]
        finally:
            builtin_race.setpowmining(False)
        assert_equal(self._claim_input(builtin_race_claim), builtin_race_inputs[LIVE_FEE_VALUES[0]])
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: builtin_race_claim not in node.getrawmempool(), timeout=20)
        self._assert_generic_abandon_rejected(builtin_race, builtin_race_claim)

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

        self.log.info("Advancing the parent quarantines the historical QQP2 claim")
        self.generateblock(node, output=funding_address, transactions=[])
        self.wait_until(lambda: first_txid not in node.getrawmempool(), timeout=20)
        assert_equal(self._is_abandoned(manual, first_txid), False)
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 0)
        self._assert_generic_abandon_rejected(manual, first_txid)
        assert_equal(len(manual.listunspent(1, 9999999, [manual_address])), 0)

        self.log.info("An injected RPC broadcast exception quarantines the persisted claim")
        fault_args = [*self.base_args, "-qqshadowpowbroadcastthrow=1", f"-mocktime={self.mock_time}"]
        self.restart_node(0, extra_args=fault_args)
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        manual = self._load_wallet(MANUAL_WALLET)
        builtin = self._load_wallet(BUILTIN_WALLET)
        fault = self._load_wallet(FAULT_WALLET)

        fault_payout = fault.getnewquantumaddress("fault-payout")["address"]
        before_fault = self._quarantined_claim_txids(fault)
        assert_raises_rpc_error(
            -4,
            "PoW Claim transaction broadcast raised an exception: injected Gold Rush PoW broadcast exception",
            fault.sendshadowpowclaim,
            fault_address,
            fault_payout,
            500000,
        )
        first_fault_txid = self._wait_for_new_quarantined_claim(fault, before_fault)
        assert first_fault_txid not in node.getrawmempool()
        assert_equal(self._is_abandoned(fault, first_fault_txid), False)
        assert_equal(len(fault.listunspent(1, 9999999, [fault_address])), 0)
        self._assert_generic_abandon_rejected(fault, first_fault_txid)

        self.log.info("The built-in miner uses the same guard and exception cleanup")
        before_builtin_fault = self._quarantined_claim_txids(builtin)
        started = builtin.setpowmining(True, 1, 100, True)
        assert started["created_payout_key"]
        builtin_payout = started["payout_address"]
        try:
            builtin_fault_txid = self._wait_for_new_quarantined_claim(builtin, before_builtin_fault)
        finally:
            builtin.setpowmining(False)
        assert_equal(builtin.getpowmininginfo()["claims_submitted"], 0)
        assert builtin_fault_txid not in node.getrawmempool()
        assert_equal(self._is_abandoned(builtin, builtin_fault_txid), False)
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 0)
        self._assert_generic_abandon_rejected(builtin, builtin_fault_txid)
        assert_equal(len(builtin.listunspent(1, 9999999, [builtin_address])), 0)

        self.log.info("Quarantine survives restart and does not reactivate a peer-visible exact-input claim")
        self.restart_node(0, extra_args=[*self.base_args, f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        fault = self._load_wallet(FAULT_WALLET)
        self._assert_generic_abandon_rejected(fault, first_fault_txid)
        assert_equal(len(fault.listunspent(1, 9999999, [fault_address])), 0)

        self.log.info("A pre-boundary QQP2 claim crosses into QQP4 policy without releasing its input")
        activation_height = 501
        pre_boundary_tip = activation_height - 2
        assert node.getblockcount() < pre_boundary_tip
        while node.getblockcount() < pre_boundary_tip:
            self.generateblock(node, output=funding_address, transactions=[])
        assert_equal(node.getblockcount(), pre_boundary_tip)
        assert_equal(node.getshadowpowwork()["height"], activation_height - 1)
        assert_equal(node.getshadowpowwork()["proof_version"], 2)

        boundary = self._load_wallet(BOUNDARY_WALLET)
        assert_equal(len(boundary.listunspent(1, 9999999, [boundary_address])), 2)
        boundary_payout = boundary.getnewquantumaddress("PoW - Quantum Claim Address")["address"]
        boundary_claim = boundary.sendshadowpowclaim(
            boundary_address, boundary_payout, 500_000
        )
        boundary_claim_txid = boundary_claim["txid"]
        boundary_claim_input = self._claim_input(boundary_claim_txid)
        boundary_raw = node.getrawtransaction(boundary_claim_txid)
        boundary_decoded = node.decoderawtransaction(boundary_raw)
        assert any(
            "51515032" in output["scriptPubKey"]["hex"]
            for output in boundary_decoded["vout"]
        )
        assert boundary_claim_txid in node.getrawmempool()

        # Deliberately omit the last QQP2 claim at its intended height. At the
        # resulting tip, the next-block policy is QQP4-only and the old
        # transaction is terminal. Its fee input remains unavailable. The
        # other confirmed UTXO stays visible, but the quarantine gate must
        # prevent it from funding another claim while the old proof resolves.
        self.generateblock(node, output=funding_address, transactions=[])
        assert_equal(node.getblockcount(), activation_height - 1)
        assert_equal(node.getshadowpowwork()["height"], activation_height)
        assert_equal(node.getshadowpowwork()["proof_version"], 4)
        rejected = node.testmempoolaccept([boundary_raw])[0]
        assert_equal(rejected["allowed"], False)
        assert_equal(rejected["reject-reason"], "shadow-proof-version")
        assert_equal(len(boundary.listunspent(1, 9999999, [boundary_address])), 1)

        # Startup repair must retain the obsolete proof and its input. A
        # second confirmed fee UTXO exists, but neither RPC nor the built-in
        # miner may consume it while the first claim remains quarantined.
        self.restart_node(0, extra_args=[*self.base_args, f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        boundary = self._load_wallet(BOUNDARY_WALLET)
        self._assert_generic_abandon_rejected(boundary, boundary_claim_txid)
        remaining_boundary_inputs = boundary.listunspent(1, 9999999, [boundary_address])
        assert_equal(len(remaining_boundary_inputs), 1)
        assert_equal(
            {"txid": remaining_boundary_inputs[0]["txid"], "vout": remaining_boundary_inputs[0]["vout"]}
            != boundary_claim_input,
            True,
        )
        before_second_claim = self._claim_txids(boundary)
        assert_raises_rpc_error(
            -4,
            "wallet will not create a second fee-input claim",
            boundary.sendshadowpowclaim,
            boundary_address,
            boundary_payout,
            500_000,
        )
        assert_equal(self._claim_txids(boundary), before_second_claim)

        started = boundary.setpowmining(True, 1, 100)
        assert_equal(started["created_payout_key"], False)
        assert_equal(started["payout_address"], boundary_payout)
        try:
            self.wait_until(
                lambda: boundary.getpowmininginfo()["state"] == "claim_quarantined",
                timeout=20,
            )
            info = boundary.getpowmininginfo()
            assert_equal(info["claims_submitted"], 0)
            assert_equal(self._claim_txids(boundary), before_second_claim)
            assert_equal(len(boundary.listunspent(1, 9999999, [boundary_address])), 1)
        finally:
            boundary.setpowmining(False)
        assert not any(
            entry.get("qq_shadow_pow_cleanup_for") == boundary_claim_txid
            for entry in boundary.listtransactions("*", 1000, 0, True)
        )


if __name__ == "__main__":
    GoldRushPowClaimSingleFlightTest().main()
