#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Stress two-wallet PoS/QQSIGNAL liveness across failure and lifecycle edges.

The historical v30.1.0 failure was an ABBA deadlock between wallet staking
status and scheduler work. This regression keeps independent node and wallet
health RPCs active while two loaded wallets stake and race automatic QQSIGNAL
submission with the scheduler. It then proves exceptional broadcast cleanup,
mempool-loss recovery, PoS confirmation, active-wallet unload/reload, and
bounded daemon shutdown.
"""

from collections import defaultdict
from decimal import Decimal
from threading import Event, Lock, Thread
import time
from urllib.parse import quote

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, get_rpc_proxy


GOLD_RUSH_END_TIME = 2_000_000_000
QQSIGNAL_HEX = "51515349474e414c"
PAYOUT_LABEL = "PoS - Quantum Stake Address"
WALLET_A = "p25_stress_a"
WALLET_B = "p25_stress_b"
RPC_TIMEOUT_SECONDS = 6
RPC_LATENCY_BUDGET_SECONDS = 5
WALLET_LIFECYCLE_BUDGET_SECONDS = 8
SHUTDOWN_BUDGET_SECONDS = 15


class GoldRushPosMultiwalletStressTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.base_args = [
            "-allowunsafequantumkeyrpc=1",
            "-autostartstaking=0",
            "-qqautoshadowsignal=1",
            "-txindex=1",
            "-staketimio=25",
            "-shadowwhitelistheight=5",
            "-shadowgoldrushblocks=1000",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            "-qqshadowsignalsubmissiondelaymillis=1500",
            "-qqshadowsignalretrybasemillis=60000",
        ]
        self.extra_args = [[
            *self.base_args,
            f"-qqshadowsignalbroadcastthrowwallet={WALLET_A}",
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

    def _load_wallet(self, name):
        node = self.nodes[0]
        if name not in node.listwallets():
            node.loadwallet(name)
        return node.get_wallet_rpc(name)

    @staticmethod
    def _signal_txids(wallet):
        return {
            entry["txid"]
            for entry in wallet.listtransactions("*", 1000, 0, True)
            if entry.get("comment") == "PoS Claim"
        }

    @staticmethod
    def _is_abandoned(wallet, txid):
        return any(detail.get("abandoned", False) for detail in wallet.gettransaction(txid)["details"])

    def _live_signal_txids(self, wallet):
        return {txid for txid in self._signal_txids(wallet) if not self._is_abandoned(wallet, txid)}

    def _abandoned_signal_txids(self, wallet):
        return {txid for txid in self._signal_txids(wallet) if self._is_abandoned(wallet, txid)}

    @staticmethod
    def _legacy_staking_inputs(wallet):
        inputs = []
        for utxo in wallet.listunspent(1, 9999999):
            address = utxo.get("address")
            if not address:
                continue
            info = wallet.getaddressinfo(address)
            if info.get("isquantum", False):
                continue
            inputs.append({"txid": utxo["txid"], "vout": utxo["vout"]})
        return inputs

    def _find_next_kernel_time(self, wallet):
        inputs = self._legacy_staking_inputs(wallet)
        assert inputs, "wallet must retain a mature legacy input while QQSIGNAL is pending"
        for _ in range(3000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_solve(self, wallet):
        node = self.nodes[0]
        start_height = node.getblockcount()
        kernel_time = self._find_next_kernel_time(wallet)
        self._set_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self._set_mocktime(kernel_time)
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
        finally:
            wallet.staking(False)
        block_hash = node.getbestblockhash()
        assert "proof-of-stake" in node.getblock(block_hash)["flags"]
        return block_hash

    def _start_health_pollers(self, wallet_names):
        """Run GUI-equivalent wallet calls and chain RPCs on independent workers."""
        node = self.nodes[0]
        stop = Event()
        state_lock = Lock()
        errors = []
        counts = defaultdict(int)
        maxima = defaultdict(float)
        enabled_samples = defaultdict(int)
        threads = []

        def record(source, method, started, staking_enabled=None):
            elapsed = time.monotonic() - started
            with state_lock:
                counts[source] += 1
                maxima[f"{source}:{method}"] = max(maxima[f"{source}:{method}"], elapsed)
                if staking_enabled:
                    enabled_samples[source] += 1
                if elapsed >= RPC_LATENCY_BUDGET_SECONDS:
                    errors.append(
                        f"{source} {method} exceeded {RPC_LATENCY_BUDGET_SECONDS}s: {elapsed:.3f}s"
                    )

        def fail(source, method, error):
            if stop.is_set():
                return
            with state_lock:
                errors.append(f"{source} {method} failed: {error}")
            stop.set()

        def poll_node():
            rpc = get_rpc_proxy(node.url, 201, timeout=RPC_TIMEOUT_SECONDS, coveragedir=node.coverage_dir)
            while not stop.is_set():
                for method in ("getblockchaininfo", "getblockcount"):
                    started = time.monotonic()
                    try:
                        getattr(rpc, method)()
                    except Exception as error:
                        fail("node", method, error)
                        return
                    record("node", method, started)
                time.sleep(0.01)

        def poll_wallet(name, rpc_index):
            wallet_url = f"{node.url}/wallet/{quote(name, safe='')}"
            rpc = get_rpc_proxy(wallet_url, rpc_index, timeout=RPC_TIMEOUT_SECONDS, coveragedir=node.coverage_dir)
            while not stop.is_set():
                for method in ("getstakinginfo", "getwalletinfo", "getgoldrushinfo"):
                    started = time.monotonic()
                    try:
                        result = getattr(rpc, method)()
                    except Exception as error:
                        fail(name, method, error)
                        return
                    record(name, method, started, result.get("enabled", False) if method == "getstakinginfo" else None)
                time.sleep(0.01)

        threads.append(Thread(target=poll_node, name="p25-node-heartbeat", daemon=True))
        for index, name in enumerate(wallet_names, start=202):
            threads.append(Thread(target=poll_wallet, args=(name, index), name=f"p25-{name}-heartbeat", daemon=True))
        for thread in threads:
            thread.start()

        self.wait_until(
            lambda: errors or all(counts[source] >= 3 for source in ["node", *wallet_names]),
            timeout=10,
        )
        assert_equal(errors, [])
        return stop, threads, errors, counts, maxima, enabled_samples

    def _stop_health_pollers(self, pollers, require_staking=()):
        stop, threads, errors, counts, maxima, enabled_samples = pollers
        stop.set()
        for thread in threads:
            thread.join(timeout=RPC_TIMEOUT_SECONDS + 2)
            assert not thread.is_alive(), f"health worker {thread.name} did not stop"
        assert_equal(errors, [])
        for source in ["node", *require_staking]:
            assert counts[source] >= 3, f"insufficient health samples for {source}: {counts[source]}"
        for name in require_staking:
            assert enabled_samples[name] > 0, f"no staking-enabled health sample for {name}"
        for method, latency in maxima.items():
            assert latency < RPC_LATENCY_BUDGET_SECONDS, f"{method} latency {latency:.3f}s exceeded budget"
        return dict(maxima)

    def _start_signal_race(self, wallets):
        node = self.nodes[0]
        expected_logs = [
            f"[{name}] Gold Rush PoS auto-signal test barrier reached".encode()
            for name in (WALLET_A, WALLET_B)
        ]
        with node.wait_for_debug_log(expected_logs, timeout=10):
            for wallet in wallets:
                wallet.staking(True)
        started = time.monotonic()
        node.mockscheduler(60)
        elapsed = time.monotonic() - started
        assert elapsed < RPC_LATENCY_BUDGET_SECONDS, f"scheduler race call took {elapsed:.3f}s"

    @staticmethod
    def _stop_staking(wallets):
        for wallet in wallets:
            wallet.staking(False)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)
        default_wallet = node.get_wallet_rpc(self.default_wallet_name)
        default_wallet.staking(False)

        self.log.info("Creating two independently funded wallets before the whitelist snapshot")
        node.createwallet(wallet_name=WALLET_A)
        node.createwallet(wallet_name=WALLET_B)
        wallet_a = node.get_wallet_rpc(WALLET_A)
        wallet_b = node.get_wallet_rpc(WALLET_B)
        wallets = [wallet_a, wallet_b]
        for wallet in wallets:
            wallet.staking(False)

        address_a = wallet_a.getnewaddress("p25-whitelist-a", "legacy")
        address_b = wallet_b.getnewaddress("p25-whitelist-b", "legacy")
        funding_address = default_wallet.getnewaddress("p25-funding", "legacy")
        self.generatetoaddress(node, 2, address_a, sync_fun=self.no_op)
        self.generatetoaddress(node, 2, address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, funding_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 8, funding_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Each wallet produces a legacy PoS solve without suppressing the other wallet")
        solve_a = self._mine_pos_solve(wallet_a)
        solve_b = self._mine_pos_solve(wallet_b)
        assert node.getblock(solve_a)["height"] < node.getblock(solve_b)["height"]
        assert_equal(wallet_a.getgoldrushinfo()["wallet_recent_solve_qualified"], True)
        assert_equal(wallet_b.getgoldrushinfo()["wallet_recent_solve_qualified"], True)

        self.log.info("Adding a second mature legacy input so pending signals cannot consume all stake weight")
        self.generatetoaddress(node, 1, address_a, sync_fun=self.no_op)
        self.generatetoaddress(node, 1, address_b, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 5, funding_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_a = wallet_a.getnewquantumaddress(PAYOUT_LABEL)["address"]
        payout_b = wallet_b.getnewquantumaddress(PAYOUT_LABEL)["address"]

        self.log.info("Racing two stakers with the scheduler while wallet A throws after QQSIGNAL persistence")
        for wallet in wallets:
            wallet.reservebalance(True, Decimal("1000000"))
        fault_health = self._start_health_pollers([WALLET_A, WALLET_B])
        self._start_signal_race(wallets)
        self.wait_until(
            lambda: len(self._abandoned_signal_txids(wallet_a)) == 1 and
            len(self._live_signal_txids(wallet_b)) == 1,
            timeout=30,
        )
        self._stop_staking(wallets)
        fault_latencies = self._stop_health_pollers(fault_health, require_staking=(WALLET_A, WALLET_B))

        fault_txid = next(iter(self._abandoned_signal_txids(wallet_a)))
        signal_b = next(iter(self._live_signal_txids(wallet_b)))
        assert fault_txid not in node.getrawmempool()
        assert signal_b in node.getrawmempool()
        assert_equal(len(self._signal_txids(wallet_a)), 1)
        assert_equal(len(self._signal_txids(wallet_b)), 1)
        fault_input = node.decoderawtransaction(wallet_a.gettransaction(fault_txid)["hex"])["vin"][0]
        assert any(
            utxo["txid"] == fault_input["txid"] and utxo["vout"] == fault_input["vout"]
            for utxo in wallet_a.listunspent(1, 9999999)
        ), "exceptional QQSIGNAL broadcast must immediately release its legacy input"
        assert_equal(set(wallet_a.getaddressesbylabel(PAYOUT_LABEL)), {payout_a})
        assert_equal(set(wallet_b.getaddressesbylabel(PAYOUT_LABEL)), {payout_b})
        assert wallet_a.dumpquantumkey(payout_a)["private_key"]
        assert wallet_b.dumpquantumkey(payout_b)["private_key"]

        self.log.info("Restarting without the fault hook evicts mempool state and recovers both wallets")
        restart_args = [*self.base_args, "-persistmempool=0", f"-mocktime={self.mock_time}"]
        restart_log_offset = node.debug_log_size(encoding="utf-8")
        restart_started = time.monotonic()
        self.restart_node(0, extra_args=restart_args)
        restart_elapsed = time.monotonic() - restart_started
        node = self.nodes[0]
        node.setmocktime(self.mock_time)
        wallet_a = self._load_wallet(WALLET_A)
        wallet_b = self._load_wallet(WALLET_B)
        wallets = [wallet_a, wallet_b]
        self.wait_until(lambda: signal_b in node.getrawmempool(), timeout=10)
        with open(node.debug_log_path, encoding="utf-8", errors="replace") as debug_log:
            debug_log.seek(restart_log_offset)
            restart_log = debug_log.read()
        assert 'Command-line arg: persistmempool="0"' in restart_log
        assert "Checking mempool with 0 transactions and 0 inputs" in restart_log
        assert "ResubmitWalletTransactions: resubmit 1 unconfirmed transactions" in restart_log
        for wallet in wallets:
            wallet.reservebalance(True, Decimal("1000000"))

        recovery_health = self._start_health_pollers([WALLET_A, WALLET_B])
        self._start_signal_race(wallets)
        self.wait_until(
            lambda: signal_b in node.getrawmempool() and
            len(self._live_signal_txids(wallet_a)) == 1 and
            next(iter(self._live_signal_txids(wallet_a))) in node.getrawmempool(),
            timeout=30,
        )
        self._stop_staking(wallets)
        recovery_latencies = self._stop_health_pollers(recovery_health, require_staking=(WALLET_A, WALLET_B))
        signal_a = next(iter(self._live_signal_txids(wallet_a)))
        assert_equal(signal_a, fault_txid)
        assert_equal(self._signal_txids(wallet_a), {fault_txid})
        assert_equal(self._abandoned_signal_txids(wallet_a), set())
        assert_equal(self._live_signal_txids(wallet_b), {signal_b})
        assert_equal(set(wallet_a.getaddressesbylabel(PAYOUT_LABEL)), {payout_a})
        assert_equal(set(wallet_b.getaddressesbylabel(PAYOUT_LABEL)), {payout_b})

        self.log.info("Both pending signals confirm in a legacy PoS block while all health RPCs remain bounded")
        for wallet in wallets:
            wallet.reservebalance(False)
        kernel_time = self._find_next_kernel_time(wallet_a)
        start_height = node.getblockcount()
        self._set_mocktime(kernel_time - 16)
        confirm_health = self._start_health_pollers([WALLET_A, WALLET_B])
        self._start_signal_race(wallets)
        self._set_mocktime(kernel_time)
        try:
            self.wait_until(lambda: node.getblockcount() > start_height, timeout=25)
        finally:
            self._stop_staking(wallets)
        confirm_latencies = self._stop_health_pollers(confirm_health, require_staking=(WALLET_A, WALLET_B))
        pos_block = node.getblock(node.getbestblockhash(), 2)
        assert "proof-of-stake" in pos_block["flags"]
        txids = [tx["txid"] for tx in pos_block["tx"]]
        assert signal_a in txids[2:]
        assert signal_b in txids[2:]
        assert_equal(
            sum(
                QQSIGNAL_HEX in output["scriptPubKey"]["hex"]
                for tx in pos_block["tx"][2:]
                for output in tx["vout"]
            ),
            2,
        )
        assert wallet_a.gettransaction(signal_a)["confirmations"] >= 1
        assert wallet_b.gettransaction(signal_b)["confirmations"] >= 1

        self.log.info("Unloading one actively staking wallet does not stall the other wallet or node")
        for wallet in wallets:
            wallet.reservebalance(True, Decimal("1000000"))
            wallet.staking(True)
        unload_health = self._start_health_pollers([WALLET_B])
        unload_started = time.monotonic()
        node.unloadwallet(WALLET_A)
        unload_elapsed = time.monotonic() - unload_started
        assert unload_elapsed < WALLET_LIFECYCLE_BUDGET_SECONDS, f"wallet unload took {unload_elapsed:.3f}s"
        assert WALLET_A not in node.listwallets()
        assert_equal(wallet_b.getstakinginfo()["enabled"], True)
        self.wait_until(lambda: unload_health[3][WALLET_B] >= 10, timeout=10)

        load_started = time.monotonic()
        wallet_a = self._load_wallet(WALLET_A)
        load_elapsed = time.monotonic() - load_started
        assert load_elapsed < WALLET_LIFECYCLE_BUDGET_SECONDS, f"wallet load took {load_elapsed:.3f}s"
        assert wallet_a.gettransaction(signal_a)["confirmations"] >= 1
        assert not self._is_abandoned(wallet_a, signal_a)
        assert wallet_b.gettransaction(signal_b)["confirmations"] >= 1
        assert not self._is_abandoned(wallet_b, signal_b)
        wallet_a.reservebalance(True, Decimal("1000000"))
        wallet_a.staking(True)
        unload_latencies = self._stop_health_pollers(unload_health, require_staking=(WALLET_B,))

        shutdown_health = self._start_health_pollers([WALLET_A, WALLET_B])
        self.wait_until(
            lambda: shutdown_health[5][WALLET_A] > 0 and shutdown_health[5][WALLET_B] > 0,
            timeout=10,
        )
        shutdown_latencies = self._stop_health_pollers(
            shutdown_health,
            require_staking=(WALLET_A, WALLET_B),
        )

        all_latencies = {
            **{f"fault:{key}": value for key, value in fault_latencies.items()},
            **{f"recovery:{key}": value for key, value in recovery_latencies.items()},
            **{f"confirm:{key}": value for key, value in confirm_latencies.items()},
            **{f"unload:{key}": value for key, value in unload_latencies.items()},
            **{f"shutdown:{key}": value for key, value in shutdown_latencies.items()},
        }
        worst_method, worst_latency = max(all_latencies.items(), key=lambda item: item[1])
        self.log.info(
            f"Measured restart={restart_elapsed:.3f}s unload={unload_elapsed:.3f}s "
            f"load={load_elapsed:.3f}s worst_rpc={worst_method}:{worst_latency:.3f}s"
        )

        shutdown_started = time.monotonic()
        self.stop_node(0)
        shutdown_elapsed = time.monotonic() - shutdown_started
        assert shutdown_elapsed < SHUTDOWN_BUDGET_SECONDS, f"daemon shutdown took {shutdown_elapsed:.3f}s"
        self.log.info(f"Bounded active-staking shutdown completed in {shutdown_elapsed:.3f}s")


if __name__ == "__main__":
    GoldRushPosMultiwalletStressTest().main()
