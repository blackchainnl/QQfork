#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test restart-safe fleet bindings without automatic quantum-key creation."""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletQuantumFleetBindingsTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def key_set(wallet):
        inventory = wallet.getquantumkeyinventory()
        assert_equal(inventory["total"], len(inventory["keys"]))
        return {entry["address"] for entry in inventory["keys"]}

    def run_test(self):
        node = self.nodes[0]
        wallet_name = node.getwalletinfo()["walletname"]
        wallet = node.get_wallet_rpc(wallet_name)

        bound = wallet.getnewquantumaddress("ordinary operator key")["address"]
        assert_equal(self.key_set(wallet), {bound})
        tiered = wallet.getnewquantumstakeaddress(
            "must not be used for automation", 9450
        )["address"]
        expected_keys = self.key_set(wallet)
        assert bound in expected_keys
        assert tiered in expected_keys

        hard_mode = [
            "-qqallowautokeycreation=0",
            "-qqautoredelegate=0",
            "-qqautodemurrageattest=0",
        ]

        self.log.info("Hard fleet mode requires explicit auto-redelegation shutdown")
        self.stop_node(0)
        node.assert_start_raises_init_error(
            extra_args=["-qqallowautokeycreation=0"],
            expected_msg=(
                "Error: -qqallowautokeycreation=0 requires explicit "
                "-qqautoredelegate=0 because automatic redelegation otherwise "
                "generates a new quantum owner key."
            ),
        )

        self.log.info("Repeated payout bindings are rejected before wallet load")
        node.assert_start_raises_init_error(
            extra_args=[
                "-qqallowautokeycreation=0",
                "-qqautoredelegate=0",
                f"-qqpowpayoutaddress={bound}",
                f"-qqpowpayoutaddress={bound}",
            ],
            expected_msg=(
                "Error: -qqpowpayoutaddress is ambiguous: specify exactly one "
                "wallet-owned quantum address."
            ),
        )

        self.log.info(
            "All three automatic paths reject a wallet-owned tiered v16 binding"
        )
        for option in (
            "-qqpowpayoutaddress",
            "-qqpospayoutaddress",
            "-qqdemurragechangeaddress",
        ):
            node.assert_start_raises_init_error(
                extra_args=hard_mode + [f"{option}={tiered}"],
                expected_msg=(
                    f"Error: {option} must be an ordinary direct "
                    "(non-tiered, non-cold-stake) Quantum Quasar ML-DSA "
                    "address for the active network."
                ),
            )

        self.log.info("A missing hard-mode PoW binding fails without creating a key")
        self.start_node(0, hard_mode)
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        assert_raises_rpc_error(
            -4,
            "-qqpowpayoutaddress",
            wallet.setpowmining,
            True,
            1,
            1,
        )
        assert_equal(self.key_set(wallet), expected_keys)

        self.log.info("The same existing key binds PoW, PoS, and demurrage change")
        bindings = hard_mode + [
            f"-qqpowpayoutaddress={bound}",
            f"-qqpospayoutaddress={bound}",
            f"-qqdemurragechangeaddress={bound}",
        ]
        self.restart_node(0, bindings)
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        log_offset = node.debug_log_path.stat().st_size
        with node.assert_debug_log(["Gold Rush PoW worker 0 started"]):
            started = wallet.setpowmining(True, 1, 1)
        assert started["enabled"]
        assert_equal(started["payout_address"], bound)
        assert "warning" not in started
        # Give the worker time to perform its first hot-loop re-resolution.
        # Before the edge-triggered log guard this produced a second identical
        # binding line immediately, then another line on every loop.
        time.sleep(0.25)
        wallet.setpowmining(False)
        log_delta = node.debug_log_path.read_bytes()[log_offset:].decode(
            "utf-8", errors="replace"
        )
        assert_equal(
            log_delta.count(
                "Gold Rush PoW miner bound to configured payout address"
            ),
            1,
        )
        wallet.staking(True)
        node.mockscheduler(61)
        assert_equal(self.key_set(wallet), expected_keys)

        self.log.info("A second restart reuses the binding and preserves the exact key set")
        self.restart_node(0, bindings)
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        assert_equal(self.key_set(wallet), expected_keys)
        started = wallet.setpowmining(True, 1, 1)
        assert_equal(started["payout_address"], bound)
        assert "warning" not in started
        wallet.setpowmining(False)
        node.mockscheduler(61)
        assert_equal(self.key_set(wallet), expected_keys)

        self.log.info("An invalid explicit binding fails closed before wallet load")
        self.stop_node(0)
        invalid_bindings = hard_mode + ["-qqpowpayoutaddress=not-a-quantum-address"]
        node.assert_start_raises_init_error(
            extra_args=invalid_bindings,
            expected_msg=(
                "Error: -qqpowpayoutaddress must be an ordinary direct "
                "(non-tiered, non-cold-stake) Quantum Quasar ML-DSA address "
                "for the active network."
            ),
        )
        self.start_node(0, hard_mode)
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        assert_equal(self.key_set(wallet), expected_keys)


if __name__ == "__main__":
    WalletQuantumFleetBindingsTest().main()
