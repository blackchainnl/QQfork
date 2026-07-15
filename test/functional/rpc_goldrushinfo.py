#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

QQSPROOF_HEX = "51515350524f4f46"
GOLD_RUSH_END_HEIGHT = 501
MIGRATION_END_HEIGHT = 700
POW_WALLET_PASSPHRASE = "goldrush-pow-state-test"

class GoldRushInfoTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        args = [
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
        ]
        self.extra_args = [
            args,
            args,
        ]

    def _sync_mocktime_to_tip(self):
        tip_time = max(
            node.getblockheader(node.getbestblockhash())["time"]
            for node in self.nodes
        )
        for node in self.nodes:
            node.setmocktime((tip_time & ~0xf) + 16)

    def _generate_with_peer_offline(self, node, blocks, address):
        """Generate a large batch without making the idle peer time out."""
        self.disconnect_nodes(0, 1)
        try:
            hashes = self.generatetoaddress(node, blocks, address, sync_fun=self.no_op)
        finally:
            self.connect_nodes(0, 1)
        self.sync_blocks()
        return hashes

    @staticmethod
    def _mempool_pow_claims(node):
        claims = []
        for txid in node.getrawmempool():
            tx = node.getrawtransaction(txid, True)
            if any(QQSPROOF_HEX in output["scriptPubKey"]["hex"] for output in tx["vout"]):
                claims.append(txid)
        return claims

    def _assert_builtin_pow_miner_lifecycle(self):
        node = self.nodes[0]
        wallet_name = "goldrush_pow_builtin"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)
        target = wallet.getnewaddress()

        self._generate_with_peer_offline(node, 101, target)
        self._sync_mocktime_to_tip()

        if not self.is_cli_compiled():
            self.log.info("Skipping built-in PoW miner CLI lifecycle test: CLI not compiled")
            return

        self.log.info("Starting the built-in PoW miner via CLI and checking worker telemetry")
        cli_wallet = node.cli(f"-rpcwallet={wallet_name}")
        legacy_payout = wallet.getnewquantumaddress("goldrush-pow")["address"]
        assert_equal(wallet.getaddressinfo(legacy_payout)["labels"], ["goldrush-pow"])
        assert_equal(wallet.getpowmininginfo()["state"], "disabled")
        wallet.encryptwallet(POW_WALLET_PASSPHRASE)
        wallet.walletpassphrase(POW_WALLET_PASSPHRASE, 600, False)
        # Use real clock time while the worker runs. The hashrate meter is wall-clock based,
        # while epoch activity is derived from the already-connected chain tip.
        node.setmocktime(0)
        payout = ""
        try:
            started = cli_wallet.setpowmining(True, 1, 100)
            assert_equal(started["enabled"], True)
            assert_equal(started["created_payout_key"], False)
            assert_equal(started["threads"], 1)
            assert_equal(started["cpu_percent"], 100)
            payout = started["payout_address"]
            assert_equal(payout, legacy_payout)
            assert "warning" not in started
            assert_equal(wallet.getaddressinfo(payout)["labels"], ["PoW - Quantum Claim Address"])
            assert_equal(node.validateaddress(payout)["isvalid"], True)
            assert_equal(wallet.getpowmininginfo()["payout_address"], payout)

            self.wait_until(
                lambda: (
                    wallet.getpowmininginfo()["hashrate"] > 0
                    and wallet.getpowmininginfo()["state"] in ("ready", "hashing", "claim_in_flight")
                ),
                timeout=60,
            )
            info = cli_wallet.getpowmininginfo()
            assert_equal(info["enabled"], True)
            assert_equal(info["threads"], 1)
            assert_equal(info["cpu_percent"], 100)
            assert_equal(info["epoch_active"], True)
            assert_equal(info["payout_address"], payout)
            assert info["hashrate"] > 0

            self.log.info("Locking an enabled miner reports a fail-soft waiting state")
            wallet.walletlock()
            self._generate_with_peer_offline(node, 1, node.get_deterministic_priv_key().address)
            self.wait_until(
                lambda: wallet.getpowmininginfo()["state"] == "wallet_locked_or_staking_only",
                timeout=10,
            )
            locked = wallet.getpowmininginfo()
            assert_equal(locked["enabled"], True)
            assert_equal(locked["state"], "wallet_locked_or_staking_only")
            assert_equal(locked["hashrate"], 0)

            wallet.walletpassphrase(POW_WALLET_PASSPHRASE, 600, False)
            self.wait_until(
                lambda: (
                    wallet.getpowmininginfo()["hashrate"] > 0
                    and wallet.getpowmininginfo()["state"] in ("ready", "hashing", "claim_in_flight")
                ),
                timeout=60,
            )
        finally:
            try:
                cli_wallet.setpowmining(False)
            finally:
                self._sync_mocktime_to_tip()

        stopped = wallet.getpowmininginfo()
        assert_equal(stopped["enabled"], False)
        assert_equal(stopped["state"], "disabled")
        assert_equal(stopped["hashrate"], 0)
        if payout:
            assert_equal(stopped["payout_address"], payout)

    def _assert_pow_claim_from_non_whitelisted_address(self):
        if not self.is_wallet_compiled():
            self.log.info("Skipping PoW claim wallet test: wallet not compiled")
            return

        node = self.nodes[0]
        self.log.info("Activating reachable Shadow Gold Rush window")
        self.generatetoaddress(node, 1, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self.sync_blocks()

        wallet_name = "goldrush_pow"
        node.createwallet(wallet_name=wallet_name)
        wallet = node.get_wallet_rpc(wallet_name)

        self.log.info("Optional wallet automation is visible and fail-closed by default")
        staking_info = wallet.getstakinginfo()
        assert_equal(staking_info["autostart_staking"], False)
        assert_equal(staking_info["automatic_qqsignal"], False)
        assert_equal(staking_info["automatic_demurrage_attestation"], False)
        assert_equal(staking_info["automatic_redelegation"], False)
        assert_equal(staking_info["allow_automatic_quantum_key_creation"], False)
        assert_equal(staking_info["consensus_demurrage_automatic"], True)
        pow_info = wallet.getpowmininginfo()
        assert_equal(pow_info["autostart"], False)
        assert_equal(pow_info["allow_automatic_quantum_key_creation"], False)
        pow_help = wallet.help("setpowmining")
        assert "allow_new_payout_key" in pow_help
        assert "Back up the wallet immediately" in pow_help

        rpc_target = wallet.getnewaddress()
        cli_target = wallet.getnewaddress()
        self._generate_with_peer_offline(node, 101, rpc_target)
        self._generate_with_peer_offline(node, 101, cli_target)
        self._sync_mocktime_to_tip()

        self.log.info("Checking miner work RPC for a non-whitelisted PoW target")
        rpc_quantum = wallet.getnewquantumaddress()["address"]
        work = node.getshadowpowwork(rpc_target, rpc_quantum)
        assert_equal(work["active"], True)
        assert_equal(work["prefix"], "QQSPROOF")
        assert_equal(work["proof_mode"], "pow")
        assert_equal(work["proof_mode_byte"], 0)
        assert "target_whitelisted" not in work
        assert "target_script" in work
        assert_equal(work["quantum_address"], rpc_quantum)
        assert_equal(work["quantum_payout_script"], node.validateaddress(rpc_quantum)["scriptPubKey"])

        legacy_payout = wallet.getnewaddress("", "legacy")
        assert_raises_rpc_error(-5, "quantum_address must be a Blackcoin migration address", node.getshadowpowwork, rpc_target, legacy_payout)
        assert_raises_rpc_error(-5, "quantum_address must be a Blackcoin migration address", wallet.sendshadowpowclaim, rpc_target, legacy_payout, 1)

        help_text = node.help("getshadowpowwork")
        assert "not whitelist-gated" in help_text
        assert "target_whitelisted" not in help_text
        assert "quantum_payout_script" in help_text

        wallet_help = wallet.help("sendshadowpowclaim")
        assert "PoW claims are NOT whitelist-gated" in wallet_help
        assert "Quantum migration address" in wallet_help
        assert "proof" in wallet_help

        self.log.info("Rejecting invalid built-in PoW miner configuration")
        assert_raises_rpc_error(-4, "threads must be between 1 and 256", wallet.setpowmining, True, 0, 10)
        assert_raises_rpc_error(-4, "cpu_percent must be between 1 and 100", wallet.setpowmining, True, 1, 101)
        assert_equal(wallet.getpowmininginfo()["enabled"], False)

        self._assert_builtin_pow_miner_lifecycle()

        # The built-in worker can win while its lifecycle telemetry is sampled.
        # Its next-block-only claim must expire before the manual claim checks.
        if self._mempool_pow_claims(node):
            self.log.info("Advancing the tip to expire a claim found by the built-in PoW miner")
            self._generate_with_peer_offline(node, 1, node.get_deterministic_priv_key().address)
            self._sync_mocktime_to_tip()
        assert_equal(self._mempool_pow_claims(node), [])

        self.disconnect_nodes(0, 1)

        self.log.info("Broadcasting non-whitelisted PoW claim via RPC")
        stale_claim = wallet.sendshadowpowclaim(rpc_target, rpc_quantum, 200000)
        assert_equal(stale_claim["address"], rpc_target)
        assert_equal(stale_claim["quantum_address"], rpc_quantum)
        assert_equal(stale_claim["external_proof"], False)
        assert_equal(stale_claim["proof_mode"], "pow")
        assert_equal(stale_claim["proof_mode_byte"], 0)
        assert stale_claim["proof"].startswith(QQSPROOF_HEX)
        assert stale_claim["txid"] in node.getrawmempool()
        rpc_decoded = node.decoderawtransaction(stale_claim["hex"])
        assert any(QQSPROOF_HEX in vout["scriptPubKey"]["hex"] for vout in rpc_decoded["vout"])
        assert all(vout["scriptPubKey"].get("address") != rpc_quantum for vout in rpc_decoded["vout"] if "scriptPubKey" in vout)
        proof_mismatch_error = "proof does not match the current tip, target address, quantum payout address, and PoW channel"
        assert_raises_rpc_error(-8, proof_mismatch_error, wallet.sendshadowpowclaim, rpc_target, rpc_quantum, 1, None, QQSPROOF_HEX + "00")
        pos_proof = bytearray.fromhex(stale_claim["proof"])
        pos_proof[len(bytes.fromhex(QQSPROOF_HEX)) + 4] = 1
        assert_raises_rpc_error(
            -8,
            "proof encodes PoS mode; fee-paying QQSPROOF claims require PoW mode byte 0",
            wallet.sendshadowpowclaim,
            rpc_target,
            rpc_quantum,
            1,
            None,
            pos_proof.hex(),
        )
        unknown_proof = bytearray.fromhex(stale_claim["proof"])
        unknown_proof[len(bytes.fromhex(QQSPROOF_HEX)) + 4] = 0x7f
        assert_raises_rpc_error(
            -8,
            "proof encodes an unknown mode; fee-paying QQSPROOF claims require PoW mode byte 0",
            wallet.sendshadowpowclaim,
            rpc_target,
            rpc_quantum,
            1,
            None,
            unknown_proof.hex(),
        )
        stolen_quantum = wallet.getnewquantumaddress()["address"]
        assert_raises_rpc_error(-8, proof_mismatch_error, wallet.sendshadowpowclaim, rpc_target, stolen_quantum, 1, None, stale_claim["proof"])
        assert_raises_rpc_error(-26, "shadow-proof-mempool-conflict", wallet.sendshadowpowclaim, rpc_target, rpc_quantum, 1, None, stale_claim["proof"])

        self.log.info("Expiring unmined next-block-only PoW claims when the tip advances")
        stale_parent = node.getbestblockhash()
        self.generatetoaddress(self.nodes[1], 3, self.nodes[1].get_deterministic_priv_key().address, sync_fun=self.no_op)
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert node.getbestblockhash() != stale_parent
        self.wait_until(lambda: stale_claim["txid"] not in node.getrawmempool(), timeout=10)
        stale_accept = node.testmempoolaccept([stale_claim["hex"]])[0]
        assert_equal(stale_accept["allowed"], False)
        assert_equal(stale_accept["reject-reason"], "shadow-proof-invalid")

        if self.is_cli_compiled():
            self.log.info("Checking miner work and broadcasting non-whitelisted PoW claim via CLI")
            cli_quantum = wallet.getnewquantumaddress()["address"]
            cli_work = node.cli.getshadowpowwork(cli_target, cli_quantum)
            assert_equal(cli_work["prefix"], "QQSPROOF")
            assert_equal(cli_work["proof_mode"], "pow")
            assert_equal(cli_work["proof_mode_byte"], 0)
            assert "target_whitelisted" not in cli_work
            assert_equal(cli_work["quantum_address"], cli_quantum)
            assert_equal(cli_work["quantum_payout_script"], node.validateaddress(cli_quantum)["scriptPubKey"])

            cli_wallet = node.cli("-rpcwallet={}".format(wallet_name))
            cli_claim = cli_wallet.sendshadowpowclaim(cli_target, cli_quantum, 200000)
            assert_equal(cli_claim["address"], cli_target)
            assert_equal(cli_claim["quantum_address"], cli_quantum)
            assert_equal(cli_claim["external_proof"], False)
            assert_equal(cli_claim["proof_mode"], "pow")
            assert_equal(cli_claim["proof_mode_byte"], 0)
            assert cli_claim["proof"].startswith(QQSPROOF_HEX)
            assert cli_claim["txid"] in node.getrawmempool()

        self.log.info("An enabled miner reports epoch_inactive after the Gold Rush height window")
        remaining = GOLD_RUSH_END_HEIGHT - node.getblockcount()
        if remaining > 0:
            self._generate_with_peer_offline(node, remaining, node.get_deterministic_priv_key().address)
        builtin_wallet = node.get_wallet_rpc("goldrush_pow_builtin")
        builtin_wallet.walletpassphrase(POW_WALLET_PASSPHRASE, 600, False)
        try:
            builtin_wallet.setpowmining(True, 1, 100)
            self.wait_until(
                lambda: builtin_wallet.getpowmininginfo()["state"] == "epoch_inactive",
                timeout=10,
            )
            inactive = builtin_wallet.getpowmininginfo()
            assert_equal(inactive["enabled"], True)
            assert_equal(inactive["state"], "epoch_inactive")
            assert_equal(inactive["hashrate"], 0)
        finally:
            builtin_wallet.setpowmining(False)
        assert_equal(builtin_wallet.getpowmininginfo()["state"], "disabled")

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Testing getgoldrushstate...")

        info = node.getgoldrushstate()
        assert "pow_amount" in info
        assert "pos_amount" in info
        assert "pow_count" in info
        assert "pos_count" in info
        assert "last_pow_height" in info
        assert "last_pos_height" in info
        assert "recent_count" in info
        assert "pow_target_bits" in info
        assert_equal(info["competing_claim_rule_activation_height"], 2)
        assert_equal(info["competing_claim_rule_active"], info["height"] >= 2)
        assert_equal(info["competing_claim_rule_active_next_block"], info["height"] + 1 >= 2)
        assert_equal(info["blocks_until_competing_claim_rule"], max(0, 2 - info["height"]))

        # Verify pow_target_bits is a valid positive integer
        assert isinstance(info["pow_target_bits"], int)
        assert info["pow_target_bits"] >= 0

        if self.is_wallet_compiled():
            self.log.info("Testing wallet getgoldrushinfo...")
            node.createwallet(wallet_name="goldrush")
            wallet_info = node.get_wallet_rpc("goldrush").getgoldrushinfo()
            assert "wallet_recent_solve_qualified" in wallet_info
            assert "wallet_scripts" in wallet_info
            assert "pow_amount" in wallet_info
            assert "pos_amount" in wallet_info
            assert_equal(wallet_info["competing_claim_rule_activation_height"], 2)
            assert_equal(wallet_info["competing_claim_rule_active"], wallet_info["height"] >= 2)
            assert_equal(wallet_info["competing_claim_rule_active_next_block"], wallet_info["height"] + 1 >= 2)
            assert_equal(wallet_info["blocks_until_competing_claim_rule"], max(0, 2 - wallet_info["height"]))

        self._assert_pow_claim_from_non_whitelisted_address()

        self.log.info("Tests successful!")

if __name__ == '__main__':
    GoldRushInfoTest().main()
