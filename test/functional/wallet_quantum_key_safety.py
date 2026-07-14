#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test durable non-HD quantum keys, verified backups, and unsafe RPC gates."""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletQuantumKeySafetyTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def assert_public_inventory(inventory):
        WalletQuantumKeySafetyTest.assert_no_private_fields(inventory)
        assert_equal(inventory["total"], len(inventory["keys"]))
        for key in inventory["keys"]:
            assert "private_key" not in key
            assert key["stored_in_wallet"]
            assert key["public_key"]
            assert key["address"]

    @staticmethod
    def assert_no_private_fields(value):
        """Normal quantum RPC results must contain public metadata only."""
        if isinstance(value, dict):
            for field, child in value.items():
                assert "private" not in field.lower()
                WalletQuantumKeySafetyTest.assert_no_private_fields(child)
        elif isinstance(value, list):
            for child in value:
                WalletQuantumKeySafetyTest.assert_no_private_fields(child)

    def run_test(self):
        node = self.nodes[0]
        wallet_name = node.getwalletinfo()["walletname"]
        wallet = node.get_wallet_rpc(wallet_name)
        legacy_address = wallet.getnewaddress("legacy-before-quantum-backup", "legacy")
        legacy_message = "Blackcoin v30.1.1 recovery proof"

        self.log.info("Raw private-key RPCs are disabled by default")
        first = wallet.getnewquantumaddress("first")
        self.assert_no_private_fields(first)
        assert first["stored_in_wallet"]
        assert not first["backup_verified"]
        assert_raises_rpc_error(-2, "disabled by default", node.createquantumkey)
        assert_raises_rpc_error(-2, "disabled by default", wallet.dumpquantumkey, first["address"])

        inventory = wallet.getquantumkeyinventory()
        self.assert_public_inventory(inventory)
        assert_equal(inventory["total"], 1)
        assert_equal(inventory["backup_verified"], 0)
        assert not inventory["all_backed_up"]

        self.log.info("The PoW miner selects only a durably stored wallet payout key")
        pow_wallet_name = "quantum_pow_payout_safety"
        node.createwallet(
            wallet_name=pow_wallet_name,
            descriptors=self.options.descriptors,
            load_on_startup=True,
        )
        pow_wallet = node.get_wallet_rpc(pow_wallet_name)
        pow_result = pow_wallet.setpowmining(True, 1, 1)
        self.assert_no_private_fields(pow_result)
        assert pow_result["enabled"]
        assert pow_result["warning"]
        pow_payout = pow_result["payout_address"]
        assert pow_payout
        pow_wallet.setpowmining(False)

        pow_inventory = pow_wallet.getquantumkeyinventory()
        self.assert_public_inventory(pow_inventory)
        assert_equal(pow_inventory["total"], 1)
        assert pow_inventory["all_durably_stored"]
        assert_equal(pow_inventory["keys"][0]["address"], pow_payout)

        self.log.info("A directory backup is reopened, challenged, and marked complete")
        first_backup_dir = node.datadir_path / "quantum-first-backup"
        first_backup_dir.mkdir()
        wallet.backupwallet(first_backup_dir)
        produced_files = list(first_backup_dir.iterdir())
        assert_equal(len(produced_files), 1)
        first_backup = produced_files[0]

        inventory = wallet.getquantumkeyinventory()
        assert_equal(inventory["backup_verified"], 1)
        assert inventory["all_backed_up"]

        self.log.info("A key created later is not covered by the earlier backup")
        second = wallet.getnewquantumaddress("second")
        self.assert_no_private_fields(second)
        inventory = wallet.getquantumkeyinventory()
        self.assert_public_inventory(inventory)
        assert_equal(inventory["total"], 2)
        assert_equal(inventory["backup_verified"], 1)
        assert_equal(inventory["backup_unverified"], 1)
        assert not inventory["all_backed_up"]

        current_backup = node.datadir_path / "quantum-current-backup.dat"
        wallet.backupwallet(current_backup)
        inventory = wallet.getquantumkeyinventory()
        assert_equal(inventory["backup_verified"], 2)
        assert inventory["all_backed_up"]

        self.log.info("Both the earlier and current verified backups restore exactly their inventories")
        node.restorewallet("quantum_first_restore", first_backup)
        first_restore = node.get_wallet_rpc("quantum_first_restore")
        first_inventory = first_restore.getquantumkeyinventory()
        assert_equal(first_inventory["total"], 1)
        assert first_inventory["all_backed_up"]
        assert_equal(first_inventory["keys"][0]["address"], first["address"])
        assert first_restore.getaddressinfo(legacy_address)["ismine"]
        assert node.verifymessage(
            legacy_address,
            first_restore.signmessage(legacy_address, legacy_message),
            legacy_message,
        )

        node.restorewallet("quantum_current_restore", current_backup)
        current_restore = node.get_wallet_rpc("quantum_current_restore")
        current_inventory = current_restore.getquantumkeyinventory()
        assert_equal(current_inventory["total"], 2)
        assert current_inventory["all_backed_up"]
        assert_equal(
            {entry["address"] for entry in current_inventory["keys"]},
            {first["address"], second["address"]},
        )
        assert current_restore.getaddressinfo(legacy_address)["ismine"]
        assert node.verifymessage(
            legacy_address,
            current_restore.signmessage(legacy_address, legacy_message),
            legacy_message,
        )

        self.log.info("A locked-wallet failure cannot replace an existing good backup")
        passphrase = "quantum-backup-passphrase"
        wallet.encryptwallet(passphrase)
        known_good = current_backup.read_bytes()
        assert_raises_rpc_error(-4, "Unlock this wallet", wallet.backupwallet, current_backup)
        assert_equal(current_backup.read_bytes(), known_good)
        locked_key_count = wallet.getquantumkeyinventory()["total"]
        assert_raises_rpc_error(-13, "walletpassphrase", wallet.getnewquantumaddress, "locked-blocked")
        assert_raises_rpc_error(-4, "requires an unlocked wallet", wallet.setpowmining, True, 1, 1)
        assert_equal(wallet.getquantumkeyinventory()["total"], locked_key_count)

        self.log.info("The explicit unsafe gate still requires a normal, non-staking-only unlock")
        self.restart_node(0, ["-allowunsafequantumkeyrpc=1", "-debug=rpc"])
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        private_material = []
        raw = node.createquantumkey()
        assert not raw["stored_in_wallet"]
        assert raw["private_key"]
        private_material.append(raw["private_key"])

        wallet.walletpassphrase(passphrase, 100, True)
        assert_raises_rpc_error(-13, "staking only", wallet.dumpquantumkey, first["address"])
        assert_raises_rpc_error(-13, "staking only", wallet.getnewquantumaddress, "blocked")
        staking_only_key_count = wallet.getquantumkeyinventory()["total"]
        assert_raises_rpc_error(-4, "normal wallet unlock", wallet.setpowmining, True, 1, 1)
        assert_equal(wallet.getquantumkeyinventory()["total"], staking_only_key_count)

        # Verification is internal and does not disclose or create a key, so a
        # staking-only unlock may still produce a complete checked backup.
        wallet.backupwallet(current_backup)
        wallet.walletpassphrase(passphrase, 100, False)
        dumped = wallet.dumpquantumkey(first["address"])
        assert_equal(dumped["address"], first["address"])
        assert dumped["private_key"]
        private_material.append(dumped["private_key"])

        imported = wallet.importquantumkey(
            raw["public_key"],
            raw["private_key"],
            "imported",
            False,
        )
        assert_equal(imported["address"], raw["address"])
        assert imported["stored_in_wallet"]
        assert not imported["backup_verified"]
        self.assert_no_private_fields(imported)
        imported_inventory = wallet.getquantumkeyinventory()
        assert_equal(imported_inventory["total"], 3)
        assert_equal(imported_inventory["backup_unverified"], 1)

        third = wallet.getnewquantumaddress("third")
        self.assert_no_private_fields(third)
        inventory = wallet.getquantumkeyinventory()
        assert_equal(inventory["total"], 4)
        assert_equal(inventory["backup_unverified"], 2)
        assert not inventory["all_backed_up"]
        wallet.backupwallet(current_backup)
        assert wallet.getquantumkeyinventory()["all_backed_up"]
        listed_addresses = wallet.listquantumaddresses()
        self.assert_no_private_fields(listed_addresses)
        assert third["address"] in {entry["address"] for entry in listed_addresses}

        self.log.info("A key returned to RPC survives an immediate ungraceful process stop")
        crash_key = wallet.getnewquantumaddress("crash-after-return")
        self.assert_no_private_fields(crash_key)
        node.process.kill()
        node.process.wait(timeout=node.rpc_timeout)
        node.stdout.close()
        node.stderr.close()
        node.running = False
        node.process = None
        node.rpc_connected = False
        node.rpc = None

        self.start_node(0, ["-allowunsafequantumkeyrpc=1", "-debug=rpc"])
        node = self.nodes[0]
        wallet = node.get_wallet_rpc(wallet_name)
        crash_inventory = wallet.getquantumkeyinventory()
        assert_equal(crash_inventory["total"], 5)
        assert_equal(crash_inventory["backup_unverified"], 1)
        assert crash_key["address"] in {entry["address"] for entry in crash_inventory["keys"]}
        wallet.walletpassphrase(passphrase, 100, False)
        crash_dump = wallet.dumpquantumkey(crash_key["address"])
        assert_equal(crash_dump["address"], crash_key["address"])
        private_material.append(crash_dump["private_key"])
        wallet.backupwallet(current_backup)
        assert wallet.getquantumkeyinventory()["all_backed_up"]

        self.log.info("The PoW payout survives a crash and is reused only with its durable key")
        if pow_wallet_name not in node.listwallets():
            node.loadwallet(pow_wallet_name)
        pow_wallet = node.get_wallet_rpc(pow_wallet_name)
        pow_inventory = pow_wallet.getquantumkeyinventory()
        self.assert_public_inventory(pow_inventory)
        assert_equal(pow_inventory["total"], 1)
        assert pow_inventory["all_durably_stored"]
        assert_equal(pow_inventory["keys"][0]["address"], pow_payout)
        pow_result = pow_wallet.setpowmining(True, 1, 1)
        self.assert_no_private_fields(pow_result)
        assert_equal(pow_result["payout_address"], pow_payout)
        assert "warning" not in pow_result
        pow_wallet.setpowmining(False)

        self.log.info("Every wallet quantum secret is absent from the daemon log, including RPC debug logging")
        for entry in wallet.getquantumkeyinventory()["keys"]:
            private_material.append(wallet.dumpquantumkey(entry["address"])["private_key"])
        for entry in pow_wallet.getquantumkeyinventory()["keys"]:
            private_material.append(pow_wallet.dumpquantumkey(entry["address"])["private_key"])
        debug_log = node.debug_log_path.read_text(encoding="utf8", errors="replace")
        if any(secret in debug_log for secret in set(private_material)):
            raise AssertionError("Private quantum key material was written to debug.log")


if __name__ == "__main__":
    WalletQuantumKeySafetyTest().main()
