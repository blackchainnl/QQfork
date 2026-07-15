#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise Gold Rush payout locking and the post-Gold-Rush migration RPC.

The positive ``migratetoquantum`` path supplies lifecycle evidence for roadmap
issues #11 (Gold Rush payout lifecycle), #14 (phase funding gates), and #16
(monotonic lifecycle).
"""

from decimal import Decimal
import time

from test_framework.authproxy import JSONRPCException
from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_HEIGHT = 501
MIGRATION_END_HEIGHT = 700
QUANTUM_SPEND_FEE = Decimal("0.01")
WALLET_NAME = "goldrush_migration_rpc"
MIGRATION_WALLET_NAME = "legacy_to_quantum_rpc"
MIGRATION_PASSPHRASE = "migration-test-passphrase"


class GoldRushMigrationRpcTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-allowunsafequantumkeyrpc=1",
            "-txindex=1",
            "-staketimio=50",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendheight={GOLD_RUSH_END_HEIGHT}",
            f"-qqmigrationendheight={MIGRATION_END_HEIGHT}",
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

    def _staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
        ]

    def _find_next_kernel_time(self, wallet):
        inputs = self._staking_inputs(wallet)
        assert inputs, "test wallet must have mature staking inputs"
        for _ in range(1000):
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
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:], "QQSPROOF claim must be included as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _mine_to_height(self, height, address):
        node = self.nodes[0]
        for _ in range(1000):
            if node.getblockcount() == height:
                return
            assert node.getblockcount() < height
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime(16)
        raise AssertionError(f"timed out mining to height {height}")

    def _get_quantum_utxos(self, wallet, address, *, min_conf=0):
        options = {"include_immature_coinbase": True}
        return wallet.listunspent(min_conf, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address, min_conf=min_conf)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address, min_conf=min_conf)[0]

    def _build_quantum_spend(self, wallet, utxo, destination):
        node = self.nodes[0]
        spend_amount = Decimal(str(utxo["amount"])) - QUANTUM_SPEND_FEE
        assert spend_amount > 0
        raw = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{destination: spend_amount}],
        )
        key = wallet.dumpquantumkey(utxo["address"])
        signed = node.signrawtransactionwithquantumkey(
            raw,
            [{"public_key": key["public_key"], "private_key": key["private_key"]}],
        )
        return raw, signed

    def _assert_one_reward_locked(self, wallet, amount, *, phase):
        status = wallet.getmigrationstatus()
        assert_equal(status["phase"], phase)
        # Compatibility fields count only payouts that are still phase-locked.
        assert_equal(status["goldrush_reward_outputs_needing_move"], 1)
        assert_equal(Decimal(status["goldrush_reward_amount_needing_move"]), amount)

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Creating a wallet with mature staking and QQSPROOF funding coins")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name=WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.staking(False)
        node.createwallet(wallet_name=MIGRATION_WALLET_NAME)
        migration_wallet = node.get_wallet_rpc(MIGRATION_WALLET_NAME)
        migration_wallet.staking(False)

        staking_address = wallet.getnewaddress("", "legacy")
        claim_address = wallet.getnewaddress("", "legacy")
        migration_legacy_address = migration_wallet.getnewaddress("migration-source", "legacy")
        self.generatetoaddress(node, 1, staking_address, sync_fun=self.no_op)
        migration_funding_block = self.generatetoaddress(
            node, 1, migration_legacy_address, sync_fun=self.no_op
        )[0]
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staking_address, sync_fun=self.no_op)
        self.generatetoaddress(node, COINBASE_MATURITY + 2, claim_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")
        migration_wallet.encryptwallet(MIGRATION_PASSPHRASE)

        self.log.info("migratetoquantum dry-runs require an existing wallet-backed destination and do not create keys")
        assert_raises_rpc_error(
            -8,
            "dry_run requires existing_address",
            wallet.migratetoquantum,
            {"dry_run": True},
        )
        legacy_dry_destination = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        wallet.encryptwallet("test-passphrase")
        legacy_dry_run = wallet.migratetoquantum({"dry_run": True, "existing_address": legacy_dry_destination})
        assert_equal(legacy_dry_run["destination"], legacy_dry_destination)
        assert_equal(legacy_dry_run["newly_generated"], False)
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        wallet.walletpassphrase("test-passphrase", 600)
        assert_raises_rpc_error(
            -8,
            "allow_new_quantum_key",
            wallet.migratetoquantum,
            {},
        )
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        assert_raises_rpc_error(
            -4,
            "Quantum funding is disabled during Gold Rush",
            wallet.migratetoquantum,
            {"allow_new_quantum_key": True},
        )
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)

        self.log.info("Mining a Gold Rush payout to a wallet-backed quantum address")
        payout_address = wallet.getnewquantumaddress()["address"]
        claim = wallet.sendshadowpowclaim(claim_address, payout_address, 500000)
        self._mine_pos_block_with_claim(wallet, claim["txid"])
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address)

        self.log.info("Maturing the synthetic payout before attempting migration")
        self.generatetoaddress(node, COINBASE_MATURITY, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo = self._wait_for_quantum_utxo(wallet, payout_address, min_conf=COINBASE_MATURITY + 1)
        payout_amount = Decimal(str(payout_utxo["amount"]))
        self._assert_one_reward_locked(wallet, payout_amount, phase="gold_rush")

        self.log.info("Cold-stake funding is phase-gated throughout Gold Rush")
        staker_key = wallet.dumpquantumkey(wallet.getnewquantumaddress()["address"])
        coldstake_address = wallet.getnewquantumcoldstakingaddress(staker_key["public_key"], "rpc-coldstake")["address"]
        mempool_before = set(node.getrawmempool())
        assert_raises_rpc_error(
            -4,
            "cannot be funded until the post-Gold-Rush migration phase",
            wallet.fundquantumcoldstakeaddress,
            coldstake_address,
            Decimal("1"),
            {"allow_goldrush_migration": False, "allow_new_quantum_key": True},
        )
        assert_equal(set(node.getrawmempool()), mempool_before)
        self._assert_one_reward_locked(wallet, payout_amount, phase="gold_rush")

        self.log.info("migrategoldrushrewards remains disabled during Gold Rush")
        goldrush_destination = wallet.getnewquantumaddress()["address"]
        assert_raises_rpc_error(
            -4,
            "remain locked until quantum witness spends activate after the Gold Rush",
            wallet.migrategoldrushrewards,
            {"dry_run": True, "existing_address": goldrush_destination},
        )
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 1)

        self.log.info("Advancing to the migration window")
        # The bridge blocks are still validated under the preceding Gold Rush
        # MTP context, so mine them to a legacy script until G+1 is active.
        mining_address = wallet.getnewaddress("", "legacy")
        self._mine_to_height(GOLD_RUSH_END_HEIGHT - 1, mining_address)

        self.log.info("The last Gold Rush candidate block still rejects legacy migration funding")
        before_boundary = node.getquantumquasarinfo()
        assert_equal(before_boundary["active_tip_height"], GOLD_RUSH_END_HEIGHT - 1)
        assert_equal(before_boundary["active_tip_phase"], "gold_rush")
        assert_equal(before_boundary["next_block_height"], GOLD_RUSH_END_HEIGHT)
        assert_equal(before_boundary["next_block_phase"], "gold_rush")
        assert_equal(before_boundary["quantum_spend_enforcement_active"], False)
        migration_wallet.walletpassphrase(MIGRATION_PASSPHRASE, 600)
        migration_inputs = migration_wallet.listunspent(1, 9999999, [migration_legacy_address])
        assert_equal(len(migration_inputs), 1)
        migration_input = migration_inputs[0]
        migration_input_amount = Decimal(str(migration_input["amount"]))
        assert_equal(
            node.getblock(migration_funding_block)["height"],
            2,
        )
        migration_status_before = migration_wallet.getmigrationstatus()
        assert_equal(migration_status_before["phase"], "gold_rush")
        assert_equal(migration_status_before["eligible_legacy_inputs"], 1)
        assert_equal(Decimal(migration_status_before["eligible_legacy_amount"]), migration_input_amount)
        assert_equal(migration_status_before["migrated_quantum_outputs"], 0)
        quantum_keys_before = len(migration_wallet.listquantumaddresses())
        assert_raises_rpc_error(
            -8,
            "allow_new_quantum_key",
            migration_wallet.migratetoquantum,
            {},
        )
        assert_equal(len(migration_wallet.listquantumaddresses()), quantum_keys_before)
        assert_raises_rpc_error(
            -4,
            "Quantum funding is disabled during Gold Rush",
            migration_wallet.migratetoquantum,
            {"allow_new_quantum_key": True},
        )
        assert_equal(len(migration_wallet.listquantumaddresses()), quantum_keys_before)

        self.log.info("Height G validates under Gold Rush while height G+1 opens Migration")
        last_goldrush_block = self.generatetoaddress(
            node, 1, mining_address, sync_fun=self.no_op
        )[0]
        self._bump_mocktime(16)
        assert_equal(node.getblock(last_goldrush_block)["height"], GOLD_RUSH_END_HEIGHT)
        boundary = node.getquantumquasarinfo()
        assert_equal(boundary["active_tip_height"], GOLD_RUSH_END_HEIGHT)
        assert_equal(boundary["active_tip_phase"], "gold_rush")
        assert_equal(boundary["next_block_height"], GOLD_RUSH_END_HEIGHT + 1)
        assert_equal(boundary["next_block_phase"], "migration")
        assert_equal(boundary["phase"], "migration")
        assert_equal(boundary["quantum_spend_enforcement_active"], True)

        self.log.info("An authorized key remains durable and produces an explicit backup warning if construction later fails")
        failed_key_addresses_before = {
            key["address"] for key in migration_wallet.listquantumaddresses()
        }
        mempool_before_failed_migration = set(node.getrawmempool())
        try:
            migration_wallet.migratetoquantum({
                "label": "failed-migration-key",
                "allow_new_quantum_key": True,
                "fee_rate": Decimal("10000000"),
            })
        except JSONRPCException as failure:
            assert_equal(failure.error["code"], -4)
            assert "failed after creating durable non-HD ML-DSA key" in failure.error["message"]
            assert "Back up the wallet now" in failure.error["message"]
        else:
            raise AssertionError("high-fee migration unexpectedly succeeded")
        failed_keys = migration_wallet.listquantumaddresses()
        assert_equal(len(failed_keys), len(failed_key_addresses_before) + 1)
        durable_failure_keys = [
            key for key in failed_keys
            if key["address"] not in failed_key_addresses_before
        ]
        assert_equal(len(durable_failure_keys), 1)
        assert_equal(durable_failure_keys[0]["label"], "failed-migration-key")
        assert_equal(durable_failure_keys[0]["stored_in_wallet"], True)
        assert_equal(durable_failure_keys[0]["encrypted"], True)
        assert_equal(set(node.getrawmempool()), mempool_before_failed_migration)

        self.log.info("migratetoquantum sweeps the funded legacy anchor into one durable v16 output")
        quantum_keys_before = len(migration_wallet.listquantumaddresses())
        migration = migration_wallet.migratetoquantum({
            "label": "lifecycle-migration",
            "allow_new_quantum_key": True,
        })
        migration_fee = Decimal(str(migration["fee"]))
        migration_amount = Decimal(str(migration["amount"]))
        assert_equal(migration["phase"], "migration")
        assert_equal(migration["eligible_inputs"], 1)
        assert_equal(Decimal(str(migration["eligible_amount"])), migration_input_amount)
        assert_equal(migration["newly_generated"], True)
        assert_equal(migration["stored_in_wallet"], True)
        assert migration_fee > 0
        assert_equal(migration_amount, migration_input_amount - migration_fee)
        assert migration["vsize"] > 0
        assert "Back up the wallet" in migration["warning"]
        assert migration["txid"] in node.getrawmempool()
        assert_equal(len(migration_wallet.listquantumaddresses()), quantum_keys_before + 1)

        migration_keys = migration_wallet.listquantumaddresses()
        assert_equal(len(migration_keys), quantum_keys_before + 1)
        migrated_key = next(key for key in migration_keys if key["address"] == migration["destination"])
        assert_equal(migrated_key["stored_in_wallet"], True)
        assert_equal(migrated_key["encrypted"], True)
        assert_equal(migrated_key["label"], "lifecycle-migration")

        decoded_migration = node.getrawtransaction(migration["txid"], True)
        assert_equal(len(decoded_migration["vin"]), 1)
        assert_equal(decoded_migration["vin"][0]["txid"], migration_input["txid"])
        assert_equal(decoded_migration["vin"][0]["vout"], migration_input["vout"])
        assert_equal(len(decoded_migration["vout"]), 1)
        assert_equal(
            decoded_migration["vout"][0]["scriptPubKey"]["hex"],
            node.validateaddress(migration["destination"])["scriptPubKey"],
        )
        assert_equal(Decimal(str(decoded_migration["vout"][0]["value"])), migration_amount)

        node.syncwithvalidationinterfacequeue()
        migration_status_mempool = migration_wallet.getmigrationstatus()
        assert_equal(migration_status_mempool["phase"], "migration")
        assert_equal(migration_status_mempool["eligible_legacy_inputs"], 0)
        assert_equal(Decimal(migration_status_mempool["eligible_legacy_amount"]), Decimal("0"))
        assert_equal(migration_status_mempool["direct_quantum_outputs"], 1)
        assert_equal(Decimal(migration_status_mempool["direct_quantum_amount"]), migration_amount)

        migration_block = self.generatetoaddress(
            node, 1, mining_address, sync_fun=self.no_op
        )[0]
        node.syncwithvalidationinterfacequeue()
        assert_equal(node.getblock(migration_block)["height"], GOLD_RUSH_END_HEIGHT + 1)
        assert migration["txid"] in node.getblock(migration_block)["tx"]
        assert node.gettxout(migration_input["txid"], migration_input["vout"], False) is None
        migrated_utxo = self._wait_for_quantum_utxo(
            migration_wallet, migration["destination"], min_conf=1
        )
        assert_equal(Decimal(str(migrated_utxo["amount"])), migration_amount)
        assert_equal(Decimal(str(migration_wallet.getwalletinfo()["balance"])), migration_amount)
        migration_wallet_tx = migration_wallet.gettransaction(migration["txid"])
        assert_equal(migration_wallet_tx["confirmations"], 1)
        assert_equal(Decimal(str(migration_wallet_tx["fee"])), -migration_fee)

        migration_status_confirmed = migration_wallet.getmigrationstatus()
        assert_equal(migration_status_confirmed["eligible_legacy_inputs"], 0)
        assert_equal(migration_status_confirmed["migrated_quantum_outputs"], 1)
        assert_equal(Decimal(migration_status_confirmed["migrated_quantum_amount"]), migration_amount)
        assert_equal(migration_status_confirmed["direct_quantum_outputs"], 1)
        assert_equal(Decimal(migration_status_confirmed["direct_quantum_amount"]), migration_amount)

        self.log.info("Legacy send RPCs refuse hidden quantum change keys and identify the explicit retry path")
        quantum_key_count_before_send = len(migration_wallet.listquantumaddresses())
        mempool_before_send = set(node.getrawmempool())
        assert_raises_rpc_error(
            -6,
            "legacy sendtoaddress, sendmany, and burn RPCs accept an existing change_address",
            migration_wallet.sendtoaddress,
            migration["destination"],
            Decimal("1"),
        )
        assert_equal(len(migration_wallet.listquantumaddresses()), quantum_key_count_before_send)
        assert_equal(set(node.getrawmempool()), mempool_before_send)

        explicit_change_send = migration_wallet.send(
            {migration["destination"]: Decimal("1")},
            {
                "inputs": [{"txid": migrated_utxo["txid"], "vout": migrated_utxo["vout"]}],
                "add_to_wallet": False,
                "change_address": migration["destination"],
            },
        )
        assert_equal(explicit_change_send["complete"], True)
        assert "hex" in explicit_change_send
        assert_equal(len(migration_wallet.listquantumaddresses()), quantum_key_count_before_send)
        assert_equal(set(node.getrawmempool()), mempool_before_send)

        self.log.info("Migration permits ML-DSA spends but forbids quantum-to-legacy downgrade")
        _, downgrade_signed = self._build_quantum_spend(
            migration_wallet,
            migrated_utxo,
            wallet.getnewaddress("migration-downgrade", "legacy"),
        )
        assert_equal(downgrade_signed["complete"], False)
        assert_equal(len(downgrade_signed["errors"]), 1)
        assert "Quantum-protected spends may only create quantum outputs" in downgrade_signed["errors"][0]["error"]
        _, quantum_signed = self._build_quantum_spend(
            migration_wallet,
            migrated_utxo,
            migration["destination"],
        )
        assert_equal(quantum_signed["complete"], True)
        quantum_accept = node.testmempoolaccept([quantum_signed["hex"]])[0]
        if not quantum_accept["allowed"]:
            raise AssertionError(f"migration-window quantum spend rejected: {quantum_accept}")

        self.log.info("Restart preserves the migration key, output, and exact wallet accounting")
        self.restart_node(0, extra_args=self.extra_args[0] + [f"-mocktime={self.mock_time}"])
        node = self.nodes[0]
        loaded_wallets = set(node.listwallets())
        for wallet_name in (WALLET_NAME, MIGRATION_WALLET_NAME):
            if wallet_name not in loaded_wallets:
                node.loadwallet(wallet_name)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        migration_wallet = node.get_wallet_rpc(MIGRATION_WALLET_NAME)
        wallet.walletpassphrase("test-passphrase", 600)
        migration_wallet.walletpassphrase(MIGRATION_PASSPHRASE, 600)
        migration_keys = migration_wallet.listquantumaddresses()
        assert_equal(len(migration_keys), quantum_keys_before + 1)
        migrated_key = next(key for key in migration_keys if key["address"] == migration["destination"])
        assert_equal(migrated_key["stored_in_wallet"], True)
        failed_key = next(key for key in migration_keys if key["label"] == "failed-migration-key")
        assert_equal(failed_key["stored_in_wallet"], True)
        migrated_utxo = self._wait_for_quantum_utxo(
            migration_wallet, migration["destination"], min_conf=1
        )
        assert_equal(Decimal(str(migrated_utxo["amount"])), migration_amount)
        restart_status = migration_wallet.getmigrationstatus()
        assert_equal(restart_status["eligible_legacy_inputs"], 0)
        assert_equal(restart_status["direct_quantum_outputs"], 1)
        assert_equal(Decimal(restart_status["direct_quantum_amount"]), migration_amount)

        self.log.info("A one-block reorg returns the migration to the mempool without losing accounting")
        node.invalidateblock(migration_block)
        self.wait_until(lambda: migration["txid"] in node.getrawmempool(), timeout=20)
        node.syncwithvalidationinterfacequeue()
        assert_equal(migration_wallet.gettransaction(migration["txid"])["confirmations"], 0)
        reorg_status = migration_wallet.getmigrationstatus()
        assert_equal(reorg_status["phase"], "migration")
        assert_equal(reorg_status["eligible_legacy_inputs"], 0)
        assert_equal(reorg_status["direct_quantum_outputs"], 1)
        assert_equal(Decimal(reorg_status["direct_quantum_amount"]), migration_amount)
        node.reconsiderblock(migration_block)
        self.wait_until(lambda: node.getbestblockhash() == migration_block, timeout=20)
        node.syncwithvalidationinterfacequeue()
        assert migration["txid"] not in node.getrawmempool()
        assert_equal(migration_wallet.gettransaction(migration["txid"])["confirmations"], 1)

        status = wallet.getmigrationstatus()
        assert_equal(status["phase"], "migration")
        assert_equal(status["goldrush_remigration_active"], True)
        assert_equal(status["goldrush_reward_outputs_needing_move"], 0)
        assert_equal(Decimal(status["goldrush_reward_amount_needing_move"]), Decimal("0"))

        self.log.info("A matured payout is an ordinary quantum input after Gold Rush")
        non_reward_locks = [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(1, 9999999)
            if utxo["txid"] != payout_utxo["txid"] or utxo["vout"] != payout_utxo["vout"]
        ]
        wallet.lockunspent(False, non_reward_locks)
        self.log.info("A same-address raw spend is valid; no fresh-address covenant exists")
        _, same_address_signed = self._build_quantum_spend(wallet, payout_utxo, payout_address)
        assert_equal(same_address_signed["complete"], True)
        same_address_accept = node.testmempoolaccept([same_address_signed["hex"]])[0]
        if not same_address_accept["allowed"]:
            raise AssertionError(f"ordinary same-address payout spend rejected: {same_address_accept}")

        self.log.info("migrategoldrushrewards can dry-run once migration activates quantum reward spends")
        assert_raises_rpc_error(
            -8,
            "dry_run requires existing_address",
            wallet.migrategoldrushrewards,
            {"dry_run": True},
        )

        self.log.info("Optional consolidation does not create a no-op same-address transaction")
        assert_raises_rpc_error(
            -6,
            "No mature wallet-owned Gold Rush reward outputs",
            wallet.migrategoldrushrewards,
            {"existing_address": payout_address},
        )

        self.log.info("Optional consolidation dry-run reports fees without changing spendability")
        migration_address = wallet.getnewquantumaddress()["address"]
        quantum_count_before = len(wallet.listquantumaddresses())
        dry_run = wallet.migrategoldrushrewards({"dry_run": True, "existing_address": migration_address})
        assert_equal(dry_run["phase"], "migration")
        assert_equal(dry_run["eligible_inputs"], 1)
        assert_equal(Decimal(dry_run["eligible_amount"]), payout_amount)
        assert_equal(dry_run["destination"], migration_address)
        assert_equal(dry_run["newly_generated"], False)
        assert_equal(dry_run["stored_in_wallet"], True)
        assert "txid" not in dry_run
        assert Decimal(dry_run["fee"]) > 0
        assert Decimal(dry_run["amount"]) == payout_amount - Decimal(dry_run["fee"])
        assert_equal(len(wallet.listquantumaddresses()), quantum_count_before)
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 0)

        self.log.info("sendtoaddress selects the payout directly and mines it without consolidation")
        ordinary_destination = wallet.getnewquantumaddress()["address"]
        try:
            ordinary_txid = wallet.sendtoaddress(
                ordinary_destination,
                Decimal("1"),
                "",
                "",
                False,
                False,
                None,
                False,
                payout_address,
            )
        finally:
            wallet.lockunspent(True, non_reward_locks)
        assert ordinary_txid in node.getrawmempool()
        ordinary_block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        assert ordinary_txid in node.getblock(ordinary_block)["tx"]
        node.syncwithvalidationinterfacequeue()
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None

        ordinary_utxo = self._wait_for_quantum_utxo(wallet, ordinary_destination, min_conf=1)
        assert_equal(Decimal(str(ordinary_utxo["amount"])), Decimal("1"))

        self.log.info("Reloading and rescanning preserves ordinary payout-spend state")
        wallet.unloadwallet()
        node.loadwallet(WALLET_NAME)
        wallet = node.get_wallet_rpc(WALLET_NAME)
        wallet.walletpassphrase("test-passphrase", 600)
        wallet.rescanblockchain(0)
        node.syncwithvalidationinterfacequeue()
        assert_equal(wallet.getmigrationstatus()["goldrush_reward_outputs_needing_move"], 0)
        ordinary_utxo = self._wait_for_quantum_utxo(wallet, ordinary_destination, min_conf=1)
        assert_equal(Decimal(str(ordinary_utxo["amount"])), Decimal("1"))

        self.log.info("The payout-derived quantum output remains an ordinary migration-window coin")
        final_destination = wallet.getnewquantumaddress()["address"]
        _, spend_signed = self._build_quantum_spend(wallet, ordinary_utxo, final_destination)
        assert_equal(spend_signed["complete"], True)
        accepted = node.testmempoolaccept([spend_signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"ordinary quantum spend rejected: {accepted}")
        spend_txid = node.sendrawtransaction(spend_signed["hex"])
        spend_block = self.generatetoaddress(node, 1, mining_address, sync_fun=self.no_op)[0]
        assert spend_txid in node.getblock(spend_block)["tx"]
        assert node.gettxout(ordinary_utxo["txid"], ordinary_utxo["vout"], False) is None


if __name__ == "__main__":
    GoldRushMigrationRpcTest().main()
