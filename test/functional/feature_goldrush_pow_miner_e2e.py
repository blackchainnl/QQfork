#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Exercise the built-in Gold Rush PoW miner through payout and maturity paths.

Manual sendshadowpowclaim coverage proves the consensus value path. This test
drives the in-process miner itself: a small non-whitelisted fee UTXO authenticates
the QQSPROOF, a separate staker includes it in a PoS block, and the resulting
synthetic quantum payout becomes an ordinary quantum UTXO after Gold Rush and normal maturity.
"""

from decimal import Decimal
import time

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


GOLD_RUSH_END_TIME = 2_000_000_000
MIGRATION_DEADLINE_TIME = GOLD_RUSH_END_TIME + 40_000
QQSPROOF_HEX = "51515350524f4f46"
QUANTUM_SPEND_FEE = Decimal("0.01")
MINER_FUNDING = Decimal("1.0")


class GoldRushPowMinerE2ETest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[
            "-txindex=1",
            "-staketimio=50",
            "-mempoolexpiry=1",
            "-shadowwhitelistheight=1",
            "-shadowgoldrushblocks=500",
            f"-qqgoldrushendtime={GOLD_RUSH_END_TIME}",
            f"-qqmigrationdeadlinetime={MIGRATION_DEADLINE_TIME}",
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
        assert inputs, "staker wallet must have mature staking inputs"
        for _ in range(1000):
            self._bump_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for a deterministic PoS kernel")

    def _mine_pos_block_with_claim(self, staker_wallet, claim_txid):
        node = self.nodes[0]
        last_error = None
        for _ in range(4):
            start_height = node.getblockcount()
            kernel_time = self._find_next_kernel_time(staker_wallet)
            self._set_mocktime(kernel_time - 16)
            staker_wallet.staking(True)
            try:
                self._set_mocktime(kernel_time)
                self.wait_until(lambda: node.getblockcount() > start_height, timeout=20)
                block_hash = node.getbestblockhash()
                block = node.getblock(block_hash, 2)
                assert "proof-of-stake" in block["flags"]
                txids = [tx["txid"] for tx in block["tx"]]
                assert claim_txid in txids[2:], "built-in miner QQSPROOF claim must be included as a fee-paying transaction"
                return block_hash
            except AssertionError as e:
                last_error = e
            finally:
                staker_wallet.staking(False)
            self._bump_mocktime(16)
        raise last_error or AssertionError("failed to mine deterministic PoS block")

    def _mine_until_phase(self, phase, target_time, address):
        node = self.nodes[0]
        self._set_mocktime(target_time)
        for _ in range(1000):
            self.generatetoaddress(node, 1, address, sync_fun=self.no_op)
            self._bump_mocktime(16)
            info = node.getquantumquasarinfo()
            if info["phase"] == phase and (phase != "migration" or info["quantum_spend_enforcement_active"]):
                return
        raise AssertionError(f"timed out waiting for phase {phase}")

    def _pow_claim_txids(self):
        node = self.nodes[0]
        claim_txids = []
        for txid in node.getrawmempool():
            decoded = node.decoderawtransaction(node.getrawtransaction(txid))
            if any(QQSPROOF_HEX in vout["scriptPubKey"]["hex"] for vout in decoded["vout"]):
                claim_txids.append(txid)
        return claim_txids

    def _wait_for_miner_claim(self, wallet, *, timeout=120):
        deadline = time.time() + timeout
        last_log = 0
        while time.time() < deadline:
            claim_txids = self._pow_claim_txids()
            info = wallet.getpowmininginfo()
            if info["claims_submitted"] > 0 and claim_txids:
                return claim_txids[0]
            now = time.time()
            if now - last_log >= 10:
                self.log.info(
                    "PoW miner wait: enabled=%s epoch_active=%s hashrate=%.2f claims=%s next_claim=%s mempool_claims=%s",
                    info["enabled"],
                    info["epoch_active"],
                    info["hashrate"],
                    info["claims_submitted"],
                    info["next_claim_amount"],
                    len(claim_txids),
                )
                last_log = now
            time.sleep(0.25)
        raise AssertionError(f"built-in PoW miner did not submit a claim within {timeout} seconds; last info={wallet.getpowmininginfo()}")

    def _get_quantum_utxos(self, wallet, address, *, min_conf=0):
        options = {"include_immature_coinbase": True}
        return wallet.listunspent(min_conf, 9999999, [address], True, options)

    def _wait_for_quantum_utxo(self, wallet, address, *, min_conf=0):
        self.wait_until(lambda: len(self._get_quantum_utxos(wallet, address, min_conf=min_conf)) == 1, timeout=30)
        return self._get_quantum_utxos(wallet, address, min_conf=min_conf)[0]

    def _assert_no_onchain_block_output_to(self, block_hash, address):
        block = self.nodes[0].getblock(block_hash, 2)
        for tx in block["tx"]:
            for vout in tx["vout"]:
                assert vout["scriptPubKey"].get("address") != address

    @staticmethod
    def _is_abandoned(wallet, txid):
        return any(detail.get("abandoned", False) for detail in wallet.gettransaction(txid)["details"])

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

    def _fund_miner_wallet(self, staker_wallet, miner_wallet, staker_address, miner_address):
        node = self.nodes[0]
        funding_txid = staker_wallet.sendtoaddress(miner_address, MINER_FUNDING)
        funding_block = self.generatetoaddress(node, 1, staker_address, sync_fun=self.no_op)[0]
        assert funding_txid in node.getblock(funding_block)["tx"]
        self._sync_mocktime_to_tip()
        self.wait_until(lambda: len(miner_wallet.listunspent(1, 9999999, [miner_address])) == 1, timeout=30)

    def _assert_unfunded_miner_requires_fee_utxo(self, miner_wallet, miner_address):
        node = self.nodes[0]
        payout_address = miner_wallet.getnewquantumaddress()["address"]
        assert_raises_rpc_error(
            -6,
            "No spendable non-dust UTXO found for the target address",
            miner_wallet.sendshadowpowclaim,
            miner_address,
            payout_address,
            1,
        )

        existing_claims = set(self._pow_claim_txids())
        started = miner_wallet.setpowmining(True, 1, 100)
        assert_equal(started["enabled"], True)
        assert_equal(started["threads"], 1)
        assert_equal(started["cpu_percent"], 100)
        assert_equal(node.validateaddress(started["payout_address"])["isvalid"], True)
        try:
            time.sleep(1)
            info = miner_wallet.getpowmininginfo()
            assert_equal(info["enabled"], True)
            assert_equal(info["claims_submitted"], 0)
            assert not (set(self._pow_claim_txids()) - existing_claims), "unfunded PoW miner must not broadcast a QQSPROOF claim"
        finally:
            miner_wallet.setpowmining(False)
            self._sync_mocktime_to_tip()

    def _start_miner_until_claim(self, miner_wallet):
        node = self.nodes[0]
        started = miner_wallet.setpowmining(True, 1, 100)
        assert_equal(started["enabled"], True)
        assert_equal(started["threads"], 1)
        assert_equal(started["cpu_percent"], 100)
        payout_address = started["payout_address"]
        assert_equal(node.validateaddress(payout_address)["isvalid"], True)
        try:
            claim_txid = self._wait_for_miner_claim(miner_wallet)
            assert_equal(miner_wallet.getpowmininginfo()["payout_address"], payout_address)
            return claim_txid, payout_address
        finally:
            miner_wallet.setpowmining(False)
            self._sync_mocktime_to_tip()

    def run_test(self):
        node = self.nodes[0]
        self._set_mocktime((int(time.time()) & ~0xf) + 16)

        self.log.info("Preparing separate staker, successful miner, and stale miner wallets")
        node.get_wallet_rpc(self.default_wallet_name).staking(False)
        node.createwallet(wallet_name="goldrush_pow_staker")
        node.createwallet(wallet_name="goldrush_pow_miner")
        node.createwallet(wallet_name="goldrush_pow_stale")
        node.createwallet(wallet_name="goldrush_pow_age")
        node.createwallet(wallet_name="goldrush_pow_repair")
        node.createwallet(wallet_name="goldrush_pow_empty")
        staker = node.get_wallet_rpc("goldrush_pow_staker")
        miner = node.get_wallet_rpc("goldrush_pow_miner")
        stale_miner = node.get_wallet_rpc("goldrush_pow_stale")
        age_miner = node.get_wallet_rpc("goldrush_pow_age")
        repair_miner = node.get_wallet_rpc("goldrush_pow_repair")
        empty_miner = node.get_wallet_rpc("goldrush_pow_empty")
        for wallet in (staker, miner, stale_miner, age_miner, repair_miner, empty_miner):
            wallet.staking(False)

        staker_address = staker.getnewaddress("", "legacy")
        miner_address = miner.getnewaddress("", "legacy")
        stale_address = stale_miner.getnewaddress("", "legacy")
        age_address = age_miner.getnewaddress("", "legacy")
        repair_address = repair_miner.getnewaddress("", "legacy")
        empty_address = empty_miner.getnewaddress("", "legacy")

        self.log.info("Funding the staker and entering the Gold Rush phase")
        self.generatetoaddress(node, COINBASE_MATURITY + 2, staker_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        self.log.info("Confirming PoW claims are not whitelist-gated but still require a fee UTXO")
        self._assert_unfunded_miner_requires_fee_utxo(empty_miner, empty_address)

        self.log.info("Funding small non-whitelisted PoW fee UTXOs")
        self._fund_miner_wallet(staker, miner, staker_address, miner_address)
        self._fund_miner_wallet(staker, stale_miner, staker_address, stale_address)
        self._fund_miner_wallet(staker, age_miner, staker_address, age_address)
        self._fund_miner_wallet(staker, repair_miner, staker_address, repair_address)

        miner_entry = [entry for entry in miner.getgoldrushinfo()["wallet_scripts"] if entry["address"] == miner_address]
        assert miner_entry, "miner fee UTXO must be visible in Gold Rush wallet status"
        assert_equal(miner_entry[0]["whitelisted"], False)

        self.log.info("Expiring a built-in miner claim when the next block excludes it")
        stale_txid, _ = self._start_miner_until_claim(stale_miner)
        assert stale_txid in node.getrawmempool()
        stale_hex = node.getrawtransaction(stale_txid)
        stale_decoded = node.decoderawtransaction(stale_hex)
        stale_change = next(vout for vout in stale_decoded["vout"] if Decimal(str(vout["value"])) > 0)
        child_address = stale_miner.getnewaddress("stale-child", "legacy")
        child_amount = Decimal(str(stale_change["value"])) - Decimal("0.01")
        child_raw = node.createrawtransaction(
            [{"txid": stale_txid, "vout": stale_change["n"]}],
            [{child_address: child_amount}],
        )
        child_signed = stale_miner.signrawtransactionwithwallet(child_raw)
        assert_equal(child_signed["complete"], True)
        child_txid = node.sendrawtransaction(child_signed["hex"])
        assert child_txid in node.getrawmempool()
        empty_block = self.generateblock(node, output=staker_address, transactions=[])["hash"]
        assert stale_txid not in node.getblock(empty_block)["tx"]
        self.wait_until(lambda: stale_txid not in node.getrawmempool(), timeout=10)
        self.wait_until(lambda: self._is_abandoned(stale_miner, stale_txid), timeout=10)
        self.wait_until(lambda: self._is_abandoned(stale_miner, child_txid), timeout=10)
        assert_equal(stale_miner.gettransaction(stale_txid)["qq_auto_shadow_stale"], "1")
        stale_miner.abandontransaction(child_txid)
        assert_equal(stale_miner.gettransaction(child_txid)["qq_manual_shadow_abandon"], "1")
        stale_accept = node.testmempoolaccept([stale_hex])[0]
        assert_equal(stale_accept["allowed"], False)
        assert_equal(stale_accept["reject-reason"], "shadow-proof-invalid")
        assert_equal(len(stale_miner.listunspent(1, 9999999, [stale_address])), 1)
        assert_equal(Decimal(str(stale_miner.getbalances()["mine"]["trusted"])), MINER_FUNDING)
        self._sync_mocktime_to_tip()

        self.log.info("Restoring a claim package when a reorg restores its bound parent")
        node.invalidateblock(empty_block)
        self.wait_until(lambda: not self._is_abandoned(stale_miner, stale_txid), timeout=10)
        assert_equal(self._is_abandoned(stale_miner, child_txid), True)
        self.wait_until(lambda: stale_txid in node.getrawmempool(), timeout=20)
        recovered = stale_miner.gettransaction(stale_txid)
        assert "qq_auto_shadow_stale" not in recovered
        assert "qq_reorg_shadow_resubmit" not in recovered
        assert child_txid not in node.getrawmempool()

        # Exclude the recovered package from the replacement tip so it becomes
        # stale again and releases the same input for the next mining attempt.
        replacement_empty = self.generateblock(node, output=staker_address, transactions=[])["hash"]
        assert stale_txid not in node.getblock(replacement_empty)["tx"]
        self.wait_until(lambda: self._is_abandoned(stale_miner, stale_txid), timeout=10)
        assert_equal(self._is_abandoned(stale_miner, child_txid), True)
        self._sync_mocktime_to_tip()

        self.log.info("Reusing the released input and confirming that block inclusion is never abandoned")
        reused_txid, _ = self._start_miner_until_claim(stale_miner)
        reused_block_hash = self._mine_pos_block_with_claim(staker, reused_txid)
        assert reused_txid in node.getblock(reused_block_hash)["tx"]
        assert_equal(self._is_abandoned(stale_miner, reused_txid), False)
        reused_record = stale_miner.gettransaction(reused_txid)
        assert "qq_auto_shadow_stale" not in reused_record
        assert "qq_reorg_shadow_resubmit" not in reused_record

        self.log.info("Ordinary mempool age expiry must not abandon a still tip-valid claim")
        age_txid, _ = self._start_miner_until_claim(age_miner)
        age_hex = node.getrawtransaction(age_txid)
        self._bump_mocktime(2 * 60 * 60)
        staker.sendtoaddress(staker_address, Decimal("0.1"))
        self.wait_until(lambda: age_txid not in node.getrawmempool(), timeout=10)
        self.wait_until(lambda: not age_miner.gettransaction(age_txid)["trusted"], timeout=10)
        assert_equal(self._is_abandoned(age_miner, age_txid), False)
        assert_equal(node.sendrawtransaction(age_hex), age_txid)
        age_block_hash = self._mine_pos_block_with_claim(staker, age_txid)
        assert age_txid in node.getblock(age_block_hash)["tx"]
        assert_equal(self._is_abandoned(age_miner, age_txid), False)

        self.log.info("Repairing an already-stale v30.1.0-style claim when its wallet is loaded")
        repair_txid, _ = self._start_miner_until_claim(repair_miner)
        assert repair_txid in node.getrawmempool()
        repair_miner.unloadwallet()
        repair_block = self.generateblock(node, output=staker_address, transactions=[])["hash"]
        assert repair_txid not in node.getblock(repair_block)["tx"]
        self.wait_until(lambda: repair_txid not in node.getrawmempool(), timeout=10)
        node.loadwallet("goldrush_pow_repair")
        repair_miner = node.get_wallet_rpc("goldrush_pow_repair")
        self.wait_until(lambda: self._is_abandoned(repair_miner, repair_txid), timeout=10)
        assert_equal(len(repair_miner.listunspent(1, 9999999, [repair_address])), 1)
        assert_equal(Decimal(str(repair_miner.getbalances()["mine"]["trusted"])), MINER_FUNDING)
        self._sync_mocktime_to_tip()

        self.log.info("Submitting a fresh built-in miner claim and mining it in a PoS block")
        claim_txid, payout_address = self._start_miner_until_claim(miner)
        assert claim_txid in node.getrawmempool()
        claim_block_hash = self._mine_pos_block_with_claim(staker, claim_txid)
        self._assert_no_onchain_block_output_to(claim_block_hash, payout_address)

        self.log.info("Verifying the built-in miner payout is a synthetic quantum UTXO")
        payout_utxo = self._wait_for_quantum_utxo(miner, payout_address)
        assert_equal(payout_utxo["confirmations"], 1)
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is not None

        self.log.info("Maturing the built-in miner payout and spending it during migration")
        self.generatetoaddress(node, COINBASE_MATURITY, staker_address, sync_fun=self.no_op)
        self._sync_mocktime_to_tip()
        payout_utxo = self._wait_for_quantum_utxo(miner, payout_address, min_conf=COINBASE_MATURITY + 1)
        migration_address = miner.getnewquantumaddress()["address"]
        self._mine_until_phase("migration", GOLD_RUSH_END_TIME + 16, staker.getnewaddress("", "legacy"))

        raw, signed = self._build_quantum_spend(miner, payout_utxo, migration_address)
        assert_equal(signed["complete"], True)
        accepted = node.testmempoolaccept([signed["hex"]])[0]
        if not accepted["allowed"]:
            raise AssertionError(f"built-in miner payout spend rejected: {accepted}")
        spend_txid = node.sendrawtransaction(signed["hex"])
        spend_block_hash = self.generatetoaddress(node, 1, staker_address, sync_fun=self.no_op)[0]
        assert spend_txid in node.getblock(spend_block_hash)["tx"]
        assert node.gettxout(payout_utxo["txid"], payout_utxo["vout"], False) is None
        self._wait_for_quantum_utxo(miner, migration_address)


if __name__ == "__main__":
    GoldRushPowMinerE2ETest().main()
