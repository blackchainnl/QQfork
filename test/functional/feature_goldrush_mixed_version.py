#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Run pinned historical releases and the v30.1.1 candidate together.

The exact v26.2.0 reference and candidate remain the normative pair for
adversarial legacy-valid blocks and two-way reorganizations. The exact pinned
v30.1.0 release is also a scoped Gold Rush bridge authority: it and the
candidate must accept byte-identical ordinary base blocks in both propagation
directions and persist their common tip across restart. v28.4.0 remains a
diagnostic build because v26/v28 already diverge on known consensus paths.
"""

from decimal import Decimal
import hashlib
import json
from pathlib import Path

from test_framework.address import address_to_scriptpubkey, key_to_p2pkh
from test_framework.blocktools import (
    COINBASE_MATURITY,
    WITNESS_COMMITMENT_HEADER,
    create_block,
    create_coinbase,
    get_witness_script,
)
from test_framework.key import ECKey
from test_framework.messages import (
    COIN,
    CBlock,
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    from_hex,
    ser_uint256,
    uint256_from_str,
)
from test_framework.p2p import NODE_WITNESS, P2P_SERVICES, P2PDataStore
from test_framework.script import (
    CScript,
    OP_0,
    OP_DEPTH,
    OP_EQUAL,
    OP_FALSE,
    OP_NOP4,
    OP_RETURN,
    OP_TRUE,
    sign_input_legacy,
)
from test_framework.script_util import key_to_p2pk_script, program_to_witness_script, script_to_p2sh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import bytes_to_wif


VERSIONS = [260200, 280400, 300100, None]
EXPECTED_RPC_VERSIONS = [260200, 280400, 300100, 300101]
REFERENCE = 0
V30_1_0 = 2
CANDIDATE = 3
V30_1_0_COMMIT = "f647dc75c9479c03e81414f145a8d233b60959c7"
V30_1_0_REF_OBJECT = "1d16eba95983fb2bf41246de6250d7762a450c50"
GOLD_RUSH_ARGS = [
    "-shadowwhitelistheight=1",
    "-shadowgoldrushstartheight=2",
    "-shadowgoldrushblocks=500",
    "-qqgoldrushendheight=600",
    "-qqmigrationendheight=800",
]
FEE = COIN // 100
POS_SUBSIDY = 3 * COIN // 2
QQSPROOF = b"QQSPROOF"


class GoldRushMixedVersionTest(BitcoinTestFramework):
    def add_options(self, parser):
        # The pinned v26.2 build can stake only from a legacy wallet. Keep the
        # candidate on the same wallet format so both producers use one exact
        # fixed-key fixture rather than version-specific wallet machinery.
        self.add_wallet_options(parser, descriptors=False, legacy=True)

    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        base_args = ["-minimumchainwork=0x00", "-assumevalid=0"]
        self.extra_args = [
            # v26.2's checkkernel result metadata incorrectly declares fields
            # that are absent from a normal {"found": false} response as
            # mandatory. Disable only that historical self-check; the RPC
            # response and every candidate documentation check remain intact.
            base_args + ["-rpcdoccheck=0"],
            list(base_args),
            base_args + GOLD_RUSH_ARGS,
            base_args + GOLD_RUSH_ARGS,
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()
        self.skip_if_no_wallet()

    def setup_nodes(self):
        self.assert_v30_1_0_provenance()
        self.add_nodes(self.num_nodes, extra_args=self.extra_args, versions=VERSIONS)
        self.start_nodes()

        # Use a fixed key funded only after the height-one whitelist snapshot.
        # Both normative wallets therefore select the same non-whitelisted
        # staking population, and neither wallet owns the ordinary fee inputs.
        self.fee_boundary_stake_key = ECKey()
        self.fee_boundary_stake_key.set(b"\x20" * 32, compressed=True)
        self.fee_boundary_stake_wif = bytes_to_wif(
            self.fee_boundary_stake_key.get_bytes(), compressed=True
        )
        self.fee_boundary_stake_address = key_to_p2pkh(
            self.fee_boundary_stake_key.get_pubkey().get_bytes()
        )
        for index in (REFERENCE, CANDIDATE):
            self.nodes[index].createwallet(
                wallet_name=self.default_wallet_name,
                descriptors=False,
                load_on_startup=True,
            )
            wallet = self.nodes[index].get_wallet_rpc(self.default_wallet_name)
            wallet.importprivkey(
                self.fee_boundary_stake_wif,
                "gold-rush-fee-boundary-staker",
                False,
            )
            wallet.staking(False)

    def setup_network(self):
        self.setup_nodes()
        # Keep a direct normative link. Diagnostic nodes receive the ordinary
        # bootstrap chain, then stop before fixtures they are known to reject.
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.connect_nodes(1, REFERENCE)
        self.connect_nodes(2, REFERENCE)
        self.sync_blocks(self.nodes)

    @property
    def normative_nodes(self):
        return [self.nodes[REFERENCE], self.nodes[CANDIDATE]]

    @property
    def v30_bridge_nodes(self):
        return [self.nodes[V30_1_0], self.nodes[CANDIDATE]]

    @staticmethod
    def file_sha256(path):
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def assert_v30_1_0_provenance(self):
        """Fail closed if the v30.1.0 fixture is not the pinned release build."""
        releases = Path(self.options.previous_releases_path)
        provenance_path = releases / "provenance.json"
        if not provenance_path.is_file():
            raise AssertionError(
                "mixed-version provenance.json is missing; build fixtures with "
                "ci/mixed-version/build_previous_releases.py"
            )
        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf8"))
        except (OSError, ValueError) as error:
            raise AssertionError(f"cannot read mixed-version provenance: {error}") from error
        if provenance.get("schema") != 1:
            raise AssertionError("unsupported mixed-version provenance schema")
        sources = [
            source for source in provenance.get("sources", [])
            if source.get("version") == "v30.1.0"
        ]
        if len(sources) != 1:
            raise AssertionError("mixed-version provenance must contain exactly one v30.1.0 source")
        source = sources[0]
        assert_equal(source.get("commit"), V30_1_0_COMMIT)
        assert_equal(source.get("ref_object"), V30_1_0_REF_OBJECT)
        assert_equal(source.get("tag_kind"), "annotated")
        assert_equal(source.get("install_dir"), "v30.1")
        for binary in ("blackcoind", "blackcoin-cli"):
            binary_path = releases / "v30.1" / "bin" / binary
            if not binary_path.is_file():
                raise AssertionError(f"pinned v30.1.0 fixture is missing {binary_path}")
            assert_equal(
                self.file_sha256(binary_path),
                source.get("binaries", {}).get(binary),
            )

    def assert_normative_tip(self):
        tips = [node.getbestblockhash() for node in self.normative_nodes]
        assert_equal(len(set(tips)), 1)
        heights = [node.getblockcount() for node in self.normative_nodes]
        assert_equal(len(set(heights)), 1)

    def assert_v30_bridge_block(self, block_hash):
        tips = [node.getbestblockhash() for node in self.v30_bridge_nodes]
        assert_equal(tips, [block_hash, block_hash])
        heights = [node.getblockcount() for node in self.v30_bridge_nodes]
        assert_equal(len(set(heights)), 1)
        raw_blocks = [node.getblock(block_hash, 0) for node in self.v30_bridge_nodes]
        assert_equal(len(set(raw_blocks)), 1)

    def mine_and_sync(self, miner, blocks=1, nodes=None):
        sync_nodes = nodes or self.normative_nodes
        address = self.nodes[CANDIDATE].get_deterministic_priv_key().address
        generated = miner.generatetoaddress(blocks, address, invalid_call=False)

        # Read the serialized header rather than the verbose object. The pinned
        # v28.4 daemon validates its own RPC result metadata and incorrectly
        # declares two verbose getblockheader fields as strings. Raw-header
        # decoding keeps this interoperability fixture focused on block bytes
        # and consensus behavior without suppressing candidate RPC validation.
        header = from_hex(CBlockHeader(), miner.getblockheader(generated[-1], False))
        for node in sync_nodes:
            current_time = node.mocktime if node.mocktime is not None else 0
            if current_time < header.nTime:
                node.setmocktime(header.nTime)
        self.sync_blocks(sync_nodes, timeout=120)

    def generate_raw_block(self, producer, transactions):
        address = self.nodes[CANDIDATE].get_deterministic_priv_key().address
        result = self.generateblock(producer, address, transactions, sync_fun=self.no_op)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        return result["hash"]

    def coinbase_utxo(self, block_hash):
        coinbase = self.nodes[CANDIDATE].getblock(block_hash, 2)["tx"][0]
        output = coinbase["vout"][0]
        return {
            "txid": coinbase["txid"],
            "vout": 0,
            "value": int(Decimal(str(output["value"])) * COIN),
            "amount": output["value"],
            "script": output["scriptPubKey"]["hex"],
        }

    def signed_coin_spend(self, coin, outputs, *, version=2, tx_time=0):
        tx = CTransaction()
        tx.nVersion = version
        tx.nTime = tx_time
        tx.vin = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]
        tx.vout = list(outputs)
        signed = self.nodes[CANDIDATE].signrawtransactionwithkey(
            tx.serialize().hex(),
            [self.nodes[CANDIDATE].get_deterministic_priv_key().key],
            [{
                "txid": coin["txid"],
                "vout": coin["vout"],
                "scriptPubKey": coin["script"],
                "amount": coin["amount"],
            }],
        )
        assert_equal(signed["complete"], True)
        return signed["hex"]

    def fund_fee_boundary_stake_inputs(self, coins):
        """Create mature stake inputs with one serialized time on every node."""
        tip = self.nodes[CANDIDATE].getbestblockhash()
        funding_time = self.nodes[CANDIDATE].getblockheader(tip)["time"] + 1
        for node in self.nodes:
            node.setmocktime(funding_time)

        stake_script = address_to_scriptpubkey(self.fee_boundary_stake_address)
        transactions = [
            self.signed_coin_spend(
                coin,
                [CTxOut(coin["value"] - FEE, stake_script)],
                version=1,
                tx_time=funding_time,
            )
            for coin in coins
        ]
        for raw_transaction in transactions:
            transaction = from_hex(CTransaction(), raw_transaction)
            assert_equal(transaction.nVersion, 1)
            assert_equal(transaction.nTime, funding_time)

        funding_block = self.generateblock(
            self.nodes[REFERENCE],
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            transactions,
            sync_fun=self.no_op,
        )
        self.sync_blocks(self.nodes, timeout=180)
        for node in self.nodes:
            block = from_hex(CBlock(), node.getblock(funding_block["hash"], 0))
            assert_equal(len(block.vtx), len(transactions) + 1)
            for transaction in block.vtx[1:]:
                assert_equal(transaction.nVersion, 1)
                assert_equal(transaction.nTime, funding_time)
        self.mine_and_sync(
            self.nodes[REFERENCE],
            blocks=COINBASE_MATURITY,
            nodes=self.nodes,
        )

    def set_normative_mocktime(self, timestamp):
        for node in self.normative_nodes:
            node.setmocktime(timestamp)

    def bump_normative_mocktime(self, seconds=16):
        current = max(
            node.mocktime if node.mocktime is not None else 0
            for node in self.normative_nodes
        )
        self.set_normative_mocktime(current + seconds)

    def fee_boundary_staking_inputs(self, wallet):
        return [
            {"txid": utxo["txid"], "vout": utxo["vout"]}
            for utxo in wallet.listunspent(
                COINBASE_MATURITY,
                9999999,
                [self.fee_boundary_stake_address],
            )
        ]

    def find_fee_boundary_kernel_time(self, wallet):
        inputs = self.fee_boundary_staking_inputs(wallet)
        assert len(inputs) >= 2, "two mixed-version PoS rounds require two mature fixed-key inputs"
        for _ in range(5000):
            self.bump_normative_mocktime(16)
            kernel = wallet.checkkernel(inputs)
            if kernel["found"]:
                return kernel["kernel"]["time"]
        raise AssertionError("timed out searching for the mixed-version PoS fee-boundary kernel")

    def produce_fee_paying_pos_block(self, producer_index, fee_tx_hex):
        """Capture one real wallet-produced PoS block while its peer is isolated."""
        producer = self.nodes[producer_index]
        receiver_index = CANDIDATE if producer_index == REFERENCE else REFERENCE
        receiver = self.nodes[receiver_index]
        wallet = producer.get_wallet_rpc(self.default_wallet_name)

        self.disconnect_nodes(CANDIDATE, REFERENCE)
        parent_hash = producer.getbestblockhash()
        parent_height = producer.getblockcount()
        assert_equal(receiver.getbestblockhash(), parent_hash)
        fee_txid = producer.sendrawtransaction(fee_tx_hex)

        kernel_time = self.find_fee_boundary_kernel_time(wallet)
        self.set_normative_mocktime(kernel_time - 16)
        wallet.staking(True)
        try:
            self.set_normative_mocktime(kernel_time)
            self.wait_until(lambda: producer.getblockcount() > parent_height, timeout=30)
        finally:
            wallet.staking(False)

        block_hash = producer.getbestblockhash()
        block_json = producer.getblock(block_hash, 2)
        assert "proof-of-stake" in block_json["flags"]
        assert_equal(block_json["previousblockhash"], parent_hash)
        assert fee_txid in [tx["txid"] for tx in block_json["tx"][2:]]
        assert_equal(receiver.getbestblockhash(), parent_hash)
        stripped_raw = producer.getblock(block_hash, 0)
        witness_nonce = self.coinbase_witness_nonce(block_json)
        full_block = self.restore_coinbase_witness(stripped_raw, witness_nonce)
        full_block.rehash()
        full_raw = full_block.serialize().hex()
        assert_equal(full_block.hash, block_hash)
        assert_equal(len(bytes.fromhex(stripped_raw)), block_json["strippedsize"])
        assert_equal(len(bytes.fromhex(full_raw)), block_json["size"])

        return (
            full_raw,
            stripped_raw,
            block_hash,
            parent_hash,
            parent_height,
            fee_txid,
        )

    @staticmethod
    def coinbase_witness_nonce(block_json):
        coinbase_vin = block_json["tx"][0]["vin"]
        assert_equal(len(coinbase_vin), 1)
        nonce_stack = coinbase_vin[0].get("txinwitness", [])
        assert_equal(len(nonce_stack), 1)
        witness_nonce = bytes.fromhex(nonce_stack[0])
        assert_equal(len(witness_nonce), 32)

        # The controlled fee and coinstake transactions use only legacy P2PKH
        # inputs. This makes the coinbase nonce the complete witness delta
        # between the stripped RPC bytes and the relayed block serialization.
        for transaction in block_json["tx"][1:]:
            for txin in transaction["vin"]:
                assert "txinwitness" not in txin
        return witness_nonce

    @staticmethod
    def restore_coinbase_witness(stripped_raw, witness_nonce):
        block = from_hex(CBlock(), stripped_raw)
        coinbase = CTransaction(block.vtx[0])
        assert_equal(len(coinbase.wit.vtxinwit), 0)
        coinbase_witness = CTxInWitness()
        coinbase_witness.scriptWitness.stack = [witness_nonce]
        coinbase.wit.vtxinwit = [coinbase_witness]
        block.vtx[0] = coinbase
        return block

    def relay_and_rewind_wallet_pos_block(
        self,
        origin_index,
        receiver_index,
        full_raw,
        stripped_raw,
        block_hash,
        parent_hash,
        parent_height,
    ):
        """Relay the unmodified wallet block, then restore both isolated parents."""
        origin = self.nodes[origin_index]
        receiver = self.nodes[receiver_index]
        assert_equal(origin.getbestblockhash(), block_hash)
        assert_equal(receiver.getbestblockhash(), parent_hash)

        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        assert_equal(
            [node.getbestblockhash() for node in self.normative_nodes],
            [block_hash, block_hash],
        )
        assert_equal(
            [node.getblock(block_hash, 0) for node in self.normative_nodes],
            [stripped_raw, stripped_raw],
        )
        for node in self.normative_nodes:
            block_json = node.getblock(block_hash, 2)
            witness_nonce = self.coinbase_witness_nonce(block_json)
            restored = self.restore_coinbase_witness(stripped_raw, witness_nonce)
            assert_equal(restored.serialize().hex(), full_raw)

        self.disconnect_nodes(CANDIDATE, REFERENCE)
        for node in self.normative_nodes:
            node.invalidateblock(block_hash)
            assert_equal(node.getbestblockhash(), parent_hash)
            assert_equal(node.getblockcount(), parent_height)

    def coinstake_reward(self, raw_block):
        block = from_hex(CBlock(), raw_block)
        coinstake = block.vtx[1]
        value_in = 0
        for txin in coinstake.vin:
            coin = None
            for node in self.normative_nodes:
                coin = node.gettxout(
                    f"{txin.prevout.hash:064x}", txin.prevout.n, False
                )
                if coin is not None:
                    break
            assert coin is not None, (
                "coinstake input must be live on the isolated parent"
            )
            value_in += int(Decimal(str(coin["value"])) * COIN)
        return sum(txout.nValue for txout in coinstake.vout) - value_in

    @staticmethod
    def refresh_witness_commitment(block):
        commitment_indices = [
            index
            for index, txout in enumerate(block.vtx[0].vout)
            if bytes(txout.scriptPubKey).startswith(
                b"\x6a\x24" + WITNESS_COMMITMENT_HEADER
            )
        ]
        if not commitment_indices:
            return

        coinbase = CTransaction(block.vtx[0])
        assert_equal(len(coinbase.wit.vtxinwit), 1)
        nonce_stack = coinbase.wit.vtxinwit[0].scriptWitness.stack
        assert_equal(len(nonce_stack), 1)
        assert_equal(len(nonce_stack[0]), 32)
        witness_nonce = uint256_from_str(nonce_stack[0])

        block.vtx[0] = coinbase
        witness_root = block.calc_witness_merkle_root()
        coinbase.vout[commitment_indices[-1]].scriptPubKey = get_witness_script(
            witness_root, witness_nonce
        )
        coinbase.rehash()
        block.vtx[0] = coinbase

    def fee_boundary_block(self, raw_block, additional_reward):
        """Re-sign a captured coinstake after increasing its total reward."""
        block = from_hex(CBlock(), raw_block)
        coinstake = CTransaction(block.vtx[1])
        value_outputs = [
            index for index, txout in enumerate(coinstake.vout)
            if index > 0 and txout.nValue > 0
        ]
        assert value_outputs, "wallet-produced coinstake must return value"
        coinstake.vout[value_outputs[-1]].nValue += additional_reward
        for txin in coinstake.vin:
            txin.scriptSig = b""
        coinstake.rehash()

        signed = self.nodes[CANDIDATE].signrawtransactionwithkey(
            coinstake.serialize().hex(),
            [self.fee_boundary_stake_wif],
        )
        assert_equal(signed["complete"], True)
        block.vtx[1] = from_hex(CTransaction(), signed["hex"])
        self.refresh_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.vchBlockSig = self.fee_boundary_stake_key.sign_ecdsa(
            ser_uint256(block.sha256),
            rfc6979=True,
        )
        return (
            block.serialize().hex(),
            block.serialize(with_witness=False).hex(),
            block.hash,
        )

    def accept_fee_boundary_block(
        self,
        origin_index,
        receiver_index,
        full_raw,
        stripped_raw,
        block_hash,
    ):
        origin = self.nodes[origin_index]
        receiver = self.nodes[receiver_index]
        proposal = {"mode": "proposal", "data": full_raw}
        for node in self.normative_nodes:
            assert_equal(node.getblocktemplate(proposal), None)

        # submitblock applies its historical PoW precheck even to a coinstake
        # body. Deliver the exact candidate through the production P2P path,
        # including the current protocol's explicit PoS marker, instead.
        block = from_hex(CBlock(), full_raw)
        block.nFlags = 1
        block.rehash()
        assert_equal(block.hash, block_hash)
        peer = origin.add_p2p_connection(
            P2PDataStore(),
            # Historical binaries may be executed through the provenance-
            # preserving container wrapper. Its inbound peer address is the
            # bridge gateway rather than the host socket, so perform the
            # protocol handshake without TestNode's host-address assertion.
            wait_for_verack=False,
            services=P2P_SERVICES | NODE_WITNESS,
        )
        try:
            peer.wait_for_verack()
            peer.sync_with_ping()
            peer.send_blocks_and_test(
                [block],
                origin,
                success=True,
                force_send=True,
                timeout=120,
            )
        finally:
            origin.disconnect_p2ps()

        assert_equal(origin.getbestblockhash(), block_hash)
        assert receiver.getbestblockhash() != block_hash

        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(receiver.getbestblockhash(), block_hash)
        accepted = [node.getblock(block_hash, 0) for node in self.normative_nodes]
        assert_equal(accepted, [stripped_raw, stripped_raw])
        for node in self.normative_nodes:
            block_json = node.getblock(block_hash, 2)
            witness_nonce = self.coinbase_witness_nonce(block_json)
            restored = self.restore_coinbase_witness(stripped_raw, witness_nonce)
            assert_equal(restored.serialize().hex(), full_raw)

    def exercise_gold_rush_pos_fee_boundary(self, fee_coins, change_script):
        """Prove the deployed v26 PoS two-fee ceiling in both directions."""
        rounds = (
            (CANDIDATE, REFERENCE, fee_coins[0]),
            (REFERENCE, CANDIDATE, fee_coins[1]),
        )
        last_hash = None
        for origin_index, receiver_index, fee_coin in rounds:
            fee_tx_hex = self.signed_coin_spend(
                fee_coin,
                [CTxOut(fee_coin["value"] - FEE, change_script)],
            )
            (
                original_full_raw,
                original_stripped_raw,
                original_hash,
                parent_hash,
                parent_height,
                fee_txid,
            ) = self.produce_fee_paying_pos_block(origin_index, fee_tx_hex)
            assert_equal(
                self.coinstake_reward(original_full_raw),
                POS_SUBSIDY + FEE,
            )
            self.relay_and_rewind_wallet_pos_block(
                origin_index,
                receiver_index,
                original_full_raw,
                original_stripped_raw,
                original_hash,
                parent_hash,
                parent_height,
            )

            ceiling_full_raw, ceiling_stripped_raw, ceiling_hash = (
                self.fee_boundary_block(original_full_raw, FEE)
            )
            over_full_raw, _, _ = self.fee_boundary_block(
                original_full_raw,
                FEE + 1,
            )
            assert ceiling_full_raw != over_full_raw
            assert_equal(
                self.coinstake_reward(ceiling_full_raw),
                POS_SUBSIDY + 2 * FEE,
            )

            # Validate the exact same one-satoshi-over bytes on both isolated
            # implementations. Each must reach the reward check and give the
            # deployed legacy rejection reason, not a signature or kernel error.
            for node in self.normative_nodes:
                assert_equal(node.getbestblockhash(), parent_hash)
                assert_equal(node.getblocktemplate({
                    "mode": "proposal",
                    "data": over_full_raw,
                }), "bad-cs-amount")
                assert_equal(node.getbestblockhash(), parent_hash)

            self.accept_fee_boundary_block(
                origin_index,
                receiver_index,
                ceiling_full_raw,
                ceiling_stripped_raw,
                ceiling_hash,
            )
            assert fee_txid in self.nodes[CANDIDATE].getblock(ceiling_hash)["tx"]
            last_hash = ceiling_hash

        # Disable and unload both fixture wallets before restart. v26.2 starts
        # loaded wallets' staking threads automatically, which would make the
        # persistence assertion race an unrelated third PoS block.
        for index in (REFERENCE, CANDIDATE):
            wallet = self.nodes[index].get_wallet_rpc(self.default_wallet_name)
            wallet.staking(False)
            self.nodes[index].unloadwallet(self.default_wallet_name, False)

        for index in (REFERENCE, CANDIDATE):
            self.restart_node(index)
            assert_equal(self.nodes[index].getbestblockhash(), last_hash)
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()

        # The fee-boundary blocks must not leave either implementation unable
        # to extend or receive the ordinary base chain after a clean restart.
        self.mine_and_sync(self.nodes[REFERENCE], nodes=self.normative_nodes)
        self.mine_and_sync(self.nodes[CANDIDATE], nodes=self.normative_nodes)
        self.assert_normative_tip()

    @staticmethod
    def tx_from_outputs(prev_txid, prev_vout, prev_value, outputs, script_sig=b""):
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(prev_txid, 16), prev_vout), script_sig)]
        tx.vout = list(outputs)
        assert sum(output.nValue for output in tx.vout) <= prev_value - FEE
        tx.rehash()
        return tx

    def exercise_nop4_both_directions(self, coins, change_script):
        # This script succeeds only when opcode 0xb3 retains the reference
        # client's NOP4 semantics. Reinterpreting it as OP_ISCOINSTAKE pushes
        # an extra stack item and makes OP_DEPTH 0 EQUAL false.
        redeem = CScript([OP_NOP4, OP_DEPTH, OP_0, OP_EQUAL])
        p2sh = script_to_p2sh_script(redeem)
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            funding_hex = self.signed_coin_spend(coin, [
                CTxOut(COIN, p2sh),
                CTxOut(coin["value"] - COIN - FEE, change_script),
            ])
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = self.tx_from_outputs(
                funding.hash, 0, COIN,
                [CTxOut(COIN - FEE, change_script)],
                CScript([bytes(redeem)]),
            )
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_non_strict_sighash_both_directions(self, coins, change_script):
        key = ECKey()
        key.set(b"\x11" * 32, True)
        p2pk = key_to_p2pk_script(key.get_pubkey().get_bytes())
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            funding_hex = self.signed_coin_spend(coin, [
                CTxOut(COIN, p2pk),
                CTxOut(coin["value"] - COIN - FEE, change_script),
            ])
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = self.tx_from_outputs(
                funding.hash, 0, COIN,
                [CTxOut(COIN - FEE, change_script)],
            )
            # Base type 4 uses the reference client's ALL-like legacy digest,
            # but STRICTENC rejects the otherwise valid DER signature.
            sign_input_legacy(spend, 0, p2pk, key, sighash_type=4)
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_future_witness_both_directions(self, coins, change_script):
        versions = (2, 13, 14, 15, 16)
        scripts = [program_to_witness_script(v, bytes([v]) * 32) for v in versions]
        for coin, funding_producer, spending_producer in (
            (coins.pop(), self.nodes[REFERENCE], self.nodes[CANDIDATE]),
            (coins.pop(), self.nodes[CANDIDATE], self.nodes[REFERENCE]),
        ):
            outputs = [CTxOut(COIN, script) for script in scripts]
            outputs.append(CTxOut(coin["value"] - len(scripts) * COIN - FEE, change_script))
            funding_hex = self.signed_coin_spend(coin, outputs)
            self.generate_raw_block(funding_producer, [funding_hex])
            funding = from_hex(CTransaction(), funding_hex)
            funding.rehash()
            spend = CTransaction()
            spend.vin = [CTxIn(COutPoint(int(funding.hash, 16), n)) for n in range(len(scripts))]
            spend.vout = [CTxOut(len(scripts) * COIN - FEE, change_script)]
            spend.rehash()
            self.generate_raw_block(spending_producer, [spend.serialize().hex()])

    def exercise_shadow_lookalikes_both_directions(self, coins, change_script):
        marker = CScript([OP_FALSE, OP_RETURN, b"QQPOOL"])
        malformed = CScript([OP_RETURN, QQSPROOF + b"\x00"])
        oversized = CScript([OP_RETURN, QQSPROOF + b"\x00" * 600])
        excess = [CScript([OP_RETURN, QQSPROOF + bytes([i])]) for i in range(65)]
        scripts = [marker, malformed, malformed, oversized, *excess]
        for coin, producer in (
            (coins.pop(), self.nodes[REFERENCE]),
            (coins.pop(), self.nodes[CANDIDATE]),
        ):
            outputs = [CTxOut(0, script) for script in scripts]
            outputs.append(CTxOut(coin["value"] - FEE, change_script))
            tx_hex = self.signed_coin_spend(coin, outputs)
            self.generate_raw_block(producer, [tx_hex])

    @staticmethod
    def shaped_shadow_proof(mode, nonce, target_script, payout_script):
        return b"".join((
            QQSPROOF,
            b"QQP2",
            bytes([mode]),
            nonce.to_bytes(8, byteorder="little"),
            len(target_script).to_bytes(2, byteorder="little"),
            bytes(target_script),
            len(payout_script).to_bytes(2, byteorder="little"),
            bytes(payout_script),
        ))

    def exercise_shadow_modes_both_directions(self, coins, change_script):
        """Wrong QQSPROOF channels remain ordinary legacy-visible block data."""
        quantum_script = program_to_witness_script(16, b"\x42" * 32)
        pow_proof = self.shaped_shadow_proof(
            0, 11, change_script, quantum_script
        )
        pos_proof = self.shaped_shadow_proof(
            1, 12, change_script, quantum_script
        )
        unknown_proof = self.shaped_shadow_proof(
            0x7f, 13, change_script, quantum_script
        )

        for producer in (self.nodes[REFERENCE], self.nodes[CANDIDATE]):
            state_before = self.nodes[CANDIDATE].getgoldrushstate()
            proof_scripts = (
                [CScript([OP_RETURN, pos_proof])],
                [CScript([OP_RETURN, unknown_proof])],
                [CScript([OP_RETURN, pow_proof])],
                [CScript([OP_RETURN, pow_proof]),
                 CScript([OP_RETURN, pow_proof])],
            )
            transactions = []
            for scripts in proof_scripts:
                coin = coins.pop()
                outputs = [CTxOut(0, script) for script in scripts]
                outputs.append(CTxOut(coin["value"] - FEE, change_script))
                transactions.append(self.signed_coin_spend(coin, outputs))

            block_hash = self.generate_raw_block(producer, transactions)
            # Acceptance by both the exact v26 authority and the candidate is
            # the base-consensus invariant. Shadow policy is evaluated only
            # after that shared block-validity decision.
            assert_equal(
                self.nodes[REFERENCE].getblock(block_hash, 0),
                self.nodes[CANDIDATE].getblock(block_hash, 0),
            )
            state_after = self.nodes[CANDIDATE].getgoldrushstate()
            for field in (
                "claimed_amount",
                "pow_count",
                "pos_count",
                "last_pow_height",
                "last_pos_height",
                "recent_count",
            ):
                assert_equal(state_after[field], state_before[field])
            assert state_after["pow_amount"] > state_before["pow_amount"]
            assert state_after["pos_amount"] > state_before["pos_amount"]

            explorer = self.nodes[CANDIDATE].getgoldrushblock(block_hash)
            assert_equal(explorer["total_payouts"], 0)
            assert_equal(explorer["pow_payout_total"], 0)
            assert_equal(explorer["pos_payout_total"], 0)
            assert_equal(explorer["observed_pow_claim_txids"], [])
            observations = explorer["proof_observations"]
            assert_equal(len(observations), 5)
            assert_equal(
                sorted(observation["mode"] for observation in observations),
                ["pos", "pow", "pow", "pow", "unknown"],
            )
            assert_equal(
                sum(observation["duplicate_in_transaction"]
                    for observation in observations),
                2,
            )
            for observation in observations:
                assert_equal(observation["fee_paying_location"], False)
                assert_equal(observation["credit_channel"], "none")
                assert_equal(observation["non_credit_reason"],
                             "invalid_location")

    def exercise_v2_clock_determinism(self, coin, change_script):
        """Prove candidate/v30.1.0 block validity never depends on node time.

        A version-1 funding transaction preserves a nonzero serialized output
        time. v26/v28 substitute local adjusted time for the omitted timestamp
        of the version-2 spend, making their result depend on the verifier's
        clock. The candidate must instead preserve the already-deployed v30.1.0
        contract: ConnectBlock supplies the candidate block time to
        CheckTxInputs.
        """
        tip_time = self.nodes[CANDIDATE].getblockheader(
            self.nodes[CANDIDATE].getbestblockhash()
        )["time"]
        funding_time = tip_time + 1
        for node in self.nodes:
            node.setmocktime(funding_time + 1)
        funding_hex = self.signed_coin_spend(coin, [
            CTxOut(COIN, CScript([OP_TRUE])),
            CTxOut(coin["value"] - COIN - FEE, change_script),
        ], version=1, tx_time=funding_time)
        funding_result = self.generateblock(
            self.nodes[CANDIDATE],
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            [funding_hex],
            sync_fun=self.no_op,
        )
        self.sync_blocks(self.nodes, timeout=180)

        funding = from_hex(CTransaction(), funding_hex)
        funding.rehash()
        parent_hash = funding_result["hash"]
        parent_time = self.nodes[CANDIDATE].getblockheader(parent_hash)["time"]
        assert parent_time >= funding_time
        spend = self.tx_from_outputs(
            funding.hash,
            0,
            COIN,
            [CTxOut(COIN - FEE, change_script)],
        )
        height = self.nodes[CANDIDATE].getblockcount() + 1
        block = create_block(
            int(parent_hash, 16),
            create_coinbase(height),
            parent_time + 1,
            txlist=[spend],
        )
        block.solve()
        raw_block = block.serialize().hex()

        # Isolate every verifier so the byte-identical block is evaluated under
        # the clock assigned below, not first relayed by another generation.
        for index in (1, 2, CANDIDATE):
            self.disconnect_nodes(index, REFERENCE)

        early_time = funding_time - 1
        late_time = parent_time + 1_000
        self.nodes[REFERENCE].setmocktime(early_time)
        self.nodes[1].setmocktime(early_time)
        self.nodes[2].setmocktime(early_time)
        self.nodes[CANDIDATE].setmocktime(late_time)

        # The two historical generations expose the inherited clock seam. The
        # already-deployed v30.1.0 and this candidate must agree despite clocks
        # on opposite sides of the funding block time.
        assert_equal(
            self.nodes[REFERENCE].submitblock(raw_block),
            "bad-txns-time-earlier-than-input",
        )
        assert_equal(
            self.nodes[1].submitblock(raw_block),
            "bad-txns-time-earlier-than-input",
        )
        assert_equal(self.nodes[2].submitblock(raw_block), None)
        assert_equal(self.nodes[CANDIDATE].submitblock(raw_block), None)

        # Recover the normative v26 node under its own late-clock behavior so
        # the remainder of the interoperability/reorg test stays on one chain.
        for node in self.nodes:
            node.setmocktime(late_time)
        self.nodes[REFERENCE].reconsiderblock(block.hash)
        # reconsiderblock clears the cached failure and immediately runs
        # ActivateBestChain.  The recovered block must therefore already be
        # the reference tip; resubmitting it would correctly report a
        # duplicate and would test RPC bookkeeping rather than validity.
        assert_equal(self.nodes[REFERENCE].getbestblockhash(), block.hash)
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()

    def exercise_v30_1_0_gold_rush_bridge(self):
        """Prove the pinned v30.1.0/candidate ordinary-block bridge both ways."""
        assert_equal(
            self.nodes[V30_1_0].getbestblockhash(),
            self.nodes[CANDIDATE].getbestblockhash(),
        )
        for node in self.v30_bridge_nodes:
            assert_equal(node.getquantumquasarinfo()["phase"], "gold_rush")

        # Isolate this scoped pair from the v26 authority. First, v30.1.0
        # produces a base block and the candidate accepts those exact bytes.
        self.disconnect_nodes(CANDIDATE, REFERENCE)
        self.connect_nodes(CANDIDATE, V30_1_0)
        v30_hash = self.generatetoaddress(
            self.nodes[V30_1_0],
            1,
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            sync_fun=self.no_op,
        )[0]
        self.sync_blocks(self.v30_bridge_nodes, timeout=120)
        self.assert_v30_bridge_block(v30_hash)

        # Reverse the producer/receiver roles and the outbound connection.
        # The lagging v30.1.0 node must fetch and accept the candidate block.
        self.disconnect_nodes(CANDIDATE, V30_1_0)
        candidate_hash = self.generatetoaddress(
            self.nodes[CANDIDATE],
            1,
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            sync_fun=self.no_op,
        )[0]
        assert_equal(self.nodes[V30_1_0].getbestblockhash(), v30_hash)
        self.connect_nodes(V30_1_0, CANDIDATE)
        self.sync_blocks(self.v30_bridge_nodes, timeout=120)
        self.assert_v30_bridge_block(candidate_hash)

        # Each daemon must reload the same accepted tip from its own isolated
        # datadir before reconnecting. This catches acceptance that was only
        # transient in memory or dependent on the original peer session.
        for index in (V30_1_0, CANDIDATE):
            self.restart_node(index)
            assert_equal(self.nodes[index].getbestblockhash(), candidate_hash)
        self.connect_nodes(CANDIDATE, V30_1_0)
        self.sync_blocks(self.v30_bridge_nodes, timeout=120)
        self.assert_v30_bridge_block(candidate_hash)

        # Return the candidate to the v26 authority for the existing
        # adversarial/reorg gate. v30.1.0 remains scoped to ordinary blocks.
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()

    def run_test(self):
        self.log.info("Verifying every daemon is the pinned historical/candidate build")
        for node, expected in zip(self.nodes, EXPECTED_RPC_VERSIONS):
            assert_equal(node.getnetworkinfo()["version"], expected)

        self.log.info("Bootstrapping spendable reference-produced outputs on all four builds")
        mined = self.generatetoaddress(
            self.nodes[REFERENCE],
            COINBASE_MATURITY + 20,
            self.nodes[CANDIDATE].get_deterministic_priv_key().address,
            sync_fun=self.no_op,
        )
        self.sync_blocks(self.nodes, timeout=180)
        # Version-2 transactions omit nTime. v26.2 records a local adjusted
        # time for those outputs, while v30.1.0 and the candidate persist the
        # containing block time. Use serialized version-1 funding here so this
        # fee-boundary gate measures fee accounting rather than the separately
        # covered historical v2 clock seam.
        self.fund_fee_boundary_stake_inputs(
            [self.coinbase_utxo(block_hash) for block_hash in mined[1:5]]
        )
        for legacy_node in self.nodes[:3]:
            self.mine_and_sync(legacy_node, nodes=self.nodes)
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=2, nodes=self.nodes)
        assert_equal(len({node.getbestblockhash() for node in self.nodes}), 1)
        assert_equal(self.nodes[2].getquantumquasarinfo()["phase"], "gold_rush")
        assert_equal(self.nodes[3].getquantumquasarinfo()["phase"], "gold_rush")

        change_script = address_to_scriptpubkey(
            self.nodes[CANDIDATE].get_deterministic_priv_key().address
        )
        self.log.info("Checking v2 missing-time behavior across four exact generations")
        self.exercise_v2_clock_determinism(
            self.coinbase_utxo(mined[0]),
            change_script,
        )

        self.log.info("Bridging byte-identical Gold Rush base blocks with pinned v30.1.0 both ways")
        self.exercise_v30_1_0_gold_rush_bridge()

        self.log.info("Stopping diagnostic builds before known split-path fixtures")
        self.stop_node(1)
        self.stop_node(2)

        self.log.info("Crossing the exact Gold Rush PoS two-fee ceiling in both directions")
        self.exercise_gold_rush_pos_fee_boundary(
            [self.coinbase_utxo(block_hash) for block_hash in mined[25:27]],
            change_script,
        )

        coins = [self.coinbase_utxo(block_hash) for block_hash in mined[5:25]]

        self.log.info("Crossing NOP4 discriminator blocks in both directions")
        self.exercise_nop4_both_directions(coins, change_script)
        self.log.info("Crossing legacy-valid undefined-hashtype blocks in both directions")
        self.exercise_non_strict_sighash_both_directions(coins, change_script)
        self.log.info("Creating and spending witness v2/v13/v14/v15/v16 in both directions")
        self.exercise_future_witness_both_directions(coins, change_script)
        self.log.info("Crossing marker, malformed, duplicate, oversized, and excess QQ notes")
        self.exercise_shadow_lookalikes_both_directions(coins, change_script)
        self.log.info("Crossing PoS-mode, unknown-mode, duplicate, and PoW-mode QQSPROOF data")
        self.exercise_shadow_modes_both_directions(coins, change_script)

        self.log.info("A longer reference branch reorganizes the candidate")
        self.disconnect_nodes(CANDIDATE, REFERENCE)
        self.mine_and_sync(self.nodes[REFERENCE], blocks=3, nodes=[self.nodes[REFERENCE]])
        reference_tip = self.nodes[REFERENCE].getbestblockhash()
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=1, nodes=[self.nodes[CANDIDATE]])
        assert self.nodes[CANDIDATE].getbestblockhash() != reference_tip
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[CANDIDATE].getbestblockhash(), reference_tip)

        self.log.info("A longer candidate branch reorganizes the reference")
        self.disconnect_nodes(CANDIDATE, REFERENCE)
        self.mine_and_sync(self.nodes[REFERENCE], blocks=1, nodes=[self.nodes[REFERENCE]])
        self.mine_and_sync(self.nodes[CANDIDATE], blocks=3, nodes=[self.nodes[CANDIDATE]])
        candidate_tip = self.nodes[CANDIDATE].getbestblockhash()
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[REFERENCE].getbestblockhash(), candidate_tip)

        self.log.info("Restarting both normative generations preserves the common tip")
        for index in (REFERENCE, CANDIDATE):
            self.restart_node(index)
        self.connect_nodes(CANDIDATE, REFERENCE)
        self.sync_blocks(self.normative_nodes, timeout=120)
        self.assert_normative_tip()
        assert_equal(self.nodes[REFERENCE].getbestblockhash(), candidate_tip)


if __name__ == "__main__":
    GoldRushMixedVersionTest().main()
