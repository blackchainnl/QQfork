#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify the explicit v30.1.0-to-v30.1.1 chainstate rebuild contract.

Blocks connected by v30.1.0 can be base-ledger valid while lacking the
authenticated schema-12 auxiliary state required by v30.1.1. Normal startup
must fail closed without changing the old logical chainstate. An explicit
-reindex-chainstate must preserve the old database until reconstruction fully
validates the stored block bodies and durably commits a deterministic result.
"""

from io import BytesIO
import hashlib

from test_framework.messages import CBlock
from test_framework.p2p import MAGIC_BYTES
from test_framework.test_framework import BitcoinTestFramework
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal


COIN = 100_000_000
GOLD_RUSH_BLOCKS = 20
REWARD_BLOCKS_CONNECTED = 5
BASE_ARGS = [
    "-shadowwhitelistheight=1",
    f"-shadowgoldrushblocks={GOLD_RUSH_BLOCKS}",
]
PRE_UPGRADE_ARGS = [
    "-shadowwhitelistheight=100",
    "-shadowgoldrushstartheight=101",
    f"-shadowgoldrushblocks={GOLD_RUSH_BLOCKS}",
]


class GoldRushShadowReplayTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [PRE_UPGRADE_ARGS]

    def state_fingerprint(self, node):
        stats = node.gettxoutsetinfo("muhash")
        return {
            "height": stats["height"],
            "bestblock": stats["bestblock"],
            "txouts": stats["txouts"],
            "bogosize": stats["bogosize"],
            "muhash": stats["muhash"],
            "total_amount": stats["total_amount"],
            "goldrush": node.getgoldrushstate(),
        }

    @staticmethod
    def block_records(block_file_bytes):
        records = []
        offset = 0
        magic = MAGIC_BYTES["regtest"]
        while True:
            marker = block_file_bytes.find(magic, offset)
            if marker < 0 or marker + 8 > len(block_file_bytes):
                break
            size = int.from_bytes(block_file_bytes[marker + 4:marker + 8], "little")
            payload_start = marker + 8
            payload_end = payload_start + size
            if size == 0 or payload_end > len(block_file_bytes):
                break
            records.append((payload_start, payload_end))
            offset = payload_end
        return records

    @staticmethod
    def stable_chainstate_fingerprint(chainstate_dir):
        """Hash immutable LevelDB tables, excluding open/recovery metadata."""
        tables = sorted([
            path for pattern in ("*.ldb", "*.sst")
            for path in chainstate_dir.glob(pattern)
        ])
        assert tables, f"no immutable LevelDB tables found in {chainstate_dir}"
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in tables
        }

    def assert_failed_rebuild_rolls_back(
        self,
        mutation,
        restore,
        expected_state,
        expected_debug,
        expected_stderr=r"Error: A fatal internal error occurred",
        staged=True,
    ):
        node = self.nodes[0]
        datadir = node.chain_path
        source_db = datadir / "chainstate"
        backup_db = datadir / "chainstate.rebuild-backup"
        source_fingerprint = self.stable_chainstate_fingerprint(source_db)
        log_offset = node.debug_log_path.stat().st_size
        mutation()
        try:
            node.assert_start_raises_init_error(
                extra_args=BASE_ARGS + ["-reindex-chainstate"],
                expected_msg=expected_stderr,
                match=ErrorMatch.PARTIAL_REGEX,
            )
        finally:
            restore()

        # Inspect the persisted source before any reconstructing restart. The
        # live chainstate may contain a partially rebuilt tip, but the original
        # immutable LevelDB tables must still be byte-identical in the journaled
        # backup.
        if staged:
            assert_equal(
                (datadir / "chainstate-rebuild.journal").read_text(),
                "blackcoin-chainstate-rebuild-v2\n"
                "phase=building\n"
                "base=1\n"
                "snapshot=0\n"
                "commitment=0\n"
                f"tip={'0' * 64}\n"
                "coins=0\n"
                f"full_coin_hash={'0' * 64}\n",
            )
            assert backup_db.is_dir()
            preserved_fingerprint = self.stable_chainstate_fingerprint(backup_db)
        else:
            # A missing block file is detected while loading the block index,
            # before the rebuild transaction begins.
            assert not (datadir / "chainstate-rebuild.journal").exists()
            assert not backup_db.exists()
            assert source_db.is_dir()
            preserved_fingerprint = self.stable_chainstate_fingerprint(source_db)

        # Opening LevelDB may recover its write-ahead log into an additional
        # immutable table. Every table that was immutable before startup must
        # nevertheless survive byte-for-byte in the authoritative source or
        # its journaled backup.
        for name, digest in source_fingerprint.items():
            assert_equal(preserved_fingerprint.get(name), digest)
        debug_delta = node.debug_log_path.read_bytes()[log_offset:].decode(
            "utf8", errors="replace"
        )
        assert expected_debug in debug_delta, debug_delta

        # Restoring the block source and starting normally must roll back the
        # partial build before opening the old logical chainstate.
        self.start_node(0, extra_args=PRE_UPGRADE_ARGS)
        assert_equal(self.state_fingerprint(self.nodes[0]), expected_state)
        self.stop_node(0)
        assert not (datadir / "chainstate-rebuild.journal").exists()
        assert not backup_db.exists()
        assert not (datadir / "chainstate.rebuild-partial").exists()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Creating locally stored blocks while V4/Gold Rush accounting is inactive")
        self.generatetoaddress(node, 1 + REWARD_BLOCKS_CONNECTED, node.get_deterministic_priv_key().address, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), 1 + REWARD_BLOCKS_CONNECTED)
        legacy_state = node.getgoldrushstate()
        assert_equal(legacy_state["pow_amount"], 0)
        assert_equal(legacy_state["pos_amount"], 0)
        assert_equal(legacy_state["claimed_amount"], 0)
        legacy_fingerprint = self.state_fingerprint(node)
        legacy_tip = node.getbestblockhash()

        self.stop_node(0)

        self.log.info("Preserving the old database when actual reconstruction finds corrupt, truncated, or missing block data")
        block_file = node.blocks_path / "blk00000.dat"
        original_block_file = block_file.read_bytes()
        records = self.block_records(original_block_file)
        assert_equal(len(records), 1 + REWARD_BLOCKS_CONNECTED + 1)
        last_start, last_end = records[-1]

        # Change a transaction body without changing its serialized length or
        # the indexed 80-byte block header. Reconstruction must recompute and
        # reject the Merkle mismatch rather than trusting index-only validity.
        original_payload = original_block_file[last_start:last_end]
        block = CBlock()
        block.deserialize(BytesIO(original_payload))
        block.vtx[0].vout[0].nValue ^= 1
        corrupt_payload = block.serialize()
        assert_equal(len(corrupt_payload), len(original_payload))
        assert_equal(corrupt_payload[:80], original_payload[:80])
        assert corrupt_payload != original_payload
        corrupt_block_file = bytearray(original_block_file)
        corrupt_block_file[last_start:last_end] = corrupt_payload
        self.assert_failed_rebuild_rolls_back(
            lambda: block_file.write_bytes(corrupt_block_file),
            lambda: block_file.write_bytes(original_block_file),
            legacy_fingerprint,
            "bad-txnmrklroot",
        )

        # Witness bytes are not covered by the legacy transaction Merkle root.
        # Corrupt the committed witness nonce without changing the block header,
        # transaction IDs, or serialized record length.
        witness_block = CBlock()
        witness_block.deserialize(BytesIO(original_payload))
        witness_nonce = bytearray(
            witness_block.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0]
        )
        witness_nonce[0] ^= 1
        witness_block.vtx[0].wit.vtxinwit[0].scriptWitness.stack[0] = bytes(
            witness_nonce
        )
        corrupt_witness_payload = witness_block.serialize()
        assert_equal(len(corrupt_witness_payload), len(original_payload))
        assert_equal(corrupt_witness_payload[:80], original_payload[:80])
        corrupt_witness_file = bytearray(original_block_file)
        corrupt_witness_file[last_start:last_end] = corrupt_witness_payload
        self.assert_failed_rebuild_rolls_back(
            lambda: block_file.write_bytes(corrupt_witness_file),
            lambda: block_file.write_bytes(original_block_file),
            legacy_fingerprint,
            "Corrupt witness or Merkle data",
        )

        self.assert_failed_rebuild_rolls_back(
            lambda: block_file.write_bytes(original_block_file[:last_end - 1]),
            lambda: block_file.write_bytes(original_block_file),
            legacy_fingerprint,
            "Deserialize or I/O error",
        )

        missing_block_file = block_file.with_suffix(".dat.rebuild-test-backup")
        self.assert_failed_rebuild_rolls_back(
            lambda: block_file.rename(missing_block_file),
            lambda: missing_block_file.rename(block_file),
            legacy_fingerprint,
            "Unable to open file",
            expected_stderr=r"Error: Error loading block database",
            staged=False,
        )

        self.log.info("Refusing an obsolete chainstate without mutating its logical state")
        node.assert_start_raises_init_error(
            extra_args=BASE_ARGS,
            expected_msg=(
                r"Quantum Quasar v30\.1\.1 requires a one-time chainstate rebuild\. "
                r"Back up wallets and restart once with -reindex-chainstate\. "
                r"This startup did not wipe the existing chainstate\."
            ),
            match=ErrorMatch.PARTIAL_REGEX,
        )

        self.start_node(0, extra_args=PRE_UPGRADE_ARGS)
        node = self.nodes[0]
        assert_equal(node.getbestblockhash(), legacy_tip)
        assert_equal(self.state_fingerprint(node), legacy_fingerprint)

        self.log.info("Rebuilding schema-12 state with an explicit -reindex-chainstate")
        self.stop_node(0)
        self.run_chainstate_rebuild_first_pass(
            node, BASE_ARGS + ["-reindex-chainstate"])
        rebuild_journal = node.chain_path / "chainstate-rebuild.journal"
        rebuild_backup = node.chain_path / "chainstate.rebuild-backup"
        assert rebuild_backup.is_dir()

        self.log.info("Refusing full -reindex until a separate process verifies the replacement")
        node.assert_start_raises_init_error(
            extra_args=BASE_ARGS + ["-reindex"],
            expected_msg=(
                r"Error: A rebuilt chainstate is awaiting its protected verification "
                r"restart\."
            ),
            match=ErrorMatch.PARTIAL_REGEX,
        )
        assert rebuild_journal.exists()
        assert rebuild_backup.is_dir()
        assert (node.chain_path / "chainstate").is_dir()

        self.log.info("Rejecting a journal whose declared sources do not match its backups")
        original_journal = rebuild_journal.read_text()
        rebuild_journal.write_text(
            original_journal.replace("base=1\nsnapshot=0\n", "base=0\nsnapshot=1\n")
        )
        node.assert_start_raises_init_error(
            extra_args=BASE_ARGS,
            expected_msg=(
                r"Error: A committed chainstate rebuild has an inconsistent backup "
                r"topology"
            ),
            match=ErrorMatch.PARTIAL_REGEX,
        )
        assert rebuild_backup.is_dir()
        rebuild_journal.write_text(original_journal)

        self.log.info("Retaining the source backup when reopened verification fails")
        backup_fingerprint = self.stable_chainstate_fingerprint(rebuild_backup)
        block_file.write_bytes(corrupt_block_file)
        try:
            node.assert_start_raises_init_error(
                extra_args=BASE_ARGS + ["-checkblocks=0", "-checklevel=4"],
                expected_msg=r"Corrupted block database detected",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        finally:
            block_file.write_bytes(original_block_file)
        assert_equal(rebuild_journal.read_text(), original_journal)
        assert rebuild_backup.is_dir()
        assert_equal(
            self.stable_chainstate_fingerprint(rebuild_backup),
            backup_fingerprint,
        )

        self.log.info("Recovering cleanup after a crash in CLEANUP_READY")
        rebuild_journal.write_text(
            original_journal.replace("phase=commit-ready\n", "phase=cleanup-ready\n")
        )
        self.start_node(0, extra_args=BASE_ARGS)
        self.wait_until(
            lambda: not rebuild_journal.exists() and not rebuild_backup.exists(),
            timeout=60,
        )
        node = self.nodes[0]
        repaired_state = node.getgoldrushstate()
        expected_half_pool = REWARD_BLOCKS_CONNECTED * 290 * COIN
        assert_equal(repaired_state["pow_amount"], expected_half_pool)
        assert_equal(repaired_state["pos_amount"], expected_half_pool)
        assert_equal(repaired_state["claimed_amount"], 0)
        assert_equal(repaired_state["height"], 1 + REWARD_BLOCKS_CONNECTED)
        assert_equal(repaired_state["bestblock"], legacy_tip)
        assert_equal(repaired_state["replay_state"]["schema"], 12)
        assert_equal(repaired_state["replay_state"]["required_for_tip"], True)
        assert_equal(repaired_state["replay_state"]["present"], True)
        assert_equal(repaired_state["replay_state"]["marker_valid"], True)
        assert_equal(repaired_state["replay_state"]["valid_for_tip"], True)
        assert_equal(len(repaired_state["replay_state"]["commitment"]), 64)
        assert_equal(node.getblockcount(), 1 + REWARD_BLOCKS_CONNECTED)
        assert_equal(node.getbestblockhash(), legacy_tip)
        rebuilt_fingerprint = self.state_fingerprint(node)

        self.log.info("Confirming a second chainstate rebuild is deterministic")
        self.stop_node(0)
        self.run_chainstate_rebuild_first_pass(
            node, BASE_ARGS + ["-reindex-chainstate"])
        assert rebuild_backup.is_dir()

        self.log.info("Verifying the second rebuilt chainstate before retiring its backup")
        self.restart_after_chainstate_rebuild(0, extra_args=BASE_ARGS)
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)

        self.log.info("Confirming shadow state survives disconnect and reconnect")
        restored_tip = self.nodes[0].getbestblockhash()
        restored_height = self.nodes[0].getblockcount()
        self.nodes[0].invalidateblock(restored_tip)
        assert_equal(self.nodes[0].getblockcount(), restored_height - 1)
        self.nodes[0].reconsiderblock(restored_tip)
        self.wait_until(
            lambda: self.nodes[0].getbestblockhash() == restored_tip,
            timeout=60,
        )
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)

        self.log.info("Confirming a full block reindex produces the same state")
        self.restart_node(0, BASE_ARGS + ["-reindex"])
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)


if __name__ == "__main__":
    GoldRushShadowReplayTest().main()
