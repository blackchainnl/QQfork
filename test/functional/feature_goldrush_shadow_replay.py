#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify the explicit v30.1.0-to-v30.1.1 chainstate rebuild contract.

Blocks connected by v30.1.0 can be base-ledger valid while lacking the
authenticated schema-11 auxiliary state and normalized UTXO timestamps required
by v30.1.1. Normal startup must fail closed without changing the old logical
chainstate. An explicit -reindex-chainstate must produce a deterministic result
that survives a clean restart and matches later chainstate and full reindexes.
"""

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

        self.log.info("Refusing an obsolete chainstate without mutating its logical state")
        self.stop_node(0)
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

        self.log.info("Rebuilding schema-11 state with an explicit -reindex-chainstate")
        self.restart_node(0, BASE_ARGS + ["-reindex-chainstate"])
        node = self.nodes[0]

        repaired_state = node.getgoldrushstate()
        expected_half_pool = REWARD_BLOCKS_CONNECTED * 290 * COIN
        assert_equal(repaired_state["pow_amount"], expected_half_pool)
        assert_equal(repaired_state["pos_amount"], expected_half_pool)
        assert_equal(repaired_state["claimed_amount"], 0)
        assert_equal(repaired_state["height"], 1 + REWARD_BLOCKS_CONNECTED)
        assert_equal(repaired_state["bestblock"], legacy_tip)
        assert_equal(repaired_state["replay_state"]["schema"], 11)
        assert_equal(repaired_state["replay_state"]["required_for_tip"], True)
        assert_equal(repaired_state["replay_state"]["present"], True)
        assert_equal(repaired_state["replay_state"]["marker_valid"], True)
        assert_equal(repaired_state["replay_state"]["valid_for_tip"], True)
        assert_equal(len(repaired_state["replay_state"]["commitment"]), 64)
        assert_equal(node.getblockcount(), 1 + REWARD_BLOCKS_CONNECTED)
        assert_equal(node.getbestblockhash(), legacy_tip)
        rebuilt_fingerprint = self.state_fingerprint(node)

        self.log.info("Confirming the rebuilt state survives a clean restart")
        self.restart_node(0, BASE_ARGS)
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)

        self.log.info("Confirming a second chainstate rebuild is deterministic")
        self.restart_node(0, BASE_ARGS + ["-reindex-chainstate"])
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)

        self.log.info("Confirming a full block reindex produces the same state")
        self.restart_node(0, BASE_ARGS + ["-reindex"])
        assert_equal(self.state_fingerprint(self.nodes[0]), rebuilt_fingerprint)


if __name__ == "__main__":
    GoldRushShadowReplayTest().main()
