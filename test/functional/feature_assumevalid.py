#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Copyright (c) 2014-2022 Blackcoin Core Developers
# Copyright (c) 2014-2022 Blackcoin More Developers
# Copyright (c) 2014-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test logic for skipping signature validation on old blocks.

Test logic for skipping signature validation on blocks which we've assumed
valid (https://github.com/bitcoin/bitcoin/pull/9484)

We build a chain that includes and invalid signature for one of the
transactions:

    0:        genesis block
    1:        block 1 with coinbase transaction output.
    2-101:    bury that block with 100 blocks so the coinbase transaction
              output can be spent
    102:      a block containing a transaction spending the coinbase
              transaction output. The transaction has an invalid signature.
    103-19003: bury the bad block beyond two weeks of Blackcoin work
               (18,901 blocks at 64 seconds per block)

Start three nodes:

    - node0 has no -assumevalid parameter. Try to sync to the final block. It will
      reject block 102 and only sync as far as block 101
    - node1 has -assumevalid set to the hash of block 102. Try to sync to
      the final block. node1 will sync all the way to the chain tip.
    - node2 has -assumevalid set to the hash of block 102. Try to sync to
      block 200. node2 will reject block 102 since it's assumed valid, but it
      isn't buried by at least two weeks' work.
"""

from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.messages import (
    CBlockHeader,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxOut,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import generate_keypair


TARGET_SPACING = 64
ASSUMEVALID_WINDOW = 14 * 24 * 60 * 60
# GetBlockProofEquivalentTime must be strictly greater than two weeks before
# script verification may be skipped for an assumed-valid ancestor.
ASSUMEVALID_BURY_DEPTH = ASSUMEVALID_WINDOW // TARGET_SPACING + 1
MAX_HEADERS_PER_MESSAGE = 2000
SHALLOW_CHAIN_HEIGHT = 200


class BaseNode(P2PInterface):
    def send_header_for_blocks(self, new_blocks):
        headers_message = msg_headers()
        headers_message.headers = [CBlockHeader(b) for b in new_blocks]
        self.send_message(headers_message)


class AssumeValidTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.rpc_timeout = 120

    def setup_network(self):
        self.add_nodes(3)
        # Start node0. We don't start the other nodes yet since
        # we need to pre-mine a block with an invalid transaction
        # signature so we can pass in the block hash as assumevalid.
        self.start_node(0)

    def send_blocks_until_disconnected(self, p2p_conn):
        """Keep sending blocks to the node until we're disconnected."""
        for i in range(len(self.blocks)):
            if not p2p_conn.is_connected:
                break
            try:
                p2p_conn.send_message(msg_block(self.blocks[i]))
            except IOError:
                assert not p2p_conn.is_connected
                break

    def send_headers(self, p2p_conn, blocks):
        """Send a header chain without exceeding the protocol batch limit."""
        for start in range(0, len(blocks), MAX_HEADERS_PER_MESSAGE):
            p2p_conn.send_header_for_blocks(blocks[start:start + MAX_HEADERS_PER_MESSAGE])
        p2p_conn.sync_with_ping()

    def send_blocks(self, p2p_conn, blocks):
        """Send a long block chain in bounded batches."""
        for index, block in enumerate(blocks, start=1):
            p2p_conn.send_message(msg_block(block))
            if index % MAX_HEADERS_PER_MESSAGE == 0:
                p2p_conn.sync_with_ping(timeout=self.rpc_timeout)
        p2p_conn.sync_with_ping(timeout=self.rpc_timeout)

    def run_test(self):
        # Build the blockchain
        self.tip = int(self.nodes[0].getbestblockhash(), 16)
        self.block_time = self.nodes[0].getblock(self.nodes[0].getbestblockhash())['time'] + TARGET_SPACING

        self.blocks = []

        # Get a pubkey for the coinbase TXO
        _, coinbase_pubkey = generate_keypair()

        # Create the first block with a coinbase output to our key
        height = 1
        block = create_block(self.tip, create_coinbase(height, coinbase_pubkey), self.block_time)
        self.blocks.append(block)
        self.block_time += TARGET_SPACING
        block.solve()
        # Save the coinbase for later
        self.block1 = block
        self.tip = block.sha256
        height += 1

        # Bury the block 100 deep so the coinbase output is spendable
        for _ in range(100):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.sha256
            self.block_time += TARGET_SPACING
            height += 1

        # Create a transaction spending the coinbase output with an invalid (null) signature
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(self.block1.vtx[0].sha256, 0), scriptSig=b""))
        tx.vout.append(CTxOut(49 * 100000000, CScript([OP_TRUE])))
        tx.calc_sha256()

        invalid_block_height = height
        block102 = create_block(self.tip, create_coinbase(height), self.block_time, txlist=[tx])
        block102.solve()
        self.blocks.append(block102)
        self.tip = block102.sha256
        self.block_time += TARGET_SPACING
        height += 1

        # Bury the assumed-valid block strictly beyond two weeks of work at
        # Blackcoin's 64-second target spacing.
        for _ in range(ASSUMEVALID_BURY_DEPTH):
            block = create_block(self.tip, create_coinbase(height), self.block_time)
            block.solve()
            self.blocks.append(block)
            self.tip = block.sha256
            self.block_time += TARGET_SPACING
            height += 1

        final_height = len(self.blocks)
        assert_equal(final_height, invalid_block_height + ASSUMEVALID_BURY_DEPTH)
        shallow_blocks = self.blocks[:SHALLOW_CHAIN_HEIGHT]
        assert len(shallow_blocks) > invalid_block_height

        # Start node1 and node2 with assumevalid so they accept a block with a bad signature.
        self.start_node(1, extra_args=["-assumevalid=" + hex(block102.sha256)])
        self.start_node(2, extra_args=["-assumevalid=" + hex(block102.sha256)])

        p2p0 = self.nodes[0].add_p2p_connection(BaseNode())
        self.send_headers(p2p0, self.blocks)

        # Send blocks to node0. Block 102 will be rejected.
        self.send_blocks_until_disconnected(p2p0)
        expected_rejection_height = invalid_block_height - 1
        self.wait_until(lambda: self.nodes[0].getblockcount() >= expected_rejection_height)
        assert_equal(self.nodes[0].getblockcount(), expected_rejection_height)

        p2p1 = self.nodes[1].add_p2p_connection(BaseNode())
        self.send_headers(p2p1, self.blocks)

        # Send all blocks to node1. All blocks will be accepted.
        self.send_blocks(p2p1, self.blocks)
        assert_equal(self.nodes[1].getblock(self.nodes[1].getbestblockhash())['height'], final_height)

        p2p2 = self.nodes[2].add_p2p_connection(BaseNode())
        self.send_headers(p2p2, shallow_blocks)

        # Send blocks to node2. Block 102 will be rejected.
        self.send_blocks_until_disconnected(p2p2)
        self.wait_until(lambda: self.nodes[2].getblockcount() >= expected_rejection_height)
        assert_equal(self.nodes[2].getblockcount(), expected_rejection_height)


if __name__ == '__main__':
    AssumeValidTest().main()
