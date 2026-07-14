// Copyright (c) 2026 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <shadow.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>

namespace {

struct ShadowScheduleSnapshot {
    const int whitelist_height{SHADOW_WHITELIST_HEIGHT};
    const int reward_start_height{SHADOW_REWARD_START_HEIGHT};
    const int gold_rush_blocks{SHADOW_GOLD_RUSH_BLOCKS};
    const int halving_interval{SHADOW_HALVING_INTERVAL_BLOCKS};

    ~ShadowScheduleSnapshot()
    {
        SetShadowTestSchedule(whitelist_height, reward_start_height, gold_rush_blocks);
        SetShadowTestHalvingInterval(halving_interval);
    }
};

struct PostGTransactionTimeSetup : public ShadowScheduleSnapshot, public TestChain100Setup {
    PostGTransactionTimeSetup()
        : TestChain100Setup{ChainType::REGTEST, {
              "-shadowwhitelistheight=99",
              "-shadowgoldrushstartheight=100",
              "-shadowgoldrushendheight=100",
              "-qqgoldrushendheight=100",
              "-qqmigrationendheight=200",
          }}
    {
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(v2_block_time_tests, PostGTransactionTimeSetup)

BOOST_AUTO_TEST_CASE(post_g_transaction_time_is_wire_canonical)
{
    LOCK(cs_main);
    CBlockIndex* tip{m_node.chainman->ActiveChain().Tip()};
    BOOST_REQUIRE(tip);
    BOOST_REQUIRE_EQUAL(tip->nHeight, 100);
    BOOST_REQUIRE(IsQuantumWitnessSpendActive(
        Params().GetConsensus(), tip->GetMedianTimePast(), tip->nHeight + 1));

    const CScript script_pub_key{CScript() << OP_TRUE};
    CBlock local_block{CreateBlock({}, script_pub_key,
                                   m_node.chainman->ActiveChainstate())};
    BOOST_REQUIRE_GE(local_block.vtx[0]->nVersion, 2);

    // This hidden value is later than the header and would trigger the G+1
    // bad-tx-time rule if local validation inspected a field absent on wire.
    CMutableTransaction local_coinbase{*local_block.vtx[0]};
    local_coinbase.nTime = local_block.nTime + 100;
    const uint256 coinbase_hash{local_block.vtx[0]->GetHash()};
    local_block.vtx[0] = MakeTransactionRef(std::move(local_coinbase));
    BOOST_CHECK_EQUAL(local_block.vtx[0]->GetHash(), coinbase_hash);
    local_block.fChecked = false;

    CDataStream wire{SER_NETWORK};
    wire << TX_WITH_WITNESS(local_block);
    CBlock wire_block;
    wire >> TX_WITH_WITNESS(wire_block);
    BOOST_REQUIRE_EQUAL(wire_block.vtx.size(), 1U);
    BOOST_CHECK_EQUAL(wire_block.vtx[0]->nTime, 0U);
    BOOST_CHECK_EQUAL(wire_block.GetHash(), local_block.GetHash());
    BOOST_CHECK_EQUAL(wire_block.hashMerkleRoot, local_block.hashMerkleRoot);

    BlockValidationState local_state;
    BOOST_CHECK_MESSAGE(TestBlockValidity(local_state, Params(),
        m_node.chainman->ActiveChainstate(), local_block, tip, GetAdjustedTime,
        /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true, /*fCheckBlockSig=*/true),
        local_state.ToString());
    BlockValidationState wire_state;
    BOOST_CHECK_MESSAGE(TestBlockValidity(wire_state, Params(),
        m_node.chainman->ActiveChainstate(), wire_block, tip, GetAdjustedTime,
        /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/true, /*fCheckBlockSig=*/true),
        wire_state.ToString());
}

BOOST_AUTO_TEST_SUITE_END()
