// Copyright (c) 2020-2022 Blackcoin Core Developers
// Copyright (c) 2020-2022 Blackcoin More Developers
// Copyright (c) 2020-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <dbwrapper.h>
#include <index/coinstatsindex.h>
#include <index/shadowindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <shadow.h>
#include <test/util/index.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(auxiliary_claim_index_schema_mismatch_wipes_and_rebuilds, TestChain100Setup)
{
    static constexpr uint8_t SCHEMA_KEY{'V'};
    static constexpr uint32_t PRERELEASE_COINSTATS_SCHEMA{2};
    static constexpr uint32_t CURRENT_COINSTATS_SCHEMA{3};
    static constexpr uint32_t PRERELEASE_SHADOW_SCHEMA{4};
    static constexpr uint32_t CURRENT_SHADOW_SCHEMA{7};
    const std::string sentinel{"prerelease-claim-allocation"};

    const auto build_index = [](BaseIndex& index) {
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index);
        BOOST_CHECK(index.BlockUntilSyncedToCurrentChain());
        index.Stop();
    };

    const fs::path coinstats_path = gArgs.GetDataDirNet() / "indexes" / "coinstats" / "db";
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, PRERELEASE_COINSTATS_SCHEMA));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, CURRENT_COINSTATS_SCHEMA);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    // A partially populated, unversioned index must be discarded rather than
    // relabeled as current. Its persisted MuHash provenance is unknowable.
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Erase(SCHEMA_KEY));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, CURRENT_COINSTATS_SCHEMA);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    const fs::path shadow_path = gArgs.GetDataDirNet() / "indexes" / "shadow";
    {
        ShadowIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, PRERELEASE_SHADOW_SCHEMA));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    {
        ShadowIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, CURRENT_SHADOW_SCHEMA);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    // An unversioned but populated database must not be relabeled as current.
    // Its records have no authenticated claim-allocation provenance.
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Erase(SCHEMA_KEY));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    {
        ShadowIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, CURRENT_SHADOW_SCHEMA);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    // A newer schema may contain semantics this binary does not understand.
    // Downgrades fail closed instead of deleting that database.
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, CURRENT_COINSTATS_SCHEMA + 1));
    }
    BOOST_CHECK_THROW((CoinStatsIndex{interfaces::MakeChain(m_node), 1 << 20}), std::runtime_error);
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, CURRENT_SHADOW_SCHEMA + 1));
    }
    BOOST_CHECK_THROW((ShadowIndex{interfaces::MakeChain(m_node), 1 << 20}), std::runtime_error);
}

BOOST_FIXTURE_TEST_CASE(shadow_replay_preserves_pre_whitelist_snapshot_stats, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    chainstate.ForceFlushStateToDisk();
    const auto before = WITH_LOCK(cs_main, return kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        &chainstate.CoinsDB(),
        chainstate.m_blockman));
    BOOST_REQUIRE(before);

    BOOST_REQUIRE(chainstate.ReplayShadowBlocks() == Chainstate::ReplayResult::SUCCESS);

    const auto after = WITH_LOCK(cs_main, return kernel::ComputeUTXOStats(
        kernel::CoinStatsHashType::HASH_SERIALIZED,
        &chainstate.CoinsDB(),
        chainstate.m_blockman));
    BOOST_REQUIRE(after);
    BOOST_CHECK_EQUAL(after->hashSerialized, before->hashSerialized);
    BOOST_CHECK_EQUAL(after->coins_count, before->coins_count);
    BOOST_CHECK_EQUAL(after->nTransactionOutputs, before->nTransactionOutputs);

    {
        LOCK(cs_main);
        CCoinsViewCache view(&chainstate.CoinsDB());
        BOOST_CHECK(!HasShadowReplayState(view));
    }
}

BOOST_FIXTURE_TEST_CASE(shadow_replay_rejects_malformed_reserved_pre_whitelist_marker, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    chainstate.ForceFlushStateToDisk();
    const COutPoint replay_outpoint = ShadowReplayStateOutpointForTesting();

    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(tip);
        Coin malformed;
        malformed.out.nValue = 1;
        malformed.out.scriptPubKey = CScript{} << OP_FALSE << OP_RETURN
            << std::vector<unsigned char>{'Q', 'Q', 'R', 'E', 'P', 'L', 'A', 'Y'}
            << std::vector<unsigned char>(32, 0);
        malformed.fCoinBase = true;
        malformed.fCoinStake = false;
        malformed.nHeight = tip->nHeight;
        malformed.nTime = tip->GetBlockTime();

        CCoinsViewCache cache(&chainstate.CoinsDB());
        cache.SetBestBlock(chainstate.CoinsDB().GetBestBlock());
        cache.AddCoin(replay_outpoint, std::move(malformed), true);
        BOOST_REQUIRE(cache.Flush());
    }

    BOOST_CHECK(chainstate.ReplayShadowBlocks() ==
                Chainstate::ReplayResult::CHAINSTATE_REBUILD_REQUIRED);

    {
        LOCK(cs_main);
        CCoinsViewCache cache(&chainstate.CoinsDB());
        Coin persisted;
        BOOST_REQUIRE(cache.GetCoin(replay_outpoint, persisted));
        BOOST_CHECK_EQUAL(persisted.out.nValue, 1);
    }
}

BOOST_FIXTURE_TEST_CASE(coinstatsindex_initial_sync, TestChain100Setup)
{
    CoinStatsIndex coin_stats_index{interfaces::MakeChain(m_node), 1 << 20, true};
    BOOST_REQUIRE(coin_stats_index.Init());

    const CBlockIndex* block_index;
    {
        LOCK(cs_main);
        block_index = m_node.chainman->ActiveChain().Tip();
    }

    // CoinStatsIndex should not be found before it is started.
    BOOST_CHECK(!coin_stats_index.LookUpStats(*block_index));

    // BlockUntilSyncedToCurrentChain should return false before CoinStatsIndex
    // is started.
    BOOST_CHECK(!coin_stats_index.BlockUntilSyncedToCurrentChain());

    BOOST_REQUIRE(coin_stats_index.StartBackgroundSync());

    IndexWaitSynced(coin_stats_index);

    // Check that CoinStatsIndex works for genesis block.
    const CBlockIndex* genesis_block_index;
    {
        LOCK(cs_main);
        genesis_block_index = m_node.chainman->ActiveChain().Genesis();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*genesis_block_index));

    // Check that CoinStatsIndex updates with new blocks.
    BOOST_CHECK(coin_stats_index.LookUpStats(*block_index));

    const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
    std::vector<CMutableTransaction> noTxns;
    CreateAndProcessBlock(noTxns, script_pub_key);

    // Let the CoinStatsIndex to catch up again.
    BOOST_CHECK(coin_stats_index.BlockUntilSyncedToCurrentChain());

    const CBlockIndex* new_block_index;
    {
        LOCK(cs_main);
        new_block_index = m_node.chainman->ActiveChain().Tip();
    }
    BOOST_CHECK(coin_stats_index.LookUpStats(*new_block_index));

    BOOST_CHECK(block_index != new_block_index);

    // It is not safe to stop and destroy the index until it finishes handling
    // the last BlockConnected notification. The BlockUntilSyncedToCurrentChain()
    // call above is sufficient to ensure this, but the
    // SyncWithValidationInterfaceQueue() call below is also needed to ensure
    // TSAN always sees the test thread waiting for the notification thread, and
    // avoid potential false positive reports.
    SyncWithValidationInterfaceQueue();

    // Shutdown sequence (c.f. Shutdown() in init.cpp)
    coin_stats_index.Stop();
}

// Test shutdown between BlockConnected and ChainStateFlushed notifications,
// make sure index is not corrupted and is able to reload.
BOOST_FIXTURE_TEST_CASE(coinstatsindex_unclean_shutdown, TestChain100Setup)
{
    Chainstate& chainstate = Assert(m_node.chainman)->ActiveChainstate();
    const CChainParams& params = Params();
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index);
        std::shared_ptr<const CBlock> new_block;
        CBlockIndex* new_block_index = nullptr;
        {
            const CScript script_pub_key{CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};
            const CBlock block = this->CreateBlock({}, script_pub_key, chainstate);

            new_block = std::make_shared<CBlock>(block);

            LOCK(cs_main);
            BlockValidationState state;
            BOOST_CHECK(CheckBlock(block, state, params.GetConsensus(), chainstate));
            BOOST_CHECK(m_node.chainman->AcceptBlock(new_block, state, &new_block_index, true, nullptr, nullptr, true));
            CCoinsViewCache view(&chainstate.CoinsTip());
            BOOST_CHECK(chainstate.ConnectBlock(block, state, new_block_index, view));
        }
        // Send block connected notification, then stop the index without
        // sending a chainstate flushed notification. Prior to #24138, this
        // would cause the index to be corrupted and fail to reload.
        ValidationInterfaceTest::BlockConnected(ChainstateRole::NORMAL, index, new_block, new_block_index);
        index.Stop();
    }

    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        BOOST_REQUIRE(index.Init());
        // Make sure the index can be loaded.
        BOOST_REQUIRE(index.StartBackgroundSync());
        index.Stop();
    }
}

BOOST_AUTO_TEST_SUITE_END()
