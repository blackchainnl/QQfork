// Copyright (c) 2020-2022 Blackcoin Core Developers
// Copyright (c) 2020-2022 Blackcoin More Developers
// Copyright (c) 2020-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <common/args.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <dbwrapper.h>
#include <index/coinstatsindex.h>
#include <index/shadowindex.h>
#include <interfaces/chain.h>
#include <kernel/coinstats.h>
#include <pow.h>
#include <shadow.h>
#include <test/util/index.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <limits>

namespace {

class BoundedShadowIndexTestingSetup : public TestChain100Setup
{
public:
    BoundedShadowIndexTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, {
              "-regtest",
              "-shadowwhitelistheight=100",
              "-shadowgoldrushstartheight=101",
              "-shadowgoldrushblocks=4",
              "-shadowcompetingclaimsheight=101",
          }}
    {
    }
};

} // namespace

BOOST_AUTO_TEST_SUITE(coinstatsindex_tests)

BOOST_FIXTURE_TEST_CASE(auxiliary_claim_index_schema_mismatch_wipes_and_rebuilds, TestChain100Setup)
{
    static constexpr uint8_t SCHEMA_KEY{'V'};
    static constexpr uint32_t PRERELEASE_COINSTATS_SCHEMA{2};
    // Schema 9 predates QQP4 version/input provenance. It cannot safely be
    // relabeled as any later schema, so it must be rebuilt from the chain.
    static constexpr uint32_t PRE_QQP4_SHADOW_SCHEMA{9};
    const std::string sentinel{"prerelease-claim-allocation"};

    const auto build_index = [](BaseIndex& index) {
        BOOST_REQUIRE(index.Init());
        BOOST_REQUIRE(index.StartBackgroundSync());
        IndexWaitSynced(index);
        BOOST_CHECK(index.BlockUntilSyncedToCurrentChain());
        index.Stop();
    };

    const fs::path coinstats_path = gArgs.GetDataDirNet() / "indexes" / "coinstats" / "db";
    uint32_t current_coinstats_schema{0};
    {
        CoinStatsIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, current_coinstats_schema));
        BOOST_REQUIRE_GT(current_coinstats_schema,
                         PRERELEASE_COINSTATS_SCHEMA);
        BOOST_REQUIRE_LT(current_coinstats_schema,
                         std::numeric_limits<uint32_t>::max());
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
        BOOST_CHECK_EQUAL(schema, current_coinstats_schema);
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
        BOOST_CHECK_EQUAL(schema, current_coinstats_schema);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    const fs::path shadow_path = gArgs.GetDataDirNet() / "indexes" / "shadow";
    uint32_t current_shadow_schema{0};
    {
        ShadowIndex index{interfaces::MakeChain(m_node), 1 << 20};
        build_index(index);
    }
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, current_shadow_schema));
        BOOST_REQUIRE_GT(current_shadow_schema, PRE_QQP4_SHADOW_SCHEMA);
        BOOST_REQUIRE_LT(current_shadow_schema,
                         std::numeric_limits<uint32_t>::max());
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, PRE_QQP4_SHADOW_SCHEMA));
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
        BOOST_CHECK_EQUAL(schema, current_shadow_schema);
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
        BOOST_CHECK_EQUAL(schema, current_shadow_schema);
        BOOST_CHECK(!db.Exists(sentinel));
    }

    // A newer schema may contain semantics this binary does not understand.
    // Downgrades fail closed instead of deleting that database.
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, current_coinstats_schema + 1));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    BOOST_CHECK_THROW((CoinStatsIndex{interfaces::MakeChain(m_node), 1 << 20}), std::runtime_error);
    {
        CDBWrapper db({.path = coinstats_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        bool sentinel_present{false};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, current_coinstats_schema + 1);
        BOOST_REQUIRE(db.Read(sentinel, sentinel_present));
        BOOST_CHECK(sentinel_present);
    }
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        BOOST_REQUIRE(db.Write(SCHEMA_KEY, current_shadow_schema + 1));
        BOOST_REQUIRE(db.Write(sentinel, true));
    }
    BOOST_CHECK_THROW((ShadowIndex{interfaces::MakeChain(m_node), 1 << 20}), std::runtime_error);
    {
        CDBWrapper db({.path = shadow_path, .cache_bytes = 1 << 20});
        uint32_t schema{0};
        bool sentinel_present{false};
        BOOST_REQUIRE(db.Read(SCHEMA_KEY, schema));
        BOOST_CHECK_EQUAL(schema, current_shadow_schema + 1);
        BOOST_REQUIRE(db.Read(sentinel, sentinel_present));
        BOOST_CHECK(sentinel_present);
    }
}

BOOST_FIXTURE_TEST_CASE(shadowindex_bounded_claim_state_survives_max_weight_reorg_and_rebuild,
                        BoundedShadowIndexTestingSetup)
{
    static constexpr int64_t MAX_OPERATION_MILLISECONDS{120000};
    static constexpr size_t MAX_PERSISTED_BLOCK_RECORD_BYTES{4096};
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    const CScript script_pub_key{
        CScript{} << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG};

    ShadowIndex index{interfaces::MakeChain(m_node), 1 << 20, true};
    BOOST_REQUIRE(index.Init());
    BOOST_REQUIRE(index.StartBackgroundSync());
    IndexWaitSynced(index);

    CBlock stress_block = CreateBlock({}, script_pub_key, chainstate);
    CMutableTransaction coinbase{*stress_block.vtx.at(0)};
    const size_t base_output_count = coinbase.vout.size();
    const valtype malformed_payload{'Q', 'Q', 'S', 'P', 'R', 'O', 'O', 'F', 0};
    const CTxOut malformed_output{
        0, CScript{} << OP_RETURN << malformed_payload};
    const size_t output_weight =
        GetSerializeSize(TX_NO_WITNESS(malformed_output)) *
        WITNESS_SCALE_FACTOR;
    BOOST_REQUIRE_GT(output_weight, 0U);
    const size_t available_weight =
        MAX_BLOCK_WEIGHT - GetBlockWeight(stress_block);
    const size_t initial_output_count = available_weight / output_weight;
    coinbase.vout.reserve(coinbase.vout.size() + initial_output_count);
    for (size_t i = 0; i < initial_output_count; ++i) {
        coinbase.vout.push_back(malformed_output);
    }
    stress_block.vtx[0] = MakeTransactionRef(coinbase);
    stress_block.hashMerkleRoot = BlockMerkleRoot(stress_block);
    while (GetBlockWeight(stress_block) > MAX_BLOCK_WEIGHT) {
        coinbase.vout.pop_back();
        stress_block.vtx[0] = MakeTransactionRef(coinbase);
        stress_block.hashMerkleRoot = BlockMerkleRoot(stress_block);
    }
    while (GetBlockWeight(stress_block) + output_weight <= MAX_BLOCK_WEIGHT) {
        coinbase.vout.push_back(malformed_output);
        stress_block.vtx[0] = MakeTransactionRef(coinbase);
        stress_block.hashMerkleRoot = BlockMerkleRoot(stress_block);
    }
    const uint32_t expected_notes =
        static_cast<uint32_t>(coinbase.vout.size() - base_output_count);
    BOOST_REQUIRE_GT(expected_notes, MAX_SHADOW_POW_EVALS_PER_BLOCK);
    BOOST_CHECK_LE(MAX_BLOCK_WEIGHT - GetBlockWeight(stress_block),
                   output_weight);
    stress_block.nNonce = 0;
    while (!CheckProofOfWork(stress_block.GetPoWHash(), stress_block.nBits,
                             chainman.GetConsensus())) {
        ++stress_block.nNonce;
    }
    const uint256 stress_hash = stress_block.GetHash();

    const auto require_within_limit = [&](const char* operation,
                                          const auto& callable) {
        const auto start = std::chrono::steady_clock::now();
        callable();
        const int64_t elapsed_milliseconds =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start)
                .count();
        BOOST_TEST_CONTEXT(operation) {
            BOOST_CHECK_LT(elapsed_milliseconds,
                           MAX_OPERATION_MILLISECONDS);
        }
    };
    const auto wait_for_index = [&] {
        SyncWithValidationInterfaceQueue();
        IndexWaitSynced(index);
    };

    require_within_limit("maximum-weight connect and live index append", [&] {
        bool new_block{false};
        BOOST_REQUIRE(chainman.ProcessNewBlock(
            std::make_shared<const CBlock>(stress_block), true, true,
            &new_block));
        BOOST_REQUIRE(new_block);
        wait_for_index();
    });

    ShadowIndexBlockRecord first_record;
    BOOST_REQUIRE(index.LookupBlock(stress_hash, first_record));
    BOOST_CHECK(first_record.pow_claims.active);
    BOOST_CHECK_EQUAL(first_record.pow_claims.observed_count, expected_notes);
    BOOST_CHECK_EQUAL(first_record.pow_claims.evaluated_count, 0U);
    BOOST_CHECK_EQUAL(first_record.pow_claims.record_count, 0U);
    BOOST_CHECK_EQUAL(first_record.pow_claims.invalid_location_count,
                      expected_notes);
    BOOST_CHECK_EQUAL(first_record.pow_claims.rejected_count, expected_notes);
    BOOST_CHECK(!first_record.pow_claims.accounting_commitment.IsNull());
    BOOST_CHECK_EQUAL(first_record.observed_pow_claim_txids.size(), 1U);
    BOOST_CHECK_LE(GetSerializeSize(first_record),
                   MAX_PERSISTED_BLOCK_RECORD_BYTES);
    std::vector<ShadowIndexPowClaimRecord> claims;
    std::optional<size_t> next;
    BOOST_REQUIRE(index.LookupPowClaims(stress_hash, 0,
                                       MAX_SHADOW_POW_EVALS_PER_BLOCK,
                                       claims, next));
    BOOST_CHECK(claims.empty());
    BOOST_CHECK(!next.has_value());
    BOOST_CHECK(!index.LookupPowClaims(stress_hash, 0,
                                      MAX_SHADOW_POW_EVALS_PER_BLOCK + 1,
                                      claims, next));

    CBlockIndex* stress_index{nullptr};
    {
        LOCK(cs_main);
        stress_index = chainman.m_blockman.LookupBlockIndex(stress_hash);
    }
    BOOST_REQUIRE(stress_index != nullptr);
    require_within_limit("maximum-weight disconnect and index undo", [&] {
        BlockValidationState state;
        BOOST_REQUIRE(chainstate.InvalidateBlock(state, stress_index));
        BOOST_REQUIRE_MESSAGE(state.IsValid(), state.ToString());
        wait_for_index();
    });
    ShadowIndexBlockRecord disconnected_record;
    BOOST_CHECK(!index.LookupBlock(stress_hash, disconnected_record));

    CBlock alternate_block;
    require_within_limit("alternate-chain connect", [&] {
        alternate_block = CreateAndProcessBlock({}, script_pub_key);
        wait_for_index();
    });
    const uint256 alternate_hash = alternate_block.GetHash();
    ShadowIndexBlockRecord alternate_record;
    BOOST_REQUIRE(index.LookupBlock(alternate_hash, alternate_record));
    BOOST_CHECK_EQUAL(alternate_record.pow_claims.observed_count, 0U);
    BOOST_CHECK(!alternate_record.pow_claims.accounting_commitment.IsNull());

    require_within_limit("reorg back to maximum-weight block", [&] {
        CBlockIndex* alternate_index{nullptr};
        {
            LOCK(cs_main);
            alternate_index =
                chainman.m_blockman.LookupBlockIndex(alternate_hash);
        }
        BOOST_REQUIRE(alternate_index != nullptr);
        BlockValidationState state;
        BOOST_REQUIRE(chainstate.InvalidateBlock(state, alternate_index));
        BOOST_REQUIRE_MESSAGE(state.IsValid(), state.ToString());
        {
            LOCK(cs_main);
            chainstate.ResetBlockFailureFlags(stress_index);
        }
        BlockValidationState activate_state;
        BOOST_REQUIRE(chainstate.ActivateBestChain(activate_state));
        BOOST_REQUIRE_MESSAGE(activate_state.IsValid(),
                              activate_state.ToString());
        wait_for_index();
    });
    BOOST_CHECK_EQUAL(
        WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash()),
        stress_hash);
    ShadowIndexBlockRecord reconnected_record;
    BOOST_REQUIRE(index.LookupBlock(stress_hash, reconnected_record));
    BOOST_CHECK_EQUAL(reconnected_record.pow_claims.accounting_commitment,
                      first_record.pow_claims.accounting_commitment);
    BOOST_CHECK_EQUAL(reconnected_record.pow_claims.observed_count,
                      expected_notes);

    SyncWithValidationInterfaceQueue();
    index.Stop();
    require_within_limit("clean shadowindex rebuild over maximum-weight block", [&] {
        ShadowIndex rebuilt{interfaces::MakeChain(m_node), 1 << 20,
                            /*memory=*/true, /*wipe=*/true};
        BOOST_REQUIRE(rebuilt.Init());
        BOOST_REQUIRE(rebuilt.StartBackgroundSync());
        IndexWaitSynced(rebuilt);
        ShadowIndexBlockRecord rebuilt_record;
        BOOST_REQUIRE(rebuilt.LookupBlock(stress_hash, rebuilt_record));
        BOOST_CHECK_EQUAL(rebuilt_record.pow_claims.accounting_commitment,
                          first_record.pow_claims.accounting_commitment);
        BOOST_CHECK_EQUAL(rebuilt_record.pow_claims.observed_count,
                          expected_notes);
        BOOST_CHECK_EQUAL(rebuilt_record.pow_claims.record_count, 0U);
        BOOST_CHECK_LE(GetSerializeSize(rebuilt_record),
                       MAX_PERSISTED_BLOCK_RECORD_BYTES);
        rebuilt.Stop();
    });
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
