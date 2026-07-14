// Copyright (c) 2019-2022 The Bitcoin Core developers
// Copyright (c) 2019-2022 Blackcoin Core Developers
// Copyright (c) 2019-2022 Blackcoin More Developers
// Copyright (c) 2019-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/validation.h>
#include <crypto/muhash.h>
#include <kernel/coinstats.h>
#include <kernel/disconnected_transactions.h>
#include <node/kernel_notifications.h>
#include <node/chainstate.h>
#include <node/chainstate_rebuild.h>
#include <node/utxo_snapshot.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/chainstate.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <timedata.h>
#include <txdb.h>
#include <uint256.h>
#include <util/time.h>
#include <validation.h>
#include <validationinterface.h>

#include <tinyformat.h>

#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using node::BlockManager;
using node::KernelNotifications;
using node::SnapshotMetadata;

BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

//! Basic tests for ChainstateManager.
//!
//! First create a legacy (IBD) chainstate, then create a snapshot chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;
    std::vector<Chainstate*> chainstates;

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);

    BOOST_CHECK(!manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    auto all = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all.begin(), all.end(), chainstates.begin(), chainstates.end());

    auto& active_chain = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain, &c1.m_chain);

    // Get to a valid assumeutxo tip (per chainparams);
    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    auto active_tip = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    auto exp_tip = c1.m_chain.Tip();
    BOOST_CHECK_EQUAL(active_tip, exp_tip);

    BOOST_CHECK(!manager.SnapshotBlockhash().has_value());

    // Create a snapshot-based chainstate.
    //
    const uint256 snapshot_blockhash = active_tip->GetBlockHash();
    Chainstate& c2 = WITH_LOCK(::cs_main, return manager.ActivateExistingSnapshot(snapshot_blockhash));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);
    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        c2.CoinsTip().SetBestBlock(active_tip->GetBlockHash());
        c2.setBlockIndexCandidates.insert(manager.m_blockman.LookupBlockIndex(active_tip->GetBlockHash()));
        c2.LoadChainTip();
    }
    BlockValidationState _;
    BOOST_CHECK(c2.ActivateBestChain(_, nullptr));

    BOOST_CHECK_EQUAL(manager.SnapshotBlockhash().value(), snapshot_blockhash);
    BOOST_CHECK(manager.IsSnapshotActive());
    BOOST_CHECK(WITH_LOCK(::cs_main, return !manager.IsSnapshotValidated()));
    BOOST_CHECK_EQUAL(&c2, &manager.ActiveChainstate());
    BOOST_CHECK(&c1 != &manager.ActiveChainstate());
    auto all2 = manager.GetAll();
    BOOST_CHECK_EQUAL_COLLECTIONS(all2.begin(), all2.end(), chainstates.begin(), chainstates.end());

    auto& active_chain2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain2, &c2.m_chain);

    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 111);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return c1.m_chain.Height()), 110);

    auto active_tip2 = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    BOOST_CHECK_EQUAL(active_tip, active_tip2->pprev);
    BOOST_CHECK_EQUAL(active_tip, c1.m_chain.Tip());
    BOOST_CHECK_EQUAL(active_tip2, c2.m_chain.Tip());

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    SyncWithValidationInterfaceQueue();
}

//! Test rebalancing the caches associated with each chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebalance_caches, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;

    size_t max_cache = 10000;
    manager.m_total_coinsdb_cache = max_cache;
    manager.m_total_coinstip_cache = max_cache;

    std::vector<Chainstate*> chainstates;

    // Create a legacy (IBD) chainstate.
    //
    Chainstate& c1 = manager.ActiveChainstate();
    chainstates.push_back(&c1);
    {
        LOCK(::cs_main);
        c1.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_EQUAL(c1.m_coinstip_cache_size_bytes, max_cache);
    BOOST_CHECK_EQUAL(c1.m_coinsdb_cache_size_bytes, max_cache);

    // Create a snapshot-based chainstate.
    //
    CBlockIndex* snapshot_base{WITH_LOCK(manager.GetMutex(), return manager.ActiveChain()[manager.ActiveChain().Height() / 2])};
    Chainstate& c2 = WITH_LOCK(cs_main, return manager.ActivateExistingSnapshot(*snapshot_base->phashBlock));
    chainstates.push_back(&c2);
    c2.InitCoinsDB(
        /*cache_size_bytes=*/1 << 23, /*in_memory=*/true, /*should_wipe=*/false);

    // Reset IBD state so IsInitialBlockDownload() returns true and causes
    // MaybeRebalancesCaches() to prioritize the snapshot chainstate, giving it
    // more cache space than the snapshot chainstate. Calling ResetIbd() is
    // necessary because m_cached_finished_ibd is already latched to true before
    // the test starts due to the test setup. After ResetIbd() is called.
    // IsInitialBlockDownload will return true because at this point the active
    // chainstate has a null chain tip.
    static_cast<TestChainstateManager&>(manager).ResetIbd();

    {
        LOCK(::cs_main);
        c2.InitCoinsCache(1 << 23);
        manager.MaybeRebalanceCaches();
    }

    BOOST_CHECK_CLOSE(c1.m_coinstip_cache_size_bytes, max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(c1.m_coinsdb_cache_size_bytes, max_cache * 0.05, 1);
    BOOST_CHECK_CLOSE(c2.m_coinstip_cache_size_bytes, max_cache * 0.95, 1);
    BOOST_CHECK_CLOSE(c2.m_coinsdb_cache_size_bytes, max_cache * 0.95, 1);
}

struct SnapshotTestSetup : TestChain100Setup {
    // Run with coinsdb on the filesystem to support, e.g., moving invalidated
    // chainstate dirs to "*_invalid".
    //
    // Note that this means the tests run considerably slower than in-memory DB
    // tests, but we can't otherwise test this functionality since it relies on
    // destructive filesystem operations.
    SnapshotTestSetup() : TestChain100Setup{
                              {},
                              {},
                              /*coins_db_in_memory=*/false,
                              /*block_tree_db_in_memory=*/false,
                          }
    {
    }

    std::tuple<Chainstate*, Chainstate*> SetupSnapshot()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_CHECK(!chainman.IsSnapshotActive());

        {
            LOCK(::cs_main);
            BOOST_CHECK(!chainman.IsSnapshotValidated());
            BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));
        }

        size_t initial_size;
        size_t initial_total_coins{100};

        // Make some initial assertions about the contents of the chainstate.
        {
            LOCK(::cs_main);
            CCoinsViewCache& ibd_coinscache = chainman.ActiveChainstate().CoinsTip();
            initial_size = ibd_coinscache.GetCacheSize();
            size_t total_coins{0};

            for (CTransactionRef& txn : m_coinbase_txns) {
                COutPoint op{txn->GetHash(), 0};
                BOOST_CHECK(ibd_coinscache.HaveCoin(op));
                total_coins++;
            }

            BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
            BOOST_CHECK_EQUAL(initial_size, initial_total_coins);
        }

        Chainstate& validation_chainstate = chainman.ActiveChainstate();

        // Snapshot should refuse to load at this height.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash);
        BOOST_CHECK(!chainman.SnapshotBlockhash());

        // Mine 10 more blocks, putting at us height 110 where a valid assumeutxo value can
        // be found.
        constexpr int snapshot_height = 110;
        mineBlocks(10);
        initial_size += 10;
        initial_total_coins += 10;

        // Should not load malleated snapshots
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // A UTXO is missing but count is correct
                metadata.m_coins_count -= 1;

                COutPoint outpoint;
                Coin coin;

                auto_infile >> outpoint;
                auto_infile >> coin;
        }));

        BOOST_CHECK(!node::FindSnapshotChainstateDir(chainman.m_options.datadir));

        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is larger than coins in file
                metadata.m_coins_count += 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Coins count is smaller than coins in file
                metadata.m_coins_count -= 1;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ZERO;
        }));
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(
            this, [](AutoFile& auto_infile, SnapshotMetadata& metadata) {
                // Wrong hash
                metadata.m_base_blockhash = uint256::ONE;
        }));

        BOOST_REQUIRE(CreateAndActivateUTXOSnapshot(this));
        BOOST_CHECK(fs::exists(*node::FindSnapshotChainstateDir(chainman.m_options.datadir)));

        // Ensure our active chain is the snapshot chainstate.
        BOOST_CHECK(!chainman.ActiveChainstate().m_from_snapshot_blockhash->IsNull());
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            *chainman.SnapshotBlockhash());

        Chainstate& snapshot_chainstate = chainman.ActiveChainstate();

        {
            LOCK(::cs_main);

            fs::path found = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);

            // Note: WriteSnapshotBaseBlockhash() is implicitly tested above.
            BOOST_CHECK_EQUAL(
                *node::ReadSnapshotBaseBlockhash(found),
                *chainman.SnapshotBlockhash());

            // Ensure that the genesis block was not marked assumed-valid.
            BOOST_CHECK(!chainman.ActiveChain().Genesis()->IsAssumedValid());
        }

        const auto& au_data = ::Params().AssumeutxoForHeight(snapshot_height);
        const CBlockIndex* tip = WITH_LOCK(chainman.GetMutex(), return chainman.ActiveTip());

        BOOST_CHECK_EQUAL(tip->nChainTx, au_data->nChainTx);

        // To be checked against later when we try loading a subsequent snapshot.
        uint256 loaded_snapshot_blockhash{*chainman.SnapshotBlockhash()};

        // Make some assertions about the both chainstates. These checks ensure the
        // legacy chainstate hasn't changed and that the newly created chainstate
        // reflects the expected content.
        {
            LOCK(::cs_main);
            int chains_tested{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();

                // Both caches will be empty initially.
                BOOST_CHECK_EQUAL((unsigned int)0, coinscache.GetCacheSize());

                size_t total_coins{0};

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    BOOST_CHECK(coinscache.HaveCoin(op));
                    total_coins++;
                }

                BOOST_CHECK_EQUAL(initial_size , coinscache.GetCacheSize());
                BOOST_CHECK_EQUAL(total_coins, initial_total_coins);
                chains_tested++;
            }

            BOOST_CHECK_EQUAL(chains_tested, 2);
        }

        // Mine some new blocks on top of the activated snapshot chainstate.
        constexpr size_t new_coins{100};
        mineBlocks(new_coins);  // Defined in TestChain100Setup.

        {
            LOCK(::cs_main);
            size_t coins_in_active{0};
            size_t coins_in_background{0};
            size_t coins_missing_from_background{0};

            for (Chainstate* chainstate : chainman.GetAll()) {
                BOOST_TEST_MESSAGE("Checking coins in " << chainstate->ToString());
                CCoinsViewCache& coinscache = chainstate->CoinsTip();
                bool is_background = chainstate != &chainman.ActiveChainstate();

                for (CTransactionRef& txn : m_coinbase_txns) {
                    COutPoint op{txn->GetHash(), 0};
                    if (coinscache.HaveCoin(op)) {
                        (is_background ? coins_in_background : coins_in_active)++;
                    } else if (is_background) {
                        coins_missing_from_background++;
                    }
                }
            }

            BOOST_CHECK_EQUAL(coins_in_active, initial_total_coins + new_coins);
            BOOST_CHECK_EQUAL(coins_in_background, initial_total_coins);
            BOOST_CHECK_EQUAL(coins_missing_from_background, new_coins);
        }

        // Snapshot should refuse to load after one has already loaded.
        BOOST_REQUIRE(!CreateAndActivateUTXOSnapshot(this));

        // Snapshot blockhash should be unchanged.
        BOOST_CHECK_EQUAL(
            *chainman.ActiveChainstate().m_from_snapshot_blockhash,
            loaded_snapshot_blockhash);
        return std::make_tuple(&validation_chainstate, &snapshot_chainstate);
    }

    // Simulate a restart of the node by flushing all state to disk, clearing the
    // existing ChainstateManager, and unloading the block index.
    //
    // @returns a reference to the "restarted" ChainstateManager
    ChainstateManager& SimulateNodeRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);

        BOOST_TEST_MESSAGE("Simulating node restart");
        {
            for (Chainstate* cs : chainman.GetAll()) {
                LOCK(::cs_main);
                cs->ForceFlushStateToDisk();
            }
            // Process all callbacks referring to the old manager before wiping it.
            SyncWithValidationInterfaceQueue();
            LOCK(::cs_main);
            chainman.ResetChainstates();
            BOOST_CHECK_EQUAL(chainman.GetAll().size(), 0);
            m_node.notifications = std::make_unique<KernelNotifications>(m_node.exit_status);
            const ChainstateManager::Options chainman_opts{
                .chainparams = ::Params(),
                .datadir = chainman.m_options.datadir,
                .adjusted_time_callback = GetAdjustedTime,
                .notifications = *m_node.notifications,
            };
            const BlockManager::Options blockman_opts{
                .chainparams = chainman_opts.chainparams,
                .blocks_dir = m_args.GetBlocksDirPath(),
                .notifications = chainman_opts.notifications,
            };
            // For robustness, ensure the old manager is destroyed before creating a
            // new one.
            m_node.chainman.reset();
            m_node.chainman = std::make_unique<ChainstateManager>(m_node.kernel->interrupt, chainman_opts, blockman_opts);
        }
        return *Assert(m_node.chainman);
    }

    // Recreate the manager without flushing, modeling process death at an
    // arbitrary point in the staged-rebuild protocol.
    ChainstateManager& SimulateCrashRestart()
    {
        ChainstateManager& chainman = *Assert(m_node.chainman);
        SyncWithValidationInterfaceQueue();
        LOCK(::cs_main);
        chainman.ResetChainstates();
        m_node.notifications = std::make_unique<KernelNotifications>(m_node.exit_status);
        const ChainstateManager::Options chainman_opts{
            .chainparams = ::Params(),
            .datadir = chainman.m_options.datadir,
            .adjusted_time_callback = GetAdjustedTime,
            .notifications = *m_node.notifications,
        };
        const BlockManager::Options blockman_opts{
            .chainparams = chainman_opts.chainparams,
            .blocks_dir = m_args.GetBlocksDirPath(),
            .notifications = chainman_opts.notifications,
        };
        m_node.chainman.reset();
        m_node.chainman = std::make_unique<ChainstateManager>(
            m_node.kernel->interrupt, chainman_opts, blockman_opts);
        return *Assert(m_node.chainman);
    }

    ChainstateManager& BuildAndCommitProtectedChainstate()
    {
        // The commitment identifies the rebuilt replacement at COMMIT_READY.
        // It deliberately does not assert byte-for-byte or Coin-for-Coin
        // equality with the legacy source, whose nTime/coinstake provenance
        // may be corrected by reconstruction. Corruption tests mutate only
        // after this baseline identity has been durably recorded.
        ChainstateManager& rebuilding = SimulateNodeRestart();
        node::ChainstateLoadOptions rebuild;
        rebuild.mempool = Assert(m_node.mempool.get());
        rebuild.reindex_chainstate = true;
        auto [status, error] = node::LoadChainstate(
            rebuilding, m_cache_sizes, rebuild);
        BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
        std::tie(status, error) = node::VerifyLoadedChainstate(
            rebuilding, rebuild);
        BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

        BlockValidationState state;
        BOOST_REQUIRE(rebuilding.ActiveChainstate().ActivateBestChain(
            state, nullptr));
        bilingual_str finalize_error;
        BOOST_REQUIRE(node::FinalizeChainstateRebuild(
            rebuilding, finalize_error));
        BOOST_REQUIRE(fs::exists(
            rebuilding.m_options.datadir / "chainstate-rebuild.journal"));
        BOOST_REQUIRE(fs::exists(
            rebuilding.m_options.datadir / "chainstate.rebuild-backup"));
        return rebuilding;
    }
};

static uint256 LegacyMuHash(CCoinsView& view)
{
    MuHash3072 muhash;
    std::unique_ptr<CCoinsViewCursor> cursor = view.Cursor();
    BOOST_REQUIRE(cursor);
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        BOOST_REQUIRE(cursor->GetKey(outpoint));
        BOOST_REQUIRE(cursor->GetValue(coin));
        BOOST_REQUIRE(!coin.IsSpent());
        kernel::ApplyCoinHash(muhash, outpoint, coin);
        cursor->Next();
    }
    uint256 result;
    muhash.Finalize(result);
    return result;
}

static void WriteCoinMutation(CCoinsViewDB& view,
                              const COutPoint& outpoint,
                              Coin coin)
{
    CCoinsMapMemoryResource resource;
    CCoinsMap changes{0, CCoinsMap::hasher{}, CCoinsMap::key_equal{},
                      &resource};
    changes.emplace(outpoint, CCoinsCacheEntry{
        std::move(coin), CCoinsCacheEntry::DIRTY});
    const uint256 tip = view.GetBestBlock();
    BOOST_REQUIRE(!tip.IsNull());
    BOOST_REQUIRE(view.BatchWrite(changes, tip));
}

static std::string ReadTextFile(const fs::path& path)
{
    std::ifstream file{path};
    BOOST_REQUIRE(file.is_open());
    return {std::istreambuf_iterator<char>{file},
            std::istreambuf_iterator<char>{}};
}

static void WriteTextFile(const fs::path& path, const std::string& contents)
{
    std::ofstream file{path, std::ios::trunc};
    BOOST_REQUIRE(file.is_open());
    file << contents;
    file.close();
    BOOST_REQUIRE(file.good());
}

static void WriteSnapshotBaseFile(const fs::path& snapshot_dir,
                                  const uint256& base,
                                  bool trailing_byte = false)
{
    const fs::path path = snapshot_dir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    AutoFile file{fsbridge::fopen(path, "wb")};
    BOOST_REQUIRE(!file.IsNull());
    file << base;
    if (trailing_byte) {
        BOOST_REQUIRE(std::fputc(0x01, file.Get()) != EOF);
    }
    BOOST_REQUIRE_EQUAL(file.fclose(), 0);
}

//! Snapshot base metadata is a fixed-width authenticated pointer. Missing,
//! truncated, and trailing data must never be accepted as a usable base.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_metadata_is_strict, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);
    const uint256 original_base = *WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir));
    const fs::path metadata_path = snapshot_dir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    {
        AutoFile file{fsbridge::fopen(metadata_path, "wb")};
        BOOST_REQUIRE(!file.IsNull());
        BOOST_REQUIRE_EQUAL(file.fclose(), 0);
    }
    BOOST_CHECK(!WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir)));

    WriteSnapshotBaseFile(snapshot_dir, original_base, /*trailing_byte=*/true);
    BOOST_CHECK(!WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir)));

    BOOST_REQUIRE(fs::remove(metadata_path));
    BOOST_CHECK(!WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir)));

    WriteSnapshotBaseFile(snapshot_dir, original_base);
    BOOST_CHECK_EQUAL(
        *WITH_LOCK(::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir)),
        original_base);

    // A failed staged write must leave the committed metadata untouched.
    const fs::path staged = fs::PathFromString(
        fs::PathToString(metadata_path) + ".new");
    fs::create_directory(staged);
    {
        AutoFile blocker{fsbridge::fopen(staged / "blocker", "wb")};
        BOOST_REQUIRE(!blocker.IsNull());
        BOOST_REQUIRE_EQUAL(blocker.fclose(), 0);
    }
    BOOST_CHECK(!WITH_LOCK(
        ::cs_main, return node::WriteSnapshotBaseBlockhash(
            chainman.ActiveChainstate())));
    BOOST_CHECK_EQUAL(
        *WITH_LOCK(::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir)),
        original_base);
    BOOST_REQUIRE_EQUAL(fs::remove_all(staged), 2U);
}

//! Snapshot removal must fail before changing the active snapshot when its
//! quarantine destination is unavailable.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_quarantine_failure_is_nonmutating, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);
    const fs::path quarantine = fs::PathFromString(
        fs::PathToString(snapshot_dir) + "_QUARANTINED");
    fs::create_directory(quarantine);

    BOOST_CHECK(!WITH_LOCK(
        ::cs_main, return chainman.DeleteSnapshotChainstate()));
    BOOST_CHECK(chainman.IsSnapshotActive());
    BOOST_CHECK(fs::exists(snapshot_dir));
    BOOST_CHECK(fs::exists(
        snapshot_dir / node::SNAPSHOT_BLOCKHASH_FILENAME));

    BOOST_REQUIRE(fs::remove(quarantine));
}

//! A chainstate-only rebuild must not erase either database when a persisted
//! snapshot directory has lost its base metadata.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_reindex_chainstate_rejects_missing_snapshot_metadata, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path base_dir = chainman.m_options.datadir / "chainstate";
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);
    const uint256 original_base = *WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir));
    const uint256 base_tip = WITH_LOCK(
        ::cs_main, return chainman.GetAll().front()->CoinsDB().GetBestBlock());
    const uint256 snapshot_tip = WITH_LOCK(
        ::cs_main, return chainman.ActiveChainstate().CoinsDB().GetBestBlock());
    const fs::path metadata_path = snapshot_dir / node::SNAPSHOT_BLOCKHASH_FILENAME;

    ChainstateManager& restarted = this->SimulateNodeRestart();
    BOOST_REQUIRE(fs::remove(metadata_path));

    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.reindex_chainstate = true;
    const auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, options);

    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED);
    BOOST_CHECK(error.original.find("base-block metadata is missing, malformed, or unreadable") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(base_dir));
    BOOST_CHECK(fs::exists(snapshot_dir));
    {
        CCoinsViewDB base_db{DBParams{
            .path = base_dir, .cache_bytes = 1 << 20, .memory_only = false,
            .wipe_data = false, .obfuscate = true}, CoinsViewOptions{}};
        CCoinsViewDB snapshot_db{DBParams{
            .path = snapshot_dir, .cache_bytes = 1 << 20, .memory_only = false,
            .wipe_data = false, .obfuscate = true}, CoinsViewOptions{}};
        BOOST_CHECK_EQUAL(base_db.GetBestBlock(), base_tip);
        BOOST_CHECK_EQUAL(snapshot_db.GetBestBlock(), snapshot_tip);
    }
    WriteSnapshotBaseFile(snapshot_dir, original_base);
}

//! A syntactically valid snapshot base that is absent from the authoritative
//! block index must fail safely instead of reaching SnapshotBase()'s assertion
//! or authorizing a destructive rebuild.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_reindex_chainstate_rejects_unknown_snapshot_base, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path base_dir = chainman.m_options.datadir / "chainstate";
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);
    const uint256 original_base = *WITH_LOCK(
        ::cs_main, return node::ReadSnapshotBaseBlockhash(snapshot_dir));

    ChainstateManager& restarted = this->SimulateNodeRestart();
    const auto approved_but_absent = Params().AssumeutxoForHeight(299);
    BOOST_REQUIRE(approved_but_absent);
    const uint256 unknown_base = approved_but_absent->blockhash;
    WriteSnapshotBaseFile(snapshot_dir, unknown_base);

    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.reindex_chainstate = true;
    const auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, options);

    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED);
    BOOST_CHECK(error.original.find("base is not an approved entry in the local block index") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(base_dir));
    BOOST_CHECK(fs::exists(snapshot_dir));
    WriteSnapshotBaseFile(snapshot_dir, original_base);
}

//! A crash after staging both source databases must restore their exact saved
//! tips before a normal startup is allowed to continue.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_staged_rebuild_crash_rolls_back, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path datadir = chainman.m_options.datadir;
    const uint256 base_tip = WITH_LOCK(
        ::cs_main, return chainman.GetAll().front()->CoinsDB().GetBestBlock());
    const uint256 snapshot_tip = WITH_LOCK(
        ::cs_main, return chainman.ActiveChainstate().CoinsDB().GetBestBlock());

    ChainstateManager& restarted = this->SimulateNodeRestart();
    node::ChainstateLoadOptions rebuild;
    rebuild.mempool = Assert(m_node.mempool.get());
    rebuild.reindex_chainstate = true;
    auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, rebuild);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));

    // ActivateBestChain returns success after making limited progress when a
    // shutdown interrupt is raised. That partial reconstruction must never be
    // allowed to cross the durable commit transition.
    m_node.kernel->interrupt();
    BlockValidationState partial_state;
    BOOST_REQUIRE(restarted.ActiveChainstate().ActivateBestChain(
        partial_state, nullptr));
    bilingual_str finalize_error;
    BOOST_CHECK(!node::FinalizeChainstateRebuild(restarted, finalize_error));
    BOOST_CHECK(finalize_error.original.find("interrupted") != std::string::npos);
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(fs::exists(datadir / "chainstate.rebuild-backup"));
    m_node.kernel->interrupt.reset();

    // Clearing the process interrupt cannot make the partial chain
    // authoritative because the manager remembers that reconstruction was
    // interrupted. Only a fresh process may recover the preserved source.
    finalize_error = {};
    BOOST_CHECK(!node::FinalizeChainstateRebuild(restarted, finalize_error));
    BOOST_CHECK(finalize_error.original.find("interrupted") != std::string::npos);
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(fs::exists(datadir / "chainstate.rebuild-backup"));

    ChainstateManager& recovered = this->SimulateCrashRestart();
    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    std::tie(status, error) = node::LoadChainstate(
        recovered, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(!fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));
    WITH_LOCK(::cs_main, {
        BOOST_CHECK_EQUAL(
            recovered.ActiveChainstate().CoinsDB().GetBestBlock(), snapshot_tip);
        if (recovered.IsSnapshotActive()) {
            BOOST_REQUIRE_EQUAL(recovered.GetAll().size(), 2U);
            BOOST_CHECK_EQUAL(
                recovered.GetAll().front()->CoinsDB().GetBestBlock(), base_tip);
        }
    });
}

//! Refuse a protected rebuild before its journal or source moves when there is
//! not enough free space to retain the source and build a replacement of at
//! least the same logical size.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_rebuild_low_disk_is_nonmutating, SnapshotTestSetup)
{
    ChainstateManager& original = *Assert(m_node.chainman);
    const fs::path datadir = original.m_options.datadir;
    const fs::path source = datadir / "chainstate";
    const uint256 source_tip = WITH_LOCK(
        ::cs_main, return original.ActiveTip()->GetBlockHash());

    ChainstateManager& restarted = this->SimulateNodeRestart();
    uint64_t required_bytes{0};
    node::ChainstateLoadOptions rebuild;
    rebuild.mempool = Assert(m_node.mempool.get());
    rebuild.reindex_chainstate = true;
    rebuild.check_rebuild_disk_space = [&](const fs::path& checked_datadir,
                                           uint64_t required) {
        BOOST_CHECK_EQUAL(checked_datadir, datadir);
        required_bytes = required;
        return false;
    };
    const auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, rebuild);

    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FATAL);
    BOOST_CHECK(error.original.find("Insufficient free disk space") !=
                std::string::npos);
    BOOST_CHECK_GT(required_bytes, 0U);
    BOOST_CHECK(fs::exists(source));
    BOOST_CHECK(!fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-partial"));

    CCoinsViewDB preserved{DBParams{
        .path = source,
        .cache_bytes = 1 << 20,
        .memory_only = false,
        .wipe_data = false,
        .obfuscate = true}, CoinsViewOptions{}};
    BOOST_CHECK_EQUAL(preserved.GetBestBlock(), source_tip);
}

//! COMMIT_READY is only a durable build marker. A fresh manager must complete
//! VerifyLoadedChainstate successfully before it can retire source backups,
//! and a later failed or interrupted verification must clear stale success.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_commit_ready_requires_current_verification, SnapshotTestSetup)
{
    ChainstateManager& original = *Assert(m_node.chainman);
    const fs::path datadir = original.m_options.datadir;
    const uint256 source_tip = WITH_LOCK(
        ::cs_main, return original.ActiveTip()->GetBlockHash());

    ChainstateManager& rebuilding = this->SimulateNodeRestart();
    node::ChainstateLoadOptions rebuild;
    rebuild.mempool = Assert(m_node.mempool.get());
    rebuild.reindex_chainstate = true;
    auto [status, error] = node::LoadChainstate(
        rebuilding, m_cache_sizes, rebuild);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    std::tie(status, error) = node::VerifyLoadedChainstate(rebuilding, rebuild);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

    BlockValidationState rebuild_state;
    BOOST_REQUIRE(rebuilding.ActiveChainstate().ActivateBestChain(
        rebuild_state, nullptr));
    BOOST_CHECK_EQUAL(WITH_LOCK(
        ::cs_main, return rebuilding.ActiveTip()->GetBlockHash()), source_tip);

    bilingual_str finalize_error;
    BOOST_REQUIRE(node::FinalizeChainstateRebuild(rebuilding, finalize_error));
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";
    BOOST_REQUIRE(fs::exists(journal));
    BOOST_REQUIRE(fs::exists(backup));

    // A repeated finalizer call from the building manager remains valid but
    // cannot interpret its own COMMIT_READY write as a verification restart.
    BOOST_CHECK(node::FinalizeChainstateRebuild(rebuilding, finalize_error));
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    ChainstateManager& reopened = this->SimulateNodeRestart();
    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    std::tie(status, error) = node::LoadChainstate(
        reopened, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

    finalize_error = {};
    BOOST_CHECK(!node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(finalize_error.original.find("has not completed verification") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(reopened.m_chainstate_rebuild_verified_this_process);

    CBlockIndex* const tip = WITH_LOCK(
        ::cs_main, return reopened.ActiveTip());
    BOOST_REQUIRE(tip);
    const uint32_t saved_time = WITH_LOCK(
        ::cs_main, return tip->nTime);
    WITH_LOCK(::cs_main, tip->nTime = static_cast<uint32_t>(
        GetTime() + MAX_FUTURE_BLOCK_TIME + 1));
    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    WITH_LOCK(::cs_main, tip->nTime = saved_time);
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
    BOOST_CHECK(!reopened.m_chainstate_rebuild_verified_this_process);
    finalize_error = {};
    BOOST_CHECK(!node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(reopened.m_chainstate_rebuild_verified_this_process);
    m_node.kernel->interrupt();
    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    m_node.kernel->interrupt.reset();
    BOOST_CHECK(status == node::ChainstateLoadStatus::INTERRUPTED);
    BOOST_CHECK(!reopened.m_chainstate_rebuild_verified_this_process);
    finalize_error = {};
    BOOST_CHECK(!node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_REQUIRE(node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(!fs::exists(journal));
    BOOST_CHECK(!fs::exists(backup));
    BOOST_CHECK_EQUAL(WITH_LOCK(
        ::cs_main, return reopened.ActiveTip()->GetBlockHash()), source_tip);
}

//! A CLEANUP_READY restart must reopen and authenticate the complete live Coin
//! set before deleting even one retained backup.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_cleanup_rejects_missing_old_coin, SnapshotTestSetup)
{
    const COutPoint target{m_coinbase_txns.front()->GetHash(), 0};
    ChainstateManager& rebuilding = BuildAndCommitProtectedChainstate();
    const fs::path datadir = rebuilding.m_options.datadir;
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";

    ChainstateManager& reopening = SimulateNodeRestart();
    {
        CCoinsViewDB live{DBParams{
            .path = datadir / "chainstate",
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = true}, CoinsViewOptions{}};
        Coin coin;
        BOOST_REQUIRE(live.GetCoin(target, coin));
        coin.Clear();
        WriteCoinMutation(live, target, std::move(coin));
    }
    std::string contents = ReadTextFile(journal);
    const size_t phase = contents.find("phase=commit-ready\n");
    BOOST_REQUIRE(phase != std::string::npos);
    contents.replace(phase, std::string{"phase=commit-ready\n"}.size(),
                     "phase=cleanup-ready\n");
    WriteTextFile(journal, contents);

    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    const auto [status, error] = node::LoadChainstate(
        reopening, m_cache_sizes, normal);
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FATAL);
    BOOST_CHECK(error.original.find("full-Coin commitment") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));
}

//! Coin time is consensus-relevant persisted provenance but is intentionally
//! absent from the legacy assumeUTXO MuHash. The rebuild commitment and a full
//! disconnect check must both detect a time-only mutation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_commitment_covers_coin_time, SnapshotTestSetup)
{
    const COutPoint target{m_coinbase_txns.front()->GetHash(), 0};
    ChainstateManager& rebuilding = BuildAndCommitProtectedChainstate();
    const fs::path datadir = rebuilding.m_options.datadir;
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";

    ChainstateManager& reopened = SimulateNodeRestart();
    {
        CCoinsViewDB live{DBParams{
            .path = datadir / "chainstate",
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = true}, CoinsViewOptions{}};
        const uint256 legacy_before = LegacyMuHash(live);
        Coin coin;
        BOOST_REQUIRE(live.GetCoin(target, coin));
        BOOST_REQUIRE(coin.nTime < std::numeric_limits<unsigned int>::max());
        ++coin.nTime;
        WriteCoinMutation(live, target, std::move(coin));
        BOOST_CHECK_EQUAL(LegacyMuHash(live), legacy_before);
    }

    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    auto [status, error] = node::LoadChainstate(
        reopened, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

    bilingual_str finalize_error;
    BOOST_CHECK(!node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(finalize_error.original.find("full-Coin commitment") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    node::ChainstateLoadOptions full_check = normal;
    full_check.check_blocks = 0;
    full_check.check_level = 4;
    std::tie(status, error) = node::VerifyLoadedChainstate(
        reopened, full_check);
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE);
}

//! Coinstake provenance is also absent from the legacy assumeUTXO MuHash. A
//! post-commit mutation of only that persisted flag must retain the backup.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_commitment_covers_coinstake_flag, SnapshotTestSetup)
{
    const COutPoint target{m_coinbase_txns.front()->GetHash(), 0};
    ChainstateManager& rebuilding = BuildAndCommitProtectedChainstate();
    const fs::path datadir = rebuilding.m_options.datadir;
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";

    ChainstateManager& reopened = SimulateNodeRestart();
    {
        CCoinsViewDB live{DBParams{
            .path = datadir / "chainstate",
            .cache_bytes = 1 << 20,
            .memory_only = false,
            .wipe_data = false,
            .obfuscate = true}, CoinsViewOptions{}};
        const uint256 legacy_before = LegacyMuHash(live);
        Coin coin;
        BOOST_REQUIRE(live.GetCoin(target, coin));
        coin.fCoinStake = !coin.fCoinStake;
        WriteCoinMutation(live, target, std::move(coin));
        BOOST_CHECK_EQUAL(LegacyMuHash(live), legacy_before);
    }

    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    auto [status, error] = node::LoadChainstate(
        reopened, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    std::tie(status, error) = node::VerifyLoadedChainstate(reopened, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);

    bilingual_str finalize_error;
    BOOST_CHECK(!node::FinalizeChainstateRebuild(reopened, finalize_error));
    BOOST_CHECK(finalize_error.original.find("full-Coin commitment") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));
}

//! A committed legacy journal has no state identity to authenticate. It must
//! retain the backup even if it claims cleanup was already authorized.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_legacy_cleanup_journal_fails_closed, SnapshotTestSetup)
{
    ChainstateManager& rebuilding = BuildAndCommitProtectedChainstate();
    const fs::path datadir = rebuilding.m_options.datadir;
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";
    ChainstateManager& reopening = SimulateNodeRestart();

    WriteTextFile(journal,
                  "blackcoin-chainstate-rebuild-v1\n"
                  "phase=cleanup-ready\n"
                  "base=1\n"
                  "snapshot=0\n");
    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    const auto [status, error] = node::LoadChainstate(
        reopening, m_cache_sizes, normal);
    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FATAL);
    BOOST_CHECK(error.original.find("predates full-Coin commitments") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));
}

//! Recovery commitment scans must honor shutdown without advancing cleanup.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_cleanup_commitment_is_interruptible, SnapshotTestSetup)
{
    ChainstateManager& rebuilding = BuildAndCommitProtectedChainstate();
    const fs::path datadir = rebuilding.m_options.datadir;
    const fs::path journal = datadir / "chainstate-rebuild.journal";
    const fs::path backup = datadir / "chainstate.rebuild-backup";
    ChainstateManager& reopening = SimulateNodeRestart();

    std::string contents = ReadTextFile(journal);
    const size_t phase = contents.find("phase=commit-ready\n");
    BOOST_REQUIRE(phase != std::string::npos);
    contents.replace(phase, std::string{"phase=commit-ready\n"}.size(),
                     "phase=cleanup-ready\n");
    WriteTextFile(journal, contents);

    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    m_node.kernel->interrupt();
    auto [status, error] = node::LoadChainstate(
        reopening, m_cache_sizes, normal);
    m_node.kernel->interrupt.reset();
    BOOST_CHECK(status == node::ChainstateLoadStatus::INTERRUPTED);
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(fs::exists(backup));

    std::tie(status, error) = node::LoadChainstate(
        reopening, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(!fs::exists(journal));
    BOOST_CHECK(!fs::exists(backup));
}

//! Shutdown between the base and snapshot renames must remain rollback-safe.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_staged_rebuild_interrupt_rolls_back, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path datadir = chainman.m_options.datadir;
    const uint256 base_tip = WITH_LOCK(
        ::cs_main, return chainman.GetAll().front()->CoinsDB().GetBestBlock());
    const uint256 snapshot_tip = WITH_LOCK(
        ::cs_main, return chainman.ActiveChainstate().CoinsDB().GetBestBlock());

    ChainstateManager& restarted = this->SimulateNodeRestart();
    int interrupt_poll{0};
    node::ChainstateLoadOptions rebuild;
    rebuild.mempool = Assert(m_node.mempool.get());
    rebuild.reindex_chainstate = true;
    rebuild.check_interrupt = [&] { return ++interrupt_poll == 5; };
    auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, rebuild);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::INTERRUPTED);
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(fs::exists(datadir / "chainstate_snapshot"));

    ChainstateManager& recovered = this->SimulateCrashRestart();
    node::ChainstateLoadOptions normal;
    normal.mempool = Assert(m_node.mempool.get());
    std::tie(status, error) = node::LoadChainstate(
        recovered, m_cache_sizes, normal);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    WITH_LOCK(::cs_main, {
        BOOST_CHECK_EQUAL(
            recovered.ActiveChainstate().CoinsDB().GetBestBlock(), snapshot_tip);
        if (recovered.IsSnapshotActive()) {
            BOOST_CHECK_EQUAL(
                recovered.GetAll().front()->CoinsDB().GetBestBlock(), base_tip);
        }
    });
}

//! If the preserved source contained only a snapshot database, rollback must
//! remove the newly created base database rather than treating it as part of
//! the original topology.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_only_rebuild_rolls_back_partial_base, SnapshotTestSetup)
{
    this->SetupSnapshot();
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const fs::path datadir = chainman.m_options.datadir;
    const fs::path base_dir = datadir / "chainstate";
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(datadir);
    const uint256 snapshot_tip = WITH_LOCK(
        ::cs_main, return chainman.ActiveChainstate().CoinsDB().GetBestBlock());

    ChainstateManager& restarted = this->SimulateNodeRestart();
    BOOST_REQUIRE(fs::remove_all(base_dir) > 0);

    node::ChainstateLoadOptions rebuild;
    rebuild.mempool = Assert(m_node.mempool.get());
    rebuild.reindex_chainstate = true;
    auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, rebuild);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::SUCCESS);
    BOOST_CHECK(fs::exists(base_dir));
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));

    ChainstateManager& recovered = this->SimulateCrashRestart();
    node::ChainstateLoadOptions interrupted_start;
    interrupted_start.mempool = Assert(m_node.mempool.get());
    interrupted_start.check_interrupt = [] { return true; };
    std::tie(status, error) = node::LoadChainstate(
        recovered, m_cache_sizes, interrupted_start);
    BOOST_REQUIRE(status == node::ChainstateLoadStatus::INTERRUPTED);

    BOOST_CHECK(!fs::exists(base_dir));
    BOOST_CHECK(fs::exists(snapshot_dir));
    BOOST_CHECK(!fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-partial"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));
    CCoinsViewDB snapshot_db{DBParams{
        .path = snapshot_dir,
        .cache_bytes = 1 << 20,
        .memory_only = false,
        .wipe_data = false,
        .obfuscate = true}, CoinsViewOptions{}};
    BOOST_CHECK_EQUAL(snapshot_db.GetBestBlock(), snapshot_tip);
}

//! Test basic snapshot activation.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_activate_snapshot, SnapshotTestSetup)
{
    this->SetupSnapshot();
}

//! Deleting an active snapshot for reindex must return the node mempool to the
//! background chainstate before the snapshot object is destroyed.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_delete_snapshot_rehomes_mempool, SnapshotTestSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& background_chainstate = chainman.ActiveChainstate();
    this->SetupSnapshot();
    CTxMemPool* const node_mempool = Assert(m_node.mempool.get());
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);
    BOOST_REQUIRE(chainman.IsSnapshotActive());
    BOOST_REQUIRE(chainman.ActiveChainstate().GetMempool() == node_mempool);
    const uint256 snapshot_tip_hash = WITH_LOCK(
        chainman.GetMutex(), return chainman.ActiveTip()->GetBlockHash());
    BOOST_REQUIRE(!snapshot_tip_hash.IsNull());
    BOOST_REQUIRE_EQUAL(chainman.GetAll().size(), 2U);

    // Keep the background chain below the snapshot base so restart detects an
    // active, not already-completed, snapshot chainstate.
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_SIZE * 1000};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, background_chainstate.MempoolMutex());
        BOOST_REQUIRE(background_chainstate.DisconnectTip(
            unused_state, &unused_pool));
        unused_pool.clear();
    }
    BOOST_REQUIRE_EQUAL(background_chainstate.m_chain.Height(), 109);

    this->SimulateNodeRestart();
    m_args.ForceSetArg("-reindex-chainstate", "1");
    this->LoadVerifyActivateChainstate();

    ChainstateManager& rebuilding = *Assert(m_node.chainman);
    const fs::path datadir = rebuilding.m_options.datadir;
    BOOST_CHECK(!rebuilding.IsSnapshotActive());
    BOOST_CHECK(rebuilding.ActiveChainstate().GetMempool() == node_mempool);
    BOOST_CHECK(!rebuilding.m_blockman.m_snapshot_height);
    BOOST_CHECK_EQUAL(rebuilding.GetAll().size(), 1U);
    BOOST_CHECK_EQUAL(WITH_LOCK(
        rebuilding.GetMutex(), return rebuilding.ActiveTip()->GetBlockHash()),
        snapshot_tip_hash);
    BOOST_CHECK(!fs::exists(snapshot_dir));
    BOOST_CHECK(fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));

    // The rebuilding process may commit the replacement, but the source
    // backups remain until a separate process reopens and verifies it. A
    // repeated one-shot flag must complete that verification, not collide
    // with the existing journal or start another rebuild.
    this->SimulateNodeRestart();
    this->LoadVerifyActivateChainstate();

    ChainstateManager& rebuilt = *Assert(m_node.chainman);
    BOOST_CHECK(!rebuilt.IsSnapshotActive());
    BOOST_CHECK(rebuilt.ActiveChainstate().GetMempool() == node_mempool);
    BOOST_CHECK_EQUAL(WITH_LOCK(
        rebuilt.GetMutex(), return rebuilt.ActiveTip()->GetBlockHash()),
        snapshot_tip_hash);
    BOOST_CHECK(!fs::exists(datadir / "chainstate-rebuild.journal"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate.rebuild-backup"));
    BOOST_CHECK(!fs::exists(datadir / "chainstate_snapshot.rebuild-backup"));

    // Exercise block creation, undo writing, and activation after the rebuild.
    const int previous_height = WITH_LOCK(
        rebuilt.GetMutex(), return rebuilt.ActiveHeight());
    mineBlocks(1);
    BOOST_CHECK_EQUAL(WITH_LOCK(
        rebuilt.GetMutex(), return rebuilt.ActiveHeight()), previous_height + 1);
    BOOST_CHECK(rebuilt.ActiveChainstate().GetMempool() == node_mempool);
    BOOST_CHECK(!rebuilt.m_blockman.m_snapshot_height);
}

//! A chainstate-only rebuild cannot recover an active assumeUTXO chain from raw
//! block bytes whose index entries have not completed transaction validation.
//! Refuse before deleting either persisted chainstate.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_reindex_chainstate_refuses_assumed_history, SnapshotTestSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& background_chainstate = chainman.ActiveChainstate();
    this->SetupSnapshot();

    // Simulate a background validator that has reached height 90 while the
    // snapshot chain has raw data, but only assumeUTXO validity, through its
    // base at height 110.
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_SIZE * 1000};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, background_chainstate.MempoolMutex());
        while (background_chainstate.m_chain.Height() > 90) {
            BOOST_REQUIRE(background_chainstate.DisconnectTip(
                unused_state, &unused_pool));
            unused_pool.clear();
        }

        for (int height = 91; height <= 110; ++height) {
            CBlockIndex* const index = background_chainstate.m_chainman.m_blockman.LookupBlockIndex(
                chainman.ActiveChain()[height]->GetBlockHash());
            BOOST_REQUIRE(index);
            index->nStatus = (index->nStatus &
                              ~(BLOCK_VALID_MASK | BLOCK_FAILED_MASK)) |
                             BLOCK_VALID_TREE | BLOCK_ASSUMED_VALID |
                             BLOCK_HAVE_DATA | BLOCK_FAILED_VALID;
            // Clear the temporary failure bit through the production helper so
            // the modified index entry is queued for persistence.
            background_chainstate.ResetBlockFailureFlags(index);
            BOOST_CHECK(index->nStatus & BLOCK_HAVE_DATA);
            BOOST_CHECK(index->IsAssumedValid());
            BOOST_CHECK(!index->IsValid(BLOCK_VALID_TRANSACTIONS));
        }
    }

    const uint256 background_tip = WITH_LOCK(
        chainman.GetMutex(), return background_chainstate.m_chain.Tip()->GetBlockHash());
    const uint256 snapshot_tip = WITH_LOCK(
        chainman.GetMutex(), return chainman.ActiveTip()->GetBlockHash());
    const fs::path base_dir = chainman.m_options.datadir / "chainstate";
    const fs::path snapshot_dir = *node::FindSnapshotChainstateDir(
        chainman.m_options.datadir);

    ChainstateManager& restarted = this->SimulateNodeRestart();
    node::ChainstateLoadOptions options;
    options.mempool = Assert(m_node.mempool.get());
    options.reindex_chainstate = true;
    const auto [status, error] = node::LoadChainstate(
        restarted, m_cache_sizes, options);

    BOOST_CHECK(status == node::ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED);
    BOOST_CHECK(error.original.find("transaction-validated block history is incomplete at height 110") !=
                std::string::npos);
    BOOST_CHECK(fs::exists(base_dir));
    BOOST_CHECK(fs::exists(snapshot_dir));
    BOOST_CHECK(restarted.IsSnapshotActive());
    BOOST_CHECK_EQUAL(restarted.GetAll().size(), 2U);

    // Reopen both databases without wiping and prove their saved tips survived
    // the refused startup.
    {
        LOCK(::cs_main);
        for (Chainstate* chainstate : restarted.GetAll()) {
            chainstate->InitCoinsDB(
                /*cache_size_bytes=*/1 << 20,
                /*in_memory=*/false,
                /*should_wipe=*/false);
            const uint256 saved_tip = chainstate->CoinsDB().GetBestBlock();
            BOOST_CHECK_EQUAL(saved_tip,
                              chainstate->m_from_snapshot_blockhash
                                  ? snapshot_tip
                                  : background_tip);
            chainstate->ResetCoinsViews();
        }
    }
}

//! Test LoadBlockIndex behavior when multiple chainstates are in use.
//!
//! - First, verify that setBlockIndexCandidates is as expected when using a single,
//!   fully-validating chainstate.
//!
//! - Then mark a region of the chain BLOCK_ASSUMED_VALID and introduce a second chainstate
//!   that will tolerate assumed-valid blocks. Run LoadBlockIndex() and ensure that the first
//!   chainstate only contains fully validated blocks and the other chainstate contains all blocks,
//!   except those marked assume-valid, because those entries don't HAVE_DATA.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    int num_assumed_valid{0};
    // Blocks in range [assumed_valid_start_idx, last_assumed_valid_idx) will be
    // marked as assumed-valid and not having data.
    const int expected_assumed_valid{20};
    const int last_assumed_valid_idx{111};
    const int assumed_valid_start_idx = last_assumed_valid_idx - expected_assumed_valid;

    // Mine to height 120, past the hardcoded regtest assumeutxo snapshot at
    // height 110
    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* assumed_base{nullptr};
    CBlockIndex* assumed_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);

    auto reload_all_block_indexes = [&]() {
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        WITH_LOCK(::cs_main, return chainman.ResetBlockSequenceCounters());
        for (Chainstate* cs : chainman.GetAll()) {
            LOCK(::cs_main);
            cs->ClearBlockIndexCandidates();
            BOOST_CHECK(cs->setBlockIndexCandidates.empty());
        }

        WITH_LOCK(::cs_main, chainman.LoadBlockIndex());
    };

    // Ensure that without any assumed-valid BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_all_block_indexes();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Mark some region of the chain assumed-valid, and remove the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked ASSUMED_VALID
        if (i < last_assumed_valid_idx && i >= assumed_valid_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE | BlockStatus::BLOCK_ASSUMED_VALID;
        }

        ++num_indexes;
        if (index->IsAssumedValid()) ++num_assumed_valid;

        // Note the last fully-validated block as the expected validated tip.
        if (i == (assumed_valid_start_idx - 1)) {
            validated_tip = index;
            BOOST_CHECK(!index->IsAssumedValid());
        }
        // Note the last assumed valid block as the snapshot base
        if (i == last_assumed_valid_idx - 1) {
            assumed_base = index;
            BOOST_CHECK(index->IsAssumedValid());
        } else if (i == last_assumed_valid_idx) {
            BOOST_CHECK(!index->IsAssumedValid());
        }
    }

    BOOST_CHECK_EQUAL(expected_assumed_valid, num_assumed_valid);

    // Note: cs2's tip is not set when ActivateExistingSnapshot is called.
    Chainstate& cs2 = WITH_LOCK(::cs_main,
        return chainman.ActivateExistingSnapshot(*assumed_base->phashBlock));

    // Set tip of the fully validated chain to be the validated tip
    cs1.m_chain.SetTip(*validated_tip);

    // Set tip of the assume-valid-based chain to the assume-valid block
    cs2.m_chain.SetTip(*assumed_base);

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(assumed_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // current cs1 chain has height 90
    BOOST_CHECK_EQUAL(assumed_base->nHeight, 110); // current cs2 chain has height 110

    // Regenerate cs1.setBlockIndexCandidates and cs2.setBlockIndexCandidate and
    // check contents below.
    reload_all_block_indexes();

    // The fully validated chain should only have the current validated tip and
    // the assumed valid base as candidates, blocks 90 and 110. Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-109 because they do not contain data.
    //
    // - It has block 110 even though it does not have data, because
    //   LoadBlockIndex has a special case to always add the snapshot block as a
    //   candidate. The special case is only actually intended to apply to the
    //   snapshot chainstate cs2, not the background chainstate cs1, but it is
    //   written broadly and applies to both.
    //
    // - It does not have any blocks after height 110 because cs1 is a background
    //   chainstate, and only blocks where are ancestors of the snapshot block
    //   are added as candidates for the background chainstate.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 2);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(assumed_base), 1);

    // The assumed-valid tolerant chain has the assumed valid base as a
    // candidate, but otherwise has none of the assumed-valid (which do not
    // HAVE_DATA) blocks as candidates.
    //
    // Specifically:
    // - All blocks below height 110 are not candidates, because cs2 chain tip
    //   has height 110 and they have less work than it does.
    //
    // - Block 110 is a candidate even though it does not have data, because it
    //   is the snapshot block, which is assumed valid.
    //
    // - Blocks 111-120 are added because they have data.

    // Check that block 90 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(validated_tip), 0);
    // Check that block 109 is absent
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base->pprev), 0);
    // Check that block 110 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_base), 1);
    // Check that block 120 is present
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.count(assumed_tip), 1);
    // Check that 11 blocks total are present.
    BOOST_CHECK_EQUAL(cs2.setBlockIndexCandidates.size(), num_indexes - last_assumed_valid_idx + 1);
}

//! Ensure that snapshot chainstates initialize properly when found on disk.
BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_init, SnapshotTestSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& bg_chainstate = chainman.ActiveChainstate();

    this->SetupSnapshot();

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 2);

    // "Rewind" the background chainstate so that its tip is not at the
    // base block of the snapshot - this is so after simulating a node restart,
    // it will initialize instead of attempting to complete validation.
    //
    // Note that this is not a realistic use of DisconnectTip().
    DisconnectedBlockTransactions unused_pool{MAX_DISCONNECTED_TX_POOL_SIZE * 1000};
    BlockValidationState unused_state;
    {
        LOCK2(::cs_main, bg_chainstate.MempoolMutex());
        BOOST_CHECK(bg_chainstate.DisconnectTip(unused_state, &unused_pool));
        unused_pool.clear();  // to avoid queuedTx assertion errors on teardown
    }
    BOOST_CHECK_EQUAL(bg_chainstate.m_chain.Height(), 109);

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates.
    this->LoadVerifyActivateChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 2);
        BOOST_CHECK(chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the initialized snapshot chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);

        // Background chainstate should be unaware of new blocks on the snapshot
        // chainstate.
        for (Chainstate* cs : chainman_restarted.GetAll()) {
            if (cs != &chainman_restarted.ActiveChainstate()) {
                BOOST_CHECK_EQUAL(cs->m_chain.Height(), 109);
            }
        }
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion, SnapshotTestSetup)
{
    this->SetupSnapshot();

    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& active_cs = chainman.ActiveChainstate();
    auto tip_cache_before_complete = active_cs.m_coinstip_cache_size_bytes;
    auto db_cache_before_complete = active_cs.m_coinsdb_cache_size_bytes;

    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    fs::path snapshot_chainstate_dir = *node::FindSnapshotChainstateDir(chainman.m_options.datadir);
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));
    BOOST_CHECK_EQUAL(snapshot_chainstate_dir, gArgs.GetDataDirNet() / "chainstate_snapshot");

    BOOST_CHECK(chainman.IsSnapshotActive());
    const uint256 snapshot_tip_hash = WITH_LOCK(chainman.GetMutex(),
        return chainman.ActiveTip()->GetBlockHash());

    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SUCCESS);

    WITH_LOCK(::cs_main, BOOST_CHECK(chainman.IsSnapshotValidated()));
    BOOST_CHECK(chainman.IsSnapshotActive());

    // Cache should have been rebalanced and reallocated to the "only" remaining
    // chainstate.
    BOOST_CHECK(active_cs.m_coinstip_cache_size_bytes > tip_cache_before_complete);
    BOOST_CHECK(active_cs.m_coinsdb_cache_size_bytes > db_cache_before_complete);

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &active_cs);

    // Trying completion again should return false.
    res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
    BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::SKIPPED);

    // The invalid snapshot path should not have been used.
    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should still exist.
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully cleans up the background-validation
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(!fs::exists(snapshot_invalid_dir));
    // chainstate_snapshot should now *not* exist.
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    const Chainstate& active_cs2 = chainman_restarted.ActiveChainstate();

    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK(active_cs2.m_coinstip_cache_size_bytes > tip_cache_before_complete);
        BOOST_CHECK(active_cs2.m_coinsdb_cache_size_bytes > db_cache_before_complete);

        BOOST_CHECK_EQUAL(chainman_restarted.ActiveTip()->GetBlockHash(), snapshot_tip_hash);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(chainman_restarted.GetMutex());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_snapshot_completion_hash_mismatch, SnapshotTestSetup)
{
    auto chainstates = this->SetupSnapshot();
    Chainstate& validation_chainstate = *std::get<0>(chainstates);
    ChainstateManager& chainman = *Assert(m_node.chainman);
    SnapshotCompletionResult res;
    m_node.notifications->m_shutdown_on_fatal_error = false;

    // Test tampering with the IBD UTXO set with an extra coin to ensure it causes
    // snapshot completion to fail.
    CCoinsViewCache& ibd_coins = WITH_LOCK(::cs_main,
        return validation_chainstate.CoinsTip());
    Coin badcoin;
    badcoin.out.nValue = InsecureRand32();
    badcoin.nHeight = 1;
    badcoin.out.scriptPubKey.assign(InsecureRandBits(6), 0);
    uint256 txid = InsecureRand256();
    ibd_coins.AddCoin(COutPoint(txid, 0), std::move(badcoin), false);

    fs::path snapshot_chainstate_dir = gArgs.GetDataDirNet() / "chainstate_snapshot";
    BOOST_CHECK(fs::exists(snapshot_chainstate_dir));

    {
        ASSERT_DEBUG_LOG("failed to validate the -assumeutxo snapshot state");
        res = WITH_LOCK(::cs_main, return chainman.MaybeCompleteSnapshotValidation());
        BOOST_CHECK_EQUAL(res, SnapshotCompletionResult::HASH_MISMATCH);
    }

    auto all_chainstates = chainman.GetAll();
    BOOST_CHECK_EQUAL(all_chainstates.size(), 1);
    BOOST_CHECK_EQUAL(all_chainstates[0], &validation_chainstate);
    BOOST_CHECK_EQUAL(&chainman.ActiveChainstate(), &validation_chainstate);

    fs::path snapshot_invalid_dir = gArgs.GetDataDirNet() / "chainstate_snapshot_INVALID";
    BOOST_CHECK(fs::exists(snapshot_invalid_dir));

    // Test that simulating a shutdown (resetting ChainstateManager) and then performing
    // chainstate reinitializing successfully loads only the fully-validated
    // chainstate data, and we end up with a single chainstate that is at tip.
    ChainstateManager& chainman_restarted = this->SimulateNodeRestart();

    BOOST_TEST_MESSAGE("Performing Load/Verify/Activate of chainstate");

    // This call reinitializes the chainstates, and should clean up the now unnecessary
    // background-validation leveldb contents.
    this->LoadVerifyActivateChainstate();

    BOOST_CHECK(fs::exists(snapshot_invalid_dir));
    BOOST_CHECK(!fs::exists(snapshot_chainstate_dir));

    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.GetAll().size(), 1);
        BOOST_CHECK(!chainman_restarted.IsSnapshotActive());
        BOOST_CHECK(!chainman_restarted.IsSnapshotValidated());
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 210);
    }

    BOOST_TEST_MESSAGE(
        "Ensure we can mine blocks on top of the \"new\" IBD chainstate");
    mineBlocks(10);
    {
        LOCK(::cs_main);
        BOOST_CHECK_EQUAL(chainman_restarted.ActiveHeight(), 220);
    }
}

BOOST_AUTO_TEST_SUITE_END()
