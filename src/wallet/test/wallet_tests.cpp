// Copyright (c) 2012-2022 Blackcoin Core Developers
// Copyright (c) 2012-2022 Blackcoin More Developers
// Copyright (c) 2012-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>

#include <algorithm>
#include <array>
#include <future>
#include <iterator>
#include <memory>
#include <stdint.h>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include <addresstype.h>
#include <chain.h>
#include <consensus/demurrage.h>
#include <coins.h>
#include <crypto/mldsa.h>
#include <interfaces/chain.h>
#include <key_io.h>
#include <node/blockstorage.h>
#include <policy/policy.h>
#include <rpc/server.h>
#include <script/solver.h>
#include <shadow.h>
#include <support/cleanse.h>
#include <streams.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <util/fs_helpers.h>
#include <util/getuniquepath.h>
#include <util/readwritefile.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/receive.h>
#include <wallet/spend.h>
#include <wallet/staking.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

using node::MAX_BLOCKFILE_SIZE;

namespace wallet {
RPCHelpMan importmulti();
RPCHelpMan dumpwallet();
RPCHelpMan importwallet();

// Blackcoin
/*
// Ensure that fee levels defined in the wallet are at least as high
// as the default levels for node policy.
static_assert(DEFAULT_TRANSACTION_MINFEE >= DEFAULT_MIN_RELAY_TX_FEE, "wallet minimum fee is smaller than default relay fee");
*/

BOOST_FIXTURE_TEST_SUITE(wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(abandon_unknown_transaction_is_safe)
{
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_CHECK(!wallet.AbandonTransaction(uint256::ONE));
}

BOOST_AUTO_TEST_CASE(shadow_pow_claim_submission_guard_is_single_flight_and_exception_safe)
{
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());

    constexpr size_t worker_count{16};
    std::promise<void> start;
    std::shared_future<void> start_future = start.get_future().share();
    std::promise<void> release_winner;
    std::shared_future<void> release_future = release_winner.get_future().share();
    std::atomic<size_t> ready{0};
    std::atomic<size_t> attempted{0};
    std::atomic<size_t> acquired{0};
    std::vector<std::future<bool>> workers;
    workers.reserve(worker_count);
    for (size_t i = 0; i < worker_count; ++i) {
        workers.emplace_back(std::async(std::launch::async, [&] {
            ++ready;
            start_future.wait();
            ShadowPowClaimSubmissionGuard guard(wallet);
            ++attempted;
            if (!guard) return false;
            ++acquired;
            release_future.wait();
            return true;
        }));
    }

    while (ready.load() != worker_count) std::this_thread::yield();
    start.set_value();
    while (attempted.load() != worker_count) std::this_thread::yield();
    BOOST_CHECK_EQUAL(acquired.load(), 1U);
    release_winner.set_value();

    size_t successful_workers{0};
    for (auto& worker : workers) {
        if (worker.get()) ++successful_workers;
    }
    BOOST_CHECK_EQUAL(successful_workers, 1U);

    try {
        ShadowPowClaimSubmissionGuard guard(wallet);
        BOOST_REQUIRE(static_cast<bool>(guard));
        throw std::runtime_error("injected claim submission failure");
    } catch (const std::runtime_error&) {
    }

    ShadowPowClaimSubmissionGuard after_exception(wallet);
    BOOST_CHECK(static_cast<bool>(after_exception));
}

static CMutableTransaction TestSimpleSpend(const CTransaction& from, uint32_t index, const CKey& key, const CScript& pubkey)
{
    CMutableTransaction mtx;
    mtx.vout.emplace_back(from.vout[index].nValue - DEFAULT_TRANSACTION_MAXFEE, pubkey);
    mtx.vin.push_back({CTxIn{from.GetHash(), index}});
    FillableSigningProvider keystore;
    keystore.AddKey(key);
    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout].out = from.vout[index];
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(mtx, &keystore, coins, SIGHASH_ALL, input_errors));
    return mtx;
}

static void AddKey(CWallet& wallet, const CKey& key)
{
    LOCK(wallet.cs_wallet);
    FlatSigningProvider provider;
    std::string error;
    std::unique_ptr<Descriptor> desc = Parse("combo(" + EncodeSecret(key) + ")", provider, error, /* require_checksum=*/ false);
    assert(desc);
    WalletDescriptor w_desc(std::move(desc), 0, 0, 1, 1);
    if (!wallet.AddWalletDescriptor(w_desc, provider, "", false)) assert(false);
}

BOOST_FIXTURE_TEST_CASE(commit_refreshes_mempool_state_before_async_callbacks, TestChain100Setup)
{
    CKey wallet_key;
    wallet_key.MakeNewKey(/*fCompressed=*/true);
    const CMutableTransaction funding = TestSimpleSpend(
        *m_coinbase_txns[0],
        /*index=*/0,
        coinbaseKey,
        GetScriptForRawPubKey(wallet_key.GetPubKey()));
    CreateAndProcessBlock({funding}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    auto wallet = CreateSyncedWallet(
        *m_node.chain,
        WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()),
        wallet_key);
    wallet->SetBroadcastTransactions(/*broadcast=*/true);
    SyncWithValidationInterfaceQueue();

    // Keep transactionAddedToMempool queued so the synchronous post-broadcast
    // refresh is the only way an immediate second send can trust and spend the
    // first transaction's change.
    std::promise<void> unblock_callbacks;
    CallFunctionInValidationInterfaceQueue([&unblock_callbacks] {
        unblock_callbacks.get_future().wait();
    });

    try {
        CKey recipient_key;
        recipient_key.MakeNewKey(/*fCompressed=*/true);
        const CRecipient recipient{PKHash{recipient_key.GetPubKey()}, COIN, /*subtract_fee=*/false};
        CCoinControl coin_control;
        constexpr int RANDOM_CHANGE_POSITION{-1};

        const auto first = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, coin_control);
        BOOST_REQUIRE_MESSAGE(first, util::ErrorString(first).original);
        BOOST_REQUIRE(wallet->CommitTransaction(first->tx, {}, {}));
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->mapWallet.at(first->tx->GetHash()).InMempool());
        }

        const auto second = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, coin_control);
        BOOST_REQUIRE_MESSAGE(second, util::ErrorString(second).original);
        BOOST_REQUIRE(wallet->CommitTransaction(second->tx, {}, {}));
        {
            LOCK(wallet->cs_wallet);
            BOOST_REQUIRE(wallet->mapWallet.at(second->tx->GetHash()).InMempool());
        }
    } catch (...) {
        unblock_callbacks.set_value();
        SyncWithValidationInterfaceQueue();
        throw;
    }

    unblock_callbacks.set_value();
    SyncWithValidationInterfaceQueue();
}

static void CheckLiveUnspentStakeIndex(CWallet& wallet)
{
    std::set<COutPoint> expected;
    std::set<COutPoint> indexed;
    {
        LOCK(wallet.cs_wallet);
        for (const auto& [txid, wtx] : wallet.mapWallet) {
            if (!wtx.tx) continue;
            for (uint32_t output = 0; output < wtx.tx->vout.size(); ++output) {
                const COutPoint outpoint{txid, output};
                if (!wallet.IsSpent(outpoint)) expected.insert(outpoint);
            }
        }
        indexed = wallet.GetLiveUnspentStakeOutpoints();
    }
    BOOST_CHECK(expected == indexed);
    BOOST_CHECK_EQUAL(wallet.GetLiveUnspentStakeOutputCount(), expected.size());
}

BOOST_AUTO_TEST_CASE(live_unspent_stake_index_tracks_state_conflicts_zap_and_reload)
{
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);

    CMutableTransaction funding_mut;
    funding_mut.vin.emplace_back(COutPoint{uint256{1}, 0});
    funding_mut.vout.emplace_back(10 * COIN, CScript{} << OP_TRUE);
    const CTransactionRef funding = MakeTransactionRef(std::move(funding_mut));
    BOOST_REQUIRE(wallet.AddToWallet(funding, TxStateInMempool{}));
    CheckLiveUnspentStakeIndex(wallet);
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }

    CMutableTransaction spend_a_mut;
    spend_a_mut.vin.emplace_back(COutPoint{funding->GetHash(), 0});
    spend_a_mut.vout.emplace_back(9 * COIN, CScript{} << OP_TRUE);
    const CTransactionRef spend_a = MakeTransactionRef(std::move(spend_a_mut));
    BOOST_REQUIRE(wallet.AddToWallet(spend_a, TxStateInMempool{}));
    CheckLiveUnspentStakeIndex(wallet);
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(!wallet.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }

    // Abandoning and then reopening a spend models the input-availability
    // transitions used by stale-claim cleanup and reorg recovery.
    BOOST_REQUIRE(wallet.AddToWallet(
        spend_a, TxStateInactive{/*abandoned=*/true},
        [](CWalletTx& wtx, bool new_tx) {
            BOOST_CHECK(!new_tx);
            wtx.m_state = TxStateInactive{/*abandoned=*/true};
            return true;
        }));
    CheckLiveUnspentStakeIndex(wallet);
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }
    BOOST_REQUIRE(wallet.AddToWallet(spend_a, TxStateInMempool{}));

    CMutableTransaction spend_b_mut;
    spend_b_mut.vin.emplace_back(COutPoint{funding->GetHash(), 0});
    spend_b_mut.vout.emplace_back(8 * COIN, CScript{} << OP_TRUE);
    const CTransactionRef spend_b = MakeTransactionRef(std::move(spend_b_mut));
    BOOST_REQUIRE(wallet.AddToWallet(spend_b, TxStateInMempool{}));
    CheckLiveUnspentStakeIndex(wallet);

    // Removing one of two conflicting spends must not lose the other spend's
    // mapTxSpends entry or prematurely reopen the shared input.
    {
        LOCK(wallet.cs_wallet);
        std::vector<uint256> selected{spend_a->GetHash()};
        std::vector<uint256> removed;
        BOOST_REQUIRE_EQUAL(wallet.ZapSelectTx(selected, removed), DBErrors::LOAD_OK);
        BOOST_REQUIRE_EQUAL(removed.size(), 1U);
        BOOST_CHECK_EQUAL(removed.front(), spend_a->GetHash());
        BOOST_CHECK(!wallet.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }
    CheckLiveUnspentStakeIndex(wallet);

    {
        LOCK(wallet.cs_wallet);
        std::vector<uint256> selected{spend_b->GetHash()};
        std::vector<uint256> removed;
        BOOST_REQUIRE_EQUAL(wallet.ZapSelectTx(selected, removed), DBErrors::LOAD_OK);
        BOOST_REQUIRE_EQUAL(removed.size(), 1U);
        BOOST_CHECK(wallet.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }
    CheckLiveUnspentStakeIndex(wallet);

    // The index is memory-only and must reconstruct exactly from persisted
    // wallet transactions rather than becoming a second source of truth.
    CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(wallet.GetDatabase()));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
    CheckLiveUnspentStakeIndex(reloaded);
    {
        LOCK(reloaded.cs_wallet);
        BOOST_CHECK(reloaded.GetLiveUnspentStakeOutpoints().count(COutPoint{funding->GetHash(), 0}));
    }
}

BOOST_AUTO_TEST_CASE(live_unspent_stake_index_is_bounded_by_live_outputs_not_history)
{
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);

    COutPoint previous{uint256{2}, 0};
    constexpr size_t HISTORY_LENGTH{512};
    for (size_t i = 0; i < HISTORY_LENGTH; ++i) {
        CMutableTransaction tx;
        tx.vin.emplace_back(previous);
        tx.vout.emplace_back((HISTORY_LENGTH - i + 1) * COIN, CScript{} << OP_TRUE);
        const CTransactionRef ref = MakeTransactionRef(std::move(tx));
        BOOST_REQUIRE(wallet.AddToWallet(ref, TxStateInMempool{}));
        previous = COutPoint{ref->GetHash(), 0};
    }

    CheckLiveUnspentStakeIndex(wallet);
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK_EQUAL(wallet.mapWallet.size(), HISTORY_LENGTH);
        BOOST_REQUIRE_EQUAL(wallet.GetLiveUnspentStakeOutpoints().size(), 1U);
        BOOST_CHECK(*wallet.GetLiveUnspentStakeOutpoints().begin() == previous);
    }
}

static void AddShadowWalletTestCoin(CCoinsViewCache& view, const COutPoint& outpoint, CAmount amount, const CScript& script)
{
    Coin coin;
    coin.out.nValue = amount;
    coin.out.scriptPubKey = script;
    coin.nHeight = 1;
    view.AddCoin(outpoint, std::move(coin), false);
}

static CTransactionRef MakeShadowWalletCoinbaseTx(const CScript& script)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.push_back(CTxOut(1 * COIN, script));
    return MakeTransactionRef(std::move(mtx));
}

static CTransactionRef MakeShadowWalletCoinstakeTx(const CScript& target)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256::ONE, 1}});
    mtx.vout.push_back(CTxOut(0, CScript{}));
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    return MakeTransactionRef(std::move(mtx));
}

static CTransactionRef MakeShadowWalletSignalTx(const CScript& target, const std::vector<unsigned char>& signal)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256{3}, 0}});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << signal));
    return MakeTransactionRef(std::move(mtx));
}

static CBlockUndo MakeShadowWalletUndo(const CBlock& block, const std::map<size_t, CScript>& input_scripts)
{
    CBlockUndo undo;
    if (block.vtx.empty()) return undo;
    undo.vtxundo.resize(block.vtx.size() - 1);
    for (const auto& [tx_index, script] : input_scripts) {
        if (tx_index == 0 || tx_index > undo.vtxundo.size()) continue;
        Coin coin;
        coin.out = CTxOut(10'000 * COIN, script);
        coin.nHeight = 1;
        coin.nTime = SHADOW_EQUAL_FOOTING_TIME;
        undo.vtxundo[tx_index - 1].vprevout.push_back(std::move(coin));
    }
    return undo;
}

BOOST_FIXTURE_TEST_CASE(loadwallet_reconciles_with_production_chain_snapshot, TestChain100Setup)
{
    uint256 active_block_hash;
    int active_block_height{-1};
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        const CBlockIndex* tip = Assert(m_node.chainman->ActiveChain().Tip());
        active_block_hash = tip->GetBlockHash();
        active_block_height = tip->nHeight;
    }

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);

    CMutableTransaction active_tx;
    active_tx.vin.emplace_back(COutPoint{uint256{11}, 0});
    active_tx.vout.emplace_back(COIN, CScript{} << OP_TRUE);
    const CTransactionRef active_ref = MakeTransactionRef(std::move(active_tx));
    BOOST_REQUIRE(wallet.AddToWallet(active_ref, TxStateConfirmed{active_block_hash, active_block_height, 0}));

    const uint256 inactive_block_hash{12};
    CMutableTransaction inactive_tx;
    inactive_tx.vin.emplace_back(COutPoint{uint256{13}, 0});
    inactive_tx.vout.emplace_back(COIN, CScript{} << OP_TRUE);
    const CTransactionRef inactive_ref = MakeTransactionRef(std::move(inactive_tx));
    BOOST_REQUIRE(wallet.AddToWallet(inactive_ref, TxStateConfirmed{inactive_block_hash, active_block_height, 0}));

    CWallet reloaded(m_node.chain.get(), "", DuplicateMockDatabase(wallet.GetDatabase()));
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
    {
        LOCK(reloaded.cs_wallet);
        const CWalletTx* reloaded_active = reloaded.GetWalletTx(active_ref->GetHash());
        BOOST_REQUIRE(reloaded_active);
        const auto* confirmed = reloaded_active->state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_hash, active_block_hash);
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_height, active_block_height);

        const CWalletTx* reloaded_inactive = reloaded.GetWalletTx(inactive_ref->GetHash());
        BOOST_REQUIRE(reloaded_inactive);
        BOOST_CHECK(reloaded_inactive->state<TxStateInactive>());
    }
}

BOOST_AUTO_TEST_CASE(rgb_wallet_record_deserialization_bounds)
{
    DataStream oversized_ticker{};
    WriteCompactSize(oversized_ticker, MAX_RGB_WALLET_TICKER_CHARS + 1);
    RGBContractRecord contract;
    BOOST_CHECK_EXCEPTION(oversized_ticker >> contract, std::ios_base::failure, HasReason("String length limit exceeded"));

    DataStream oversized_allocations{};
    WriteCompactSize(oversized_allocations, MAX_RGB_WALLET_RECORD_VECTOR_ENTRIES + 1);
    RGBGenesisProofRecord genesis_proof;
    BOOST_CHECK_EXCEPTION(oversized_allocations >> genesis_proof, std::ios_base::failure, HasReason("RGB wallet vector length limit exceeded"));

    DataStream oversized_inputs{};
    oversized_inputs << uint256::ONE << uint256::ONE << uint32_t{0} << int64_t{1} << true;
    WriteCompactSize(oversized_inputs, MAX_RGB_WALLET_RECORD_VECTOR_ENTRIES + 1);
    RGBTransitionRecord transition;
    BOOST_CHECK_EXCEPTION(oversized_inputs >> transition, std::ios_base::failure, HasReason("RGB wallet vector length limit exceeded"));
}

class ShadowScheduleScope
{
    const int m_whitelist_height{SHADOW_WHITELIST_HEIGHT};
    const int m_reward_start_height{SHADOW_REWARD_START_HEIGHT};
    const int m_gold_rush_blocks{SHADOW_GOLD_RUSH_BLOCKS};
    const int m_phase1_end_height{SHADOW_PHASE1_END_HEIGHT};
    const int m_reward_end_height{SHADOW_REWARD_END_HEIGHT};

public:
    ~ShadowScheduleScope()
    {
        SHADOW_WHITELIST_HEIGHT = m_whitelist_height;
        SHADOW_REWARD_START_HEIGHT = m_reward_start_height;
        SHADOW_GOLD_RUSH_BLOCKS = m_gold_rush_blocks;
        SHADOW_PHASE1_END_HEIGHT = m_phase1_end_height;
        SHADOW_REWARD_END_HEIGHT = m_reward_end_height;
    }
};

class MockTimeScope
{
public:
    ~MockTimeScope() { SetMockTime(0); }
};

BOOST_AUTO_TEST_CASE(shadow_solve_index_is_bounded_ordered_and_disconnect_safe)
{
    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    CKey key_a;
    CKey key_b;
    CKey key_c;
    key_a.MakeNewKey(true);
    key_b.MakeNewKey(true);
    key_c.MakeNewKey(true);
    AddKey(wallet, key_a);
    AddKey(wallet, key_b);
    AddKey(wallet, key_c);

    const CScript target_a = GetScriptForDestination(PKHash(key_a.GetPubKey()));
    const CScript target_b = GetScriptForDestination(PKHash(key_b.GetPubKey()));
    const CScript target_c = GetScriptForDestination(PKHash(key_c.GetPubKey()));

    auto add_funding = [&](const CScript& target, int height, uint64_t block_tag) {
        CMutableTransaction tx;
        tx.vin.resize(1);
        tx.vin[0].prevout.SetNull();
        tx.vout.emplace_back(10 * COIN, target);
        CTransactionRef ref = MakeTransactionRef(std::move(tx));
        BOOST_REQUIRE(wallet.AddToWallet(ref, TxStateConfirmed{uint256{static_cast<uint8_t>(block_tag)}, height, 0}));
        return ref;
    };
    auto add_solve = [&](const CTransactionRef& previous, uint32_t output_index, const CScript& target,
                         int height, uint64_t block_tag) {
        CMutableTransaction tx;
        tx.vin.emplace_back(COutPoint{previous->GetHash(), output_index});
        tx.vout.emplace_back(0, CScript{});
        tx.vout.emplace_back(10 * COIN, target);
        CTransactionRef ref = MakeTransactionRef(std::move(tx));
        BOOST_REQUIRE(wallet.AddToWallet(ref, TxStateConfirmed{uint256{static_cast<uint8_t>(block_tag)}, height, 1}));
        return ref;
    };

    const CTransactionRef funding_a = add_funding(target_a, 1, 1);
    const CTransactionRef funding_b = add_funding(target_b, 1, 2);
    const CTransactionRef funding_c = add_funding(target_c, 1, 3);
    const CTransactionRef solve_a_old = add_solve(funding_a, 0, target_a, 100, 100);
    const CTransactionRef solve_b = add_solve(funding_b, 0, target_b, 101, 101);
    const CTransactionRef solve_c = add_solve(funding_c, 0, target_c, 101, 102);
    const CTransactionRef solve_a_new = add_solve(solve_a_old, 1, target_a, 102, 103);

    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.GetOwnedLegacyShadowScripts(0).empty());
        BOOST_CHECK(wallet.GetRecentShadowSolveReferences(102, 0).empty());

        const auto newest = wallet.GetRecentShadowSolveReferences(102, 2);
        BOOST_REQUIRE_EQUAL(newest.size(), 2U);
        BOOST_CHECK_EQUAL(newest[0].solve_txid, solve_a_new->GetHash());
        BOOST_CHECK_EQUAL(newest[0].solve_height, 102U);
        BOOST_CHECK_EQUAL(newest[1].solve_height, 101U);

        const auto capped = wallet.GetRecentShadowSolveReferences(102, 1);
        BOOST_REQUIRE_EQUAL(capped.size(), 1U);
        BOOST_CHECK_EQUAL(capped[0].solve_txid, solve_a_new->GetHash());

        const auto at_101 = wallet.GetRecentShadowSolveReferences(101, 3);
        BOOST_REQUIRE_EQUAL(at_101.size(), 2U);
        BOOST_CHECK_EQUAL(at_101[0].solve_height, 101U);
        BOOST_CHECK_EQUAL(at_101[1].solve_height, 101U);
        BOOST_CHECK(at_101[1].target < at_101[0].target);
    }

    BOOST_REQUIRE(wallet.AddToWallet(solve_a_new, TxStateInactive{}));
    {
        LOCK(wallet.cs_wallet);
        const auto after_disconnect = wallet.GetRecentShadowSolveReferences(102, 3);
        BOOST_REQUIRE_EQUAL(after_disconnect.size(), 3U);
        BOOST_CHECK_EQUAL(after_disconnect[0].solve_height, 101U);
        BOOST_CHECK_EQUAL(after_disconnect[1].solve_height, 101U);
        BOOST_CHECK_EQUAL(after_disconnect[2].solve_txid, solve_a_old->GetHash());
    }

    BOOST_REQUIRE(wallet.AddToWallet(solve_a_new, TxStateConfirmed{uint256{103}, 102, 1}));
    {
        LOCK(wallet.cs_wallet);
        const auto after_reconnect = wallet.GetRecentShadowSolveReferences(102, 1);
        BOOST_REQUIRE_EQUAL(after_reconnect.size(), 1U);
        BOOST_CHECK_EQUAL(after_reconnect[0].solve_txid, solve_a_new->GetHash());
    }
}

BOOST_AUTO_TEST_CASE(goldrush_pow_miner_lifecycle_creates_quantum_payout)
{
    bilingual_str error;
    BOOST_REQUIRE(m_wallet.SetPowMining(/*enabled=*/true, /*threads=*/1, /*cpu_percent=*/10, error));
    BOOST_CHECK(m_wallet.m_pow_mining_enabled.load());
    std::string original_payout;
    {
        LOCK(m_wallet.cs_wallet);
        BOOST_CHECK(!m_wallet.m_pow_payout_quantum.empty());
        original_payout = m_wallet.m_pow_payout_quantum;
        const CTxDestination payout = DecodeDestination(m_wallet.m_pow_payout_quantum);
        BOOST_CHECK(IsValidDestination(payout));
        BOOST_CHECK(IsQuantumMigrationDestination(payout));
    }
    m_wallet.StopPowMining();
    BOOST_CHECK(!m_wallet.m_pow_mining_enabled.load());

    {
        LOCK(m_wallet.cs_wallet);
        m_wallet.m_pow_payout_quantum.clear();
    }
    BOOST_REQUIRE(m_wallet.EnsurePowPayoutAddress(error));
    {
        LOCK(m_wallet.cs_wallet);
        BOOST_CHECK_EQUAL(m_wallet.m_pow_payout_quantum, original_payout);
    }
}

BOOST_FIXTURE_TEST_CASE(scan_for_wallet_transactions, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    const CAmount block_subsidy{GetBlockSubsidy(newTip->nHeight, Params().GetConsensus(), /*fProofOfStake=*/false)};

    // Verify ScanForWalletTransactions fails to read an unknown start block.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/{}, /*start_height=*/0, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::FAILURE);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK(result.last_scanned_block.IsNull());
        BOOST_CHECK(!result.last_scanned_height);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    // Verify ScanForWalletTransactions picks up transactions in both the old
    // and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        std::chrono::steady_clock::time_point fake_time;
        reserver.setNow([&] { fake_time += 60s; return fake_time; });
        reserver.reserve();

        {
            CBlockLocator locator;
            BOOST_CHECK(!WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(locator.IsNull());
        }

        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/true);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 2 * block_subsidy);

        {
            CBlockLocator locator;
            BOOST_CHECK(WalletBatch{wallet.GetDatabase()}.ReadBestBlock(locator));
            BOOST_CHECK(!locator.IsNull());
        }
    }

    // Verify ScanForWalletTransactions succeeds without pruning and picks up
    // the coinbases in the old and new block files.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 2 * block_subsidy);
    }

    // Verify ScanForWalletTransactions can run without progress persistence.
    {
        CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet.cs_wallet);
            LOCK(Assert(m_node.chainman)->GetMutex());
            wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        AddKey(wallet, coinbaseKey);
        WalletRescanReserver reserver(wallet);
        reserver.reserve();
        CWallet::ScanResult result = wallet.ScanForWalletTransactions(/*start_block=*/oldTip->GetBlockHash(), /*start_height=*/oldTip->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
        BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
        BOOST_CHECK(result.last_failed_block.IsNull());
        BOOST_CHECK_EQUAL(result.last_scanned_block, newTip->GetBlockHash());
        BOOST_CHECK_EQUAL(*result.last_scanned_height, newTip->nHeight);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 2 * block_subsidy);
    }
}

BOOST_FIXTURE_TEST_CASE(goldrush_shadow_payouts_sync_on_connect_disconnect_and_rescan, TestChain100Setup)
{
    ShadowScheduleScope restore_shadow_schedule;
    MockTimeScope restore_mock_time;

    const CScript block_script = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
    CBlock first_real_block = CreateAndProcessBlock({}, block_script);
    CBlock reward_real_block = CreateAndProcessBlock({}, block_script);

    CBlockIndex* whitelist_index{nullptr};
    CBlockIndex* first_index{nullptr};
    CBlockIndex* reward_index{nullptr};
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        CChain& active_chain = m_node.chainman->ActiveChain();
        reward_index = active_chain.Tip();
        first_index = reward_index->pprev;
        whitelist_index = first_index->pprev;
        BOOST_REQUIRE(reward_index);
        BOOST_REQUIRE(first_index);
        BOOST_REQUIRE(whitelist_index);
        BOOST_CHECK_EQUAL(first_real_block.GetHash(), first_index->GetBlockHash());
        BOOST_CHECK_EQUAL(reward_real_block.GetHash(), reward_index->GetBlockHash());
    }
    SetShadowRegtestSchedule(whitelist_index->nHeight, 300);
    SetMockTime(reward_index->GetBlockTime());

    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);

    CTxDestination quantum_dest;
    CScript quantum_script;
    std::vector<unsigned char> quantum_public_key;
    CKeyingMaterial quantum_private_key;
    {
        LOCK(wallet.cs_wallet);
        auto op_dest = wallet.GetNewQuantumDestination("goldrush-shadow");
        BOOST_REQUIRE(op_dest);
        quantum_dest = *op_dest;
        quantum_script = GetScriptForDestination(quantum_dest);
        BOOST_CHECK(wallet.IsMine(quantum_dest) & ISMINE_SPENDABLE);
        const auto info = wallet.GetQuantumKeyInfo(quantum_dest);
        BOOST_REQUIRE(info.has_value());
        bilingual_str error;
        BOOST_REQUIRE(wallet.GetQuantumKey(info->witness_program, quantum_public_key, quantum_private_key, error));
        wallet.SetLastBlockProcessed(whitelist_index->nHeight, whitelist_index->GetBlockHash());
    }

    const CScript legacy_target = CScript{} << OP_TRUE;
    const COutPoint snapshot_coin_outpoint{uint256{42}, 0};
    CBlock first_shadow_block;
    CBlockUndo first_shadow_undo;
    CBlock reward_shadow_block;
    CBlockUndo reward_shadow_undo;
    CTransactionRef synthetic_payout_tx;
    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        CCoinsViewCache& coins_tip = m_node.chainman->ActiveChainstate().CoinsTip();
        AddShadowWalletTestCoin(coins_tip, snapshot_coin_outpoint, 10'000 * COIN, legacy_target);
        ApplyLegacyWhitelistSnapshot(coins_tip, whitelist_index);

        first_shadow_block.vtx.push_back(MakeShadowWalletCoinbaseTx(CScript{} << OP_2));
        first_shadow_block.vtx.push_back(MakeShadowWalletCoinstakeTx(legacy_target));
        first_shadow_undo = MakeShadowWalletUndo(first_shadow_block, {{1, legacy_target}});
        BOOST_REQUIRE(ApplyShadowBlock(coins_tip, first_shadow_block, first_index, &first_shadow_undo));
        BOOST_REQUIRE(AdvanceGoldRushInventoryTip(coins_tip, first_index));

        std::vector<unsigned char> signal;
        BOOST_REQUIRE(BuildShadowSignalData(legacy_target, quantum_script, first_index->nHeight, first_index->GetBlockHash(), signal));

        reward_shadow_block.vtx.push_back(MakeShadowWalletCoinbaseTx(CScript{} << OP_3));
        reward_shadow_block.vtx.push_back(MakeShadowWalletCoinstakeTx(legacy_target));
        reward_shadow_block.vtx.push_back(MakeShadowWalletSignalTx(legacy_target, signal));
        reward_shadow_undo = MakeShadowWalletUndo(reward_shadow_block, {{1, legacy_target}, {2, legacy_target}});
        BOOST_REQUIRE(ApplyShadowBlock(coins_tip, reward_shadow_block, reward_index, &reward_shadow_undo));
        BOOST_REQUIRE(AdvanceGoldRushInventoryTip(coins_tip, reward_index));

        const std::vector<CTransactionRef> payouts = GetAppliedShadowClaimPayoutTransactions(
            coins_tip, reward_index->nHeight, reward_index->GetBlockHash(), reward_index->GetBlockTime());
        BOOST_REQUIRE_EQUAL(payouts.size(), 1U);
        synthetic_payout_tx = payouts[0];
        BOOST_REQUIRE_EQUAL(synthetic_payout_tx->vout.size(), 1U);
        BOOST_CHECK_EQUAL(synthetic_payout_tx->vout[0].nValue, 580 * COIN);
        BOOST_CHECK(synthetic_payout_tx->vout[0].scriptPubKey == quantum_script);
    }

    uint256 reward_hash = reward_index->GetBlockHash();
    uint256 reward_prev_hash = first_index->GetBlockHash();
    interfaces::BlockInfo reward_block_info{reward_hash};
    reward_block_info.prev_hash = &reward_prev_hash;
    reward_block_info.height = reward_index->nHeight;
    reward_block_info.data = &reward_real_block;
    reward_block_info.chain_time_max = reward_index->GetBlockTimeMax();

    wallet.blockConnected(ChainstateRole::NORMAL, reward_block_info);
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.GetWalletTx(synthetic_payout_tx->GetHash());
        BOOST_REQUIRE(wtx);
        const auto* confirmed = wtx->state<TxStateConfirmed>();
        BOOST_REQUIRE(confirmed);
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_hash, reward_index->GetBlockHash());
        BOOST_CHECK_EQUAL(confirmed->confirmed_block_height, reward_index->nHeight);
        BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, *wtx, ISMINE_SPENDABLE), 580 * COIN);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx, ISMINE_SPENDABLE), 0);
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 580 * COIN);
        BOOST_CHECK_EQUAL(wtx->mapValue.at("comment"), "PoS - Quantum Stake");
        BOOST_CHECK_EQUAL(wtx->mapValue.at("to"), EncodeDestination(quantum_dest));
    }

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        CCoinsViewCache& coins_tip = m_node.chainman->ActiveChainstate().CoinsTip();
        BOOST_REQUIRE(UndoShadowBlock(coins_tip, reward_shadow_block, reward_index, &reward_shadow_undo));
        BOOST_REQUIRE(RewindGoldRushInventoryTip(coins_tip, reward_index));
    }
    wallet.blockDisconnected(reward_block_info);
    {
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx = wallet.GetWalletTx(synthetic_payout_tx->GetHash());
        BOOST_REQUIRE(wtx);
        BOOST_CHECK(wtx->isInactive());
        BOOST_CHECK_EQUAL(GetBalance(wallet).m_mine_immature, 0);
    }

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        CCoinsViewCache& coins_tip = m_node.chainman->ActiveChainstate().CoinsTip();
        BOOST_REQUIRE(ApplyShadowBlock(coins_tip, reward_shadow_block, reward_index, &reward_shadow_undo));
        BOOST_REQUIRE(AdvanceGoldRushInventoryTip(coins_tip, reward_index));
    }

    CWallet rescan_wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(rescan_wallet.LoadWallet(), DBErrors::LOAD_OK);
    {
        LOCK(rescan_wallet.cs_wallet);
        auto op_dest = rescan_wallet.AddQuantumKey(quantum_public_key, quantum_private_key, "goldrush-shadow", reward_index->GetBlockTime());
        BOOST_REQUIRE(op_dest);
        BOOST_CHECK(*op_dest == quantum_dest);
        rescan_wallet.SetLastBlockProcessed(reward_index->nHeight, reward_index->GetBlockHash());
    }
    WalletRescanReserver reserver(rescan_wallet);
    BOOST_REQUIRE(reserver.reserve());
    CWallet::ScanResult result = rescan_wallet.ScanForWalletTransactions(
        reward_index->GetBlockHash(), reward_index->nHeight, /*max_height=*/{}, reserver, /*fUpdate=*/false, /*save_progress=*/false);
    BOOST_CHECK_EQUAL(result.status, CWallet::ScanResult::SUCCESS);
    BOOST_CHECK_EQUAL(result.last_scanned_block, reward_index->GetBlockHash());
    BOOST_REQUIRE(result.last_scanned_height);
    BOOST_CHECK_EQUAL(*result.last_scanned_height, reward_index->nHeight);
    {
        LOCK(rescan_wallet.cs_wallet);
        const CWalletTx* wtx = rescan_wallet.GetWalletTx(synthetic_payout_tx->GetHash());
        BOOST_REQUIRE(wtx);
        BOOST_CHECK(wtx->state<TxStateConfirmed>() != nullptr);
        BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(rescan_wallet, *wtx, ISMINE_SPENDABLE), 580 * COIN);
        BOOST_CHECK_EQUAL(GetBalance(rescan_wallet).m_mine_immature, 580 * COIN);
        BOOST_CHECK_EQUAL(wtx->mapValue.at("comment"), "PoS - Quantum Stake");
        BOOST_CHECK_EQUAL(wtx->mapValue.at("to"), EncodeDestination(quantum_dest));
    }

    {
        LOCK(Assert(m_node.chainman)->GetMutex());
        CCoinsViewCache& coins_tip = m_node.chainman->ActiveChainstate().CoinsTip();
        BOOST_REQUIRE(UndoShadowBlock(coins_tip, reward_shadow_block, reward_index, &reward_shadow_undo));
        BOOST_REQUIRE(RewindGoldRushInventoryTip(coins_tip, reward_index));
        BOOST_REQUIRE(UndoShadowBlock(coins_tip, first_shadow_block, first_index, &first_shadow_undo));
        BOOST_REQUIRE(RewindGoldRushInventoryTip(coins_tip, first_index));
        UndoLegacyWhitelistSnapshot(coins_tip, whitelist_index);
        coins_tip.SpendCoin(snapshot_coin_outpoint);
    }
}

BOOST_FIXTURE_TEST_CASE(importmulti_rescan, TestChain100Setup)
{
    // Cap last block file size, and mine new block in a new block file.
    CBlockIndex* oldTip = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    WITH_LOCK(::cs_main, m_node.chainman->m_blockman.GetBlockFileInfo(oldTip->GetBlockPos().nFile)->nSize = MAX_BLOCKFILE_SIZE);
    CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    CBlockIndex* newTip = m_node.chainman->ActiveChain().Tip();

    // Blackcoin
    /*
    // Prune the older block file.
    int file_number;
    {
        LOCK(cs_main);
        file_number = oldTip->GetBlockPos().nFile;
        Assert(m_node.chainman)->m_blockman.PruneOneBlockFile(file_number);
    }
    m_node.chainman->m_blockman.UnlinkPrunedFiles({file_number});
    */

    // Verify importmulti RPC returns failure for a key whose creation time is
    // before the missing block, and success for a key whose creation time is
    // after.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        WITH_LOCK(wallet->cs_wallet, wallet->SetLastBlockProcessed(newTip->nHeight, newTip->GetBlockHash()));
        WalletContext context;
        context.args = &m_args;
        AddWallet(context, wallet);
        UniValue keys;
        keys.setArray();
        UniValue key;
        key.setObject();
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(coinbaseKey.GetPubKey())));
        key.pushKV("timestamp", 0);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        key.clear();
        key.setObject();
        CKey futureKey;
        futureKey.MakeNewKey(true);
        key.pushKV("scriptPubKey", HexStr(GetScriptForRawPubKey(futureKey.GetPubKey())));
        key.pushKV("timestamp", newTip->GetBlockTimeMax() + TIMESTAMP_WINDOW + 1);
        key.pushKV("internal", UniValue(true));
        keys.push_back(key);
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(keys);

        UniValue response = importmulti().HandleRequest(request);
        BOOST_CHECK_EQUAL(response.write(), "[{\"success\":true},{\"success\":true}]");
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }
}

// Verify importwallet RPC starts rescan at earliest block with timestamp
// greater or equal than key birthday. Previously there was a bug where
// importwallet RPC would start the scan at the latest block with timestamp less
// than or equal to key birthday.
BOOST_FIXTURE_TEST_CASE(importwallet_rescan, TestChain100Setup)
{
    // Create two blocks with same timestamp to verify that importwallet rescan
    // will pick up both blocks, not just the first.
    const int64_t BLOCK_TIME = WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip()->GetBlockTimeMax() + 5);
    SetMockTime(BLOCK_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    // Set key birthday to block time increased by the timestamp window, so
    // rescan will start at the block time.
    const int64_t KEY_TIME = BLOCK_TIME + TIMESTAMP_WINDOW;
    SetMockTime(KEY_TIME);
    m_coinbase_txns.emplace_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);

    std::string backup_file = fs::PathToString(m_args.GetDataDirNet() / "wallet.backup");

    // Import key into wallet and call dumpwallet to create backup file.
    {
        WalletContext context;
        context.args = &m_args;
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            auto spk_man = wallet->GetOrCreateLegacyScriptPubKeyMan();
            LOCK2(wallet->cs_wallet, spk_man->cs_KeyStore);
            spk_man->mapKeyMetadata[coinbaseKey.GetPubKey().GetID()].nCreateTime = KEY_TIME;
            spk_man->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        }
        AddWallet(context, wallet);
        {
            LOCK2(Assert(m_node.chainman)->GetMutex(), wallet->cs_wallet);
            wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);

        wallet::dumpwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);
    }

    // Call importwallet RPC and verify all blocks with timestamps >= BLOCK_TIME
    // were scanned, and no prior blocks were scanned.
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        {
            LOCK(wallet->cs_wallet);
            wallet->SetupLegacyScriptPubKeyMan();
        }

        WalletContext context;
        context.args = &m_args;
        JSONRPCRequest request;
        request.context = &context;
        request.params.setArray();
        request.params.push_back(backup_file);
        AddWallet(context, wallet);
        {
            LOCK2(Assert(m_node.chainman)->GetMutex(), wallet->cs_wallet);
            wallet->SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        }
        wallet::importwallet().HandleRequest(request);
        RemoveWallet(context, wallet, /* load_on_start= */ std::nullopt);

        BOOST_CHECK_EQUAL(m_coinbase_txns.size(), 103U);
        {
            LOCK(wallet->cs_wallet);
            BOOST_CHECK_EQUAL(wallet->mapWallet.size(), 3U);
            for (size_t i = 0; i < m_coinbase_txns.size(); ++i) {
                bool found = wallet->GetWalletTx(m_coinbase_txns[i]->GetHash());
                bool expected = i >= 100;
                BOOST_CHECK_EQUAL(found, expected);
            }
        }
    }
}

// Check that GetImmatureCredit() returns a newly calculated value instead of
// the cached value after a MarkDirty() call.
//
// This is a regression test written to verify a bugfix for the immature credit
// function. Similar tests probably should be written for the other credit and
// debit functions.
BOOST_FIXTURE_TEST_CASE(coin_mark_dirty_immature_credit, TestChain100Setup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());

    LOCK(wallet.cs_wallet);
    LOCK(Assert(m_node.chainman)->GetMutex());
    CWalletTx wtx{m_coinbase_txns.back(), TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/0}};
    wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet.SetupDescriptorScriptPubKeyMans();

    wallet.SetLastBlockProcessed(m_node.chainman->ActiveChain().Height(), m_node.chainman->ActiveChain().Tip()->GetBlockHash());

    // Call GetImmatureCredit() once before adding the key to the wallet to
    // cache the current immature credit amount, which is 0.
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), 0);

    // Invalidate the cached value, add the key, and make sure a new immature
    // credit amount is calculated.
    wtx.MarkDirty();
    AddKey(wallet, coinbaseKey);
    BOOST_CHECK_EQUAL(CachedTxGetImmatureCredit(wallet, wtx, ISMINE_SPENDABLE), wtx.tx->vout[0].nValue);
}

static int64_t AddTx(ChainstateManager& chainman, CWallet& wallet, uint32_t lockTime, int64_t mockTime, int64_t blockTime)
{
    CMutableTransaction tx;
    TxState state = TxStateInactive{};
    tx.nLockTime = lockTime;
    SetMockTime(mockTime);
    CBlockIndex* block = nullptr;
    if (blockTime > 0) {
        LOCK(cs_main);
        auto inserted = chainman.BlockIndex().emplace(std::piecewise_construct, std::make_tuple(GetRandHash()), std::make_tuple());
        assert(inserted.second);
        const uint256& hash = inserted.first->first;
        block = &inserted.first->second;
        block->nTime = blockTime;
        block->phashBlock = &hash;
        state = TxStateConfirmed{hash, block->nHeight, /*index=*/0};
    }
    const std::optional<WalletBlockTime> block_time = blockTime > 0
        ? std::make_optional(WalletBlockTime{blockTime, blockTime})
        : std::nullopt;
    return wallet.AddToWallet(MakeTransactionRef(tx), state, [&](CWalletTx& wtx, bool /* new_tx */) {
        // Assign wtx.m_state to simplify test and avoid the need to simulate
        // reorg events. Without this, AddToWallet asserts false when the same
        // transaction is confirmed in different blocks.
        wtx.m_state = state;
        return true;
    }, /*fFlushOnClose=*/true, /*rescanning_old_block=*/false, block_time)->nTimeSmart;
}

// Simple test to verify assignment of CWalletTx::nSmartTime value. Could be
// expanded to cover more corner cases of smart time logic.
BOOST_AUTO_TEST_CASE(ComputeTimeSmart)
{
    // New transaction should use clock time if lower than block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 100, 120), 100);

    // Test that updating existing transaction does not change smart time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 1, 200, 220), 100);

    // New transaction should use clock time if there's no block time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 2, 300, 0), 300);

    // New transaction should use block time if lower than clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 3, 420, 400), 400);

    // New transaction should use latest entry time if higher than
    // min(block time, clock time).
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 4, 500, 390), 400);

    // If there are future entries, new transaction should use time of the
    // newest entry that is no more than 300 seconds ahead of the clock time.
    BOOST_CHECK_EQUAL(AddTx(*m_node.chainman, m_wallet, 5, 50, 600), 300);
}

void TestLoadWallet(const std::string& name, DatabaseFormat format, std::function<void(std::shared_ptr<CWallet>)> f)
{
    node::NodeContext node;
    auto chain{interfaces::MakeChain(node)};
    DatabaseOptions options;
    options.require_format = format;
    DatabaseStatus status;
    bilingual_str error;
    std::vector<bilingual_str> warnings;
    auto database{MakeWalletDatabase(name, options, status, error)};
    auto wallet{std::make_shared<CWallet>(chain.get(), "", std::move(database))};
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    WITH_LOCK(wallet->cs_wallet, f(wallet));
}

BOOST_FIXTURE_TEST_CASE(LoadReceiveRequests, TestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("receive-requests-%i", format)};
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), true));
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(ScriptHash(), true));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "0", "val_rr00"));
            BOOST_CHECK(wallet->EraseAddressReceiveRequest(batch, PKHash(), "0"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr10"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, PKHash(), "1", "val_rr11"));
            BOOST_CHECK(wallet->SetAddressReceiveRequest(batch, ScriptHash(), "2", "val_rr20"));
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11", "val_rr20"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_CHECK(batch.WriteAddressPreviouslySpent(PKHash(), false));
            BOOST_CHECK(batch.EraseAddressData(ScriptHash()));
        });
        TestLoadWallet(name, format, [](std::shared_ptr<CWallet> wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet) {
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(PKHash()));
            BOOST_CHECK(!wallet->IsAddressPreviouslySpent(ScriptHash()));
            auto requests = wallet->GetAddressReceiveRequests();
            auto erequests = {"val_rr11"};
            BOOST_CHECK_EQUAL_COLLECTIONS(requests.begin(), requests.end(), std::begin(erequests), std::end(erequests));
        });
    }
}

static CMutableTransaction QuantumWalletSpendFixture(const CTxDestination& dest, std::map<COutPoint, Coin>& coins)
{
    BOOST_REQUIRE(IsQuantumMigrationDestination(dest));
    const CScript quantum_script = GetScriptForDestination(dest);

    CMutableTransaction funding_mut;
    funding_mut.nVersion = 2;
    funding_mut.vout.emplace_back(COIN, quantum_script);
    const CTransaction funding_tx{funding_mut};

    CMutableTransaction spend;
    spend.nVersion = 2;
    spend.vin.emplace_back(COutPoint{funding_tx.GetHash(), 0});
    spend.vout.emplace_back(COIN - 1000, quantum_script);
    coins.emplace(spend.vin[0].prevout, Coin{funding_tx.vout[0], 1, false, false, 0});
    return spend;
}

static void CheckQuantumWalletSigning(CWallet& wallet, const CTxDestination& dest)
{
    const CScript quantum_script = GetScriptForDestination(dest);
    {
        LOCK(wallet.cs_wallet);
        BOOST_CHECK(wallet.IsMine(quantum_script) & ISMINE_SPENDABLE);
    }

    std::map<COutPoint, Coin> coins;
    CMutableTransaction spend = QuantumWalletSpendFixture(dest, coins);
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(wallet.SignTransaction(spend, coins, SIGHASH_ALL, input_errors));
    BOOST_CHECK(input_errors.empty());
    BOOST_REQUIRE_EQUAL(spend.vin[0].scriptWitness.stack.size(), 2U);
    BOOST_CHECK_EQUAL(spend.vin[0].scriptWitness.stack[0].size(), ML_DSA::SIGNATURE_BYTES);
    BOOST_CHECK_EQUAL(spend.vin[0].scriptWitness.stack[1].size(), ML_DSA::PUBLICKEY_BYTES);
    BOOST_CHECK(spend.vin[0].scriptSig.empty());
}

static void CheckQuantumKeyChallenge(CWallet& wallet, const CTxDestination& dest) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    const auto info = wallet.GetQuantumKeyInfo(dest);
    BOOST_REQUIRE(info.has_value());
    std::vector<unsigned char> public_key;
    CKeyingMaterial private_key;
    bilingual_str error;
    BOOST_REQUIRE_MESSAGE(wallet.GetQuantumKey(info->witness_program, public_key, private_key, error), error.original);

    const uint256 challenge = GetRandHash();
    std::vector<unsigned char> private_key_bytes(private_key.begin(), private_key.end());
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(ML_DSA::Sign(private_key_bytes, challenge.begin(), uint256::size(), signature));
    memory_cleanse(private_key_bytes.data(), private_key_bytes.size());
    BOOST_CHECK(ML_DSA::Verify(public_key, challenge.begin(), uint256::size(), signature));
}

class QuantumWalletSigningTestingSetup : public TestChain100Setup
{
public:
    QuantumWalletSigningTestingSetup()
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

static std::shared_ptr<CWallet> TestLoadQuantumWallet(const std::string& name, DatabaseFormat format, interfaces::Chain* chain = nullptr)
{
    DatabaseOptions options;
    options.require_format = format;
    DatabaseStatus status;
    bilingual_str error;
    auto database{MakeWalletDatabase(name, options, status, error)};
    auto wallet{std::make_shared<CWallet>(chain, "", std::move(database))};
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    return wallet;
}

static std::shared_ptr<CWallet> TestLoadQuantumWalletBackup(const fs::path& path)
{
    // A wallet backup is a standalone data file. Load it from an isolated
    // wallet directory so SQLiteDataFile() does not append wallet.dat to the
    // backup filename and probe <backup>/wallet.dat.
    const fs::path scratch_dir{GetUniquePath(path.parent_path())};
    BOOST_REQUIRE(TryCreateDirectories(scratch_dir));
    fs::copy_file(path, scratch_dir / "wallet.dat", fs::copy_options::none);

    DatabaseOptions options;
    options.require_existing = true;
    options.verify = true;
    DatabaseStatus status;
    bilingual_str error;
    auto database{MakeDatabase(scratch_dir, options, status, error)};
    BOOST_REQUIRE_MESSAGE(database, error.original);
    auto wallet = std::shared_ptr<CWallet>{
        new CWallet(/*chain=*/nullptr, "restored-quantum-backup", std::move(database)),
        [scratch_dir](CWallet* wallet) {
            delete wallet;
            try {
                fs::remove_all(scratch_dir);
            } catch (const std::exception&) {
                // The fixture root is removed after the test. A cleanup
                // failure must not mask the backup verification result.
            }
        }};
    BOOST_REQUIRE_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    return wallet;
}

BOOST_FIXTURE_TEST_CASE(QuantumWalletKeysPersistAndSign, QuantumWalletSigningTestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("quantum-wallet-keys-%i", format)};
        CTxDestination dest;
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                auto op_dest = wallet->GetNewQuantumDestination("quantum");
                BOOST_REQUIRE(op_dest);
                dest = *op_dest;
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(!wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
                const auto info = wallet->GetQuantumKeyInfo(dest);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(!info->encrypted);
                BOOST_CHECK(info->durably_stored);
                BOOST_CHECK(!info->backup_verified);
            }
            CheckQuantumWalletSigning(*wallet, dest);
        }
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(wallet->IsMine(dest) & ISMINE_SPENDABLE);
                const auto info = wallet->GetQuantumKeyInfo(dest);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(!info->encrypted);
                BOOST_CHECK(info->durably_stored);
                BOOST_CHECK(!info->backup_verified);
            }
            CheckQuantumWalletSigning(*wallet, dest);
        }
    }
}

BOOST_AUTO_TEST_CASE(QuantumWalletKeyCreationIsAtomicAndDurable)
{
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> generated_private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, generated_private_key));
    const CKeyingMaterial private_key(generated_private_key.begin(), generated_private_key.end());

    // A transaction that cannot begin must not change either the live wallet
    // or the database image a restarted process would load.
    {
        CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        MockableDatabase& database = GetMockableDatabase(wallet);
        const MockableData initial_records = database.m_records;
        database.m_fail_begin = true;

        auto result = wallet.AddQuantumKey(public_key, private_key, "atomic-quantum", GetTime(), /*record_as_receive=*/true);
        BOOST_CHECK(!result);
        BOOST_CHECK(database.m_records == initial_records);
        {
            LOCK(wallet.cs_wallet);
            BOOST_CHECK(wallet.ListQuantumKeyInfos().empty());
            BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
        }

        CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(database));
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(reloaded.cs_wallet);
        BOOST_CHECK(reloaded.ListQuantumKeyInfos().empty());
    }

    // A receive key is one transaction containing the private key, initial
    // unverified-backup marker, wallet flags, address purpose, and label.
    // Fail each write in turn and prove neither memory nor a crash-style
    // reload can observe a partial key.
    for (size_t fail_write = 0; fail_write < 5; ++fail_write) {
        CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        MockableDatabase& database = GetMockableDatabase(wallet);
        const MockableData initial_records = database.m_records;
        database.m_fail_write_at = fail_write;

        auto result = wallet.AddQuantumKey(public_key, private_key, "atomic-quantum", GetTime(), /*record_as_receive=*/true);
        BOOST_CHECK(!result);
        BOOST_CHECK(database.m_last_txn_durable);
        BOOST_CHECK(database.m_records == initial_records);
        {
            LOCK(wallet.cs_wallet);
            BOOST_CHECK(wallet.ListQuantumKeyInfos().empty());
            BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
        }

        CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(database));
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(reloaded.cs_wallet);
        BOOST_CHECK(reloaded.ListQuantumKeyInfos().empty());
    }

    // An encrypted receive key has one additional database operation: write
    // the encrypted record, erase a possible plaintext record, then write the
    // backup marker, wallet flags, purpose, and label. Exercise every one of
    // those six boundaries while the wallet is normally unlocked.
    for (size_t fail_write = 0; fail_write < 6; ++fail_write) {
        CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        BOOST_REQUIRE(wallet.EncryptWallet("pass"));
        BOOST_REQUIRE(wallet.Unlock("pass"));

        MockableDatabase& database = GetMockableDatabase(wallet);
        const MockableData initial_records = database.m_records;
        database.m_fail_write_at = fail_write;

        auto result = wallet.AddQuantumKey(public_key, private_key, "atomic-encrypted-quantum", GetTime(), /*record_as_receive=*/true);
        BOOST_CHECK(!result);
        BOOST_CHECK(database.m_last_txn_durable);
        BOOST_CHECK(database.m_records == initial_records);
        {
            LOCK(wallet.cs_wallet);
            BOOST_CHECK(wallet.ListQuantumKeyInfos().empty());
            BOOST_CHECK(!wallet.IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
        }

        CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(database));
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
        BOOST_REQUIRE(reloaded.Unlock("pass"));
        LOCK(reloaded.cs_wallet);
        BOOST_CHECK(reloaded.ListQuantumKeyInfos().empty());
    }

    // A failed durable commit has the same all-or-nothing result.
    {
        CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        MockableDatabase& database = GetMockableDatabase(wallet);
        const MockableData initial_records = database.m_records;
        database.m_fail_commit = true;
        auto result = wallet.AddQuantumKey(public_key, private_key, "atomic-quantum", GetTime(), /*record_as_receive=*/true);
        BOOST_CHECK(!result);
        BOOST_CHECK(database.m_last_txn_durable);
        BOOST_CHECK(database.m_records == initial_records);

        CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(database));
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(reloaded.cs_wallet);
        BOOST_CHECK(reloaded.ListQuantumKeyInfos().empty());
    }

    // Once the durable commit reports success, a fresh process view recovers
    // the complete key and can sign. It remains conservatively unverified
    // until backupwallet reopens and challenges a produced backup.
    {
        CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
        MockableDatabase& database = GetMockableDatabase(wallet);
        auto result = wallet.AddQuantumKey(public_key, private_key, "atomic-quantum", GetTime(), /*record_as_receive=*/true);
        BOOST_REQUIRE(result);
        const CTxDestination destination = *result;
        BOOST_CHECK(database.m_last_txn_durable);

        CWallet reloaded(/*chain=*/nullptr, "", DuplicateMockDatabase(database));
        BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(), DBErrors::LOAD_OK);
        LOCK(reloaded.cs_wallet);
        const auto info = reloaded.GetQuantumKeyInfo(destination);
        BOOST_REQUIRE(info.has_value());
        BOOST_CHECK(info->durably_stored);
        BOOST_CHECK(!info->backup_verified);
        CheckQuantumKeyChallenge(reloaded, destination);
    }
}

BOOST_AUTO_TEST_CASE(QuantumWalletEncryptionUsesCheckedDurabilityBarrier)
{
    CWallet master_write_failure_wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(master_write_failure_wallet.LoadWallet(), DBErrors::LOAD_OK);
    auto master_write_failure_destination = master_write_failure_wallet.GetNewQuantumDestination("master-write-failure");
    BOOST_REQUIRE(master_write_failure_destination);
    MockableDatabase& master_write_failure_database = GetMockableDatabase(master_write_failure_wallet);
    master_write_failure_database.m_fail_write_at = 0;
    BOOST_CHECK(!master_write_failure_wallet.EncryptWallet("pass"));
    BOOST_CHECK(master_write_failure_database.m_last_txn_durable);
    BOOST_CHECK(!master_write_failure_wallet.IsCrypted());
    {
        LOCK(master_write_failure_wallet.cs_wallet);
        const auto info = master_write_failure_wallet.GetQuantumKeyInfo(*master_write_failure_destination);
        BOOST_REQUIRE(info.has_value());
        BOOST_CHECK(!info->encrypted);
        CheckQuantumKeyChallenge(master_write_failure_wallet, *master_write_failure_destination);
    }

    CWallet wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(), DBErrors::LOAD_OK);
    auto destination = wallet.GetNewQuantumDestination("durable-encryption");
    BOOST_REQUIRE(destination);

    MockableDatabase& database = GetMockableDatabase(wallet);
    database.m_last_txn_durable = false;
    BOOST_REQUIRE(wallet.EncryptWallet("pass"));
    BOOST_CHECK(database.m_last_txn_durable);

    CWallet rewrite_failure_wallet(/*chain=*/nullptr, "", CreateMockableWalletDatabase());
    BOOST_REQUIRE_EQUAL(rewrite_failure_wallet.LoadWallet(), DBErrors::LOAD_OK);
    auto rewrite_failure_destination = rewrite_failure_wallet.GetNewQuantumDestination("rewrite-failure");
    BOOST_REQUIRE(rewrite_failure_destination);
    MockableDatabase& rewrite_failure_database = GetMockableDatabase(rewrite_failure_wallet);
    rewrite_failure_database.m_last_txn_durable = false;
    rewrite_failure_database.m_fail_rewrite = true;
    BOOST_CHECK(!rewrite_failure_wallet.EncryptWallet("pass"));
    BOOST_CHECK(rewrite_failure_database.m_last_txn_durable);
    BOOST_CHECK(rewrite_failure_wallet.IsCrypted());
    BOOST_CHECK(rewrite_failure_wallet.IsLocked());
    LOCK(rewrite_failure_wallet.cs_wallet);
    const auto info = rewrite_failure_wallet.GetQuantumKeyInfo(*rewrite_failure_destination);
    BOOST_REQUIRE(info.has_value());
    BOOST_CHECK(info->encrypted);
}

BOOST_AUTO_TEST_CASE(QuantumWalletVerifiedBackupsAreCompleteAndRestorable)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("quantum-wallet-backup-%i", format)};
        const fs::path first_backup_dir = m_path_root / fs::PathFromString(strprintf("quantum-first-backup-%i", format));
        const fs::path current_backup_dir = m_path_root / fs::PathFromString(strprintf("quantum-current-backup-%i", format));
        BOOST_REQUIRE(fs::create_directory(first_backup_dir));
        BOOST_REQUIRE(fs::create_directory(current_backup_dir));

        CTxDestination first_destination;
        CTxDestination second_destination;
        CTxDestination third_destination;
        std::string wallet_filename;
        {
            auto wallet{TestLoadQuantumWallet(name, format)};
            wallet_filename = fs::PathToString(fs::PathFromString(wallet->GetDatabase().Filename()).filename());

            auto first = wallet->GetNewQuantumDestination("first-quantum");
            BOOST_REQUIRE(first);
            first_destination = *first;
            {
                LOCK(wallet->cs_wallet);
                const auto info = wallet->GetQuantumKeyInfo(first_destination);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(info->durably_stored);
                BOOST_CHECK(!info->backup_verified);
            }

            bilingual_str error;
            BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(first_backup_dir), &error), error.original);
            {
                LOCK(wallet->cs_wallet);
                const auto info = wallet->GetQuantumKeyInfo(first_destination);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(info->backup_verified);
            }

            // A later non-HD key is not covered by the earlier backup. The
            // older key stays verified; the new one fails closed until the
            // next complete backup is reopened and challenged.
            auto second = wallet->GetNewQuantumDestination("second-quantum");
            BOOST_REQUIRE(second);
            second_destination = *second;
            {
                LOCK(wallet->cs_wallet);
                const auto infos = wallet->ListQuantumKeyInfos();
                BOOST_REQUIRE_EQUAL(infos.size(), 2U);
                BOOST_CHECK_EQUAL(std::count_if(infos.begin(), infos.end(), [](const QuantumKeyInfo& info) { return info.backup_verified; }), 1);
            }

            error.clear();
            BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(current_backup_dir), &error), error.original);
            {
                LOCK(wallet->cs_wallet);
                const auto infos = wallet->ListQuantumKeyInfos();
                BOOST_REQUIRE_EQUAL(infos.size(), 2U);
                BOOST_CHECK(std::all_of(infos.begin(), infos.end(), [](const QuantumKeyInfo& info) {
                    return info.durably_stored && info.backup_verified;
                }));
            }

            // Every staged-copy boundary is fail-closed. In particular, no
            // injected failure may modify a pre-existing good destination;
            // only the final verified stage is ever atomically promoted.
            const fs::path current_backup_path = current_backup_dir / fs::PathFromString(wallet_filename);
            const std::array<std::string_view, 16> failpoints{{
                "before_first_copy",
                "fail_initial_file_commit",
                "fail_initial_file_close",
                "fail_initial_stage_directory_commit",
                "after_first_copy",
                "before_marker_prepare",
                "after_marker_prepare",
                "fail_marked_file_commit",
                "fail_marked_file_close",
                "fail_marked_stage_directory_commit",
                "after_marker_commit",
                "before_final_verify",
                "after_final_verify",
                "before_promote",
                "before_final_identity_revalidation",
                "fail_rename",
            }};
            for (const std::string_view injected : failpoints) {
                error.clear();
                BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(current_backup_dir), &error), error.original);
                const auto [before_ok, before] = ReadBinaryFile(current_backup_path);
                BOOST_REQUIRE(before_ok);

                wallet->m_quantum_backup_failpoint = [injected](std::string_view point) { return point == injected; };
                error.clear();
                BOOST_CHECK(!wallet->BackupWallet(fs::PathToString(current_backup_dir), &error));
                wallet->m_quantum_backup_failpoint = {};
                BOOST_CHECK(!error.empty());

                const auto [after_ok, after] = ReadBinaryFile(current_backup_path);
                BOOST_REQUIRE(after_ok);
                BOOST_CHECK_EQUAL_COLLECTIONS(before.begin(), before.end(), after.begin(), after.end());
                BOOST_CHECK_EQUAL(static_cast<size_t>(std::distance(fs::directory_iterator(current_backup_dir), fs::directory_iterator{})), 1U);
            }

            // The exact bytes challenged by the final reopen must be the bytes
            // atomically promoted. Even a same-process replacement inside the
            // otherwise private staging directory is detected by the immediate
            // identity revalidation and cannot modify a known-good destination.
            const auto [identity_before_ok, identity_before] = ReadBinaryFile(current_backup_path);
            BOOST_REQUIRE(identity_before_ok);
            bool tampered_stage{false};
            wallet->m_quantum_backup_failpoint = [&](std::string_view point) {
                if (point != "before_final_identity_revalidation") return false;
                for (const auto& entry : fs::directory_iterator(current_backup_dir)) {
                    const fs::path candidate{entry.path()};
                    const std::string name = fs::PathToString(candidate.filename());
                    if (!entry.is_directory() || name.rfind(".blackcoin-wallet-backup-stage-", 0) != 0) continue;
                    tampered_stage = WriteBinaryFile(candidate / "wallet.dat", "tampered after verification");
                    break;
                }
                return false;
            };
            error.clear();
            BOOST_CHECK(!wallet->BackupWallet(fs::PathToString(current_backup_dir), &error));
            wallet->m_quantum_backup_failpoint = {};
            BOOST_REQUIRE(tampered_stage);
            BOOST_CHECK(!error.empty());
            const auto [identity_after_ok, identity_after] = ReadBinaryFile(current_backup_path);
            BOOST_REQUIRE(identity_after_ok);
            BOOST_CHECK_EQUAL_COLLECTIONS(identity_before.begin(), identity_before.end(), identity_after.begin(), identity_after.end());
            BOOST_CHECK_EQUAL(static_cast<size_t>(std::distance(fs::directory_iterator(current_backup_dir), fs::directory_iterator{})), 1U);

            auto third = wallet->GetNewQuantumDestination("source-marker-failure");
            BOOST_REQUIRE(third);
            third_destination = *third;
            {
                LOCK(wallet->cs_wallet);
                const auto info = wallet->GetQuantumKeyInfo(third_destination);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(!info->backup_verified);
            }

            // Once the verified stage has been atomically installed, a
            // directory-sync failure cannot safely be rolled back. Report the
            // failure without deleting the complete destination. A source
            // marker failure is also reported after the independently verified
            // destination is installed, and that destination remains usable.
            for (const std::string_view injected : {
                     std::string_view{"before_final_directory_commit"},
                     std::string_view{"before_final_stage_directory_commit"},
                     std::string_view{"before_source_marker_commit"}}) {
                error.clear();
                wallet->m_quantum_backup_failpoint = [injected](std::string_view point) { return point == injected; };
                BOOST_CHECK(!wallet->BackupWallet(fs::PathToString(current_backup_dir), &error));
                wallet->m_quantum_backup_failpoint = {};
                BOOST_CHECK(!error.empty());
                BOOST_CHECK(fs::is_regular_file(current_backup_path));
                BOOST_CHECK_EQUAL(static_cast<size_t>(std::distance(fs::directory_iterator(current_backup_dir), fs::directory_iterator{})), 1U);
                {
                    auto restored{TestLoadQuantumWalletBackup(current_backup_path)};
                    LOCK(restored->cs_wallet);
                    const auto infos = restored->ListQuantumKeyInfos();
                    BOOST_REQUIRE_EQUAL(infos.size(), 3U);
                    BOOST_CHECK(std::all_of(infos.begin(), infos.end(), [](const QuantumKeyInfo& info) {
                        return info.durably_stored && info.backup_verified;
                    }));
                }
                {
                    LOCK(wallet->cs_wallet);
                    const auto info = wallet->GetQuantumKeyInfo(third_destination);
                    BOOST_REQUIRE(info.has_value());
                    BOOST_CHECK(!info->backup_verified);
                }
            }

            // Revalidate the exact installed bytes before recording source
            // markers. A same-user process can always alter an external file
            // later, but a replacement racing the promotion itself must fail
            // closed and leave a newly added source key unverified.
            bool tampered_destination{false};
            wallet->m_quantum_backup_failpoint = [&](std::string_view point) {
                if (point != "before_installed_identity_revalidation") return false;
                tampered_destination = WriteBinaryFile(current_backup_path, "tampered during promotion");
                return false;
            };
            error.clear();
            BOOST_CHECK(!wallet->BackupWallet(fs::PathToString(current_backup_dir), &error));
            wallet->m_quantum_backup_failpoint = {};
            BOOST_REQUIRE(tampered_destination);
            BOOST_CHECK(!error.empty());
            {
                LOCK(wallet->cs_wallet);
                const auto info = wallet->GetQuantumKeyInfo(third_destination);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(!info->backup_verified);
            }

            error.clear();
            BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(current_backup_dir), &error), error.original);
            {
                LOCK(wallet->cs_wallet);
                const auto info = wallet->GetQuantumKeyInfo(third_destination);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(info->backup_verified);
            }
        }

        const fs::path first_backup_path = first_backup_dir / fs::PathFromString(wallet_filename);
        const fs::path current_backup_path = current_backup_dir / fs::PathFromString(wallet_filename);
        BOOST_REQUIRE(fs::is_regular_file(first_backup_path));
        BOOST_REQUIRE(fs::is_regular_file(current_backup_path));

        {
            auto restored{TestLoadQuantumWalletBackup(first_backup_path)};
            LOCK(restored->cs_wallet);
            const auto infos = restored->ListQuantumKeyInfos();
            BOOST_REQUIRE_EQUAL(infos.size(), 1U);
            BOOST_CHECK(infos.front().durably_stored);
            BOOST_CHECK(infos.front().backup_verified);
            BOOST_CHECK(restored->GetQuantumKeyInfo(first_destination).has_value());
            BOOST_CHECK(!restored->GetQuantumKeyInfo(second_destination).has_value());
            CheckQuantumKeyChallenge(*restored, first_destination);
        }
        {
            auto restored{TestLoadQuantumWalletBackup(current_backup_path)};
            LOCK(restored->cs_wallet);
            const auto infos = restored->ListQuantumKeyInfos();
            BOOST_REQUIRE_EQUAL(infos.size(), 3U);
            BOOST_CHECK(std::all_of(infos.begin(), infos.end(), [](const QuantumKeyInfo& info) {
                return info.durably_stored && info.backup_verified;
            }));
            CheckQuantumKeyChallenge(*restored, first_destination);
            CheckQuantumKeyChallenge(*restored, second_destination);
            CheckQuantumKeyChallenge(*restored, third_destination);
        }
    }
}

BOOST_AUTO_TEST_CASE(QuantumWalletEncryptedBackupAndOldWalletCompatibility)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string encrypted_name{strprintf("quantum-wallet-encrypted-backup-%i", format)};
        const fs::path backup_path = m_path_root / fs::PathFromString(strprintf("quantum-encrypted-backup-%i.dat", format));
        CTxDestination destination;

        {
            auto wallet{TestLoadQuantumWallet(encrypted_name, format)};
            auto created = wallet->GetNewQuantumDestination("encrypted-backup");
            BOOST_REQUIRE(created);
            destination = *created;
            BOOST_REQUIRE(wallet->EncryptWallet("pass"));
            BOOST_REQUIRE(wallet->Unlock("pass"));

            bilingual_str error;
            BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(backup_path), &error), error.original);
            const auto [read_ok, known_good_backup] = ReadBinaryFile(backup_path);
            BOOST_REQUIRE(read_ok);

            BOOST_REQUIRE(wallet->Lock());
            error.clear();
            BOOST_CHECK(!wallet->BackupWallet(fs::PathToString(backup_path), &error));
            BOOST_CHECK_EQUAL(error.original, "Unlock this wallet before creating a verified quantum-key backup");
            const auto [failed_read_ok, after_failed_backup] = ReadBinaryFile(backup_path);
            BOOST_REQUIRE(failed_read_ok);
            BOOST_CHECK_EQUAL_COLLECTIONS(known_good_backup.begin(), known_good_backup.end(), after_failed_backup.begin(), after_failed_backup.end());

            BOOST_REQUIRE(wallet->Unlock("pass"));
            wallet->m_wallet_unlock_staking_only = true;
            auto blocked_creation = wallet->GetNewQuantumDestination("staking-only-must-not-create");
            BOOST_CHECK(!blocked_creation);
            error.clear();
            BOOST_REQUIRE_MESSAGE(wallet->BackupWallet(fs::PathToString(backup_path), &error), error.original);
            wallet->m_wallet_unlock_staking_only = false;
            BOOST_REQUIRE(wallet->Lock());
        }

        {
            auto restored{TestLoadQuantumWalletBackup(backup_path)};
            LOCK(restored->cs_wallet);
            const auto info = restored->GetQuantumKeyInfo(destination);
            BOOST_REQUIRE(info.has_value());
            BOOST_CHECK(info->encrypted);
            BOOST_CHECK(info->durably_stored);
            BOOST_CHECK(info->backup_verified);
            BOOST_CHECK(restored->IsLocked());
            BOOST_REQUIRE(restored->Unlock("pass"));
            CheckQuantumKeyChallenge(*restored, destination);
        }

        // A pre-v30.1.1 database has the key record but no per-key backup
        // marker. It must remain usable while loading conservatively as
        // unverified on both supported backends.
        const std::string old_name{strprintf("quantum-wallet-old-key-%i", format)};
        std::vector<uint8_t> public_key;
        std::vector<uint8_t> generated_private_key;
        BOOST_REQUIRE(ML_DSA::KeyGen(public_key, generated_private_key));
        const CKeyingMaterial private_key(generated_private_key.begin(), generated_private_key.end());
        const CTxDestination old_destination = WitnessUnknown{
            QUANTUM_MIGRATION_WITNESS_VERSION,
            QuantumMigrationProgramForPubkey(public_key)};
        {
            auto wallet{TestLoadQuantumWallet(old_name, format)};
            WalletBatch batch{wallet->GetDatabase()};
            BOOST_REQUIRE(batch.WriteQuantumKey(public_key, private_key, CKeyMetadata{GetTime()}));
        }
        {
            auto wallet{TestLoadQuantumWallet(old_name, format)};
            LOCK(wallet->cs_wallet);
            const auto info = wallet->GetQuantumKeyInfo(old_destination);
            BOOST_REQUIRE(info.has_value());
            BOOST_CHECK(info->durably_stored);
            BOOST_CHECK(!info->backup_verified);
            CheckQuantumKeyChallenge(*wallet, old_destination);
        }

        // The v30.1.0 compatibility path also applies to encrypted records.
        // Remove only the v30.1.1 per-key backup marker and prove the old key
        // still loads, unlocks, and signs while remaining conservatively
        // unverified.
        const std::string old_encrypted_name{strprintf("quantum-wallet-old-encrypted-key-%i", format)};
        CTxDestination old_encrypted_destination;
        std::vector<unsigned char> old_encrypted_program;
        {
            auto wallet{TestLoadQuantumWallet(old_encrypted_name, format)};
            auto created = wallet->GetNewQuantumDestination("old-encrypted-key");
            BOOST_REQUIRE(created);
            old_encrypted_destination = *created;
            const auto* witness = std::get_if<WitnessUnknown>(&old_encrypted_destination);
            BOOST_REQUIRE(witness);
            old_encrypted_program = witness->GetWitnessProgram();
            BOOST_REQUIRE(wallet->EncryptWallet("old-pass"));

            auto batch = wallet->GetDatabase().MakeBatch();
            BOOST_REQUIRE(batch->Erase(std::make_pair(DBKeys::QUANTUM_KEY_BACKUP_STATE, old_encrypted_program)));
        }
        {
            auto wallet{TestLoadQuantumWallet(old_encrypted_name, format)};
            LOCK(wallet->cs_wallet);
            const auto info = wallet->GetQuantumKeyInfo(old_encrypted_destination);
            BOOST_REQUIRE(info.has_value());
            BOOST_CHECK(info->encrypted);
            BOOST_CHECK(info->durably_stored);
            BOOST_CHECK(!info->backup_verified);
            BOOST_CHECK(wallet->IsLocked());
            BOOST_REQUIRE(wallet->Unlock("old-pass"));
            CheckQuantumKeyChallenge(*wallet, old_encrypted_destination);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(QuantumWalletInactiveSpendFailsBeforeSigning, WalletTestingSetup)
{
    CTxDestination dest;
    {
        LOCK(m_wallet.cs_wallet);
        auto op_dest = m_wallet.GetNewQuantumDestination("quantum-inactive");
        BOOST_REQUIRE(op_dest);
        dest = *op_dest;
    }

    std::map<COutPoint, Coin> coins;
    CMutableTransaction spend = QuantumWalletSpendFixture(dest, coins);
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!m_wallet.SignTransaction(spend, coins, SIGHASH_ALL, input_errors));
    BOOST_REQUIRE(input_errors.count(0));
    BOOST_CHECK_EQUAL(input_errors.at(0).original, "quantum-output-premature");
    BOOST_CHECK(spend.vin[0].scriptWitness.IsNull());
}

BOOST_FIXTURE_TEST_CASE(QuantumWalletChangeKeysPersistAndStayOffReceiveBook, QuantumWalletSigningTestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("quantum-wallet-change-keys-%i", format)};
        CTxDestination dest;
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                auto op_dest = wallet->GetNewQuantumChangeDestination();
                BOOST_REQUIRE(op_dest);
                dest = *op_dest;
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(wallet->IsMine(dest) & ISMINE_SPENDABLE);
                BOOST_CHECK(wallet->FindAddressBookEntry(dest) == nullptr);
            }
            CheckQuantumWalletSigning(*wallet, dest);
        }
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(wallet->IsMine(dest) & ISMINE_SPENDABLE);
                BOOST_CHECK(wallet->FindAddressBookEntry(dest) == nullptr);
            }
            CheckQuantumWalletSigning(*wallet, dest);
        }
    }
}

BOOST_AUTO_TEST_CASE(TieredQuantumStakeAliasesPersistAndListAfterReload)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("quantum-tiered-aliases-%i", format)};
        CTxDestination stake_dest;
        {
            auto wallet{TestLoadQuantumWallet(name, format)};
            LOCK(wallet->cs_wallet);
            auto op_dest = wallet->GetNewTieredQuantumDestination("quantum-stake", /*unbonding_blocks=*/9450);
            BOOST_REQUIRE(op_dest);
            stake_dest = *op_dest;
            const auto info = wallet->GetQuantumKeyInfo(stake_dest);
            BOOST_REQUIRE(info.has_value());
            BOOST_CHECK(wallet->FindAddressBookEntry(stake_dest) != nullptr);
        }
        {
            auto wallet{TestLoadQuantumWallet(name, format)};
            LOCK(wallet->cs_wallet);
            BOOST_CHECK(wallet->IsMine(stake_dest) & ISMINE_SPENDABLE);
            const auto info = wallet->GetQuantumKeyInfo(stake_dest);
            BOOST_REQUIRE(info.has_value());

            const std::vector<QuantumKeyInfo> infos = wallet->ListQuantumKeyInfos();
            const auto listed = std::find_if(infos.begin(), infos.end(), [&](const QuantumKeyInfo& listed_info) {
                return listed_info.destination == stake_dest;
            });
            BOOST_REQUIRE(listed != infos.end());
            const auto* entry = wallet->FindAddressBookEntry(listed->destination);
            BOOST_REQUIRE(entry);
            BOOST_CHECK_EQUAL(entry->GetLabel(), "quantum-stake");
            QuantumStakeTierProgram tier;
            BOOST_CHECK(DecodeQuantumStakeTierProgram(QUANTUM_MIGRATION_WITNESS_VERSION, listed->witness_program, tier));
            BOOST_CHECK(tier.IsBonded());
            BOOST_CHECK_EQUAL(tier.unbonding_blocks, 9450);
        }
    }
}

BOOST_FIXTURE_TEST_CASE(QuantumWalletKeysEncryptReloadAndSign, QuantumWalletSigningTestingSetup)
{
    for (DatabaseFormat format : DATABASE_FORMATS) {
        const std::string name{strprintf("quantum-wallet-encrypted-keys-%i", format)};
        CTxDestination dest;
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                auto op_dest = wallet->GetNewQuantumDestination("quantum-encrypted");
                BOOST_REQUIRE(op_dest);
                dest = *op_dest;
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(!wallet->IsWalletFlagSet(WALLET_FLAG_BLANK_WALLET));
            }
            BOOST_CHECK(wallet->EncryptWallet("pass"));
            LOCK(wallet->cs_wallet);
            BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
            BOOST_CHECK(wallet->IsLocked());
            BOOST_CHECK(wallet->IsMine(dest) & ISMINE_SPENDABLE);
            const auto info = wallet->GetQuantumKeyInfo(dest);
            BOOST_REQUIRE(info.has_value());
            BOOST_CHECK(info->encrypted);
        }
        {
            auto wallet{TestLoadQuantumWallet(name, format, m_node.chain.get())};
            {
                LOCK(wallet->cs_wallet);
                BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_QUANTUM_KEYS));
                BOOST_CHECK(wallet->IsLocked());
                BOOST_CHECK(wallet->IsMine(dest) & ISMINE_SPENDABLE);
                const auto info = wallet->GetQuantumKeyInfo(dest);
                BOOST_REQUIRE(info.has_value());
                BOOST_CHECK(info->encrypted);

                const auto* witness = std::get_if<WitnessUnknown>(&dest);
                BOOST_REQUIRE(witness != nullptr);
                std::vector<unsigned char> public_key;
                CKeyingMaterial private_key;
                bilingual_str error;
                BOOST_CHECK(!wallet->GetQuantumKey(witness->GetWitnessProgram(), public_key, private_key, error));
                BOOST_CHECK_EQUAL(error.original, "Wallet is locked");

                BOOST_CHECK(wallet->Unlock("pass"));
            }
            CheckQuantumWalletSigning(*wallet, dest);
            BOOST_CHECK(wallet->Lock());
        }
    }
}

// Test some watch-only LegacyScriptPubKeyMan methods by the procedure of loading (LoadWatchOnly),
// checking (HaveWatchOnly), getting (GetWatchPubKey) and removing (RemoveWatchOnly) a
// given PubKey, resp. its corresponding P2PK Script. Results of the impact on
// the address -> PubKey map is dependent on whether the PubKey is a point on the curve
static void TestWatchOnlyPubKey(LegacyScriptPubKeyMan* spk_man, const CPubKey& add_pubkey)
{
    CScript p2pk = GetScriptForRawPubKey(add_pubkey);
    CKeyID add_address = add_pubkey.GetID();
    CPubKey found_pubkey;
    LOCK(spk_man->cs_KeyStore);

    // all Scripts (i.e. also all PubKeys) are added to the general watch-only set
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));
    spk_man->LoadWatchOnly(p2pk);
    BOOST_CHECK(spk_man->HaveWatchOnly(p2pk));

    // only PubKeys on the curve shall be added to the watch-only address -> PubKey map
    bool is_pubkey_fully_valid = add_pubkey.IsFullyValid();
    if (is_pubkey_fully_valid) {
        BOOST_CHECK(spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey);
    } else {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == CPubKey()); // passed key is unchanged
    }

    spk_man->RemoveWatchOnly(p2pk);
    BOOST_CHECK(!spk_man->HaveWatchOnly(p2pk));

    if (is_pubkey_fully_valid) {
        BOOST_CHECK(!spk_man->GetWatchPubKey(add_address, found_pubkey));
        BOOST_CHECK(found_pubkey == add_pubkey); // passed key is unchanged
    }
}

// Cryptographically invalidate a PubKey whilst keeping length and first byte
static void PollutePubKey(CPubKey& pubkey)
{
    std::vector<unsigned char> pubkey_raw(pubkey.begin(), pubkey.end());
    std::fill(pubkey_raw.begin()+1, pubkey_raw.end(), 0);
    pubkey = CPubKey(pubkey_raw);
    assert(!pubkey.IsFullyValid());
    assert(pubkey.IsValid());
}

// Test watch-only logic for PubKeys
BOOST_AUTO_TEST_CASE(WatchOnlyPubKeys)
{
    CKey key;
    CPubKey pubkey;
    LegacyScriptPubKeyMan* spk_man = m_wallet.GetOrCreateLegacyScriptPubKeyMan();

    BOOST_CHECK(!spk_man->HaveWatchOnly());

    // uncompressed valid PubKey
    key.MakeNewKey(false);
    pubkey = key.GetPubKey();
    assert(!pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // uncompressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed valid PubKey
    key.MakeNewKey(true);
    pubkey = key.GetPubKey();
    assert(pubkey.IsCompressed());
    TestWatchOnlyPubKey(spk_man, pubkey);

    // compressed cryptographically invalid PubKey
    PollutePubKey(pubkey);
    TestWatchOnlyPubKey(spk_man, pubkey);

    // invalid empty PubKey
    pubkey = CPubKey();
    TestWatchOnlyPubKey(spk_man, pubkey);
}

class ListCoinsTestingSetup : public TestChain100Setup
{
public:
    explicit ListCoinsTestingSetup(const std::vector<const char*>& extra_args = {})
        : TestChain100Setup{ChainType::REGTEST, extra_args}
    {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
        wallet = CreateSyncedWallet(*m_node.chain, WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain()), coinbaseKey);
    }

    ~ListCoinsTestingSetup()
    {
        wallet.reset();
    }

    CWalletTx& AddTx(CRecipient recipient)
    {
        CTransactionRef tx;
        CCoinControl dummy;
        {
            constexpr int RANDOM_CHANGE_POSITION = -1;
            auto res = CreateTransaction(*wallet, {recipient}, RANDOM_CHANGE_POSITION, dummy);
            BOOST_REQUIRE_MESSAGE(res, util::ErrorString(res).original);
            tx = res->tx;
        }
        wallet->CommitTransaction(tx, {}, {});
        CMutableTransaction blocktx;
        {
            LOCK(wallet->cs_wallet);
            blocktx = CMutableTransaction(*wallet->mapWallet.at(tx->GetHash()).tx);
        }
        CreateAndProcessBlock({CMutableTransaction(blocktx)}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

        LOCK2(Assert(m_node.chainman)->GetMutex(), wallet->cs_wallet);
        wallet->SetLastBlockProcessed(wallet->GetLastBlockHeight() + 1, m_node.chainman->ActiveChain().Tip()->GetBlockHash());
        auto it = wallet->mapWallet.find(tx->GetHash());
        BOOST_CHECK(it != wallet->mapWallet.end());
        it->second.m_state = TxStateConfirmed{m_node.chainman->ActiveChain().Tip()->GetBlockHash(), m_node.chainman->ActiveChain().Height(), /*index=*/1};
        return it->second;
    }

    std::unique_ptr<CWallet> wallet;
};

class DemurrageAttestationTestingSetup : public ListCoinsTestingSetup
{
public:
    DemurrageAttestationTestingSetup()
        : ListCoinsTestingSetup{{
              "-shadowwhitelistheight=100",
              "-shadowgoldrushstartheight=101",
              "-shadowgoldrushendheight=101",
              "-qqgoldrushendheight=101",
              "-qqmigrationendheight=102",
          }}
    {
    }
};

BOOST_FIXTURE_TEST_CASE(DemurrageAttestationBuilderPreservesReplayAnchor, DemurrageAttestationTestingSetup)
{
    CTxDestination quantum_dest;
    std::vector<unsigned char> witness_program;
    {
        LOCK(wallet->cs_wallet);
        auto op_dest = wallet->GetNewQuantumDestination("b7-attestation");
        BOOST_REQUIRE(op_dest);
        quantum_dest = *op_dest;
        const auto info = wallet->GetQuantumKeyInfo(quantum_dest);
        BOOST_REQUIRE(info.has_value());
        witness_program = info->witness_program;
    }

    DemurrageAttestationTxResult tx_result;
    bilingual_str error;
    CCoinControl coin_control;
    BOOST_CHECK(!CreateDemurrageAttestationTransaction(
        *wallet, witness_program, coin_control, /*sign=*/true, tx_result, error));
    BOOST_CHECK_EQUAL(error.original, "Demurrage is not active for the next block");

    // Height 102 is the compressed test schedule's Migration boundary. Fund
    // two ordinary quantum outputs there: one becomes the attestation target,
    // and the other is a non-decaying quantum fee input after Final Lockout
    // begins at height 103.
    CMutableTransaction funding_tx;
    {
        const CScript quantum_script = GetScriptForDestination(quantum_dest);
        CCoinControl control;
        constexpr int RANDOM_CHANGE_POSITION = -1;
        auto funding = CreateTransaction(
            *wallet,
            {
                CRecipient{quantum_script, 2 * COIN, /*subtract_fee=*/false},
                CRecipient{quantum_script, COIN, /*subtract_fee=*/false},
            },
            RANDOM_CHANGE_POSITION, control, /*sign=*/true);
        BOOST_REQUIRE_MESSAGE(funding, util::ErrorString(funding).original);
        funding_tx = CMutableTransaction(*funding->tx);
    }
    CreateAndProcessBlock({funding_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    const CBlockIndex* funding_index = WITH_LOCK(
        Assert(m_node.chainman)->GetMutex(), return m_node.chainman->ActiveChain().Tip());
    BOOST_REQUIRE(funding_index);
    WalletRescanReserver reserver(*wallet);
    BOOST_REQUIRE(reserver.reserve());
    const CWallet::ScanResult scan = wallet->ScanForWalletTransactions(
        funding_index->GetBlockHash(), funding_index->nHeight,
        /*max_height=*/funding_index->nHeight, reserver,
        /*fUpdate=*/false, /*save_progress=*/false);
    BOOST_REQUIRE_EQUAL(scan.status, CWallet::ScanResult::SUCCESS);
    {
        LOCK2(Assert(m_node.chainman)->GetMutex(), wallet->cs_wallet);
        wallet->SetLastBlockProcessed(funding_index->nHeight, funding_index->GetBlockHash());
    }

    tx_result = {};
    error.clear();
    BOOST_REQUIRE_MESSAGE(CreateDemurrageAttestationTransaction(*wallet, witness_program, coin_control, /*sign=*/true, tx_result, error), error.original);
    BOOST_REQUIRE(tx_result.tx);
    BOOST_REQUIRE(!tx_result.tx->vin.empty());
    BOOST_CHECK_EQUAL(tx_result.replay_anchor.ToString(), tx_result.tx->vin.front().prevout.ToString());
    BOOST_REQUIRE_GE(tx_result.attestation_vout, 0);
    BOOST_REQUIRE_LT(static_cast<size_t>(tx_result.attestation_vout), tx_result.tx->vout.size());
    BOOST_CHECK_EQUAL(tx_result.tx->vout[tx_result.attestation_vout].nValue, 0);

    const std::vector<Consensus::DemurrageAttestation> attestations = Consensus::ExtractDemurrageAttestations(*tx_result.tx);
    BOOST_REQUIRE_EQUAL(attestations.size(), 1U);
    const Consensus::DemurrageAttestation& attestation = attestations.front();
    BOOST_CHECK_GE(attestation.height, 0);
    BOOST_CHECK_EQUAL(attestation.replay_anchor.ToString(), tx_result.replay_anchor.ToString());
    BOOST_CHECK_EQUAL(attestation.target_outpoint.ToString(), tx_result.target_outpoint.ToString());
    BOOST_CHECK_EQUAL_COLLECTIONS(attestation.pubkey.begin(), attestation.pubkey.end(), tx_result.public_key.begin(), tx_result.public_key.end());
    const uint256 message_hash = Consensus::DemurrageAttestationMessageHash(
        tx_result.replay_anchor, tx_result.target_outpoint,
        attestation.previous_height, attestation.previous_time,
        attestation.previous_coverage_start_height,
        attestation.previous_source,
        tx_result.public_key, Params().GetConsensus().nQuantumSighashChainId);
    BOOST_CHECK(ML_DSA::Verify(tx_result.public_key, message_hash.begin(), uint256::size(), attestation.signature));
}

BOOST_FIXTURE_TEST_CASE(ListCoinsTest, ListCoinsTestingSetup)
{
    std::string coinbaseAddress = coinbaseKey.GetPubKey().GetID().ToString();

    // Confirm ListCoins initially returns 1 coin grouped under coinbaseKey
    // address.
    std::map<CTxDestination, std::vector<COutput>> list;
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    CoinsResult initial_available = WITH_LOCK(::cs_main, return WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet)));
    const size_t initial_available_count = initial_available.Size();
    const CAmount initial_available_amount = initial_available.GetTotalAmount();

    BOOST_REQUIRE_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), initial_available_count);

    // Check initial balance from the fixture's mature coinbase transactions.
    BOOST_CHECK_EQUAL(initial_available_amount, WITH_LOCK(::cs_main, return WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet).GetTotalAmount())));

    // Add a transaction creating a change address, and confirm ListCoins still
    // returns the coin associated with the change address underneath the
    // coinbaseKey pubkey, even though the change address has a different
    // pubkey.
    AddTx(CRecipient{PubKeyDestination{{}}, 1 * COIN, /*subtract_fee=*/false});
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    const size_t post_tx_available_count = initial_available_count + 1;

    BOOST_REQUIRE_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), post_tx_available_count);

    // Lock both coins. Confirm number of available coins drops to 0.
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), post_tx_available_count);
    }
    for (const auto& group : list) {
        for (const auto& coin : group.second) {
            LOCK(wallet->cs_wallet);
            wallet->LockCoin(coin.outpoint);
        }
    }
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        BOOST_CHECK_EQUAL(AvailableCoinsListUnspent(*wallet).Size(), 0U);
    }
    // Confirm ListCoins still returns same result as before, despite coins
    // being locked.
    {
        LOCK2(::cs_main, wallet->cs_wallet);
        list = ListCoins(*wallet);
    }
    BOOST_REQUIRE_EQUAL(list.size(), 1U);
    BOOST_CHECK_EQUAL(std::get<PKHash>(list.begin()->first).ToString(), coinbaseAddress);
    BOOST_CHECK_EQUAL(list.begin()->second.size(), post_tx_available_count);
}

void TestCoinsResult(ListCoinsTest& context, OutputType out_type, CAmount amount)
{
    CTxDestination dest;
    {
        LOCK(context.wallet->cs_wallet);
        dest = *Assert(context.wallet->GetNewDestination(out_type, ""));
    }
    const CScript recipient_script = GetScriptForDestination(dest);
    CWalletTx& wtx = context.AddTx(CRecipient{dest, amount, /*fSubtractFeeFromAmount=*/true});
    LOCK2(::cs_main, context.wallet->cs_wallet);
    CoinFilterParams filter;
    filter.skip_locked = false;
    CoinsResult available_coins = AvailableCoins(*context.wallet, nullptr, std::nullopt, filter);
    bool found_recipient = false;
    for (const COutput& coin : available_coins.coins[out_type]) {
        if (coin.outpoint.hash == wtx.GetHash() && coin.txout.scriptPubKey == recipient_script) {
            found_recipient = true;
        }
    }
    BOOST_CHECK(found_recipient);
    // Lock outputs so they are not spent in follow-up transactions
    for (uint32_t i = 0; i < wtx.tx->vout.size(); i++) context.wallet->LockCoin({wtx.GetHash(), i});
}

BOOST_FIXTURE_TEST_CASE(BasicOutputTypesTest, ListCoinsTest)
{
    // The fixture's P2PK coinbase UTXOs should show up in the Other bucket.
    CoinsResult available_coins = WITH_LOCK(::cs_main, return WITH_LOCK(wallet->cs_wallet, return AvailableCoins(*wallet)));
    BOOST_CHECK_GT(available_coins.coins[OutputType::UNKNOWN].size(), 0U);

    // We will create a self transfer for each of the OutputTypes and
    // verify it is put in the correct bucket after running GetAvailablecoins
    //
    // For each OutputType, We expect 2 UTXOs in our wallet following the self transfer:
    //   1. One UTXO as the recipient
    //   2. One UTXO from the change, due to payment address matching logic

    for (const auto& out_type : OUTPUT_TYPES) {
        if (out_type == OutputType::UNKNOWN) continue;
        TestCoinsResult(*this, out_type, 1 * COIN);
    }
}

BOOST_FIXTURE_TEST_CASE(wallet_disableprivkeys, TestChain100Setup)
{
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        wallet->SetupLegacyScriptPubKeyMan();
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->TopUpKeyPool(1000));
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
    {
        const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        BOOST_CHECK(!wallet->GetNewDestination(OutputType::BECH32, ""));
    }
}

// Explicit calculation which is used to test the wallet constant
// We get the same virtual size due to rounding(weight/4) for both use_max_sig values
static size_t CalculateNestedKeyhashInputSize(bool use_max_sig)
{
    // Generate ephemeral valid pubkey
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();

    // Generate pubkey hash
    uint160 key_hash(Hash160(pubkey));

    // Create inner-script to enter into keystore. Key hash can't be 0...
    CScript inner_script = CScript() << OP_0 << std::vector<unsigned char>(key_hash.begin(), key_hash.end());

    // Create outer P2SH script for the output
    uint160 script_id(Hash160(inner_script));
    CScript script_pubkey = CScript() << OP_HASH160 << std::vector<unsigned char>(script_id.begin(), script_id.end()) << OP_EQUAL;

    // Add inner-script to key store and key to watchonly
    FillableSigningProvider keystore;
    keystore.AddCScript(inner_script);
    keystore.AddKeyPubKey(key, pubkey);

    // Fill in dummy signatures for fee calculation.
    SignatureData sig_data;

    if (!ProduceSignature(keystore, use_max_sig ? DUMMY_MAXIMUM_SIGNATURE_CREATOR : DUMMY_SIGNATURE_CREATOR, script_pubkey, sig_data)) {
        // We're hand-feeding it correct arguments; shouldn't happen
        assert(false);
    }

    CTxIn tx_in;
    UpdateInput(tx_in, sig_data);
    return (size_t)GetVirtualTransactionInputSize(tx_in);
}

BOOST_FIXTURE_TEST_CASE(dummy_input_size_test, TestChain100Setup)
{
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(false), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
    BOOST_CHECK_EQUAL(CalculateNestedKeyhashInputSize(true), DUMMY_NESTED_P2WPKH_INPUT_SIZE);
}

bool malformed_descriptor(std::ios_base::failure e)
{
    std::string s(e.what());
    return s.find("Missing checksum") != std::string::npos;
}

BOOST_FIXTURE_TEST_CASE(wallet_descriptor_test, BasicTestingSetup)
{
    std::vector<unsigned char> malformed_record;
    VectorWriter vw{0, malformed_record, 0};
    vw << std::string("notadescriptor");
    vw << uint64_t{0};
    vw << int32_t{0};
    vw << int32_t{0};
    vw << int32_t{1};

    SpanReader vr{malformed_record};
    WalletDescriptor w_desc;
    BOOST_CHECK_EXCEPTION(vr >> w_desc, std::ios_base::failure, malformed_descriptor);
}

//! Test CWallet::Create() and its behavior handling potential race
//! conditions if it's called the same time an incoming transaction shows up in
//! the mempool or a new block.
//!
//! It isn't possible to verify there aren't race condition in every case, so
//! this test just checks two specific cases and ensures that timing of
//! notifications in these cases doesn't prevent the wallet from detecting
//! transactions.
//!
//! In the first case, block and mempool transactions are created before the
//! wallet is loaded, but notifications about these transactions are delayed
//! until after it is loaded. The notifications are superfluous in this case, so
//! the test verifies the transactions are detected before they arrive.
//!
//! In the second case, block and mempool transactions are created after the
//! wallet rescan and notifications are immediately synced, to verify the wallet
//! must already have a handler in place for them, and there's no gap after
//! rescanning where new transactions in new blocks could be lost.
BOOST_FIXTURE_TEST_CASE(CreateWallet, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    // Create new wallet with known key and unload it.
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key;
    key.MakeNewKey(true);
    AddKey(*wallet, key);
    TestUnloadWallet(std::move(wallet));


    // Add log hook to detect AddToWallet events from rescans, blockConnected,
    // and transactionAddedToMempool notifications
    int addtx_count = 0;
    DebugLogHelper addtx_counter("[default wallet] AddToWallet", [&](const std::string* s) {
        if (s) ++addtx_count;
        return false;
    });


    bool rescan_completed = false;
    DebugLogHelper rescan_check("[default wallet] Rescan completed", [&](const std::string* s) {
        if (s) rescan_completed = true;
        return false;
    });


    // Block the queue to prevent the wallet receiving blockConnected and
    // transactionAddedToMempool notifications, and create block and mempool
    // transactions paying to the wallet
    std::promise<void> promise;
    CallFunctionInValidationInterfaceQueue([&promise] {
        promise.get_future().wait();
    });
    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto mempool_tx = TestSimpleSpend(*m_coinbase_txns[1], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));


    // Reload wallet and make sure new transactions are detected despite events
    // being blocked
    // Loading will also ask for current mempool transactions
    wallet = TestLoadWallet(context);
    BOOST_CHECK(rescan_completed);
    // AddToWallet events for block_tx and mempool_tx (x2)
    BOOST_CHECK_EQUAL(addtx_count, 3);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    // Unblock notification queue and make sure stale blockConnected and
    // transactionAddedToMempool events are processed
    promise.set_value();
    SyncWithValidationInterfaceQueue();
    // AddToWallet events for block_tx and mempool_tx events are counted a
    // second time as the notification queue is processed
    BOOST_CHECK_EQUAL(addtx_count, 5);


    TestUnloadWallet(std::move(wallet));


    // Load wallet again, this time creating new block and mempool transactions
    // paying to the wallet as the wallet finishes loading and syncing the
    // queue so the events have to be handled immediately. Releasing the wallet
    // lock during the sync is a little artificial but is needed to avoid a
    // deadlock during the sync and simulates a new block notification happening
    // as soon as possible.
    addtx_count = 0;
    auto handler = HandleLoadWallet(context, [&](std::unique_ptr<interfaces::Wallet> wallet) {
            BOOST_CHECK(rescan_completed);
            m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            block_tx = TestSimpleSpend(*m_coinbase_txns[2], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            m_coinbase_txns.push_back(CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
            mempool_tx = TestSimpleSpend(*m_coinbase_txns[3], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
            BOOST_CHECK(m_node.chain->broadcastTransaction(MakeTransactionRef(mempool_tx), DEFAULT_TRANSACTION_MAXFEE, false, error));
            SyncWithValidationInterfaceQueue();
        });
    wallet = TestLoadWallet(context);
    // Since mempool transactions are requested at the end of loading, there will
    // be 2 additional AddToWallet calls, one from the previous test, and a duplicate for mempool_tx
    BOOST_CHECK_EQUAL(addtx_count, 2 + 2);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_tx.GetHash()), 1U);
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(mempool_tx.GetHash()), 1U);
    }


    TestUnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(CreateWalletWithoutChain, BasicTestingSetup)
{
    WalletContext context;
    context.args = &m_args;
    auto wallet = TestLoadWallet(context);
    BOOST_CHECK(wallet);
    UnloadWallet(std::move(wallet));
}

BOOST_FIXTURE_TEST_CASE(ZapSelectTx, TestChain100Setup)
{
    m_args.ForceSetArg("-unsafesqlitesync", "1");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    auto wallet = TestLoadWallet(context);
    CKey key;
    key.MakeNewKey(true);
    AddKey(*wallet, key);

    std::string error;
    m_coinbase_txns.push_back(CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey())).vtx[0]);
    auto block_tx = TestSimpleSpend(*m_coinbase_txns[0], 0, coinbaseKey, GetScriptForRawPubKey(key.GetPubKey()));
    CreateAndProcessBlock({block_tx}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));

    SyncWithValidationInterfaceQueue();

    {
        auto block_hash = block_tx.GetHash();
        auto prev_tx = m_coinbase_txns[0];

        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 1u);

        std::vector<uint256> vHashIn{ block_hash }, vHashOut;
        BOOST_CHECK_EQUAL(wallet->ZapSelectTx(vHashIn, vHashOut), DBErrors::LOAD_OK);

        BOOST_CHECK(!wallet->HasWalletSpend(prev_tx));
        BOOST_CHECK_EQUAL(wallet->mapWallet.count(block_hash), 0u);
    }

    TestUnloadWallet(std::move(wallet));
}

/**
 * Checks a wallet invalid state where the inputs (prev-txs) of a new arriving transaction are not marked dirty,
 * while the transaction that spends them exist inside the in-memory wallet tx map (not stored on db due a db write failure).
 */
BOOST_FIXTURE_TEST_CASE(wallet_sync_tx_invalid_state_test, TestingSetup)
{
    CWallet wallet(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet.cs_wallet);
        wallet.SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet.SetupDescriptorScriptPubKeyMans();
    }

    // Add tx to wallet
    const auto op_dest{*Assert(wallet.GetNewDestination(OutputType::BECH32M, ""))};

    CMutableTransaction mtx;
    mtx.vout.emplace_back(COIN, GetScriptForDestination(op_dest));
    mtx.vin.emplace_back(g_insecure_rand_ctx.rand256(), 0);
    const auto& tx_id_to_spend = wallet.AddToWallet(MakeTransactionRef(mtx), TxStateInMempool{})->GetHash();

    {
        // Cache and verify available balance for the wtx
        LOCK(wallet.cs_wallet);
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 1 * COIN);
    }

    // Now the good case:
    // 1) Add a transaction that spends the previously created transaction
    // 2) Verify that the available balance of this new tx and the old one is updated (prev tx is marked dirty)

    mtx.vin.clear();
    mtx.vin.emplace_back(tx_id_to_spend, 0);
    wallet.transactionAddedToMempool(MakeTransactionRef(mtx));
    const uint256& good_tx_id = mtx.GetHash();

    {
        // Verify balance update for the new tx and the old one
        LOCK(wallet.cs_wallet);
        const CWalletTx* new_wtx = wallet.GetWalletTx(good_tx_id);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *new_wtx), 1 * COIN);

        // Now the old wtx
        const CWalletTx* wtx_to_spend = wallet.GetWalletTx(tx_id_to_spend);
        BOOST_CHECK_EQUAL(CachedTxGetAvailableCredit(wallet, *wtx_to_spend), 0 * COIN);
    }

    // Now the bad case:
    // 1) Make db always fail
    // 2) Try to add a transaction that spends the previously created transaction and
    //    verify that we are not moving forward if the wallet cannot store it
    GetMockableDatabase(wallet).m_pass = false;
    mtx.vin.clear();
    mtx.vin.emplace_back(good_tx_id, 0);
    BOOST_CHECK_EXCEPTION(wallet.transactionAddedToMempool(MakeTransactionRef(mtx)),
                          std::runtime_error,
                          HasReason("DB error adding transaction to wallet, write failed"));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
