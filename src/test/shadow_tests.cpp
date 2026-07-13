// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/common.h>
#include <chain.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <shadow.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <undo.h>
#include <util/strencodings.h>

#include <map>
#include <array>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shadow_tests, BasicTestingSetup)

namespace {

void AddCoinForScript(CCoinsViewCache& view, const COutPoint& outpoint, CAmount amount, const CScript& script)
{
    Coin coin;
    coin.out.nValue = amount;
    coin.out.scriptPubKey = script;
    coin.nHeight = 1;
    view.AddCoin(outpoint, std::move(coin), false);
}

std::vector<unsigned char> EncodePoolForTest(CAmount pow_amount, CAmount pos_amount, CAmount claimed_amount)
{
    std::vector<unsigned char> out(49);
    WriteLE64(out.data(), static_cast<uint64_t>(pow_amount));
    WriteLE64(out.data() + 8, static_cast<uint64_t>(pos_amount));
    WriteLE32(out.data() + 16, 0);
    WriteLE32(out.data() + 20, 0);
    WriteLE32(out.data() + 24, 0);
    WriteLE32(out.data() + 28, 0);
    out[32] = 0;
    WriteLE64(out.data() + 33, 0);
    WriteLE64(out.data() + 41, static_cast<uint64_t>(claimed_amount));
    return out;
}

COutPoint PoolOutpointForTest()
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Pool") << std::vector<unsigned char>{};
    return COutPoint{ss.GetHash(), 0};
}

void AddPoolForTest(CCoinsViewCache& view, const CBlockIndex& index, CAmount pow_amount, CAmount pos_amount, CAmount claimed_amount)
{
    static const std::vector<unsigned char> pool_tag{'Q', 'Q', 'P', 'O', 'O', 'L'};
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = CScript{} << OP_FALSE << OP_RETURN << pool_tag << EncodePoolForTest(pow_amount, pos_amount, claimed_amount);
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = index.nHeight;
    coin.nTime = index.GetBlockTime();
    view.AddCoin(PoolOutpointForTest(), std::move(coin), true);
}

void InitIndex(CBlockIndex& index, int height, CBlockIndex* prev, uint256& hash_storage)
{
    CBlockHeader header;
    header.nVersion = 7;
    header.hashPrevBlock = prev ? prev->GetBlockHash() : uint256{};
    header.nTime = 1713938400 + height * 64;
    header.nBits = 1;
    header.nNonce = height;
    hash_storage = header.GetHash();
    index.nVersion = header.nVersion;
    index.hashMerkleRoot = header.hashMerkleRoot;
    index.nTime = header.nTime;
    index.nBits = header.nBits;
    index.nNonce = header.nNonce;
    index.phashBlock = &hash_storage;
    index.pprev = prev;
    index.nHeight = height;
}

CTransactionRef MakeCoinbaseTx(const CScript& script)
{
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    mtx.vout.push_back(CTxOut(1 * COIN, script));
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakeCoinstakeTx(const CScript& target, const std::vector<unsigned char>& signal = {}, const std::vector<CTxOut>& extra_outputs = {})
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256::ONE, 1}});
    mtx.vout.push_back(CTxOut(0, CScript{}));
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    if (!signal.empty()) {
        mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << signal));
    }
    for (const CTxOut& out : extra_outputs) {
        mtx.vout.push_back(out);
    }
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakeSignalTx(const CScript& target, const std::vector<unsigned char>& signal, uint32_t input_n = 0)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256{3}, input_n}});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << signal));
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakePowClaimTx(const CScript& target, const std::vector<unsigned char>& proof, uint32_t input_n = 0)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256{2}, input_n}});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << proof));
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakePowClaimTxWithTwoProofs(const CScript& target,
                                            const std::vector<unsigned char>& first_proof,
                                            const std::vector<unsigned char>& second_proof,
                                            uint32_t input_n = 0)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256{2}, input_n}});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << first_proof));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << second_proof));
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakeBadProofTx(uint64_t index, const CScript& target, const std::vector<unsigned char>& proof)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{COutPoint{uint256::ONE, static_cast<uint32_t>(index + 100)}});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << proof));
    return MakeTransactionRef(std::move(mtx));
}

std::vector<unsigned char> MakeInvalidPowProofData(uint64_t nonce, const CScript& target, const CScript& payout_script)
{
    std::vector<unsigned char> proof = GetShadowPrefix();
    proof.insert(proof.end(), {'Q', 'Q', 'P', '2', 0});
    for (unsigned int i = 0; i < 8; ++i) {
        proof.push_back(static_cast<unsigned char>((nonce >> (8 * i)) & 0xff));
    }
    proof.push_back(static_cast<unsigned char>(target.size() & 0xff));
    proof.push_back(static_cast<unsigned char>((target.size() >> 8) & 0xff));
    proof.insert(proof.end(), target.begin(), target.end());
    proof.push_back(static_cast<unsigned char>(payout_script.size() & 0xff));
    proof.push_back(static_cast<unsigned char>((payout_script.size() >> 8) & 0xff));
    proof.insert(proof.end(), payout_script.begin(), payout_script.end());
    return proof;
}

CBlockUndo MakeUndoWithInputScripts(const CBlock& block, const std::map<size_t, CScript>& input_scripts)
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

void SetUndoInputValue(CBlockUndo& undo, size_t tx_index, CAmount value)
{
    if (tx_index == 0 || tx_index > undo.vtxundo.size() ||
        undo.vtxundo[tx_index - 1].vprevout.empty()) return;
    undo.vtxundo[tx_index - 1].vprevout.front().out.nValue = value;
}

struct ScanResult {
    uint32_t count{0};
    CAmount total{0};
};

ScanResult ScanSpendableCoins(const CCoinsViewCache& view, const CScript& script)
{
    ScanResult result;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
            coin.out.nValue > 0 && coin.out.scriptPubKey == script) {
            ++result.count;
            result.total += coin.out.nValue;
        }
        cursor->Next();
    }
    return result;
}

ScanResult ScanShadowClaimMarkers(const CCoinsViewCache& view, const CScript& script)
{
    ScanResult result;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        ShadowClaimMarkerInfo info;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
            DecodeShadowClaimMarker(coin.out, info) && info.target == script) {
            ++result.count;
            result.total += info.amount;
        }
        cursor->Next();
    }
    return result;
}



CScript QuantumScript(unsigned char tag)
{
    return GetScriptForDestination(WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, tag)});
}

CScript QuantumColdStakeScript(unsigned char tag)
{
    return GetScriptForDestination(WitnessUnknown{QUANTUM_COLDSTAKE_WITNESS_VERSION, std::vector<unsigned char>(QUANTUM_COLDSTAKE_PROGRAM_SIZE, tag)});
}

CScript TieredQuantumMigrationScript()
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumTieredProgramForCommitment(QUANTUM_TIERED_STATE_BONDED, /*unbonding_blocks=*/40500, /*unlock_height=*/0, uint256::ONE)});
}

bool ApplyShadowAndCheckpoint(CCoinsViewCache& view, const CBlock& block,
                              const CBlockIndex* pindex,
                              const CBlockUndo* blockundo = nullptr,
                              bool gold_rush_active = true)
{
    if (!::ApplyShadowBlock(view, block, pindex, blockundo, gold_rush_active)) return false;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT ||
        pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;
    return AdvanceGoldRushInventoryTip(view, pindex);
}

bool UndoShadowAndRewind(CCoinsViewCache& view, const CBlock& block,
                         const CBlockIndex* pindex,
                         const CBlockUndo* blockundo = nullptr,
                         bool gold_rush_active = true)
{
    if (!::UndoShadowBlock(view, block, pindex, blockundo, gold_rush_active)) return false;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT ||
        pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;
    return RewindGoldRushInventoryTip(view, pindex);
}

} // namespace

#define ApplyShadowBlock ApplyShadowAndCheckpoint
#define UndoShadowBlock UndoShadowAndRewind

BOOST_AUTO_TEST_CASE(legacy_whitelist_uses_aggregate_script_balance)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript split_eligible = CScript{} << OP_TRUE;
    const CScript split_below_threshold = CScript{} << OP_2;
    const CScript single_below_threshold = CScript{} << OP_3;
    const CScript unspendable = CScript{} << OP_RETURN << std::vector<unsigned char>{1};
    const CScript direct_quantum = QuantumScript(0x31);
    const CScript tiered_quantum = TieredQuantumMigrationScript();
    const CScript cold_stake = QuantumColdStakeScript(0x32);
    const CScript eutxo = GetScriptForEUTXO({0x33}, CScript{} << OP_TRUE);

    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 6'000 * COIN, split_eligible);
    AddCoinForScript(view, COutPoint{uint256::ONE, 1}, 5'000 * COIN, split_eligible);
    AddCoinForScript(view, COutPoint{uint256::ONE, 2}, 5'000 * COIN, split_below_threshold);
    AddCoinForScript(view, COutPoint{uint256::ONE, 3}, 4'999 * COIN, split_below_threshold);
    AddCoinForScript(view, COutPoint{uint256{2}, 0}, 9'999 * COIN, single_below_threshold);
    AddCoinForScript(view, COutPoint{uint256{2}, 1}, 20'000 * COIN, unspendable);
    AddCoinForScript(view, COutPoint{uint256{3}, 0}, 10'000 * COIN, direct_quantum);
    AddCoinForScript(view, COutPoint{uint256{3}, 1}, 10'000 * COIN, tiered_quantum);
    AddCoinForScript(view, COutPoint{uint256{3}, 2}, 10'000 * COIN, cold_stake);
    AddCoinForScript(view, COutPoint{uint256{3}, 3}, 10'000 * COIN, eutxo);

    const std::set<CScript> whitelist = BuildLegacyWhitelist(view);
    BOOST_CHECK_EQUAL(whitelist.size(), 1U);
    BOOST_CHECK(whitelist.count(split_eligible));
    BOOST_CHECK(!whitelist.count(split_below_threshold));
    BOOST_CHECK(!whitelist.count(single_below_threshold));
    BOOST_CHECK(!whitelist.count(unspendable));
    BOOST_CHECK(!whitelist.count(direct_quantum));
    BOOST_CHECK(!whitelist.count(tiered_quantum));
    BOOST_CHECK(!whitelist.count(cold_stake));
    BOOST_CHECK(!whitelist.count(eutxo));
}

BOOST_AUTO_TEST_CASE(whitelist_snapshot_markers_have_exact_authenticatable_provenance)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};
    const CScript eligible = CScript{} << OP_TRUE;
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, eligible);

    uint256 snapshot_hash;
    CBlockIndex snapshot_index;
    InitIndex(snapshot_index, SHADOW_WHITELIST_HEIGHT, nullptr, snapshot_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, &snapshot_index));
    BOOST_CHECK(IsWhitelisted(view, eligible));

    uint256 wrong_outpoint_hash;
    wrong_outpoint_hash.SetHex("0f423f");
    size_t authenticated_markers{0};
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        BOOST_REQUIRE(cursor->GetKey(outpoint));
        BOOST_REQUIRE(cursor->GetValue(coin));
        if (coin.out.nValue == 0 && IsShadowMarkerScript(coin.out.scriptPubKey)) {
            BOOST_CHECK(IsAuthenticatedShadowMarkerOutpoint(
                outpoint, coin, &snapshot_index));
            BOOST_CHECK(!IsAuthenticatedShadowMarkerOutpoint(
                COutPoint{wrong_outpoint_hash, outpoint.n}, coin, &snapshot_index));
            ++authenticated_markers;
        }
        cursor->Next();
    }
    // One member cache, one manifest, one manifest shard, and one ready marker.
    BOOST_CHECK_EQUAL(authenticated_markers, 4U);
}

BOOST_AUTO_TEST_CASE(legacy_whitelist_canonicalizes_p2pk_stake_outputs)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CPubKey pubkey{ParseHex("033d79776a0fbf7204f8c584c3e9acdc1b130473012d0c402f2145784c94e2d5b3")};
    const CScript p2pk = CScript{} << ToByteVector(pubkey) << OP_CHECKSIG;
    const CScript p2pkh = GetScriptForDestination(PKHash(pubkey));
    const CScript quantum_payout = QuantumScript(0x61);

    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 6'000 * COIN, p2pkh);
    AddCoinForScript(view, COutPoint{uint256::ONE, 1}, 4'000 * COIN, p2pk);

    const std::set<CScript> whitelist = BuildLegacyWhitelist(view);
    BOOST_REQUIRE_EQUAL(whitelist.size(), 1U);
    BOOST_CHECK(whitelist.count(p2pkh));
    BOOST_CHECK(!whitelist.count(p2pk));

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, p2pkh));
    BOOST_CHECK(IsWhitelisted(view, p2pk));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    first_block.vtx.push_back(MakeCoinstakeTx(p2pk));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, p2pk}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));
    const auto recent_activity = GetRecentShadowSolverActivityForScript(view, &first_index, p2pkh);
    BOOST_REQUIRE(recent_activity);
    BOOST_CHECK_EQUAL(recent_activity->height, static_cast<uint32_t>(first_index.nHeight));

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(p2pkh, quantum_payout, first_index.nHeight, first_index.GetBlockHash(), signal));

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, reward_hash);
    CBlock reward_block;
    reward_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    reward_block.vtx.push_back(MakeCoinstakeTx(p2pk));
    reward_block.vtx.push_back(MakeSignalTx(p2pkh, signal));
    CBlockUndo reward_undo = MakeUndoWithInputScripts(reward_block, {{1, p2pk}, {2, p2pk}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, reward_block, &reward_index, &reward_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], 580 * COIN);
}

BOOST_AUTO_TEST_CASE(goldrush_payouts_must_use_direct_quantum_addresses)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript legacy_target = CScript{} << OP_2;
    const CScript direct_payout = QuantumScript(0x72);
    const CScript tiered_payout = TieredQuantumMigrationScript();

    std::vector<unsigned char> signal;
    BOOST_CHECK(BuildShadowSignalData(legacy_target, direct_payout, prev_index.nHeight, prev_index.GetBlockHash(), signal));
    BOOST_CHECK(!BuildShadowSignalData(legacy_target, tiered_payout, prev_index.nHeight, prev_index.GetBlockHash(), signal));

    BOOST_CHECK(PrepareShadowPowWork(legacy_target, direct_payout, &prev_index, view).valid);
    BOOST_CHECK(!PrepareShadowPowWork(legacy_target, tiered_payout, &prev_index, view).valid);
}

BOOST_AUTO_TEST_CASE(legacy_whitelist_snapshot_undo_removes_markers)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript target = CScript{} << OP_TRUE;
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(HasLegacyWhitelistSnapshot(view));
    BOOST_CHECK(IsWhitelisted(view, target));

    UndoLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(!HasLegacyWhitelistSnapshot(view));
    BOOST_CHECK(!IsWhitelisted(view, target));
}

BOOST_AUTO_TEST_CASE(legacy_whitelist_snapshot_matches_replayed_builder)
{
    CCoinsView first_base;
    CCoinsViewCache first_view{&first_base, true};
    CCoinsView replay_base;
    CCoinsViewCache replay_view{&replay_base, true};

    const CPubKey pubkey{ParseHex("033d79776a0fbf7204f8c584c3e9acdc1b130473012d0c402f2145784c94e2d5b3")};
    const CScript p2pk = CScript{} << ToByteVector(pubkey) << OP_CHECKSIG;
    const CScript p2pkh = GetScriptForDestination(PKHash(pubkey));
    const CScript multisig = CScript{} << OP_1 << ToByteVector(pubkey) << OP_1 << OP_CHECKMULTISIG;
    const CScript below_threshold = CScript{} << OP_2;
    const CScript direct_quantum = QuantumScript(0x39);

    const std::vector<std::tuple<COutPoint, CAmount, CScript>> fixtures{
        {COutPoint{uint256::ONE, 0}, 5'500 * COIN, p2pkh},
        {COutPoint{uint256::ONE, 1}, 4'500 * COIN, p2pk},
        {COutPoint{uint256::ONE, 2}, 10'000 * COIN, multisig},
        {COutPoint{uint256::ONE, 3}, 9'999 * COIN, below_threshold},
        {COutPoint{uint256::ONE, 4}, 50'000 * COIN, direct_quantum},
    };
    for (const auto& [outpoint, amount, script] : fixtures) {
        AddCoinForScript(first_view, outpoint, amount, script);
        AddCoinForScript(replay_view, outpoint, amount, script);
    }

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_WHITELIST_HEIGHT, nullptr, first_hash);
    ApplyLegacyWhitelistSnapshot(first_view, &first_index);

    uint256 replay_hash;
    CBlockIndex replay_index;
    InitIndex(replay_index, SHADOW_WHITELIST_HEIGHT, nullptr, replay_hash);
    ApplyLegacyWhitelistSnapshot(replay_view, &replay_index);

    const std::set<CScript> expected = BuildLegacyWhitelist(replay_view);
    BOOST_CHECK_EQUAL(expected.size(), 2U);
    BOOST_CHECK(expected.count(p2pkh));
    BOOST_CHECK(expected.count(multisig));
    BOOST_CHECK(!expected.count(p2pk));
    BOOST_CHECK(!expected.count(below_threshold));
    BOOST_CHECK(!expected.count(direct_quantum));

    for (const CScript& script : expected) {
        BOOST_CHECK(IsWhitelisted(first_view, script));
        BOOST_CHECK(IsWhitelisted(replay_view, script));
    }
    BOOST_CHECK(IsWhitelisted(first_view, p2pk));
    BOOST_CHECK(IsWhitelisted(replay_view, p2pk));
    BOOST_CHECK_EQUAL(HasLegacyWhitelistSnapshot(first_view), HasLegacyWhitelistSnapshot(replay_view));
}

BOOST_AUTO_TEST_CASE(blackcoin_block_notice_matches_release_message)
{
    const std::string& notice = GetQuantumQuasarBlockNotice();
    const CScript script = BuildQuantumQuasarBlockNoticeScript();
    BOOST_CHECK_EQUAL(notice,
        "Quantum Quasar V30 Gold Rush is live. Upgrade now; the 18-month legacy migration begins after Gold Rush. Source: https://github.com/blackcoin-dev/blackcoin");

    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;
    BOOST_REQUIRE(script.GetOp(pc, opcode, data));
    BOOST_CHECK_EQUAL(opcode, OP_RETURN);
    BOOST_REQUIRE(script.GetOp(pc, opcode, data));
    BOOST_CHECK(std::string(data.begin(), data.end()) == notice);
    BOOST_CHECK(pc == script.end());
}


BOOST_AUTO_TEST_CASE(pos_shadow_signal_v2_records_fee_paying_quantum_ledger_credit)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript legacy_target = CScript{} << OP_TRUE;
    const CScript quantum_payout = QuantumScript(0x42);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, legacy_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, legacy_target));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    first_block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, legacy_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));
    const auto recent_activity = GetRecentShadowSolverActivity(view, &first_index);
    BOOST_REQUIRE(recent_activity.count(legacy_target));
    BOOST_CHECK_EQUAL(recent_activity.at(legacy_target).height, static_cast<uint32_t>(first_index.nHeight));

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(legacy_target, quantum_payout, first_index.nHeight, first_index.GetBlockHash(), signal));

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    block.vtx.push_back(MakeSignalTx(legacy_target, signal));
    CBlockUndo undo = MakeUndoWithInputScripts(block, {{1, legacy_target}, {2, legacy_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, block, &reward_index, &undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], 580 * COIN);

    BOOST_REQUIRE(ApplyShadowBlock(view, block, &reward_index, &undo));
    std::map<CScript, CAmount> applied_credits;
    CAmount applied_total{0};
    BOOST_REQUIRE(GetAppliedShadowDirectPayouts(view, &reward_index, applied_credits, applied_total));
    BOOST_CHECK_EQUAL(applied_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(applied_credits.size(), 1U);
    BOOST_CHECK_EQUAL(applied_credits[quantum_payout], 580 * COIN);

    const ScanResult pos_markers = ScanShadowClaimMarkers(view, quantum_payout);
    BOOST_CHECK_EQUAL(pos_markers.count, 1U);
    BOOST_CHECK_EQUAL(pos_markers.total, 580 * COIN);
    const ScanResult pos_spendable = ScanSpendableCoins(view, quantum_payout);
    BOOST_CHECK_EQUAL(pos_spendable.count, 1U);
    BOOST_CHECK_EQUAL(pos_spendable.total, 580 * COIN);
    const std::vector<CTransactionRef> synthetic_payouts =
        GetAppliedShadowClaimPayoutTransactions(view, reward_index.nHeight, reward_index.GetBlockHash(), reward_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(synthetic_payouts.size(), 1U);
    BOOST_REQUIRE_EQUAL(synthetic_payouts[0]->vout.size(), 1U);
    BOOST_CHECK_EQUAL(synthetic_payouts[0]->vout[0].nValue, 580 * COIN);
    BOOST_CHECK(synthetic_payouts[0]->vout[0].scriptPubKey == quantum_payout);
    Coin synthetic_coin;
    BOOST_CHECK(view.GetCoin(COutPoint{synthetic_payouts[0]->GetHash(), 0}, synthetic_coin));
    BOOST_CHECK_EQUAL(synthetic_coin.out.nValue, 580 * COIN);
    BOOST_CHECK(synthetic_coin.out.scriptPubKey == quantum_payout);
    const ShadowGoldRushInfo reward_info = GetShadowGoldRushInfo(view, &reward_index);
    BOOST_CHECK_EQUAL(reward_info.claimed_amount, 580 * COIN);

    BOOST_REQUIRE(UndoShadowBlock(view, block, &reward_index, &undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, quantum_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, quantum_payout).count, 0U);
    BOOST_REQUIRE(UndoShadowBlock(view, first_block, &first_index, &first_undo));
}

BOOST_AUTO_TEST_CASE(pos_shadow_below_threshold_solver_does_not_collect_goldrush_reward)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript whitelisted_target = CScript{} << OP_TRUE;
    const CScript below_threshold_target = CScript{} << OP_2;
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, whitelisted_target);
    AddCoinForScript(view, COutPoint{uint256::ONE, 1}, 9'999 * COIN, below_threshold_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, whitelisted_target));
    BOOST_CHECK(!IsWhitelisted(view, below_threshold_target));

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    block.vtx.push_back(MakeCoinstakeTx(below_threshold_target));
    CBlockUndo undo = MakeUndoWithInputScripts(block, {{1, below_threshold_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, block, &reward_index, &undo, direct_payouts, direct_total));
    BOOST_CHECK(direct_payouts.empty());
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_REQUIRE(ApplyShadowBlock(view, block, &reward_index, &undo));

    const auto recent_activity = GetRecentShadowSolverActivity(view, &reward_index);
    BOOST_CHECK(!recent_activity.count(below_threshold_target));
    const ShadowGoldRushInfo reward_info = GetShadowGoldRushInfo(view, &reward_index);
    BOOST_CHECK_EQUAL(reward_info.pos_count, 0U);
    BOOST_CHECK_EQUAL(reward_info.pos_amount, 290 * COIN);
    BOOST_CHECK_EQUAL(reward_info.claimed_amount, 0);

    BOOST_REQUIRE(UndoShadowBlock(view, block, &reward_index, &undo));
}

BOOST_AUTO_TEST_CASE(pos_shadow_signal_lookback_pays_without_per_block_signal_and_expires)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript legacy_target = CScript{} << OP_TRUE;
    const CScript quantum_payout = QuantumScript(0x55);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, legacy_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 solve_hash;
    CBlockIndex solve_index;
    InitIndex(solve_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, solve_hash);
    CBlock solve_block;
    solve_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    solve_block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    CBlockUndo solve_undo = MakeUndoWithInputScripts(solve_block, {{1, legacy_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, solve_block, &solve_index, &solve_undo));

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(legacy_target, quantum_payout, solve_index.nHeight, solve_index.GetBlockHash(), signal));

    uint256 signal_hash;
    CBlockIndex signal_index;
    InitIndex(signal_index, SHADOW_REWARD_START_HEIGHT + 1, &solve_index, signal_hash);
    CBlock signal_block;
    signal_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    signal_block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    signal_block.vtx.push_back(MakeSignalTx(legacy_target, signal));
    CBlockUndo signal_undo = MakeUndoWithInputScripts(signal_block, {{1, legacy_target}, {2, legacy_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, signal_block, &signal_index, &signal_undo));

    uint256 no_signal_hash;
    CBlockIndex no_signal_index;
    InitIndex(no_signal_index, SHADOW_REWARD_START_HEIGHT + 2, &signal_index, no_signal_hash);
    CBlock no_signal_block;
    no_signal_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    no_signal_block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    CBlockUndo no_signal_undo = MakeUndoWithInputScripts(no_signal_block, {{1, legacy_target}});

    std::map<CScript, CAmount> no_signal_payouts;
    CAmount no_signal_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, no_signal_block, &no_signal_index, &no_signal_undo, no_signal_payouts, no_signal_total));
    BOOST_CHECK_EQUAL(no_signal_total, 290 * COIN);
    BOOST_REQUIRE_EQUAL(no_signal_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(no_signal_payouts[quantum_payout], 290 * COIN);
    BOOST_REQUIRE(ApplyShadowBlock(view, no_signal_block, &no_signal_index, &no_signal_undo));

    uint256 expiry_hash;
    CBlockIndex expiry_index;
    InitIndex(expiry_index, signal_index.nHeight + SHADOW_SOLVER_ACTIVITY_WINDOW + 1, &no_signal_index, expiry_hash);
    CBlock expiry_block;
    expiry_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    expiry_block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    CBlockUndo expiry_undo = MakeUndoWithInputScripts(expiry_block, {{1, legacy_target}});
    std::map<CScript, CAmount> expired_payouts;
    CAmount expired_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, expiry_block, &expiry_index, &expiry_undo, expired_payouts, expired_total));
    BOOST_CHECK(expired_payouts.empty());
    BOOST_CHECK_EQUAL(expired_total, 0);

    BOOST_REQUIRE(UndoShadowBlock(view, no_signal_block, &no_signal_index, &no_signal_undo));
    BOOST_REQUIRE(UndoShadowBlock(view, signal_block, &signal_index, &signal_undo));

    uint256 rewound_hash;
    CBlockIndex rewound_index;
    InitIndex(rewound_index, SHADOW_REWARD_START_HEIGHT + 2, &solve_index, rewound_hash);
    std::map<CScript, CAmount> rewound_payouts;
    CAmount rewound_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, no_signal_block, &rewound_index, &no_signal_undo, rewound_payouts, rewound_total));
    BOOST_CHECK(rewound_payouts.empty());
    BOOST_CHECK_EQUAL(rewound_total, 0);

    BOOST_REQUIRE(UndoShadowBlock(view, solve_block, &solve_index, &solve_undo));
}

BOOST_AUTO_TEST_CASE(shadow_undo_inactive_gold_rush_epoch_is_noop)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript legacy_target = CScript{} << OP_TRUE;
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, legacy_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    block.vtx.push_back(MakeCoinstakeTx(legacy_target));
    CBlockUndo undo = MakeUndoWithInputScripts(block, {{1, legacy_target}});

    ShadowGoldRushInfo before = GetShadowGoldRushInfo(view, &whitelist_index);
    BOOST_REQUIRE(ApplyShadowBlock(view, block, &reward_index, &undo, /*gold_rush_active=*/false));
    ShadowGoldRushInfo after_apply = GetShadowGoldRushInfo(view, &reward_index);
    BOOST_CHECK_EQUAL(after_apply.pow_amount, before.pow_amount);
    BOOST_CHECK_EQUAL(after_apply.pos_amount, before.pos_amount);
    BOOST_CHECK_EQUAL(after_apply.claimed_amount, before.claimed_amount);

    BOOST_REQUIRE(UndoShadowBlock(view, block, &reward_index, &undo, /*gold_rush_active=*/false));
    ShadowGoldRushInfo after_undo = GetShadowGoldRushInfo(view, &reward_index);
    BOOST_CHECK_EQUAL(after_undo.pow_amount, before.pow_amount);
    BOOST_CHECK_EQUAL(after_undo.pos_amount, before.pos_amount);
    BOOST_CHECK_EQUAL(after_undo.claimed_amount, before.claimed_amount);
}

BOOST_AUTO_TEST_CASE(shadow_apply_active_epoch_ignores_blocks_outside_reward_height_window)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 seed_hash;
    CBlockIndex seed_index;
    InitIndex(seed_index, SHADOW_REWARD_START_HEIGHT, nullptr, seed_hash);
    AddPoolForTest(view, seed_index, 123 * COIN, 456 * COIN, 789 * COIN);

    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));

    uint256 before_hash;
    CBlockIndex before_index;
    InitIndex(before_index, SHADOW_REWARD_START_HEIGHT - 1, nullptr, before_hash);
    BOOST_REQUIRE(ApplyShadowBlock(view, block, &before_index, nullptr, /*gold_rush_active=*/true));
    ShadowGoldRushInfo before_info = GetShadowGoldRushInfo(view, &before_index);
    BOOST_CHECK_EQUAL(before_info.pow_amount, 123 * COIN);
    BOOST_CHECK_EQUAL(before_info.pos_amount, 456 * COIN);
    BOOST_CHECK_EQUAL(before_info.claimed_amount, 789 * COIN);

    uint256 after_hash;
    CBlockIndex after_index;
    InitIndex(after_index, SHADOW_REWARD_END_HEIGHT + 1, &before_index, after_hash);
    BOOST_REQUIRE(ApplyShadowBlock(view, block, &after_index, nullptr, /*gold_rush_active=*/true));
    ShadowGoldRushInfo after_info = GetShadowGoldRushInfo(view, &after_index);
    BOOST_CHECK_EQUAL(after_info.pow_amount, 123 * COIN);
    BOOST_CHECK_EQUAL(after_info.pos_amount, 456 * COIN);
    BOOST_CHECK_EQUAL(after_info.claimed_amount, 789 * COIN);
}

BOOST_AUTO_TEST_CASE(pos_shadow_excludes_quantum_coldstake_solver)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript cold_target = QuantumColdStakeScript(0x51);
    const CScript quantum_payout = QuantumScript(0x52);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, cold_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(!IsWhitelisted(view, cold_target));

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(cold_target, quantum_payout, 0, uint256{}, signal));

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));
    block.vtx.push_back(MakeCoinstakeTx(cold_target, signal));
    CBlockUndo undo = MakeUndoWithInputScripts(block, {{1, cold_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPosDirectPayouts(view, block, &reward_index, &undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_CHECK(direct_payouts.empty());
}


BOOST_AUTO_TEST_CASE(pow_shadow_claim_is_reachable_in_pos_era_and_uses_pow_bucket)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x43);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, pos_target));
    BOOST_CHECK(!IsWhitelisted(view, pow_target));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    first_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &first_index, view, 50'000, pow_proof));

    uint256 second_hash;
    CBlockIndex second_index;
    InitIndex(second_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, second_hash);
    CBlock second_block;
    second_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    second_block.vtx.push_back(MakeCoinstakeTx(pos_target, {}, {CTxOut(580 * COIN, quantum_payout)}));
    second_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    BOOST_REQUIRE(second_block.IsProofOfStake());
    CBlockUndo second_undo = MakeUndoWithInputScripts(second_block, {{1, pos_target}, {2, pow_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, second_block, &second_index, &second_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], 580 * COIN);

    BOOST_REQUIRE(ApplyShadowBlock(view, second_block, &second_index, &second_undo));
    BOOST_REQUIRE(UndoShadowBlock(view, second_block, &second_index, &second_undo));
}

BOOST_AUTO_TEST_CASE(pow_shadow_claim_records_ledger_credit_without_coinstake_payout)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x4b);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, pos_target));
    BOOST_CHECK(!IsWhitelisted(view, pow_target));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    first_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &first_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    BOOST_REQUIRE(claim_block.IsProofOfStake());
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, pos_target}, {2, pow_target}});

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));

    std::map<CScript, CAmount> applied_credits;
    CAmount applied_total{0};
    BOOST_REQUIRE(GetAppliedShadowDirectPayouts(view, &claim_index, applied_credits, applied_total));
    BOOST_CHECK_EQUAL(applied_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(applied_credits.size(), 1U);
    BOOST_CHECK_EQUAL(applied_credits[quantum_payout], applied_total);

    const ScanResult pow_markers = ScanShadowClaimMarkers(view, quantum_payout);
    BOOST_CHECK_EQUAL(pow_markers.count, 1U);
    BOOST_CHECK_EQUAL(pow_markers.total, 580 * COIN);
    const ScanResult pow_spendable = ScanSpendableCoins(view, quantum_payout);
    BOOST_CHECK_EQUAL(pow_spendable.count, 1U);
    BOOST_CHECK_EQUAL(pow_spendable.total, 580 * COIN);

    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.claimed_amount, 580 * COIN);
    BOOST_CHECK_EQUAL(info.pow_count, 1U);

    BOOST_REQUIRE(UndoShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, quantum_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, quantum_payout).count, 0U);
}

BOOST_AUTO_TEST_CASE(pow_shadow_claim_in_proof_of_work_block_is_legacy_visible_but_not_credited)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x4d);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    first_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &first_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    BOOST_REQUIRE(!claim_block.IsProofOfStake());
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, pow_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_CHECK(direct_payouts.empty());
    std::vector<ShadowPowClaimAccounting> pow_block_accounting;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, pow_block_accounting) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(pow_block_accounting.size(), 1U);
    BOOST_CHECK(pow_block_accounting.front().disposition ==
                ShadowPowClaimDisposition::INVALID_LOCATION);
    BOOST_CHECK_EQUAL(pow_block_accounting.front().credited_amount, 0);

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, quantum_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, quantum_payout).count, 0U);

    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 580 * COIN);
    BOOST_CHECK_EQUAL(info.pos_amount, 580 * COIN);
    BOOST_CHECK_EQUAL(info.claimed_amount, 0);
    BOOST_CHECK_EQUAL(info.pow_count, 0U);

    BOOST_REQUIRE(UndoShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, quantum_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, quantum_payout).count, 0U);
    const ShadowGoldRushInfo undo_info = GetShadowGoldRushInfo(view, &first_index);
    BOOST_CHECK_EQUAL(undo_info.pow_amount, 290 * COIN);
    BOOST_CHECK_EQUAL(undo_info.pos_amount, 290 * COIN);
    BOOST_CHECK_EQUAL(undo_info.claimed_amount, 0);
}

BOOST_AUTO_TEST_CASE(pow_shadow_mempool_policy_is_next_tip_bound_and_not_whitelist_gated)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript wrong_input = CScript{} << OP_3;
    const CScript quantum_payout = QuantumScript(0x4c);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);
    AddCoinForScript(view, COutPoint{uint256{2}, 0}, 1 * COIN, pow_target);
    AddCoinForScript(view, COutPoint{uint256{2}, 1}, 1 * COIN, wrong_input);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);
    BOOST_CHECK(IsWhitelisted(view, pos_target));
    BOOST_CHECK(!IsWhitelisted(view, pow_target));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    first_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo first_undo = MakeUndoWithInputScripts(first_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index, &first_undo));

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &first_index, view, 50'000, pow_proof));

    const CTransactionRef claim_tx = MakePowClaimTx(pow_target, pow_proof);
    std::string reject_reason;
    BOOST_CHECK(CheckShadowPowClaimForMempool(*claim_tx, &first_index, view, true, reject_reason));
    BOOST_CHECK(reject_reason.empty());

    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(*claim_tx, &first_index, view, true, reject_reason) ==
                ShadowProofValidationResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK_EQUAL(reject_reason, "local-shadow-proof-error");
    reject_reason.clear();
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(*claim_tx, &first_index, view, true, reject_reason) ==
                ShadowProofValidationResult::VALID);
    ClearShadowArgon2FailuresForTesting();
    BOOST_CHECK(reject_reason.empty());

    const CTransactionRef wrong_input_tx = MakePowClaimTx(pow_target, pow_proof, 1);
    BOOST_CHECK(!CheckShadowPowClaimForMempool(*wrong_input_tx, &first_index, view, true, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-input-mismatch");

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    claim_block.vtx.push_back(claim_tx);
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, pos_target}, {2, pow_target}});
    const ShadowGoldRushInfo before_fault = GetShadowGoldRushInfo(view, &first_index);
    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(ApplyShadowBlockResult(view, claim_block, &claim_index, &claim_undo) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    ClearShadowArgon2FailuresForTesting();
    const ShadowGoldRushInfo after_fault = GetShadowGoldRushInfo(view, &first_index);
    BOOST_CHECK_EQUAL(after_fault.pow_amount, before_fault.pow_amount);
    BOOST_CHECK_EQUAL(after_fault.pos_amount, before_fault.pos_amount);
    BOOST_CHECK_EQUAL(after_fault.claimed_amount, before_fault.claimed_amount);
    BOOST_CHECK_EQUAL(after_fault.pow_count, before_fault.pow_count);
    BOOST_CHECK_EQUAL(after_fault.pos_count, before_fault.pos_count);
    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));

    reject_reason.clear();
    BOOST_CHECK(!CheckShadowPowClaimForMempool(*claim_tx, &claim_index, view, true, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-invalid");
}

BOOST_AUTO_TEST_CASE(pow_shadow_claim_requires_legacy_input_named_by_proof)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript pow_target = CScript{} << OP_2;
    const CScript wrong_input = CScript{} << OP_3;
    const CScript quantum_payout = QuantumScript(0x44);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &prev_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5, {}, {CTxOut(580 * COIN, quantum_payout)}));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_5}, {2, wrong_input}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_CHECK(direct_payouts.empty());
}

BOOST_AUTO_TEST_CASE(pow_shadow_claim_binds_quantum_payout_to_proof_hash)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript pow_target = CScript{} << OP_2;
    const CScript honest_payout = QuantumScript(0x45);
    const CScript attacker_payout = QuantumScript(0x46);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, honest_payout, &prev_index, view, 50'000, pow_proof));
    BOOST_REQUIRE(pow_proof.size() >= attacker_payout.size());
    std::copy(attacker_payout.begin(), attacker_payout.end(), pow_proof.end() - attacker_payout.size());

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5, {}, {CTxOut(580 * COIN, attacker_payout)}));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_5}, {2, pow_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_CHECK(direct_payouts.empty());
}

BOOST_AUTO_TEST_CASE(pow_shadow_canonical_claim_reimburses_valid_loser_without_inflation)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x47);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &prev_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5, {}, {CTxOut(580 * COIN, quantum_payout)}));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof, 0));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof, 1));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_5}, {2, pow_target}, {3, pow_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_CHECK(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], 580 * COIN);
    std::vector<ShadowPowClaimAccounting> accounting;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, accounting) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 2U);
    const auto winner = std::find_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        });
    const auto loser = std::find_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::REIMBURSED_LOSER;
        });
    BOOST_REQUIRE(winner != accounting.end());
    BOOST_REQUIRE(loser != accounting.end());
    BOOST_CHECK(winner->base_fee_known);
    BOOST_CHECK(loser->base_fee_known);
    BOOST_CHECK_EQUAL(winner->credited_amount, 580 * COIN - CENT);
    BOOST_CHECK_EQUAL(loser->credited_amount, CENT);
    BOOST_CHECK(winner->source_txid != loser->source_txid);
    BOOST_CHECK(winner->canonical_rank < loser->canonical_rank);
    BOOST_CHECK(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 2U);
    std::array<CAmount, 2> amounts{payouts[0].txout.nValue, payouts[1].txout.nValue};
    std::sort(amounts.begin(), amounts.end());
    BOOST_CHECK_EQUAL(amounts[0], CENT);
    BOOST_CHECK_EQUAL(amounts[1], 580 * COIN - CENT);
    BOOST_CHECK_EQUAL(amounts[0] + amounts[1], 580 * COIN);
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.pow_count, 1U);
}

BOOST_AUTO_TEST_CASE(pow_shadow_canonical_winner_is_order_independent_and_replay_safe)
{
    CCoinsView base;
    const CScript staker_target = CScript{} << OP_TRUE;
    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    CCoinsViewCache seed_view{&base, true};
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(seed_view, &whitelist_index));
    BOOST_REQUIRE(ApplyShadowBlock(seed_view, prev_block, &prev_index));

    CCoinsViewCache view{&seed_view, true};
    const CScript target_a = CScript{} << OP_2;
    const CScript target_b = CScript{} << OP_3;
    const CScript payout_a = QuantumScript(0x75);
    const CScript payout_b = QuantumScript(0x76);
    std::vector<unsigned char> proof_a;
    std::vector<unsigned char> proof_b;
    BOOST_REQUIRE(MineShadowProofData(target_a, payout_a, &prev_index, view, 100'000, proof_a));
    BOOST_REQUIRE(MineShadowProofData(target_b, payout_b, &prev_index, view, 100'000, proof_b));

    const CTransactionRef tx_a = MakePowClaimTx(target_a, proof_a, 0);
    const CTransactionRef tx_b = MakePowClaimTx(target_b, proof_b, 1);
    const CAmount actual_fee = CENT / 2;

    uint256 claim_hash_a;
    CBlockIndex claim_index_a;
    InitIndex(claim_index_a, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash_a);
    CBlock block_a;
    block_a.vtx = {MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target), tx_a, tx_b};
    CBlockUndo undo_a = MakeUndoWithInputScripts(
        block_a, {{1, staker_target}, {2, target_a}, {3, target_b}});
    SetUndoInputValue(undo_a, 2, COIN + actual_fee);
    SetUndoInputValue(undo_a, 3, COIN + actual_fee);

    uint256 claim_hash_b;
    CBlockIndex claim_index_b;
    InitIndex(claim_index_b, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash_b);
    claim_hash_b.SetHex("0f1206");
    CBlock block_b;
    block_b.vtx = {MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target), tx_b, tx_a};
    CBlockUndo undo_b = MakeUndoWithInputScripts(
        block_b, {{1, staker_target}, {2, target_b}, {3, target_a}});
    SetUndoInputValue(undo_b, 2, COIN + actual_fee);
    SetUndoInputValue(undo_b, 3, COIN + actual_fee);

    std::map<CScript, CAmount> payouts_a;
    std::map<CScript, CAmount> payouts_b;
    CAmount total_a{0};
    CAmount total_b{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, block_a, &claim_index_a, &undo_a,
                                            payouts_a, total_a));
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, block_b, &claim_index_b, &undo_b,
                                            payouts_b, total_b));
    BOOST_CHECK(payouts_a == payouts_b);
    BOOST_CHECK_EQUAL(total_a, 580 * COIN);
    BOOST_CHECK_EQUAL(total_b, total_a);
    BOOST_REQUIRE_EQUAL(payouts_a.size(), 2U);
    std::array<CAmount, 2> ordered_amounts{payouts_a[payout_a], payouts_a[payout_b]};
    std::sort(ordered_amounts.begin(), ordered_amounts.end());
    BOOST_CHECK_EQUAL(ordered_amounts[0], actual_fee);
    BOOST_CHECK_EQUAL(ordered_amounts[1], 580 * COIN - actual_fee);

    std::vector<ShadowPowClaimAccounting> accounting_a;
    std::vector<ShadowPowClaimAccounting> accounting_b;
    ShadowPowAccountingContext context_a;
    BOOST_REQUIRE(PrepareShadowPowClaimAccounting(view, &claim_index_a,
                                                  context_a) ==
                  ShadowPowAccountingResult::OK);
    BOOST_CHECK(context_a.valid);
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(context_a, block_a, &undo_a,
                                                   accounting_a) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, block_b, &claim_index_b, &undo_b,
                                              accounting_b) == ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting_a.size(), 2U);
    BOOST_REQUIRE_EQUAL(accounting_b.size(), 2U);
    for (size_t i = 0; i < accounting_a.size(); ++i) {
        BOOST_CHECK(accounting_a[i].source_txid == accounting_b[i].source_txid);
        BOOST_CHECK(accounting_a[i].canonical_rank == accounting_b[i].canonical_rank);
        BOOST_CHECK(accounting_a[i].disposition == accounting_b[i].disposition);
        BOOST_CHECK_EQUAL(accounting_a[i].base_fee, actual_fee);
        BOOST_CHECK_EQUAL(accounting_a[i].credited_amount, accounting_b[i].credited_amount);
    }

    BOOST_REQUIRE(ApplyShadowBlock(view, block_a, &claim_index_a, &undo_a));
    ShadowPowAccountingContext historical_context_a;
    std::vector<ShadowPowClaimAccounting> historical_accounting_a;
    BOOST_REQUIRE(PrepareShadowPowClaimAccounting(view, &claim_index_a,
                                                  historical_context_a) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
                      historical_context_a, block_a, &undo_a,
                      historical_accounting_a) == ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(historical_accounting_a.size(), accounting_a.size());
    for (size_t i = 0; i < accounting_a.size(); ++i) {
        BOOST_CHECK(historical_accounting_a[i].source_txid == accounting_a[i].source_txid);
        BOOST_CHECK(historical_accounting_a[i].disposition == accounting_a[i].disposition);
        BOOST_CHECK_EQUAL(historical_accounting_a[i].credited_amount,
                          accounting_a[i].credited_amount);
    }
    std::map<CScript, CAmount> applied_a;
    CAmount applied_total_a{0};
    BOOST_REQUIRE(GetAppliedShadowDirectPayouts(view, &claim_index_a, applied_a,
                                                applied_total_a));
    BOOST_CHECK(applied_a == payouts_a);
    BOOST_REQUIRE(UndoShadowBlock(view, block_a, &claim_index_a, &undo_a));

    BOOST_REQUIRE(ApplyShadowBlock(view, block_b, &claim_index_b, &undo_b));
    std::map<CScript, CAmount> applied_b;
    CAmount applied_total_b{0};
    BOOST_REQUIRE(GetAppliedShadowDirectPayouts(view, &claim_index_b, applied_b,
                                                applied_total_b));
    BOOST_CHECK(applied_b == payouts_a);
    BOOST_CHECK_EQUAL(applied_total_b, applied_total_a);
    BOOST_REQUIRE(UndoShadowBlock(view, block_b, &claim_index_b, &undo_b));

    CCoinsViewCache replay_view{&seed_view, true};
    BOOST_REQUIRE(ApplyShadowBlock(replay_view, block_a, &claim_index_a, &undo_a));
    std::map<CScript, CAmount> replayed;
    CAmount replayed_total{0};
    BOOST_REQUIRE(GetAppliedShadowDirectPayouts(replay_view, &claim_index_a,
                                                replayed, replayed_total));
    BOOST_CHECK(replayed == payouts_a);
    BOOST_CHECK_EQUAL(replayed_total, applied_total_a);
}

BOOST_AUTO_TEST_CASE(pow_shadow_malformed_multi_proof_transaction_is_never_reimbursed)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, &whitelist_index));

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript target = CScript{} << OP_2;
    const CScript payout = QuantumScript(0x77);
    std::vector<unsigned char> proof;
    BOOST_REQUIRE(MineShadowProofData(target, payout, &prev_index, view, 100'000, proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5));
    claim_block.vtx.push_back(MakePowClaimTx(target, proof, 0));
    claim_block.vtx.push_back(MakePowClaimTxWithTwoProofs(target, proof, proof, 1));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(
        claim_block, {{1, CScript{} << OP_5}, {2, target}, {3, target}});

    std::vector<ShadowPowClaimAccounting> accounting;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, accounting) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 3U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::MALFORMED_TRANSACTION;
        }), 2U);
    for (const ShadowPowClaimAccounting& entry : accounting) {
        if (entry.disposition == ShadowPowClaimDisposition::MALFORMED_TRANSACTION) {
            BOOST_CHECK(!entry.base_fee_known);
            BOOST_CHECK_EQUAL(entry.credited_amount, 0);
        }
    }

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 1U);
    BOOST_CHECK_EQUAL(payouts.front().txout.nValue, 580 * COIN);
}

BOOST_AUTO_TEST_CASE(pow_shadow_ignores_proofs_inside_coinstake)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x4a);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &prev_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5, pow_proof, {CTxOut(580 * COIN, quantum_payout)}));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_5}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_CHECK(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 0);
    BOOST_CHECK(direct_payouts.empty());
    BOOST_CHECK(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 580 * COIN);
    BOOST_CHECK_EQUAL(info.pow_count, 0U);
}

BOOST_AUTO_TEST_CASE(pow_shadow_target_relaxes_after_missed_claims_and_resets_on_claim)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index));

    const ShadowGoldRushInfo first_info = GetShadowGoldRushInfo(view, &first_index);
    BOOST_CHECK_EQUAL(first_info.pow_target_bits, 12U);
    BOOST_CHECK_EQUAL(first_info.last_pow_height, 0U);

    // Advance every authenticated inventory tip. Production code must never
    // permit a missing middle checkpoint, even when this test only cares about
    // the difficulty relaxation after 70 empty claim opportunities.
    std::array<uint256, 70> empty_hashes;
    std::array<CBlockIndex, 70> empty_indexes;
    CBlockIndex* late_prev_index = &first_index;
    for (size_t i = 0; i < empty_indexes.size(); ++i) {
        InitIndex(empty_indexes[i], SHADOW_REWARD_START_HEIGHT + 1 + i,
                  late_prev_index, empty_hashes[i]);
        CBlock empty_block;
        empty_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
        BOOST_REQUIRE(ApplyShadowBlock(view, empty_block, &empty_indexes[i]));
        late_prev_index = &empty_indexes[i];
    }
    const ShadowGoldRushInfo late_info = GetShadowGoldRushInfo(view, late_prev_index);
    BOOST_CHECK_LT(late_info.pow_target_bits, first_info.pow_target_bits);

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x48);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, late_prev_index, view, 20'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, late_prev_index->nHeight + 1, late_prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_4, {}, {CTxOut(580 * COIN, quantum_payout)}));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_4}, {2, pow_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));

    const ShadowGoldRushInfo after_claim_info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(after_claim_info.last_pow_height, static_cast<uint32_t>(claim_index.nHeight));
    BOOST_CHECK_EQUAL(after_claim_info.pow_target_bits, first_info.pow_target_bits);

    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 1U);
    CScript marked_payout;
    BOOST_CHECK(IsGoldRushDirectPayoutOutput(view, payouts[0].outpoint, &marked_payout));
    BOOST_CHECK(marked_payout == quantum_payout);
}

BOOST_AUTO_TEST_CASE(pow_shadow_ignores_claims_over_proof_evaluation_cap)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_3));
    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x49);
    for (uint64_t i = 0; i < 65; ++i) {
        block.vtx.push_back(MakeBadProofTx(i, pow_target, MakeInvalidPowProofData(i, pow_target, quantum_payout)));
    }

    CBlockUndo undo = MakeUndoWithInputScripts(block, {{1, CScript{} << OP_3}});
    BOOST_CHECK(ApplyShadowBlock(view, block, &reward_index, &undo));
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &reward_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 290 * COIN);
    BOOST_CHECK_EQUAL(info.pow_count, 0U);
}

BOOST_AUTO_TEST_CASE(pow_shadow_canonical_evaluation_cap_reimburses_only_63_losers)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, prev_hash);
    CBlock prev_block;
    prev_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, prev_block, &prev_index));

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x4a);
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout, &prev_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5, {}, {CTxOut(580 * COIN, quantum_payout)}));
    std::map<size_t, CScript> input_scripts{{1, CScript{} << OP_5}};
    for (uint32_t i = 0; i < 65; ++i) {
        claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof, i));
        input_scripts.emplace(2 + i, pow_target);
    }
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, input_scripts);

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_CHECK(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, 580 * COIN);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], 580 * COIN);

    std::vector<ShadowPowClaimAccounting> accounting;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, accounting) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 65U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::REIMBURSED_LOSER;
        }), 63U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::EVALUATION_LIMIT;
        }), 1U);
    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 64U);
    CAmount payout_total{0};
    for (const ShadowSyntheticPayoutCoin& payout : payouts) payout_total += payout.txout.nValue;
    BOOST_CHECK_EQUAL(payout_total, 580 * COIN);
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.pow_count, 1U);
}

BOOST_AUTO_TEST_CASE(obsolete_goldrush_direct_payout_markers_are_exact_and_reorg_safe)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript staker_target = CScript{} << OP_TRUE;
    const CScript quantum_payout = QuantumScript(0x53);
    const CScript wrong_amount_payout = QuantumScript(0x54);
    const CTransactionRef coinstake = MakeCoinstakeTx(staker_target, {}, {
        CTxOut(580 * COIN, quantum_payout),
        CTxOut(580 * COIN, quantum_payout),
        CTxOut(581 * COIN, wrong_amount_payout),
    });

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, nullptr, reward_hash);

    const std::map<CScript, CAmount> direct_payouts{
        {quantum_payout, 580 * COIN},
        {wrong_amount_payout, 580 * COIN},
    };
    MarkGoldRushDirectPayoutOutputs(view, *coinstake, &reward_index, direct_payouts);

    const uint256 txid = coinstake->GetHash();
    CScript marker_payload;
    // Legacy raw-script QQGRPAY records are purge-only in v30.1.1. Spend
    // authorization requires the source-bound v2 record emitted by the shadow
    // claim path.
    BOOST_CHECK(!IsGoldRushDirectPayoutOutput(view, COutPoint{txid, 2}, &marker_payload));

    // A duplicate output to the same script and an output with the wrong amount
    // are not marked, so obsolete direct-output cleanup tracks exact test-build rewards.
    BOOST_CHECK(!IsGoldRushDirectPayoutOutput(view, COutPoint{txid, 3}));
    BOOST_CHECK(!IsGoldRushDirectPayoutOutput(view, COutPoint{txid, 4}));

    CBlock reward_block;
    reward_block.vtx.push_back(coinstake);
    UndoGoldRushDirectPayoutOutputMarkers(view, reward_block, &reward_index);
    BOOST_CHECK(!IsGoldRushDirectPayoutOutput(view, COutPoint{txid, 2}));
}

// Property test: the deterministic Gold Rush reward schedule must stay pinned
// to the intended shadow-ledger credit ceiling.
BOOST_AUTO_TEST_CASE(shadow_emission_schedule_within_cap)
{
    CAmount scheduled_total = 0;
    for (int h = SHADOW_REWARD_START_HEIGHT; h <= SHADOW_REWARD_END_HEIGHT; ++h) {
        scheduled_total += ShadowBaseReward(h);
    }
    // The whole schedule can never mint past the consensus cap.
    BOOST_CHECK(scheduled_total <= SHADOW_MAX_EMISSION);
    // Locks the exact 180-day Gold Rush emission against accidental schedule edits.
    BOOST_CHECK_EQUAL(scheduled_total, 51437700LL * COIN);
    // The cap is set to exactly the schedule sum, so accidental edits cannot
    // inflate the shadow-ledger budget.
    BOOST_CHECK_EQUAL(scheduled_total, SHADOW_MAX_EMISSION);
    // No reward is emitted outside the epoch window.
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT - 1), CAmount{0});
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_END_HEIGHT + 1), CAmount{0});
}

BOOST_AUTO_TEST_CASE(shadow_base_reward_boundaries_are_pinned)
{
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT), 580 * COIN);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 43'199), 580 * COIN);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 43'200), 290 * COIN);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 86'400), 145 * COIN);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 129'600), (580 * COIN) >> 3);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 172'800), (580 * COIN) >> 4);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 216'000), (580 * COIN) >> 5);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_PHASE1_END_HEIGHT), (580 * COIN) >> 5);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_PHASE1_END_HEIGHT + 1), 463 * COIN);
    BOOST_CHECK_EQUAL(ShadowBaseReward(SHADOW_REWARD_END_HEIGHT), 463 * COIN);
}

BOOST_AUTO_TEST_CASE(shadow_apply_rejects_pool_obligation_over_emission_cap)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 prev_hash;
    CBlockIndex prev_index;
    InitIndex(prev_index, SHADOW_REWARD_START_HEIGHT - 1, nullptr, prev_hash);
    AddPoolForTest(view, prev_index, 0, 0, SHADOW_MAX_EMISSION - ShadowBaseReward(SHADOW_REWARD_START_HEIGHT) + 1);

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &prev_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));

    BOOST_CHECK(!ApplyShadowBlock(view, block, &reward_index));
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &prev_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.pos_amount, 0);
    BOOST_CHECK_EQUAL(info.claimed_amount, SHADOW_MAX_EMISSION - ShadowBaseReward(SHADOW_REWARD_START_HEIGHT) + 1);
}

BOOST_AUTO_TEST_CASE(shadow_final_cap_block_accepts_dual_venue_claims_and_undoes_cleanly)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript pos_payout = QuantumScript(0x6a);
    const CScript pow_payout = QuantumScript(0x6b);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    ApplyLegacyWhitelistSnapshot(view, &whitelist_index);

    uint256 solve_hash;
    CBlockIndex solve_index;
    InitIndex(solve_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, solve_hash);
    CBlock solve_block;
    solve_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    solve_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo solve_undo = MakeUndoWithInputScripts(solve_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, solve_block, &solve_index, &solve_undo));

    // Simulate the last possible credited block: carried first-block PoW+PoS
    // pools plus this block's scheduled credit exactly fill the emission cap.
    AddPoolForTest(view,
                   solve_index,
                   290 * COIN,
                   290 * COIN,
                   SHADOW_MAX_EMISSION - (580 * COIN) - ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 1));

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(pos_target, pos_payout, solve_index.nHeight, solve_index.GetBlockHash(), signal));
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, pow_payout, &solve_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &solve_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    claim_block.vtx.push_back(MakeSignalTx(pos_target, signal));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, pos_target}, {2, pos_target}, {3, pow_target}});

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const ShadowGoldRushInfo accepted_info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(accepted_info.claimed_amount, SHADOW_MAX_EMISSION);
    BOOST_CHECK_EQUAL(accepted_info.pow_amount, 0);
    BOOST_CHECK_EQUAL(accepted_info.pos_amount, 0);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pos_payout).total, 580 * COIN);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pow_payout).total, 580 * COIN);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pos_payout).total, 580 * COIN);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pow_payout).total, 580 * COIN);

    BOOST_REQUIRE(UndoShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pos_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pow_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pos_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pow_payout).count, 0U);
}

BOOST_AUTO_TEST_CASE(shadow_cap_rejects_without_creating_dual_venue_markers)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    const CScript pos_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript pos_payout = QuantumScript(0x6c);
    const CScript pow_payout = QuantumScript(0x6d);
    AddCoinForScript(view, COutPoint{uint256::ONE, 0}, 10'000 * COIN, pos_target);

    uint256 solve_hash;
    CBlockIndex solve_index;
    InitIndex(solve_index, SHADOW_REWARD_START_HEIGHT, nullptr, solve_hash);
    AddPoolForTest(view,
                   solve_index,
                   290 * COIN,
                   290 * COIN,
                   SHADOW_MAX_EMISSION - (580 * COIN) - ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 1) + 1);

    std::vector<unsigned char> signal;
    BOOST_REQUIRE(BuildShadowSignalData(pos_target, pos_payout, solve_index.nHeight, solve_index.GetBlockHash(), signal));
    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, pow_payout, &solve_index, view, 50'000, pow_proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &solve_index, claim_hash);
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    claim_block.vtx.push_back(MakeSignalTx(pos_target, signal));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, pos_target}, {2, pos_target}, {3, pow_target}});

    BOOST_CHECK(!ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pos_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, pow_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pos_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, pow_payout).count, 0U);
}

// The legacy direct-emission ceiling helper is retained for stale marker cleanup and
// schedule-regression coverage. ConnectBlock no longer uses it for live Gold Rush blocks.
BOOST_AUTO_TEST_CASE(shadow_max_block_direct_total_bounds_to_schedule)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    // Outside the Gold Rush window the ceiling is 0 (no direct emission permitted).
    CBlockIndex before; before.nHeight = SHADOW_REWARD_START_HEIGHT - 1;
    BOOST_CHECK_EQUAL(ShadowMaxBlockDirectTotal(view, &before), CAmount{0});
    CBlockIndex after; after.nHeight = SHADOW_REWARD_END_HEIGHT + 1;
    BOOST_CHECK_EQUAL(ShadowMaxBlockDirectTotal(view, &after), CAmount{0});

    // First Gold Rush block with an empty pool: ceiling == this block's scheduled credit.
    CBlockIndex first; first.nHeight = SHADOW_REWARD_START_HEIGHT;
    BOOST_CHECK_EQUAL(ShadowMaxBlockDirectTotal(view, &first), ShadowBaseReward(SHADOW_REWARD_START_HEIGHT));
}

BOOST_AUTO_TEST_SUITE_END()
