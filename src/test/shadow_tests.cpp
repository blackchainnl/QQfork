// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <crypto/common.h>
#include <chain.h>
#include <consensus/params.h>
#include <hash.h>
#include <index/shadowindex.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <shadow.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <undo.h>
#include <util/strencodings.h>

#include <algorithm>
#include <functional>
#include <map>
#include <array>
#include <limits>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(shadow_tests, BasicTestingSetup)

namespace {

class ShadowScheduleGuard
{
public:
    ShadowScheduleGuard(int whitelist_height, int reward_start_height, int gold_rush_blocks)
        : m_whitelist_height{SHADOW_WHITELIST_HEIGHT},
          m_reward_start_height{SHADOW_REWARD_START_HEIGHT},
          m_gold_rush_blocks{SHADOW_GOLD_RUSH_BLOCKS},
          m_halving_interval{SHADOW_HALVING_INTERVAL_BLOCKS}
    {
        SetShadowTestSchedule(whitelist_height, reward_start_height, gold_rush_blocks);
    }

    ~ShadowScheduleGuard()
    {
        SetShadowTestSchedule(m_whitelist_height, m_reward_start_height, m_gold_rush_blocks);
        SetShadowTestHalvingInterval(m_halving_interval);
    }

private:
    const int m_whitelist_height;
    const int m_reward_start_height;
    const int m_gold_rush_blocks;
    const int m_halving_interval;
};

class ShadowFailureGuard
{
public:
    ShadowFailureGuard()
    {
        ClearShadowArgon2FailuresForTesting();
        ClearShadowAllocationFailureForTesting();
    }

    ~ShadowFailureGuard()
    {
        ClearShadowArgon2FailuresForTesting();
        ClearShadowAllocationFailureForTesting();
    }
};

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

COutPoint ClaimOutpointForTest(int height, const uint256& block_hash,
                               uint32_t marker_index)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Claim") << height << block_hash
       << marker_index;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalSetOutpointForTest()
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal Set");
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

CTransactionRef MakePowClaimTx(const CScript& target,
                               const std::vector<unsigned char>& proof,
                               const COutPoint& input)
{
    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{input});
    mtx.vout.push_back(CTxOut(1 * COIN, target));
    mtx.vout.push_back(CTxOut(0, CScript{} << OP_RETURN << proof));
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef MakePowClaimTx(const CScript& target,
                               const std::vector<unsigned char>& proof,
                               uint32_t input_n = 0)
{
    return MakePowClaimTx(target, proof, COutPoint{uint256{2}, input_n});
}

bool MineQQP4Proof(const CScript& target, const CScript& payout,
                  uint32_t input_n, const CBlockIndex* parent,
                  const CCoinsViewCache& view, uint64_t max_tries,
                  std::vector<unsigned char>& proof_out)
{
    return MineShadowProofData(target, payout,
                               COutPoint{uint256{2}, input_n}, parent, view,
                               max_tries, proof_out);
}

/** A regtest fixture with an explicit, independently scheduled QQP4 fork.
 * QQP3 remains active for two blocks first so boundary tests cannot accidentally
 * couple the two wire formats again. */
class QQP4ActivationTestingSetup : public TestChain100Setup
{
public:
    QQP4ActivationTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, {
              "-regtest",
              "-shadowwhitelistheight=100",
              "-shadowgoldrushstartheight=101",
              "-shadowgoldrushblocks=96",
              "-shadowcompetingclaimsheight=110",
              "-shadowqqp4height=112",
          }}
    {
    }
};

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

std::vector<unsigned char> MakeQQP1ProofData(uint64_t nonce,
                                              const CScript& target)
{
    std::vector<unsigned char> proof = GetShadowPrefix();
    proof.insert(proof.end(), {'Q', 'Q', 'P', '1', 0});
    for (unsigned int i = 0; i < 8; ++i) {
        proof.push_back(static_cast<unsigned char>((nonce >> (8 * i)) & 0xff));
    }
    proof.insert(proof.end(), target.begin(), target.end());
    return proof;
}

std::vector<unsigned char> MakeQQP3ProofData(
    uint64_t nonce, uint32_t origin_height, const uint256& origin_parent,
    const CScript& target, const CScript& payout_script)
{
    std::vector<unsigned char> proof = GetShadowPrefix();
    proof.insert(proof.end(), {'Q', 'Q', 'P', '3', 0});
    for (unsigned int i = 0; i < 8; ++i) {
        proof.push_back(static_cast<unsigned char>((nonce >> (8 * i)) & 0xff));
    }
    for (unsigned int i = 0; i < 4; ++i) {
        proof.push_back(static_cast<unsigned char>(
            (origin_height >> (8 * i)) & 0xff));
    }
    proof.insert(proof.end(), origin_parent.begin(), origin_parent.end());
    proof.push_back(static_cast<unsigned char>(target.size() & 0xff));
    proof.push_back(static_cast<unsigned char>((target.size() >> 8) & 0xff));
    proof.insert(proof.end(), target.begin(), target.end());
    proof.push_back(static_cast<unsigned char>(payout_script.size() & 0xff));
    proof.push_back(static_cast<unsigned char>(
        (payout_script.size() >> 8) & 0xff));
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

BOOST_AUTO_TEST_CASE(synthetic_claim_limit_preserves_history_and_tightens_at_activation)
{
    const Consensus::Params& mainnet = Params().GetConsensus();
    BOOST_REQUIRE_EQUAL(mainnet.nShadowCompetingClaimsActivationHeight,
                        MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT);
    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(
                          mainnet,
                          MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT - 1,
                          687),
                      (V4_MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) + 2);
    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(
                          mainnet,
                          MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT,
                          687),
                      751U);

    Consensus::Params consensus = mainnet;
    consensus.nShadowCompetingClaimsActivationHeight = 100;
    static constexpr uint32_t legacy_limit =
        (V4_MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) + 2;

    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(consensus, 99, 687),
                      legacy_limit);
    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(consensus, 100, 687),
                      751U);
    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(consensus, 100, 0),
                      MAX_SHADOW_POW_EVALS_PER_BLOCK);
    BOOST_CHECK_EQUAL(GetShadowSyntheticClaimLimit(
                          consensus, 100,
                          std::numeric_limits<uint32_t>::max()),
                      legacy_limit);
}

BOOST_AUTO_TEST_CASE(active_signal_resource_bounds_follow_authenticated_whitelist)
{
    // Mainnet's observed 687 canonical P2PKH targets produce a whitelist blob
    // of 5 + 687 * (2 + 25) bytes. The bound is derived from those manifest
    // dimensions rather than the generic 32 MiB deserialization ceiling.
    const auto direct = GetShadowActiveSignalResourceBounds(
        /*whitelist_entries=*/687,
        /*whitelist_blob_bytes=*/18'554);
    BOOST_REQUIRE(direct);
    BOOST_CHECK_EQUAL(direct->maximum_state_bytes, 46'066U);
    BOOST_CHECK_EQUAL(direct->maximum_undo_bytes, 46'890U);
    BOOST_CHECK_EQUAL(direct->maximum_state_shards, 6U);
    BOOST_CHECK_EQUAL(direct->maximum_undo_shards, 6U);

    const auto empty = GetShadowActiveSignalResourceBounds(
        /*whitelist_entries=*/0,
        /*whitelist_blob_bytes=*/5);
    BOOST_REQUIRE(empty);
    BOOST_CHECK_EQUAL(empty->maximum_state_bytes, 37U);
    BOOST_CHECK_EQUAL(empty->maximum_undo_bytes, 174U);
    BOOST_CHECK_EQUAL(empty->maximum_state_shards, 1U);
    BOOST_CHECK_EQUAL(empty->maximum_undo_shards, 1U);

    BOOST_CHECK(!GetShadowActiveSignalResourceBounds(
        /*whitelist_entries=*/1,
        /*whitelist_blob_bytes=*/7));
    BOOST_CHECK(!GetShadowActiveSignalResourceBounds(
        /*whitelist_entries=*/687,
        /*whitelist_blob_bytes=*/MAX_SIZE));

    const auto envelope = GetShadowActiveSignalResourceBounds(
        /*whitelist_entries=*/687,
        /*whitelist_blob_bytes=*/MAX_SIZE - 1024);
    BOOST_REQUIRE(envelope);
    BOOST_CHECK_EQUAL(envelope->maximum_state_bytes, MAX_SIZE - 1024);
    BOOST_CHECK_EQUAL(envelope->maximum_undo_bytes, MAX_SIZE - 1024);
    BOOST_CHECK_EQUAL(envelope->maximum_state_shards, 4'195U);
    BOOST_CHECK_EQUAL(envelope->maximum_undo_shards, 4'195U);
}

BOOST_AUTO_TEST_CASE(shadow_index_record_validation_respects_claim_boundary)
{
    ShadowIndexRecord record;
    record.outpoint = COutPoint{uint256::ONE, 0};
    record.origin_height = MAINNET_SHADOW_REWARD_START_HEIGHT;
    record.origin_block_hash = uint256S("02");
    record.origin_block_time = 1;
    record.proof_of_work = true;
    record.nominal_amount = 10 * COIN;
    record.script_pub_key = QuantumScript(0x51);

    BOOST_CHECK(IsValidShadowIndexRecord(record));

    record.pow_claim_source_present = true;
    record.pow_claim_source.txid = uint256S("03");
    record.pow_claim_source.canonical_rank = uint256S("04");
    record.pow_claim_source.base_fee_known = true;
    record.pow_claim_source.base_fee = CENT;
    record.pow_claim_source.disposition = ShadowPowClaimDisposition::WINNER;
    record.pow_claim_source.proof_version = 3;
    record.pow_claim_source.origin_bound = true;
    record.pow_claim_source.origin_height =
        MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT;
    record.pow_claim_source.origin_previous_block_hash = uint256S("07");
    record.pow_claim_source.inclusion_height =
        MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT;
    record.pow_claim_source.input_bound = false;
    record.pow_claim_source.claim_outpoint.SetNull();
    BOOST_CHECK(!IsValidShadowIndexRecord(record));

    record.origin_height = MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT;
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    // Current winners and current losers cannot be relabeled as a late
    // provenance row by a corrupt auxiliary index.
    record.pow_claim_source.origin_height = record.origin_height - 1;
    record.pow_claim_source.origin_age = 1;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source.disposition =
        ShadowPowClaimDisposition::REIMBURSED_LOSER;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source.disposition = ShadowPowClaimDisposition::WINNER;
    record.pow_claim_source.origin_height = record.origin_height;
    record.pow_claim_source.origin_age = 0;
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    // QQP3 intentionally preserves valid QQP2 rows.  The canonical-accounting
    // boundary is not an exact-input wire fork.
    const ShadowIndexPowClaimSource valid_v3_source =
        record.pow_claim_source;
    record.pow_claim_source.proof_version = 2;
    record.pow_claim_source.origin_bound = false;
    record.pow_claim_source.input_bound = false;
    record.pow_claim_source.claim_outpoint.SetNull();
    BOOST_CHECK(IsValidShadowIndexRecord(record));
    record.pow_claim_source.disposition =
        ShadowPowClaimDisposition::REIMBURSED_LOSER;
    BOOST_CHECK(IsValidShadowIndexRecord(record));
    record.pow_claim_source.disposition = ShadowPowClaimDisposition::WINNER;
    record.pow_claim_source = valid_v3_source;

    record.pow_claim_source.disposition =
        ShadowPowClaimDisposition::REIMBURSED_LOSER;
    BOOST_CHECK(IsValidShadowIndexRecord(record));
    record.pow_claim_source = valid_v3_source;

    // QQP4 cannot be smuggled into the deployed QQP3 history.  Its own
    // schedule is disabled on mainnet in this alpha/beta.
    record.pow_claim_source.proof_version = 4;
    record.pow_claim_source.input_bound = true;
    record.pow_claim_source.claim_outpoint = COutPoint{uint256S("08"), 1};
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source = valid_v3_source;

    record.pow_claim_source_present = false;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));

    record.pow_claim_source_present = true;
    record.pow_claim_source.disposition =
        ShadowPowClaimDisposition::REIMBURSED_LATE;
    record.pow_claim_source.origin_height = record.origin_height - 3;
    record.pow_claim_source.inclusion_height = record.origin_height;
    record.pow_claim_source.origin_age = 3;
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    DataStream stream;
    stream << record.pow_claim_source;
    ShadowIndexPowClaimSource restored_source;
    stream >> restored_source;
    BOOST_CHECK(restored_source.txid == record.pow_claim_source.txid);
    BOOST_CHECK(restored_source.disposition ==
                ShadowPowClaimDisposition::REIMBURSED_LATE);
    BOOST_CHECK(restored_source.origin_bound);
    BOOST_CHECK_EQUAL(restored_source.origin_height,
                      record.pow_claim_source.origin_height);
    BOOST_CHECK(restored_source.origin_previous_block_hash ==
                record.pow_claim_source.origin_previous_block_hash);
    BOOST_CHECK_EQUAL(restored_source.inclusion_height, record.origin_height);
    BOOST_CHECK_EQUAL(restored_source.origin_age, 3U);
    BOOST_CHECK_EQUAL(restored_source.proof_version, 3U);
    BOOST_CHECK(!restored_source.input_bound);
    BOOST_CHECK(restored_source.claim_outpoint.IsNull());

    // QQP3 must not carry QQP4's input provenance fields.
    record.pow_claim_source.input_bound = true;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source.input_bound = false;
    record.pow_claim_source.claim_outpoint = COutPoint{uint256S("08"), 1};
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source.claim_outpoint.SetNull();
    record.pow_claim_source.inclusion_height = record.origin_height + 1;
    record.pow_claim_source.origin_age = 4;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
    record.pow_claim_source.inclusion_height = record.origin_height;
    record.pow_claim_source.origin_age = 3;
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    record.spent = true;
    record.spend_height = record.origin_height + 1;
    record.spend_block_hash = uint256S("05");
    record.spending_txid = uint256S("06");
    record.effective_amount_at_spend = 9 * COIN;
    record.decayed_amount_at_spend = COIN;
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    record.decayed_amount_at_spend = 2 * COIN;
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
}

// Registered below, after the file-wide BasicTestingSetup suite is closed.
// TestChain100Setup owns global chain parameters and cannot be nested below
// that fixture without invalidating both fixtures' lifecycle.
static void CheckShadowIndexRecordQQP4ExactInputAfterSeparateActivation()
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int q4_height = consensus.nShadowQQP4ActivationHeight;
    BOOST_REQUIRE_EQUAL(consensus.nShadowCompetingClaimsActivationHeight, 110);
    BOOST_REQUIRE_EQUAL(q4_height, 112);
    BOOST_REQUIRE(consensus.IsShadowQQP4Active(q4_height));

    ShadowIndexRecord record;
    record.outpoint = COutPoint{uint256::ONE, 0};
    record.origin_height = q4_height;
    record.origin_block_hash = uint256S("02");
    record.origin_block_time = 1;
    record.proof_of_work = true;
    record.nominal_amount = 10 * COIN;
    record.script_pub_key = QuantumScript(0x51);
    record.pow_claim_source_present = true;
    record.pow_claim_source.txid = uint256S("03");
    record.pow_claim_source.canonical_rank = uint256S("04");
    record.pow_claim_source.base_fee_known = true;
    record.pow_claim_source.base_fee = CENT;
    record.pow_claim_source.disposition = ShadowPowClaimDisposition::WINNER;
    record.pow_claim_source.proof_version = 4;
    record.pow_claim_source.origin_bound = true;
    record.pow_claim_source.origin_height = q4_height;
    record.pow_claim_source.origin_previous_block_hash = uint256S("07");
    record.pow_claim_source.inclusion_height = q4_height;
    record.pow_claim_source.input_bound = true;
    record.pow_claim_source.claim_outpoint = COutPoint{uint256S("08"), 1};
    BOOST_CHECK(IsValidShadowIndexRecord(record));

    record.pow_claim_source.proof_version = 3;
    record.pow_claim_source.input_bound = false;
    record.pow_claim_source.claim_outpoint.SetNull();
    BOOST_CHECK(!IsValidShadowIndexRecord(record));
}

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

BOOST_AUTO_TEST_CASE(user_marker_lookalikes_are_never_authenticated_or_purged)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 tip_hash;
    CBlockIndex tip;
    InitIndex(tip, SHADOW_REWARD_START_HEIGHT, nullptr, tip_hash);

    const std::vector<std::vector<unsigned char>> marker_tags{
        {'Q', 'Q', 'W', 'L'},
        {'Q', 'Q', 'W', 'L', 'R', 'E', 'A', 'D', 'Y'},
        {'Q', 'Q', 'W', 'L', 'M', 'A', 'N'},
        {'Q', 'Q', 'W', 'L', 'S', 'H'},
        {'Q', 'Q', 'P', 'O', 'O', 'L'},
        {'Q', 'Q', 'P', 'U', 'N', 'D'},
        {'Q', 'Q', 'D', 'C', 'L', 'A', 'I', 'M'},
        {'Q', 'Q', 'G', 'R', 'P', 'A', 'Y'},
        {'Q', 'Q', 'G', 'R', 'S', 'P', 'E', 'N', 'T'},
        {'Q', 'Q', 'G', 'R', 'I', 'N', 'V'},
        {'Q', 'Q', 'S', 'O', 'L', 'V', 'E'},
        {'Q', 'Q', 'A', 'S', 'I', 'G'},
        {'Q', 'Q', 'A', 'S', 'E', 'T'},
        {'Q', 'Q', 'A', 'S', 'H', 'D'},
        {'Q', 'Q', 'A', 'U', 'N', 'D'},
        {'Q', 'Q', 'A', 'U', 'S', 'H'},
        {'Q', 'Q', 'R', 'E', 'P', 'L', 'A', 'Y'},
    };
    std::vector<COutPoint> lookalikes;
    for (const auto& tag : marker_tags) {
        for (uint32_t i = 0; i < 64; ++i) {
            CHashWriter key;
            key << std::string("ordinary user marker lookalike") << tag << i;
            const COutPoint outpoint{key.GetHash(), 0};
            Coin coin;
            coin.out.nValue = 0;
            coin.out.scriptPubKey = CScript{} << OP_FALSE << OP_RETURN << tag
                                             << std::vector<unsigned char>{
                                                    static_cast<unsigned char>(i)};
            coin.fCoinBase = false;
            coin.fCoinStake = false;
            coin.nHeight = tip.nHeight;
            coin.nTime = tip.GetBlockTime();
            BOOST_REQUIRE(IsShadowMarkerScript(coin.out.scriptPubKey));
            BOOST_CHECK(!IsAuthenticatedShadowMarkerOutpoint(outpoint, coin,
                                                               &tip));
            view.AddCoin(outpoint, std::move(coin), false);
            lookalikes.push_back(outpoint);
        }
    }

    const ShadowBlockReader empty_block_reader =
        [](const CBlockIndex&, CBlock& block) {
            block = CBlock{};
            return true;
        };
    std::set<COutPoint> authenticated;
    BOOST_REQUIRE(CollectAuthenticatedShadowStateOutpoints(
        view, &tip, empty_block_reader, authenticated));
    BOOST_CHECK(authenticated.empty());

    uint64_t removed{0};
    BOOST_REQUIRE(PurgeAuthenticatedShadowState(
        view, &tip, empty_block_reader, removed));
    BOOST_CHECK_EQUAL(removed, 0U);
    for (const COutPoint& outpoint : lookalikes) {
        BOOST_CHECK(view.HaveCoin(outpoint));
    }
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

    // A claim-shaped coin at the next deterministic index is not authority
    // to extend the block's synthetic claim set. Enumeration is anchored to
    // the authenticated QQPUND count and claims hash.
    Coin authentic_claim;
    BOOST_REQUIRE(view.GetCoin(ClaimOutpointForTest(
        reward_index.nHeight, reward_index.GetBlockHash(), 0),
        authentic_claim));
    const COutPoint fake_next_claim = ClaimOutpointForTest(
        reward_index.nHeight, reward_index.GetBlockHash(), 1);
    view.AddCoin(fake_next_claim, Coin{authentic_claim}, true);
    const std::vector<ShadowSyntheticPayoutTransaction> bounded_payouts =
        GetAppliedShadowClaimPayoutTransactionRecords(
            view, reward_index.nHeight, reward_index.GetBlockHash(),
            reward_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(bounded_payouts.size(), 1U);
    BOOST_REQUIRE(view.SpendCoin(fake_next_claim));

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

BOOST_AUTO_TEST_CASE(active_signal_and_pool_state_are_atomic_and_fail_closed)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, &whitelist_index));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index));

    const ShadowReplayStateInfo absent_replay = GetShadowReplayStateInfo(
        view, Params().GetConsensus(), &first_index);
    BOOST_CHECK_EQUAL(absent_replay.schema, 12U);
    BOOST_CHECK(absent_replay.required_for_tip);
    BOOST_CHECK(!absent_replay.present);
    BOOST_CHECK(!absent_replay.valid_for_tip);

    // ApplyShadowBlock is the isolated accounting helper; full validation
    // writes QQRSTATE only after all sibling checkpoints advance. The fixture
    // has completed those transitions, so writing the exact-tip marker here
    // makes the authenticated replay state current.
    WriteShadowReplayStateMarker(view, &first_index, Params().GetConsensus());
    const ShadowReplayStateInfo replay = GetShadowReplayStateInfo(
        view, Params().GetConsensus(), &first_index);
    BOOST_CHECK(replay.present);
    BOOST_CHECK(replay.marker_valid);
    BOOST_CHECK(replay.valid_for_tip);
    BOOST_CHECK_EQUAL(replay.marker_height, static_cast<uint32_t>(first_index.nHeight));
    BOOST_CHECK_EQUAL(replay.marker_time, static_cast<uint32_t>(first_index.GetBlockTime()));
    BOOST_CHECK(replay.marker_block_hash == first_index.GetBlockHash());
    BOOST_CHECK_EQUAL(replay.commitment.size(), uint256::size());

    // A separately scheduled QQP4 fork must not rewrite the deployed
    // schema-12 checkpoint domain before it activates. This is the direct
    // v30.1.0 chainstate/restart compatibility vector: the same marker remains
    // current when a future QQP4 height is configured beyond this tip.
    Consensus::Params future_qqp4 = Params().GetConsensus();
    future_qqp4.nShadowQQP4ActivationHeight = first_index.nHeight + 1;
    BOOST_REQUIRE(!future_qqp4.IsShadowQQP4Active(first_index.nHeight));
    const ShadowReplayStateInfo future_qqp4_replay =
        GetShadowReplayStateInfo(view, future_qqp4, &first_index);
    BOOST_CHECK(future_qqp4_replay.present);
    BOOST_CHECK(future_qqp4_replay.marker_valid);
    BOOST_CHECK(future_qqp4_replay.valid_for_tip);
    BOOST_CHECK(future_qqp4_replay.commitment == replay.commitment);

    const COutPoint replay_outpoint = ShadowReplayStateOutpointForTesting();
    Coin canonical_replay_coin;
    BOOST_REQUIRE(view.GetCoin(replay_outpoint, canonical_replay_coin));

    const auto replace_replay_coin = [&](Coin replacement) {
        BOOST_REQUIRE(view.SpendCoin(replay_outpoint));
        view.AddCoin(replay_outpoint, std::move(replacement), true);
    };
    const auto require_rejected_replay_coin = [&](Coin replacement,
                                                   bool structurally_valid) {
        replace_replay_coin(std::move(replacement));
        const ShadowReplayStateInfo rejected = GetShadowReplayStateInfo(
            view, Params().GetConsensus(), &first_index);
        BOOST_CHECK(rejected.present);
        BOOST_CHECK_EQUAL(rejected.marker_valid, structurally_valid);
        BOOST_CHECK(!rejected.valid_for_tip);
        BOOST_CHECK(!HasCurrentShadowReplayState(
            view, Params().GetConsensus(), &first_index));
        replace_replay_coin(canonical_replay_coin);
        BOOST_REQUIRE(HasCurrentShadowReplayState(
            view, Params().GetConsensus(), &first_index));
    };

    Coin nonzero_replay = canonical_replay_coin;
    nonzero_replay.out.nValue = 1;
    require_rejected_replay_coin(std::move(nonzero_replay), false);

    Coin non_coinbase_replay = canonical_replay_coin;
    non_coinbase_replay.fCoinBase = false;
    require_rejected_replay_coin(std::move(non_coinbase_replay), false);

    Coin coinstake_replay = canonical_replay_coin;
    coinstake_replay.fCoinStake = true;
    require_rejected_replay_coin(std::move(coinstake_replay), false);

    Coin wrong_height_replay = canonical_replay_coin;
    --wrong_height_replay.nHeight;
    require_rejected_replay_coin(std::move(wrong_height_replay), false);

    Coin wrong_time_replay = canonical_replay_coin;
    ++wrong_time_replay.nTime;
    require_rejected_replay_coin(std::move(wrong_time_replay), false);

    Coin noncanonical_replay = canonical_replay_coin;
    const CScript& canonical_script = canonical_replay_coin.out.scriptPubKey;
    BOOST_REQUIRE_GE(canonical_script.size(), 12U);
    const size_t tag_size = canonical_script[2];
    BOOST_REQUIRE_EQUAL(tag_size, 8U);
    CScript noncanonical_script;
    noncanonical_script.push_back(OP_FALSE);
    noncanonical_script.push_back(OP_RETURN);
    noncanonical_script.push_back(OP_PUSHDATA1);
    noncanonical_script.push_back(static_cast<unsigned char>(tag_size));
    noncanonical_script.insert(noncanonical_script.end(),
                               canonical_script.begin() + 3,
                               canonical_script.begin() + 3 + tag_size);
    noncanonical_script.insert(noncanonical_script.end(),
                               canonical_script.begin() + 3 + tag_size,
                               canonical_script.end());
    noncanonical_replay.out.scriptPubKey = std::move(noncanonical_script);
    require_rejected_replay_coin(std::move(noncanonical_replay), false);

    Coin wrong_payload_replay = canonical_replay_coin;
    wrong_payload_replay.out.scriptPubKey.back() ^= 1;
    require_rejected_replay_coin(std::move(wrong_payload_replay), true);

    uint256 stale_hash;
    CBlockIndex stale_index;
    InitIndex(stale_index, first_index.nHeight, &whitelist_index, stale_hash);
    stale_hash = uint256::ONE;
    WriteShadowReplayStateMarker(
        view, &stale_index, Params().GetConsensus());
    const ShadowReplayStateInfo stale_replay = GetShadowReplayStateInfo(
        view, Params().GetConsensus(), &first_index);
    BOOST_CHECK(stale_replay.marker_valid);
    BOOST_CHECK(!stale_replay.valid_for_tip);
    BOOST_CHECK(!HasCurrentShadowReplayState(
        view, Params().GetConsensus(), &first_index));
    replace_replay_coin(canonical_replay_coin);

    Coin pool_coin;
    Coin signal_coin;
    BOOST_REQUIRE(view.GetCoin(PoolOutpointForTest(), pool_coin));
    BOOST_REQUIRE(view.GetCoin(ActiveSignalSetOutpointForTest(), signal_coin));

    uint256 second_hash;
    CBlockIndex second_index;
    InitIndex(second_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, second_hash);
    CBlock second_block;
    second_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_2));

    BOOST_REQUIRE(view.SpendCoin(ActiveSignalSetOutpointForTest()));
    BOOST_CHECK(ApplyShadowBlockResult(view, second_block, &second_index) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    view.AddCoin(ActiveSignalSetOutpointForTest(), Coin{signal_coin}, true);

    BOOST_REQUIRE(view.SpendCoin(PoolOutpointForTest()));
    BOOST_CHECK(ApplyShadowBlockResult(view, second_block, &second_index) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    view.AddCoin(PoolOutpointForTest(), Coin{pool_coin}, true);

    BOOST_REQUIRE(view.SpendCoin(PoolOutpointForTest()));
    BOOST_REQUIRE(view.SpendCoin(ActiveSignalSetOutpointForTest()));
    BOOST_CHECK(ApplyShadowBlockResult(view, second_block, &second_index) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    view.AddCoin(PoolOutpointForTest(), Coin{pool_coin}, true);
    view.AddCoin(ActiveSignalSetOutpointForTest(), Coin{signal_coin}, true);

    BOOST_REQUIRE(ApplyShadowBlock(view, second_block, &second_index));
    BOOST_REQUIRE(UndoShadowBlock(view, second_block, &second_index));
    BOOST_REQUIRE(UndoShadowBlock(view, first_block, &first_index));
    BOOST_CHECK(!view.HaveCoin(PoolOutpointForTest()));
    BOOST_CHECK(!view.HaveCoin(ActiveSignalSetOutpointForTest()));
}

BOOST_AUTO_TEST_CASE(active_signal_pool_pair_matches_exact_reward_history)
{
    // Use a short, contiguous history so the time-only compatibility path can
    // locate the first V4 reward-height block without a synthetic gap.
    ShadowScheduleGuard schedule{/*whitelist_height=*/1,
                                 /*reward_start_height=*/2,
                                 /*gold_rush_blocks=*/4};
    std::vector<CBlockIndex> indexes(8);
    std::vector<uint256> hashes(8);
    for (int height = 0; height < static_cast<int>(indexes.size()); ++height) {
        InitIndex(indexes[height], height, height == 0 ? nullptr : &indexes[height - 1], hashes[height]);
    }

    const auto pair_valid = [&](const Consensus::Params& consensus, int height,
                                bool pool_present, bool signal_present) {
        return ShadowActiveSignalPoolPairValidForTesting(
            consensus, &indexes.at(height), pool_present, signal_present);
    };

    // A time-only schedule may jump directly from Legacy past Gold Rush. No
    // reward transition occurs in that case, so even a symmetric present pair
    // is invalid; only symmetric absence is authentic.
    Consensus::Params skipped;
    const int64_t reward_start_parent_mtp = indexes[1].GetMedianTimePast();
    skipped.nProtocolV4Time = reward_start_parent_mtp - 1;
    skipped.nGoldRushEndTime = reward_start_parent_mtp - 2;
    skipped.nQuantumMigrationDeadlineTime = indexes[7].GetMedianTimePast() + 1;
    BOOST_CHECK(pair_valid(skipped, 6, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(skipped, 6, /*pool_present=*/true, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(skipped, 6, /*pool_present=*/false, /*signal_present=*/true));
    BOOST_CHECK(!pair_valid(skipped, 6, /*pool_present=*/true, /*signal_present=*/true));

    // In a genuine time-only Gold Rush, absence is required before the first
    // active transition and presence is required from that transition onward,
    // including after the lifecycle has advanced to Migration.
    Consensus::Params time_only;
    time_only.nProtocolV4Time = indexes[1].GetMedianTimePast();
    time_only.nGoldRushEndTime = indexes[3].GetMedianTimePast();
    time_only.nQuantumMigrationDeadlineTime = indexes[7].GetMedianTimePast() + 1;
    BOOST_CHECK(pair_valid(time_only, 2, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(time_only, 2, /*pool_present=*/true, /*signal_present=*/true));
    BOOST_CHECK(!pair_valid(time_only, 3, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(pair_valid(time_only, 3, /*pool_present=*/true, /*signal_present=*/true));
    BOOST_CHECK(pair_valid(time_only, 6, /*pool_present=*/true, /*signal_present=*/true));
    BOOST_CHECK(!pair_valid(time_only, 6, /*pool_present=*/false, /*signal_present=*/false));

    // A complete height schedule can deliberately begin after reward-start.
    // The pair remains absent until the first overlapping lifecycle height.
    Consensus::Params delayed_height;
    delayed_height.nQuantumLifecycleStartHeight = 4;
    delayed_height.nGoldRushEndHeight = 5;
    delayed_height.nQuantumMigrationEndHeight = 7;
    BOOST_CHECK(pair_valid(delayed_height, 3, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(delayed_height, 3, /*pool_present=*/true, /*signal_present=*/true));
    BOOST_CHECK(!pair_valid(delayed_height, 4, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(pair_valid(delayed_height, 4, /*pool_present=*/true, /*signal_present=*/true));

    // Partial and unordered height schedules have no trustworthy provenance.
    // Fail closed regardless of whether the two markers happen to be symmetric.
    Consensus::Params partial_height;
    partial_height.nQuantumLifecycleStartHeight = 2;
    BOOST_CHECK(!pair_valid(partial_height, 6, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(partial_height, 6, /*pool_present=*/true, /*signal_present=*/true));

    Consensus::Params unordered_height;
    unordered_height.nQuantumLifecycleStartHeight = 5;
    unordered_height.nGoldRushEndHeight = 4;
    unordered_height.nQuantumMigrationEndHeight = 7;
    BOOST_CHECK(!pair_valid(unordered_height, 6, /*pool_present=*/false, /*signal_present=*/false));
    BOOST_CHECK(!pair_valid(unordered_height, 6, /*pool_present=*/true, /*signal_present=*/true));
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

BOOST_AUTO_TEST_CASE(shadow_undo_zero_input_noncoinbase_disconnect_is_safe)
{
    CCoinsView base;
    CCoinsViewCache view{&base, true};

    uint256 block_hash;
    CBlockIndex index;
    InitIndex(index, SHADOW_REWARD_START_HEIGHT, nullptr, block_hash);

    CMutableTransaction zero_input;
    zero_input.nVersion = 2;
    zero_input.vout.emplace_back(1 * COIN, CScript{} << OP_TRUE);
    const CTransactionRef zero_input_tx = MakeTransactionRef(std::move(zero_input));
    BOOST_REQUIRE(!zero_input_tx->IsCoinBase());
    BOOST_REQUIRE(zero_input_tx->vin.empty());

    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    block.vtx.push_back(zero_input_tx);
    CBlockUndo undo;
    undo.vtxundo.resize(block.vtx.size() - 1);

    // DisconnectBlock reaches this helper before restoring the base UTXO
    // undo. A malformed zero-input non-coinbase transaction must not make
    // the reverse-input loop underflow while unwinding the block.
    BOOST_CHECK(UndoSpentGoldRushPayouts(view, block, undo, &index));
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
    BOOST_REQUIRE_GT(pow_proof.size(), GetShadowPrefix().size() + 4);
    BOOST_CHECK_EQUAL(pow_proof[GetShadowPrefix().size() + 3], '2');

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

    const int activation_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    BOOST_REQUIRE_GT(activation_height, first_index.nHeight);
    uint256 activation_parent_hash;
    CBlockIndex activation_parent;
    InitIndex(activation_parent, activation_height - 1, &first_index,
              activation_parent_hash);
    BOOST_REQUIRE(AdvanceGoldRushInventoryTip(view, &activation_parent));

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout,
                                      &activation_parent, view, 50'000,
                                      pow_proof));
    BOOST_REQUIRE_GT(pow_proof.size(), GetShadowPrefix().size() + 4);
    BOOST_CHECK_EQUAL(pow_proof[GetShadowPrefix().size() + 3], '3');

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, activation_height, &activation_parent, claim_hash);
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
    ShadowPowClaimAggregate pow_block_aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, pow_block_accounting,
                                              &pow_block_aggregate) ==
                  ShadowPowAccountingResult::OK);
    BOOST_CHECK(pow_block_accounting.empty());
    BOOST_CHECK_EQUAL(pow_block_aggregate.observed_count, 1U);
    BOOST_CHECK_EQUAL(pow_block_aggregate.evaluated_count, 0U);
    BOOST_CHECK_EQUAL(pow_block_aggregate.invalid_location_count, 1U);
    BOOST_CHECK(!pow_block_aggregate.accounting_commitment.IsNull());

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(view, quantum_payout).count, 0U);
    BOOST_CHECK_EQUAL(ScanSpendableCoins(view, quantum_payout).count, 0U);

    const CAmount first_reward = ShadowBaseReward(first_index.nHeight);
    const CAmount claim_reward = ShadowBaseReward(claim_index.nHeight);
    const CAmount expected_pow_pool =
        first_reward / 2 + claim_reward / 2;
    const CAmount expected_pos_pool =
        (first_reward - first_reward / 2) +
        (claim_reward - claim_reward / 2);
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, expected_pow_pool);
    BOOST_CHECK_EQUAL(info.pos_amount, expected_pos_pool);
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

    const int activation_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    BOOST_REQUIRE_GT(activation_height, prev_index.nHeight);
    uint256 activation_parent_hash;
    CBlockIndex activation_parent;
    InitIndex(activation_parent, activation_height - 1, &prev_index,
              activation_parent_hash);
    BOOST_REQUIRE(AdvanceGoldRushInventoryTip(view, &activation_parent));

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x47);
    std::vector<unsigned char> pow_proof_a;
    std::vector<unsigned char> pow_proof_b;
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout,
                                      &activation_parent, view, 50'000,
                                      pow_proof_a));
    BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout,
                                      &activation_parent, view, 50'000,
                                      pow_proof_b));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, activation_height, &activation_parent, claim_hash);
    const CAmount expected_pow_pool =
        ShadowBaseReward(prev_index.nHeight) / 2 +
        ShadowBaseReward(claim_index.nHeight) / 2;
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(
        CScript{} << OP_5, {}, {CTxOut(expected_pow_pool, quantum_payout)}));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof_a, 0));
    claim_block.vtx.push_back(MakePowClaimTx(pow_target, pow_proof_b, 1));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, {{1, CScript{} << OP_5}, {2, pow_target}, {3, pow_target}});

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_CHECK(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, expected_pow_pool);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], expected_pow_pool);
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
    BOOST_CHECK_EQUAL(winner->credited_amount, expected_pow_pool - CENT);
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
    BOOST_CHECK_EQUAL(amounts[1], expected_pow_pool - CENT);
    BOOST_CHECK_EQUAL(amounts[0] + amounts[1], expected_pow_pool);
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &claim_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.pow_count, 1U);
}

BOOST_AUTO_TEST_CASE(pow_shadow_qqp3_late_claims_are_bounded_and_emission_neutral)
{
    const int origin_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    const uint256 origin_parent = uint256S("1010");
    const uint256 inclusion_parent = uint256S("2020");
    const CScript late_target = CScript{} << OP_2;
    const CScript current_target = CScript{} << OP_3;
    const CScript late_payout = QuantumScript(0x90);
    const CScript current_payout = QuantumScript(0x91);

    ShadowPowWork late_work;
    late_work.valid = true;
    late_work.origin_bound = true;
    late_work.input_bound = false;
    late_work.height = origin_height;
    late_work.prev_hash = origin_parent;
    late_work.bits = 10;
    late_work.target = late_target;
    late_work.quantum_payout_script = late_payout;
    std::vector<unsigned char> late_proof;
    BOOST_REQUIRE(GrindShadowPowWork(late_work, 0, 1, 100'000, late_proof));
    BOOST_REQUIRE_GT(late_proof.size(), GetShadowPrefix().size() + 4);
    BOOST_CHECK_EQUAL(late_proof[GetShadowPrefix().size() + 3], '3');

    ShadowPowWork current_work = late_work;
    current_work.height = origin_height + 1;
    current_work.prev_hash = inclusion_parent;
    current_work.target = current_target;
    current_work.quantum_payout_script = current_payout;
    std::vector<unsigned char> current_proof;
    BOOST_REQUIRE(GrindShadowPowWork(current_work, 0, 1, 100'000,
                                    current_proof));

    const CAmount late_fee = CENT / 2;
    const CAmount current_fee = CENT / 4;
    CBlock mixed_block;
    mixed_block.vtx = {
        MakeCoinbaseTx(CScript{} << OP_4),
        MakeCoinstakeTx(CScript{} << OP_5),
        MakePowClaimTx(late_target, late_proof, 0),
        MakePowClaimTx(current_target, current_proof, 1),
    };
    CBlockUndo mixed_undo = MakeUndoWithInputScripts(
        mixed_block, {{1, CScript{} << OP_5}, {2, late_target},
                      {3, current_target}});
    SetUndoInputValue(mixed_undo, 2, COIN + late_fee);
    SetUndoInputValue(mixed_undo, 3, COIN + current_fee);

    ShadowPowAccountingContext context;
    context.valid = true;
    context.canonical_rule_active = true;
    context.height = origin_height + 1;
    context.previous_block_hash = inclusion_parent;
    context.credited_pow_pool = 290 * COIN;
    context.target_bits = current_work.bits;
    context.late_origins.push_back(ShadowPowOriginContext{
        static_cast<uint32_t>(origin_height), origin_parent, late_work.bits});

    std::vector<ShadowPowClaimAccounting> accounting;
    ShadowPowClaimAggregate aggregate;
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
        context, mixed_block, &mixed_undo, accounting, &aggregate) ==
        ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 2U);
    const auto late = std::find_if(
        accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition ==
                   ShadowPowClaimDisposition::REIMBURSED_LATE;
        });
    const auto winner = std::find_if(
        accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        });
    BOOST_REQUIRE(late != accounting.end());
    BOOST_REQUIRE(winner != accounting.end());
    BOOST_CHECK(late->origin_bound);
    BOOST_CHECK_EQUAL(late->origin_height,
                      static_cast<uint32_t>(origin_height));
    BOOST_CHECK_EQUAL(late->inclusion_height,
                      static_cast<uint32_t>(origin_height + 1));
    BOOST_CHECK_EQUAL(late->origin_age, 1U);
    BOOST_CHECK_EQUAL(late->credited_amount, late_fee);
    BOOST_CHECK_EQUAL(winner->credited_amount,
                      context.credited_pow_pool - late_fee);
    BOOST_CHECK_EQUAL(late->credited_amount + winner->credited_amount,
                      context.credited_pow_pool);
    BOOST_CHECK_EQUAL(aggregate.winner_count, 1U);
    BOOST_CHECK_EQUAL(aggregate.reimbursed_late_count, 1U);

    CBlock late_only_block;
    late_only_block.vtx = {
        MakeCoinbaseTx(CScript{} << OP_4),
        MakeCoinstakeTx(CScript{} << OP_5),
        MakePowClaimTx(late_target, late_proof, 0),
    };
    CBlockUndo late_only_undo = MakeUndoWithInputScripts(
        late_only_block, {{1, CScript{} << OP_5}, {2, late_target}});
    SetUndoInputValue(late_only_undo, 2, COIN + late_fee);
    accounting.clear();
    aggregate = {};
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
        context, late_only_block, &late_only_undo, accounting, &aggregate) ==
        ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 1U);
    BOOST_CHECK(accounting[0].disposition ==
                ShadowPowClaimDisposition::REIMBURSED_LATE);
    BOOST_CHECK_EQUAL(accounting[0].credited_amount, late_fee);
    BOOST_CHECK_EQUAL(aggregate.winner_count, 0U);
    BOOST_CHECK_EQUAL(aggregate.reimbursed_late_count, 1U);

    ShadowPowAccountingContext expired = context;
    expired.height = origin_height + SHADOW_POW_LATE_ORIGIN_WINDOW + 1;
    expired.previous_block_hash = uint256S("3030");
    expired.late_origins.clear();
    accounting.clear();
    aggregate = {};
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
        expired, late_only_block, &late_only_undo, accounting, &aggregate) ==
        ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 1U);
    BOOST_CHECK(accounting[0].disposition ==
                ShadowPowClaimDisposition::ORIGIN_EXPIRED);
    BOOST_CHECK_EQUAL(accounting[0].credited_amount, 0);
    BOOST_CHECK_EQUAL(aggregate.origin_expired_count, 1U);

    ShadowPowAccountingContext off_branch = context;
    off_branch.late_origins.clear();
    accounting.clear();
    aggregate = {};
    BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
        off_branch, late_only_block, &late_only_undo, accounting, &aggregate) ==
        ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 1U);
    BOOST_CHECK(accounting[0].disposition ==
                ShadowPowClaimDisposition::ORIGIN_MISMATCH);
    BOOST_CHECK_EQUAL(aggregate.origin_mismatch_count, 1U);

    // Mempool policy rejects an attacker-selected off-branch origin without
    // treating it as node failure, but a matching active ancestor whose
    // mandatory authenticated QQPUND marker is absent fails closed.
    CCoinsView base;
    CCoinsViewCache view{&base, true};
    AddCoinForScript(view, COutPoint{uint256{2}, 0}, COIN + late_fee,
                     late_target);
    CBlockIndex origin_parent_index;
    origin_parent_index.nHeight = origin_height - 1;
    origin_parent_index.nTime = 1'900'000'000;
    origin_parent_index.phashBlock = &origin_parent;
    uint256 origin_block_hash = uint256S("4040");
    CBlockIndex origin_block_index;
    origin_block_index.nHeight = origin_height;
    origin_block_index.nTime = origin_parent_index.nTime + 64;
    origin_block_index.pprev = &origin_parent_index;
    origin_block_index.phashBlock = &origin_block_hash;
    AddPoolForTest(view, origin_block_index, 290 * COIN, 0, 0);

    std::string reject_reason;
    const CTransactionRef late_tx =
        MakePowClaimTx(late_target, late_proof, 0);
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                    *late_tx, &origin_block_index, view, true,
                    reject_reason) ==
                ShadowProofValidationResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK_EQUAL(reject_reason, "local-shadow-proof-origin-state");

    ShadowPowWork off_branch_work = late_work;
    off_branch_work.prev_hash = uint256S("5050");
    std::vector<unsigned char> off_branch_proof;
    BOOST_REQUIRE(GrindShadowPowWork(off_branch_work, 0, 1, 100'000,
                                    off_branch_proof));
    reject_reason.clear();
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                    *MakePowClaimTx(late_target, off_branch_proof, 0),
                    &origin_block_index, view, true, reject_reason) ==
                ShadowProofValidationResult::INVALID);
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-origin-mismatch");
}

BOOST_AUTO_TEST_CASE(pow_shadow_qqp3_preserves_v30_1_0_qqp2_qqp3_and_rank_v1)
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

    const CScript staker_target = CScript{} << OP_TRUE;
    const CScript target_a = CScript{} << OP_2;
    const CScript target_b = CScript{} << OP_3;
    const CScript payout_a = QuantumScript(0x84);
    const CScript payout_b = QuantumScript(0x85);
    // The same intended claim height has both historical QQP2 and QQP3 wire
    // candidates.  Q3 is explicitly constructed here because this unit test
    // passes a compressed consensus schedule rather than mutating global
    // mainnet parameters.
    std::vector<unsigned char> qqp2_proof;
    BOOST_REQUIRE(MineShadowProofData(target_a, payout_a, &prev_index, view,
                                      100'000, qqp2_proof));
    ShadowPowWork qqp3_work = PrepareShadowPowWork(
        target_b, payout_b, &prev_index, view);
    BOOST_REQUIRE(qqp3_work.valid);
    qqp3_work.origin_bound = true;
    qqp3_work.input_bound = false;
    std::vector<unsigned char> qqp3_proof;
    BOOST_REQUIRE(GrindShadowPowWork(qqp3_work, 0, 1, 100'000,
                                     qqp3_proof));
    BOOST_CHECK_EQUAL(qqp2_proof[GetShadowPrefix().size() + 3], '2');
    BOOST_CHECK_EQUAL(qqp3_proof[GetShadowPrefix().size() + 3], '3');

    const CTransactionRef tx_a = MakePowClaimTx(target_a, qqp2_proof, 0);
    const CTransactionRef tx_b = MakePowClaimTx(target_b, qqp3_proof, 1);
    const CAmount actual_fee = CENT / 2;

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, SHADOW_REWARD_START_HEIGHT + 1, &prev_index,
              claim_hash);
    CBlock block_ab;
    block_ab.vtx = {MakeCoinbaseTx(CScript{} << OP_4),
                    MakeCoinstakeTx(staker_target), tx_a, tx_b};
    CBlockUndo undo_ab = MakeUndoWithInputScripts(
        block_ab, {{1, staker_target}, {2, target_a}, {3, target_b}});
    SetUndoInputValue(undo_ab, 2, COIN + actual_fee);
    SetUndoInputValue(undo_ab, 3, COIN + actual_fee);

    CBlock block_ba;
    block_ba.vtx = {MakeCoinbaseTx(CScript{} << OP_4),
                    MakeCoinstakeTx(staker_target), tx_b, tx_a};
    CBlockUndo undo_ba = MakeUndoWithInputScripts(
        block_ba, {{1, staker_target}, {2, target_b}, {3, target_a}});
    SetUndoInputValue(undo_ba, 2, COIN + actual_fee);
    SetUndoInputValue(undo_ba, 3, COIN + actual_fee);

    Consensus::Params historical = Params().GetConsensus();
    historical.nShadowCompetingClaimsActivationHeight = claim_index.nHeight + 1;
    std::map<CScript, CAmount> historical_ab;
    std::map<CScript, CAmount> historical_ba;
    CAmount historical_ab_total{0};
    CAmount historical_ba_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        view, block_ab, &claim_index, &undo_ab, historical,
        historical_ab, historical_ab_total));
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        view, block_ba, &claim_index, &undo_ba, historical,
        historical_ba, historical_ba_total));
    // Before Q3, only the non-origin-bound QQP2 candidate is valid. The
    // first-valid historical allocation therefore remains unchanged even if
    // the QQP3-shaped transaction comes first in the block.
    BOOST_REQUIRE_EQUAL(historical_ab.size(), 1U);
    BOOST_REQUIRE_EQUAL(historical_ba.size(), 1U);
    BOOST_CHECK_EQUAL(historical_ab[payout_a], 580 * COIN);
    BOOST_CHECK_EQUAL(historical_ba[payout_a], 580 * COIN);
    BOOST_CHECK_EQUAL(historical_ab_total, 580 * COIN);
    BOOST_CHECK_EQUAL(historical_ba_total, historical_ab_total);
    BOOST_CHECK(historical_ab == historical_ba);

    std::vector<ShadowPowClaimAccounting> preactivation_accounting;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(
        view, block_ab, &claim_index, &undo_ab, historical,
        preactivation_accounting) == ShadowPowAccountingResult::OK);
    BOOST_CHECK(preactivation_accounting.empty());

    Consensus::Params canonical = historical;
    canonical.nShadowCompetingClaimsActivationHeight = claim_index.nHeight;
    std::map<CScript, CAmount> canonical_ab;
    std::map<CScript, CAmount> canonical_ba;
    CAmount canonical_ab_total{0};
    CAmount canonical_ba_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        view, block_ab, &claim_index, &undo_ab, canonical,
        canonical_ab, canonical_ab_total));
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        view, block_ba, &claim_index, &undo_ba, canonical,
        canonical_ba, canonical_ba_total));
    // v30.1.0 Q3 accepts both wire formats.  It only adds canonical
    // allocation, QQP3 origin/late semantics, and rank-v1; QQP4 remains
    // disabled in this schedule.
    BOOST_CHECK(!canonical.IsShadowQQP4Active(claim_index.nHeight));
    BOOST_CHECK(canonical_ab == canonical_ba);
    BOOST_REQUIRE_EQUAL(canonical_ab.size(), 2U);
    BOOST_CHECK_EQUAL(canonical_ab_total, 580 * COIN);
    BOOST_CHECK_EQUAL(canonical_ba_total, canonical_ab_total);

    ShadowPowAccountingContext q3_context;
    BOOST_REQUIRE(PrepareShadowPowClaimAccounting(
                      view, block_ab, &claim_index, canonical, q3_context) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE(q3_context.valid);
    BOOST_CHECK(!q3_context.qqp4_rule_active);
    std::vector<ShadowPowClaimAccounting> activation_accounting;
    ShadowPowClaimAggregate activation_aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(
        view, block_ab, &claim_index, &undo_ab, canonical,
        activation_accounting, &activation_aggregate) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(activation_accounting.size(), 2U);
    BOOST_CHECK_EQUAL(std::count_if(
        activation_accounting.begin(), activation_accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(
        activation_accounting.begin(), activation_accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition ==
                ShadowPowClaimDisposition::REIMBURSED_LOSER;
        }), 1U);
    for (const ShadowPowClaimAccounting& entry : activation_accounting) {
        const std::vector<unsigned char>& proof =
            entry.source_txid == tx_a->GetHash() ? qqp2_proof : qqp3_proof;
        const std::vector<unsigned char> proof_payload(
            proof.begin() + GetShadowPrefix().size(), proof.end());
        CHashWriter rank;
        rank << std::string{"Quantum Quasar Canonical POW Claim Rank v1"}
             << claim_index.nHeight << prev_index.GetBlockHash()
             << entry.source_txid << entry.source_vout << proof_payload;
        BOOST_CHECK(entry.canonical_rank == rank.GetHash());
        BOOST_CHECK(!entry.input_bound);
    }

    // Differential-vector check for the exact deployed QQP3 accounting
    // stream.  In particular, proof_version/input_bound/outpoint are *not*
    // serialized under the v2 domain before QQP4 activation.
    CHashWriter observations;
    observations << std::string{"Quantum Quasar POW Claim Observations v1"}
                 << q3_context.height << q3_context.previous_block_hash
                 << block_ab.GetHash();
    for (const auto& [tx, proof] : std::array{
             std::pair{tx_a, std::cref(qqp2_proof)},
             std::pair{tx_b, std::cref(qqp3_proof)}}) {
        const std::vector<unsigned char> payload(
            proof.get().begin() + GetShadowPrefix().size(), proof.get().end());
        observations << tx->GetHash() << uint32_t{1} << payload
                     << true << uint32_t{1};
    }
    CHashWriter q3_commitment;
    q3_commitment << std::string{"Quantum Quasar Bounded POW Claim Accounting v2"}
                  << q3_context.height << q3_context.previous_block_hash
                  << q3_context.credited_pow_pool << q3_context.target_bits
                  << observations.GetHash()
                  << activation_aggregate.observed_count
                  << activation_aggregate.evaluated_count
                  << activation_aggregate.invalid_location_count
                  << activation_aggregate.malformed_transaction_count
                  << activation_aggregate.invalid_proof_count
                  << activation_aggregate.wrong_mode_count
                  << activation_aggregate.unknown_mode_count
                  << activation_aggregate.origin_mismatch_count
                  << activation_aggregate.origin_expired_count
                  << activation_aggregate.input_mismatch_count
                  << activation_aggregate.invalid_base_fee_count
                  << activation_aggregate.evaluation_limit_count
                  << activation_aggregate.winner_count
                  << activation_aggregate.reimbursed_loser_count
                  << activation_aggregate.reimbursed_late_count;
    for (const ShadowPowClaimAccounting& entry : activation_accounting) {
        q3_commitment << entry.source_txid << entry.source_vout
                      << entry.canonical_rank << entry.payout_script
                      << entry.base_fee << entry.credited_amount
                      << entry.base_fee_known << entry.origin_bound
                      << entry.origin_height
                      << entry.origin_previous_block_hash
                      << entry.inclusion_height << entry.origin_age
                      << static_cast<uint8_t>(entry.disposition);
    }
    BOOST_CHECK(activation_aggregate.accounting_commitment ==
                q3_commitment.GetHash());

    // QQP1 remains invalid, while Q3 continues to accept QQP2 and QQP3. This
    // is the pre-QQP4 compatibility vector that protects replay behavior.
    const std::vector<unsigned char> qqp1 =
        MakeQQP1ProofData(/*nonce=*/11, target_a);
    CBlock q3_formats_block;
    q3_formats_block.vtx = {
        MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target),
        MakePowClaimTx(target_a, qqp1, 0),
        MakePowClaimTx(target_a, qqp2_proof, 1),
        MakePowClaimTx(target_b, qqp3_proof, 2),
    };
    CBlockUndo q3_formats_undo = MakeUndoWithInputScripts(
        q3_formats_block,
        {{1, staker_target}, {2, target_a}, {3, target_a}, {4, target_b}});
    SetUndoInputValue(q3_formats_undo, 2, COIN + actual_fee);
    SetUndoInputValue(q3_formats_undo, 3, COIN + actual_fee);
    SetUndoInputValue(q3_formats_undo, 4, COIN + actual_fee);
    std::vector<ShadowPowClaimAccounting> q3_accounting;
    ShadowPowClaimAggregate q3_aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(
                      view, q3_formats_block, &claim_index,
                      &q3_formats_undo, canonical, q3_accounting,
                      &q3_aggregate) == ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(q3_accounting.size(), 3U);
    BOOST_CHECK_EQUAL(std::count_if(
        q3_accounting.begin(), q3_accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::INVALID_PROOF;
        }), 1U);
    BOOST_CHECK_EQUAL(q3_aggregate.winner_count, 1U);
    BOOST_CHECK_EQUAL(q3_aggregate.reimbursed_loser_count, 1U);

    // Preserve v30.1.0 invalid-proof precedence byte-for-byte. The first
    // payload is syntactically valid QQP2 but deliberately fails work while
    // its carrier has both a bad fee and a wrong input. Two deterministic
    // QQP1 payloads then exercise invalid fee and input paths independently.
    // The final carrier is a structurally valid QQP4 payload with a valid fee
    // and matching input. Before QQP4, every one must stop at INVALID_PROOF:
    // fee/input classification cannot alter the QQP3 aggregate or v2 hash.
    const ShadowPowWork q2_work = PrepareShadowPowWork(
        target_a, payout_a, &prev_index, view);
    BOOST_REQUIRE(q2_work.valid);
    BOOST_REQUIRE(ValidateShadowPowProofForWork(q2_work, qqp2_proof));
    const size_t nonce_offset = GetShadowPrefix().size() + 5;
    BOOST_REQUIRE_GT(qqp2_proof.size(), nonce_offset);
    std::vector<unsigned char> bad_work_qqp2;
    for (uint16_t delta = 1; delta <= 255; ++delta) {
        bad_work_qqp2 = qqp2_proof;
        bad_work_qqp2[nonce_offset] ^= static_cast<unsigned char>(delta);
        if (!ValidateShadowPowProofForWork(q2_work, bad_work_qqp2)) break;
    }
    BOOST_REQUIRE(!bad_work_qqp2.empty());
    BOOST_REQUIRE(!ValidateShadowPowProofForWork(q2_work, bad_work_qqp2));

    ShadowPowWork malicious_qqp4_work = q2_work;
    malicious_qqp4_work.target = target_b;
    malicious_qqp4_work.quantum_payout_script = payout_b;
    malicious_qqp4_work.origin_bound = true;
    malicious_qqp4_work.input_bound = true;
    malicious_qqp4_work.claim_outpoint = COutPoint{uint256{2}, 8};
    std::vector<unsigned char> malicious_qqp4;
    BOOST_REQUIRE(GrindShadowPowWork(malicious_qqp4_work,
                                     /*start_nonce=*/0,
                                     /*nonce_step=*/1,
                                     /*max_tries=*/100'000,
                                     malicious_qqp4));
    BOOST_REQUIRE(ValidateShadowPowProofForWork(malicious_qqp4_work,
                                                malicious_qqp4));
    const std::vector<unsigned char> invalid_qqp1_low_fee =
        MakeQQP1ProofData(/*nonce=*/100, target_a);
    const std::vector<unsigned char> invalid_qqp1_wrong_input =
        MakeQQP1ProofData(/*nonce=*/101, target_a);
    const CTransactionRef bad_work_tx = MakePowClaimTx(
        target_a, bad_work_qqp2, 7);
    const CTransactionRef invalid_low_fee_tx = MakePowClaimTx(
        target_a, invalid_qqp1_low_fee, 9);
    const CTransactionRef invalid_wrong_input_tx = MakePowClaimTx(
        target_a, invalid_qqp1_wrong_input, 10);
    const CTransactionRef malicious_qqp4_tx = MakePowClaimTx(
        target_b, malicious_qqp4, 8);
    CBlock invalid_order_block;
    invalid_order_block.vtx = {
        MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target),
        bad_work_tx, invalid_low_fee_tx, invalid_wrong_input_tx,
        malicious_qqp4_tx,
    };
    const CScript wrong_input = CScript{} << OP_5;
    CBlockUndo invalid_order_undo = MakeUndoWithInputScripts(
        invalid_order_block,
        {{1, staker_target}, {2, wrong_input}, {3, target_a},
         {4, target_b}, {5, target_b}});
    // The QQP2 and first QQP1 carrier spend less than they create. The second
    // QQP1 carrier has a valid fee but its actual input script differs from
    // its target. The QQP4 carrier has a valid fee and matching bound input.
    SetUndoInputValue(invalid_order_undo, 2, COIN / 2);
    SetUndoInputValue(invalid_order_undo, 3, COIN / 2);
    SetUndoInputValue(invalid_order_undo, 4, COIN + actual_fee);
    SetUndoInputValue(invalid_order_undo, 5, COIN + actual_fee);

    ShadowPowAccountingContext invalid_order_context;
    BOOST_REQUIRE(PrepareShadowPowClaimAccounting(
                      view, invalid_order_block, &claim_index, canonical,
                      invalid_order_context) == ShadowPowAccountingResult::OK);
    BOOST_REQUIRE(invalid_order_context.valid);
    BOOST_CHECK(!invalid_order_context.qqp4_rule_active);
    std::vector<ShadowPowClaimAccounting> invalid_order_accounting;
    ShadowPowClaimAggregate invalid_order_aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(
                      view, invalid_order_block, &claim_index,
                      &invalid_order_undo, canonical,
                      invalid_order_accounting,
                      &invalid_order_aggregate) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(invalid_order_accounting.size(), 4U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.observed_count, 4U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.evaluated_count, 4U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.invalid_proof_count, 4U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.invalid_base_fee_count, 0U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.input_mismatch_count, 0U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.winner_count, 0U);
    BOOST_CHECK_EQUAL(invalid_order_aggregate.reimbursed_loser_count, 0U);

    const auto bad_work_row = std::find_if(
        invalid_order_accounting.begin(), invalid_order_accounting.end(),
        [&](const ShadowPowClaimAccounting& entry) {
            return entry.source_txid == bad_work_tx->GetHash();
        });
    const auto malicious_qqp4_row = std::find_if(
        invalid_order_accounting.begin(), invalid_order_accounting.end(),
        [&](const ShadowPowClaimAccounting& entry) {
            return entry.source_txid == malicious_qqp4_tx->GetHash();
        });
    const auto invalid_low_fee_row = std::find_if(
        invalid_order_accounting.begin(), invalid_order_accounting.end(),
        [&](const ShadowPowClaimAccounting& entry) {
            return entry.source_txid == invalid_low_fee_tx->GetHash();
        });
    const auto invalid_wrong_input_row = std::find_if(
        invalid_order_accounting.begin(), invalid_order_accounting.end(),
        [&](const ShadowPowClaimAccounting& entry) {
            return entry.source_txid == invalid_wrong_input_tx->GetHash();
        });
    BOOST_REQUIRE(bad_work_row != invalid_order_accounting.end());
    BOOST_REQUIRE(malicious_qqp4_row != invalid_order_accounting.end());
    BOOST_REQUIRE(invalid_low_fee_row != invalid_order_accounting.end());
    BOOST_REQUIRE(invalid_wrong_input_row != invalid_order_accounting.end());
    BOOST_CHECK_EQUAL(bad_work_row->proof_version, 2U);
    BOOST_CHECK(!bad_work_row->base_fee_known);
    BOOST_CHECK_EQUAL(invalid_low_fee_row->proof_version, 1U);
    BOOST_CHECK(!invalid_low_fee_row->base_fee_known);
    BOOST_CHECK_EQUAL(invalid_wrong_input_row->proof_version, 1U);
    BOOST_CHECK(!invalid_wrong_input_row->base_fee_known);
    BOOST_CHECK_EQUAL(malicious_qqp4_row->proof_version, 0U);
    BOOST_CHECK(malicious_qqp4_row->payout_script.empty());
    BOOST_CHECK(!malicious_qqp4_row->base_fee_known);

    // Explorer-facing structural metadata receives the same activation
    // context. A historical Q3 block must continue to expose future QQP4
    // magic as malformed, rather than retroactively advertising it as PoW.
    ShadowProofObservationSummary invalid_order_summary;
    const std::vector<ShadowProofObservation> invalid_order_observations_out =
        GetShadowProofObservations(invalid_order_block, canonical,
                                   claim_index.nHeight,
                                   invalid_order_summary);
    const auto malicious_qqp4_observation = std::find_if(
        invalid_order_observations_out.begin(),
        invalid_order_observations_out.end(),
        [&](const ShadowProofObservation& observation) {
            return observation.source_txid == malicious_qqp4_tx->GetHash();
        });
    BOOST_REQUIRE(malicious_qqp4_observation !=
                  invalid_order_observations_out.end());
    BOOST_CHECK(malicious_qqp4_observation->mode ==
                ShadowProofPayloadMode::MALFORMED);
    BOOST_CHECK(ClassifyShadowProofPayload(malicious_qqp4) ==
                ShadowProofPayloadMode::MALFORMED);
    BOOST_CHECK(ClassifyShadowProofPayload(malicious_qqp4,
                                           /*qqp4_active=*/true) ==
                ShadowProofPayloadMode::POW);

    CHashWriter invalid_order_observations;
    invalid_order_observations
        << std::string{"Quantum Quasar POW Claim Observations v1"}
        << invalid_order_context.height
        << invalid_order_context.previous_block_hash
        << invalid_order_block.GetHash();
    for (const auto& [tx, proof] : std::array{
             std::pair{bad_work_tx, std::cref(bad_work_qqp2)},
             std::pair{invalid_low_fee_tx, std::cref(invalid_qqp1_low_fee)},
             std::pair{invalid_wrong_input_tx,
                       std::cref(invalid_qqp1_wrong_input)},
             std::pair{malicious_qqp4_tx, std::cref(malicious_qqp4)}}) {
        const std::vector<unsigned char> payload(
            proof.get().begin() + GetShadowPrefix().size(),
            proof.get().end());
        invalid_order_observations << tx->GetHash() << uint32_t{1} << payload
                                   << true << uint32_t{1};
    }
    CHashWriter invalid_order_commitment;
    invalid_order_commitment
        << std::string{"Quantum Quasar Bounded POW Claim Accounting v2"}
        << invalid_order_context.height
        << invalid_order_context.previous_block_hash
        << invalid_order_context.credited_pow_pool
        << invalid_order_context.target_bits
        << invalid_order_observations.GetHash()
        << invalid_order_aggregate.observed_count
        << invalid_order_aggregate.evaluated_count
        << invalid_order_aggregate.invalid_location_count
        << invalid_order_aggregate.malformed_transaction_count
        << invalid_order_aggregate.invalid_proof_count
        << invalid_order_aggregate.wrong_mode_count
        << invalid_order_aggregate.unknown_mode_count
        << invalid_order_aggregate.origin_mismatch_count
        << invalid_order_aggregate.origin_expired_count
        << invalid_order_aggregate.input_mismatch_count
        << invalid_order_aggregate.invalid_base_fee_count
        << invalid_order_aggregate.evaluation_limit_count
        << invalid_order_aggregate.winner_count
        << invalid_order_aggregate.reimbursed_loser_count
        << invalid_order_aggregate.reimbursed_late_count;
    for (const ShadowPowClaimAccounting& entry : invalid_order_accounting) {
        invalid_order_commitment
            << entry.source_txid << entry.source_vout
            << entry.canonical_rank << entry.payout_script
            << entry.base_fee << entry.credited_amount
            << entry.base_fee_known << entry.origin_bound
            << entry.origin_height << entry.origin_previous_block_hash
            << entry.inclusion_height << entry.origin_age
            << static_cast<uint8_t>(entry.disposition);
    }
    BOOST_CHECK(invalid_order_aggregate.accounting_commitment ==
                invalid_order_commitment.GetHash());
}

BOOST_AUTO_TEST_CASE(pow_shadow_canonical_winner_is_order_independent_and_replay_safe)
{
    ShadowFailureGuard failure_guard;
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

    const int activation_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    BOOST_REQUIRE_GT(activation_height, prev_index.nHeight);
    uint256 activation_parent_hash;
    CBlockIndex activation_parent;
    InitIndex(activation_parent, activation_height - 1, &prev_index,
              activation_parent_hash);
    BOOST_REQUIRE(AdvanceGoldRushInventoryTip(seed_view, &activation_parent));

    CCoinsViewCache view{&seed_view, true};
    const CScript target_a = CScript{} << OP_2;
    const CScript target_b = CScript{} << OP_3;
    const CScript payout_a = QuantumScript(0x75);
    const CScript payout_b = QuantumScript(0x76);
    std::vector<unsigned char> proof_a;
    std::vector<unsigned char> proof_b;
    BOOST_REQUIRE(MineShadowProofData(target_a, payout_a, &activation_parent,
                                      view, 100'000, proof_a));
    BOOST_REQUIRE(MineShadowProofData(target_b, payout_b, &activation_parent,
                                      view, 100'000, proof_b));

    const CTransactionRef tx_a = MakePowClaimTx(target_a, proof_a, 0);
    const CTransactionRef tx_b = MakePowClaimTx(target_b, proof_b, 1);
    const CAmount actual_fee = CENT / 2;

    uint256 claim_hash_a;
    CBlockIndex claim_index_a;
    InitIndex(claim_index_a, activation_height, &activation_parent,
              claim_hash_a);
    CBlock block_a;
    block_a.vtx = {MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target), tx_a, tx_b};
    CBlockUndo undo_a = MakeUndoWithInputScripts(
        block_a, {{1, staker_target}, {2, target_a}, {3, target_b}});
    SetUndoInputValue(undo_a, 2, COIN + actual_fee);
    SetUndoInputValue(undo_a, 3, COIN + actual_fee);

    uint256 claim_hash_b;
    CBlockIndex claim_index_b;
    InitIndex(claim_index_b, activation_height, &activation_parent,
              claim_hash_b);
    claim_hash_b.SetHex("0f1206");
    CBlock block_b;
    block_b.vtx = {MakeCoinbaseTx(CScript{} << OP_4), MakeCoinstakeTx(staker_target), tx_b, tx_a};
    CBlockUndo undo_b = MakeUndoWithInputScripts(
        block_b, {{1, staker_target}, {2, target_b}, {3, target_a}});
    SetUndoInputValue(undo_b, 2, COIN + actual_fee);
    SetUndoInputValue(undo_b, 3, COIN + actual_fee);

    const CAmount expected_pow_pool =
        ShadowBaseReward(prev_index.nHeight) / 2 +
        ShadowBaseReward(claim_index_a.nHeight) / 2;

    std::map<CScript, CAmount> payouts_a;
    std::map<CScript, CAmount> payouts_b;
    CAmount total_a{0};
    CAmount total_b{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, block_a, &claim_index_a, &undo_a,
                                            payouts_a, total_a));
    BOOST_REQUIRE(GetShadowPowDirectPayouts(view, block_b, &claim_index_b, &undo_b,
                                            payouts_b, total_b));
    BOOST_CHECK(payouts_a == payouts_b);
    BOOST_CHECK_EQUAL(total_a, expected_pow_pool);
    BOOST_CHECK_EQUAL(total_b, total_a);
    BOOST_REQUIRE_EQUAL(payouts_a.size(), 2U);
    std::array<CAmount, 2> ordered_amounts{payouts_a[payout_a], payouts_a[payout_b]};
    std::sort(ordered_amounts.begin(), ordered_amounts.end());
    BOOST_CHECK_EQUAL(ordered_amounts[0], actual_fee);
    BOOST_CHECK_EQUAL(ordered_amounts[1], expected_pow_pool - actual_fee);

    std::vector<ShadowPowClaimAccounting> accounting_a;
    std::vector<ShadowPowClaimAccounting> accounting_b;
    ShadowPowAccountingContext context_a;
    BOOST_REQUIRE(PrepareShadowPowClaimAccounting(view, &claim_index_a,
                                                  context_a) ==
                  ShadowPowAccountingResult::OK);
    BOOST_CHECK(context_a.valid);

    // Explorer/index evaluation is all-or-nothing. Neither a simulated
    // allocation failure nor an Argon2 library failure may expose a partial
    // classification prefix to a caller, and the exact bytes must be
    // retryable after the local condition clears.
    accounting_a.push_back(ShadowPowClaimAccounting{});
    SetShadowAllocationFailureForTesting(
        ShadowAllocationFailurePoint::ACCOUNTING);
    BOOST_CHECK(EvaluateShadowPowClaimAccounting(context_a, block_a, &undo_a,
                                                  accounting_a) ==
                ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK(accounting_a.empty());
    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(EvaluateShadowPowClaimAccounting(context_a, block_a, &undo_a,
                                                  accounting_a) ==
                ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK(accounting_a.empty());
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

    const ShadowGoldRushInfo before_local_failures =
        GetShadowGoldRushInfo(view, &activation_parent);
    const uint256 best_block_before_local_failures = view.GetBestBlock();
    const std::vector<ShadowSyntheticPayoutCoin> payouts_before_local_failures =
        GetAppliedShadowClaimPayoutCoins(
            view, claim_index_a.nHeight, claim_index_a.GetBlockHash(),
            claim_index_a.GetBlockTime());

    SetShadowAllocationFailureForTesting(ShadowAllocationFailurePoint::APPLY);
    BOOST_CHECK(ApplyShadowBlockResult(view, block_a, &claim_index_a, &undo_a) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    SetShadowAllocationFailureForTesting(
        ShadowAllocationFailurePoint::APPLY_AFTER_STAGED_MUTATION);
    BOOST_CHECK(ApplyShadowBlockResult(view, block_a, &claim_index_a, &undo_a) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    SetShadowAllocationFailureForTesting(
        ShadowAllocationFailurePoint::ACCOUNTING);
    BOOST_CHECK(ApplyShadowBlockResult(view, block_a, &claim_index_a, &undo_a) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);
    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(ApplyShadowBlockResult(view, block_a, &claim_index_a, &undo_a) ==
                ShadowApplyResult::LOCAL_INTERNAL_ERROR);

    const ShadowGoldRushInfo after_local_failures =
        GetShadowGoldRushInfo(view, &activation_parent);
    BOOST_CHECK_EQUAL(after_local_failures.pow_amount,
                      before_local_failures.pow_amount);
    BOOST_CHECK_EQUAL(after_local_failures.pos_amount,
                      before_local_failures.pos_amount);
    BOOST_CHECK_EQUAL(after_local_failures.claimed_amount,
                      before_local_failures.claimed_amount);
    BOOST_CHECK_EQUAL(after_local_failures.pow_count,
                      before_local_failures.pow_count);
    BOOST_CHECK_EQUAL(after_local_failures.pos_count,
                      before_local_failures.pos_count);
    BOOST_CHECK(view.GetBestBlock() == best_block_before_local_failures);
    const std::vector<ShadowSyntheticPayoutCoin> payouts_after_local_failures =
        GetAppliedShadowClaimPayoutCoins(
            view, claim_index_a.nHeight, claim_index_a.GetBlockHash(),
            claim_index_a.GetBlockTime());
    BOOST_CHECK_EQUAL(payouts_after_local_failures.size(),
                      payouts_before_local_failures.size());

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

// Registered below, after the file-wide BasicTestingSetup suite is closed.
static void CheckQQP4PayloadModesAreStrictlyBoundToPowAccounting()
{
    CCoinsView base;
    CCoinsViewCache seed_view{&base, true};

    const CScript staker_target = CScript{} << OP_TRUE;
    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x8a);
    AddCoinForScript(seed_view, COutPoint{uint256::ONE, 0},
                     10'000 * COIN, staker_target);
    for (uint32_t input_n = 0; input_n < 4; ++input_n) {
        AddCoinForScript(seed_view, COutPoint{uint256{2}, input_n},
                         COIN, pow_target);
    }

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr,
              whitelist_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(seed_view, &whitelist_index));

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index,
              reward_hash);
    CBlock reward_block;
    reward_block.vtx = {MakeCoinbaseTx(CScript{} << OP_TRUE),
                        MakeCoinstakeTx(staker_target)};
    CBlockUndo reward_undo = MakeUndoWithInputScripts(
        reward_block, {{1, staker_target}});
    BOOST_REQUIRE(ApplyShadowBlock(seed_view, reward_block, &reward_index,
                                  &reward_undo));

    const int activation_height =
        Params().GetConsensus().nShadowQQP4ActivationHeight;
    BOOST_REQUIRE_GT(activation_height, reward_index.nHeight);
    // Apply every intervening Gold Rush block. The pool and active-signal
    // markers are branch-authenticated at each height, so merely advancing the
    // inventory tip would create a state combination that no connected chain
    // can have and would test a false local failure instead of QQP4 behavior.
    std::array<CBlockIndex, 10> activation_path;
    std::array<uint256, 10> activation_path_hashes;
    BOOST_REQUIRE_EQUAL(static_cast<int>(activation_path.size()),
                        activation_height - reward_index.nHeight - 1);
    CBlockIndex* activation_parent = &reward_index;
    for (size_t i = 0; i < activation_path.size(); ++i) {
        InitIndex(activation_path[i], activation_parent->nHeight + 1,
                  activation_parent, activation_path_hashes[i]);
        CBlock empty_block;
        empty_block.vtx = {MakeCoinbaseTx(CScript{} << OP_TRUE),
                           MakeCoinstakeTx(staker_target)};
        CBlockUndo empty_undo = MakeUndoWithInputScripts(
            empty_block, {{1, staker_target}});
        BOOST_REQUIRE(ApplyShadowBlock(seed_view, empty_block,
                                      &activation_path[i], &empty_undo));
        activation_parent = &activation_path[i];
    }
    BOOST_REQUIRE_EQUAL(activation_parent->nHeight, activation_height - 1);

    std::vector<unsigned char> pow_proof;
    BOOST_REQUIRE(MineQQP4Proof(pow_target, quantum_payout, 3,
                                activation_parent, seed_view, 100'000,
                                pow_proof));
    const size_t mode_offset = GetShadowPrefix().size() + 4;
    BOOST_REQUIRE_GT(pow_proof.size(), mode_offset);
    std::vector<unsigned char> pos_proof = pow_proof;
    std::vector<unsigned char> unknown_proof = pow_proof;
    pos_proof[mode_offset] = 1;
    unknown_proof[mode_offset] = 0x7f;
    BOOST_CHECK(ClassifyShadowProofPayload(pow_proof, /*qqp4_active=*/true) ==
                ShadowProofPayloadMode::POW);
    BOOST_CHECK(ClassifyShadowProofPayload(pos_proof, /*qqp4_active=*/true) ==
                ShadowProofPayloadMode::POS);
    BOOST_CHECK(ClassifyShadowProofPayload(unknown_proof, /*qqp4_active=*/true) ==
                ShadowProofPayloadMode::UNKNOWN);

    const CTransactionRef pos_tx = MakePowClaimTx(pow_target, pos_proof, 0);
    const CTransactionRef unknown_tx = MakePowClaimTx(
        pow_target, unknown_proof, 1);
    const CTransactionRef duplicate_tx = MakePowClaimTxWithTwoProofs(
        pow_target, pow_proof, pow_proof, 2);
    const CTransactionRef pow_tx = MakePowClaimTx(pow_target, pow_proof, 3);
    const CTransactionRef qqp1_tx = MakePowClaimTx(
        pow_target, MakeQQP1ProofData(/*nonce=*/1, pow_target), 0);
    const CTransactionRef qqp2_tx = MakePowClaimTx(
        pow_target, MakeInvalidPowProofData(/*nonce=*/2, pow_target,
                                            quantum_payout), 1);
    const CTransactionRef qqp3_tx = MakePowClaimTx(
        pow_target, MakeQQP3ProofData(
                        /*nonce=*/3,
                        static_cast<uint32_t>(activation_height),
                        activation_parent->GetBlockHash(), pow_target,
                        quantum_payout),
        2);

    std::string reject_reason;
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                    *pos_tx, activation_parent, seed_view, true,
                    reject_reason) == ShadowProofValidationResult::INVALID);
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-wrong-mode-pos");
    reject_reason.clear();
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                    *unknown_tx, activation_parent, seed_view, true,
                    reject_reason) == ShadowProofValidationResult::INVALID);
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-unknown-mode");
    reject_reason.clear();
    BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                    *duplicate_tx, activation_parent, seed_view, true,
                    reject_reason) == ShadowProofValidationResult::INVALID);
    BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-duplicate");
    for (const CTransactionRef& retired_tx : {qqp1_tx, qqp2_tx, qqp3_tx}) {
        reject_reason.clear();
        BOOST_CHECK(CheckShadowPowClaimForMempoolDetailed(
                        *retired_tx, activation_parent, seed_view, true,
                        reject_reason) == ShadowProofValidationResult::INVALID);
        BOOST_CHECK_EQUAL(reject_reason, "shadow-proof-version");
    }

    // Wrong, unknown, and duplicate payloads are rejected before Argon2. The
    // injected failure must remain armed until the canonical PoW proof runs.
    SetShadowArgon2FailuresForTesting();
    reject_reason.clear();
    const ShadowProofValidationResult skipped_pos =
        CheckShadowPowClaimForMempoolDetailed(
            *pos_tx, activation_parent, seed_view, true, reject_reason);
    reject_reason.clear();
    const ShadowProofValidationResult skipped_unknown =
        CheckShadowPowClaimForMempoolDetailed(
            *unknown_tx, activation_parent, seed_view, true, reject_reason);
    reject_reason.clear();
    const ShadowProofValidationResult skipped_duplicate =
        CheckShadowPowClaimForMempoolDetailed(
            *duplicate_tx, activation_parent, seed_view, true, reject_reason);
    reject_reason.clear();
    const ShadowProofValidationResult pow_fault =
        CheckShadowPowClaimForMempoolDetailed(
            *pow_tx, activation_parent, seed_view, true, reject_reason);
    ClearShadowArgon2FailuresForTesting();
    BOOST_CHECK(skipped_pos == ShadowProofValidationResult::INVALID);
    BOOST_CHECK(skipped_unknown == ShadowProofValidationResult::INVALID);
    BOOST_CHECK(skipped_duplicate == ShadowProofValidationResult::INVALID);
    BOOST_CHECK(pow_fault == ShadowProofValidationResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK_EQUAL(reject_reason, "local-shadow-proof-error");

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, activation_height, activation_parent, claim_hash);
    CBlock mode_block;
    mode_block.vtx = {MakeCoinbaseTx(CScript{} << OP_3),
                      MakeCoinstakeTx(staker_target), pos_tx, unknown_tx,
                      duplicate_tx};
    CBlockUndo mode_undo = MakeUndoWithInputScripts(
        mode_block, {{1, staker_target}, {2, pow_target}, {3, pow_target},
                     {4, pow_target}});

    ShadowProofObservationSummary observation_summary;
    const std::vector<ShadowProofObservation> observations =
        GetShadowProofObservations(mode_block, Params().GetConsensus(),
                                   claim_index.nHeight,
                                   observation_summary);
    BOOST_REQUIRE_EQUAL(observations.size(), 4U);
    BOOST_CHECK_EQUAL(std::count_if(
        observations.begin(), observations.end(),
        [](const ShadowProofObservation& observation) {
            return observation.mode == ShadowProofPayloadMode::POS &&
                   observation.fee_paying_location &&
                   !observation.duplicate_in_transaction;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(
        observations.begin(), observations.end(),
        [](const ShadowProofObservation& observation) {
            return observation.mode == ShadowProofPayloadMode::UNKNOWN &&
                   observation.fee_paying_location &&
                   !observation.duplicate_in_transaction;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(
        observations.begin(), observations.end(),
        [](const ShadowProofObservation& observation) {
            return observation.mode == ShadowProofPayloadMode::POW &&
                   observation.fee_paying_location &&
                   observation.duplicate_in_transaction;
        }), 2U);

    std::vector<ShadowPowClaimAccounting> mode_accounting;
    ShadowPowClaimAggregate mode_aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(
                      seed_view, mode_block, &claim_index, &mode_undo,
                      mode_accounting,
                      &mode_aggregate) == ShadowPowAccountingResult::OK);
    BOOST_CHECK(mode_accounting.empty());
    BOOST_CHECK_EQUAL(mode_aggregate.observed_count, 4U);
    BOOST_CHECK_EQUAL(mode_aggregate.evaluated_count, 0U);
    BOOST_CHECK_EQUAL(mode_aggregate.wrong_mode_count, 1U);
    BOOST_CHECK_EQUAL(mode_aggregate.unknown_mode_count, 1U);
    BOOST_CHECK_EQUAL(mode_aggregate.malformed_transaction_count, 2U);
    BOOST_CHECK(!mode_aggregate.accounting_commitment.IsNull());

    CBlock control_block;
    control_block.vtx = {MakeCoinbaseTx(CScript{} << OP_3),
                         MakeCoinstakeTx(staker_target)};
    CBlockUndo control_undo = MakeUndoWithInputScripts(
        control_block, {{1, staker_target}});
    CCoinsViewCache mode_view{&seed_view, true};
    CCoinsViewCache control_view{&seed_view, true};
    BOOST_REQUIRE(ApplyShadowBlock(mode_view, mode_block, &claim_index,
                                  &mode_undo));
    BOOST_REQUIRE(ApplyShadowBlock(control_view, control_block, &claim_index,
                                  &control_undo));
    const ShadowGoldRushInfo mode_info = GetShadowGoldRushInfo(
        mode_view, &claim_index);
    const ShadowGoldRushInfo control_info = GetShadowGoldRushInfo(
        control_view, &claim_index);
    BOOST_CHECK_EQUAL(mode_info.pow_amount, control_info.pow_amount);
    BOOST_CHECK_EQUAL(mode_info.pos_amount, control_info.pos_amount);
    BOOST_CHECK_EQUAL(mode_info.claimed_amount, control_info.claimed_amount);
    BOOST_CHECK_EQUAL(mode_info.pow_count, control_info.pow_count);
    BOOST_CHECK_EQUAL(mode_info.pos_count, control_info.pos_count);
    BOOST_CHECK_EQUAL(mode_info.last_pow_height, control_info.last_pow_height);
    BOOST_CHECK_EQUAL(mode_info.last_pos_height, control_info.last_pos_height);
    BOOST_CHECK_EQUAL(mode_info.recent_count, control_info.recent_count);
    BOOST_CHECK_EQUAL(mode_info.recent_modes, control_info.recent_modes);
    BOOST_CHECK_EQUAL(mode_info.pow_target_bits, control_info.pow_target_bits);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(mode_view, quantum_payout).count,
                      0U);

    const ShadowGoldRushInfo parent_info = GetShadowGoldRushInfo(
        seed_view, activation_parent);
    BOOST_REQUIRE(UndoShadowBlock(mode_view, mode_block, &claim_index,
                                 &mode_undo));
    const ShadowGoldRushInfo undo_info = GetShadowGoldRushInfo(
        mode_view, activation_parent);
    BOOST_CHECK_EQUAL(undo_info.pow_amount, parent_info.pow_amount);
    BOOST_CHECK_EQUAL(undo_info.pos_amount, parent_info.pos_amount);
    BOOST_CHECK_EQUAL(undo_info.claimed_amount, parent_info.claimed_amount);
    BOOST_CHECK_EQUAL(undo_info.pow_count, parent_info.pow_count);
    BOOST_CHECK_EQUAL(undo_info.pos_count, parent_info.pos_count);
    BOOST_REQUIRE(ApplyShadowBlock(mode_view, mode_block, &claim_index,
                                  &mode_undo));
    const ShadowGoldRushInfo replay_info = GetShadowGoldRushInfo(
        mode_view, &claim_index);
    BOOST_CHECK_EQUAL(replay_info.pow_amount, mode_info.pow_amount);
    BOOST_CHECK_EQUAL(replay_info.pos_amount, mode_info.pos_amount);
    BOOST_CHECK_EQUAL(replay_info.claimed_amount, mode_info.claimed_amount);
    BOOST_CHECK_EQUAL(replay_info.recent_modes, mode_info.recent_modes);
    WriteShadowReplayStateMarker(mode_view, &claim_index,
                                 Params().GetConsensus());
    WriteShadowReplayStateMarker(control_view, &claim_index,
                                 Params().GetConsensus());
    const ShadowReplayStateInfo mode_replay = GetShadowReplayStateInfo(
        mode_view, Params().GetConsensus(), &claim_index);
    const ShadowReplayStateInfo control_replay = GetShadowReplayStateInfo(
        control_view, Params().GetConsensus(), &claim_index);
    BOOST_REQUIRE(mode_replay.valid_for_tip);
    BOOST_REQUIRE(control_replay.valid_for_tip);
    BOOST_CHECK(mode_replay.commitment == control_replay.commitment);

    CBlock pow_block;
    pow_block.vtx = {MakeCoinbaseTx(CScript{} << OP_3),
                     MakeCoinstakeTx(staker_target), pow_tx};
    CBlockUndo pow_undo = MakeUndoWithInputScripts(
        pow_block, {{1, staker_target}, {2, pow_target}});
    CCoinsViewCache pow_view{&seed_view, true};
    BOOST_REQUIRE(ApplyShadowBlock(pow_view, pow_block, &claim_index,
                                  &pow_undo));
    const ShadowGoldRushInfo pow_info = GetShadowGoldRushInfo(
        pow_view, &claim_index);
    BOOST_CHECK_EQUAL(pow_info.pow_amount, 0);
    BOOST_CHECK_EQUAL(pow_info.claimed_amount, control_info.pow_amount);
    BOOST_CHECK_EQUAL(pow_info.pow_count, control_info.pow_count + 1);
    BOOST_CHECK_EQUAL(pow_info.last_pow_height,
                      static_cast<uint32_t>(claim_index.nHeight));
    BOOST_CHECK_EQUAL(pow_info.pos_amount, control_info.pos_amount);
    BOOST_CHECK_EQUAL(pow_info.pos_count, control_info.pos_count);
    BOOST_CHECK_EQUAL(pow_info.last_pos_height, control_info.last_pos_height);
    BOOST_CHECK_EQUAL(ScanShadowClaimMarkers(pow_view, quantum_payout).count,
                      1U);
    const std::vector<ShadowSyntheticPayoutTransaction> pow_records =
        GetAppliedShadowClaimPayoutTransactionRecords(
            pow_view, claim_index.nHeight, claim_index.GetBlockHash(),
            claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(pow_records.size(), 1U);
    BOOST_CHECK(pow_records.front().proof_of_work);
    const uint256 payout_txid = pow_records.front().tx->GetHash();
    BOOST_REQUIRE(UndoShadowBlock(pow_view, pow_block, &claim_index,
                                 &pow_undo));
    BOOST_REQUIRE(ApplyShadowBlock(pow_view, pow_block, &claim_index,
                                  &pow_undo));
    const std::vector<ShadowSyntheticPayoutTransaction> replayed_pow_records =
        GetAppliedShadowClaimPayoutTransactionRecords(
            pow_view, claim_index.nHeight, claim_index.GetBlockHash(),
            claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(replayed_pow_records.size(), 1U);
    BOOST_CHECK(replayed_pow_records.front().proof_of_work);
    BOOST_CHECK(replayed_pow_records.front().target ==
                pow_records.front().target);
    BOOST_CHECK_EQUAL(replayed_pow_records.front().amount,
                      pow_records.front().amount);
    BOOST_CHECK(replayed_pow_records.front().tx->GetHash() == payout_txid);

    // Before the existing competing-claim activation, the same PoW proof
    // retains the historical first-claim result. Wrong modes still receive no
    // credit; no new activation boundary is required for this hardening.
    Consensus::Params historical = Params().GetConsensus();
    historical.nShadowCompetingClaimsActivationHeight = claim_index.nHeight + 1;
    std::map<CScript, CAmount> historical_payouts;
    CAmount historical_total{0};
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        seed_view, pow_block, &claim_index, &pow_undo, historical,
        historical_payouts, historical_total));
    BOOST_CHECK_EQUAL(historical_total, control_info.pow_amount);
    CBlock wrong_mode_block;
    wrong_mode_block.vtx = {MakeCoinbaseTx(CScript{} << OP_3),
                            MakeCoinstakeTx(staker_target), pos_tx,
                            unknown_tx};
    CBlockUndo wrong_mode_undo = MakeUndoWithInputScripts(
        wrong_mode_block,
        {{1, staker_target}, {2, pow_target}, {3, pow_target}});
    historical_payouts.clear();
    historical_total = 0;
    BOOST_REQUIRE(GetShadowPowDirectPayouts(
        seed_view, wrong_mode_block, &claim_index, &wrong_mode_undo,
        historical, historical_payouts, historical_total));
    BOOST_CHECK_EQUAL(historical_total, 0);
    BOOST_CHECK(historical_payouts.empty());
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

    const int activation_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    BOOST_REQUIRE_GT(activation_height, prev_index.nHeight);
    uint256 activation_parent_hash;
    CBlockIndex activation_parent;
    InitIndex(activation_parent, activation_height - 1, &prev_index,
              activation_parent_hash);
    BOOST_REQUIRE(AdvanceGoldRushInventoryTip(view, &activation_parent));

    const CScript target = CScript{} << OP_2;
    const CScript payout = QuantumScript(0x77);
    std::vector<unsigned char> proof;
    BOOST_REQUIRE(MineShadowProofData(target, payout, &activation_parent,
                                      view, 100'000, proof));

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, activation_height, &activation_parent, claim_hash);
    const CAmount expected_pow_pool =
        ShadowBaseReward(prev_index.nHeight) / 2 +
        ShadowBaseReward(claim_index.nHeight) / 2;
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(CScript{} << OP_5));
    claim_block.vtx.push_back(MakePowClaimTx(target, proof, 0));
    claim_block.vtx.push_back(MakePowClaimTxWithTwoProofs(target, proof, proof, 1));
    CBlockUndo claim_undo = MakeUndoWithInputScripts(
        claim_block, {{1, CScript{} << OP_5}, {2, target}, {3, target}});

    std::vector<ShadowPowClaimAccounting> accounting;
    ShadowPowClaimAggregate aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, accounting,
                                              &aggregate) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 1U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        }), 1U);
    BOOST_CHECK_EQUAL(aggregate.observed_count, 3U);
    BOOST_CHECK_EQUAL(aggregate.evaluated_count, 1U);
    BOOST_CHECK_EQUAL(aggregate.malformed_transaction_count, 2U);
    BOOST_CHECK_EQUAL(aggregate.winner_count, 1U);
    BOOST_CHECK(!aggregate.accounting_commitment.IsNull());

    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 1U);
    BOOST_CHECK_EQUAL(payouts.front().txout.nValue, expected_pow_pool);
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

    const int activation_height =
        Params().GetConsensus().nShadowCompetingClaimsActivationHeight;
    BOOST_REQUIRE_GT(activation_height, prev_index.nHeight);
    uint256 activation_parent_hash;
    CBlockIndex activation_parent;
    InitIndex(activation_parent, activation_height - 1, &prev_index,
              activation_parent_hash);
    BOOST_REQUIRE(AdvanceGoldRushInventoryTip(view, &activation_parent));

    const CScript pow_target = CScript{} << OP_2;
    const CScript quantum_payout = QuantumScript(0x4a);

    uint256 claim_hash;
    CBlockIndex claim_index;
    InitIndex(claim_index, activation_height, &activation_parent, claim_hash);
    const CAmount expected_pow_pool =
        ShadowBaseReward(prev_index.nHeight) / 2 +
        ShadowBaseReward(claim_index.nHeight) / 2;
    CBlock claim_block;
    claim_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_4));
    claim_block.vtx.push_back(MakeCoinstakeTx(
        CScript{} << OP_5, {}, {CTxOut(expected_pow_pool, quantum_payout)}));
    std::map<size_t, CScript> input_scripts{{1, CScript{} << OP_5}};
    std::vector<std::vector<unsigned char>> proofs;
    proofs.reserve(65);
    for (uint32_t i = 0; i < 65; ++i) {
        std::vector<unsigned char> proof;
        BOOST_REQUIRE(MineShadowProofData(pow_target, quantum_payout,
                                          &activation_parent, view, 50'000,
                                          proof));
        claim_block.vtx.push_back(MakePowClaimTx(pow_target, proof, i));
        proofs.push_back(std::move(proof));
        input_scripts.emplace(2 + i, pow_target);
    }
    std::vector<uint256> expected_ranks;
    expected_ranks.reserve(65);
    for (const std::vector<unsigned char>& proof : proofs) {
        const std::vector<unsigned char> canonical_proof{
            proof.begin() + GetShadowPrefix().size(), proof.end()};
        CHashWriter rank_writer;
        rank_writer << std::string{"Quantum Quasar Canonical POW Claim Rank v1"}
                    << claim_index.nHeight
                    << activation_parent.GetBlockHash()
                    << claim_block.vtx[2 + expected_ranks.size()]->GetHash()
                    << uint32_t{1} << canonical_proof;
        expected_ranks.push_back(rank_writer.GetHash());
    }
    std::sort(expected_ranks.begin(), expected_ranks.end());
    CBlockUndo claim_undo = MakeUndoWithInputScripts(claim_block, input_scripts);

    std::map<CScript, CAmount> direct_payouts;
    CAmount direct_total{0};
    BOOST_CHECK(GetShadowPowDirectPayouts(view, claim_block, &claim_index, &claim_undo, direct_payouts, direct_total));
    BOOST_CHECK_EQUAL(direct_total, expected_pow_pool);
    BOOST_REQUIRE_EQUAL(direct_payouts.size(), 1U);
    BOOST_CHECK_EQUAL(direct_payouts[quantum_payout], expected_pow_pool);

    std::vector<ShadowPowClaimAccounting> accounting;
    ShadowPowClaimAggregate aggregate;
    BOOST_REQUIRE(GetShadowPowClaimAccounting(view, claim_block, &claim_index,
                                              &claim_undo, accounting,
                                              &aggregate) ==
                  ShadowPowAccountingResult::OK);
    BOOST_REQUIRE_EQUAL(accounting.size(), 64U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::WINNER;
        }), 1U);
    BOOST_CHECK_EQUAL(std::count_if(accounting.begin(), accounting.end(),
        [](const ShadowPowClaimAccounting& entry) {
            return entry.disposition == ShadowPowClaimDisposition::REIMBURSED_LOSER;
        }), 63U);
    BOOST_CHECK_EQUAL(aggregate.observed_count, 65U);
    BOOST_CHECK_EQUAL(aggregate.evaluated_count, 64U);
    BOOST_CHECK_EQUAL(aggregate.evaluation_limit_count, 1U);
    BOOST_CHECK_EQUAL(aggregate.winner_count, 1U);
    BOOST_CHECK_EQUAL(aggregate.reimbursed_loser_count, 63U);
    BOOST_CHECK(!aggregate.accounting_commitment.IsNull());
    for (size_t i = 0; i < accounting.size(); ++i) {
        BOOST_CHECK_EQUAL(accounting[i].canonical_rank, expected_ranks[i]);
    }
    BOOST_REQUIRE(ApplyShadowBlock(view, claim_block, &claim_index, &claim_undo));
    const std::vector<ShadowSyntheticPayoutCoin> payouts = GetAppliedShadowClaimPayoutCoins(
        view, claim_index.nHeight, claim_index.GetBlockHash(), claim_index.GetBlockTime());
    BOOST_REQUIRE_EQUAL(payouts.size(), 64U);
    CAmount payout_total{0};
    for (const ShadowSyntheticPayoutCoin& payout : payouts) payout_total += payout.txout.nValue;
    BOOST_CHECK_EQUAL(payout_total, expected_pow_pool);
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

BOOST_AUTO_TEST_CASE(value_lifecycle_categories_pin_gold_rush_and_final_boundaries)
{
    ShadowScheduleGuard schedule{/*whitelist_height=*/9,
                                 /*reward_start_height=*/10,
                                 /*gold_rush_blocks=*/11};
    Consensus::Params params = Params().GetConsensus();
    params.nQuantumLifecycleStartHeight = 10;
    params.nGoldRushEndHeight = 20;
    params.nQuantumMigrationEndHeight = 40;
    params.nDemurrageActivationHeight = 41;
    params.nDemurrageMinActivationHeight = 41;
    params.nDemurrageBlocksPerMonth = 1;
    params.nCoinbaseMaturity = 5;
    params.nLastPOWBlock = 0;

    const Coin legacy{CTxOut{5 * COIN, CScript{} << OP_TRUE},
                      /*height=*/12, /*coinbase=*/false, /*coinstake=*/false,
                      /*time=*/0};
    ValueLifecycleClassification state;
    BOOST_REQUIRE(ClassifyValueLifecycle(
        legacy, /*synthetic=*/false, params, /*evaluation_height=*/20,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::SPENDABLE_LEGACY);
    BOOST_CHECK(state.consensus_spendable);
    BOOST_CHECK(state.ordinary_spendable);
    BOOST_CHECK(state.legacy_scheduled_final_lockout);
    BOOST_CHECK(state.requires_quantum_migration);
    BOOST_CHECK_EQUAL(state.nominal_amount, 5 * COIN);
    BOOST_CHECK_EQUAL(state.effective_amount, 5 * COIN);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        legacy, /*synthetic=*/false, params, /*evaluation_height=*/41,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::FINAL_LOCKED_LEGACY);
    BOOST_CHECK(!state.consensus_spendable);
    BOOST_CHECK(!state.ordinary_spendable);
    BOOST_CHECK(state.permanently_locked);
    BOOST_CHECK(!state.legacy_scheduled_final_lockout);
    BOOST_CHECK(!state.requires_quantum_migration);

    const Coin synthetic{CTxOut{580 * COIN, QuantumScript(0x71)},
                         /*height=*/15, /*coinbase=*/true, /*coinstake=*/false,
                         /*time=*/0};
    BOOST_REQUIRE(ClassifyValueLifecycle(
        synthetic, /*synthetic=*/true, params, /*evaluation_height=*/19,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_IMMATURE);
    BOOST_CHECK(state.synthetic);
    BOOST_CHECK(!state.merkle_included);
    BOOST_CHECK(!state.mature);
    BOOST_CHECK(!state.consensus_spendable);
    BOOST_CHECK_EQUAL(state.maturity_height, 20);
    BOOST_CHECK_EQUAL(state.earliest_spend_height, 21);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        synthetic, /*synthetic=*/true, params, /*evaluation_height=*/20,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_MATURE_LOCKED);
    BOOST_CHECK(state.mature);
    BOOST_CHECK(!state.consensus_spendable);
    BOOST_CHECK_EQUAL(state.earliest_spend_height, 21);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        synthetic, /*synthetic=*/true, params, /*evaluation_height=*/21,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::MIGRATION_SPENDABLE_DIRECT_QUANTUM);
    BOOST_CHECK(state.consensus_spendable);
    BOOST_CHECK(state.ordinary_spendable);
    BOOST_CHECK(state.synthetic);
    BOOST_CHECK(!state.merkle_included);
    BOOST_CHECK_EQUAL(state.earliest_spend_height, 21);

    const Coin false_synthetic{CTxOut{580 * COIN, CScript{} << OP_TRUE},
                               /*height=*/15, /*coinbase=*/true,
                               /*coinstake=*/false, /*time=*/0};
    BOOST_CHECK(ClassifyValueLifecycle(
        false_synthetic, /*synthetic=*/true, params, /*evaluation_height=*/21,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::INVALID_SYNTHETIC_PROVENANCE);
}

BOOST_AUTO_TEST_CASE(value_lifecycle_pins_direct_quantum_and_demurrage_accounting)
{
    ShadowScheduleGuard schedule{/*whitelist_height=*/9,
                                 /*reward_start_height=*/10,
                                 /*gold_rush_blocks=*/11};
    Consensus::Params params = Params().GetConsensus();
    params.nQuantumLifecycleStartHeight = 10;
    params.nGoldRushEndHeight = 20;
    params.nQuantumMigrationEndHeight = 40;
    params.nDemurrageActivationHeight = 41;
    params.nDemurrageMinActivationHeight = 41;
    params.nDemurrageBlocksPerMonth = 1;
    params.nCoinbaseMaturity = 5;
    params.nLastPOWBlock = 0;

    const Coin direct{CTxOut{10 * COIN, QuantumScript(0x72)},
                      /*height=*/12, /*coinbase=*/false, /*coinstake=*/false,
                      /*time=*/0};
    ValueLifecycleClassification state;
    BOOST_REQUIRE(ClassifyValueLifecycle(
        direct, /*synthetic=*/false, params, /*evaluation_height=*/20,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::DIRECT_QUANTUM_PHASE_LOCKED);
    BOOST_CHECK(!state.consensus_spendable);
    BOOST_CHECK_EQUAL(state.earliest_spend_height, 21);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        direct, /*synthetic=*/false, params, /*evaluation_height=*/21,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::MIGRATION_SPENDABLE_DIRECT_QUANTUM);
    BOOST_CHECK(state.consensus_spendable);
    BOOST_CHECK(state.ordinary_spendable);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        direct, /*synthetic=*/false, params, /*evaluation_height=*/65,
        /*evaluation_mtp=*/0, std::nullopt, std::nullopt, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::DEMURRAGE_LOCKED);
    BOOST_CHECK(state.demurrage_active);
    BOOST_CHECK(state.demurrage_locked);
    BOOST_CHECK(state.permanently_locked);
    BOOST_CHECK_EQUAL(state.nominal_amount, 10 * COIN);
    BOOST_CHECK_EQUAL(state.effective_amount, 0);
    BOOST_CHECK_EQUAL(state.burned_amount, 10 * COIN);

    BOOST_REQUIRE(ClassifyValueLifecycle(
        direct, /*synthetic=*/false, params, /*evaluation_height=*/50,
        /*evaluation_mtp=*/0, /*latest_attestation_height=*/50,
        /*attestation_coverage_start_height=*/41, state) ==
        ValueLifecycleResult::OK);
    BOOST_CHECK(state.category == ValueLifecycleCategory::MIGRATION_SPENDABLE_DIRECT_QUANTUM);
    BOOST_CHECK(state.demurrage_active);
    BOOST_CHECK(state.demurrage_exempt);
    BOOST_CHECK_EQUAL(state.demurrage_exemption, "attested");
    BOOST_CHECK_EQUAL(state.effective_amount, 10 * COIN);
    BOOST_CHECK_EQUAL(state.burned_amount, 0);
}

BOOST_AUTO_TEST_CASE(shadow_emission_checked_helper_pins_boundaries)
{
    BOOST_REQUIRE(GetScheduledShadowEmissionThrough(SHADOW_REWARD_START_HEIGHT - 1));
    BOOST_CHECK_EQUAL(*GetScheduledShadowEmissionThrough(SHADOW_REWARD_START_HEIGHT - 1), 0);
    BOOST_REQUIRE(GetScheduledShadowEmissionThrough(SHADOW_REWARD_START_HEIGHT));
    BOOST_CHECK_EQUAL(*GetScheduledShadowEmissionThrough(SHADOW_REWARD_START_HEIGHT), 580 * COIN);
    BOOST_REQUIRE(GetScheduledShadowEmissionThrough(SHADOW_REWARD_END_HEIGHT));
    BOOST_CHECK_EQUAL(*GetScheduledShadowEmissionThrough(SHADOW_REWARD_END_HEIGHT), SHADOW_MAX_EMISSION);
    BOOST_REQUIRE(GetScheduledShadowEmissionThrough(std::numeric_limits<int>::max()));
    BOOST_CHECK_EQUAL(*GetScheduledShadowEmissionThrough(std::numeric_limits<int>::max()), SHADOW_MAX_EMISSION);
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

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, &whitelist_index));

    uint256 first_hash;
    CBlockIndex first_index;
    InitIndex(first_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, first_hash);
    CBlock first_block;
    first_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));
    BOOST_REQUIRE(ApplyShadowBlock(view, first_block, &first_index));

    const CAmount corrupt_claimed =
        SHADOW_MAX_EMISSION - ShadowBaseReward(SHADOW_REWARD_START_HEIGHT + 1) + 1;
    AddPoolForTest(view, first_index, 0, 0, corrupt_claimed);

    uint256 reward_hash;
    CBlockIndex reward_index;
    InitIndex(reward_index, SHADOW_REWARD_START_HEIGHT + 1, &first_index, reward_hash);
    CBlock block;
    block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_TRUE));

    BOOST_CHECK(!ApplyShadowBlock(view, block, &reward_index));
    const ShadowGoldRushInfo info = GetShadowGoldRushInfo(view, &first_index);
    BOOST_CHECK_EQUAL(info.pow_amount, 0);
    BOOST_CHECK_EQUAL(info.pos_amount, 0);
    BOOST_CHECK_EQUAL(info.claimed_amount, corrupt_claimed);
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

    uint256 whitelist_hash;
    CBlockIndex whitelist_index;
    InitIndex(whitelist_index, SHADOW_WHITELIST_HEIGHT, nullptr, whitelist_hash);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, &whitelist_index));

    uint256 solve_hash;
    CBlockIndex solve_index;
    InitIndex(solve_index, SHADOW_REWARD_START_HEIGHT, &whitelist_index, solve_hash);
    CBlock solve_block;
    solve_block.vtx.push_back(MakeCoinbaseTx(CScript{} << OP_3));
    solve_block.vtx.push_back(MakeCoinstakeTx(pos_target));
    CBlockUndo solve_undo = MakeUndoWithInputScripts(solve_block, {{1, pos_target}});
    BOOST_REQUIRE(ApplyShadowBlock(view, solve_block, &solve_index, &solve_undo));

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

// QQP4 tests need a real regtest schedule. Give each case its own explicit
// fixture so the file-level shadow_tests suite keeps its canonical name and
// the preceding BasicTestingSetup fixture is torn down before construction.
BOOST_FIXTURE_TEST_CASE(
    shadow_index_record_validation_enforces_qqp4_exact_input_after_separate_activation,
    QQP4ActivationTestingSetup)
{
    CheckShadowIndexRecordQQP4ExactInputAfterSeparateActivation();
}

BOOST_FIXTURE_TEST_CASE(
    pow_shadow_payload_modes_are_strictly_bound_to_pow_accounting,
    QQP4ActivationTestingSetup)
{
    CheckQQP4PayloadModesAreStrictlyBoundToPowAccounting();
}

BOOST_AUTO_TEST_SUITE_END()
