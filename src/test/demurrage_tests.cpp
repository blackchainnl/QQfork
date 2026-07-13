// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <consensus/tx_verify.h>
#include <crypto/mldsa.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <tuple>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(demurrage_tests, BasicTestingSetup)

namespace {

static constexpr int64_t TEST_MIGRATION_DEADLINE_TIME = 2000;
static constexpr int64_t TEST_POST_MIGRATION_TIME = TEST_MIGRATION_DEADLINE_TIME + 1;
static constexpr uint32_t TEST_QUANTUM_CHAIN_ID = 0xD3110001U;

CScript PlainScript(unsigned char tag)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
}

const std::vector<unsigned char> TEST_TAG_LATEST{'Q', 'Q', 'A', 'L', 'I', 'V', 'E'};
const std::vector<unsigned char> TEST_TAG_INVENTORY{'Q', 'Q', 'A', 'I', 'N', 'V'};

CScript TestMarkerScript(const std::vector<unsigned char>& tag,
                         const std::vector<unsigned char>& payload)
{
    return CScript{} << OP_FALSE << OP_RETURN << tag << payload;
}

COutPoint PrereleaseLatestOutpoint(const uint256& pubkey_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Latest") << pubkey_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint PrereleaseInventoryOutpoint()
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Inventory v1");
    return COutPoint{ss.GetHash(), 0};
}

Coin TestMarkerCoin(CAmount value, const CScript& script, int height,
                    int time, bool coinbase = true)
{
    return Coin{CTxOut{value, script}, height, coinbase, false, time};
}

std::vector<unsigned char> PrereleaseLatestPayload(
    const uint256& pubkey_hash,
    const CBlockIndex& source,
    const uint256& source_txid)
{
    DataStream stream;
    stream << uint8_t{2} << pubkey_hash
           << static_cast<uint32_t>(source.nHeight)
           << static_cast<uint32_t>(source.GetBlockTime())
           << static_cast<uint32_t>(source.nHeight)
           << source.GetBlockHash() << source_txid << uint32_t{0};
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

std::vector<unsigned char> PrereleaseEmptyInventoryPayload(const CBlockIndex& tip)
{
    MuHash3072 live_set;
    uint256 live_root;
    live_set.Finalize(live_root);
    DataStream stream;
    stream << uint8_t{3} << static_cast<uint32_t>(tip.nHeight)
           << tip.GetBlockHash() << uint64_t{0} << live_set << live_root;
    const auto bytes = MakeUCharSpan(stream);
    return {bytes.begin(), bytes.end()};
}

CScript QuantumColdStakeScript()
{
    const std::vector<unsigned char> staker(ML_DSA::PUBLICKEY_BYTES, 0x11);
    const std::vector<unsigned char> owner(ML_DSA::PUBLICKEY_BYTES, 0x22);
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_COLDSTAKE_WITNESS_VERSION,
        QuantumColdStakeProgramForPubkeys(staker, owner)});
}

Coin TestCoin(CAmount value, int height, const CScript& script)
{
    return Coin{CTxOut{value, script}, height, false, false, 0};
}

CScript QuantumMigrationScriptForPubkey(const std::vector<unsigned char>& pubkey)
{
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumMigrationProgramForPubkey(pubkey)});
}

COutPoint DefaultAttestationTarget()
{
    return COutPoint{uint256::ONE, 999};
}

std::vector<unsigned char> SignAttestation(const std::vector<unsigned char>& private_key,
                                           const COutPoint& replay_anchor,
                                           const std::vector<unsigned char>& public_key,
                                           const COutPoint& target_outpoint = DefaultAttestationTarget(),
                                           std::optional<int> previous_height = std::nullopt,
                                           uint32_t previous_time = 0,
                                           uint32_t previous_coverage_start_height = 0,
                                           std::optional<Consensus::DemurrageAttestationSource> previous_source = std::nullopt)
{
    const uint256 msg_hash = Consensus::DemurrageAttestationMessageHash(
        replay_anchor, target_outpoint, previous_height, previous_time,
        previous_coverage_start_height, previous_source, public_key,
        TEST_QUANTUM_CHAIN_ID);
    std::vector<unsigned char> signature;
    BOOST_REQUIRE(ML_DSA::Sign(private_key, msg_hash.begin(), uint256::size(), signature));
    return signature;
}

CScript BuildTestAttestationScript(const COutPoint& replay_anchor,
                                   const std::vector<unsigned char>& public_key,
                                   const std::vector<unsigned char>& signature,
                                   const COutPoint& target_outpoint = DefaultAttestationTarget(),
                                   std::optional<int> previous_height = std::nullopt,
                                   uint32_t previous_time = 0,
                                   uint32_t previous_coverage_start_height = 0,
                                   std::optional<Consensus::DemurrageAttestationSource> previous_source = std::nullopt)
{
    return Consensus::BuildDemurrageAttestationScript(
        replay_anchor, target_outpoint, previous_height, previous_time,
        previous_coverage_start_height, previous_source, public_key, signature);
}

void InitTestIndex(CBlockIndex& index, int height, const uint256& block_hash)
{
    index.nHeight = height;
    index.nTime = 1000 + height;
    index.phashBlock = &block_hash;
}

Consensus::Params ActiveParams(int activation_height = 100)
{
    Consensus::Params params;
    params.nProtocolV4Time = 0;
    params.nGoldRushEndTime = 1000;
    params.nDemurrageActivationHeight = activation_height;
    params.nQuantumMigrationDeadlineTime = TEST_MIGRATION_DEADLINE_TIME;
    params.nQuantumSighashChainId = TEST_QUANTUM_CHAIN_ID;
    return params;
}

void AttachActivationPredecessor(CCoinsViewCache& view, CBlockIndex& active_index,
                                 const Consensus::Params& params,
                                 CBlockIndex& predecessor, const uint256& predecessor_hash)
{
    InitTestIndex(predecessor, /*height=*/0, predecessor_hash);
    predecessor.nTime = TEST_POST_MIGRATION_TIME;
    active_index.pprev = &predecessor;
    BOOST_REQUIRE(!params.IsDemurrageActive(predecessor.nHeight, predecessor.GetBlockTime()));
    BOOST_REQUIRE(params.IsDemurrageActive(active_index.nHeight,
                                           predecessor.GetMedianTimePast()));
    BOOST_REQUIRE(Consensus::PrepareDemurrageActivationInventory(view, &predecessor, params));
    BOOST_REQUIRE(Consensus::HasCurrentDemurrageInventory(view, &predecessor, params));
}

using CoinState = std::tuple<COutPoint, CAmount, CScript, uint32_t, uint32_t, bool, bool>;

std::vector<CoinState> SnapshotCoins(CCoinsViewCache& view)
{
    std::vector<CoinState> result;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            const uint32_t height = coin.nHeight;
            const uint32_t time = coin.nTime;
            const bool coinbase = coin.fCoinBase;
            const bool coinstake = coin.fCoinStake;
            result.emplace_back(outpoint, coin.out.nValue, coin.out.scriptPubKey,
                                height, time, coinbase, coinstake);
        }
        cursor->Next();
    }
    return result;
}

class CursorCountingCoinsView final : public CCoinsView
{
public:
    mutable size_t cursor_calls{0};

    std::unique_ptr<CCoinsViewCursor> Cursor() const override
    {
        ++cursor_calls;
        return nullptr;
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(curve_boundaries_and_flooring)
{
    using namespace Consensus;

    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(0), DEMURRAGE_PPM);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_GRACE_BLOCKS), DEMURRAGE_PPM);
    BOOST_CHECK(DemurrageRemainingPpm(DEMURRAGE_GRACE_BLOCKS + 1000) < DEMURRAGE_PPM);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_ZERO_BLOCKS), 0);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(DEMURRAGE_ZERO_BLOCKS + 1), 0);

    const int twelve_months = 12 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int fifteen_months = 15 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int eighteen_months = 18 * DEMURRAGE_BLOCKS_PER_MONTH;
    const int twenty_one_months = 21 * DEMURRAGE_BLOCKS_PER_MONTH;
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(twelve_months), 888890);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(fifteen_months), 750000);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(eighteen_months), 555557);
    BOOST_CHECK_EQUAL(DemurrageRemainingPpm(twenty_one_months), 305557);

    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1 * COIN, DEMURRAGE_PPM), 1 * COIN);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1 * COIN, 750000), 75000000);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(1, 999999), 0);
    BOOST_CHECK_EQUAL(DemurrageEffectiveValue(MAX_MONEY, DEMURRAGE_PPM), MAX_MONEY);
}

BOOST_AUTO_TEST_CASE(decay_is_destroyed_and_never_reclassified_as_transaction_fee)
{
    using namespace Consensus;

    const Params& params = ::Params().GetConsensus();
    const int coin_height = params.EffectiveDemurrageActivationHeight();
    const int spend_height = coin_height + params.DemurrageGraceBlocks() + 1000;
    const int64_t spend_time = params.nQuantumMigrationDeadlineTime + 1;
    const CAmount nominal_value = 10 * COIN;
    const CAmount explicit_fee = 10 * CENT;
    const CScript script = QuantumMigrationScriptForPubkey(
        std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x73));
    const COutPoint outpoint{uint256::ONE, 73};
    const Coin coin = TestCoin(nominal_value, coin_height, script);
    const DemurrageEvaluation eval = EvaluateDemurrage(
        coin, params, spend_height, spend_time);
    BOOST_REQUIRE(eval.active);
    BOOST_REQUIRE(!eval.locked);
    BOOST_REQUIRE_GT(eval.burned_value, 0);
    BOOST_REQUIRE_GT(eval.effective_value, explicit_fee);
    BOOST_CHECK_EQUAL(eval.nominal_value,
                      eval.effective_value + eval.burned_value);

    CCoinsView base;
    CCoinsViewCache view{&base};
    view.AddCoin(outpoint, Coin{coin}, false);

    CMutableTransaction spend;
    spend.nVersion = 2;
    spend.nTime = static_cast<uint32_t>(spend_time);
    spend.vin.emplace_back(outpoint);
    spend.vout.emplace_back(eval.effective_value - explicit_fee, script);

    TxValidationState state;
    CAmount measured_fee{-1};
    BOOST_REQUIRE(CheckTxInputs(CTransaction{spend}, state, view,
                                spend_height, spend_time, spend_time,
                                measured_fee));
    BOOST_CHECK_EQUAL(measured_fee, explicit_fee);
    BOOST_CHECK_NE(measured_fee, explicit_fee + eval.burned_value);
    BOOST_CHECK_EQUAL(nominal_value - spend.vout[0].nValue,
                      eval.burned_value + explicit_fee);

    // Neither the recipient nor the block producer may reclaim one satoshi of
    // burned principal by presenting it as transaction output value.
    spend.vout[0].nValue = eval.effective_value + 1;
    TxValidationState overclaim_state;
    measured_fee = -1;
    BOOST_CHECK(!CheckTxInputs(CTransaction{spend}, overclaim_state, view,
                               spend_height, spend_time, spend_time,
                               measured_fee));
    BOOST_CHECK_EQUAL(overclaim_state.GetRejectReason(), "bad-txns-in-belowout");
}

BOOST_AUTO_TEST_CASE(gate_off_and_non_retroactive_clock)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1000);
    const Coin old_coin = TestCoin(10 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x33)));

    DemurrageEvaluation before = EvaluateDemurrage(old_coin, params, /*spend_height=*/999, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!before.active);
    BOOST_CHECK_EQUAL(before.effective_value, 10 * COIN);

    DemurrageEvaluation at_activation = EvaluateDemurrage(old_coin, params, /*spend_height=*/1000, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(at_activation.active);
    BOOST_CHECK(at_activation.exempt);
    BOOST_CHECK_EQUAL(at_activation.exemption, "young");
    BOOST_CHECK_EQUAL(at_activation.inactive_blocks, 0);
    BOOST_CHECK_EQUAL(at_activation.effective_value, 10 * COIN);

    DemurrageEvaluation after_grace = EvaluateDemurrage(old_coin, params, 1000 + DEMURRAGE_GRACE_BLOCKS + 1000, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(after_grace.active);
    BOOST_CHECK(!after_grace.exempt);
    BOOST_CHECK(!after_grace.locked);
    BOOST_CHECK(after_grace.effective_value < 10 * COIN);
    BOOST_CHECK(after_grace.burned_value > 0);
}

BOOST_AUTO_TEST_CASE(activation_requires_post_migration_deadline_and_gold_rush_clamp)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    params.nDemurrageMinActivationHeight = 100;
    const Coin quantum_coin = TestCoin(10 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x34)));

    BOOST_CHECK(!params.IsDemurrageActive(/*nHeight=*/99, TEST_POST_MIGRATION_TIME));
    BOOST_CHECK(!params.IsDemurrageActive(/*nHeight=*/100, TEST_MIGRATION_DEADLINE_TIME));
    BOOST_CHECK(params.IsDemurrageActive(/*nHeight=*/100, TEST_POST_MIGRATION_TIME));

    DemurrageEvaluation before_deadline = EvaluateDemurrage(quantum_coin, params, DEMURRAGE_ZERO_BLOCKS, TEST_MIGRATION_DEADLINE_TIME);
    BOOST_CHECK(!before_deadline.active);
    BOOST_CHECK_EQUAL(before_deadline.effective_value, 10 * COIN);

    DemurrageEvaluation before_min_height = EvaluateDemurrage(quantum_coin, params, /*spend_height=*/99, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!before_min_height.active);
    BOOST_CHECK_EQUAL(before_min_height.effective_value, 10 * COIN);
}

BOOST_AUTO_TEST_CASE(activation_inventory_preparation_is_bounded)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    CursorCountingCoinsView base;
    CCoinsViewCache view(&base);
    CBlockIndex predecessor;
    const uint256 predecessor_hash = uint256S("0a");
    InitTestIndex(predecessor, /*height=*/0, predecessor_hash);
    predecessor.nTime = TEST_POST_MIGRATION_TIME;

    BOOST_REQUIRE(PrepareDemurrageActivationInventory(view, &predecessor, params));
    BOOST_CHECK_EQUAL(base.cursor_calls, 0U);
    BOOST_CHECK(HasCurrentDemurrageInventory(view, &predecessor, params));
    BOOST_CHECK_EQUAL(base.cursor_calls, 0U);
}

BOOST_AUTO_TEST_CASE(activation_sentinel_is_branch_bound)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    CCoinsView base;
    CCoinsViewCache view(&base);

    CBlockIndex original_predecessor;
    CBlockIndex alternate_predecessor;
    const uint256 original_hash = uint256S("0f");
    const uint256 alternate_hash = uint256S("10");
    InitTestIndex(original_predecessor, /*height=*/0, original_hash);
    InitTestIndex(alternate_predecessor, /*height=*/0, alternate_hash);
    original_predecessor.nTime = TEST_POST_MIGRATION_TIME;
    alternate_predecessor.nTime = TEST_POST_MIGRATION_TIME;

    CBlockIndex original_activation;
    CBlockIndex alternate_activation;
    const uint256 original_activation_hash = uint256S("11");
    const uint256 alternate_activation_hash = uint256S("12");
    InitTestIndex(original_activation, /*height=*/1, original_activation_hash);
    InitTestIndex(alternate_activation, /*height=*/1, alternate_activation_hash);
    original_activation.pprev = &original_predecessor;
    alternate_activation.pprev = &alternate_predecessor;

    BOOST_REQUIRE(PrepareDemurrageActivationInventory(
        view, &original_predecessor, params));
    BOOST_CHECK(HasCurrentDemurrageInventory(
        view, &original_predecessor, params));
    BOOST_CHECK(CanApplyDemurrageInventory(
        view, &original_activation, params));

    // A same-height competing predecessor cannot inherit the old branch's
    // empty sentinel or overwrite it in place. Recovery must first undo the
    // connected predecessor, then materialize a sentinel bound to the new tip.
    BOOST_CHECK(!HasCurrentDemurrageInventory(
        view, &alternate_predecessor, params));
    BOOST_CHECK(!CanApplyDemurrageInventory(
        view, &alternate_activation, params));
    BOOST_CHECK(!PrepareDemurrageActivationInventory(
        view, &alternate_predecessor, params));

    const CBlock empty_block;
    BOOST_REQUIRE(UndoDemurrageBlock(
        view, empty_block, &original_predecessor, params));
    BOOST_REQUIRE(PrepareDemurrageActivationInventory(
        view, &alternate_predecessor, params));
    BOOST_CHECK(HasCurrentDemurrageInventory(
        view, &alternate_predecessor, params));
    BOOST_CHECK(CanApplyDemurrageInventory(
        view, &alternate_activation, params));
}

BOOST_AUTO_TEST_CASE(purge_recognizes_only_authenticated_obsolete_reserved_state)
{
    using namespace Consensus;

    CBlockIndex tip;
    const uint256 tip_hash = uint256S("0b");
    InitTestIndex(tip, /*height=*/12, tip_hash);
    const uint256 pubkey_hash = uint256S("0c");
    const uint256 legacy_pubkey_hash = uint256S("13");
    const uint256 source_txid = uint256S("0d");
    const std::vector<unsigned char> latest_payload =
        PrereleaseLatestPayload(pubkey_hash, tip, source_txid);
    const std::vector<unsigned char> legacy_latest_payload{
        legacy_pubkey_hash.begin(), legacy_pubkey_hash.end()};

    CCoinsView base;
    CCoinsViewCache view(&base);
    const COutPoint obsolete_latest = PrereleaseLatestOutpoint(pubkey_hash);
    const COutPoint obsolete_legacy_latest =
        PrereleaseLatestOutpoint(legacy_pubkey_hash);
    const COutPoint obsolete_inventory = PrereleaseInventoryOutpoint();
    const COutPoint ordinary_user_outpoint{uint256S("0e"), 1};
    view.AddCoin(obsolete_latest,
                 TestMarkerCoin(0, TestMarkerScript(TEST_TAG_LATEST, latest_payload),
                                tip.nHeight, tip.GetBlockTime()),
                 /*possible_overwrite=*/false);
    view.AddCoin(obsolete_legacy_latest,
                 TestMarkerCoin(0, TestMarkerScript(
                     TEST_TAG_LATEST, legacy_latest_payload),
                     tip.nHeight, tip.GetBlockTime()),
                 /*possible_overwrite=*/false);
    view.AddCoin(obsolete_inventory,
                 TestMarkerCoin(0, TestMarkerScript(
                     TEST_TAG_INVENTORY, PrereleaseEmptyInventoryPayload(tip)),
                     tip.nHeight, tip.GetBlockTime()),
                 /*possible_overwrite=*/false);
    // An exact marker payload at a normal transaction outpoint is user state,
    // not an auxiliary record, and must never be removed by cleanup.
    view.AddCoin(ordinary_user_outpoint,
                 TestMarkerCoin(0, TestMarkerScript(TEST_TAG_LATEST, latest_payload),
                                tip.nHeight, tip.GetBlockTime()),
                 /*possible_overwrite=*/false);

    uint64_t removed{999};
    BOOST_REQUIRE(PurgeAuthenticatedDemurrageState(view, &tip, removed));
    BOOST_CHECK_EQUAL(removed, 3U);
    BOOST_CHECK(!view.HaveCoin(obsolete_latest));
    BOOST_CHECK(!view.HaveCoin(obsolete_legacy_latest));
    BOOST_CHECK(!view.HaveCoin(obsolete_inventory));
    BOOST_CHECK(view.HaveCoin(ordinary_user_outpoint));

    // Even at the reserved outpoint, value-bearing or non-auxiliary metadata
    // is not authenticated as internal state.
    view.AddCoin(obsolete_latest,
                 TestMarkerCoin(1, TestMarkerScript(TEST_TAG_LATEST, latest_payload),
                                tip.nHeight, tip.GetBlockTime()),
                 /*possible_overwrite=*/false);
    removed = 999;
    BOOST_REQUIRE(PurgeAuthenticatedDemurrageState(view, &tip, removed));
    BOOST_CHECK_EQUAL(removed, 0U);
    BOOST_CHECK(view.HaveCoin(obsolete_latest));
    BOOST_CHECK(view.HaveCoin(ordinary_user_outpoint));
}

BOOST_AUTO_TEST_CASE(exemptions_and_locked_spend_state)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    const int spend_height = 1 + DEMURRAGE_ZERO_BLOCKS;

    const Coin inactive_cold = TestCoin(5 * COIN, /*height=*/1, QuantumColdStakeScript());
    DemurrageEvaluation inactive_cold_eval = EvaluateDemurrage(
        inactive_cold, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(inactive_cold_eval.locked);
    BOOST_CHECK_EQUAL(inactive_cold_eval.effective_value, 0);

    const Coin active_cold = TestCoin(5 * COIN, spend_height - 100, QuantumColdStakeScript());
    DemurrageEvaluation active_cold_eval = EvaluateDemurrage(
        active_cold, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!active_cold_eval.locked);
    BOOST_CHECK_EQUAL(active_cold_eval.exemption, "young");
    BOOST_CHECK_EQUAL(active_cold_eval.effective_value, 5 * COIN);

    const CScript tiered_script = GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumTieredProgramForCommitment(
            QUANTUM_TIERED_STATE_BONDED, /*unbonding_blocks=*/40500,
            /*unlock_height=*/0, uint256::ONE)});
    const Coin inactive_tiered = TestCoin(3 * COIN, /*height=*/1, tiered_script);
    const DemurrageEvaluation inactive_tiered_eval = EvaluateDemurrage(
        inactive_tiered, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(inactive_tiered_eval.locked);
    BOOST_CHECK_EQUAL(inactive_tiered_eval.effective_value, 0);

    const CScript eutxo_script = GetScriptForEUTXO({0x01}, CScript{} << OP_TRUE);
    const Coin inactive_eutxo = TestCoin(4 * COIN, /*height=*/1, eutxo_script);
    const DemurrageEvaluation inactive_eutxo_eval = EvaluateDemurrage(
        inactive_eutxo, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(inactive_eutxo_eval.locked);
    BOOST_CHECK_EQUAL(inactive_eutxo_eval.effective_value, 0);

    const CScript treasury_script = PlainScript(0x44);
    params.m_demurrage_exempt_scripts.push_back(treasury_script);
    const Coin treasury = TestCoin(6 * COIN, /*height=*/1, treasury_script);
    DemurrageEvaluation treasury_eval = EvaluateDemurrage(treasury, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(treasury_eval.exempt);
    BOOST_CHECK_EQUAL(treasury_eval.exemption, "treasury");
    BOOST_CHECK_EQUAL(treasury_eval.effective_value, 6 * COIN);

    const Coin attested = TestCoin(7 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x55)));
    DemurrageEvaluation attested_eval = EvaluateDemurrage(
        attested, params, spend_height, TEST_POST_MIGRATION_TIME,
        spend_height - 100, spend_height - 100);
    BOOST_CHECK(attested_eval.exempt);
    BOOST_CHECK_EQUAL(attested_eval.exemption, "attested");
    BOOST_CHECK_EQUAL(attested_eval.effective_value, 7 * COIN);

    const Coin locked = TestCoin(8 * COIN, /*height=*/1, QuantumMigrationScriptForPubkey(std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x66)));
    DemurrageEvaluation locked_eval = EvaluateDemurrage(locked, params, spend_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(locked_eval.locked);
    BOOST_CHECK_EQUAL(locked_eval.remaining_ppm, 0);
    BOOST_CHECK_EQUAL(locked_eval.effective_value, 0);
    BOOST_CHECK_EQUAL(locked_eval.burned_value, 8 * COIN);
}

BOOST_AUTO_TEST_CASE(attestation_coverage_epoch_cannot_resurrect_terminal_coin)
{
    using namespace Consensus;

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    const CScript script = QuantumMigrationScriptForPubkey(
        std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x67));
    const Coin old_coin = TestCoin(8 * COIN, /*height=*/1, script);
    const int terminal_height = 1 + params.DemurrageZeroBlocks();

    const DemurrageEvaluation just_before_zero = EvaluateDemurrage(
        old_coin, params, terminal_height - 1, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(!just_before_zero.locked);
    const DemurrageEvaluation at_zero = EvaluateDemurrage(
        old_coin, params, terminal_height, TEST_POST_MIGRATION_TIME);
    BOOST_CHECK(at_zero.locked);

    const int late_attestation_height = terminal_height + 100;
    const DemurrageEvaluation late_old = EvaluateDemurrage(
        old_coin, params, late_attestation_height, TEST_POST_MIGRATION_TIME,
        late_attestation_height, late_attestation_height);
    BOOST_CHECK(late_old.locked);

    const Coin fresh_same_key = TestCoin(2 * COIN, late_attestation_height - 1, script);
    const DemurrageEvaluation late_fresh = EvaluateDemurrage(
        fresh_same_key, params, late_attestation_height, TEST_POST_MIGRATION_TIME,
        late_attestation_height, late_attestation_height);
    BOOST_CHECK(!late_fresh.locked);
    BOOST_CHECK_EQUAL(late_fresh.effective_value, 2 * COIN);

    const DemurrageEvaluation continuous_old = EvaluateDemurrage(
        old_coin, params, late_attestation_height, TEST_POST_MIGRATION_TIME,
        late_attestation_height, /*coverage_start_height=*/terminal_height - 1);
    BOOST_CHECK(!continuous_old.locked);
    BOOST_CHECK_EQUAL(continuous_old.exemption, "attested");
}

BOOST_AUTO_TEST_CASE(terminal_output_cannot_be_owner_cleaned_with_a_separate_fee_input)
{
    const Consensus::Params& params = Params().GetConsensus();
    const int coin_height = params.EffectiveDemurrageActivationHeight();
    const int spend_height = coin_height + params.DemurrageZeroBlocks();
    const int64_t spend_time = params.nQuantumMigrationDeadlineTime + 1;
    const CScript terminal_script = QuantumMigrationScriptForPubkey(
        std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x68));
    const CScript fee_script = QuantumMigrationScriptForPubkey(
        std::vector<unsigned char>(ML_DSA::PUBLICKEY_BYTES, 0x69));

    const COutPoint terminal_outpoint{uint256{68}, 0};
    const COutPoint fee_outpoint{uint256{69}, 0};
    CCoinsView base;
    CCoinsViewCache view{&base};
    view.AddCoin(terminal_outpoint,
                 TestCoin(8 * COIN, coin_height, terminal_script), false);
    view.AddCoin(fee_outpoint,
                 TestCoin(1 * COIN, spend_height - 1, fee_script), false);

    const Consensus::DemurrageEvaluation terminal = Consensus::EvaluateDemurrage(
        TestCoin(8 * COIN, coin_height, terminal_script), params,
        spend_height, spend_time);
    BOOST_REQUIRE(terminal.locked);
    BOOST_CHECK_EQUAL(terminal.effective_value, 0);

    CMutableTransaction cleanup;
    cleanup.vin.emplace_back(terminal_outpoint);
    cleanup.vin.emplace_back(fee_outpoint);
    cleanup.vout.emplace_back(COIN - 1, fee_script);
    TxValidationState state;
    CAmount fee{-1};
    BOOST_CHECK(!Consensus::CheckTxInputs(
        CTransaction{cleanup}, state, view, spend_height, spend_time,
        spend_time, fee));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-spends-locked-coin");
}

BOOST_AUTO_TEST_CASE(attestation_index_connect_disconnect)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const int height = 1234;
    const COutPoint replay_anchor{uint256::ONE, 0};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(replay_anchor);
    mtx.vout.emplace_back(0, BuildTestAttestationScript(replay_anchor, public_key, signature));
    const CTransaction tx{mtx};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));
    const uint256 block_hash = block.GetHash();
    CBlockIndex index;
    InitTestIndex(index, height, block_hash);
    Consensus::Params params = ActiveParams(/*activation_height=*/1);

    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(DefaultAttestationTarget(),
                 TestCoin(COIN, /*height=*/1, QuantumMigrationScriptForPubkey(public_key)), false);
    CBlockIndex activation_predecessor;
    const uint256 activation_predecessor_hash = uint256S("01");
    AttachActivationPredecessor(view, index, params, activation_predecessor,
                                activation_predecessor_hash);
    const std::vector<CoinState> before_first = SnapshotCoins(view);
    std::string reject_reason;
    BOOST_CHECK(ApplyDemurrageBlock(view, block, &index, params, reject_reason));
    const uint256 pubkey_hash = DemurragePubKeyHash(public_key);
    BOOST_REQUIRE(LatestDemurrageAttestationHeight(view, pubkey_hash).has_value());
    BOOST_CHECK_EQUAL(*LatestDemurrageAttestationHeight(view, pubkey_hash), height);
    BOOST_REQUIRE(LatestDemurrageAttestationState(view, pubkey_hash).has_value());
    BOOST_CHECK_EQUAL(LatestDemurrageAttestationState(view, pubkey_hash)->coverage_start_height, height);
    const std::vector<CoinState> after_first = SnapshotCoins(view);
    BOOST_REQUIRE(RollforwardDemurrageBlock(view, block, &index, params));
    BOOST_CHECK(SnapshotCoins(view) == after_first);

    const CScript migration_script = QuantumMigrationScriptForPubkey(public_key);
    BOOST_REQUIRE(LatestDemurrageAttestationHeightForScript(view, migration_script).has_value());
    BOOST_CHECK_EQUAL(*LatestDemurrageAttestationHeightForScript(view, migration_script), height);

    const std::vector<CoinState> before_reattest = SnapshotCoins(view);
    const COutPoint second_anchor{uint256::ONE, 1};
    const DemurrageAttestationSource first_source{
        index.GetBlockHash(), tx.GetHash(), /*output_index=*/0};
    const std::vector<unsigned char> second_signature = SignAttestation(
        private_key, second_anchor, public_key, DefaultAttestationTarget(), height,
        index.GetBlockTime(), height, first_source);
    CMutableTransaction second_mtx;
    second_mtx.vin.emplace_back(second_anchor);
    second_mtx.vout.emplace_back(0, BuildTestAttestationScript(
        second_anchor, public_key, second_signature, DefaultAttestationTarget(), height,
        index.GetBlockTime(), height, first_source));
    CBlock second_block;
    second_block.vtx.push_back(MakeTransactionRef(CTransaction{second_mtx}));
    const uint256 second_block_hash = second_block.GetHash();
    CBlockIndex second_index;
    InitTestIndex(second_index, height + params.DemurrageAutoAttestBlocks(), second_block_hash);
    second_index.pprev = &index;
    reject_reason.clear();
    BOOST_REQUIRE(ApplyDemurrageBlock(view, second_block, &second_index, params, reject_reason));
    BOOST_REQUIRE(LatestDemurrageAttestationState(view, pubkey_hash).has_value());
    BOOST_CHECK_EQUAL(LatestDemurrageAttestationState(view, pubkey_hash)->coverage_start_height, height);
    const std::vector<CoinState> after_second = SnapshotCoins(view);

    // Recovery is tip-anchored. Replaying an ancestor over a descendant state
    // must fail without mutating the authenticated inventory.
    BOOST_CHECK(!RollforwardDemurrageBlock(view, block, &index, params));
    BOOST_CHECK(SnapshotCoins(view) == after_second);
    BOOST_REQUIRE(UndoDemurrageBlock(view, second_block, &second_index, params));
    BOOST_CHECK(SnapshotCoins(view) == before_reattest);
    BOOST_CHECK(!UndoDemurrageBlock(view, second_block, &second_index, params));
    BOOST_CHECK(SnapshotCoins(view) == before_reattest);

    BOOST_CHECK(UndoDemurrageBlock(view, block, &index, params));
    BOOST_CHECK(!LatestDemurrageAttestationHeight(view, pubkey_hash).has_value());
    BOOST_CHECK(!UndoDemurrageBlock(view, block, &index, params));
    BOOST_CHECK(SnapshotCoins(view) == before_first);
}

BOOST_AUTO_TEST_CASE(attestation_rejects_bad_signature_and_height)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const int height = 2000;
    const COutPoint replay_anchor{uint256::ONE, 7};
    std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);
    signature[0] ^= 0x01;

    CMutableTransaction bad_sig_mtx;
    bad_sig_mtx.vin.emplace_back(replay_anchor);
    bad_sig_mtx.vout.emplace_back(0, BuildTestAttestationScript(replay_anchor, public_key, signature));
    CBlock bad_sig_block;
    bad_sig_block.vtx.push_back(MakeTransactionRef(CTransaction{bad_sig_mtx}));
    const uint256 bad_sig_hash = bad_sig_block.GetHash();
    CBlockIndex bad_sig_index;
    InitTestIndex(bad_sig_index, height, bad_sig_hash);

    CCoinsView base;
    CCoinsViewCache view(&base);
    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    CBlockIndex activation_predecessor;
    const uint256 activation_predecessor_hash = uint256S("02");
    AttachActivationPredecessor(view, bad_sig_index, params, activation_predecessor,
                                activation_predecessor_hash);
    std::string reject_reason;
    BOOST_CHECK(!ApplyDemurrageBlock(view, bad_sig_block, &bad_sig_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation-signature");

    signature = SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction bad_anchor_mtx;
    bad_anchor_mtx.vin.emplace_back(COutPoint{uint256::ONE, 8});
    bad_anchor_mtx.vout.emplace_back(0, BuildTestAttestationScript(replay_anchor, public_key, signature));
    CBlock bad_anchor_block;
    bad_anchor_block.vtx.push_back(MakeTransactionRef(CTransaction{bad_anchor_mtx}));
    const uint256 bad_anchor_hash = bad_anchor_block.GetHash();
    CBlockIndex bad_height_index;
    InitTestIndex(bad_height_index, height + 1, bad_anchor_hash);
    bad_height_index.pprev = &activation_predecessor;
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, bad_anchor_block, &bad_height_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation");

    const COutPoint null_anchor;
    signature = SignAttestation(private_key, null_anchor, public_key);
    CMutableTransaction coinbase_mtx;
    coinbase_mtx.vin.emplace_back(null_anchor);
    coinbase_mtx.vout.emplace_back(0, BuildTestAttestationScript(null_anchor, public_key, signature));
    CBlock coinbase_attest_block;
    coinbase_attest_block.vtx.push_back(MakeTransactionRef(CTransaction{coinbase_mtx}));
    const uint256 coinbase_attest_hash = coinbase_attest_block.GetHash();
    CBlockIndex coinbase_attest_index;
    InitTestIndex(coinbase_attest_index, height + 2, coinbase_attest_hash);
    coinbase_attest_index.pprev = &activation_predecessor;
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, coinbase_attest_block, &coinbase_attest_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "bad-demurrage-attestation");

    view.AddCoin(DefaultAttestationTarget(),
                 TestCoin(COIN, /*height=*/1, QuantumMigrationScriptForPubkey(public_key)), false);
    signature = SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction self_spend_mtx;
    self_spend_mtx.vin.emplace_back(replay_anchor);
    self_spend_mtx.vin.emplace_back(DefaultAttestationTarget());
    self_spend_mtx.vout.emplace_back(0, BuildTestAttestationScript(
        replay_anchor, public_key, signature));
    CBlock self_spend_block;
    self_spend_block.vtx.push_back(MakeTransactionRef(CTransaction{self_spend_mtx}));
    const uint256 self_spend_hash = self_spend_block.GetHash();
    CBlockIndex self_spend_index;
    InitTestIndex(self_spend_index, height + 3, self_spend_hash);
    self_spend_index.pprev = &activation_predecessor;
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, self_spend_block, &self_spend_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "demurrage-attestation-target-conflict");
}

BOOST_AUTO_TEST_CASE(attestation_crypto_failure_is_typed_retryable_and_nonmutating)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const COutPoint replay_anchor{uint256::ONE, 12};
    const std::vector<unsigned char> signature =
        SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction mtx;
    mtx.vin.emplace_back(replay_anchor);
    mtx.vout.emplace_back(0, BuildTestAttestationScript(
        replay_anchor, public_key, signature));
    const CTransaction tx{mtx};

    CCoinsView base;
    CCoinsViewCache view{&base};
    view.AddCoin(DefaultAttestationTarget(),
                 TestCoin(COIN, /*height=*/1,
                          QuantumMigrationScriptForPubkey(public_key)), false);
    const Consensus::Params params = ActiveParams(/*activation_height=*/1);
    std::set<uint256> attested_keys;
    size_t attestation_count{0};
    std::string reject_reason;

    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BOOST_CHECK(CheckDemurrageAttestationsDetailed(
                    tx, view, params, /*spend_height=*/2000,
                    /*spend_time=*/TEST_POST_MIGRATION_TIME,
                    attested_keys, attestation_count, reject_reason) ==
                DemurrageAttestationValidationResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK_EQUAL(reject_reason, "local-demurrage-mldsa-verification-error");
    BOOST_CHECK(attested_keys.empty());
    BOOST_CHECK_EQUAL(attestation_count, 0U);

    reject_reason.clear();
    BOOST_CHECK(CheckDemurrageAttestationsDetailed(
                    tx, view, params, /*spend_height=*/2000,
                    /*spend_time=*/TEST_POST_MIGRATION_TIME,
                    attested_keys, attestation_count, reject_reason) ==
                DemurrageAttestationValidationResult::VALID);
    ML_DSA::ClearFailureForTesting();
    BOOST_CHECK(reject_reason.empty());
    BOOST_CHECK_EQUAL(attested_keys.size(), 1U);
    BOOST_CHECK_EQUAL(attestation_count, 1U);

    // Startup roll-forward is also retryable. It must complete ML-DSA
    // verification before writing any authenticated inventory records.
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));
    const uint256 block_hash = block.GetHash();
    CBlockIndex index;
    InitTestIndex(index, /*height=*/2000, block_hash);
    CCoinsView replay_base;
    CCoinsViewCache replay_view{&replay_base};
    replay_view.AddCoin(DefaultAttestationTarget(),
                        TestCoin(COIN, /*height=*/1,
                                 QuantumMigrationScriptForPubkey(public_key)), false);
    CBlockIndex activation_predecessor;
    const uint256 activation_predecessor_hash = uint256S("02");
    AttachActivationPredecessor(replay_view, index, params,
                                activation_predecessor,
                                activation_predecessor_hash);
    const std::vector<CoinState> before_rollforward = SnapshotCoins(replay_view);

    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BOOST_CHECK(!RollforwardDemurrageBlock(replay_view, block, &index, params));
    BOOST_CHECK(SnapshotCoins(replay_view) == before_rollforward);
    BOOST_CHECK(RollforwardDemurrageBlock(replay_view, block, &index, params));
    ML_DSA::ClearFailureForTesting();
    BOOST_REQUIRE(LatestDemurrageAttestationHeight(
                      replay_view, DemurragePubKeyHash(public_key)).has_value());
    BOOST_CHECK_EQUAL(*LatestDemurrageAttestationHeight(
                          replay_view, DemurragePubKeyHash(public_key)),
                      index.nHeight);
}

BOOST_AUTO_TEST_CASE(attestation_limits_and_duplicate_keys_are_consensus_enforced)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const int height = 2100;
    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(DefaultAttestationTarget(),
                 TestCoin(COIN, /*height=*/1, QuantumMigrationScriptForPubkey(public_key)), false);

    CBlock too_many_block;
    const std::vector<unsigned char> dummy_signature(ML_DSA::SIGNATURE_BYTES, 0);
    for (size_t i = 0; i <= MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK; ++i) {
        const COutPoint anchor{uint256::ONE, static_cast<uint32_t>(i + 1)};
        CMutableTransaction mtx;
        mtx.vin.emplace_back(anchor);
        mtx.vout.emplace_back(0, BuildTestAttestationScript(anchor, public_key, dummy_signature));
        too_many_block.vtx.push_back(MakeTransactionRef(CTransaction{mtx}));
    }
    const uint256 too_many_hash = too_many_block.GetHash();
    CBlockIndex too_many_index;
    InitTestIndex(too_many_index, height, too_many_hash);
    CBlockIndex activation_predecessor;
    const uint256 activation_predecessor_hash = uint256S("03");
    AttachActivationPredecessor(view, too_many_index, params, activation_predecessor,
                                activation_predecessor_hash);
    std::string reject_reason;
    BOOST_CHECK(!ApplyDemurrageBlock(view, too_many_block, &too_many_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "too-many-demurrage-attestations-block");

    CBlock duplicate_block;
    for (uint32_t i = 0; i < 2; ++i) {
        const COutPoint anchor{uint256::ONE, 100 + i};
        const std::vector<unsigned char> signature = SignAttestation(private_key, anchor, public_key);
        CMutableTransaction mtx;
        mtx.vin.emplace_back(anchor);
        mtx.vout.emplace_back(0, BuildTestAttestationScript(anchor, public_key, signature));
        duplicate_block.vtx.push_back(MakeTransactionRef(CTransaction{mtx}));
    }
    const uint256 duplicate_hash = duplicate_block.GetHash();
    CBlockIndex duplicate_index;
    InitTestIndex(duplicate_index, height + 1, duplicate_hash);
    duplicate_index.pprev = &activation_predecessor;
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, duplicate_block, &duplicate_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "duplicate-demurrage-attestation");

    const COutPoint tx_anchor{uint256::ONE, 200};
    const std::vector<unsigned char> tx_signature = SignAttestation(private_key, tx_anchor, public_key);
    CMutableTransaction too_many_tx;
    too_many_tx.vin.emplace_back(tx_anchor);
    too_many_tx.vout.emplace_back(0, BuildTestAttestationScript(tx_anchor, public_key, tx_signature));
    too_many_tx.vout.emplace_back(0, BuildTestAttestationScript(tx_anchor, public_key, tx_signature));
    CBlock too_many_tx_block;
    too_many_tx_block.vtx.push_back(MakeTransactionRef(CTransaction{too_many_tx}));
    const uint256 too_many_tx_hash = too_many_tx_block.GetHash();
    CBlockIndex too_many_tx_index;
    InitTestIndex(too_many_tx_index, height + 2, too_many_tx_hash);
    too_many_tx_index.pprev = &activation_predecessor;
    reject_reason.clear();
    BOOST_CHECK(!ApplyDemurrageBlock(view, too_many_tx_block, &too_many_tx_index, params, reject_reason));
    BOOST_CHECK_EQUAL(reject_reason, "too-many-demurrage-attestations-tx");
}

BOOST_AUTO_TEST_CASE(attestation_is_standard_even_above_default_op_return_limit)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    const COutPoint replay_anchor{uint256::ONE, 3};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(replay_anchor);
    mtx.vout.emplace_back(0, BuildTestAttestationScript(replay_anchor, public_key, signature));
    BOOST_CHECK(mtx.vout[0].scriptPubKey.size() > MAX_OP_RETURN_RELAY);
    BOOST_CHECK(IsDemurrageAttestationScript(mtx.vout[0].scriptPubKey));

    std::string reason;
    BOOST_CHECK(IsStandardTx(
        CTransaction{mtx},
        MAX_OP_RETURN_RELAY,
        /*permit_bare_multisig=*/true,
        CFeeRate{DUST_RELAY_TX_FEE},
        reason,
        /*witnessEnabled=*/true));
    BOOST_CHECK(reason.empty());

    mtx.vout[0].scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>(mtx.vout[0].scriptPubKey.size() - 3, 0x42);
    reason.clear();
    BOOST_CHECK(!IsStandardTx(
        CTransaction{mtx},
        MAX_OP_RETURN_RELAY,
        /*permit_bare_multisig=*/true,
        CFeeRate{DUST_RELAY_TX_FEE},
        reason,
        /*witnessEnabled=*/true));
    BOOST_CHECK_EQUAL(reason, "scriptpubkey");
}

BOOST_AUTO_TEST_CASE(adjusted_value_in_uses_attestation_index)
{
    using namespace Consensus;

    std::vector<unsigned char> public_key;
    std::vector<unsigned char> private_key;
    BOOST_REQUIRE(ML_DSA::KeyGen(public_key, private_key));

    Consensus::Params params = ActiveParams(/*activation_height=*/1);
    const CScript migration_script = QuantumMigrationScriptForPubkey(public_key);
    const COutPoint prevout{uint256::ONE, 1};

    CCoinsView base;
    CCoinsViewCache view(&base);
    view.AddCoin(prevout, TestCoin(10 * COIN, /*height=*/1, migration_script), false);
    view.AddCoin(DefaultAttestationTarget(), TestCoin(COIN, /*height=*/1, migration_script), false);

    CMutableTransaction spend_mtx;
    spend_mtx.vin.emplace_back(prevout);
    spend_mtx.vout.emplace_back(1 * COIN, PlainScript(0x77));
    const CTransaction spend{spend_mtx};

    const int spend_height = 1 + DEMURRAGE_ZERO_BLOCKS;
    BOOST_CHECK_EQUAL(GetDemurrageAdjustedValueIn(spend, view, params, spend_height, TEST_POST_MIGRATION_TIME), 0);

    const int attest_height = spend_height - 100;
    const COutPoint replay_anchor{uint256::ONE, 9};
    const std::vector<unsigned char> signature = SignAttestation(private_key, replay_anchor, public_key);
    CMutableTransaction attest_mtx;
    attest_mtx.vin.emplace_back(replay_anchor);
    attest_mtx.vout.emplace_back(0, BuildTestAttestationScript(replay_anchor, public_key, signature));
    CBlock attest_block;
    attest_block.vtx.push_back(MakeTransactionRef(CTransaction{attest_mtx}));
    const uint256 attest_block_hash = attest_block.GetHash();
    CBlockIndex attest_index;
    InitTestIndex(attest_index, attest_height, attest_block_hash);
    CBlockIndex activation_predecessor;
    const uint256 activation_predecessor_hash = uint256S("04");
    AttachActivationPredecessor(view, attest_index, params, activation_predecessor,
                                activation_predecessor_hash);
    std::string reject_reason;
    BOOST_REQUIRE(ApplyDemurrageBlock(view, attest_block, &attest_index, params, reject_reason));

    BOOST_CHECK_EQUAL(GetDemurrageAdjustedValueIn(spend, view, params, spend_height, TEST_POST_MIGRATION_TIME), 10 * COIN);
}

BOOST_AUTO_TEST_SUITE_END()
