// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/demurrage.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <crypto/argon2/argon2.h>
#include <crypto/mldsa.h>
#include <crypto/mldsa_kat.h>
#include <hash.h>
#include <primitives/block.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <shadow.h>
#include <test/util/setup_common.h>
#include <undo.h>
#include <util/strencodings.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr size_t MIN_QUANTUM_INPUT_NONWITNESS_BYTES{
    uint256::size() + sizeof(uint32_t) + GetSizeOfCompactSize(0) + sizeof(uint32_t)};
constexpr size_t MIN_QUANTUM_INPUT_WITNESS_BYTES{
    GetSizeOfCompactSize(2) +
    GetSizeOfCompactSize(ML_DSA::SIGNATURE_BYTES) + ML_DSA::SIGNATURE_BYTES +
    GetSizeOfCompactSize(ML_DSA::PUBLICKEY_BYTES) + ML_DSA::PUBLICKEY_BYTES};
constexpr size_t MIN_QUANTUM_INPUT_WEIGHT{
    MIN_QUANTUM_INPUT_NONWITNESS_BYTES * WITNESS_SCALE_FACTOR +
    MIN_QUANTUM_INPUT_WITNESS_BYTES};
constexpr size_t MAX_WEIGHT_BOUND_QUANTUM_INPUTS{
    V4_MAX_BLOCK_WEIGHT / MIN_QUANTUM_INPUT_WEIGHT};
constexpr size_t MAX_BLOCK_MLDSA_VERIFICATIONS{
    MAX_WEIGHT_BOUND_QUANTUM_INPUTS +
    Consensus::MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK + 1}; // PoS block signature
constexpr size_t MAXIMUM_QUANTUM_BENCHMARK_BLOCK_WEIGHT{31'997'596};
constexpr size_t MAXIMUM_QUANTUM_BENCHMARK_SERIALIZED_SIZE{30'988'642};
// Height 5,945,000 permanently fixes the mainnet whitelist at 687 entries.
// The post-activation production maximum is therefore 687 PoS records plus
// the existing 64-proof PoW evaluation budget.
constexpr uint32_t MAINNET_AUTHENTICATED_WHITELIST_ENTRIES{687};
constexpr uint32_t MAXIMUM_MAINNET_SYNTHETIC_CLAIMS{
    MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + MAX_SHADOW_POW_EVALS_PER_BLOCK};
static_assert(MIN_QUANTUM_INPUT_NONWITNESS_BYTES == 41);
static_assert(MIN_QUANTUM_INPUT_WITNESS_BYTES == 3739);
static_assert(MIN_QUANTUM_INPUT_WEIGHT == 3903);
static_assert(MAX_WEIGHT_BOUND_QUANTUM_INPUTS == 8198);
static_assert(MAX_BLOCK_MLDSA_VERIFICATIONS == 8215);
static_assert(MAINNET_SHADOW_WHITELIST_HEIGHT == 5'945'000);
static_assert(MAXIMUM_MAINNET_SYNTHETIC_CLAIMS == 751);

struct MaximumQuantumBlock
{
    CBlock block;
    CTransactionRef spend;
    std::vector<CTxOut> spent_outputs;
    size_t input_count{0};
    size_t block_weight{0};
    size_t serialized_size{0};
};

struct MLDSAVector
{
    std::vector<uint8_t> public_key{ParseHex(mldsa_kat::PUBLIC_KEY_HEX)};
    std::vector<uint8_t> message{ParseHex(mldsa_kat::VALID_MESSAGE_HEX)};
    std::vector<uint8_t> signature{ParseHex(mldsa_kat::VALID_SIGNATURE_HEX)};
};

MLDSAVector LoadMLDSAVector()
{
    MLDSAVector vector;
    if (ML_DSA::VerifyDetailed(vector.public_key, vector.message.data(),
                               vector.message.size(), vector.signature) !=
        MLDSAVerifyResult::VALID) {
        throw std::runtime_error("ML-DSA benchmark vector failed verification");
    }
    return vector;
}

void RequireSyntheticFixture(bool condition, const std::string& message)
{
    if (!condition) throw std::runtime_error(message);
}

void InitSyntheticIndex(CBlockIndex& index, int height, CBlockIndex* previous,
                        uint256& hash_storage)
{
    CBlockHeader header;
    header.nVersion = 7;
    header.hashPrevBlock = previous ? previous->GetBlockHash() : uint256{};
    header.nTime = SHADOW_EQUAL_FOOTING_TIME +
                   (height - SHADOW_WHITELIST_HEIGHT) * 64;
    header.nBits = 1;
    header.nNonce = height;
    hash_storage = header.GetHash();
    index.nVersion = header.nVersion;
    index.hashMerkleRoot = header.hashMerkleRoot;
    index.nTime = header.nTime;
    index.nBits = header.nBits;
    index.nNonce = header.nNonce;
    index.phashBlock = &hash_storage;
    index.pprev = previous;
    index.nHeight = height;
    // The fixture intentionally starts at the authenticated whitelist height,
    // not genesis. Leave pskip empty so ancestor traversal stays on the
    // contiguous pprev chain represented below.
}

CScript SyntheticLegacyTarget(uint32_t ordinal)
{
    std::vector<unsigned char> key_hash(20);
    WriteLE32(key_hash.data(), ordinal + 1);
    key_hash.back() = 0x51;
    return CScript{} << OP_DUP << OP_HASH160 << key_hash
                     << OP_EQUALVERIFY << OP_CHECKSIG;
}

CScript SyntheticQuantumPayout(uint32_t ordinal)
{
    std::vector<unsigned char> program(QUANTUM_MIGRATION_PROGRAM_SIZE);
    WriteLE32(program.data(), ordinal + 1);
    program.back() = 0xa5;
    return GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION, std::move(program)});
}

CTransactionRef MakeSyntheticCoinbase()
{
    CMutableTransaction transaction;
    transaction.vin.resize(1);
    transaction.vin[0].prevout.SetNull();
    transaction.vout.emplace_back(COIN, CScript{} << OP_TRUE);
    return MakeTransactionRef(std::move(transaction));
}

CTransactionRef MakeSyntheticCoinstake(const CScript& target)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{uint256::ONE, 1});
    transaction.vout.emplace_back(0, CScript{});
    transaction.vout.emplace_back(COIN, target);
    return MakeTransactionRef(std::move(transaction));
}

CTransactionRef MakeSyntheticSignal(const CScript& target,
                                    const std::vector<unsigned char>& signal,
                                    uint32_t ordinal)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{uint256{3}, ordinal});
    transaction.vout.emplace_back(COIN, target);
    transaction.vout.emplace_back(0, CScript{} << OP_RETURN << signal);
    return MakeTransactionRef(std::move(transaction));
}

CTransactionRef MakeSyntheticPowClaim(const CScript& target,
                                      const std::vector<unsigned char>& proof,
                                      uint32_t ordinal)
{
    CMutableTransaction transaction;
    transaction.vin.emplace_back(COutPoint{uint256{2}, ordinal});
    transaction.vout.emplace_back(COIN, target);
    transaction.vout.emplace_back(0, CScript{} << OP_RETURN << proof);
    return MakeTransactionRef(std::move(transaction));
}

bool SameSyntheticPowWork(const ShadowPowWork& lhs,
                          const ShadowPowWork& rhs)
{
    return lhs.valid == rhs.valid && lhs.target == rhs.target &&
           lhs.quantum_payout_script == rhs.quantum_payout_script &&
           lhs.height == rhs.height && lhs.prev_hash == rhs.prev_hash &&
           lhs.bits == rhs.bits && lhs.origin_bound == rhs.origin_bound &&
           lhs.input_bound == rhs.input_bound &&
           lhs.claim_outpoint == rhs.claim_outpoint;
}

const std::vector<std::vector<unsigned char>>& MaximumSyntheticPowProofs(
    const ShadowPowWork& work)
{
    struct ProofCache {
        ShadowPowWork work;
        std::vector<std::vector<unsigned char>> proofs;
    };

    // The two synthetic-state benchmarks use identical deterministic work.
    // Mine its distinct logical proofs once per benchmark process, then
    // revalidate the cached bytes against each fixture. Reusing one proof in
    // 64 carrier transactions would correctly collapse to one QQP3 logical
    // proof and would no longer exercise the 64-evaluation production bound.
    static const ProofCache cache = [&work] {
        RequireSyntheticFixture(work.valid && work.origin_bound &&
                                    !work.input_bound,
                                "maximum synthetic PoW work is invalid");
        ProofCache result{work, {}};
        result.proofs.reserve(MAX_SHADOW_POW_EVALS_PER_BLOCK);
        uint64_t start_nonce{0};
        for (uint32_t ordinal = 0;
             ordinal < MAX_SHADOW_POW_EVALS_PER_BLOCK; ++ordinal) {
            std::vector<unsigned char> proof;
            uint64_t tries_done{0};
            RequireSyntheticFixture(
                GrindShadowPowWorkDetailed(
                    work, start_nonce, /*nonce_step=*/1,
                    /*max_tries=*/1'000'000, proof, &tries_done) ==
                        ShadowPowGrindResult::FOUND &&
                    tries_done > 0 && !proof.empty(),
                "cannot mine distinct maximum synthetic PoW proof");
            result.proofs.push_back(std::move(proof));
            if (ordinal + 1 < MAX_SHADOW_POW_EVALS_PER_BLOCK) {
                RequireSyntheticFixture(
                    std::numeric_limits<uint64_t>::max() - start_nonce >=
                        tries_done,
                    "maximum synthetic PoW nonce range overflowed");
                start_nonce += tries_done;
            }
        }
        const std::set<std::vector<unsigned char>> unique{
            result.proofs.begin(), result.proofs.end()};
        RequireSyntheticFixture(
            unique.size() == MAX_SHADOW_POW_EVALS_PER_BLOCK,
            "maximum synthetic PoW proofs are not byte-distinct");
        return result;
    }();

    RequireSyntheticFixture(
        SameSyntheticPowWork(cache.work, work) &&
            cache.proofs.size() == MAX_SHADOW_POW_EVALS_PER_BLOCK &&
            std::all_of(cache.proofs.begin(), cache.proofs.end(),
                        [&work](const std::vector<unsigned char>& proof) {
                            return ValidateShadowPowProofForWork(work, proof);
                        }),
        "cached maximum synthetic PoW proofs do not match current work");
    return cache.proofs;
}

CBlockUndo MakeSyntheticUndo(const CBlock& block,
                             const std::vector<CScript>& input_scripts)
{
    RequireSyntheticFixture(!block.vtx.empty(),
                            "synthetic benchmark block has no coinbase");
    RequireSyntheticFixture(input_scripts.size() + 1 == block.vtx.size(),
                            "synthetic benchmark undo/script count mismatch");
    CBlockUndo undo;
    undo.vtxundo.resize(block.vtx.size() - 1);
    for (size_t tx_index = 1; tx_index < block.vtx.size(); ++tx_index) {
        RequireSyntheticFixture(block.vtx[tx_index]->vin.size() == 1,
                                "synthetic benchmark transaction input count changed");
        Coin coin;
        coin.out = CTxOut{10'000 * COIN, input_scripts[tx_index - 1]};
        coin.nHeight = SHADOW_WHITELIST_HEIGHT;
        coin.nTime = SHADOW_EQUAL_FOOTING_TIME;
        undo.vtxundo[tx_index - 1].vprevout.push_back(std::move(coin));
    }
    return undo;
}

bool EqualShadowPoolInfo(const ShadowGoldRushInfo& lhs,
                         const ShadowGoldRushInfo& rhs)
{
    return lhs.pow_amount == rhs.pow_amount &&
           lhs.pos_amount == rhs.pos_amount &&
           lhs.claimed_amount == rhs.claimed_amount &&
           lhs.pow_count == rhs.pow_count &&
           lhs.pos_count == rhs.pos_count &&
           lhs.last_pow_height == rhs.last_pow_height &&
           lhs.last_pos_height == rhs.last_pos_height &&
           lhs.recent_count == rhs.recent_count &&
           lhs.recent_modes == rhs.recent_modes &&
           lhs.pow_target_bits == rhs.pow_target_bits;
}

uint256 SyntheticStateIdentity(const CCoinsViewCache& view,
                               const CBlockIndex* parent)
{
    const ShadowGoldRushInfo pool = GetShadowGoldRushInfo(view, parent);
    const std::map<CScript, CScript> signals =
        GetActiveShadowSignalPayouts(view, parent);

    bool inventory_found{false};
    GoldRushInventoryInfo inventory;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) &&
            !coin.IsSpent() && IsGoldRushInventoryMarkerOutpoint(outpoint)) {
            RequireSyntheticFixture(!inventory_found,
                                    "duplicate synthetic inventory marker");
            RequireSyntheticFixture(
                DecodeAuthenticatedGoldRushInventory(outpoint, coin, parent,
                                                     inventory),
                "synthetic inventory marker failed authentication");
            inventory_found = true;
        }
        cursor->Next();
    }
    RequireSyntheticFixture(inventory_found,
                            "synthetic inventory marker is missing");

    CHashWriter writer;
    writer << std::string("Quantum Quasar Synthetic Benchmark Identity v1")
           << pool.pow_amount << pool.pos_amount << pool.claimed_amount
           << pool.pow_count << pool.pos_count << pool.last_pow_height
           << pool.last_pos_height << pool.recent_count << pool.recent_modes
           << pool.pow_target_bits << signals
           << inventory.tip_height << inventory.tip_hash
           << inventory.issued_count << inventory.issued_nominal
           << inventory.spent_count << inventory.spent_nominal;
    return writer.GetHash();
}

class MaximumSyntheticStateFixture
{
public:
    MaximumSyntheticStateFixture()
        : m_hashes(MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + 3),
          m_indexes(MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + 3),
          m_bridge_hashes(SHADOW_REWARD_START_HEIGHT -
                          SHADOW_WHITELIST_HEIGHT - 1),
          m_bridge_indexes(SHADOW_REWARD_START_HEIGHT -
                           SHADOW_WHITELIST_HEIGHT - 1)
    {
        RequireSyntheticFixture(
            SHADOW_WHITELIST_HEIGHT == MAINNET_SHADOW_WHITELIST_HEIGHT &&
                SHADOW_REWARD_START_HEIGHT ==
                    MAINNET_SHADOW_REWARD_START_HEIGHT,
            "synthetic benchmark requires the pinned mainnet shadow schedule");
        RequireSyntheticFixture(
            Params().GetConsensus().IsShadowCompetingClaimsActive(
                SHADOW_REWARD_START_HEIGHT),
            "synthetic benchmark test chain must activate bounded claims");

        m_targets.reserve(MAINNET_AUTHENTICATED_WHITELIST_ENTRIES);
        m_payouts.reserve(MAINNET_AUTHENTICATED_WHITELIST_ENTRIES);
        m_signals.reserve(MAINNET_AUTHENTICATED_WHITELIST_ENTRIES);
        for (uint32_t ordinal = 0;
             ordinal < MAINNET_AUTHENTICATED_WHITELIST_ENTRIES; ++ordinal) {
            m_targets.push_back(SyntheticLegacyTarget(ordinal));
            m_payouts.push_back(SyntheticQuantumPayout(ordinal));
            uint256 txid;
            WriteLE64(txid.begin(), ordinal + 1);
            Coin coin;
            coin.out = CTxOut{10'000 * COIN, m_targets.back()};
            coin.nHeight = SHADOW_WHITELIST_HEIGHT;
            coin.nTime = SHADOW_EQUAL_FOOTING_TIME;
            m_view.AddCoin(COutPoint{txid, 0}, std::move(coin), false);
        }

        for (auto& index : m_indexes) index = std::make_unique<CBlockIndex>();
        InitSyntheticIndex(*m_indexes[0], SHADOW_WHITELIST_HEIGHT, nullptr,
                           m_hashes[0]);
        const std::set<CScript> whitelist = BuildLegacyWhitelist(m_view);
        RequireSyntheticFixture(
            whitelist.size() == MAINNET_AUTHENTICATED_WHITELIST_ENTRIES &&
                std::all_of(m_targets.begin(), m_targets.end(),
                            [&](const CScript& target) {
                                return whitelist.count(target) == 1;
                            }),
            "synthetic benchmark does not reproduce the 687-entry mainnet snapshot bound");
        RequireSyntheticFixture(
            ApplyLegacyWhitelistSnapshot(m_view, m_indexes[0].get()),
            "cannot build maximum synthetic benchmark whitelist");
        RequireSyntheticFixture(
            GetShadowSyntheticClaimLimit(
                Params().GetConsensus(), SHADOW_REWARD_START_HEIGHT,
                MAINNET_AUTHENTICATED_WHITELIST_ENTRIES) ==
                MAXIMUM_MAINNET_SYNTHETIC_CLAIMS,
            "synthetic claim limit no longer matches the pinned mainnet bound");

        CBlockIndex* previous = m_indexes[0].get();
        // CBlockIndex::GetAncestor assumes a contiguous pprev chain. Preserve
        // the production height gap between the whitelist snapshot and reward
        // start with header-only indexes so skip-list traversal is authentic.
        for (size_t position = 0; position < m_bridge_indexes.size(); ++position) {
            m_bridge_indexes[position] = std::make_unique<CBlockIndex>();
            InitSyntheticIndex(*m_bridge_indexes[position],
                               SHADOW_WHITELIST_HEIGHT + position + 1,
                               previous, m_bridge_hashes[position]);
            previous = m_bridge_indexes[position].get();
        }
        for (uint32_t ordinal = 0;
             ordinal < MAINNET_AUTHENTICATED_WHITELIST_ENTRIES; ++ordinal) {
            const size_t index_position = ordinal + 1;
            InitSyntheticIndex(*m_indexes[index_position],
                               SHADOW_REWARD_START_HEIGHT + ordinal, previous,
                               m_hashes[index_position]);
            CBlock solve_block;
            solve_block.vtx = {
                MakeSyntheticCoinbase(),
                MakeSyntheticCoinstake(m_targets[ordinal]),
            };
            const CBlockUndo solve_undo =
                MakeSyntheticUndo(solve_block, {m_targets[ordinal]});
            RequireSyntheticFixture(
                ApplyShadowBlock(m_view, solve_block,
                                 m_indexes[index_position].get(),
                                 &solve_undo) &&
                    AdvanceGoldRushInventoryTip(
                        m_view, m_indexes[index_position].get()),
                "cannot seed synthetic benchmark solver state");
            std::vector<unsigned char> signal;
            RequireSyntheticFixture(
                BuildShadowSignalData(
                    m_targets[ordinal], m_payouts[ordinal],
                    m_indexes[index_position]->nHeight,
                    m_indexes[index_position]->GetBlockHash(), signal),
                "cannot build synthetic benchmark signal");
            m_signals.push_back(std::move(signal));
            previous = m_indexes[index_position].get();
        }

        const size_t signal_index_position =
            MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + 1;
        InitSyntheticIndex(*m_indexes[signal_index_position],
                           previous->nHeight + 1, previous,
                           m_hashes[signal_index_position]);
        CBlock signal_block;
        signal_block.vtx.push_back(MakeSyntheticCoinbase());
        // A non-whitelisted coinstake records all signals without consuming the
        // accumulated PoS pool. The timed block can then exercise 687 payouts.
        signal_block.vtx.push_back(
            MakeSyntheticCoinstake(CScript{} << OP_2));
        std::vector<CScript> signal_undo_scripts{CScript{} << OP_2};
        signal_undo_scripts.reserve(
            MAINNET_AUTHENTICATED_WHITELIST_ENTRIES + 1);
        for (uint32_t ordinal = 0;
             ordinal < MAINNET_AUTHENTICATED_WHITELIST_ENTRIES; ++ordinal) {
            signal_block.vtx.push_back(MakeSyntheticSignal(
                m_targets[ordinal], m_signals[ordinal], ordinal));
            signal_undo_scripts.push_back(m_targets[ordinal]);
        }
        const CBlockUndo signal_undo =
            MakeSyntheticUndo(signal_block, signal_undo_scripts);
        RequireSyntheticFixture(
            ApplyShadowBlock(m_view, signal_block,
                             m_indexes[signal_index_position].get(),
                             &signal_undo) &&
                AdvanceGoldRushInventoryTip(
                    m_view, m_indexes[signal_index_position].get()),
            "cannot seed maximum synthetic active-signal state");
        RequireSyntheticFixture(
            GetActiveShadowSignalCount(
                m_view, m_indexes[signal_index_position].get()) ==
                MAINNET_AUTHENTICATED_WHITELIST_ENTRIES,
            "synthetic active-signal fixture is not maximal");

        const size_t target_index_position = signal_index_position + 1;
        InitSyntheticIndex(*m_indexes[target_index_position],
                           m_indexes[signal_index_position]->nHeight + 1,
                           m_indexes[signal_index_position].get(),
                           m_hashes[target_index_position]);
        m_parent = m_indexes[signal_index_position].get();
        m_target = m_indexes[target_index_position].get();

        const CScript pow_target = CScript{} << OP_3;
        const ShadowPowWork pow_work = PrepareShadowPowWork(
            pow_target, m_payouts.front(), m_parent, m_view);
        const auto& pow_proofs = MaximumSyntheticPowProofs(pow_work);

        m_block.vtx.push_back(MakeSyntheticCoinbase());
        m_block.vtx.push_back(MakeSyntheticCoinstake(m_targets.front()));
        std::vector<CScript> target_undo_scripts{m_targets.front()};
        target_undo_scripts.reserve(
            1 + MAINNET_AUTHENTICATED_WHITELIST_ENTRIES +
            MAX_SHADOW_POW_EVALS_PER_BLOCK);
        std::set<uint256> pow_logical_proof_ids;
        // Refreshing every signal in the measured block exercises the maximum
        // active-state manifest, shards, and undo shards at the same time as
        // the maximum authenticated claim family.
        for (uint32_t ordinal = 0;
             ordinal < MAINNET_AUTHENTICATED_WHITELIST_ENTRIES; ++ordinal) {
            m_block.vtx.push_back(MakeSyntheticSignal(
                m_targets[ordinal], m_signals[ordinal], ordinal));
            target_undo_scripts.push_back(m_targets[ordinal]);
        }
        for (uint32_t ordinal = 0;
             ordinal < MAX_SHADOW_POW_EVALS_PER_BLOCK; ++ordinal) {
            const CTransactionRef claim = MakeSyntheticPowClaim(
                pow_target, pow_proofs.at(ordinal), ordinal);
            const auto logical_proof_id = GetShadowPowProofLogicalId(*claim);
            RequireSyntheticFixture(
                logical_proof_id &&
                    pow_logical_proof_ids.insert(*logical_proof_id).second,
                "maximum synthetic PoW proof identity is not distinct");
            m_block.vtx.push_back(claim);
            target_undo_scripts.push_back(pow_target);
        }
        RequireSyntheticFixture(
            pow_logical_proof_ids.size() == MAX_SHADOW_POW_EVALS_PER_BLOCK,
            "maximum synthetic PoW logical proof set is incomplete");
        m_undo = MakeSyntheticUndo(m_block, target_undo_scripts);
        m_parent_pool = GetShadowGoldRushInfo(m_view, m_parent);
        m_parent_signals = GetActiveShadowSignalPayouts(m_view, m_parent);
        RequireSyntheticFixture(
            m_parent_signals.size() ==
                MAINNET_AUTHENTICATED_WHITELIST_ENTRIES,
            "synthetic benchmark parent signal set changed");
        m_parent_identity = SyntheticStateIdentity(m_view, m_parent);
    }

    bool ApplyAndUndoCold()
    {
        // A fresh child cache on every timed iteration includes first-touch
        // marker/tombstone allocation. It cannot become artificially cheaper
        // because a prior iteration retained warmed synthetic entries.
        {
            CCoinsViewCache transition_view{&m_view, true};
            if (!ApplyAndUndo(transition_view)) return false;
        }
        return m_view.GetCacheSize() == m_parent_cache_size &&
               m_view.DynamicMemoryUsage() == m_parent_cache_memory;
    }

    void VerifyMaximumTransition()
    {
        CCoinsViewCache transition_view{&m_view, true};
        RequireSyntheticFixture(
            ApplyShadowBlockResult(transition_view, m_block, m_target, &m_undo) ==
                    ShadowApplyResult::OK &&
                AdvanceGoldRushInventoryTip(transition_view, m_target),
            "maximum synthetic benchmark apply failed");
        const std::vector<ShadowSyntheticPayoutTransaction> payouts =
            GetAppliedShadowClaimPayoutTransactionRecords(
                transition_view, m_target->nHeight, m_target->GetBlockHash(),
                m_target->GetBlockTime());
        RequireSyntheticFixture(
            payouts.size() == MAXIMUM_MAINNET_SYNTHETIC_CLAIMS,
            "maximum synthetic benchmark claim count changed");
        RequireSyntheticFixture(
            std::count_if(
                payouts.begin(), payouts.end(),
                [](const ShadowSyntheticPayoutTransaction& payout) {
                    return payout.proof_of_work;
                }) == MAX_SHADOW_POW_EVALS_PER_BLOCK,
            "maximum synthetic benchmark PoW claim count changed");
        RequireSyntheticFixture(
            UndoShadowBlock(transition_view, m_block, m_target, &m_undo) &&
                RewindGoldRushInventoryTip(transition_view, m_target),
            "maximum synthetic benchmark undo failed");
        RequireSyntheticFixture(
            SyntheticStateIdentity(transition_view, m_parent) == m_parent_identity,
            "maximum synthetic benchmark apply/undo changed parent state");

        // Independently prove that a production-style persistent cache reaches
        // a fixed point after its first connect/disconnect. Repeated cycles may
        // not accumulate tombstones or allocator growth.
        CCoinsViewCache persistent_view{&m_view, true};
        RequireSyntheticFixture(
            ApplyAndUndo(persistent_view),
            "persistent synthetic benchmark preflight failed");
        const unsigned int stable_cache_size = persistent_view.GetCacheSize();
        const size_t stable_cache_memory = persistent_view.DynamicMemoryUsage();
        for (int attempt = 0; attempt < 3; ++attempt) {
            RequireSyntheticFixture(
                ApplyAndUndo(persistent_view) &&
                    persistent_view.GetCacheSize() == stable_cache_size &&
                    persistent_view.DynamicMemoryUsage() == stable_cache_memory,
                "repeated synthetic apply/undo grew persistent cache state");
        }

        // The timed path uses disposable children. Record the immutable parent
        // cache after preflight so every measured iteration proves isolation.
        m_parent_cache_size = m_view.GetCacheSize();
        m_parent_cache_memory = m_view.DynamicMemoryUsage();
    }

    void VerifyFinalIdentity() const
    {
        RequireSyntheticFixture(
            SyntheticStateIdentity(m_view, m_parent) == m_parent_identity &&
                m_view.GetCacheSize() == m_parent_cache_size &&
                m_view.DynamicMemoryUsage() == m_parent_cache_memory,
            "repeated synthetic benchmark transitions changed parent state");
    }

    void PrepareSnapshotLookupBenchmark()
    {
        m_lookup_view = std::make_unique<CCoinsViewCache>(&m_view, true);
        RequireSyntheticFixture(
            ApplyShadowBlockResult(*m_lookup_view, m_block, m_target, &m_undo) ==
                    ShadowApplyResult::OK &&
                AdvanceGoldRushInventoryTip(*m_lookup_view, m_target),
            "maximum synthetic marker-lookup fixture apply failed");
        m_lookup_payouts = GetAppliedShadowClaimPayoutCoins(
            *m_lookup_view, m_target->nHeight, m_target->GetBlockHash(),
            m_target->GetBlockTime());
        RequireSyntheticFixture(
            m_lookup_payouts.size() == MAXIMUM_MAINNET_SYNTHETIC_CLAIMS,
            "maximum synthetic marker-lookup claim count changed");
        m_lookup_memory = m_lookup_view->DynamicMemoryUsage();
        RequireSyntheticFixture(LookupMaximumSnapshotMarkers(),
                                "maximum synthetic marker-lookup preflight failed");
    }

    bool LookupMaximumSnapshotMarkers() const
    {
        if (!m_lookup_view ||
            m_lookup_payouts.size() != MAXIMUM_MAINNET_SYNTHETIC_CLAIMS) {
            return false;
        }
        std::unique_ptr<CCoinsViewCursor> marker_cursor =
            m_lookup_view->Cursor();
        if (!marker_cursor) return false;
        for (const ShadowSyntheticPayoutCoin& payout : m_lookup_payouts) {
            GoldRushPayoutMarkerInfo info;
            if (LookupAuthenticatedGoldRushPayoutMarker(
                    *marker_cursor, payout.outpoint, m_target, info) !=
                    GoldRushPayoutMarkerLookupResult::AUTHENTICATED ||
                info.payout_outpoint != payout.outpoint ||
                info.payout_script != payout.txout.scriptPubKey ||
                info.nominal_amount != payout.txout.nValue ||
                info.origin_height != payout.height ||
                info.origin_block_time != payout.time) {
                return false;
            }
        }
        return m_lookup_view->DynamicMemoryUsage() == m_lookup_memory;
    }

private:
    bool ApplyAndUndo(CCoinsViewCache& view) const
    {
        if (ApplyShadowBlockResult(view, m_block, m_target, &m_undo) !=
                ShadowApplyResult::OK ||
            !AdvanceGoldRushInventoryTip(view, m_target) ||
            !UndoShadowBlock(view, m_block, m_target, &m_undo) ||
            !RewindGoldRushInventoryTip(view, m_target)) {
            return false;
        }
        return EqualShadowPoolInfo(
                   GetShadowGoldRushInfo(view, m_parent), m_parent_pool) &&
               GetActiveShadowSignalPayouts(view, m_parent) ==
                   m_parent_signals &&
               SyntheticStateIdentity(view, m_parent) == m_parent_identity;
    }

    CCoinsView m_base;
    CCoinsViewCache m_view{&m_base, true};
    std::vector<uint256> m_hashes;
    std::vector<std::unique_ptr<CBlockIndex>> m_indexes;
    std::vector<uint256> m_bridge_hashes;
    std::vector<std::unique_ptr<CBlockIndex>> m_bridge_indexes;
    std::vector<CScript> m_targets;
    std::vector<CScript> m_payouts;
    std::vector<std::vector<unsigned char>> m_signals;
    CBlockIndex* m_parent{nullptr};
    CBlockIndex* m_target{nullptr};
    CBlock m_block;
    CBlockUndo m_undo;
    ShadowGoldRushInfo m_parent_pool;
    std::map<CScript, CScript> m_parent_signals;
    uint256 m_parent_identity;
    unsigned int m_parent_cache_size{0};
    size_t m_parent_cache_memory{0};
    std::unique_ptr<CCoinsViewCache> m_lookup_view;
    std::vector<ShadowSyntheticPayoutCoin> m_lookup_payouts;
    size_t m_lookup_memory{0};
};

MaximumQuantumBlock BuildMaximumQuantumBlock(
    const std::vector<uint8_t>& public_key,
    const std::vector<uint8_t>& private_key,
    uint32_t chain_id)
{
    const CScript quantum_script = GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        QuantumMigrationProgramForPubkey(public_key)});
    const CTxOut spent_output{COIN, quantum_script};

    CMutableTransaction spend;
    spend.nVersion = 2;
    spend.vout.emplace_back(COIN, quantum_script);
    spend.vin.reserve(MAX_WEIGHT_BOUND_QUANTUM_INPUTS);
    for (size_t input_index = 0;
         input_index < MAX_WEIGHT_BOUND_QUANTUM_INPUTS; ++input_index) {
        uint256 txid;
        WriteLE64(txid.begin(), input_index + 1);
        spend.vin.emplace_back(COutPoint{txid, 0});
        spend.vin.back().scriptWitness.stack = {
            std::vector<unsigned char>(ML_DSA::SIGNATURE_BYTES),
            std::vector<unsigned char>(public_key.begin(), public_key.end()),
        };
    }

    CMutableTransaction coinbase;
    coinbase.nVersion = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << OP_0 << OP_0;
    coinbase.vout.emplace_back(0, CScript{} << OP_RETURN);

    const auto assemble = [&coinbase](const CMutableTransaction& candidate) {
        CBlock block;
        block.nVersion = 7;
        block.nTime = 1;
        block.vtx = {
            MakeTransactionRef(CTransaction{coinbase}),
            MakeTransactionRef(CTransaction{candidate}),
        };
        block.hashMerkleRoot = BlockMerkleRoot(block);
        return block;
    };

    CBlock block = assemble(spend);
    while (GetBlockWeight(block) > V4_MAX_BLOCK_WEIGHT) {
        if (spend.vin.empty()) {
            throw std::runtime_error("cannot construct maximum-weight quantum block");
        }
        spend.vin.pop_back();
        block = assemble(spend);
    }
    if (V4_MAX_BLOCK_WEIGHT - GetBlockWeight(block) >= MIN_QUANTUM_INPUT_WEIGHT) {
        throw std::runtime_error("maximum-weight quantum block is not at the realizable input boundary");
    }

    std::vector<CTxOut> spent_outputs(spend.vin.size(), spent_output);
    for (size_t input_index = 0; input_index < spend.vin.size(); ++input_index) {
        const uint256 sighash = QuantumSignatureHash(
            spend, input_index, spent_outputs, chain_id);
        std::vector<uint8_t> signature;
        if (!ML_DSA::Sign(private_key, sighash.begin(), uint256::size(), signature)) {
            throw std::runtime_error("failed to sign maximum-weight quantum block");
        }
        spend.vin[input_index].scriptWitness.stack[0] = {
            signature.begin(), signature.end()};
    }

    block = assemble(spend);
    const size_t block_weight = GetBlockWeight(block);
    const size_t serialized_size = GetSerializeSize(TX_WITH_WITNESS(block));
    if (block_weight > V4_MAX_BLOCK_WEIGHT ||
        serialized_size > V4_MAX_BLOCK_SERIALIZED_SIZE ||
        V4_MAX_BLOCK_WEIGHT - block_weight >= MIN_QUANTUM_INPUT_WEIGHT ||
        spend.vin.size() != MAX_WEIGHT_BOUND_QUANTUM_INPUTS ||
        block_weight != MAXIMUM_QUANTUM_BENCHMARK_BLOCK_WEIGHT ||
        serialized_size != MAXIMUM_QUANTUM_BENCHMARK_SERIALIZED_SIZE) {
        throw std::runtime_error("signed maximum-weight quantum block violates its consensus budget");
    }

    MaximumQuantumBlock result;
    result.block = std::move(block);
    result.spend = result.block.vtx.at(1);
    result.spent_outputs = std::move(spent_outputs);
    result.input_count = result.spend->vin.size();
    result.block_weight = block_weight;
    result.serialized_size = serialized_size;
    return result;
}

} // namespace

static void QuantumArgon2id1MiB(benchmark::Bench& bench)
{
    std::array<uint8_t, 80> input{};
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 32> output{};
    bench.run([&] {
        const int result = argon2id_hash_raw(
            SHADOW_ARGON2_TIME_COST, SHADOW_ARGON2_MEMORY_KIB,
            SHADOW_ARGON2_LANES,
            input.data(), input.size(), salt.data(), salt.size(),
            output.data(), output.size());
        if (result != ARGON2_OK) {
            throw std::runtime_error("Argon2 single-operation benchmark failed");
        }
        ankerl::nanobench::doNotOptimizeAway(result);
        ankerl::nanobench::doNotOptimizeAway(output);
    });
}

static void QuantumArgon2id64ClaimBlock(benchmark::Bench& bench)
{
    std::array<uint8_t, 80> input{};
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 32> output{};
    bench.batch(MAX_SHADOW_POW_EVALS_PER_BLOCK).unit("proof").run([&] {
        int failures{0};
        for (size_t evaluation = 0;
             evaluation < MAX_SHADOW_POW_EVALS_PER_BLOCK; ++evaluation) {
            failures += argon2id_hash_raw(
                SHADOW_ARGON2_TIME_COST, SHADOW_ARGON2_MEMORY_KIB,
                SHADOW_ARGON2_LANES,
                input.data(), input.size(), salt.data(), salt.size(),
                output.data(), output.size());
        }
        if (failures != 0) throw std::runtime_error("Argon2 block benchmark failed");
        ankerl::nanobench::doNotOptimizeAway(output);
    });
}

static void QuantumMLDSA44Verify(benchmark::Bench& bench)
{
    const MLDSAVector vector = LoadMLDSAVector();
    bench.run([&] {
        const MLDSAVerifyResult result =
            ML_DSA::VerifyDetailed(vector.public_key, vector.message.data(),
                                   vector.message.size(), vector.signature);
        if (result != MLDSAVerifyResult::VALID) {
            throw std::runtime_error("ML-DSA single-operation benchmark failed");
        }
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

static void QuantumMLDSA44MaxWeightBlock(benchmark::Bench& bench)
{
    const MLDSAVector vector = LoadMLDSAVector();
    bench.batch(MAX_BLOCK_MLDSA_VERIFICATIONS).unit("signature").run([&] {
        size_t valid{0};
        for (size_t verification = 0;
             verification < MAX_BLOCK_MLDSA_VERIFICATIONS; ++verification) {
            valid += ML_DSA::VerifyDetailed(
                         vector.public_key, vector.message.data(),
                         vector.message.size(), vector.signature) ==
                MLDSAVerifyResult::VALID;
        }
        if (valid != MAX_BLOCK_MLDSA_VERIFICATIONS) {
            throw std::runtime_error("ML-DSA block benchmark failed verification");
        }
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
}

static void QuantumLargeBlockValidation32MiB(benchmark::Bench& bench)
{
    const auto testing_setup =
        MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST);
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;
    if (!ML_DSA::KeyGen(public_key, private_key)) {
        throw std::runtime_error("maximum-weight block key generation failed");
    }
    MaximumQuantumBlock fixture = BuildMaximumQuantumBlock(
        public_key, private_key,
        Params().GetConsensus().nQuantumSighashChainId);

    CCoinsView empty;
    CCoinsViewCache coins{&empty};
    for (size_t input_index = 0; input_index < fixture.input_count;
         ++input_index) {
        coins.AddCoin(
            fixture.spend->vin[input_index].prevout,
            Coin{fixture.spent_outputs[input_index], 1, false, false, 0},
            /*possible_overwrite=*/false);
    }

    constexpr unsigned int SCRIPT_FLAGS{
        SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
        SCRIPT_VERIFY_QUANTUM_ML_DSA};
    bench.batch(1).unit("block").run([&] {
        fixture.block.fChecked = false;
        fixture.block.m_checked_merkle_root = false;
        BlockValidationState block_state;
        TxValidationState tx_state;
        PrecomputedTransactionData txdata;
        bool block_valid{false};
        bool scripts_valid{false};
        {
            LOCK(cs_main);
            block_valid = CheckBlock(
                fixture.block, block_state, Params().GetConsensus(),
                testing_setup->m_node.chainman->ActiveChainstate(),
                /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/true,
                /*fCheckSig=*/true);
            scripts_valid = CheckInputScripts(
                *fixture.spend, tx_state, coins, SCRIPT_FLAGS,
                /*cacheSigStore=*/false, /*cacheFullScriptStore=*/false,
                txdata);
        }
        if (!block_valid || !scripts_valid ||
            GetBlockWeight(fixture.block) != fixture.block_weight ||
            GetSerializeSize(TX_WITH_WITNESS(fixture.block)) !=
                fixture.serialized_size) {
            throw std::runtime_error(
                "maximum-weight quantum validation benchmark failed");
        }
        ankerl::nanobench::doNotOptimizeAway(fixture.block_weight);
        ankerl::nanobench::doNotOptimizeAway(fixture.input_count);
    });
}

static void QuantumSyntheticStateApplyUndoMaxMarkers(benchmark::Bench& bench)
{
    const auto testing_setup =
        MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST);
    MaximumSyntheticStateFixture fixture;
    // Prove the fixture reaches the exact 687 PoS + 64 PoW mainnet maximum and
    // restores the authenticated parent before nanobench starts timing it.
    fixture.VerifyMaximumTransition();
    bench.batch(1).unit("state-transition").run([&] {
        const bool success = fixture.ApplyAndUndoCold();
        if (!success) {
            throw std::runtime_error(
                "maximum synthetic state apply/undo benchmark failed");
        }
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    fixture.VerifyFinalIdentity();
}

static void QuantumSyntheticSnapshotPayoutLookupMaxMarkers(
    benchmark::Bench& bench)
{
    const auto testing_setup =
        MakeNoLogFileContext<const TestingSetup>(ChainType::REGTEST);
    MaximumSyntheticStateFixture fixture;
    fixture.VerifyMaximumTransition();
    fixture.PrepareSnapshotLookupBenchmark();
    bench.batch(MAXIMUM_MAINNET_SYNTHETIC_CLAIMS).unit("marker").run([&] {
        const bool success = fixture.LookupMaximumSnapshotMarkers();
        if (!success) {
            throw std::runtime_error(
                "maximum synthetic snapshot marker lookup failed");
        }
        ankerl::nanobench::doNotOptimizeAway(success);
    });
    fixture.VerifyFinalIdentity();
}

BENCHMARK(QuantumArgon2id1MiB, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumArgon2id64ClaimBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44Verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44MaxWeightBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumLargeBlockValidation32MiB, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumSyntheticStateApplyUndoMaxMarkers,
          benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumSyntheticSnapshotPayoutLookupMaxMarkers,
          benchmark::PriorityLevel::HIGH);
