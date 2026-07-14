// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <crypto/argon2_selftest.h>
#include <crypto/mldsa.h>
#include <crypto/mldsa_kat.h>
#include <crypto/sha256.h>
#include <node/kernel_notifications.h>
#include <pow.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <shadow.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>
#include <warnings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {

class MLDSAFailureGuard
{
public:
    MLDSAFailureGuard() { ML_DSA::ClearFailureForTesting(); }
    ~MLDSAFailureGuard() { ML_DSA::ClearFailureForTesting(); }
};

class ShadowArgon2FailureGuard
{
public:
    ShadowArgon2FailureGuard()
    {
        ClearShadowArgon2FailuresForTesting();
        ClearShadowAllocationFailureForTesting();
    }
    ~ShadowArgon2FailureGuard()
    {
        ClearShadowArgon2FailuresForTesting();
        ClearShadowAllocationFailureForTesting();
    }
};

class ShadowScheduleTestGuard
{
public:
    ShadowScheduleTestGuard(int whitelist_height, int reward_start_height,
                            int gold_rush_blocks)
        : m_whitelist_height{SHADOW_WHITELIST_HEIGHT},
          m_reward_start_height{SHADOW_REWARD_START_HEIGHT},
          m_gold_rush_blocks{SHADOW_GOLD_RUSH_BLOCKS},
          m_halving_interval{SHADOW_HALVING_INTERVAL_BLOCKS}
    {
        SetShadowTestSchedule(whitelist_height, reward_start_height,
                              gold_rush_blocks);
    }

    ~ShadowScheduleTestGuard()
    {
        SetShadowTestSchedule(m_whitelist_height, m_reward_start_height,
                              m_gold_rush_blocks);
        SetShadowTestHalvingInterval(m_halving_interval);
    }

private:
    const int m_whitelist_height;
    const int m_reward_start_height;
    const int m_gold_rush_blocks;
    const int m_halving_interval;
};

class FatalErrorTestGuard
{
public:
    explicit FatalErrorTestGuard(node::NodeContext& node)
        : m_node{node},
          m_previous_shutdown_on_fatal{node.notifications->m_shutdown_on_fatal_error},
          m_previous_exit_status{node.exit_status.load()}
    {
        m_node.notifications->m_shutdown_on_fatal_error = false;
        ClearExpectedFatal();
    }

    ~FatalErrorTestGuard()
    {
        m_node.notifications->m_shutdown_on_fatal_error = m_previous_shutdown_on_fatal;
        m_node.exit_status.store(m_previous_exit_status);
        SetMiscWarning(Untranslated(""));
    }

    void ClearExpectedFatal()
    {
        m_node.exit_status.store(EXIT_SUCCESS);
        SetMiscWarning(Untranslated(""));
    }

private:
    node::NodeContext& m_node;
    const bool m_previous_shutdown_on_fatal;
    const int m_previous_exit_status;
};

class QuantumScriptQueueTestingSetup : public TestChain100Setup
{
public:
    QuantumScriptQueueTestingSetup()
        : TestChain100Setup{ChainType::REGTEST, {
              "-regtest",
              "-shadowwhitelistheight=99",
              "-shadowgoldrushstartheight=100",
              "-shadowgoldrushendheight=100",
              "-qqgoldrushendheight=100",
              "-qqmigrationendheight=200",
          }}
    {
    }
};

class BoundedShadowClaimTestingSetup : public TestChain100Setup
{
public:
    BoundedShadowClaimTestingSetup()
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

class BlockCheckedCatcher final : public CValidationInterface
{
public:
    explicit BlockCheckedCatcher(const uint256& expected_hash)
        : m_expected_hash{expected_hash}
    {
    }

    void BlockChecked(const CBlock& block, const BlockValidationState& state) override
    {
        if (block.GetHash() == m_expected_hash) m_state = state;
    }

    std::optional<BlockValidationState> m_state;

private:
    const uint256 m_expected_hash;
};

std::vector<unsigned char> ProgramForPubkey(const std::vector<uint8_t>& pubkey)
{
    std::vector<unsigned char> program(QUANTUM_MIGRATION_PROGRAM_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(program.data());
    return program;
}

struct QuantumSpend
{
    CTxOut spent_output;
    CTransaction transaction;
};

QuantumSpend BuildQuantumSpend(const std::vector<uint8_t>& pubkey,
                               const std::vector<uint8_t>& privkey,
                               uint32_t chain_id)
{
    const CScript script = GetScriptForDestination(
        WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION, ProgramForPubkey(pubkey)});
    const CTxOut spent_output{10 * COIN, script};
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.vin.emplace_back(COutPoint{uint256::ONE, 0});
    tx.vout.emplace_back(9 * COIN, script);
    const CTransaction unsigned_tx{tx};
    const uint256 sighash = QuantumSignatureHash(unsigned_tx, 0, spent_output, chain_id);
    std::vector<uint8_t> signature;
    if (!ML_DSA::Sign(privkey, sighash.begin(), uint256::size(), signature)) {
        throw std::runtime_error("failed to sign quantum test transaction");
    }
    tx.vin[0].scriptWitness.stack.emplace_back(signature.begin(), signature.end());
    tx.vin[0].scriptWitness.stack.emplace_back(pubkey.begin(), pubkey.end());
    return {spent_output, CTransaction{tx}};
}

CBlock BuildQuantumSignedBlock(const std::vector<uint8_t>& pubkey,
                               const std::vector<uint8_t>& privkey,
                               const uint256& previous_block)
{
    CMutableTransaction coinbase;
    coinbase.nVersion = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << OP_0 << OP_0;
    coinbase.vout.emplace_back(0, CScript{});

    CMutableTransaction coinstake;
    coinstake.nVersion = 2;
    coinstake.vin.emplace_back(COutPoint{uint256::ONE, 0});
    coinstake.vout.emplace_back(0, CScript{});
    coinstake.vout.emplace_back(
        0, CScript{} << OP_RETURN << std::vector<unsigned char>{pubkey.begin(), pubkey.end()});

    CBlock block;
    block.nVersion = 7;
    block.hashPrevBlock = previous_block;
    block.nTime = 16;
    block.nBits = 0x207fffff;
    block.vtx.emplace_back(MakeTransactionRef(std::move(coinbase)));
    block.vtx.emplace_back(MakeTransactionRef(std::move(coinstake)));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    const uint256 block_hash = block.GetHash();
    if (!ML_DSA::Sign(privkey, block_hash.begin(), uint256::size(), block.vchBlockSig)) {
        throw std::runtime_error("failed to sign quantum test block");
    }
    return block;
}

CBlock ReplayBlockBytes(const CBlock& block)
{
    CDataStream stream{SER_NETWORK};
    stream << TX_WITH_WITNESS(block);
    CBlock replay;
    stream >> TX_WITH_WITNESS(replay);
    return replay;
}

struct LegacyShadowClaimCandidate
{
    CBlock block;
    std::unique_ptr<CBlockIndex> index;
    uint256 block_hash;
    COutPoint stake_outpoint{uint256{0x71}, 0};
    COutPoint claim_outpoint{uint256{0x72}, 0};
    CScript legacy_script{CScript{} << OP_TRUE};
    CScript payout_script;
    CAmount stake_amount{20'000 * COIN};
    CAmount claim_amount{2 * COIN};
};

void SeedLegacyShadowClaimView(CCoinsViewCache& view,
                               const CBlockIndex* parent,
                               const LegacyShadowClaimCandidate& candidate)
{
    BOOST_REQUIRE(parent != nullptr);
    Coin stake_coin{CTxOut{candidate.stake_amount, candidate.legacy_script},
                    std::max(1, parent->nHeight - 20), false, false,
                    /*nTime=*/1};
    Coin claim_coin{CTxOut{candidate.claim_amount, candidate.legacy_script},
                    std::max(1, parent->nHeight - 20), false, false,
                    /*nTime=*/1};
    view.AddCoin(candidate.stake_outpoint, std::move(stake_coin), false);
    view.AddCoin(candidate.claim_outpoint, std::move(claim_coin), false);
    BOOST_REQUIRE(ApplyLegacyWhitelistSnapshot(view, parent));
}

LegacyShadowClaimCandidate BuildLegacyShadowClaimCandidate(
    const CBlockIndex* parent, CCoinsViewCache& view,
    const Consensus::Params& consensus)
{
    BOOST_REQUIRE(parent != nullptr);
    LegacyShadowClaimCandidate candidate;
    candidate.payout_script = GetScriptForDestination(WitnessUnknown{
        QUANTUM_MIGRATION_WITNESS_VERSION,
        std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x5a)});

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(MineShadowProofData(candidate.legacy_script,
                                      candidate.payout_script, parent, view,
                                      100'000, proof));

    // The exact Protocol-V3 boundary retains the designated historical
    // behavior and lets this test isolate ConnectBlock's shadow path without
    // manufacturing an unrelated stake-kernel solution.
    const uint32_t block_time = static_cast<uint32_t>(consensus.nProtocolV3Time);

    CMutableTransaction coinbase;
    coinbase.nVersion = 1;
    coinbase.nTime = block_time;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << parent->nHeight + 1 << OP_0;
    coinbase.vout.emplace_back(0, CScript{});

    CMutableTransaction coinstake;
    coinstake.nVersion = 1;
    coinstake.nTime = block_time;
    coinstake.vin.emplace_back(candidate.stake_outpoint);
    coinstake.vout.emplace_back(0, CScript{});
    coinstake.vout.emplace_back(candidate.stake_amount,
                                candidate.legacy_script);

    CMutableTransaction claim;
    claim.nVersion = 1;
    claim.nTime = block_time;
    claim.vin.emplace_back(candidate.claim_outpoint);
    claim.vout.emplace_back(candidate.claim_amount - COIN,
                            candidate.legacy_script);
    claim.vout.emplace_back(0, CScript{} << OP_RETURN << proof);

    candidate.block.nVersion = 7;
    candidate.block.hashPrevBlock = parent->GetBlockHash();
    candidate.block.nTime = block_time;
    candidate.block.nBits = GetNextTargetRequired(parent, consensus,
                                                  /*fProofOfStake=*/true);
    candidate.block.vtx = {
        MakeTransactionRef(std::move(coinbase)),
        MakeTransactionRef(std::move(coinstake)),
        MakeTransactionRef(std::move(claim)),
    };
    candidate.block.hashMerkleRoot = BlockMerkleRoot(candidate.block);
    candidate.block_hash = candidate.block.GetHash();
    candidate.index =
        std::make_unique<CBlockIndex>(candidate.block.GetBlockHeader());
    candidate.index->phashBlock = &candidate.block_hash;
    candidate.index->pprev = const_cast<CBlockIndex*>(parent);
    candidate.index->nHeight = parent->nHeight + 1;
    candidate.index->SetProofOfStake();
    return candidate;
}

void CheckShadowInfoEqual(const ShadowGoldRushInfo& expected, const ShadowGoldRushInfo& actual)
{
    BOOST_CHECK_EQUAL(actual.pow_amount, expected.pow_amount);
    BOOST_CHECK_EQUAL(actual.pos_amount, expected.pos_amount);
    BOOST_CHECK_EQUAL(actual.claimed_amount, expected.claimed_amount);
    BOOST_CHECK_EQUAL(actual.pow_count, expected.pow_count);
    BOOST_CHECK_EQUAL(actual.pos_count, expected.pos_count);
    BOOST_CHECK_EQUAL(actual.last_pow_height, expected.last_pow_height);
    BOOST_CHECK_EQUAL(actual.last_pos_height, expected.last_pos_height);
    BOOST_CHECK_EQUAL(actual.recent_count, expected.recent_count);
    BOOST_CHECK_EQUAL(actual.recent_modes, expected.recent_modes);
    BOOST_CHECK_EQUAL(actual.pow_target_bits, expected.pow_target_bits);
}

void CheckShadowReplayEqual(const ShadowReplayStateInfo& expected, const ShadowReplayStateInfo& actual)
{
    BOOST_CHECK_EQUAL(actual.schema, expected.schema);
    BOOST_CHECK_EQUAL(actual.required_for_tip, expected.required_for_tip);
    BOOST_CHECK_EQUAL(actual.present, expected.present);
    BOOST_CHECK_EQUAL(actual.marker_valid, expected.marker_valid);
    BOOST_CHECK_EQUAL(actual.valid_for_tip, expected.valid_for_tip);
    BOOST_CHECK_EQUAL(actual.marker_height, expected.marker_height);
    BOOST_CHECK_EQUAL(actual.marker_time, expected.marker_time);
    BOOST_CHECK(actual.marker_block_hash == expected.marker_block_hash);
    BOOST_CHECK(actual.commitment == expected.commitment);
}

void RefreshShadowCandidateBlock(LegacyShadowClaimCandidate& candidate,
                                 const CBlockIndex* parent)
{
    candidate.block.hashMerkleRoot = BlockMerkleRoot(candidate.block);
    candidate.block_hash = candidate.block.GetHash();
    candidate.index =
        std::make_unique<CBlockIndex>(candidate.block.GetBlockHeader());
    candidate.index->phashBlock = &candidate.block_hash;
    candidate.index->pprev = const_cast<CBlockIndex*>(parent);
    candidate.index->nHeight = parent->nHeight + 1;
    candidate.index->SetProofOfStake();
}

} // namespace

BOOST_AUTO_TEST_SUITE(crypto_hardening_tests)

BOOST_AUTO_TEST_CASE(argon2id_rfc9106_startup_vector)
{
    BOOST_CHECK(Argon2idSelfTest());
}

BOOST_AUTO_TEST_CASE(shadow_argon2_faults_are_typed_retryable_and_canonical)
{
    ShadowArgon2FailureGuard guard;
    ShadowPowWork work;
    work.valid = true;
    work.target = CScript{} << OP_TRUE;
    work.quantum_payout_script = GetScriptForDestination(
        WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION,
                       std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x42)});
    work.height = SHADOW_REWARD_START_HEIGHT;
    work.prev_hash = uint256::ONE;
    work.bits = 0;

    std::vector<unsigned char> proof;
    uint64_t tries{0};
    BOOST_REQUIRE(GrindShadowPowWorkDetailed(work, 7, 1, 1, proof, &tries) ==
                  ShadowPowGrindResult::FOUND);
    BOOST_CHECK_EQUAL(tries, 1U);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, proof) ==
                ShadowProofValidationResult::VALID);

    std::vector<unsigned char> repeated;
    BOOST_REQUIRE(GrindShadowPowWorkDetailed(work, 7, 1, 1, repeated) ==
                  ShadowPowGrindResult::FOUND);
    BOOST_CHECK(proof == repeated);

    std::vector<unsigned char> malformed = proof;
    malformed[0] ^= 0x01;
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, malformed) ==
                ShadowProofValidationResult::INVALID);
    malformed = proof;
    malformed[GetShadowPrefix().size() + 4] = 1; // POS mode is not valid PoW work.
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, malformed) ==
                ShadowProofValidationResult::INVALID);
    malformed = proof;
    malformed.push_back(0); // Declared payout length no longer consumes the payload.
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, malformed) ==
                ShadowProofValidationResult::INVALID);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(
                    work, std::vector<unsigned char>(MAX_SCRIPT_ELEMENT_SIZE + 1, 0)) ==
                ShadowProofValidationResult::INVALID);

    ShadowPowWork mismatched = work;
    mismatched.target = CScript{} << OP_2;
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(mismatched, proof) ==
                ShadowProofValidationResult::INVALID);

    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, proof) ==
                ShadowProofValidationResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, proof) ==
                ShadowProofValidationResult::VALID);

    SetShadowArgon2FailuresForTesting();
    BOOST_CHECK(GrindShadowPowWorkDetailed(work, 7, 1, 1, repeated) ==
                ShadowPowGrindResult::LOCAL_INTERNAL_ERROR);
    BOOST_CHECK(GrindShadowPowWorkDetailed(work, 7, 1, 1, repeated) ==
                ShadowPowGrindResult::FOUND);
}

BOOST_AUTO_TEST_CASE(shadow_qqp2_exact_encoding_boundaries)
{
    ShadowPowWork work;
    work.valid = true;
    work.target = CScript{} << OP_TRUE;
    work.quantum_payout_script = GetScriptForDestination(
        WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION,
                       std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x24)});
    work.height = SHADOW_REWARD_START_HEIGHT;
    work.prev_hash = uint256::ONE;
    work.bits = 0;

    std::vector<unsigned char> proof;
    BOOST_REQUIRE(GrindShadowPowWorkDetailed(work, 0, 1, 1, proof) ==
                  ShadowPowGrindResult::FOUND);
    BOOST_REQUIRE(ValidateShadowPowProofForWorkDetailed(work, proof) ==
                  ShadowProofValidationResult::VALID);

    const size_t prefix_size = GetShadowPrefix().size();
    constexpr size_t MAGIC_SIZE{4};
    constexpr size_t MODE_SIZE{1};
    constexpr size_t NONCE_SIZE{8};
    constexpr size_t LENGTH_SIZE{2};
    const size_t target_length_offset = prefix_size + MAGIC_SIZE + MODE_SIZE + NONCE_SIZE;
    const size_t target_offset = target_length_offset + LENGTH_SIZE;
    const size_t payout_length_offset = target_offset + work.target.size();
    const size_t payout_offset = payout_length_offset + LENGTH_SIZE;
    BOOST_REQUIRE_EQUAL(payout_offset + work.quantum_payout_script.size(), proof.size());

    const auto write_length = [](std::vector<unsigned char>& bytes, size_t offset, uint16_t value) {
        bytes[offset] = static_cast<unsigned char>(value);
        bytes[offset + 1] = static_cast<unsigned char>(value >> 8);
    };
    const auto check_invalid = [&work](const std::vector<unsigned char>& candidate) {
        BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(work, candidate) ==
                    ShadowProofValidationResult::INVALID);
    };

    // Every strict prefix is truncated and must be rejected.
    for (size_t size = 0; size < proof.size(); ++size) {
        check_invalid(std::vector<unsigned char>{proof.begin(), proof.begin() + size});
    }

    for (size_t magic_index = 0; magic_index < MAGIC_SIZE; ++magic_index) {
        std::vector<unsigned char> malformed = proof;
        malformed[prefix_size + magic_index] ^= 0x01;
        check_invalid(malformed);
    }

    std::vector<unsigned char> malformed = proof;
    malformed[prefix_size + MAGIC_SIZE] = 0xff;
    check_invalid(malformed);

    malformed = proof;
    write_length(malformed, target_length_offset, 0);
    check_invalid(malformed);
    malformed = proof;
    write_length(malformed, target_length_offset,
                 static_cast<uint16_t>(work.target.size() + 1));
    check_invalid(malformed);
    malformed = proof;
    write_length(malformed, target_length_offset, std::numeric_limits<uint16_t>::max());
    check_invalid(malformed);

    malformed = proof;
    write_length(malformed, payout_length_offset, 0);
    check_invalid(malformed);
    malformed = proof;
    write_length(malformed, payout_length_offset,
                 static_cast<uint16_t>(work.quantum_payout_script.size() - 1));
    check_invalid(malformed);
    malformed = proof;
    write_length(malformed, payout_length_offset,
                 static_cast<uint16_t>(work.quantum_payout_script.size() + 1));
    check_invalid(malformed);
    malformed = proof;
    write_length(malformed, payout_length_offset, std::numeric_limits<uint16_t>::max());
    check_invalid(malformed);

    malformed = proof;
    malformed[payout_offset] = OP_15;
    check_invalid(malformed);
    malformed = proof;
    malformed.push_back(0);
    check_invalid(malformed);

    // The 520-byte script-element ceiling is inclusive. Construct a valid
    // byte-exact QQP2 proof at the ceiling, then prove one additional byte is
    // rejected.
    const size_t fixed_size = proof.size() - work.target.size() - work.quantum_payout_script.size();
    BOOST_REQUIRE_LT(fixed_size + work.quantum_payout_script.size(), MAX_SCRIPT_ELEMENT_SIZE);
    const size_t boundary_target_size =
        MAX_SCRIPT_ELEMENT_SIZE - fixed_size - work.quantum_payout_script.size();
    ShadowPowWork boundary_work = work;
    boundary_work.target.clear();
    boundary_work.target.insert(boundary_work.target.end(), boundary_target_size,
                                static_cast<unsigned char>(OP_TRUE));
    std::vector<unsigned char> boundary_proof;
    BOOST_REQUIRE(GrindShadowPowWorkDetailed(boundary_work, 0, 1, 1, boundary_proof) ==
                  ShadowPowGrindResult::FOUND);
    BOOST_REQUIRE_EQUAL(boundary_proof.size(), MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(boundary_work, boundary_proof) ==
                ShadowProofValidationResult::VALID);

    std::vector<unsigned char> oversized = boundary_proof;
    oversized.push_back(0);
    BOOST_REQUIRE_EQUAL(oversized.size(), MAX_SCRIPT_ELEMENT_SIZE + 1);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(boundary_work, oversized) ==
                ShadowProofValidationResult::INVALID);

    // Lengths are canonical little-endian integers. Reversing a multi-byte
    // target length must not select an alternate parse of the same bytes.
    const size_t boundary_target_length_offset =
        prefix_size + MAGIC_SIZE + MODE_SIZE + NONCE_SIZE;
    std::vector<unsigned char> wrong_endian = boundary_proof;
    std::swap(wrong_endian[boundary_target_length_offset],
              wrong_endian[boundary_target_length_offset + 1]);
    BOOST_REQUIRE(wrong_endian != boundary_proof);
    BOOST_CHECK(ValidateShadowPowProofForWorkDetailed(boundary_work, wrong_endian) ==
                ShadowProofValidationResult::INVALID);
}

BOOST_AUTO_TEST_CASE(shadow_argon2_concurrent_stress)
{
    ShadowArgon2FailureGuard guard;
    constexpr size_t THREADS{8};
    constexpr size_t ITERATIONS{8};
    std::atomic_bool success{true};
    std::vector<std::thread> workers;
    workers.reserve(THREADS);
    for (size_t thread_index = 0; thread_index < THREADS; ++thread_index) {
        workers.emplace_back([thread_index, &success] {
            ShadowPowWork work;
            work.valid = true;
            work.target = CScript{} << OP_TRUE;
            work.quantum_payout_script = GetScriptForDestination(
                WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION,
                               std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x33)});
            work.height = SHADOW_REWARD_START_HEIGHT + static_cast<int>(thread_index);
            work.prev_hash = uint256{static_cast<uint8_t>(thread_index + 1)};
            work.bits = 0;
            for (size_t iteration = 0; iteration < ITERATIONS; ++iteration) {
                std::vector<unsigned char> proof;
                if (GrindShadowPowWorkDetailed(work, iteration, 1, 1, proof) != ShadowPowGrindResult::FOUND ||
                    ValidateShadowPowProofForWorkDetailed(work, proof) != ShadowProofValidationResult::VALID) {
                    success.store(false, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    for (std::thread& worker : workers) worker.join();
    BOOST_CHECK(success.load(std::memory_order_relaxed));
}

BOOST_AUTO_TEST_CASE(mldsa_wycheproof_positive_negative_and_boundaries)
{
    const std::vector<uint8_t> pubkey = ParseHex(mldsa_kat::PUBLIC_KEY_HEX);
    const std::vector<uint8_t> valid_message = ParseHex(mldsa_kat::VALID_MESSAGE_HEX);
    const std::vector<uint8_t> valid_signature = ParseHex(mldsa_kat::VALID_SIGNATURE_HEX);
    const std::vector<uint8_t> noncanonical_message = ParseHex(mldsa_kat::NONCANONICAL_MESSAGE_HEX);
    const std::vector<uint8_t> noncanonical_signature = ParseHex(mldsa_kat::NONCANONICAL_SIGNATURE_HEX);

    BOOST_REQUIRE_EQUAL(pubkey.size(), ML_DSA::PUBLICKEY_BYTES);
    BOOST_REQUIRE_EQUAL(valid_message.size(), uint256::size());
    BOOST_REQUIRE_EQUAL(valid_signature.size(), ML_DSA::SIGNATURE_BYTES);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), valid_signature) ==
                MLDSAVerifyResult::VALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, noncanonical_message.data(), noncanonical_message.size(), noncanonical_signature) ==
                MLDSAVerifyResult::INVALID);

    std::vector<uint8_t> short_pubkey{pubkey.begin(), pubkey.end() - 1};
    std::vector<uint8_t> long_pubkey{pubkey};
    long_pubkey.push_back(0);
    std::vector<uint8_t> short_signature{valid_signature.begin(), valid_signature.end() - 1};
    std::vector<uint8_t> long_signature{valid_signature};
    long_signature.push_back(0);
    BOOST_CHECK(ML_DSA::VerifyDetailed(short_pubkey, valid_message.data(), valid_message.size(), valid_signature) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(long_pubkey, valid_message.data(), valid_message.size(), valid_signature) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), short_signature) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), long_signature) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size() - 1, valid_signature) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), pubkey.size(), valid_message.data(), valid_message.size() + 1,
                                      valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(nullptr, pubkey.size(), valid_message.data(), valid_message.size(), valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), pubkey.size(), nullptr, valid_message.size(),
                                      valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), pubkey.size(), valid_message.data(), valid_message.size(),
                                      nullptr, valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), 0, valid_message.data(), valid_message.size(),
                                      valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), pubkey.size(), valid_message.data(), 0,
                                      valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey.data(), pubkey.size(), valid_message.data(), valid_message.size(),
                                      valid_signature.data(), 0) == MLDSAVerifyResult::INVALID);
}

BOOST_AUTO_TEST_CASE(mldsa_faults_are_internal_and_retryable)
{
    MLDSAFailureGuard guard;
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    const uint256 message = uint256::ONE;
    std::vector<uint8_t> signature;
    BOOST_REQUIRE(ML_DSA::Sign(privkey, message.begin(), uint256::size(), signature));

    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, message.begin(), uint256::size(), signature) == MLDSAVerifyResult::INTERNAL_ERROR);
    BOOST_CHECK(ML_DSA::VerifyDetailed(pubkey, message.begin(), uint256::size(), signature) == MLDSAVerifyResult::VALID);

    ML_DSA::SetFailureForTesting(MLDSATestFailure::SIGN);
    BOOST_CHECK(ML_DSA::SignDetailed(privkey, message.begin(), uint256::size(), signature) == MLDSAOperationResult::INTERNAL_ERROR);
    BOOST_CHECK(ML_DSA::SignDetailed(privkey, message.begin(), uint256::size(), signature) == MLDSAOperationResult::SUCCESS);

    ML_DSA::SetFailureForTesting(MLDSATestFailure::KEYGEN);
    std::vector<uint8_t> unused_pubkey;
    std::vector<uint8_t> unused_privkey;
    BOOST_CHECK(ML_DSA::KeyGenDetailed(unused_pubkey, unused_privkey) == MLDSAOperationResult::INTERNAL_ERROR);
    BOOST_CHECK(ML_DSA::KeyGenDetailed(unused_pubkey, unused_privkey) == MLDSAOperationResult::SUCCESS);

    std::vector<uint8_t> short_key(privkey.begin(), privkey.end() - 1);
    std::vector<uint8_t> long_key{privkey};
    long_key.push_back(0);
    BOOST_CHECK(ML_DSA::SignDetailed(short_key, message.begin(), uint256::size(), signature) == MLDSAOperationResult::INVALID_INPUT);
    BOOST_CHECK(ML_DSA::SignDetailed(long_key, message.begin(), uint256::size(), signature) == MLDSAOperationResult::INVALID_INPUT);
    BOOST_CHECK(ML_DSA::SignDetailed(privkey, nullptr, uint256::size(), signature) == MLDSAOperationResult::INVALID_INPUT);
    BOOST_CHECK(ML_DSA::SignDetailed(privkey, message.begin(), uint256::size() - 1, signature) == MLDSAOperationResult::INVALID_INPUT);
    BOOST_CHECK(ML_DSA::SignDetailed(privkey, message.begin(), uint256::size() + 1, signature) == MLDSAOperationResult::INVALID_INPUT);
}

BOOST_AUTO_TEST_CASE(mldsa_concurrent_keygen_sign_verify_stress)
{
    MLDSAFailureGuard guard;
    constexpr size_t THREADS{8};
    constexpr size_t ITERATIONS{32};
    std::atomic_bool success{true};
    std::vector<std::thread> workers;
    workers.reserve(THREADS);
    for (size_t thread_index = 0; thread_index < THREADS; ++thread_index) {
        workers.emplace_back([thread_index, &success] {
            for (size_t iteration = 0; iteration < ITERATIONS && success.load(std::memory_order_relaxed); ++iteration) {
                std::vector<uint8_t> pubkey;
                std::vector<uint8_t> privkey;
                if (!ML_DSA::KeyGen(pubkey, privkey)) {
                    success.store(false, std::memory_order_relaxed);
                    return;
                }
                std::array<uint8_t, uint256::size()> message{};
                message[0] = static_cast<uint8_t>(thread_index);
                message[1] = static_cast<uint8_t>(iteration);
                std::vector<uint8_t> signature;
                if (!ML_DSA::Sign(privkey, message.data(), message.size(), signature) ||
                    ML_DSA::VerifyDetailed(pubkey, message.data(), message.size(), signature) != MLDSAVerifyResult::VALID) {
                    success.store(false, std::memory_order_relaxed);
                    return;
                }
            }
        });
    }
    for (std::thread& worker : workers) worker.join();
    BOOST_CHECK(success.load(std::memory_order_relaxed));
}

BOOST_FIXTURE_TEST_CASE(script_internal_failure_is_not_consensus_invalid_or_cached, BasicTestingSetup)
{
    MLDSAFailureGuard guard;
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    const uint32_t chain_id = Params().GetConsensus().nQuantumSighashChainId;
    const QuantumSpend spend = BuildQuantumSpend(pubkey, privkey, chain_id);

    CCoinsView empty;
    CCoinsViewCache coins{&empty};
    coins.AddCoin(spend.transaction.vin[0].prevout,
                  Coin{spend.spent_output, 1, false, false, 0}, false);

    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(!CheckInputScripts(
            spend.transaction, state, coins,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
            /*cacheSigStore=*/true, /*cacheFullScriptStore=*/true, txdata));
        BOOST_CHECK(state.IsError());
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "local-mldsa-verification-error");
    }

    // The internal failure must not populate the full-script cache. Retrying
    // the exact transaction after the local fault clears performs verification
    // and succeeds.
    {
        LOCK(cs_main);
        TxValidationState state;
        PrecomputedTransactionData txdata;
        BOOST_CHECK(CheckInputScripts(
            spend.transaction, state, coins,
            SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_QUANTUM_ML_DSA,
            /*cacheSigStore=*/true, /*cacheFullScriptStore=*/true, txdata));
        BOOST_CHECK(state.IsValid());
    }
}

BOOST_FIXTURE_TEST_CASE(script_queue_internal_failure_is_fail_stop_retryable_and_not_cached,
                        QuantumScriptQueueTestingSetup)
{
    MLDSAFailureGuard mldsa_guard;
    FatalErrorTestGuard fatal_guard{m_node};
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    // Advance one block past Gold Rush. The disposable overlay below then
    // models a non-coinbase Migration output so the candidate reaches the
    // quantum script-verification path.
    mineBlocks(1);

    CBlockIndex* parent{nullptr};
    uint256 durable_tip_hash;
    uint256 durable_coins_hash;
    {
        LOCK(cs_main);
        parent = chainstate.m_chain.Tip();
        BOOST_REQUIRE(parent != nullptr);
        BOOST_REQUIRE_EQUAL(parent->nHeight, 101);
        durable_tip_hash = parent->GetBlockHash();
        durable_coins_hash = chainstate.CoinsTip().GetBestBlock();
    }

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    const QuantumSpend spend = BuildQuantumSpend(
        pubkey, privkey, Params().GetConsensus().nQuantumSighashChainId);

    CMutableTransaction coinbase;
    coinbase.nVersion = 2;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript{} << parent->nHeight + 1 << OP_0;
    coinbase.vout.emplace_back(0, CScript{} << OP_TRUE);

    CBlock block;
    block.nVersion = 7;
    block.hashPrevBlock = parent->GetBlockHash();
    block.nTime = parent->GetBlockTime() + 1;
    block.nBits = GetNextTargetRequired(
        parent, Params().GetConsensus(), /*fProofOfStake=*/false);
    block.vtx = {
        MakeTransactionRef(std::move(coinbase)),
        MakeTransactionRef(CTransaction{spend.transaction}),
    };
    chainman.GenerateCoinbaseCommitment(block, parent);
    block.hashMerkleRoot = BlockMerkleRoot(block);

    uint256 block_hash = block.GetHash();
    CBlockIndex candidate_index{block.GetBlockHeader()};
    candidate_index.phashBlock = &block_hash;
    candidate_index.pprev = parent;
    candidate_index.nHeight = parent->nHeight + 1;

    const auto make_overlay = [&]() {
        auto view = std::make_unique<CCoinsViewCache>(
            &chainstate.CoinsTip());
        view->AddCoin(
            spend.transaction.vin[0].prevout,
            Coin{spend.spent_output, parent->nHeight,
                 /*coinbase=*/false, /*coinstake=*/false,
                 static_cast<int>(parent->GetBlockTime())},
            /*possible_overwrite=*/false);
        return view;
    };

    std::unique_ptr<CCoinsViewCache> failed_view;
    {
        LOCK(cs_main);
        failed_view = make_overlay();
    }

    // ChainTestingSetup starts two script-check workers. The injected failure
    // is consumed by the queued quantum script check, after ConnectBlock has
    // staged ordinary transaction and auxiliary-state writes in this overlay.
    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BlockValidationState failure_state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!chainstate.ConnectBlock(
            block, failure_state, &candidate_index, *failed_view,
            /*fJustCheck=*/true, /*fCheckBlockSig=*/false));
    }
    BOOST_CHECK(failure_state.IsError());
    BOOST_CHECK(!failure_state.IsInvalid());
    BOOST_CHECK_EQUAL(failure_state.GetResult(),
                      BlockValidationResult::BLOCK_RESULT_UNSET);
    BOOST_CHECK(failure_state.GetRejectReason().find("script-check queue") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
    {
        LOCK(cs_main);
        BOOST_CHECK((candidate_index.nStatus & BLOCK_FAILED_MASK) == 0);
        BOOST_REQUIRE(chainstate.m_chain.Tip() != nullptr);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() ==
                    durable_tip_hash);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() ==
                    durable_coins_hash);
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
            spend.transaction.vin[0].prevout));
        BOOST_CHECK(!chainstate.CoinsTip().HaveCoin(
            COutPoint{spend.transaction.GetHash(), 0}));
    }

    // ConnectBlock's contract requires a failed overlay to be discarded. A
    // clean restart/replay therefore rebuilds from the same durable parent.
    failed_view.reset();
    fatal_guard.ClearExpectedFatal();
    std::unique_ptr<CCoinsViewCache> retry_view;
    {
        LOCK(cs_main);
        retry_view = make_overlay();
    }
    BlockValidationState retry_state;
    {
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(
            chainstate.ConnectBlock(
                block, retry_state, &candidate_index, *retry_view,
                /*fJustCheck=*/true, /*fCheckBlockSig=*/false),
            retry_state.ToString());
    }
    BOOST_CHECK(retry_state.IsValid());
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    {
        LOCK(cs_main);
        BOOST_CHECK(!retry_view->HaveCoin(
            spend.transaction.vin[0].prevout));
        BOOST_CHECK(retry_view->HaveCoin(
            COutPoint{spend.transaction.GetHash(), 0}));
        BOOST_CHECK((candidate_index.nStatus & BLOCK_FAILED_MASK) == 0);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() ==
                    durable_tip_hash);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() ==
                    durable_coins_hash);
    }
}

BOOST_FIXTURE_TEST_CASE(shadow_proof_internal_failure_preserves_base_validity_and_retries,
                        TestChain100Setup)
{
    ShadowArgon2FailureGuard shadow_failure_guard;
    FatalErrorTestGuard fatal_guard{m_node};
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    CBlockIndex* parent{nullptr};
    uint256 active_tip_hash;
    uint256 active_coins_hash;
    {
        LOCK(cs_main);
        parent = chainstate.m_chain.Tip();
        BOOST_REQUIRE(parent != nullptr);
        active_tip_hash = parent->GetBlockHash();
        active_coins_hash = chainstate.CoinsTip().GetBestBlock();
    }

    ShadowScheduleTestGuard schedule_guard{
        parent->nHeight, parent->nHeight + 1, /*gold_rush_blocks=*/4};

    LegacyShadowClaimCandidate candidate;
    {
        LOCK(cs_main);
        CCoinsViewCache construction_view{&chainstate.CoinsTip()};
        SeedLegacyShadowClaimView(construction_view, parent, candidate);
        candidate = BuildLegacyShadowClaimCandidate(
            parent, construction_view, chainman.GetConsensus());
        candidate.index->phashBlock = &candidate.block_hash;
        // The helper's fixed input identities and scripts are unchanged by
        // construction, so reseeding before construction supplied the exact
        // coins consumed by this candidate.
    }

    // Establish context-free base validity independently of the injected
    // shadow-library fault. Block-signature verification is irrelevant here:
    // the historical ECDSA carrier is empty because this synthetic block uses
    // OP_TRUE solely to reach the shadow integration boundary.
    BlockValidationState base_state;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(CheckBlock(candidate.block, base_state,
                                 chainman.GetConsensus(), chainstate,
                                 /*fCheckPOW=*/true,
                                 /*fCheckMerkleRoot=*/true,
                                 /*fCheckSig=*/false));
    }
    BOOST_CHECK(base_state.IsValid());

    // Exercise both the linked proof-library boundary and a host allocation
    // failure at the transactional apply boundary. Each attempt starts from a
    // fresh outer cache, matching ConnectTip's discard-and-retry contract.
    for (const bool allocation_failure : {false, true}) {
        fatal_guard.ClearExpectedFatal();
        std::unique_ptr<CCoinsViewCache> failed_view;
        ShadowGoldRushInfo shadow_before;
        {
            LOCK(cs_main);
            failed_view =
                std::make_unique<CCoinsViewCache>(&chainstate.CoinsTip());
            SeedLegacyShadowClaimView(*failed_view, parent, candidate);
            shadow_before = GetShadowGoldRushInfo(*failed_view, parent);
        }
        if (allocation_failure) {
            SetShadowAllocationFailureForTesting(
                ShadowAllocationFailurePoint::APPLY_AFTER_STAGED_MUTATION);
        } else {
            SetShadowArgon2FailuresForTesting();
        }

        BlockValidationState local_failure_state;
        {
            LOCK(cs_main);
            BOOST_CHECK_MESSAGE(!chainstate.ConnectBlock(
                                    candidate.block, local_failure_state,
                                    candidate.index.get(), *failed_view,
                                    /*fJustCheck=*/true,
                                    /*fCheckBlockSig=*/false),
                                local_failure_state.ToString());
        }
        BOOST_CHECK_MESSAGE(local_failure_state.IsError(),
                            local_failure_state.ToString());
        BOOST_CHECK(!local_failure_state.IsInvalid());
        BOOST_CHECK_EQUAL(local_failure_state.GetResult(),
                          BlockValidationResult::BLOCK_RESULT_UNSET);
        BOOST_CHECK(local_failure_state.GetRejectReason().find(
                        "shadow-state evaluation failed") != std::string::npos);
        BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);

        {
            LOCK(cs_main);
            BOOST_CHECK((candidate.index->nStatus & BLOCK_FAILED_MASK) == 0);
            BOOST_REQUIRE(chainstate.m_chain.Tip() != nullptr);
            BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() ==
                        active_tip_hash);
            BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() ==
                        active_coins_hash);
            BOOST_CHECK(failed_view->GetBestBlock() == active_coins_hash);
            const ShadowGoldRushInfo shadow_after =
                GetShadowGoldRushInfo(*failed_view, parent);
            CheckShadowInfoEqual(shadow_before, shadow_after);
        }
    }

    // A clean process rebuilds the per-block cache from its durable parent.
    // Retrying the identical block must run Argon2 again, accept the base
    // block, and derive the same credit without any invalid-cache residue.
    fatal_guard.ClearExpectedFatal();
    std::unique_ptr<CCoinsViewCache> retry_view;
    ShadowGoldRushInfo retry_shadow;
    std::vector<ShadowSyntheticPayoutTransaction> retry_payouts;
    BlockValidationState retry_state;
    {
        LOCK(cs_main);
        retry_view = std::make_unique<CCoinsViewCache>(&chainstate.CoinsTip());
        SeedLegacyShadowClaimView(*retry_view, parent, candidate);
        const bool retry_connected = chainstate.ConnectBlock(
            candidate.block, retry_state, candidate.index.get(), *retry_view,
            /*fJustCheck=*/true, /*fCheckBlockSig=*/false);
        BOOST_REQUIRE_MESSAGE(retry_connected, retry_state.ToString());
        retry_shadow = GetShadowGoldRushInfo(*retry_view,
                                             candidate.index.get());
        retry_payouts = GetAppliedShadowClaimPayoutTransactionRecords(
            *retry_view, candidate.index->nHeight, candidate.block_hash,
            candidate.index->GetBlockTime());
    }
    BOOST_CHECK(retry_state.IsValid());
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    BOOST_CHECK_EQUAL(retry_shadow.pow_amount, 0);
    BOOST_CHECK_EQUAL(retry_shadow.pow_count, 1U);
    BOOST_REQUIRE_EQUAL(retry_payouts.size(), 1U);
    BOOST_CHECK(retry_payouts.front().proof_of_work);
    BOOST_CHECK(retry_payouts.front().target == candidate.payout_script);

    // Replaying from the same durable parent reproduces the exact synthetic
    // transaction identity and accounting, which is the restart/reindex
    // contract used by ConnectBlock and RollforwardBlock callers.
    CCoinsViewCache replay_view{&chainstate.CoinsTip()};
    BlockValidationState replay_state;
    std::vector<ShadowSyntheticPayoutTransaction> replay_payouts;
    ShadowGoldRushInfo replay_shadow;
    {
        LOCK(cs_main);
        SeedLegacyShadowClaimView(replay_view, parent, candidate);
        BOOST_REQUIRE(chainstate.ConnectBlock(
            candidate.block, replay_state, candidate.index.get(), replay_view,
            /*fJustCheck=*/true, /*fCheckBlockSig=*/false));
        replay_shadow = GetShadowGoldRushInfo(replay_view,
                                              candidate.index.get());
        replay_payouts = GetAppliedShadowClaimPayoutTransactionRecords(
            replay_view, candidate.index->nHeight, candidate.block_hash,
            candidate.index->GetBlockTime());
    }
    BOOST_CHECK(replay_state.IsValid());
    CheckShadowInfoEqual(retry_shadow, replay_shadow);
    BOOST_REQUIRE_EQUAL(replay_payouts.size(), retry_payouts.size());
    BOOST_CHECK(replay_payouts.front().tx->GetHash() ==
                retry_payouts.front().tx->GetHash());
    BOOST_CHECK_EQUAL(replay_payouts.front().amount,
                      retry_payouts.front().amount);
    BOOST_CHECK((candidate.index->nStatus & BLOCK_FAILED_MASK) == 0);
}

BOOST_FIXTURE_TEST_CASE(bounded_claim_accounting_accepts_max_weight_malformed_blocks,
                        BoundedShadowClaimTestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();
    CBlockIndex* parent{nullptr};
    {
        LOCK(cs_main);
        parent = chainstate.m_chain.Tip();
    }
    BOOST_REQUIRE(parent != nullptr);
    BOOST_REQUIRE_EQUAL(parent->nHeight, 100);
    const valtype malformed_payload{'Q', 'Q', 'S', 'P', 'R', 'O', 'O', 'F', 0};
    const CTxOut malformed_output{
        0, CScript{} << OP_RETURN << malformed_payload};

    const auto evaluate_and_connect = [&](LegacyShadowClaimCandidate& candidate,
                                          uint32_t expected_observed,
                                          uint32_t expected_evaluated,
                                          uint32_t expected_malformed,
                                          uint32_t expected_invalid,
                                          uint32_t expected_over_limit) {
        CCoinsViewCache view{&chainstate.CoinsTip()};
        SeedLegacyShadowClaimView(view, parent, candidate);
        ShadowPowAccountingContext context;
        BOOST_REQUIRE(PrepareShadowPowClaimAccounting(
                          view, candidate.index.get(), context) ==
                      ShadowPowAccountingResult::OK);
        BOOST_REQUIRE(context.valid);
        BOOST_REQUIRE(context.canonical_rule_active);

        std::vector<ShadowPowClaimAccounting> accounting;
        ShadowPowClaimAggregate aggregate;
        const auto evaluation_start = std::chrono::steady_clock::now();
        BOOST_REQUIRE(EvaluateShadowPowClaimAccounting(
                          context, candidate.block, nullptr, accounting,
                          &aggregate) == ShadowPowAccountingResult::OK);
        const auto evaluation_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - evaluation_start)
                .count();
        BOOST_CHECK_LT(evaluation_seconds, 120);
        BOOST_CHECK_LE(accounting.size(), MAX_SHADOW_POW_EVALS_PER_BLOCK);
        BOOST_CHECK_LE(accounting.capacity(), MAX_SHADOW_POW_EVALS_PER_BLOCK);
        BOOST_CHECK_LE(accounting.capacity() * sizeof(ShadowPowClaimAccounting),
                       MAX_SHADOW_POW_EVALS_PER_BLOCK *
                           sizeof(ShadowPowClaimAccounting));
        BOOST_CHECK_EQUAL(aggregate.observed_count, expected_observed);
        BOOST_CHECK_EQUAL(aggregate.evaluated_count, expected_evaluated);
        BOOST_CHECK_EQUAL(aggregate.malformed_transaction_count,
                          expected_malformed);
        BOOST_CHECK_EQUAL(aggregate.invalid_proof_count, expected_invalid);
        BOOST_CHECK_EQUAL(aggregate.evaluation_limit_count,
                          expected_over_limit);
        BOOST_CHECK(!aggregate.accounting_commitment.IsNull());

        ShadowProofObservationSummary observation_summary;
        const std::vector<ShadowProofObservation> observations =
            GetShadowProofObservations(candidate.block, observation_summary);
        BOOST_CHECK_EQUAL(observation_summary.observed_count,
                          expected_observed);
        BOOST_CHECK_EQUAL(observation_summary.returned_count,
                          std::min<uint32_t>(expected_observed,
                                             MAX_SHADOW_POW_EVALS_PER_BLOCK));
        BOOST_CHECK_EQUAL(observation_summary.omitted_count,
                          expected_observed -
                              observation_summary.returned_count);
        BOOST_CHECK_EQUAL(observations.size(),
                          observation_summary.returned_count);
        BOOST_CHECK_LE(observations.capacity(),
                       MAX_SHADOW_POW_EVALS_PER_BLOCK);
        BOOST_CHECK(!observation_summary.commitment.IsNull());

        BlockValidationState state;
        const auto connect_start = std::chrono::steady_clock::now();
        {
            LOCK(cs_main);
            BOOST_REQUIRE_MESSAGE(
                chainstate.ConnectBlock(candidate.block, state,
                                        candidate.index.get(), view,
                                        /*fJustCheck=*/true,
                                        /*fCheckBlockSig=*/false),
                state.ToString());
        }
        const auto connect_seconds =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - connect_start)
                .count();
        BOOST_CHECK_LT(connect_seconds, 120);
        BOOST_CHECK(state.IsValid());
        const ShadowGoldRushInfo info =
            GetShadowGoldRushInfo(view, candidate.index.get());
        BOOST_CHECK_EQUAL(info.pow_count, 0U);
        BOOST_CHECK_GT(info.pow_amount, 0);
    };

    LegacyShadowClaimCandidate single;
    {
        CCoinsViewCache construction_view{&chainstate.CoinsTip()};
        SeedLegacyShadowClaimView(construction_view, parent, single);
        single = BuildLegacyShadowClaimCandidate(
            parent, construction_view, chainman.GetConsensus());
    }
    CMutableTransaction single_tx{*single.block.vtx[2]};
    single_tx.vout.resize(1);
    CBlock sizing_block = single.block;
    sizing_block.vtx[2] = MakeTransactionRef(single_tx);
    const size_t output_weight =
        GetSerializeSize(TX_NO_WITNESS(malformed_output)) *
        WITNESS_SCALE_FACTOR;
    const size_t available_weight =
        MAX_BLOCK_WEIGHT - GetBlockWeight(sizing_block);
    const size_t initial_output_count =
        available_weight / output_weight > 8
            ? available_weight / output_weight - 8
            : 2;
    single_tx.vout.reserve(1 + initial_output_count + 8);
    for (size_t i = 0; i < initial_output_count; ++i) {
        single_tx.vout.push_back(malformed_output);
    }
    single.block.vtx[2] = MakeTransactionRef(single_tx);
    RefreshShadowCandidateBlock(single, parent);
    while (GetBlockWeight(single.block) + output_weight <=
           MAX_BLOCK_WEIGHT) {
        single_tx.vout.push_back(malformed_output);
        single.block.vtx[2] = MakeTransactionRef(single_tx);
        RefreshShadowCandidateBlock(single, parent);
    }
    while (GetBlockWeight(single.block) > MAX_BLOCK_WEIGHT) {
        single_tx.vout.pop_back();
        single.block.vtx[2] = MakeTransactionRef(single_tx);
        RefreshShadowCandidateBlock(single, parent);
    }
    const uint32_t single_notes =
        static_cast<uint32_t>(single_tx.vout.size() - 1);
    BOOST_REQUIRE_GT(single_notes, MAX_SHADOW_POW_EVALS_PER_BLOCK);
    BOOST_CHECK_LE(MAX_BLOCK_WEIGHT - GetBlockWeight(single.block),
                   output_weight);
    evaluate_and_connect(single, single_notes, 0, single_notes, 0, 0);

    LegacyShadowClaimCandidate many;
    {
        CCoinsViewCache construction_view{&chainstate.CoinsTip()};
        SeedLegacyShadowClaimView(construction_view, parent, many);
        many = BuildLegacyShadowClaimCandidate(
            parent, construction_view, chainman.GetConsensus());
    }
    many.block.vtx.resize(2);
    COutPoint previous = many.claim_outpoint;
    size_t estimated_weight = GetBlockWeight(many.block);
    size_t one_tx_weight{0};
    while (true) {
        CMutableTransaction tx;
        tx.nVersion = 1;
        tx.nTime = many.block.nTime;
        tx.vin.emplace_back(previous);
        tx.vout.emplace_back(many.claim_amount, many.legacy_script);
        tx.vout.push_back(malformed_output);
        CTransactionRef tx_ref = MakeTransactionRef(std::move(tx));
        const size_t tx_weight = GetTransactionWeight(*tx_ref);
        if (one_tx_weight == 0) one_tx_weight = tx_weight;
        if (estimated_weight + tx_weight + 16 > MAX_BLOCK_WEIGHT) break;
        previous = COutPoint{tx_ref->GetHash(), 0};
        many.block.vtx.push_back(std::move(tx_ref));
        estimated_weight += tx_weight;
    }
    RefreshShadowCandidateBlock(many, parent);
    while (GetBlockWeight(many.block) > MAX_BLOCK_WEIGHT) {
        many.block.vtx.pop_back();
        RefreshShadowCandidateBlock(many, parent);
    }
    const uint32_t many_notes =
        static_cast<uint32_t>(many.block.vtx.size() - 2);
    BOOST_REQUIRE_GT(many_notes, MAX_SHADOW_POW_EVALS_PER_BLOCK);
    BOOST_CHECK_LE(MAX_BLOCK_WEIGHT - GetBlockWeight(many.block),
                   one_tx_weight + 16);
    evaluate_and_connect(
        many, many_notes, MAX_SHADOW_POW_EVALS_PER_BLOCK, 0,
        MAX_SHADOW_POW_EVALS_PER_BLOCK,
        many_notes - MAX_SHADOW_POW_EVALS_PER_BLOCK);
}

BOOST_FIXTURE_TEST_CASE(block_signature_internal_failure_is_fail_stop_retryable_and_not_cached, RegTestingSetup)
{
    MLDSAFailureGuard mldsa_guard;
    FatalErrorTestGuard fatal_guard{m_node};
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    uint256 tip_hash;
    uint256 coins_tip_hash;
    ShadowGoldRushInfo active_shadow_before;
    ShadowReplayStateInfo active_replay_before;
    {
        LOCK(cs_main);
        const CBlockIndex* tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(tip != nullptr);
        tip_hash = tip->GetBlockHash();
        coins_tip_hash = chainstate.CoinsTip().GetBestBlock();
        active_shadow_before = GetShadowGoldRushInfo(chainstate.CoinsTip(), tip);
        active_replay_before = GetShadowReplayStateInfo(
            chainstate.CoinsTip(), Params().GetConsensus(), tip);
    }

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    const CBlock signed_block = BuildQuantumSignedBlock(pubkey, privkey, tip_hash);
    const uint256 signed_block_hash = signed_block.GetHash();

    // CheckBlock must preserve the distinction before either caller handles it.
    CBlock context_free = ReplayBlockBytes(signed_block);
    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BlockValidationState check_state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!CheckBlock(context_free, check_state, Params().GetConsensus(), chainstate));
    }
    BOOST_CHECK(check_state.IsError());
    BOOST_CHECK_EQUAL(check_state.GetResult(), BlockValidationResult::BLOCK_RESULT_UNSET);
    BOOST_CHECK_EQUAL(check_state.GetRejectReason(), "local-mldsa-block-signature-verification-error");
    BOOST_CHECK(!context_free.fChecked);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);

    // Reconstructing the same network bytes models a clean restart/replay: no
    // in-memory validation bit survives, and the cleared local fault is retried.
    CBlock replayed = ReplayBlockBytes(signed_block);
    BlockValidationState replay_state;
    {
        LOCK(cs_main);
        BOOST_CHECK(CheckBlock(replayed, replay_state, Params().GetConsensus(), chainstate));
    }
    BOOST_CHECK(replay_state.IsValid());
    BOOST_CHECK(replayed.fChecked);

    // Network ingress must fail-stop locally before AcceptBlock can create or
    // poison a block-index entry.
    CBlock ingress = ReplayBlockBytes(signed_block);
    auto ingress_ptr = std::make_shared<const CBlock>(std::move(ingress));
    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    bool new_block{true};
    BOOST_CHECK(!chainman.ProcessNewBlock(
        ingress_ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
    BOOST_CHECK(!ingress_ptr->fChecked);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(signed_block_hash) == nullptr);
        BOOST_REQUIRE(chainstate.m_chain.Tip() != nullptr);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() == tip_hash);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == coins_tip_hash);
        CheckShadowInfoEqual(active_shadow_before,
                             GetShadowGoldRushInfo(chainstate.CoinsTip(), chainstate.m_chain.Tip()));
        CheckShadowReplayEqual(active_replay_before,
                               GetShadowReplayStateInfo(chainstate.CoinsTip(), Params().GetConsensus(),
                                                        chainstate.m_chain.Tip()));
    }
    fatal_guard.ClearExpectedFatal();

    // ConnectBlock is the disk replay/reindex path. Its local view, candidate
    // status, active tip, and authenticated shadow state must remain unchanged.
    CBlock reconnect = ReplayBlockBytes(signed_block);
    uint256 reconnect_hash = reconnect.GetHash();
    CBlockIndex reconnect_index{reconnect.GetBlockHeader()};
    std::unique_ptr<CCoinsViewCache> reconnect_view;
    CBlockIndex* active_tip{nullptr};
    ShadowGoldRushInfo reconnect_shadow_before;
    ShadowReplayStateInfo reconnect_replay_before;
    uint256 reconnect_view_best;
    unsigned int reconnect_cache_size{0};
    {
        LOCK(cs_main);
        active_tip = chainstate.m_chain.Tip();
        BOOST_REQUIRE(active_tip != nullptr);
        reconnect_view = std::make_unique<CCoinsViewCache>(&chainstate.CoinsTip());
        reconnect_index.pprev = active_tip;
        reconnect_index.nHeight = active_tip->nHeight + 1;
        reconnect_index.phashBlock = &reconnect_hash;
        reconnect_index.SetProofOfStake();
        reconnect_shadow_before = GetShadowGoldRushInfo(*reconnect_view, active_tip);
        reconnect_replay_before = GetShadowReplayStateInfo(
            *reconnect_view, Params().GetConsensus(), active_tip);
        reconnect_view_best = reconnect_view->GetBestBlock();
        reconnect_cache_size = reconnect_view->GetCacheSize();
    }

    ML_DSA::SetFailureForTesting(MLDSATestFailure::VERIFY);
    BlockValidationState reconnect_state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!chainstate.ConnectBlock(reconnect, reconnect_state, &reconnect_index,
                                             *reconnect_view, /*fJustCheck=*/true,
                                             /*fCheckBlockSig=*/true));
    }
    BOOST_CHECK(reconnect_state.IsError());
    BOOST_CHECK_EQUAL(reconnect_state.GetResult(), BlockValidationResult::BLOCK_RESULT_UNSET);
    BOOST_CHECK_EQUAL(reconnect_state.GetRejectReason(), "local-mldsa-block-signature-verification-error");
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_FAILURE);
    BOOST_CHECK(!reconnect.fChecked);
    {
        LOCK(cs_main);
        BOOST_CHECK((reconnect_index.nStatus & BLOCK_FAILED_MASK) == 0);
        BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(reconnect_hash) == nullptr);
        BOOST_REQUIRE(chainstate.m_chain.Tip() != nullptr);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() == tip_hash);
        BOOST_CHECK(reconnect_view->GetBestBlock() == reconnect_view_best);
        BOOST_CHECK_EQUAL(reconnect_view->GetCacheSize(), reconnect_cache_size);
        CheckShadowInfoEqual(reconnect_shadow_before,
                             GetShadowGoldRushInfo(*reconnect_view, active_tip));
        CheckShadowReplayEqual(reconnect_replay_before,
                               GetShadowReplayStateInfo(*reconnect_view, Params().GetConsensus(), active_tip));
    }

    // Once the injected fault is gone, ConnectBlock re-evaluates the same bytes
    // and reaches their real contextual result. At this early regtest height the
    // quantum signing carrier is genuinely premature, so it is invalid rather
    // than a sticky local error; neither result mutates chain or shadow state.
    fatal_guard.ClearExpectedFatal();
    BlockValidationState reconnect_retry_state;
    {
        LOCK(cs_main);
        BOOST_CHECK(!chainstate.ConnectBlock(reconnect, reconnect_retry_state, &reconnect_index,
                                             *reconnect_view, /*fJustCheck=*/true,
                                             /*fCheckBlockSig=*/true));
    }
    BOOST_CHECK(reconnect_retry_state.IsInvalid());
    BOOST_CHECK_EQUAL(reconnect_retry_state.GetResult(), BlockValidationResult::BLOCK_CONSENSUS);
    BOOST_CHECK_EQUAL(reconnect_retry_state.GetRejectReason(), "bad-blk-signature");
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    {
        LOCK(cs_main);
        BOOST_CHECK((reconnect_index.nStatus & BLOCK_FAILED_MASK) == 0);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() == tip_hash);
        BOOST_CHECK(reconnect_view->GetBestBlock() == reconnect_view_best);
        BOOST_CHECK_EQUAL(reconnect_view->GetCacheSize(), reconnect_cache_size);
        CheckShadowInfoEqual(reconnect_shadow_before,
                             GetShadowGoldRushInfo(*reconnect_view, active_tip));
        CheckShadowReplayEqual(reconnect_replay_before,
                               GetShadowReplayStateInfo(*reconnect_view, Params().GetConsensus(), active_tip));
    }

    // A cryptographically bad signature remains deterministic consensus-invalid
    // and must not be promoted to a local fatal error.
    CBlock invalid = ReplayBlockBytes(signed_block);
    BOOST_REQUIRE(!invalid.vchBlockSig.empty());
    invalid.vchBlockSig[0] ^= 0x01;
    for (int attempt = 0; attempt < 2; ++attempt) {
        BlockValidationState invalid_state;
        {
            LOCK(cs_main);
            BOOST_CHECK(!CheckBlock(invalid, invalid_state, Params().GetConsensus(), chainstate));
        }
        BOOST_CHECK(invalid_state.IsInvalid());
        BOOST_CHECK_EQUAL(invalid_state.GetResult(), BlockValidationResult::BLOCK_CONSENSUS);
        BOOST_CHECK_EQUAL(invalid_state.GetRejectReason(), "bad-blk-signature");
        BOOST_CHECK(!invalid.fChecked);
    }

    auto invalid_ptr = std::make_shared<const CBlock>(ReplayBlockBytes(invalid));
    new_block = true;
    BOOST_CHECK(!chainman.ProcessNewBlock(
        invalid_ptr, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block));
    BOOST_CHECK(!new_block);
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    {
        LOCK(cs_main);
        BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(signed_block_hash) == nullptr);
        BOOST_CHECK(chainstate.m_chain.Tip()->GetBlockHash() == tip_hash);
        BOOST_CHECK(chainstate.CoinsTip().GetBestBlock() == coins_tip_hash);
        CheckShadowInfoEqual(active_shadow_before,
                             GetShadowGoldRushInfo(chainstate.CoinsTip(), chainstate.m_chain.Tip()));
        CheckShadowReplayEqual(active_replay_before,
                               GetShadowReplayStateInfo(chainstate.CoinsTip(), Params().GetConsensus(),
                                                        chainstate.m_chain.Tip()));
    }
}

BOOST_FIXTURE_TEST_CASE(noncanonical_block_signature_is_reported_as_invalid_header, RegTestingSetup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    const uint256 tip_hash = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()->GetBlockHash());

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    BOOST_REQUIRE(ML_DSA::KeyGen(pubkey, privkey));
    CBlock malformed = BuildQuantumSignedBlock(pubkey, privkey, tip_hash);
    BOOST_REQUIRE_EQUAL(malformed.vchBlockSig.size(), ML_DSA::SIGNATURE_BYTES);
    malformed.vchBlockSig.pop_back();

    auto block = std::make_shared<const CBlock>(ReplayBlockBytes(malformed));
    BlockCheckedCatcher catcher{block->GetHash()};
    RegisterValidationInterface(&catcher);
    bool new_block{true};
    const bool processed = chainman.ProcessNewBlock(
        block, /*force_processing=*/true, /*min_pow_checked=*/true, &new_block);
    UnregisterValidationInterface(&catcher);
    SyncWithValidationInterfaceQueue();

    BOOST_CHECK(!processed);
    BOOST_CHECK(!new_block);
    BOOST_REQUIRE(catcher.m_state.has_value());
    BOOST_CHECK(catcher.m_state->IsInvalid());
    BOOST_CHECK_EQUAL(catcher.m_state->GetResult(), BlockValidationResult::BLOCK_INVALID_HEADER);
    BOOST_CHECK_EQUAL(catcher.m_state->GetRejectReason(), "bad-signature-encoding");
    BOOST_CHECK_EQUAL(m_node.exit_status.load(), EXIT_SUCCESS);
    LOCK(cs_main);
    BOOST_CHECK(chainman.m_blockman.LookupBlockIndex(block->GetHash()) == nullptr);
    BOOST_CHECK(chainman.ActiveChain().Tip()->GetBlockHash() == tip_hash);
}

BOOST_AUTO_TEST_SUITE_END()
