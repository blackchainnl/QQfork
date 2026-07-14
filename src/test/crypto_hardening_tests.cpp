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
#include <warnings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <memory>
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

BOOST_AUTO_TEST_SUITE_END()
