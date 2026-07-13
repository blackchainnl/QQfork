// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <crypto/argon2_selftest.h>
#include <crypto/mldsa.h>
#include <crypto/mldsa_kat.h>
#include <crypto/sha256.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <shadow.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <atomic>
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
    ShadowArgon2FailureGuard() { ClearShadowArgon2FailuresForTesting(); }
    ~ShadowArgon2FailureGuard() { ClearShadowArgon2FailuresForTesting(); }
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
    BOOST_CHECK(ML_DSA::VerifyDetailed(nullptr, pubkey.size(), valid_message.data(), valid_message.size(), valid_signature.data(), valid_signature.size()) == MLDSAVerifyResult::INVALID);
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
    BOOST_CHECK(ML_DSA::SignDetailed(short_key, message.begin(), uint256::size(), signature) == MLDSAOperationResult::INVALID_INPUT);
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

BOOST_AUTO_TEST_SUITE_END()
