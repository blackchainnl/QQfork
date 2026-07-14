// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <consensus/consensus.h>
#include <consensus/demurrage.h>
#include <crypto/argon2/argon2.h>
#include <crypto/mldsa.h>
#include <crypto/mldsa_kat.h>
#include <shadow.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

constexpr size_t MIN_QUANTUM_INPUT_WEIGHT{3903};
constexpr size_t MAX_WEIGHT_BOUND_QUANTUM_INPUTS{
    V4_MAX_BLOCK_WEIGHT / MIN_QUANTUM_INPUT_WEIGHT};
constexpr size_t MAX_BLOCK_MLDSA_VERIFICATIONS{
    MAX_WEIGHT_BOUND_QUANTUM_INPUTS +
    Consensus::MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK + 1}; // PoS block signature
static_assert(MAX_WEIGHT_BOUND_QUANTUM_INPUTS == 8198);
static_assert(MAX_BLOCK_MLDSA_VERIFICATIONS == 8215);

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

} // namespace

static void QuantumArgon2id1MiB(benchmark::Bench& bench)
{
    std::array<uint8_t, 80> input{};
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 32> output{};
    bench.run([&] {
        const int result = argon2id_hash_raw(
            /*t_cost=*/1, /*m_cost=*/1024, /*parallelism=*/1,
            input.data(), input.size(), salt.data(), salt.size(),
            output.data(), output.size());
        ankerl::nanobench::doNotOptimizeAway(result);
        ankerl::nanobench::doNotOptimizeAway(output);
    });
}

static void QuantumArgon2id64ClaimBlock(benchmark::Bench& bench)
{
    std::array<uint8_t, 80> input{};
    std::array<uint8_t, 16> salt{};
    std::array<uint8_t, 32> output{};
    bench.unit("block").run([&] {
        int failures{0};
        for (size_t evaluation = 0;
             evaluation < MAX_SHADOW_POW_EVALS_PER_BLOCK; ++evaluation) {
            failures += argon2id_hash_raw(
                /*t_cost=*/1, /*m_cost=*/1024, /*parallelism=*/1,
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
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

static void QuantumMLDSA44MaxWeightBlock(benchmark::Bench& bench)
{
    const MLDSAVector vector = LoadMLDSAVector();
    bench.unit("block").run([&] {
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

BENCHMARK(QuantumArgon2id1MiB, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumArgon2id64ClaimBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44Verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44MaxWeightBlock, benchmark::PriorityLevel::HIGH);
