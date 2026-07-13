// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <crypto/argon2/argon2.h>
#include <crypto/mldsa.h>
#include <crypto/mldsa_kat.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

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

static void QuantumMLDSA44Verify(benchmark::Bench& bench)
{
    const std::vector<uint8_t> public_key = ParseHex(mldsa_kat::PUBLIC_KEY_HEX);
    const std::vector<uint8_t> message = ParseHex(mldsa_kat::VALID_MESSAGE_HEX);
    const std::vector<uint8_t> signature = ParseHex(mldsa_kat::VALID_SIGNATURE_HEX);
    if (ML_DSA::VerifyDetailed(public_key, message.data(), message.size(), signature) !=
        MLDSAVerifyResult::VALID) {
        throw std::runtime_error("ML-DSA benchmark vector failed verification");
    }
    bench.run([&] {
        const MLDSAVerifyResult result =
            ML_DSA::VerifyDetailed(public_key, message.data(), message.size(), signature);
        ankerl::nanobench::doNotOptimizeAway(result);
    });
}

BENCHMARK(QuantumArgon2id1MiB, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44Verify, benchmark::PriorityLevel::HIGH);
