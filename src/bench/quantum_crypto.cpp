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
#include <primitives/block.h>
#include <script/interpreter.h>
#include <serialize.h>
#include <shadow.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <validation.h>

#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
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
static_assert(MIN_QUANTUM_INPUT_NONWITNESS_BYTES == 41);
static_assert(MIN_QUANTUM_INPUT_WITNESS_BYTES == 3739);
static_assert(MIN_QUANTUM_INPUT_WEIGHT == 3903);
static_assert(MAX_WEIGHT_BOUND_QUANTUM_INPUTS == 8198);
static_assert(MAX_BLOCK_MLDSA_VERIFICATIONS == 8215);

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

BENCHMARK(QuantumArgon2id1MiB, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumArgon2id64ClaimBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44Verify, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumMLDSA44MaxWeightBlock, benchmark::PriorityLevel::HIGH);
BENCHMARK(QuantumLargeBlockValidation32MiB, benchmark::PriorityLevel::HIGH);
