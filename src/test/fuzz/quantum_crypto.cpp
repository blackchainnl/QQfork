// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <crypto/mldsa.h>
#include <shadow.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <uint256.h>

#include <algorithm>
#include <cstdint>
#include <vector>

FUZZ_TARGET(quantum_crypto)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};

    // Fixed-width extraction lets corpus entries directly exercise ML-DSA-44
    // canonical decoding. Short inputs exercise every exact-size boundary.
    const std::vector<uint8_t> public_key = provider.ConsumeBytes<uint8_t>(ML_DSA::PUBLICKEY_BYTES);
    const std::vector<uint8_t> message = provider.ConsumeBytes<uint8_t>(uint256::size());
    const std::vector<uint8_t> signature = provider.ConsumeBytes<uint8_t>(ML_DSA::SIGNATURE_BYTES);
    (void)ML_DSA::VerifyDetailed(public_key, message.data(), message.size(), signature);

    ShadowPowWork work;
    work.valid = true;
    work.target = CScript{} << OP_TRUE;
    work.quantum_payout_script = GetScriptForDestination(
        WitnessUnknown{QUANTUM_MIGRATION_WITNESS_VERSION,
                       std::vector<unsigned char>(QUANTUM_MIGRATION_PROGRAM_SIZE, 0x51)});
    work.height = SHADOW_REWARD_START_HEIGHT;
    work.prev_hash = uint256::ONE;
    work.bits = 0;

    const size_t proof_size = std::min<size_t>(provider.remaining_bytes(), MAX_SCRIPT_ELEMENT_SIZE + 1);
    const std::vector<unsigned char> proof = provider.ConsumeBytes<unsigned char>(proof_size);
    (void)ValidateShadowPowProofForWorkDetailed(work, proof);
}
