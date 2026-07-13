#ifndef BLACKCOIN_CRYPTO_MLDSA_H
#define BLACKCOIN_CRYPTO_MLDSA_H

#include <vector>
#include <stdint.h>
#include <stddef.h>

/**
 * Quantum Quasar Post-Quantum Cryptography Engine
 * Wraps the NIST standard ML-DSA-44 implementation provided by liboqs.
 */

enum class MLDSAOperationResult : uint8_t {
    SUCCESS,
    INVALID_INPUT,
    INTERNAL_ERROR,
};

enum class MLDSAVerifyResult : uint8_t {
    VALID,
    INVALID,
    INTERNAL_ERROR,
};

/**
 * Test-only fault points. The setters are not wired to configuration, RPC, or
 * network input. They exist so unit tests can prove that local failures do not
 * become consensus-invalid results.
 */
enum class MLDSATestFailure : uint8_t {
    NONE,
    KEYGEN,
    SIGN,
    VERIFY,
};

class ML_DSA {
public:
    static constexpr size_t PUBLICKEY_BYTES = 1312;
    static constexpr size_t SECRETKEY_BYTES = 2560;
    static constexpr size_t SIGNATURE_BYTES = 2420;

    /** Generate a new ML-DSA keypair */
    static bool KeyGen(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey);
    static MLDSAOperationResult KeyGenDetailed(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey);

    /** Sign a 32-byte message hash using the ML-DSA private key */
    static bool Sign(const std::vector<uint8_t>& privkey, const uint8_t* hash, size_t hash_len, std::vector<uint8_t>& signature);
    static MLDSAOperationResult SignDetailed(const std::vector<uint8_t>& privkey, const uint8_t* hash, size_t hash_len, std::vector<uint8_t>& signature);

    /** Verify an ML-DSA signature against a message hash and public key */
    static bool Verify(const std::vector<uint8_t>& pubkey, const uint8_t* hash, size_t hash_len, const std::vector<uint8_t>& signature);
    static MLDSAVerifyResult VerifyDetailed(const std::vector<uint8_t>& pubkey, const uint8_t* hash, size_t hash_len, const std::vector<uint8_t>& signature);
    static MLDSAVerifyResult VerifyDetailed(const uint8_t* pubkey, size_t pubkey_len,
                                            const uint8_t* hash, size_t hash_len,
                                            const uint8_t* signature, size_t signature_len);

    /** Startup self-test for linked ML-DSA implementation */
    static bool SelfTest();

    static void SetFailureForTesting(MLDSATestFailure failure, uint64_t count = 1);
    static void ClearFailureForTesting();
};

#endif // BLACKCOIN_CRYPTO_MLDSA_H
