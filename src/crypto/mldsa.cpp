#include <crypto/mldsa.h>

#include <crypto/mldsa_kat.h>
#include <support/cleanse.h>

#include <oqs/oqs.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <new>
#include <string_view>

namespace {

constexpr size_t MESSAGE_HASH_BYTES{32};
constexpr std::string_view REQUIRED_LIBOQS_VERSION{"0.15.0"};

std::atomic<MLDSATestFailure> g_test_failure{MLDSATestFailure::NONE};
std::atomic<uint64_t> g_test_failure_remaining{0};

struct OQSSigDeleter {
    void operator()(OQS_SIG* sig) const { OQS_SIG_free(sig); }
};

const OQS_SIG* GetMLDSA44()
{
    // OQS_SIG is immutable after construction. Sharing one instance eliminates
    // per-verification allocation and is safe for concurrent callers because
    // all algorithm state is held in each liboqs call's local buffers.
    static const std::unique_ptr<OQS_SIG, OQSSigDeleter> sig{OQS_SIG_new(OQS_SIG_alg_ml_dsa_44)};
    return sig.get();
}

bool HasExpectedMetadata(const OQS_SIG* sig)
{
    return sig != nullptr &&
           sig->method_name != nullptr &&
           std::strcmp(sig->method_name, OQS_SIG_alg_ml_dsa_44) == 0 &&
           sig->alg_version != nullptr &&
           std::strcmp(sig->alg_version, "FIPS204") == 0 &&
           sig->length_public_key == ML_DSA::PUBLICKEY_BYTES &&
           sig->length_secret_key == ML_DSA::SECRETKEY_BYTES &&
           sig->length_signature == ML_DSA::SIGNATURE_BYTES;
}

bool ConsumeTestFailure(MLDSATestFailure failure)
{
    if (g_test_failure.load(std::memory_order_acquire) != failure) return false;
    uint64_t remaining = g_test_failure_remaining.load(std::memory_order_relaxed);
    while (remaining != 0) {
        if (g_test_failure_remaining.compare_exchange_weak(
                remaining, remaining - 1,
                std::memory_order_acq_rel, std::memory_order_relaxed)) {
            return true;
        }
    }
    return false;
}

int HexDigit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool DecodeHex(std::string_view hex, std::vector<uint8_t>& out)
{
    if ((hex.size() & 1U) != 0) return false;
    try {
        std::vector<uint8_t> decoded(hex.size() / 2);
        for (size_t i = 0; i < decoded.size(); ++i) {
            const int high = HexDigit(hex[2 * i]);
            const int low = HexDigit(hex[2 * i + 1]);
            if (high < 0 || low < 0) return false;
            decoded[i] = static_cast<uint8_t>((high << 4) | low);
        }
        out.swap(decoded);
        return true;
    } catch (const std::bad_alloc&) {
        out.clear();
        return false;
    }
}

bool RunIndependentKnownAnswerTest()
{
    // C2SP/Wycheproof ML-DSA-44 vectors, independently generated from the
    // implementation linked here. See mldsa_kat.h for the pinned source,
    // commit, and digest. tcId 20 is valid; tcId 15 has a noncanonical reverse-
    // ordered hint encoding and must be rejected.
    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> valid_message;
    std::vector<uint8_t> valid_signature;
    std::vector<uint8_t> noncanonical_message;
    std::vector<uint8_t> noncanonical_signature;
    if (!DecodeHex(mldsa_kat::PUBLIC_KEY_HEX, pubkey) ||
        !DecodeHex(mldsa_kat::VALID_MESSAGE_HEX, valid_message) ||
        !DecodeHex(mldsa_kat::VALID_SIGNATURE_HEX, valid_signature) ||
        !DecodeHex(mldsa_kat::NONCANONICAL_MESSAGE_HEX, noncanonical_message) ||
        !DecodeHex(mldsa_kat::NONCANONICAL_SIGNATURE_HEX, noncanonical_signature)) {
        return false;
    }
    if (pubkey.size() != ML_DSA::PUBLICKEY_BYTES ||
        valid_message.size() != MESSAGE_HASH_BYTES ||
        valid_signature.size() != ML_DSA::SIGNATURE_BYTES ||
        noncanonical_message.size() != MESSAGE_HASH_BYTES ||
        noncanonical_signature.size() != ML_DSA::SIGNATURE_BYTES) {
        return false;
    }
    if (ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), valid_signature) !=
        MLDSAVerifyResult::VALID) {
        return false;
    }
    if (ML_DSA::VerifyDetailed(pubkey, noncanonical_message.data(), noncanonical_message.size(), noncanonical_signature) !=
        MLDSAVerifyResult::INVALID) {
        return false;
    }

    std::vector<uint8_t> short_signature{valid_signature.begin(), valid_signature.end() - 1};
    std::vector<uint8_t> long_signature{valid_signature};
    long_signature.push_back(0);
    return ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), short_signature) == MLDSAVerifyResult::INVALID &&
           ML_DSA::VerifyDetailed(pubkey, valid_message.data(), valid_message.size(), long_signature) == MLDSAVerifyResult::INVALID;
}

} // namespace

MLDSAOperationResult ML_DSA::KeyGenDetailed(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey)
{
    pubkey.clear();
    if (!privkey.empty()) memory_cleanse(privkey.data(), privkey.size());
    privkey.clear();
    if (ConsumeTestFailure(MLDSATestFailure::KEYGEN)) return MLDSAOperationResult::INTERNAL_ERROR;

    const OQS_SIG* sig = GetMLDSA44();
    if (!HasExpectedMetadata(sig)) return MLDSAOperationResult::INTERNAL_ERROR;

    try {
        std::vector<uint8_t> generated_pubkey(PUBLICKEY_BYTES);
        std::vector<uint8_t> generated_privkey(SECRETKEY_BYTES);
        if (OQS_SIG_keypair(sig, generated_pubkey.data(), generated_privkey.data()) != OQS_SUCCESS) {
            memory_cleanse(generated_privkey.data(), generated_privkey.size());
            return MLDSAOperationResult::INTERNAL_ERROR;
        }
        pubkey.swap(generated_pubkey);
        privkey.swap(generated_privkey);
        return MLDSAOperationResult::SUCCESS;
    } catch (const std::bad_alloc&) {
        pubkey.clear();
        if (!privkey.empty()) memory_cleanse(privkey.data(), privkey.size());
        privkey.clear();
        return MLDSAOperationResult::INTERNAL_ERROR;
    }
}

bool ML_DSA::KeyGen(std::vector<uint8_t>& pubkey, std::vector<uint8_t>& privkey)
{
    return KeyGenDetailed(pubkey, privkey) == MLDSAOperationResult::SUCCESS;
}

MLDSAOperationResult ML_DSA::SignDetailed(const std::vector<uint8_t>& privkey,
                                          const uint8_t* hash,
                                          size_t hash_len,
                                          std::vector<uint8_t>& signature)
{
    signature.clear();
    if (privkey.size() != SECRETKEY_BYTES || hash == nullptr || hash_len != MESSAGE_HASH_BYTES) {
        return MLDSAOperationResult::INVALID_INPUT;
    }
    if (ConsumeTestFailure(MLDSATestFailure::SIGN)) return MLDSAOperationResult::INTERNAL_ERROR;

    const OQS_SIG* sig = GetMLDSA44();
    if (!HasExpectedMetadata(sig)) return MLDSAOperationResult::INTERNAL_ERROR;

    try {
        std::vector<uint8_t> generated_signature(SIGNATURE_BYTES);
        size_t signature_len{0};
        if (OQS_SIG_sign(sig, generated_signature.data(), &signature_len, hash, hash_len, privkey.data()) != OQS_SUCCESS ||
            signature_len != SIGNATURE_BYTES) {
            std::fill(generated_signature.begin(), generated_signature.end(), 0);
            return MLDSAOperationResult::INTERNAL_ERROR;
        }
        signature.swap(generated_signature);
        return MLDSAOperationResult::SUCCESS;
    } catch (const std::bad_alloc&) {
        signature.clear();
        return MLDSAOperationResult::INTERNAL_ERROR;
    }
}

bool ML_DSA::Sign(const std::vector<uint8_t>& privkey,
                  const uint8_t* hash,
                  size_t hash_len,
                  std::vector<uint8_t>& signature)
{
    return SignDetailed(privkey, hash, hash_len, signature) == MLDSAOperationResult::SUCCESS;
}

MLDSAVerifyResult ML_DSA::VerifyDetailed(const uint8_t* pubkey,
                                         size_t pubkey_len,
                                         const uint8_t* hash,
                                         size_t hash_len,
                                         const uint8_t* signature,
                                         size_t signature_len)
{
    if (pubkey == nullptr || pubkey_len != PUBLICKEY_BYTES ||
        hash == nullptr || hash_len != MESSAGE_HASH_BYTES ||
        signature == nullptr || signature_len != SIGNATURE_BYTES) {
        return MLDSAVerifyResult::INVALID;
    }
    if (ConsumeTestFailure(MLDSATestFailure::VERIFY)) return MLDSAVerifyResult::INTERNAL_ERROR;

    const OQS_SIG* sig = GetMLDSA44();
    if (!HasExpectedMetadata(sig)) return MLDSAVerifyResult::INTERNAL_ERROR;

    // In pinned liboqs 0.15.0, ML-DSA-44 verification performs no recoverable
    // allocation: malformed/noncanonical signatures return OQS_ERROR, while
    // SHAKE allocation failure is process-fatal inside liboqs. Therefore an
    // OQS_ERROR here is a deterministic invalid-signature result.
    return OQS_SIG_verify(sig, hash, hash_len, signature, signature_len, pubkey) == OQS_SUCCESS
        ? MLDSAVerifyResult::VALID
        : MLDSAVerifyResult::INVALID;
}

MLDSAVerifyResult ML_DSA::VerifyDetailed(const std::vector<uint8_t>& pubkey,
                                         const uint8_t* hash,
                                         size_t hash_len,
                                         const std::vector<uint8_t>& signature)
{
    return VerifyDetailed(pubkey.data(), pubkey.size(), hash, hash_len,
                          signature.data(), signature.size());
}

bool ML_DSA::Verify(const std::vector<uint8_t>& pubkey,
                    const uint8_t* hash,
                    size_t hash_len,
                    const std::vector<uint8_t>& signature)
{
    return VerifyDetailed(pubkey, hash, hash_len, signature) == MLDSAVerifyResult::VALID;
}

bool ML_DSA::SelfTest()
{
    const char* linked_version = OQS_version();
    if (linked_version == nullptr || linked_version != REQUIRED_LIBOQS_VERSION) return false;
    if (!HasExpectedMetadata(GetMLDSA44())) return false;
    if (!RunIndependentKnownAnswerTest()) return false;

    std::vector<uint8_t> pubkey;
    std::vector<uint8_t> privkey;
    if (KeyGenDetailed(pubkey, privkey) != MLDSAOperationResult::SUCCESS) return false;

    std::array<uint8_t, MESSAGE_HASH_BYTES> message{};
    for (size_t i = 0; i < message.size(); ++i) message[i] = static_cast<uint8_t>(i);

    std::vector<uint8_t> signature;
    const MLDSAOperationResult signed_result = SignDetailed(privkey, message.data(), message.size(), signature);
    memory_cleanse(privkey.data(), privkey.size());
    privkey.clear();
    if (signed_result != MLDSAOperationResult::SUCCESS) return false;
    if (VerifyDetailed(pubkey, message.data(), message.size(), signature) != MLDSAVerifyResult::VALID) return false;

    signature[0] ^= 0x01;
    if (VerifyDetailed(pubkey, message.data(), message.size(), signature) != MLDSAVerifyResult::INVALID) return false;
    return true;
}

void ML_DSA::SetFailureForTesting(MLDSATestFailure failure, uint64_t count)
{
    if (failure == MLDSATestFailure::NONE || count == 0) {
        ClearFailureForTesting();
        return;
    }
    g_test_failure_remaining.store(count, std::memory_order_relaxed);
    g_test_failure.store(failure, std::memory_order_release);
}

void ML_DSA::ClearFailureForTesting()
{
    g_test_failure.store(MLDSATestFailure::NONE, std::memory_order_release);
    g_test_failure_remaining.store(0, std::memory_order_relaxed);
}
