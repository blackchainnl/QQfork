// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CONSENSUS_DEMURRAGE_H
#define BITCOIN_CONSENSUS_DEMURRAGE_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class Coin;
class CCoinsViewCache;
class CScript;
class CTransaction;

namespace Consensus {
struct Params;

static constexpr int DEMURRAGE_BLOCKS_PER_MONTH = 40500;
static constexpr int DEMURRAGE_GRACE_BLOCKS = 6 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int DEMURRAGE_ZERO_BLOCKS = 24 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int DEMURRAGE_DECAY_WINDOW_BLOCKS = DEMURRAGE_ZERO_BLOCKS - DEMURRAGE_GRACE_BLOCKS;
static constexpr int DEMURRAGE_ATTEST_VALIDITY_BLOCKS = DEMURRAGE_GRACE_BLOCKS;
static constexpr int DEMURRAGE_AUTO_ATTEST_BLOCKS = 3 * DEMURRAGE_BLOCKS_PER_MONTH;
static constexpr int64_t DEMURRAGE_PPM = 1000000;

struct DemurrageEvaluation {
    bool active{false};
    bool exempt{false};
    bool locked{false};
    int inactive_blocks{0};
    int64_t remaining_ppm{DEMURRAGE_PPM};
    CAmount nominal_value{0};
    CAmount effective_value{0};
    CAmount burned_value{0};
    std::string exemption;
};

struct DemurrageAttestationState {
    int height{0};
    uint32_t time{0};
    uint32_t coverage_start_height{0};
};

struct DemurrageAttestationSource {
    uint256 block_hash;
    uint256 txid;
    uint32_t output_index{0};

    bool operator==(const DemurrageAttestationSource& other) const
    {
        return block_hash == other.block_hash && txid == other.txid &&
               output_index == other.output_index;
    }
};

struct DemurrageAttestationRecord {
    uint256 pubkey_hash;
    DemurrageAttestationState state;
    uint256 source_block_hash;
    uint256 source_txid;
    uint32_t source_output_index{0};
};

struct DemurrageAttestation {
    int height{0};
    uint32_t output_index{0};
    COutPoint replay_anchor;
    COutPoint target_outpoint;
    std::optional<int> previous_height;
    uint32_t previous_time{0};
    uint32_t previous_coverage_start_height{0};
    std::optional<DemurrageAttestationSource> previous_source;
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> signature;
    uint256 pubkey_hash;
};

/** Typed attestation result. Local cryptographic or chainstate failures are
 * retryable node errors and must not be converted to transaction/block
 * invalidity. */
enum class DemurrageAttestationValidationResult {
    VALID,
    INVALID,
    LOCAL_INTERNAL_ERROR,
};

static constexpr size_t MAX_DEMURRAGE_ATTESTATIONS_PER_TX = 1;
static constexpr size_t MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK = 16;

int64_t DemurrageRemainingPpm(int inactive_blocks);
int64_t DemurrageRemainingPpm(int inactive_blocks, const Params& params);
CAmount DemurrageEffectiveValue(CAmount nominal_value, int64_t remaining_ppm);
bool IsDemurrageTreasuryExemptScript(const CScript& script_pub_key, const Params& params);
uint256 DemurragePubKeyHash(const std::vector<unsigned char>& pubkey);
uint256 DemurrageAttestationMessageHash(const COutPoint& replay_anchor,
                                        const COutPoint& target_outpoint,
                                        std::optional<int> previous_height,
                                        uint32_t previous_time,
                                        uint32_t previous_coverage_start_height,
                                        const std::optional<DemurrageAttestationSource>& previous_source,
                                        const std::vector<unsigned char>& pubkey,
                                        uint32_t quantum_chain_id);
std::vector<unsigned char> EncodeDemurrageAttestationPayload(const COutPoint& replay_anchor,
                                                              const COutPoint& target_outpoint,
                                                              std::optional<int> previous_height,
                                                              uint32_t previous_time,
                                                              uint32_t previous_coverage_start_height,
                                                              const std::optional<DemurrageAttestationSource>& previous_source,
                                                              const std::vector<unsigned char>& pubkey,
                                                              const std::vector<unsigned char>& signature);
CScript BuildDemurrageAttestationScript(const COutPoint& replay_anchor,
                                         const COutPoint& target_outpoint,
                                         std::optional<int> previous_height,
                                         uint32_t previous_time,
                                         uint32_t previous_coverage_start_height,
                                         const std::optional<DemurrageAttestationSource>& previous_source,
                                         const std::vector<unsigned char>& pubkey,
                                         const std::vector<unsigned char>& signature);
bool IsDemurrageAttestationScript(const CScript& script_pub_key);
bool DecodeDemurrageAttestationPayload(const std::vector<unsigned char>& payload, DemurrageAttestation& attestation);
std::vector<DemurrageAttestation> ExtractDemurrageAttestations(const CTransaction& tx);
DemurrageAttestationValidationResult CheckDemurrageAttestationsDetailed(
                                const CTransaction& tx,
                                const CCoinsViewCache& view,
                                const Params& params,
                                int spend_height,
                                int64_t spend_time,
                                std::set<uint256>& attested_keys,
                                size_t& attestation_count,
                                std::string& reject_reason);
bool CheckDemurrageAttestations(const CTransaction& tx,
                                const CCoinsViewCache& view,
                                const Params& params,
                                int spend_height,
                                int64_t spend_time,
                                std::set<uint256>& attested_keys,
                                size_t& attestation_count,
                                std::string& reject_reason);
std::optional<uint256> DemurrageControllingKeyHashForScript(const CScript& script_pub_key);
std::optional<int> LatestDemurrageAttestationHeight(const CCoinsViewCache& view, const uint256& pubkey_hash);
std::optional<DemurrageAttestationState> LatestDemurrageAttestationState(const CCoinsViewCache& view, const uint256& pubkey_hash);
std::optional<DemurrageAttestationRecord> LatestDemurrageAttestationRecord(const CCoinsViewCache& view, const uint256& pubkey_hash);
std::optional<int> LatestDemurrageAttestationHeightForScript(const CCoinsViewCache& view, const CScript& script_pub_key);
std::optional<DemurrageAttestationState> LatestDemurrageAttestationStateForScript(const CCoinsViewCache& view, const CScript& script_pub_key);
/** True when the deterministic latest-state record is absent or structurally
 * valid. False denotes local chainstate corruption, not a consensus result. */
bool IsDemurrageStateSaneForScript(const CCoinsViewCache& view,
                                   const CScript& script_pub_key);
bool DecodeAuthenticatedDemurrageLatestState(const COutPoint& outpoint, const Coin& coin,
                                             const CBlockIndex* pindex_tip, uint256& pubkey_hash,
                                             DemurrageAttestationState& state);
bool IsAuthenticatedDemurrageStateOutpoint(const COutPoint& outpoint, const Coin& coin, const CBlockIndex* pindex_tip);
/** Purge only current or obsolete auxiliary records authenticated by their
 * reserved outpoint, zero-value metadata, and active-chain source. Marker-like
 * transaction outputs at ordinary outpoints are never eligible. */
bool PurgeAuthenticatedDemurrageState(CCoinsViewCache& view, const CBlockIndex* pindex_tip, uint64_t& removed);
/** O(1) commitment used by the Quantum Quasar replay-state fingerprint. */
uint256 DemurrageInventoryCoinCommitment(const CCoinsViewCache& view);
/** Validate the rolling demurrage map commitment at an exact active tip. */
bool HasCurrentDemurrageInventory(const CCoinsViewCache& view,
                                  const CBlockIndex* pindex_tip,
                                  const Params& params);
bool CanApplyDemurrageInventory(const CCoinsViewCache& view,
                                const CBlockIndex* pindex,
                                const Params& params);
/** Constant-memory reconciliation of every authenticated QQALIVE leaf against
 * QQAINV. Intended for explicit maintenance verification after Final, not
 * normal startup or per block. */
bool DeepAuditDemurrageInventory(const CCoinsViewCache& view,
                                 const CBlockIndex* pindex_tip,
                                 const Params& params);
/** On an actually connected A-1 block, persist the versioned authenticated
 * empty inventory sentinel for A in O(1). Pre-activation attestations cannot
 * create records in its namespace. */
bool PrepareDemurrageActivationInventory(CCoinsViewCache& view,
                                         const CBlockIndex* pindex,
                                         const Params& params);

bool ApplyDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params, std::string& reject_reason);
/** Idempotently derive attestation marker post-state while recovering an
 *  already-validated block from a partially flushed coins database. */
bool RollforwardDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params);
bool UndoDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params);
CAmount GetDemurrageAdjustedValueIn(const CTransaction& tx, const CCoinsViewCache& inputs, const Params& params, int spend_height, int64_t spend_time);

DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time);
DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time,
    std::optional<int> latest_attestation_height,
    std::optional<int> attestation_coverage_start_height);

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_DEMURRAGE_H
