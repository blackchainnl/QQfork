#include <shadow.h>

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <crypto/argon2/argon2.h>
#include <crypto/common.h>
#include <crypto/muhash.h>
#include <hash.h>
#include <logging.h>
#include <streams.h>
#include <undo.h>
#include <util/fs.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <set>
#include <stdexcept>

namespace {

using valtype = std::vector<unsigned char>;

thread_local bool g_shadow_solver_activity_full_scan_disallowed{false};

static const valtype SHADOW_PREFIX{'Q', 'Q', 'S', 'P', 'R', 'O', 'O', 'F'};
static const valtype SIGNAL_PREFIX{'Q', 'Q', 'S', 'I', 'G', 'N', 'A', 'L'};
static const valtype MARKER_WHITELIST{'Q', 'Q', 'W', 'L'};
static const valtype MARKER_WHITELIST_READY{'Q', 'Q', 'W', 'L', 'R', 'E', 'A', 'D', 'Y'};
static const valtype MARKER_WHITELIST_MANIFEST{'Q', 'Q', 'W', 'L', 'M', 'A', 'N'};
static const valtype MARKER_WHITELIST_SHARD{'Q', 'Q', 'W', 'L', 'S', 'H'};
static const valtype MARKER_POOL{'Q', 'Q', 'P', 'O', 'O', 'L'};
static const valtype MARKER_POOL_UNDO{'Q', 'Q', 'P', 'U', 'N', 'D'};
static const valtype MARKER_DIRECT_CLAIM{'Q', 'Q', 'D', 'C', 'L', 'A', 'I', 'M'};
static const valtype MARKER_GOLD_RUSH_PAYOUT{'Q', 'Q', 'G', 'R', 'P', 'A', 'Y'};
static const valtype MARKER_GOLD_RUSH_SPENT{'Q', 'Q', 'G', 'R', 'S', 'P', 'E', 'N', 'T'};
static const valtype MARKER_GOLD_RUSH_INVENTORY{'Q', 'Q', 'G', 'R', 'I', 'N', 'V'};
static const valtype MARKER_SOLVER{'Q', 'Q', 'S', 'O', 'L', 'V', 'E'};
static const valtype MARKER_ACTIVE_SIGNAL{'Q', 'Q', 'A', 'S', 'I', 'G'};
static const valtype MARKER_ACTIVE_SIGNAL_SET{'Q', 'Q', 'A', 'S', 'E', 'T'};
static const valtype MARKER_ACTIVE_SIGNAL_SHARD{'Q', 'Q', 'A', 'S', 'H', 'D'};
static const valtype MARKER_ACTIVE_SIGNAL_UNDO{'Q', 'Q', 'A', 'U', 'N', 'D'};
static const valtype MARKER_ACTIVE_SIGNAL_UNDO_SHARD{'Q', 'Q', 'A', 'U', 'S', 'H'};
static const valtype MARKER_REPLAY_STATE{'Q', 'Q', 'R', 'E', 'P', 'L', 'A', 'Y'};
static const valtype MARKER_CLAIM_PAYOUT_TX{'Q', 'Q', 'C', 'P', 'A', 'Y'};
static const valtype PROOF_MAGIC_V1{'Q', 'Q', 'P', '1'};
static const valtype PROOF_MAGIC_V2{'Q', 'Q', 'P', '2'};
static const valtype PROOF_MAGIC_V3{'Q', 'Q', 'P', '3'};
static const valtype SIGNAL_MAGIC_V2{'Q', 'Q', 'S', '2'};
static const valtype CLAIM_MAGIC_V2{'Q', 'Q', 'C', '2'};
static const valtype CLAIM_MARKER_MAGIC_V3{'Q', 'Q', 'C', '3'};
static constexpr size_t PROOF_SIZE = 13; // magic(4) | mode(1) | nonce(8)
static constexpr size_t PROOF_V3_ORIGIN_SIZE = 36; // origin_height(4) | origin_parent_hash(32)
static constexpr size_t SIGNAL_HEADER_SIZE = 40; // magic(4) | solve_height(4) | solve_hash(32)
static constexpr size_t POOL_LEGACY_SIZE = 16;
static constexpr size_t POOL_V1_SIZE = 41;
static constexpr size_t POOL_V2_SIZE = 49;
static constexpr unsigned int BASE_SHADOW_TARGET_BITS = 12;
static constexpr unsigned int MIN_SHADOW_TARGET_BITS = 10;
static constexpr unsigned int MAX_SHADOW_TARGET_BITS = 18;
static constexpr uint8_t SHADOW_RETARGET_WINDOW = 64;
static constexpr int SHADOW_POW_TARGET_SPACING_BLOCKS = 1;
static constexpr int SHADOW_POW_ASERT_HALF_LIFE_BLOCKS = 64;
static constexpr uint32_t MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK = (V4_MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT) + 2;
// DoS bound: each QQSPROOF output triggers a memory-hard Argon2id (1 MiB) evaluation.
// An attacker could otherwise stuff a block with thousands of QQSPROOF outputs to force
// unbounded memory-hashing on every validating node. Honest blocks carry a single claim,
// so capping the number of proof evaluations per block at a generous constant bounds the
// worst-case validation cost (<= cap * 1 MiB) without affecting legitimate claims.
static_assert(static_cast<CAmount>(MAX_SHADOW_POW_EVALS_PER_BLOCK - 1) * CENT <
              (463 * COIN) / 2,
              "Gold Rush POW pool must exceed all capped loser reimbursements");
std::atomic<uint64_t> g_shadow_argon2_test_failures{0};
std::atomic<ShadowAllocationFailurePoint> g_shadow_allocation_test_failure{
    ShadowAllocationFailurePoint::NONE};

void MaybeThrowShadowAllocationFailureForTesting(
    ShadowAllocationFailurePoint point)
{
    ShadowAllocationFailurePoint expected{point};
    if (g_shadow_allocation_test_failure.compare_exchange_strong(
            expected, ShadowAllocationFailurePoint::NONE,
            std::memory_order_relaxed)) {
        throw std::bad_alloc{};
    }
}

// Increment whenever an auxiliary namespace or its authentication semantics
// changes. This prevents a checkpoint produced by a prerelease schema from
// authenticating merely because the affected inventory is currently empty.
static constexpr uint32_t SHADOW_REPLAY_STATE_VERSION = 12;
// Auxiliary marker payloads are serialized through the same 32 MiB bounded
// deserializer as other chain data. Enforce the bound while constructing and
// decoding the local authenticated state so a corrupt marker cannot trigger an
// oversized allocation before deterministic replay repairs it.
static constexpr size_t MAX_SHADOW_STATE_MARKER_BYTES = MAX_SIZE - 1024;
// CTxOutCompressor replaces scripts larger than MAX_SCRIPT_SIZE when reading
// them back from disk. Keep every persisted auxiliary marker comfortably below
// that hard boundary and split logical state across deterministic shards.
static constexpr size_t MAX_SHADOW_SHARD_DATA_BYTES = 8000;

bool IsDirectQuantumMigrationScript(const CScript& script)
{
    const auto tier = GetQuantumStakeTierProgram(script);
    return tier && !tier->tiered && !tier->cold_stake;
}

bool IsLegacyShadowTargetScript(const CScript& script)
{
    return !script.IsUnspendable() &&
           !IsQuantumMigrationScript(script) &&
           !IsQuantumColdStakeScript(script) &&
           !IsEUTXOScript(script);
}

const CBlockIndex* SafeGetAncestor(const CBlockIndex* tip, int height)
{
    if (!tip || height < 0 || height > tip->nHeight) return nullptr;
    const CBlockIndex* cursor = tip;
    while (cursor && cursor->nHeight > height) {
        if (cursor->pskip && cursor->pskip->nHeight >= height &&
            cursor->pskip->nHeight < cursor->nHeight) {
            cursor = cursor->pskip;
        } else {
            cursor = cursor->pprev;
        }
    }
    return cursor && cursor->nHeight == height ? cursor : nullptr;
}

enum class ShadowProofMode : unsigned char {
    POW = 0,
    POS = 1,
};

ShadowProofPayloadMode ClassifyProofPayloadMode(const valtype& proof)
{
    if (proof.size() < PROOF_SIZE ||
        (!std::equal(PROOF_MAGIC_V1.begin(), PROOF_MAGIC_V1.end(), proof.begin()) &&
         !std::equal(PROOF_MAGIC_V2.begin(), PROOF_MAGIC_V2.end(), proof.begin()) &&
         !std::equal(PROOF_MAGIC_V3.begin(), PROOF_MAGIC_V3.end(), proof.begin()))) {
        return ShadowProofPayloadMode::MALFORMED;
    }
    if (proof[4] == static_cast<unsigned char>(ShadowProofMode::POW)) {
        return ShadowProofPayloadMode::POW;
    }
    if (proof[4] == static_cast<unsigned char>(ShadowProofMode::POS)) {
        return ShadowProofPayloadMode::POS;
    }
    return ShadowProofPayloadMode::UNKNOWN;
}

struct ShadowPoolState {
    CAmount pow_amount{0};
    CAmount pos_amount{0};
    CAmount claimed_amount{0};
    uint32_t pow_count{0};
    uint32_t pos_count{0};
    uint32_t last_pow_height{0};
    uint32_t last_pos_height{0};
    uint8_t recent_count{0};
    uint64_t recent_modes{0};
};

struct ShadowPoolUndoState {
    bool previous_present{false};
    uint32_t previous_height{0};
    uint32_t previous_time{0};
    uint256 previous_marker_hash;
    uint256 block_hash;
    uint256 previous_block_hash;
    uint256 pre_state_hash;
    uint256 post_state_hash;
    uint32_t claim_count{0};
    uint256 claims_hash;
    ShadowPoolState previous;
};

struct ShadowClaim {
    CScript target;
    CAmount amount{0};
    ShadowProofMode mode{ShadowProofMode::POW};
    ShadowPoolState undo_pool;
    bool direct{false};
};

uint256 HashBlockClaims(int height, const uint256& block_hash,
                        const std::vector<ShadowClaim>& claims);
uint256 HashBlockClaims(const CBlockIndex* pindex,
                        const std::vector<ShadowClaim>& claims);

/** A fee-paying QQSPROOF can produce only this PoW-specific value. The generic
 * ShadowClaim mode is assigned later at the single marker-construction seam. */
struct ShadowPowCredit {
    CScript payout_script;
    CAmount amount{0};
};

struct ShadowPowClaimResult {
    std::vector<ShadowPowCredit> credits;
    std::vector<ShadowPowClaimAccounting> accounting;
    ShadowPowClaimAggregate aggregate;
    bool internal_error{false};
    bool proof_limit_exceeded{false};
    bool competing_claims{false};
    bool malformed_claim{false};
    bool invalid_claim_location{false};
    bool wrong_mode_claim{false};
    bool unknown_mode_claim{false};
    bool current_winner{false};
    uint32_t valid_claim_count{0};
    uint32_t reimbursed_claim_count{0};
};

struct ShadowSignal {
    CScript target;
    CScript payout_script;
    uint32_t solve_height{0};
    uint256 solve_hash;
    bool quantum_linked{false};
};

struct ShadowActiveSignal {
    CScript target;
    CScript payout_script;
    uint32_t last_signal_height{0};
};

struct ActiveSignalStateManifest {
    uint256 marker_hash;
    uint32_t entry_count{0};
    uint32_t total_size{0};
    uint32_t shard_count{0};
    uint256 blob_hash;
};

struct ActiveSignalUndoManifest {
    uint256 block_hash;
    uint256 previous_block_hash;
    uint32_t total_size{0};
    uint32_t shard_count{0};
    uint256 blob_hash;
};

struct WhitelistManifest {
    uint32_t snapshot_height{0};
    uint256 snapshot_hash;
    uint32_t entry_count{0};
    uint32_t total_size{0};
    uint32_t shard_count{0};
    uint256 blob_hash;
};

struct WhitelistMemberRecord {
    uint256 snapshot_hash;
    uint256 manifest_hash;
    uint256 script_hash;
    CScript script;
};

struct ShadowActiveSignalUndo {
    bool state_was_present{false};
    uint32_t previous_marker_height{0};
    uint32_t previous_marker_time{0};
    uint256 previous_marker_hash;
    uint256 block_hash;
    uint256 previous_block_hash;
    uint256 pre_state_hash;
    uint256 post_state_hash;
    std::map<CScript, std::optional<ShadowActiveSignal>> previous_entries;
};

struct ShadowProof {
    ShadowProofMode mode{ShadowProofMode::POW};
    uint64_t nonce{0};
    CScript target;
    CScript payout_script;
    bool quantum_linked{false};
    bool origin_bound{false};
    uint32_t origin_height{0};
    uint256 origin_previous_block_hash;
};

CScript MarkerScript(const valtype& tag, const valtype& payload = {})
{
    // This is not pruned by AddCoin() because it does not start with OP_RETURN,
    // but any attempted spend reaches OP_RETURN and fails.
    return CScript() << OP_FALSE << OP_RETURN << tag << payload;
}

bool ParseMarkerScript(const CScript& script, const valtype& expected_tag, valtype* payload = nullptr)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_FALSE) return false;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, data) || data != expected_tag) return false;
    if (pc == script.end()) {
        if (payload) payload->clear();
        return true;
    }
    if (!script.GetOp(pc, opcode, data)) return false;
    if (pc != script.end()) return false;
    if (payload) *payload = data;
    return true;
}

uint256 TaggedHash(const std::string& tag, const valtype& payload)
{
    CHashWriter ss;
    ss << tag << payload;
    return ss.GetHash();
}

CScript CanonicalLegacyStakeScript(const CScript& script)
{
    if ((script.size() == CPubKey::COMPRESSED_SIZE + 2 && script[0] == CPubKey::COMPRESSED_SIZE && script.back() == OP_CHECKSIG) ||
        (script.size() == CPubKey::SIZE + 2 && script[0] == CPubKey::SIZE && script.back() == OP_CHECKSIG)) {
        const valtype pubkey_bytes(script.begin() + 1, script.end() - 1);
        const CPubKey pubkey(pubkey_bytes);
        if (pubkey.IsValid()) {
            return GetScriptForDestination(PKHash(pubkey));
        }
    }
    return script;
}

COutPoint WhitelistOutpoint(const CScript& script)
{
    return COutPoint{TaggedHash("Quantum Quasar Legacy Whitelist", {script.begin(), script.end()}), 0};
}

COutPoint WhitelistReadyOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Legacy Whitelist Ready", {}), 0};
}

COutPoint WhitelistManifestOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Legacy Whitelist Manifest", {}), 0};
}

COutPoint WhitelistManifestShardOutpoint(const uint256& snapshot_hash, uint32_t shard_index)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Legacy Whitelist Manifest Shard")
       << snapshot_hash << shard_index;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint PoolOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Shadow Pool", {}), 0};
}

COutPoint PoolUndoOutpoint(int height, const uint256& block_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Pool Undo")
       << height << block_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint PoolUndoOutpoint(const CBlockIndex* pindex)
{
    return PoolUndoOutpoint(pindex->nHeight, pindex->GetBlockHash());
}

COutPoint ReplayStateOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Shadow Replay State", {}), 0};
}

valtype ReplayStateFingerprint(const Consensus::Params& consensus, const CBlockIndex* pindex,
                               const CCoinsViewCache& view);

} // namespace

uint32_t GetShadowSyntheticClaimLimit(const Consensus::Params& consensus,
                                      int height,
                                      uint32_t authenticated_whitelist_count)
{
    if (!consensus.IsShadowCompetingClaimsActive(height)) {
        return MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK;
    }
    const uint64_t derived_limit =
        static_cast<uint64_t>(authenticated_whitelist_count) +
        MAX_SHADOW_POW_EVALS_PER_BLOCK;
    return static_cast<uint32_t>(std::min<uint64_t>(
        MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK, derived_limit));
}

std::optional<ShadowActiveSignalResourceBounds>
GetShadowActiveSignalResourceBounds(uint32_t whitelist_entries,
                                    uint32_t whitelist_blob_bytes)
{
    // The whitelist blob is version(1), count(4), then at least a uint16
    // length and one script byte per entry. Reject impossible dimensions
    // before using them to relax any active-state allocation bound.
    static constexpr uint64_t WHITELIST_HEADER_BYTES{1 + sizeof(uint32_t)};
    static constexpr uint64_t MINIMUM_WHITELIST_ENTRY_BYTES{
        sizeof(uint16_t) + 1};
    const uint64_t minimum_whitelist_bytes = WHITELIST_HEADER_BYTES +
        static_cast<uint64_t>(whitelist_entries) *
            MINIMUM_WHITELIST_ENTRY_BYTES;
    if (whitelist_entries > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK ||
        whitelist_blob_bytes < minimum_whitelist_bytes ||
        whitelist_blob_bytes > MAX_SHADOW_STATE_MARKER_BYTES) {
        return std::nullopt;
    }

    // Whitelist encoding contributes (uint16 length + target) per entry.
    // Active state contributes (height + two uint16 lengths + target + the
    // fixed 34-byte direct quantum payout), plus a 37-byte header. Relative
    // to the whitelist blob this is exactly 32 + 40 bytes per entry.
    //
    // Undo has a 174-byte header. Its maximum entry restores a previous
    // signal and contributes (target length + target + presence + height +
    // payout length + fixed payout), exactly 169 + 41 bytes per whitelist
    // entry beyond the whitelist blob.
    static_assert(2 + QUANTUM_MIGRATION_PROGRAM_SIZE == 34);
    const uint64_t state_bytes = std::min<uint64_t>(
        MAX_SHADOW_STATE_MARKER_BYTES,
        static_cast<uint64_t>(whitelist_blob_bytes) + 32 +
            static_cast<uint64_t>(whitelist_entries) * 40);
    const uint64_t undo_bytes = std::min<uint64_t>(
        MAX_SHADOW_STATE_MARKER_BYTES,
        static_cast<uint64_t>(whitelist_blob_bytes) + 169 +
            static_cast<uint64_t>(whitelist_entries) * 41);
    const auto shard_count = [](uint64_t bytes) {
        return static_cast<uint32_t>(
            (bytes + MAX_SHADOW_SHARD_DATA_BYTES - 1) /
            MAX_SHADOW_SHARD_DATA_BYTES);
    };

    return ShadowActiveSignalResourceBounds{
        whitelist_entries,
        whitelist_blob_bytes,
        static_cast<uint32_t>(state_bytes),
        static_cast<uint32_t>(undo_bytes),
        shard_count(state_bytes),
        shard_count(undo_bytes),
    };
}

CScript CanonicalizeLegacyStakeScript(const CScript& scriptPubKey)
{
    return CanonicalLegacyStakeScript(scriptPubKey);
}

namespace {

COutPoint ClaimOutpoint(int height, const uint256& block_hash, uint32_t n)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Claim") << height << block_hash << n;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ClaimOutpoint(const CBlockIndex* pindex, uint32_t n)
{
    return ClaimOutpoint(pindex->nHeight, pindex->GetBlockHash(), n);
}

CTransactionRef BuildClaimPayoutTransaction(int height, const uint256& block_hash, int64_t block_time, uint32_t marker_index, const ShadowClaim& claim)
{
    valtype anchor;
    anchor.reserve(4 + uint256::size() + 4);
    anchor.resize(4);
    WriteLE32(anchor.data(), static_cast<uint32_t>(height));
    anchor.insert(anchor.end(), block_hash.begin(), block_hash.end());
    const size_t marker_offset = anchor.size();
    anchor.resize(anchor.size() + 4);
    WriteLE32(anchor.data() + marker_offset, marker_index);

    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.nTime = block_time;
    mtx.vin.emplace_back(COutPoint{}, CScript{} << MARKER_CLAIM_PAYOUT_TX << anchor);
    mtx.vout.emplace_back(claim.amount, claim.target);
    return MakeTransactionRef(std::move(mtx));
}

CTransactionRef BuildClaimPayoutTransaction(const CBlockIndex* pindex, uint32_t marker_index, const ShadowClaim& claim)
{
    return BuildClaimPayoutTransaction(pindex->nHeight, pindex->GetBlockHash(), pindex->GetBlockTime(), marker_index, claim);
}

COutPoint ClaimPayoutOutpoint(const CBlockIndex* pindex, uint32_t marker_index, const ShadowClaim& claim)
{
    return COutPoint{BuildClaimPayoutTransaction(pindex, marker_index, claim)->GetHash(), 0};
}

COutPoint SolverOutpoint(const CScript& script, uint32_t height, const uint256& block_hash)
{
    const uint256 script_hash = TaggedHash("Quantum Quasar Solver Target v2", {script.begin(), script.end()});
    CHashWriter ss;
    ss << std::string("Quantum Quasar Recent Solver v2") << script_hash << height << block_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalOutpoint(int height, const uint256& block_hash, uint32_t n)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal") << height << block_hash << n;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalOutpoint(const CBlockIndex* pindex, uint32_t n)
{
    return ActiveSignalOutpoint(pindex->nHeight, pindex->GetBlockHash(), n);
}

COutPoint ActiveSignalSetOutpoint()
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal Set");
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalShardOutpoint(const uint256& marker_hash, uint32_t shard_index)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal State Shard")
       << marker_hash << shard_index;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalUndoOutpoint(const CBlockIndex* pindex)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal Undo")
       << pindex->nHeight << pindex->GetBlockHash();
    return COutPoint{ss.GetHash(), 0};
}

COutPoint ActiveSignalUndoShardOutpoint(const uint256& block_hash, uint32_t shard_index)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal Undo Shard")
       << block_hash << shard_index;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint GoldRushPayoutOutpoint(const COutPoint& payout_outpoint)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Direct Gold Rush Payout") << payout_outpoint;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint GoldRushSpentOutpoint(const COutPoint& payout_outpoint)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Gold Rush Payout Spent v1") << payout_outpoint;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint GoldRushInventoryOutpoint()
{
    return COutPoint{TaggedHash("Quantum Quasar Gold Rush Inventory v1", {}), 0};
}

struct GoldRushPayoutRecord {
    uint32_t origin_height{0};
    uint256 origin_block_hash;
    uint32_t claim_index{0};
    COutPoint payout_outpoint;
    CAmount nominal_amount{0};
    ShadowProofMode mode{ShadowProofMode::POW};
    uint256 claim_hash;
    CScript target;
};

bool AuthenticateGoldRushPayoutRecord(const CCoinsViewCache& view,
                                      const COutPoint& outpoint,
                                      GoldRushPayoutRecord& record,
                                      CScript* payout_script,
                                      const CBlockIndex* pindex_tip = nullptr);

valtype DataStreamBytes(const DataStream& stream)
{
    const auto bytes = MakeUCharSpan(stream);
    return valtype(bytes.begin(), bytes.end());
}

valtype EncodeGoldRushPayoutRecord(const GoldRushPayoutRecord& record)
{
    DataStream stream;
    stream << uint8_t{2} << record.origin_height << record.origin_block_hash
           << record.claim_index << record.payout_outpoint << record.nominal_amount
           << static_cast<uint8_t>(record.mode) << record.claim_hash << record.target;
    return DataStreamBytes(stream);
}

bool DecodeGoldRushPayoutRecordPayload(const valtype& payload, GoldRushPayoutRecord& record)
{
    record = {};
    try {
        DataStream stream{MakeUCharSpan(payload)};
        uint8_t version{0};
        uint8_t mode{0};
        stream >> version >> record.origin_height >> record.origin_block_hash
               >> record.claim_index >> record.payout_outpoint >> record.nominal_amount
               >> mode >> record.claim_hash >> record.target;
        if (!stream.empty() || version != 2 || mode > static_cast<uint8_t>(ShadowProofMode::POS)) return false;
        record.mode = static_cast<ShadowProofMode>(mode);
    } catch (const std::exception&) {
        return false;
    }
    return record.origin_height >= static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) &&
           record.origin_height <= static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) &&
           record.claim_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK &&
           !record.origin_block_hash.IsNull() && !record.payout_outpoint.IsNull() &&
           record.nominal_amount > 0 && MoneyRange(record.nominal_amount) &&
           !record.claim_hash.IsNull() && IsDirectQuantumMigrationScript(record.target);
}

uint256 GoldRushPayoutRecordHash(const GoldRushPayoutRecord& record)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Gold Rush Payout Record v2")
       << EncodeGoldRushPayoutRecord(record);
    return ss.GetHash();
}

struct GoldRushSpentState {
    COutPoint payout_outpoint;
    uint256 payout_record_hash;
    CAmount nominal_amount{0};
    uint32_t spend_height{0};
    uint256 spend_block_hash;
    uint256 spending_txid;
    uint32_t input_index{0};
};

valtype EncodeGoldRushSpentState(const GoldRushSpentState& state)
{
    DataStream stream;
    stream << uint8_t{2} << state.payout_outpoint << state.payout_record_hash
           << state.nominal_amount << state.spend_height << state.spend_block_hash
           << state.spending_txid << state.input_index;
    return DataStreamBytes(stream);
}

bool DecodeGoldRushSpentState(const CScript& script, GoldRushSpentState& state)
{
    state = {};
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_GOLD_RUSH_SPENT, &payload) ||
        payload.size() > MAX_SHADOW_STATE_MARKER_BYTES) return false;
    try {
        DataStream stream{MakeUCharSpan(payload)};
        uint8_t version{0};
        stream >> version >> state.payout_outpoint >> state.payout_record_hash
               >> state.nominal_amount >> state.spend_height >> state.spend_block_hash
               >> state.spending_txid >> state.input_index;
        if (!stream.empty() || version != 2) return false;
    } catch (const std::exception&) {
        return false;
    }
    return !state.payout_outpoint.IsNull() && !state.spend_block_hash.IsNull() &&
           !state.spending_txid.IsNull() && !state.payout_record_hash.IsNull() &&
           state.nominal_amount > 0 && MoneyRange(state.nominal_amount);
}

struct GoldRushInventoryState {
    uint32_t tip_height{0};
    uint256 tip_hash;
    uint64_t issued_count{0};
    CAmount issued_nominal{0};
    uint64_t spent_count{0};
    CAmount spent_nominal{0};
    MuHash3072 issued_set;
    MuHash3072 unspent_set;
    uint256 issued_root;
    uint256 unspent_root;
};

uint256 FinalizedMuHash(const MuHash3072& source)
{
    MuHash3072 copy{source};
    uint256 result;
    copy.Finalize(result);
    return result;
}

void FinalizeGoldRushInventory(GoldRushInventoryState& state)
{
    // Finalize the persisted accumulators themselves, not copies. This
    // normalizes each denominator to one so a disconnect/reconnect that
    // restores the same logical set produces byte-identical QQGRINV/QQRSTATE.
    state.issued_set.Finalize(state.issued_root);
    state.unspent_set.Finalize(state.unspent_root);
}

valtype EncodeGoldRushInventory(const GoldRushInventoryState& state)
{
    DataStream stream;
    stream << uint8_t{1} << state.tip_height << state.tip_hash
           << state.issued_count << state.issued_nominal
           << state.spent_count << state.spent_nominal
           << state.issued_set << state.unspent_set
           << state.issued_root << state.unspent_root;
    return DataStreamBytes(stream);
}

bool DecodeGoldRushInventory(const CScript& script, GoldRushInventoryState& state)
{
    state = {};
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_GOLD_RUSH_INVENTORY, &payload) ||
        payload.size() > MAX_SHADOW_STATE_MARKER_BYTES) return false;
    try {
        DataStream stream{MakeUCharSpan(payload)};
        uint8_t version{0};
        stream >> version >> state.tip_height >> state.tip_hash
               >> state.issued_count >> state.issued_nominal
               >> state.spent_count >> state.spent_nominal
               >> state.issued_set >> state.unspent_set
               >> state.issued_root >> state.unspent_root;
        if (!stream.empty() || version != 1) return false;
    } catch (const std::exception&) {
        return false;
    }
    return !state.tip_hash.IsNull() && state.spent_count <= state.issued_count &&
           state.issued_nominal >= 0 && MoneyRange(state.issued_nominal) &&
           state.spent_nominal >= 0 && state.spent_nominal <= state.issued_nominal;
}

bool GoldRushInventoryRootsValid(const GoldRushInventoryState& state)
{
    return FinalizedMuHash(state.issued_set) == state.issued_root &&
           FinalizedMuHash(state.unspent_set) == state.unspent_root;
}

enum class GoldRushInventoryReadResult { MISSING, VALID, INVALID };

GoldRushInventoryReadResult ReadGoldRushInventory(const CCoinsViewCache& view,
                                                  GoldRushInventoryState& state,
                                                  Coin* coin_out = nullptr)
{
    Coin coin;
    if (!view.GetCoin(GoldRushInventoryOutpoint(), coin) || coin.IsSpent()) {
        state = {};
        return GoldRushInventoryReadResult::MISSING;
    }
    if (coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeGoldRushInventory(coin.out.scriptPubKey, state) ||
        coin.nHeight != state.tip_height) {
        return GoldRushInventoryReadResult::INVALID;
    }
    if (coin_out) *coin_out = coin;
    return GoldRushInventoryReadResult::VALID;
}

bool WriteGoldRushInventory(CCoinsViewCache& view, const CBlockIndex* pindex,
                            GoldRushInventoryState state, bool finalize = true)
{
    if (!pindex) return false;
    state.tip_height = pindex->nHeight;
    state.tip_hash = pindex->GetBlockHash();
    if (finalize) FinalizeGoldRushInventory(state);
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_INVENTORY,
                                         EncodeGoldRushInventory(state));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(GoldRushInventoryOutpoint(), std::move(coin), true);
    return true;
}

valtype GoldRushPayoutLeaf(const GoldRushPayoutRecord& record)
{
    DataStream stream;
    stream << std::string("Quantum Quasar Gold Rush Inventory Leaf v1")
           << EncodeGoldRushPayoutRecord(record);
    return DataStreamBytes(stream);
}

bool AdvanceGoldRushInventoryTipInternal(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT) return pindex != nullptr;
    GoldRushInventoryState state;
    const GoldRushInventoryReadResult result = ReadGoldRushInventory(view, state);
    if (result == GoldRushInventoryReadResult::INVALID ||
        (result == GoldRushInventoryReadResult::MISSING &&
         pindex->nHeight != SHADOW_REWARD_START_HEIGHT)) return false;
    if (result == GoldRushInventoryReadResult::VALID &&
        state.tip_hash != pindex->GetBlockHash() &&
        (!pindex->pprev || state.tip_hash != pindex->pprev->GetBlockHash())) {
        return false;
    }
    if (result == GoldRushInventoryReadResult::VALID &&
        state.tip_hash != pindex->GetBlockHash() &&
        !GoldRushInventoryRootsValid(state)) return false;
    return WriteGoldRushInventory(view, pindex, std::move(state), /*finalize=*/true);
}

bool RewindGoldRushInventoryTipInternal(CCoinsViewCache& view, const CBlockIndex* disconnected)
{
    if (!disconnected || disconnected->nHeight < SHADOW_REWARD_START_HEIGHT) return disconnected != nullptr;
    GoldRushInventoryState state;
    if (ReadGoldRushInventory(view, state) != GoldRushInventoryReadResult::VALID ||
        state.tip_hash != disconnected->GetBlockHash()) return false;
    if (!disconnected->pprev || disconnected->pprev->nHeight < SHADOW_REWARD_START_HEIGHT) {
        view.SpendCoin(GoldRushInventoryOutpoint());
        return true;
    }
    return WriteGoldRushInventory(view, disconnected->pprev, std::move(state), /*finalize=*/true);
}

uint256 GoldRushInventoryCoinCommitment(const CCoinsViewCache& view)
{
    Coin coin;
    const bool present = view.GetCoin(GoldRushInventoryOutpoint(), coin) && !coin.IsSpent();
    CHashWriter ss;
    ss << std::string("Quantum Quasar Gold Rush Inventory Coin Commitment v1") << present;
    if (present) ss << coin.nHeight << coin.nTime << coin.out.scriptPubKey;
    return ss.GetHash();
}

valtype EncodeAmount(CAmount amount)
{
    valtype out(8);
    WriteLE64(out.data(), static_cast<uint64_t>(amount));
    return out;
}

std::optional<CAmount> DecodeAmount(const valtype& data)
{
    if (data.size() < 8) return std::nullopt;
    const uint64_t raw = ReadLE64(data.data());
    if (raw > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    return static_cast<CAmount>(raw);
}

std::optional<CAmount> CheckedAddMoney(CAmount left, CAmount right)
{
    if (!MoneyRange(left) || !MoneyRange(right)) return std::nullopt;
    if (left > MAX_MONEY - right) return std::nullopt;
    return left + right;
}

valtype EncodeSignalPayloadV2(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash)
{
    valtype out(SIGNAL_HEADER_SIZE + 4 + target.size() + quantum_payout_script.size());
    std::copy(SIGNAL_MAGIC_V2.begin(), SIGNAL_MAGIC_V2.end(), out.begin());
    WriteLE32(out.data() + 4, solve_height);
    std::copy(solve_hash.begin(), solve_hash.end(), out.begin() + 8);
    WriteLE16(out.data() + SIGNAL_HEADER_SIZE, static_cast<uint16_t>(target.size()));
    auto cursor = out.begin() + SIGNAL_HEADER_SIZE + 2;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(quantum_payout_script.size()));
    cursor += 2;
    std::copy(quantum_payout_script.begin(), quantum_payout_script.end(), cursor);
    return out;
}

bool DecodeSignalPayload(const valtype& payload, ShadowSignal& signal)
{
    if (payload.size() < SIGNAL_HEADER_SIZE) return false;
    signal = {};
    signal.solve_height = ReadLE32(payload.data() + 4);
    std::copy(payload.begin() + 8, payload.begin() + 40, signal.solve_hash.begin());

    if (std::equal(SIGNAL_MAGIC_V2.begin(), SIGNAL_MAGIC_V2.end(), payload.begin())) {
        if (payload.size() < SIGNAL_HEADER_SIZE + 4) return false;
        const size_t target_size = ReadLE16(payload.data() + SIGNAL_HEADER_SIZE);
        size_t cursor = SIGNAL_HEADER_SIZE + 2;
        if (target_size == 0 || cursor + target_size + 2 > payload.size()) return false;
        signal.target = CScript(payload.begin() + cursor, payload.begin() + cursor + target_size);
        cursor += target_size;
        const size_t payout_size = ReadLE16(payload.data() + cursor);
        cursor += 2;
        if (payout_size == 0 || cursor + payout_size != payload.size()) return false;
        signal.payout_script = CScript(payload.begin() + cursor, payload.end());
        signal.quantum_linked = true;
        if (!IsDirectQuantumMigrationScript(signal.payout_script)) return false;
    } else {
        return false;
    }

    return !signal.target.empty() && !signal.target.IsUnspendable() &&
           !signal.payout_script.empty() && !signal.payout_script.IsUnspendable();
}

valtype EncodeActiveSignalMarker(const CScript& target, const CScript& payout_script, uint32_t last_signal_height)
{
    valtype out(8 + target.size() + payout_script.size());
    WriteLE32(out.data(), last_signal_height);
    WriteLE16(out.data() + 4, static_cast<uint16_t>(target.size()));
    auto cursor = out.begin() + 6;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(payout_script.size()));
    cursor += 2;
    std::copy(payout_script.begin(), payout_script.end(), cursor);
    return out;
}

bool DecodeActiveSignalMarker(const CScript& script, ShadowActiveSignal& signal)
{
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL, &payload)) return false;
    if (payload.size() < 8) return false;
    const uint32_t last_signal_height = ReadLE32(payload.data());
    const size_t target_size = ReadLE16(payload.data() + 4);
    size_t cursor = 6;
    if (target_size == 0 || cursor + target_size + 2 > payload.size()) return false;
    CScript target(payload.begin() + cursor, payload.begin() + cursor + target_size);
    cursor += target_size;
    const size_t payout_size = ReadLE16(payload.data() + cursor);
    cursor += 2;
    if (payout_size == 0 || cursor + payout_size != payload.size()) return false;
    CScript payout(payload.begin() + cursor, payload.end());
    if (target.empty() || target.IsUnspendable()) return false;
    if (!IsDirectQuantumMigrationScript(payout)) return false;
    signal = ShadowActiveSignal{target, payout, last_signal_height};
    return true;
}

valtype EncodeSolverMarker(const CScript& solver)
{
    const uint256 hash = TaggedHash("Quantum Quasar Solver Target v2", {solver.begin(), solver.end()});
    valtype payload(1 + uint256::size());
    payload[0] = 2;
    std::copy(hash.begin(), hash.end(), payload.begin() + 1);
    return payload;
}

bool DecodeSolverMarkerHash(const CScript& script, uint256& solver_hash)
{
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_SOLVER, &payload) ||
        payload.size() != 1 + uint256::size() || payload[0] != 2) return false;
    std::copy(payload.begin() + 1, payload.end(), solver_hash.begin());
    return !solver_hash.IsNull();
}

bool SolverMarkerMatches(const CScript& marker_script, const CScript& solver)
{
    uint256 marker_hash;
    return DecodeSolverMarkerHash(marker_script, marker_hash) &&
           marker_hash == TaggedHash("Quantum Quasar Solver Target v2", {solver.begin(), solver.end()});
}

uint256 HashStateBlob(const std::string& domain, const valtype& blob)
{
    return TaggedHash(domain, blob);
}

uint32_t BlobShardCount(size_t blob_size)
{
    if (blob_size == 0) return 0;
    const size_t count = (blob_size + MAX_SHADOW_SHARD_DATA_BYTES - 1) / MAX_SHADOW_SHARD_DATA_BYTES;
    return count > std::numeric_limits<uint32_t>::max() ? 0 : static_cast<uint32_t>(count);
}

valtype EncodeBlobShard(const uint256& anchor_hash, uint32_t shard_index,
                        uint32_t shard_count, size_t total_size,
                        const valtype& blob)
{
    if (total_size != blob.size() || shard_count == 0 || shard_index >= shard_count ||
        total_size > MAX_SHADOW_STATE_MARKER_BYTES) return {};
    const size_t offset = static_cast<size_t>(shard_index) * MAX_SHADOW_SHARD_DATA_BYTES;
    if (offset >= blob.size()) return {};
    const size_t data_size = std::min(MAX_SHADOW_SHARD_DATA_BYTES, blob.size() - offset);
    valtype payload(1 + uint256::size() + 3 * sizeof(uint32_t) + data_size);
    size_t cursor = 0;
    payload[cursor++] = 1;
    std::copy(anchor_hash.begin(), anchor_hash.end(), payload.begin() + cursor);
    cursor += uint256::size();
    WriteLE32(payload.data() + cursor, shard_index);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, shard_count);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, static_cast<uint32_t>(total_size));
    cursor += sizeof(uint32_t);
    std::copy(blob.begin() + offset, blob.begin() + offset + data_size, payload.begin() + cursor);
    return payload;
}

bool DecodeBlobShard(const CScript& script, const valtype& tag, const uint256& anchor_hash,
                     uint32_t expected_index, uint32_t expected_count, uint32_t expected_total_size,
                     valtype& data_out)
{
    data_out.clear();
    valtype payload;
    static constexpr size_t HEADER_SIZE = 1 + uint256::size() + 3 * sizeof(uint32_t);
    if (!ParseMarkerScript(script, tag, &payload) || payload.size() < HEADER_SIZE ||
        payload.size() > HEADER_SIZE + MAX_SHADOW_SHARD_DATA_BYTES || payload[0] != 1) return false;
    size_t cursor = 1;
    uint256 decoded_anchor;
    std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), decoded_anchor.begin());
    cursor += uint256::size();
    const uint32_t index = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    const uint32_t count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    const uint32_t total_size = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    if (decoded_anchor != anchor_hash || index != expected_index || count != expected_count ||
        total_size != expected_total_size || expected_count == 0 || expected_index >= expected_count ||
        expected_total_size > MAX_SHADOW_STATE_MARKER_BYTES) return false;
    const size_t expected_offset = static_cast<size_t>(expected_index) * MAX_SHADOW_SHARD_DATA_BYTES;
    if (expected_offset >= expected_total_size) return false;
    const size_t expected_data_size = std::min<size_t>(MAX_SHADOW_SHARD_DATA_BYTES,
                                                       expected_total_size - expected_offset);
    if (payload.size() - cursor != expected_data_size) return false;
    data_out.assign(payload.begin() + cursor, payload.end());
    return true;
}

bool EncodeWhitelistBlob(const std::set<CScript>& whitelist, valtype& blob)
{
    if (whitelist.size() > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK) return false;
    blob.assign(1 + sizeof(uint32_t), 0);
    blob[0] = 1;
    WriteLE32(blob.data() + 1, static_cast<uint32_t>(whitelist.size()));
    for (const CScript& script : whitelist) {
        if (!IsLegacyShadowTargetScript(script) || script.size() > std::numeric_limits<uint16_t>::max()) return false;
        const size_t entry_size = sizeof(uint16_t) + script.size();
        if (entry_size > MAX_SHADOW_STATE_MARKER_BYTES - blob.size()) return false;
        const size_t old_size = blob.size();
        blob.resize(old_size + entry_size);
        WriteLE16(blob.data() + old_size, static_cast<uint16_t>(script.size()));
        std::copy(script.begin(), script.end(), blob.begin() + old_size + sizeof(uint16_t));
    }
    return true;
}

bool DecodeWhitelistBlob(const valtype& blob, uint32_t max_entries, std::set<CScript>& whitelist)
{
    whitelist.clear();
    if (blob.size() < 1 + sizeof(uint32_t) || blob.size() > MAX_SHADOW_STATE_MARKER_BYTES || blob[0] != 1) return false;
    const uint32_t count = ReadLE32(blob.data() + 1);
    if (count > max_entries || count > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK) return false;
    size_t cursor = 1 + sizeof(uint32_t);
    CScript previous;
    for (uint32_t i = 0; i < count; ++i) {
        if (cursor + sizeof(uint16_t) > blob.size()) return false;
        const size_t script_size = ReadLE16(blob.data() + cursor);
        cursor += sizeof(uint16_t);
        if (script_size == 0 || cursor + script_size > blob.size()) return false;
        CScript script(blob.begin() + cursor, blob.begin() + cursor + script_size);
        cursor += script_size;
        if (!IsLegacyShadowTargetScript(script) || (i != 0 && !(previous < script)) ||
            !whitelist.insert(script).second) return false;
        previous = std::move(script);
    }
    return cursor == blob.size() && whitelist.size() == count;
}

valtype EncodeWhitelistManifest(const WhitelistManifest& manifest)
{
    valtype payload(1 + 4 * sizeof(uint32_t) + 2 * uint256::size());
    size_t cursor = 0;
    payload[cursor++] = 1;
    WriteLE32(payload.data() + cursor, manifest.snapshot_height);
    cursor += sizeof(uint32_t);
    std::copy(manifest.snapshot_hash.begin(), manifest.snapshot_hash.end(), payload.begin() + cursor);
    cursor += uint256::size();
    for (uint32_t value : {manifest.entry_count, manifest.total_size, manifest.shard_count}) {
        WriteLE32(payload.data() + cursor, value);
        cursor += sizeof(uint32_t);
    }
    std::copy(manifest.blob_hash.begin(), manifest.blob_hash.end(), payload.begin() + cursor);
    return payload;
}

bool DecodeWhitelistManifest(const CScript& script, WhitelistManifest& manifest)
{
    manifest = {};
    valtype payload;
    static constexpr size_t SIZE = 1 + 4 * sizeof(uint32_t) + 2 * uint256::size();
    if (!ParseMarkerScript(script, MARKER_WHITELIST_MANIFEST, &payload) ||
        payload.size() != SIZE || payload[0] != 1) return false;
    size_t cursor = 1;
    manifest.snapshot_height = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), manifest.snapshot_hash.begin());
    cursor += uint256::size();
    manifest.entry_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    manifest.total_size = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    manifest.shard_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    std::copy(payload.begin() + cursor, payload.end(), manifest.blob_hash.begin());
    return manifest.snapshot_height == static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) &&
           !manifest.snapshot_hash.IsNull() && !manifest.blob_hash.IsNull() &&
           manifest.entry_count <= MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK &&
           manifest.total_size > 0 && manifest.total_size <= MAX_SHADOW_STATE_MARKER_BYTES &&
           manifest.shard_count == BlobShardCount(manifest.total_size);
}

valtype EncodeWhitelistMember(const uint256& snapshot_hash,
                              const uint256& manifest_hash,
                              const CScript& script)
{
    if (!IsLegacyShadowTargetScript(script) ||
        script.size() > std::numeric_limits<uint16_t>::max()) return {};
    const uint256 script_hash = TaggedHash(
        "Quantum Quasar Whitelist Member v2", {script.begin(), script.end()});
    valtype payload(1 + 3 * uint256::size() + sizeof(uint16_t) + script.size());
    payload[0] = 3;
    size_t cursor = 1;
    for (const uint256* hash : {&snapshot_hash, &manifest_hash, &script_hash}) {
        std::copy(hash->begin(), hash->end(), payload.begin() + cursor);
        cursor += uint256::size();
    }
    WriteLE16(payload.data() + cursor, static_cast<uint16_t>(script.size()));
    cursor += sizeof(uint16_t);
    std::copy(script.begin(), script.end(), payload.begin() + cursor);
    return payload;
}

bool DecodeWhitelistMember(const valtype& payload, WhitelistMemberRecord& member)
{
    member = {};
    const size_t header_size = 1 + 3 * uint256::size() + sizeof(uint16_t);
    if (payload.size() < header_size || payload[0] != 3) return false;
    size_t cursor = 1;
    for (uint256* hash : {&member.snapshot_hash, &member.manifest_hash,
                          &member.script_hash}) {
        std::copy(payload.begin() + cursor,
                  payload.begin() + cursor + uint256::size(), hash->begin());
        cursor += uint256::size();
    }
    const size_t script_size = ReadLE16(payload.data() + cursor);
    cursor += sizeof(uint16_t);
    if (script_size == 0 || cursor + script_size != payload.size()) return false;
    member.script = CScript(payload.begin() + cursor, payload.end());
    return !member.snapshot_hash.IsNull() && !member.manifest_hash.IsNull() &&
           IsLegacyShadowTargetScript(member.script) &&
           CanonicalLegacyStakeScript(member.script) == member.script &&
           member.script_hash == TaggedHash(
               "Quantum Quasar Whitelist Member v2",
               {member.script.begin(), member.script.end()});
}

bool ReadWhitelistManifest(const CCoinsViewCache& view, const CBlockIndex* pindex,
                           WhitelistManifest& manifest, std::set<CScript>* whitelist_out = nullptr)
{
    Coin manifest_coin;
    if (!view.GetCoin(WhitelistManifestOutpoint(), manifest_coin) || manifest_coin.IsSpent() ||
        manifest_coin.out.nValue != 0 || !manifest_coin.fCoinBase || manifest_coin.fCoinStake ||
        manifest_coin.nHeight != static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) ||
        manifest_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeWhitelistManifest(manifest_coin.out.scriptPubKey, manifest)) return false;
    if (pindex) {
        const CBlockIndex* snapshot_block = SafeGetAncestor(pindex, manifest.snapshot_height);
        if (!snapshot_block || snapshot_block->GetBlockHash() != manifest.snapshot_hash ||
            manifest_coin.nTime != static_cast<uint32_t>(snapshot_block->GetBlockTime())) return false;
    }
    valtype blob;
    blob.reserve(manifest.total_size);
    for (uint32_t shard_index = 0; shard_index < manifest.shard_count; ++shard_index) {
        Coin shard_coin;
        valtype shard_data;
        if (!view.GetCoin(WhitelistManifestShardOutpoint(manifest.snapshot_hash, shard_index), shard_coin) ||
            shard_coin.IsSpent() || shard_coin.out.nValue != 0 ||
            !shard_coin.fCoinBase || shard_coin.fCoinStake ||
            shard_coin.nHeight != manifest_coin.nHeight ||
            shard_coin.nTime != manifest_coin.nTime || shard_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
            !DecodeBlobShard(shard_coin.out.scriptPubKey, MARKER_WHITELIST_SHARD,
                             manifest.snapshot_hash, shard_index, manifest.shard_count,
                             manifest.total_size, shard_data)) return false;
        blob.insert(blob.end(), shard_data.begin(), shard_data.end());
    }
    if (blob.size() != manifest.total_size ||
        HashStateBlob("Quantum Quasar Whitelist Manifest Blob v1", blob) != manifest.blob_hash) return false;
    std::set<CScript> whitelist;
    if (!DecodeWhitelistBlob(blob, manifest.entry_count, whitelist) ||
        whitelist.size() != manifest.entry_count) return false;
    if (whitelist_out) *whitelist_out = std::move(whitelist);
    return true;
}

bool ActiveSignalEqual(const ShadowActiveSignal& lhs, const ShadowActiveSignal& rhs)
{
    return lhs.target == rhs.target &&
           lhs.payout_script == rhs.payout_script &&
           lhs.last_signal_height == rhs.last_signal_height;
}

bool EncodeActiveSignalSetPayload(const std::map<CScript, ShadowActiveSignal>& active,
                                  const uint256& marker_hash, valtype& out)
{
    if (active.size() > std::numeric_limits<uint32_t>::max()) return false;
    out.assign(1 + uint256::size() + sizeof(uint32_t), 0);
    out[0] = 2;
    std::copy(marker_hash.begin(), marker_hash.end(), out.begin() + 1);
    WriteLE32(out.data() + 1 + uint256::size(), static_cast<uint32_t>(active.size()));
    for (const auto& [target, signal] : active) {
        if (target.empty() || target.IsUnspendable() || signal.target != target ||
            target.size() > std::numeric_limits<uint16_t>::max() ||
            !IsDirectQuantumMigrationScript(signal.payout_script) ||
            signal.payout_script.size() > std::numeric_limits<uint16_t>::max()) {
            return false;
        }
        const size_t entry_size = sizeof(uint32_t) + sizeof(uint16_t) + target.size() +
                                  sizeof(uint16_t) + signal.payout_script.size();
        const size_t old_size = out.size();
        if (entry_size > MAX_SHADOW_STATE_MARKER_BYTES - old_size) return false;
        out.resize(old_size + entry_size);
        unsigned char* cursor = out.data() + old_size;
        WriteLE32(cursor, signal.last_signal_height);
        cursor += sizeof(uint32_t);
        WriteLE16(cursor, static_cast<uint16_t>(target.size()));
        cursor += sizeof(uint16_t);
        cursor = std::copy(target.begin(), target.end(), cursor);
        WriteLE16(cursor, static_cast<uint16_t>(signal.payout_script.size()));
        cursor += sizeof(uint16_t);
        std::copy(signal.payout_script.begin(), signal.payout_script.end(), cursor);
    }
    return true;
}

bool DecodeActiveSignalSetPayload(const valtype& payload, std::map<CScript, ShadowActiveSignal>& active,
                                  uint256* marker_hash_out = nullptr,
                                  uint32_t max_entries = std::numeric_limits<uint32_t>::max())
{
    active.clear();
    if (payload.size() < 1 + uint256::size() + sizeof(uint32_t) ||
        payload.size() > MAX_SHADOW_STATE_MARKER_BYTES || payload[0] != 2) {
        return false;
    }
    uint256 marker_hash;
    std::copy(payload.begin() + 1, payload.begin() + 1 + uint256::size(), marker_hash.begin());
    if (marker_hash.IsNull()) return false;
    if (marker_hash_out) *marker_hash_out = marker_hash;
    const uint32_t count = ReadLE32(payload.data() + 1 + uint256::size());
    if (count > max_entries) return false;
    size_t cursor = 1 + uint256::size() + sizeof(uint32_t);
    // Every entry needs at least a height, two lengths, and one byte in each
    // script. Reject impossible counts before the map starts allocating.
    static constexpr size_t MIN_ENTRY_SIZE = sizeof(uint32_t) + 2 * sizeof(uint16_t) + 2;
    if (count > (payload.size() - cursor) / MIN_ENTRY_SIZE) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (cursor + sizeof(uint32_t) + sizeof(uint16_t) > payload.size()) return false;
        const uint32_t last_height = ReadLE32(payload.data() + cursor);
        cursor += sizeof(uint32_t);
        const size_t target_size = ReadLE16(payload.data() + cursor);
        cursor += sizeof(uint16_t);
        if (target_size == 0 || cursor + target_size + sizeof(uint16_t) > payload.size()) return false;
        CScript target(payload.begin() + cursor, payload.begin() + cursor + target_size);
        cursor += target_size;
        const size_t payout_size = ReadLE16(payload.data() + cursor);
        cursor += sizeof(uint16_t);
        if (payout_size == 0 || cursor + payout_size > payload.size()) return false;
        CScript payout(payload.begin() + cursor, payload.begin() + cursor + payout_size);
        cursor += payout_size;
        if (target.IsUnspendable() || !IsDirectQuantumMigrationScript(payout) ||
            !active.emplace(target, ShadowActiveSignal{target, payout, last_height}).second) {
            return false;
        }
    }
    return cursor == payload.size();
}

valtype EncodeActiveSignalStateManifest(const ActiveSignalStateManifest& manifest)
{
    valtype payload(1 + uint256::size() + 3 * sizeof(uint32_t) + uint256::size());
    size_t cursor = 0;
    payload[cursor++] = 3;
    std::copy(manifest.marker_hash.begin(), manifest.marker_hash.end(), payload.begin() + cursor);
    cursor += uint256::size();
    WriteLE32(payload.data() + cursor, manifest.entry_count);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, manifest.total_size);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, manifest.shard_count);
    cursor += sizeof(uint32_t);
    std::copy(manifest.blob_hash.begin(), manifest.blob_hash.end(), payload.begin() + cursor);
    return payload;
}

bool DecodeActiveSignalStateManifest(const CScript& script, ActiveSignalStateManifest& manifest)
{
    manifest = {};
    valtype payload;
    static constexpr size_t SIZE = 1 + uint256::size() + 3 * sizeof(uint32_t) + uint256::size();
    if (!ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_SET, &payload) ||
        payload.size() != SIZE || payload[0] != 3) return false;
    size_t cursor = 1;
    std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), manifest.marker_hash.begin());
    cursor += uint256::size();
    manifest.entry_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    manifest.total_size = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    manifest.shard_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    std::copy(payload.begin() + cursor, payload.end(), manifest.blob_hash.begin());
    return !manifest.marker_hash.IsNull() && !manifest.blob_hash.IsNull() &&
           manifest.total_size > 0 && manifest.total_size <= MAX_SHADOW_STATE_MARKER_BYTES &&
           manifest.shard_count == BlobShardCount(manifest.total_size);
}

valtype EncodeActiveSignalUndoManifest(const ActiveSignalUndoManifest& manifest)
{
    valtype payload(1 + 2 * uint256::size() + 2 * sizeof(uint32_t) + uint256::size());
    size_t cursor = 0;
    payload[cursor++] = 2;
    for (const uint256* hash : {&manifest.block_hash, &manifest.previous_block_hash}) {
        std::copy(hash->begin(), hash->end(), payload.begin() + cursor);
        cursor += uint256::size();
    }
    WriteLE32(payload.data() + cursor, manifest.total_size);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, manifest.shard_count);
    cursor += sizeof(uint32_t);
    std::copy(manifest.blob_hash.begin(), manifest.blob_hash.end(), payload.begin() + cursor);
    return payload;
}

bool DecodeActiveSignalUndoManifest(const CScript& script, ActiveSignalUndoManifest& manifest)
{
    manifest = {};
    valtype payload;
    static constexpr size_t SIZE = 1 + 2 * uint256::size() + 2 * sizeof(uint32_t) + uint256::size();
    if (!ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_UNDO, &payload) ||
        payload.size() != SIZE || payload[0] != 2) return false;
    size_t cursor = 1;
    for (uint256* hash : {&manifest.block_hash, &manifest.previous_block_hash}) {
        std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), hash->begin());
        cursor += uint256::size();
    }
    manifest.total_size = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    manifest.shard_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    std::copy(payload.begin() + cursor, payload.end(), manifest.blob_hash.begin());
    return !manifest.block_hash.IsNull() && !manifest.blob_hash.IsNull() &&
           manifest.total_size > 0 && manifest.total_size <= MAX_SHADOW_STATE_MARKER_BYTES &&
           manifest.shard_count == BlobShardCount(manifest.total_size);
}

bool HashActiveSignalState(bool present, uint32_t marker_height, uint32_t marker_time,
                           const uint256& marker_hash,
                           const std::map<CScript, ShadowActiveSignal>& active,
                           uint256& hash_out)
{
    valtype encoded;
    if (present && marker_hash.IsNull()) return false;
    if (!present && !marker_hash.IsNull()) return false;
    if (!EncodeActiveSignalSetPayload(active, marker_hash, encoded)) return false;
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal State v1")
       << present << marker_height << marker_time << marker_hash << encoded;
    hash_out = ss.GetHash();
    return true;
}

bool EncodeActiveSignalUndo(const ShadowActiveSignalUndo& undo, valtype& out)
{
    if (undo.previous_entries.size() > std::numeric_limits<uint32_t>::max()) return false;
    static constexpr size_t HEADER_SIZE = 2 + 2 * sizeof(uint32_t) + 5 * uint256::size() + sizeof(uint32_t);
    out.assign(HEADER_SIZE, 0);
    size_t cursor = 0;
    out[cursor++] = 1;
    out[cursor++] = undo.state_was_present ? 1 : 0;
    WriteLE32(out.data() + cursor, undo.previous_marker_height);
    cursor += sizeof(uint32_t);
    WriteLE32(out.data() + cursor, undo.previous_marker_time);
    cursor += sizeof(uint32_t);
    for (const uint256* hash : {&undo.previous_marker_hash, &undo.block_hash, &undo.previous_block_hash,
                                &undo.pre_state_hash, &undo.post_state_hash}) {
        std::copy(hash->begin(), hash->end(), out.begin() + cursor);
        cursor += uint256::size();
    }
    WriteLE32(out.data() + cursor, static_cast<uint32_t>(undo.previous_entries.size()));

    for (const auto& [target, previous] : undo.previous_entries) {
        if (target.empty() || target.IsUnspendable() ||
            target.size() > std::numeric_limits<uint16_t>::max()) return false;
        size_t entry_size = sizeof(uint16_t) + target.size() + 1;
        if (previous) {
            if (previous->target != target || !IsDirectQuantumMigrationScript(previous->payout_script) ||
                previous->payout_script.size() > std::numeric_limits<uint16_t>::max()) return false;
            entry_size += sizeof(uint32_t) + sizeof(uint16_t) + previous->payout_script.size();
        }
        const size_t old_size = out.size();
        if (entry_size > MAX_SHADOW_STATE_MARKER_BYTES - old_size) return false;
        out.resize(old_size + entry_size);
        unsigned char* write = out.data() + old_size;
        WriteLE16(write, static_cast<uint16_t>(target.size()));
        write += sizeof(uint16_t);
        write = std::copy(target.begin(), target.end(), write);
        *write++ = previous ? 1 : 0;
        if (previous) {
            WriteLE32(write, previous->last_signal_height);
            write += sizeof(uint32_t);
            WriteLE16(write, static_cast<uint16_t>(previous->payout_script.size()));
            write += sizeof(uint16_t);
            std::copy(previous->payout_script.begin(), previous->payout_script.end(), write);
        }
    }
    return true;
}

bool DecodeActiveSignalUndoPayload(const valtype& payload, ShadowActiveSignalUndo& undo,
                                   uint32_t max_entries = std::numeric_limits<uint32_t>::max())
{
    undo = {};
    static constexpr size_t HEADER_SIZE = 2 + 2 * sizeof(uint32_t) + 5 * uint256::size() + sizeof(uint32_t);
    if (payload.size() < HEADER_SIZE || payload.size() > MAX_SHADOW_STATE_MARKER_BYTES || payload[0] != 1 ||
        payload[1] > 1) return false;
    size_t cursor = 2;
    undo.state_was_present = payload[1] != 0;
    undo.previous_marker_height = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    undo.previous_marker_time = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    for (uint256* hash : {&undo.previous_marker_hash, &undo.block_hash, &undo.previous_block_hash,
                          &undo.pre_state_hash, &undo.post_state_hash}) {
        std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), hash->begin());
        cursor += uint256::size();
    }
    const uint32_t count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    if (count > max_entries) return false;
    static constexpr size_t MIN_ENTRY_SIZE = sizeof(uint16_t) + 1 + 1;
    if (count > (payload.size() - cursor) / MIN_ENTRY_SIZE) return false;
    for (uint32_t i = 0; i < count; ++i) {
        if (cursor + sizeof(uint16_t) > payload.size()) return false;
        const size_t target_size = ReadLE16(payload.data() + cursor);
        cursor += sizeof(uint16_t);
        if (target_size == 0 || cursor + target_size + 1 > payload.size()) return false;
        CScript target(payload.begin() + cursor, payload.begin() + cursor + target_size);
        cursor += target_size;
        if (target.IsUnspendable()) return false;
        const unsigned char has_previous = payload[cursor++];
        if (has_previous > 1) return false;
        std::optional<ShadowActiveSignal> previous;
        if (has_previous) {
            if (cursor + sizeof(uint32_t) + sizeof(uint16_t) > payload.size()) return false;
            const uint32_t last_height = ReadLE32(payload.data() + cursor);
            cursor += sizeof(uint32_t);
            const size_t payout_size = ReadLE16(payload.data() + cursor);
            cursor += sizeof(uint16_t);
            if (payout_size == 0 || cursor + payout_size > payload.size()) return false;
            CScript payout(payload.begin() + cursor, payload.begin() + cursor + payout_size);
            cursor += payout_size;
            if (!IsDirectQuantumMigrationScript(payout)) return false;
            previous = ShadowActiveSignal{target, payout, last_height};
        }
        if (!undo.previous_entries.emplace(target, std::move(previous)).second) return false;
    }
    if (cursor != payload.size()) return false;
    if (!undo.state_was_present && (undo.previous_marker_height != 0 || undo.previous_marker_time != 0 ||
                                    !undo.previous_marker_hash.IsNull())) return false;
    if (undo.state_was_present && undo.previous_marker_hash.IsNull()) return false;
    return true;
}

uint256 ActiveSignalStateCoinCommitment(const CCoinsViewCache& view)
{
    Coin coin;
    const bool present = view.GetCoin(ActiveSignalSetOutpoint(), coin) && !coin.IsSpent();
    CHashWriter ss;
    ss << std::string("Quantum Quasar Active Signal Coin Commitment v1") << present;
    if (present) {
        ss << coin.nHeight << coin.nTime << coin.out.scriptPubKey;
    }
    return ss.GetHash();
}

uint256 ShadowPoolCoinCommitment(const CCoinsViewCache& view)
{
    Coin coin;
    const bool present = view.GetCoin(PoolOutpoint(), coin) && !coin.IsSpent();
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Pool Coin Commitment v1") << present;
    if (present) {
        ss << coin.nHeight << coin.nTime << coin.out.scriptPubKey;
    }
    return ss.GetHash();
}

uint256 WhitelistStateCommitment(const CCoinsViewCache& view)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Whitelist State Commitment v1");
    for (const COutPoint& outpoint : {WhitelistReadyOutpoint(), WhitelistManifestOutpoint()}) {
        Coin coin;
        const bool present = view.GetCoin(outpoint, coin) && !coin.IsSpent();
        ss << present;
        if (present) ss << coin.nHeight << coin.nTime << coin.out.scriptPubKey;
    }
    return ss.GetHash();
}

uint256 DemurrageScheduleCommitment(const Consensus::Params& consensus)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Schedule Commitment v1")
       << consensus.nDemurrageActivationHeight
       << consensus.nDemurrageMinActivationHeight
       << consensus.nDemurrageBlocksPerMonth
       << static_cast<uint32_t>(consensus.m_demurrage_exempt_scripts.size());
    for (const CScript& script : consensus.m_demurrage_exempt_scripts) ss << script;
    return ss.GetHash();
}

valtype ReplayStateFingerprint(const Consensus::Params& consensus, const CBlockIndex* pindex,
                               const CCoinsViewCache& view)
{
    if (!pindex) return {};
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Replay State v4")
       << SHADOW_REPLAY_STATE_VERSION
       << SHADOW_WHITELIST_HEIGHT
       << SHADOW_REWARD_START_HEIGHT
       << SHADOW_REWARD_END_HEIGHT
       << SHADOW_HALVING_INTERVAL_BLOCKS
       << consensus.nProtocolV4Time
       << consensus.nGoldRushEndTime
       << consensus.nQuantumMigrationDeadlineTime
       << consensus.nQuantumLifecycleStartHeight
       << consensus.nGoldRushEndHeight
       << consensus.nQuantumMigrationEndHeight
       << consensus.nShadowCompetingClaimsActivationHeight
       << DemurrageScheduleCommitment(consensus)
       << pindex->nHeight
       << pindex->GetBlockHash()
       << ActiveSignalStateCoinCommitment(view)
       << ShadowPoolCoinCommitment(view)
       << WhitelistStateCommitment(view)
       << GoldRushInventoryCoinCommitment(view)
       << Consensus::DemurrageInventoryCoinCommitment(view);
    const uint256 hash = ss.GetHash();
    return valtype(hash.begin(), hash.end());
}

valtype EncodePool(const ShadowPoolState& pool)
{
    valtype out(POOL_V2_SIZE);
    WriteLE64(out.data(), static_cast<uint64_t>(pool.pow_amount));
    WriteLE64(out.data() + 8, static_cast<uint64_t>(pool.pos_amount));
    WriteLE32(out.data() + 16, pool.pow_count);
    WriteLE32(out.data() + 20, pool.pos_count);
    WriteLE32(out.data() + 24, pool.last_pow_height);
    WriteLE32(out.data() + 28, pool.last_pos_height);
    out[32] = pool.recent_count;
    WriteLE64(out.data() + 33, pool.recent_modes);
    WriteLE64(out.data() + 41, static_cast<uint64_t>(pool.claimed_amount));
    return out;
}

enum class ShadowPoolReadResult {
    MISSING,
    VALID,
    INVALID,
};

bool ShadowObligationWithinCap(const ShadowPoolState& pool);

ShadowPoolReadResult DecodePoolCoin(const Coin& coin, ShadowPoolState& pool)
{
    pool = {};
    if (coin.IsSpent()) return ShadowPoolReadResult::MISSING;
    if (coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        SHADOW_REWARD_START_HEIGHT < 0 ||
        SHADOW_REWARD_END_HEIGHT < SHADOW_REWARD_START_HEIGHT ||
        coin.nHeight < static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) ||
        coin.nHeight > static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) ||
        coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE) {
        return ShadowPoolReadResult::INVALID;
    }
    valtype payload;
    if (!ParseMarkerScript(coin.out.scriptPubKey, MARKER_POOL, &payload)) return ShadowPoolReadResult::INVALID;
    if (payload.size() != POOL_LEGACY_SIZE && payload.size() != POOL_V1_SIZE && payload.size() != POOL_V2_SIZE) {
        return ShadowPoolReadResult::INVALID;
    }
    if (payload.size() == POOL_LEGACY_SIZE) {
        const uint64_t amount = ReadLE64(payload.data());
        if (amount > static_cast<uint64_t>(MAX_MONEY)) return ShadowPoolReadResult::INVALID;
        pool.pow_amount = static_cast<CAmount>(amount / 2);
        pool.pos_amount = static_cast<CAmount>(amount - amount / 2);
        pool.pow_count = ReadLE32(payload.data() + 8);
        pool.pos_count = ReadLE32(payload.data() + 12);
    } else {
        const uint64_t pow_amount = ReadLE64(payload.data());
        const uint64_t pos_amount = ReadLE64(payload.data() + 8);
        if (pow_amount > static_cast<uint64_t>(MAX_MONEY) ||
            pos_amount > static_cast<uint64_t>(MAX_MONEY)) return ShadowPoolReadResult::INVALID;
        pool.pow_amount = static_cast<CAmount>(pow_amount);
        pool.pos_amount = static_cast<CAmount>(pos_amount);
        pool.pow_count = ReadLE32(payload.data() + 16);
        pool.pos_count = ReadLE32(payload.data() + 20);
        pool.last_pow_height = ReadLE32(payload.data() + 24);
        pool.last_pos_height = ReadLE32(payload.data() + 28);
        if (payload[32] > SHADOW_RETARGET_WINDOW) return ShadowPoolReadResult::INVALID;
        pool.recent_count = payload[32];
        pool.recent_modes = ReadLE64(payload.data() + 33);
        if (pool.recent_count < SHADOW_RETARGET_WINDOW) {
            const uint64_t mask = pool.recent_count == 0 ? 0 : (uint64_t{1} << pool.recent_count) - 1;
            if ((pool.recent_modes & ~mask) != 0) return ShadowPoolReadResult::INVALID;
        }
        if (payload.size() == POOL_V2_SIZE) {
            const uint64_t claimed_amount = ReadLE64(payload.data() + 41);
            if (claimed_amount > static_cast<uint64_t>(MAX_MONEY)) return ShadowPoolReadResult::INVALID;
            pool.claimed_amount = static_cast<CAmount>(claimed_amount);
        }
    }
    if (pool.last_pow_height > coin.nHeight || pool.last_pos_height > coin.nHeight ||
        !ShadowObligationWithinCap(pool)) return ShadowPoolReadResult::INVALID;
    return ShadowPoolReadResult::VALID;
}

ShadowPoolReadResult ReadPoolState(const CCoinsViewCache& view, ShadowPoolState& pool)
{
    Coin coin;
    if (!view.GetCoin(PoolOutpoint(), coin) || coin.IsSpent()) {
        pool = {};
        return ShadowPoolReadResult::MISSING;
    }
    return DecodePoolCoin(coin, pool);
}

ShadowPoolState ReadPool(const CCoinsViewCache& view, bool* state_valid = nullptr)
{
    ShadowPoolState pool;
    const ShadowPoolReadResult result = ReadPoolState(view, pool);
    if (state_valid) *state_valid = result != ShadowPoolReadResult::INVALID;
    return pool;
}

void WritePool(CCoinsViewCache& view, const CBlockIndex* pindex, const ShadowPoolState& pool)
{
    const COutPoint outpoint = PoolOutpoint();
    if (view.HaveCoin(outpoint)) view.SpendCoin(outpoint);
    if (pool.pow_amount == 0 && pool.pos_amount == 0 && pool.claimed_amount == 0 &&
        pool.pow_count == 0 && pool.pos_count == 0) return;

    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_POOL, EncodePool(pool));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(outpoint, std::move(coin), true);
}

bool ShadowObligationWithinCap(const ShadowPoolState& pool)
{
    const auto claimed_plus_pow = CheckedAddMoney(pool.claimed_amount, pool.pow_amount);
    if (!claimed_plus_pow) return false;
    const auto total = CheckedAddMoney(*claimed_plus_pow, pool.pos_amount);
    return total && *total <= SHADOW_MAX_EMISSION;
}

bool HashShadowPoolState(bool present, uint32_t marker_height, uint32_t marker_time,
                         const uint256& marker_hash, const ShadowPoolState& pool,
                         uint256& hash_out)
{
    if (present != !marker_hash.IsNull()) return false;
    CHashWriter ss;
    ss << std::string("Quantum Quasar Shadow Pool State v1")
       << present << marker_height << marker_time << marker_hash << EncodePool(pool);
    hash_out = ss.GetHash();
    return true;
}

valtype EncodePoolUndo(const ShadowPoolUndoState& undo)
{
    static constexpr size_t SIZE = 2 + 3 * sizeof(uint32_t) + 6 * uint256::size() + POOL_V2_SIZE;
    valtype payload(SIZE, 0);
    size_t cursor = 0;
    payload[cursor++] = 1;
    payload[cursor++] = undo.previous_present ? 1 : 0;
    WriteLE32(payload.data() + cursor, undo.previous_height);
    cursor += sizeof(uint32_t);
    WriteLE32(payload.data() + cursor, undo.previous_time);
    cursor += sizeof(uint32_t);
    for (const uint256* hash : {&undo.previous_marker_hash, &undo.block_hash,
                                &undo.previous_block_hash, &undo.pre_state_hash,
                                &undo.post_state_hash, &undo.claims_hash}) {
        std::copy(hash->begin(), hash->end(), payload.begin() + cursor);
        cursor += uint256::size();
    }
    WriteLE32(payload.data() + cursor, undo.claim_count);
    cursor += sizeof(uint32_t);
    const valtype pool_payload = EncodePool(undo.previous);
    std::copy(pool_payload.begin(), pool_payload.end(), payload.begin() + cursor);
    return payload;
}

bool DecodePoolUndo(const CScript& script, ShadowPoolUndoState& undo)
{
    undo = {};
    valtype payload;
    static constexpr size_t SIZE = 2 + 3 * sizeof(uint32_t) + 6 * uint256::size() + POOL_V2_SIZE;
    if (!ParseMarkerScript(script, MARKER_POOL_UNDO, &payload) ||
        payload.size() != SIZE || payload[0] != 1 || payload[1] > 1) return false;
    size_t cursor = 2;
    undo.previous_present = payload[1] != 0;
    undo.previous_height = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    undo.previous_time = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    for (uint256* hash : {&undo.previous_marker_hash, &undo.block_hash,
                          &undo.previous_block_hash, &undo.pre_state_hash,
                          &undo.post_state_hash, &undo.claims_hash}) {
        std::copy(payload.begin() + cursor, payload.begin() + cursor + uint256::size(), hash->begin());
        cursor += uint256::size();
    }
    undo.claim_count = ReadLE32(payload.data() + cursor);
    cursor += sizeof(uint32_t);
    undo.previous.pow_amount = static_cast<CAmount>(ReadLE64(payload.data() + cursor));
    undo.previous.pos_amount = static_cast<CAmount>(ReadLE64(payload.data() + cursor + 8));
    undo.previous.pow_count = ReadLE32(payload.data() + cursor + 16);
    undo.previous.pos_count = ReadLE32(payload.data() + cursor + 20);
    undo.previous.last_pow_height = ReadLE32(payload.data() + cursor + 24);
    undo.previous.last_pos_height = ReadLE32(payload.data() + cursor + 28);
    undo.previous.recent_count = payload[cursor + 32];
    undo.previous.recent_modes = ReadLE64(payload.data() + cursor + 33);
    undo.previous.claimed_amount = static_cast<CAmount>(ReadLE64(payload.data() + cursor + 41));
    if (!MoneyRange(undo.previous.pow_amount) || !MoneyRange(undo.previous.pos_amount) ||
        !MoneyRange(undo.previous.claimed_amount) ||
        undo.previous.recent_count > SHADOW_RETARGET_WINDOW ||
        !ShadowObligationWithinCap(undo.previous) ||
        undo.claim_count > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK || undo.claims_hash.IsNull()) return false;
    if (!undo.previous_present) {
        if (undo.previous_height != 0 || undo.previous_time != 0 ||
            !undo.previous_marker_hash.IsNull()) return false;
        const ShadowPoolState zero;
        if (EncodePool(undo.previous) != EncodePool(zero)) return false;
    } else if (undo.previous_marker_hash.IsNull()) {
        return false;
    }
    return true;
}

bool AddPoolUndoMarker(CCoinsViewCache& view, const CBlockIndex* pindex,
                       bool previous_present, const Coin& previous_coin,
                       const ShadowPoolState& previous, const ShadowPoolState& post,
                       const std::vector<ShadowClaim>& claims)
{
    if (!pindex) return false;
    ShadowPoolUndoState undo;
    undo.previous_present = previous_present;
    undo.previous_height = previous_present ? previous_coin.nHeight : 0;
    undo.previous_time = previous_present ? previous_coin.nTime : 0;
    if (previous_present) {
        if (!pindex->pprev || previous_coin.nHeight > static_cast<uint32_t>(pindex->pprev->nHeight)) return false;
        const CBlockIndex* marker_block = SafeGetAncestor(pindex->pprev, previous_coin.nHeight);
        if (!marker_block || previous_coin.nTime != static_cast<uint32_t>(marker_block->GetBlockTime())) return false;
        undo.previous_marker_hash = marker_block->GetBlockHash();
    }
    undo.block_hash = pindex->GetBlockHash();
    undo.previous_block_hash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{};
    undo.previous = previous;
    if (claims.size() > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK) return false;
    undo.claim_count = static_cast<uint32_t>(claims.size());
    undo.claims_hash = HashBlockClaims(pindex, claims);
    if (!HashShadowPoolState(previous_present, undo.previous_height, undo.previous_time,
                             undo.previous_marker_hash, previous, undo.pre_state_hash) ||
        !HashShadowPoolState(true, pindex->nHeight, pindex->GetBlockTime(),
                             pindex->GetBlockHash(), post, undo.post_state_hash)) return false;
    const COutPoint outpoint = PoolUndoOutpoint(pindex);
    if (view.HaveCoin(outpoint)) return false;
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_POOL_UNDO, EncodePoolUndo(undo));
    if (coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(outpoint, std::move(coin), true);
    return true;
}

bool AddClaimedAmount(ShadowPoolState& pool, CAmount amount)
{
    if (amount <= 0 || !MoneyRange(amount)) return false;
    const auto next = CheckedAddMoney(pool.claimed_amount, amount);
    if (!next || *next > SHADOW_MAX_EMISSION) return false;
    pool.claimed_amount = *next;
    return true;
}


valtype EncodeClaim(const ShadowClaim& claim)
{
    const valtype undo_pool = EncodePool(claim.undo_pool);
    valtype out;
    out.reserve(CLAIM_MAGIC_V2.size() + 8 + 1 + undo_pool.size() + 2 + claim.target.size());
    out.insert(out.end(), CLAIM_MAGIC_V2.begin(), CLAIM_MAGIC_V2.end());
    const valtype amount = EncodeAmount(claim.amount);
    out.insert(out.end(), amount.begin(), amount.end());
    out.push_back(static_cast<unsigned char>(claim.mode));
    out.insert(out.end(), undo_pool.begin(), undo_pool.end());
    const uint16_t target_size = static_cast<uint16_t>(claim.target.size());
    out.push_back(static_cast<unsigned char>(target_size & 0xff));
    out.push_back(static_cast<unsigned char>(target_size >> 8));
    out.insert(out.end(), claim.target.begin(), claim.target.end());
    return out;
}

valtype EncodeClaimMarkerPayload(const CBlockIndex* pindex, uint32_t marker_index,
                                 const ShadowClaim& claim)
{
    if (!pindex) return {};
    valtype payload;
    const valtype encoded_claim = EncodeClaim(claim);
    payload.reserve(CLAIM_MARKER_MAGIC_V3.size() + sizeof(uint32_t) + uint256::size() +
                    sizeof(uint32_t) + encoded_claim.size());
    payload.insert(payload.end(), CLAIM_MARKER_MAGIC_V3.begin(), CLAIM_MARKER_MAGIC_V3.end());
    const size_t height_offset = payload.size();
    payload.resize(payload.size() + sizeof(uint32_t));
    WriteLE32(payload.data() + height_offset, static_cast<uint32_t>(pindex->nHeight));
    const uint256 origin_hash = pindex->GetBlockHash();
    payload.insert(payload.end(), origin_hash.begin(), origin_hash.end());
    const size_t index_offset = payload.size();
    payload.resize(payload.size() + sizeof(uint32_t));
    WriteLE32(payload.data() + index_offset, marker_index);
    payload.insert(payload.end(), encoded_claim.begin(), encoded_claim.end());
    return payload;
}

bool DecodeClaimMarkerEnvelope(const valtype& marker_payload, uint32_t& origin_height,
                               uint256& origin_hash, uint32_t& marker_index,
                               valtype& claim_payload)
{
    static constexpr size_t HEADER_SIZE = 4 + sizeof(uint32_t) + uint256::size() + sizeof(uint32_t);
    if (marker_payload.size() <= HEADER_SIZE ||
        !std::equal(CLAIM_MARKER_MAGIC_V3.begin(), CLAIM_MARKER_MAGIC_V3.end(),
                    marker_payload.begin())) return false;
    size_t cursor = CLAIM_MARKER_MAGIC_V3.size();
    origin_height = ReadLE32(marker_payload.data() + cursor);
    cursor += sizeof(uint32_t);
    std::copy(marker_payload.begin() + cursor,
              marker_payload.begin() + cursor + uint256::size(), origin_hash.begin());
    cursor += uint256::size();
    marker_index = ReadLE32(marker_payload.data() + cursor);
    cursor += sizeof(uint32_t);
    claim_payload.assign(marker_payload.begin() + cursor, marker_payload.end());
    return origin_height >= static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) &&
           origin_height <= static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) &&
           marker_index < MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK && !origin_hash.IsNull();
}

uint256 HashBlockClaims(int height, const uint256& block_hash,
                        const std::vector<ShadowClaim>& claims)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Block Claim Set v1")
       << height << block_hash
       << static_cast<uint32_t>(claims.size());
    for (const ShadowClaim& claim : claims) ss << EncodeClaim(claim);
    return ss.GetHash();
}

uint256 HashBlockClaims(const CBlockIndex* pindex,
                        const std::vector<ShadowClaim>& claims)
{
    return HashBlockClaims(pindex ? pindex->nHeight : 0,
                           pindex ? pindex->GetBlockHash() : uint256{},
                           claims);
}

uint256 HashGoldRushClaim(const ShadowClaim& claim)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Gold Rush Claim v2") << EncodeClaim(claim);
    return ss.GetHash();
}

std::optional<ShadowClaim> DecodeClaimPayloadV1(const valtype& payload)
{
    if (payload.size() < 9 + POOL_V1_SIZE + 1) return std::nullopt;
    auto amount = DecodeAmount(payload);
    if (!amount) return std::nullopt;
    const auto mode = static_cast<ShadowProofMode>(payload[8]);
    if (mode != ShadowProofMode::POW && mode != ShadowProofMode::POS) return std::nullopt;
    ShadowPoolState undo_pool;
    const uint64_t undo_pow_amount = ReadLE64(payload.data() + 9);
    const uint64_t undo_pos_amount = ReadLE64(payload.data() + 17);
    if (undo_pow_amount > static_cast<uint64_t>(MAX_MONEY) || undo_pos_amount > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    undo_pool.pow_amount = static_cast<CAmount>(undo_pow_amount);
    undo_pool.pos_amount = static_cast<CAmount>(undo_pos_amount);
    undo_pool.pow_count = ReadLE32(payload.data() + 25);
    undo_pool.pos_count = ReadLE32(payload.data() + 29);
    undo_pool.last_pow_height = ReadLE32(payload.data() + 33);
    undo_pool.last_pos_height = ReadLE32(payload.data() + 37);
    undo_pool.recent_count = std::min<uint8_t>(payload[41], SHADOW_RETARGET_WINDOW);
    undo_pool.recent_modes = ReadLE64(payload.data() + 42);
    if (undo_pool.recent_count < SHADOW_RETARGET_WINDOW) {
        undo_pool.recent_modes &= (uint64_t{1} << undo_pool.recent_count) - 1;
    }
    CScript target(payload.begin() + 9 + POOL_V1_SIZE, payload.end());
    if (target.empty() || target.IsUnspendable()) return std::nullopt;
    return ShadowClaim{target, *amount, mode, undo_pool, true};
}

std::optional<ShadowClaim> DecodeClaimScript(const CScript& script)
{
    valtype payload;
    if (!ParseMarkerScript(script, MARKER_DIRECT_CLAIM, &payload)) return std::nullopt;
    uint32_t envelope_height{0};
    uint256 envelope_hash;
    uint32_t envelope_index{0};
    valtype enclosed_claim;
    if (DecodeClaimMarkerEnvelope(payload, envelope_height, envelope_hash,
                                  envelope_index, enclosed_claim)) {
        payload = std::move(enclosed_claim);
    }
    if (payload.size() < CLAIM_MAGIC_V2.size() ||
        !std::equal(CLAIM_MAGIC_V2.begin(), CLAIM_MAGIC_V2.end(), payload.begin())) {
        return DecodeClaimPayloadV1(payload);
    }

    size_t cursor = CLAIM_MAGIC_V2.size();
    if (payload.size() < cursor + 8 + 1 + POOL_V2_SIZE + 2 + 1) return std::nullopt;
    auto amount = DecodeAmount(valtype(payload.begin() + cursor, payload.begin() + cursor + 8));
    if (!amount) return std::nullopt;
    cursor += 8;
    const auto mode = static_cast<ShadowProofMode>(payload[cursor++]);
    if (mode != ShadowProofMode::POW && mode != ShadowProofMode::POS) return std::nullopt;
    ShadowPoolState undo_pool;
    const unsigned char* pool_data = payload.data() + cursor;
    const uint64_t undo_pow_amount = ReadLE64(pool_data);
    const uint64_t undo_pos_amount = ReadLE64(pool_data + 8);
    const uint64_t undo_claimed_amount = ReadLE64(pool_data + 41);
    if (undo_pow_amount > static_cast<uint64_t>(MAX_MONEY) ||
        undo_pos_amount > static_cast<uint64_t>(MAX_MONEY) ||
        undo_claimed_amount > static_cast<uint64_t>(MAX_MONEY)) return std::nullopt;
    undo_pool.pow_amount = static_cast<CAmount>(undo_pow_amount);
    undo_pool.pos_amount = static_cast<CAmount>(undo_pos_amount);
    undo_pool.claimed_amount = static_cast<CAmount>(undo_claimed_amount);
    undo_pool.pow_count = ReadLE32(pool_data + 16);
    undo_pool.pos_count = ReadLE32(pool_data + 20);
    undo_pool.last_pow_height = ReadLE32(pool_data + 24);
    undo_pool.last_pos_height = ReadLE32(pool_data + 28);
    undo_pool.recent_count = std::min<uint8_t>(pool_data[32], SHADOW_RETARGET_WINDOW);
    undo_pool.recent_modes = ReadLE64(pool_data + 33);
    if (undo_pool.recent_count < SHADOW_RETARGET_WINDOW) {
        undo_pool.recent_modes &= (uint64_t{1} << undo_pool.recent_count) - 1;
    }
    cursor += POOL_V2_SIZE;
    const size_t target_size = ReadLE16(payload.data() + cursor);
    cursor += 2;
    if (target_size == 0 || cursor + target_size != payload.size()) return std::nullopt;
    CScript target(payload.begin() + cursor, payload.end());
    if (target.empty() || target.IsUnspendable()) return std::nullopt;
    return ShadowClaim{target, *amount, mode, undo_pool, true};
}

unsigned int RetargetedBits(ShadowProofMode mode, const ShadowPoolState& pool, int height)
{
    if (mode != ShadowProofMode::POW || height <= SHADOW_REWARD_START_HEIGHT) {
        return BASE_SHADOW_TARGET_BITS;
    }

    // Shadow PoW can be claimed at most once per block. Use block height as the
    // 64-second ASERT clock and relax difficulty by one leading-zero bit for
    // each half-life of missed PoW claims.
    const int anchor_height = pool.last_pow_height != 0
        ? static_cast<int>(pool.last_pow_height)
        : SHADOW_REWARD_START_HEIGHT - SHADOW_POW_TARGET_SPACING_BLOCKS;
    const int actual_spacing = std::max(0, height - anchor_height);
    const int drift = actual_spacing - SHADOW_POW_TARGET_SPACING_BLOCKS;
    const int rounded_half_lives = std::max(0, (drift + SHADOW_POW_ASERT_HALF_LIFE_BLOCKS / 2) / SHADOW_POW_ASERT_HALF_LIFE_BLOCKS);
    const int bits = static_cast<int>(BASE_SHADOW_TARGET_BITS) - rounded_half_lives;
    return static_cast<unsigned int>(std::clamp(bits, static_cast<int>(MIN_SHADOW_TARGET_BITS), static_cast<int>(MAX_SHADOW_TARGET_BITS)));
}

bool HashMeetsLeadingZeroBits(const uint256& hash, unsigned int bits)
{
    const unsigned char* data = hash.data();
    while (bits >= 8) {
        if (*data++ != 0) return false;
        bits -= 8;
    }
    if (bits == 0) return true;
    // Integer promotion makes the shift operate on unsigned int. Narrow the
    // result explicitly after the shift so sanitizer builds do not treat the
    // intentional low-byte mask as an implicit signed truncation.
    const unsigned char mask = static_cast<unsigned char>(0xffU << (8U - bits));
    return (*data & mask) == 0;
}

bool DecodeProof(const valtype& proof, ShadowProof& decoded)
{
    if (proof.size() < PROOF_SIZE) return false;
    decoded = {};
    decoded.mode = static_cast<ShadowProofMode>(proof[4]);
    if (decoded.mode != ShadowProofMode::POW && decoded.mode != ShadowProofMode::POS) return false;
    decoded.nonce = ReadLE64(proof.data() + 5);

    if (std::equal(PROOF_MAGIC_V1.begin(), PROOF_MAGIC_V1.end(), proof.begin())) {
        decoded.target = CScript(proof.begin() + PROOF_SIZE, proof.end());
        decoded.payout_script = decoded.target;
        decoded.quantum_linked = false;
    } else if (std::equal(PROOF_MAGIC_V2.begin(), PROOF_MAGIC_V2.end(), proof.begin()) ||
               std::equal(PROOF_MAGIC_V3.begin(), PROOF_MAGIC_V3.end(), proof.begin())) {
        const bool origin_bound = std::equal(
            PROOF_MAGIC_V3.begin(), PROOF_MAGIC_V3.end(), proof.begin());
        const size_t script_header = PROOF_SIZE +
            (origin_bound ? PROOF_V3_ORIGIN_SIZE : 0);
        if (proof.size() < script_header + 4) return false;
        if (origin_bound) {
            decoded.origin_bound = true;
            decoded.origin_height = ReadLE32(proof.data() + PROOF_SIZE);
            std::copy(proof.begin() + PROOF_SIZE + sizeof(uint32_t),
                      proof.begin() + PROOF_SIZE + PROOF_V3_ORIGIN_SIZE,
                      decoded.origin_previous_block_hash.begin());
            if (decoded.origin_height == 0 ||
                decoded.origin_previous_block_hash.IsNull()) return false;
        }
        const size_t target_size = ReadLE16(proof.data() + script_header);
        size_t cursor = script_header + 2;
        if (target_size == 0 || cursor + target_size + 2 > proof.size()) return false;
        decoded.target = CScript(proof.begin() + cursor, proof.begin() + cursor + target_size);
        cursor += target_size;
        const size_t payout_size = ReadLE16(proof.data() + cursor);
        cursor += 2;
        if (payout_size == 0 || cursor + payout_size != proof.size()) return false;
        decoded.payout_script = CScript(proof.begin() + cursor, proof.end());
        decoded.quantum_linked = true;
        if (!IsDirectQuantumMigrationScript(decoded.payout_script)) return false;
    } else {
        return false;
    }

    return !decoded.target.empty() && !decoded.target.IsUnspendable() &&
           !decoded.payout_script.empty() && !decoded.payout_script.IsUnspendable();
}

bool ComputeShadowProofHash(const CScript& target, const CScript& payout_script, int height, const uint256& prev_hash, ShadowProofMode mode, uint64_t nonce, uint256& result)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar QQPROOF POW Argon2id v1");
    ss << static_cast<unsigned char>(mode);
    ss << nonce;
    ss << height;
    ss << prev_hash;
    ss << target;
    ss << payout_script;
    const uint256 prehash = ss.GetHash();

    std::array<unsigned char, 80> input{};
    auto out = input.begin();
    out = std::copy(prehash.begin(), prehash.end(), out);
    out = std::copy(prev_hash.begin(), prev_hash.end(), out);
    WriteLE32(&*out, static_cast<uint32_t>(height));
    out += 4;
    WriteLE64(&*out, nonce);
    out += 8;
    *out++ = static_cast<unsigned char>(mode);
    *out++ = 'Q';
    *out++ = 'Q';
    *out++ = 'A';

    std::array<unsigned char, 16> salt{};
    std::copy(prev_hash.begin(), prev_hash.begin() + salt.size(), salt.begin());

    uint64_t remaining = g_shadow_argon2_test_failures.load(std::memory_order_relaxed);
    while (remaining != 0 &&
           !g_shadow_argon2_test_failures.compare_exchange_weak(
               remaining, remaining - 1, std::memory_order_relaxed)) {
    }
    if (remaining != 0) {
        result.SetNull();
        return false;
    }

    const int rc = argon2id_hash_raw(
        SHADOW_ARGON2_TIME_COST,
        SHADOW_ARGON2_MEMORY_KIB,
        SHADOW_ARGON2_LANES,
        input.data(),
        input.size(),
        salt.data(),
        salt.size(),
        result.begin(),
        result.size());
    if (rc != ARGON2_OK) {
        LogPrintf("ERROR: Quantum Quasar Argon2id shadow proof evaluation failed: %s\n", argon2_error_message(rc));
        result.SetNull();
        return false;
    }
    return true;
}

valtype EncodeProofPayloadV2(ShadowProofMode mode, uint64_t nonce, const CScript& target, const CScript& quantum_payout_script)
{
    valtype proof(PROOF_SIZE + 4 + target.size() + quantum_payout_script.size());
    std::copy(PROOF_MAGIC_V2.begin(), PROOF_MAGIC_V2.end(), proof.begin());
    proof[4] = static_cast<unsigned char>(mode);
    WriteLE64(proof.data() + 5, nonce);
    WriteLE16(proof.data() + PROOF_SIZE, static_cast<uint16_t>(target.size()));
    auto cursor = proof.begin() + PROOF_SIZE + 2;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(quantum_payout_script.size()));
    cursor += 2;
    std::copy(quantum_payout_script.begin(), quantum_payout_script.end(), cursor);
    return proof;
}

valtype EncodeProofPayloadV3(ShadowProofMode mode, uint64_t nonce,
                             uint32_t origin_height,
                             const uint256& origin_previous_block_hash,
                             const CScript& target,
                             const CScript& quantum_payout_script)
{
    valtype proof(PROOF_SIZE + PROOF_V3_ORIGIN_SIZE + 4 + target.size() +
                  quantum_payout_script.size());
    std::copy(PROOF_MAGIC_V3.begin(), PROOF_MAGIC_V3.end(), proof.begin());
    proof[4] = static_cast<unsigned char>(mode);
    WriteLE64(proof.data() + 5, nonce);
    WriteLE32(proof.data() + PROOF_SIZE, origin_height);
    std::copy(origin_previous_block_hash.begin(),
              origin_previous_block_hash.end(),
              proof.begin() + PROOF_SIZE + sizeof(uint32_t));
    const size_t script_header = PROOF_SIZE + PROOF_V3_ORIGIN_SIZE;
    WriteLE16(proof.data() + script_header,
              static_cast<uint16_t>(target.size()));
    auto cursor = proof.begin() + script_header + 2;
    cursor = std::copy(target.begin(), target.end(), cursor);
    WriteLE16(&*cursor, static_cast<uint16_t>(quantum_payout_script.size()));
    cursor += 2;
    std::copy(quantum_payout_script.begin(), quantum_payout_script.end(), cursor);
    return proof;
}

ShadowProofValidationResult ValidateQQProofAtBits(const valtype& proof, int height,
                                                  const uint256& prev_hash,
                                                  unsigned int target_bits,
                                                  ShadowProof& decoded_out,
                                                  unsigned int& proof_evals,
                                                  bool& proof_limit_exceeded)
{
    ShadowProof decoded;
    if (!DecodeProof(proof, decoded)) return ShadowProofValidationResult::INVALID;
    if (decoded.mode != ShadowProofMode::POW) return ShadowProofValidationResult::INVALID;
    if (!decoded.quantum_linked) return ShadowProofValidationResult::INVALID;
    if (decoded.origin_bound &&
        (!Params().GetConsensus().IsShadowCompetingClaimsActive(height) ||
         decoded.origin_height != static_cast<uint32_t>(height) ||
         decoded.origin_previous_block_hash != prev_hash)) {
        return ShadowProofValidationResult::INVALID;
    }
    if (decoded.target.empty() || decoded.target.IsUnspendable()) return ShadowProofValidationResult::INVALID;
    if (IsQuantumMigrationScript(decoded.target) || IsQuantumColdStakeScript(decoded.target) || IsEUTXOScript(decoded.target)) return ShadowProofValidationResult::INVALID;

    if (proof_evals >= MAX_SHADOW_POW_EVALS_PER_BLOCK) {
        proof_limit_exceeded = true;
        return ShadowProofValidationResult::INVALID;
    }
    ++proof_evals;

    uint256 proof_hash;
    if (!ComputeShadowProofHash(decoded.target, decoded.payout_script, height, prev_hash, decoded.mode, decoded.nonce, proof_hash)) {
        return ShadowProofValidationResult::LOCAL_INTERNAL_ERROR;
    }
    if (!HashMeetsLeadingZeroBits(proof_hash, target_bits)) return ShadowProofValidationResult::INVALID;
    decoded_out = std::move(decoded);
    return ShadowProofValidationResult::VALID;
}

ShadowProofValidationResult ValidateQQProofAt(const valtype& proof, int height,
                                              const uint256& prev_hash,
                                              const ShadowPoolState& pool,
                                              ShadowProof& decoded_out,
                                              unsigned int& proof_evals,
                                              bool& proof_limit_exceeded)
{
    return ValidateQQProofAtBits(proof, height, prev_hash,
        RetargetedBits(ShadowProofMode::POW, pool, height), decoded_out,
        proof_evals, proof_limit_exceeded);
}

ShadowProofValidationResult ValidateQQProof(const valtype& proof, const CBlockIndex* pindex, const ShadowPoolState& pool, ShadowProof& decoded_out, unsigned int& proof_evals, bool& proof_limit_exceeded)
{
    if (!pindex) return ShadowProofValidationResult::INVALID;
    return ValidateQQProofAt(proof, pindex->nHeight, pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}, pool, decoded_out, proof_evals, proof_limit_exceeded);
}

void AddPowSolve(ShadowPoolState& pool, int height)
{
    ++pool.pow_count;
    pool.last_pow_height = height;
    pool.recent_modes <<= 1;
    if (pool.recent_count < SHADOW_RETARGET_WINDOW) ++pool.recent_count;
}

void AddPosSolve(ShadowPoolState& pool, int height)
{
    ++pool.pos_count;
    pool.last_pos_height = height;
    pool.recent_modes = (pool.recent_modes << 1) | uint64_t{1};
    if (pool.recent_count < SHADOW_RETARGET_WINDOW) ++pool.recent_count;
}

std::optional<valtype> ExtractPrefixedOpReturnPayload(const CScript& script, const valtype& prefix)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return std::nullopt;
    if (!script.GetOp(pc, opcode, data) || pc != script.end()) return std::nullopt;
    if (data.size() < prefix.size()) return std::nullopt;
    if (!std::equal(prefix.begin(), prefix.end(), data.begin())) return std::nullopt;
    return valtype(data.begin() + prefix.size(), data.end());
}

std::optional<valtype> ExtractProofPayload(const CScript& script)
{
    return ExtractPrefixedOpReturnPayload(script, SHADOW_PREFIX);
}

std::optional<valtype> ExtractSignalPayload(const CScript& script)
{
    return ExtractPrefixedOpReturnPayload(script, SIGNAL_PREFIX);
}

const CScript* GetInputScript(const CBlockUndo* blockundo, size_t tx_index, size_t input_index)
{
    if (!blockundo || tx_index == 0 || blockundo->vtxundo.size() <= tx_index - 1) return nullptr;
    const CTxUndo& txundo = blockundo->vtxundo[tx_index - 1];
    if (txundo.vprevout.size() <= input_index || txundo.vprevout[input_index].IsSpent()) return nullptr;
    return &txundo.vprevout[input_index].out.scriptPubKey;
}

std::optional<CScript> GetCurrentSolverScript(const CCoinsViewCache& view, const CBlock& block, const CBlockUndo* blockundo)
{
    if (!block.IsProofOfStake() || block.vtx.size() < 2 || !block.vtx[1]->IsCoinStake()) return std::nullopt;
    const CScript* stake_input_script = GetInputScript(blockundo, 1, 0);
    if (!stake_input_script) return std::nullopt;
    if (!IsLegacyShadowTargetScript(*stake_input_script)) return std::nullopt;
    const CScript solver_script = CanonicalLegacyStakeScript(*stake_input_script);
    if (!IsWhitelisted(view, solver_script)) return std::nullopt;
    return solver_script;
}

bool TxSpendsFromScript(const CTransaction& tx, size_t tx_index, const CBlockUndo* blockundo, const CScript& script)
{
    const CScript canonical_script = CanonicalLegacyStakeScript(script);
    for (size_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
        const CScript* input_script = GetInputScript(blockundo, tx_index, input_index);
        if (input_script && IsLegacyShadowTargetScript(*input_script) && CanonicalLegacyStakeScript(*input_script) == canonical_script) return true;
    }
    return false;
}

enum class ShadowBaseFeeResult {
    VALID,
    INVALID_TRANSACTION,
    LOCAL_INTERNAL_ERROR,
};

ShadowBaseFeeResult GetShadowClaimBaseFee(const CTransaction& tx, size_t tx_index,
                                          const CBlockUndo* blockundo, CAmount& fee_out)
{
    fee_out = 0;
    if (!blockundo || tx_index == 0 || blockundo->vtxundo.size() <= tx_index - 1) {
        return ShadowBaseFeeResult::LOCAL_INTERNAL_ERROR;
    }
    const CTxUndo& txundo = blockundo->vtxundo[tx_index - 1];
    if (txundo.vprevout.size() != tx.vin.size()) {
        return ShadowBaseFeeResult::LOCAL_INTERNAL_ERROR;
    }

    CAmount value_in{0};
    for (const Coin& coin : txundo.vprevout) {
        if (coin.IsSpent() || !MoneyRange(coin.out.nValue)) {
            return ShadowBaseFeeResult::LOCAL_INTERNAL_ERROR;
        }
        const auto next = CheckedAddMoney(value_in, coin.out.nValue);
        if (!next) return ShadowBaseFeeResult::LOCAL_INTERNAL_ERROR;
        value_in = *next;
    }

    CAmount value_out{0};
    for (const CTxOut& txout : tx.vout) {
        if (!MoneyRange(txout.nValue)) return ShadowBaseFeeResult::INVALID_TRANSACTION;
        const auto next = CheckedAddMoney(value_out, txout.nValue);
        if (!next) return ShadowBaseFeeResult::INVALID_TRANSACTION;
        value_out = *next;
    }
    if (value_in < value_out) return ShadowBaseFeeResult::INVALID_TRANSACTION;
    fee_out = value_in - value_out;
    return MoneyRange(fee_out) ? ShadowBaseFeeResult::VALID
                               : ShadowBaseFeeResult::INVALID_TRANSACTION;
}

bool TxPaysToScript(const CTransaction& tx, const CScript& script)
{
    const CScript canonical_script = CanonicalLegacyStakeScript(script);
    return std::any_of(tx.vout.begin(), tx.vout.end(), [&](const CTxOut& txout) {
        return txout.nValue > 0 &&
               IsLegacyShadowTargetScript(txout.scriptPubKey) &&
               CanonicalLegacyStakeScript(txout.scriptPubKey) == canonical_script;
    });
}

bool SignalReferencesRecentSolve(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash, bool allow_tip_solve = false)
{
    if (!pindex || solve_height == 0 || solve_hash.IsNull()) return false;
    if (solve_height > static_cast<uint32_t>(pindex->nHeight) ||
        (!allow_tip_solve && solve_height == static_cast<uint32_t>(pindex->nHeight))) return false;
    if (pindex->nHeight - static_cast<int>(solve_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) return false;
    const CBlockIndex* solve_block = SafeGetAncestor(pindex, static_cast<int>(solve_height));
    if (!solve_block || solve_block->GetBlockHash() != solve_hash || !IsWhitelisted(view, target)) return false;
    Coin solver_coin;
    if (!view.GetCoin(SolverOutpoint(target, solve_height, solve_hash), solver_coin) || solver_coin.IsSpent() ||
        solver_coin.out.nValue != 0 || !solver_coin.fCoinBase || solver_coin.fCoinStake ||
        solver_coin.nHeight != solve_height ||
        solver_coin.nTime != static_cast<uint32_t>(solve_block->GetBlockTime()) ||
        !SolverMarkerMatches(solver_coin.out.scriptPubKey, target)) return false;
    const int64_t block_time = pindex->GetBlockTime();
    const int64_t solver_time = static_cast<int64_t>(solver_coin.nTime);
    if (solver_time > block_time) return false;
    if (block_time - solver_time > SHADOW_SOLVER_ACTIVITY_SECONDS) return false;
    return true;
}

std::map<CScript, CScript> FindValidShadowSignalsInBlock(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo)
{
    std::map<CScript, CScript> signals;
    std::set<CScript> conflicted_targets;
    for (size_t tx_index = 1; tx_index < block.vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.vtx[tx_index];
        if (tx.IsCoinBase() || tx.IsCoinStake()) continue;
        for (const CTxOut& out : tx.vout) {
            const auto payload = ExtractSignalPayload(out.scriptPubKey);
            if (!payload) continue;
            ShadowSignal signal;
            if (!DecodeSignalPayload(*payload, signal)) continue;
            if (!signal.quantum_linked) continue;
            const CScript target = CanonicalLegacyStakeScript(signal.target);
            if (!IsLegacyShadowTargetScript(target)) continue;
            if (!IsWhitelisted(view, target)) continue;
            if (!TxSpendsFromScript(tx, tx_index, blockundo, target)) continue;

            if (!TxPaysToScript(tx, target)) continue;
            if (SignalReferencesRecentSolve(view, pindex, target, signal.solve_height, signal.solve_hash)) {
                if (conflicted_targets.count(target)) continue;
                const auto [it, inserted] = signals.emplace(target, signal.payout_script);
                if (!inserted && it->second != signal.payout_script) {
                    signals.erase(it);
                    conflicted_targets.insert(target);
                }
            }
        }
    }
    return signals;
}

void UpsertActiveSignals(std::map<CScript, ShadowActiveSignal>& active, const std::map<CScript, CScript>& signals, uint32_t height)
{
    for (const auto& [target, payout_script] : signals) {
        active[target] = ShadowActiveSignal{target, payout_script, height};
    }
}

void FilterActiveSignals(std::map<CScript, ShadowActiveSignal>& active, int evaluation_height)
{
    for (auto it = active.begin(); it != active.end();) {
        if (it->second.last_signal_height > static_cast<uint32_t>(evaluation_height) ||
            evaluation_height - static_cast<int>(it->second.last_signal_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) {
            it = active.erase(it);
        } else {
            ++it;
        }
    }
}

enum class ActiveSignalStateReadResult {
    MISSING,
    VALID,
    INVALID,
};

std::optional<bool> HasAppliedShadowRewardTransition(const Consensus::Params& consensus,
                                                     const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT) return false;
    const int last_height = std::min(pindex->nHeight, SHADOW_REWARD_END_HEIGHT);
    if (last_height < SHADOW_REWARD_START_HEIGHT) return false;

    if (consensus.HasAnyHeightLifecycleBoundary()) {
        if (!consensus.UsesHeightLifecycle() ||
            !consensus.IsQuantumLifecycleScheduleOrdered()) {
            return std::nullopt;
        }
        const int first_active_height = std::max(
            SHADOW_REWARD_START_HEIGHT, consensus.nQuantumLifecycleStartHeight);
        const int last_active_height = std::min(
            last_height, consensus.nGoldRushEndHeight);
        return first_active_height <= last_active_height;
    }

    // Time-only schedules are retained for compatibility tests. MTP is
    // monotonic, so locate the first reward-height block whose parent MTP is
    // past V4, then verify that it did not jump directly beyond Gold Rush.
    int low = SHADOW_REWARD_START_HEIGHT;
    int high = last_height;
    while (low < high) {
        const int middle = low + (high - low) / 2;
        const CBlockIndex* candidate = SafeGetAncestor(pindex, middle);
        if (!candidate) return std::nullopt;
        const int64_t mtp = candidate->pprev
            ? candidate->pprev->GetMedianTimePast()
            : candidate->GetBlockTime();
        if (consensus.IsProtocolV4(mtp)) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    const CBlockIndex* first_v4 = SafeGetAncestor(pindex, low);
    if (!first_v4) return std::nullopt;
    const int64_t first_v4_mtp = first_v4->pprev
        ? first_v4->pprev->GetMedianTimePast()
        : first_v4->GetBlockTime();
    return IsShadowGoldRushRewardActive(consensus, first_v4_mtp, first_v4->nHeight);
}

bool ActiveSignalPoolPairValid(const Consensus::Params& consensus,
                               const CBlockIndex* pindex,
                               ShadowPoolReadResult pool_result,
                               ActiveSignalStateReadResult signal_result)
{
    if (pool_result == ShadowPoolReadResult::INVALID ||
        signal_result == ActiveSignalStateReadResult::INVALID) {
        return false;
    }
    // The first applied Gold Rush reward writes both records in one cache
    // transition. Before that transition both are absent; after it both are
    // present for the rest of the lifecycle. An asymmetric pair is therefore
    // an obsolete or interrupted auxiliary chainstate and must be replayed.
    const bool pool_present = pool_result == ShadowPoolReadResult::VALID;
    const bool signal_present = signal_result == ActiveSignalStateReadResult::VALID;
    const std::optional<bool> transition_applied =
        HasAppliedShadowRewardTransition(consensus, pindex);
    if (!transition_applied) return false;
    return pool_present == signal_present &&
           pool_present == *transition_applied;
}

std::optional<ShadowActiveSignalResourceBounds>
ReadAuthenticatedWhitelistResourceBounds(const CCoinsViewCache& view,
                                          const CBlockIndex* pindex)
{
    Coin coin;
    WhitelistManifest manifest;
    if (!pindex || !view.GetCoin(WhitelistManifestOutpoint(), coin) || coin.IsSpent() ||
        coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.nHeight != static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) ||
        coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeWhitelistManifest(coin.out.scriptPubKey, manifest)) return std::nullopt;
    const CBlockIndex* snapshot_block = SafeGetAncestor(pindex, manifest.snapshot_height);
    if (!snapshot_block || snapshot_block->GetBlockHash() != manifest.snapshot_hash ||
        coin.nTime != static_cast<uint32_t>(snapshot_block->GetBlockTime())) return std::nullopt;
    return GetShadowActiveSignalResourceBounds(manifest.entry_count,
                                               manifest.total_size);
}

std::optional<uint32_t> ReadAuthenticatedWhitelistCount(const CCoinsViewCache& view,
                                                        const CBlockIndex* pindex)
{
    const auto bounds = ReadAuthenticatedWhitelistResourceBounds(view, pindex);
    if (!bounds) return std::nullopt;
    return bounds->whitelist_entries;
}

bool PoolUndoClaimCountWithinBound(const CCoinsViewCache& view,
                                   const CBlockIndex* pindex,
                                   const Consensus::Params& consensus,
                                   const ShadowPoolUndoState& undo)
{
    if (!pindex || undo.claim_count > MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK) {
        return false;
    }
    if (!consensus.IsShadowCompetingClaimsActive(pindex->nHeight)) {
        return true;
    }
    const std::optional<uint32_t> whitelist_count =
        ReadAuthenticatedWhitelistCount(view, pindex);
    return whitelist_count &&
           undo.claim_count <= GetShadowSyntheticClaimLimit(
               consensus, pindex->nHeight, *whitelist_count);
}

std::optional<ShadowPoolUndoState> ReadAuthenticatedPoolUndo(
    const CCoinsViewCache& view, int height, const uint256& block_hash,
    int64_t block_time)
{
    if (height < SHADOW_REWARD_START_HEIGHT ||
        height > SHADOW_REWARD_END_HEIGHT || block_hash.IsNull() ||
        block_time < 0 ||
        static_cast<uint64_t>(block_time) >
            std::numeric_limits<uint32_t>::max()) {
        return std::nullopt;
    }
    Coin coin;
    ShadowPoolUndoState undo;
    if (!view.GetCoin(PoolUndoOutpoint(height, block_hash), coin) ||
        coin.IsSpent() || coin.out.nValue != 0 || !coin.fCoinBase ||
        coin.fCoinStake || coin.nHeight != static_cast<uint32_t>(height) ||
        coin.nTime != static_cast<uint32_t>(block_time) ||
        !DecodePoolUndo(coin.out.scriptPubKey, undo) ||
        undo.block_hash != block_hash) {
        return std::nullopt;
    }
    return undo;
}

std::optional<ShadowPoolUndoState> ReadAuthenticatedPoolUndo(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    const Consensus::Params& consensus)
{
    if (!pindex) return std::nullopt;
    std::optional<ShadowPoolUndoState> undo = ReadAuthenticatedPoolUndo(
        view, pindex->nHeight, pindex->GetBlockHash(), pindex->GetBlockTime());
    if (!undo ||
        undo->previous_block_hash !=
            (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}) ||
        !PoolUndoClaimCountWithinBound(view, pindex, consensus, *undo)) {
        return std::nullopt;
    }
    return undo;
}

ActiveSignalStateReadResult ReadActiveSignalStateMarker(const CCoinsViewCache& view,
                                                         const CBlockIndex* pindex,
                                                         std::map<CScript, ShadowActiveSignal>& active,
                                                         uint32_t& marker_height,
                                                         uint32_t& marker_time,
                                                         uint256& marker_hash)
{
    active.clear();
    marker_height = 0;
    marker_time = 0;
    marker_hash.SetNull();
    Coin coin;
    if (!view.GetCoin(ActiveSignalSetOutpoint(), coin) || coin.IsSpent()) {
        return ActiveSignalStateReadResult::MISSING;
    }
    if (!pindex || coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.nHeight < static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) ||
        coin.nHeight > static_cast<uint32_t>(pindex->nHeight)) {
        return ActiveSignalStateReadResult::INVALID;
    }
    const CBlockIndex* marker_block = SafeGetAncestor(pindex, static_cast<int>(coin.nHeight));
    const auto resource_bounds =
        ReadAuthenticatedWhitelistResourceBounds(view, pindex);
    ActiveSignalStateManifest manifest;
    if (!marker_block || coin.nTime != static_cast<uint32_t>(marker_block->GetBlockTime()) ||
        !resource_bounds ||
        coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeActiveSignalStateManifest(coin.out.scriptPubKey, manifest) ||
        manifest.marker_hash != marker_block->GetBlockHash() ||
        manifest.entry_count > resource_bounds->whitelist_entries ||
        manifest.total_size > resource_bounds->maximum_state_bytes ||
        manifest.shard_count > resource_bounds->maximum_state_shards) {
        active.clear();
        return ActiveSignalStateReadResult::INVALID;
    }
    valtype blob;
    blob.reserve(manifest.total_size);
    for (uint32_t shard_index = 0; shard_index < manifest.shard_count; ++shard_index) {
        Coin shard_coin;
        valtype shard_data;
        if (!view.GetCoin(ActiveSignalShardOutpoint(manifest.marker_hash, shard_index), shard_coin) ||
            shard_coin.IsSpent() || shard_coin.out.nValue != 0 || !shard_coin.fCoinBase || shard_coin.fCoinStake ||
            shard_coin.nHeight != coin.nHeight || shard_coin.nTime != coin.nTime ||
            shard_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
            !DecodeBlobShard(shard_coin.out.scriptPubKey, MARKER_ACTIVE_SIGNAL_SHARD,
                             manifest.marker_hash, shard_index, manifest.shard_count,
                             manifest.total_size, shard_data)) {
            active.clear();
            return ActiveSignalStateReadResult::INVALID;
        }
        blob.insert(blob.end(), shard_data.begin(), shard_data.end());
    }
    if (blob.size() != manifest.total_size ||
        HashStateBlob("Quantum Quasar Active Signal State Blob v1", blob) != manifest.blob_hash ||
        !DecodeActiveSignalSetPayload(blob, active, &marker_hash,
                                      resource_bounds->whitelist_entries) ||
        marker_hash != manifest.marker_hash || active.size() != manifest.entry_count) {
        active.clear();
        return ActiveSignalStateReadResult::INVALID;
    }
    for (const auto& [target, signal] : active) {
        if (signal.target != target || signal.last_signal_height > coin.nHeight ||
            !IsLegacyShadowTargetScript(target) || !IsWhitelisted(view, target)) {
            active.clear();
            return ActiveSignalStateReadResult::INVALID;
        }
    }
    marker_height = coin.nHeight;
    marker_time = coin.nTime;
    return ActiveSignalStateReadResult::VALID;
}

std::map<CScript, ShadowActiveSignal> ReadActiveShadowSignals(const CCoinsViewCache& view,
                                                              const CBlockIndex* pindex,
                                                              int evaluation_height,
                                                              bool* state_valid = nullptr)
{
    if (state_valid) *state_valid = true;
    std::map<CScript, ShadowActiveSignal> active;
    if (!pindex) return active;
    uint32_t marker_height{0};
    uint32_t marker_time{0};
    uint256 marker_hash;
    const ActiveSignalStateReadResult result =
        ReadActiveSignalStateMarker(view, pindex, active, marker_height, marker_time, marker_hash);
    ShadowPoolState pool;
    const ShadowPoolReadResult pool_result = ReadPoolState(view, pool);
    if (!ActiveSignalPoolPairValid(Params().GetConsensus(), pindex,
                                   pool_result, result)) {
        if (state_valid) *state_valid = false;
        return {};
    }
    FilterActiveSignals(active, evaluation_height);
    return active;
}

std::map<CScript, CScript> ActiveSignalPayoutScripts(const std::map<CScript, ShadowActiveSignal>& active)
{
    std::map<CScript, CScript> payouts;
    for (const auto& [target, signal] : active) {
        payouts.emplace(target, signal.payout_script);
    }
    return payouts;
}

bool BuildPosPayouts(const ShadowPoolState& credited_pool, const std::optional<CScript>& current_solver, const std::map<CScript, CScript>& active_signals, bool require_quantum_payouts, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!current_solver || !active_signals.count(*current_solver) || credited_pool.pos_amount <= 0 || active_signals.empty()) return true;

    if (require_quantum_payouts) {
        for (const auto& [legacy_target, payout_script] : active_signals) {
            if (!IsDirectQuantumMigrationScript(payout_script)) return true;
        }
    }

    const CAmount share = credited_pool.pos_amount / active_signals.size();
    CAmount remainder = credited_pool.pos_amount - share * active_signals.size();
    for (const auto& [legacy_target, payout_script] : active_signals) {
        CAmount amount = share;
        if (remainder > 0) {
            ++amount;
            --remainder;
        }
        if (amount <= 0) continue;
        CAmount& current = payouts_out[payout_script];
        const auto next = CheckedAddMoney(current, amount);
        if (!next) return false;
        current = *next;
        const auto next_total = CheckedAddMoney(total_out, amount);
        if (!next_total) return false;
        total_out = *next_total;
    }
    return true;
}

ShadowPowClaimResult FindLegacyPowShadowClaims(const CBlock& block, const CBlockIndex* pindex,
                                               const CBlockUndo* blockundo,
                                               const ShadowPoolState& pool)
{
    unsigned int proof_evals = 0;
    bool proof_limit_exceeded = false;
    ShadowPowClaimResult result;
    // QQSPROOF is merged-mined by fee-paying transactions inside regular PoS
    // blocks. A proof accidentally included by a proof-of-work block remains a
    // legacy-visible transaction, but it is not a Gold Rush payout venue.
    if (!block.IsProofOfStake()) return result;
    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const auto& ptx = block.vtx[tx_index];
        const CTransaction& tx = *ptx;
        if (tx.IsCoinBase() || tx.IsCoinStake()) {
            for (const CTxOut& out : tx.vout) {
                if (ExtractProofPayload(out.scriptPubKey)) result.invalid_claim_location = true;
            }
            continue;
        }
        for (const CTxOut& out : tx.vout) {
            const auto proof = ExtractProofPayload(out.scriptPubKey);
            if (!proof) continue;
            const ShadowProofPayloadMode payload_mode = ClassifyProofPayloadMode(*proof);
            if (payload_mode == ShadowProofPayloadMode::POS) {
                result.wrong_mode_claim = true;
            } else if (payload_mode == ShadowProofPayloadMode::UNKNOWN) {
                result.unknown_mode_claim = true;
            }
            // DoS bound (H-2): stop after a fixed number of Argon2id evaluations per block.
            // During the staged legacy-compatible Gold Rush, malformed or excess QQPROOF
            // notes do not make an otherwise legacy-valid block invalid; they simply receive
            // no shadow-ledger credit.
            ShadowProof decoded;
            const ShadowProofValidationResult status = ValidateQQProof(*proof, pindex, pool, decoded, proof_evals, proof_limit_exceeded);
            if (proof_limit_exceeded) {
                result.proof_limit_exceeded = true;
                return result;
            }
            if (status == ShadowProofValidationResult::LOCAL_INTERNAL_ERROR) {
                result.internal_error = true;
                return result;
            }
            if (status == ShadowProofValidationResult::VALID) {
                if (!TxSpendsFromScript(tx, tx_index, blockundo, decoded.target)) continue;
                const CAmount amount = pool.pow_amount;
                if (amount <= 0) continue;
                if (!result.credits.empty()) {
                    result.competing_claims = true;
                    return result;
                }
                result.credits.push_back(ShadowPowCredit{decoded.payout_script, amount});
                result.current_winner = true;
                result.valid_claim_count = 1;
            }
        }
    }
    return result;
}

struct CanonicalPowCandidate {
    size_t tx_index{0};
    uint32_t output_index{0};
    uint256 txid;
    uint256 rank;
    valtype proof;
    ShadowProof decoded;
    CAmount base_fee{0};
};

uint256 CanonicalPowCandidateRank(int height, const uint256& previous_block_hash,
                                 const uint256& txid, uint32_t output_index,
                                 const valtype& proof)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Canonical POW Claim Rank v1")
       << height
       << previous_block_hash
       << txid << output_index << proof;
    return ss.GetHash();
}

bool CanonicalPowCandidateLess(const CanonicalPowCandidate& lhs,
                               const CanonicalPowCandidate& rhs)
{
    if (lhs.rank != rhs.rank) return lhs.rank < rhs.rank;
    if (lhs.txid != rhs.txid) return lhs.txid < rhs.txid;
    if (lhs.output_index != rhs.output_index) return lhs.output_index < rhs.output_index;
    return lhs.proof < rhs.proof;
}

std::vector<CanonicalPowCandidate> SelectCanonicalPowCandidates(
    const CBlock& block, const ShadowPowAccountingContext& context)
{
    std::vector<CanonicalPowCandidate> candidates;
    candidates.reserve(MAX_SHADOW_POW_EVALS_PER_BLOCK);
    const bool proof_of_stake_block = block.IsProofOfStake();
    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.vtx[tx_index];
        uint32_t proof_count{0};
        for (const CTxOut& output : tx.vout) {
            if (!ExtractProofPayload(output.scriptPubKey)) continue;
            if (proof_count >= MAX_SHADOW_POW_NOTES_PER_BLOCK) return {};
            ++proof_count;
        }
        if (proof_count != 1 || !proof_of_stake_block || tx.IsCoinBase() ||
            tx.IsCoinStake()) continue;
        for (size_t output_pos = 0; output_pos < tx.vout.size(); ++output_pos) {
            const auto extracted = ExtractProofPayload(
                tx.vout[output_pos].scriptPubKey);
            if (!extracted ||
                ClassifyProofPayloadMode(*extracted) ==
                    ShadowProofPayloadMode::POS ||
                ClassifyProofPayloadMode(*extracted) ==
                    ShadowProofPayloadMode::UNKNOWN ||
                output_pos > std::numeric_limits<uint32_t>::max()) continue;
            CanonicalPowCandidate candidate;
            candidate.tx_index = tx_index;
            candidate.output_index = static_cast<uint32_t>(output_pos);
            candidate.txid = tx.GetHash();
            candidate.rank = CanonicalPowCandidateRank(
                context.height, context.previous_block_hash, candidate.txid,
                candidate.output_index, *extracted);
            candidate.proof = *extracted;
            if (candidates.size() < MAX_SHADOW_POW_EVALS_PER_BLOCK) {
                candidates.push_back(std::move(candidate));
                std::push_heap(candidates.begin(), candidates.end(),
                               CanonicalPowCandidateLess);
            } else if (CanonicalPowCandidateLess(candidate,
                                                 candidates.front())) {
                std::pop_heap(candidates.begin(), candidates.end(),
                              CanonicalPowCandidateLess);
                candidates.back() = std::move(candidate);
                std::push_heap(candidates.begin(), candidates.end(),
                               CanonicalPowCandidateLess);
            }
        }
    }
    std::sort_heap(candidates.begin(), candidates.end(),
                   CanonicalPowCandidateLess);
    return candidates;
}

bool IncrementPowAggregate(uint32_t& value)
{
    if (value >= MAX_SHADOW_POW_NOTES_PER_BLOCK) return false;
    ++value;
    return true;
}

bool FinalizePowClaimAggregate(ShadowPowClaimResult& result,
                               const ShadowPowAccountingContext& context,
                               const uint256& observation_commitment)
{
    if (result.accounting.size() > MAX_SHADOW_POW_EVALS_PER_BLOCK) return false;
    result.aggregate.evaluated_count =
        static_cast<uint32_t>(result.accounting.size());
    for (const ShadowPowClaimAccounting& accounting : result.accounting) {
        uint32_t* counter{nullptr};
        switch (accounting.disposition) {
        case ShadowPowClaimDisposition::INVALID_PROOF:
            counter = &result.aggregate.invalid_proof_count;
            break;
        case ShadowPowClaimDisposition::INPUT_MISMATCH:
            counter = &result.aggregate.input_mismatch_count;
            break;
        case ShadowPowClaimDisposition::INVALID_BASE_FEE:
            counter = &result.aggregate.invalid_base_fee_count;
            break;
        case ShadowPowClaimDisposition::WINNER:
            counter = &result.aggregate.winner_count;
            break;
        case ShadowPowClaimDisposition::REIMBURSED_LOSER:
            counter = &result.aggregate.reimbursed_loser_count;
            break;
        case ShadowPowClaimDisposition::ORIGIN_MISMATCH:
            counter = &result.aggregate.origin_mismatch_count;
            break;
        case ShadowPowClaimDisposition::ORIGIN_EXPIRED:
            counter = &result.aggregate.origin_expired_count;
            break;
        case ShadowPowClaimDisposition::REIMBURSED_LATE:
            counter = &result.aggregate.reimbursed_late_count;
            break;
        default:
            // Structural and over-budget dispositions are aggregate-only.
            return false;
        }
        if (!IncrementPowAggregate(*counter)) return false;
    }

    const uint64_t classified =
        static_cast<uint64_t>(result.aggregate.invalid_location_count) +
        result.aggregate.malformed_transaction_count +
        result.aggregate.invalid_proof_count +
        result.aggregate.wrong_mode_count +
        result.aggregate.unknown_mode_count +
        result.aggregate.origin_mismatch_count +
        result.aggregate.origin_expired_count +
        result.aggregate.input_mismatch_count +
        result.aggregate.invalid_base_fee_count +
        result.aggregate.evaluation_limit_count +
        result.aggregate.winner_count +
        result.aggregate.reimbursed_loser_count +
        result.aggregate.reimbursed_late_count;
    if (classified != result.aggregate.observed_count) return false;

    CHashWriter commitment;
    commitment << std::string{"Quantum Quasar Bounded POW Claim Accounting v2"}
               << context.height << context.previous_block_hash
               << context.credited_pow_pool << context.target_bits
               << observation_commitment
               << result.aggregate.observed_count
               << result.aggregate.evaluated_count
               << result.aggregate.invalid_location_count
               << result.aggregate.malformed_transaction_count
               << result.aggregate.invalid_proof_count
               << result.aggregate.wrong_mode_count
               << result.aggregate.unknown_mode_count
               << result.aggregate.origin_mismatch_count
               << result.aggregate.origin_expired_count
               << result.aggregate.input_mismatch_count
               << result.aggregate.invalid_base_fee_count
               << result.aggregate.evaluation_limit_count
               << result.aggregate.winner_count
               << result.aggregate.reimbursed_loser_count
               << result.aggregate.reimbursed_late_count;
    for (const ShadowPowClaimAccounting& accounting : result.accounting) {
        commitment << accounting.source_txid << accounting.source_vout
                   << accounting.canonical_rank << accounting.payout_script
                   << accounting.base_fee << accounting.credited_amount
                   << accounting.base_fee_known << accounting.origin_bound
                   << accounting.origin_height
                   << accounting.origin_previous_block_hash
                   << accounting.inclusion_height << accounting.origin_age
                   << static_cast<uint8_t>(accounting.disposition);
    }
    result.aggregate.accounting_commitment = commitment.GetHash();
    return !result.aggregate.accounting_commitment.IsNull();
}

ShadowPowClaimResult FindCanonicalPowShadowClaimsImpl(
    const CBlock& block, const CBlockUndo* blockundo,
    const ShadowPowAccountingContext& context)
{
    ShadowPowClaimResult result;
    if (!context.valid || !context.canonical_rule_active ||
        context.credited_pow_pool <= 0) return result;
    const bool proof_of_stake_block = block.IsProofOfStake();

    CHashWriter observations;
    observations << std::string{"Quantum Quasar POW Claim Observations v1"}
                 << context.height << context.previous_block_hash
                 << block.GetHash();

    // Stream every output and retain only the lowest 64 canonical candidates.
    // This makes both validation memory and the later index batch independent
    // of the number of QQSPROOF-shaped outputs in a legacy-valid block.
    std::vector<CanonicalPowCandidate> candidates;
    candidates.reserve(MAX_SHADOW_POW_EVALS_PER_BLOCK);
    uint32_t candidate_count{0};
    for (size_t tx_index = 0; tx_index < block.vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.vtx[tx_index];
        const uint256 txid = tx.GetHash();
        uint32_t proof_count{0};
        for (const CTxOut& output : tx.vout) {
            if (ExtractProofPayload(output.scriptPubKey) &&
                !IncrementPowAggregate(proof_count)) {
                result.internal_error = true;
                return result;
            }
        }
        if (proof_count == 0) continue;
        const bool fee_paying_location = proof_of_stake_block &&
            !tx.IsCoinBase() && !tx.IsCoinStake();
        for (size_t output_pos = 0; output_pos < tx.vout.size(); ++output_pos) {
            const auto extracted =
                ExtractProofPayload(tx.vout[output_pos].scriptPubKey);
            if (!extracted) continue;
            if (output_pos > std::numeric_limits<uint32_t>::max() ||
                !IncrementPowAggregate(result.aggregate.observed_count)) {
                result.internal_error = true;
                return result;
            }
            const uint32_t output_index = static_cast<uint32_t>(output_pos);
            valtype proof = *extracted;
            observations << txid << output_index << proof
                         << fee_paying_location << proof_count;
            if (!fee_paying_location) {
                result.invalid_claim_location = true;
                if (!IncrementPowAggregate(
                        result.aggregate.invalid_location_count)) {
                    result.internal_error = true;
                    return result;
                }
                continue;
            }
            if (proof_count != 1) {
                result.malformed_claim = true;
                if (!IncrementPowAggregate(
                        result.aggregate.malformed_transaction_count)) {
                    result.internal_error = true;
                    return result;
                }
                continue;
            }
            const ShadowProofPayloadMode payload_mode =
                ClassifyProofPayloadMode(proof);
            if (payload_mode == ShadowProofPayloadMode::POS ||
                payload_mode == ShadowProofPayloadMode::UNKNOWN) {
                result.wrong_mode_claim |=
                    payload_mode == ShadowProofPayloadMode::POS;
                result.unknown_mode_claim |=
                    payload_mode == ShadowProofPayloadMode::UNKNOWN;
                uint32_t& counter = payload_mode == ShadowProofPayloadMode::POS
                    ? result.aggregate.wrong_mode_count
                    : result.aggregate.unknown_mode_count;
                if (!IncrementPowAggregate(counter)) {
                    result.internal_error = true;
                    return result;
                }
                continue;
            }

            if (!IncrementPowAggregate(candidate_count)) {
                result.internal_error = true;
                return result;
            }
            CanonicalPowCandidate candidate;
            candidate.tx_index = tx_index;
            candidate.output_index = output_index;
            candidate.txid = txid;
            candidate.rank = CanonicalPowCandidateRank(
                context.height, context.previous_block_hash, candidate.txid,
                output_index, proof);
            candidate.proof = std::move(proof);
            if (candidates.size() < MAX_SHADOW_POW_EVALS_PER_BLOCK) {
                candidates.push_back(std::move(candidate));
                std::push_heap(candidates.begin(), candidates.end(),
                               CanonicalPowCandidateLess);
            } else if (CanonicalPowCandidateLess(candidate,
                                                 candidates.front())) {
                std::pop_heap(candidates.begin(), candidates.end(),
                              CanonicalPowCandidateLess);
                candidates.back() = std::move(candidate);
                std::push_heap(candidates.begin(), candidates.end(),
                               CanonicalPowCandidateLess);
            }
        }
    }
    std::sort_heap(candidates.begin(), candidates.end(),
                   CanonicalPowCandidateLess);
    result.aggregate.evaluation_limit_count =
        candidate_count - static_cast<uint32_t>(candidates.size());
    result.proof_limit_exceeded = result.aggregate.evaluation_limit_count > 0;
    const uint256 observation_commitment = observations.GetHash();

    unsigned int proof_evals{0};
    std::vector<size_t> current_valid;
    std::vector<size_t> late_valid;
    current_valid.reserve(candidates.size());
    late_valid.reserve(candidates.size());
    result.accounting.reserve(candidates.size());
    for (size_t candidate_index = 0; candidate_index < candidates.size(); ++candidate_index) {
        CanonicalPowCandidate& candidate = candidates[candidate_index];
        result.accounting.emplace_back();
        ShadowPowClaimAccounting& accounting = result.accounting.back();
        accounting.source_txid = candidate.txid;
        accounting.source_vout = candidate.output_index;
        accounting.canonical_rank = candidate.rank;
        accounting.inclusion_height = static_cast<uint32_t>(context.height);

        ShadowProof decoded_shape;
        if (!DecodeProof(candidate.proof, decoded_shape)) continue;
        accounting.payout_script = decoded_shape.payout_script;
        accounting.origin_bound = decoded_shape.origin_bound;
        accounting.origin_height = decoded_shape.origin_bound
            ? decoded_shape.origin_height
            : static_cast<uint32_t>(context.height);
        accounting.origin_previous_block_hash = decoded_shape.origin_bound
            ? decoded_shape.origin_previous_block_hash
            : context.previous_block_hash;

        int proof_height = context.height;
        uint256 proof_previous_block_hash = context.previous_block_hash;
        unsigned int proof_target_bits = context.target_bits;
        bool late_origin{false};
        if (decoded_shape.origin_bound) {
            if (decoded_shape.origin_height >
                static_cast<uint32_t>(context.height)) {
                accounting.disposition =
                    ShadowPowClaimDisposition::ORIGIN_MISMATCH;
                continue;
            }
            accounting.origin_age = static_cast<uint32_t>(context.height) -
                                    decoded_shape.origin_height;
            if (accounting.origin_age > SHADOW_POW_LATE_ORIGIN_WINDOW) {
                accounting.disposition =
                    ShadowPowClaimDisposition::ORIGIN_EXPIRED;
                continue;
            }
            if (accounting.origin_age == 0) {
                if (decoded_shape.origin_previous_block_hash !=
                    context.previous_block_hash) {
                    accounting.disposition =
                        ShadowPowClaimDisposition::ORIGIN_MISMATCH;
                    continue;
                }
            } else {
                const auto origin = std::find_if(
                    context.late_origins.begin(), context.late_origins.end(),
                    [&](const ShadowPowOriginContext& item) {
                        return item.height == decoded_shape.origin_height &&
                               item.previous_block_hash ==
                                   decoded_shape.origin_previous_block_hash;
                    });
                if (origin == context.late_origins.end()) {
                    accounting.disposition =
                        ShadowPowClaimDisposition::ORIGIN_MISMATCH;
                    continue;
                }
                proof_height = static_cast<int>(origin->height);
                proof_previous_block_hash = origin->previous_block_hash;
                proof_target_bits = origin->target_bits;
                late_origin = true;
            }
        }

        bool proof_limit_exceeded{false};
        const ShadowProofValidationResult status = ValidateQQProofAtBits(
            candidate.proof, proof_height, proof_previous_block_hash,
            proof_target_bits, candidate.decoded, proof_evals,
            proof_limit_exceeded);
        if (proof_limit_exceeded) {
            result.internal_error = true;
            return result;
        }
        if (status == ShadowProofValidationResult::LOCAL_INTERNAL_ERROR) {
            result.internal_error = true;
            return result;
        }
        if (status != ShadowProofValidationResult::VALID) continue;

        const CTransaction& tx = *block.vtx[candidate.tx_index];
        const ShadowBaseFeeResult fee_result = GetShadowClaimBaseFee(
            tx, candidate.tx_index, blockundo, candidate.base_fee);
        if (fee_result == ShadowBaseFeeResult::LOCAL_INTERNAL_ERROR) {
            result.internal_error = true;
            return result;
        }
        if (fee_result != ShadowBaseFeeResult::VALID) {
            accounting.disposition = ShadowPowClaimDisposition::INVALID_BASE_FEE;
            continue;
        }
        accounting.base_fee = candidate.base_fee;
        accounting.base_fee_known = true;
        if (!TxSpendsFromScript(tx, candidate.tx_index, blockundo,
                                candidate.decoded.target)) {
            accounting.disposition = ShadowPowClaimDisposition::INPUT_MISMATCH;
            continue;
        }
        accounting.disposition = late_origin
            ? ShadowPowClaimDisposition::REIMBURSED_LATE
            : ShadowPowClaimDisposition::REIMBURSED_LOSER;
        (late_origin ? late_valid : current_valid).push_back(candidate_index);
    }

    result.valid_claim_count = static_cast<uint32_t>(
        current_valid.size() + late_valid.size());
    result.competing_claims = result.valid_claim_count > 1;
    if (result.valid_claim_count == 0) {
        if (!FinalizePowClaimAggregate(result, context,
                                       observation_commitment)) {
            result.internal_error = true;
        }
        return result;
    }

    // The first current-origin candidate in canonical rank order wins. Every
    // other current candidate and every eligible late-origin QQP3 receives
    // only its actual base fee capped at 0.01 BLK. A block containing only
    // late claims leaves the unreimbursed pool remainder accumulated; no late
    // proof can capture the jackpot or reset PoW difficulty.
    CAmount total_reimbursements{0};
    auto add_reimbursement = [&](size_t candidate_index) {
        const CAmount reimbursement = std::min(
            candidates[candidate_index].base_fee, CENT);
        const auto next = CheckedAddMoney(total_reimbursements, reimbursement);
        if (!next) return false;
        total_reimbursements = *next;
        return true;
    };
    for (size_t i = current_valid.empty() ? 0 : 1;
         i < current_valid.size(); ++i) {
        if (!add_reimbursement(current_valid[i])) {
            result.internal_error = true;
            return result;
        }
    }
    for (const size_t candidate_index : late_valid) {
        if (!add_reimbursement(candidate_index)) {
            result.internal_error = true;
            return result;
        }
    }
    if (total_reimbursements > context.credited_pow_pool ||
        (!current_valid.empty() &&
         total_reimbursements >= context.credited_pow_pool)) {
        result.internal_error = true;
        return result;
    }

    result.credits.reserve(current_valid.size() + late_valid.size());
    for (size_t i = 0; i < current_valid.size(); ++i) {
        const CAmount amount = i == 0
            ? context.credited_pow_pool - total_reimbursements
            : std::min(candidates[current_valid[i]].base_fee, CENT);
        ShadowPowClaimAccounting& accounting =
            result.accounting[current_valid[i]];
        accounting.disposition = i == 0
            ? ShadowPowClaimDisposition::WINNER
            : ShadowPowClaimDisposition::REIMBURSED_LOSER;
        accounting.credited_amount = amount;
        if (i != 0 && amount > 0) ++result.reimbursed_claim_count;
    }
    result.current_winner = !current_valid.empty();
    for (const size_t candidate_index : late_valid) {
        const CAmount amount = std::min(
            candidates[candidate_index].base_fee, CENT);
        ShadowPowClaimAccounting& accounting =
            result.accounting[candidate_index];
        accounting.disposition = ShadowPowClaimDisposition::REIMBURSED_LATE;
        accounting.credited_amount = amount;
        if (amount > 0) ++result.reimbursed_claim_count;
    }
    // Preserve the global canonical candidate order when materializing
    // synthetic payouts. The shadow index links payouts to accounting rows in
    // this same order, including when current and late origins interleave.
    for (size_t candidate_index = 0; candidate_index < candidates.size();
         ++candidate_index) {
        const ShadowPowClaimAccounting& accounting =
            result.accounting[candidate_index];
        if (accounting.credited_amount <= 0) continue;
        if (accounting.disposition != ShadowPowClaimDisposition::WINNER &&
            accounting.disposition !=
                ShadowPowClaimDisposition::REIMBURSED_LOSER &&
            accounting.disposition !=
                ShadowPowClaimDisposition::REIMBURSED_LATE) continue;
        result.credits.push_back(ShadowPowCredit{
            candidates[candidate_index].decoded.payout_script,
            accounting.credited_amount});
    }
    if (!FinalizePowClaimAggregate(result, context, observation_commitment)) {
        result.internal_error = true;
    }
    return result;
}

ShadowPowClaimResult FindCanonicalPowShadowClaims(
    const CBlock& block, const CBlockUndo* blockundo,
    const ShadowPowAccountingContext& context)
{
    try {
        MaybeThrowShadowAllocationFailureForTesting(
            ShadowAllocationFailurePoint::ACCOUNTING);
        return FindCanonicalPowShadowClaimsImpl(block, blockundo, context);
    } catch (const std::bad_alloc&) {
        LogPrintf("ERROR: Quantum Quasar canonical claim accounting allocation failed at height %d\n",
                  context.height);
    } catch (const std::length_error&) {
        LogPrintf("ERROR: Quantum Quasar canonical claim accounting exceeded a local container bound at height %d\n",
                  context.height);
    }
    ShadowPowClaimResult result;
    result.internal_error = true;
    return result;
}

ShadowPowClaimResult FindPowShadowClaims(const CCoinsViewCache& view,
                                         const CBlock& block, const CBlockIndex* pindex,
                                         const CBlockUndo* blockundo,
                                         const ShadowPoolState& pool,
                                         const Consensus::Params& consensus)
{
    if (pindex && consensus.IsShadowCompetingClaimsActive(pindex->nHeight)) {
        ShadowPowAccountingContext context;
        if (PrepareShadowPowClaimAccounting(view, block, pindex, consensus,
                                            context) !=
                ShadowPowAccountingResult::OK ||
            !context.valid || context.credited_pow_pool != pool.pow_amount) {
            ShadowPowClaimResult result;
            result.internal_error = true;
            return result;
        }
        return FindCanonicalPowShadowClaims(block, blockundo, context);
    }
    return FindLegacyPowShadowClaims(block, pindex, blockundo, pool);
}

bool IsValidDirectClaimMarker(const CBlockIndex* pindex, const ShadowClaim& claim)
{
    return pindex && claim.amount > 0 && MoneyRange(claim.amount) &&
        IsDirectQuantumMigrationScript(claim.target) &&
        claim.target.size() <= std::numeric_limits<uint16_t>::max();
}

bool AddClaimMarker(CCoinsViewCache& view, const CBlockIndex* pindex, uint32_t marker_index, ShadowClaim claim)
{
    claim.direct = true;
    if (!IsValidDirectClaimMarker(pindex, claim)) {
        return false;
    }

    const COutPoint payout_outpoint = ClaimPayoutOutpoint(pindex, marker_index, claim);
    GoldRushPayoutRecord payout_record;
    payout_record.origin_height = pindex->nHeight;
    payout_record.origin_block_hash = pindex->GetBlockHash();
    payout_record.claim_index = marker_index;
    payout_record.payout_outpoint = payout_outpoint;
    payout_record.nominal_amount = claim.amount;
    payout_record.mode = claim.mode;
    payout_record.claim_hash = HashGoldRushClaim(claim);
    payout_record.target = claim.target;

    GoldRushInventoryState inventory;
    const GoldRushInventoryReadResult inventory_result = ReadGoldRushInventory(view, inventory);
    if (inventory_result == GoldRushInventoryReadResult::INVALID ||
        (inventory_result == GoldRushInventoryReadResult::MISSING &&
         pindex->nHeight != SHADOW_REWARD_START_HEIGHT)) return false;
    if (inventory_result == GoldRushInventoryReadResult::VALID &&
        inventory.tip_hash != pindex->GetBlockHash() &&
        (!pindex->pprev || inventory.tip_hash != pindex->pprev->GetBlockHash())) {
        return false;
    }
    if (inventory_result == GoldRushInventoryReadResult::VALID &&
        inventory.tip_hash != pindex->GetBlockHash() &&
        !GoldRushInventoryRootsValid(inventory)) return false;
    if (inventory.issued_count == std::numeric_limits<uint64_t>::max() ||
        inventory.issued_nominal > MAX_MONEY - claim.amount) {
        return false;
    }
    const valtype payout_leaf = GoldRushPayoutLeaf(payout_record);
    inventory.issued_set.Insert(payout_leaf);
    inventory.unspent_set.Insert(payout_leaf);
    ++inventory.issued_count;
    inventory.issued_nominal += claim.amount;

    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_DIRECT_CLAIM,
                                         EncodeClaimMarkerPayload(pindex, marker_index, claim));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(ClaimOutpoint(pindex, marker_index), std::move(coin), true);

    Coin payout;
    payout.out = CTxOut{claim.amount, claim.target};
    payout.fCoinBase = true;
    payout.fCoinStake = false;
    payout.nHeight = pindex->nHeight;
    payout.nTime = pindex->GetBlockTime();
    view.AddCoin(payout_outpoint, std::move(payout), true);

    Coin payout_marker;
    payout_marker.out.nValue = 0;
    payout_marker.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_PAYOUT,
                                                  EncodeGoldRushPayoutRecord(payout_record));
    payout_marker.fCoinBase = true;
    payout_marker.fCoinStake = false;
    payout_marker.nHeight = pindex->nHeight;
    payout_marker.nTime = pindex->GetBlockTime();
    view.AddCoin(GoldRushPayoutOutpoint(payout_outpoint), std::move(payout_marker), true);
    return WriteGoldRushInventory(view, pindex, std::move(inventory), /*finalize=*/false);
}

std::optional<std::vector<ShadowClaim>> ReadAuthenticatedBlockClaims(
    const CCoinsViewCache& view, int height, const uint256& block_hash,
    int64_t block_time, const ShadowPoolUndoState& undo)
{
    std::vector<ShadowClaim> claims;
    claims.reserve(undo.claim_count);
    for (uint32_t marker_index = 0; marker_index < undo.claim_count;
         ++marker_index) {
        Coin claim_coin;
        if (!view.GetCoin(ClaimOutpoint(height, block_hash, marker_index),
                          claim_coin) ||
            claim_coin.IsSpent() || claim_coin.out.nValue != 0 ||
            !claim_coin.fCoinBase || claim_coin.fCoinStake ||
            claim_coin.nHeight != static_cast<uint32_t>(height) ||
            claim_coin.nTime != static_cast<uint32_t>(block_time)) {
            return std::nullopt;
        }
        valtype marker_payload;
        if (!ParseMarkerScript(claim_coin.out.scriptPubKey,
                               MARKER_DIRECT_CLAIM, &marker_payload)) {
            return std::nullopt;
        }
        if (marker_payload.size() >= CLAIM_MARKER_MAGIC_V3.size() &&
            std::equal(CLAIM_MARKER_MAGIC_V3.begin(),
                       CLAIM_MARKER_MAGIC_V3.end(), marker_payload.begin())) {
            uint32_t envelope_height{0};
            uint256 envelope_hash;
            uint32_t envelope_index{0};
            valtype enclosed_claim;
            if (!DecodeClaimMarkerEnvelope(marker_payload, envelope_height,
                                           envelope_hash, envelope_index,
                                           enclosed_claim) ||
                envelope_height != static_cast<uint32_t>(height) ||
                envelope_hash != block_hash || envelope_index != marker_index) {
                return std::nullopt;
            }
        }
        const std::optional<ShadowClaim> claim =
            DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || claim->amount <= 0 ||
            !MoneyRange(claim->amount) ||
            !IsDirectQuantumMigrationScript(claim->target) ||
            EncodePool(claim->undo_pool) != EncodePool(undo.previous)) {
            return std::nullopt;
        }
        claims.push_back(*claim);
    }
    if (HashBlockClaims(height, block_hash, claims) != undo.claims_hash) {
        return std::nullopt;
    }
    return claims;
}

std::optional<std::vector<ShadowClaim>> ReadAuthenticatedBlockClaims(
    const CCoinsViewCache& view, int height, const uint256& block_hash,
    int64_t block_time)
{
    const std::optional<ShadowPoolUndoState> undo = ReadAuthenticatedPoolUndo(
        view, height, block_hash, block_time);
    if (!undo) return std::nullopt;
    return ReadAuthenticatedBlockClaims(view, height, block_hash, block_time,
                                        *undo);
}

std::optional<std::vector<ShadowClaim>> ReadAuthenticatedBlockClaims(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    const Consensus::Params& consensus)
{
    if (!pindex) return std::nullopt;
    const std::optional<ShadowPoolUndoState> undo = ReadAuthenticatedPoolUndo(
        view, pindex, consensus);
    if (!undo) return std::nullopt;
    return ReadAuthenticatedBlockClaims(
        view, pindex->nHeight, pindex->GetBlockHash(), pindex->GetBlockTime(),
        *undo);
}

std::vector<COutPoint> FindDeterministicClaimMarkers(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    std::vector<COutPoint> outpoints;
    if (!pindex) return outpoints;
    const std::optional<std::vector<ShadowClaim>> claims =
        ReadAuthenticatedBlockClaims(
        view, pindex, Params().GetConsensus());
    if (!claims) return outpoints;
    outpoints.reserve(claims->size());
    for (uint32_t marker_index = 0; marker_index < claims->size();
         ++marker_index) {
        outpoints.push_back(ClaimOutpoint(pindex, marker_index));
    }
    return outpoints;
}

bool ValidateGoldRushInventorySummary(const CCoinsViewCache& view,
                                      const CBlockIndex* pindex_tip)
{
    GoldRushInventoryState inventory;
    Coin inventory_coin;
    const GoldRushInventoryReadResult inventory_result =
        ReadGoldRushInventory(view, inventory, &inventory_coin);
    if (!pindex_tip || pindex_tip->nHeight < SHADOW_REWARD_START_HEIGHT) {
        return inventory_result == GoldRushInventoryReadResult::MISSING;
    }
    if (inventory_result != GoldRushInventoryReadResult::VALID ||
        inventory.tip_height != static_cast<uint32_t>(pindex_tip->nHeight) ||
        inventory.tip_hash != pindex_tip->GetBlockHash() ||
        inventory_coin.nTime != static_cast<uint32_t>(pindex_tip->GetBlockTime()) ||
        inventory.issued_nominal > SHADOW_MAX_EMISSION ||
        !GoldRushInventoryRootsValid(inventory)) {
        return false;
    }
    ShadowPoolState pool;
    const ShadowPoolReadResult pool_result = ReadPoolState(view, pool);
    if (pool_result == ShadowPoolReadResult::MISSING) {
        return inventory.issued_count == 0 && inventory.issued_nominal == 0 &&
               inventory.spent_count == 0 && inventory.spent_nominal == 0;
    }
    if (pool_result != ShadowPoolReadResult::VALID) return false;
    return inventory.issued_nominal == pool.claimed_amount;
}

bool DeepAuditGoldRushClaimInventory(const CCoinsViewCache& view,
                                    const Consensus::Params& consensus,
                                    const CBlockIndex* pindex_tip,
                                    const ShadowBlockReader* read_block)
{
    if (!pindex_tip || pindex_tip->nHeight < SHADOW_REWARD_START_HEIGHT) {
        return true;
    }

    bool found_active_block{false};
    uint256 previous_post_hash;
    const CBlockIndex* previous_active_block{nullptr};
    CAmount authenticated_claimed_amount{0};
    std::set<COutPoint> expected_claim_outpoints;
    std::set<COutPoint> expected_payout_outpoints;
    std::set<COutPoint> expected_payout_marker_outpoints;
    std::set<COutPoint> expected_spent_marker_outpoints;
    std::map<int, std::vector<GoldRushSpentState>> spend_queries;
    const int last_height = std::min(pindex_tip->nHeight, SHADOW_REWARD_END_HEIGHT);
    const int64_t tip_spend_mtp = pindex_tip->pprev
        ? pindex_tip->pprev->GetMedianTimePast()
        : pindex_tip->GetBlockTime();
    const bool quantum_spends_active_at_tip = IsQuantumWitnessSpendActive(
        consensus, tip_spend_mtp, pindex_tip->nHeight);

    for (int height = SHADOW_REWARD_START_HEIGHT; height <= last_height; ++height) {
        const CBlockIndex* pindex = SafeGetAncestor(pindex_tip, height);
        if (!pindex) return false;
        const int64_t mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast()
                                          : pindex->GetBlockTime();
        if (!IsShadowGoldRushRewardActive(consensus, mtp, height)) continue;

        Coin undo_coin;
        ShadowPoolUndoState undo;
        if (!view.GetCoin(PoolUndoOutpoint(pindex), undo_coin) || undo_coin.IsSpent() ||
            undo_coin.out.nValue != 0 || !undo_coin.fCoinBase || undo_coin.fCoinStake ||
            undo_coin.nHeight != static_cast<uint32_t>(height) ||
            undo_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
            !DecodePoolUndo(undo_coin.out.scriptPubKey, undo) ||
            undo.block_hash != pindex->GetBlockHash() ||
            undo.previous_block_hash != (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}) ||
            !PoolUndoClaimCountWithinBound(view, pindex, consensus, undo)) {
            return false;
        }

        uint256 authenticated_pre_hash;
        if (!HashShadowPoolState(undo.previous_present, undo.previous_height,
                                 undo.previous_time, undo.previous_marker_hash,
                                 undo.previous, authenticated_pre_hash) ||
            authenticated_pre_hash != undo.pre_state_hash) {
            return false;
        }
        if (!found_active_block) {
            if (undo.previous_present) return false;
        } else {
            if (!undo.previous_present || !previous_active_block ||
                undo.previous_height != static_cast<uint32_t>(previous_active_block->nHeight) ||
                undo.previous_time != static_cast<uint32_t>(previous_active_block->GetBlockTime()) ||
                undo.previous_marker_hash != previous_active_block->GetBlockHash() ||
                undo.pre_state_hash != previous_post_hash) {
                return false;
            }
        }

        std::vector<ShadowClaim> claims;
        claims.reserve(undo.claim_count);
        for (uint32_t marker_index = 0; marker_index < undo.claim_count; ++marker_index) {
            Coin claim_coin;
            const COutPoint claim_outpoint = ClaimOutpoint(pindex, marker_index);
            expected_claim_outpoints.insert(claim_outpoint);
            if (!view.GetCoin(claim_outpoint, claim_coin) || claim_coin.IsSpent() ||
                claim_coin.out.nValue != 0 || !claim_coin.fCoinBase || claim_coin.fCoinStake ||
                claim_coin.nHeight != static_cast<uint32_t>(height) ||
                claim_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime())) {
                return false;
            }
            const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
            if (!claim || !claim->direct || !IsValidDirectClaimMarker(pindex, *claim) ||
                EncodePool(claim->undo_pool) != EncodePool(undo.previous)) {
                return false;
            }
            claims.push_back(*claim);

            const COutPoint payout_outpoint = ClaimPayoutOutpoint(pindex, marker_index, *claim);
            expected_payout_outpoints.insert(payout_outpoint);
            expected_payout_marker_outpoints.insert(GoldRushPayoutOutpoint(payout_outpoint));
            Coin marker;
            GoldRushPayoutRecord payout_record;
            if (!view.GetCoin(GoldRushPayoutOutpoint(payout_outpoint), marker) || marker.IsSpent() ||
                marker.out.nValue != 0 || !marker.fCoinBase || marker.fCoinStake ||
                marker.nHeight != static_cast<uint32_t>(height) ||
                marker.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
                !AuthenticateGoldRushPayoutRecord(view, payout_outpoint, payout_record, nullptr) ||
                payout_record.target != claim->target ||
                payout_record.nominal_amount != claim->amount) {
                return false;
            }

            Coin payout;
            const bool payout_unspent = view.GetCoin(payout_outpoint, payout) && !payout.IsSpent();
            Coin spent_marker;
            GoldRushSpentState spent_state;
            const COutPoint spent_marker_outpoint = GoldRushSpentOutpoint(payout_outpoint);
            const bool has_spent_marker = view.GetCoin(spent_marker_outpoint, spent_marker) &&
                !spent_marker.IsSpent();
            if (payout_unspent && has_spent_marker) return false;
            if (!payout_unspent) {
                if (!quantum_spends_active_at_tip || !has_spent_marker ||
                    spent_marker.out.nValue != 0 || !spent_marker.fCoinBase || spent_marker.fCoinStake ||
                    !DecodeGoldRushSpentState(spent_marker.out.scriptPubKey, spent_state) ||
                    spent_state.payout_outpoint != payout_outpoint ||
                    spent_state.spend_height <= static_cast<uint32_t>(height) ||
                    spent_state.spend_height > static_cast<uint32_t>(pindex_tip->nHeight) ||
                    spent_marker.nHeight != spent_state.spend_height) {
                    return false;
                }
                const CBlockIndex* spend_block = SafeGetAncestor(
                    pindex_tip, static_cast<int>(spent_state.spend_height));
                if (!spend_block || spent_state.spend_block_hash != spend_block->GetBlockHash() ||
                    spent_marker.nTime != static_cast<uint32_t>(spend_block->GetBlockTime())) {
                    return false;
                }
                spend_queries[spend_block->nHeight].push_back(spent_state);
                expected_spent_marker_outpoints.insert(spent_marker_outpoint);
            }
            if (payout_unspent &&
                (payout.out.nValue != claim->amount || payout.out.scriptPubKey != claim->target ||
                 !payout.fCoinBase || payout.fCoinStake ||
                 payout.nHeight != static_cast<uint32_t>(height) ||
                 payout.nTime != static_cast<uint32_t>(pindex->GetBlockTime()))) {
                return false;
            }
            const auto next_claimed = CheckedAddMoney(authenticated_claimed_amount, claim->amount);
            if (!next_claimed || *next_claimed > SHADOW_MAX_EMISSION) return false;
            authenticated_claimed_amount = *next_claimed;
        }
        if (view.HaveCoin(ClaimOutpoint(pindex, undo.claim_count)) ||
            HashBlockClaims(pindex, claims) != undo.claims_hash) {
            return false;
        }

        found_active_block = true;
        previous_post_hash = undo.post_state_hash;
        previous_active_block = pindex;
    }

    if (!spend_queries.empty() && !read_block) return false;
    for (const auto& [spend_height, queries] : spend_queries) {
        const CBlockIndex* spend_index = SafeGetAncestor(pindex_tip, spend_height);
        if (!spend_index) return false;
        CBlock spend_block;
        if (!(*read_block)(*spend_index, spend_block)) return false;
        for (const GoldRushSpentState& query : queries) {
            const auto spending_tx = std::find_if(
                spend_block.vtx.begin(), spend_block.vtx.end(),
                [&](const CTransactionRef& candidate) {
                    return candidate->GetHash() == query.spending_txid;
                });
            if (spending_tx == spend_block.vtx.end() ||
                query.input_index >= (*spending_tx)->vin.size() ||
                (*spending_tx)->vin[query.input_index].prevout != query.payout_outpoint) {
                return false;
            }
        }
    }

    // Check the reverse direction as well. Without this pass, a valid expected
    // inventory could coexist with an orphan auxiliary coin or provenance
    // record that is not covered by any block's authenticated QQPUND count and
    // claims hash. Restrict metadata inference to heights after ordinary PoW;
    // on overlapping-PoW test schedules the same shape can be a real base
    // coinbase and must not be treated as auxiliary state.
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    if (!cursor) return false;
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
            coin.out.nValue == 0 && coin.fCoinBase && !coin.fCoinStake &&
            coin.nHeight > static_cast<uint32_t>(consensus.nLastPOWBlock)) {
            GoldRushSpentState extra_spent;
            if (DecodeGoldRushSpentState(coin.out.scriptPubKey, extra_spent) &&
                outpoint == GoldRushSpentOutpoint(extra_spent.payout_outpoint) &&
                expected_spent_marker_outpoints.count(outpoint) == 0) {
                return false;
            }
        }
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
            coin.fCoinBase && !coin.fCoinStake &&
            coin.nHeight >= static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) &&
            coin.nHeight <= static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) &&
            coin.nHeight > static_cast<uint32_t>(consensus.nLastPOWBlock)) {
            if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_DIRECT_CLAIM) &&
                expected_claim_outpoints.count(outpoint) == 0) {
                return false;
            }
            if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT) &&
                expected_payout_marker_outpoints.count(outpoint) == 0) {
                return false;
            }
            const auto tier = coin.out.nValue > 0
                ? GetQuantumStakeTierProgram(coin.out.scriptPubKey)
                : std::optional<QuantumStakeTierProgram>{};
            if (tier && !tier->tiered && !tier->cold_stake &&
                expected_payout_outpoints.count(outpoint) == 0) {
                return false;
            }
        }
        cursor->Next();
    }

    ShadowPoolState current_pool;
    const ShadowPoolReadResult pool_result = ReadPoolState(view, current_pool);
    if (!found_active_block) return pool_result == ShadowPoolReadResult::MISSING;
    if (pool_result != ShadowPoolReadResult::VALID || !previous_active_block ||
        current_pool.claimed_amount != authenticated_claimed_amount) {
        return false;
    }
    Coin current_pool_coin;
    uint256 current_pool_hash;
    return view.GetCoin(PoolOutpoint(), current_pool_coin) && !current_pool_coin.IsSpent() &&
           current_pool_coin.nHeight == static_cast<uint32_t>(previous_active_block->nHeight) &&
           current_pool_coin.nTime == static_cast<uint32_t>(previous_active_block->GetBlockTime()) &&
           HashShadowPoolState(true, current_pool_coin.nHeight, current_pool_coin.nTime,
                               previous_active_block->GetBlockHash(), current_pool, current_pool_hash) &&
           current_pool_hash == previous_post_hash;
}

void AddSolverMarker(CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& solver)
{
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_SOLVER, EncodeSolverMarker(solver));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(SolverOutpoint(solver, pindex->nHeight, pindex->GetBlockHash()), std::move(coin), true);
}

bool ValidateActiveSignalMarkers(const CBlockIndex* pindex, const std::map<CScript, CScript>& signals)
{
    if (!pindex) return false;
    uint32_t marker_index = 0;
    for (const auto& [target, payout_script] : signals) {
        if (marker_index >= MAX_SHADOW_CLAIM_MARKERS_PER_BLOCK ||
            target.empty() || target.IsUnspendable() ||
            target.size() > std::numeric_limits<uint16_t>::max() ||
            !IsDirectQuantumMigrationScript(payout_script) ||
            payout_script.size() > std::numeric_limits<uint16_t>::max()) {
            return false;
        }
        ++marker_index;
    }
    return true;
}

bool AddActiveSignalMarkers(CCoinsViewCache& view, const CBlockIndex* pindex, const std::map<CScript, CScript>& signals)
{
    if (!ValidateActiveSignalMarkers(pindex, signals)) return false;
    uint32_t marker_index = 0;
    for (const auto& [target, payout_script] : signals) {
        Coin coin;
        coin.out.nValue = 0;
        coin.out.scriptPubKey = MarkerScript(MARKER_ACTIVE_SIGNAL, EncodeActiveSignalMarker(target, payout_script, pindex->nHeight));
        coin.fCoinBase = true;
        coin.fCoinStake = false;
        coin.nHeight = pindex->nHeight;
        coin.nTime = pindex->GetBlockTime();
        view.AddCoin(ActiveSignalOutpoint(pindex, marker_index++), std::move(coin), true);
    }
    return true;
}

bool ActiveSignalMapsEqual(const std::map<CScript, ShadowActiveSignal>& lhs,
                           const std::map<CScript, ShadowActiveSignal>& rhs)
{
    if (lhs.size() != rhs.size()) return false;
    auto left = lhs.begin();
    auto right = rhs.begin();
    while (left != lhs.end()) {
        if (left->first != right->first || !ActiveSignalEqual(left->second, right->second)) return false;
        ++left;
        ++right;
    }
    return true;
}

bool BuildActiveSignalStateScripts(const std::map<CScript, ShadowActiveSignal>& active,
                                   const uint256& marker_hash,
                                   size_t maximum_blob_bytes,
                                   CScript& manifest_script,
                                   std::vector<CScript>& shard_scripts)
{
    valtype blob;
    if (!EncodeActiveSignalSetPayload(active, marker_hash, blob) ||
        blob.size() > maximum_blob_bytes) return false;
    const uint32_t shard_count = BlobShardCount(blob.size());
    if (shard_count == 0) return false;
    ActiveSignalStateManifest manifest;
    manifest.marker_hash = marker_hash;
    manifest.entry_count = static_cast<uint32_t>(active.size());
    manifest.total_size = static_cast<uint32_t>(blob.size());
    manifest.shard_count = shard_count;
    manifest.blob_hash = HashStateBlob("Quantum Quasar Active Signal State Blob v1", blob);
    manifest_script = MarkerScript(MARKER_ACTIVE_SIGNAL_SET, EncodeActiveSignalStateManifest(manifest));
    if (manifest_script.size() > MAX_SCRIPT_SIZE) return false;
    shard_scripts.clear();
    shard_scripts.reserve(shard_count);
    for (uint32_t shard_index = 0; shard_index < shard_count; ++shard_index) {
        const valtype payload = EncodeBlobShard(marker_hash, shard_index, shard_count, blob.size(), blob);
        if (payload.empty()) return false;
        CScript script = MarkerScript(MARKER_ACTIVE_SIGNAL_SHARD, payload);
        if (script.size() > MAX_SCRIPT_SIZE) return false;
        shard_scripts.push_back(std::move(script));
    }
    return true;
}

bool BuildActiveSignalUndoScripts(const ShadowActiveSignalUndo& undo,
                                  size_t maximum_blob_bytes,
                                  CScript& manifest_script,
                                  std::vector<CScript>& shard_scripts)
{
    valtype blob;
    if (!EncodeActiveSignalUndo(undo, blob) ||
        blob.size() > maximum_blob_bytes) return false;
    const uint32_t shard_count = BlobShardCount(blob.size());
    if (shard_count == 0) return false;
    ActiveSignalUndoManifest manifest;
    manifest.block_hash = undo.block_hash;
    manifest.previous_block_hash = undo.previous_block_hash;
    manifest.total_size = static_cast<uint32_t>(blob.size());
    manifest.shard_count = shard_count;
    manifest.blob_hash = HashStateBlob("Quantum Quasar Active Signal Undo Blob v1", blob);
    manifest_script = MarkerScript(MARKER_ACTIVE_SIGNAL_UNDO, EncodeActiveSignalUndoManifest(manifest));
    if (manifest_script.size() > MAX_SCRIPT_SIZE) return false;
    shard_scripts.clear();
    shard_scripts.reserve(shard_count);
    for (uint32_t shard_index = 0; shard_index < shard_count; ++shard_index) {
        const valtype payload = EncodeBlobShard(undo.block_hash, shard_index, shard_count, blob.size(), blob);
        if (payload.empty()) return false;
        CScript script = MarkerScript(MARKER_ACTIVE_SIGNAL_UNDO_SHARD, payload);
        if (script.size() > MAX_SCRIPT_SIZE) return false;
        shard_scripts.push_back(std::move(script));
    }
    return true;
}

void SpendActiveSignalStateCoins(CCoinsViewCache& view, const uint256& marker_hash,
                                 const std::map<CScript, ShadowActiveSignal>& active)
{
    valtype blob;
    if (EncodeActiveSignalSetPayload(active, marker_hash, blob)) {
        const uint32_t shard_count = BlobShardCount(blob.size());
        for (uint32_t shard_index = 0; shard_index < shard_count; ++shard_index) {
            const COutPoint outpoint = ActiveSignalShardOutpoint(marker_hash, shard_index);
            if (view.HaveCoin(outpoint)) view.SpendCoin(outpoint);
        }
    }
    if (view.HaveCoin(ActiveSignalSetOutpoint())) view.SpendCoin(ActiveSignalSetOutpoint());
}

bool ReadActiveSignalUndoBlob(const CCoinsViewCache& view, const CBlockIndex* pindex,
                              const Coin& undo_coin, valtype& blob_out)
{
    ActiveSignalUndoManifest manifest;
    const auto resource_bounds =
        ReadAuthenticatedWhitelistResourceBounds(view, pindex);
    if (!pindex || undo_coin.out.nValue != 0 || !undo_coin.fCoinBase || undo_coin.fCoinStake ||
        !resource_bounds ||
        undo_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeActiveSignalUndoManifest(undo_coin.out.scriptPubKey, manifest) ||
        manifest.block_hash != pindex->GetBlockHash() ||
        manifest.previous_block_hash != (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}) ||
        manifest.total_size > resource_bounds->maximum_undo_bytes ||
        manifest.shard_count > resource_bounds->maximum_undo_shards) return false;
    blob_out.clear();
    blob_out.reserve(manifest.total_size);
    for (uint32_t shard_index = 0; shard_index < manifest.shard_count; ++shard_index) {
        Coin shard_coin;
        valtype shard_data;
        if (!view.GetCoin(ActiveSignalUndoShardOutpoint(manifest.block_hash, shard_index), shard_coin) ||
            shard_coin.IsSpent() || shard_coin.out.nValue != 0 ||
            !shard_coin.fCoinBase || shard_coin.fCoinStake ||
            shard_coin.nHeight != undo_coin.nHeight || shard_coin.nTime != undo_coin.nTime ||
            shard_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
            !DecodeBlobShard(shard_coin.out.scriptPubKey, MARKER_ACTIVE_SIGNAL_UNDO_SHARD,
                             manifest.block_hash, shard_index, manifest.shard_count,
                             manifest.total_size, shard_data)) return false;
        blob_out.insert(blob_out.end(), shard_data.begin(), shard_data.end());
    }
    return blob_out.size() == manifest.total_size &&
           HashStateBlob("Quantum Quasar Active Signal Undo Blob v1", blob_out) == manifest.blob_hash;
}

bool WriteActiveSignalStateChange(CCoinsViewCache& view, const CBlockIndex* pindex,
                                  bool prior_present, uint32_t prior_height, uint32_t prior_time,
                                  const uint256& prior_hash,
                                  const std::map<CScript, ShadowActiveSignal>& prior,
                                  const std::map<CScript, ShadowActiveSignal>& next)
{
    if (!pindex) return false;
    const auto resource_bounds =
        ReadAuthenticatedWhitelistResourceBounds(view, pindex);
    if (!resource_bounds ||
        prior.size() > resource_bounds->whitelist_entries ||
        next.size() > resource_bounds->whitelist_entries) return false;
    CScript state_manifest_script;
    std::vector<CScript> state_shard_scripts;
    if (!BuildActiveSignalStateScripts(next, pindex->GetBlockHash(),
                                       resource_bounds->maximum_state_bytes,
                                       state_manifest_script, state_shard_scripts)) return false;

    ShadowActiveSignalUndo undo;
    undo.state_was_present = prior_present;
    undo.previous_marker_height = prior_present ? prior_height : 0;
    undo.previous_marker_time = prior_present ? prior_time : 0;
    undo.previous_marker_hash = prior_present ? prior_hash : uint256{};
    undo.block_hash = pindex->GetBlockHash();
    undo.previous_block_hash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{};
    if (!HashActiveSignalState(prior_present, undo.previous_marker_height,
                               undo.previous_marker_time, undo.previous_marker_hash,
                               prior, undo.pre_state_hash) ||
        !HashActiveSignalState(true, pindex->nHeight, pindex->GetBlockTime(),
                               pindex->GetBlockHash(), next, undo.post_state_hash)) return false;

    auto prior_it = prior.begin();
    auto next_it = next.begin();
    while (prior_it != prior.end() || next_it != next.end()) {
        if (next_it == next.end() || (prior_it != prior.end() && prior_it->first < next_it->first)) {
            undo.previous_entries.emplace(prior_it->first, prior_it->second);
            ++prior_it;
        } else if (prior_it == prior.end() || next_it->first < prior_it->first) {
            undo.previous_entries.emplace(next_it->first, std::nullopt);
            ++next_it;
        } else {
            if (!ActiveSignalEqual(prior_it->second, next_it->second)) {
                undo.previous_entries.emplace(prior_it->first, prior_it->second);
            }
            ++prior_it;
            ++next_it;
        }
    }

    CScript undo_manifest_script;
    std::vector<CScript> undo_shard_scripts;
    if (!BuildActiveSignalUndoScripts(undo,
                                      resource_bounds->maximum_undo_bytes,
                                      undo_manifest_script,
                                      undo_shard_scripts)) return false;
    const COutPoint undo_outpoint = ActiveSignalUndoOutpoint(pindex);
    if (view.HaveCoin(undo_outpoint)) return false;

    const COutPoint state_outpoint = ActiveSignalSetOutpoint();
    if (prior_present != view.HaveCoin(state_outpoint)) return false;
    if (prior_present) SpendActiveSignalStateCoins(view, prior_hash, prior);

    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = std::move(state_manifest_script);
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(state_outpoint, std::move(coin), true);
    for (uint32_t shard_index = 0; shard_index < state_shard_scripts.size(); ++shard_index) {
        Coin shard_coin;
        shard_coin.out.nValue = 0;
        shard_coin.out.scriptPubKey = std::move(state_shard_scripts[shard_index]);
        shard_coin.fCoinBase = true;
        shard_coin.fCoinStake = false;
        shard_coin.nHeight = pindex->nHeight;
        shard_coin.nTime = pindex->GetBlockTime();
        view.AddCoin(ActiveSignalShardOutpoint(pindex->GetBlockHash(), shard_index), std::move(shard_coin), true);
    }

    Coin undo_coin;
    undo_coin.out.nValue = 0;
    undo_coin.out.scriptPubKey = std::move(undo_manifest_script);
    undo_coin.fCoinBase = true;
    undo_coin.fCoinStake = false;
    undo_coin.nHeight = pindex->nHeight;
    undo_coin.nTime = pindex->GetBlockTime();
    view.AddCoin(undo_outpoint, std::move(undo_coin), true);
    for (uint32_t shard_index = 0; shard_index < undo_shard_scripts.size(); ++shard_index) {
        Coin shard_coin;
        shard_coin.out.nValue = 0;
        shard_coin.out.scriptPubKey = std::move(undo_shard_scripts[shard_index]);
        shard_coin.fCoinBase = true;
        shard_coin.fCoinStake = false;
        shard_coin.nHeight = pindex->nHeight;
        shard_coin.nTime = pindex->GetBlockTime();
        view.AddCoin(ActiveSignalUndoShardOutpoint(pindex->GetBlockHash(), shard_index), std::move(shard_coin), true);
    }
    return true;
}

bool UndoActiveSignalMarkers(CCoinsViewCache& view, const CBlockIndex* pindex,
                             bool expected_previous_present)
{
    if (!pindex) return false;
    const auto resource_bounds =
        ReadAuthenticatedWhitelistResourceBounds(view, pindex);
    if (!resource_bounds) return false;
    // Remove obsolete append-only compatibility markers if an old prerelease
    // chainstate is being inspected. They are never used to authorize state.
    for (uint32_t marker_index = 0;
         marker_index < resource_bounds->whitelist_entries;
         ++marker_index) {
        const COutPoint outpoint = ActiveSignalOutpoint(pindex, marker_index);
        if (!view.HaveCoin(outpoint)) break;
        view.SpendCoin(outpoint);
    }

    const COutPoint undo_outpoint = ActiveSignalUndoOutpoint(pindex);
    Coin undo_coin;
    if (!view.GetCoin(undo_outpoint, undo_coin) || undo_coin.IsSpent()) {
        Coin state_coin;
        // A block without a signal delta is valid only when it inherited an
        // authenticated state from an earlier transition. The first state
        // transition always has an undo record.
        return expected_previous_present &&
               view.GetCoin(ActiveSignalSetOutpoint(), state_coin) &&
               !state_coin.IsSpent() &&
               state_coin.nHeight < static_cast<uint32_t>(pindex->nHeight);
    }
    if (undo_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
        undo_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime())) return false;
    valtype undo_blob;
    ShadowActiveSignalUndo undo;
    if (!ReadActiveSignalUndoBlob(view, pindex, undo_coin, undo_blob) ||
        !DecodeActiveSignalUndoPayload(
            undo_blob, undo, resource_bounds->whitelist_entries) ||
        undo.state_was_present != expected_previous_present ||
        undo.block_hash != pindex->GetBlockHash() ||
        undo.previous_block_hash != (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{})) return false;
    for (const auto& [target, previous] : undo.previous_entries) {
        if (!IsLegacyShadowTargetScript(target) || !IsWhitelisted(view, target) ||
            (previous && previous->target != target)) return false;
    }

    std::map<CScript, ShadowActiveSignal> current;
    uint32_t current_marker_height{0};
    uint32_t current_marker_time{0};
    uint256 current_marker_hash;
    if (ReadActiveSignalStateMarker(view, pindex, current, current_marker_height,
                                    current_marker_time, current_marker_hash) != ActiveSignalStateReadResult::VALID ||
        current_marker_height != static_cast<uint32_t>(pindex->nHeight) ||
        current_marker_time != static_cast<uint32_t>(pindex->GetBlockTime()) ||
        current_marker_hash != pindex->GetBlockHash()) return false;
    uint256 current_hash;
    if (!HashActiveSignalState(true, current_marker_height, current_marker_time,
                               current_marker_hash, current, current_hash) ||
        current_hash != undo.post_state_hash) return false;

    std::map<CScript, ShadowActiveSignal> restored = current;
    for (const auto& [target, previous] : undo.previous_entries) {
        if (previous) {
            restored[target] = *previous;
        } else {
            restored.erase(target);
        }
    }
    uint256 restored_hash;
    if (!HashActiveSignalState(undo.state_was_present, undo.previous_marker_height,
                               undo.previous_marker_time, undo.previous_marker_hash,
                               restored, restored_hash) ||
        restored_hash != undo.pre_state_hash) return false;

    SpendActiveSignalStateCoins(view, current_marker_hash, current);
    if (undo.state_was_present) {
        if (!pindex->pprev || undo.previous_marker_height > static_cast<uint32_t>(pindex->pprev->nHeight)) return false;
        const CBlockIndex* marker_block = SafeGetAncestor(pindex->pprev, static_cast<int>(undo.previous_marker_height));
        if (!marker_block || undo.previous_marker_time != static_cast<uint32_t>(marker_block->GetBlockTime()) ||
            undo.previous_marker_hash != marker_block->GetBlockHash()) return false;
        CScript restored_manifest_script;
        std::vector<CScript> restored_shard_scripts;
        if (!BuildActiveSignalStateScripts(restored, undo.previous_marker_hash,
                                           resource_bounds->maximum_state_bytes,
                                           restored_manifest_script, restored_shard_scripts)) return false;
        Coin restored_coin;
        restored_coin.out.nValue = 0;
        restored_coin.out.scriptPubKey = std::move(restored_manifest_script);
        restored_coin.fCoinBase = true;
        restored_coin.fCoinStake = false;
        restored_coin.nHeight = undo.previous_marker_height;
        restored_coin.nTime = undo.previous_marker_time;
        view.AddCoin(ActiveSignalSetOutpoint(), std::move(restored_coin), true);
        for (uint32_t shard_index = 0; shard_index < restored_shard_scripts.size(); ++shard_index) {
            Coin shard_coin;
            shard_coin.out.nValue = 0;
            shard_coin.out.scriptPubKey = std::move(restored_shard_scripts[shard_index]);
            shard_coin.fCoinBase = true;
            shard_coin.fCoinStake = false;
            shard_coin.nHeight = undo.previous_marker_height;
            shard_coin.nTime = undo.previous_marker_time;
            view.AddCoin(ActiveSignalShardOutpoint(undo.previous_marker_hash, shard_index), std::move(shard_coin), true);
        }
    } else if (!restored.empty()) {
        // Absence of the predecessor marker is authenticated by the undo hash.
        // It is valid only when disconnecting the first state transition.
        return false;
    }
    const uint32_t undo_shard_count = BlobShardCount(undo_blob.size());
    for (uint32_t shard_index = 0; shard_index < undo_shard_count; ++shard_index) {
        const COutPoint shard_outpoint = ActiveSignalUndoShardOutpoint(pindex->GetBlockHash(), shard_index);
        if (!view.HaveCoin(shard_outpoint)) return false;
        view.SpendCoin(shard_outpoint);
    }
    view.SpendCoin(undo_outpoint);
    return true;
}

} // namespace

bool ShadowActiveSignalPoolPairValidForTesting(const Consensus::Params& consensus,
                                               const CBlockIndex* pindex,
                                               bool pool_present,
                                               bool signal_present)
{
    return ActiveSignalPoolPairValid(
        consensus, pindex,
        pool_present ? ShadowPoolReadResult::VALID : ShadowPoolReadResult::MISSING,
        signal_present ? ActiveSignalStateReadResult::VALID : ActiveSignalStateReadResult::MISSING);
}

bool AdvanceGoldRushInventoryTip(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    return AdvanceGoldRushInventoryTipInternal(view, pindex);
}

bool RewindGoldRushInventoryTip(CCoinsViewCache& view, const CBlockIndex* disconnected)
{
    return RewindGoldRushInventoryTipInternal(view, disconnected);
}

uint64_t GetActiveShadowSignalCount(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return 0;
    return ReadActiveShadowSignals(view, pindex, pindex->nHeight).size();
}

std::map<CScript, CScript> GetActiveShadowSignalPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex) return {};
    return ActiveSignalPayoutScripts(ReadActiveShadowSignals(view, pindex, pindex->nHeight));
}

CAmount ShadowBaseReward(int height)
{
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return 0;
    const int blocks_since_snapshot = height - SHADOW_REWARD_START_HEIGHT;
    if (height <= SHADOW_PHASE1_END_HEIGHT) {
        const int halvings = blocks_since_snapshot / std::max(1, SHADOW_HALVING_INTERVAL_BLOCKS);
        return (580 * COIN) >> halvings;
    }
    return 463 * COIN;
}

std::optional<CAmount> GetScheduledShadowEmissionThrough(int last_height)
{
    if (SHADOW_REWARD_START_HEIGHT < 0 ||
        SHADOW_REWARD_END_HEIGHT < SHADOW_REWARD_START_HEIGHT ||
        SHADOW_PHASE1_END_HEIGHT < SHADOW_REWARD_START_HEIGHT ||
        SHADOW_PHASE1_END_HEIGHT > SHADOW_REWARD_END_HEIGHT ||
        SHADOW_HALVING_INTERVAL_BLOCKS < 1) {
        return std::nullopt;
    }

    const int end = std::min(last_height, SHADOW_REWARD_END_HEIGHT);
    if (end < SHADOW_REWARD_START_HEIGHT) return CAmount{0};

    CAmount total{0};
    for (int64_t height = SHADOW_REWARD_START_HEIGHT; height <= end; ++height) {
        const CAmount reward = ShadowBaseReward(static_cast<int>(height));
        const auto next = CheckedAddMoney(total, reward);
        if (!next) return std::nullopt;
        total = *next;
    }
    return total;
}

const std::string& GetQuantumQuasarBlockNotice()
{
    static const std::string notice =
        "Quantum Quasar V30 Gold Rush is live. Upgrade now; the 18-month legacy migration begins after Gold Rush. Source: https://github.com/blackcoin-dev/blackcoin";
    return notice;
}

CScript BuildQuantumQuasarBlockNoticeScript()
{
    const std::string& notice = GetQuantumQuasarBlockNotice();
    return CScript{} << OP_RETURN << valtype{notice.begin(), notice.end()};
}

CAmount ShadowMaxBlockDirectTotal(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) {
        return 0;
    }
    // Carried pool as it stands BEFORE this block is applied, plus this block's scheduled
    // credit. This is the largest value the block could legally pay out.
    bool pool_state_valid{true};
    const ShadowPoolState pool = ReadPool(view, &pool_state_valid);
    if (!pool_state_valid) return 0;
    const auto carried = CheckedAddMoney(pool.pow_amount, pool.pos_amount);
    if (!carried) return 0;
    const auto bound = CheckedAddMoney(*carried, ShadowBaseReward(pindex->nHeight));
    if (!bound) return 0;
    return *bound;
}

ShadowGoldRushInfo GetShadowGoldRushInfo(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    const ShadowPoolState pool = ReadPool(view);
    ShadowGoldRushInfo info;
    info.pow_amount = pool.pow_amount;
    info.pos_amount = pool.pos_amount;
    info.claimed_amount = pool.claimed_amount;
    info.pow_count = pool.pow_count;
    info.pos_count = pool.pos_count;
    info.last_pow_height = pool.last_pow_height;
    info.last_pos_height = pool.last_pos_height;
    info.recent_count = pool.recent_count;
    info.recent_modes = pool.recent_modes;
    info.pow_target_bits = pindex ? RetargetedBits(ShadowProofMode::POW, pool, pindex->nHeight + 1) : RetargetedBits(ShadowProofMode::POW, pool, 0);
    return info;
}

ScopedDisallowShadowSolverActivityFullScan::ScopedDisallowShadowSolverActivityFullScan()
    : m_previous(g_shadow_solver_activity_full_scan_disallowed)
{
    g_shadow_solver_activity_full_scan_disallowed = true;
}

ScopedDisallowShadowSolverActivityFullScan::~ScopedDisallowShadowSolverActivityFullScan()
{
    g_shadow_solver_activity_full_scan_disallowed = m_previous;
}

std::map<CScript, ShadowSolverActivity> GetRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex)
{
    // A full chainstate cursor is diagnostic-only. Latency-sensitive callers
    // install ScopedDisallowShadowSolverActivityFullScan, and their functional
    // tests fail immediately if a future change routes them back here.
    assert(!g_shadow_solver_activity_full_scan_disallowed);
    std::map<CScript, ShadowSolverActivity> activity;
    if (!pindex) return activity;

    const int tip_height = pindex->nHeight;
    const int64_t tip_time = pindex->GetBlockTime();
    WhitelistManifest whitelist_manifest;
    std::set<CScript> whitelist;
    if (!ReadWhitelistManifest(view, pindex, whitelist_manifest, &whitelist)) return activity;
    std::map<uint256, CScript> solvers_by_hash;
    for (const CScript& script : whitelist) {
        solvers_by_hash.emplace(TaggedHash("Quantum Quasar Solver Target v2", {script.begin(), script.end()}), script);
    }
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            uint256 solver_hash;
            if (DecodeSolverMarkerHash(coin.out.scriptPubKey, solver_hash)) {
                const int coin_height = static_cast<int>(coin.nHeight);
                const int64_t coin_time = static_cast<int64_t>(coin.nTime);
                const CBlockIndex* marker_block = SafeGetAncestor(pindex, coin_height);
                if (!marker_block) {
                    cursor->Next();
                    continue;
                }
                const auto solver_it = solvers_by_hash.find(solver_hash);
                if (solver_it == solvers_by_hash.end()) {
                    cursor->Next();
                    continue;
                }
                const CScript& solver = solver_it->second;
                if (outpoint != SolverOutpoint(solver, coin.nHeight, marker_block->GetBlockHash())) {
                    cursor->Next();
                    continue;
                }
                if (coin_height <= tip_height &&
                    tip_height - coin_height <= SHADOW_SOLVER_ACTIVITY_WINDOW &&
                    coin_time <= tip_time &&
                    tip_time - coin_time <= SHADOW_SOLVER_ACTIVITY_SECONDS) {
                    if (!solver.empty() && !solver.IsUnspendable()) {
                        ShadowSolverActivity& entry = activity[solver];
                        if (coin.nHeight > entry.height) {
                            entry.height = coin.nHeight;
                            entry.time = coin_time;
                        }
                    }
                }
            }
        }
        cursor->Next();
    }
    return activity;
}

std::optional<ShadowSolverActivity> GetRecentShadowSolverActivityForScript(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target)
{
    if (!pindex || target.empty() || target.IsUnspendable()) return std::nullopt;

    const int tip_height = pindex->nHeight;
    const int64_t tip_time = pindex->GetBlockTime();
    for (const CBlockIndex* cursor = pindex;
         cursor && cursor->nHeight <= tip_height && tip_height - cursor->nHeight <= SHADOW_SOLVER_ACTIVITY_WINDOW;
         cursor = cursor->pprev) {
        Coin coin;
        if (!view.GetCoin(SolverOutpoint(target, cursor->nHeight, cursor->GetBlockHash()), coin) || coin.IsSpent()) continue;

        if (!SolverMarkerMatches(coin.out.scriptPubKey, target)) continue;

        const int coin_height = static_cast<int>(coin.nHeight);
        const int64_t coin_time = static_cast<int64_t>(coin.nTime);
        if (coin_height > tip_height || tip_height - coin_height > SHADOW_SOLVER_ACTIVITY_WINDOW) continue;
        if (coin_time > tip_time || tip_time - coin_time > SHADOW_SOLVER_ACTIVITY_SECONDS) continue;
        return ShadowSolverActivity{coin.nHeight, coin_time};
    }
    return std::nullopt;
}

bool HasRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash)
{
    // Wallet/mempool callers validate a transaction for the next block using
    // the current active tip, so its marker is already signalable. Consensus
    // block evaluation keeps the stricter default above and cannot accept a
    // transaction that claims the block containing that transaction.
    return SignalReferencesRecentSolve(view, pindex, target, solve_height, solve_hash, /*allow_tip_solve=*/true);
}

bool GetShadowPosDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    bool pool_state_valid{true};
    ShadowPoolState pool = ReadPool(view, &pool_state_valid);
    if (!pool_state_valid) return false;
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pos_reward = reward - reward / 2;
    const auto next_pos_amount = CheckedAddMoney(pool.pos_amount, pos_reward);
    if (!next_pos_amount) return false;
    pool.pos_amount = *next_pos_amount;

    const std::optional<CScript> current_solver = GetCurrentSolverScript(view, block, blockundo);
    bool signal_state_valid{true};
    std::map<CScript, ShadowActiveSignal> active_signal_state =
        ReadActiveShadowSignals(view, pindex->pprev, pindex->nHeight, &signal_state_valid);
    if (!signal_state_valid) return false;
    const std::map<CScript, CScript> current_signals =
        FindValidShadowSignalsInBlock(view, block, pindex, blockundo);
    UpsertActiveSignals(active_signal_state, current_signals, pindex->nHeight);
    const std::map<CScript, CScript> active_signals = ActiveSignalPayoutScripts(active_signal_state);
    return BuildPosPayouts(pool, current_solver, active_signals, /*require_quantum_payouts=*/true, payouts_out, total_out);
}

bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, const Consensus::Params& consensus, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    bool pool_state_valid{true};
    ShadowPoolState pool = ReadPool(view, &pool_state_valid);
    if (!pool_state_valid) return false;
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pow_reward = reward / 2;
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, pow_reward);
    if (!next_pow_amount) return false;
    pool.pow_amount = *next_pow_amount;

    ShadowPowClaimResult pow_claim = FindPowShadowClaims(
        view, block, pindex, blockundo, pool, consensus);
    if (pow_claim.internal_error) return false;
    for (const ShadowPowCredit& credit : pow_claim.credits) {
        if (!IsDirectQuantumMigrationScript(credit.payout_script)) return false;
        const auto next_total = CheckedAddMoney(total_out, credit.amount);
        const auto next_script = CheckedAddMoney(
            payouts_out[credit.payout_script], credit.amount);
        if (!next_total || !next_script) return false;
        total_out = *next_total;
        payouts_out[credit.payout_script] = *next_script;
    }
    return MoneyRange(total_out);
}

bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    return GetShadowPowDirectPayouts(view, block, pindex, blockundo,
                                     Params().GetConsensus(), payouts_out,
                                     total_out);
}

ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    const Consensus::Params& consensus,
    ShadowPowAccountingContext& context_out)
{
    context_out = {};
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT ||
        pindex->nHeight > SHADOW_REWARD_END_HEIGHT) {
        return ShadowPowAccountingResult::OK;
    }

    // The helper serves both ConnectBlock's pre-application view and an
    // indexer's later active-tip view. Prefer the authenticated per-block undo
    // whenever it exists; otherwise require the fixed pool marker to be the
    // exact predecessor state. Never interpret an arbitrary current-tip pool
    // as historical pre-state.
    ShadowPoolState pool;
    Coin pool_undo_coin;
    const COutPoint pool_undo_outpoint = PoolUndoOutpoint(pindex);
    if (view.GetCoin(pool_undo_outpoint, pool_undo_coin) && !pool_undo_coin.IsSpent()) {
        ShadowPoolUndoState pool_undo;
        if (pool_undo_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
            pool_undo_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
            !DecodePoolUndo(pool_undo_coin.out.scriptPubKey, pool_undo) ||
            pool_undo.block_hash != pindex->GetBlockHash() ||
            pool_undo.previous_block_hash !=
                (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}) ||
            !PoolUndoClaimCountWithinBound(view, pindex, consensus, pool_undo)) {
            return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
        }
        pool = pool_undo.previous;
    } else if (pindex->nHeight == SHADOW_REWARD_START_HEIGHT) {
        Coin predecessor_pool_coin;
        if (view.GetCoin(PoolOutpoint(), predecessor_pool_coin) &&
            !predecessor_pool_coin.IsSpent()) {
            return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
        }
    } else {
        Coin predecessor_pool_coin;
        bool pool_state_valid{true};
        pool = ReadPool(view, &pool_state_valid);
        const CBlockIndex* predecessor_pool_block =
            pool_state_valid && pindex->pprev &&
                    view.GetCoin(PoolOutpoint(), predecessor_pool_coin) &&
                    !predecessor_pool_coin.IsSpent() &&
                    predecessor_pool_coin.nHeight <= static_cast<uint32_t>(pindex->pprev->nHeight)
                ? SafeGetAncestor(pindex->pprev,
                                  static_cast<int>(predecessor_pool_coin.nHeight))
                : nullptr;
        if (!pool_state_valid || !pindex->pprev ||
            !predecessor_pool_block ||
            predecessor_pool_coin.nTime !=
                static_cast<uint32_t>(predecessor_pool_block->GetBlockTime())) {
            return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
        }
    }
    const auto next_pow_amount = CheckedAddMoney(
        pool.pow_amount, ShadowBaseReward(pindex->nHeight) / 2);
    if (!next_pow_amount) return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
    pool.pow_amount = *next_pow_amount;

    context_out.height = pindex->nHeight;
    context_out.previous_block_hash = pindex->pprev
        ? pindex->pprev->GetBlockHash() : uint256{};
    context_out.credited_pow_pool = pool.pow_amount;
    context_out.target_bits = RetargetedBits(ShadowProofMode::POW, pool,
                                             pindex->nHeight);
    context_out.canonical_rule_active =
        consensus.IsShadowCompetingClaimsActive(pindex->nHeight);
    context_out.valid = true;
    return ShadowPowAccountingResult::OK;
}

ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    ShadowPowAccountingContext& context_out)
{
    return PrepareShadowPowClaimAccounting(view, pindex,
                                            Params().GetConsensus(),
                                            context_out);
}

ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block,
    const CBlockIndex* pindex, const Consensus::Params& consensus,
    ShadowPowAccountingContext& context_out)
{
    const ShadowPowAccountingResult base_result =
        PrepareShadowPowClaimAccounting(view, pindex, consensus, context_out);
    if (base_result != ShadowPowAccountingResult::OK || !context_out.valid ||
        !context_out.canonical_rule_active) return base_result;

    const std::vector<CanonicalPowCandidate> candidates =
        SelectCanonicalPowCandidates(block, context_out);
    context_out.late_origins.reserve(candidates.size());
    for (const CanonicalPowCandidate& candidate : candidates) {
        ShadowProof decoded;
        if (!DecodeProof(candidate.proof, decoded) || !decoded.origin_bound ||
            decoded.origin_height >= static_cast<uint32_t>(context_out.height) ||
            !consensus.IsShadowCompetingClaimsActive(
                static_cast<int>(decoded.origin_height))) continue;
        const uint32_t age = static_cast<uint32_t>(context_out.height) -
                             decoded.origin_height;
        if (age > SHADOW_POW_LATE_ORIGIN_WINDOW) continue;
        const CBlockIndex* origin_parent = SafeGetAncestor(
            pindex ? pindex->pprev : nullptr,
            static_cast<int>(decoded.origin_height) - 1);
        if (!origin_parent ||
            origin_parent->GetBlockHash() !=
                decoded.origin_previous_block_hash) continue;
        if (std::any_of(context_out.late_origins.begin(),
                        context_out.late_origins.end(),
                        [&](const ShadowPowOriginContext& origin) {
                            return origin.height == decoded.origin_height &&
                                   origin.previous_block_hash ==
                                       decoded.origin_previous_block_hash;
                        })) continue;

        const CBlockIndex* origin_block = SafeGetAncestor(
            pindex ? pindex->pprev : nullptr,
            static_cast<int>(decoded.origin_height));
        const std::optional<ShadowPoolUndoState> undo =
            ReadAuthenticatedPoolUndo(view, origin_block, consensus);
        // Once height and parent match the active ancestor this marker is
        // mandatory authenticated chainstate. Missing/corrupt state is a
        // local replay failure, not an attacker-selected claim mismatch.
        if (!undo) return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
        ShadowPoolState origin_pool = undo->previous;
        const auto origin_pow_amount = CheckedAddMoney(
            origin_pool.pow_amount,
            ShadowBaseReward(static_cast<int>(decoded.origin_height)) / 2);
        if (!origin_pow_amount) {
            return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
        }
        origin_pool.pow_amount = *origin_pow_amount;
        context_out.late_origins.push_back(ShadowPowOriginContext{
            decoded.origin_height, decoded.origin_previous_block_hash,
            RetargetedBits(ShadowProofMode::POW, origin_pool,
                           static_cast<int>(decoded.origin_height))});
    }
    return ShadowPowAccountingResult::OK;
}

ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block,
    const CBlockIndex* pindex, ShadowPowAccountingContext& context_out)
{
    return PrepareShadowPowClaimAccounting(
        view, block, pindex, Params().GetConsensus(), context_out);
}

ShadowPowAccountingResult EvaluateShadowPowClaimAccounting(
    const ShadowPowAccountingContext& context, const CBlock& block,
    const CBlockUndo* blockundo,
    std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out)
{
    accounting_out.clear();
    if (aggregate_out) *aggregate_out = {};
    if (!context.valid || !context.canonical_rule_active) {
        return ShadowPowAccountingResult::OK;
    }
    ShadowPowClaimResult result = FindCanonicalPowShadowClaims(
        block, blockundo, context);
    if (result.internal_error) {
        // Index and RPC callers must not mistake a prefix produced before a
        // local failure for durable classification. The identical block is
        // evaluated from scratch after restart/retry.
        return ShadowPowAccountingResult::LOCAL_INTERNAL_ERROR;
    }
    accounting_out = std::move(result.accounting);
    if (aggregate_out) *aggregate_out = result.aggregate;
    return ShadowPowAccountingResult::OK;
}

ShadowPowAccountingResult GetShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex,
    const CBlockUndo* blockundo, const Consensus::Params& consensus,
    std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out)
{
    ShadowPowAccountingContext context;
    const ShadowPowAccountingResult prepare_result =
        PrepareShadowPowClaimAccounting(view, block, pindex, consensus, context);
    if (prepare_result != ShadowPowAccountingResult::OK) {
        accounting_out.clear();
        if (aggregate_out) *aggregate_out = {};
        return prepare_result;
    }
    return EvaluateShadowPowClaimAccounting(context, block, blockundo,
                                             accounting_out, aggregate_out);
}

ShadowPowAccountingResult GetShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex,
    const CBlockUndo* blockundo,
    std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out)
{
    return GetShadowPowClaimAccounting(view, block, pindex, blockundo,
                                       Params().GetConsensus(), accounting_out,
                                       aggregate_out);
}

bool CheckShadowDirectPayoutOutputs(const CTransaction& tx, const std::map<CScript, CAmount>& expected_payouts, std::string& reject_reason)
{
    if (expected_payouts.empty()) return true;

    std::set<CScript> paid;
    for (const CTxOut& txout : tx.vout) {
        const auto it = expected_payouts.find(txout.scriptPubKey);
        if (it == expected_payouts.end()) continue;
        if (!MoneyRange(txout.nValue) || txout.nValue != it->second || paid.count(txout.scriptPubKey)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
        paid.insert(txout.scriptPubKey);
    }

    for (const auto& [script, amount] : expected_payouts) {
        if (amount <= 0 || !MoneyRange(amount)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
        if (!paid.count(script)) {
            reject_reason = "bad-shadow-payout";
            return false;
        }
    }
    return true;
}

bool GetAppliedShadowDirectPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex, std::map<CScript, CAmount>& payouts_out, CAmount& total_out)
{
    payouts_out.clear();
    total_out = 0;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;

    for (const COutPoint& claim_outpoint : FindDeterministicClaimMarkers(view, pindex)) {
        Coin claim_coin;
        if (!view.GetCoin(claim_outpoint, claim_coin)) return false;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount)) return false;
        CAmount& current = payouts_out[claim->target];
        const auto next = CheckedAddMoney(current, claim->amount);
        if (!next) return false;
        current = *next;
        const auto next_total = CheckedAddMoney(total_out, claim->amount);
        if (!next_total) return false;
        total_out = *next_total;
    }
    return MoneyRange(total_out);
}

bool DecodeShadowClaimMarker(const CTxOut& txout, ShadowClaimMarkerInfo& info)
{
    info = {};
    const auto claim = DecodeClaimScript(txout.scriptPubKey);
    if (!claim || !claim->direct || claim->amount <= 0 || !MoneyRange(claim->amount) ||
        !IsDirectQuantumMigrationScript(claim->target)) {
        return false;
    }
    info.target = claim->target;
    info.amount = claim->amount;
    info.proof_of_work = claim->mode == ShadowProofMode::POW;
    return true;
}

bool IsShadowMarkerScript(const CScript& script)
{
    return ParseMarkerScript(script, MARKER_WHITELIST) ||
           ParseMarkerScript(script, MARKER_WHITELIST_READY) ||
           ParseMarkerScript(script, MARKER_WHITELIST_MANIFEST) ||
           ParseMarkerScript(script, MARKER_WHITELIST_SHARD) ||
           ParseMarkerScript(script, MARKER_POOL) ||
           ParseMarkerScript(script, MARKER_POOL_UNDO) ||
           ParseMarkerScript(script, MARKER_DIRECT_CLAIM) ||
           ParseMarkerScript(script, MARKER_GOLD_RUSH_PAYOUT) ||
           ParseMarkerScript(script, MARKER_GOLD_RUSH_SPENT) ||
           ParseMarkerScript(script, MARKER_GOLD_RUSH_INVENTORY) ||
           ParseMarkerScript(script, MARKER_SOLVER) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_SET) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_SHARD) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_UNDO) ||
           ParseMarkerScript(script, MARKER_ACTIVE_SIGNAL_UNDO_SHARD) ||
           ParseMarkerScript(script, MARKER_REPLAY_STATE);
}

void WriteShadowReplayStateMarker(CCoinsViewCache& view, const CBlockIndex* pindex, const Consensus::Params& consensus)
{
    if (!pindex || pindex->nHeight < SHADOW_WHITELIST_HEIGHT) return;
    const COutPoint outpoint = ReplayStateOutpoint();
    if (view.HaveCoin(outpoint)) view.SpendCoin(outpoint);
    Coin coin;
    coin.out.nValue = 0;
    coin.out.scriptPubKey = MarkerScript(MARKER_REPLAY_STATE, ReplayStateFingerprint(consensus, pindex, view));
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = pindex->nHeight;
    coin.nTime = pindex->GetBlockTime();
    view.AddCoin(outpoint, std::move(coin), true);
}

void RewindShadowReplayStateMarker(CCoinsViewCache& view, const CBlockIndex* disconnected, const Consensus::Params& consensus)
{
    const COutPoint outpoint = ReplayStateOutpoint();
    if (view.HaveCoin(outpoint)) view.SpendCoin(outpoint);
    if (disconnected && disconnected->pprev && disconnected->pprev->nHeight >= SHADOW_WHITELIST_HEIGHT) {
        WriteShadowReplayStateMarker(view, disconnected->pprev, consensus);
    }
}

static bool ValidateCanonicalShadowReplayStateMarker(
    const Coin& coin, const CBlockIndex* pindex, valtype& payload,
    const CBlockIndex*& marker_block)
{
    marker_block = nullptr;
    payload.clear();
    if (!pindex || pindex->nHeight < 0 || coin.IsSpent() ||
        coin.nHeight > static_cast<uint32_t>(pindex->nHeight)) {
        return false;
    }

    marker_block = SafeGetAncestor(pindex, static_cast<int>(coin.nHeight));
    if (!marker_block || coin.out.nValue != 0 || !coin.fCoinBase ||
        coin.fCoinStake ||
        coin.nTime != static_cast<uint32_t>(marker_block->GetBlockTime()) ||
        coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !ParseMarkerScript(coin.out.scriptPubKey, MARKER_REPLAY_STATE, &payload) ||
        payload.size() != uint256::size()) {
        return false;
    }

    // General marker discovery accepts non-minimal pushes. QQRSTATE has one
    // exact authenticated encoding.
    return coin.out.scriptPubKey == MarkerScript(MARKER_REPLAY_STATE, payload);
}

bool HasCurrentShadowReplayState(const CCoinsViewCache& view, const Consensus::Params& consensus,
                                 const CBlockIndex* pindex,
                                 const ShadowBlockReader* read_block)
{
    (void)read_block;
    if (!pindex || pindex->nHeight < SHADOW_WHITELIST_HEIGHT) return false;
    if (!HasLegacyWhitelistSnapshot(view)) return false;
    WhitelistManifest whitelist_manifest;
    if (!ReadWhitelistManifest(view, pindex, whitelist_manifest)) return false;
    ShadowPoolState pool;
    const ShadowPoolReadResult pool_result = ReadPoolState(view, pool);
    std::map<CScript, ShadowActiveSignal> active;
    uint32_t marker_height{0};
    uint32_t marker_time{0};
    uint256 marker_hash;
    const ActiveSignalStateReadResult active_state_result =
        ReadActiveSignalStateMarker(view, pindex, active, marker_height, marker_time, marker_hash);
    if (!ActiveSignalPoolPairValid(consensus, pindex, pool_result,
                                   active_state_result)) return false;
    // Normal startup is constant-space and performs no block reads or UTXO
    // cursor scan. The rolling inventory marker and claim/provenance leaves are
    // one logical chainstate transition and are committed by QQRSTATE below;
    // ReplayBlocks rejects an interrupted multi-batch disk flush instead of
    // treating that summary as proof that every leaf reached disk. The
    // exhaustive auditor is reserved for explicit maintenance and migration QA.
    if (!ValidateGoldRushInventorySummary(view, pindex)) return false;
    if (!Consensus::HasCurrentDemurrageInventory(view, pindex, consensus)) return false;
    Coin coin;
    valtype payload;
    const CBlockIndex* marker_block{nullptr};
    return view.GetCoin(ReplayStateOutpoint(), coin) &&
           ValidateCanonicalShadowReplayStateMarker(
               coin, pindex, payload, marker_block) &&
           marker_block == pindex &&
           payload == ReplayStateFingerprint(consensus, pindex, view);
}

bool HasShadowReplayState(const CCoinsViewCache& view)
{
    return view.HaveCoin(ReplayStateOutpoint());
}

ShadowReplayStateInfo GetShadowReplayStateInfo(const CCoinsViewCache& view,
                                               const Consensus::Params& consensus,
                                               const CBlockIndex* pindex)
{
    ShadowReplayStateInfo info;
    info.schema = SHADOW_REPLAY_STATE_VERSION;
    info.required_for_tip = pindex && pindex->nHeight >= SHADOW_WHITELIST_HEIGHT;

    Coin coin;
    if (!view.GetCoin(ReplayStateOutpoint(), coin) || coin.IsSpent()) return info;
    info.present = true;
    info.marker_height = coin.nHeight;
    info.marker_time = coin.nTime;

    valtype payload;
    const CBlockIndex* marker_block{nullptr};
    info.marker_valid = ValidateCanonicalShadowReplayStateMarker(
        coin, pindex, payload, marker_block);
    if (marker_block) info.marker_block_hash = marker_block->GetBlockHash();
    if (info.marker_valid) info.commitment = std::move(payload);
    info.valid_for_tip = info.marker_valid &&
                         HasCurrentShadowReplayState(view, consensus, pindex);
    return info;
}

std::vector<ShadowSyntheticPayoutTransaction> GetAppliedShadowClaimPayoutTransactionRecords(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<ShadowSyntheticPayoutTransaction> payouts;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return payouts;
    const std::optional<std::vector<ShadowClaim>> claims =
        ReadAuthenticatedBlockClaims(view, height, block_hash, block_time);
    if (!claims) return payouts;
    payouts.reserve(claims->size());
    for (uint32_t marker_index = 0; marker_index < claims->size();
         ++marker_index) {
        const ShadowClaim& claim = claims->at(marker_index);
        payouts.push_back(ShadowSyntheticPayoutTransaction{
            BuildClaimPayoutTransaction(height, block_hash, block_time,
                                        marker_index, claim),
            claim.target,
            claim.amount,
            claim.mode == ShadowProofMode::POW,
        });
    }
    return payouts;
}

std::vector<CTransactionRef> GetAppliedShadowClaimPayoutTransactions(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<CTransactionRef> payouts;
    for (const ShadowSyntheticPayoutTransaction& payout : GetAppliedShadowClaimPayoutTransactionRecords(view, height, block_hash, block_time)) {
        payouts.push_back(payout.tx);
    }
    return payouts;
}

std::vector<ShadowSyntheticPayoutCoin> GetAppliedShadowClaimPayoutCoins(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time)
{
    std::vector<ShadowSyntheticPayoutCoin> payouts;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return payouts;
    const std::optional<std::vector<ShadowClaim>> claims =
        ReadAuthenticatedBlockClaims(view, height, block_hash, block_time);
    if (!claims) return payouts;
    payouts.reserve(claims->size());
    for (uint32_t marker_index = 0; marker_index < claims->size();
         ++marker_index) {
        const ShadowClaim& claim = claims->at(marker_index);
        const CTransactionRef payout_tx = BuildClaimPayoutTransaction(
            height, block_hash, block_time, marker_index, claim);
        payouts.push_back(ShadowSyntheticPayoutCoin{
            COutPoint{payout_tx->GetHash(), 0},
            CTxOut{claim.amount, claim.target},
            static_cast<uint32_t>(height),
            block_time,
        });
    }
    return payouts;
}

void MarkGoldRushDirectPayoutOutputs(CCoinsViewCache& view, const CTransaction& coinstake, const CBlockIndex* pindex, const std::map<CScript, CAmount>& payouts)
{
    if (!pindex || payouts.empty()) return;
    const uint256 txid = coinstake.GetHash();
    std::set<CScript> marked;
    for (uint32_t i = 0; i < coinstake.vout.size(); ++i) {
        const CTxOut& txout = coinstake.vout[i];
        const auto it = payouts.find(txout.scriptPubKey);
        if (it == payouts.end() || marked.count(txout.scriptPubKey) || txout.nValue != it->second) continue;

        Coin marker;
        marker.out.nValue = 0;
        marker.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_PAYOUT, {txout.scriptPubKey.begin(), txout.scriptPubKey.end()});
        marker.fCoinBase = true;
        marker.fCoinStake = false;
        marker.nHeight = pindex->nHeight;
        marker.nTime = pindex->GetBlockTime();
        view.AddCoin(GoldRushPayoutOutpoint(COutPoint{txid, i}), std::move(marker), true);
        marked.insert(txout.scriptPubKey);
    }
}

void UndoGoldRushDirectPayoutOutputMarkers(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex)
{
    if (!pindex) return;
    // Always address the reserved outpoints for this concrete block. Replay
    // can disconnect state written under an older test schedule whose reward
    // window no longer matches the current process configuration.
    for (const auto& tx : block.vtx) {
        const uint256 txid = tx->GetHash();
        for (uint32_t i = 0; i < tx->vout.size(); ++i) {
            view.SpendCoin(GoldRushPayoutOutpoint(COutPoint{txid, i}));
        }
    }
}

namespace {

bool AuthenticateGoldRushPayoutRecord(const CCoinsViewCache& view, const COutPoint& outpoint,
                                      GoldRushPayoutRecord& record, CScript* payout_script,
                                      const CBlockIndex* pindex_tip)
{
    Coin payout;
    const bool has_payout = view.GetCoin(outpoint, payout) && !payout.IsSpent();
    Coin marker;
    valtype payload;
    if (!view.GetCoin(GoldRushPayoutOutpoint(outpoint), marker) || marker.IsSpent() ||
        marker.out.nValue != 0 || !marker.fCoinBase || marker.fCoinStake ||
        !ParseMarkerScript(marker.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT, &payload) ||
        !DecodeGoldRushPayoutRecordPayload(payload, record) ||
        record.payout_outpoint != outpoint || marker.nHeight != record.origin_height ||
        (has_payout && (marker.nHeight != payout.nHeight || marker.nTime != payout.nTime))) {
        return false;
    }

    const CBlockIndex* origin_block = pindex_tip
        ? SafeGetAncestor(pindex_tip, static_cast<int>(record.origin_height))
        : nullptr;
    if (pindex_tip && (!origin_block || origin_block->GetBlockHash() != record.origin_block_hash ||
                       marker.nTime != static_cast<uint32_t>(origin_block->GetBlockTime()))) {
        return false;
    }

    Coin claim_coin;
    const COutPoint claim_outpoint = ClaimOutpoint(record.origin_height,
                                                   record.origin_block_hash,
                                                   record.claim_index);
    if (!view.GetCoin(claim_outpoint, claim_coin) || claim_coin.IsSpent() ||
        claim_coin.out.nValue != 0 || !claim_coin.fCoinBase || claim_coin.fCoinStake ||
        claim_coin.nHeight != record.origin_height || claim_coin.nTime != marker.nTime) {
        return false;
    }
    const std::optional<ShadowClaim> claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
    if (!claim || !claim->direct || HashGoldRushClaim(*claim) != record.claim_hash ||
        claim->amount != record.nominal_amount || claim->mode != record.mode ||
        claim->target != record.target) {
        return false;
    }
    const COutPoint deterministic_payout{
        BuildClaimPayoutTransaction(record.origin_height, record.origin_block_hash,
                                    marker.nTime, record.claim_index, *claim)->GetHash(), 0};
    if (deterministic_payout != outpoint) return false;

    const std::optional<ShadowPoolUndoState> undo = ReadAuthenticatedPoolUndo(
        view, static_cast<int>(record.origin_height), record.origin_block_hash,
        marker.nTime);
    if (!undo || record.claim_index >= undo->claim_count ||
        (origin_block &&
         (undo->previous_block_hash !=
              (origin_block->pprev ? origin_block->pprev->GetBlockHash()
                                   : uint256{}) ||
          !PoolUndoClaimCountWithinBound(view, origin_block,
                                         Params().GetConsensus(), *undo)))) {
        return false;
    }

    if (has_payout && (payout.out.nValue != record.nominal_amount ||
                       payout.out.scriptPubKey != record.target || !payout.fCoinBase ||
                       payout.fCoinStake || payout.nHeight != record.origin_height ||
                       payout.nTime != marker.nTime)) {
        return false;
    }
    if (payout_script) *payout_script = record.target;
    return true;
}

} // namespace

bool IsGoldRushDirectPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint, CScript* payout_script)
{
    GoldRushPayoutRecord record;
    return AuthenticateGoldRushPayoutRecord(view, outpoint, record, payout_script);
}

bool IsGoldRushPayoutCandidate(const CCoinsViewCache& view, const COutPoint& outpoint,
                               const Consensus::Params& consensus, CScript* payout_script)
{
    Coin coin;
    if (!view.GetCoin(outpoint, coin) || coin.IsSpent()) return false;
    const auto tier = GetQuantumStakeTierProgram(coin.out.scriptPubKey);
    if (!coin.fCoinBase || coin.fCoinStake || coin.out.nValue <= 0 ||
        coin.nHeight < static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) ||
        coin.nHeight > static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) ||
        coin.nHeight <= static_cast<uint32_t>(consensus.nLastPOWBlock) ||
        !tier || tier->tiered || tier->cold_stake) {
        return false;
    }
    if (payout_script) *payout_script = coin.out.scriptPubKey;
    return true;
}

GoldRushPayoutStatus GetGoldRushPayoutStatus(const CCoinsViewCache& view,
                                             const COutPoint& outpoint,
                                             const Consensus::Params& consensus,
                                             CScript* payout_script,
                                             const CBlockIndex* pindex_tip)
{
    GoldRushPayoutRecord record;
    if (AuthenticateGoldRushPayoutRecord(view, outpoint, record, payout_script, pindex_tip)) {
        Coin payout;
        if (view.GetCoin(outpoint, payout) && !payout.IsSpent()) {
            return GoldRushPayoutStatus::AUTHENTICATED;
        }
        Coin spent_marker;
        GoldRushSpentState spent_state;
        const bool authenticated_spent =
            view.GetCoin(GoldRushSpentOutpoint(outpoint), spent_marker) && !spent_marker.IsSpent() &&
            spent_marker.out.nValue == 0 && spent_marker.fCoinBase && !spent_marker.fCoinStake &&
            DecodeGoldRushSpentState(spent_marker.out.scriptPubKey, spent_state) &&
            spent_state.payout_outpoint == outpoint &&
            spent_state.payout_record_hash == GoldRushPayoutRecordHash(record) &&
            spent_state.nominal_amount == record.nominal_amount &&
            spent_marker.nHeight == spent_state.spend_height;
        if (authenticated_spent && pindex_tip) {
            const CBlockIndex* spend_block = SafeGetAncestor(
                pindex_tip, static_cast<int>(spent_state.spend_height));
            if (!spend_block || spend_block->GetBlockHash() != spent_state.spend_block_hash ||
                spent_marker.nTime != static_cast<uint32_t>(spend_block->GetBlockTime())) {
                return GoldRushPayoutStatus::CORRUPT;
            }
        }
        // A valid record without either its positive coin or an exact spent
        // tombstone is local chainstate corruption. Never let CheckTxInputs
        // turn that into a peer/block consensus invalidation.
        return authenticated_spent ? GoldRushPayoutStatus::NOT_CANDIDATE
                                   : GoldRushPayoutStatus::CORRUPT;
    }
    return IsGoldRushPayoutCandidate(view, outpoint, consensus, payout_script)
        ? GoldRushPayoutStatus::CORRUPT
        : GoldRushPayoutStatus::NOT_CANDIDATE;
}

bool IsLockedGoldRushPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint,
                                  const Consensus::Params& consensus, int64_t nMedianTimePast,
                                  int nSpendHeight, CScript* payout_script)
{
    if (IsQuantumWitnessSpendActive(consensus, nMedianTimePast, nSpendHeight)) return false;
    return GetGoldRushPayoutStatus(view, outpoint, consensus, payout_script) !=
           GoldRushPayoutStatus::NOT_CANDIDATE;
}

bool IsGoldRushSyntheticPayoutInput(const CCoinsViewCache& view, const COutPoint& outpoint,
                                    const Consensus::Params& consensus, CScript* payout_script)
{
    return GetGoldRushPayoutStatus(view, outpoint, consensus, payout_script) ==
           GoldRushPayoutStatus::AUTHENTICATED;
}

bool RecordSpentGoldRushPayouts(CCoinsViewCache& view, const CTransaction& tx,
                                const CBlockIndex* pindex)
{
    if (!pindex || tx.IsCoinBase()) return pindex != nullptr;
    const uint256 spending_txid = tx.GetHash();
    for (uint32_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
        const COutPoint& payout_outpoint = tx.vin[input_index].prevout;
        GoldRushPayoutRecord payout_record;
        const GoldRushPayoutStatus payout_status = GetGoldRushPayoutStatus(
            view, payout_outpoint, Params().GetConsensus(), nullptr, pindex->pprev);
        if (payout_status == GoldRushPayoutStatus::NOT_CANDIDATE) continue;
        if (payout_status == GoldRushPayoutStatus::CORRUPT ||
            !AuthenticateGoldRushPayoutRecord(view, payout_outpoint, payout_record, nullptr,
                                              pindex->pprev)) return false;
        const COutPoint spent_outpoint = GoldRushSpentOutpoint(payout_outpoint);
        if (view.HaveCoin(spent_outpoint)) return false;
        GoldRushInventoryState inventory;
        if (ReadGoldRushInventory(view, inventory) != GoldRushInventoryReadResult::VALID ||
            (inventory.tip_hash != pindex->GetBlockHash() &&
             (!pindex->pprev || inventory.tip_hash != pindex->pprev->GetBlockHash())) ||
            (inventory.tip_hash != pindex->GetBlockHash() &&
             !GoldRushInventoryRootsValid(inventory)) ||
            inventory.spent_count >= inventory.issued_count ||
            inventory.spent_nominal > inventory.issued_nominal - payout_record.nominal_amount) {
            return false;
        }
        inventory.unspent_set.Remove(GoldRushPayoutLeaf(payout_record));
        ++inventory.spent_count;
        inventory.spent_nominal += payout_record.nominal_amount;
        GoldRushSpentState state;
        state.payout_outpoint = payout_outpoint;
        state.payout_record_hash = GoldRushPayoutRecordHash(payout_record);
        state.nominal_amount = payout_record.nominal_amount;
        state.spend_height = pindex->nHeight;
        state.spend_block_hash = pindex->GetBlockHash();
        state.spending_txid = spending_txid;
        state.input_index = input_index;
        Coin marker;
        marker.out.nValue = 0;
        marker.out.scriptPubKey = MarkerScript(MARKER_GOLD_RUSH_SPENT,
                                               EncodeGoldRushSpentState(state));
        marker.fCoinBase = true;
        marker.fCoinStake = false;
        marker.nHeight = pindex->nHeight;
        marker.nTime = pindex->GetBlockTime();
        view.AddCoin(spent_outpoint, std::move(marker), true);
        if (!WriteGoldRushInventory(view, pindex, std::move(inventory), /*finalize=*/false)) return false;
    }
    return true;
}

bool UndoSpentGoldRushPayouts(CCoinsViewCache& view, const CBlock& block,
                              const CBlockUndo& block_undo,
                              const CBlockIndex* pindex)
{
    if (!pindex || block.vtx.empty() || block_undo.vtxundo.size() + 1 != block.vtx.size()) return false;
    for (size_t tx_pos = block.vtx.size(); tx_pos-- > 1;) {
        const CTransactionRef& tx = block.vtx[tx_pos];
        const CTxUndo& tx_undo = block_undo.vtxundo[tx_pos - 1];
        if (tx_undo.vprevout.size() != tx->vin.size()) return false;
        for (size_t input_pos = tx->vin.size(); input_pos-- > 0;) {
            const CTxIn& input = tx->vin[input_pos];
            const Coin& undo_coin = tx_undo.vprevout[input_pos];
            const uint32_t input_index = static_cast<uint32_t>(input_pos);
            const COutPoint marker_outpoint = GoldRushSpentOutpoint(input.prevout);
            Coin spent_marker;
            GoldRushPayoutRecord payout_record;
            const bool payout_record_valid = AuthenticateGoldRushPayoutRecord(
                view, input.prevout, payout_record, nullptr, pindex);
            if (!view.GetCoin(marker_outpoint, spent_marker) || spent_marker.IsSpent()) {
                if (payout_record_valid) return false;
                // Base undo is authoritative evidence about the coin that will
                // be restored later in DisconnectBlock. Ordinary blocks cannot
                // create a positive coinbase-class output in the Gold Rush
                // reward range after mainnet PoW ended, so this shape is a synthetic payout
                // whose missing record+tombstone is local corruption. Fail
                // before mutating inventory instead of restoring it untracked.
                if (undo_coin.fCoinBase && !undo_coin.fCoinStake &&
                    undo_coin.out.nValue > 0 &&
                    undo_coin.nHeight >= static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) &&
                    undo_coin.nHeight <= static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) &&
                    undo_coin.nHeight > static_cast<uint32_t>(Params().GetConsensus().nLastPOWBlock)) {
                    return false;
                }
                continue;
            }
            GoldRushSpentState spent_state;
            if (!payout_record_valid ||
                !DecodeGoldRushSpentState(spent_marker.out.scriptPubKey, spent_state) ||
                spent_state.payout_outpoint != input.prevout ||
                spent_state.spend_height != static_cast<uint32_t>(pindex->nHeight) ||
                spent_state.spend_block_hash != pindex->GetBlockHash() ||
                spent_state.spending_txid != tx->GetHash() ||
                spent_state.input_index != input_index ||
                spent_marker.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
                spent_marker.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
                spent_state.payout_record_hash != GoldRushPayoutRecordHash(payout_record) ||
                spent_state.nominal_amount != payout_record.nominal_amount) {
                return false;
            }
            GoldRushInventoryState inventory;
            if (ReadGoldRushInventory(view, inventory) != GoldRushInventoryReadResult::VALID ||
                inventory.tip_hash != pindex->GetBlockHash() || inventory.spent_count == 0 ||
                inventory.spent_nominal < payout_record.nominal_amount) {
                return false;
            }
            inventory.unspent_set.Insert(GoldRushPayoutLeaf(payout_record));
            --inventory.spent_count;
            inventory.spent_nominal -= payout_record.nominal_amount;
            if (!WriteGoldRushInventory(view, pindex, std::move(inventory), /*finalize=*/false)) return false;
            view.SpendCoin(marker_outpoint);
        }
    }
    return true;
}

COutPoint GetGoldRushPayoutMarkerOutpoint(const COutPoint& payout_outpoint)
{
    return GoldRushPayoutOutpoint(payout_outpoint);
}

bool IsGoldRushPayoutMarkerScript(const CScript& script)
{
    return ParseMarkerScript(script, MARKER_GOLD_RUSH_PAYOUT);
}

const std::vector<unsigned char>& GetShadowPrefix()
{
    return SHADOW_PREFIX;
}

ShadowProofPayloadMode ClassifyShadowProofPayload(const std::vector<unsigned char>& prefixed_proof)
{
    if (prefixed_proof.size() <= SHADOW_PREFIX.size() ||
        !std::equal(SHADOW_PREFIX.begin(), SHADOW_PREFIX.end(),
                    prefixed_proof.begin())) {
        return ShadowProofPayloadMode::MALFORMED;
    }
    return ClassifyProofPayloadMode(valtype{
        prefixed_proof.begin() + SHADOW_PREFIX.size(), prefixed_proof.end()});
}

void SetShadowArgon2FailuresForTesting(uint64_t count)
{
    g_shadow_argon2_test_failures.store(count, std::memory_order_relaxed);
}

void ClearShadowArgon2FailuresForTesting()
{
    g_shadow_argon2_test_failures.store(0, std::memory_order_relaxed);
}

void SetShadowAllocationFailureForTesting(ShadowAllocationFailurePoint point)
{
    g_shadow_allocation_test_failure.store(point, std::memory_order_relaxed);
}

void ClearShadowAllocationFailureForTesting()
{
    g_shadow_allocation_test_failure.store(ShadowAllocationFailurePoint::NONE,
                                           std::memory_order_relaxed);
}

COutPoint ShadowReplayStateOutpointForTesting()
{
    return ReplayStateOutpoint();
}

bool TransactionHasShadowProof(const CTransaction& tx)
{
    for (const CTxOut& out : tx.vout) {
        if (ExtractProofPayload(out.scriptPubKey)) return true;
    }
    return false;
}

std::vector<ShadowProofObservation> GetShadowProofObservations(const CBlock& block)
{
    ShadowProofObservationSummary summary;
    return GetShadowProofObservations(block, summary);
}

std::vector<ShadowProofObservation> GetShadowProofObservations(
    const CBlock& block, ShadowProofObservationSummary& summary)
{
    summary = {};
    std::vector<ShadowProofObservation> observations;
    observations.reserve(MAX_SHADOW_POW_EVALS_PER_BLOCK);
    CHashWriter commitment;
    commitment << std::string{"Quantum Quasar Structural POW Observations v1"}
               << block.GetHash();
    const bool proof_of_stake_block = block.IsProofOfStake();
    for (const CTransactionRef& tx_ref : block.vtx) {
        const CTransaction& tx = *tx_ref;
        uint32_t proof_count{0};
        for (const CTxOut& output : tx.vout) {
            if (ExtractProofPayload(output.scriptPubKey)) {
                if (!IncrementPowAggregate(proof_count)) {
                    throw std::length_error{"QQSPROOF output count exceeds consensus block bound"};
                }
            }
        }
        const bool fee_paying_location = proof_of_stake_block &&
            !tx.IsCoinBase() && !tx.IsCoinStake();
        const bool duplicate = proof_count > 1;
        for (size_t output_pos = 0; output_pos < tx.vout.size(); ++output_pos) {
            const auto proof =
                ExtractProofPayload(tx.vout[output_pos].scriptPubKey);
            if (!proof) continue;
            if (output_pos > std::numeric_limits<uint32_t>::max() ||
                !IncrementPowAggregate(summary.observed_count)) {
                throw std::length_error{"QQSPROOF observation exceeds consensus block bound"};
            }
            const uint32_t output_index = static_cast<uint32_t>(output_pos);
            commitment << tx.GetHash() << output_index << *proof
                       << fee_paying_location << proof_count;
            if (observations.size() < MAX_SHADOW_POW_EVALS_PER_BLOCK) {
                observations.push_back(ShadowProofObservation{
                    tx.GetHash(), output_index,
                    ClassifyProofPayloadMode(*proof), fee_paying_location,
                    duplicate});
            }
        }
    }
    summary.returned_count = static_cast<uint32_t>(observations.size());
    summary.omitted_count = summary.observed_count - summary.returned_count;
    summary.commitment = commitment.GetHash();
    return observations;
}

bool IsAuthenticatedShadowMarkerOutpoint(const COutPoint& outpoint, const Coin& coin, const CBlockIndex* pindexTip)
{
    if (!pindexTip || coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.nHeight > static_cast<uint32_t>(pindexTip->nHeight)) return false;
    const CBlockIndex* coin_block = pindexTip && coin.nHeight <= static_cast<uint32_t>(pindexTip->nHeight)
        ? SafeGetAncestor(pindexTip, static_cast<int>(coin.nHeight))
        : nullptr;
    const bool branch_metadata_valid = coin_block &&
        coin.nTime == static_cast<uint32_t>(coin_block->GetBlockTime());
    // Fixed/reserved outpoints are computationally unreachable to ordinary
    // transactions. Authenticate them from outpoint plus active-branch
    // metadata before decoding the inner payload, so deterministic replay can
    // purge a corrupt or obsolete schema instead of colliding with it.
    if (outpoint == ActiveSignalSetOutpoint()) return branch_metadata_valid;
    if (branch_metadata_valid && outpoint == ActiveSignalUndoOutpoint(coin_block)) return true;
    if (branch_metadata_valid && outpoint == PoolUndoOutpoint(coin_block)) return true;
    if (outpoint == PoolOutpoint() || outpoint == ReplayStateOutpoint()) return branch_metadata_valid;
    if (outpoint == GoldRushInventoryOutpoint()) {
        return branch_metadata_valid;
    }
    if (outpoint == WhitelistManifestOutpoint()) {
        return branch_metadata_valid && coin.nHeight == static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT);
    }
    if (outpoint == WhitelistReadyOutpoint()) {
        return branch_metadata_valid && coin.nHeight == static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT);
    }

    valtype payload;
    static constexpr size_t SHARD_HEADER_SIZE = 1 + uint256::size() + 3 * sizeof(uint32_t);
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_WHITELIST_SHARD, &payload)) {
        if (!branch_metadata_valid || coin.nHeight != static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) ||
            payload.size() < SHARD_HEADER_SIZE || payload[0] != 1) return false;
        uint256 anchor_hash;
        std::copy(payload.begin() + 1, payload.begin() + 1 + uint256::size(), anchor_hash.begin());
        const uint32_t shard_index = ReadLE32(payload.data() + 1 + uint256::size());
        return anchor_hash == coin_block->GetBlockHash() &&
               outpoint == WhitelistManifestShardOutpoint(anchor_hash, shard_index);
    }
    for (const auto& [tag, undo_shard] : std::array<std::pair<const valtype*, bool>, 2>{
             std::pair{&MARKER_ACTIVE_SIGNAL_SHARD, false},
             std::pair{&MARKER_ACTIVE_SIGNAL_UNDO_SHARD, true}}) {
        if (!ParseMarkerScript(coin.out.scriptPubKey, *tag, &payload)) continue;
        if (!branch_metadata_valid || payload.size() < SHARD_HEADER_SIZE || payload[0] != 1) return false;
        uint256 anchor_hash;
        std::copy(payload.begin() + 1, payload.begin() + 1 + uint256::size(), anchor_hash.begin());
        const uint32_t shard_index = ReadLE32(payload.data() + 1 + uint256::size());
        if (anchor_hash != coin_block->GetBlockHash()) return false;
        return outpoint == (undo_shard
            ? ActiveSignalUndoShardOutpoint(anchor_hash, shard_index)
            : ActiveSignalShardOutpoint(anchor_hash, shard_index));
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_POOL, &payload)) {
        return outpoint == PoolOutpoint();
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_WHITELIST_READY, &payload)) {
        return outpoint == WhitelistReadyOutpoint();
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_WHITELIST, &payload)) {
        WhitelistMemberRecord member;
        return branch_metadata_valid &&
               coin.nHeight == static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) &&
               DecodeWhitelistMember(payload, member) &&
               member.snapshot_hash == coin_block->GetBlockHash() &&
               outpoint == WhitelistOutpoint(member.script);
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_ACTIVE_SIGNAL_SET, &payload)) {
        return false; // the reserved fixed outpoint was handled above
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_ACTIVE_SIGNAL_UNDO, &payload)) {
        return false; // the deterministic per-block outpoint was handled above
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_SOLVER, &payload)) {
        if (!pindexTip || coin.nHeight > static_cast<uint32_t>(pindexTip->nHeight)) return false;
        const CBlockIndex* marker_block = SafeGetAncestor(pindexTip, static_cast<int>(coin.nHeight));
        uint256 solver_hash;
        if (!marker_block || coin.nTime != static_cast<uint32_t>(marker_block->GetBlockTime()) ||
            !DecodeSolverMarkerHash(coin.out.scriptPubKey, solver_hash)) return false;
        CHashWriter ss;
        ss << std::string("Quantum Quasar Recent Solver v2")
           << solver_hash << coin.nHeight << marker_block->GetBlockHash();
        return outpoint == COutPoint{ss.GetHash(), 0};
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_REPLAY_STATE, &payload)) {
        return outpoint == ReplayStateOutpoint();
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_DIRECT_CLAIM, &payload)) {
        uint32_t origin_height{0};
        uint256 origin_hash;
        uint32_t marker_index{0};
        valtype claim_payload;
        if (!DecodeClaimMarkerEnvelope(payload, origin_height, origin_hash,
                                       marker_index, claim_payload)) return false;
        const CBlockIndex* origin = SafeGetAncestor(pindexTip, static_cast<int>(origin_height));
        return origin && branch_metadata_valid && coin.nHeight == origin_height &&
               origin->GetBlockHash() == origin_hash &&
               outpoint == ClaimOutpoint(origin_height, origin_hash, marker_index) &&
               DecodeClaimScript(coin.out.scriptPubKey).has_value();
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT, &payload)) {
        GoldRushPayoutRecord record;
        if (!DecodeGoldRushPayoutRecordPayload(payload, record)) return false;
        const CBlockIndex* origin = SafeGetAncestor(pindexTip, static_cast<int>(record.origin_height));
        return origin && branch_metadata_valid && coin.nHeight == record.origin_height &&
               origin->GetBlockHash() == record.origin_block_hash &&
               outpoint == GoldRushPayoutOutpoint(record.payout_outpoint);
    }
    GoldRushSpentState spent_state;
    if (DecodeGoldRushSpentState(coin.out.scriptPubKey, spent_state)) {
        return branch_metadata_valid && spent_state.spend_height == coin.nHeight &&
               spent_state.spend_block_hash == coin_block->GetBlockHash() &&
               outpoint == GoldRushSpentOutpoint(spent_state.payout_outpoint);
    }

    // Claim, active-signal, and payout markers in v30.1.0 do not encode enough
    // provenance to reconstruct their reserved outpoint from the marker alone.
    // Retain them here rather than risk deleting a legacy-valid user output;
    // deterministic replay overwrites the authentic records it reconstructs.
    return false;
}

bool DecodeAuthenticatedGoldRushPayoutMarker(const COutPoint& marker_outpoint,
                                             const Coin& marker_coin,
                                             const CBlockIndex* pindex_tip,
                                             GoldRushPayoutMarkerInfo& info)
{
    info = {};
    valtype payload;
    GoldRushPayoutRecord record;
    if (!IsAuthenticatedShadowMarkerOutpoint(marker_outpoint, marker_coin, pindex_tip) ||
        !ParseMarkerScript(marker_coin.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT, &payload) ||
        !DecodeGoldRushPayoutRecordPayload(payload, record) ||
        marker_outpoint != GoldRushPayoutOutpoint(record.payout_outpoint)) {
        return false;
    }
    const CBlockIndex* origin = SafeGetAncestor(pindex_tip, static_cast<int>(record.origin_height));
    if (!origin || origin->GetBlockHash() != record.origin_block_hash ||
        marker_coin.nHeight != record.origin_height ||
        marker_coin.nTime != static_cast<uint32_t>(origin->GetBlockTime())) {
        return false;
    }
    info.payout_outpoint = record.payout_outpoint;
    info.payout_script = record.target;
    info.nominal_amount = record.nominal_amount;
    info.origin_height = record.origin_height;
    info.origin_block_hash = record.origin_block_hash;
    info.origin_block_time = marker_coin.nTime;
    return true;
}

bool DecodeAuthenticatedGoldRushInventory(const COutPoint& inventory_outpoint,
                                          const Coin& inventory_coin,
                                          const CBlockIndex* pindex_tip,
                                          GoldRushInventoryInfo& info)
{
    info = {};
    GoldRushInventoryState state;
    if (!pindex_tip || inventory_outpoint != GoldRushInventoryOutpoint() ||
        !IsAuthenticatedShadowMarkerOutpoint(inventory_outpoint, inventory_coin, pindex_tip) ||
        !DecodeGoldRushInventory(inventory_coin.out.scriptPubKey, state) ||
        !GoldRushInventoryRootsValid(state) ||
        state.tip_height != static_cast<uint32_t>(pindex_tip->nHeight) ||
        state.tip_hash != pindex_tip->GetBlockHash()) {
        return false;
    }
    info.tip_height = state.tip_height;
    info.tip_hash = state.tip_hash;
    info.issued_count = state.issued_count;
    info.issued_nominal = state.issued_nominal;
    info.spent_count = state.spent_count;
    info.spent_nominal = state.spent_nominal;
    return true;
}

bool DecodeAuthenticatedShadowPool(const COutPoint& pool_outpoint,
                                   const Coin& pool_coin,
                                   const CBlockIndex* pindex_tip,
                                   ShadowGoldRushInfo& info)
{
    info = {};
    ShadowPoolState pool;
    if (pool_outpoint != PoolOutpoint() ||
        !IsAuthenticatedShadowMarkerOutpoint(pool_outpoint, pool_coin, pindex_tip) ||
        DecodePoolCoin(pool_coin, pool) != ShadowPoolReadResult::VALID) {
        return false;
    }
    info.pow_amount = pool.pow_amount;
    info.pos_amount = pool.pos_amount;
    info.claimed_amount = pool.claimed_amount;
    info.pow_count = pool.pow_count;
    info.pos_count = pool.pos_count;
    info.last_pow_height = pool.last_pow_height;
    info.last_pos_height = pool.last_pos_height;
    info.recent_count = pool.recent_count;
    info.recent_modes = pool.recent_modes;
    info.pow_target_bits = pindex_tip
        ? RetargetedBits(ShadowProofMode::POW, pool, pindex_tip->nHeight + 1)
        : RetargetedBits(ShadowProofMode::POW, pool, 0);
    return true;
}

bool IsShadowPoolMarkerOutpoint(const COutPoint& outpoint)
{
    return outpoint == PoolOutpoint();
}

bool IsGoldRushInventoryMarkerOutpoint(const COutPoint& outpoint)
{
    return outpoint == GoldRushInventoryOutpoint();
}

bool IsGoldRushPayoutCandidateCoin(const Coin& coin, const Consensus::Params& consensus)
{
    if (SHADOW_REWARD_START_HEIGHT < 0 ||
        SHADOW_REWARD_END_HEIGHT < SHADOW_REWARD_START_HEIGHT) {
        return false;
    }
    const auto tier = GetQuantumStakeTierProgram(coin.out.scriptPubKey);
    return coin.fCoinBase && !coin.fCoinStake && coin.out.nValue > 0 &&
        static_cast<int64_t>(coin.nHeight) >= SHADOW_REWARD_START_HEIGHT &&
        static_cast<int64_t>(coin.nHeight) <= SHADOW_REWARD_END_HEIGHT &&
        static_cast<int64_t>(coin.nHeight) > consensus.nLastPOWBlock &&
        tier && !tier->tiered && !tier->cold_stake;
}

const char* ValueLifecycleCategoryName(ValueLifecycleCategory category)
{
    switch (category) {
    case ValueLifecycleCategory::SPENDABLE_LEGACY: return "spendable_legacy";
    case ValueLifecycleCategory::IMMATURE_LEGACY: return "immature_legacy";
    case ValueLifecycleCategory::FINAL_LOCKED_LEGACY: return "final_locked_legacy";
    case ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_IMMATURE: return "gold_rush_synthetic_immature";
    case ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_MATURE_LOCKED: return "gold_rush_synthetic_mature_locked";
    case ValueLifecycleCategory::DIRECT_QUANTUM_PHASE_LOCKED: return "direct_quantum_phase_locked";
    case ValueLifecycleCategory::MIGRATION_SPENDABLE_DIRECT_QUANTUM: return "migration_spendable_direct_quantum";
    case ValueLifecycleCategory::QUANTUM_CONTRACT_RESTRICTED: return "quantum_contract_restricted";
    case ValueLifecycleCategory::DEMURRAGE_LOCKED: return "demurrage_locked";
    case ValueLifecycleCategory::FINAL_CONDITIONAL_EUTXO: return "final_conditional_eutxo";
    case ValueLifecycleCategory::IMMATURE_OTHER: return "immature_other";
    case ValueLifecycleCategory::OTHER: return "other";
    case ValueLifecycleCategory::COUNT: break;
    }
    return "unknown";
}

ValueLifecycleResult ClassifyValueLifecycle(
    const Coin& coin,
    bool authenticated_synthetic_goldrush,
    const Consensus::Params& consensus,
    int evaluation_height,
    int64_t evaluation_mtp,
    std::optional<int> latest_attestation_height,
    std::optional<int> attestation_coverage_start_height,
    ValueLifecycleClassification& classification)
{
    classification = {};
    if (!MoneyRange(coin.out.nValue) || evaluation_height < 0 ||
        consensus.nCoinbaseMaturity < 0) {
        return ValueLifecycleResult::INVALID_AMOUNT;
    }

    const Consensus::Params::QuantumLifecycleState lifecycle =
        consensus.GetQuantumLifecycleState(evaluation_mtp, evaluation_height);
    if (!lifecycle.schedule_valid) return ValueLifecycleResult::INVALID_SCHEDULE;

    const auto tier = GetQuantumStakeTierProgram(coin.out.scriptPubKey);
    const bool direct_quantum = tier && !tier->tiered && !tier->cold_stake;
    const bool quantum_contract = (tier && (tier->tiered || tier->cold_stake)) ||
        IsQuantumColdStakeScript(coin.out.scriptPubKey);
    const bool eutxo = IsEUTXOScript(coin.out.scriptPubKey);
    const bool legacy = !direct_quantum && !quantum_contract && !eutxo;
    const bool authenticated_synthetic_shape = direct_quantum &&
        coin.fCoinBase && !coin.fCoinStake && coin.out.nValue > 0 &&
        SHADOW_REWARD_START_HEIGHT >= 0 &&
        SHADOW_REWARD_END_HEIGHT >= SHADOW_REWARD_START_HEIGHT &&
        static_cast<int64_t>(coin.nHeight) >= SHADOW_REWARD_START_HEIGHT &&
        static_cast<int64_t>(coin.nHeight) <= SHADOW_REWARD_END_HEIGHT;
    if (authenticated_synthetic_goldrush && !authenticated_synthetic_shape) {
        return ValueLifecycleResult::INVALID_SYNTHETIC_PROVENANCE;
    }

    classification.synthetic = authenticated_synthetic_goldrush;
    classification.merkle_included = !authenticated_synthetic_goldrush;
    classification.nominal_amount = coin.out.nValue;

    const bool generated = coin.IsCoinBase() || coin.IsCoinStake();
    if (generated) {
        classification.maturity_height =
            static_cast<int64_t>(coin.nHeight) + consensus.nCoinbaseMaturity;
        classification.mature = static_cast<int64_t>(evaluation_height) >=
            classification.maturity_height;
    }

    const Consensus::DemurrageEvaluation demurrage = Consensus::EvaluateDemurrage(
        coin, consensus, evaluation_height, evaluation_mtp,
        latest_attestation_height, attestation_coverage_start_height);
    if (!MoneyRange(demurrage.nominal_value) ||
        !MoneyRange(demurrage.effective_value) ||
        !MoneyRange(demurrage.burned_value) ||
        demurrage.nominal_value != coin.out.nValue ||
        demurrage.effective_value > demurrage.nominal_value ||
        demurrage.burned_value != demurrage.nominal_value - demurrage.effective_value) {
        return ValueLifecycleResult::INVALID_AMOUNT;
    }
    classification.effective_amount = demurrage.effective_value;
    classification.burned_amount = demurrage.burned_value;
    classification.demurrage_active = demurrage.active;
    classification.demurrage_exempt = demurrage.exempt;
    classification.demurrage_locked = demurrage.locked;
    classification.demurrage_exemption = demurrage.exemption;

    const bool quantum_spends_active = IsQuantumWitnessSpendActive(
        consensus, evaluation_mtp, evaluation_height);
    const bool final_lockout = consensus.IsQuantumFinalLockout(
        evaluation_mtp, evaluation_height);

    int64_t quantum_unlock_height = SHADOW_REWARD_END_HEIGHT >= 0
        ? static_cast<int64_t>(SHADOW_REWARD_END_HEIGHT) + 1
        : -1;
    int64_t quantum_unlock_mtp{-1};
    if (consensus.IsGoldRushEndScheduled()) {
        if (lifecycle.height_authoritative) {
            quantum_unlock_height = std::max<int64_t>(
                quantum_unlock_height,
                static_cast<int64_t>(consensus.nGoldRushEndHeight) + 1);
        } else if (consensus.nGoldRushEndTime == std::numeric_limits<int64_t>::max()) {
            return ValueLifecycleResult::INVALID_SCHEDULE;
        } else {
            quantum_unlock_mtp = consensus.nGoldRushEndTime + 1;
        }
    }

    if (legacy) {
        classification.legacy_scheduled_final_lockout =
            consensus.IsMigrationEndScheduled() && !final_lockout;
        classification.requires_quantum_migration = !final_lockout;
        if (final_lockout) {
            classification.category = ValueLifecycleCategory::FINAL_LOCKED_LEGACY;
            classification.permanently_locked = true;
            return ValueLifecycleResult::OK;
        }
    }

    if (authenticated_synthetic_goldrush) {
        classification.earliest_spend_height = classification.maturity_height;
        if (quantum_unlock_height >= 0) {
            classification.earliest_spend_height = std::max(
                classification.earliest_spend_height, quantum_unlock_height);
        }
        classification.earliest_spend_mtp = quantum_unlock_mtp;
        if (!classification.mature) {
            classification.category = ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_IMMATURE;
            return ValueLifecycleResult::OK;
        }
        if (!quantum_spends_active) {
            classification.category = ValueLifecycleCategory::GOLD_RUSH_SYNTHETIC_MATURE_LOCKED;
            return ValueLifecycleResult::OK;
        }
    } else if (!classification.mature) {
        classification.category = legacy
            ? ValueLifecycleCategory::IMMATURE_LEGACY
            : ValueLifecycleCategory::IMMATURE_OTHER;
        classification.earliest_spend_height = classification.maturity_height;
        if (legacy && lifecycle.height_authoritative &&
            classification.maturity_height >
                static_cast<int64_t>(consensus.nQuantumMigrationEndHeight)) {
            classification.earliest_spend_height = -1;
        }
        return ValueLifecycleResult::OK;
    }

    if (demurrage.locked) {
        classification.category = ValueLifecycleCategory::DEMURRAGE_LOCKED;
        classification.permanently_locked = true;
        return ValueLifecycleResult::OK;
    }

    if (legacy) {
        classification.category = ValueLifecycleCategory::SPENDABLE_LEGACY;
        classification.consensus_spendable = true;
        classification.ordinary_spendable = true;
        classification.earliest_spend_height = evaluation_height;
        return ValueLifecycleResult::OK;
    }

    if (direct_quantum) {
        if (!quantum_spends_active) {
            classification.category = ValueLifecycleCategory::DIRECT_QUANTUM_PHASE_LOCKED;
            classification.earliest_spend_height = quantum_unlock_height;
            classification.earliest_spend_mtp = quantum_unlock_mtp;
            return ValueLifecycleResult::OK;
        }
        classification.category =
            ValueLifecycleCategory::MIGRATION_SPENDABLE_DIRECT_QUANTUM;
        classification.consensus_spendable = true;
        classification.ordinary_spendable = true;
        classification.earliest_spend_height = evaluation_height;
        return ValueLifecycleResult::OK;
    }

    if (quantum_contract) {
        classification.category = ValueLifecycleCategory::QUANTUM_CONTRACT_RESTRICTED;
        classification.consensus_spendable = quantum_spends_active;
        if (!quantum_spends_active) {
            classification.earliest_spend_height = quantum_unlock_height;
            classification.earliest_spend_mtp = quantum_unlock_mtp;
        }
        if (tier && tier->IsUnbonding()) {
            classification.earliest_spend_height = std::max<int64_t>(
                classification.earliest_spend_height, tier->unlock_height);
        }
        return ValueLifecycleResult::OK;
    }

    if (eutxo && final_lockout) {
        classification.category = ValueLifecycleCategory::FINAL_CONDITIONAL_EUTXO;
        classification.conditional = true;
        return ValueLifecycleResult::OK;
    }

    classification.category = ValueLifecycleCategory::OTHER;
    return ValueLifecycleResult::OK;
}

bool CollectAuthenticatedShadowStateOutpoints(const CCoinsViewCache& view, const CBlockIndex* pindexTip,
                                              const ShadowBlockReader& read_block,
                                              std::set<COutPoint>& authenticated)
{
    authenticated.clear();
    if (!pindexTip) return true;

    std::map<int, std::vector<COutPoint>> claim_marker_candidates;
    std::map<int, std::vector<COutPoint>> active_signal_candidates;
    std::map<int, std::vector<COutPoint>> payout_marker_candidates;
    std::set<COutPoint> expected_whitelist_members;
    WhitelistManifest whitelist_manifest;
    std::set<CScript> whitelist;
    if (ReadWhitelistManifest(view, pindexTip, whitelist_manifest, &whitelist)) {
        for (const CScript& script : whitelist) expected_whitelist_members.insert(WhitelistOutpoint(script));
    }

    // First classify marker-shaped records without mutating the cursor's
    // underlying cache. Marker shape alone never authorizes deletion.
    {
        std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
        while (cursor->Valid()) {
            COutPoint outpoint;
            Coin coin;
            if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
                if ((expected_whitelist_members.count(outpoint) != 0 &&
                     coin.nHeight == static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT)) ||
                    IsAuthenticatedShadowMarkerOutpoint(outpoint, coin, pindexTip)) {
                    authenticated.insert(outpoint);
                } else if (coin.nHeight <= static_cast<uint32_t>(pindexTip->nHeight) &&
                           SafeGetAncestor(pindexTip, static_cast<int>(coin.nHeight))) {
                    if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_DIRECT_CLAIM)) {
                        claim_marker_candidates[static_cast<int>(coin.nHeight)].push_back(outpoint);
                    } else if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_ACTIVE_SIGNAL)) {
                        active_signal_candidates[static_cast<int>(coin.nHeight)].push_back(outpoint);
                    } else if (ParseMarkerScript(coin.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT)) {
                        payout_marker_candidates[static_cast<int>(coin.nHeight)].push_back(outpoint);
                    }
                }
            }
            cursor->Next();
        }
    }

    std::set<COutPoint> authenticated_payout_markers;
    for (const auto& [height, candidates] : claim_marker_candidates) {
        const CBlockIndex* marker_block = SafeGetAncestor(pindexTip, height);
        if (!marker_block) continue;
        const std::optional<ShadowPoolUndoState> undo = ReadAuthenticatedPoolUndo(
            view, marker_block, Params().GetConsensus());
        const uint32_t candidate_bound = static_cast<uint32_t>(
            std::min<size_t>(candidates.size(),
                             std::numeric_limits<uint32_t>::max()));
        const uint32_t search_count = undo ? undo->claim_count : candidate_bound;
        std::map<COutPoint, uint32_t> expected_claim_indices;
        for (uint32_t marker_index = 0; marker_index < search_count;
             ++marker_index) {
            expected_claim_indices.emplace(
                ClaimOutpoint(marker_block, marker_index), marker_index);
        }
        for (const COutPoint& claim_outpoint : candidates) {
            const auto matched = expected_claim_indices.find(claim_outpoint);
            if (matched == expected_claim_indices.end()) continue;
            const uint32_t matched_index = matched->second;
            Coin claim_coin;
            if (!view.GetCoin(claim_outpoint, claim_coin) || claim_coin.nHeight != static_cast<uint32_t>(height)) continue;
            const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
            if (!claim || !claim->direct || !IsValidDirectClaimMarker(marker_block, *claim)) continue;
            authenticated.insert(claim_outpoint);

            const COutPoint payout_outpoint = ClaimPayoutOutpoint(marker_block, matched_index, *claim);
            Coin payout_coin;
            if (view.GetCoin(payout_outpoint, payout_coin) &&
                payout_coin.nHeight == static_cast<uint32_t>(height) &&
                payout_coin.out.nValue == claim->amount && payout_coin.out.scriptPubKey == claim->target) {
                authenticated.insert(payout_outpoint);
            }

            const COutPoint payout_marker_outpoint = GoldRushPayoutOutpoint(payout_outpoint);
            Coin payout_marker;
            GoldRushPayoutRecord payout_record;
            if (view.GetCoin(payout_marker_outpoint, payout_marker) &&
                payout_marker.nHeight == static_cast<uint32_t>(height) &&
                AuthenticateGoldRushPayoutRecord(view, payout_outpoint, payout_record, nullptr) &&
                payout_record.target == claim->target) {
                authenticated.insert(payout_marker_outpoint);
                authenticated_payout_markers.insert(payout_marker_outpoint);
            }
            const COutPoint spent_marker_outpoint = GoldRushSpentOutpoint(payout_outpoint);
            if (view.HaveCoin(spent_marker_outpoint)) {
                // The authenticated claim deterministically names this
                // reserved outpoint, so purge may remove it even when its
                // payload is malformed and cannot self-authenticate.
                authenticated.insert(spent_marker_outpoint);
            }
        }
    }

    for (const auto& [height, candidates] : active_signal_candidates) {
        const CBlockIndex* marker_block = SafeGetAncestor(pindexTip, height);
        if (!marker_block) continue;
        const uint32_t candidate_bound = static_cast<uint32_t>(
            std::min<size_t>(candidates.size(),
                             std::numeric_limits<uint32_t>::max()));
        std::set<COutPoint> expected_signal_outpoints;
        for (uint32_t marker_index = 0; marker_index < candidate_bound;
             ++marker_index) {
            expected_signal_outpoints.insert(
                ActiveSignalOutpoint(marker_block, marker_index));
        }
        for (const COutPoint& outpoint : candidates) {
            if (expected_signal_outpoints.count(outpoint) == 0) continue;
            Coin coin;
            ShadowActiveSignal signal;
            if (view.GetCoin(outpoint, coin) && coin.nHeight == static_cast<uint32_t>(height) &&
                DecodeActiveSignalMarker(coin.out.scriptPubKey, signal) &&
                signal.last_signal_height == static_cast<uint32_t>(height)) {
                authenticated.insert(outpoint);
            }
        }
    }

    // Payout markers for synthetic claims were authenticated above. Any
    // remaining candidate must match an actual output in its source block.
    for (const auto& [height, candidates] : payout_marker_candidates) {
        const bool needs_block = std::any_of(candidates.begin(), candidates.end(), [&](const COutPoint& outpoint) {
            return !authenticated_payout_markers.count(outpoint);
        });
        if (!needs_block) continue;
        const CBlockIndex* marker_block = SafeGetAncestor(pindexTip, height);
        if (!marker_block) continue;
        CBlock block;
        if (!read_block(*marker_block, block)) return false;
        for (const CTransactionRef& tx : block.vtx) {
            const uint256 txid = tx->GetHash();
            for (uint32_t output_index = 0; output_index < tx->vout.size(); ++output_index) {
                const COutPoint marker_outpoint = GoldRushPayoutOutpoint(COutPoint{txid, output_index});
                Coin marker;
                valtype payload;
                if (view.GetCoin(marker_outpoint, marker) &&
                    marker.nHeight == static_cast<uint32_t>(height) &&
                    ParseMarkerScript(marker.out.scriptPubKey, MARKER_GOLD_RUSH_PAYOUT, &payload) &&
                    CScript(payload.begin(), payload.end()) == tx->vout[output_index].scriptPubKey) {
                    authenticated.insert(marker_outpoint);
                }
            }
        }
    }

    return true;
}

bool PurgeAuthenticatedShadowState(CCoinsViewCache& view, const CBlockIndex* pindexTip,
                                   const ShadowBlockReader& read_block, uint64_t& removed)
{
    std::set<COutPoint> authenticated;
    if (!CollectAuthenticatedShadowStateOutpoints(view, pindexTip, read_block, authenticated)) return false;
    removed = 0;
    for (const COutPoint& outpoint : authenticated) {
        if (view.SpendCoin(outpoint)) ++removed;
    }
    return true;
}

bool TransactionHasShadowSignal(const CTransaction& tx)
{
    for (const CTxOut& out : tx.vout) {
        if (ExtractSignalPayload(out.scriptPubKey)) return true;
    }
    return false;
}

bool CheckShadowSignalForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev,
                                 const CCoinsViewCache& view, bool gold_rush_active,
                                 std::string& reject_reason)
{
    if (!TransactionHasShadowSignal(tx)) return true;
    if (!gold_rush_active || !pindexPrev) {
        reject_reason = "shadow-signal-inactive";
        return false;
    }
    if (tx.IsCoinBase() || tx.IsCoinStake()) {
        reject_reason = "shadow-signal-invalid-location";
        return false;
    }

    std::optional<ShadowSignal> decoded_signal;
    for (const CTxOut& out : tx.vout) {
        const auto payload = ExtractSignalPayload(out.scriptPubKey);
        if (!payload) continue;
        ShadowSignal signal;
        if (decoded_signal || !DecodeSignalPayload(*payload, signal) || !signal.quantum_linked) {
            reject_reason = "shadow-signal-invalid";
            return false;
        }
        decoded_signal = std::move(signal);
    }
    if (!decoded_signal) {
        reject_reason = "shadow-signal-invalid";
        return false;
    }

    const ShadowSignal& signal = *decoded_signal;
    const CScript target = CanonicalLegacyStakeScript(signal.target);
    if (!IsLegacyShadowTargetScript(target) || !IsWhitelisted(view, target)) {
        reject_reason = "shadow-signal-target";
        return false;
    }
    bool spends_target{false};
    for (const CTxIn& txin : tx.vin) {
        Coin coin;
        if (view.GetCoin(txin.prevout, coin) && !coin.IsSpent() &&
            IsLegacyShadowTargetScript(coin.out.scriptPubKey) &&
            CanonicalLegacyStakeScript(coin.out.scriptPubKey) == target) {
            spends_target = true;
            break;
        }
    }
    if (!spends_target || !TxPaysToScript(tx, target)) {
        reject_reason = "shadow-signal-input-mismatch";
        return false;
    }

    const int next_height = pindexPrev->nHeight + 1;
    if (signal.solve_height == 0 || signal.solve_hash.IsNull() ||
        signal.solve_height > static_cast<uint32_t>(pindexPrev->nHeight) ||
        next_height - static_cast<int>(signal.solve_height) > SHADOW_SOLVER_ACTIVITY_WINDOW) {
        reject_reason = "shadow-signal-stale-solve";
        return false;
    }
    const CBlockIndex* solve_block = SafeGetAncestor(pindexPrev, static_cast<int>(signal.solve_height));
    Coin solver_coin;
    if (!solve_block || solve_block->GetBlockHash() != signal.solve_hash ||
        !view.GetCoin(SolverOutpoint(target, signal.solve_height, signal.solve_hash), solver_coin) ||
        solver_coin.IsSpent() || solver_coin.out.nValue != 0 || !solver_coin.fCoinBase || solver_coin.fCoinStake ||
        solver_coin.nHeight != signal.solve_height ||
        solver_coin.nTime != static_cast<uint32_t>(solve_block->GetBlockTime()) ||
        !SolverMarkerMatches(solver_coin.out.scriptPubKey, target) ||
        solver_coin.nTime > static_cast<uint32_t>(pindexPrev->GetBlockTime()) ||
        pindexPrev->GetBlockTime() - static_cast<int64_t>(solver_coin.nTime) > SHADOW_SOLVER_ACTIVITY_SECONDS) {
        reject_reason = "shadow-signal-stale-solve";
        return false;
    }

    bool signal_state_valid{true};
    (void)ReadActiveShadowSignals(view, pindexPrev, next_height, &signal_state_valid);
    if (!signal_state_valid) {
        reject_reason = "shadow-signal-state";
        return false;
    }
    // Refreshes and payout-address replacements are intentionally accepted.
    // That is the v30.1.0 monetary behavior and keeps a participant active
    // without a one-block gap at the inclusive 18,900-block boundary.
    return true;
}

ShadowProofValidationResult CheckShadowPowClaimForMempoolDetailed(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason)
{
    if (!TransactionHasShadowProof(tx)) return ShadowProofValidationResult::VALID;
    if (!gold_rush_active || !pindexPrev) {
        reject_reason = "shadow-proof-inactive";
        return ShadowProofValidationResult::INVALID;
    }
    if (tx.IsCoinBase() || tx.IsCoinStake()) {
        reject_reason = "shadow-proof-invalid-location";
        return ShadowProofValidationResult::INVALID;
    }

    const int height = pindexPrev->nHeight + 1;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) {
        reject_reason = "shadow-proof-height";
        return ShadowProofValidationResult::INVALID;
    }

    bool pool_state_valid{true};
    ShadowPoolState pool = ReadPool(view, &pool_state_valid);
    if (!pool_state_valid) {
        reject_reason = "shadow-proof-pool-state";
        return ShadowProofValidationResult::INVALID;
    }
    const CAmount reward = ShadowBaseReward(height);
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, reward / 2);
    if (!next_pow_amount) {
        reject_reason = "shadow-proof-pool-overflow";
        return ShadowProofValidationResult::INVALID;
    }
    pool.pow_amount = *next_pow_amount;

    std::vector<valtype> proofs;
    for (const CTxOut& out : tx.vout) {
        const auto proof = ExtractProofPayload(out.scriptPubKey);
        if (proof) proofs.push_back(*proof);
    }
    if (proofs.size() != 1) {
        reject_reason = "shadow-proof-duplicate";
        return ShadowProofValidationResult::INVALID;
    }

    unsigned int proof_evals = 0;
    bool proof_limit_exceeded = false;
    const ShadowProofPayloadMode payload_mode = ClassifyProofPayloadMode(proofs.front());
    if (payload_mode == ShadowProofPayloadMode::POS) {
        reject_reason = "shadow-proof-wrong-mode-pos";
        return ShadowProofValidationResult::INVALID;
    }
    if (payload_mode == ShadowProofPayloadMode::UNKNOWN) {
        reject_reason = "shadow-proof-unknown-mode";
        return ShadowProofValidationResult::INVALID;
    }

    ShadowProof decoded_shape;
    if (!DecodeProof(proofs.front(), decoded_shape)) {
        reject_reason = "shadow-proof-invalid";
        return ShadowProofValidationResult::INVALID;
    }

    int proof_height = height;
    uint256 proof_previous_block_hash = pindexPrev->GetBlockHash();
    unsigned int proof_target_bits = RetargetedBits(
        ShadowProofMode::POW, pool, height);
    if (decoded_shape.origin_bound) {
        const Consensus::Params& consensus = Params().GetConsensus();
        if (!consensus.IsShadowCompetingClaimsActive(
                static_cast<int>(decoded_shape.origin_height)) ||
            decoded_shape.origin_height > static_cast<uint32_t>(height)) {
            reject_reason = "shadow-proof-origin-mismatch";
            return ShadowProofValidationResult::INVALID;
        }
        const uint32_t age = static_cast<uint32_t>(height) -
                             decoded_shape.origin_height;
        if (age > SHADOW_POW_LATE_ORIGIN_WINDOW) {
            reject_reason = "shadow-proof-origin-expired";
            return ShadowProofValidationResult::INVALID;
        }
        const CBlockIndex* origin_parent = SafeGetAncestor(
            pindexPrev, static_cast<int>(decoded_shape.origin_height) - 1);
        if (!origin_parent ||
            origin_parent->GetBlockHash() !=
                decoded_shape.origin_previous_block_hash) {
            reject_reason = "shadow-proof-origin-mismatch";
            return ShadowProofValidationResult::INVALID;
        }
        proof_height = static_cast<int>(decoded_shape.origin_height);
        proof_previous_block_hash = decoded_shape.origin_previous_block_hash;
        if (age > 0) {
            const CBlockIndex* origin_block = SafeGetAncestor(
                pindexPrev, proof_height);
            const std::optional<ShadowPoolUndoState> origin_undo =
                ReadAuthenticatedPoolUndo(view, origin_block, consensus);
            if (!origin_undo) {
                reject_reason = "local-shadow-proof-origin-state";
                return ShadowProofValidationResult::LOCAL_INTERNAL_ERROR;
            }
            ShadowPoolState origin_pool = origin_undo->previous;
            const auto origin_pow_amount = CheckedAddMoney(
                origin_pool.pow_amount, ShadowBaseReward(proof_height) / 2);
            if (!origin_pow_amount) {
                reject_reason = "local-shadow-proof-origin-state";
                return ShadowProofValidationResult::LOCAL_INTERNAL_ERROR;
            }
            origin_pool.pow_amount = *origin_pow_amount;
            proof_target_bits = RetargetedBits(
                ShadowProofMode::POW, origin_pool, proof_height);
        }
    }

    ShadowProof decoded;
    const ShadowProofValidationResult status = ValidateQQProofAtBits(
        proofs.front(), proof_height, proof_previous_block_hash,
        proof_target_bits, decoded, proof_evals, proof_limit_exceeded);
    if (proof_limit_exceeded) {
        reject_reason = "shadow-proof-limit";
        return ShadowProofValidationResult::INVALID;
    }
    if (status != ShadowProofValidationResult::VALID) {
        reject_reason = status == ShadowProofValidationResult::LOCAL_INTERNAL_ERROR
            ? "local-shadow-proof-error"
            : "shadow-proof-invalid";
        return status;
    }

    bool spends_target = false;
    const CScript canonical_target = CanonicalLegacyStakeScript(decoded.target);
    for (const CTxIn& txin : tx.vin) {
        Coin coin;
        if (view.GetCoin(txin.prevout, coin) && !coin.IsSpent() &&
            CanonicalLegacyStakeScript(coin.out.scriptPubKey) == canonical_target) {
            spends_target = true;
            break;
        }
    }
    if (!spends_target) {
        reject_reason = "shadow-proof-input-mismatch";
        return ShadowProofValidationResult::INVALID;
    }

    return ShadowProofValidationResult::VALID;
}

bool CheckShadowPowClaimForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason)
{
    return CheckShadowPowClaimForMempoolDetailed(tx, pindexPrev, view, gold_rush_active, reject_reason) ==
           ShadowProofValidationResult::VALID;
}

std::set<CScript> BuildLegacyWhitelist(CCoinsView& view)
{
    std::set<CScript> whitelist;
    std::map<CScript, CAmount> balances;
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    // Scanning the full mainnet UTXO set takes minutes; heartbeat to the log
    // so the one-off snapshot at the whitelist height does not look like a
    // hang to node operators watching a frozen progress bar.
    uint64_t scanned{0};
    LogPrintf("Quantum Quasar: building the legacy whitelist snapshot from the UTXO set; this one-time scan can take several minutes...\n");
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (++scanned % 2000000 == 0) {
            LogPrintf("Quantum Quasar: whitelist snapshot scan progress: %u million coins scanned, %u qualifying scripts so far\n",
                      scanned / 1000000, whitelist.size());
        }
        if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent()) {
            if (coin.out.nValue > 0 && IsLegacyShadowTargetScript(coin.out.scriptPubKey)) {
                const CScript script = CanonicalLegacyStakeScript(coin.out.scriptPubKey);
                CAmount& balance = balances[script];
                if (balance < SHADOW_WHITELIST_MIN_BALANCE) {
                    const CAmount needed = SHADOW_WHITELIST_MIN_BALANCE - balance;
                    balance = coin.out.nValue >= needed ? SHADOW_WHITELIST_MIN_BALANCE : balance + coin.out.nValue;
                    if (balance >= SHADOW_WHITELIST_MIN_BALANCE) {
                        whitelist.insert(script);
                    }
                }
            }
        }
        cursor->Next();
    }
    LogPrintf("Quantum Quasar: whitelist snapshot scan complete: %u coins scanned, %u whitelisted scripts\n", scanned, whitelist.size());
    return whitelist;
}

void SaveLegacyWhitelist(const fs::path& path, const std::set<CScript>& whitelist)
{
    CAutoFile fileout{fsbridge::fopen(path, "wb")};
    if (fileout.IsNull()) {
        LogPrintf("Quantum Quasar: Error opening %s for writing\n", fs::PathToString(path));
        return;
    }
    try {
        fileout << whitelist;
        LogPrintf("Quantum Quasar: Saved diagnostic legacy whitelist to %s (%u entries)\n", fs::PathToString(path), whitelist.size());
    } catch (const std::exception& e) {
        LogPrintf("Quantum Quasar: Error saving whitelist to %s: %s\n", fs::PathToString(path), e.what());
    }
}

bool LoadLegacyWhitelist(const fs::path& path, std::set<CScript>& whitelist)
{
    CAutoFile filein{fsbridge::fopen(path, "rb")};
    if (filein.IsNull()) return false;
    try {
        filein >> whitelist;
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Quantum Quasar: Error loading whitelist from %s: %s\n", fs::PathToString(path), e.what());
        whitelist.clear();
        return false;
    }
}

bool ApplyLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex, const fs::path* dump_path)
{
    if (!pindex || pindex->nHeight != SHADOW_WHITELIST_HEIGHT) return false;
    const std::set<CScript> whitelist = BuildLegacyWhitelist(view);
    const uint256 snapshot_hash = pindex->GetBlockHash();
    valtype manifest_blob;
    if (!EncodeWhitelistBlob(whitelist, manifest_blob)) {
        LogPrintf("ERROR: Quantum Quasar whitelist snapshot exceeds the authenticated manifest bounds\n");
        return false;
    }
    WhitelistManifest manifest;
    manifest.snapshot_height = pindex->nHeight;
    manifest.snapshot_hash = snapshot_hash;
    manifest.entry_count = static_cast<uint32_t>(whitelist.size());
    manifest.total_size = static_cast<uint32_t>(manifest_blob.size());
    manifest.shard_count = BlobShardCount(manifest_blob.size());
    manifest.blob_hash = HashStateBlob("Quantum Quasar Whitelist Manifest Blob v1", manifest_blob);
    if (manifest.shard_count == 0) return false;

    for (const CScript& script : whitelist) {
        const valtype member_payload = EncodeWhitelistMember(
            snapshot_hash, manifest.blob_hash, script);
        if (member_payload.empty()) return false;
        Coin coin;
        coin.out.nValue = 0;
        coin.out.scriptPubKey = MarkerScript(MARKER_WHITELIST, member_payload);
        if (coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
        coin.fCoinBase = true;
        coin.fCoinStake = false;
        coin.nHeight = pindex->nHeight;
        coin.nTime = pindex->GetBlockTime();
        view.AddCoin(WhitelistOutpoint(script), std::move(coin), true);
    }
    Coin manifest_coin;
    manifest_coin.out.nValue = 0;
    manifest_coin.out.scriptPubKey = MarkerScript(MARKER_WHITELIST_MANIFEST, EncodeWhitelistManifest(manifest));
    manifest_coin.fCoinBase = true;
    manifest_coin.fCoinStake = false;
    manifest_coin.nHeight = pindex->nHeight;
    manifest_coin.nTime = pindex->GetBlockTime();
    view.AddCoin(WhitelistManifestOutpoint(), std::move(manifest_coin), true);
    for (uint32_t shard_index = 0; shard_index < manifest.shard_count; ++shard_index) {
        const valtype shard_payload = EncodeBlobShard(snapshot_hash, shard_index, manifest.shard_count,
                                                      manifest_blob.size(), manifest_blob);
        if (shard_payload.empty()) return false;
        Coin shard_coin;
        shard_coin.out.nValue = 0;
        shard_coin.out.scriptPubKey = MarkerScript(MARKER_WHITELIST_SHARD, shard_payload);
        if (shard_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE) return false;
        shard_coin.fCoinBase = true;
        shard_coin.fCoinStake = false;
        shard_coin.nHeight = pindex->nHeight;
        shard_coin.nTime = pindex->GetBlockTime();
        view.AddCoin(WhitelistManifestShardOutpoint(snapshot_hash, shard_index), std::move(shard_coin), true);
    }
    valtype ready_payload(4 + uint256::size() + 4);
    WriteLE32(ready_payload.data(), static_cast<uint32_t>(pindex->nHeight));
    std::copy(snapshot_hash.begin(), snapshot_hash.end(), ready_payload.begin() + 4);
    WriteLE32(ready_payload.data() + 4 + uint256::size(), static_cast<uint32_t>(whitelist.size()));
    Coin ready_coin;
    ready_coin.out.nValue = 0;
    ready_coin.out.scriptPubKey = MarkerScript(MARKER_WHITELIST_READY, ready_payload);
    ready_coin.fCoinBase = true;
    ready_coin.fCoinStake = false;
    ready_coin.nHeight = pindex->nHeight;
    ready_coin.nTime = pindex->GetBlockTime();
    view.AddCoin(WhitelistReadyOutpoint(), std::move(ready_coin), true);
    if (dump_path) SaveLegacyWhitelist(*dump_path, whitelist);
    LogPrintf("Quantum Quasar: Applied deterministic legacy whitelist snapshot with %u entries\n", whitelist.size());
    return true;
}

bool UndoLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex)
{
    if (!pindex || pindex->nHeight != SHADOW_WHITELIST_HEIGHT) return false;
    uint32_t removed = 0;
    WhitelistManifest manifest;
    std::set<CScript> whitelist;
    if (!ReadWhitelistManifest(view, pindex, manifest, &whitelist)) return false;
    for (const CScript& script : whitelist) {
        const COutPoint outpoint = WhitelistOutpoint(script);
        if (view.SpendCoin(outpoint)) ++removed;
    }
    for (uint32_t shard_index = 0; shard_index < manifest.shard_count; ++shard_index) {
        if (!view.SpendCoin(WhitelistManifestShardOutpoint(manifest.snapshot_hash, shard_index))) return false;
    }
    if (!view.SpendCoin(WhitelistManifestOutpoint())) return false;
    view.SpendCoin(WhitelistReadyOutpoint());
    LogPrintf("Quantum Quasar: Removed %u legacy whitelist snapshot markers during reorg\n", removed);
    return true; // compact member coins are an optional O(1) cache; manifest is authoritative
}

bool HasLegacyWhitelistSnapshot(const CCoinsViewCache& view)
{
    WhitelistManifest manifest;
    if (!ReadWhitelistManifest(view, /*pindex=*/nullptr, manifest)) return false;
    Coin ready_coin;
    valtype payload;
    if (!view.GetCoin(WhitelistReadyOutpoint(), ready_coin) || ready_coin.IsSpent() ||
        ready_coin.out.nValue != 0 || !ready_coin.fCoinBase || ready_coin.fCoinStake ||
        ready_coin.nHeight != manifest.snapshot_height ||
        ready_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !ParseMarkerScript(ready_coin.out.scriptPubKey, MARKER_WHITELIST_READY, &payload) ||
        payload.size() != 2 * sizeof(uint32_t) + uint256::size()) return false;
    uint256 ready_hash;
    std::copy(payload.begin() + sizeof(uint32_t),
              payload.begin() + sizeof(uint32_t) + uint256::size(), ready_hash.begin());
    return ReadLE32(payload.data()) == manifest.snapshot_height &&
           ready_hash == manifest.snapshot_hash &&
           ReadLE32(payload.data() + sizeof(uint32_t) + uint256::size()) == manifest.entry_count &&
           ready_coin.nTime == view.AccessCoin(WhitelistManifestOutpoint()).nTime;
}

bool IsWhitelisted(const CCoinsViewCache& view, const CScript& scriptPubKey)
{
    const CScript script = CanonicalLegacyStakeScript(scriptPubKey);
    if (!IsLegacyShadowTargetScript(script)) return false;
    WhitelistManifest manifest;
    Coin manifest_coin;
    if (!view.GetCoin(WhitelistManifestOutpoint(), manifest_coin) || manifest_coin.IsSpent() ||
        manifest_coin.out.nValue != 0 || !manifest_coin.fCoinBase || manifest_coin.fCoinStake ||
        manifest_coin.nHeight != static_cast<uint32_t>(SHADOW_WHITELIST_HEIGHT) ||
        manifest_coin.out.scriptPubKey.size() > MAX_SCRIPT_SIZE ||
        !DecodeWhitelistManifest(manifest_coin.out.scriptPubKey, manifest)) return false;

    Coin member_coin;
    valtype member_payload;
    if (view.GetCoin(WhitelistOutpoint(script), member_coin) && !member_coin.IsSpent() &&
        member_coin.out.nValue == 0 && member_coin.fCoinBase && !member_coin.fCoinStake &&
        member_coin.nHeight == manifest.snapshot_height && member_coin.nTime == manifest_coin.nTime &&
        member_coin.out.scriptPubKey.size() <= MAX_SCRIPT_SIZE &&
        ParseMarkerScript(member_coin.out.scriptPubKey, MARKER_WHITELIST, &member_payload)) {
        WhitelistMemberRecord member;
        if (DecodeWhitelistMember(member_payload, member) &&
            member.snapshot_hash == manifest.snapshot_hash &&
            member.manifest_hash == manifest.blob_hash &&
            member.script == script) {
            return true;
        }
        // v30.1.0/v30.1.1 prerelease cache bridge. The sharded manifest below
        // remains authoritative, and schema-11 replay rewrites this as v3.
        if (member_payload.size() == 1 + 3 * uint256::size() && member_payload[0] == 2) {
            uint256 snapshot_hash;
            uint256 manifest_hash;
            uint256 script_hash;
            std::copy(member_payload.begin() + 1,
                      member_payload.begin() + 1 + uint256::size(), snapshot_hash.begin());
            std::copy(member_payload.begin() + 1 + uint256::size(),
                      member_payload.begin() + 1 + 2 * uint256::size(), manifest_hash.begin());
            std::copy(member_payload.begin() + 1 + 2 * uint256::size(), member_payload.end(), script_hash.begin());
            if (snapshot_hash == manifest.snapshot_hash &&
                manifest_hash == manifest.blob_hash &&
                script_hash == TaggedHash("Quantum Quasar Whitelist Member v2", {script.begin(), script.end()})) {
                return true;
            }
        }
    }

    // The sharded manifest is authoritative. Falling back to it prevents one
    // missing compact lookup coin from changing signal eligibility; replay can
    // later recreate the O(1) member cache.
    std::set<CScript> whitelist;
    return ReadWhitelistManifest(view, /*pindex=*/nullptr, manifest, &whitelist) &&
           whitelist.count(script) != 0;
}

bool BuildShadowSignalData(const CScript& target, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    (void)target;
    (void)solve_height;
    (void)solve_hash;
    return false;
}

bool BuildShadowSignalData(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    const CScript canonical_target = CanonicalLegacyStakeScript(target);
    if (canonical_target.empty() || canonical_target.IsUnspendable()) return false;
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) return false;
    if (canonical_target.size() > std::numeric_limits<uint16_t>::max() || quantum_payout_script.size() > std::numeric_limits<uint16_t>::max()) return false;
    if ((solve_height == 0) != solve_hash.IsNull()) return false;
    const valtype payload = EncodeSignalPayloadV2(canonical_target, quantum_payout_script, solve_height, solve_hash);
    data_out = SIGNAL_PREFIX;
    data_out.insert(data_out.end(), payload.begin(), payload.end());
    return true;
}

bool MineShadowProofData(const CScript& target, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool proof_of_stake, uint64_t max_tries, std::vector<unsigned char>& data_out)
{
    data_out.clear();
    (void)target;
    (void)pindexPrev;
    (void)view;
    (void)proof_of_stake;
    (void)max_tries;
    return false;
}

bool MineShadowProofData(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t max_tries, std::vector<unsigned char>& data_out)
{
    return MineShadowProofDataRange(target, quantum_payout_script, pindexPrev, view, 0, 1, max_tries, data_out);
}

ShadowPowWork PrepareShadowPowWork(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view)
{
    ShadowPowWork work;
    if (!pindexPrev) return work;
    const int height = pindexPrev->nHeight + 1;
    if (height < SHADOW_REWARD_START_HEIGHT || height > SHADOW_REWARD_END_HEIGHT) return work;
    const CScript canonical_target = CanonicalLegacyStakeScript(target);
    if (canonical_target.empty() || canonical_target.IsUnspendable()) return work;
    if (IsQuantumMigrationScript(canonical_target) || IsQuantumColdStakeScript(canonical_target) || IsEUTXOScript(canonical_target)) return work;
    if (!IsDirectQuantumMigrationScript(quantum_payout_script)) return work;
    if (canonical_target.size() > std::numeric_limits<uint16_t>::max() || quantum_payout_script.size() > std::numeric_limits<uint16_t>::max()) return work;
    work.origin_bound = Params().GetConsensus().IsShadowCompetingClaimsActive(height);
    const size_t origin_size = work.origin_bound ? PROOF_V3_ORIGIN_SIZE : 0;
    if (SHADOW_PREFIX.size() + PROOF_SIZE + origin_size + 4 +
        canonical_target.size() + quantum_payout_script.size() >
        MAX_SCRIPT_ELEMENT_SIZE) return work;

    // The ONLY coins-view read: snapshot the shadow pool and derive this tip's difficulty.
    bool pool_state_valid{true};
    ShadowPoolState pool = ReadPool(view, &pool_state_valid);
    if (!pool_state_valid) return work;
    const CAmount reward = ShadowBaseReward(height);
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, reward / 2);
    if (!next_pow_amount) return work;
    pool.pow_amount = *next_pow_amount;

    work.bits = RetargetedBits(ShadowProofMode::POW, pool, height);
    work.target = canonical_target;
    work.quantum_payout_script = quantum_payout_script;
    work.height = height;
    work.prev_hash = pindexPrev->GetBlockHash();
    work.valid = true;
    return work;
}

ShadowPowGrindResult GrindShadowPowWorkDetailed(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done)
{
    // Pure Argon2id grind. Touches no chain state, so it must run WITHOUT cs_main held.
    data_out.clear();
    if (tries_done) *tries_done = 0;
    if (!work.valid || nonce_step == 0 || max_tries == 0) return ShadowPowGrindResult::INVALID_WORK;
    if (work.origin_bound !=
        Params().GetConsensus().IsShadowCompetingClaimsActive(work.height)) {
        return ShadowPowGrindResult::INVALID_WORK;
    }
    uint64_t nonce = start_nonce;
    for (uint64_t tries = 0; tries < max_tries; ++tries) {
        if (tries_done) *tries_done = tries + 1;
        uint256 proof_hash;
        if (!ComputeShadowProofHash(work.target, work.quantum_payout_script, work.height, work.prev_hash, ShadowProofMode::POW, nonce, proof_hash)) {
            return ShadowPowGrindResult::LOCAL_INTERNAL_ERROR;
        }
        if (HashMeetsLeadingZeroBits(proof_hash, work.bits)) {
            const valtype payload = work.origin_bound
                ? EncodeProofPayloadV3(ShadowProofMode::POW, nonce,
                                       static_cast<uint32_t>(work.height),
                                       work.prev_hash, work.target,
                                       work.quantum_payout_script)
                : EncodeProofPayloadV2(ShadowProofMode::POW, nonce, work.target,
                                       work.quantum_payout_script);
            data_out = SHADOW_PREFIX;
            data_out.insert(data_out.end(), payload.begin(), payload.end());
            return ShadowPowGrindResult::FOUND;
        }
        // `nonce_step` is normally 1 for contiguous atomic ranges. The overflow
        // guard keeps a long-running miner from wrapping into already-searched space.
        if (std::numeric_limits<uint64_t>::max() - nonce < nonce_step) break;
        nonce += nonce_step;
    }
    return ShadowPowGrindResult::EXHAUSTED;
}

bool GrindShadowPowWork(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done)
{
    return GrindShadowPowWorkDetailed(work, start_nonce, nonce_step, max_tries, data_out, tries_done) ==
           ShadowPowGrindResult::FOUND;
}

ShadowProofValidationResult ValidateShadowPowProofForWorkDetailed(const ShadowPowWork& work, const std::vector<unsigned char>& prefixed_proof)
{
    if (!work.valid) return ShadowProofValidationResult::INVALID;
    if (work.origin_bound !=
        Params().GetConsensus().IsShadowCompetingClaimsActive(work.height)) {
        return ShadowProofValidationResult::INVALID;
    }
    const std::vector<unsigned char>& prefix = GetShadowPrefix();
    if (prefixed_proof.size() <= prefix.size() ||
        prefixed_proof.size() > MAX_SCRIPT_ELEMENT_SIZE ||
        !std::equal(prefix.begin(), prefix.end(), prefixed_proof.begin())) {
        return ShadowProofValidationResult::INVALID;
    }

    const valtype proof(prefixed_proof.begin() + prefix.size(), prefixed_proof.end());
    ShadowProof decoded;
    if (!DecodeProof(proof, decoded)) return ShadowProofValidationResult::INVALID;
    if (decoded.mode != ShadowProofMode::POW || !decoded.quantum_linked) return ShadowProofValidationResult::INVALID;
    if (decoded.target != work.target || decoded.payout_script != work.quantum_payout_script) return ShadowProofValidationResult::INVALID;
    if (work.origin_bound != decoded.origin_bound) return ShadowProofValidationResult::INVALID;
    if (decoded.origin_bound &&
        (decoded.origin_height != static_cast<uint32_t>(work.height) ||
         decoded.origin_previous_block_hash != work.prev_hash)) {
        return ShadowProofValidationResult::INVALID;
    }

    uint256 proof_hash;
    if (!ComputeShadowProofHash(decoded.target, decoded.payout_script, work.height, work.prev_hash, decoded.mode, decoded.nonce, proof_hash)) {
        return ShadowProofValidationResult::LOCAL_INTERNAL_ERROR;
    }
    return HashMeetsLeadingZeroBits(proof_hash, work.bits)
        ? ShadowProofValidationResult::VALID
        : ShadowProofValidationResult::INVALID;
}

bool ValidateShadowPowProofForWork(const ShadowPowWork& work, const std::vector<unsigned char>& prefixed_proof)
{
    return ValidateShadowPowProofForWorkDetailed(work, prefixed_proof) ==
           ShadowProofValidationResult::VALID;
}

bool MineShadowProofDataRange(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done)
{
    // Convenience wrapper (used by the RPC path): prepare under the caller's lock, then grind.
    const ShadowPowWork work = PrepareShadowPowWork(target, quantum_payout_script, pindexPrev, view);
    return GrindShadowPowWork(work, start_nonce, nonce_step, max_tries, data_out, tries_done);
}

static ShadowApplyResult ApplyShadowBlockToCache(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    if (!gold_rush_active) return ShadowApplyResult::OK;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return ShadowApplyResult::OK;
    Coin undo_pool_coin;
    ShadowPoolState undo_pool;
    const ShadowPoolReadResult pool_state_result = ReadPoolState(view, undo_pool);
    if (pool_state_result == ShadowPoolReadResult::INVALID) {
        LogPrintf("ERROR: Quantum Quasar shadow pool state is malformed at height %d; refusing to overwrite it\n",
                  pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    const bool undo_pool_present = pool_state_result == ShadowPoolReadResult::VALID;
    if (undo_pool_present &&
        (!view.GetCoin(PoolOutpoint(), undo_pool_coin) || undo_pool_coin.IsSpent())) {
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    ShadowPoolState pool = undo_pool;
    const CAmount reward = ShadowBaseReward(pindex->nHeight);
    const CAmount pow_reward = reward / 2;
    const CAmount pos_reward = reward - pow_reward;
    const auto next_pow_amount = CheckedAddMoney(pool.pow_amount, pow_reward);
    const auto next_pos_amount = CheckedAddMoney(pool.pos_amount, pos_reward);
    if (!next_pow_amount || !next_pos_amount) {
        LogPrintf("ERROR: Quantum Quasar shadow jackpot pool overflow at height %d\n", pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    pool.pow_amount = *next_pow_amount;
    pool.pos_amount = *next_pos_amount;
    if (!ShadowObligationWithinCap(pool)) {
        LogPrintf("ERROR: Quantum Quasar shadow emission cap exceeded at height %d\n", pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }

    const ShadowPoolState credited_pool = pool;

    const std::optional<CScript> current_solver = GetCurrentSolverScript(view, block, blockundo);
    std::map<CScript, ShadowActiveSignal> prior_signal_state;
    uint32_t prior_signal_marker_height{0};
    uint32_t prior_signal_marker_time{0};
    uint256 prior_signal_marker_hash;
    const ActiveSignalStateReadResult signal_state_result = ReadActiveSignalStateMarker(
        view, pindex->pprev, prior_signal_state, prior_signal_marker_height,
        prior_signal_marker_time, prior_signal_marker_hash);
    if (!ActiveSignalPoolPairValid(Params().GetConsensus(), pindex->pprev,
                                   pool_state_result, signal_state_result)) {
        LogPrintf("ERROR: Quantum Quasar shadow pool/active-signal state pair is missing or malformed at height %d; replay is required\n",
                  pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    const bool prior_signal_state_present = signal_state_result == ActiveSignalStateReadResult::VALID;
    const std::optional<uint32_t> whitelist_count = ReadAuthenticatedWhitelistCount(view, pindex);
    if (!whitelist_count || prior_signal_state.size() > *whitelist_count) {
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    std::map<CScript, ShadowActiveSignal> active_signal_state = prior_signal_state;
    FilterActiveSignals(active_signal_state, pindex->nHeight);
    const std::map<CScript, CScript> current_signals =
        FindValidShadowSignalsInBlock(view, block, pindex, blockundo);
    if (!ValidateActiveSignalMarkers(pindex, current_signals)) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    UpsertActiveSignals(active_signal_state, current_signals, pindex->nHeight);
    if (active_signal_state.size() > *whitelist_count) {
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    const std::map<CScript, CScript> active_signals = ActiveSignalPayoutScripts(active_signal_state);
    ShadowPowClaimResult pow_claim = FindPowShadowClaims(
        view, block, pindex, blockundo, credited_pool,
        Params().GetConsensus());
    if (pow_claim.internal_error) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    if (pow_claim.competing_claims) {
        LogPrintf("Quantum Quasar: evaluated %u competing QQPROOF claims at height %d; reimbursed %u valid losers under the canonical monetary rule\n",
            pow_claim.valid_claim_count, pindex->nHeight, pow_claim.reimbursed_claim_count);
    }
    if (pow_claim.malformed_claim) {
        LogPrintf("Quantum Quasar: ignored a transaction with multiple QQPROOF outputs at height %d; malformed claims receive no reimbursement\n",
            pindex->nHeight);
    }
    if (pow_claim.invalid_claim_location) {
        LogPrintf("Quantum Quasar: ignored QQPROOF outside a regular fee-paying transaction in a PoS block at height %d\n",
            pindex->nHeight);
    }
    if (pow_claim.wrong_mode_claim) {
        LogPrintf("Quantum Quasar: ignored fee-paying QQSPROOF with PoS mode at height %d; PoS mode cannot consume either shadow pool\n",
            pindex->nHeight);
    }
    if (pow_claim.unknown_mode_claim) {
        LogPrintf("Quantum Quasar: ignored fee-paying QQSPROOF with an unknown mode at height %d; unknown modes receive no shadow credit\n",
            pindex->nHeight);
    }
    if (pow_claim.proof_limit_exceeded) {
        LogPrintf("Quantum Quasar: ignored QQPROOF claims at height %d after the %u-proof validation limit; block remains legacy-compatible\n",
            pindex->nHeight, MAX_SHADOW_POW_EVALS_PER_BLOCK);
    }

    std::map<CScript, CAmount> pos_payouts;
    CAmount pos_payout_total{0};
    if (!BuildPosPayouts(credited_pool, current_solver, active_signals, /*require_quantum_payouts=*/true, pos_payouts, pos_payout_total)) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;

    std::vector<ShadowClaim> claims_to_apply;
    if (pos_payout_total > 0) {
        if (!AddClaimedAmount(pool, pos_payout_total)) {
            LogPrintf("ERROR: Quantum Quasar POS shadow claim exceeds emission cap at height %d\n", pindex->nHeight);
            return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
        }
        for (const auto& [payout_script, amount] : pos_payouts) {
            if (amount <= 0) continue;
            ShadowClaim claim{payout_script, amount, ShadowProofMode::POS, undo_pool, true};
            if (!IsValidDirectClaimMarker(pindex, claim)) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
            claims_to_apply.push_back(std::move(claim));
        }
        AddPosSolve(pool, pindex->nHeight);
        pool.pos_amount = 0;
        LogPrintf("Quantum Quasar: Accepted quantum-linked POS shadow-ledger credit at height %d for %u active participants\n",
            pindex->nHeight,
            active_signals.size());
    }

    if (!pow_claim.credits.empty()) {
        CAmount pow_claim_total{0};
        for (const ShadowPowCredit& credit : pow_claim.credits) {
            const auto next_total = CheckedAddMoney(pow_claim_total, credit.amount);
            if (!next_total || !AddClaimedAmount(pool, credit.amount)) {
                LogPrintf("ERROR: Quantum Quasar POW shadow claims exceed the pool or emission cap at height %d\n", pindex->nHeight);
                return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
            }
            pow_claim_total = *next_total;
            ShadowClaim claim{credit.payout_script, credit.amount,
                              ShadowProofMode::POW, undo_pool, true};
            if (!IsValidDirectClaimMarker(pindex, claim)) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
            claims_to_apply.push_back(std::move(claim));
        }
        if (pow_claim.current_winner) {
            if (pow_claim_total != credited_pool.pow_amount) {
                LogPrintf("ERROR: Quantum Quasar canonical POW winner block does not exhaust exactly the fixed pool at height %d\n", pindex->nHeight);
                return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
            }
            AddPowSolve(pool, pindex->nHeight);
            pool.pow_amount = 0;
        } else {
            if (pow_claim_total <= 0 || pow_claim_total > pool.pow_amount) {
                LogPrintf("ERROR: Quantum Quasar late-origin reimbursements exceed the fixed pool at height %d\n", pindex->nHeight);
                return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
            }
            pool.pow_amount -= pow_claim_total;
        }
        LogPrintf("Quantum Quasar: accepted %u quantum-linked POW shadow-ledger credits at height %d for %d satoshis%s\n",
            pow_claim.credits.size(), pindex->nHeight, pow_claim_total,
            pow_claim.current_winner ? " including the current-origin winner" : " in late-origin fee reimbursements only");
    }
    if (!ShadowObligationWithinCap(pool)) {
        LogPrintf("ERROR: Quantum Quasar shadow obligation cap exceeded at height %d\n", pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    const uint32_t synthetic_claim_limit = GetShadowSyntheticClaimLimit(
        Params().GetConsensus(), pindex->nHeight, *whitelist_count);
    if (pos_payouts.size() > *whitelist_count ||
        claims_to_apply.size() > synthetic_claim_limit) {
        LogPrintf("ERROR: Quantum Quasar synthetic claim count exceeds the authenticated marker bound at height %d\n",
                  pindex->nHeight);
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    if (current_solver) {
        AddSolverMarker(view, pindex, *current_solver);
    }
    // v30.1.0 append-only records are read only as an upgrade bridge. New
    // state is persisted in compressor-safe authenticated shards; duplicating
    // arbitrary legacy scripts into QQASIG marker coins can exceed the 10 kB
    // CTxOutCompressor limit after a flush.
    if (!prior_signal_state_present || !ActiveSignalMapsEqual(prior_signal_state, active_signal_state)) {
        if (!WriteActiveSignalStateChange(view, pindex,
                                          prior_signal_state_present,
                                          prior_signal_marker_height,
                                          prior_signal_marker_time,
                                          prior_signal_marker_hash,
                                          prior_signal_state,
                                          active_signal_state)) {
            return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
        }
    }
    uint32_t claim_marker_index = 0;
    for (const ShadowClaim& claim : claims_to_apply) {
        if (!AddClaimMarker(view, pindex, claim_marker_index++, claim)) return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    WritePool(view, pindex, pool);
    // The public wrapper evaluates against a child cache. This hook proves
    // that an allocation failure after a concrete staged mutation cannot
    // publish that partial state to the caller.
    MaybeThrowShadowAllocationFailureForTesting(
        ShadowAllocationFailurePoint::APPLY_AFTER_STAGED_MUTATION);
    if (!AddPoolUndoMarker(view, pindex, undo_pool_present, undo_pool_coin,
                           undo_pool, pool, claims_to_apply)) {
        return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
    }
    return ShadowApplyResult::OK;
}

ShadowApplyResult ApplyShadowBlockResult(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    if (!gold_rush_active || !pindex ||
        pindex->nHeight < SHADOW_REWARD_START_HEIGHT ||
        pindex->nHeight > SHADOW_REWARD_END_HEIGHT) {
        return ShadowApplyResult::OK;
    }
    try {
        MaybeThrowShadowAllocationFailureForTesting(
            ShadowAllocationFailurePoint::APPLY);

        // A shadow-layer failure may occur after several authenticated marker
        // writes have been prepared. Keep them isolated until every check and
        // write succeeds. ConnectTip and replay add an outer cache transaction,
        // so even a host allocation failure while publishing this child is
        // discarded rather than persisted or associated with block invalidity.
        CCoinsViewCache staged{&view};
        // An empty child cache has no lazy best-block value of its own. Preserve
        // the caller's anchor explicitly so publishing shadow-only writes can
        // never clear or advance the base-chain tip.
        staged.SetBestBlock(view.GetBestBlock());
        const ShadowApplyResult result = ApplyShadowBlockToCache(
            staged, block, pindex, blockundo, gold_rush_active);
        if (result != ShadowApplyResult::OK) return result;
        if (!staged.Flush()) {
            LogPrintf("ERROR: Quantum Quasar shadow-state staging flush failed at height %d\n",
                      pindex ? pindex->nHeight : -1);
            return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
        }
        return ShadowApplyResult::OK;
    } catch (const std::bad_alloc&) {
        LogPrintf("ERROR: Quantum Quasar shadow-state allocation failed at height %d\n",
                  pindex ? pindex->nHeight : -1);
    } catch (const std::length_error&) {
        LogPrintf("ERROR: Quantum Quasar shadow-state container bound failed at height %d\n",
                  pindex ? pindex->nHeight : -1);
    }
    return ShadowApplyResult::LOCAL_INTERNAL_ERROR;
}

bool ApplyShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    return ApplyShadowBlockResult(view, block, pindex, blockundo, gold_rush_active) == ShadowApplyResult::OK;
}

bool UndoShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, bool gold_rush_active)
{
    if (!gold_rush_active) return true;
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT || pindex->nHeight > SHADOW_REWARD_END_HEIGHT) return true;
    Coin current_pool_coin;
    if (!view.GetCoin(PoolOutpoint(), current_pool_coin) || current_pool_coin.IsSpent() ||
        current_pool_coin.out.nValue != 0 || !current_pool_coin.fCoinBase || current_pool_coin.fCoinStake ||
        current_pool_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
        current_pool_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime())) return false;
    ShadowPoolState pool;
    const ShadowPoolReadResult pool_result = ReadPoolState(view, pool);
    if (pool_result != ShadowPoolReadResult::VALID) return false;
    std::map<CScript, ShadowActiveSignal> active_signal_state;
    uint32_t active_marker_height{0};
    uint32_t active_marker_time{0};
    uint256 active_marker_hash;
    const ActiveSignalStateReadResult active_result = ReadActiveSignalStateMarker(
        view, pindex, active_signal_state, active_marker_height,
        active_marker_time, active_marker_hash);
    if (!ActiveSignalPoolPairValid(Params().GetConsensus(), pindex,
                                   pool_result, active_result)) return false;
    Coin pool_undo_coin;
    const COutPoint pool_undo_outpoint = PoolUndoOutpoint(pindex);
    ShadowPoolUndoState pool_undo;
    if (!view.GetCoin(pool_undo_outpoint, pool_undo_coin) || pool_undo_coin.IsSpent() ||
        pool_undo_coin.out.nValue != 0 || !pool_undo_coin.fCoinBase || pool_undo_coin.fCoinStake ||
        pool_undo_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
        pool_undo_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
        !DecodePoolUndo(pool_undo_coin.out.scriptPubKey, pool_undo) ||
        pool_undo.block_hash != pindex->GetBlockHash() ||
        pool_undo.previous_block_hash != (pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{}) ||
        !PoolUndoClaimCountWithinBound(view, pindex, Params().GetConsensus(), pool_undo)) return false;
    uint256 post_pool_hash;
    if (!HashShadowPoolState(true, current_pool_coin.nHeight, current_pool_coin.nTime,
                             pindex->GetBlockHash(), pool, post_pool_hash) ||
        post_pool_hash != pool_undo.post_state_hash) return false;
    if (pool_undo.previous_present) {
        if (!pindex->pprev || pool_undo.previous_height > static_cast<uint32_t>(pindex->pprev->nHeight)) return false;
        const CBlockIndex* previous_pool_block = SafeGetAncestor(pindex->pprev, pool_undo.previous_height);
        if (!previous_pool_block || pool_undo.previous_time != static_cast<uint32_t>(previous_pool_block->GetBlockTime()) ||
            pool_undo.previous_marker_hash != previous_pool_block->GetBlockHash()) return false;
    }
    uint256 pre_pool_hash;
    if (!HashShadowPoolState(pool_undo.previous_present, pool_undo.previous_height,
                             pool_undo.previous_time, pool_undo.previous_marker_hash,
                             pool_undo.previous, pre_pool_hash) ||
        pre_pool_hash != pool_undo.pre_state_hash) return false;

    std::vector<ShadowClaim> block_claims;
    block_claims.reserve(pool_undo.claim_count);
    GoldRushInventoryState inventory;
    if (ReadGoldRushInventory(view, inventory) != GoldRushInventoryReadResult::VALID ||
        inventory.tip_hash != pindex->GetBlockHash()) return false;
    for (uint32_t marker_index = 0; marker_index < pool_undo.claim_count; ++marker_index) {
        const COutPoint claim_outpoint = ClaimOutpoint(pindex, marker_index);
        Coin claim_coin;
        if (!view.GetCoin(claim_outpoint, claim_coin) || claim_coin.IsSpent() ||
            claim_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
            claim_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime())) return false;
        const auto claim = DecodeClaimScript(claim_coin.out.scriptPubKey);
        if (!claim || !claim->direct || !IsValidDirectClaimMarker(pindex, *claim)) return false;
        block_claims.push_back(*claim);
        const COutPoint payout_outpoint = ClaimPayoutOutpoint(pindex, marker_index, *claim);
        const COutPoint payout_marker_outpoint = GoldRushPayoutOutpoint(payout_outpoint);
        Coin payout_coin;
        Coin payout_marker_coin;
        CScript payout_marker_script;
        if (!view.GetCoin(payout_outpoint, payout_coin) || payout_coin.IsSpent() ||
            payout_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
            payout_coin.out.nValue != claim->amount || payout_coin.out.scriptPubKey != claim->target ||
            !view.GetCoin(payout_marker_outpoint, payout_marker_coin) || payout_marker_coin.IsSpent() ||
            payout_marker_coin.nHeight != static_cast<uint32_t>(pindex->nHeight) ||
            !IsGoldRushDirectPayoutOutput(view, payout_outpoint, &payout_marker_script) ||
            payout_marker_script != claim->target) return false;
        GoldRushPayoutRecord payout_record;
        if (!AuthenticateGoldRushPayoutRecord(view, payout_outpoint, payout_record, nullptr) ||
            inventory.issued_count == 0 || inventory.issued_nominal < claim->amount) return false;
        const valtype payout_leaf = GoldRushPayoutLeaf(payout_record);
        inventory.issued_set.Remove(payout_leaf);
        inventory.unspent_set.Remove(payout_leaf);
        --inventory.issued_count;
        inventory.issued_nominal -= claim->amount;
        view.SpendCoin(payout_marker_outpoint);
        view.SpendCoin(payout_outpoint);
        view.SpendCoin(claim_outpoint);
    }
    if (view.HaveCoin(ClaimOutpoint(pindex, pool_undo.claim_count)) ||
        HashBlockClaims(pindex, block_claims) != pool_undo.claims_hash) return false;
    if (!WriteGoldRushInventory(view, pindex, std::move(inventory), /*finalize=*/false)) return false;
    // Remove the (at most one) solver marker this block added. ApplyShadowBlock stores it at
    // the deterministic SolverOutpoint(solver, height, blockhash), so when block-undo data is
    // available we recompute the solver and spend that exact outpoint -- avoiding a full
    // UTXO-set cursor scan on every disconnected block (reorg-DoS, H-3). The cursor scan is
    // retained only as a fallback for callers without undo data (e.g. some unit tests).
    if (blockundo) {
        const std::optional<CScript> solver = GetCurrentSolverScript(view, block, blockundo);
        if (solver) {
            const COutPoint solver_outpoint = SolverOutpoint(*solver, pindex->nHeight, pindex->GetBlockHash());
            if (view.HaveCoin(solver_outpoint)) view.SpendCoin(solver_outpoint);
        }
    } else {
        std::vector<COutPoint> solver_outpoints;
        {
            std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
            while (cursor->Valid()) {
                COutPoint outpoint;
                Coin coin;
                uint256 solver_hash;
                if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
                    coin.nHeight == static_cast<uint32_t>(pindex->nHeight) &&
                    DecodeSolverMarkerHash(coin.out.scriptPubKey, solver_hash)) {
                    CHashWriter ss;
                    ss << std::string("Quantum Quasar Recent Solver v2")
                       << solver_hash << pindex->nHeight << pindex->GetBlockHash();
                    if (outpoint == COutPoint{ss.GetHash(), 0}) {
                        solver_outpoints.push_back(outpoint);
                    }
                }
                cursor->Next();
            }
        }
        for (const COutPoint& solver_outpoint : solver_outpoints) {
            view.SpendCoin(solver_outpoint);
        }
    }
    if (!UndoActiveSignalMarkers(view, pindex, pool_undo.previous_present)) {
        LogPrintf("ERROR: Quantum Quasar active-signal undo authentication failed at height %d\n", pindex->nHeight);
        return false;
    }
    view.SpendCoin(PoolOutpoint());
    if (pool_undo.previous_present) {
        Coin restored_pool_coin;
        restored_pool_coin.out.nValue = 0;
        restored_pool_coin.out.scriptPubKey = MarkerScript(MARKER_POOL, EncodePool(pool_undo.previous));
        restored_pool_coin.fCoinBase = true;
        restored_pool_coin.fCoinStake = false;
        restored_pool_coin.nHeight = pool_undo.previous_height;
        restored_pool_coin.nTime = pool_undo.previous_time;
        view.AddCoin(PoolOutpoint(), std::move(restored_pool_coin), true);
    }
    view.SpendCoin(pool_undo_outpoint);
    ShadowPoolState restored_pool;
    const ShadowPoolReadResult restored_pool_result = ReadPoolState(view, restored_pool);
    std::map<CScript, ShadowActiveSignal> restored_active;
    uint32_t restored_active_height{0};
    uint32_t restored_active_time{0};
    uint256 restored_active_hash;
    const ActiveSignalStateReadResult restored_active_result =
        ReadActiveSignalStateMarker(view, pindex->pprev, restored_active,
                                    restored_active_height, restored_active_time,
                                    restored_active_hash);
    if (!ActiveSignalPoolPairValid(Params().GetConsensus(), pindex->pprev,
                                   restored_pool_result, restored_active_result)) {
        return false;
    }
    return true;
}
