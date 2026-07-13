#ifndef BLACKCOIN_SHADOW_H
#define BLACKCOIN_SHADOW_H

#include <consensus/amount.h>
#include <primitives/block.h>
#include <script/script.h>
#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

class CBlockIndex;
class CBlockUndo;
class CCoinsView;
class CCoinsViewCache;
struct Coin;
namespace Consensus {
struct Params;
}

struct ShadowGoldRushInfo {
    CAmount pow_amount{0};
    CAmount pos_amount{0};
    CAmount claimed_amount{0};
    uint32_t pow_count{0};
    uint32_t pos_count{0};
    uint32_t last_pow_height{0};
    uint32_t last_pos_height{0};
    uint8_t recent_count{0};
    uint64_t recent_modes{0};
    unsigned int pow_target_bits{0};
};

struct ShadowReplayStateInfo {
    uint32_t schema{0};
    bool required_for_tip{false};
    bool present{false};
    bool marker_valid{false};
    bool valid_for_tip{false};
    uint32_t marker_height{0};
    uint32_t marker_time{0};
    uint256 marker_block_hash{};
    std::vector<unsigned char> commitment{};
};

struct ShadowSolverActivity {
    uint32_t height{0};
    int64_t time{0};
};

struct ShadowClaimMarkerInfo {
    CScript target;
    CAmount amount{0};
    bool proof_of_work{false};
};

enum class ShadowPowClaimDisposition : uint8_t {
    INVALID_LOCATION,
    MALFORMED_TRANSACTION,
    INVALID_PROOF,
    INPUT_MISMATCH,
    INVALID_BASE_FEE,
    EVALUATION_LIMIT,
    WINNER,
    REIMBURSED_LOSER,
};

struct ShadowPowClaimAccounting {
    uint256 source_txid;
    uint32_t source_vout{0};
    uint256 canonical_rank;
    CScript payout_script;
    CAmount base_fee{0};
    CAmount credited_amount{0};
    bool base_fee_known{false};
    ShadowPowClaimDisposition disposition{ShadowPowClaimDisposition::INVALID_PROOF};
};

/** Immutable, lock-free input to the bounded claim-accounting engine. */
struct ShadowPowAccountingContext {
    int height{0};
    uint256 previous_block_hash;
    CAmount credited_pow_pool{0};
    unsigned int target_bits{0};
    bool canonical_rule_active{false};
    bool valid{false};
};

enum class ShadowPowAccountingResult {
    OK,
    LOCAL_INTERNAL_ERROR,
};

struct ShadowSyntheticPayoutCoin {
    COutPoint outpoint;
    CTxOut txout;
    uint32_t height{0};
    int64_t time{0};
};

struct ShadowSyntheticPayoutTransaction {
    CTransactionRef tx;
    CScript target;
    CAmount amount{0};
    bool proof_of_work{false};
};

// Immutable mainnet lifecycle anchors. Mutable schedule globals below exist
// only so one test-chain process can compress the window; production
// chainparams must derive consensus boundaries from these constants.
static constexpr int MAINNET_SHADOW_WHITELIST_HEIGHT = 5945000;
static constexpr int MAINNET_SHADOW_REWARD_START_HEIGHT = 5950000;
static constexpr int MAINNET_SHADOW_GOLD_RUSH_BLOCKS = (180 * 24 * 60 * 60) / 64;
static constexpr int MAINNET_SHADOW_REWARD_END_HEIGHT = MAINNET_SHADOW_REWARD_START_HEIGHT + MAINNET_SHADOW_GOLD_RUSH_BLOCKS - 1;
static constexpr int MAINNET_QUANTUM_MIGRATION_BLOCKS = (540 * 24 * 60 * 60) / 64;
static constexpr int MAINNET_QUANTUM_MIGRATION_END_HEIGHT = MAINNET_SHADOW_REWARD_END_HEIGHT + MAINNET_QUANTUM_MIGRATION_BLOCKS;
static constexpr int MAINNET_QUANTUM_FINAL_START_HEIGHT = MAINNET_QUANTUM_MIGRATION_END_HEIGHT + 1;
static_assert(MAINNET_SHADOW_REWARD_START_HEIGHT == 5950000);
static_assert(MAINNET_SHADOW_REWARD_END_HEIGHT == 6192999);
static_assert(MAINNET_QUANTUM_MIGRATION_END_HEIGHT == 6921999);
static_assert(MAINNET_QUANTUM_FINAL_START_HEIGHT == 6922000);

// Gold Rush schedule heights. Defaults are the mainnet values. The dedicated
// testnet schedule branch may override them on testnet/regtest only via
// -shadowwhitelistheight / -shadowgoldrushstartheight / -shadowgoldrushblocks so
// the reward window is reachable for manual public-testnet experiments.
// They are set once during chainparams init (before any block validation) and read-only
// thereafter, so the runtime globals are race-free.
extern int SHADOW_WHITELIST_HEIGHT;
extern int SHADOW_REWARD_START_HEIGHT;
extern int SHADOW_GOLD_RUSH_BLOCKS;
extern int SHADOW_PHASE1_END_HEIGHT;
extern int SHADOW_REWARD_END_HEIGHT;
extern int SHADOW_HALVING_INTERVAL_BLOCKS;
static constexpr int MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS = 43200;

/** Test-only: shift the Gold Rush schedule to a small, reachable window. */
void SetShadowTestSchedule(int whitelist_height, int reward_start_height, int gold_rush_blocks);
/** Test-only: compress the phase-one reward halving interval. */
void SetShadowTestHalvingInterval(int halving_interval_blocks);
/** Legacy regtest helper: shift the reward window to whitelist_height + 1. */
void SetShadowRegtestSchedule(int whitelist_height, int gold_rush_blocks);

/** Gold Rush reward accounting is height-gated so the legacy-compatible
 * distribution window cannot be skipped by an MTP schedule mismatch. */
bool IsShadowGoldRushRewardHeight(int nHeight);
bool IsShadowGoldRushRewardActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nHeight);

/** Quantum witness spends stay disabled through the legacy-compatible Gold Rush
 * and activate only after the reward-height window and in the migration/final-lockout phases. */
bool IsQuantumWitnessSpendActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight);
/** Tiered staking can activate only after quantum spending and its scheduled height are both active. */
bool IsQuantumStakeTiersActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight);
static constexpr unsigned int SHADOW_EQUAL_FOOTING_TIME = 1713938400;
static constexpr CAmount SHADOW_WHITELIST_MIN_BALANCE = 10000 * COIN;
static constexpr int SHADOW_SOLVER_ACTIVITY_SECONDS = 14 * 24 * 60 * 60;
static constexpr int SHADOW_SOLVER_ACTIVITY_WINDOW = SHADOW_SOLVER_ACTIVITY_SECONDS / 64;

/** Exact total value in the deterministic 180-day Gold Rush schedule.
 *  Direct payouts are bounded per block by ShadowBaseReward() and the coinstake
 *  reward cap; this invariant locks the total scheduled issuance against drift. */
static constexpr CAmount SHADOW_MAX_EMISSION = 51437700 * COIN;

/** Get the magic OP_RETURN prefix used for Quantum Quasar shadow proofs. */
const std::vector<unsigned char>& GetShadowPrefix();

/** Build the height-5,945,000 whitelist from aggregate balances in the currently connected UTXO view. */
std::set<CScript> BuildLegacyWhitelist(CCoinsView& view);

/** Optional diagnostic cache. Consensus must not trust this file. */
void SaveLegacyWhitelist(const fs::path& path, const std::set<CScript>& whitelist);
bool LoadLegacyWhitelist(const fs::path& path, std::set<CScript>& whitelist);

/** Apply/remove deterministic chainstate markers for the legacy whitelist snapshot. */
bool ApplyLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex, const fs::path* dump_path = nullptr);
bool UndoLegacyWhitelistSnapshot(CCoinsViewCache& view, const CBlockIndex* pindex);
bool HasLegacyWhitelistSnapshot(const CCoinsViewCache& view);

/** Check if a script is in the deterministic height-5,945,000 whitelist. */
bool IsWhitelisted(const CCoinsViewCache& view, const CScript& scriptPubKey);
/** Convert legacy P2PK stake scripts to their P2PKH identity for whitelist/signal matching. */
CScript CanonicalizeLegacyStakeScript(const CScript& scriptPubKey);

/** Deterministic per-block Gold Rush shadow reward schedule (exposed for tests/cap checks). */
CAmount ShadowBaseReward(int height);

/** Plain-English transition notice embedded by upgraded local block producers. */
const std::string& GetQuantumQuasarBlockNotice();
CScript BuildQuantumQuasarBlockNoticeScript();

/** Legacy direct-emission helper retained for stale marker tests and migration cleanup.
 *  ConnectBlock no longer uses this path during the staged compatibility bridge; Gold Rush
 *  note transactions update the upgraded shadow ledger without increasing base block rewards. */
CAmount ShadowMaxBlockDirectTotal(const CCoinsViewCache& view, const CBlockIndex* pindex);

/** Read-only Gold Rush pool and participant diagnostics for RPC/status reporting. */
ShadowGoldRushInfo GetShadowGoldRushInfo(const CCoinsViewCache& view, const CBlockIndex* pindex);

/**
 * Fail-fast scope for latency-sensitive wallet paths. The legacy global
 * diagnostic enumerator walks the full UTXO database through Cursor(); GUI,
 * RPC, and automatic staking paths must use deterministic per-script marker
 * lookups instead. Functional tests exercise these scopes so reintroducing a
 * chainstate cursor becomes an immediate regression rather than a field hang.
 */
class ScopedDisallowShadowSolverActivityFullScan
{
public:
    ScopedDisallowShadowSolverActivityFullScan();
    ~ScopedDisallowShadowSolverActivityFullScan();
    ScopedDisallowShadowSolverActivityFullScan(const ScopedDisallowShadowSolverActivityFullScan&) = delete;
    ScopedDisallowShadowSolverActivityFullScan& operator=(const ScopedDisallowShadowSolverActivityFullScan&) = delete;

private:
    bool m_previous;
};

std::map<CScript, ShadowSolverActivity> GetRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex);
std::optional<ShadowSolverActivity> GetRecentShadowSolverActivityForScript(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target);
uint64_t GetActiveShadowSignalCount(const CCoinsViewCache& view, const CBlockIndex* pindex);
std::map<CScript, CScript> GetActiveShadowSignalPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex);
bool HasRecentShadowSolverActivity(const CCoinsViewCache& view, const CBlockIndex* pindex, const CScript& target, uint32_t solve_height, const uint256& solve_hash);

/** Compute PoS Gold Rush shadow-ledger credits implied by a candidate block.
 *  Returns false only on malformed/overflow state; a true return with total_out=0 means no credit is recorded. */
bool GetShadowPosDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Build a quantum-linked QQSIGNAL OP_RETURN data push proving recent whitelisted solver activity.
 *  Live Gold Rush consensus only credits regular fee-paying transactions that reference a
 *  prior solver marker inside the 14-day window. The legacy overload is retained for source
 *  compatibility and always fails closed. */
bool BuildShadowSignalData(const CScript& target, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out);
bool BuildShadowSignalData(const CScript& target, const CScript& quantum_payout_script, uint32_t solve_height, const uint256& solve_hash, std::vector<unsigned char>& data_out);

/** Build a mined OP_RETURN data push containing the QQSPROOF prefix and payload. */
bool MineShadowProofData(const CScript& target, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool proof_of_stake, uint64_t max_tries, std::vector<unsigned char>& data_out);
bool MineShadowProofData(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t max_tries, std::vector<unsigned char>& data_out);
bool MineShadowProofDataRange(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done = nullptr);

/** Immutable Gold Rush PoW work parameters snapshotted for one tip. Produced under the chain
 *  lock by PrepareShadowPowWork(); GrindShadowPowWork() then grinds Argon2id over a nonce range
 *  with NO lock held (the grind never reads the coins view). This keeps the in-process miner from
 *  holding cs_main across the memory-hard grind. */
struct ShadowPowWork {
    bool valid{false};
    CScript target;
    CScript quantum_payout_script;
    int height{0};
    uint256 prev_hash;
    unsigned int bits{0};
};

/** Typed validation result used wherever Argon2id evaluation can fail locally.
 *  INVALID is deterministic for the supplied bytes. LOCAL_INTERNAL_ERROR is a
 *  retryable node failure and must never be cached or reported as consensus
 *  invalidity. */
enum class ShadowProofValidationResult {
    VALID,
    INVALID,
    LOCAL_INTERNAL_ERROR,
};

/** Typed result for a bounded PoW nonce search. */
enum class ShadowPowGrindResult {
    FOUND,
    EXHAUSTED,
    INVALID_WORK,
    LOCAL_INTERNAL_ERROR,
};
/** Snapshot PoW work for the block after pindexPrev. Reads the shadow pool from `view`, so the
 *  caller must hold the chain state stable (cs_main). Cheap; does no Argon2id work. */
ShadowPowWork PrepareShadowPowWork(const CScript& target, const CScript& quantum_payout_script, const CBlockIndex* pindexPrev, const CCoinsViewCache& view);
/** Pure Argon2id grind over a nonce range. No chain/view access; safe to call with NO lock held. */
ShadowPowGrindResult GrindShadowPowWorkDetailed(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done = nullptr);
bool GrindShadowPowWork(const ShadowPowWork& work, uint64_t start_nonce, uint64_t nonce_step, uint64_t max_tries, std::vector<unsigned char>& data_out, uint64_t* tries_done = nullptr);
/** Wallet/RPC guard for externally supplied QQSPROOF payloads. The proof must
 *  match the prepared next-block work exactly, including legacy target and
 *  quantum payout script, before the wallet broadcasts a claim transaction. */
ShadowProofValidationResult ValidateShadowPowProofForWorkDetailed(const ShadowPowWork& work, const std::vector<unsigned char>& prefixed_proof);
bool ValidateShadowPowProofForWork(const ShadowPowWork& work, const std::vector<unsigned char>& prefixed_proof);

/** Test-only, process-local fault injection for one or more Argon2id calls.
 *  No configuration, RPC, or network path can arm this hook. */
void SetShadowArgon2FailuresForTesting(uint64_t count = 1);
void ClearShadowArgon2FailuresForTesting();
COutPoint ShadowReplayStateOutpointForTesting();
/** Test-only oracle for the authenticated pool/active-signal pair invariant. */
bool ShadowActiveSignalPoolPairValidForTesting(const Consensus::Params& consensus,
                                               const CBlockIndex* pindex,
                                               bool pool_present,
                                               bool signal_present);

/** Compute PoW Gold Rush shadow-ledger credits implied by a candidate block. */
bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Deterministically classify every QQSPROOF note in a block. This is the
 *  bounded accounting engine used by ApplyShadowBlock itself and is exposed
 *  so reorg-aware indexes can record source transaction provenance without
 *  duplicating monetary logic or persisting extra chainstate. */
ShadowPowAccountingResult GetShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex,
    const CBlockUndo* blockundo, std::vector<ShadowPowClaimAccounting>& accounting_out);
/** Copy and authenticate the small historical pool context while the caller
 *  holds its chain/view lock. This performs no Argon2 work. */
ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    ShadowPowAccountingContext& context_out);
/** Evaluate the immutable context, base block, and undo without reading
 *  chainstate. The caller may release cs_main before invoking this function. */
ShadowPowAccountingResult EvaluateShadowPowClaimAccounting(
    const ShadowPowAccountingContext& context, const CBlock& block,
    const CBlockUndo* blockundo,
    std::vector<ShadowPowClaimAccounting>& accounting_out);

/** Mempool policy helpers for next-block-only QQSPROOF claims. */
bool TransactionHasShadowProof(const CTransaction& tx);
bool TransactionHasShadowSignal(const CTransaction& tx);
ShadowProofValidationResult CheckShadowPowClaimForMempoolDetailed(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason);
bool CheckShadowPowClaimForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev, const CCoinsViewCache& view, bool gold_rush_active, std::string& reject_reason);
bool CheckShadowSignalForMempool(const CTransaction& tx, const CBlockIndex* pindexPrev,
                                 const CCoinsViewCache& view, bool gold_rush_active,
                                 std::string& reject_reason);

/** Obsolete direct-emission helper retained for stale test-build marker cleanup. */
bool CheckShadowDirectPayoutOutputs(const CTransaction& tx, const std::map<CScript, CAmount>& expected_payouts, std::string& reject_reason);

/** Read quantum Gold Rush shadow-ledger credits already recorded by ApplyShadowBlock. */
bool GetAppliedShadowDirectPayouts(const CCoinsViewCache& view, const CBlockIndex* pindex, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Decode a spendable Gold Rush shadow-ledger claim marker. */
bool DecodeShadowClaimMarker(const CTxOut& txout, ShadowClaimMarkerInfo& info);

/** Return true for Quantum Quasar's zero-value internal chainstate marker records. */
bool IsShadowMarkerScript(const CScript& script);
/** Authenticate a marker by its reserved deterministic outpoint before destructive maintenance. */
bool IsAuthenticatedShadowMarkerOutpoint(const COutPoint& outpoint, const Coin& coin, const CBlockIndex* pindexTip);
using ShadowBlockReader = std::function<bool(const CBlockIndex&, CBlock&)>;
/** Versioned schedule/semantics marker used to decide whether startup must
 *  rebuild exact shadow state even when aggregate obligation is unchanged. */
void WriteShadowReplayStateMarker(CCoinsViewCache& view, const CBlockIndex* pindex, const Consensus::Params& consensus);
void RewindShadowReplayStateMarker(CCoinsViewCache& view, const CBlockIndex* disconnected, const Consensus::Params& consensus);
/** O(1) rolling inventory checkpoint maintenance. The checkpoint is anchored
 * to every connected tip from the first Gold Rush reward height onward. */
bool AdvanceGoldRushInventoryTip(CCoinsViewCache& view, const CBlockIndex* pindex);
bool RewindGoldRushInventoryTip(CCoinsViewCache& view, const CBlockIndex* disconnected);
bool HasShadowReplayState(const CCoinsViewCache& view);
bool HasCurrentShadowReplayState(const CCoinsViewCache& view, const Consensus::Params& consensus,
                                 const CBlockIndex* pindex,
                                 const ShadowBlockReader* read_block = nullptr);
/** Return the authenticated replay marker and exact-tip verification state for
 * offline upgrade/reindex comparison. */
ShadowReplayStateInfo GetShadowReplayStateInfo(const CCoinsViewCache& view,
                                               const Consensus::Params& consensus,
                                               const CBlockIndex* pindex);
/** Remove every authenticated internal shadow-state family while preserving
 *  marker-shaped user UTXOs at ordinary outpoints. The block reader is used
 *  only to authenticate legacy base-transaction payout markers. */
bool CollectAuthenticatedShadowStateOutpoints(const CCoinsViewCache& view, const CBlockIndex* pindexTip,
                                              const ShadowBlockReader& read_block,
                                              std::set<COutPoint>& authenticated);
bool PurgeAuthenticatedShadowState(CCoinsViewCache& view, const CBlockIndex* pindexTip,
                                   const ShadowBlockReader& read_block, uint64_t& removed);

/** Build wallet-indexable synthetic payout transactions for applied claim markers in one block. */
std::vector<CTransactionRef> GetAppliedShadowClaimPayoutTransactions(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time);
/** Build wallet-indexable synthetic payout transactions plus claim metadata for UI/wallet annotations. */
std::vector<ShadowSyntheticPayoutTransaction> GetAppliedShadowClaimPayoutTransactionRecords(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time);

/** Build indexable synthetic payout coins for applied claim markers in one block. */
std::vector<ShadowSyntheticPayoutCoin> GetAppliedShadowClaimPayoutCoins(const CCoinsViewCache& view, int height, const uint256& block_hash, int64_t block_time);

/** Mark/check obsolete direct Gold Rush emission outputs from earlier test builds.
 *  Current Gold Rush blocks no longer create these base-chain payout outputs. */
void MarkGoldRushDirectPayoutOutputs(CCoinsViewCache& view, const CTransaction& coinstake, const CBlockIndex* pindex, const std::map<CScript, CAmount>& payouts);
void UndoGoldRushDirectPayoutOutputMarkers(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex);
bool IsGoldRushDirectPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint, CScript* payout_script = nullptr);
enum class GoldRushPayoutStatus {
    NOT_CANDIDATE,
    AUTHENTICATED,
    CORRUPT,
};
/** Distinguish an ordinary coin from a strictly authenticated synthetic
 * payout and from a fail-closed payout-shaped coin whose provenance marker is
 * missing or corrupt. */
GoldRushPayoutStatus GetGoldRushPayoutStatus(const CCoinsViewCache& view,
                                             const COutPoint& outpoint,
                                             const Consensus::Params& consensus,
                                             CScript* payout_script = nullptr,
                                             const CBlockIndex* pindex_tip = nullptr);
/** Wallet/policy helper for the only lifecycle restriction on authenticated
 * Gold Rush payouts: they are locked through the reward window. Once quantum
 * witness spends activate, the payout is an ordinary v16 UTXO (including at
 * Final Lockout), subject only to normal maturity and demurrage rules. */
bool IsLockedGoldRushPayoutOutput(const CCoinsViewCache& view, const COutPoint& outpoint,
                                  const Consensus::Params& consensus, int64_t nMedianTimePast,
                                  int nSpendHeight, CScript* payout_script = nullptr);
/** Consensus-side synthetic-payout classifier. In addition to exact QQGRPAY
 * provenance, this fails closed on production-style schedules where positive
 * coinbase-class outputs after nLastPOWBlock can only be auxiliary payouts. */
bool IsGoldRushSyntheticPayoutInput(const CCoinsViewCache& view, const COutPoint& outpoint,
                                    const Consensus::Params& consensus,
                                    CScript* payout_script = nullptr);
/** Record/remove authenticated active-chain provenance when a synthetic payout
 * is spent, allowing startup to distinguish a legitimate spent UTXO from a
 * locally missing/corrupt unspent payout. */
bool RecordSpentGoldRushPayouts(CCoinsViewCache& view, const CTransaction& tx,
                                const CBlockIndex* pindex);
bool UndoSpentGoldRushPayouts(CCoinsViewCache& view, const CBlock& block,
                              const CBlockUndo& block_undo,
                              const CBlockIndex* pindex);
/** Snapshot-friendly helpers used by explorers/accounting RPCs. */
COutPoint GetGoldRushPayoutMarkerOutpoint(const COutPoint& payout_outpoint);
bool IsGoldRushPayoutMarkerScript(const CScript& script);

/** Applying shadow state can fail because of a local cryptographic/storage
 *  fault. Such a failure must stop the local node; it must never classify the
 *  otherwise legacy-valid base block as consensus-invalid. */
enum class ShadowApplyResult {
    OK,
    LOCAL_INTERNAL_ERROR,
};

/** Apply/remove deterministic shadow claim state for one shadow-epoch block. */
ShadowApplyResult ApplyShadowBlockResult(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);
bool ApplyShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);
bool UndoShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);



#endif // BLACKCOIN_SHADOW_H
