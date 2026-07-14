#ifndef BITCOIN_SHADOW_H
#define BITCOIN_SHADOW_H

#include <consensus/amount.h>
#include <consensus/consensus.h>
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

/** Snapshot-decodable provenance for one synthetic Gold Rush payout marker. */
struct GoldRushPayoutMarkerInfo {
    COutPoint payout_outpoint;
    CScript payout_script;
    CAmount nominal_amount{0};
    uint32_t origin_height{0};
    uint256 origin_block_hash;
    uint32_t origin_block_time{0};
};

/** Authenticated rolling issuance/spend totals at an exact active tip. */
struct GoldRushInventoryInfo {
    uint32_t tip_height{0};
    uint256 tip_hash;
    uint64_t issued_count{0};
    CAmount issued_nominal{0};
    uint64_t spent_count{0};
    CAmount spent_nominal{0};
};

/** Mutually exclusive next-block value states used by wallet and supply APIs. */
enum class ValueLifecycleCategory : uint8_t {
    SPENDABLE_LEGACY,
    IMMATURE_LEGACY,
    FINAL_LOCKED_LEGACY,
    GOLD_RUSH_SYNTHETIC_IMMATURE,
    GOLD_RUSH_SYNTHETIC_MATURE_LOCKED,
    DIRECT_QUANTUM_PHASE_LOCKED,
    MIGRATION_SPENDABLE_DIRECT_QUANTUM,
    QUANTUM_CONTRACT_RESTRICTED,
    DEMURRAGE_LOCKED,
    FINAL_CONDITIONAL_EUTXO,
    IMMATURE_OTHER,
    OTHER,
    COUNT,
};

struct ValueLifecycleClassification {
    ValueLifecycleCategory category{ValueLifecycleCategory::OTHER};
    bool synthetic{false};
    bool merkle_included{true};
    bool mature{true};
    bool consensus_spendable{false};
    bool ordinary_spendable{false};
    bool permanently_locked{false};
    bool conditional{false};
    bool legacy_scheduled_final_lockout{false};
    bool requires_quantum_migration{false};
    bool demurrage_active{false};
    bool demurrage_exempt{false};
    bool demurrage_locked{false};
    int64_t maturity_height{-1};
    int64_t earliest_spend_height{-1};
    int64_t earliest_spend_mtp{-1};
    CAmount nominal_amount{0};
    CAmount effective_amount{0};
    CAmount burned_amount{0};
    std::string demurrage_exemption;
};

enum class ValueLifecycleResult : uint8_t {
    OK,
    INVALID_AMOUNT,
    INVALID_SCHEDULE,
    INVALID_SYNTHETIC_PROVENANCE,
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

/** Byte-level QQSPROOF channel classification. This deliberately does not
 * imply that the proof, input binding, or claim location is valid. */
enum class ShadowProofPayloadMode : uint8_t {
    POW,
    POS,
    UNKNOWN,
    MALFORMED,
};

/** Explorer-facing classification of an on-chain QQSPROOF note. */
struct ShadowProofObservation {
    uint256 source_txid;
    uint32_t source_vout{0};
    ShadowProofPayloadMode mode{ShadowProofPayloadMode::MALFORMED};
    bool fee_paying_location{false};
    bool duplicate_in_transaction{false};
};

/** Bounded structural scan metadata for compatibility RPCs. */
struct ShadowProofObservationSummary {
    uint32_t observed_count{0};
    uint32_t returned_count{0};
    uint32_t omitted_count{0};
    uint256 commitment;
};

enum class ShadowPowClaimDisposition : uint8_t {
    // Values 0-7 were persisted by the first canonical-accounting release.
    // Keep them explicit so old shadow indexes retain their exact meaning.
    INVALID_LOCATION = 0,
    MALFORMED_TRANSACTION = 1,
    INVALID_PROOF = 2,
    INPUT_MISMATCH = 3,
    INVALID_BASE_FEE = 4,
    EVALUATION_LIMIT = 5,
    WINNER = 6,
    REIMBURSED_LOSER = 7,
    WRONG_MODE = 8,
    UNKNOWN_MODE = 9,
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

/**
 * Fixed-size block aggregate for post-boundary QQSPROOF accounting.
 *
 * Only Argon2-evaluated candidates have detailed rows. All other notes are
 * represented by these counters and by accounting_commitment, which commits
 * to every exact note plus the complete deterministic classification.
 */
struct ShadowPowClaimAggregate {
    uint32_t observed_count{0};
    uint32_t evaluated_count{0};
    uint32_t invalid_location_count{0};
    uint32_t malformed_transaction_count{0};
    uint32_t invalid_proof_count{0};
    uint32_t wrong_mode_count{0};
    uint32_t unknown_mode_count{0};
    uint32_t input_mismatch_count{0};
    uint32_t invalid_base_fee_count{0};
    uint32_t evaluation_limit_count{0};
    uint32_t winner_count{0};
    uint32_t reimbursed_loser_count{0};
    uint256 accounting_commitment;
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
static constexpr int MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS = 43200;
// v30.1.0 assigned the first valid in-block QQSPROOF the whole PoW pool. Keep
// that already-mined history immutable. The order-independent, emission-neutral
// competing-claim rule begins at the first pre-announced Gold Rush halving.
static constexpr int MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT =
    MAINNET_SHADOW_REWARD_START_HEIGHT + MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS;
static constexpr int MAINNET_SHADOW_REWARD_END_HEIGHT = MAINNET_SHADOW_REWARD_START_HEIGHT + MAINNET_SHADOW_GOLD_RUSH_BLOCKS - 1;
static constexpr int MAINNET_QUANTUM_MIGRATION_BLOCKS = (540 * 24 * 60 * 60) / 64;
static constexpr int MAINNET_QUANTUM_MIGRATION_END_HEIGHT = MAINNET_SHADOW_REWARD_END_HEIGHT + MAINNET_QUANTUM_MIGRATION_BLOCKS;
static constexpr int MAINNET_QUANTUM_FINAL_START_HEIGHT = MAINNET_QUANTUM_MIGRATION_END_HEIGHT + 1;
static_assert(MAINNET_SHADOW_REWARD_START_HEIGHT == 5950000);
static_assert(MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT == 5993200);
static_assert(MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT <= MAINNET_SHADOW_REWARD_END_HEIGHT);
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
static constexpr unsigned int MAX_SHADOW_POW_EVALS_PER_BLOCK = 64;
/** A serialized CTxOut consumes at least 9 non-witness bytes (36 weight).
 *  This is therefore a conservative consensus-derived ceiling on the number
 *  of QQSPROOF-shaped outputs in any V4-valid block. */
static constexpr uint32_t MAX_SHADOW_POW_NOTES_PER_BLOCK =
    V4_MAX_BLOCK_WEIGHT / (WITNESS_SCALE_FACTOR * 9);
static constexpr uint32_t SHADOW_ARGON2_TIME_COST = 1;
static constexpr uint32_t SHADOW_ARGON2_MEMORY_KIB = 1024;
static constexpr uint32_t SHADOW_ARGON2_LANES = 1;

/** Exact total value in the deterministic 180-day Gold Rush schedule.
 *  Direct payouts are bounded per block by ShadowBaseReward() and the coinstake
 *  reward cap; this invariant locks the total scheduled issuance against drift. */
static constexpr CAmount SHADOW_MAX_EMISSION = 51437700 * COIN;

/** Checked deterministic scheduled emission through last_height, inclusive. */
std::optional<CAmount> GetScheduledShadowEmissionThrough(int last_height);

/** Deterministic upper bound for synthetic claim records written by one
 * Gold Rush block. Historical v30.1.0 blocks retain their legacy block-size
 * bound. From the competing-claims activation height onward, the bound is
 * derived from authenticated whitelist state plus the fixed PoW evaluation
 * cap; this is an assertion of existing allocation rules, not a participant
 * cap or reward-allocation change. */
uint32_t GetShadowSyntheticClaimLimit(const Consensus::Params& consensus,
                                      int height,
                                      uint32_t authenticated_whitelist_count);

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
/** Test-only allocation-failure injection. APPLY fails before constructing
 *  shadow state; APPLY_AFTER_STAGED_MUTATION fails after the child cache has
 *  received a pool mutation but before it is published; ACCOUNTING throws
 *  from the canonical explorer/credit accounting engine. */
enum class ShadowAllocationFailurePoint : uint8_t {
    NONE,
    APPLY,
    APPLY_AFTER_STAGED_MUTATION,
    ACCOUNTING,
};
void SetShadowAllocationFailureForTesting(ShadowAllocationFailurePoint point);
void ClearShadowAllocationFailureForTesting();
COutPoint ShadowReplayStateOutpointForTesting();
/** Test-only oracle for the authenticated pool/active-signal pair invariant. */
bool ShadowActiveSignalPoolPairValidForTesting(const Consensus::Params& consensus,
                                               const CBlockIndex* pindex,
                                               bool pool_present,
                                               bool signal_present);

/** Compute PoW Gold Rush shadow-ledger credits implied by a candidate block. */
bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);
bool GetShadowPowDirectPayouts(const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo, const Consensus::Params& consensus, std::map<CScript, CAmount>& payouts_out, CAmount& total_out);

/** Deterministically classify every QQSPROOF note in a block. This is the
 *  bounded accounting engine used by ApplyShadowBlock itself and is exposed
 *  so reorg-aware indexes can record source transaction provenance without
 *  duplicating monetary logic or persisting extra chainstate. */
ShadowPowAccountingResult GetShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex,
    const CBlockUndo* blockundo, std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out = nullptr);
ShadowPowAccountingResult GetShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex,
    const CBlockUndo* blockundo, const Consensus::Params& consensus,
    std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out = nullptr);
/** Copy and authenticate the small historical pool context while the caller
 *  holds its chain/view lock. This performs no Argon2 work. */
ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    ShadowPowAccountingContext& context_out);
ShadowPowAccountingResult PrepareShadowPowClaimAccounting(
    const CCoinsViewCache& view, const CBlockIndex* pindex,
    const Consensus::Params& consensus,
    ShadowPowAccountingContext& context_out);
/** Evaluate the immutable context, base block, and undo without reading
 *  chainstate. The caller may release cs_main before invoking this function. */
ShadowPowAccountingResult EvaluateShadowPowClaimAccounting(
    const ShadowPowAccountingContext& context, const CBlock& block,
    const CBlockUndo* blockundo,
    std::vector<ShadowPowClaimAccounting>& accounting_out,
    ShadowPowClaimAggregate* aggregate_out = nullptr);

/** Mempool policy helpers for next-block-only QQSPROOF claims. */
ShadowProofPayloadMode ClassifyShadowProofPayload(const std::vector<unsigned char>& prefixed_proof);
std::vector<ShadowProofObservation> GetShadowProofObservations(const CBlock& block);
std::vector<ShadowProofObservation> GetShadowProofObservations(
    const CBlock& block, ShadowProofObservationSummary& summary);
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
/** Decode a payout marker using only one immutable UTXO snapshot entry and its
 * exact active-chain anchor. This deliberately does not consult live chainstate. */
bool DecodeAuthenticatedGoldRushPayoutMarker(const COutPoint& marker_outpoint,
                                             const Coin& marker_coin,
                                             const CBlockIndex* pindex_tip,
                                             GoldRushPayoutMarkerInfo& info);
/** Decode the authenticated rolling Gold Rush inventory from one immutable
 * UTXO snapshot entry. */
bool DecodeAuthenticatedGoldRushInventory(const COutPoint& inventory_outpoint,
                                          const Coin& inventory_coin,
                                          const CBlockIndex* pindex_tip,
                                          GoldRushInventoryInfo& info);
/** Decode the authenticated reward-pool checkpoint from the same immutable
 * UTXO snapshot used for aggregate accounting. */
bool DecodeAuthenticatedShadowPool(const COutPoint& pool_outpoint,
                                   const Coin& pool_coin,
                                   const CBlockIndex* pindex_tip,
                                   ShadowGoldRushInfo& info);
bool IsShadowPoolMarkerOutpoint(const COutPoint& outpoint);
bool IsGoldRushInventoryMarkerOutpoint(const COutPoint& outpoint);
/** True only for the strict positive coin shape that consensus requires to
 * have authenticated synthetic provenance. */
bool IsGoldRushPayoutCandidateCoin(const Coin& coin, const Consensus::Params& consensus);

/** Classify one UTXO for the candidate next block. The caller supplies whether
 * synthetic provenance was authenticated from the same chainstate snapshot. */
ValueLifecycleResult ClassifyValueLifecycle(
    const Coin& coin,
    bool authenticated_synthetic_goldrush,
    const Consensus::Params& consensus,
    int evaluation_height,
    int64_t evaluation_mtp,
    std::optional<int> latest_attestation_height,
    std::optional<int> attestation_coverage_start_height,
    ValueLifecycleClassification& classification);
const char* ValueLifecycleCategoryName(ValueLifecycleCategory category);
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

/** Apply/remove deterministic shadow claim state for one shadow-epoch block.
 *  ApplyShadowBlockResult stages every shadow mutation in a child cache and
 *  publishes that cache only after the complete evaluation succeeds. A host
 *  allocation failure while publishing the child can partially mutate the
 *  supplied cache; every production caller must therefore supply a disposable
 *  outer cache and discard it on LOCAL_INTERNAL_ERROR. */
ShadowApplyResult ApplyShadowBlockResult(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);
bool ApplyShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);
bool UndoShadowBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const CBlockUndo* blockundo = nullptr, bool gold_rush_active = true);



#endif // BITCOIN_SHADOW_H
