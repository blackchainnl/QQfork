// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 Blackcoin Core Developers
// Copyright (c) 2009-2022 Blackcoin More Developers
// Copyright (c) 2009-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/consensus.h>
#include <script/script.h>
#include <uint256.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_CSV = std::numeric_limits<int16_t>::min(),
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_CSV; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_SEGWIT, // Deployment of SegWit (BIP141, BIP143, and BIP147)
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    DEPLOYMENT_QUANTUM_QUASAR, // Readiness signalling for the V4 hard-fork schedule
    DEPLOYMENT_QUANTUM_MIGRATION, // Readiness signalling for the post-quantum migration deadline
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

enum class QuantumQuasarPhase : uint8_t {
    LEGACY,
    GOLD_RUSH,
    MIGRATION,
    FINAL_LOCKOUT,
};

static constexpr int64_t QUANTUM_QUASAR_GOLD_RUSH_SECONDS = 180 * 24 * 60 * 60;
static constexpr int64_t QUANTUM_QUASAR_MIGRATION_SECONDS = 540 * 24 * 60 * 60;
static constexpr int64_t QUANTUM_QUASAR_MAINNET_V4_TIME = 1783835299; // Expected mainnet height 5,950,000 (2026-07-12 05:48:19 UTC)

/**
 * The legacy pre-Protocol-V3.1 replay branch obtained this maturity from a
 * value-initialized Consensus::Params temporary, which evaluated to zero.
 * Preserve that accepted-chain replay behavior explicitly rather than
 * depending on namespace lookup and implicit value initialization.
 */
static constexpr int HISTORICAL_PRE_V3_1_COINBASE_MATURITY = 0;

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nMaxReorganizationDepth;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV activation. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nTargetTimespan / nTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 posLimit;
    uint256 posLimitV2;
    bool fPowAllowMinDifficultyBlocks;
    int64_t nTargetSpacingV1;
    bool fPowNoRetargeting;
    bool fPoSNoRetargeting;
    int64_t nTargetSpacing;
    int64_t nTargetTimespan;
    std::chrono::seconds TargetSpacing() const
    {
        return std::chrono::seconds{nTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nTargetTimespan / nTargetSpacing; }
    int64_t nProtocolV1RetargetingFixedTime;
    int64_t nProtocolV2Time;
    int64_t nProtocolV3Time;
    int64_t nProtocolV3_1Time;
    int64_t nProtocolV4Time;
    int64_t nGoldRushEndTime;
    int64_t nQuantumMigrationDeadlineTime;
    /** Optional height-authoritative lifecycle (start < 0 = disabled). The
     *  boundary blocks are inclusive: nGoldRushEndHeight is the last Gold Rush
     *  block and nQuantumMigrationEndHeight is the last Migration block. A
     *  partial or unordered height schedule is invalid and fails closed in
     *  GetQuantumLifecycleState instead of falling back to wall-clock time. */
    int nQuantumLifecycleStartHeight{-1};
    int nGoldRushEndHeight{0};
    int nQuantumMigrationEndHeight{0};
    uint32_t nQuantumSighashChainId{0};
    int nStakeTierActivationHeight{std::numeric_limits<int>::max()};
    int nStakeRewardSplitActivationHeight{std::numeric_limits<int>::max()};
    /** Height at which competing Gold Rush proof claims use the canonical,
     *  order-independent winner and bounded loser-fee reimbursement rule. */
    int nShadowCompetingClaimsActivationHeight{std::numeric_limits<int>::max()};
    /**
     * Height at which the *new* QQP4 wire format is required for Gold Rush
     * PoW claims. This is deliberately independent of the new v30.1.1 QQP3
     * canonical-accounting activation. Neither boundary is selected by
     * readiness signalling.
     * The max-int default leaves QQP4 disabled until a separately announced hard fork.
     */
    int nShadowQQP4ActivationHeight{std::numeric_limits<int>::max()};
    int nDemurrageActivationHeight{std::numeric_limits<int>::max()};
    int nDemurrageMinActivationHeight{0};
    int nDemurrageBlocksPerMonth{40500};
    std::vector<CScript> m_demurrage_exempt_scripts{};
    bool IsProtocolV1RetargetingFixed(int64_t nTime) const { return nTime > nProtocolV1RetargetingFixedTime && nTime != 1395631999; }
    bool IsProtocolV2(int64_t nTime) const { return nTime > nProtocolV2Time && nTime != 1407053678; }
    bool IsProtocolV3(int64_t nTime) const { return nTime > nProtocolV3Time && nTime != 1444028400; }
    bool IsProtocolV3_1(int64_t nTime) const { return nTime > nProtocolV3_1Time && nTime != 1713938400; }
    bool IsProtocolV4(int64_t nTime) const { return nTime > nProtocolV4Time; }
    /**
     * Return the coinbase/coinstake maturity enforced for a spending
     * transaction's effective consensus time. IsProtocolV3_1 is used
     * deliberately: its strict boundary and historical timestamp exception
     * are part of the already-accepted chain and must not be rewritten as a
     * greater-than-or-equal comparison during replay. The method name follows
     * the legacy nCoinbaseMaturity parameter and reject-reason vocabulary;
     * callers apply the returned depth to both coinbase and coinstake outputs.
     */
    int CoinbaseMaturityForSpendTime(int64_t nTime) const
    {
        return IsProtocolV3_1(nTime) ? nCoinbaseMaturity
                                     : HISTORICAL_PRE_V3_1_COINBASE_MATURITY;
    }
    struct QuantumLifecycleState {
        QuantumQuasarPhase phase{QuantumQuasarPhase::LEGACY};
        bool schedule_valid{true};
        bool height_authoritative{false};
    };

    /**
     * Return the single authoritative lifecycle decision for a block context.
     *
     * nTime is the parent median-time-past used by consensus for the block and
     * nHeight is the height of that block. For mempool/template decisions pass
     * tip MTP and tip height + 1. For active-tip status pass tip MTP and tip
     * height. Mainnet uses the complete height schedule, so MTP drift cannot
     * skip, delay, or reverse a production transition. Time-only schedules are
     * retained solely for isolated compatibility tests.
     */
    QuantumLifecycleState GetQuantumLifecycleState(int64_t nTime, int nHeight) const
    {
        const bool any_height = HasAnyHeightLifecycleBoundary();
        if (any_height) {
            if (!UsesHeightLifecycle() || !IsQuantumLifecycleScheduleOrdered()) {
                return {QuantumQuasarPhase::LEGACY, /*schedule_valid=*/false,
                        /*height_authoritative=*/true};
            }
            if (nHeight < nQuantumLifecycleStartHeight) {
                return {QuantumQuasarPhase::LEGACY, true, true};
            }
            if (nHeight <= nGoldRushEndHeight) {
                return {QuantumQuasarPhase::GOLD_RUSH, true, true};
            }
            if (nHeight <= nQuantumMigrationEndHeight) {
                return {QuantumQuasarPhase::MIGRATION, true, true};
            }
            return {QuantumQuasarPhase::FINAL_LOCKOUT, true, true};
        }

        if (!IsProtocolV4(nTime)) {
            return {QuantumQuasarPhase::LEGACY, true, false};
        }
        if (nGoldRushEndTime == 0 || nTime <= nGoldRushEndTime) {
            return {QuantumQuasarPhase::GOLD_RUSH, true, false};
        }
        if (nQuantumMigrationDeadlineTime != 0 &&
            nQuantumMigrationDeadlineTime > nGoldRushEndTime &&
            nTime > nQuantumMigrationDeadlineTime) {
            return {QuantumQuasarPhase::FINAL_LOCKOUT, true, false};
        }
        return {QuantumQuasarPhase::MIGRATION, true, false};
    }

    bool HasAnyHeightLifecycleBoundary() const
    {
        return nQuantumLifecycleStartHeight >= 0 ||
               nGoldRushEndHeight > 0 ||
               nQuantumMigrationEndHeight > 0;
    }
    bool UsesHeightLifecycle() const
    {
        return nQuantumLifecycleStartHeight >= 0 &&
               nGoldRushEndHeight > 0 &&
               nQuantumMigrationEndHeight > 0;
    }
    bool IsGoldRushEndScheduled() const
    {
        if (HasAnyHeightLifecycleBoundary()) return UsesHeightLifecycle() && IsQuantumLifecycleScheduleOrdered();
        return nGoldRushEndTime != 0;
    }
    bool IsMigrationEndScheduled() const
    {
        if (HasAnyHeightLifecycleBoundary()) return UsesHeightLifecycle() && IsQuantumLifecycleScheduleOrdered();
        return nGoldRushEndTime != 0 &&
               nQuantumMigrationDeadlineTime > nGoldRushEndTime;
    }
    bool IsQuantumLifecycleScheduleOrdered() const
    {
        if (UsesHeightLifecycle()) {
            return nQuantumLifecycleStartHeight <= nGoldRushEndHeight &&
                   nQuantumMigrationEndHeight > nGoldRushEndHeight;
        }
        if (HasAnyHeightLifecycleBoundary()) return false;
        return nGoldRushEndTime != 0 &&
               nQuantumMigrationDeadlineTime > nGoldRushEndTime;
    }
    bool GoldRushEndPassed(int64_t nTime, int nHeight) const
    {
        const QuantumQuasarPhase phase = GetQuantumLifecycleState(nTime, nHeight).phase;
        return phase == QuantumQuasarPhase::MIGRATION ||
               phase == QuantumQuasarPhase::FINAL_LOCKOUT;
    }
    bool MigrationDeadlinePassed(int64_t nTime, int nHeight) const
    {
        return GetQuantumLifecycleState(nTime, nHeight).phase ==
               QuantumQuasarPhase::FINAL_LOCKOUT;
    }
    bool IsQuantumFinalLockout(int64_t nTime, int nHeight) const
    {
        return GetQuantumLifecycleState(nTime, nHeight).phase ==
               QuantumQuasarPhase::FINAL_LOCKOUT;
    }
    bool IsGoldRushEpoch(int64_t nTime, int nHeight) const
    {
        return GetQuantumLifecycleState(nTime, nHeight).phase ==
               QuantumQuasarPhase::GOLD_RUSH;
    }
    bool IsQuantumMigrationWindow(int64_t nTime, int nHeight) const
    {
        return GetQuantumLifecycleState(nTime, nHeight).phase ==
               QuantumQuasarPhase::MIGRATION;
    }
    bool IsQuantumSpendEnforcementActive(int64_t nTime, int nHeight) const { return IsQuantumMigrationWindow(nTime, nHeight) || IsQuantumFinalLockout(nTime, nHeight); }
    bool IsQuantumStakeRulesActive(int64_t nTime, int nHeight) const { return IsQuantumSpendEnforcementActive(nTime, nHeight); }
    bool IsNewNetworkStakeOnly(int64_t nTime, int nHeight) const { return IsQuantumFinalLockout(nTime, nHeight); }
    bool IsBaseNetworkStakeCompatible(int64_t nTime, int nHeight) const { return !IsNewNetworkStakeOnly(nTime, nHeight); }
    bool IsStakeTiersActive(int nHeight) const { return nHeight >= nStakeTierActivationHeight; }
    bool IsStakeRewardSplitActive(int nHeight) const { return nHeight >= nStakeRewardSplitActivationHeight; }
    bool IsShadowCompetingClaimsActive(int nHeight) const { return nHeight >= nShadowCompetingClaimsActivationHeight; }
    bool IsShadowQQP4Active(int nHeight) const { return nHeight >= nShadowQQP4ActivationHeight; }
    int EffectiveDemurrageActivationHeight() const
    {
        // A complete height-authoritative lifecycle has one atomic transition:
        // the block after the last Migration block is both the first Final
        // block and the first demurrage-active block. Do not permit the legacy
        // demurrage-height fields to become an independent activation gate.
        if (UsesHeightLifecycle() && IsQuantumLifecycleScheduleOrdered()) {
            if (nQuantumMigrationEndHeight == std::numeric_limits<int>::max()) {
                return std::numeric_limits<int>::max();
            }
            return nQuantumMigrationEndHeight + 1;
        }
        return std::max(nDemurrageActivationHeight, nDemurrageMinActivationHeight);
    }
    int DemurrageBlocksPerMonth() const { return std::max(1, nDemurrageBlocksPerMonth); }
    int DemurrageGraceBlocks() const { return 6 * DemurrageBlocksPerMonth(); }
    int DemurrageZeroBlocks() const { return 24 * DemurrageBlocksPerMonth(); }
    int DemurrageDecayWindowBlocks() const { return DemurrageZeroBlocks() - DemurrageGraceBlocks(); }
    int DemurrageAutoAttestBlocks() const { return 3 * DemurrageBlocksPerMonth(); }
    bool IsDemurrageActive(int nHeight, int64_t nParentMedianTimePast) const
    {
        return IsQuantumFinalLockout(nParentMedianTimePast, nHeight) &&
               nHeight >= EffectiveDemurrageActivationHeight();
    }
    QuantumQuasarPhase GetQuantumQuasarPhase(int64_t nTime, int nHeight) const
    {
        return GetQuantumLifecycleState(nTime, nHeight).phase;
    }
    int nLastPOWBlock;
    int nStakeTimestampMask;
    int nCoinbaseMaturity;
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_CSV:
            return CSVHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
