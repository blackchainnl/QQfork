#include <shadow.h>

#include <consensus/params.h>

#include <algorithm>
// Gold Rush schedule heights (mainnet defaults; regtest-overridable, see header).
int SHADOW_WHITELIST_HEIGHT = MAINNET_SHADOW_WHITELIST_HEIGHT;
int SHADOW_REWARD_START_HEIGHT = MAINNET_SHADOW_REWARD_START_HEIGHT;
int SHADOW_GOLD_RUSH_BLOCKS = MAINNET_SHADOW_GOLD_RUSH_BLOCKS;
int SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + 237599;
int SHADOW_REWARD_END_HEIGHT = MAINNET_SHADOW_REWARD_END_HEIGHT;
int SHADOW_HALVING_INTERVAL_BLOCKS = MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS;

void SetShadowTestSchedule(int whitelist_height, int reward_start_height, int gold_rush_blocks)
{
    if (whitelist_height < 0) whitelist_height = 0;
    if (reward_start_height <= whitelist_height) reward_start_height = whitelist_height + 1;
    if (gold_rush_blocks < 1) gold_rush_blocks = 1;
    SHADOW_WHITELIST_HEIGHT = whitelist_height;
    SHADOW_REWARD_START_HEIGHT = reward_start_height;
    SHADOW_GOLD_RUSH_BLOCKS = gold_rush_blocks;
    SHADOW_PHASE1_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + std::min(gold_rush_blocks - 1, 237599);
    SHADOW_REWARD_END_HEIGHT = SHADOW_REWARD_START_HEIGHT + gold_rush_blocks - 1;
}

void SetShadowTestHalvingInterval(int halving_interval_blocks)
{
    SHADOW_HALVING_INTERVAL_BLOCKS = std::max(1, halving_interval_blocks);
}

void SetShadowRegtestSchedule(int whitelist_height, int gold_rush_blocks)
{
    SetShadowTestSchedule(whitelist_height, whitelist_height + 1, gold_rush_blocks);
}

bool IsShadowGoldRushRewardHeight(int nHeight)
{
    return nHeight >= SHADOW_REWARD_START_HEIGHT && nHeight <= SHADOW_REWARD_END_HEIGHT;
}

bool IsShadowGoldRushRewardActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nHeight)
{
    if (!IsShadowGoldRushRewardHeight(nHeight)) return false;
    // Reward accounting starts only with V4 and remains within the same
    // Gold Rush phase that keeps quantum spends locked. This makes the core
    // lifecycle invariant explicit: every credited reward block is Gold Rush.
    return consensus.IsGoldRushEpoch(nMedianTimePast, nHeight);
}

bool IsQuantumWitnessSpendActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight)
{
    if (consensus.UsesHeightLifecycle() && nSpendHeight <= SHADOW_REWARD_END_HEIGHT) return false;
    if (consensus.IsQuantumSpendEnforcementActive(nMedianTimePast, nSpendHeight)) return true;
    return false;
}

bool IsQuantumStakeTiersActive(const Consensus::Params& consensus, int64_t nMedianTimePast, int nSpendHeight)
{
    return nSpendHeight > SHADOW_REWARD_END_HEIGHT &&
           IsQuantumWitnessSpendActive(consensus, nMedianTimePast, nSpendHeight) &&
           consensus.IsStakeTiersActive(nSpendHeight);
}
