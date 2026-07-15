// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/shadow_resource_monitor.h>

#include <chain.h>
#include <chainparams.h>
#include <logging.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <sync.h>
#include <util/fs.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <warnings.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <system_error>

namespace node {
namespace {

constexpr int SHADOW_REWARD_START_HEIGHT{5950000};
constexpr int SHADOW_REWARD_END_HEIGHT{6192999};

Mutex g_shadow_supply_scan_mutex;
ShadowSupplyScanProgress g_shadow_supply_scan GUARDED_BY(g_shadow_supply_scan_mutex);
uint64_t g_next_shadow_supply_scan_id GUARDED_BY(g_shadow_supply_scan_mutex){1};
int64_t g_shadow_supply_scan_started_steady_ms GUARDED_BY(g_shadow_supply_scan_mutex){0};
std::atomic<uint64_t> g_shadow_supply_scan_abort_id{0};

uint64_t SaturatingAdd(uint64_t left, uint64_t right)
{
    if (left > std::numeric_limits<uint64_t>::max() - right) {
        return std::numeric_limits<uint64_t>::max();
    }
    return left + right;
}

uint64_t SaturatingMultiply(uint64_t left, uint64_t right)
{
    if (left != 0 && right > std::numeric_limits<uint64_t>::max() / left) {
        return std::numeric_limits<uint64_t>::max();
    }
    return left * right;
}

uint64_t WarningThreshold(uint64_t required)
{
    const uint64_t quotient = required / SHADOW_RESOURCE_WARNING_DENOMINATOR;
    const uint64_t remainder = required % SHADOW_RESOURCE_WARNING_DENOMINATOR;
    return SaturatingAdd(
        SaturatingMultiply(quotient, SHADOW_RESOURCE_WARNING_NUMERATOR),
        (remainder * SHADOW_RESOURCE_WARNING_NUMERATOR +
         SHADOW_RESOURCE_WARNING_DENOMINATOR - 1) /
            SHADOW_RESOURCE_WARNING_DENOMINATOR);
}

std::string GiB(uint64_t bytes)
{
    return strprintf("%.1f GiB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
}

} // namespace

const char* ShadowResourceStatusName(ShadowResourceStatusLevel level)
{
    switch (level) {
    case ShadowResourceStatusLevel::NOT_APPLICABLE:
        return "not_applicable";
    case ShadowResourceStatusLevel::UNAVAILABLE:
        return "unavailable";
    case ShadowResourceStatusLevel::HEALTHY:
        return "healthy";
    case ShadowResourceStatusLevel::WARNING:
        return "warning";
    case ShadowResourceStatusLevel::OUTSIDE_ENVELOPE:
        return "outside_operational_envelope";
    }
    return "unavailable";
}

ShadowResourceStatus EvaluateShadowResourceStatus(
    const ShadowResourceMeasurements& measurements)
{
    ShadowResourceStatus status;
    status.applicable = measurements.applicable;
    status.measurements_available = measurements.available;
    status.height = measurements.height;
    status.best_block = measurements.best_block;
    status.estimated_chainstate_bytes = measurements.estimated_chainstate_bytes;
    status.filesystem_available_bytes = measurements.filesystem_available_bytes;
    status.minimum_free_bytes = SHADOW_RESOURCE_MINIMUM_FREE_BYTES;
    status.immediate_scan_free_bytes = SHADOW_RESOURCE_IMMEDIATE_SCAN_FREE_BYTES;
    status.critical_free_bytes = SHADOW_RESOURCE_CRITICAL_FREE_BYTES;
    status.maximum_estimated_chainstate_bytes =
        SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES;
    status.maximum_records_per_cursor = SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR;
    status.maximum_sequential_visits = SHADOW_RESOURCE_MAX_SEQUENTIAL_VISITS;
    status.maximum_point_seeks = SHADOW_RESOURCE_MAX_POINT_SEEKS;
    status.absolute_records_per_cursor =
        SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR;
    status.absolute_point_seeks = SHADOW_RESOURCE_ABSOLUTE_POINT_SEEKS;
    status.support_through_height = SHADOW_RESOURCE_SUPPORT_THROUGH_HEIGHT;

    if (!measurements.applicable) {
        status.level = ShadowResourceStatusLevel::NOT_APPLICABLE;
        status.within_chainstate_size = true;
        status.within_immediate_scan_free_space = true;
        status.within_projected_free_space = true;
        status.critical_free_space_satisfied = true;
        status.within_supported_height = true;
        status.operational_envelope_satisfied = true;
        status.diagnostic_scan_default_authorized = true;
        status.operator_action =
            "No action. The scoped v30.1.1 operating envelope is a mainnet release qualification, not a consensus rule.";
        return status;
    }

    if (!measurements.available || measurements.height < 0 ||
        measurements.best_block.empty()) {
        status.level = ShadowResourceStatusLevel::UNAVAILABLE;
        status.warning =
            "Quantum Quasar operational resource measurements are unavailable. "
            "Base-chain validation, networking, staking, mining, and consensus rules remain unchanged. "
            "Inspect getshadowresourceinfo before requesting a full supply scan.";
        status.operator_action =
            "Retry getshadowresourceinfo after chainstate initialization. A full supply scan cannot start until these measurements are available, and explicit consent cannot bypass this protection.";
        return status;
    }

    const int64_t first_unmeasured_height = std::max<int64_t>(
        static_cast<int64_t>(measurements.height) + 1,
        SHADOW_REWARD_START_HEIGHT);
    if (first_unmeasured_height <= SHADOW_REWARD_END_HEIGHT) {
        status.remaining_gold_rush_blocks = static_cast<uint64_t>(
            SHADOW_REWARD_END_HEIGHT - first_unmeasured_height + 1);
    }
    status.projected_background_growth_bytes = SaturatingMultiply(
        status.remaining_gold_rush_blocks,
        SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK);
    status.projected_remaining_shadow_physical_bytes = SaturatingMultiply(
        status.remaining_gold_rush_blocks,
        SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK);
    status.required_free_bytes = SaturatingAdd(
        SaturatingAdd(status.projected_remaining_shadow_physical_bytes,
                      status.projected_background_growth_bytes),
        status.minimum_free_bytes);
    status.warning_free_bytes = WarningThreshold(status.required_free_bytes);
    status.within_chainstate_size =
        status.estimated_chainstate_bytes <=
        status.maximum_estimated_chainstate_bytes;
    status.within_supported_height =
        status.height <= status.support_through_height;
    status.within_immediate_scan_free_space =
        status.filesystem_available_bytes >= status.immediate_scan_free_bytes;
    status.critical_free_space_satisfied =
        status.filesystem_available_bytes >= status.critical_free_bytes;
    status.within_projected_free_space =
        status.filesystem_available_bytes >= status.required_free_bytes;
    status.operational_envelope_satisfied =
        status.within_supported_height && status.within_chainstate_size &&
        status.within_projected_free_space;

    // Free-space projection alone does not make a current snapshot scan
    // unsafe. The fixed height, current database size, and immediate free-space
    // reserve still gate an unqualified scan behind explicit one-call consent.
    status.diagnostic_scan_default_authorized =
        status.within_supported_height && status.within_chainstate_size &&
        status.within_immediate_scan_free_space;

    if (!status.within_supported_height) {
        status.level = ShadowResourceStatusLevel::OUTSIDE_ENVELOPE;
        status.warning = strprintf(
            "Quantum Quasar has passed the reviewed operational support horizon at height %d (reviewed through %d). "
            "Base-chain validation, networking, staking, mining, and consensus rules remain unchanged. Optional full supply scans require explicit operator consent and fresh qualification.",
            status.height, status.support_through_height);
        status.operator_action =
            "Obtain fresh exact-build resource evidence for the new phase before relying on a full supply scan. A one-call override does not qualify the release.";
        return status;
    }

    if (!status.within_chainstate_size ||
        !status.within_immediate_scan_free_space ||
        !status.within_projected_free_space) {
        status.level = ShadowResourceStatusLevel::OUTSIDE_ENVELOPE;
        if (!status.within_chainstate_size) {
            status.warning = strprintf(
                "Quantum Quasar is outside the reviewed operational resource envelope: the estimated chainstate is %s and the reviewed limit is %s. "
                "Base-chain validation, networking, staking, mining, and consensus rules remain unchanged. Optional full supply scans require explicit operator consent.",
                GiB(status.estimated_chainstate_bytes),
                GiB(status.maximum_estimated_chainstate_bytes));
            status.operator_action =
                "Review current growth and storage evidence. Use getcirculatingsupply true only if you explicitly accept an out-of-envelope diagnostic scan.";
        } else if (!status.within_immediate_scan_free_space) {
            status.warning = strprintf(
                "Quantum Quasar has only %s free on the chainstate filesystem; the reviewed immediate full-scan reserve is %s. "
                "No supply scan starts by default. Base-chain validation, networking, staking, mining, and consensus rules remain unchanged.",
                GiB(status.filesystem_available_bytes),
                GiB(status.immediate_scan_free_bytes));
            status.operator_action =
                "Add storage before scanning. The immediate 64 GiB pre-flush reserve and ongoing 50 MiB integrity floor cannot be overridden.";
        } else {
            status.warning = strprintf(
                "Quantum Quasar storage is below the reviewed operational projection: %s is available and %s is reserved through the Gold Rush envelope. "
                "Base-chain validation, networking, staking, mining, and consensus rules remain unchanged; no automatic shutdown or network action is taken.",
                GiB(status.filesystem_available_bytes),
                GiB(status.required_free_bytes));
            status.operator_action =
                "Add storage or move the datadir. Current snapshot supply scans remain available while the present chainstate stays within its reviewed size limit.";
        }
        return status;
    }

    const bool low_free_headroom =
        status.filesystem_available_bytes < status.warning_free_bytes;
    const bool high_chainstate_use =
        status.estimated_chainstate_bytes >
        (status.maximum_estimated_chainstate_bytes / 4) * 3;
    if (low_free_headroom || high_chainstate_use) {
        status.level = ShadowResourceStatusLevel::WARNING;
        status.warning = strprintf(
            "Quantum Quasar operational resource headroom is narrowing: estimated chainstate %s, available storage %s, reviewed projected requirement %s. "
            "No consensus, networking, staking, or mining behavior is changed.",
            GiB(status.estimated_chainstate_bytes),
            GiB(status.filesystem_available_bytes),
            GiB(status.required_free_bytes));
        status.operator_action =
            "Monitor getshadowresourceinfo and plan additional storage before the hard operating-envelope threshold is reached.";
        return status;
    }

    status.level = ShadowResourceStatusLevel::HEALTHY;
    status.operator_action =
        "No action. Continue monitoring getshadowresourceinfo; this is a scoped operating envelope, not a universal consensus bound.";
    return status;
}

ShadowResourceStatus GetShadowResourceStatus(ChainstateManager& chainman)
{
    ShadowResourceMeasurements measurements;
    measurements.applicable =
        chainman.GetParams().GetChainTypeString() == "main";

    std::optional<fs::path> storage_path;
    {
        LOCK(::cs_main);
        const CBlockIndex* tip = chainman.ActiveChain().Tip();
        if (!tip) return EvaluateShadowResourceStatus(measurements);
        measurements.height = tip->nHeight;
        measurements.best_block = tip->GetBlockHash().GetHex();
        if (!measurements.applicable) {
            measurements.available = true;
            return EvaluateShadowResourceStatus(measurements);
        }
        measurements.estimated_chainstate_bytes =
            chainman.ActiveChainstate().CoinsDB().EstimateSize();
        storage_path = chainman.ActiveChainstate().CoinsDB().StoragePath();
    }

    if (!storage_path) return EvaluateShadowResourceStatus(measurements);
    std::error_code error;
    const fs::space_info space = fs::space(*storage_path, error);
    if (error || space.available == static_cast<uintmax_t>(-1)) {
        return EvaluateShadowResourceStatus(measurements);
    }
    if constexpr (sizeof(uintmax_t) > sizeof(uint64_t)) {
        if (space.available > std::numeric_limits<uint64_t>::max()) {
            return EvaluateShadowResourceStatus(measurements);
        }
    }
    measurements.filesystem_available_bytes =
        static_cast<uint64_t>(space.available);
    measurements.available = true;
    return EvaluateShadowResourceStatus(measurements);
}

std::optional<uint64_t> TryBeginShadowSupplyScan(
    int height, const std::string& best_block)
{
    LOCK(g_shadow_supply_scan_mutex);
    if (g_shadow_supply_scan.active) return std::nullopt;
    uint64_t scan_id = g_next_shadow_supply_scan_id++;
    if (scan_id == 0) {
        scan_id = g_next_shadow_supply_scan_id++;
    }
    g_shadow_supply_scan = {};
    g_shadow_supply_scan.active = true;
    g_shadow_supply_scan.scan_id = scan_id;
    g_shadow_supply_scan.height = height;
    g_shadow_supply_scan.best_block = best_block;
    g_shadow_supply_scan.stage = "preparing_snapshot";
    g_shadow_supply_scan.started_at_unix =
        GetTime<std::chrono::seconds>().count();
    g_shadow_supply_scan.last_outcome = "running";
    g_shadow_supply_scan_abort_id.store(0, std::memory_order_release);
    g_shadow_supply_scan_started_steady_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
    return scan_id;
}

void SetShadowSupplyScanAnchor(uint64_t scan_id, int height,
                              const std::string& best_block)
{
    LOCK(g_shadow_supply_scan_mutex);
    if (!g_shadow_supply_scan.active ||
        g_shadow_supply_scan.scan_id != scan_id) return;
    g_shadow_supply_scan.height = height;
    g_shadow_supply_scan.best_block = best_block;
}

void UpdateShadowSupplyScan(uint64_t scan_id, const std::string& stage,
                            uint64_t marker_records_scanned,
                            uint64_t utxo_records_scanned,
                            uint64_t active_coin_batch_payload_bytes_scanned,
                            uint64_t authenticated_shadow_records_scanned,
                            uint64_t authenticated_shadow_batch_payload_bytes_scanned,
                            uint64_t provenance_point_seeks,
                            uint64_t demurrage_point_seeks)
{
    LOCK(g_shadow_supply_scan_mutex);
    if (!g_shadow_supply_scan.active ||
        g_shadow_supply_scan.scan_id != scan_id) return;
    g_shadow_supply_scan.stage = stage;
    g_shadow_supply_scan.marker_records_scanned = marker_records_scanned;
    g_shadow_supply_scan.utxo_records_scanned = utxo_records_scanned;
    g_shadow_supply_scan.active_coin_batch_payload_bytes_scanned =
        active_coin_batch_payload_bytes_scanned;
    g_shadow_supply_scan.authenticated_shadow_records_scanned =
        authenticated_shadow_records_scanned;
    g_shadow_supply_scan.authenticated_shadow_batch_payload_bytes_scanned =
        authenticated_shadow_batch_payload_bytes_scanned;
    g_shadow_supply_scan.provenance_point_seeks = provenance_point_seeks;
    g_shadow_supply_scan.demurrage_point_seeks = demurrage_point_seeks;
}

bool RequestShadowSupplyScanAbort()
{
    LOCK(g_shadow_supply_scan_mutex);
    if (!g_shadow_supply_scan.active) return false;
    g_shadow_supply_scan.abort_requested = true;
    g_shadow_supply_scan_abort_id.store(
        g_shadow_supply_scan.scan_id, std::memory_order_release);
    return true;
}

bool ShadowSupplyScanAbortRequested(uint64_t scan_id)
{
    return scan_id != 0 &&
        g_shadow_supply_scan_abort_id.load(std::memory_order_acquire) == scan_id;
}

void FinishShadowSupplyScan(uint64_t scan_id, const std::string& outcome,
                            const std::string& reason)
{
    LOCK(g_shadow_supply_scan_mutex);
    if (!g_shadow_supply_scan.active ||
        g_shadow_supply_scan.scan_id != scan_id) return;
    const int64_t now_steady_ms =
        TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
    if (now_steady_ms >= g_shadow_supply_scan_started_steady_ms) {
        g_shadow_supply_scan.elapsed_milliseconds = static_cast<uint64_t>(
            now_steady_ms - g_shadow_supply_scan_started_steady_ms);
    }
    g_shadow_supply_scan.active = false;
    g_shadow_supply_scan.stage = "idle";
    g_shadow_supply_scan.completed_at_unix =
        GetTime<std::chrono::seconds>().count();
    g_shadow_supply_scan.last_outcome = outcome;
    g_shadow_supply_scan.last_reason = reason;
    g_shadow_supply_scan_abort_id.store(0, std::memory_order_release);
}

ShadowSupplyScanProgress GetShadowSupplyScanProgress()
{
    LOCK(g_shadow_supply_scan_mutex);
    ShadowSupplyScanProgress result = g_shadow_supply_scan;
    if (result.active) {
        const int64_t now_steady_ms =
            TicksSinceEpoch<std::chrono::milliseconds>(SteadyClock::now());
        if (now_steady_ms >= g_shadow_supply_scan_started_steady_ms) {
            result.elapsed_milliseconds = static_cast<uint64_t>(
                now_steady_ms - g_shadow_supply_scan_started_steady_ms);
        }
    }
    return result;
}

void RefreshShadowResourceWarning(NodeContext& node)
{
    if (!node.chainman) return;
    const ShadowResourceStatus status = GetShadowResourceStatus(*node.chainman);
    const bilingual_str warning = status.warning.empty()
        ? bilingual_str{}
        : Untranslated(status.warning);
    if (!SetShadowResourceWarning(warning)) return;
    if (!warning.empty()) {
        LogPrintf("Shadow resource monitor: %s\n", warning.original);
    } else {
        LogPrintf("Shadow resource monitor: warning cleared\n");
    }
    uiInterface.NotifyAlertChanged();
}

} // namespace node
