// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_SHADOW_RESOURCE_MONITOR_H
#define BITCOIN_NODE_SHADOW_RESOURCE_MONITOR_H

#include <cstdint>
#include <optional>
#include <string>

class ChainstateManager;

namespace node {

struct NodeContext;

/**
 * Source-bound operating envelope for the v30.1.1 shadow-state implementation.
 *
 * These values are not consensus limits. A valid base block must never be
 * rejected because one of these limits is crossed. They bound only the release
 * qualification claim, persistent operator warnings, and optional diagnostic
 * scans such as getcirculatingsupply.
 */
inline constexpr int SHADOW_RESOURCE_SUPPORT_THROUGH_HEIGHT{6192999};
inline constexpr uint64_t SHADOW_RESOURCE_MODELED_SHADOW_LOGICAL_BYTES{103622484600ULL};
inline constexpr uint64_t SHADOW_RESOURCE_POLICY_DISK_AMPLIFICATION_FACTOR{3};
inline constexpr uint64_t SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES{310867453800ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK{432613ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK{1297839ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_LOGICAL_BYTES_PER_BLOCK{398396ULL};
// This is an allowance for LevelDB's approximate active Coin-key-range size,
// not a physical-directory measurement or a consensus-derived maximum.
inline constexpr uint64_t SHADOW_RESOURCE_CURRENT_CHAINSTATE_ESTIMATE_ALLOWANCE_BYTES{68719476736ULL};
inline constexpr uint64_t SHADOW_RESOURCE_CURRENT_BACKGROUND_RECORDS{16777216ULL};
inline constexpr uint64_t SHADOW_RESOURCE_GOLD_RUSH_BLOCKS{243000ULL};
inline constexpr uint64_t SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK{262144ULL};
inline constexpr uint64_t SHADOW_RESOURCE_BACKGROUND_GROWTH_RECORDS_PER_BLOCK{1024ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_SYNTHETIC_RECORDS{541701000ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_MODELED_SHADOW_RECORDS_PER_BLOCK{2263ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_RECORDS_PER_BLOCK{2073ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MINIMUM_FREE_BYTES{68719476736ULL};
inline constexpr uint64_t SHADOW_RESOURCE_IMMEDIATE_SCAN_FREE_BYTES{68719476736ULL};
inline constexpr uint64_t SHADOW_RESOURCE_CRITICAL_FREE_BYTES{52428800ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES{443287922536ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR{807310216ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_SEQUENTIAL_VISITS{1614620432ULL};
inline constexpr uint64_t SHADOW_RESOURCE_MAX_POINT_SEEKS{1614620432ULL};
// Explicit operator consent can cross the qualified operating threshold, but
// never these absolute per-call protection limits. They remain RPC-only and
// do not constrain consensus-valid chainstate.
inline constexpr uint64_t SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR{1614620432ULL};
inline constexpr uint64_t SHADOW_RESOURCE_ABSOLUTE_POINT_SEEKS{3229240864ULL};
inline constexpr uint64_t SHADOW_RESOURCE_WARNING_NUMERATOR{5};
inline constexpr uint64_t SHADOW_RESOURCE_WARNING_DENOMINATOR{4};

static_assert(SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES == 310867453800ULL);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK == 432613ULL);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK == 1297839ULL);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_RECORDS_PER_BLOCK == 2263ULL);
static_assert(SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_LOGICAL_BYTES_PER_BLOCK == 398396ULL);
static_assert(SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_RECORDS_PER_BLOCK == 2073ULL);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK ==
              751ULL * 509ULL + 48204ULL + 2150ULL);
static_assert(SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_LOGICAL_BYTES_PER_BLOCK ==
              688ULL * 509ULL + 48204ULL);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_RECORDS_PER_BLOCK ==
              751ULL * 3ULL + 9ULL + 1ULL);
static_assert(SHADOW_RESOURCE_MODELED_LEGACY_SHADOW_RECORDS_PER_BLOCK ==
              688ULL * 3ULL + 9ULL);
static_assert(SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES == 443287922536ULL);
static_assert(SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR == 807310216ULL);
static_assert(SHADOW_RESOURCE_MAX_SEQUENTIAL_VISITS == 1614620432ULL);
static_assert(SHADOW_RESOURCE_MAX_POINT_SEEKS == 1614620432ULL);
static_assert(SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES ==
              SHADOW_RESOURCE_MODELED_SHADOW_LOGICAL_BYTES *
                  SHADOW_RESOURCE_POLICY_DISK_AMPLIFICATION_FACTOR);
static_assert(SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK ==
              SHADOW_RESOURCE_MAX_MODELED_SHADOW_LOGICAL_BYTES_PER_BLOCK *
                  SHADOW_RESOURCE_POLICY_DISK_AMPLIFICATION_FACTOR);
static_assert(SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES ==
              SHADOW_RESOURCE_CURRENT_CHAINSTATE_ESTIMATE_ALLOWANCE_BYTES +
                  SHADOW_RESOURCE_MODELED_SHADOW_PHYSICAL_RESERVE_BYTES +
                  SHADOW_RESOURCE_GOLD_RUSH_BLOCKS *
                      SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK);
static_assert(SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR ==
              SHADOW_RESOURCE_CURRENT_BACKGROUND_RECORDS +
                  SHADOW_RESOURCE_MAX_SYNTHETIC_RECORDS +
                  SHADOW_RESOURCE_GOLD_RUSH_BLOCKS *
                      SHADOW_RESOURCE_BACKGROUND_GROWTH_RECORDS_PER_BLOCK);
static_assert(SHADOW_RESOURCE_MAX_SEQUENTIAL_VISITS ==
              SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR * 2);
static_assert(SHADOW_RESOURCE_MAX_POINT_SEEKS ==
              SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR * 2);
static_assert(SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR ==
              SHADOW_RESOURCE_MAX_RECORDS_PER_CURSOR * 2);
static_assert(SHADOW_RESOURCE_ABSOLUTE_POINT_SEEKS ==
              SHADOW_RESOURCE_ABSOLUTE_RECORDS_PER_CURSOR * 2);

enum class ShadowResourceStatusLevel {
    NOT_APPLICABLE,
    UNAVAILABLE,
    HEALTHY,
    WARNING,
    OUTSIDE_ENVELOPE,
};

struct ShadowResourceMeasurements {
    bool applicable{false};
    bool available{false};
    int height{-1};
    std::string best_block;
    uint64_t estimated_chainstate_bytes{0};
    uint64_t filesystem_available_bytes{0};
};

struct ShadowResourceStatus {
    ShadowResourceStatusLevel level{ShadowResourceStatusLevel::UNAVAILABLE};
    bool applicable{false};
    bool measurements_available{false};
    int height{-1};
    std::string best_block;
    uint64_t estimated_chainstate_bytes{0};
    uint64_t filesystem_available_bytes{0};
    uint64_t remaining_gold_rush_blocks{0};
    uint64_t projected_remaining_shadow_physical_bytes{0};
    uint64_t projected_background_growth_bytes{0};
    uint64_t minimum_free_bytes{0};
    uint64_t required_free_bytes{0};
    uint64_t warning_free_bytes{0};
    uint64_t immediate_scan_free_bytes{0};
    uint64_t critical_free_bytes{0};
    uint64_t maximum_estimated_chainstate_bytes{0};
    uint64_t maximum_records_per_cursor{0};
    uint64_t maximum_sequential_visits{0};
    uint64_t maximum_point_seeks{0};
    uint64_t absolute_records_per_cursor{0};
    uint64_t absolute_point_seeks{0};
    int support_through_height{0};
    bool within_supported_height{false};
    bool within_chainstate_size{false};
    bool within_immediate_scan_free_space{false};
    bool within_projected_free_space{false};
    bool critical_free_space_satisfied{false};
    bool operational_envelope_satisfied{false};
    bool diagnostic_scan_default_authorized{false};
    std::string warning;
    std::string operator_action;
};

/** Process-wide progress for the intentionally single-flight supply scan. */
struct ShadowSupplyScanProgress {
    bool active{false};
    uint64_t scan_id{0};
    int height{-1};
    std::string best_block;
    std::string stage{"idle"};
    bool abort_requested{false};
    uint64_t marker_records_scanned{0};
    uint64_t utxo_records_scanned{0};
    uint64_t active_coin_batch_payload_bytes_scanned{0};
    uint64_t authenticated_shadow_records_scanned{0};
    uint64_t authenticated_shadow_batch_payload_bytes_scanned{0};
    uint64_t provenance_point_seeks{0};
    uint64_t demurrage_point_seeks{0};
    uint64_t elapsed_milliseconds{0};
    int64_t started_at_unix{0};
    int64_t completed_at_unix{0};
    std::string last_outcome{"never_run"};
    std::string last_reason;
};

const char* ShadowResourceStatusName(ShadowResourceStatusLevel level);

/** Pure arithmetic used by runtime code and unit tests. */
ShadowResourceStatus EvaluateShadowResourceStatus(
    const ShadowResourceMeasurements& measurements);

/** Take a cheap current LevelDB/filesystem measurement. */
ShadowResourceStatus GetShadowResourceStatus(ChainstateManager& chainman);

/** Acquire the only full-supply scan slot in this daemon. */
std::optional<uint64_t> TryBeginShadowSupplyScan(int height,
                                                const std::string& best_block);
void SetShadowSupplyScanAnchor(uint64_t scan_id, int height,
                              const std::string& best_block);
void UpdateShadowSupplyScan(uint64_t scan_id, const std::string& stage,
                            uint64_t marker_records_scanned,
                            uint64_t utxo_records_scanned,
                            uint64_t active_coin_batch_payload_bytes_scanned,
                            uint64_t authenticated_shadow_records_scanned,
                            uint64_t authenticated_shadow_batch_payload_bytes_scanned,
                            uint64_t provenance_point_seeks,
                            uint64_t demurrage_point_seeks);
/** Request cooperative cancellation. Returns false when no scan is active. */
bool RequestShadowSupplyScanAbort();
bool ShadowSupplyScanAbortRequested(uint64_t scan_id);
void FinishShadowSupplyScan(uint64_t scan_id, const std::string& outcome,
                            const std::string& reason);
ShadowSupplyScanProgress GetShadowSupplyScanProgress();

/** Refresh the independent GUI/CLI/daemon warning without changing consensus. */
void RefreshShadowResourceWarning(NodeContext& node);

} // namespace node

#endif // BITCOIN_NODE_SHADOW_RESOURCE_MONITOR_H
