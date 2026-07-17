// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/shadow_resource_monitor.h>

#include <test/util/setup_common.h>
#include <util/translation.h>
#include <warnings.h>

#include <boost/test/unit_test.hpp>

#include <limits>
#include <string>

BOOST_FIXTURE_TEST_SUITE(shadow_resource_monitor_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(scope_and_unavailable_state_fail_closed)
{
    node::ShadowResourceMeasurements measurement;
    const node::ShadowResourceStatus not_applicable =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(not_applicable.level),
        "not_applicable");
    BOOST_CHECK(not_applicable.operational_envelope_satisfied);
    BOOST_CHECK(not_applicable.diagnostic_scan_default_authorized);

    measurement.applicable = true;
    const node::ShadowResourceStatus unavailable =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(unavailable.level), "unavailable");
    BOOST_CHECK(!unavailable.operational_envelope_satisfied);
    BOOST_CHECK(!unavailable.diagnostic_scan_default_authorized);
    BOOST_CHECK(unavailable.warning.find("consensus rules remain unchanged") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(height_projection_and_thresholds_are_exact)
{
    node::ShadowResourceMeasurements measurement;
    measurement.applicable = true;
    measurement.available = true;
    measurement.height = 5'949'999;
    measurement.best_block = std::string(64, '1');
    measurement.estimated_chainstate_bytes = 1ULL << 30;
    measurement.filesystem_available_bytes =
        std::numeric_limits<uint64_t>::max();

    node::ShadowResourceStatus status =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(status.remaining_gold_rush_blocks, 243'000U);
    BOOST_CHECK_EQUAL(
        status.projected_remaining_shadow_physical_bytes,
        243'000ULL *
            node::SHADOW_RESOURCE_MAX_MODELED_SHADOW_PHYSICAL_BYTES_PER_BLOCK);
    BOOST_CHECK_EQUAL(
        status.projected_background_growth_bytes,
        243'000ULL *
            node::SHADOW_RESOURCE_BACKGROUND_PHYSICAL_RESERVE_BYTES_PER_BLOCK);
    BOOST_CHECK_EQUAL(
        status.maximum_estimated_chainstate_bytes, 443'287'922'536ULL);
    BOOST_CHECK_EQUAL(status.maximum_records_per_cursor, 807'310'216ULL);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(status.level), "healthy");

    measurement.height = 6'192'999;
    status = node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(status.remaining_gold_rush_blocks, 0U);
    BOOST_CHECK_EQUAL(status.projected_remaining_shadow_physical_bytes, 0U);
    BOOST_CHECK_EQUAL(status.projected_background_growth_bytes, 0U);
    BOOST_CHECK_EQUAL(status.required_free_bytes,
                      node::SHADOW_RESOURCE_MINIMUM_FREE_BYTES);

    measurement.height = 6'193'000;
    status = node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(status.level),
        "outside_operational_envelope");
    BOOST_CHECK(!status.within_supported_height);
    BOOST_CHECK(!status.diagnostic_scan_default_authorized);

    // A corrupt or synthetic extreme height must stay fail-closed without
    // overflowing the next-height projection.
    measurement.height = std::numeric_limits<int>::max();
    status = node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(status.remaining_gold_rush_blocks, 0U);
    BOOST_CHECK(!status.within_supported_height);
}

BOOST_AUTO_TEST_CASE(warning_and_hard_thresholds_do_not_change_scan_policy)
{
    node::ShadowResourceMeasurements measurement;
    measurement.applicable = true;
    measurement.available = true;
    measurement.height = 5'949'999;
    measurement.best_block = std::string(64, '2');
    measurement.estimated_chainstate_bytes = 1ULL << 30;
    measurement.filesystem_available_bytes =
        std::numeric_limits<uint64_t>::max();
    const node::ShadowResourceStatus healthy =
        node::EvaluateShadowResourceStatus(measurement);

    measurement.filesystem_available_bytes = healthy.required_free_bytes;
    const node::ShadowResourceStatus warning =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(warning.level), "warning");
    BOOST_CHECK(warning.operational_envelope_satisfied);
    BOOST_CHECK(warning.diagnostic_scan_default_authorized);

    measurement.filesystem_available_bytes = healthy.required_free_bytes - 1;
    const node::ShadowResourceStatus low_storage =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(low_storage.level),
        "outside_operational_envelope");
    BOOST_CHECK(!low_storage.operational_envelope_satisfied);
    // Low future storage does not make a current read-only scan unsafe.
    BOOST_CHECK(low_storage.diagnostic_scan_default_authorized);
    BOOST_CHECK(low_storage.warning.find("no automatic shutdown") !=
                std::string::npos);

    measurement.filesystem_available_bytes =
        std::numeric_limits<uint64_t>::max();
    measurement.estimated_chainstate_bytes =
        node::SHADOW_RESOURCE_MAX_ESTIMATED_CHAINSTATE_BYTES + 1;
    const node::ShadowResourceStatus oversized =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK_EQUAL(
        node::ShadowResourceStatusName(oversized.level),
        "outside_operational_envelope");
    BOOST_CHECK(!oversized.diagnostic_scan_default_authorized);
    BOOST_CHECK(oversized.warning.find("explicit operator consent") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(immediate_scan_reserve_and_single_flight_are_enforced)
{
    node::ShadowResourceMeasurements measurement;
    measurement.applicable = true;
    measurement.available = true;
    measurement.height = 5'950'000;
    measurement.best_block = std::string(64, '3');
    measurement.estimated_chainstate_bytes = 1ULL << 30;
    measurement.filesystem_available_bytes =
        node::SHADOW_RESOURCE_IMMEDIATE_SCAN_FREE_BYTES - 1;

    node::ShadowResourceStatus status =
        node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK(!status.within_immediate_scan_free_space);
    BOOST_CHECK(status.critical_free_space_satisfied);
    BOOST_CHECK(!status.diagnostic_scan_default_authorized);

    measurement.filesystem_available_bytes =
        node::SHADOW_RESOURCE_CRITICAL_FREE_BYTES - 1;
    status = node::EvaluateShadowResourceStatus(measurement);
    BOOST_CHECK(!status.critical_free_space_satisfied);

    const std::optional<uint64_t> first =
        node::TryBeginShadowSupplyScan(5'950'000, std::string(64, '4'));
    BOOST_REQUIRE(first);
    BOOST_CHECK(!node::TryBeginShadowSupplyScan(
        5'950'001, std::string(64, '5')));
    node::UpdateShadowSupplyScan(
        *first, "scanning_utxos", 20, 10, 1234, 4, 500, 3, 4);
    node::ShadowSupplyScanProgress progress =
        node::GetShadowSupplyScanProgress();
    BOOST_CHECK(progress.active);
    BOOST_CHECK_EQUAL(progress.marker_records_scanned, 20U);
    BOOST_CHECK_EQUAL(progress.utxo_records_scanned, 10U);
    BOOST_CHECK_EQUAL(progress.active_coin_batch_payload_bytes_scanned,
                      1234U);
    BOOST_CHECK_EQUAL(progress.authenticated_shadow_records_scanned, 4U);
    BOOST_CHECK_EQUAL(
        progress.authenticated_shadow_batch_payload_bytes_scanned, 500U);
    BOOST_CHECK_EQUAL(progress.provenance_point_seeks, 3U);
    BOOST_CHECK_EQUAL(progress.demurrage_point_seeks, 4U);
    BOOST_CHECK(node::RequestShadowSupplyScanAbort());
    BOOST_CHECK(node::ShadowSupplyScanAbortRequested(*first));
    BOOST_CHECK(!node::ShadowSupplyScanAbortRequested(*first + 1));
    BOOST_CHECK(node::GetShadowSupplyScanProgress().abort_requested);
    node::FinishShadowSupplyScan(*first, "complete", "test complete");
    progress = node::GetShadowSupplyScanProgress();
    BOOST_CHECK(!progress.active);
    BOOST_CHECK(!node::ShadowSupplyScanAbortRequested(*first));
    BOOST_CHECK(!node::RequestShadowSupplyScanAbort());
    BOOST_CHECK_EQUAL(progress.last_outcome, "complete");
    BOOST_CHECK(node::TryBeginShadowSupplyScan(
        5'950'001, std::string(64, '5')));
    const uint64_t second_id =
        node::GetShadowSupplyScanProgress().scan_id;
    node::FinishShadowSupplyScan(second_id, "aborted", "test cleanup");
}

BOOST_AUTO_TEST_CASE(resource_warning_does_not_replace_misc_warning)
{
    SetMiscWarning(Untranslated("misc-warning-sentinel"));
    BOOST_CHECK(SetShadowResourceWarning(
        Untranslated("resource-warning-sentinel")));
    BOOST_CHECK(!SetShadowResourceWarning(
        Untranslated("resource-warning-sentinel")));

    const std::string warnings = GetWarnings(true).original;
    BOOST_CHECK(warnings.find("misc-warning-sentinel") != std::string::npos);
    BOOST_CHECK(warnings.find("resource-warning-sentinel") !=
                std::string::npos);
    BOOST_CHECK_EQUAL(GetWarnings(false).original,
                      "misc-warning-sentinel");

    BOOST_CHECK(SetShadowResourceWarning(Untranslated("")));
    BOOST_CHECK(GetWarnings(true).original.find("misc-warning-sentinel") !=
                std::string::npos);
    BOOST_CHECK(GetWarnings(true).original.find("resource-warning-sentinel") ==
                std::string::npos);
    SetMiscWarning(Untranslated(""));
}

BOOST_AUTO_TEST_SUITE_END()
