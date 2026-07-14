// Copyright (c) 2018-2023 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <chainparams.h>
#include <consensus/tx_verify.h>

#include <limits>

BOOST_AUTO_TEST_SUITE(minfee_tests)

BOOST_AUTO_TEST_CASE(minfee_test)
{
    SelectParams(ChainType::MAIN);

    // Check minimum fees before V3_1 fork
    BOOST_CHECK_EQUAL(GetMinFee(0, 0), 0);
    BOOST_CHECK_EQUAL(GetMinFee(99, 0), 9900);
    BOOST_CHECK_EQUAL(GetMinFee(100, 0), 10000);
    BOOST_CHECK_EQUAL(GetMinFee(101, 0), 10100);
    BOOST_CHECK_EQUAL(GetMinFee(10000, 0), 1000000);

    const CAmount legacy_max_size_fee = GetMinFee(std::numeric_limits<size_t>::max(), 0);
    if constexpr (sizeof(size_t) > sizeof(uint32_t)) {
        const size_t max_fee_rate_bytes{std::numeric_limits<uint32_t>::max()};
        BOOST_CHECK(GetMinFee(max_fee_rate_bytes, 0) < MAX_MONEY);
        BOOST_CHECK_EQUAL(GetMinFee(max_fee_rate_bytes + 1, 0), MAX_MONEY);
        BOOST_CHECK_EQUAL(legacy_max_size_fee, MAX_MONEY);
    } else {
        BOOST_CHECK(legacy_max_size_fee <= MAX_MONEY);
    }

    // Check minimum fees after V3_1 fork
    BOOST_CHECK_EQUAL(GetMinFee(0, Params().GetConsensus().nProtocolV3_1Time + 1), 10000);
    BOOST_CHECK_EQUAL(GetMinFee(99, Params().GetConsensus().nProtocolV3_1Time + 1), 10000);
    BOOST_CHECK_EQUAL(GetMinFee(100, Params().GetConsensus().nProtocolV3_1Time + 1), 10000);
    BOOST_CHECK_EQUAL(GetMinFee(101, Params().GetConsensus().nProtocolV3_1Time + 1), 10100);
    BOOST_CHECK_EQUAL(GetMinFee(10000, Params().GetConsensus().nProtocolV3_1Time + 1), 1000000);

    const CAmount current_max_size_fee = GetMinFee(
        std::numeric_limits<size_t>::max(),
        Params().GetConsensus().nProtocolV3_1Time + 1);
    if constexpr (sizeof(size_t) > sizeof(uint32_t)) {
        const size_t max_fee_rate_bytes{std::numeric_limits<uint32_t>::max()};
        BOOST_CHECK(GetMinFee(
            max_fee_rate_bytes,
            Params().GetConsensus().nProtocolV3_1Time + 1) < MAX_MONEY);
        BOOST_CHECK_EQUAL(GetMinFee(
            max_fee_rate_bytes + 1,
            Params().GetConsensus().nProtocolV3_1Time + 1), MAX_MONEY);
        BOOST_CHECK_EQUAL(current_max_size_fee, MAX_MONEY);
    } else {
        BOOST_CHECK(current_max_size_fee <= MAX_MONEY);
    }
}

BOOST_AUTO_TEST_SUITE_END()
