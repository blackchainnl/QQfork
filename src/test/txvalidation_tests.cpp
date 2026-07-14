// Copyright (c) 2017-2021 Blackcoin Core Developers
// Copyright (c) 2017-2021 Blackcoin More Developers
// Copyright (c) 2017-2021 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <key_io.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>


BOOST_AUTO_TEST_SUITE(txvalidation_tests)

/**
 * Ensure that the mempool won't accept coinbase transactions.
 */
BOOST_FIXTURE_TEST_CASE(tx_mempool_reject_coinbase, TestChain100Setup)
{
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    CMutableTransaction coinbaseTx;

    coinbaseTx.nVersion = 1;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vout.resize(1);
    coinbaseTx.vin[0].scriptSig = CScript() << OP_11 << OP_EQUAL;
    coinbaseTx.vout[0].nValue = 1 * CENT;
    coinbaseTx.vout[0].scriptPubKey = scriptPubKey;

    BOOST_CHECK(CTransaction(coinbaseTx).IsCoinBase());

    LOCK(cs_main);

    unsigned int initialPoolSize = m_node.mempool->size();
    const MempoolAcceptResult result = m_node.chainman->ProcessTransaction(MakeTransactionRef(coinbaseTx));

    BOOST_CHECK(result.m_result_type == MempoolAcceptResult::ResultType::INVALID);

    // Check that the transaction hasn't been added to mempool.
    BOOST_CHECK_EQUAL(m_node.mempool->size(), initialPoolSize);

    // Check that the validation state reflects the unsuccessful attempt.
    BOOST_CHECK(result.m_state.IsInvalid());
    BOOST_CHECK_EQUAL(result.m_state.GetRejectReason(), "coinbase");
    BOOST_CHECK(result.m_state.GetResult() == TxValidationResult::TX_CONSENSUS);
}

BOOST_FIXTURE_TEST_CASE(v2_mempool_time_is_wire_canonical, TestChain100Setup)
{
    const COutPoint prevout{m_coinbase_txns.front()->GetHash(), 0};
    Coin input_coin;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(m_node.chainman->ActiveChainstate().CoinsTip().GetCoin(prevout, input_coin));
    }
    BOOST_REQUIRE_GT(input_coin.nTime, 1U);

    const CScript output_script{GetScriptForDestination(PKHash{coinbaseKey.GetPubKey()})};
    CMutableTransaction local_tx{CreateValidMempoolTransaction(
        m_coinbase_txns.front(), 0, input_coin.nHeight, coinbaseKey,
        output_script, 1 * COIN, /*submit=*/false)};
    BOOST_REQUIRE_GE(local_tx.nVersion, 2);

    // A local immutable object can retain this field even though the same
    // transaction necessarily loses it on the wire.
    local_tx.nTime = input_coin.nTime;
    const CTransaction local_immutable{local_tx};
    CDataStream wire{SER_NETWORK};
    wire << TX_WITH_WITNESS(local_immutable);
    CMutableTransaction deserialized_tx;
    wire >> TX_WITH_WITNESS(deserialized_tx);
    BOOST_REQUIRE_EQUAL(deserialized_tx.nTime, 0U);
    BOOST_REQUIRE_EQUAL(local_immutable.GetHash(), CTransaction{deserialized_tx}.GetHash());

    // Put adjusted time before the input coin while the prospective PoW block
    // time (MTP+1) remains mineable. Both representations must receive the
    // same result, and neither may depend on the hidden local nTime.
    SetMockTime(input_coin.nTime - 1);
    {
        LOCK(cs_main);
        const MempoolAcceptResult local_result =
            m_node.chainman->ProcessTransaction(MakeTransactionRef(local_tx), /*test_accept=*/true);
        const MempoolAcceptResult deserialized_result =
            m_node.chainman->ProcessTransaction(MakeTransactionRef(deserialized_tx), /*test_accept=*/true);
        BOOST_CHECK(local_result.m_result_type == deserialized_result.m_result_type);
        BOOST_CHECK(local_result.m_result_type == MempoolAcceptResult::ResultType::VALID);
    }
    SetMockTime(0);
}
BOOST_AUTO_TEST_SUITE_END()
