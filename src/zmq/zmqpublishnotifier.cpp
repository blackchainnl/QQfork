// Copyright (c) 2015-2022 The Bitcoin Core developers
// Copyright (c) 2015-2022 Blackcoin Core Developers
// Copyright (c) 2015-2022 Blackcoin More Developers
// Copyright (c) 2015-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <zmq/zmqpublishnotifier.h>

#include <chain.h>
#include <chainparams.h>
#include <core_io.h>
#include <crypto/common.h>
#include <index/shadowindex.h>
#include <kernel/cs_main.h>
#include <key_io.h>
#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/blockstorage.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <serialize.h>
#include <script/solver.h>
#include <streams.h>
#include <sync.h>
#include <uint256.h>
#include <version.h>
#include <zmq/zmqutil.h>

#include <univalue.h>

#include <zmq.h>

#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace Consensus {
struct Params;
}

static std::multimap<std::string, CZMQAbstractPublishNotifier*> mapPublishNotifiers;

static const char *MSG_HASHBLOCK = "hashblock";
static const char *MSG_HASHTX    = "hashtx";
static const char *MSG_RAWBLOCK  = "rawblock";
static const char *MSG_RAWTX     = "rawtx";
static const char *MSG_SEQUENCE  = "sequence";
static const char *MSG_SHADOW    = "shadow";

namespace {

const char* ShadowPowDispositionName(ShadowPowClaimDisposition disposition)
{
    switch (static_cast<uint8_t>(disposition)) {
    case static_cast<uint8_t>(ShadowPowClaimDisposition::INVALID_LOCATION): return "invalid_location";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::MALFORMED_TRANSACTION): return "malformed_transaction";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::INVALID_PROOF): return "invalid_proof";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::INPUT_MISMATCH): return "input_mismatch";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::INVALID_BASE_FEE): return "invalid_base_fee";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::EVALUATION_LIMIT): return "evaluation_limit";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::WINNER): return "winner";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::REIMBURSED_LOSER): return "reimbursed_loser";
    // Persisted disposition values added by the proof-mode accounting update.
    // Keep their wire names stable when this transport commit is applied
    // before or after that additive enum change.
    case 8: return "wrong_mode_pos";
    case 9: return "unknown_mode";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::ORIGIN_MISMATCH): return "origin_mismatch";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::ORIGIN_EXPIRED): return "origin_expired";
    case static_cast<uint8_t>(ShadowPowClaimDisposition::REIMBURSED_LATE): return "reimbursed_late";
    }
    return "unknown";
}

UniValue ShadowEventUnits()
{
    UniValue units(UniValue::VOBJ);
    units.pushKV("display", "BLK");
    units.pushKV("atomic", "satoshi");
    units.pushKV("atomic_decimals", 8);
    units.pushKV("atomic_encoding", "base-10 string");
    return units;
}

void PushShadowDestination(UniValue& object, const CScript& script)
{
    object.pushKV("scriptPubKey", HexStr(script));
    CTxDestination destination;
    object.pushKV("address", ExtractDestination(script, destination)
        ? UniValue(EncodeDestination(destination)) : UniValue{});
}

UniValue ShadowCreditJSON(const ShadowIndexRecord& record)
{
    UniValue credit(UniValue::VOBJ);
    credit.pushKV("synthetic", true);
    credit.pushKV("merkle_included", false);
    credit.pushKV("synthetic_txid", record.outpoint.hash.GetHex());
    credit.pushKV("vout", record.outpoint.n);
    credit.pushKV("claim_index", record.claim_index);
    credit.pushKV("mode", record.proof_of_work ? "pow" : "pos");
    credit.pushKV("nominal_amount", ValueFromAmount(record.nominal_amount));
    credit.pushKV("nominal_amount_atomic", strprintf("%d", record.nominal_amount));
    PushShadowDestination(credit, record.script_pub_key);

    UniValue source;
    if (record.pow_claim_source_present) {
        source.setObject();
        source.pushKV("txid", record.pow_claim_source.txid.GetHex());
        source.pushKV("vout", record.pow_claim_source.vout);
        source.pushKV("canonical_rank", record.pow_claim_source.canonical_rank.GetHex());
        source.pushKV("disposition", ShadowPowDispositionName(record.pow_claim_source.disposition));
        source.pushKV("base_fee_known", record.pow_claim_source.base_fee_known);
        source.pushKV("base_fee", record.pow_claim_source.base_fee_known
            ? UniValue(ValueFromAmount(record.pow_claim_source.base_fee)) : UniValue{});
        source.pushKV("base_fee_atomic", record.pow_claim_source.base_fee_known
            ? UniValue(strprintf("%d", record.pow_claim_source.base_fee)) : UniValue{});
        source.pushKV("proof_version", record.pow_claim_source.proof_version);
        source.pushKV("origin_bound", record.pow_claim_source.origin_bound);
        source.pushKV("origin_height", record.pow_claim_source.origin_height);
        source.pushKV("origin_previous_block_hash",
                      record.pow_claim_source.origin_previous_block_hash.IsNull()
                          ? UniValue{}
                          : UniValue(record.pow_claim_source.origin_previous_block_hash.GetHex()));
        source.pushKV("inclusion_height", record.pow_claim_source.inclusion_height);
        source.pushKV("origin_age", record.pow_claim_source.origin_age);
        source.pushKV("input_bound", record.pow_claim_source.input_bound);
        if (record.pow_claim_source.input_bound) {
            UniValue outpoint(UniValue::VOBJ);
            outpoint.pushKV("txid",
                             record.pow_claim_source.claim_outpoint.hash.GetHex());
            outpoint.pushKV("vout", record.pow_claim_source.claim_outpoint.n);
            source.pushKV("claim_outpoint", std::move(outpoint));
        } else {
            source.pushKV("claim_outpoint", UniValue{});
        }
    }
    credit.pushKV("pow_claim_source", std::move(source));
    return credit;
}

UniValue ShadowSpendJSON(const ShadowIndexRecord& record)
{
    UniValue spend(UniValue::VOBJ);
    spend.pushKV("synthetic", true);
    spend.pushKV("merkle_included", false);
    spend.pushKV("synthetic_txid", record.outpoint.hash.GetHex());
    spend.pushKV("vout", record.outpoint.n);
    spend.pushKV("origin_height", record.origin_height);
    spend.pushKV("origin_blockhash", record.origin_block_hash.GetHex());
    spend.pushKV("spending_txid", record.spending_txid.GetHex());
    spend.pushKV("tx_index", record.spend_tx_index);
    spend.pushKV("input_index", record.spend_input_index);
    spend.pushKV("nominal_amount", ValueFromAmount(record.nominal_amount));
    spend.pushKV("nominal_amount_atomic", strprintf("%d", record.nominal_amount));
    spend.pushKV("effective_amount", ValueFromAmount(record.effective_amount_at_spend));
    spend.pushKV("effective_amount_atomic", strprintf("%d", record.effective_amount_at_spend));
    spend.pushKV("burned_amount", ValueFromAmount(record.decayed_amount_at_spend));
    spend.pushKV("burned_amount_atomic", strprintf("%d", record.decayed_amount_at_spend));
    PushShadowDestination(spend, record.script_pub_key);
    return spend;
}

} // namespace

// Internal function to send multipart message
static int zmq_send_multipart(void *sock, const void* data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            va_end(args);
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void*);

        rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            va_end(args);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    va_end(args);
    return 0;
}

static bool IsZMQAddressIPV6(const std::string &zmq_address)
{
    const std::string tcp_prefix = "tcp://";
    const size_t tcp_index = zmq_address.rfind(tcp_prefix);
    const size_t colon_index = zmq_address.rfind(':');
    if (tcp_index == 0 && colon_index != std::string::npos) {
        const std::string ip = zmq_address.substr(tcp_prefix.length(), colon_index - tcp_prefix.length());
        const std::optional<CNetAddr> addr{LookupHost(ip, false)};
        if (addr.has_value() && addr.value().IsIPv6()) return true;
    }
    return false;
}

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator i = mapPublishNotifiers.find(address);

    if (i==mapPublishNotifiers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }

        LogPrint(BCLog::ZMQ, "Outbound message high water mark for %s at %s is %d\n", type, address, outbound_message_high_water_mark);

        int rc = zmq_setsockopt(psocket, ZMQ_SNDHWM, &outbound_message_high_water_mark, sizeof(outbound_message_high_water_mark));
        if (rc != 0)
        {
            zmqError("Failed to set outbound message high water mark");
            zmq_close(psocket);
            return false;
        }

        const int so_keepalive_option {1};
        rc = zmq_setsockopt(psocket, ZMQ_TCP_KEEPALIVE, &so_keepalive_option, sizeof(so_keepalive_option));
        if (rc != 0) {
            zmqError("Failed to set SO_KEEPALIVE");
            zmq_close(psocket);
            return false;
        }

        // On some systems (e.g. OpenBSD) the ZMQ_IPV6 must not be enabled, if the address to bind isn't IPv6
        const int enable_ipv6 { IsZMQAddressIPV6(address) ? 1 : 0};
        rc = zmq_setsockopt(psocket, ZMQ_IPV6, &enable_ipv6, sizeof(enable_ipv6));
        if (rc != 0) {
            zmqError("Failed to set ZMQ_IPV6");
            zmq_close(psocket);
            return false;
        }

        rc = zmq_bind(psocket, address.c_str());
        if (rc != 0)
        {
            zmqError("Failed to bind address");
            zmq_close(psocket);
            return false;
        }

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LogPrint(BCLog::ZMQ, "Reusing socket for address %s\n", address);
        LogPrint(BCLog::ZMQ, "Outbound message high water mark for %s at %s is %d\n", type, address, outbound_message_high_water_mark);

        psocket = i->second->psocket;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    // Early return if Initialize was not called
    if (!psocket) return;

    int count = mapPublishNotifiers.count(address);

    // remove this notifier from the list of publishers using this address
    typedef std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator iterator;
    std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

    for (iterator it = iterpair.first; it != iterpair.second; ++it)
    {
        if (it->second==this)
        {
            mapPublishNotifiers.erase(it);
            break;
        }
    }

    if (count == 1)
    {
        LogPrint(BCLog::ZMQ, "Close socket at address %s\n", address);
        int linger = 0;
        zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(psocket);
    }

    psocket = nullptr;
}

bool CZMQAbstractPublishNotifier::SendZmqMessage(const char *command, const void* data, size_t size)
{
    assert(psocket);

    /* send three parts, command & data & a LE 4byte sequence number */
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(msgseq, nSequence);
    int rc = zmq_send_multipart(psocket, command, strlen(command), data, size, msgseq, (size_t)sizeof(uint32_t), nullptr);
    if (rc == -1)
        return false;

    /* increment memory only sequence number after sending */
    nSequence++;

    return true;
}

bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint(BCLog::ZMQ, "Publish hashblock %s to %s\n", hash.GetHex(), this->address);
    uint8_t data[32];
    for (unsigned int i = 0; i < 32; i++) {
        data[31 - i] = hash.begin()[i];
    }
    return SendZmqMessage(MSG_HASHBLOCK, data, 32);
}

bool CZMQPublishHashTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    uint256 hash = transaction.GetHash();
    LogPrint(BCLog::ZMQ, "Publish hashtx %s to %s\n", hash.GetHex(), this->address);
    uint8_t data[32];
    for (unsigned int i = 0; i < 32; i++) {
        data[31 - i] = hash.begin()[i];
    }
    return SendZmqMessage(MSG_HASHTX, data, 32);
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    LogPrint(BCLog::ZMQ, "Publish rawblock %s to %s\n", pindex->GetBlockHash().GetHex(), this->address);

    CDataStream ss(SER_NETWORK);
    CBlock block;
    if (!m_get_block_by_index(block, *pindex)) {
        zmqError("Can't read block from disk");
        return false;
    }

    ss << RPCTxSerParams(block);

    return SendZmqMessage(MSG_RAWBLOCK, &(*ss.begin()), ss.size());
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    uint256 hash = transaction.GetHash();
    LogPrint(BCLog::ZMQ, "Publish rawtx %s to %s\n", hash.GetHex(), this->address);
    CDataStream ss(SER_NETWORK);
    ss << RPCTxSerParams(transaction);
    return SendZmqMessage(MSG_RAWTX, &(*ss.begin()), ss.size());
}

// Helper function to send a 'sequence' topic message with the following structure:
//    <32-byte hash> | <1-byte label> | <8-byte LE sequence> (optional)
static bool SendSequenceMsg(CZMQAbstractPublishNotifier& notifier, uint256 hash, char label, std::optional<uint64_t> sequence = {})
{
    unsigned char data[sizeof(hash) + sizeof(label) + sizeof(uint64_t)];
    for (unsigned int i = 0; i < sizeof(hash); ++i) {
        data[sizeof(hash) - 1 - i] = hash.begin()[i];
    }
    data[sizeof(hash)] = label;
    if (sequence) WriteLE64(data + sizeof(hash) + sizeof(label), *sequence);
    return notifier.SendZmqMessage(MSG_SEQUENCE, data, sequence ? sizeof(data) : sizeof(hash) + sizeof(label));
}

bool CZMQPublishSequenceNotifier::NotifyBlockConnect(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint(BCLog::ZMQ, "Publish sequence block connect %s to %s\n", hash.GetHex(), this->address);
    return SendSequenceMsg(*this, hash, /* Block (C)onnect */ 'C');
}

bool CZMQPublishSequenceNotifier::NotifyBlockDisconnect(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint(BCLog::ZMQ, "Publish sequence block disconnect %s to %s\n", hash.GetHex(), this->address);
    return SendSequenceMsg(*this, hash, /* Block (D)isconnect */ 'D');
}

bool CZMQPublishSequenceNotifier::NotifyTransactionAcceptance(const CTransaction &transaction, uint64_t mempool_sequence)
{
    uint256 hash = transaction.GetHash();
    LogPrint(BCLog::ZMQ, "Publish hashtx mempool acceptance %s to %s\n", hash.GetHex(), this->address);
    return SendSequenceMsg(*this, hash, /* Mempool (A)cceptance */ 'A', mempool_sequence);
}

bool CZMQPublishSequenceNotifier::NotifyTransactionRemoval(const CTransaction &transaction, uint64_t mempool_sequence)
{
    uint256 hash = transaction.GetHash();
    LogPrint(BCLog::ZMQ, "Publish hashtx mempool removal %s to %s\n", hash.GetHex(), this->address);
    return SendSequenceMsg(*this, hash, /* Mempool (R)emoval */ 'R', mempool_sequence);
}

bool CZMQPublishShadowNotifier::NotifyShadowBlock(bool connected,
                                                  const ShadowIndexBlockEvent& event)
{
    UniValue credits(UniValue::VARR);
    for (const ShadowIndexRecord& record : event.credits) {
        credits.push_back(ShadowCreditJSON(record));
    }
    UniValue spends(UniValue::VARR);
    for (const ShadowIndexRecord& record : event.spends) {
        spends.push_back(ShadowSpendJSON(record));
    }

    UniValue payload(UniValue::VOBJ);
    payload.pushKV("schema", "blackcoin.shadow.event.v1");
    payload.pushKV("event", connected ? "shadow.block.connected" : "shadow.block.disconnected");
    payload.pushKV("height", event.height);
    payload.pushKV("blockhash", event.block_hash.GetHex());
    payload.pushKV("previousblockhash", event.previous_block_hash.GetHex());
    payload.pushKV("time", event.block_time);
    payload.pushKV("synthetic", true);
    payload.pushKV("merkle_included", false);
    payload.pushKV("credit_count", static_cast<uint64_t>(event.credits.size()));
    payload.pushKV("spend_count", static_cast<uint64_t>(event.spends.size()));
    payload.pushKV("units", ShadowEventUnits());
    payload.pushKV("credits", std::move(credits));
    payload.pushKV("spends", std::move(spends));

    const std::string body = payload.write();
    if (body.size() > MAX_SHADOW_EVENT_JSON_BYTES) {
        LogPrintf("Shadow ZMQ event for %s exceeds the %u-byte transport bound; subscribers must reconcile by RPC\n",
                  event.block_hash.GetHex(),
                  static_cast<unsigned int>(MAX_SHADOW_EVENT_JSON_BYTES));
        return true;
    }
    LogPrint(BCLog::ZMQ,
             "Publish shadow %s height=%d block=%s credits=%u spends=%u to %s\n",
             connected ? "connect" : "disconnect", event.height,
             event.block_hash.GetHex(), static_cast<unsigned int>(event.credits.size()),
             static_cast<unsigned int>(event.spends.size()), this->address);
    return SendZmqMessage(MSG_SHADOW, body.data(), body.size());
}
