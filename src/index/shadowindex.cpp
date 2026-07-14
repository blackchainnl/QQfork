// Copyright (c) 2026 Blackcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <index/shadowindex.h>

#include <addresstype.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <consensus/demurrage.h>
#include <consensus/quantum_witness.h>
#include <hash.h>
#include <interfaces/chain.h>
#include <logging.h>
#include <shadow.h>
#include <undo.h>
#include <validation.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace {

static constexpr uint8_t DB_SCHEMA_VERSION{'V'};
static constexpr uint8_t DB_BLOCK{'b'};
static constexpr uint8_t DB_TRANSACTION{'t'};
static constexpr uint8_t DB_SPENT_OUTPOINT{'p'};
static constexpr uint8_t DB_SCRIPT{'s'};
static constexpr uint8_t DB_UNDO{'u'};
static constexpr uint8_t DB_ATTESTATION{'a'};
static constexpr uint8_t DB_QUANTUM_WITNESS_OUTPUT{'w'};
static constexpr uint8_t DB_QUANTUM_WITNESS_BLOCK{'W'};
static constexpr uint8_t DB_POW_CLAIM{'c'};
static constexpr uint8_t DB_CUSTOM_TIP{'T'};
// Schema 5 invalidated prerelease records built with the superseded claim
// activation boundary. Schema 6 is reserved for the additive proof-mode
// accounting update. Schema 7 persists ordered shadow-spend anchors for bounded
// event construction. The index is auxiliary and fully reconstructible, so a
// recognized older schema is wiped and rebuilt instead of being interpreted.
static constexpr uint32_t SHADOW_INDEX_SCHEMA_VERSION{7};
static constexpr size_t MAX_SCRIPT_QUERY_RESULTS{1000};
static constexpr size_t DIRECT_QUANTUM_SCRIPT_SIZE{2 + QUANTUM_MIGRATION_PROGRAM_SIZE};

bool IsBoundedShadowEventScript(const CScript& script)
{
    return script.size() == DIRECT_QUANTUM_SCRIPT_SIZE &&
        IsQuantumMigrationScript(script);
}

uint256 ShadowScriptHash(const CScript& script)
{
    CHashWriter hasher;
    hasher << std::string{"Blackcoin shadow index script v1"} << script;
    return hasher.GetHash();
}

struct DBBlockKey {
    uint256 hash;

    SERIALIZE_METHODS(DBBlockKey, obj)
    {
        uint8_t prefix{DB_BLOCK};
        READWRITE(prefix);
        if (prefix != DB_BLOCK) throw std::ios_base::failure("Invalid shadow block index key");
        READWRITE(obj.hash);
    }
};

struct DBTransactionKey {
    uint256 txid;

    SERIALIZE_METHODS(DBTransactionKey, obj)
    {
        uint8_t prefix{DB_TRANSACTION};
        READWRITE(prefix);
        if (prefix != DB_TRANSACTION) throw std::ios_base::failure("Invalid shadow transaction index key");
        READWRITE(obj.txid);
    }
};

struct DBSpentOutpointKey {
    COutPoint outpoint;

    SERIALIZE_METHODS(DBSpentOutpointKey, obj)
    {
        uint8_t prefix{DB_SPENT_OUTPOINT};
        READWRITE(prefix);
        if (prefix != DB_SPENT_OUTPOINT) throw std::ios_base::failure("Invalid shadow spent-outpoint index key");
        READWRITE(obj.outpoint);
    }
};

struct DBScriptKey {
    uint256 script_hash;
    uint32_t height{0};
    uint256 txid;

    template <typename Stream>
    void Serialize(Stream& stream) const
    {
        ser_writedata8(stream, DB_SCRIPT);
        stream << script_hash;
        ser_writedata32be(stream, height);
        stream << txid;
    }

    template <typename Stream>
    void Unserialize(Stream& stream)
    {
        if (ser_readdata8(stream) != DB_SCRIPT) throw std::ios_base::failure("Invalid shadow script index key");
        stream >> script_hash;
        height = ser_readdata32be(stream);
        stream >> txid;
    }

    bool operator==(const DBScriptKey& other) const
    {
        return script_hash == other.script_hash && height == other.height && txid == other.txid;
    }
};

struct DBUndoKey {
    uint256 hash;

    SERIALIZE_METHODS(DBUndoKey, obj)
    {
        uint8_t prefix{DB_UNDO};
        READWRITE(prefix);
        if (prefix != DB_UNDO) throw std::ios_base::failure("Invalid shadow undo index key");
        READWRITE(obj.hash);
    }
};

struct DBAttestationKey {
    uint256 pubkey_hash;

    SERIALIZE_METHODS(DBAttestationKey, obj)
    {
        uint8_t prefix{DB_ATTESTATION};
        READWRITE(prefix);
        if (prefix != DB_ATTESTATION) throw std::ios_base::failure("Invalid shadow attestation index key");
        READWRITE(obj.pubkey_hash);
    }
};

struct DBQuantumWitnessOutputKey {
    COutPoint outpoint;

    SERIALIZE_METHODS(DBQuantumWitnessOutputKey, obj)
    {
        uint8_t prefix{DB_QUANTUM_WITNESS_OUTPUT};
        READWRITE(prefix);
        if (prefix != DB_QUANTUM_WITNESS_OUTPUT) throw std::ios_base::failure("Invalid quantum witness output index key");
        READWRITE(obj.outpoint);
    }
};

struct DBQuantumWitnessBlockKey {
    uint256 block_hash;

    SERIALIZE_METHODS(DBQuantumWitnessBlockKey, obj)
    {
        uint8_t prefix{DB_QUANTUM_WITNESS_BLOCK};
        READWRITE(prefix);
        if (prefix != DB_QUANTUM_WITNESS_BLOCK) throw std::ios_base::failure("Invalid quantum witness block index key");
        READWRITE(obj.block_hash);
    }
};

struct DBPowClaimKey {
    uint256 block_hash;
    uint32_t index{0};

    SERIALIZE_METHODS(DBPowClaimKey, obj)
    {
        uint8_t prefix{DB_POW_CLAIM};
        READWRITE(prefix);
        if (prefix != DB_POW_CLAIM) throw std::ios_base::failure("Invalid shadow POW claim index key");
        READWRITE(obj.block_hash, obj.index);
    }
};

struct ShadowIndexAttestationState {
    int32_t height{-1};
    uint32_t time{0};
    uint32_t coverage_start_height{0};
    uint256 source_block_hash;
    uint256 source_txid;
    uint32_t source_output_index{0};

    SERIALIZE_METHODS(ShadowIndexAttestationState, obj)
    {
        READWRITE(obj.height);
        READWRITE(obj.time);
        READWRITE(obj.coverage_start_height);
        READWRITE(obj.source_block_hash);
        READWRITE(obj.source_txid);
        READWRITE(obj.source_output_index);
    }
};

struct ShadowIndexAttestationUndo {
    uint256 pubkey_hash;
    bool previous_present{false};
    ShadowIndexAttestationState previous;

    SERIALIZE_METHODS(ShadowIndexAttestationUndo, obj)
    {
        READWRITE(obj.pubkey_hash);
        READWRITE(obj.previous_present);
        READWRITE(obj.previous);
    }
};

struct ShadowIndexBlockUndo {
    int32_t height{-1};
    uint256 block_hash;
    std::vector<uint256> created_txids;
    std::vector<ShadowIndexRecord> spent_previous;
    std::vector<ShadowIndexAttestationUndo> attestation_previous;

    SERIALIZE_METHODS(ShadowIndexBlockUndo, obj)
    {
        READWRITE(obj.height);
        READWRITE(obj.block_hash);
        READWRITE(obj.created_txids);
        READWRITE(obj.spent_previous);
        READWRITE(obj.attestation_previous);
    }
};

struct QuantumWitnessBlockUndo {
    int32_t height{-1};
    uint256 block_hash;
    std::vector<COutPoint> created_outpoints;
    std::vector<QuantumWitnessIndexRecord> spent_previous;

    SERIALIZE_METHODS(QuantumWitnessBlockUndo, obj)
    {
        READWRITE(obj.height);
        READWRITE(obj.block_hash);
        READWRITE(obj.created_outpoints);
        READWRITE(obj.spent_previous);
    }
};

struct ShadowIndexTip {
    uint256 hash;
    int32_t height{-1};

    SERIALIZE_METHODS(ShadowIndexTip, obj)
    {
        READWRITE(obj.hash);
        READWRITE(obj.height);
    }
};

bool AddMoney(CAmount& total, CAmount amount)
{
    if (amount < 0 || !MoneyRange(amount) || total < 0 || total > MAX_MONEY - amount) return false;
    total += amount;
    return true;
}

bool Increment(uint64_t& value)
{
    if (value == std::numeric_limits<uint64_t>::max()) return false;
    ++value;
    return true;
}

bool Increment(uint32_t& value)
{
    if (value == std::numeric_limits<uint32_t>::max()) return false;
    ++value;
    return true;
}

bool IsCreditedPowDisposition(ShadowPowClaimDisposition disposition)
{
    return disposition == ShadowPowClaimDisposition::WINNER ||
           disposition == ShadowPowClaimDisposition::REIMBURSED_LOSER;
}

bool IsValidShadowPowClaimSource(const ShadowIndexPowClaimSource& source)
{
    return !source.txid.IsNull() && !source.canonical_rank.IsNull() &&
        (source.base_fee_known
             ? source.base_fee >= 0 && MoneyRange(source.base_fee)
             : source.base_fee == 0);
}

bool ShadowPowClaimSourcesEqual(const ShadowIndexPowClaimSource& lhs,
                                const ShadowIndexPowClaimSource& rhs)
{
    return lhs.txid == rhs.txid && lhs.vout == rhs.vout &&
        lhs.canonical_rank == rhs.canonical_rank &&
        lhs.base_fee == rhs.base_fee &&
        lhs.base_fee_known == rhs.base_fee_known &&
        lhs.disposition == rhs.disposition;
}

bool IsValidShadowPowClaimRecord(const ShadowIndexPowClaimRecord& record)
{
    if (!IsValidShadowPowClaimSource(record.source) ||
        record.credited_amount < 0 || !MoneyRange(record.credited_amount)) {
        return false;
    }
    const bool credited_disposition =
        IsCreditedPowDisposition(record.source.disposition);
    if ((credited_disposition &&
         (!record.source.base_fee_known ||
          !IsBoundedShadowEventScript(record.payout_script))) ||
        (!credited_disposition && record.credited_amount != 0) ||
        record.synthetic_payout_present != (record.credited_amount > 0)) {
        return false;
    }
    if (!record.synthetic_payout_present) {
        return record.synthetic_payout_outpoint.IsNull();
    }
    return record.synthetic_payout_outpoint.n == 0 &&
        !record.synthetic_payout_outpoint.hash.IsNull() &&
        IsBoundedShadowEventScript(record.payout_script);
}

bool IsValidShadowIndexBlockRecord(const ShadowIndexBlockRecord& record)
{
    if (record.height < SHADOW_REWARD_START_HEIGHT || record.block_hash.IsNull() ||
        record.block_time == 0 || record.median_time_past < 0 ||
        record.median_time_past > record.block_time ||
        record.supply.spent_count > record.supply.issued_count ||
        record.supply.issued_count < record.payout_txids.size() ||
        record.supply.spent_count < record.spent_outpoints.size() ||
        record.supply.issued_nominal < 0 ||
        !MoneyRange(record.supply.issued_nominal) ||
        record.supply.spent_nominal < 0 ||
        !MoneyRange(record.supply.spent_nominal) ||
        record.supply.spent_effective < 0 ||
        !MoneyRange(record.supply.spent_effective) ||
        record.supply.spent_decayed < 0 ||
        !MoneyRange(record.supply.spent_decayed) ||
        record.supply.spent_nominal > record.supply.issued_nominal ||
        record.supply.spent_effective + record.supply.spent_decayed !=
            record.supply.spent_nominal) {
        return false;
    }

    const ShadowIndexPowClaimSummary& summary = record.pow_claims;
    if (summary.winner_count > 1 ||
        static_cast<uint64_t>(summary.winner_count) +
                summary.reimbursed_loser_count + summary.rejected_count !=
            summary.record_count ||
        summary.credited_total < 0 || !MoneyRange(summary.credited_total) ||
        summary.winner_credited_total < 0 ||
        !MoneyRange(summary.winner_credited_total) ||
        summary.reimbursed_credited_total < 0 ||
        !MoneyRange(summary.reimbursed_credited_total) ||
        summary.winner_credited_total + summary.reimbursed_credited_total !=
            summary.credited_total) {
        return false;
    }
    const bool accounting_expected = record.height <= SHADOW_REWARD_END_HEIGHT &&
        Params().GetConsensus().IsShadowCompetingClaimsActive(record.height);
    if (summary.active != accounting_expected ||
        (!summary.active &&
         (summary.record_count != 0 || summary.credited_total != 0))) {
        return false;
    }

    std::set<uint256> payout_txids;
    for (const uint256& txid : record.payout_txids) {
        if (txid.IsNull() || !payout_txids.insert(txid).second) return false;
    }
    std::set<COutPoint> spent_outpoints;
    for (const COutPoint& outpoint : record.spent_outpoints) {
        if (outpoint.n != 0 || outpoint.hash.IsNull() ||
            !spent_outpoints.insert(outpoint).second) {
            return false;
        }
    }
    return true;
}

} // namespace

std::unique_ptr<ShadowIndex> g_shadow_index;

bool IsValidShadowIndexRecord(const ShadowIndexRecord& record)
{
    if (record.outpoint.hash.IsNull() || record.outpoint.n != 0 ||
        record.origin_height < static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) ||
        record.origin_height > static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) ||
        record.origin_block_hash.IsNull() || record.origin_block_time == 0 ||
        record.nominal_amount <= 0 ||
        !MoneyRange(record.nominal_amount) ||
        !IsBoundedShadowEventScript(record.script_pub_key)) {
        return false;
    }
    const bool source_required = record.proof_of_work &&
        Params().GetConsensus().IsShadowCompetingClaimsActive(
            static_cast<int>(record.origin_height));
    if ((!record.proof_of_work && record.pow_claim_source_present) ||
        record.pow_claim_source_present != source_required) {
        return false;
    }
    if (record.pow_claim_source_present) {
        if (!IsValidShadowPowClaimSource(record.pow_claim_source) ||
            !record.pow_claim_source.base_fee_known ||
            !IsCreditedPowDisposition(record.pow_claim_source.disposition)) {
            return false;
        }
    }
    if (!record.spent) {
        return record.spend_height == 0 && record.spend_block_hash.IsNull() &&
            record.spending_txid.IsNull() && record.spend_tx_index == 0 &&
            record.spend_input_index == 0 && record.effective_amount_at_spend == 0 &&
            record.decayed_amount_at_spend == 0;
    }
    return record.spend_height > record.origin_height &&
        !record.spend_block_hash.IsNull() && !record.spending_txid.IsNull() &&
        record.effective_amount_at_spend >= 0 &&
        MoneyRange(record.effective_amount_at_spend) &&
        record.decayed_amount_at_spend >= 0 &&
        MoneyRange(record.decayed_amount_at_spend) &&
        record.effective_amount_at_spend <=
            record.nominal_amount - record.decayed_amount_at_spend &&
        record.effective_amount_at_spend + record.decayed_amount_at_spend ==
            record.nominal_amount;
}

class ShadowIndex::DB final : public BaseIndex::DB
{
public:
    explicit DB(size_t cache_size, bool memory, bool wipe)
        : BaseIndex::DB(gArgs.GetDataDirNet() / "indexes" / "shadow", cache_size, memory, wipe)
    {}

    bool ReadBlock(const uint256& hash, ShadowIndexBlockRecord& record) const
    {
        return Read(DBBlockKey{hash}, record);
    }

    bool ReadTransaction(const uint256& txid, ShadowIndexRecord& record) const
    {
        return Read(DBTransactionKey{txid}, record);
    }

    bool ReadAttestation(const uint256& pubkey_hash, ShadowIndexAttestationState& state) const
    {
        return Read(DBAttestationKey{pubkey_hash}, state);
    }
};

ShadowIndex::ShadowIndex(std::unique_ptr<interfaces::Chain> chain, size_t cache_size,
                         bool memory, bool wipe,
                         ShadowIndexEventCallback event_callback)
    : BaseIndex(std::move(chain), "shadowindex"),
      m_db(std::make_unique<ShadowIndex::DB>(cache_size, memory, wipe)),
      m_event_callback(std::move(event_callback))
{
    uint32_t stored_version{0};
    const bool has_version = m_db->Read(DB_SCHEMA_VERSION, stored_version);
    if (!has_version && m_db->Exists(DB_SCHEMA_VERSION)) {
        throw std::runtime_error("Unable to read shadowindex schema version");
    }
    if (has_version && stored_version > SHADOW_INDEX_SCHEMA_VERSION) {
        throw std::runtime_error(strprintf(
            "Unsupported newer shadowindex schema %u (maximum supported %u)",
            stored_version, SHADOW_INDEX_SCHEMA_VERSION));
    }
    const bool mock_obsolete_schema = has_version &&
        Params().GetChainType() == ChainType::REGTEST &&
        gArgs.GetBoolArg("-shadowindexmockobsoleteschema", false);
    const uint32_t compatibility_version = mock_obsolete_schema
        ? SHADOW_INDEX_SCHEMA_VERSION - 1 : stored_version;
    const bool populated_unversioned_index = !has_version && !m_db->IsEmpty();
    const bool obsolete_version = has_version &&
        compatibility_version < SHADOW_INDEX_SCHEMA_VERSION;
    if (!wipe && (populated_unversioned_index || obsolete_version)) {
        LogPrintf("ShadowIndex: rebuilding incompatible schema %s as version %u\n",
                  populated_unversioned_index ? "without a version" : strprintf("version %u", compatibility_version),
                  SHADOW_INDEX_SCHEMA_VERSION);
        m_db.reset();
        m_db = std::make_unique<ShadowIndex::DB>(cache_size, memory, /*wipe=*/true);
    }
    if (!m_db->Write(DB_SCHEMA_VERSION, SHADOW_INDEX_SCHEMA_VERSION)) {
        throw std::runtime_error("Unable to write shadowindex schema version");
    }
}

ShadowIndex::~ShadowIndex() = default;

bool ShadowIndex::BuildBlockEvent(const CBlock& block, const CBlockIndex* pindex,
                                  ShadowIndexBlockEvent& event) const
{
    if (!pindex || pindex->nHeight < SHADOW_REWARD_START_HEIGHT ||
        pindex->GetBlockHash() != block.GetHash()) {
        return false;
    }

    ShadowIndexBlockRecord indexed;
    if (!m_db->ReadBlock(pindex->GetBlockHash(), indexed) ||
        indexed.height != pindex->nHeight ||
        indexed.block_hash != pindex->GetBlockHash() ||
        indexed.block_time != static_cast<uint32_t>(block.GetBlockTime())) {
        return false;
    }

    ShadowIndexBlockEvent result;
    result.height = pindex->nHeight;
    result.block_hash = pindex->GetBlockHash();
    result.previous_block_hash = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256{};
    result.block_time = indexed.block_time;
    if (indexed.payout_txids.size() > MAX_SHADOW_EVENT_RECORDS ||
        indexed.spent_outpoints.size() >
            MAX_SHADOW_EVENT_RECORDS - indexed.payout_txids.size()) {
        return false;
    }
    result.credits.reserve(indexed.payout_txids.size());
    for (size_t claim_index = 0; claim_index < indexed.payout_txids.size(); ++claim_index) {
        ShadowIndexRecord record;
        const uint256& txid = indexed.payout_txids[claim_index];
        if (!m_db->ReadTransaction(txid, record) ||
            record.outpoint.hash != txid ||
            record.origin_height != static_cast<uint32_t>(pindex->nHeight) ||
            record.origin_block_hash != pindex->GetBlockHash() ||
            record.claim_index != claim_index ||
            !IsValidShadowIndexRecord(record)) {
            return false;
        }
        result.credits.push_back(std::move(record));
    }

    result.spends.reserve(indexed.spent_outpoints.size());
    for (const COutPoint& prevout : indexed.spent_outpoints) {
        ShadowIndexRecord record;
        if (!m_db->Read(DBSpentOutpointKey{prevout}, record)) return false;
        if (record.spend_tx_index >= block.vtx.size()) return false;
        const CTransaction& spending_tx = *block.vtx[record.spend_tx_index];
        if (record.spend_input_index >= spending_tx.vin.size() ||
            spending_tx.vin[record.spend_input_index].prevout != prevout ||
            !record.spent || record.outpoint != prevout ||
            record.spend_height != static_cast<uint32_t>(pindex->nHeight) ||
            record.spend_block_hash != pindex->GetBlockHash() ||
            record.spending_txid != spending_tx.GetHash() ||
            !IsValidShadowIndexRecord(record)) {
            return false;
        }
        result.spends.push_back(std::move(record));
    }

    event = std::move(result);
    return true;
}

bool ShadowIndex::IndexMatchesActiveTip(const IndexSummary& summary) const
{
    LOCK(cs_main);
    const CBlockIndex* active_tip = m_chainstate ? m_chainstate->m_chain.Tip() : nullptr;
    return active_tip && summary.synced &&
        summary.best_block_height == active_tip->nHeight &&
        summary.best_block_hash == active_tip->GetBlockHash();
}

void ShadowIndex::BlockConnected(ChainstateRole role,
                                 const std::shared_ptr<const CBlock>& block,
                                 const CBlockIndex* pindex)
{
    const IndexSummary before = GetSummary();
    const bool direct_transition = role == ChainstateRole::NORMAL && pindex && pindex->pprev &&
        before.synced && before.best_block_height == pindex->pprev->nHeight &&
        before.best_block_hash == pindex->pprev->GetBlockHash();
    if (m_event_callback && role == ChainstateRole::NORMAL && pindex && !direct_transition) {
        if (!m_event_stream_suppressed) {
            LogPrintf("ShadowIndex: suppressing shadow events while reconciling a non-sequential connect at %s\n",
                      pindex->GetBlockHash().ToString());
        }
        m_event_stream_suppressed = true;
    }

    BaseIndex::BlockConnected(role, block, pindex);
    if (role != ChainstateRole::NORMAL || !pindex) {
        return;
    }

    const IndexSummary summary = GetSummary();
    if (!summary.synced || summary.best_block_height != pindex->nHeight ||
        summary.best_block_hash != pindex->GetBlockHash()) {
        return;
    }
    m_revision.fetch_add(1, std::memory_order_release);
    if (m_event_stream_suppressed) {
        if (IndexMatchesActiveTip(summary)) {
            m_event_stream_suppressed = false;
            LogPrintf("ShadowIndex: shadow event stream reconciled at %s; future live deltas will be published\n",
                      pindex->GetBlockHash().ToString());
        }
        return;
    }
    if (!m_event_callback || pindex->nHeight < SHADOW_REWARD_START_HEIGHT) return;

    ShadowIndexBlockEvent event;
    if (!BuildBlockEvent(*block, pindex, event)) {
        LogPrintf("ShadowIndex: unable to construct connected event for %s; subscribers must reconcile by RPC\n",
                  pindex->GetBlockHash().ToString());
        return;
    }
    m_event_callback(/*connected=*/true, event);
}

void ShadowIndex::BlockDisconnected(const std::shared_ptr<const CBlock>& block,
                                    const CBlockIndex* pindex)
{
    std::optional<ShadowIndexBlockEvent> event;
    const IndexSummary before = GetSummary();
    const bool direct_transition = pindex && before.synced &&
        before.best_block_height == pindex->nHeight &&
        before.best_block_hash == pindex->GetBlockHash();
    if (m_event_callback && pindex && !direct_transition) {
        if (!m_event_stream_suppressed) {
            LogPrintf("ShadowIndex: suppressing shadow events while reconciling a non-sequential disconnect at %s\n",
                      pindex->GetBlockHash().ToString());
        }
        m_event_stream_suppressed = true;
    }
    if (m_event_callback && !m_event_stream_suppressed && direct_transition &&
        pindex->nHeight >= SHADOW_REWARD_START_HEIGHT) {
        ShadowIndexBlockEvent candidate;
        if (BuildBlockEvent(*block, pindex, candidate)) {
            event = std::move(candidate);
        } else {
            LogPrintf("ShadowIndex: unable to construct disconnected event for %s; subscribers must reconcile by RPC\n",
                      pindex->GetBlockHash().ToString());
        }
    }

    BaseIndex::BlockDisconnected(block, pindex);
    if (!pindex || !pindex->pprev) return;

    const IndexSummary after = GetSummary();
    if (after.synced && after.best_block_height == pindex->pprev->nHeight &&
        after.best_block_hash == pindex->pprev->GetBlockHash()) {
        m_revision.fetch_add(1, std::memory_order_release);
        if (m_event_stream_suppressed) {
            if (IndexMatchesActiveTip(after)) {
                m_event_stream_suppressed = false;
                LogPrintf("ShadowIndex: shadow event stream reconciled at %s; future live deltas will be published\n",
                          pindex->pprev->GetBlockHash().ToString());
            }
            return;
        }
        if (event) m_event_callback(/*connected=*/false, *event);
    }
}

BaseIndex::DB& ShadowIndex::GetDB() const
{
    return *m_db;
}

bool ShadowIndex::CustomInit(const std::optional<interfaces::BlockKey>& block)
{
    ShadowIndexTip custom_tip;
    if (!m_db->Read(DB_CUSTOM_TIP, custom_tip)) {
        if (m_db->Exists(DB_CUSTOM_TIP)) {
            return error("%s: unreadable shadowindex custom tip", __func__);
        }
        if (block && block->height >= SHADOW_REWARD_START_HEIGHT) {
            return error(
                "%s: shadowindex custom tip is missing at persisted locator %s; use -reindex",
                __func__, block->hash.ToString());
        }
        return true;
    }
    if (custom_tip.height < SHADOW_REWARD_START_HEIGHT || custom_tip.hash.IsNull()) {
        return error("%s: invalid shadowindex custom tip", __func__);
    }

    // BaseIndex persists its locator separately from CustomAppend. An unclean
    // shutdown may therefore leave the custom database ahead of that locator.
    // Always unwind mutable custom state to the persisted boundary before
    // BaseIndex resumes. This also covers a reorg that occurred while the node
    // was down and keeps the custom tip equal to BaseIndex's source for every
    // later CustomRewind call.
    const CBlockIndex* indexed_tip = m_chainstate->m_blockman.LookupBlockIndex(custom_tip.hash);
    if (!indexed_tip || indexed_tip->nHeight != custom_tip.height) {
        return error("%s: shadowindex custom tip is absent from the block index; use -reindex", __func__);
    }
    const CBlockIndex* locator{nullptr};
    if (block) {
        locator = m_chainstate->m_blockman.LookupBlockIndex(block->hash);
        if (!locator || locator->nHeight != block->height ||
            locator->nHeight > indexed_tip->nHeight ||
            indexed_tip->GetAncestor(locator->nHeight) != locator) {
            return error("%s: shadowindex custom tip does not descend from its persisted locator; use -reindex", __func__);
        }
    }

    // Mutable shadow accounting begins at the reward start. Historical witness
    // records below it are branch-filtered and idempotent, so no pre-reward
    // rewind is needed when BaseIndex has not yet persisted that far.
    const int rewind_height = locator && locator->nHeight >= SHADOW_REWARD_START_HEIGHT
        ? locator->nHeight
        : SHADOW_REWARD_START_HEIGHT - 1;
    const CBlockIndex* target = indexed_tip->GetAncestor(rewind_height);
    if (!target) {
        return error("%s: shadowindex custom tip has no pre-reward ancestor; use -reindex", __func__);
    }

    std::vector<interfaces::BlockKey> disconnected;
    for (const CBlockIndex* cursor = indexed_tip; cursor != target; cursor = cursor->pprev) {
        if (!cursor) return error("%s: corrupt shadowindex custom-tip ancestry", __func__);
        disconnected.push_back({cursor->GetBlockHash(), cursor->nHeight});
    }

    // CustomInit is called by BaseIndex with cs_main held, so perform the same
    // per-block undo as CustomRewind without recursively acquiring that lock.
    // The custom-tip update shares each undo batch, making restart during this
    // recovery idempotent as well.
    for (size_t i = 0; i < disconnected.size(); ++i) {
        const interfaces::BlockKey& disconnected_block = disconnected[i];
        const interfaces::BlockKey parent = i + 1 < disconnected.size()
            ? disconnected[i + 1]
            : interfaces::BlockKey{target->GetBlockHash(), target->nHeight};
        CDBBatch batch(*m_db);

        QuantumWitnessBlockUndo witness_undo;
        if (m_db->Read(DBQuantumWitnessBlockKey{disconnected_block.hash}, witness_undo)) {
            if (witness_undo.height != disconnected_block.height ||
                witness_undo.block_hash != disconnected_block.hash) {
                return error("%s: corrupt quantum witness undo for %s", __func__, disconnected_block.hash.ToString());
            }
            for (const QuantumWitnessIndexRecord& previous : witness_undo.spent_previous) {
                if (previous.spent) return error("%s: invalid quantum witness spend undo", __func__);
                batch.Write(DBQuantumWitnessOutputKey{previous.outpoint}, previous);
            }
            for (const COutPoint& created : witness_undo.created_outpoints) {
                QuantumWitnessIndexRecord record;
                if (!m_db->Read(DBQuantumWitnessOutputKey{created}, record) ||
                    record.origin_block_hash != disconnected_block.hash) {
                    return error("%s: missing created quantum witness output %s", __func__, created.ToString());
                }
                batch.Erase(DBQuantumWitnessOutputKey{created});
            }
            batch.Erase(DBQuantumWitnessBlockKey{disconnected_block.hash});
        } else if (m_db->Exists(DBQuantumWitnessBlockKey{disconnected_block.hash})) {
            return error("%s: unreadable quantum witness undo for %s", __func__, disconnected_block.hash.ToString());
        }

        ShadowIndexBlockRecord block_record;
        ShadowIndexBlockUndo undo;
        if (!m_db->ReadBlock(disconnected_block.hash, block_record) ||
            !m_db->Read(DBUndoKey{disconnected_block.hash}, undo) ||
            block_record.block_hash != disconnected_block.hash ||
            undo.block_hash != disconnected_block.hash ||
            block_record.height != undo.height) {
            return error("%s: missing or corrupt shadowindex undo for %s", __func__, disconnected_block.hash.ToString());
        }
        for (const ShadowIndexRecord& previous : undo.spent_previous) {
            if (previous.spent) return error("%s: invalid spent undo record", __func__);
            batch.Write(DBTransactionKey{previous.outpoint.hash}, previous);
            batch.Erase(DBSpentOutpointKey{previous.outpoint});
        }
        for (const uint256& created_txid : undo.created_txids) {
            ShadowIndexRecord record;
            if (!m_db->ReadTransaction(created_txid, record) ||
                record.origin_block_hash != disconnected_block.hash) {
                return error("%s: missing created shadow record %s", __func__, created_txid.ToString());
            }
            batch.Erase(DBTransactionKey{created_txid});
            batch.Erase(DBSpentOutpointKey{record.outpoint});
            batch.Erase(DBScriptKey{ShadowScriptHash(record.script_pub_key), record.origin_height, created_txid});
        }
        for (const ShadowIndexAttestationUndo& previous : undo.attestation_previous) {
            if (previous.previous_present) {
                batch.Write(DBAttestationKey{previous.pubkey_hash}, previous.previous);
            } else {
                batch.Erase(DBAttestationKey{previous.pubkey_hash});
            }
        }
        for (uint32_t claim_index = 0; claim_index < block_record.pow_claims.record_count;
             ++claim_index) {
            batch.Erase(DBPowClaimKey{disconnected_block.hash, claim_index});
        }
        batch.Erase(DBBlockKey{disconnected_block.hash});
        batch.Erase(DBUndoKey{disconnected_block.hash});
        if (parent.height >= SHADOW_REWARD_START_HEIGHT) {
            batch.Write(DB_CUSTOM_TIP, ShadowIndexTip{parent.hash, parent.height});
        } else {
            batch.Erase(DB_CUSTOM_TIP);
        }
        if (!m_db->WriteBatch(batch)) return false;
    }
    return true;
}

bool ShadowIndex::CustomAppend(const interfaces::BlockInfo& block)
{
    if (!block.data || (block.height > 0 && !block.prev_hash)) {
        return error("%s: missing block data at height %d", __func__, block.height);
    }

    ShadowIndexBlockRecord existing;
    if (block.height >= SHADOW_REWARD_START_HEIGHT && m_db->ReadBlock(block.hash, existing)) {
        return existing.height == block.height && existing.block_hash == block.hash;
    }
    if (block.height >= SHADOW_REWARD_START_HEIGHT && m_db->Exists(DBBlockKey{block.hash})) {
        return error("%s: unreadable shadow block record for %s", __func__, block.hash.ToString());
    }

    QuantumWitnessBlockUndo existing_witness_undo;
    const bool witness_block_already_indexed = m_db->Read(
        DBQuantumWitnessBlockKey{block.hash}, existing_witness_undo);
    if (!witness_block_already_indexed && m_db->Exists(DBQuantumWitnessBlockKey{block.hash})) {
        return error("%s: unreadable quantum witness block record for %s", __func__, block.hash.ToString());
    }

    const CBlockIndex* pindex{nullptr};
    int64_t block_mtp{0};
    std::vector<ShadowSyntheticPayoutTransaction> payouts;
    ShadowPowAccountingContext pow_accounting_context;
    {
        LOCK(cs_main);
        pindex = m_chainstate->m_blockman.LookupBlockIndex(block.hash);
        if (!pindex || pindex->nHeight != block.height ||
            pindex->GetBlockHash() != block.hash) {
            return error("%s: block index mismatch for %s", __func__, block.hash.ToString());
        }
        block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
        if (block.height >= SHADOW_REWARD_START_HEIGHT) {
            payouts = GetAppliedShadowClaimPayoutTransactionRecords(
                m_chainstate->CoinsTip(), block.height, block.hash, block.data->GetBlockTime());
            if (PrepareShadowPowClaimAccounting(m_chainstate->CoinsTip(), pindex,
                                                pow_accounting_context) !=
                ShadowPowAccountingResult::OK) {
                return error("%s: unable to authenticate POW claim context for %s",
                             __func__, block.hash.ToString());
            }
        }
    }

    // Preparing the immutable context above performs no Argon2 work. Read undo
    // and run the shared bounded accounting engine only after releasing
    // cs_main, so explorer indexing cannot hold the validation lock while
    // evaluating memory-hard proofs.
    std::vector<ShadowPowClaimAccounting> pow_accounting;
    const bool has_pow_notes = std::any_of(
        block.data->vtx.begin(), block.data->vtx.end(),
        [](const CTransactionRef& tx) { return TransactionHasShadowProof(*tx); });
    if (pow_accounting_context.valid && pow_accounting_context.canonical_rule_active &&
        has_pow_notes) {
        CBlockUndo block_undo;
        if (block.height <= 0 ||
            !m_chainstate->m_blockman.UndoReadFromDisk(block_undo, *pindex)) {
            return error("%s: unable to read undo for POW claim accounting at %s",
                         __func__, block.hash.ToString());
        }
        if (EvaluateShadowPowClaimAccounting(pow_accounting_context, *block.data,
                                             &block_undo, pow_accounting) !=
            ShadowPowAccountingResult::OK) {
            return error("%s: POW claim accounting failed locally for %s",
                         __func__, block.hash.ToString());
        }
    }

    ShadowIndexBlockRecord block_record;
    if (block.height >= SHADOW_REWARD_START_HEIGHT) {
        block_record.height = block.height;
        block_record.block_hash = block.hash;
        block_record.block_time = block.data->GetBlockTime();
        block_record.median_time_past = block_mtp;
        block_record.pow_claims.active =
            pow_accounting_context.valid && pow_accounting_context.canonical_rule_active;
    }
    if (block.height > SHADOW_REWARD_START_HEIGHT) {
        ShadowIndexBlockRecord previous;
        if (!m_db->ReadBlock(*block.prev_hash, previous) ||
            previous.height != block.height - 1 || previous.block_hash != *block.prev_hash) {
            return error("%s: previous shadow block record is missing at height %d", __func__, block.height - 1);
        }
        block_record.supply = previous.supply;
    }

    ShadowIndexBlockUndo undo;
    undo.height = block.height;
    undo.block_hash = block.hash;

    CDBBatch batch(*m_db);
    bool witness_writes{false};
    if (witness_block_already_indexed) {
        if (existing_witness_undo.height != block.height ||
            existing_witness_undo.block_hash != block.hash) {
            return error("%s: quantum witness block record mismatch for %s", __func__, block.hash.ToString());
        }
    } else {
        QuantumWitnessBlockUndo witness_undo;
        witness_undo.height = block.height;
        witness_undo.block_hash = block.hash;
        std::map<COutPoint, QuantumWitnessIndexRecord> changed_witness;
        std::set<COutPoint> created_witness;
        const CBlockIndex* parent = pindex->pprev;
        const auto active_on_parent = [&](uint32_t height, const uint256& hash) {
            const CBlockIndex* ancestor = parent && height <= static_cast<uint32_t>(parent->nHeight)
                ? parent->GetAncestor(static_cast<int>(height))
                : nullptr;
            return ancestor && ancestor->GetBlockHash() == hash;
        };
        const auto clear_spend = [](QuantumWitnessIndexRecord& record) {
            record.spent = false;
            record.spend_height = 0;
            record.spend_block_hash.SetNull();
            record.spending_txid.SetNull();
            record.spend_tx_index = 0;
            record.spend_input_index = 0;
        };

        for (uint32_t tx_index = 0; tx_index < block.data->vtx.size(); ++tx_index) {
            const CTransaction& tx = *block.data->vtx[tx_index];
            for (uint32_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
                const COutPoint& prevout = tx.vin[input_index].prevout;
                QuantumWitnessIndexRecord record;
                const auto changed = changed_witness.find(prevout);
                const bool found = changed != changed_witness.end()
                    ? (record = changed->second, true)
                    : m_db->Read(DBQuantumWitnessOutputKey{prevout}, record);
                if (!found) {
                    if (m_db->Exists(DBQuantumWitnessOutputKey{prevout})) {
                        return error("%s: unreadable quantum witness output %s", __func__, prevout.ToString());
                    }
                    continue;
                }
                const bool created_this_block = created_witness.count(prevout) != 0;
                if (!created_this_block && !active_on_parent(record.origin_height, record.origin_block_hash)) {
                    // A direct database write can be ahead of BaseIndex's
                    // committed locator after an unclean shutdown. Ignore an
                    // orphan-branch creation; active-history RPCs also bind
                    // every record to the current tip.
                    continue;
                }
                if (record.spent) {
                    const bool active_spend = !created_this_block &&
                        active_on_parent(record.spend_height, record.spend_block_hash);
                    if (active_spend || created_this_block) {
                        return error("%s: quantum witness output %s is already spent", __func__, prevout.ToString());
                    }
                    clear_spend(record);
                }
                if (!created_this_block) witness_undo.spent_previous.push_back(record);
                record.spent = true;
                record.spend_height = block.height;
                record.spend_block_hash = block.hash;
                record.spending_txid = tx.GetHash();
                record.spend_tx_index = tx_index;
                record.spend_input_index = input_index;
                changed_witness[prevout] = std::move(record);
            }

            const uint256 txid = tx.GetHash();
            for (uint32_t output_index = 0; output_index < tx.vout.size(); ++output_index) {
                const CTxOut& output = tx.vout[output_index];
                int witness_version{0};
                std::vector<unsigned char> witness_program;
                if (output.nValue <= 0 ||
                    !output.scriptPubKey.IsWitnessProgram(witness_version, witness_program) ||
                    witness_version <= 1) {
                    continue;
                }
                if (witness_version > 16 || !MoneyRange(output.nValue)) {
                    return error("%s: invalid value-bearing witness output", __func__);
                }
                const COutPoint outpoint{txid, output_index};
                QuantumWitnessIndexRecord duplicate;
                const bool has_duplicate = changed_witness.count(outpoint) ||
                    m_db->Read(DBQuantumWitnessOutputKey{outpoint}, duplicate);
                if (has_duplicate &&
                    (changed_witness.count(outpoint) ||
                     active_on_parent(duplicate.origin_height, duplicate.origin_block_hash))) {
                    return error("%s: duplicate quantum witness output %s", __func__, outpoint.ToString());
                }
                if (!has_duplicate && m_db->Exists(DBQuantumWitnessOutputKey{outpoint})) {
                    return error("%s: unreadable quantum witness output %s", __func__, outpoint.ToString());
                }

                QuantumWitnessIndexRecord record;
                record.outpoint = outpoint;
                record.origin_height = block.height;
                record.origin_block_hash = block.hash;
                record.origin_block_time = block.data->GetBlockTime();
                record.witness_version = static_cast<uint8_t>(witness_version);
                record.nominal_amount = output.nValue;
                record.script_pub_key = output.scriptPubKey;
                record.coinbase = tx.IsCoinBase();
                record.coinstake = tx.IsCoinStake();
                changed_witness[outpoint] = std::move(record);
                created_witness.insert(outpoint);
                witness_undo.created_outpoints.push_back(outpoint);
            }
        }

        for (const auto& [outpoint, record] : changed_witness) {
            batch.Write(DBQuantumWitnessOutputKey{outpoint}, record);
        }
        if (!witness_undo.created_outpoints.empty() || !witness_undo.spent_previous.empty()) {
            batch.Write(DBQuantumWitnessBlockKey{block.hash}, witness_undo);
            witness_writes = true;
        }
    }

    if (block.height < SHADOW_REWARD_START_HEIGHT) {
        return witness_writes ? m_db->WriteBatch(batch) : true;
    }

    std::map<uint256, ShadowIndexRecord> changed_records;

    // Synthetic payouts cannot be spent in their origin base block. Process
    // spends first so demurrage uses the attestation state at the parent tip,
    // matching transaction input validation.
    for (uint32_t tx_index = 0; tx_index < block.data->vtx.size(); ++tx_index) {
        const CTransaction& tx = *block.data->vtx[tx_index];
        for (uint32_t input_index = 0; input_index < tx.vin.size(); ++input_index) {
            const COutPoint& prevout = tx.vin[input_index].prevout;
            ShadowIndexRecord record;
            const auto changed = changed_records.find(prevout.hash);
            const bool found = changed != changed_records.end()
                ? (record = changed->second, true)
                : m_db->ReadTransaction(prevout.hash, record);
            if (!found || record.outpoint != prevout) continue;
            if (record.spent) {
                return error("%s: synthetic payout %s is already spent", __func__, prevout.ToString());
            }

            undo.spent_previous.push_back(record);
            Coin coin{CTxOut{record.nominal_amount, record.script_pub_key},
                      static_cast<int>(record.origin_height),
                      /*coinbase=*/true, /*coinstake=*/false,
                      static_cast<int>(record.origin_block_time)};
            std::optional<int> latest_height;
            std::optional<int> coverage_start;
            if (const std::optional<uint256> key =
                    Consensus::DemurrageControllingKeyHashForScript(record.script_pub_key)) {
                ShadowIndexAttestationState state;
                if (m_db->ReadAttestation(*key, state)) {
                    latest_height = state.height;
                    coverage_start = static_cast<int>(state.coverage_start_height);
                } else if (m_db->Exists(DBAttestationKey{*key})) {
                    return error("%s: unreadable demurrage state for %s", __func__, key->ToString());
                }
            }
            const Consensus::DemurrageEvaluation evaluation = Consensus::EvaluateDemurrage(
                coin, Params().GetConsensus(), block.height, block_mtp,
                latest_height, coverage_start);

            record.spent = true;
            record.spend_height = block.height;
            record.spend_block_hash = block.hash;
            record.spending_txid = tx.GetHash();
            record.spend_tx_index = tx_index;
            record.spend_input_index = input_index;
            record.effective_amount_at_spend = evaluation.effective_value;
            record.decayed_amount_at_spend = evaluation.burned_value;
            block_record.spent_outpoints.push_back(prevout);
            changed_records[prevout.hash] = record;
            batch.Write(DBTransactionKey{prevout.hash}, record);
            batch.Write(DBSpentOutpointKey{prevout}, record);

            if (!Increment(block_record.supply.spent_count) ||
                !AddMoney(block_record.supply.spent_nominal, record.nominal_amount) ||
                !AddMoney(block_record.supply.spent_effective, evaluation.effective_value) ||
                !AddMoney(block_record.supply.spent_decayed, evaluation.burned_value)) {
                return error("%s: shadow supply overflow while recording spend", __func__);
            }
        }
    }

    if (pow_accounting.size() > std::numeric_limits<uint32_t>::max()) {
        return error("%s: too many POW claim accounting records", __func__);
    }
    std::vector<const ShadowSyntheticPayoutTransaction*> pow_payouts;
    CAmount pow_payout_total{0};
    for (const ShadowSyntheticPayoutTransaction& payout : payouts) {
        if (!payout.proof_of_work) continue;
        if (!AddMoney(pow_payout_total, payout.amount)) {
            return error("%s: POW synthetic payout total overflow", __func__);
        }
        pow_payouts.push_back(&payout);
    }
    size_t next_pow_payout{0};
    std::map<uint256, ShadowIndexPowClaimSource> pow_payout_sources;
    for (uint32_t accounting_index = 0; accounting_index < pow_accounting.size();
         ++accounting_index) {
        const ShadowPowClaimAccounting& accounting = pow_accounting[accounting_index];
        if (accounting.credited_amount < 0 || !MoneyRange(accounting.credited_amount) ||
            (accounting.base_fee_known &&
             (accounting.base_fee < 0 || !MoneyRange(accounting.base_fee)))) {
            return error("%s: invalid POW claim accounting amount", __func__);
        }

        ShadowIndexPowClaimRecord claim_record;
        claim_record.source.txid = accounting.source_txid;
        claim_record.source.vout = accounting.source_vout;
        claim_record.source.canonical_rank = accounting.canonical_rank;
        claim_record.source.base_fee = accounting.base_fee;
        claim_record.source.base_fee_known = accounting.base_fee_known;
        claim_record.source.disposition = accounting.disposition;
        claim_record.payout_script = accounting.payout_script;
        claim_record.credited_amount = accounting.credited_amount;

        if (!Increment(block_record.pow_claims.record_count) ||
            !AddMoney(block_record.pow_claims.credited_total,
                      accounting.credited_amount)) {
            return error("%s: POW claim accounting aggregate overflow", __func__);
        }
        if (accounting.disposition == ShadowPowClaimDisposition::WINNER) {
            if (!Increment(block_record.pow_claims.winner_count) ||
                !AddMoney(block_record.pow_claims.winner_credited_total,
                          accounting.credited_amount)) {
                return error("%s: POW winner accounting overflow", __func__);
            }
        } else if (accounting.disposition ==
                   ShadowPowClaimDisposition::REIMBURSED_LOSER) {
            if (!Increment(block_record.pow_claims.reimbursed_loser_count) ||
                !AddMoney(block_record.pow_claims.reimbursed_credited_total,
                          accounting.credited_amount)) {
                return error("%s: POW loser accounting overflow", __func__);
            }
        } else if (!Increment(block_record.pow_claims.rejected_count)) {
            return error("%s: POW rejection accounting overflow", __func__);
        }

        if (IsCreditedPowDisposition(accounting.disposition) &&
            accounting.credited_amount > 0) {
            if (next_pow_payout >= pow_payouts.size()) {
                return error("%s: missing synthetic payout for credited POW claim", __func__);
            }
            const ShadowSyntheticPayoutTransaction& payout = *pow_payouts[next_pow_payout++];
            if (payout.target != accounting.payout_script ||
                payout.amount != accounting.credited_amount) {
                return error("%s: POW claim provenance does not match synthetic payout", __func__);
            }
            claim_record.synthetic_payout_present = true;
            claim_record.synthetic_payout_outpoint = COutPoint{payout.tx->GetHash(), 0};
            if (!pow_payout_sources.emplace(payout.tx->GetHash(), claim_record.source).second) {
                return error("%s: duplicate POW synthetic payout provenance", __func__);
            }
        }
        batch.Write(DBPowClaimKey{block.hash, accounting_index}, claim_record);
    }
    if (block_record.pow_claims.record_count != pow_accounting.size() ||
        block_record.pow_claims.winner_count > 1 ||
        block_record.pow_claims.winner_count +
                block_record.pow_claims.reimbursed_loser_count +
                block_record.pow_claims.rejected_count !=
            block_record.pow_claims.record_count ||
        block_record.pow_claims.winner_credited_total +
                block_record.pow_claims.reimbursed_credited_total !=
            block_record.pow_claims.credited_total ||
        (block_record.pow_claims.active &&
         (next_pow_payout != pow_payouts.size() ||
          block_record.pow_claims.credited_total != pow_payout_total)) ||
        (!block_record.pow_claims.active &&
         (next_pow_payout != 0 || block_record.pow_claims.record_count != 0 ||
          block_record.pow_claims.credited_total != 0))) {
        return error("%s: inconsistent POW claim accounting summary", __func__);
    }

    for (uint32_t claim_index = 0; claim_index < payouts.size(); ++claim_index) {
        const ShadowSyntheticPayoutTransaction& payout = payouts[claim_index];
        const COutPoint outpoint{payout.tx->GetHash(), 0};
        ShadowIndexRecord duplicate;
        if (m_db->ReadTransaction(outpoint.hash, duplicate) || changed_records.count(outpoint.hash) ||
            m_db->Exists(DBTransactionKey{outpoint.hash})) {
            return error("%s: duplicate synthetic payout id %s", __func__, outpoint.hash.ToString());
        }

        ShadowIndexRecord record;
        record.outpoint = outpoint;
        record.origin_height = block.height;
        record.origin_block_hash = block.hash;
        record.origin_block_time = block.data->GetBlockTime();
        record.claim_index = claim_index;
        record.proof_of_work = payout.proof_of_work;
        record.nominal_amount = payout.amount;
        record.script_pub_key = payout.target;
        if (record.proof_of_work) {
            const auto source = pow_payout_sources.find(outpoint.hash);
            if (source != pow_payout_sources.end()) {
                record.pow_claim_source_present = true;
                record.pow_claim_source = source->second;
            } else if (block_record.pow_claims.active) {
                return error("%s: POW payout is missing canonical source provenance", __func__);
            }
        }
        if (record.nominal_amount <= 0 || !MoneyRange(record.nominal_amount)) {
            return error("%s: invalid synthetic payout amount", __func__);
        }

        batch.Write(DBTransactionKey{outpoint.hash}, record);
        batch.Write(DBScriptKey{ShadowScriptHash(record.script_pub_key), record.origin_height, outpoint.hash}, uint8_t{1});
        block_record.payout_txids.push_back(outpoint.hash);
        undo.created_txids.push_back(outpoint.hash);
        if (!Increment(block_record.supply.issued_count) ||
            !AddMoney(block_record.supply.issued_nominal, record.nominal_amount)) {
            return error("%s: shadow supply overflow while recording issuance", __func__);
        }
    }

    for (const CTransactionRef& tx : block.data->vtx) {
        if (TransactionHasShadowProof(*tx)) block_record.observed_pow_claim_txids.push_back(tx->GetHash());
        if (TransactionHasShadowSignal(*tx)) block_record.observed_signal_txids.push_back(tx->GetHash());
    }

    // Index the accepted attestation chain after evaluating this block's
    // spends. This makes later historical effective-at-spend values exact even
    // when the index is rebuilt long after a payout was consumed.
    if (Params().GetConsensus().IsDemurrageActive(block.height, block_mtp)) {
        std::map<uint256, ShadowIndexAttestationState> changed_attestations;
        for (const CTransactionRef& tx : block.data->vtx) {
            for (const Consensus::DemurrageAttestation& attestation :
                    Consensus::ExtractDemurrageAttestations(*tx)) {
                if (attestation.height < 0 || changed_attestations.count(attestation.pubkey_hash)) {
                    return error("%s: invalid accepted demurrage attestation index state", __func__);
                }
                ShadowIndexAttestationUndo attestation_undo;
                attestation_undo.pubkey_hash = attestation.pubkey_hash;
                attestation_undo.previous_present = m_db->ReadAttestation(
                    attestation.pubkey_hash, attestation_undo.previous);
                if (!attestation_undo.previous_present &&
                    m_db->Exists(DBAttestationKey{attestation.pubkey_hash})) {
                    return error("%s: unreadable previous demurrage attestation", __func__);
                }

                const bool previous_matches =
                    attestation.previous_height.has_value() == attestation_undo.previous_present &&
                    (!attestation_undo.previous_present ||
                     (*attestation.previous_height == attestation_undo.previous.height &&
                      attestation.previous_time == attestation_undo.previous.time &&
                      attestation.previous_coverage_start_height == attestation_undo.previous.coverage_start_height &&
                      attestation.previous_source &&
                      attestation.previous_source->block_hash == attestation_undo.previous.source_block_hash &&
                      attestation.previous_source->txid == attestation_undo.previous.source_txid &&
                      attestation.previous_source->output_index == attestation_undo.previous.source_output_index));
                if (!previous_matches) {
                    return error("%s: stale accepted demurrage attestation index state", __func__);
                }

                ShadowIndexAttestationState next;
                next.height = block.height;
                next.time = block.data->GetBlockTime();
                next.coverage_start_height = attestation_undo.previous_present &&
                    block.height - attestation_undo.previous.height < Params().GetConsensus().DemurrageZeroBlocks()
                        ? attestation_undo.previous.coverage_start_height
                        : static_cast<uint32_t>(block.height);
                next.source_block_hash = block.hash;
                next.source_txid = tx->GetHash();
                next.source_output_index = attestation.output_index;
                undo.attestation_previous.push_back(attestation_undo);
                changed_attestations.emplace(attestation.pubkey_hash, next);
                batch.Write(DBAttestationKey{attestation.pubkey_hash}, next);
            }
        }
    }

    if (block_record.supply.spent_count > block_record.supply.issued_count ||
        block_record.supply.spent_nominal > block_record.supply.issued_nominal ||
        block_record.supply.spent_effective > block_record.supply.spent_nominal ||
        block_record.supply.spent_decayed > block_record.supply.spent_nominal ||
        block_record.supply.spent_effective + block_record.supply.spent_decayed !=
            block_record.supply.spent_nominal) {
        return error("%s: inconsistent cumulative shadow supply", __func__);
    }

    batch.Write(DBBlockKey{block.hash}, block_record);
    batch.Write(DBUndoKey{block.hash}, undo);
    batch.Write(DB_CUSTOM_TIP, ShadowIndexTip{block.hash, block.height});
    return m_db->WriteBatch(batch);
}

bool ShadowIndex::CustomRewind(const interfaces::BlockKey& current_tip,
                               const interfaces::BlockKey& new_tip)
{
    ShadowIndexTip custom_tip;
    if (current_tip.height >= SHADOW_REWARD_START_HEIGHT) {
        if (!m_db->Read(DB_CUSTOM_TIP, custom_tip) ||
            custom_tip.height != current_tip.height || custom_tip.hash != current_tip.hash) {
            return error("%s: shadowindex custom tip does not match rewind source", __func__);
        }
    } else if (m_db->Exists(DB_CUSTOM_TIP)) {
        return error("%s: unexpected shadowindex custom tip below reward start", __func__);
    }

    std::vector<interfaces::BlockKey> disconnected;
    {
        LOCK(cs_main);
        const CBlockIndex* current = m_chainstate->m_blockman.LookupBlockIndex(current_tip.hash);
        const CBlockIndex* stop = m_chainstate->m_blockman.LookupBlockIndex(new_tip.hash);
        if (!current || !stop || current->nHeight != current_tip.height ||
            stop->nHeight != new_tip.height || current->GetAncestor(stop->nHeight) != stop) {
            return error("%s: invalid shadowindex rewind range", __func__);
        }
        while (current != stop) {
            disconnected.push_back({current->GetBlockHash(), current->nHeight});
            current = current->pprev;
        }
    }

    for (size_t i = 0; i < disconnected.size(); ++i) {
        const interfaces::BlockKey& disconnected_block = disconnected[i];
        const interfaces::BlockKey parent = i + 1 < disconnected.size()
            ? disconnected[i + 1]
            : new_tip;
        const uint256& block_hash = disconnected_block.hash;
        CDBBatch batch(*m_db);
        bool has_writes{false};

        QuantumWitnessBlockUndo witness_undo;
        if (m_db->Read(DBQuantumWitnessBlockKey{block_hash}, witness_undo)) {
            if (witness_undo.height != disconnected_block.height ||
                witness_undo.block_hash != block_hash) {
                return error("%s: corrupt quantum witness undo for %s", __func__, block_hash.ToString());
            }
            for (const QuantumWitnessIndexRecord& previous : witness_undo.spent_previous) {
                if (previous.spent) return error("%s: invalid quantum witness spend undo", __func__);
                batch.Write(DBQuantumWitnessOutputKey{previous.outpoint}, previous);
            }
            for (const COutPoint& created : witness_undo.created_outpoints) {
                QuantumWitnessIndexRecord record;
                if (!m_db->Read(DBQuantumWitnessOutputKey{created}, record) ||
                    record.origin_block_hash != block_hash) {
                    return error("%s: missing created quantum witness output %s", __func__, created.ToString());
                }
                batch.Erase(DBQuantumWitnessOutputKey{created});
            }
            batch.Erase(DBQuantumWitnessBlockKey{block_hash});
            has_writes = true;
        } else if (m_db->Exists(DBQuantumWitnessBlockKey{block_hash})) {
            return error("%s: unreadable quantum witness undo for %s", __func__, block_hash.ToString());
        }

        if (disconnected_block.height >= SHADOW_REWARD_START_HEIGHT) {
            ShadowIndexBlockRecord block_record;
            ShadowIndexBlockUndo undo;
            if (!m_db->ReadBlock(block_hash, block_record) ||
                !m_db->Read(DBUndoKey{block_hash}, undo) ||
                block_record.block_hash != block_hash || undo.block_hash != block_hash ||
                block_record.height != undo.height) {
                return error("%s: missing or corrupt shadowindex undo for %s", __func__, block_hash.ToString());
            }
            for (const ShadowIndexRecord& previous : undo.spent_previous) {
                if (previous.spent) return error("%s: invalid spent undo record", __func__);
                batch.Write(DBTransactionKey{previous.outpoint.hash}, previous);
                batch.Erase(DBSpentOutpointKey{previous.outpoint});
            }
            for (const uint256& created_txid : undo.created_txids) {
                ShadowIndexRecord record;
                if (!m_db->ReadTransaction(created_txid, record) ||
                    record.origin_block_hash != block_hash) {
                    return error("%s: missing created shadow record %s", __func__, created_txid.ToString());
                }
                batch.Erase(DBTransactionKey{created_txid});
                batch.Erase(DBSpentOutpointKey{record.outpoint});
                batch.Erase(DBScriptKey{ShadowScriptHash(record.script_pub_key), record.origin_height, created_txid});
            }
            for (const ShadowIndexAttestationUndo& previous : undo.attestation_previous) {
                if (previous.previous_present) {
                    batch.Write(DBAttestationKey{previous.pubkey_hash}, previous.previous);
                } else {
                    batch.Erase(DBAttestationKey{previous.pubkey_hash});
                }
            }
            for (uint32_t claim_index = 0; claim_index < block_record.pow_claims.record_count;
                 ++claim_index) {
                batch.Erase(DBPowClaimKey{block_hash, claim_index});
            }
            batch.Erase(DBBlockKey{block_hash});
            batch.Erase(DBUndoKey{block_hash});
            has_writes = true;
        }
        if (disconnected_block.height >= SHADOW_REWARD_START_HEIGHT) {
            if (parent.height >= SHADOW_REWARD_START_HEIGHT) {
                batch.Write(DB_CUSTOM_TIP, ShadowIndexTip{parent.hash, parent.height});
            } else {
                batch.Erase(DB_CUSTOM_TIP);
            }
            has_writes = true;
        }
        if (has_writes && !m_db->WriteBatch(batch)) return false;
    }
    return true;
}

bool ShadowIndex::LookupBlock(const uint256& block_hash, ShadowIndexBlockRecord& record) const
{
    return m_db->ReadBlock(block_hash, record) && record.block_hash == block_hash &&
        IsValidShadowIndexBlockRecord(record);
}

bool ShadowIndex::LookupTransaction(const uint256& synthetic_txid, ShadowIndexRecord& record) const
{
    return m_db->ReadTransaction(synthetic_txid, record) &&
        record.outpoint.hash == synthetic_txid && IsValidShadowIndexRecord(record);
}

bool ShadowIndex::LookupSpentOutpoint(const COutPoint& outpoint, ShadowIndexRecord& record) const
{
    return m_db->Read(DBSpentOutpointKey{outpoint}, record) &&
        record.outpoint == outpoint && record.spent &&
        IsValidShadowIndexRecord(record);
}

bool ShadowIndex::LookupSupply(const uint256& block_hash, ShadowIndexSupply& supply) const
{
    ShadowIndexBlockRecord block;
    if (!LookupBlock(block_hash, block)) return false;
    supply = block.supply;
    return true;
}

bool ShadowIndex::LookupPowClaims(
    const uint256& block_hash, size_t offset, size_t limit,
    std::vector<ShadowIndexPowClaimRecord>& records,
    std::optional<size_t>& next) const
{
    records.clear();
    next.reset();
    if (limit == 0 || limit > MAX_SCRIPT_QUERY_RESULTS) return false;
    ShadowIndexBlockRecord block;
    if (!LookupBlock(block_hash, block)) return false;
    const size_t total = block.pow_claims.record_count;
    if (offset > total) offset = total;
    const size_t end = std::min(total, offset + limit);
    records.reserve(end - offset);
    for (size_t index = offset; index < end; ++index) {
        ShadowIndexPowClaimRecord record;
        if (!m_db->Read(DBPowClaimKey{block_hash, static_cast<uint32_t>(index)},
                        record) || !IsValidShadowPowClaimRecord(record)) {
            return false;
        }
        if (record.synthetic_payout_present) {
            ShadowIndexRecord payout;
            if (!m_db->ReadTransaction(record.synthetic_payout_outpoint.hash, payout) ||
                !IsValidShadowIndexRecord(payout) ||
                payout.outpoint != record.synthetic_payout_outpoint ||
                payout.origin_height != static_cast<uint32_t>(block.height) ||
                payout.origin_block_hash != block_hash || !payout.proof_of_work ||
                payout.nominal_amount != record.credited_amount ||
                payout.script_pub_key != record.payout_script ||
                !payout.pow_claim_source_present ||
                !ShadowPowClaimSourcesEqual(payout.pow_claim_source, record.source)) {
                return false;
            }
        }
        records.push_back(std::move(record));
    }
    if (end < total) next = end;
    return true;
}

bool ShadowIndex::LookupLatestAttestation(const CScript& script_pub_key,
                                          std::optional<int>& height,
                                          std::optional<int>& coverage_start_height) const
{
    height.reset();
    coverage_start_height.reset();
    const std::optional<uint256> key =
        Consensus::DemurrageControllingKeyHashForScript(script_pub_key);
    if (!key) return true;
    ShadowIndexAttestationState state;
    if (!m_db->ReadAttestation(*key, state)) {
        return !m_db->Exists(DBAttestationKey{*key});
    }
    height = state.height;
    coverage_start_height = static_cast<int>(state.coverage_start_height);
    return true;
}

bool ShadowIndex::ForEachTransaction(
    size_t max_records,
    const std::function<bool(const ShadowIndexRecord&)>& callback,
    size_t& visited,
    bool& complete) const
{
    visited = 0;
    complete = true;
    if (max_records == 0) return false;
    std::unique_ptr<CDBIterator> iterator{m_db->NewIterator()};
    iterator->Seek(DBTransactionKey{uint256::ZERO});
    while (iterator->Valid()) {
        DBTransactionKey key;
        if (!iterator->GetKey(key)) break;
        if (visited == max_records) {
            complete = false;
            return true;
        }
        ShadowIndexRecord record;
        if (!iterator->GetValue(record) || record.outpoint.hash != key.txid ||
            !IsValidShadowIndexRecord(record) ||
            !callback(record)) {
            return false;
        }
        ++visited;
        iterator->Next();
    }
    return true;
}

bool ShadowIndex::ForEachQuantumWitnessOutput(
    size_t max_records,
    const std::function<bool(const QuantumWitnessIndexRecord&)>& callback,
    size_t& visited,
    bool& complete) const
{
    visited = 0;
    complete = true;
    if (max_records == 0) return false;
    std::unique_ptr<CDBIterator> iterator{m_db->NewIterator()};
    iterator->Seek(DBQuantumWitnessOutputKey{COutPoint{}});
    while (iterator->Valid()) {
        DBQuantumWitnessOutputKey key;
        if (!iterator->GetKey(key)) break;
        if (visited == max_records) {
            complete = false;
            return true;
        }
        QuantumWitnessIndexRecord record;
        if (!iterator->GetValue(record) || record.outpoint != key.outpoint ||
            !callback(record)) {
            return false;
        }
        ++visited;
        iterator->Next();
    }
    return true;
}

bool ShadowIndex::LookupScript(const CScript& script_pub_key,
                               const std::optional<ShadowIndexScriptCursor>& after,
                               size_t limit,
                               std::vector<ShadowIndexRecord>& records,
                               std::optional<ShadowIndexScriptCursor>& next) const
{
    records.clear();
    next.reset();
    if (limit == 0 || limit > MAX_SCRIPT_QUERY_RESULTS) return false;

    const uint256 script_hash = ShadowScriptHash(script_pub_key);
    DBScriptKey seek{script_hash, after ? after->height : 0,
                     after ? after->synthetic_txid : uint256::ZERO};
    std::unique_ptr<CDBIterator> iterator{m_db->NewIterator()};
    iterator->Seek(seek);
    DBScriptKey key;
    if (after && iterator->Valid() && iterator->GetKey(key) && key == seek) iterator->Next();

    while (iterator->Valid()) {
        if (!iterator->GetKey(key) || key.script_hash != script_hash) break;
        ShadowIndexRecord record;
        if (!m_db->ReadTransaction(key.txid, record) ||
            record.outpoint.hash != key.txid || record.origin_height != key.height ||
            record.script_pub_key != script_pub_key ||
            !IsValidShadowIndexRecord(record)) {
            return false;
        }
        if (records.size() == limit) {
            const ShadowIndexRecord& last = records.back();
            next = ShadowIndexScriptCursor{last.origin_height, last.outpoint.hash};
            break;
        }
        records.push_back(std::move(record));
        iterator->Next();
    }
    return true;
}
