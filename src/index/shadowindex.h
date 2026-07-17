// Copyright (c) 2026 Blackcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_INDEX_SHADOWINDEX_H
#define BITCOIN_INDEX_SHADOWINDEX_H

#include <consensus/amount.h>
#include <index/base.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <shadow.h>
#include <uint256.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <memory>
#include <optional>
#include <vector>

static constexpr bool DEFAULT_SHADOWINDEX{false};
/** Hard transport bounds; oversized deltas remain queryable through shadow RPCs. */
static constexpr size_t MAX_SHADOW_EVENT_RECORDS{4096};
static constexpr size_t MAX_SHADOW_EVENT_JSON_BYTES{16 * 1024 * 1024};

/** Stable source provenance for one canonically classified QQSPROOF note. */
struct ShadowIndexPowClaimSource {
    uint256 txid;
    uint32_t vout{0};
    uint256 logical_proof_id;
    uint256 canonical_rank;
    CAmount base_fee{0};
    bool base_fee_known{false};
    ShadowPowClaimDisposition disposition{ShadowPowClaimDisposition::INVALID_PROOF};
    uint8_t proof_version{0};
    bool origin_bound{false};
    uint32_t origin_height{0};
    uint256 origin_previous_block_hash;
    uint32_t inclusion_height{0};
    uint32_t origin_age{0};
    bool input_bound{false};
    COutPoint claim_outpoint;

    SERIALIZE_METHODS(ShadowIndexPowClaimSource, obj)
    {
        uint8_t disposition{static_cast<uint8_t>(obj.disposition)};
        READWRITE(obj.txid, obj.vout, obj.logical_proof_id,
                  obj.canonical_rank, obj.base_fee,
                  obj.base_fee_known, disposition, obj.proof_version,
                  obj.origin_bound,
                  obj.origin_height, obj.origin_previous_block_hash,
                  obj.inclusion_height, obj.origin_age, obj.input_bound,
                  obj.claim_outpoint);
        SER_READ(obj, {
            if (disposition > static_cast<uint8_t>(ShadowPowClaimDisposition::ALREADY_ACCOUNTED)) {
                throw std::ios_base::failure("Invalid shadow POW claim disposition");
            }
            obj.disposition = static_cast<ShadowPowClaimDisposition>(disposition);
        });
    }
};

/** Block-scoped claim classification stored independently for bounded paging. */
struct ShadowIndexPowClaimRecord {
    ShadowIndexPowClaimSource source;
    CScript payout_script;
    CAmount credited_amount{0};
    bool synthetic_payout_present{false};
    COutPoint synthetic_payout_outpoint;

    SERIALIZE_METHODS(ShadowIndexPowClaimRecord, obj)
    {
        READWRITE(obj.source, obj.payout_script, obj.credited_amount,
                  obj.synthetic_payout_present, obj.synthetic_payout_outpoint);
    }
};

struct ShadowIndexPowClaimSummary {
    bool active{false};
    /** Number of persisted detailed rows; always <= 64. */
    uint32_t record_count{0};
    /** Number of all QQSPROOF-shaped outputs committed by this block. */
    uint32_t observed_count{0};
    uint32_t evaluated_count{0};
    uint32_t winner_count{0};
    uint32_t reimbursed_loser_count{0};
    uint32_t reimbursed_late_count{0};
    uint32_t rejected_count{0};
    uint32_t invalid_location_count{0};
    uint32_t malformed_transaction_count{0};
    uint32_t invalid_proof_count{0};
    uint32_t wrong_mode_count{0};
    uint32_t unknown_mode_count{0};
    uint32_t input_mismatch_count{0};
    uint32_t invalid_base_fee_count{0};
    uint32_t origin_mismatch_count{0};
    uint32_t origin_expired_count{0};
    uint32_t duplicate_logical_proof_count{0};
    uint32_t already_accounted_count{0};
    uint32_t evaluation_limit_count{0};
    uint256 accounting_commitment;
    CAmount credited_total{0};
    CAmount winner_credited_total{0};
    CAmount reimbursed_credited_total{0};

    SERIALIZE_METHODS(ShadowIndexPowClaimSummary, obj)
    {
        READWRITE(obj.active, obj.record_count, obj.observed_count,
                  obj.evaluated_count, obj.winner_count,
                  obj.reimbursed_loser_count, obj.reimbursed_late_count,
                  obj.rejected_count,
                  obj.invalid_location_count,
                  obj.malformed_transaction_count,
                  obj.invalid_proof_count, obj.wrong_mode_count,
                  obj.unknown_mode_count, obj.input_mismatch_count,
                  obj.invalid_base_fee_count, obj.origin_mismatch_count,
                  obj.origin_expired_count,
                  obj.duplicate_logical_proof_count,
                  obj.already_accounted_count,
                  obj.evaluation_limit_count,
                  obj.accounting_commitment,
                  obj.credited_total, obj.winner_credited_total,
                  obj.reimbursed_credited_total);
    }
};

/** Explorer-facing representation of one deterministic shadow-ledger payout. */
struct ShadowIndexRecord {
    COutPoint outpoint;
    uint32_t origin_height{0};
    uint256 origin_block_hash;
    uint32_t origin_block_time{0};
    uint32_t claim_index{0};
    bool proof_of_work{false};
    CAmount nominal_amount{0};
    CScript script_pub_key;
    bool pow_claim_source_present{false};
    ShadowIndexPowClaimSource pow_claim_source;

    bool spent{false};
    uint32_t spend_height{0};
    uint256 spend_block_hash;
    uint256 spending_txid;
    uint32_t spend_tx_index{0};
    uint32_t spend_input_index{0};
    CAmount effective_amount_at_spend{0};
    CAmount decayed_amount_at_spend{0};

    SERIALIZE_METHODS(ShadowIndexRecord, obj)
    {
        READWRITE(obj.outpoint);
        READWRITE(obj.origin_height);
        READWRITE(obj.origin_block_hash);
        READWRITE(obj.origin_block_time);
        READWRITE(obj.claim_index);
        READWRITE(obj.proof_of_work);
        READWRITE(obj.nominal_amount);
        READWRITE(obj.script_pub_key);
        READWRITE(obj.pow_claim_source_present);
        READWRITE(obj.pow_claim_source);
        READWRITE(obj.spent);
        READWRITE(obj.spend_height);
        READWRITE(obj.spend_block_hash);
        READWRITE(obj.spending_txid);
        READWRITE(obj.spend_tx_index);
        READWRITE(obj.spend_input_index);
        READWRITE(obj.effective_amount_at_spend);
        READWRITE(obj.decayed_amount_at_spend);
    }
};

/** Reject malformed or cross-key primary records before explorer use. */
bool IsValidShadowIndexRecord(const ShadowIndexRecord& record);

/** Deterministic active-chain delta transported to shadow-ledger subscribers. */
struct ShadowIndexBlockEvent {
    int32_t height{-1};
    uint256 block_hash;
    uint256 previous_block_hash;
    uint32_t block_time{0};
    std::vector<ShadowIndexRecord> credits;
    std::vector<ShadowIndexRecord> spends;
};

using ShadowIndexEventCallback =
    std::function<void(bool connected, const ShadowIndexBlockEvent& event)>;

/** Cumulative active-chain accounting at an exact indexed block. */
struct ShadowIndexSupply {
    uint64_t issued_count{0};
    CAmount issued_nominal{0};
    uint64_t spent_count{0};
    CAmount spent_nominal{0};
    CAmount spent_effective{0};
    CAmount spent_decayed{0};

    SERIALIZE_METHODS(ShadowIndexSupply, obj)
    {
        READWRITE(obj.issued_count);
        READWRITE(obj.issued_nominal);
        READWRITE(obj.spent_count);
        READWRITE(obj.spent_nominal);
        READWRITE(obj.spent_effective);
        READWRITE(obj.spent_decayed);
    }
};

/** Block-scoped page anchor and cumulative accounting. */
struct ShadowIndexBlockRecord {
    int32_t height{-1};
    uint256 block_hash;
    uint32_t block_time{0};
    int64_t median_time_past{0};
    std::vector<uint256> payout_txids;
    std::vector<COutPoint> spent_outpoints;
    std::vector<uint256> observed_pow_claim_txids;
    std::vector<uint256> observed_signal_txids;
    ShadowIndexPowClaimSummary pow_claims;
    ShadowIndexSupply supply;

    SERIALIZE_METHODS(ShadowIndexBlockRecord, obj)
    {
        READWRITE(obj.height);
        READWRITE(obj.block_hash);
        READWRITE(obj.block_time);
        READWRITE(obj.median_time_past);
        READWRITE(obj.payout_txids);
        READWRITE(obj.spent_outpoints);
        READWRITE(obj.observed_pow_claim_txids);
        READWRITE(obj.observed_signal_txids);
        READWRITE(obj.pow_claims);
        READWRITE(obj.supply);
    }
};

struct ShadowIndexScriptCursor {
    uint32_t height{0};
    uint256 synthetic_txid;
};

/** Historical base-block creation record for a value-bearing witness output. */
struct QuantumWitnessIndexRecord {
    COutPoint outpoint;
    uint32_t origin_height{0};
    uint256 origin_block_hash;
    uint32_t origin_block_time{0};
    uint8_t witness_version{0};
    CAmount nominal_amount{0};
    CScript script_pub_key;
    bool coinbase{false};
    bool coinstake{false};

    bool spent{false};
    uint32_t spend_height{0};
    uint256 spend_block_hash;
    uint256 spending_txid;
    uint32_t spend_tx_index{0};
    uint32_t spend_input_index{0};

    SERIALIZE_METHODS(QuantumWitnessIndexRecord, obj)
    {
        READWRITE(obj.outpoint);
        READWRITE(obj.origin_height);
        READWRITE(obj.origin_block_hash);
        READWRITE(obj.origin_block_time);
        READWRITE(obj.witness_version);
        READWRITE(obj.nominal_amount);
        READWRITE(obj.script_pub_key);
        READWRITE(obj.coinbase);
        READWRITE(obj.coinstake);
        READWRITE(obj.spent);
        READWRITE(obj.spend_height);
        READWRITE(obj.spend_block_hash);
        READWRITE(obj.spending_txid);
        READWRITE(obj.spend_tx_index);
        READWRITE(obj.spend_input_index);
    }
};

/**
 * Persistent active-chain index for synthetic shadow-ledger payouts.
 *
 * The index is deliberately separate from consensus chainstate. It may be
 * wiped and rebuilt without changing block validity or synthetic payout IDs.
 */
class ShadowIndex final : public BaseIndex
{
protected:
    class DB;

private:
    std::unique_ptr<DB> m_db;
    ShadowIndexEventCallback m_event_callback;
    std::atomic<uint64_t> m_revision{0};
    bool m_event_stream_suppressed{false};

    bool BuildBlockEvent(const CBlock& block, const CBlockIndex* pindex,
                         ShadowIndexBlockEvent& event) const;
    bool IndexMatchesActiveTip(const IndexSummary& summary) const;

protected:
    void BlockConnected(ChainstateRole role, const std::shared_ptr<const CBlock>& block,
                        const CBlockIndex* pindex) override;
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block,
                           const CBlockIndex* pindex) override;
    bool CustomInit(const std::optional<interfaces::BlockKey>& block) override;
    bool CustomAppend(const interfaces::BlockInfo& block) override;
    bool CustomRewind(const interfaces::BlockKey& current_tip,
                      const interfaces::BlockKey& new_tip) override;
    BaseIndex::DB& GetDB() const override;

public:
    explicit ShadowIndex(std::unique_ptr<interfaces::Chain> chain, size_t cache_size,
                         bool memory = false, bool wipe = false,
                         ShadowIndexEventCallback event_callback = {});
    ~ShadowIndex() override;

    /** Monotonic live-index generation used to reject cross-reorg RPC reads. */
    uint64_t GetRevision() const { return m_revision.load(std::memory_order_acquire); }

    bool LookupBlock(const uint256& block_hash, ShadowIndexBlockRecord& record) const;
    bool LookupTransaction(const uint256& synthetic_txid, ShadowIndexRecord& record) const;
    bool LookupSpentOutpoint(const COutPoint& outpoint, ShadowIndexRecord& record) const;
    bool LookupSupply(const uint256& block_hash, ShadowIndexSupply& supply) const;
    bool LookupPowClaims(const uint256& block_hash, size_t offset, size_t limit,
                         std::vector<ShadowIndexPowClaimRecord>& records,
                         std::optional<size_t>& next) const;
    bool LookupLatestAttestation(const CScript& script_pub_key,
                                 std::optional<int>& height,
                                 std::optional<int>& coverage_start_height) const;

    /** Iterate primary payout records in database-key order with a hard cap. */
    bool ForEachTransaction(size_t max_records,
                            const std::function<bool(const ShadowIndexRecord&)>& callback,
                            size_t& visited,
                            bool& complete) const;
    bool ForEachQuantumWitnessOutput(
        size_t max_records,
        const std::function<bool(const QuantumWitnessIndexRecord&)>& callback,
        size_t& visited,
        bool& complete) const;

    /** Bounded address/script history lookup, ordered by origin height then txid. */
    bool LookupScript(const CScript& script_pub_key,
                      const std::optional<ShadowIndexScriptCursor>& after,
                      size_t limit,
                      std::vector<ShadowIndexRecord>& records,
                      std::optional<ShadowIndexScriptCursor>& next) const;
};

extern std::unique_ptr<ShadowIndex> g_shadow_index;

#endif // BITCOIN_INDEX_SHADOWINDEX_H
