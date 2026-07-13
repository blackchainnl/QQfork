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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <ios>
#include <memory>
#include <optional>
#include <vector>

static constexpr bool DEFAULT_SHADOWINDEX{false};

/** Stable source provenance for one canonically classified QQSPROOF note. */
struct ShadowIndexPowClaimSource {
    uint256 txid;
    uint32_t vout{0};
    uint256 canonical_rank;
    CAmount base_fee{0};
    bool base_fee_known{false};
    ShadowPowClaimDisposition disposition{ShadowPowClaimDisposition::INVALID_PROOF};

    SERIALIZE_METHODS(ShadowIndexPowClaimSource, obj)
    {
        uint8_t disposition{static_cast<uint8_t>(obj.disposition)};
        READWRITE(obj.txid, obj.vout, obj.canonical_rank, obj.base_fee,
                  obj.base_fee_known, disposition);
        SER_READ(obj, {
            if (disposition > static_cast<uint8_t>(ShadowPowClaimDisposition::REIMBURSED_LOSER)) {
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
    uint32_t record_count{0};
    uint32_t winner_count{0};
    uint32_t reimbursed_loser_count{0};
    uint32_t rejected_count{0};
    CAmount credited_total{0};
    CAmount winner_credited_total{0};
    CAmount reimbursed_credited_total{0};

    SERIALIZE_METHODS(ShadowIndexPowClaimSummary, obj)
    {
        READWRITE(obj.active, obj.record_count, obj.winner_count,
                  obj.reimbursed_loser_count, obj.rejected_count,
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
    const std::unique_ptr<DB> m_db;

protected:
    bool CustomInit(const std::optional<interfaces::BlockKey>& block) override;
    bool CustomAppend(const interfaces::BlockInfo& block) override;
    bool CustomRewind(const interfaces::BlockKey& current_tip,
                      const interfaces::BlockKey& new_tip) override;
    BaseIndex::DB& GetDB() const override;

public:
    explicit ShadowIndex(std::unique_ptr<interfaces::Chain> chain, size_t cache_size,
                         bool memory = false, bool wipe = false);
    ~ShadowIndex() override;

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
