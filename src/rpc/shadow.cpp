// Copyright (c) 2026 Blackcoin Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/demurrage.h>
#include <consensus/params.h>
#include <core_io.h>
#include <index/shadowindex.h>
#include <key_io.h>
#include <node/context.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/solver.h>
#include <shadow.h>
#include <univalue.h>
#include <validation.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace {

static constexpr int DEFAULT_SHADOW_PAGE_SIZE{100};
static constexpr int MAX_SHADOW_PAGE_SIZE{1000};
static constexpr int64_t DEFAULT_EFFECTIVE_SCAN_LIMIT{1000000};
static constexpr int64_t MAX_EFFECTIVE_SCAN_LIMIT{10000000};

struct WitnessInventoryBucket {
    uint64_t count{0};
    arith_uint256 amount_atomic{0};
};

bool AddInventoryValue(WitnessInventoryBucket& bucket, CAmount amount)
{
    if (amount <= 0 || !MoneyRange(amount) ||
        bucket.count == std::numeric_limits<uint64_t>::max()) return false;
    bucket.amount_atomic += arith_uint256{static_cast<uint64_t>(amount)};
    ++bucket.count;
    return true;
}

UniValue InventoryAmount(const arith_uint256& amount_atomic)
{
    const arith_uint256 coin{static_cast<uint64_t>(COIN)};
    const arith_uint256 whole = amount_atomic / coin;
    const arith_uint256 remainder = amount_atomic - whole * static_cast<uint32_t>(COIN);
    return UniValue(UniValue::VNUM,
                    strprintf("%s.%08u", whole.ToString(),
                              static_cast<unsigned int>(remainder.GetLow64())));
}

UniValue InventoryBucketToJSON(const WitnessInventoryBucket& bucket)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("count", bucket.count);
    result.pushKV("amount", InventoryAmount(bucket.amount_atomic));
    result.pushKV("amount_atomic", bucket.amount_atomic.ToString());
    return result;
}

std::string WitnessVersionClass(int witness_version)
{
    if (witness_version == 14) return "v14";
    if (witness_version == 15) return "v15";
    if (witness_version == 16) return "v16";
    return "unknown";
}

std::string WitnessBridgeHandling(const CScript& script_pub_key)
{
    if (IsQuantumColdStakeScript(script_pub_key)) return "recognized_quantum_cold_stake";
    if (IsEUTXOScript(script_pub_key)) return "recognized_eutxo";
    if (IsQuantumMigrationScript(script_pub_key)) return "recognized_direct_quantum";
    return "unknown_or_malformed_witness_program_requires_explicit_review";
}

std::string WitnessOriginGroup(const std::string& phase)
{
    return phase == "migration" || phase == "final"
        ? "migration_or_later"
        : "pre_migration_window";
}

UniValue InventoryMapToJSON(const std::map<std::string, WitnessInventoryBucket>& buckets)
{
    UniValue result(UniValue::VOBJ);
    for (const auto& [name, bucket] : buckets) result.pushKV(name, InventoryBucketToJSON(bucket));
    return result;
}

void EnsureShadowIndexReady()
{
    if (!g_shadow_index) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "shadowindex is disabled; restart with -shadowindex=1. "
                           "Initial construction requires historical block files; explorer nodes should use -prune=0.");
    }
    if (!g_shadow_index->BlockUntilSyncedToCurrentChain()) {
        const IndexSummary summary = g_shadow_index->GetSummary();
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           strprintf("shadowindex is still syncing at height %d", summary.best_block_height));
    }
}

const CBlockIndex* ParseActiveBlock(const UniValue& value, ChainstateManager& chainman)
{
    LOCK(cs_main);
    CChain& chain = chainman.ActiveChain();
    const CBlockIndex* pindex{nullptr};
    if (value.isNum()) {
        const int height = value.getInt<int>();
        if (height < 0 || height > chain.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height is out of range");
        }
        pindex = chain[height];
    } else {
        const uint256 hash = ParseHashV(value, "hash_or_height");
        pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (!pindex || !chain.Contains(pindex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block is not in the active chain");
        }
    }
    if (!pindex) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
    return pindex;
}

std::string ShadowPhase(const Consensus::Params& consensus, int64_t mtp, int height)
{
    const auto state = consensus.GetQuantumLifecycleState(mtp, height);
    if (!state.schedule_valid) return "invalid_schedule";
    switch (state.phase) {
    case Consensus::QuantumQuasarPhase::LEGACY: return "pre_v4";
    case Consensus::QuantumQuasarPhase::GOLD_RUSH: return "gold_rush";
    case Consensus::QuantumQuasarPhase::MIGRATION: return "migration";
    case Consensus::QuantumQuasarPhase::FINAL_LOCKOUT: return "final";
    }
    return "invalid_schedule";
}

UniValue AmountUnits()
{
    UniValue units(UniValue::VOBJ);
    units.pushKV("display", "BLK");
    units.pushKV("atomic_decimals", 8);
    units.pushKV("amount_encoding", "JSON number in BLK; atomic integer amounts are exact internally");
    return units;
}

std::string PowClaimDispositionName(ShadowPowClaimDisposition disposition)
{
    switch (disposition) {
    case ShadowPowClaimDisposition::INVALID_LOCATION: return "invalid_location";
    case ShadowPowClaimDisposition::MALFORMED_TRANSACTION: return "malformed_transaction";
    case ShadowPowClaimDisposition::INVALID_PROOF: return "invalid_proof";
    case ShadowPowClaimDisposition::INPUT_MISMATCH: return "input_mismatch";
    case ShadowPowClaimDisposition::INVALID_BASE_FEE: return "invalid_base_fee";
    case ShadowPowClaimDisposition::EVALUATION_LIMIT: return "evaluation_limit";
    case ShadowPowClaimDisposition::WINNER: return "winner";
    case ShadowPowClaimDisposition::REIMBURSED_LOSER: return "reimbursed_loser";
    }
    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unknown indexed POW claim disposition");
}

UniValue PowClaimSourceToJSON(const ShadowIndexPowClaimSource& source)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", source.txid.GetHex());
    result.pushKV("vout", source.vout);
    result.pushKV("canonical_rank", source.canonical_rank.GetHex());
    result.pushKV("disposition", PowClaimDispositionName(source.disposition));
    result.pushKV("base_fee_known", source.base_fee_known);
    result.pushKV("base_fee", source.base_fee_known
        ? UniValue(ValueFromAmount(source.base_fee)) : UniValue{});
    return result;
}

UniValue PowClaimRecordToJSON(const ShadowIndexPowClaimRecord& record,
                              uint64_t index)
{
    UniValue result = PowClaimSourceToJSON(record.source);
    result.pushKV("index", index);
    result.pushKV("credited_amount", ValueFromAmount(record.credited_amount));
    result.pushKV("rejected", !record.synthetic_payout_present &&
        record.source.disposition != ShadowPowClaimDisposition::REIMBURSED_LOSER);
    result.pushKV("payout_scriptPubKey", record.payout_script.empty()
        ? UniValue{} : UniValue(HexStr(record.payout_script)));
    CTxDestination destination;
    result.pushKV("payout_address",
        !record.payout_script.empty() && ExtractDestination(record.payout_script, destination)
            ? UniValue(EncodeDestination(destination)) : UniValue{});
    result.pushKV("synthetic_txid", record.synthetic_payout_present
        ? UniValue(record.synthetic_payout_outpoint.hash.GetHex()) : UniValue{});
    result.pushKV("synthetic_vout", record.synthetic_payout_present
        ? UniValue(record.synthetic_payout_outpoint.n) : UniValue{});
    return result;
}

UniValue ShadowRecordToJSON(const ShadowIndexRecord& record,
                            const CBlockIndex& tip,
                            const Consensus::Params& consensus)
{
    const int evaluation_height = tip.nHeight + 1;
    const int64_t evaluation_mtp = tip.GetMedianTimePast();
    const int maturity_height = static_cast<int>(record.origin_height) + consensus.nCoinbaseMaturity;
    const int phase_unlock_height = consensus.UsesHeightLifecycle()
        ? consensus.nGoldRushEndHeight + 1
        : SHADOW_REWARD_END_HEIGHT + 1;
    const int earliest_spend_height = std::max(maturity_height, phase_unlock_height);
    const bool mature = evaluation_height >= maturity_height;
    const bool gold_rush_locked = !IsQuantumWitnessSpendActive(
        consensus, evaluation_mtp, evaluation_height);

    Consensus::DemurrageEvaluation evaluation;
    if (record.spent) {
        evaluation.nominal_value = record.nominal_amount;
        evaluation.effective_value = record.effective_amount_at_spend;
        evaluation.burned_value = record.decayed_amount_at_spend;
        evaluation.active = record.decayed_amount_at_spend > 0;
    } else {
        std::optional<int> latest_height;
        std::optional<int> coverage_start;
        if (!g_shadow_index->LookupLatestAttestation(
                record.script_pub_key, latest_height, coverage_start)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read shadowindex demurrage state");
        }
        Coin coin{CTxOut{record.nominal_amount, record.script_pub_key},
                  static_cast<int>(record.origin_height),
                  /*coinbase=*/true, /*coinstake=*/false,
                  static_cast<int>(record.origin_block_time)};
        evaluation = Consensus::EvaluateDemurrage(
            coin, consensus, evaluation_height, evaluation_mtp,
            latest_height, coverage_start);
    }

    const bool spendable = !record.spent && mature && !gold_rush_locked && !evaluation.locked;
    std::string status;
    if (record.spent) status = "spent";
    else if (gold_rush_locked) status = "gold_rush_locked";
    else if (!mature) status = "immature";
    else if (evaluation.locked) status = "demurrage_locked";
    else status = "unspent";

    UniValue result(UniValue::VOBJ);
    result.pushKV("synthetic", true);
    result.pushKV("merkle_included", false);
    result.pushKV("synthetic_txid", record.outpoint.hash.GetHex());
    result.pushKV("vout", record.outpoint.n);
    result.pushKV("mode", record.proof_of_work ? "pow" : "pos");
    result.pushKV("status", status);
    result.pushKV("nominal_amount", ValueFromAmount(record.nominal_amount));
    result.pushKV("effective_amount", ValueFromAmount(evaluation.effective_value));
    result.pushKV("decayed_amount", ValueFromAmount(evaluation.burned_value));
    result.pushKV("valuation_status", record.spent ? "recorded_at_spend" : "current_next_block_consensus");
    result.pushKV("scriptPubKey", HexStr(record.script_pub_key));
    CTxDestination destination;
    if (ExtractDestination(record.script_pub_key, destination)) {
        result.pushKV("address", EncodeDestination(destination));
    }
    if (record.pow_claim_source_present) {
        result.pushKV("pow_claim_source", PowClaimSourceToJSON(record.pow_claim_source));
    } else {
        result.pushKV("pow_claim_source", UniValue{});
    }

    UniValue anchor(UniValue::VOBJ);
    anchor.pushKV("height", record.origin_height);
    anchor.pushKV("blockhash", record.origin_block_hash.GetHex());
    anchor.pushKV("time", record.origin_block_time);
    anchor.pushKV("claim_index", record.claim_index);
    result.pushKV("base_anchor", std::move(anchor));

    UniValue lifecycle(UniValue::VOBJ);
    lifecycle.pushKV("coinbase_maturity", consensus.nCoinbaseMaturity);
    lifecycle.pushKV("maturity_height", maturity_height);
    lifecycle.pushKV("mature", mature);
    lifecycle.pushKV("gold_rush_phase_locked", gold_rush_locked);
    lifecycle.pushKV("earliest_spend_height", earliest_spend_height);
    lifecycle.pushKV("earliest_spend_height_exact", consensus.UsesHeightLifecycle());
    lifecycle.pushKV("spendable_next_block", spendable);
    result.pushKV("lifecycle", std::move(lifecycle));

    UniValue demurrage(UniValue::VOBJ);
    demurrage.pushKV("valuation_height", record.spent ? record.spend_height : evaluation_height);
    demurrage.pushKV("active", evaluation.active);
    demurrage.pushKV("exempt", evaluation.exempt);
    demurrage.pushKV("locked", evaluation.locked);
    demurrage.pushKV("inactive_blocks", evaluation.inactive_blocks);
    demurrage.pushKV("remaining_ppm", evaluation.remaining_ppm);
    if (!evaluation.exemption.empty()) demurrage.pushKV("classification", evaluation.exemption);
    result.pushKV("demurrage", std::move(demurrage));

    if (record.spent) {
        UniValue spend(UniValue::VOBJ);
        spend.pushKV("height", record.spend_height);
        spend.pushKV("blockhash", record.spend_block_hash.GetHex());
        spend.pushKV("txid", record.spending_txid.GetHex());
        spend.pushKV("tx_index", record.spend_tx_index);
        spend.pushKV("input_index", record.spend_input_index);
        result.pushKV("spend", std::move(spend));
    } else {
        result.pushKV("spend", UniValue{});
    }
    return result;
}

RPCHelpMan getshadowblock()
{
    return RPCHelpMan{
        "getshadowblock",
        "Returns a stable, paginated active-chain view of deterministic synthetic shadow-ledger payouts.\n"
        "Synthetic payout transaction IDs are not members of the base block Merkle tree. "
        "Use base_anchor to bind every record to its active-chain source block.\n",
        {
            {"hash_or_height", RPCArg::Type::NUM, RPCArg::Optional::NO, "Active-chain block hash or height",
                RPCArgOptions{.skip_type_check = true, .type_str = {"", "string or numeric"}}},
            {"offset", RPCArg::Type::NUM, RPCArg::Default{0}, "Zero-based payout offset"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_SHADOW_PAGE_SIZE}, "Maximum payouts to return (1-1000)"},
            {"claim_offset", RPCArg::Type::NUM, RPCArg::Default{0}, "Zero-based canonical POW-claim accounting offset"},
            {"claim_count", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_SHADOW_PAGE_SIZE}, "Maximum POW-claim records to return (1-1000)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Versioned explorer-facing shadow block record"},
        RPCExamples{
            HelpExampleCli("getshadowblock", "5950003") +
            HelpExampleRpc("getshadowblock", "5950003, 0, 100")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const int offset = request.params[1].isNull() ? 0 : request.params[1].getInt<int>();
            const int count = request.params[2].isNull() ? DEFAULT_SHADOW_PAGE_SIZE : request.params[2].getInt<int>();
            const int claim_offset = request.params[3].isNull() ? 0 : request.params[3].getInt<int>();
            const int claim_count = request.params[4].isNull() ? DEFAULT_SHADOW_PAGE_SIZE : request.params[4].getInt<int>();
            if (offset < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "offset must be non-negative");
            if (claim_offset < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "claim_offset must be non-negative");
            if (count < 1 || count > MAX_SHADOW_PAGE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 1000");
            }
            if (claim_count < 1 || claim_count > MAX_SHADOW_PAGE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "claim_count must be between 1 and 1000");
            }

            EnsureShadowIndexReady();
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* pindex = ParseActiveBlock(request.params[0], chainman);
            const CBlockIndex* tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
            if (!tip) throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Chain is not initialized");

            ShadowIndexBlockRecord indexed;
            if (pindex->nHeight >= SHADOW_REWARD_START_HEIGHT) {
                if (!g_shadow_index->LookupBlock(pindex->GetBlockHash(), indexed)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Block is not available in the synchronized shadowindex");
                }
            } else {
                indexed.height = pindex->nHeight;
                indexed.block_hash = pindex->GetBlockHash();
                indexed.block_time = pindex->GetBlockTime();
                indexed.median_time_past = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
            }

            CAmount pow_total{0};
            CAmount pos_total{0};
            for (const uint256& txid : indexed.payout_txids) {
                ShadowIndexRecord record;
                if (!g_shadow_index->LookupTransaction(txid, record)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Shadow block references a missing synthetic transaction");
                }
                CAmount& mode_total = record.proof_of_work ? pow_total : pos_total;
                if (record.nominal_amount <= 0 || !MoneyRange(record.nominal_amount) ||
                    mode_total > MAX_MONEY - record.nominal_amount) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Shadow block payout total is out of range");
                }
                mode_total += record.nominal_amount;
            }
            if (indexed.pow_claims.active &&
                indexed.pow_claims.credited_total != pow_total) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "Indexed POW claim credits do not match POW payouts");
            }

            const size_t begin = std::min<size_t>(static_cast<size_t>(offset), indexed.payout_txids.size());
            const size_t end = std::min<size_t>(begin + static_cast<size_t>(count), indexed.payout_txids.size());
            UniValue payouts(UniValue::VARR);
            for (size_t i = begin; i < end; ++i) {
                ShadowIndexRecord record;
                if (!g_shadow_index->LookupTransaction(indexed.payout_txids[i], record)) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read synthetic transaction from shadowindex");
                }
                UniValue item = ShadowRecordToJSON(record, *tip, chainman.GetConsensus());
                item.pushKV("index", static_cast<uint64_t>(i));
                payouts.push_back(std::move(item));
            }

            std::vector<ShadowIndexPowClaimRecord> indexed_claims;
            std::optional<size_t> next_claim_offset;
            if (pindex->nHeight >= SHADOW_REWARD_START_HEIGHT &&
                !g_shadow_index->LookupPowClaims(
                    pindex->GetBlockHash(), static_cast<size_t>(claim_offset),
                    static_cast<size_t>(claim_count), indexed_claims,
                    next_claim_offset)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR,
                                   "Unable to read POW claim accounting from shadowindex");
            }
            UniValue claims(UniValue::VARR);
            for (size_t i = 0; i < indexed_claims.size(); ++i) {
                claims.push_back(PowClaimRecordToJSON(
                    indexed_claims[i], static_cast<uint64_t>(claim_offset) + i));
            }

            UniValue observed_pow(UniValue::VARR);
            for (const uint256& txid : indexed.observed_pow_claim_txids) observed_pow.push_back(txid.GetHex());
            UniValue observed_pos(UniValue::VARR);
            for (const uint256& txid : indexed.observed_signal_txids) observed_pos.push_back(txid.GetHex());

            const Consensus::Params& consensus = chainman.GetConsensus();
            const bool reward_active = IsShadowGoldRushRewardActive(
                consensus, indexed.median_time_past, pindex->nHeight);
            UniValue result(UniValue::VOBJ);
            result.pushKV("schema", "blackcoin.shadow.block.v2");
            result.pushKV("height", pindex->nHeight);
            result.pushKV("blockhash", pindex->GetBlockHash().GetHex());
            result.pushKV("time", indexed.block_time);
            result.pushKV("mediantime", indexed.median_time_past);
            result.pushKV("confirmations", tip->nHeight - pindex->nHeight + 1);
            result.pushKV("phase", ShadowPhase(consensus, indexed.median_time_past, pindex->nHeight));
            result.pushKV("gold_rush_reward_active", reward_active);
            result.pushKV("scheduled_reward", ValueFromAmount(reward_active ? ShadowBaseReward(pindex->nHeight) : 0));
            result.pushKV("synthetic", true);
            result.pushKV("merkle_included", false);
            result.pushKV("total_payouts", static_cast<uint64_t>(indexed.payout_txids.size()));
            result.pushKV("offset", offset);
            result.pushKV("count", static_cast<uint64_t>(end - begin));
            result.pushKV("next_offset", end < indexed.payout_txids.size() ? UniValue(static_cast<uint64_t>(end)) : UniValue{});
            result.pushKV("pow_payout_total", ValueFromAmount(pow_total));
            result.pushKV("pos_payout_total", ValueFromAmount(pos_total));
            UniValue claim_summary(UniValue::VOBJ);
            claim_summary.pushKV("active", indexed.pow_claims.active);
            claim_summary.pushKV("total_records", indexed.pow_claims.record_count);
            claim_summary.pushKV("winner_count", indexed.pow_claims.winner_count);
            claim_summary.pushKV("reimbursed_loser_count", indexed.pow_claims.reimbursed_loser_count);
            claim_summary.pushKV("rejected_count", indexed.pow_claims.rejected_count);
            claim_summary.pushKV("credited_total", ValueFromAmount(indexed.pow_claims.credited_total));
            claim_summary.pushKV("winner_credited_total", ValueFromAmount(indexed.pow_claims.winner_credited_total));
            claim_summary.pushKV("reimbursed_credited_total", ValueFromAmount(indexed.pow_claims.reimbursed_credited_total));
            claim_summary.pushKV("offset", claim_offset);
            claim_summary.pushKV("count", static_cast<uint64_t>(indexed_claims.size()));
            claim_summary.pushKV("next_offset", next_claim_offset
                ? UniValue(static_cast<uint64_t>(*next_claim_offset)) : UniValue{});
            claim_summary.pushKV("records", std::move(claims));
            result.pushKV("pow_claim_accounting", std::move(claim_summary));
            result.pushKV("observed_pow_claim_txids", std::move(observed_pow));
            result.pushKV("observed_signal_txids", std::move(observed_pos));
            result.pushKV("units", AmountUnits());
            result.pushKV("payouts", std::move(payouts));
            return result;
        },
    };
}

RPCHelpMan getshadowtransaction()
{
    return RPCHelpMan{
        "getshadowtransaction",
        "Returns one deterministic synthetic shadow-ledger payout and its active-chain origin/spend status.\n",
        {{"synthetic_txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Synthetic payout transaction id"}},
        RPCResult{RPCResult::Type::OBJ, "", "Versioned explorer-facing synthetic transaction record"},
        RPCExamples{
            HelpExampleCli("getshadowtransaction", "\"txid\"") +
            HelpExampleRpc("getshadowtransaction", "\"txid\"")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            EnsureShadowIndexReady();
            const uint256 txid = ParseHashV(request.params[0], "synthetic_txid");
            ShadowIndexRecord record;
            if (!g_shadow_index->LookupTransaction(txid, record)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Synthetic shadow transaction not found");
            }
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* tip{nullptr};
            {
                LOCK(cs_main);
                tip = chainman.ActiveChain().Tip();
                const CBlockIndex* origin = tip ? tip->GetAncestor(record.origin_height) : nullptr;
                if (!origin || origin->GetBlockHash() != record.origin_block_hash) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Synthetic transaction is not on the active chain");
                }
            }
            UniValue result = ShadowRecordToJSON(record, *tip, chainman.GetConsensus());
            result.pushKV("schema", "blackcoin.shadow.transaction.v1");
            result.pushKV("confirmations", tip->nHeight - static_cast<int>(record.origin_height) + 1);
            result.pushKV("units", AmountUnits());
            return result;
        },
    };
}

RPCHelpMan getshadowaddress()
{
    return RPCHelpMan{
        "getshadowaddress",
        "Returns cursor-paginated synthetic shadow-ledger payout history for one destination address.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "Destination address"},
            {"after_height", RPCArg::Type::NUM, RPCArg::DefaultHint{"null"}, "Exclusive cursor origin height; provide with after_txid"},
            {"after_txid", RPCArg::Type::STR_HEX, RPCArg::DefaultHint{"null"}, "Exclusive cursor synthetic transaction id; provide with after_height"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_SHADOW_PAGE_SIZE}, "Maximum records to return (1-1000)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Versioned address-history page"},
        RPCExamples{
            HelpExampleCli("getshadowaddress", "\"blk1...\"") +
            HelpExampleCli("getshadowaddress", "\"blk1...\" 5950003 \"txid\" 100")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const int count = request.params[3].isNull()
                ? DEFAULT_SHADOW_PAGE_SIZE
                : request.params[3].getInt<int>();
            if (count < 1 || count > MAX_SHADOW_PAGE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 1000");
            }
            const bool has_height = !request.params[1].isNull();
            const bool has_txid = !request.params[2].isNull();
            if (has_height != has_txid) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "after_height and after_txid must be provided together");
            }

            const std::string address = request.params[0].get_str();
            const CTxDestination destination = DecodeDestination(address);
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Blackcoin address");
            }
            std::optional<ShadowIndexScriptCursor> after;
            if (has_height) {
                const int64_t height = request.params[1].getInt<int64_t>();
                if (height < 0 || height > std::numeric_limits<uint32_t>::max()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "after_height is out of range");
                }
                after = ShadowIndexScriptCursor{
                    static_cast<uint32_t>(height),
                    ParseHashV(request.params[2], "after_txid")};
            }

            EnsureShadowIndexReady();
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
            if (!tip) throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Chain is not initialized");

            std::vector<ShadowIndexRecord> indexed;
            std::optional<ShadowIndexScriptCursor> next;
            if (!g_shadow_index->LookupScript(GetScriptForDestination(destination), after,
                                              static_cast<size_t>(count), indexed, next)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read shadow address history");
            }
            UniValue records(UniValue::VARR);
            for (const ShadowIndexRecord& record : indexed) {
                const CBlockIndex* origin = tip->GetAncestor(record.origin_height);
                if (!origin || origin->GetBlockHash() != record.origin_block_hash) {
                    throw JSONRPCError(RPC_MISC_ERROR,
                                       "Shadow index changed during address lookup; retry the request");
                }
                records.push_back(ShadowRecordToJSON(record, *tip, chainman.GetConsensus()));
            }

            UniValue next_cursor;
            if (next) {
                next_cursor.setObject();
                next_cursor.pushKV("height", next->height);
                next_cursor.pushKV("txid", next->synthetic_txid.GetHex());
            }
            UniValue result(UniValue::VOBJ);
            result.pushKV("schema", "blackcoin.shadow.address.v1");
            result.pushKV("address", EncodeDestination(destination));
            result.pushKV("scriptPubKey", HexStr(GetScriptForDestination(destination)));
            result.pushKV("height", tip->nHeight);
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("count", static_cast<uint64_t>(indexed.size()));
            result.pushKV("next_cursor", std::move(next_cursor));
            result.pushKV("units", AmountUnits());
            result.pushKV("records", std::move(records));
            return result;
        },
    };
}

RPCHelpMan getquantumwitnessinventory()
{
    return RPCHelpMan{
        "getquantumwitnessinventory",
        "Enumerates and classifies every current active-chain value-bearing native witness-version >1 UTXO. "
        "When shadowindex is enabled and synchronized, it also reports active-chain historical creation/spend totals and can page spent history.\n",
        {
            {"view", RPCArg::Type::STR, RPCArg::Default{"utxos"}, "Records page to return: utxos or history"},
            {"offset", RPCArg::Type::NUM, RPCArg::Default{0}, "Zero-based record offset"},
            {"count", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_SHADOW_PAGE_SIZE}, "Maximum records to return (1-1000)"},
            {"max_history_records", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_EFFECTIVE_SCAN_LIMIT}, "Hard cap for historical index reconciliation (1-10000000)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Versioned witness inventory, history coverage, and selected records page"},
        RPCExamples{
            HelpExampleCli("getquantumwitnessinventory", "") +
            HelpExampleCli("getquantumwitnessinventory", "\"history\" 0 100")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const std::string view = request.params[0].isNull() ? "utxos" : request.params[0].get_str();
            const int64_t offset = request.params[1].isNull() ? 0 : request.params[1].getInt<int64_t>();
            const int count = request.params[2].isNull() ? DEFAULT_SHADOW_PAGE_SIZE : request.params[2].getInt<int>();
            const int64_t max_history_records = request.params[3].isNull()
                ? DEFAULT_EFFECTIVE_SCAN_LIMIT
                : request.params[3].getInt<int64_t>();
            if (view != "utxos" && view != "history") {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "view must be utxos or history");
            }
            if (offset < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "offset must be non-negative");
            if (count < 1 || count > MAX_SHADOW_PAGE_SIZE) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "count must be between 1 and 1000");
            }
            if (max_history_records < 1 || max_history_records > MAX_EFFECTIVE_SCAN_LIMIT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "max_history_records must be between 1 and 10000000");
            }

            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureChainman(node);
            Chainstate& chainstate = chainman.ActiveChainstate();
            const Consensus::Params& consensus = chainman.GetConsensus();
            const CBlockIndex* snapshot_tip{nullptr};
            std::unique_ptr<CCoinsViewCursor> cursor;
            std::unique_ptr<CCoinsViewCursor> marker_cursor;
            {
                LOCK(cs_main);
                chainstate.ForceFlushStateToDisk();
                CCoinsView& coins_db = chainstate.CoinsDB();
                snapshot_tip = CHECK_NONFATAL(chainstate.m_blockman.LookupBlockIndex(coins_db.GetBestBlock()));
                marker_cursor = coins_db.Cursor();
                cursor = coins_db.Cursor();
            }
            if (!snapshot_tip) throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Chain is not initialized");

            // The two LevelDB cursors own immutable snapshots from the same
            // flushed chainstate tip. Authenticate every payout-provenance
            // marker first; a value-bearing coin is excluded as synthetic only
            // when its deterministic marker exists in that exact snapshot.
            std::set<COutPoint> authenticated_payout_markers;
            COutPoint marker_outpoint;
            Coin marker_coin;
            while (marker_cursor->Valid()) {
                node.rpc_interruption_point();
                if (marker_cursor->GetKey(marker_outpoint) &&
                    marker_cursor->GetValue(marker_coin) && !marker_coin.IsSpent() &&
                    marker_coin.out.nValue == 0 &&
                    IsGoldRushPayoutMarkerScript(marker_coin.out.scriptPubKey) &&
                    IsAuthenticatedShadowMarkerOutpoint(marker_outpoint, marker_coin, snapshot_tip)) {
                    authenticated_payout_markers.insert(marker_outpoint);
                }
                marker_cursor->Next();
            }

            WitnessInventoryBucket current_total;
            WitnessInventoryBucket excluded_synthetic;
            std::map<std::string, WitnessInventoryBucket> current_versions;
            std::map<std::string, WitnessInventoryBucket> current_origins;
            std::map<std::string, WitnessInventoryBucket> current_phases;
            std::map<std::string, WitnessInventoryBucket> current_cross;
            std::map<std::string, WitnessInventoryBucket> current_handling;
            UniValue current_page(UniValue::VARR);
            uint64_t current_position{0};

            COutPoint outpoint;
            Coin coin;
            while (cursor->Valid()) {
                node.rpc_interruption_point();
                if (cursor->GetKey(outpoint) && cursor->GetValue(coin) &&
                    !coin.IsSpent() && coin.out.nValue > 0) {
                    int witness_version{0};
                    std::vector<unsigned char> witness_program;
                    if (coin.out.scriptPubKey.IsWitnessProgram(witness_version, witness_program) &&
                        witness_version > 1) {
                        const bool payout_shape = coin.fCoinBase && !coin.fCoinStake &&
                            coin.nHeight >= static_cast<uint32_t>(SHADOW_REWARD_START_HEIGHT) &&
                            coin.nHeight <= static_cast<uint32_t>(SHADOW_REWARD_END_HEIGHT) &&
                            coin.nHeight > static_cast<uint32_t>(consensus.nLastPOWBlock) &&
                            IsQuantumMigrationScript(coin.out.scriptPubKey);
                        const bool synthetic_shadow = authenticated_payout_markers.count(
                            GetGoldRushPayoutMarkerOutpoint(outpoint)) != 0;
                        if (payout_shape != synthetic_shadow) {
                            throw JSONRPCError(
                                RPC_INTERNAL_ERROR,
                                strprintf("Gold Rush payout provenance mismatch for %s; chainstate audit required",
                                          outpoint.ToString()));
                        }
                        if (synthetic_shadow) {
                            if (!AddInventoryValue(excluded_synthetic, coin.out.nValue)) {
                                throw JSONRPCError(RPC_INTERNAL_ERROR, "Witness inventory amount overflow");
                            }
                            cursor->Next();
                            continue;
                        }

                        const CBlockIndex* origin = snapshot_tip->GetAncestor(coin.nHeight);
                        if (!origin) throw JSONRPCError(RPC_INTERNAL_ERROR, "Witness UTXO origin is outside the snapshot chain");
                        const int64_t origin_mtp = origin->pprev
                            ? origin->pprev->GetMedianTimePast()
                            : origin->GetBlockTime();
                        const std::string phase = ShadowPhase(consensus, origin_mtp, origin->nHeight);
                        const std::string origin_group = WitnessOriginGroup(phase);
                        const std::string version_class = WitnessVersionClass(witness_version);
                        const std::string handling = WitnessBridgeHandling(coin.out.scriptPubKey);
                        if (!AddInventoryValue(current_total, coin.out.nValue) ||
                            !AddInventoryValue(current_versions[version_class], coin.out.nValue) ||
                            !AddInventoryValue(current_origins[origin_group], coin.out.nValue) ||
                            !AddInventoryValue(current_phases[phase], coin.out.nValue) ||
                            !AddInventoryValue(current_cross[version_class + "/" + origin_group], coin.out.nValue) ||
                            !AddInventoryValue(current_handling[handling], coin.out.nValue)) {
                            throw JSONRPCError(RPC_INTERNAL_ERROR, "Witness inventory amount overflow");
                        }

                        if (view == "utxos" && current_position >= static_cast<uint64_t>(offset) &&
                            current_page.size() < static_cast<size_t>(count)) {
                            UniValue item(UniValue::VOBJ);
                            item.pushKV("txid", outpoint.hash.GetHex());
                            item.pushKV("vout", outpoint.n);
                            item.pushKV("amount", ValueFromAmount(coin.out.nValue));
                            item.pushKV("scriptPubKey", HexStr(coin.out.scriptPubKey));
                            item.pushKV("witness_version", witness_version);
                            item.pushKV("version_class", version_class);
                            item.pushKV("bridge_handling", handling);
                            item.pushKV("origin_height", static_cast<uint64_t>(coin.nHeight));
                            item.pushKV("origin_blockhash", origin->GetBlockHash().GetHex());
                            item.pushKV("origin_block_time", origin->GetBlockTime());
                            item.pushKV("coin_time", coin.nTime);
                            item.pushKV("origin_phase", phase);
                            item.pushKV("origin_group", origin_group);
                            item.pushKV("coinbase", coin.fCoinBase != 0);
                            item.pushKV("coinstake", coin.fCoinStake != 0);
                            CTxDestination destination;
                            if (ExtractDestination(coin.out.scriptPubKey, destination)) {
                                item.pushKV("address", EncodeDestination(destination));
                            }
                            current_page.push_back(std::move(item));
                        }
                        ++current_position;
                    }
                }
                cursor->Next();
            }

            const bool history_index_enabled = g_shadow_index != nullptr;
            const bool history_index_synced = history_index_enabled &&
                g_shadow_index->BlockUntilSyncedToCurrentChain();
            IndexSummary history_index_summary;
            bool history_snapshot_covered{false};
            if (history_index_synced) {
                history_index_summary = g_shadow_index->GetSummary();
                LOCK(cs_main);
                const CBlockIndex* index_tip = chainman.m_blockman.LookupBlockIndex(
                    history_index_summary.best_block_hash);
                history_snapshot_covered = index_tip &&
                    index_tip->nHeight == history_index_summary.best_block_height &&
                    index_tip->nHeight >= snapshot_tip->nHeight &&
                    index_tip->GetAncestor(snapshot_tip->nHeight) == snapshot_tip;
            }
            if (view == "history" && !history_snapshot_covered) {
                throw JSONRPCError(RPC_MISC_ERROR,
                    !history_index_enabled
                        ? "historical witness records require -shadowindex=1"
                        : !history_index_synced
                            ? "shadowindex is still synchronizing; historical witness records are unavailable"
                            : "shadowindex does not cover the immutable UTXO snapshot tip; retry the request");
            }

            WitnessInventoryBucket history_created;
            WitnessInventoryBucket history_spent;
            WitnessInventoryBucket history_unspent;
            std::map<std::string, WitnessInventoryBucket> history_created_versions;
            std::map<std::string, WitnessInventoryBucket> history_spent_versions;
            std::map<std::string, WitnessInventoryBucket> history_created_origins;
            std::map<std::string, WitnessInventoryBucket> history_created_cross;
            UniValue history_page(UniValue::VARR);
            size_t history_db_records{0};
            uint64_t history_active_position{0};
            uint64_t history_stale_records{0};
            bool history_complete{false};
            if (history_snapshot_covered) {
                const bool history_ok = g_shadow_index->ForEachQuantumWitnessOutput(
                    static_cast<size_t>(max_history_records),
                    [&](const QuantumWitnessIndexRecord& stored) {
                        const CBlockIndex* origin = snapshot_tip->GetAncestor(stored.origin_height);
                        if (!origin || origin->GetBlockHash() != stored.origin_block_hash) {
                            ++history_stale_records;
                            return true;
                        }
                        const CBlockIndex* spend = stored.spent &&
                            stored.spend_height <= static_cast<uint32_t>(snapshot_tip->nHeight)
                                ? snapshot_tip->GetAncestor(stored.spend_height)
                                : nullptr;
                        const bool actively_spent = spend && spend->GetBlockHash() == stored.spend_block_hash;
                        const int64_t origin_mtp = origin->pprev
                            ? origin->pprev->GetMedianTimePast()
                            : origin->GetBlockTime();
                        const std::string phase = ShadowPhase(consensus, origin_mtp, origin->nHeight);
                        const std::string origin_group = WitnessOriginGroup(phase);
                        const std::string version_class = WitnessVersionClass(stored.witness_version);
                        if (!AddInventoryValue(history_created, stored.nominal_amount) ||
                            !AddInventoryValue(history_created_versions[version_class], stored.nominal_amount) ||
                            !AddInventoryValue(history_created_origins[origin_group], stored.nominal_amount) ||
                            !AddInventoryValue(history_created_cross[version_class + "/" + origin_group], stored.nominal_amount) ||
                            !(actively_spent
                                ? AddInventoryValue(history_spent, stored.nominal_amount) &&
                                  AddInventoryValue(history_spent_versions[version_class], stored.nominal_amount)
                                : AddInventoryValue(history_unspent, stored.nominal_amount))) {
                            return false;
                        }

                        if (view == "history" && history_active_position >= static_cast<uint64_t>(offset) &&
                            history_page.size() < static_cast<size_t>(count)) {
                            UniValue item(UniValue::VOBJ);
                            item.pushKV("txid", stored.outpoint.hash.GetHex());
                            item.pushKV("vout", stored.outpoint.n);
                            item.pushKV("amount", ValueFromAmount(stored.nominal_amount));
                            item.pushKV("scriptPubKey", HexStr(stored.script_pub_key));
                            item.pushKV("witness_version", stored.witness_version);
                            item.pushKV("version_class", version_class);
                            item.pushKV("bridge_handling", WitnessBridgeHandling(stored.script_pub_key));
                            item.pushKV("origin_height", stored.origin_height);
                            item.pushKV("origin_blockhash", stored.origin_block_hash.GetHex());
                            item.pushKV("origin_block_time", stored.origin_block_time);
                            item.pushKV("origin_phase", phase);
                            item.pushKV("origin_group", origin_group);
                            item.pushKV("coinbase", stored.coinbase);
                            item.pushKV("coinstake", stored.coinstake);
                            item.pushKV("spent", actively_spent);
                            if (actively_spent) {
                                UniValue spend_json(UniValue::VOBJ);
                                spend_json.pushKV("height", stored.spend_height);
                                spend_json.pushKV("blockhash", stored.spend_block_hash.GetHex());
                                spend_json.pushKV("txid", stored.spending_txid.GetHex());
                                spend_json.pushKV("tx_index", stored.spend_tx_index);
                                spend_json.pushKV("input_index", stored.spend_input_index);
                                item.pushKV("spend", std::move(spend_json));
                            } else {
                                item.pushKV("spend", UniValue{});
                            }
                            history_page.push_back(std::move(item));
                        }
                        ++history_active_position;
                        return true;
                    },
                    history_db_records, history_complete);
                if (!history_ok) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to reconcile historical witness records");
                }
            }

            const bool history_reconciles_current = history_snapshot_covered && history_complete &&
                history_unspent.count == current_total.count &&
                history_unspent.amount_atomic == current_total.amount_atomic;
            UniValue records = view == "history" ? std::move(history_page) : std::move(current_page);

            UniValue coverage(UniValue::VOBJ);
            coverage.pushKV("snapshot_current_utxos_exact", true);
            coverage.pushKV("snapshot_includes_mempool", false);
            coverage.pushKV("snapshot_includes_synthetic_shadow_outputs", false);
            coverage.pushKV("history_index_enabled", history_index_enabled);
            coverage.pushKV("history_index_synced_to_current_chain", history_index_synced);
            coverage.pushKV("history_index_tip_height", history_index_synced
                ? UniValue(history_index_summary.best_block_height)
                : UniValue{});
            coverage.pushKV("history_index_tip_hash", history_index_synced
                ? UniValue(history_index_summary.best_block_hash.GetHex())
                : UniValue{});
            coverage.pushKV("history_snapshot_tip_covered", history_snapshot_covered);
            coverage.pushKV("history_creation_start_height", history_snapshot_covered ? UniValue(0) : UniValue{});
            coverage.pushKV("history_includes_spent_creations", history_snapshot_covered);
            coverage.pushKV("history_scan_complete", history_complete);
            coverage.pushKV("history_aggregates_exact", history_snapshot_covered && history_complete);
            coverage.pushKV("history_database_records_scanned", static_cast<uint64_t>(history_db_records));
            coverage.pushKV("history_stale_branch_records_ignored", history_stale_records);
            coverage.pushKV("history_reconciles_current_utxos",
                history_snapshot_covered && history_complete
                    ? UniValue(history_reconciles_current)
                    : UniValue{});

            UniValue current(UniValue::VOBJ);
            current.pushKV("total", InventoryBucketToJSON(current_total));
            current.pushKV("by_version", InventoryMapToJSON(current_versions));
            current.pushKV("by_origin_group", InventoryMapToJSON(current_origins));
            current.pushKV("by_origin_phase", InventoryMapToJSON(current_phases));
            current.pushKV("by_version_and_origin", InventoryMapToJSON(current_cross));
            current.pushKV("by_bridge_handling", InventoryMapToJSON(current_handling));
            current.pushKV("excluded_synthetic_shadow", InventoryBucketToJSON(excluded_synthetic));

            UniValue history(UniValue::VOBJ);
            if (history_snapshot_covered && history_complete) {
                history.pushKV("created", InventoryBucketToJSON(history_created));
                history.pushKV("spent", InventoryBucketToJSON(history_spent));
                history.pushKV("unspent", InventoryBucketToJSON(history_unspent));
                history.pushKV("created_by_version", InventoryMapToJSON(history_created_versions));
                history.pushKV("spent_by_version", InventoryMapToJSON(history_spent_versions));
                history.pushKV("created_by_origin_group", InventoryMapToJSON(history_created_origins));
                history.pushKV("created_by_version_and_origin", InventoryMapToJSON(history_created_cross));
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("schema", "blackcoin.quantum.witness_inventory.v1");
            result.pushKV("height", snapshot_tip->nHeight);
            result.pushKV("bestblock", snapshot_tip->GetBlockHash().GetHex());
            result.pushKV("view", view);
            result.pushKV("offset", offset);
            result.pushKV("count", static_cast<uint64_t>(records.size()));
            result.pushKV("total_records", view == "utxos"
                ? UniValue(current_position)
                : history_complete ? UniValue(history_active_position) : UniValue{});
            const uint64_t page_end = static_cast<uint64_t>(offset) + records.size();
            const bool has_next = view == "utxos"
                ? page_end < current_position
                : records.size() == static_cast<size_t>(count) &&
                    (!history_complete || page_end < history_active_position);
            result.pushKV("next_offset", has_next ? UniValue(page_end) : UniValue{});
            result.pushKV("classification", "native value-bearing witness versions >1; exact v14/v15/v16/unknown and active-chain origin phase");
            result.pushKV("current_utxos", std::move(current));
            result.pushKV("history", std::move(history));
            result.pushKV("coverage", std::move(coverage));
            result.pushKV("units", AmountUnits());
            result.pushKV("records", std::move(records));
            return result;
        },
    };
}

RPCHelpMan getshadowsupply()
{
    return RPCHelpMan{
        "getshadowsupply",
        "Returns exact indexed nominal shadow-ledger issuance/spend totals. "
        "After demurrage activation, current effective unspent value is an optional bounded scan.\n",
        {
            {"include_effective", RPCArg::Type::BOOL, RPCArg::Default{true}, "Calculate current demurrage-adjusted unspent value when demurrage is active"},
            {"max_records", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_EFFECTIVE_SCAN_LIMIT}, "Hard cap for an effective-value scan (1-10000000)"},
        },
        RPCResult{RPCResult::Type::OBJ, "", "Versioned explorer-facing shadow supply record"},
        RPCExamples{
            HelpExampleCli("getshadowsupply", "") +
            HelpExampleRpc("getshadowsupply", "")
        },
        [&](const RPCHelpMan&, const JSONRPCRequest& request) -> UniValue {
            const bool include_effective = request.params[0].isNull() || request.params[0].get_bool();
            const int64_t max_records = request.params[1].isNull()
                ? DEFAULT_EFFECTIVE_SCAN_LIMIT
                : request.params[1].getInt<int64_t>();
            if (max_records < 1 || max_records > MAX_EFFECTIVE_SCAN_LIMIT) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "max_records must be between 1 and 10000000");
            }

            EnsureShadowIndexReady();
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            const CBlockIndex* tip = WITH_LOCK(cs_main, return chainman.ActiveChain().Tip());
            if (!tip) throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Chain is not initialized");

            ShadowIndexSupply supply;
            if (tip->nHeight >= SHADOW_REWARD_START_HEIGHT &&
                !g_shadow_index->LookupSupply(tip->GetBlockHash(), supply)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read current shadow supply from shadowindex");
            }
            const CAmount unspent_nominal = supply.issued_nominal - supply.spent_nominal;
            const uint64_t unspent_count = supply.issued_count - supply.spent_count;
            const int evaluation_height = tip->nHeight + 1;
            const int64_t evaluation_mtp = tip->GetMedianTimePast();
            const Consensus::Params& consensus = chainman.GetConsensus();
            const bool demurrage_active = consensus.IsDemurrageActive(evaluation_height, evaluation_mtp);

            bool effective_exact = !demurrage_active;
            size_t scanned_records{0};
            CAmount effective_unspent = effective_exact ? unspent_nominal : 0;
            CAmount decayed_unspent{0};
            if (demurrage_active && include_effective) {
                bool complete{false};
                const bool scan_ok = g_shadow_index->ForEachTransaction(
                    static_cast<size_t>(max_records),
                    [&](const ShadowIndexRecord& record) {
                        if (record.spent) return true;
                        std::optional<int> latest_height;
                        std::optional<int> coverage_start;
                        if (!g_shadow_index->LookupLatestAttestation(
                                record.script_pub_key, latest_height, coverage_start)) return false;
                        Coin coin{CTxOut{record.nominal_amount, record.script_pub_key},
                                  static_cast<int>(record.origin_height),
                                  /*coinbase=*/true, /*coinstake=*/false,
                                  static_cast<int>(record.origin_block_time)};
                        const Consensus::DemurrageEvaluation evaluation = Consensus::EvaluateDemurrage(
                            coin, consensus, evaluation_height, evaluation_mtp,
                            latest_height, coverage_start);
                        effective_unspent += evaluation.effective_value;
                        decayed_unspent += evaluation.burned_value;
                        return MoneyRange(effective_unspent) && MoneyRange(decayed_unspent);
                    },
                    scanned_records, complete);
                if (!scan_ok) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to scan shadowindex valuation records");
                }
                effective_exact = complete;
                if (!complete) {
                    effective_unspent = 0;
                    decayed_unspent = 0;
                }
            }

            UniValue result(UniValue::VOBJ);
            result.pushKV("schema", "blackcoin.shadow.supply.v1");
            result.pushKV("height", tip->nHeight);
            result.pushKV("bestblock", tip->GetBlockHash().GetHex());
            result.pushKV("evaluation_height", evaluation_height);
            result.pushKV("phase", ShadowPhase(consensus, evaluation_mtp, evaluation_height));
            result.pushKV("issued_count", supply.issued_count);
            result.pushKV("issued_nominal_amount", ValueFromAmount(supply.issued_nominal));
            result.pushKV("spent_count", supply.spent_count);
            result.pushKV("spent_nominal_amount", ValueFromAmount(supply.spent_nominal));
            result.pushKV("spent_effective_amount", ValueFromAmount(supply.spent_effective));
            result.pushKV("spent_decayed_amount", ValueFromAmount(supply.spent_decayed));
            result.pushKV("spent_burned_amount", ValueFromAmount(supply.spent_decayed));
            result.pushKV("unspent_count", unspent_count);
            result.pushKV("unspent_nominal_amount", ValueFromAmount(unspent_nominal));
            result.pushKV("demurrage_active", demurrage_active);
            result.pushKV("effective_scan_requested", include_effective);
            result.pushKV("effective_scan_records", static_cast<uint64_t>(scanned_records));
            result.pushKV("effective_amount_exact", effective_exact);
            result.pushKV("unspent_effective_amount", effective_exact ? UniValue(ValueFromAmount(effective_unspent)) : UniValue{});
            result.pushKV("unspent_decayed_amount", effective_exact ? UniValue(ValueFromAmount(decayed_unspent)) : UniValue{});
            result.pushKV("unspent_projected_burn_amount", effective_exact ? UniValue(ValueFromAmount(decayed_unspent)) : UniValue{});
            result.pushKV("decay_disposition", "burned_by_consensus");
            result.pushKV("decay_paid_as_fee", false);
            result.pushKV("decay_redistributed", false);
            result.pushKV("units", AmountUnits());
            return result;
        },
    };
}

} // namespace

void RegisterShadowRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]{
        {"blockchain", &getquantumwitnessinventory},
        {"blockchain", &getshadowaddress},
        {"blockchain", &getshadowblock},
        {"blockchain", &getshadowtransaction},
        {"blockchain", &getshadowsupply},
    };
    for (const auto& command : commands) table.appendCommand(command.name, &command);
}
