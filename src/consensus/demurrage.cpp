// Copyright (c) 2026 The Quantum Quasar developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/demurrage.h>

#include <addresstype.h>
#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <compat/endian.h>
#include <consensus/params.h>
#include <crypto/mldsa.h>
#include <crypto/muhash.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <span.h>
#include <streams.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <set>

namespace Consensus {
namespace {

using valtype = std::vector<unsigned char>;

static constexpr unsigned char DEMURRAGE_ATTESTATION_VERSION = 3;
static constexpr uint32_t DEMURRAGE_NO_PREVIOUS_ATTESTATION = std::numeric_limits<uint32_t>::max();
static const valtype TAG_ATTEST{'Q', 'Q', 'A', 'T', 'T', 'E', 'S', 'T'};
static const valtype TAG_LATEST{'Q', 'Q', 'A', 'L', 'I', 'V', 'E'};
static const valtype TAG_UNDO{'Q', 'Q', 'A', 'U', 'N', 'D', 'O'};
static const valtype TAG_INVENTORY{'Q', 'Q', 'A', 'I', 'N', 'V'};

CScript MarkerScript(const valtype& tag, const valtype& payload = {})
{
    return CScript() << OP_FALSE << OP_RETURN << tag << payload;
}

bool ParseMarkerScript(const CScript& script, const valtype& expected_tag, valtype* payload = nullptr)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_FALSE) return false;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, data) || data != expected_tag) return false;
    if (pc == script.end()) {
        if (payload) payload->clear();
        return true;
    }
    if (!script.GetOp(pc, opcode, data)) return false;
    if (pc != script.end()) return false;
    if (payload) *payload = data;
    return true;
}

bool HasMarkerTag(const CScript& script, const valtype& expected_tag)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    return script.GetOp(pc, opcode, data) && opcode == OP_FALSE &&
           script.GetOp(pc, opcode, data) && opcode == OP_RETURN &&
           script.GetOp(pc, opcode, data) && data == expected_tag;
}

bool ParseAttestationScript(const CScript& script, valtype& payload)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    valtype data;
    if (!script.GetOp(pc, opcode, data) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, data) || data != TAG_ATTEST) return false;
    if (!script.GetOp(pc, opcode, data)) return false;
    if (pc != script.end()) return false;
    payload = std::move(data);
    return true;
}

COutPoint LatestAttestationOutpoint(const uint256& pubkey_hash)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Latest") << pubkey_hash;
    return COutPoint{ss.GetHash(), 0};
}

COutPoint DemurrageInventoryOutpoint()
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Inventory v1");
    return COutPoint{ss.GetHash(), 0};
}

using DemurrageLatestRecord = DemurrageAttestationRecord;

valtype EncodeLatestPayload(const DemurrageLatestRecord& record)
{
    DataStream stream;
    stream << uint8_t{2} << record.pubkey_hash
           << static_cast<uint32_t>(record.state.height) << record.state.time
           << record.state.coverage_start_height << record.source_block_hash
           << record.source_txid << record.source_output_index;
    const auto bytes = MakeUCharSpan(stream);
    return valtype(bytes.begin(), bytes.end());
}

bool DecodeLatestPayload(const valtype& payload, DemurrageLatestRecord& record)
{
    record = {};
    try {
        DataStream stream{MakeUCharSpan(payload)};
        uint8_t version{0};
        uint32_t height{0};
        stream >> version >> record.pubkey_hash >> height >> record.state.time
               >> record.state.coverage_start_height >> record.source_block_hash
               >> record.source_txid >> record.source_output_index;
        if (!stream.empty() || version != 2 || height > std::numeric_limits<int>::max()) return false;
        record.state.height = static_cast<int>(height);
    } catch (const std::exception&) {
        return false;
    }
    return !record.pubkey_hash.IsNull() && !record.source_block_hash.IsNull() &&
           !record.source_txid.IsNull() && record.state.height >= 0 &&
           record.state.coverage_start_height <= static_cast<uint32_t>(record.state.height);
}

Coin MarkerCoin(CAmount value, const CScript& script, int height, int64_t time)
{
    Coin coin;
    coin.out.nValue = value;
    coin.out.scriptPubKey = script;
    coin.fCoinBase = true;
    coin.fCoinStake = false;
    coin.nHeight = height;
    coin.nTime = time;
    return coin;
}

uint32_t AttestationCoverageStart(const DemurrageAttestation& attestation,
                                  const CBlockIndex* pindex,
                                  const Params& params);

struct DemurrageInventoryState {
    uint32_t tip_height{0};
    uint256 tip_hash;
    uint64_t live_count{0};
    MuHash3072 live_set;
    uint256 live_root;
};

uint256 FinalizedMuHash(const MuHash3072& source)
{
    MuHash3072 copy{source};
    uint256 result;
    copy.Finalize(result);
    return result;
}

valtype DemurrageStateLeaf(const DemurrageLatestRecord& record)
{
    DataStream stream;
    stream << std::string("Quantum Quasar Demurrage Inventory Leaf v1")
           << LatestAttestationOutpoint(record.pubkey_hash)
           << EncodeLatestPayload(record);
    const auto bytes = MakeUCharSpan(stream);
    return valtype(bytes.begin(), bytes.end());
}

valtype EncodeDemurrageInventory(const DemurrageInventoryState& state)
{
    DataStream stream;
    stream << uint8_t{3} << state.tip_height << state.tip_hash << state.live_count
           << state.live_set << state.live_root;
    const auto bytes = MakeUCharSpan(stream);
    return valtype(bytes.begin(), bytes.end());
}

bool DecodeDemurrageInventory(const CScript& script, DemurrageInventoryState& state)
{
    state = {};
    valtype payload;
    if (!ParseMarkerScript(script, TAG_INVENTORY, &payload)) return false;
    try {
        DataStream stream{MakeUCharSpan(payload)};
        uint8_t version{0};
        stream >> version >> state.tip_height >> state.tip_hash >> state.live_count
               >> state.live_set >> state.live_root;
        if (!stream.empty() || version != 3) return false;
    } catch (const std::exception&) {
        return false;
    }
    return !state.tip_hash.IsNull() && FinalizedMuHash(state.live_set) == state.live_root;
}

enum class InventoryReadResult { MISSING, VALID, INVALID };

InventoryReadResult ReadDemurrageInventory(const CCoinsViewCache& view,
                                           DemurrageInventoryState& state,
                                           Coin* coin_out = nullptr)
{
    Coin coin;
    if (!view.GetCoin(DemurrageInventoryOutpoint(), coin) || coin.IsSpent()) {
        state = {};
        return InventoryReadResult::MISSING;
    }
    if (coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        !DecodeDemurrageInventory(coin.out.scriptPubKey, state) ||
        coin.nHeight != state.tip_height) {
        return InventoryReadResult::INVALID;
    }
    if (coin_out) *coin_out = coin;
    return InventoryReadResult::VALID;
}

bool WriteDemurrageInventory(CCoinsViewCache& view, const CBlockIndex* pindex,
                             DemurrageInventoryState state)
{
    if (!pindex) return false;
    state.tip_height = pindex->nHeight;
    state.tip_hash = pindex->GetBlockHash();
    // Normalize the persisted accumulator so reorg restoration of the same
    // logical set is byte-for-byte deterministic.
    state.live_set.Finalize(state.live_root);
    view.AddCoin(DemurrageInventoryOutpoint(),
                 MarkerCoin(0, MarkerScript(TAG_INVENTORY,
                                            EncodeDemurrageInventory(state)),
                            pindex->nHeight, pindex->GetBlockTime()),
                 /*possible_overwrite=*/true);
    return true;
}

bool InventoryIsEmpty(const DemurrageInventoryState& inventory);

bool InventoryAnchoredForApply(const DemurrageInventoryState& inventory,
                               InventoryReadResult result,
                               const CBlockIndex* pindex,
                               const Params& params)
{
    if (!pindex) return false;
    const int64_t previous_mtp = pindex->pprev
        ? (pindex->pprev->pprev ? pindex->pprev->pprev->GetMedianTimePast()
                                : pindex->pprev->GetBlockTime())
        : 0;
    const bool previously_active = pindex->pprev &&
        params.IsDemurrageActive(pindex->pprev->nHeight, previous_mtp);
    if (!previously_active) {
        return pindex->pprev && result == InventoryReadResult::VALID &&
               inventory.tip_height == static_cast<uint32_t>(pindex->pprev->nHeight) &&
               inventory.tip_hash == pindex->pprev->GetBlockHash() &&
               InventoryIsEmpty(inventory);
    }
    return result == InventoryReadResult::VALID &&
           inventory.tip_height == static_cast<uint32_t>(pindex->pprev->nHeight) &&
           inventory.tip_hash == pindex->pprev->GetBlockHash();
}

bool InventoryIsEmpty(const DemurrageInventoryState& inventory)
{
    MuHash3072 empty_live;
    return inventory.live_count == 0 &&
           FinalizedMuHash(inventory.live_set) == FinalizedMuHash(empty_live);
}

enum class LatestReadResult { MISSING, VALID, INVALID };

LatestReadResult ReadLatestRecord(const CCoinsViewCache& view, const uint256& pubkey_hash,
                                  DemurrageLatestRecord& record)
{
    Coin coin;
    if (!view.GetCoin(LatestAttestationOutpoint(pubkey_hash), coin) || coin.IsSpent()) {
        record = {};
        return LatestReadResult::MISSING;
    }
    valtype payload;
    if (coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        !ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload) ||
        !DecodeLatestPayload(payload, record) || record.pubkey_hash != pubkey_hash ||
        coin.nHeight != static_cast<uint32_t>(record.state.height) ||
        coin.nTime != record.state.time) {
        return LatestReadResult::INVALID;
    }
    return LatestReadResult::VALID;
}

bool ApplyAttestationInventoryTransition(CCoinsViewCache& view,
                                         DemurrageInventoryState& inventory,
                                         const DemurrageAttestation& attestation,
                                         const uint256& txid,
                                         const CBlockIndex* pindex,
                                         const Params& params)
{
    DemurrageLatestRecord previous_record;
    const LatestReadResult previous_result = ReadLatestRecord(
        view, attestation.pubkey_hash, previous_record);
    if (previous_result == LatestReadResult::INVALID) return false;
    if (previous_result == LatestReadResult::VALID) {
        if (!attestation.previous_height ||
            *attestation.previous_height != previous_record.state.height ||
            attestation.previous_time != previous_record.state.time ||
            attestation.previous_coverage_start_height != previous_record.state.coverage_start_height ||
            !attestation.previous_source ||
            attestation.previous_source->block_hash != previous_record.source_block_hash ||
            attestation.previous_source->txid != previous_record.source_txid ||
            attestation.previous_source->output_index != previous_record.source_output_index) {
            return false;
        }
        const CBlockIndex* previous_source_block = pindex->pprev
            ? pindex->pprev->GetAncestor(previous_record.state.height)
            : nullptr;
        if (!previous_source_block ||
            previous_source_block->GetBlockHash() != previous_record.source_block_hash ||
            previous_record.state.time != static_cast<uint32_t>(previous_source_block->GetBlockTime())) {
            return false;
        }
        inventory.live_set.Remove(DemurrageStateLeaf(previous_record));
    } else {
        if (attestation.previous_height || attestation.previous_time != 0 ||
            attestation.previous_coverage_start_height != 0 || attestation.previous_source) return false;
        if (inventory.live_count == std::numeric_limits<uint64_t>::max()) return false;
        ++inventory.live_count;
    }
    DemurrageLatestRecord next;
    next.pubkey_hash = attestation.pubkey_hash;
    next.state = DemurrageAttestationState{
        pindex->nHeight, static_cast<uint32_t>(pindex->GetBlockTime()),
        AttestationCoverageStart(attestation, pindex, params)};
    next.source_block_hash = pindex->GetBlockHash();
    next.source_txid = txid;
    next.source_output_index = attestation.output_index;
    inventory.live_set.Insert(DemurrageStateLeaf(next));
    view.AddCoin(LatestAttestationOutpoint(attestation.pubkey_hash),
                 MarkerCoin(0, MarkerScript(TAG_LATEST, EncodeLatestPayload(next)),
                            next.state.height, next.state.time),
                 /*possible_overwrite=*/true);
    return true;
}

uint32_t AttestationCoverageStart(const DemurrageAttestation& attestation,
                                  const CBlockIndex* pindex,
                                  const Params& params)
{
    if (attestation.previous_height &&
        pindex->nHeight - *attestation.previous_height < params.DemurrageZeroBlocks()) {
        return attestation.previous_coverage_start_height;
    }
    return static_cast<uint32_t>(pindex->nHeight);
}

} // namespace

uint256 DemurrageInventoryCoinCommitment(const CCoinsViewCache& view)
{
    Coin coin;
    const bool present = view.GetCoin(DemurrageInventoryOutpoint(), coin) && !coin.IsSpent();
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Inventory Coin Commitment v1") << present;
    if (present) ss << coin.nHeight << coin.nTime << coin.out.scriptPubKey;
    return ss.GetHash();
}

bool HasCurrentDemurrageInventory(const CCoinsViewCache& view,
                                  const CBlockIndex* pindex_tip,
                                  const Params& params)
{
    DemurrageInventoryState inventory;
    Coin coin;
    const InventoryReadResult result = ReadDemurrageInventory(view, inventory, &coin);
    if (!pindex_tip) return result == InventoryReadResult::MISSING;
    const int64_t mtp = pindex_tip->pprev
        ? pindex_tip->pprev->GetMedianTimePast()
        : pindex_tip->GetBlockTime();
    if (!params.IsDemurrageActive(pindex_tip->nHeight, mtp)) {
        const bool next_active = params.IsDemurrageActive(
            pindex_tip->nHeight + 1, pindex_tip->GetMedianTimePast());
        if (!next_active) return result == InventoryReadResult::MISSING;
        return result == InventoryReadResult::VALID &&
               inventory.tip_height == static_cast<uint32_t>(pindex_tip->nHeight) &&
               inventory.tip_hash == pindex_tip->GetBlockHash() &&
               InventoryIsEmpty(inventory) &&
               coin.nTime == static_cast<uint32_t>(pindex_tip->GetBlockTime());
    }
    return result == InventoryReadResult::VALID &&
           inventory.tip_height == static_cast<uint32_t>(pindex_tip->nHeight) &&
           inventory.tip_hash == pindex_tip->GetBlockHash() &&
           coin.nTime == static_cast<uint32_t>(pindex_tip->GetBlockTime());
}

bool CanApplyDemurrageInventory(const CCoinsViewCache& view,
                                const CBlockIndex* pindex,
                                const Params& params)
{
    if (!pindex) return false;
    const int64_t mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast()
                                      : pindex->GetBlockTime();
    DemurrageInventoryState inventory;
    const InventoryReadResult result = ReadDemurrageInventory(view, inventory);
    if (!params.IsDemurrageActive(pindex->nHeight, mtp)) {
        return result == InventoryReadResult::MISSING;
    }
    return InventoryAnchoredForApply(inventory, result, pindex, params);
}

bool PrepareDemurrageActivationInventory(CCoinsViewCache& view,
                                         const CBlockIndex* pindex,
                                         const Params& params)
{
    if (!pindex) return false;
    const int64_t current_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast()
                                              : pindex->GetBlockTime();
    if (params.IsDemurrageActive(pindex->nHeight, current_mtp) ||
        !params.IsDemurrageActive(pindex->nHeight + 1, pindex->GetMedianTimePast())) {
        return true;
    }
    DemurrageInventoryState inventory;
    const InventoryReadResult result = ReadDemurrageInventory(view, inventory);
    if (result == InventoryReadResult::VALID) {
        return inventory.tip_height == static_cast<uint32_t>(pindex->nHeight) &&
               inventory.tip_hash == pindex->GetBlockHash() &&
               InventoryIsEmpty(inventory);
    }
    if (result != InventoryReadResult::MISSING) return false;

    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    if (!cursor) return false;
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) return false;
        if (!coin.IsSpent()) {
            const bool latest_marker = HasMarkerTag(coin.out.scriptPubKey, TAG_LATEST);
            if (latest_marker) {
                valtype payload;
                DemurrageLatestRecord record;
                if (ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload) &&
                    DecodeLatestPayload(payload, record) &&
                    outpoint == LatestAttestationOutpoint(record.pubkey_hash)) {
                    // A valid record at its reserved outpoint before A is stale
                    // internal state. Ordinary marker-shaped outputs at normal
                    // transaction outpoints remain ordinary UTXOs.
                    return false;
                }
            }
            if (outpoint == DemurrageInventoryOutpoint()) return false;
        }
        cursor->Next();
    }
    return WriteDemurrageInventory(view, pindex, {});
}

bool DeepAuditDemurrageInventory(const CCoinsViewCache& view,
                                 const CBlockIndex* pindex_tip,
                                 const Params& params)
{
    if (!HasCurrentDemurrageInventory(view, pindex_tip, params)) return false;
    if (!pindex_tip) return true;
    const int64_t mtp = pindex_tip->pprev
        ? pindex_tip->pprev->GetMedianTimePast()
        : pindex_tip->GetBlockTime();
    const bool active = params.IsDemurrageActive(pindex_tip->nHeight, mtp);
    const bool next_active = params.IsDemurrageActive(
        pindex_tip->nHeight + 1, pindex_tip->GetMedianTimePast());
    if (!active && !next_active) return true;

    DemurrageInventoryState inventory;
    if (ReadDemurrageInventory(view, inventory) != InventoryReadResult::VALID) return false;
    MuHash3072 reconstructed;
    uint64_t count{0};
    std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
    if (!cursor) return false;
    while (cursor->Valid()) {
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin)) return false;
        if (!coin.IsSpent()) {
            valtype payload;
            DemurrageLatestRecord latest;
            uint256 pubkey_hash;
            DemurrageAttestationState state;
            const bool latest_marker = HasMarkerTag(coin.out.scriptPubKey, TAG_LATEST);
            if (latest_marker) {
                const bool decodes = ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload) &&
                                     DecodeLatestPayload(payload, latest);
                if (decodes && outpoint == LatestAttestationOutpoint(latest.pubkey_hash)) {
                    if (!DecodeAuthenticatedDemurrageLatestState(outpoint, coin, pindex_tip,
                                                                 pubkey_hash, state)) return false;
                    if (count == std::numeric_limits<uint64_t>::max()) return false;
                    reconstructed.Insert(DemurrageStateLeaf(latest));
                    ++count;
                }
            }
            if (outpoint == DemurrageInventoryOutpoint() &&
                !IsAuthenticatedDemurrageStateOutpoint(outpoint, coin, pindex_tip)) return false;
        }
        cursor->Next();
    }
    uint256 root;
    reconstructed.Finalize(root);
    return count == inventory.live_count && root == inventory.live_root;
}

int64_t DemurrageRemainingPpm(int inactive_blocks)
{
    if (inactive_blocks <= DEMURRAGE_GRACE_BLOCKS) return DEMURRAGE_PPM;
    if (inactive_blocks >= DEMURRAGE_ZERO_BLOCKS) return 0;

    const int64_t elapsed = inactive_blocks - DEMURRAGE_GRACE_BLOCKS;
    const int64_t t_ppm = (elapsed * DEMURRAGE_PPM) / DEMURRAGE_DECAY_WINDOW_BLOCKS;
    return DEMURRAGE_PPM - ((t_ppm * t_ppm) / DEMURRAGE_PPM);
}

int64_t DemurrageRemainingPpm(int inactive_blocks, const Params& params)
{
    const int grace_blocks = params.DemurrageGraceBlocks();
    const int zero_blocks = params.DemurrageZeroBlocks();
    if (inactive_blocks <= grace_blocks) return DEMURRAGE_PPM;
    if (inactive_blocks >= zero_blocks) return 0;

    const int64_t elapsed = inactive_blocks - grace_blocks;
    const int64_t t_ppm = (elapsed * DEMURRAGE_PPM) / params.DemurrageDecayWindowBlocks();
    return DEMURRAGE_PPM - ((t_ppm * t_ppm) / DEMURRAGE_PPM);
}

CAmount DemurrageEffectiveValue(CAmount nominal_value, int64_t remaining_ppm)
{
    if (nominal_value <= 0 || remaining_ppm <= 0) return 0;
    if (remaining_ppm >= DEMURRAGE_PPM) return nominal_value;

    arith_uint256 value{static_cast<uint64_t>(nominal_value)};
    value *= static_cast<uint32_t>(remaining_ppm);
    value /= arith_uint256{static_cast<uint64_t>(DEMURRAGE_PPM)};
    if (value > arith_uint256{static_cast<uint64_t>(MAX_MONEY)}) return MAX_MONEY;
    return static_cast<CAmount>(value.GetLow64());
}

bool IsDemurrageTreasuryExemptScript(const CScript& script_pub_key, const Params& params)
{
    return std::find(params.m_demurrage_exempt_scripts.begin(), params.m_demurrage_exempt_scripts.end(), script_pub_key) !=
           params.m_demurrage_exempt_scripts.end();
}

uint256 DemurragePubKeyHash(const std::vector<unsigned char>& pubkey)
{
    uint256 out;
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(out.begin());
    return out;
}

uint256 DemurrageAttestationMessageHash(const COutPoint& replay_anchor,
                                        const COutPoint& target_outpoint,
                                        std::optional<int> previous_height,
                                        uint32_t previous_time,
                                        uint32_t previous_coverage_start_height,
                                        const std::optional<DemurrageAttestationSource>& previous_source,
                                        const std::vector<unsigned char>& pubkey,
                                        uint32_t quantum_chain_id)
{
    CHashWriter ss;
    ss << std::string("Quantum Quasar Demurrage Attestation v4");
    ss << quantum_chain_id;
    ss << replay_anchor;
    ss << target_outpoint;
    ss << (previous_height ? static_cast<uint32_t>(*previous_height) : DEMURRAGE_NO_PREVIOUS_ATTESTATION);
    ss << previous_time;
    ss << previous_coverage_start_height;
    ss << previous_source.has_value();
    if (previous_source) {
        ss << previous_source->block_hash << previous_source->txid
           << previous_source->output_index;
    } else {
        ss << uint256{} << uint256{} << uint32_t{0};
    }
    ss << pubkey;
    return ss.GetHash();
}

std::vector<unsigned char> EncodeDemurrageAttestationPayload(const COutPoint& replay_anchor,
                                                              const COutPoint& target_outpoint,
                                                              std::optional<int> previous_height,
                                                              uint32_t previous_time,
                                                              uint32_t previous_coverage_start_height,
                                                              const std::optional<DemurrageAttestationSource>& previous_source,
                                                              const std::vector<unsigned char>& pubkey,
                                                              const std::vector<unsigned char>& signature)
{
    if (pubkey.size() != ML_DSA::PUBLICKEY_BYTES || signature.size() != ML_DSA::SIGNATURE_BYTES ||
        previous_height.has_value() != previous_source.has_value() ||
        (!previous_height && (previous_time != 0 || previous_coverage_start_height != 0)) ||
        (previous_height && (*previous_height < 0 ||
                             previous_coverage_start_height > static_cast<uint32_t>(*previous_height))) ||
        (previous_source && (previous_source->block_hash.IsNull() || previous_source->txid.IsNull()))) return {};
    std::vector<unsigned char> payload(1 + (2 * (uint256::size() + sizeof(uint32_t))) +
                                       (3 * sizeof(uint32_t)) + 1 + (2 * uint256::size()) + sizeof(uint32_t) +
                                       ML_DSA::PUBLICKEY_BYTES +
                                       ML_DSA::SIGNATURE_BYTES);
    payload[0] = DEMURRAGE_ATTESTATION_VERSION;
    auto cursor = payload.begin() + 1;
    cursor = std::copy(replay_anchor.hash.begin(), replay_anchor.hash.end(), cursor);
    WriteLE32(&*cursor, replay_anchor.n);
    cursor += sizeof(uint32_t);
    cursor = std::copy(target_outpoint.hash.begin(), target_outpoint.hash.end(), cursor);
    WriteLE32(&*cursor, target_outpoint.n);
    cursor += sizeof(uint32_t);
    WriteLE32(&*cursor, previous_height ? static_cast<uint32_t>(*previous_height) : DEMURRAGE_NO_PREVIOUS_ATTESTATION);
    cursor += sizeof(uint32_t);
    WriteLE32(&*cursor, previous_time);
    cursor += sizeof(uint32_t);
    WriteLE32(&*cursor, previous_coverage_start_height);
    cursor += sizeof(uint32_t);
    *cursor++ = previous_source ? 1 : 0;
    if (previous_source) {
        cursor = std::copy(previous_source->block_hash.begin(), previous_source->block_hash.end(), cursor);
        cursor = std::copy(previous_source->txid.begin(), previous_source->txid.end(), cursor);
        WriteLE32(&*cursor, previous_source->output_index);
    } else {
        cursor = std::fill_n(cursor, 2 * uint256::size(), 0);
        WriteLE32(&*cursor, 0);
    }
    cursor += sizeof(uint32_t);
    cursor = std::copy(pubkey.begin(), pubkey.end(), cursor);
    std::copy(signature.begin(), signature.end(), cursor);
    return payload;
}

CScript BuildDemurrageAttestationScript(const COutPoint& replay_anchor,
                                         const COutPoint& target_outpoint,
                                         std::optional<int> previous_height,
                                         uint32_t previous_time,
                                         uint32_t previous_coverage_start_height,
                                         const std::optional<DemurrageAttestationSource>& previous_source,
                                         const std::vector<unsigned char>& pubkey,
                                         const std::vector<unsigned char>& signature)
{
    return CScript() << OP_RETURN << TAG_ATTEST << EncodeDemurrageAttestationPayload(
        replay_anchor, target_outpoint, previous_height, previous_time,
        previous_coverage_start_height, previous_source, pubkey, signature);
}

bool IsDemurrageAttestationScript(const CScript& script_pub_key)
{
    valtype payload;
    DemurrageAttestation attestation;
    return ParseAttestationScript(script_pub_key, payload) && DecodeDemurrageAttestationPayload(payload, attestation);
}

bool DecodeDemurrageAttestationPayload(const std::vector<unsigned char>& payload, DemurrageAttestation& attestation)
{
    static constexpr size_t EXPECTED_SIZE = 1 + (2 * (uint256::size() + sizeof(uint32_t))) +
                                            (3 * sizeof(uint32_t)) + 1 + (2 * uint256::size()) + sizeof(uint32_t) +
                                            ML_DSA::PUBLICKEY_BYTES +
                                            ML_DSA::SIGNATURE_BYTES;
    if (payload.size() != EXPECTED_SIZE || payload[0] != DEMURRAGE_ATTESTATION_VERSION) return false;

    attestation = {};
    auto cursor = payload.begin() + 1;
    std::copy(cursor, cursor + uint256::size(), attestation.replay_anchor.hash.begin());
    cursor += uint256::size();
    attestation.replay_anchor.n = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    std::copy(cursor, cursor + uint256::size(), attestation.target_outpoint.hash.begin());
    cursor += uint256::size();
    attestation.target_outpoint.n = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    const uint32_t raw_previous_height = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    attestation.previous_height = raw_previous_height == DEMURRAGE_NO_PREVIOUS_ATTESTATION
        ? std::optional<int>{}
        : std::optional<int>{static_cast<int>(raw_previous_height)};
    attestation.previous_time = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    attestation.previous_coverage_start_height = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    const uint8_t previous_source_present = *cursor++;
    if (previous_source_present > 1) return false;
    DemurrageAttestationSource previous_source;
    std::copy(cursor, cursor + uint256::size(), previous_source.block_hash.begin());
    cursor += uint256::size();
    std::copy(cursor, cursor + uint256::size(), previous_source.txid.begin());
    cursor += uint256::size();
    previous_source.output_index = ReadLE32(&*cursor);
    cursor += sizeof(uint32_t);
    if (previous_source_present) attestation.previous_source = previous_source;
    if (attestation.previous_height.has_value() != attestation.previous_source.has_value() ||
        (!attestation.previous_height && (attestation.previous_time != 0 ||
                                          attestation.previous_coverage_start_height != 0 ||
                                          !previous_source.block_hash.IsNull() ||
                                          !previous_source.txid.IsNull() || previous_source.output_index != 0)) ||
        (attestation.previous_height && (*attestation.previous_height < 0 ||
                                         attestation.previous_coverage_start_height > static_cast<uint32_t>(*attestation.previous_height) ||
                                         previous_source.block_hash.IsNull() || previous_source.txid.IsNull()))) return false;
    attestation.pubkey.assign(cursor, cursor + ML_DSA::PUBLICKEY_BYTES);
    cursor += ML_DSA::PUBLICKEY_BYTES;
    attestation.signature.assign(cursor, cursor + ML_DSA::SIGNATURE_BYTES);
    attestation.pubkey_hash = DemurragePubKeyHash(attestation.pubkey);
    return true;
}

std::vector<DemurrageAttestation> ExtractDemurrageAttestations(const CTransaction& tx)
{
    std::vector<DemurrageAttestation> attestations;
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        valtype payload;
        if (!ParseAttestationScript(tx.vout[i].scriptPubKey, payload)) continue;
        DemurrageAttestation attestation;
        if (!DecodeDemurrageAttestationPayload(payload, attestation) ||
            tx.IsCoinBase() ||
            tx.vin.empty() ||
            attestation.replay_anchor.IsNull() ||
            attestation.target_outpoint.IsNull() ||
            attestation.target_outpoint == attestation.replay_anchor ||
            attestation.replay_anchor != tx.vin.front().prevout) {
            attestation.height = -1;
        }
        attestation.output_index = i;
        attestations.push_back(std::move(attestation));
    }
    return attestations;
}

bool CheckDemurrageAttestations(const CTransaction& tx,
                                const CCoinsViewCache& view,
                                const Params& params,
                                int spend_height,
                                int64_t spend_time,
                                std::set<uint256>& attested_keys,
                                size_t& attestation_count,
                                std::string& reject_reason)
{
    if (!params.IsDemurrageActive(spend_height, spend_time)) return true;
    if (params.nQuantumSighashChainId == 0) {
        reject_reason = "bad-demurrage-chain-id";
        return false;
    }

    const std::vector<DemurrageAttestation> attestations = ExtractDemurrageAttestations(tx);
    if (attestations.size() > MAX_DEMURRAGE_ATTESTATIONS_PER_TX) {
        reject_reason = "too-many-demurrage-attestations-tx";
        return false;
    }
    if (attestation_count > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK ||
        attestations.size() > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK - attestation_count) {
        reject_reason = "too-many-demurrage-attestations-block";
        return false;
    }

    // Work on temporary state so a rejected transaction cannot consume a
    // block/package slot or reserve a key for later candidates.
    std::set<uint256> next_keys{attested_keys};
    for (const DemurrageAttestation& attestation : attestations) {
        if (attestation.height < 0) {
            reject_reason = "bad-demurrage-attestation";
            return false;
        }
        if (!next_keys.insert(attestation.pubkey_hash).second) {
            reject_reason = "duplicate-demurrage-attestation";
            return false;
        }
        const uint256 msg_hash = DemurrageAttestationMessageHash(
            attestation.replay_anchor, attestation.target_outpoint,
            attestation.previous_height, attestation.previous_time,
            attestation.previous_coverage_start_height,
            attestation.previous_source,
            attestation.pubkey, params.nQuantumSighashChainId);
        if (!ML_DSA::Verify(attestation.pubkey, msg_hash.begin(), uint256::size(), attestation.signature)) {
            reject_reason = "bad-demurrage-attestation-signature";
            return false;
        }
        if (std::any_of(tx.vin.begin(), tx.vin.end(), [&](const CTxIn& txin) {
                return txin.prevout == attestation.target_outpoint;
            })) {
            reject_reason = "demurrage-attestation-target-conflict";
            return false;
        }
        Coin target_coin;
        if (!view.GetCoin(attestation.target_outpoint, target_coin) || target_coin.IsSpent()) {
            reject_reason = "bad-demurrage-attestation-target";
            return false;
        }
        const std::optional<uint256> controlling_key = DemurrageControllingKeyHashForScript(target_coin.out.scriptPubKey);
        if (!controlling_key || *controlling_key != attestation.pubkey_hash) {
            reject_reason = "bad-demurrage-attestation-target";
            return false;
        }
        DemurrageLatestRecord previous_record;
        const LatestReadResult previous_read = ReadLatestRecord(
            view, attestation.pubkey_hash, previous_record);
        if (previous_read == LatestReadResult::INVALID) {
            reject_reason = "local-demurrage-state-inconsistent";
            return false;
        }
        const std::optional<DemurrageAttestationState> previous_state =
            previous_read == LatestReadResult::VALID
                ? std::optional<DemurrageAttestationState>{previous_record.state}
                : std::nullopt;
        if (previous_state.has_value() != attestation.previous_height.has_value() ||
            (previous_state && (previous_state->height != *attestation.previous_height ||
                                previous_state->time != attestation.previous_time ||
                                previous_state->coverage_start_height != attestation.previous_coverage_start_height)) ||
            ((previous_read == LatestReadResult::VALID) != attestation.previous_source.has_value()) ||
            (previous_read == LatestReadResult::VALID &&
             (previous_record.source_block_hash != attestation.previous_source->block_hash ||
              previous_record.source_txid != attestation.previous_source->txid ||
              previous_record.source_output_index != attestation.previous_source->output_index)) ||
            (!previous_state && (attestation.previous_time != 0 ||
                                 attestation.previous_coverage_start_height != 0))) {
            reject_reason = "stale-demurrage-attestation-state";
            return false;
        }
        const DemurrageEvaluation target_evaluation = EvaluateDemurrage(
            target_coin, params, spend_height, spend_time,
            previous_state ? std::optional<int>{previous_state->height} : std::nullopt,
            previous_state ? std::optional<int>{static_cast<int>(previous_state->coverage_start_height)} : std::nullopt);
        if (target_evaluation.locked) {
            reject_reason = "demurrage-attestation-target-locked";
            return false;
        }
        if (previous_state && spend_height - previous_state->height < params.DemurrageAutoAttestBlocks()) {
            reject_reason = "demurrage-attestation-too-soon";
            return false;
        }
    }

    attested_keys = std::move(next_keys);
    attestation_count += attestations.size();
    return true;
}

std::optional<uint256> DemurrageControllingKeyHashForScript(const CScript& script_pub_key)
{
    int witness_version{0};
    std::vector<unsigned char> witness_program;
    if (!script_pub_key.IsWitnessProgram(witness_version, witness_program)) return std::nullopt;
    QuantumStakeTierProgram tier;
    if (!DecodeQuantumStakeTierProgram(static_cast<unsigned int>(witness_version), witness_program, tier) || tier.cold_stake) {
        return std::nullopt;
    }
    return tier.commitment;
}

std::optional<int> LatestDemurrageAttestationHeight(const CCoinsViewCache& view, const uint256& pubkey_hash)
{
    const std::optional<DemurrageAttestationState> state = LatestDemurrageAttestationState(view, pubkey_hash);
    if (!state) return std::nullopt;
    return state->height;
}

std::optional<DemurrageAttestationState> LatestDemurrageAttestationState(const CCoinsViewCache& view, const uint256& pubkey_hash)
{
    const auto record = LatestDemurrageAttestationRecord(view, pubkey_hash);
    return record ? std::optional<DemurrageAttestationState>{record->state} : std::nullopt;
}

std::optional<DemurrageAttestationRecord> LatestDemurrageAttestationRecord(const CCoinsViewCache& view, const uint256& pubkey_hash)
{
    DemurrageLatestRecord record;
    if (ReadLatestRecord(view, pubkey_hash, record) != LatestReadResult::VALID) return std::nullopt;
    return record;
}

std::optional<int> LatestDemurrageAttestationHeightForScript(const CCoinsViewCache& view, const CScript& script_pub_key)
{
    const std::optional<DemurrageAttestationState> state = LatestDemurrageAttestationStateForScript(view, script_pub_key);
    return state ? std::optional<int>{state->height} : std::nullopt;
}

std::optional<DemurrageAttestationState> LatestDemurrageAttestationStateForScript(const CCoinsViewCache& view, const CScript& script_pub_key)
{
    const std::optional<uint256> key_hash = DemurrageControllingKeyHashForScript(script_pub_key);
    if (!key_hash) return std::nullopt;
    return LatestDemurrageAttestationState(view, *key_hash);
}

bool IsDemurrageStateSaneForScript(const CCoinsViewCache& view,
                                   const CScript& script_pub_key)
{
    const std::optional<uint256> key_hash = DemurrageControllingKeyHashForScript(script_pub_key);
    if (!key_hash) return true;
    DemurrageLatestRecord record;
    return ReadLatestRecord(view, *key_hash, record) != LatestReadResult::INVALID;
}

bool IsAuthenticatedDemurrageStateOutpoint(const COutPoint& outpoint, const Coin& coin, const CBlockIndex* pindex_tip)
{
    if (!pindex_tip || coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.nHeight > static_cast<uint32_t>(pindex_tip->nHeight)) return false;
    const CBlockIndex* marker_block = pindex_tip->GetAncestor(static_cast<int>(coin.nHeight));
    if (!marker_block) return false;
    if (outpoint == DemurrageInventoryOutpoint()) {
        DemurrageInventoryState inventory;
        return coin.nTime == static_cast<uint32_t>(marker_block->GetBlockTime()) &&
               DecodeDemurrageInventory(coin.out.scriptPubKey, inventory) &&
               inventory.tip_height == coin.nHeight &&
               inventory.tip_hash == marker_block->GetBlockHash();
    }

    valtype payload;
    if (ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload)) {
        uint256 pubkey_hash;
        DemurrageAttestationState state;
        return DecodeAuthenticatedDemurrageLatestState(outpoint, coin, pindex_tip, pubkey_hash, state);
    }
    if (ParseMarkerScript(coin.out.scriptPubKey, TAG_UNDO, &payload)) return false;
    return false;
}

bool DecodeAuthenticatedDemurrageLatestState(const COutPoint& outpoint, const Coin& coin,
                                             const CBlockIndex* pindex_tip, uint256& pubkey_hash,
                                             DemurrageAttestationState& state)
{
    if (!pindex_tip || coin.out.nValue != 0 || !coin.fCoinBase || coin.fCoinStake ||
        coin.nHeight > static_cast<uint32_t>(pindex_tip->nHeight) ||
        !pindex_tip->GetAncestor(static_cast<int>(coin.nHeight))) {
        return false;
    }
    valtype payload;
    DemurrageLatestRecord record;
    if (!ParseMarkerScript(coin.out.scriptPubKey, TAG_LATEST, &payload) ||
        !DecodeLatestPayload(payload, record)) return false;
    const CBlockIndex* source_block = pindex_tip->GetAncestor(record.state.height);
    if (!source_block || source_block->GetBlockHash() != record.source_block_hash ||
        coin.nHeight != static_cast<uint32_t>(record.state.height) ||
        coin.nTime != record.state.time ||
        coin.nTime != static_cast<uint32_t>(source_block->GetBlockTime()) ||
        outpoint != LatestAttestationOutpoint(record.pubkey_hash)) return false;
    pubkey_hash = record.pubkey_hash;
    state = record.state;
    return true;
}

bool PurgeAuthenticatedDemurrageState(CCoinsViewCache& view, const CBlockIndex* pindex_tip, uint64_t& removed)
{
    std::vector<COutPoint> authenticated;
    {
        std::unique_ptr<CCoinsViewCursor> cursor(view.Cursor());
        while (cursor->Valid()) {
            COutPoint outpoint;
            Coin coin;
            if (cursor->GetKey(outpoint) && cursor->GetValue(coin) && !coin.IsSpent() &&
                IsAuthenticatedDemurrageStateOutpoint(outpoint, coin, pindex_tip)) {
                authenticated.push_back(outpoint);
            }
            cursor->Next();
        }
    }

    removed = 0;
    for (const COutPoint& outpoint : authenticated) {
        if (view.SpendCoin(outpoint)) ++removed;
    }
    return true;
}

bool ApplyDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params, std::string& reject_reason)
{
    if (!pindex) return true;
    const int64_t block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
    if (!params.IsDemurrageActive(pindex->nHeight, block_mtp)) return true;

    DemurrageInventoryState inventory;
    const InventoryReadResult inventory_result = ReadDemurrageInventory(view, inventory);
    if (!InventoryAnchoredForApply(inventory, inventory_result, pindex, params)) {
        reject_reason = "local-demurrage-inventory-inconsistent";
        return false;
    }

    std::vector<std::pair<CTransactionRef, std::vector<DemurrageAttestation>>> block_attestations;
    size_t raw_attestation_count{0};
    for (const CTransactionRef& tx : block.vtx) {
        const size_t tx_count = ExtractDemurrageAttestations(*tx).size();
        if (tx_count > MAX_DEMURRAGE_ATTESTATIONS_PER_TX) {
            reject_reason = "too-many-demurrage-attestations-tx";
            return false;
        }
        if (raw_attestation_count > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK ||
            tx_count > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK - raw_attestation_count) {
            reject_reason = "too-many-demurrage-attestations-block";
            return false;
        }
        raw_attestation_count += tx_count;
    }

    std::set<uint256> attested_keys;
    size_t attestation_count{0};
    for (const CTransactionRef& tx : block.vtx) {
        if (!CheckDemurrageAttestations(*tx, view, params, pindex->nHeight, block_mtp,
                                        attested_keys, attestation_count, reject_reason)) {
            return false;
        }
        std::vector<DemurrageAttestation> attestations = ExtractDemurrageAttestations(*tx);
        if (!attestations.empty()) block_attestations.emplace_back(tx, std::move(attestations));
    }

    for (const auto& [tx, attestations] : block_attestations) {
        for (const DemurrageAttestation& attestation : attestations) {
            if (!ApplyAttestationInventoryTransition(view, inventory, attestation, tx->GetHash(),
                                                     pindex, params)) {
                reject_reason = "local-demurrage-inventory-inconsistent";
                return false;
            }
        }
    }
    if (!WriteDemurrageInventory(view, pindex, std::move(inventory))) {
        reject_reason = "local-demurrage-inventory-inconsistent";
        return false;
    }
    return true;
}

bool RollforwardDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params)
{
    if (!pindex) return true;
    const int64_t block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
    if (!params.IsDemurrageActive(pindex->nHeight, block_mtp)) {
        return PrepareDemurrageActivationInventory(view, pindex, params);
    }
    if (params.nQuantumSighashChainId == 0) return false;

    DemurrageInventoryState inventory;
    const InventoryReadResult inventory_result = ReadDemurrageInventory(view, inventory);
    if (inventory_result == InventoryReadResult::VALID &&
        inventory.tip_height == static_cast<uint32_t>(pindex->nHeight) &&
        inventory.tip_hash == pindex->GetBlockHash()) {
        return true;
    }
    if (!InventoryAnchoredForApply(inventory, inventory_result, pindex, params)) return false;

    // ReplayBlocks is repairing an already-validated block after a partial
    // CoinsDB flush. Require the exact predecessor inventory and derive this
    // block's state transition from its signed attestations.
    std::set<uint256> keys;
    size_t count{0};
    for (const CTransactionRef& tx : block.vtx) {
        const std::vector<DemurrageAttestation> attestations = ExtractDemurrageAttestations(*tx);
        if (attestations.size() > MAX_DEMURRAGE_ATTESTATIONS_PER_TX ||
            count > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK ||
            attestations.size() > MAX_DEMURRAGE_ATTESTATIONS_PER_BLOCK - count) {
            return false;
        }
        count += attestations.size();
        for (const DemurrageAttestation& attestation : attestations) {
            if (attestation.height < 0 || !keys.insert(attestation.pubkey_hash).second ||
                (attestation.previous_height &&
                 (*attestation.previous_height < 0 || *attestation.previous_height >= pindex->nHeight ||
                  attestation.previous_coverage_start_height > static_cast<uint32_t>(*attestation.previous_height))) ||
                (!attestation.previous_height &&
                 (attestation.previous_time != 0 || attestation.previous_coverage_start_height != 0))) {
                return false;
            }
            const uint256 msg_hash = DemurrageAttestationMessageHash(
                attestation.replay_anchor, attestation.target_outpoint,
                attestation.previous_height, attestation.previous_time,
                attestation.previous_coverage_start_height, attestation.previous_source,
                attestation.pubkey,
                params.nQuantumSighashChainId);
            if (!ML_DSA::Verify(attestation.pubkey, msg_hash.begin(), uint256::size(), attestation.signature)) {
                return false;
            }
            if (!ApplyAttestationInventoryTransition(view, inventory, attestation, tx->GetHash(),
                                                     pindex, params)) return false;
        }
    }
    return WriteDemurrageInventory(view, pindex, std::move(inventory));
}

bool UndoDemurrageBlock(CCoinsViewCache& view, const CBlock& block, const CBlockIndex* pindex, const Params& params)
{
    if (!pindex) return true;
    const int64_t block_mtp = pindex->pprev ? pindex->pprev->GetMedianTimePast() : pindex->GetBlockTime();
    if (!params.IsDemurrageActive(pindex->nHeight, block_mtp)) {
        const bool next_active = params.IsDemurrageActive(
            pindex->nHeight + 1, pindex->GetMedianTimePast());
        if (!next_active) return true;
        DemurrageInventoryState sentinel;
        Coin sentinel_coin;
        if (ReadDemurrageInventory(view, sentinel, &sentinel_coin) != InventoryReadResult::VALID ||
            sentinel.tip_height != static_cast<uint32_t>(pindex->nHeight) ||
            sentinel.tip_hash != pindex->GetBlockHash() ||
            sentinel_coin.nTime != static_cast<uint32_t>(pindex->GetBlockTime()) ||
            !InventoryIsEmpty(sentinel)) return false;
        return view.SpendCoin(DemurrageInventoryOutpoint());
    }

    DemurrageInventoryState inventory;
    if (ReadDemurrageInventory(view, inventory) != InventoryReadResult::VALID ||
        inventory.tip_height != static_cast<uint32_t>(pindex->nHeight) ||
        inventory.tip_hash != pindex->GetBlockHash()) return false;

    for (auto tx_it = block.vtx.rbegin(); tx_it != block.vtx.rend(); ++tx_it) {
        const CTransactionRef& tx = *tx_it;
        std::vector<DemurrageAttestation> attestations = ExtractDemurrageAttestations(*tx);
        for (auto att_it = attestations.rbegin(); att_it != attestations.rend(); ++att_it) {
            const DemurrageAttestation& attestation = *att_it;
            if (attestation.height < 0) return false;
            const COutPoint latest_outpoint = LatestAttestationOutpoint(attestation.pubkey_hash);
            DemurrageLatestRecord current;
            if (ReadLatestRecord(view, attestation.pubkey_hash, current) != LatestReadResult::VALID ||
                current.state.height != pindex->nHeight ||
                current.state.time != static_cast<uint32_t>(pindex->GetBlockTime()) ||
                current.state.coverage_start_height != AttestationCoverageStart(attestation, pindex, params) ||
                current.source_block_hash != pindex->GetBlockHash() ||
                current.source_txid != tx->GetHash() ||
                current.source_output_index != attestation.output_index) {
                return false;
            }
            inventory.live_set.Remove(DemurrageStateLeaf(current));
            if (attestation.previous_height) {
                if (!attestation.previous_source) return false;
                DemurrageLatestRecord previous;
                previous.pubkey_hash = attestation.pubkey_hash;
                previous.state = DemurrageAttestationState{
                    *attestation.previous_height, attestation.previous_time,
                    attestation.previous_coverage_start_height};
                previous.source_block_hash = attestation.previous_source->block_hash;
                previous.source_txid = attestation.previous_source->txid;
                previous.source_output_index = attestation.previous_source->output_index;
                if (previous.state.height < 0 || previous.state.height >= pindex->nHeight ||
                    previous.state.coverage_start_height > static_cast<uint32_t>(previous.state.height) ||
                    previous.source_block_hash.IsNull() || previous.source_txid.IsNull()) return false;
                const CBlockIndex* source_block = pindex->pprev
                    ? pindex->pprev->GetAncestor(previous.state.height)
                    : nullptr;
                if (!source_block || source_block->GetBlockHash() != previous.source_block_hash ||
                    previous.state.time != static_cast<uint32_t>(source_block->GetBlockTime())) return false;
                inventory.live_set.Insert(DemurrageStateLeaf(previous));
                view.AddCoin(latest_outpoint,
                             MarkerCoin(0, MarkerScript(TAG_LATEST,
                                                       EncodeLatestPayload(previous)),
                                        previous.state.height,
                                        previous.state.time),
                             /*possible_overwrite=*/true);
            } else {
                if (attestation.previous_source || attestation.previous_time != 0 ||
                    attestation.previous_coverage_start_height != 0) return false;
                view.SpendCoin(latest_outpoint);
                if (inventory.live_count == 0) return false;
                --inventory.live_count;
            }
        }
    }
    const int64_t previous_mtp = pindex->pprev
        ? (pindex->pprev->pprev ? pindex->pprev->pprev->GetMedianTimePast()
                                : pindex->pprev->GetBlockTime())
        : 0;
    if (!pindex->pprev || !params.IsDemurrageActive(pindex->pprev->nHeight, previous_mtp)) {
        if (!pindex->pprev || !InventoryIsEmpty(inventory)) return false;
        return WriteDemurrageInventory(view, pindex->pprev, {});
    }
    return WriteDemurrageInventory(view, pindex->pprev, std::move(inventory));
}

CAmount GetDemurrageAdjustedValueIn(const CTransaction& tx, const CCoinsViewCache& inputs, const Params& params, int spend_height, int64_t spend_time)
{
    if (tx.IsCoinBase()) return 0;

    CAmount n_result = 0;
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = inputs.AccessCoin(txin.prevout);
        const std::optional<DemurrageAttestationState> latest_attestation =
            LatestDemurrageAttestationStateForScript(inputs, coin.out.scriptPubKey);
        const DemurrageEvaluation eval = EvaluateDemurrage(
            coin, params, spend_height, spend_time,
            latest_attestation ? std::optional<int>{latest_attestation->height} : std::nullopt,
            latest_attestation ? std::optional<int>{static_cast<int>(latest_attestation->coverage_start_height)} : std::nullopt);
        n_result += eval.effective_value;
    }
    return n_result;
}

DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time)
{
    return EvaluateDemurrage(coin, params, spend_height, spend_time, std::nullopt, std::nullopt);
}

DemurrageEvaluation EvaluateDemurrage(
    const Coin& coin,
    const Params& params,
    int spend_height,
    int64_t spend_time,
    std::optional<int> latest_attestation_height,
    std::optional<int> attestation_coverage_start_height)
{
    DemurrageEvaluation eval;
    eval.nominal_value = coin.out.nValue;
    eval.effective_value = coin.out.nValue;

    if (!params.IsDemurrageActive(spend_height, spend_time)) {
        eval.exemption = "inactive";
        return eval;
    }
    eval.active = true;

    if (IsDemurrageTreasuryExemptScript(coin.out.scriptPubKey, params)) {
        eval.exempt = true;
        eval.exemption = "treasury";
        return eval;
    }

    // Value-bearing EUTXO and quantum cold-stake state are permitted after
    // Final activation and must not become permanent demurrage shelters. Their
    // activity is expressed by spending/recreating the state output (including
    // an actual coinstake); unlike a direct quantum key they have no separate
    // liveness-attestation identity.
    if (!IsQuantumMigrationScript(coin.out.scriptPubKey) &&
        !IsQuantumColdStakeScript(coin.out.scriptPubKey) &&
        !IsEUTXOScript(coin.out.scriptPubKey)) {
        eval.exempt = true;
        eval.exemption = "non_quantum";
        return eval;
    }

    const int activity_start = std::max<int>(coin.nHeight, params.EffectiveDemurrageActivationHeight());
    int effective_last_active = activity_start;
    const bool attestation_covers_coin = latest_attestation_height &&
        attestation_coverage_start_height &&
        *latest_attestation_height <= spend_height &&
        static_cast<int64_t>(*attestation_coverage_start_height) - activity_start < params.DemurrageZeroBlocks();
    if (attestation_covers_coin) {
        effective_last_active = std::max(effective_last_active, *latest_attestation_height);
    }
    eval.inactive_blocks = std::max(0, spend_height - effective_last_active);

    if (eval.inactive_blocks <= params.DemurrageGraceBlocks()) {
        eval.exempt = true;
        eval.exemption = attestation_covers_coin && *latest_attestation_height >= effective_last_active ? "attested" : "young";
        return eval;
    }

    eval.remaining_ppm = DemurrageRemainingPpm(eval.inactive_blocks, params);
    eval.locked = eval.remaining_ppm == 0;
    eval.effective_value = DemurrageEffectiveValue(eval.nominal_value, eval.remaining_ppm);
    eval.burned_value = eval.nominal_value - eval.effective_value;
    return eval;
}

} // namespace Consensus
