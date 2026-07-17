// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Deterministic physical LevelDB workload for the complete mainnet Gold Rush.
//
// This is deliberately a byte-exact storage fixture, not a synthetic
// blockchain and not evidence about the current live chain. Consensus and
// provenance equivalence remain covered by the source-bound maximum-block,
// replay, reorg, RPC, and live-snapshot gates. This executable supplies the
// otherwise unavailable completed-epoch SST/WAL/compaction envelope now.

#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <leveldb/filter_policy.h>
#include <leveldb/iterator.h>
#include <leveldb/options.h>
#include <leveldb/write_batch.h>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

constexpr uint32_t START_HEIGHT{5'950'000};
constexpr uint32_t CLAIM_BOUNDARY_HEIGHT{5'993'200};
constexpr uint32_t END_HEIGHT{6'192'999};
constexpr uint64_t GOLD_RUSH_BLOCKS{243'000};
constexpr uint64_t LEGACY_BLOCKS{43'200};
constexpr uint64_t CANONICAL_BLOCKS{199'800};
constexpr uint64_t WHITELIST_ENTRIES{687};
constexpr uint64_t LEGACY_CLAIMS_PER_BLOCK{688};
constexpr uint64_t CANONICAL_CLAIMS_PER_BLOCK{751};
constexpr uint64_t ISSUED_CLAIMS{179'771'400};
constexpr uint64_t CLAIM_FAMILY_RECORDS{539'314'200};
constexpr uint64_t NON_SOLVER_FIXED_RECORDS{8};
constexpr uint64_t FIXED_RECORDS_PER_BLOCK{9};
constexpr uint64_t LOGICAL_PROOF_BUCKET_RECORDS{CANONICAL_BLOCKS};
constexpr uint64_t LOGICAL_PROOF_BUCKET_WINDOW{64};
constexpr uint64_t LOGICAL_PROOF_BUCKET_BASE{
    CLAIM_FAMILY_RECORDS + GOLD_RUSH_BLOCKS * FIXED_RECORDS_PER_BLOCK};
constexpr uint64_t TOTAL_RECORDS{
    LOGICAL_PROOF_BUCKET_BASE + LOGICAL_PROOF_BUCKET_RECORDS};
constexpr uint64_t RETAINED_LOGICAL_BYTES{103'622'484'600ULL};
constexpr uint64_t AUTHENTICATION_SEQUENTIAL_RECORDS{TOTAL_RECORDS * 2};
constexpr uint64_t PAYOUT_POINT_LOOKUPS{ISSUED_CLAIMS};
constexpr uint64_t ATTESTATION_POINT_LOOKUPS{ISSUED_CLAIMS};
constexpr uint64_t LOGICAL_PROOF_BUCKET_POINT_LOOKUPS{
    LOGICAL_PROOF_BUCKET_WINDOW * (LOGICAL_PROOF_BUCKET_WINDOW + 1) / 2 +
    (CANONICAL_BLOCKS - LOGICAL_PROOF_BUCKET_WINDOW) *
        LOGICAL_PROOF_BUCKET_WINDOW};
constexpr uint64_t AUTHENTICATION_POINT_LOOKUPS{
    PAYOUT_POINT_LOOKUPS + ATTESTATION_POINT_LOOKUPS +
    LOGICAL_PROOF_BUCKET_POINT_LOOKUPS};
constexpr size_t COIN_KEY_BYTES{34};
constexpr size_t LEVELDB_CACHE_BYTES{4U << 20};
constexpr size_t LEVELDB_WRITE_BUFFER_BYTES{2U << 20};
constexpr std::string_view STATE_KEY{"\x00blackcoin.qq.resource.state", 28};
constexpr std::string_view CONTRACT_ID{
    "blackcoin.qq.shadow.synthetic-full-epoch.leveldb.v3"};

static_assert(CLAIM_BOUNDARY_HEIGHT - START_HEIGHT == LEGACY_BLOCKS);
static_assert(END_HEIGHT - START_HEIGHT + 1 == GOLD_RUSH_BLOCKS);
static_assert(GOLD_RUSH_BLOCKS - LEGACY_BLOCKS == CANONICAL_BLOCKS);
static_assert(LEGACY_BLOCKS * LEGACY_CLAIMS_PER_BLOCK +
                  CANONICAL_BLOCKS * CANONICAL_CLAIMS_PER_BLOCK ==
              ISSUED_CLAIMS);
static_assert(ISSUED_CLAIMS * 3 == CLAIM_FAMILY_RECORDS);
static_assert(LOGICAL_PROOF_BUCKET_POINT_LOOKUPS == 12'785'184);

enum class RecordKind : uint8_t {
    CLAIM = 1,
    PAYOUT = 2,
    PROVENANCE = 3,
    ACTIVE_MANIFEST = 4,
    ACTIVE_SHARD_FULL = 5,
    ACTIVE_SHARD_LAST = 6,
    POOL_UNDO = 7,
    SOLVER = 8,
    LOGICAL_PROOF_BUCKET = 9,
};

struct RecordSpec {
    RecordKind kind;
    size_t value_bytes;
    uint64_t logical_bytes;
};

constexpr std::array<RecordSpec, 3> CLAIM_RECORDS{{
    {RecordKind::CLAIM, 167, 205},
    {RecordKind::PAYOUT, 52, 89},
    {RecordKind::PROVENANCE, 177, 215},
}};
constexpr std::array<RecordSpec, NON_SOLVER_FIXED_RECORDS> FIXED_RECORDS{{
    {RecordKind::ACTIVE_MANIFEST, 127, 164},
    {RecordKind::ACTIVE_SHARD_FULL, 8069, 8107},
    {RecordKind::ACTIVE_SHARD_FULL, 8069, 8107},
    {RecordKind::ACTIVE_SHARD_FULL, 8069, 8107},
    {RecordKind::ACTIVE_SHARD_FULL, 8069, 8107},
    {RecordKind::ACTIVE_SHARD_FULL, 8069, 8107},
    {RecordKind::ACTIVE_SHARD_LAST, 6959, 6997},
    {RecordKind::POOL_UNDO, 278, 316},
}};
constexpr RecordSpec SOLVER_RECORD{RecordKind::SOLVER, 55, 92};
// Maximum QQPROOFS bucket: 2,086-byte payload, 2,100-byte marker script,
// 2,112-byte Coin value, and a 2,150-byte CoinEntry/CDBBatch put.
constexpr RecordSpec LOGICAL_PROOF_BUCKET_RECORD{
    RecordKind::LOGICAL_PROOF_BUCKET, 2'112, 2'150};
constexpr uint64_t CLAIM_FAMILY_LOGICAL_BYTES{509};
constexpr uint64_t FIXED_BLOCK_LOGICAL_BYTES{47'696 + 316 + 92};
static_assert(CLAIM_RECORDS[0].logical_bytes +
                  CLAIM_RECORDS[1].logical_bytes +
                  CLAIM_RECORDS[2].logical_bytes ==
              CLAIM_FAMILY_LOGICAL_BYTES);
static_assert(FIXED_RECORDS[0].logical_bytes +
                  FIXED_RECORDS[1].logical_bytes +
                  FIXED_RECORDS[2].logical_bytes +
                  FIXED_RECORDS[3].logical_bytes +
                  FIXED_RECORDS[4].logical_bytes +
                  FIXED_RECORDS[5].logical_bytes +
                  FIXED_RECORDS[6].logical_bytes +
                  FIXED_RECORDS[7].logical_bytes +
                  SOLVER_RECORD.logical_bytes ==
              FIXED_BLOCK_LOGICAL_BYTES);
static_assert(ISSUED_CLAIMS * CLAIM_FAMILY_LOGICAL_BYTES +
                  GOLD_RUSH_BLOCKS * FIXED_BLOCK_LOGICAL_BYTES +
                  LOGICAL_PROOF_BUCKET_RECORDS *
                      LOGICAL_PROOF_BUCKET_RECORD.logical_bytes ==
              RETAINED_LOGICAL_BYTES);

struct State {
    std::string phase{"empty"};
    int64_t height{static_cast<int64_t>(START_HEIGHT) - 1};
};

[[noreturn]] void Fail(const std::string& message)
{
    throw std::runtime_error(message);
}

void RequireStatus(const leveldb::Status& status, std::string_view operation)
{
    if (!status.ok()) Fail(std::string{operation} + ": " + status.ToString());
}

uint64_t ParseUnsigned(std::string_view text, std::string_view label)
{
    uint64_t value{0};
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc{} || end != text.data() + text.size()) {
        Fail(std::string{"invalid "} + std::string{label});
    }
    return value;
}

uint64_t Permute(uint64_t value)
{
    // SplitMix64's finalizer is a bijection over uint64_t. Record ids remain
    // collision-free while their leading bytes have hash-like key ordering.
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

std::string RecordKey(uint64_t record_id, RecordKind kind)
{
    std::string key(COIN_KEY_BYTES, '\0');
    key[0] = 'C';
    const uint64_t mixed = Permute(record_id + 0x9e3779b97f4a7c15ULL);
    std::memcpy(key.data() + 1, &mixed, sizeof(mixed));
    std::memcpy(key.data() + 9, &record_id, sizeof(record_id));
    key[17] = static_cast<char>(kind);
    const uint64_t second = Permute(record_id ^
                                    (static_cast<uint64_t>(kind) << 56));
    std::memcpy(key.data() + 18, &second, sizeof(second));
    const uint64_t third = Permute(second);
    std::memcpy(key.data() + 26, &third, 7);
    // byte 33 is the canonical one-byte VARINT(0) vout.
    return key;
}

std::string RecordValue(uint64_t record_id, const RecordSpec& spec)
{
    std::string value(spec.value_bytes, '\0');
    value[0] = static_cast<char>(spec.kind);
    if (value.size() >= 9) {
        const uint64_t mixed = Permute(record_id);
        std::memcpy(value.data() + 1, &mixed, sizeof(mixed));
    }
    return value;
}

uint64_t ClaimsBeforeBlock(uint64_t block_index)
{
    const uint64_t legacy = std::min(block_index, LEGACY_BLOCKS);
    const uint64_t canonical = block_index - legacy;
    return legacy * LEGACY_CLAIMS_PER_BLOCK +
           canonical * CANONICAL_CLAIMS_PER_BLOCK;
}

uint64_t ClaimsInBlock(uint64_t block_index)
{
    return block_index < LEGACY_BLOCKS ? LEGACY_CLAIMS_PER_BLOCK
                                       : CANONICAL_CLAIMS_PER_BLOCK;
}

void AppendBlock(leveldb::WriteBatch& batch, uint64_t block_index, bool erase)
{
    const uint64_t first_claim = ClaimsBeforeBlock(block_index);
    const uint64_t claim_count = ClaimsInBlock(block_index);
    for (uint64_t claim = 0; claim < claim_count; ++claim) {
        const uint64_t claim_index = first_claim + claim;
        for (size_t slot = 0; slot < CLAIM_RECORDS.size(); ++slot) {
            const uint64_t record_id = claim_index * CLAIM_RECORDS.size() + slot;
            const RecordSpec& spec = CLAIM_RECORDS[slot];
            const std::string key = RecordKey(record_id, spec.kind);
            if (erase) {
                batch.Delete(key);
            } else {
                batch.Put(key, RecordValue(record_id, spec));
            }
        }
    }
    const uint64_t fixed_base = CLAIM_FAMILY_RECORDS +
                                block_index * FIXED_RECORDS_PER_BLOCK;
    for (size_t slot = 0; slot < FIXED_RECORDS.size(); ++slot) {
        const RecordSpec& spec = FIXED_RECORDS[slot];
        const uint64_t record_id = fixed_base + slot;
        const std::string key = RecordKey(record_id, spec.kind);
        if (erase) {
            batch.Delete(key);
        } else {
            batch.Put(key, RecordValue(record_id, spec));
        }
    }
    // The eighth fixed slot is the solver record. It is separated above so
    // the six-shard active-undo arithmetic stays directly auditable.
    const uint64_t solver_id = fixed_base + FIXED_RECORDS.size();
    const std::string solver_key = RecordKey(solver_id, SOLVER_RECORD.kind);
    if (erase) {
        batch.Delete(solver_key);
    } else {
        batch.Put(solver_key, RecordValue(solver_id, SOLVER_RECORD));
    }
    if (block_index >= LEGACY_BLOCKS) {
        const uint64_t bucket_id = LOGICAL_PROOF_BUCKET_BASE +
                                   block_index - LEGACY_BLOCKS;
        const std::string bucket_key = RecordKey(
            bucket_id, LOGICAL_PROOF_BUCKET_RECORD.kind);
        if (erase) {
            batch.Delete(bucket_key);
        } else {
            batch.Put(bucket_key, RecordValue(
                bucket_id, LOGICAL_PROOF_BUCKET_RECORD));
        }
    }
}

std::string EncodeState(const State& state)
{
    std::array<char, 32> height_buffer{};
    const auto [height_end, error] = std::to_chars(
        height_buffer.data(), height_buffer.data() + height_buffer.size(),
        state.height);
    if (error != std::errc{}) Fail("cannot encode state height");
    return std::string{CONTRACT_ID} + ";" + state.phase + ";" +
           std::string{height_buffer.data(), height_end};
}

State DecodeState(const std::string& encoded)
{
    const size_t first = encoded.find(';');
    const size_t second = first == std::string::npos
        ? std::string::npos : encoded.find(';', first + 1);
    if (first == std::string::npos || second == std::string::npos ||
        encoded.substr(0, first) != CONTRACT_ID) {
        Fail("resource fixture state belongs to a different contract");
    }
    State state;
    state.phase = encoded.substr(first + 1, second - first - 1);
    const std::string_view height_text{encoded.data() + second + 1,
                                       encoded.size() - second - 1};
    bool negative = !height_text.empty() && height_text.front() == '-';
    const uint64_t magnitude = ParseUnsigned(
        negative ? height_text.substr(1) : height_text, "state height");
    if (magnitude > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        Fail("state height is out of range");
    }
    state.height = negative ? -static_cast<int64_t>(magnitude)
                            : static_cast<int64_t>(magnitude);
    return state;
}

State ReadState(leveldb::DB& db)
{
    std::string encoded;
    const leveldb::Status status = db.Get(leveldb::ReadOptions{},
                                           leveldb::Slice{STATE_KEY.data(), STATE_KEY.size()},
                                           &encoded);
    if (status.IsNotFound()) return {};
    RequireStatus(status, "read fixture state");
    return DecodeState(encoded);
}

void PrintState(const State& state)
{
    std::cout << "{\"schema\":1,\"phase\":\"" << state.phase
              << "\",\"height\":" << state.height << "}\n";
}

void WriteBlock(leveldb::DB& db, uint64_t block_index, bool erase,
                const State& state)
{
    leveldb::WriteBatch batch;
    AppendBlock(batch, block_index, erase);
    const std::string encoded = EncodeState(state);
    batch.Put(leveldb::Slice{STATE_KEY.data(), STATE_KEY.size()}, encoded);
    RequireStatus(db.Write(leveldb::WriteOptions{}, &batch),
                  erase ? "delete synthetic block" : "write synthetic block");
}

class Database {
public:
    Database(const std::string& path, bool create)
        : m_cache(leveldb::NewLRUCache(LEVELDB_CACHE_BYTES)),
          m_filter(leveldb::NewBloomFilterPolicy(10))
    {
        leveldb::Options options;
        options.create_if_missing = create;
        options.error_if_exists = false;
        options.paranoid_checks = true;
        options.compression = leveldb::kNoCompression;
        options.block_cache = m_cache.get();
        options.filter_policy = m_filter.get();
        options.write_buffer_size = LEVELDB_WRITE_BUFFER_BYTES;
        leveldb::DB* raw{nullptr};
        RequireStatus(leveldb::DB::Open(options, path, &raw), "open fixture database");
        m_db.reset(raw);
    }

    leveldb::DB& operator*() { return *m_db; }
    leveldb::DB* operator->() { return m_db.get(); }

private:
    std::unique_ptr<leveldb::Cache> m_cache;
    std::unique_ptr<const leveldb::FilterPolicy> m_filter;
    std::unique_ptr<leveldb::DB> m_db;
};

struct InvocationOptions {
    uint64_t limit{std::numeric_limits<uint64_t>::max()};
    bool measurement_barriers{false};
};

InvocationOptions ParseOptions(int argc, char** argv)
{
    InvocationOptions options;
    bool has_limit{false};
    for (int index = 3; index < argc; ++index) {
        const std::string_view argument{argv[index]};
        if (argument.rfind("--limit-blocks=", 0) == 0) {
            if (has_limit) Fail("duplicate --limit-blocks option");
            options.limit = ParseUnsigned(argument.substr(15), "block limit");
            has_limit = true;
        } else if (argument == "--measurement-barriers") {
            if (options.measurement_barriers) {
                Fail("duplicate --measurement-barriers option");
            }
            options.measurement_barriers = true;
        } else {
            Fail("expected --limit-blocks=N or --measurement-barriers");
        }
    }
    return options;
}

void Apply(leveldb::DB& db, uint64_t limit)
{
    State state = ReadState(db);
    if (state.phase == "applied" || state.phase == "reapplied") return;
    if (state.phase != "empty" && state.phase != "applying") {
        Fail("apply requires empty or applying state");
    }
    uint64_t block = state.phase == "empty"
        ? 0 : static_cast<uint64_t>(state.height - START_HEIGHT + 1);
    uint64_t completed{0};
    for (; block < GOLD_RUSH_BLOCKS && completed < limit; ++block, ++completed) {
        state.phase = block + 1 == GOLD_RUSH_BLOCKS ? "applied" : "applying";
        state.height = START_HEIGHT + block;
        WriteBlock(db, block, false, state);
    }
}

void Undo(leveldb::DB& db, uint64_t limit)
{
    State state = ReadState(db);
    if (state.phase == "undone") return;
    if (state.phase != "applied" && state.phase != "reapplied" &&
        state.phase != "undoing") {
        Fail("undo requires an applied fixture");
    }
    int64_t block = state.phase == "undoing"
        ? state.height - START_HEIGHT - 1
        : static_cast<int64_t>(GOLD_RUSH_BLOCKS) - 1;
    uint64_t completed{0};
    for (; block >= 0 && completed < limit; --block, ++completed) {
        state.phase = block == 0 ? "undone" : "undoing";
        state.height = block == 0 ? static_cast<int64_t>(START_HEIGHT) - 1
                                  : static_cast<int64_t>(START_HEIGHT) + block;
        WriteBlock(db, static_cast<uint64_t>(block), true, state);
    }
}

void Reapply(leveldb::DB& db, uint64_t limit)
{
    State state = ReadState(db);
    if (state.phase == "reapplied") return;
    if (state.phase != "undone" && state.phase != "reapplying") {
        Fail("reapply requires an undone fixture");
    }
    uint64_t block = state.phase == "undone"
        ? 0 : static_cast<uint64_t>(state.height - START_HEIGHT + 1);
    uint64_t completed{0};
    for (; block < GOLD_RUSH_BLOCKS && completed < limit; ++block, ++completed) {
        state.phase = block + 1 == GOLD_RUSH_BLOCKS ? "reapplied" : "reapplying";
        state.height = START_HEIGHT + block;
        WriteBlock(db, block, false, state);
    }
}

size_t VarintBytes(uint64_t value)
{
    size_t result{1};
    while (value >= 128) {
        value >>= 7;
        ++result;
    }
    return result;
}

void Scan(leveldb::DB& db)
{
    const State state = ReadState(db);
    uint64_t records{0};
    uint64_t claims{0};
    uint64_t payouts{0};
    uint64_t provenance{0};
    uint64_t logical_proof_buckets{0};
    uint64_t logical{0};
    leveldb::ReadOptions options;
    options.fill_cache = false;
    std::unique_ptr<leveldb::Iterator> iterator{db.NewIterator(options)};
    for (iterator->Seek("C"); iterator->Valid(); iterator->Next()) {
        const leveldb::Slice key = iterator->key();
        if (key.empty() || key[0] != 'C') break;
        const leveldb::Slice value = iterator->value();
        if (key.size() != COIN_KEY_BYTES || value.empty()) {
            Fail("synthetic record shape is corrupt");
        }
        ++records;
        switch (static_cast<RecordKind>(static_cast<uint8_t>(value[0]))) {
        case RecordKind::CLAIM: ++claims; break;
        case RecordKind::PAYOUT: ++payouts; break;
        case RecordKind::PROVENANCE: ++provenance; break;
        case RecordKind::ACTIVE_MANIFEST:
        case RecordKind::ACTIVE_SHARD_FULL:
        case RecordKind::ACTIVE_SHARD_LAST:
        case RecordKind::POOL_UNDO:
        case RecordKind::SOLVER:
            break;
        case RecordKind::LOGICAL_PROOF_BUCKET:
            ++logical_proof_buckets;
            break;
        default: Fail("synthetic record kind is corrupt");
        }
        logical += 1 + VarintBytes(key.size()) + key.size() +
                   VarintBytes(value.size()) + value.size();
    }
    RequireStatus(iterator->status(), "scan synthetic fixture");
    std::cout << "{\"schema\":1,\"contract_id\":\"" << CONTRACT_ID
              << "\",\"phase\":\"" << state.phase
              << "\",\"height\":" << state.height
              << ",\"records\":" << records
              << ",\"claims\":" << claims
              << ",\"payouts\":" << payouts
              << ",\"provenance\":" << provenance
              << ",\"logical_proof_buckets\":" << logical_proof_buckets
              << ",\"logical_bytes\":" << logical << "}\n";
}

uint64_t DecodeRecordId(const leveldb::Slice& key)
{
    if (key.size() != COIN_KEY_BYTES || key[0] != 'C') {
        Fail("synthetic record key is corrupt");
    }
    uint64_t record_id{0};
    std::memcpy(&record_id, key.data() + 9, sizeof(record_id));
    return record_id;
}

void VerifyPointLookup(leveldb::Iterator& iterator, uint64_t record_id,
                       const RecordSpec& spec)
{
    const std::string expected_key = RecordKey(record_id, spec.kind);
    iterator.Seek(expected_key);
    if (!iterator.Valid() ||
        iterator.key().compare(leveldb::Slice{expected_key}) != 0) {
        Fail("synthetic authentication point lookup is missing");
    }
    const leveldb::Slice value = iterator.value();
    if (value.size() != spec.value_bytes || value.empty() ||
        static_cast<RecordKind>(static_cast<uint8_t>(value[0])) != spec.kind) {
        Fail("synthetic authentication point lookup has corrupt shape");
    }
    if (value.size() >= 9) {
        uint64_t encoded{0};
        std::memcpy(&encoded, value.data() + 1, sizeof(encoded));
        if (encoded != Permute(record_id)) {
            Fail("synthetic authentication point lookup has corrupt identity");
        }
    }
}

void Authenticate(leveldb::DB& db, bool allow_partial)
{
    const State state = ReadState(db);
    if (state.phase != "applied" && state.phase != "reapplied" &&
        !(allow_partial && state.phase == "applying")) {
        Fail("authentication requires a completed synthetic fixture");
    }

    leveldb::ReadOptions options;
    options.fill_cache = false;
    std::unique_ptr<leveldb::Iterator> marker_cursor{db.NewIterator(options)};
    std::unique_ptr<leveldb::Iterator> attestation_cursor{db.NewIterator(options)};
    std::unique_ptr<leveldb::Iterator> main_cursor{db.NewIterator(options)};

    uint64_t first_scan_records{0};
    uint64_t provenance_records{0};
    for (marker_cursor->Seek("C"); marker_cursor->Valid(); marker_cursor->Next()) {
        const leveldb::Slice key = marker_cursor->key();
        if (key.empty() || key[0] != 'C') break;
        const leveldb::Slice value = marker_cursor->value();
        if (key.size() != COIN_KEY_BYTES || value.empty()) {
            Fail("synthetic marker scan record is corrupt");
        }
        ++first_scan_records;
        if (static_cast<RecordKind>(static_cast<uint8_t>(value[0])) ==
            RecordKind::PROVENANCE) {
            ++provenance_records;
        }
    }
    RequireStatus(marker_cursor->status(), "scan synthetic authentication markers");

    uint64_t second_scan_records{0};
    uint64_t payout_candidates{0};
    uint64_t payout_authenticated{0};
    uint64_t attestation_candidates{0};
    uint64_t attestation_lookup_hits{0};
    for (main_cursor->Seek("C"); main_cursor->Valid(); main_cursor->Next()) {
        const leveldb::Slice key = main_cursor->key();
        if (key.empty() || key[0] != 'C') break;
        const leveldb::Slice value = main_cursor->value();
        if (key.size() != COIN_KEY_BYTES || value.empty()) {
            Fail("synthetic lifecycle scan record is corrupt");
        }
        ++second_scan_records;
        if (static_cast<RecordKind>(static_cast<uint8_t>(value[0])) !=
            RecordKind::PAYOUT) {
            continue;
        }

        const uint64_t payout_record_id = DecodeRecordId(key);
        if (payout_record_id >= CLAIM_FAMILY_RECORDS ||
            payout_record_id % CLAIM_RECORDS.size() != 1) {
            Fail("synthetic payout record identity is corrupt");
        }
        ++payout_candidates;
        VerifyPointLookup(
            *marker_cursor, payout_record_id + 1, CLAIM_RECORDS[2]);
        ++payout_authenticated;

        // Treat every synthetic payout as a distinct quantum-output lookup.
        // The claim-family value is a conservative-sized deterministic hit;
        // actual latest-state decoding is covered by the source-bound unit
        // test. This phase measures the terminal RPC's second bounded seek at
        // the same maximum cardinality without labeling this DB a live chain.
        ++attestation_candidates;
        VerifyPointLookup(
            *attestation_cursor, payout_record_id - 1, CLAIM_RECORDS[0]);
        ++attestation_lookup_hits;
    }
    RequireStatus(main_cursor->status(), "scan synthetic lifecycle outputs");
    RequireStatus(marker_cursor->status(), "authenticate synthetic payout provenance");
    RequireStatus(attestation_cursor->status(), "authenticate synthetic demurrage state");

    uint64_t logical_proof_bucket_lookups{0};
    std::unique_ptr<leveldb::Iterator> bucket_cursor{db.NewIterator(options)};
    const uint64_t available_canonical_blocks = state.height <
            static_cast<int64_t>(CLAIM_BOUNDARY_HEIGHT)
        ? 0
        : std::min<uint64_t>(
              CANONICAL_BLOCKS,
              static_cast<uint64_t>(
                  state.height - CLAIM_BOUNDARY_HEIGHT + 1));
    for (uint64_t canonical_block = 0;
         canonical_block < available_canonical_blocks; ++canonical_block) {
        const uint64_t window = std::min(
            canonical_block + 1, LOGICAL_PROOF_BUCKET_WINDOW);
        const uint64_t first = canonical_block + 1 - window;
        for (uint64_t bucket = first; bucket <= canonical_block; ++bucket) {
            VerifyPointLookup(
                *bucket_cursor, LOGICAL_PROOF_BUCKET_BASE + bucket,
                LOGICAL_PROOF_BUCKET_RECORD);
            ++logical_proof_bucket_lookups;
        }
    }
    RequireStatus(bucket_cursor->status(),
                  "authenticate synthetic logical proof buckets");

    const uint64_t sequential_records = first_scan_records + second_scan_records;
    const uint64_t point_lookups = payout_authenticated +
                                   attestation_lookup_hits +
                                   logical_proof_bucket_lookups;
    std::cout << "{\"schema\":1,\"contract_id\":\"" << CONTRACT_ID
              << "\",\"phase\":\"" << state.phase
              << "\",\"height\":" << state.height
              << ",\"sequential_records\":" << sequential_records
              << ",\"provenance_records\":" << provenance_records
              << ",\"payout_candidates\":" << payout_candidates
              << ",\"payout_authenticated\":" << payout_authenticated
              << ",\"attestation_candidates\":" << attestation_candidates
              << ",\"attestation_lookup_hits\":" << attestation_lookup_hits
              << ",\"logical_proof_bucket_lookups\":"
              << logical_proof_bucket_lookups
              << ",\"point_lookups\":" << point_lookups << "}\n";
}

void PrintContract()
{
    std::cout << "{\"schema\":1,\"contract_id\":\"" << CONTRACT_ID
              << "\",\"reward_start_height\":" << START_HEIGHT
              << ",\"competing_claims_activation_height\":" << CLAIM_BOUNDARY_HEIGHT
              << ",\"reward_end_height\":" << END_HEIGHT
              << ",\"gold_rush_blocks\":" << GOLD_RUSH_BLOCKS
              << ",\"authenticated_whitelist_entries\":" << WHITELIST_ENTRIES
              << ",\"issued_claims\":" << ISSUED_CLAIMS
              << ",\"claim_family_records\":" << CLAIM_FAMILY_RECORDS
              << ",\"logical_proof_bucket_records\":"
              << LOGICAL_PROOF_BUCKET_RECORDS
              << ",\"total_records\":" << TOTAL_RECORDS
              << ",\"retained_logical_batch_payload_bytes\":"
              << RETAINED_LOGICAL_BYTES
              << ",\"authentication_sequential_records\":"
              << AUTHENTICATION_SEQUENTIAL_RECORDS
              << ",\"payout_point_lookups\":" << PAYOUT_POINT_LOOKUPS
              << ",\"attestation_point_lookups\":" << ATTESTATION_POINT_LOOKUPS
              << ",\"logical_proof_bucket_point_lookups\":"
              << LOGICAL_PROOF_BUCKET_POINT_LOOKUPS
              << ",\"authentication_point_lookups\":"
              << AUTHENTICATION_POINT_LOOKUPS
              << ",\"leveldb_cache_bytes\":" << LEVELDB_CACHE_BYTES
              << ",\"leveldb_write_buffer_bytes\":"
              << LEVELDB_WRITE_BUFFER_BYTES << "}\n";
}

} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc == 2 && std::string_view{argv[1]} == "contract") {
            PrintContract();
            return 0;
        }
        if (argc < 3) {
            Fail("usage: shadow_resource_leveldb_fixture COMMAND DB "
                 "[--limit-blocks=N] [--measurement-barriers]");
        }
        const std::string command{argv[1]};
        const InvocationOptions options = ParseOptions(argc, argv);
        const uint64_t limit = options.limit;
        if (options.measurement_barriers && !std::cin.get()) {
            Fail("start barrier closed before release");
        }
        Database database{argv[2], command == "apply"};
        if (command == "apply") {
            Apply(*database, limit);
            PrintState(ReadState(*database));
        } else if (command == "undo") {
            Undo(*database, limit);
            PrintState(ReadState(*database));
        } else if (command == "reapply") {
            Reapply(*database, limit);
            PrintState(ReadState(*database));
        } else if (command == "scan") {
            if (limit != std::numeric_limits<uint64_t>::max()) {
                Fail("scan does not accept a block limit");
            }
            Scan(*database);
        } else if (command == "authenticate") {
            Authenticate(
                *database,
                limit != std::numeric_limits<uint64_t>::max());
        } else if (command == "compact") {
            if (limit != std::numeric_limits<uint64_t>::max()) {
                Fail("compact does not accept a block limit");
            }
            database->CompactRange(nullptr, nullptr);
            PrintState(ReadState(*database));
        } else if (command == "open") {
            if (limit != std::numeric_limits<uint64_t>::max()) {
                Fail("open does not accept a block limit");
            }
            PrintState(ReadState(*database));
        } else {
            Fail("unknown command");
        }
        if (options.measurement_barriers) {
            std::cout.flush();
            if (!std::cin.get()) {
                Fail("completion barrier closed before final sampling");
            }
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "shadow resource fixture: " << error.what() << "\n";
        return 1;
    }
}
