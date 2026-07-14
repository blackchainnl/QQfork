// Copyright (c) 2021-2022 Blackcoin Core Developers
// Copyright (c) 2021-2022 Blackcoin More Developers
// Copyright (c) 2021-2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstate.h>
#include <node/chainstate_rebuild.h>

#include <arith_uint256.h>
#include <chain.h>
#include <coins.h>
#include <consensus/params.h>
#include <hash.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/caches.h>
#include <node/utxo_snapshot.h>
#include <sync.h>
#include <threadsafety.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <exception>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace node {

namespace {

constexpr const char* REBUILD_JOURNAL{"chainstate-rebuild.journal"};
constexpr const char* REBUILD_BASE_BACKUP{"chainstate.rebuild-backup"};
constexpr const char* REBUILD_SNAPSHOT_BACKUP{"chainstate_snapshot.rebuild-backup"};
constexpr const char* REBUILD_BASE_PARTIAL{"chainstate.rebuild-partial"};
constexpr const char* REBUILD_SNAPSHOT_PARTIAL{"chainstate_snapshot.rebuild-partial"};

enum class RebuildPhase {
    PREPARED,
    BUILDING,
    ROLLING_BACK,
    COMMIT_READY,
    CLEANUP_READY,
};

struct RebuildCommitment {
    uint256 tip;
    uint64_t coin_count{0};
    uint256 full_coin_hash;

    friend bool operator==(const RebuildCommitment& lhs, const RebuildCommitment& rhs)
    {
        return lhs.tip == rhs.tip && lhs.coin_count == rhs.coin_count &&
            lhs.full_coin_hash == rhs.full_coin_hash;
    }
    friend bool operator!=(const RebuildCommitment& lhs, const RebuildCommitment& rhs)
    {
        return !(lhs == rhs);
    }
};

struct RebuildJournal {
    uint32_t version{2};
    RebuildPhase phase;
    bool base_present;
    bool snapshot_present;
    std::optional<RebuildCommitment> commitment;
};

enum class CommitmentResult {
    SUCCESS,
    INTERRUPTED,
    FAILURE,
};

bool PathExists(const fs::path& path)
{
    // Filesystem errors are not equivalent to absence. Let the caller fail
    // closed while the rebuild journal and any preserved backups remain.
    return fs::exists(path);
}

const char* PhaseName(RebuildPhase phase)
{
    switch (phase) {
    case RebuildPhase::PREPARED: return "prepared";
    case RebuildPhase::BUILDING: return "building";
    case RebuildPhase::ROLLING_BACK: return "rolling-back";
    case RebuildPhase::COMMIT_READY: return "commit-ready";
    case RebuildPhase::CLEANUP_READY: return "cleanup-ready";
    }
    return "invalid";
}

std::optional<RebuildPhase> ParsePhase(const std::string& value)
{
    if (value == "prepared") return RebuildPhase::PREPARED;
    if (value == "building") return RebuildPhase::BUILDING;
    if (value == "rolling-back") return RebuildPhase::ROLLING_BACK;
    if (value == "commit-ready") return RebuildPhase::COMMIT_READY;
    if (value == "cleanup-ready") return RebuildPhase::CLEANUP_READY;
    return std::nullopt;
}

fs::path JournalPath(const fs::path& datadir) { return datadir / REBUILD_JOURNAL; }
fs::path BasePath(const fs::path& datadir) { return datadir / "chainstate"; }
fs::path SnapshotPath(const fs::path& datadir) { return datadir / fs::u8path(std::string{"chainstate"} + std::string{SNAPSHOT_CHAINSTATE_SUFFIX}); }
fs::path BaseBackupPath(const fs::path& datadir) { return datadir / REBUILD_BASE_BACKUP; }
fs::path SnapshotBackupPath(const fs::path& datadir) { return datadir / REBUILD_SNAPSHOT_BACKUP; }
fs::path BasePartialPath(const fs::path& datadir) { return datadir / REBUILD_BASE_PARTIAL; }
fs::path SnapshotPartialPath(const fs::path& datadir) { return datadir / REBUILD_SNAPSHOT_PARTIAL; }

bool WriteJournal(const fs::path& datadir, const RebuildJournal& journal)
{
    const fs::path path = JournalPath(datadir);
    const fs::path staged = fs::PathFromString(fs::PathToString(path) + ".new");
    const bool committed_phase = journal.phase == RebuildPhase::COMMIT_READY ||
        journal.phase == RebuildPhase::CLEANUP_READY;
    if ((journal.version != 1 && journal.version != 2) ||
        (journal.version == 1 && journal.commitment) ||
        (journal.version == 2 && committed_phase != journal.commitment.has_value())) {
        return false;
    }

    std::string contents;
    if (journal.version == 1) {
        contents = strprintf(
            "blackcoin-chainstate-rebuild-v1\nphase=%s\nbase=%d\nsnapshot=%d\n",
            PhaseName(journal.phase), journal.base_present ? 1 : 0,
            journal.snapshot_present ? 1 : 0);
    } else {
        const RebuildCommitment commitment = journal.commitment.value_or(RebuildCommitment{});
        contents = strprintf(
            "blackcoin-chainstate-rebuild-v2\nphase=%s\nbase=%d\nsnapshot=%d\n"
            "commitment=%d\ntip=%s\ncoins=%u\nfull_coin_hash=%s\n",
            PhaseName(journal.phase), journal.base_present ? 1 : 0,
            journal.snapshot_present ? 1 : 0, journal.commitment ? 1 : 0,
            commitment.tip.ToString(), commitment.coin_count,
            commitment.full_coin_hash.ToString());
    }

    std::error_code ec;
    fs::remove(staged, ec);
    FILE* file = fsbridge::fopen(staged, "wb");
    if (!file) return false;
    const bool wrote = std::fwrite(contents.data(), 1, contents.size(), file) == contents.size();
    const bool committed = wrote && FileCommit(file);
    const bool closed = std::fclose(file) == 0;
    if (!committed || !closed || !RenameOver(staged, path) || !DirectoryCommit(datadir)) {
        fs::remove(staged, ec);
        return false;
    }
    return true;
}

std::optional<RebuildJournal> ReadJournal(const fs::path& datadir, std::string& error)
{
    const fs::path path = JournalPath(datadir);
    if (!PathExists(path)) return std::nullopt;
    std::ifstream file{path};
    if (!file) {
        error = "chainstate rebuild journal is unreadable";
        return std::nullopt;
    }
    std::string magic, phase_line, base_line, snapshot_line;
    if (!std::getline(file, magic) || !std::getline(file, phase_line) ||
        !std::getline(file, base_line) || !std::getline(file, snapshot_line) ||
        phase_line.rfind("phase=", 0) != 0 || base_line.rfind("base=", 0) != 0 ||
        snapshot_line.rfind("snapshot=", 0) != 0) {
        error = "chainstate rebuild journal is malformed";
        return std::nullopt;
    }
    const auto phase = ParsePhase(phase_line.substr(6));
    const std::string base = base_line.substr(5);
    const std::string snapshot = snapshot_line.substr(9);
    if (!phase || (base != "0" && base != "1") ||
        (snapshot != "0" && snapshot != "1") ||
        (base == "0" && snapshot == "0")) {
        error = "chainstate rebuild journal contains an invalid state";
        return std::nullopt;
    }

    if (magic == "blackcoin-chainstate-rebuild-v1") {
        std::string trailing;
        if (std::getline(file, trailing)) {
            error = "chainstate rebuild journal is malformed";
            return std::nullopt;
        }
        return RebuildJournal{1, *phase, base == "1", snapshot == "1", std::nullopt};
    }
    if (magic != "blackcoin-chainstate-rebuild-v2") {
        error = "chainstate rebuild journal has an unsupported version";
        return std::nullopt;
    }

    std::string commitment_line, tip_line, coins_line, hash_line, trailing;
    if (!std::getline(file, commitment_line) || !std::getline(file, tip_line) ||
        !std::getline(file, coins_line) || !std::getline(file, hash_line) ||
        std::getline(file, trailing) || commitment_line.rfind("commitment=", 0) != 0 ||
        tip_line.rfind("tip=", 0) != 0 || coins_line.rfind("coins=", 0) != 0 ||
        hash_line.rfind("full_coin_hash=", 0) != 0) {
        error = "chainstate rebuild journal is malformed";
        return std::nullopt;
    }
    const std::string commitment_flag = commitment_line.substr(11);
    const std::string tip_hex = tip_line.substr(4);
    const std::string coins_value = coins_line.substr(6);
    const std::string hash_hex = hash_line.substr(15);
    uint64_t coin_count{0};
    if ((commitment_flag != "0" && commitment_flag != "1") ||
        tip_hex.size() != uint256::size() * 2 || !IsHex(tip_hex) ||
        hash_hex.size() != uint256::size() * 2 || !IsHex(hash_hex) ||
        !ParseUInt64(coins_value, &coin_count)) {
        error = "chainstate rebuild journal contains an invalid commitment";
        return std::nullopt;
    }
    RebuildCommitment commitment{uint256S(tip_hex), coin_count, uint256S(hash_hex)};
    const bool commitment_present = commitment_flag == "1";
    const bool committed_phase = *phase == RebuildPhase::COMMIT_READY ||
        *phase == RebuildPhase::CLEANUP_READY;
    if (commitment_present != committed_phase ||
        (commitment_present && (commitment.tip.IsNull() || commitment.full_coin_hash.IsNull())) ||
        (!commitment_present && (!commitment.tip.IsNull() || commitment.coin_count != 0 ||
                                 !commitment.full_coin_hash.IsNull()))) {
        error = "chainstate rebuild journal commitment does not match its phase";
        return std::nullopt;
    }
    return RebuildJournal{2, *phase, base == "1", snapshot == "1",
                          commitment_present ? std::optional<RebuildCommitment>{commitment}
                                             : std::nullopt};
}

CommitmentResult ComputeFullCoinCommitment(
    CCoinsView& view,
    const std::function<bool()>& interrupted,
    RebuildCommitment& result,
    std::string& error)
{
    // This is a commit/reopen identity for the replacement, not a comparison
    // with the preserved source. Reconstruction may intentionally correct
    // nTime and coinstake provenance while replaying old blocks. The source is
    // retained for rollback; the hash binds every logical Coin field in the
    // rebuilt database to the state that a later process reopens.
    result = {};
    if (!view.GetHeadBlocks().empty()) {
        error = "chainstate has an interrupted-flush marker";
        return CommitmentResult::FAILURE;
    }

    std::unique_ptr<CCoinsViewCursor> cursor = view.Cursor();
    if (!cursor || cursor->GetBestBlock().IsNull()) {
        error = "chainstate has no stable cursor or saved tip";
        return CommitmentResult::FAILURE;
    }

    result.tip = cursor->GetBestBlock();
    CHashWriter commitment;
    commitment << std::string{"Blackcoin Chainstate Full Coin Commitment v1"}
               << result.tip;
    while (cursor->Valid()) {
        if ((result.coin_count & 0x3fff) == 0 && interrupted && interrupted()) {
            return CommitmentResult::INTERRUPTED;
        }
        COutPoint outpoint;
        Coin coin;
        if (!cursor->GetKey(outpoint) || !cursor->GetValue(coin) || coin.IsSpent()) {
            error = "chainstate cursor contains an unreadable or spent coin";
            return CommitmentResult::FAILURE;
        }
        if (result.coin_count == std::numeric_limits<uint64_t>::max()) {
            error = "chainstate coin count overflows";
            return CommitmentResult::FAILURE;
        }
        const uint8_t flags = (coin.fCoinBase ? 1 : 0) | (coin.fCoinStake ? 2 : 0);
        commitment << outpoint << static_cast<uint32_t>(coin.nHeight) << flags
                   << static_cast<uint32_t>(coin.nTime) << coin.out;
        ++result.coin_count;
        cursor->Next();
    }
    if (interrupted && interrupted()) return CommitmentResult::INTERRUPTED;
    if (!view.GetHeadBlocks().empty() || view.GetBestBlock() != result.tip) {
        error = "chainstate changed while its full-Coin commitment was computed";
        return CommitmentResult::FAILURE;
    }
    commitment << result.coin_count;
    result.full_coin_hash = commitment.GetHash();
    if (result.full_coin_hash.IsNull()) {
        error = "chainstate full-Coin commitment is null";
        return CommitmentResult::FAILURE;
    }
    return CommitmentResult::SUCCESS;
}

bool ValidateBackupTopology(const fs::path& datadir,
                            const RebuildJournal& journal,
                            bool allow_missing_expected,
                            std::string& error)
{
    const std::array<std::pair<bool, fs::path>, 2> backups{{
        {journal.base_present, BaseBackupPath(datadir)},
        {journal.snapshot_present, SnapshotBackupPath(datadir)},
    }};
    for (const auto& [expected, path] : backups) {
        const bool exists = PathExists(path);
        if (!expected && exists) {
            error = strprintf("undeclared chainstate rebuild backup exists at %s",
                              fs::PathToString(path));
            return false;
        }
        if (expected && !exists && !allow_missing_expected) {
            error = strprintf("declared chainstate rebuild backup is missing at %s",
                              fs::PathToString(path));
            return false;
        }
    }
    return true;
}

bool ReopeningCommittedRebuild(const fs::path& datadir)
{
    std::string error;
    const std::optional<RebuildJournal> journal = ReadJournal(datadir, error);
    return journal && journal->version == 2 && journal->commitment &&
        journal->phase == RebuildPhase::COMMIT_READY;
}

bool RemoveJournal(const fs::path& datadir)
{
    std::error_code ec;
    if (!fs::remove(JournalPath(datadir), ec) || ec) return false;
    return DirectoryCommit(datadir);
}

bool CommitRename(const fs::path& from, const fs::path& to, const fs::path& datadir)
{
    if (!RenameNoReplace(from, to)) {
        LogPrintf("Chainstate rebuild no-replace rename %s -> %s failed\n",
                  fs::PathToString(from), fs::PathToString(to));
        return false;
    }
    return DirectoryCommit(datadir);
}

bool RestoreJournaledPath(const fs::path& datadir, const fs::path& live,
                          const fs::path& backup, const fs::path& partial,
                          bool expected, std::string& error)
{
    if (!expected) {
        if (PathExists(backup)) {
            error = strprintf("unexpected rebuild backup exists at %s", fs::PathToString(backup));
            return false;
        }
        if (PathExists(live)) {
            if (PathExists(partial)) {
                error = strprintf("cannot preserve partial rebuild because %s already exists", fs::PathToString(partial));
                return false;
            }
            if (!CommitRename(live, partial, datadir)) {
                error = strprintf("could not preserve partial rebuild at %s", fs::PathToString(partial));
                return false;
            }
        }
        return true;
    }
    if (PathExists(backup)) {
        if (PathExists(live)) {
            if (PathExists(partial)) {
                error = strprintf("cannot preserve partial rebuild because %s already exists", fs::PathToString(partial));
                return false;
            }
            if (!CommitRename(live, partial, datadir)) {
                error = strprintf("could not preserve partial rebuild at %s", fs::PathToString(partial));
                return false;
            }
        }
        if (!CommitRename(backup, live, datadir)) {
            error = strprintf("could not restore original chainstate from %s", fs::PathToString(backup));
            return false;
        }
    } else if (!PathExists(live)) {
        error = strprintf("both live and backup chainstate are missing for %s", fs::PathToString(live));
        return false;
    }
    return true;
}

bool CleanupTree(const fs::path& path)
{
    if (!PathExists(path)) return true;
    std::error_code ec;
    fs::remove_all(path, ec);
    return !ec && !PathExists(path);
}

bool AddRebuildSourceBytes(const fs::path& root, uint64_t& total,
                           std::string& error)
{
    if (!PathExists(root)) return true;

    std::error_code ec;
    const fs::file_status root_status = fs::symlink_status(root, ec);
    if (ec || !fs::is_directory(root_status)) {
        error = strprintf("chainstate rebuild source is not a readable directory: %s",
                          fs::PathToString(root));
        return false;
    }

    fs::recursive_directory_iterator it{root, ec};
    const fs::recursive_directory_iterator end{};
    if (ec) {
        error = strprintf("cannot scan chainstate rebuild source %s: %s",
                          fs::PathToString(root), ec.message());
        return false;
    }
    while (it != end) {
        const fs::file_status status = it->symlink_status(ec);
        if (ec) {
            error = strprintf("cannot inspect chainstate rebuild source %s: %s",
                              fs::PathToString(it->path()), ec.message());
            return false;
        }
        if (fs::is_regular_file(status)) {
            const uintmax_t size = it->file_size(ec);
            if (ec) {
                error = strprintf("cannot size chainstate rebuild source %s: %s",
                                  fs::PathToString(it->path()), ec.message());
                return false;
            }
            if (size > std::numeric_limits<uint64_t>::max() - total) {
                error = strprintf("chainstate rebuild source size overflows at %s",
                                  fs::PathToString(it->path()));
                return false;
            }
            total += static_cast<uint64_t>(size);
        } else if (!fs::is_directory(status)) {
            // A symlink or special file can change after this scan or hide
            // storage outside the locked datadir. Refuse it rather than make
            // a disk-space claim from an unstable source topology.
            error = strprintf("unsupported entry in chainstate rebuild source: %s",
                              fs::PathToString(it->path()));
            return false;
        }

        it.increment(ec);
        if (ec) {
            error = strprintf("cannot complete chainstate rebuild source scan at %s: %s",
                              fs::PathToString(root), ec.message());
            return false;
        }
    }
    return true;
}

ChainstateLoadResult CheckRebuildDiskSpace(
    const fs::path& datadir,
    const ChainstateLoadOptions& options)
{
    uint64_t source_bytes{0};
    std::string scan_error;
    if (!AddRebuildSourceBytes(BasePath(datadir), source_bytes, scan_error) ||
        !AddRebuildSourceBytes(SnapshotPath(datadir), source_bytes, scan_error)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("Cannot establish chainstate rebuild disk requirements (%s). No chainstate was moved or wiped."),
                          scan_error)};
    }

    bool sufficient{false};
    try {
        sufficient = options.check_rebuild_disk_space
            ? options.check_rebuild_disk_space(datadir, source_bytes)
            : CheckDiskSpace(datadir, source_bytes);
    } catch (const std::exception& e) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("Cannot query free disk space for the protected chainstate rebuild (%s). No chainstate was moved or wiped."),
                          e.what())};
    }
    if (!sufficient) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("Insufficient free disk space for a protected chainstate rebuild. At least %u bytes plus the 50 MiB safety reserve must be available before preserving the existing chainstate. No chainstate was moved or wiped."),
                          source_bytes)};
    }
    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult RecoverInterruptedRebuild(ChainstateManager& chainman)
{
    const fs::path& datadir = chainman.m_options.datadir;
    std::string parse_error;
    const bool journal_exists = PathExists(JournalPath(datadir));
    std::optional<RebuildJournal> journal = ReadJournal(datadir, parse_error);
    if (journal_exists && !journal) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("The chainstate rebuild journal is unreadable or malformed (%s). No data was changed. Preserve the datadir and repair the journal or restore from backup."), parse_error)};
    }
    if (!journal) {
        if (PathExists(BaseBackupPath(datadir)) || PathExists(SnapshotBackupPath(datadir))) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("An unjournaled chainstate rebuild backup exists. No data was changed. Preserve the datadir and resolve the backup manually before startup.")};
        }
        if (!CleanupTree(BasePartialPath(datadir)) ||
            !CleanupTree(SnapshotPartialPath(datadir))) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("An abandoned partial chainstate rebuild could not be removed. The authoritative chainstate was not changed; correct filesystem permissions and retry.")};
        }
        return {ChainstateLoadStatus::SUCCESS, {}};
    }

    if (journal->version < 2 &&
        (journal->phase == RebuildPhase::COMMIT_READY ||
         journal->phase == RebuildPhase::CLEANUP_READY)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("The committed chainstate rebuild journal predates full-Coin commitments. No backup was removed by this startup. Preserve the datadir and restore or inspect the retained rebuild backup manually.")};
    }

    if (journal->phase == RebuildPhase::COMMIT_READY) {
        std::string topology_error;
        if (!ValidateBackupTopology(datadir, *journal,
                                    /*allow_missing_expected=*/false,
                                    topology_error)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    strprintf(_("A committed chainstate rebuild has an inconsistent backup topology (%s). No data was changed; preserve the datadir for manual recovery."), topology_error)};
        }
        if (!PathExists(BasePath(datadir))) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("A committed replacement chainstate is missing. The preserved backup was not changed; manual recovery is required.")};
        }
        // The replacement reached a durable commit point in a previous
        // process, but the preserved source must remain until this process has
        // reopened and verified the replacement. FinalizeChainstateRebuild()
        // advances to CLEANUP_READY only after that succeeds.
        return {ChainstateLoadStatus::SUCCESS, {}};
    }

    if (journal->phase == RebuildPhase::CLEANUP_READY) {
        std::string topology_error;
        if (!ValidateBackupTopology(datadir, *journal,
                                    /*allow_missing_expected=*/true,
                                    topology_error)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    strprintf(_("A verified chainstate rebuild has an inconsistent backup topology (%s). No additional data was changed; preserve the datadir for manual recovery."), topology_error)};
        }
        if (!PathExists(BasePath(datadir))) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("A verified replacement chainstate is missing. Manual recovery is required.")};
        }

        RebuildCommitment reopened_commitment;
        std::string commitment_error;
        CommitmentResult commitment_result{CommitmentResult::FAILURE};
        try {
            CCoinsViewDB reopened_db{DBParams{
                .path = BasePath(datadir),
                .cache_bytes = 1 << 20,
                .memory_only = false,
                .wipe_data = false,
                .obfuscate = true}, CoinsViewOptions{}};
            commitment_result = ComputeFullCoinCommitment(
                reopened_db,
                [&chainman] { return bool{chainman.m_interrupt}; },
                reopened_commitment,
                commitment_error);
        } catch (const std::exception& e) {
            commitment_error = e.what();
            commitment_result = CommitmentResult::FAILURE;
        }
        if (commitment_result == CommitmentResult::INTERRUPTED) {
            return {ChainstateLoadStatus::INTERRUPTED, {}};
        }
        if (commitment_result != CommitmentResult::SUCCESS ||
            !journal->commitment ||
            reopened_commitment != *journal->commitment) {
            if (commitment_error.empty()) {
                commitment_error = "the reopened database does not match its recorded full-Coin commitment";
            }
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    strprintf(_("The reopened replacement chainstate failed its full-Coin commitment check (%s). Preserved rebuild backups were not removed; preserve the datadir for recovery."), commitment_error)};
        }
        if ((journal->base_present && !CleanupTree(BaseBackupPath(datadir))) ||
            (journal->snapshot_present && !CleanupTree(SnapshotBackupPath(datadir))) ||
            !DirectoryCommit(datadir) || !RemoveJournal(datadir)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("The rebuilt chainstate was reopened and verified, but old backup cleanup could not be completed. Retry after correcting filesystem permissions.")};
        }
        CleanupTree(BasePartialPath(datadir));
        CleanupTree(SnapshotPartialPath(datadir));
        return {ChainstateLoadStatus::SUCCESS, {}};
    }

    std::string topology_error;
    const bool backup_moves_may_be_incomplete =
        journal->phase == RebuildPhase::PREPARED ||
        journal->phase == RebuildPhase::ROLLING_BACK;
    if (!ValidateBackupTopology(datadir, *journal,
                                backup_moves_may_be_incomplete,
                                topology_error)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("A chainstate rebuild has an inconsistent backup topology (%s). No data was changed; preserve the datadir for manual recovery."), topology_error)};
    }
    if (journal->phase != RebuildPhase::ROLLING_BACK) {
        journal->phase = RebuildPhase::ROLLING_BACK;
        if (!WriteJournal(datadir, *journal)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("Unable to durably mark an interrupted chainstate rebuild for rollback. No chainstate was changed.")};
        }
    }

    std::string restore_error;
    if (!RestoreJournaledPath(datadir, BasePath(datadir), BaseBackupPath(datadir),
                              BasePartialPath(datadir), journal->base_present, restore_error) ||
        !RestoreJournaledPath(datadir, SnapshotPath(datadir), SnapshotBackupPath(datadir),
                              SnapshotPartialPath(datadir), journal->snapshot_present, restore_error)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                strprintf(_("Interrupted chainstate rebuild rollback stopped safely: %s. Preserve the datadir and backups for manual recovery."), restore_error)};
    }
    if (!RemoveJournal(datadir)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("The original chainstate was restored, but the rebuild journal could not be cleared. No data was removed; correct filesystem permissions and retry.")};
    }
    if (!CleanupTree(BasePartialPath(datadir)) ||
        !CleanupTree(SnapshotPartialPath(datadir)) ||
        !DirectoryCommit(datadir)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("The original chainstate was restored, but an abandoned partial rebuild could not be removed. Correct filesystem permissions and retry.")};
    }
    LogPrintf("Restored the original chainstate after an interrupted staged rebuild\n");
    return {ChainstateLoadStatus::SUCCESS, {}};
}

} // namespace

static bilingual_str ChainstateRebuildRequiredMessage()
{
    return _("Quantum Quasar v30.1.1 requires a one-time chainstate rebuild. Back up wallets and restart once with -reindex-chainstate. This startup did not wipe the existing chainstate.");
}

std::optional<int> FindChainstateRebuildPreflightFailureHeight(
    const CBlockIndex* target, const uint256& expected_genesis)
{
    AssertLockHeld(::cs_main);
    const CBlockIndex* block = target;
    while (block) {
        // A chainstate-only rebuild does not re-import block files. Entries
        // accepted only through assumeUTXO therefore cannot be used to rebuild
        // the active chainstate even when their raw block bytes are present.
        if (!(block->nStatus & BLOCK_HAVE_DATA) ||
            !block->IsValid(BLOCK_VALID_TRANSACTIONS)) {
            return block->nHeight;
        }
        if (block->nHeight == 0) {
            return block->GetBlockHash() == expected_genesis
                ? std::nullopt
                : std::optional<int>{0};
        }
        const int expected_parent_height = block->nHeight - 1;
        block = block->pprev;
        if (!block || block->nHeight != expected_parent_height) {
            return expected_parent_height;
        }
    }
    return std::nullopt;
}

static ChainstateLoadResult ValidateChainstateRebuildSources(
    ChainstateManager& chainman,
    const CacheSizes& cache_sizes,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    if (options.coins_db_in_memory) return {ChainstateLoadStatus::SUCCESS, {}};

    const size_t cache_bytes = std::max<size_t>(1, cache_sizes.coins_db / 5);
    for (Chainstate* chainstate : chainman.GetAll()) {
        fs::path leveldb_name{"chainstate"};
        if (chainstate->m_from_snapshot_blockhash) {
            leveldb_name += std::string{SNAPSHOT_CHAINSTATE_SUFFIX};
        }
        const fs::path db_path = chainman.m_options.datadir / leveldb_name;
        if (!fs::exists(db_path)) continue;

        chainstate->InitCoinsDB(cache_bytes, /*in_memory=*/false,
                                /*should_wipe=*/false);
        CCoinsViewDB& coins_db = chainstate->CoinsDB();
        const std::vector<uint256> heads = coins_db.GetHeadBlocks();
        uint256 target = coins_db.GetBestBlock();
        if (!heads.empty()) {
            // BatchWrite persists exactly [new_tip, old_tip]. A null new tip
            // cannot be produced by a valid flush and must not authorize a
            // destructive rebuild.
            if (heads.size() != 2 || heads.front().IsNull()) {
                chainstate->ResetCoinsViews();
                return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                        _("Cannot run -reindex-chainstate because the existing chainstate has an unrecognized interrupted-flush marker. The existing chainstate was not wiped. Restart with full -reindex to redownload and rebuild block history; wallets are not removed.")};
            }
            target = heads.front();
        }

        if (target.IsNull()) {
            chainstate->ResetCoinsViews();
            return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                    _("Cannot run -reindex-chainstate because an existing chainstate has no authenticated saved tip. No files were moved or wiped. Restart with full -reindex to rebuild block history; wallets are not removed.")};
        }

        const CBlockIndex* block = chainman.m_blockman.LookupBlockIndex(target);
        if (!block) {
            chainstate->ResetCoinsViews();
            return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                    _("Cannot run -reindex-chainstate because its saved tip is absent from the local block index. The existing chainstate was not wiped. Restart with full -reindex to rebuild the block index and chainstate; wallets are not removed.")};
        }

        const std::optional<int> missing_height =
            FindChainstateRebuildPreflightFailureHeight(
                block, chainman.GetConsensus().hashGenesisBlock);
        if (missing_height) {
            chainstate->ResetCoinsViews();
            return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                    strprintf(_("Cannot run -reindex-chainstate because locally stored, transaction-validated block history is incomplete at height %d. The existing chainstate was not wiped. Disable pruning and restart with full -reindex to redownload and validate missing history; wallets are not removed."),
                              *missing_height)};
        }

        chainstate->ResetCoinsViews();
    }
    return {ChainstateLoadStatus::SUCCESS, {}};
}

static ChainstateLoadResult BeginStagedChainstateRebuild(
    ChainstateManager& chainman,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    AssertLockHeld(::cs_main);
    const fs::path& datadir = chainman.m_options.datadir;
    chainman.m_chainstate_rebuild_interrupted = false;
    chainman.m_chainstate_rebuild_committed_this_process = false;
    chainman.m_chainstate_rebuild_verified_this_process = false;
    RebuildJournal journal{
        2,
        RebuildPhase::PREPARED,
        PathExists(BasePath(datadir)),
        PathExists(SnapshotPath(datadir)),
        std::nullopt,
    };
    if (!journal.base_present && !journal.snapshot_present) {
        return {ChainstateLoadStatus::SUCCESS, {}};
    }
    if (PathExists(BaseBackupPath(datadir)) ||
        PathExists(SnapshotBackupPath(datadir)) ||
        PathExists(BasePartialPath(datadir)) ||
        PathExists(SnapshotPartialPath(datadir)) ||
        PathExists(JournalPath(datadir))) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("Refusing to stage a chainstate rebuild because a journal, backup, or partial rebuild already exists. No data was changed.")};
    }
    auto [space_status, space_error] = CheckRebuildDiskSpace(datadir, options);
    if (space_status != ChainstateLoadStatus::SUCCESS) {
        return {space_status, space_error};
    }
    if (options.check_interrupt && options.check_interrupt()) {
        return {ChainstateLoadStatus::INTERRUPTED, {}};
    }
    if (!WriteJournal(datadir, journal)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("Unable to durably create the chainstate rebuild journal. No chainstate was moved or wiped.")};
    }

    if (journal.base_present) {
        if (options.check_interrupt && options.check_interrupt()) {
            return {ChainstateLoadStatus::INTERRUPTED, {}};
        }
        if (!CommitRename(BasePath(datadir), BaseBackupPath(datadir), datadir)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("Unable to preserve the original chainstate in its rebuild backup. The journal will restore any completed rename on next startup.")};
        }
    }
    if (journal.snapshot_present) {
        if (options.check_interrupt && options.check_interrupt()) {
            return {ChainstateLoadStatus::INTERRUPTED, {}};
        }
        if (!CommitRename(SnapshotPath(datadir), SnapshotBackupPath(datadir), datadir)) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    _("Unable to preserve the snapshot chainstate in its rebuild backup. The journal will restore completed renames on next startup.")};
        }
    }
    if (options.check_interrupt && options.check_interrupt()) {
        return {ChainstateLoadStatus::INTERRUPTED, {}};
    }

    if (chainman.IsSnapshotActive()) {
        chainman.DetachSnapshotChainstateForRebuild();
    }
    journal.phase = RebuildPhase::BUILDING;
    if (!WriteJournal(datadir, journal)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("Unable to durably enter the chainstate rebuild phase. Preserved backups remain journaled and will be restored on next startup.")};
    }
    LogPrintf("Staged chainstate rebuild: original databases preserved until rebuilt state commits\n");
    return {ChainstateLoadStatus::SUCCESS, {}};
}

// Complete initialization of chainstates after the initial call has been made
// to ChainstateManager::InitializeChainstate().
static ChainstateLoadResult CompleteChainstateInitialization(
    ChainstateManager& chainman,
    const CacheSizes& cache_sizes,
    const ChainstateLoadOptions& options) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
{
    // A rebuilding process leaves COMMIT_READY and its source backup in place.
    // The next process must reopen the replacement as an ordinary chainstate
    // before it is allowed to retire that backup. Treat a repeated one-shot
    // -reindex-chainstate flag as verification during this transition rather
    // than attempting to stage another rebuild over the existing journal.
    const bool reopen_committed_rebuild =
        ReopeningCommittedRebuild(chainman.m_options.datadir);
    const bool rebuild_chainstate =
        options.reindex_chainstate && !reopen_committed_rebuild;

    auto& pblocktree{chainman.m_blockman.m_block_tree_db};
    // new BlockTreeDB tries to delete the existing file, which
    // fails if it's still open from the previous loop. Close it first:
    pblocktree.reset();
    pblocktree = std::make_unique<BlockTreeDB>(DBParams{
        .path = chainman.m_options.datadir / "blocks" / "index",
        .cache_bytes = static_cast<size_t>(cache_sizes.block_tree_db),
        .memory_only = options.block_tree_db_in_memory,
        .wipe_data = options.reindex,
        .options = chainman.m_options.block_tree_db});

    if (options.reindex) {
        pblocktree->WriteReindexing(true);
    }

    if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};

    // Validate the persisted snapshot pointer directly against the block-tree
    // database before BlockManager can dereference it while bootstrapping
    // assumeUTXO metadata.
    if (chainman.IsSnapshotActive()) {
        const std::optional<uint256> snapshot_hash = chainman.SnapshotBlockhash();
        const auto assumeutxo = snapshot_hash
            ? chainman.GetParams().AssumeutxoForBlockhash(*snapshot_hash)
            : std::nullopt;
        CDiskBlockIndex disk_base;
        if (!snapshot_hash || !assumeutxo ||
            !pblocktree->ReadBlockIndexEntry(*snapshot_hash, disk_base) ||
            disk_base.nHeight != assumeutxo->height) {
            return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                    _("The snapshot chainstate base is not an approved entry in the local block index. No chainstate was moved or wiped. Move the chainstate_snapshot directory aside or use full -reindex.")};
        }
    }

    // Note that LoadBlockIndex sets fReindex global based on the disk flag!
    // From here on, fReindex and options.reindex values may be different!
    if (!chainman.LoadBlockIndex()) {
        if (options.check_interrupt && options.check_interrupt()) return {ChainstateLoadStatus::INTERRUPTED, {}};
        return {ChainstateLoadStatus::FAILURE, _("Error loading block database")};
    }

    if (!chainman.BlockIndex().empty() &&
            !chainman.m_blockman.LookupBlockIndex(chainman.GetConsensus().hashGenesisBlock)) {
        // If the loaded chain has a wrong genesis, bail out immediately
        // (we're likely using a testnet datadir, or the other way around).
        return {ChainstateLoadStatus::FAILURE_INCOMPATIBLE_DB, _("Incorrect or no genesis block found. Wrong datadir for network?")};
    }

    // Snapshot metadata is read before the block index is loaded. Validate its
    // base against the now-authoritative index before initializing, deleting,
    // or wiping either chainstate. A stale or fabricated base must remain a
    // recoverable startup error rather than reaching SnapshotBase() as null.
    if (chainman.IsSnapshotActive()) {
        const std::optional<uint256> snapshot_base = chainman.SnapshotBlockhash();
        if (!snapshot_base ||
            !chainman.m_blockman.LookupBlockIndex(*snapshot_base)) {
            return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                    _("The snapshot chainstate base block is absent from the local block index. No chainstate was wiped. Remove or restore the snapshot chainstate, or restart with full -reindex to rebuild local block history.")};
        }
    }

    // Authenticate each saved source before moving it. The original databases
    // remain available in a journaled backup while reconstruction performs
    // full block/transaction/signature checks on the chain it actually selects.
    if (rebuild_chainstate && !options.reindex) {
        auto [source_status, source_error] =
            ValidateChainstateRebuildSources(chainman, cache_sizes, options);
        if (source_status != ChainstateLoadStatus::SUCCESS) {
            return {source_status, source_error};
        }
        if (options.check_interrupt && options.check_interrupt()) {
            return {ChainstateLoadStatus::INTERRUPTED, {}};
        }
        auto [stage_status, stage_error] =
            BeginStagedChainstateRebuild(chainman, options);
        if (stage_status != ChainstateLoadStatus::SUCCESS) {
            return {stage_status, stage_error};
        }
    }

    // At this point blocktree args are consistent with what's on disk.
    // If we're not mid-reindex (based on disk + args), add a genesis block on disk
    // (otherwise we use the one already on disk).
    // This is called again in ImportBlocks after the reindex completes.
    if (!fReindex && !chainman.ActiveChainstate().LoadGenesisBlock()) {
        return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
    }

    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.reindex || rebuild_chainstate || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    assert(chainman.m_total_coinstip_cache > 0);
    assert(chainman.m_total_coinsdb_cache > 0);

    // Conservative value which is arbitrarily chosen, as it will ultimately be changed
    // by a call to `chainman.MaybeRebalanceCaches()`. We just need to make sure
    // that the sum of the two caches (40%) does not exceed the allowable amount
    // during this temporary initialization state.
    double init_cache_fraction = 0.2;

    // At this point we're either in reindex or we've loaded a useful
    // block tree into BlockIndex()!

    for (Chainstate* chainstate : chainman.GetAll()) {
        LogPrintf("Initializing chainstate %s\n", chainstate->ToString());

        chainstate->InitCoinsDB(
            /*cache_size_bytes=*/chainman.m_total_coinsdb_cache * init_cache_fraction,
            /*in_memory=*/options.coins_db_in_memory,
            // -reindex-chainstate builds in a fresh live path while the old
            // database remains journaled under its backup name.
            /*should_wipe=*/options.reindex);

        if (options.coins_error_cb) {
            chainstate->CoinsErrorCatcher().AddReadErrCallback(options.coins_error_cb);
        }

        // Refuse to load unsupported database format.
        // This is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        if (chainstate->CoinsDB().NeedsUpgrade()) {
            return {ChainstateLoadStatus::FAILURE_CHAINSTATE_REBUILD_REQUIRED,
                    ChainstateRebuildRequiredMessage()};
        }

        // ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate
        const Chainstate::ReplayResult replay_result = chainstate->ReplayBlocks();
        if (replay_result == Chainstate::ReplayResult::CHAINSTATE_REBUILD_REQUIRED) {
            return {ChainstateLoadStatus::FAILURE_CHAINSTATE_REBUILD_REQUIRED,
                    ChainstateRebuildRequiredMessage()};
        }
        if (replay_result == Chainstate::ReplayResult::FAILURE) {
            return {ChainstateLoadStatus::FAILURE_CHAINSTATE_REBUILD_REQUIRED,
                    ChainstateRebuildRequiredMessage()};
        }
        const Chainstate::ReplayResult shadow_result = chainstate->ReplayShadowBlocks();
        if (shadow_result == Chainstate::ReplayResult::CHAINSTATE_REBUILD_REQUIRED) {
            return {ChainstateLoadStatus::FAILURE_CHAINSTATE_REBUILD_REQUIRED,
                    ChainstateRebuildRequiredMessage()};
        }
        if (shadow_result == Chainstate::ReplayResult::FAILURE) {
            return {ChainstateLoadStatus::FAILURE_CHAINSTATE_REBUILD_REQUIRED,
                    ChainstateRebuildRequiredMessage()};
        }

        // The on-disk coinsdb is now in a good state, create the cache
        chainstate->InitCoinsCache(chainman.m_total_coinstip_cache * init_cache_fraction);
        assert(chainstate->CanFlushToDisk());

        if (!is_coinsview_empty(chainstate)) {
            // LoadChainTip initializes the chain based on CoinsTip()'s best block
            if (!chainstate->LoadChainTip()) {
                return {ChainstateLoadStatus::FAILURE, _("Error initializing block database")};
            }
            assert(chainstate->m_chain.Tip() != nullptr);
        }
    }

    if (!options.reindex) {
        auto chainstates{chainman.GetAll()};
        if (std::any_of(chainstates.begin(), chainstates.end(),
                        [](const Chainstate* cs) EXCLUSIVE_LOCKS_REQUIRED(cs_main) { return cs->NeedsRedownload(); })) {
            return {ChainstateLoadStatus::FAILURE, strprintf(_("Witness data for blocks after height %d requires validation. Please restart with -reindex."),
                                                             chainman.GetConsensus().SegwitHeight)};
        };
    }

    // Now that chainstates are loaded and we're able to flush to
    // disk, rebalance the coins caches to desired levels based
    // on the condition of each chainstate.
    chainman.MaybeRebalanceCaches();

    return {ChainstateLoadStatus::SUCCESS, {}};
}

ChainstateLoadResult LoadChainstate(ChainstateManager& chainman, const CacheSizes& cache_sizes,
                                    const ChainstateLoadOptions& options)
{
    // A load invalidates any verification result previously obtained through
    // this manager. COMMIT_READY cleanup requires verification of the state
    // produced by this exact load operation.
    chainman.m_chainstate_rebuild_verified_this_process = false;
    if (!chainman.AssumedValidBlock().IsNull()) {
        LogPrintf("Assuming ancestors of block %s have valid signatures.\n", chainman.AssumedValidBlock().GetHex());
    } else {
        LogPrintf("Validating signatures for all blocks.\n");
    }
    LogPrintf("Setting nMinimumChainWork=%s\n", chainman.MinimumChainWork().GetHex());
    if (chainman.MinimumChainWork() < UintToArith256(chainman.GetConsensus().nMinimumChainWork)) {
        LogPrintf("Warning: nMinimumChainWork set below default value of %s\n", chainman.GetConsensus().nMinimumChainWork.GetHex());
    }
    if (chainman.m_blockman.GetPruneTarget() == BlockManager::PRUNE_TARGET_MANUAL) {
        LogPrintf("Block pruning enabled.  Use RPC call pruneblockchain(height) to manually prune block and undo files.\n");
    } else if (chainman.m_blockman.GetPruneTarget()) {
        LogPrintf("Prune configured to target %u MiB on disk for block and undo files.\n", chainman.m_blockman.GetPruneTarget() / 1024 / 1024);
    }

    LOCK(cs_main);

    chainman.m_total_coinstip_cache = cache_sizes.coins;
    chainman.m_total_coinsdb_cache = cache_sizes.coins_db;

    const auto [recovery_status, recovery_error] =
        RecoverInterruptedRebuild(chainman);
    if (recovery_status != ChainstateLoadStatus::SUCCESS) {
        return {recovery_status, recovery_error};
    }
    if (options.reindex &&
        ReopeningCommittedRebuild(chainman.m_options.datadir)) {
        return {ChainstateLoadStatus::FAILURE_FATAL,
                _("A rebuilt chainstate is awaiting its protected verification restart. Restart once without -reindex so the preserved backup can be verified and retired, then retry the full reindex if it is still required.")};
    }

    // Load the fully validated chainstate.
    chainman.InitializeChainstate(options.mempool);

    // Load a chain created from a UTXO snapshot, if any exist. A full reindex
    // removes it before the block index is wiped, so an interrupted startup
    // cannot leave an empty index paired with a stale snapshot. A
    // chainstate-only rebuild defers deletion until block-data preflight.
    const bool snapshot_dir_present =
        node::FindSnapshotChainstateDir(chainman.m_options.datadir).has_value();
    const bool has_snapshot = chainman.DetectSnapshotChainstate();
    if (snapshot_dir_present && !has_snapshot) {
        return {ChainstateLoadStatus::FAILURE_FULL_REINDEX_REQUIRED,
                _("A snapshot chainstate directory exists but its base-block metadata is missing, malformed, or unreadable. No chainstate was wiped. Remove or restore the malformed snapshot directory before retrying; use full -reindex if local block history also requires recovery.")};
    }
    if (has_snapshot && options.reindex) {
        LogPrintf("[snapshot] deleting snapshot chainstate before full reindex\n");
        if (!chainman.DeleteSnapshotChainstate()) {
            return {ChainstateLoadStatus::FAILURE_FATAL,
                    Untranslated("Couldn't remove snapshot chainstate.")};
        }
    }

    auto [init_status, init_error] = CompleteChainstateInitialization(chainman, cache_sizes, options);
    if (init_status != ChainstateLoadStatus::SUCCESS) {
        return {init_status, init_error};
    }

    // If a snapshot chainstate was fully validated by a background chainstate during
    // the last run, detect it here and clean up the now-unneeded background
    // chainstate.
    //
    // Why is this cleanup done here (on subsequent restart) and not just when the
    // snapshot is actually validated? Because this entails unusual
    // filesystem operations to move leveldb data directories around, and that seems
    // too risky to do in the middle of normal runtime.
    auto snapshot_completion = chainman.MaybeCompleteSnapshotValidation();

    if (snapshot_completion == SnapshotCompletionResult::SKIPPED) {
        // do nothing; expected case
    } else if (snapshot_completion == SnapshotCompletionResult::SUCCESS) {
        LogPrintf("[snapshot] cleaning up unneeded background chainstate, then reinitializing\n");
        if (!chainman.ValidatedSnapshotCleanup()) {
            return {ChainstateLoadStatus::FAILURE_FATAL, Untranslated("Background chainstate cleanup failed unexpectedly.")};
        }

        // Because ValidatedSnapshotCleanup() has torn down chainstates with
        // ChainstateManager::ResetChainstates(), reinitialize them here without
        // duplicating the blockindex work above.
        assert(chainman.GetAll().empty());
        assert(!chainman.IsSnapshotActive());
        assert(!chainman.IsSnapshotValidated());

        chainman.InitializeChainstate(options.mempool);

        // A reload of the block index is required to recompute setBlockIndexCandidates
        // for the fully validated chainstate.
        chainman.ActiveChainstate().ClearBlockIndexCandidates();

        auto [init_status, init_error] = CompleteChainstateInitialization(chainman, cache_sizes, options);
        if (init_status != ChainstateLoadStatus::SUCCESS) {
            return {init_status, init_error};
        }
    } else {
        return {ChainstateLoadStatus::FAILURE, _(
           "UTXO snapshot failed to validate. "
           "Restart to resume normal initial block download, or try loading a different snapshot.")};
    }

    return {ChainstateLoadStatus::SUCCESS, {}};
}

static bool RebuiltChainReachesPreservedWork(
    ChainstateManager& chainman,
    const RebuildJournal& journal,
    bilingual_str& error)
{
    const fs::path& datadir = chainman.m_options.datadir;
    const std::array<std::pair<bool, fs::path>, 2> sources{{
        {journal.base_present, BaseBackupPath(datadir)},
        {journal.snapshot_present, SnapshotBackupPath(datadir)},
    }};

    for (const auto& [present, path] : sources) {
        if (!present) continue;
        if (!PathExists(path)) {
            error = strprintf(_("Cannot authenticate preserved chainstate source %s because it is missing."), fs::PathToString(path));
            return false;
        }
        try {
            CCoinsViewDB source_db{DBParams{
                .path = path,
                .cache_bytes = 1 << 20,
                .memory_only = false,
                .wipe_data = false,
                .obfuscate = true}, CoinsViewOptions{}};
            const std::vector<uint256> heads = source_db.GetHeadBlocks();
            uint256 target = source_db.GetBestBlock();
            if (!heads.empty()) {
                if (heads.size() != 2 || heads.front().IsNull()) {
                    error = strprintf(_("Cannot commit the rebuilt chainstate because preserved source %s has an invalid interrupted-flush marker."), fs::PathToString(path));
                    return false;
                }
                target = heads.front();
            }
            if (target.IsNull()) {
                error = strprintf(_("Cannot commit the rebuilt chainstate because preserved source %s has no authenticated tip."), fs::PathToString(path));
                return false;
            }

            const bool sufficient_work = WITH_LOCK(::cs_main, {
                const CBlockIndex* source_tip =
                    chainman.m_blockman.LookupBlockIndex(target);
                const CBlockIndex* rebuilt_tip =
                    chainman.ActiveChainstate().m_chain.Tip();
                return source_tip && rebuilt_tip &&
                    rebuilt_tip->nChainWork >= source_tip->nChainWork;
            });
            if (!sufficient_work) {
                error = strprintf(_("Cannot commit the rebuilt chainstate because it does not reach the validated work of preserved source %s. The preserved database will be restored on restart."), fs::PathToString(path));
                return false;
            }
        } catch (const std::exception& e) {
            error = strprintf(_("Cannot authenticate preserved chainstate source %s before commit: %s"), fs::PathToString(path), e.what());
            return false;
        }
    }
    return true;
}

bool FinalizeChainstateRebuild(ChainstateManager& chainman, bilingual_str& error)
{
    const fs::path& datadir = chainman.m_options.datadir;
    if (!PathExists(JournalPath(datadir))) return true;

    std::string parse_error;
    std::optional<RebuildJournal> journal = ReadJournal(datadir, parse_error);
    if (!journal || (journal->phase != RebuildPhase::BUILDING &&
                     journal->phase != RebuildPhase::COMMIT_READY)) {
        if (parse_error.empty()) parse_error = "unsupported rebuild phase";
        error = strprintf(_("Cannot commit the rebuilt chainstate because its journal is invalid (%s). Preserved backups were not removed."), parse_error);
        return false;
    }
    if (journal->version != 2) {
        error = _("Cannot commit a chainstate rebuild recorded by an old journal version without a full-Coin commitment. Preserved backups were not removed.");
        return false;
    }
    std::string topology_error;
    if (!ValidateBackupTopology(datadir, *journal,
                                /*allow_missing_expected=*/false,
                                topology_error)) {
        error = strprintf(_("Cannot commit the rebuilt chainstate because its backup topology is inconsistent (%s). Preserved data was not removed."), topology_error);
        return false;
    }

    // COMMIT_READY written by this manager proves a durable build, but not a
    // separate-process reopen. Leave the backup in place until next startup.
    if (journal->phase == RebuildPhase::COMMIT_READY &&
        chainman.m_chainstate_rebuild_committed_this_process) {
        return true;
    }

    if (journal->phase == RebuildPhase::COMMIT_READY &&
        !chainman.m_chainstate_rebuild_verified_this_process) {
        error = _("The rebuilt chainstate has not completed verification in this process. Preserved backups were not removed.");
        return false;
    }

    if (chainman.m_chainstate_rebuild_interrupted || chainman.m_interrupt) {
        chainman.m_chainstate_rebuild_interrupted = true;
        error = journal->phase == RebuildPhase::BUILDING
            ? _("Chainstate reconstruction was interrupted. The preserved database will be restored on restart.")
            : _("Reopened-chainstate verification was interrupted. Preserved backups were not removed; retry in a fresh process.");
        return false;
    }
    if (!RebuiltChainReachesPreservedWork(chainman, *journal, error)) {
        return false;
    }

    BlockValidationState flush_state;
    if (!chainman.ActiveChainstate().FlushStateToDisk(
            flush_state, FlushStateMode::ALWAYS)) {
        error = strprintf(_("Cannot durably flush the rebuilt chainstate (%s). Preserved backups were not removed."),
                          flush_state.ToString());
        return false;
    }
    if (chainman.m_interrupt) {
        chainman.m_chainstate_rebuild_interrupted = true;
        error = journal->phase == RebuildPhase::BUILDING
            ? _("Chainstate reconstruction was interrupted before commit. The preserved database will be restored on restart.")
            : _("Reopened-chainstate verification was interrupted before cleanup. Preserved backups were not removed; retry in a fresh process.");
        return false;
    }

    try {
        // Keep the active chain and its on-disk Coin set stable from the scan
        // through the durable phase transition and any authorized cleanup.
        // Otherwise a concurrent flush could change the database after it was
        // authenticated but before the preserved source was retired.
        LOCK(::cs_main);
        const CBlockIndex* active_tip = chainman.ActiveChainstate().m_chain.Tip();
        if (!active_tip) {
            error = _("Cannot authenticate the rebuilt chainstate's full-Coin set because the active chainstate has no tip. Preserved backups were not removed.");
            return false;
        }
        RebuildCommitment current_commitment;
        std::string commitment_error;
        const CommitmentResult commitment_result = ComputeFullCoinCommitment(
            chainman.ActiveChainstate().CoinsDB(),
            [&chainman] { return bool{chainman.m_interrupt}; },
            current_commitment,
            commitment_error);
        if (commitment_result == CommitmentResult::INTERRUPTED) {
            chainman.m_chainstate_rebuild_interrupted = true;
            error = _("The full-Coin commitment scan was interrupted. Preserved backups were not removed.");
            return false;
        }
        if (commitment_result != CommitmentResult::SUCCESS) {
            error = strprintf(_("Cannot authenticate the rebuilt chainstate's full-Coin set (%s). Preserved backups were not removed."), commitment_error);
            return false;
        }
        if (current_commitment.tip != active_tip->GetBlockHash()) {
            error = _("Cannot authenticate the rebuilt chainstate because its persisted tip does not match the active chain tip. Preserved backups were not removed.");
            return false;
        }

        if (journal->phase == RebuildPhase::BUILDING) {
            journal->commitment = current_commitment;
            journal->phase = RebuildPhase::COMMIT_READY;
            if (!WriteJournal(datadir, *journal)) {
                error = _("Cannot durably commit the rebuilt chainstate. Preserved backups were not removed and will be restored on restart.");
                return false;
            }
            chainman.m_chainstate_rebuild_committed_this_process = true;
            LogPrintf("Committed staged chainstate rebuild; preserved database will be retired only after a verified restart\n");
            return true;
        }

        if (!journal->commitment || current_commitment != *journal->commitment) {
            error = _("The reopened chainstate does not match the full-Coin commitment recorded at rebuild commit. Preserved backups were not removed.");
            return false;
        }

        // This manager reopened and verified a COMMIT_READY replacement. Make
        // that fact durable before beginning retryable backup cleanup.
        journal->phase = RebuildPhase::CLEANUP_READY;
        if (!WriteJournal(datadir, *journal)) {
            error = _("The rebuilt chainstate was reopened and verified, but that state could not be committed for backup cleanup. The preserved backups were not removed.");
            return false;
        }
        if ((journal->base_present && !CleanupTree(BaseBackupPath(datadir))) ||
            (journal->snapshot_present && !CleanupTree(SnapshotBackupPath(datadir))) ||
            !DirectoryCommit(datadir) || !RemoveJournal(datadir)) {
            error = _("The rebuilt chainstate was reopened and verified, but preserved backup cleanup could not be completed. Correct filesystem permissions and retry.");
            return false;
        }
        CleanupTree(BasePartialPath(datadir));
        CleanupTree(SnapshotPartialPath(datadir));
        DirectoryCommit(datadir);
        LogPrintf("Verified the rebuilt chainstate after restart and retired preserved databases\n");
        return true;
    } catch (const std::exception& e) {
        error = strprintf(_("Chainstate rebuild authentication or cleanup stopped because of a filesystem/database error (%s). Preserve the datadir and any remaining rebuild backups."), e.what());
        return false;
    }
}

ChainstateLoadResult VerifyLoadedChainstate(ChainstateManager& chainman, const ChainstateLoadOptions& options)
{
    // Clear first so a failed, interrupted, or repeated verification cannot
    // inherit a successful result from an earlier call on the same manager.
    chainman.m_chainstate_rebuild_verified_this_process = false;
    const bool rebuild_chainstate =
        options.reindex_chainstate &&
        !ReopeningCommittedRebuild(chainman.m_options.datadir);
    auto is_coinsview_empty = [&](Chainstate* chainstate) EXCLUSIVE_LOCKS_REQUIRED(::cs_main) {
        return options.reindex || rebuild_chainstate || chainstate->CoinsTip().GetBestBlock().IsNull();
    };

    LOCK(cs_main);

    for (Chainstate* chainstate : chainman.GetAll()) {
        if (!is_coinsview_empty(chainstate)) {
            const CBlockIndex* tip = chainstate->m_chain.Tip();
            if (tip && tip->nTime > GetTime() + MAX_FUTURE_BLOCK_TIME) {
                return {ChainstateLoadStatus::FAILURE, _("The block database contains a block which appears to be from the future. "
                                                         "This may be due to your computer's date and time being set incorrectly. "
                                                         "Only rebuild the block database if you are sure that your computer's date and time are correct")};
            }

            VerifyDBResult result = CVerifyDB(chainman.GetNotifications()).VerifyDB(
                *chainstate, chainman.GetConsensus(), chainstate->CoinsDB(),
                options.check_level,
                options.check_blocks);
            switch (result) {
            case VerifyDBResult::SUCCESS:
            case VerifyDBResult::SKIPPED_MISSING_BLOCKS:
                break;
            case VerifyDBResult::INTERRUPTED:
                return {ChainstateLoadStatus::INTERRUPTED, _("Block verification was interrupted")};
            case VerifyDBResult::CORRUPTED_BLOCK_DB:
                return {ChainstateLoadStatus::FAILURE, _("Corrupted block database detected")};
            case VerifyDBResult::SKIPPED_L3_CHECKS:
                if (options.require_full_verification) {
                    return {ChainstateLoadStatus::FAILURE_INSUFFICIENT_DBCACHE, _("Insufficient dbcache for block verification")};
                }
                break;
            } // no default case, so the compiler can warn about missing cases
        }
    }

    chainman.m_chainstate_rebuild_verified_this_process = true;
    return {ChainstateLoadStatus::SUCCESS, {}};
}
} // namespace node
