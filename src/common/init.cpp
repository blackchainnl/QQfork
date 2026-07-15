// Copyright (c) 2023 Blackcoin Core Developers
// Copyright (c) 2023 Blackcoin More Developers
// Copyright (c) 2023 Blackcoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <compat/compat.h>
#include <common/args.h>
#include <common/init.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <random.h>
#include <tinyformat.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <stdexcept>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace {

constexpr const char* LEGACY_BLACKMORE_CONF_FILENAME = "blackmore.conf";
constexpr const char* MIGRATION_DONE_FILENAME = ".blackcoin-migration-done";
constexpr const char* MIGRATION_RECOVERY_FILENAME = ".blackcoin-migration-recovery";
constexpr const char* MIGRATION_LOCK_FILENAME = ".lock";
constexpr const char* MIGRATION_OPERATION_LOCK_SUFFIX = ".migration.lock";
constexpr std::array<const char*, 3> LEGACY_NETWORK_DIRS{"testnet", "signet", "regtest"};
constexpr std::array<std::string_view, 4> MIGRATION_TEST_TRANSITIONS{
    "staged-import-ready", "recovery-record-ready", "active-moved",
    "promoted"};

enum class MigrationChoice {
    AUTO,
    BLACKMORE,
    BLACKCOIN,
    NONE,
    ABORT, //!< user chose to exit without deciding; leave everything untouched
};

struct LegacySource {
    const char* label;
    fs::path path;
    const char* config_filename;
};

//! Front-end progress sink for the first-run migration; set once by
//! InitConfig before any migration work starts (single-threaded init path).
common::MigrationProgressFn g_migration_progress_fn;

void ReportMigrationProgress(const std::string& phase, int progress_percent)
{
    if (g_migration_progress_fn) g_migration_progress_fn(phase, progress_percent);
}

bool IsSupportedMigrationTestTransition(std::string_view transition)
{
    return std::find(MIGRATION_TEST_TRANSITIONS.begin(),
                     MIGRATION_TEST_TRANSITIONS.end(), transition) !=
        MIGRATION_TEST_TRANSITIONS.end();
}

fs::path MigrationTestPauseMarker(const fs::path& destination)
{
    fs::path marker{destination.parent_path()};
    marker /= fs::PathFromString(
        fs::PathToString(destination.filename()) + ".migration-test-pause");
    return marker;
}

void MaybePauseMigrationForTest(const ArgsManager& args,
                                const fs::path& destination,
                                std::string_view transition)
{
    const std::string selected =
        args.GetArg("-testdatadirmigrationpauseafter", "");
    if (selected != transition) return;

    const fs::path marker = MigrationTestPauseMarker(destination);
    {
        std::ofstream stream{marker};
        if (!stream.is_open()) {
            throw std::runtime_error(strprintf(
                "unable to create datadir migration test pause marker %s",
                fs::PathToString(marker)));
        }
        stream << transition << '\n';
        stream.flush();
        if (!stream.good()) {
            throw std::runtime_error(strprintf(
                "unable to write datadir migration test pause marker %s",
                fs::PathToString(marker)));
        }
    }
    DirectoryCommit(marker.parent_path());
    LogPrintf("Regtest datadir migration paused after durable %s transition; kill the process or remove %s to resume\n",
              transition, fs::PathToString(marker));
    while (fs::exists(marker)) {
        UninterruptibleSleep(std::chrono::milliseconds{10});
    }
}

bool PathExistsNoThrow(const fs::path& path)
{
    try {
        return fs::exists(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsDirectoryNoThrow(const fs::path& path)
{
    try {
        return fs::is_directory(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsRegularFileNoThrow(const fs::path& path)
{
    try {
        return fs::is_regular_file(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool PathIsSymlinkNoThrow(const fs::path& path)
{
    try {
        return fs::is_symlink(path);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy path %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

bool DirectoryHasEntriesNoThrow(const fs::path& path)
{
    try {
        if (!fs::is_directory(path)) return false;
        return fs::directory_iterator(path) != fs::directory_iterator();
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect legacy directory %s: %s\n", fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

fs::path NormalizedAbsolutePath(const fs::path& path)
{
    return fs::absolute(path).lexically_normal();
}

/**
 * Own migration-time file locks directly instead of putting them in the
 * process-global directory-lock map. This makes the lifetime explicit and
 * prevents a helper from accidentally releasing a lock held by the migration.
 */
class MigrationLockSet
{
public:
    bool TryLockFile(const fs::path& lock_path, const std::string& purpose, std::string& failure)
    {
        const fs::path normalized = NormalizedAbsolutePath(lock_path);
        const std::string key = fs::PathToString(normalized);
        if (m_lock_paths.count(key) != 0) return true;

        FILE* file = fsbridge::fopen(normalized, "a");
        if (file == nullptr) {
            failure = strprintf("unable to create %s lock file %s", purpose, fs::quoted(key));
            return false;
        }
        if (std::fclose(file) != 0) {
            failure = strprintf("unable to close %s lock file %s", purpose, fs::quoted(key));
            return false;
        }

        auto lock = std::make_unique<fsbridge::FileLock>(normalized);
        if (!lock->TryLock()) {
            failure = strprintf("%s is already locked at %s: %s", purpose, fs::quoted(key), lock->GetReason());
            return false;
        }
        m_lock_paths.insert(key);
        m_locks.emplace_back(normalized, std::move(lock));
        return true;
    }

    bool TryLockDirectory(const fs::path& directory, const std::string& purpose, std::string& failure)
    {
        return TryLockFile(DirectoryIdentity(directory) / MIGRATION_LOCK_FILENAME, purpose, failure);
    }

    bool HoldsDirectory(const fs::path& directory) const
    {
        return m_lock_paths.count(fs::PathToString(NormalizedAbsolutePath(DirectoryIdentity(directory) / MIGRATION_LOCK_FILENAME))) != 0;
    }

    void ReleaseDirectory(const fs::path& directory)
    {
        const fs::path normalized = NormalizedAbsolutePath(DirectoryIdentity(directory) / MIGRATION_LOCK_FILENAME);
        const std::string key = fs::PathToString(normalized);
        m_lock_paths.erase(key);
        m_locks.erase(std::remove_if(m_locks.begin(), m_locks.end(), [&](const auto& held_lock) {
            return held_lock.first == normalized;
        }), m_locks.end());
    }

    fs::path DirectoryIdentity(const fs::path& directory) const
    {
        std::error_code ec;
        const fs::path canonical = fs::canonical(directory, ec);
        return ec ? NormalizedAbsolutePath(directory) : canonical;
    }

private:
    std::set<std::string> m_lock_paths;
    std::vector<std::pair<fs::path, std::unique_ptr<fsbridge::FileLock>>> m_locks;
};

bool DestinationAllowsLegacyMigration(const fs::path& destination)
{
    if (!PathExistsNoThrow(destination)) return true;
    try {
        return fs::is_directory(destination) && fs::is_empty(destination);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to inspect Blackcoin datadir %s: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

std::vector<fs::path> BlackmoreDataDirCandidates(const fs::path& new_base_path)
{
    std::vector<fs::path> candidates;
    const fs::path normalized_new_base = NormalizedAbsolutePath(new_base_path);

    auto add_candidate = [&](const fs::path& candidate) {
        if (candidate.empty()) return;
        const fs::path normalized = NormalizedAbsolutePath(candidate);
        if (normalized == normalized_new_base) return;
        if (std::find(candidates.begin(), candidates.end(), normalized) == candidates.end()) {
            candidates.push_back(normalized);
        }
    };

    if (!new_base_path.parent_path().empty()) {
        const fs::path sibling_base = new_base_path.parent_path();
        add_candidate(sibling_base / "Blackmore");
        add_candidate(sibling_base / ".blackmore");
    }

    if (const char* home = std::getenv("HOME")) {
        const fs::path home_path{home};
        add_candidate(home_path / ".blackmore");
    }
    if (const char* appdata = std::getenv("APPDATA")) {
        add_candidate(fs::path{appdata} / "Blackmore");
    }

    return candidates;
}

bool HasDataPayload(const fs::path& base_path, const char* primary_config_filename)
{
    if (!PathIsDirectoryNoThrow(base_path)) return false;

    bool has_payload =
        PathExistsNoThrow(base_path / primary_config_filename) ||
        PathExistsNoThrow(base_path / BITCOIN_CONF_FILENAME) ||
        PathExistsNoThrow(base_path / LEGACY_BLACKMORE_CONF_FILENAME) ||
        PathExistsNoThrow(base_path / BITCOIN_SETTINGS_FILENAME) ||
        PathExistsNoThrow(base_path / "wallet.dat") ||
        DirectoryHasEntriesNoThrow(base_path / "wallets") ||
        DirectoryHasEntriesNoThrow(base_path / "blocks") ||
        DirectoryHasEntriesNoThrow(base_path / "chainstate");

    for (const char* network_dir : LEGACY_NETWORK_DIRS) {
        const fs::path legacy_net_path = base_path / network_dir;
        has_payload = has_payload ||
            PathExistsNoThrow(legacy_net_path / "wallet.dat") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "wallets") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "blocks") ||
            DirectoryHasEntriesNoThrow(legacy_net_path / "chainstate");
    }
    return has_payload;
}

bool HasMigrationDoneMarker(const fs::path& destination)
{
    return PathIsRegularFileNoThrow(destination / MIGRATION_DONE_FILENAME);
}

std::string UniqueMigrationSuffix(const std::string& label)
{
    static std::atomic<uint64_t> sequence{0};
    FastRandomContext rng;
    const auto wall_ticks = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
#ifdef WIN32
    const uint64_t process_id = static_cast<uint64_t>(GetCurrentProcessId());
#else
    const uint64_t process_id = static_cast<uint64_t>(getpid());
#endif
    return strprintf("%s-%d-%d-%d-%s",
                     label,
                     wall_ticks,
                     process_id,
                     sequence.fetch_add(1),
                     HexStr(rng.randbytes(8)));
}

fs::path UniqueMigrationPath(const fs::path& destination, const std::string& suffix)
{
    fs::path temp = destination;
    temp += "." + UniqueMigrationSuffix(suffix);
    return temp;
}

fs::path MigrationBackupRoot(const fs::path& destination)
{
    fs::path backup_root = destination;
    backup_root += ".backup";
    return backup_root;
}

fs::path MigrationRecoveryPath(const fs::path& destination)
{
    return MigrationBackupRoot(destination) / MIGRATION_RECOVERY_FILENAME;
}

fs::path MigrationOperationLockPath(const fs::path& destination)
{
    const std::string filename = fs::PathToString(destination.filename()) + MIGRATION_OPERATION_LOCK_SUFFIX;
    const fs::path parent{destination.parent_path()};
    const fs::path lock_filename{fs::PathFromString(filename)};
    return parent / lock_filename;
}

fs::path UniqueBackupPath(const fs::path& destination, const std::string& label)
{
    return MigrationBackupRoot(destination) / fs::PathFromString(UniqueMigrationSuffix(label));
}

bool PathNameStartsWith(const fs::path& path, const std::string& prefix)
{
    return fs::PathToString(path.filename()).rfind(prefix, 0) == 0;
}

bool PathNameContains(const fs::path& path, const std::string& fragment)
{
    return fs::PathToString(path.filename()).find(fragment) != std::string::npos;
}

void RemoveStaleMigrationPath(const fs::path& path)
{
    std::error_code remove_ec;
    fs::remove_all(path, remove_ec);
    if (remove_ec) {
        LogPrintf("Warning: failed to remove stale migration temp path %s: %s\n",
                  fs::quoted(fs::PathToString(path)),
                  remove_ec.message());
    }
}

void CleanupStaleMigrationTemps(const fs::path& destination)
{
    if (destination.parent_path().empty() || !PathIsDirectoryNoThrow(destination.parent_path())) return;

    const std::string base_name = fs::PathToString(destination.filename());
    std::error_code ec;
    for (fs::directory_iterator it(destination.parent_path(), fs::directory_options::skip_permission_denied, ec), end; it != end && !ec; it.increment(ec)) {
        const fs::path path = it->path();
        if (PathNameStartsWith(path, base_name + ".tmp-") || PathNameStartsWith(path, base_name + ".import-")) {
            RemoveStaleMigrationPath(path);
        }
    }

    // A crash while writing the completion marker can leave only its uniquely
    // named staging file. It is never authoritative and is safe to remove
    // while the operation lock is held.
    if (PathIsDirectoryNoThrow(destination)) {
        std::error_code destination_ec;
        for (fs::directory_iterator it(destination, fs::directory_options::skip_permission_denied, destination_ec), end; it != end && !destination_ec; it.increment(destination_ec)) {
            if (PathNameStartsWith(it->path(), std::string{MIGRATION_DONE_FILENAME} + ".tmp-")) {
                RemoveStaleMigrationPath(it->path());
            }
        }
    }

    // Backup copies use unique final names and a second unique `.tmp-` suffix
    // while being populated. Only the latter are incomplete. A completed
    // backup never contains `.tmp-` in its generated name and is preserved.
    const fs::path backup_root = MigrationBackupRoot(destination);
    if (PathIsDirectoryNoThrow(backup_root)) {
        std::error_code backup_ec;
        for (fs::directory_iterator it(backup_root, fs::directory_options::skip_permission_denied, backup_ec), end; it != end && !backup_ec; it.increment(backup_ec)) {
            const bool incomplete_backup =
                (PathNameStartsWith(it->path(), "original-blackcoin-") || PathNameStartsWith(it->path(), "blackmore-")) &&
                PathNameContains(it->path(), ".tmp-");
            const bool incomplete_recovery_record =
                PathNameStartsWith(it->path(), std::string{MIGRATION_RECOVERY_FILENAME} + ".tmp-");
            if (incomplete_backup || incomplete_recovery_record) {
                RemoveStaleMigrationPath(it->path());
            }
        }
    }
}

std::optional<fs::path> ResolveSourceRoot(const fs::path& source)
{
    if (!PathIsDirectoryNoThrow(source)) return std::nullopt;

    std::error_code ec;
    const fs::path resolved_source = fs::canonical(source, ec);
    if (ec || !PathIsDirectoryNoThrow(resolved_source)) {
        LogPrintf("Warning: refusing legacy datadir migration from unresolved source root %s: %s\n",
                  fs::quoted(fs::PathToString(source)),
                  ec ? ec.message() : "target is not a directory");
        return std::nullopt;
    }
    if (PathIsSymlinkNoThrow(source)) {
        LogPrintf("Blackcoin: legacy datadir source %s is a symlink; migrating resolved target %s\n",
                  fs::quoted(fs::PathToString(source)),
                  fs::quoted(fs::PathToString(resolved_source)));
    }
    return resolved_source;
}

bool AcquireSourceDirectoryLocks(const fs::path& resolved_source, MigrationLockSet& locks, std::string& failure)
{
    std::vector<fs::path> directories{resolved_source};
    for (const char* network_dir : LEGACY_NETWORK_DIRS) {
        const fs::path candidate = resolved_source / network_dir;
        if (!PathIsDirectoryNoThrow(candidate)) continue;

        std::error_code ec;
        const fs::path resolved_network = fs::canonical(candidate, ec);
        if (ec || !PathIsDirectoryNoThrow(resolved_network)) {
            failure = strprintf("unable to resolve legacy network datadir %s: %s",
                                fs::quoted(fs::PathToString(candidate)),
                                ec ? ec.message() : "target is not a directory");
            return false;
        }
        directories.push_back(resolved_network);
    }

    std::sort(directories.begin(), directories.end(), [](const fs::path& lhs, const fs::path& rhs) {
        return fs::PathToString(lhs) < fs::PathToString(rhs);
    });
    directories.erase(std::unique(directories.begin(), directories.end()), directories.end());

    for (const fs::path& directory : directories) {
        if (!locks.TryLockDirectory(directory, "legacy source datadir", failure)) return false;
    }
    return true;
}

std::optional<fs::path> ResolveAndLockSourceRoot(const fs::path& source, MigrationLockSet& locks, std::string& failure)
{
    const std::optional<fs::path> resolved_source = ResolveSourceRoot(source);
    if (!resolved_source) {
        failure = strprintf("unable to resolve legacy source datadir %s", fs::quoted(fs::PathToString(source)));
        return std::nullopt;
    }
    if (!AcquireSourceDirectoryLocks(*resolved_source, locks, failure)) return std::nullopt;
    return resolved_source;
}

bool PathIsRealDirectoryNoThrow(const fs::path& path)
{
    return PathIsDirectoryNoThrow(path) && !PathIsSymlinkNoThrow(path);
}

bool WriteDurableTextFile(const fs::path& path, const std::string& text)
{
    const fs::path temp_path = UniqueMigrationPath(path, "tmp");
    try {
        fs::create_directories(path.parent_path());
        FILE* file = fsbridge::fopen(temp_path, "wb");
        if (!file) return false;

        const bool wrote_all = std::fwrite(text.data(), 1, text.size(), file) == text.size();
        const bool committed = wrote_all && FileCommit(file);
        const bool closed = std::fclose(file) == 0;
        if (!committed || !closed) {
            std::error_code remove_ec;
            fs::remove(temp_path, remove_ec);
            return false;
        }

        if (!RenameOver(temp_path, path)) {
            std::error_code remove_ec;
            fs::remove(temp_path, remove_ec);
            return false;
        }
        DirectoryCommit(path.parent_path());
        return true;
    } catch (const std::exception& e) {
        std::error_code remove_ec;
        fs::remove(temp_path, remove_ec);
        LogPrintf("Warning: failed to durably replace migration file %s: %s\n",
                  fs::quoted(fs::PathToString(path)), e.what());
        return false;
    }
}

//! Transient per-network state that must not follow a legacy datadir into a
//! new client: serialization formats drift between forks and a stale
//! peers.dat or mempool.dat turns the first post-upgrade start into a hard
//! "corrupt file" error. All of these are safely regenerated from scratch.
bool IsTransientNetworkFile(const fs::path& filename)
{
    static const std::array<const char*, 8> TRANSIENT_FILES{
        "peers.dat", "banlist.dat", "banlist.json", "anchors.dat",
        "mempool.dat", "fee_estimates.dat", "db.log", "debug.log"};
    const std::string name = fs::PathToString(filename);
    for (const char* transient : TRANSIENT_FILES) {
        if (name == transient) return true;
    }
    return false;
}

enum class MigrationEntryType : uint8_t {
    DIRECTORY,
    REGULAR_FILE,
    SYMLINK,
};

struct MigrationCopyPlan {
    bool skip_blocks{false};
    bool skip_transient{false};
    bool skip_lock_files{false};
};

struct MigrationManifestEntry {
    fs::path relative_path;
    MigrationEntryType type{MigrationEntryType::DIRECTORY};
    uintmax_t size{0};
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash{};
    fs::path symlink_target;

    bool operator==(const MigrationManifestEntry& other) const
    {
        return relative_path == other.relative_path &&
            type == other.type &&
            size == other.size &&
            hash == other.hash &&
            symlink_target == other.symlink_target;
    }
};

using MigrationManifest = std::vector<MigrationManifestEntry>;

bool ShouldSkipMigrationEntry(const fs::path& relative, const fs::file_status& status, const MigrationCopyPlan& plan)
{
    if (plan.skip_lock_files && relative.filename() == MIGRATION_LOCK_FILENAME) return true;
    // `blocks` may itself be a symlink to a separately mounted block store.
    // A plan that excludes block data must exclude that entry by name before
    // considering its type; preserving the symlink in a backup would make the
    // supposedly self-contained recovery tree depend on an external path.
    if (plan.skip_blocks && relative.filename() == "blocks") return true;
    if (plan.skip_transient && fs::is_regular_file(status) && IsTransientNetworkFile(relative.filename())) return true;
    return false;
}

std::pair<uintmax_t, std::array<unsigned char, CSHA256::OUTPUT_SIZE>> HashRegularFile(const fs::path& path)
{
    FILE* file = fsbridge::fopen(path, "rb");
    if (file == nullptr) {
        throw std::runtime_error(strprintf("unable to open regular file %s for migration verification", fs::PathToString(path)));
    }

    CSHA256 hasher;
    uintmax_t size{0};
    std::array<unsigned char, 64 * 1024> buffer{};
    while (true) {
        const size_t bytes_read = std::fread(buffer.data(), 1, buffer.size(), file);
        if (bytes_read > 0) {
            if (size > std::numeric_limits<uintmax_t>::max() - bytes_read) {
                std::fclose(file);
                throw std::runtime_error(strprintf("regular file %s is too large to manifest safely", fs::PathToString(path)));
            }
            size += bytes_read;
            hasher.Write(buffer.data(), bytes_read);
        }
        if (bytes_read == buffer.size()) continue;
        if (std::ferror(file)) {
            std::fclose(file);
            throw std::runtime_error(strprintf("failed while reading regular file %s for migration verification", fs::PathToString(path)));
        }
        break;
    }
    if (std::fclose(file) != 0) {
        throw std::runtime_error(strprintf("failed to close regular file %s after migration verification", fs::PathToString(path)));
    }

    std::array<unsigned char, CSHA256::OUTPUT_SIZE> hash{};
    hasher.Finalize(hash.data());
    return {size, hash};
}

MigrationManifestEntry ManifestEntryForPath(const fs::path& root, const fs::path& path, const fs::file_status& status)
{
    MigrationManifestEntry entry;
    entry.relative_path = path.lexically_relative(root);
    if (fs::is_directory(status)) {
        entry.type = MigrationEntryType::DIRECTORY;
    } else if (fs::is_regular_file(status)) {
        entry.type = MigrationEntryType::REGULAR_FILE;
        std::tie(entry.size, entry.hash) = HashRegularFile(path);
    } else if (fs::is_symlink(status)) {
        entry.type = MigrationEntryType::SYMLINK;
        entry.symlink_target = fs::read_symlink(path);
    } else {
        throw std::runtime_error(strprintf("unsupported special file %s in legacy datadir", fs::PathToString(path)));
    }
    return entry;
}

void SortMigrationManifest(MigrationManifest& manifest)
{
    std::sort(manifest.begin(), manifest.end(), [](const MigrationManifestEntry& lhs, const MigrationManifestEntry& rhs) {
        return lhs.relative_path < rhs.relative_path;
    });
}

MigrationManifest BuildMigrationManifest(const fs::path& root, const MigrationCopyPlan& plan)
{
    MigrationManifest manifest;
    for (fs::recursive_directory_iterator it(root), end; it != end; ++it) {
        const fs::file_status status = it->symlink_status();
        const fs::path relative = it->path().lexically_relative(root);
        if (ShouldSkipMigrationEntry(relative, status, plan)) {
            if (fs::is_directory(status)) it.disable_recursion_pending();
            continue;
        }
        manifest.push_back(ManifestEntryForPath(root, it->path(), status));
    }
    SortMigrationManifest(manifest);
    return manifest;
}

uintmax_t AddPlanBytes(uintmax_t total, uintmax_t additional, const fs::path& path)
{
    if (total > std::numeric_limits<uintmax_t>::max() - additional) {
        throw std::runtime_error(strprintf("migration size overflow while scanning %s", fs::PathToString(path)));
    }
    return total + additional;
}

//! Scan sizes before hashing so a sparse or otherwise oversized source fails
//! the destination-space gate without reading the entire file.
uintmax_t ScanCopyPlanBytes(const fs::path& source, const MigrationCopyPlan& plan, bool convert_blackmore_config)
{
    uintmax_t total{0};
    for (fs::recursive_directory_iterator it(source), end; it != end; ++it) {
        const fs::file_status status = it->symlink_status();
        const fs::path relative = it->path().lexically_relative(source);
        if (ShouldSkipMigrationEntry(relative, status, plan)) {
            if (fs::is_directory(status)) it.disable_recursion_pending();
            continue;
        }
        if (fs::is_regular_file(status)) {
            total = AddPlanBytes(total, it->file_size(), it->path());
        } else if (!fs::is_directory(status) && !fs::is_symlink(status)) {
            throw std::runtime_error(strprintf("unsupported special file %s in legacy datadir", fs::PathToString(it->path())));
        }
    }

    const fs::path legacy_config = source / LEGACY_BLACKMORE_CONF_FILENAME;
    const fs::path blackcoin_config = source / BITCOIN_CONF_FILENAME;
    if (convert_blackmore_config && PathExistsNoThrow(legacy_config) && !PathExistsNoThrow(blackcoin_config)) {
        if (!PathIsRegularFileNoThrow(legacy_config)) {
            throw std::runtime_error("legacy blackmore.conf is not a readable regular file");
        }
        total = AddPlanBytes(total, fs::file_size(legacy_config), legacy_config);
    }
    return total;
}

MigrationManifest BuildExpectedMigrationManifest(const fs::path& source, const MigrationCopyPlan& plan, bool convert_blackmore_config)
{
    MigrationManifest expected = BuildMigrationManifest(source, plan);
    const fs::path legacy_config = source / LEGACY_BLACKMORE_CONF_FILENAME;
    const fs::path blackcoin_config = source / BITCOIN_CONF_FILENAME;
    if (convert_blackmore_config && PathExistsNoThrow(legacy_config) && !PathExistsNoThrow(blackcoin_config)) {
        const fs::file_status regular_status = fs::status(legacy_config);
        MigrationManifestEntry converted = ManifestEntryForPath(source, legacy_config, regular_status);
        converted.relative_path = BITCOIN_CONF_FILENAME;
        expected.push_back(std::move(converted));
        SortMigrationManifest(expected);
    }
    return expected;
}

void CopyRegularFileDurably(const fs::path& source, const fs::path& destination)
{
    if (!fs::copy_file(source, destination, fs::copy_options::none)) {
        throw std::runtime_error(strprintf("failed to copy regular file %s", fs::PathToString(source)));
    }
    FILE* destination_file = fsbridge::fopen(destination, "rb+");
    if (destination_file == nullptr) {
        throw std::runtime_error(strprintf("unable to open copied file %s for durable commit", fs::PathToString(destination)));
    }
    const bool committed = FileCommit(destination_file);
    const bool closed = std::fclose(destination_file) == 0;
    if (!committed || !closed) {
        throw std::runtime_error(strprintf("failed to durably commit copied file %s", fs::PathToString(destination)));
    }
}

//! Copy `source` into `destination` file by file so front ends can render
//! progress, skipping any "blocks" subtree when requested instead of copying
//! gigabytes of block files only to delete them again afterwards.
void CopyTreeWithProgress(const fs::path& source, const fs::path& destination, const MigrationCopyPlan& plan, const std::string& phase, uintmax_t total_bytes)
{
    uintmax_t copied_bytes{0};
    int last_percent{-1};
    ReportMigrationProgress(phase, total_bytes == 0 ? -1 : 0);

    fs::create_directories(destination);
    for (fs::recursive_directory_iterator it(source), end; it != end; ++it) {
        const fs::path relative = it->path().lexically_relative(source);
        const fs::path target = destination / relative;
        const fs::file_status status = it->symlink_status();
        if (ShouldSkipMigrationEntry(relative, status, plan)) {
            if (fs::is_directory(status)) it.disable_recursion_pending();
            continue;
        }
        if (fs::is_symlink(status)) {
            fs::create_directories(target.parent_path());
            fs::copy_symlink(it->path(), target);
        } else if (fs::is_directory(status)) {
            fs::create_directories(target);
        } else if (fs::is_regular_file(status)) {
            fs::create_directories(target.parent_path());
            CopyRegularFileDurably(it->path(), target);
            copied_bytes = AddPlanBytes(copied_bytes, it->file_size(), it->path());
            if (total_bytes > 0) {
                const int percent = static_cast<int>(std::min<long double>(100.0L, (static_cast<long double>(copied_bytes) * 100.0L) / total_bytes));
                if (percent != last_percent) {
                    last_percent = percent;
                    ReportMigrationProgress(phase, percent);
                }
            }
        } else {
            throw std::runtime_error(strprintf("unsupported special file %s in legacy datadir", fs::PathToString(it->path())));
        }
    }
    ReportMigrationProgress(phase, 100);
}

size_t PathDepth(const fs::path& path)
{
    size_t depth{0};
    for ([[maybe_unused]] const auto& component : path) ++depth;
    return depth;
}

void CommitDirectoryTree(const fs::path& root)
{
    std::vector<fs::path> directories{root};
    for (fs::recursive_directory_iterator it(root), end; it != end; ++it) {
        const fs::file_status status = it->symlink_status();
        if (fs::is_directory(status)) directories.push_back(it->path());
    }
    std::sort(directories.begin(), directories.end(), [](const fs::path& lhs, const fs::path& rhs) {
        return PathDepth(lhs) > PathDepth(rhs);
    });
    for (const fs::path& directory : directories) DirectoryCommit(directory);
}

std::string DescribeManifestEntry(const MigrationManifestEntry& entry)
{
    switch (entry.type) {
    case MigrationEntryType::DIRECTORY:
        return strprintf("%s directory", fs::PathToString(entry.relative_path));
    case MigrationEntryType::REGULAR_FILE:
        return strprintf("%s file size=%d sha256=%s", fs::PathToString(entry.relative_path), entry.size, HexStr(entry.hash));
    case MigrationEntryType::SYMLINK:
        return strprintf("%s symlink target=%s", fs::PathToString(entry.relative_path), fs::PathToString(entry.symlink_target));
    }
    return "unknown manifest entry";
}

void VerifyMigrationManifest(const MigrationManifest& expected, const MigrationManifest& actual)
{
    if (expected == actual) return;

    size_t mismatch{0};
    while (mismatch < expected.size() && mismatch < actual.size() && expected[mismatch] == actual[mismatch]) ++mismatch;
    const std::string expected_detail = mismatch < expected.size() ? DescribeManifestEntry(expected[mismatch]) : "<end-of-manifest>";
    const std::string actual_detail = mismatch < actual.size() ? DescribeManifestEntry(actual[mismatch]) : "<end-of-manifest>";
    throw std::runtime_error(strprintf(
        "deterministic migration manifest mismatch at entry %d (expected %s, copied %s; expected entries=%d copied entries=%d)",
        mismatch, expected_detail, actual_detail, expected.size(), actual.size()));
}

bool CopyDirectoryTreeVerified(const fs::path& source, const fs::path& destination, const char* verify_config_filename, bool skip_blocks, bool convert_blackmore_config, const std::string& progress_phase)
{
    const fs::path temp_path = UniqueMigrationPath(destination, "tmp");
    try {
        fs::create_directories(destination.parent_path());
        if (PathExistsNoThrow(destination)) {
            LogPrintf("Warning: refusing to copy legacy datadir into existing path %s\n", fs::quoted(fs::PathToString(destination)));
            return false;
        }

        const MigrationCopyPlan source_plan{
            .skip_blocks = skip_blocks,
            .skip_transient = convert_blackmore_config,
            .skip_lock_files = true,
        };
        const uintmax_t plan_bytes = ScanCopyPlanBytes(source, source_plan, convert_blackmore_config);

        // Fail fast with a clear message when the destination volume cannot
        // hold the copy instead of dying deep into a multi-gigabyte transfer.
        std::error_code space_ec;
        const fs::space_info space = fs::space(destination.parent_path(), space_ec);
        constexpr uintmax_t SPACE_MARGIN{512ull * 1024 * 1024};
        if (!space_ec && (space.available < SPACE_MARGIN || plan_bytes > space.available - SPACE_MARGIN)) {
            throw std::runtime_error(strprintf(
                "not enough free disk space to migrate safely: need about %.1f GB plus working room, only %.1f GB available on the destination volume",
                plan_bytes / 1e9, space.available / 1e9));
        }

        const MigrationManifest expected_manifest = BuildExpectedMigrationManifest(source, source_plan, convert_blackmore_config);
        LogPrintf("Blackcoin: %s: copying %.1f MB from %s\n", progress_phase, plan_bytes / 1e6, fs::quoted(fs::PathToString(source)));
        // Only the promoted import filters transient network files; backups
        // stay byte-faithful to the source (minus blocks) for manual recovery.
        CopyTreeWithProgress(source, temp_path, source_plan, progress_phase, plan_bytes);

        if (convert_blackmore_config) {
            const fs::path legacy_config = temp_path / LEGACY_BLACKMORE_CONF_FILENAME;
            const fs::path blackcoin_config = temp_path / BITCOIN_CONF_FILENAME;
            if (PathExistsNoThrow(legacy_config) && !PathExistsNoThrow(blackcoin_config)) {
                CopyRegularFileDurably(source / LEGACY_BLACKMORE_CONF_FILENAME, blackcoin_config);
            }
        }

        if (!PathIsRealDirectoryNoThrow(temp_path)) {
            throw std::runtime_error("copied datadir root was not a real directory");
        }
        CommitDirectoryTree(temp_path);

        // The destination scan deliberately has no exclusions. A copied lock,
        // transient file, blocks subtree, unexpected special file, truncation,
        // or single-byte corruption therefore makes the exact manifest differ.
        const MigrationManifest actual_manifest = BuildMigrationManifest(temp_path, {});
        VerifyMigrationManifest(expected_manifest, actual_manifest);
        if (!HasDataPayload(temp_path, verify_config_filename) &&
            !(skip_blocks && HasDataPayload(source, verify_config_filename))) {
            throw std::runtime_error("verified datadir did not contain a recognizable wallet, config, block, or chainstate payload");
        }

        if (PathExistsNoThrow(destination)) {
            throw std::runtime_error("migration destination appeared before atomic promotion");
        }
        if (!RenameNoReplace(temp_path, destination)) {
            throw std::runtime_error("failed to atomically promote verified migration copy without replacing an existing destination");
        }
        if (!PathIsRealDirectoryNoThrow(destination)) {
            throw std::runtime_error("migrated datadir root was not a real directory");
        }
        DirectoryCommit(destination.parent_path());
        return true;
    } catch (const std::exception& e) {
        std::error_code ec;
        fs::remove_all(temp_path, ec);
        LogPrintf("Warning: failed to copy legacy datadir %s to %s: %s\n",
                  fs::quoted(fs::PathToString(source)),
                  fs::quoted(fs::PathToString(destination)),
                  e.what());
        return false;
    }
}

bool BackupLegacySource(const fs::path& source, const fs::path& resolved_source, const fs::path& destination, const std::string& label, const char* verify_config_filename)
{
    if (!HasDataPayload(resolved_source, verify_config_filename)) return false;

    const fs::path backup_path = UniqueBackupPath(destination, label);
    // Backups exist to protect wallets, configs, and chain databases; the
    // multi-gigabyte blocks directory is never modified by migration (the
    // original source directory is preserved in place), so skip it here
    // instead of doubling the disk cost and copy time of the upgrade.
    const bool copied = CopyDirectoryTreeVerified(resolved_source, backup_path, verify_config_filename, /*skip_blocks=*/true, /*convert_blackmore_config=*/false,
                                                  strprintf("Backing up %s data", label));
    if (!copied) return false;

    LogPrintf("Blackcoin: backed up legacy datadir %s to %s (blocks directory left with the original)\n",
              fs::quoted(fs::PathToString(source)),
              fs::quoted(fs::PathToString(backup_path)));
    return true;
}

bool MoveActiveDestinationAside(const fs::path& destination, const fs::path& moved_path, MigrationLockSet& locks)
{
    if (!HasDataPayload(destination, BITCOIN_CONF_FILENAME)) return false;
    if (PathIsSymlinkNoThrow(destination)) {
        LogPrintf("Warning: refusing to replace symlinked active Blackcoin datadir %s automatically\n", fs::quoted(fs::PathToString(destination)));
        return false;
    }
    if (!locks.HoldsDirectory(destination)) {
        LogPrintf("Warning: refusing to move active Blackcoin datadir %s without its migration lock\n", fs::quoted(fs::PathToString(destination)));
        return false;
    }
    const fs::path destination_lock_identity = locks.DirectoryIdentity(destination);

    try {
        fs::create_directories(moved_path.parent_path());
        if (!RenameNoReplace(destination, moved_path)) {
            throw std::runtime_error("failed to atomically preserve active datadir without replacing an existing backup");
        }
        std::error_code ec;
        fs::remove(moved_path / MIGRATION_LOCK_FILENAME, ec);
        locks.ReleaseDirectory(destination_lock_identity);
        DirectoryCommit(destination.parent_path());
        DirectoryCommit(moved_path.parent_path());
        LogPrintf("Blackcoin: moved active legacy datadir %s to %s before selected migration\n",
                  fs::quoted(fs::PathToString(destination)),
                  fs::quoted(fs::PathToString(moved_path)));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to move active Blackcoin datadir %s aside: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

//! Clear a pre-existing destination directory that holds no wallet/chain
//! payload so a staged import can be promoted into its place. The GUI's
//! data-directory chooser (Intro) creates the Blackcoin datadir before the
//! first-run migration runs, so on a fresh install importing a Blackmore
//! datadir the destination already exists as an empty directory. A truly
//! empty directory is removed; a directory that only holds non-wallet cruft
//! (e.g. a stray settings.json or lock file) is moved aside into the backup
//! area so nothing is ever destroyed. Refuses to touch a directory that has
//! real data payload.
bool ClearNonPayloadDestination(const fs::path& destination, MigrationLockSet& locks)
{
    if (!PathExistsNoThrow(destination)) return true;
    if (PathIsDirectoryNoThrow(destination) && !locks.HoldsDirectory(destination)) {
        LogPrintf("Warning: refusing to clear pre-existing Blackcoin datadir %s without its migration lock\n",
                  fs::quoted(fs::PathToString(destination)));
        return false;
    }
    const fs::path destination_lock_identity = locks.DirectoryIdentity(destination);
    if (HasDataPayload(destination, BITCOIN_CONF_FILENAME)) {
        LogPrintf("Warning: refusing to clear Blackcoin datadir %s during migration because it contains wallet or chain data\n",
                  fs::quoted(fs::PathToString(destination)));
        return false;
    }

    std::error_code ec;
    if (fs::is_directory(destination, ec) && !ec && fs::is_empty(destination, ec) && !ec) {
        fs::remove(destination, ec);
        if (!ec) {
            locks.ReleaseDirectory(destination_lock_identity);
            DirectoryCommit(destination.parent_path());
            LogPrintf("Blackcoin: removed pre-existing empty Blackcoin datadir %s before importing legacy data\n",
                      fs::quoted(fs::PathToString(destination)));
            return true;
        }
    }

    const fs::path moved = UniqueBackupPath(destination, "preexisting-blackcoin");
    try {
        fs::create_directories(moved.parent_path());
        if (!RenameNoReplace(destination, moved)) {
            throw std::runtime_error("failed to atomically preserve pre-existing datadir without replacing an existing backup");
        }
        std::error_code remove_ec;
        fs::remove(moved / MIGRATION_LOCK_FILENAME, remove_ec);
        locks.ReleaseDirectory(destination_lock_identity);
        DirectoryCommit(destination.parent_path());
        DirectoryCommit(moved.parent_path());
        LogPrintf("Blackcoin: moved pre-existing non-wallet Blackcoin datadir %s aside to %s before importing legacy data\n",
                  fs::quoted(fs::PathToString(destination)),
                  fs::quoted(fs::PathToString(moved)));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to move pre-existing Blackcoin datadir %s aside: %s\n",
                  fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

bool WriteMigrationDoneMarker(const fs::path& destination, const std::string& status)
{
    try {
        fs::create_directories(destination);
        const std::string marker_text = "Blackcoin first-run data migration completed.\n" + status + "\n";
        if (!WriteDurableTextFile(destination / MIGRATION_DONE_FILENAME, marker_text)) {
            LogPrintf("Warning: failed to commit Blackcoin migration marker in %s\n", fs::quoted(fs::PathToString(destination)));
            return false;
        }
        DirectoryCommit(destination);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to write Blackcoin migration marker in %s: %s\n", fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

bool WriteRecoveryRecord(const fs::path& destination, const fs::path& moved_path)
{
    try {
        const std::string text = fs::PathToString(moved_path) + "\n";
        if (!WriteDurableTextFile(MigrationRecoveryPath(destination), text)) {
            LogPrintf("Warning: failed to commit Blackcoin migration recovery record under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(destination))));
            return false;
        }
        DirectoryCommit(MigrationBackupRoot(destination));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to write Blackcoin migration recovery record: %s\n", e.what());
        return false;
    }
}

std::optional<fs::path> ReadRecoveryRecord(const fs::path& destination)
{
    const fs::path recovery_path = MigrationRecoveryPath(destination);
    if (!PathIsRegularFileNoThrow(recovery_path)) return std::nullopt;

    try {
        std::ifstream file{recovery_path};
        std::string line;
        std::getline(file, line);
        if (line.empty()) return std::nullopt;
        return fs::PathFromString(line);
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to read Blackcoin migration recovery record %s: %s\n",
                  fs::quoted(fs::PathToString(recovery_path)),
                  e.what());
        return std::nullopt;
    }
}

void ClearRecoveryRecord(const fs::path& destination)
{
    std::error_code ec;
    fs::remove(MigrationRecoveryPath(destination), ec);
    DirectoryCommit(MigrationBackupRoot(destination));
}

bool RecoveryPathIsSafe(const fs::path& destination, const fs::path& recovery_path)
{
    const fs::path normalized_backup_root = NormalizedAbsolutePath(MigrationBackupRoot(destination));
    const fs::path normalized_recovery = NormalizedAbsolutePath(recovery_path);
    return normalized_recovery.parent_path() == normalized_backup_root &&
        PathNameStartsWith(normalized_recovery, "active-blackcoin-");
}

bool PreserveInterruptedDestination(const fs::path& destination, MigrationLockSet& locks)
{
    if (!PathExistsNoThrow(destination)) return true;
    if (PathIsDirectoryNoThrow(destination) && !locks.HoldsDirectory(destination)) {
        LogPrintf("Warning: refusing to preserve interrupted Blackcoin destination %s without its migration lock\n",
                  fs::quoted(fs::PathToString(destination)));
        return false;
    }
    const fs::path destination_lock_identity = locks.DirectoryIdentity(destination);

    const fs::path preserved = UniqueBackupPath(destination, "interrupted-destination");
    try {
        fs::create_directories(preserved.parent_path());
        if (!RenameNoReplace(destination, preserved)) {
            throw std::runtime_error("failed to atomically preserve interrupted datadir without replacing an existing backup");
        }
        std::error_code remove_ec;
        fs::remove(preserved / MIGRATION_LOCK_FILENAME, remove_ec);
        locks.ReleaseDirectory(destination_lock_identity);
        DirectoryCommit(destination.parent_path());
        DirectoryCommit(preserved.parent_path());
        LogPrintf("Blackcoin: preserved incomplete migration destination %s at %s before restoring the original\n",
                  fs::quoted(fs::PathToString(destination)),
                  fs::quoted(fs::PathToString(preserved)));
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Warning: failed to preserve interrupted Blackcoin destination %s: %s\n",
                  fs::quoted(fs::PathToString(destination)), e.what());
        return false;
    }
}

bool RestoreStrandedActiveBackup(const fs::path& destination, MigrationLockSet& locks)
{
    const bool recovery_record_exists = PathIsRegularFileNoThrow(MigrationRecoveryPath(destination));
    const std::optional<fs::path> recovery_path = ReadRecoveryRecord(destination);
    if (!recovery_path) {
        if (!recovery_record_exists) return true;
        LogPrintf("Warning: Blackcoin migration recovery record is empty or unreadable; leaving all data untouched for manual recovery\n");
        return false;
    }

    // A completion marker is staged and committed before destination
    // promotion. If both it and the recovery record exist, the promotion won
    // the crash race and is safe to keep; only clearing the stale record
    // remains.
    if (HasMigrationDoneMarker(destination) &&
        PathIsRealDirectoryNoThrow(destination) &&
        HasDataPayload(destination, BITCOIN_CONF_FILENAME)) {
        ClearRecoveryRecord(destination);
        LogPrintf("Blackcoin: completed migration destination survived restart; cleared stale recovery record\n");
        return true;
    }
    if (HasMigrationDoneMarker(destination)) {
        LogPrintf("Warning: marked Blackcoin migration destination has no recognizable data payload; preserving it and restoring the recorded original instead\n");
    }

    if (!RecoveryPathIsSafe(destination, *recovery_path)) {
        LogPrintf("Warning: Blackcoin migration recovery record points outside its expected active-backup location: %s\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }

    // The recovery record is committed before the active-directory rename.
    // After a power loss, the filesystem may therefore retain the record but
    // roll the rename back. An unmarked, populated original still at the
    // destination and no backup at the recorded path is that precise state.
    if (!PathExistsNoThrow(*recovery_path) &&
        !HasMigrationDoneMarker(destination) &&
        PathIsRealDirectoryNoThrow(destination) &&
        HasDataPayload(destination, BITCOIN_CONF_FILENAME)) {
        ClearRecoveryRecord(destination);
        LogPrintf("Blackcoin: active-datadir move did not survive restart; retained the original destination and cleared its stale recovery record\n");
        return true;
    }

    if (!PathIsRealDirectoryNoThrow(*recovery_path) || !HasDataPayload(*recovery_path, BITCOIN_CONF_FILENAME)) {
        LogPrintf("Warning: Blackcoin migration recovery record points to missing or invalid backup %s; leaving backups untouched for manual recovery\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }

    std::string lock_failure;
    const std::optional<fs::path> resolved_recovery = ResolveAndLockSourceRoot(*recovery_path, locks, lock_failure);
    if (!resolved_recovery) {
        LogPrintf("Warning: cannot lock Blackcoin migration recovery source %s: %s\n",
                  fs::quoted(fs::PathToString(*recovery_path)), lock_failure);
        return false;
    }

    // A destination without the precommitted marker is never selected. It may
    // be a partial directory from an older release or a crash before atomic
    // promotion. Preserve it verbatim, then restore the known original.
    if (!PreserveInterruptedDestination(destination, locks)) return false;

    if (!CopyDirectoryTreeVerified(*resolved_recovery, destination, BITCOIN_CONF_FILENAME, /*skip_blocks=*/false, /*convert_blackmore_config=*/false,
                                   "Restoring Blackcoin data after an interrupted upgrade")) {
        LogPrintf("Warning: failed to copy stranded original .blackcoin datadir from %s\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }
    if (!PathIsRealDirectoryNoThrow(destination) || !HasDataPayload(destination, BITCOIN_CONF_FILENAME)) {
        LogPrintf("Warning: restored .blackcoin datadir from %s failed post-copy verification\n",
                  fs::quoted(fs::PathToString(*recovery_path)));
        return false;
    }

    ClearRecoveryRecord(destination);
    DirectoryCommit(destination.parent_path());
    LogPrintf("Blackcoin: restored stranded original .blackcoin datadir from %s after interrupted migration; backup copy preserved\n",
              fs::quoted(fs::PathToString(*recovery_path)));
    return true;
}

bool CopyLegacyDataDirAtomically(const fs::path& legacy_base_path, const fs::path& resolved_source, const fs::path& destination, bool skip_blocks)
{
    if (!HasDataPayload(resolved_source, LEGACY_BLACKMORE_CONF_FILENAME)) return false;
    if (!DestinationAllowsLegacyMigration(destination)) return false;

    const bool copied = CopyDirectoryTreeVerified(resolved_source, destination, LEGACY_BLACKMORE_CONF_FILENAME, skip_blocks, /*convert_blackmore_config=*/true,
                                                  "Importing Blackmore data");
    if (copied) {
        LogPrintf("Blackcoin: completed copy-only legacy datadir migration from %s to %s\n",
                  fs::quoted(fs::PathToString(legacy_base_path)),
                  fs::quoted(fs::PathToString(destination)));
        return true;
    }
    return false;
}

std::optional<LegacySource> FindBlackmoreSource(const fs::path& base_path)
{
    for (const fs::path& candidate : BlackmoreDataDirCandidates(base_path)) {
        if (HasDataPayload(candidate, LEGACY_BLACKMORE_CONF_FILENAME)) {
            return LegacySource{"blackmore", candidate, LEGACY_BLACKMORE_CONF_FILENAME};
        }
    }
    return std::nullopt;
}

MigrationChoice ParseMigrationChoiceValue(const std::string& raw_choice)
{
    const std::string choice = ToLower(raw_choice);
    if (choice == "auto") return MigrationChoice::AUTO;
    if (choice == "blackmore") return MigrationChoice::BLACKMORE;
    if (choice == "blackcoin") return MigrationChoice::BLACKCOIN;
    if (choice == "none") return MigrationChoice::NONE;
    if (choice == "abort") return MigrationChoice::ABORT;

    LogPrintf("Warning: unknown -migratewallet value %s; using auto\n", choice);
    return MigrationChoice::AUTO;
}

MigrationChoice ParseMigrationChoice(const ArgsManager& args)
{
    return ParseMigrationChoiceValue(args.GetArg("-migratewallet", "auto"));
}

MigrationChoice ResolveAutoMigrationChoice(bool has_blackcoin, const fs::path& blackcoin_path, const std::optional<LegacySource>& blackmore_source, const common::LegacyMigrationPromptFn& legacy_migration_prompt_fn, bool explicit_choice)
{
    if (blackmore_source && !has_blackcoin) return MigrationChoice::BLACKMORE;
    if (has_blackcoin && !blackmore_source) return MigrationChoice::BLACKCOIN;
    if (!has_blackcoin && !blackmore_source) return MigrationChoice::NONE;

    if (!explicit_choice && legacy_migration_prompt_fn) {
        const MigrationChoice prompted = ParseMigrationChoiceValue(
            legacy_migration_prompt_fn(fs::PathToString(blackcoin_path), fs::PathToString(blackmore_source->path)));
        if (prompted == MigrationChoice::BLACKMORE || prompted == MigrationChoice::BLACKCOIN || prompted == MigrationChoice::NONE || prompted == MigrationChoice::ABORT) {
            return prompted;
        }
    }

    LogPrintf("Blackcoin: both .blackcoin and .blackmore legacy datadirs were found; keeping the populated .blackcoin datadir by default. The .blackmore datadir will be backed up and preserved. Restart with -migratewallet=blackmore to import it explicitly.\n");
    return MigrationChoice::BLACKCOIN;
}

std::optional<std::string> CommitMigrationMarker(const fs::path& destination, const std::string& status)
{
    if (WriteMigrationDoneMarker(destination, status)) return std::nullopt;
    return "failed to durably write the first-run migration marker";
}

struct MigrationOutcome {
    bool aborted{false};
    std::optional<std::string> error;
};

MigrationOutcome MaybeMigrateLegacyDataDir(ArgsManager& args, const common::LegacyMigrationPromptFn& legacy_migration_prompt_fn)
{
    const std::string migration_pause_transition =
        args.GetArg("-testdatadirmigrationpauseafter", "");
    if (!migration_pause_transition.empty()) {
        if (args.GetChainType() != ChainType::REGTEST) {
            return {.aborted = false, .error = "-testdatadirmigrationpauseafter is only supported on regtest"};
        }
        if (!IsSupportedMigrationTestTransition(migration_pause_transition)) {
            return {.aborted = false, .error = strprintf(
                "unknown -testdatadirmigrationpauseafter transition: %s",
                migration_pause_transition)};
        }
    }
    if (args.IsArgSet("-datadir") || args.IsArgSet("-conf")) return {};

    const fs::path base_path = args.GetDataDirBase();
    MigrationLockSet migration_locks;
    std::string lock_failure;

    // Serialize every migration and recovery decision before inspecting or
    // deleting a stale staging path. The lock file lives beside the datadir so
    // it remains reachable while the active datadir itself is renamed.
    try {
        fs::create_directories(base_path.parent_path());
    } catch (const std::exception& e) {
        return {.aborted = false, .error = strprintf("unable to create the default datadir parent for migration locking: %s", e.what())};
    }
    if (!migration_locks.TryLockFile(MigrationOperationLockPath(base_path), "first-run migration operation", lock_failure)) {
        return {.aborted = false, .error = lock_failure};
    }

    // The destination may itself be a source (the existing .blackcoin case),
    // or an incomplete destination that recovery must preserve. Hold its root
    // and all present network-subdirectory locks for the whole operation.
    std::optional<fs::path> resolved_blackcoin;
    if (PathExistsNoThrow(base_path)) {
        if (PathIsSymlinkNoThrow(base_path)) {
            return {.aborted = false, .error = "refusing automatic migration with a symlinked active .blackcoin datadir"};
        }
        if (!PathIsRealDirectoryNoThrow(base_path)) {
            return {.aborted = false, .error = "active .blackcoin path exists but is not a real directory"};
        }
        resolved_blackcoin = ResolveAndLockSourceRoot(base_path, migration_locks, lock_failure);
        if (!resolved_blackcoin) {
            return {.aborted = false, .error = strprintf("failed to lock the active .blackcoin datadir: %s", lock_failure)};
        }
    }

    CleanupStaleMigrationTemps(base_path);
    if (!RestoreStrandedActiveBackup(base_path, migration_locks)) {
        return {.aborted = false, .error = "failed to restore original .blackcoin datadir after an interrupted migration"};
    }

    // Recovery can atomically replace the destination. Acquire locks on that
    // restored inode set before it is inspected or copied again.
    if (PathIsRealDirectoryNoThrow(base_path) && !migration_locks.HoldsDirectory(base_path)) {
        resolved_blackcoin = ResolveAndLockSourceRoot(base_path, migration_locks, lock_failure);
        if (!resolved_blackcoin) {
            return {.aborted = false, .error = strprintf("failed to lock the recovered .blackcoin datadir: %s", lock_failure)};
        }
    }
    if (HasMigrationDoneMarker(base_path)) return {};

    const bool has_blackcoin = HasDataPayload(base_path, BITCOIN_CONF_FILENAME);
    const std::optional<LegacySource> blackmore_source = FindBlackmoreSource(base_path);

    if (!has_blackcoin && !blackmore_source) {
        return {};
    }

    if (has_blackcoin && !resolved_blackcoin) {
        return {.aborted = false, .error = "populated .blackcoin datadir was not locked for migration"};
    }

    std::optional<fs::path> resolved_blackmore;
    if (blackmore_source) {
        resolved_blackmore = ResolveAndLockSourceRoot(blackmore_source->path, migration_locks, lock_failure);
        if (!resolved_blackmore) {
            return {.aborted = false, .error = strprintf("failed to lock the legacy .blackmore datadir: %s", lock_failure)};
        }
        if (!HasDataPayload(*resolved_blackmore, blackmore_source->config_filename)) {
            return {.aborted = false, .error = "legacy .blackmore datadir changed while its migration locks were being acquired"};
        }
        if (resolved_blackcoin && NormalizedAbsolutePath(*resolved_blackcoin) == NormalizedAbsolutePath(*resolved_blackmore)) {
            return {.aborted = false, .error = "legacy .blackmore source resolves to the active .blackcoin destination"};
        }
    }

    MigrationChoice choice = ParseMigrationChoice(args);
    const bool explicit_choice = args.IsArgSet("-migratewallet");
    if (choice == MigrationChoice::AUTO) {
        choice = ResolveAutoMigrationChoice(has_blackcoin, base_path, blackmore_source, legacy_migration_prompt_fn, explicit_choice);
    }
    if (choice == MigrationChoice::ABORT) {
        // The user chose to exit instead of deciding. Nothing has been copied,
        // moved, or marked yet, so the next start will ask again.
        LogPrintf("Blackcoin: first-run legacy datadir migration cancelled by the user before any changes; exiting\n");
        return {.aborted = true, .error = std::nullopt};
    }

    if (has_blackcoin && !BackupLegacySource(base_path, *resolved_blackcoin, base_path, "original-blackcoin", BITCOIN_CONF_FILENAME)) {
        return {.aborted = false, .error = "failed to preserve a backup of the existing .blackcoin datadir"};
    }
    if (blackmore_source && !BackupLegacySource(blackmore_source->path, *resolved_blackmore, base_path, blackmore_source->label, blackmore_source->config_filename)) {
        return {.aborted = false, .error = "failed to preserve a backup of the legacy .blackmore datadir"};
    }

    if (choice == MigrationChoice::NONE) {
        LogPrintf("Blackcoin: first-run legacy datadir migration was disabled; backups were preserved under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(base_path))));
        const auto marker_error = CommitMigrationMarker(base_path, "Migration disabled by -migratewallet=none; backups preserved.");
        if (marker_error) return {.aborted = false, .error = marker_error};
        ClearRecoveryRecord(base_path);
        return {};
    }

    if (choice == MigrationChoice::BLACKCOIN) {
        if (has_blackcoin) {
            LogPrintf("Blackcoin: using existing .blackcoin datadir after preserving a backup under %s\n", fs::quoted(fs::PathToString(MigrationBackupRoot(base_path))));
            const auto marker_error = CommitMigrationMarker(base_path, "Using existing original .blackcoin datadir; backups preserved.");
            if (marker_error) return {.aborted = false, .error = marker_error};
            ClearRecoveryRecord(base_path);
            return {};
        }
        return {.aborted = false, .error = "-migratewallet=blackcoin was selected but no populated .blackcoin datadir was found"};
    }

    if (choice == MigrationChoice::BLACKMORE) {
        if (!blackmore_source) {
            return {.aborted = false, .error = "-migratewallet=blackmore was selected but no .blackmore datadir was found"};
        }

        const fs::path staged_import_path = UniqueMigrationPath(base_path, "import");
        if (!CopyLegacyDataDirAtomically(blackmore_source->path, *resolved_blackmore, staged_import_path, args.IsArgSet("-blocksdir"))) {
            return {.aborted = false, .error = "failed to stage the .blackmore datadir import"};
        }

        // Commit the authoritative completion marker inside the verified
        // staging tree before the active destination is moved. After this
        // point a restart deterministically selects either the old destination
        // through the recovery record or the marked, atomically promoted one.
        if (!WriteMigrationDoneMarker(staged_import_path, "Imported .blackmore datadir into active .blackcoin datadir; backups preserved.")) {
            std::error_code ec;
            fs::remove_all(staged_import_path, ec);
            return {.aborted = false, .error = "failed to stage the durable migration completion marker"};
        }
        MaybePauseMigrationForTest(args, base_path, "staged-import-ready");

        std::optional<fs::path> moved_active_path;
        if (has_blackcoin) {
            const fs::path moved_path = UniqueBackupPath(base_path, "active-blackcoin");
            if (!WriteRecoveryRecord(base_path, moved_path)) {
                std::error_code ec;
                fs::remove_all(staged_import_path, ec);
                return {.aborted = false, .error = "failed to write recovery record before replacing the active .blackcoin datadir"};
            }
            MaybePauseMigrationForTest(args, base_path, "recovery-record-ready");
            if (!MoveActiveDestinationAside(base_path, moved_path, migration_locks)) {
                std::error_code ec;
                fs::remove_all(staged_import_path, ec);
                return {.aborted = false, .error = "failed to move the active .blackcoin datadir aside before selected .blackmore import"};
            }
            moved_active_path = moved_path;
            MaybePauseMigrationForTest(args, base_path, "active-moved");
        } else if (PathExistsNoThrow(base_path)) {
            // No populated .blackcoin datadir, but the destination directory
            // already exists — typically an empty datadir the GUI created
            // before this migration ran. Move it out of the way (preserving
            // any contents in the backup area) so the import can be promoted.
            if (!ClearNonPayloadDestination(base_path, migration_locks)) {
                std::error_code ec;
                fs::remove_all(staged_import_path, ec);
                return {.aborted = false, .error = "failed to clear the pre-existing empty .blackcoin datadir before importing"};
            }
        }

        try {
            if (PathExistsNoThrow(base_path)) {
                throw std::runtime_error("active .blackcoin datadir still exists before staged import promotion");
            }
            if (!RenameNoReplace(staged_import_path, base_path)) {
                throw std::runtime_error("failed to atomically promote staged import without replacing an active datadir");
            }
            if (!PathIsRealDirectoryNoThrow(base_path)) {
                throw std::runtime_error("promoted .blackmore import was not a real directory");
            }
            DirectoryCommit(base_path.parent_path());
            MaybePauseMigrationForTest(args, base_path, "promoted");
            std::string promoted_lock_failure;
            if (!ResolveAndLockSourceRoot(base_path, migration_locks, promoted_lock_failure)) {
                throw std::runtime_error(strprintf("promoted datadir could not be locked: %s", promoted_lock_failure));
            }
            ClearRecoveryRecord(base_path);
            return {};
        } catch (const std::exception& e) {
            LogPrintf("Warning: failed to promote staged .blackmore datadir import into %s: %s\n",
                      fs::quoted(fs::PathToString(base_path)),
                      e.what());
        }

        if (moved_active_path && !PathExistsNoThrow(base_path)) {
            try {
                if (!RenameNoReplace(*moved_active_path, base_path)) {
                    throw std::runtime_error("failed to atomically restore original datadir without replacing an active destination");
                }
                ClearRecoveryRecord(base_path);
                DirectoryCommit(base_path.parent_path());
                LogPrintf("Blackcoin: restored original .blackcoin datadir after .blackmore migration failed\n");
            } catch (const std::exception& e) {
                LogPrintf("Warning: failed to restore original .blackcoin datadir from %s after .blackmore migration failure: %s\n",
                          fs::quoted(fs::PathToString(*moved_active_path)),
                          e.what());
            }
        }
        std::error_code ec;
        fs::remove_all(staged_import_path, ec);
        return {.aborted = false, .error = "failed to activate the staged .blackmore datadir import"};
    }
    return {.aborted = false, .error = "unknown first-run migration choice"};
}

} // namespace

namespace common {
std::optional<ConfigError> InitConfig(ArgsManager& args, SettingsAbortFn settings_abort_fn, LegacyMigrationPromptFn legacy_migration_prompt_fn, MigrationProgressFn migration_progress_fn)
{
    try {
        g_migration_progress_fn = std::move(migration_progress_fn);
        if (!CheckDataDirOption(args)) {
            return ConfigError{ConfigStatus::FAILED, strprintf(_("Specified data directory \"%s\" does not exist."), args.GetArg("-datadir", ""))};
        }

        const MigrationOutcome migration_outcome = MaybeMigrateLegacyDataDir(args, legacy_migration_prompt_fn);
        if (migration_outcome.aborted) {
            return ConfigError{ConfigStatus::ABORTED, _("Startup cancelled: no wallet data was changed. Launch again to choose which wallet data to use.")};
        }
        if (migration_outcome.error) {
            return ConfigError{ConfigStatus::FAILED, Untranslated(strprintf("Legacy datadir migration failed: %s. Startup aborted to avoid creating or loading the wrong wallet.", *migration_outcome.error))};
        }

        // Record original datadir and config paths before parsing the config
        // file. It is possible for the config file to contain a datadir= line
        // that changes the datadir path after it is parsed. This is useful for
        // CLI tools to let them use a different data storage location without
        // needing to pass it every time on the command line. (It is not
        // possible for the config file to cause another configuration to be
        // used, though. Specifying a conf= option in the config file causes a
        // parse error, and specifying a datadir= location containing another
        // blackcoin.conf file just ignores the other file.)
        const fs::path orig_datadir_path{args.GetDataDirBase()};
        const fs::path orig_config_path{AbsPathForConfigVal(args, args.GetPathArg("-conf", BITCOIN_CONF_FILENAME), /*net_specific=*/false)};

        std::string error;
        if (!args.ReadConfigFiles(error, true)) {
            return ConfigError{ConfigStatus::FAILED, strprintf(_("Error reading configuration file: %s"), error)};
        }

        // Check for chain settings (Params() calls are only valid after this clause)
        SelectParams(args.GetChainType());

        // Create datadir if it does not exist.
        const auto base_path{args.GetDataDirBase()};
        if (!fs::exists(base_path)) {
            // When creating a *new* datadir, also create a "wallets" subdirectory,
            // whether or not the wallet is enabled now, so if the wallet is enabled
            // in the future, it will use the "wallets" subdirectory for creating
            // and listing wallets, rather than the top-level directory where
            // wallets could be mixed up with other files. For backwards
            // compatibility, wallet code will use the "wallets" subdirectory only
            // if it already exists, but never create it itself. There is discussion
            // in https://github.com/bitcoin/bitcoin/issues/16220 about ways to
            // change wallet code so it would no longer be necessary to create
            // "wallets" subdirectories here.
            fs::create_directories(base_path / "wallets");
        }
        const auto net_path{args.GetDataDirNet()};
        if (!fs::exists(net_path)) {
            fs::create_directories(net_path / "wallets");
        }

        // Show an error or warning if there is a blackcoin.conf file in the
        // datadir that is being ignored.
        const fs::path base_config_path = base_path / BITCOIN_CONF_FILENAME;
        if (fs::exists(base_config_path) && !fs::equivalent(orig_config_path, base_config_path)) {
            const std::string cli_config_path = args.GetArg("-conf", "");
            const std::string config_source = cli_config_path.empty()
                ? strprintf("data directory %s", fs::quoted(fs::PathToString(orig_datadir_path)))
                : strprintf("command line argument %s", fs::quoted("-conf=" + cli_config_path));
            const std::string error = strprintf(
                "Data directory %1$s contains a %2$s file which is ignored, because a different configuration file "
                "%3$s from %4$s is being used instead. Possible ways to address this would be to:\n"
                "- Delete or rename the %2$s file in data directory %1$s.\n"
                "- Change datadir= or conf= options to specify one configuration file, not two, and use "
                "includeconf= to include any other configuration files.\n"
                "- Set allowignoredconf=1 option to treat this condition as a warning, not an error.",
                fs::quoted(fs::PathToString(base_path)),
                fs::quoted(BITCOIN_CONF_FILENAME),
                fs::quoted(fs::PathToString(orig_config_path)),
                config_source);
            if (args.GetBoolArg("-allowignoredconf", false)) {
                LogPrintf("Warning: %s\n", error);
            } else {
                return ConfigError{ConfigStatus::FAILED, Untranslated(error)};
            }
        }

        // Create settings.json if -nosettings was not specified.
        if (args.GetSettingsPath()) {
            std::vector<std::string> details;
            if (!args.ReadSettingsFile(&details)) {
                const bilingual_str& message = _("Settings file could not be read");
                if (!settings_abort_fn) {
                    return ConfigError{ConfigStatus::FAILED, message, details};
                } else if (settings_abort_fn(message, details)) {
                    return ConfigError{ConfigStatus::ABORTED, message, details};
                } else {
                    details.clear(); // User chose to ignore the error and proceed.
                }
            }
            if (!args.WriteSettingsFile(&details)) {
                const bilingual_str& message = _("Settings file could not be written");
                return ConfigError{ConfigStatus::FAILED_WRITE, message, details};
            }
        }
    } catch (const std::exception& e) {
        return ConfigError{ConfigStatus::FAILED, Untranslated(e.what())};
    }
    return {};
}
} // namespace common
