// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_REBUILD_H
#define BITCOIN_NODE_CHAINSTATE_REBUILD_H

#include <util/fs.h>

class ChainstateManager;
class ArgsManager;
struct bilingual_str;

namespace node {
/** GUI-visible state of the mandatory v30.1.1 chainstate upgrade. */
enum class ChainstateRebuildStatus {
    NONE,
    REQUIRED,
    FULL_REINDEX_REQUIRED,
    REBUILD_COMMITTED,
    VERIFICATION_COMPLETE,
};

/** Durable journal state needed by the GUI before node initialization. */
enum class ChainstateRebuildJournalStatus {
    NONE,
    RECOVERY_PENDING,
    VERIFICATION_PENDING,
    INVALID,
};

/** Inspect the journal without changing the datadir. */
ChainstateRebuildJournalStatus GetChainstateRebuildJournalStatus(const fs::path& datadir);

/** Apply or clear nonpersistent fail-closed wallet-automation overrides used
 * only during the GUI-assisted rebuild and verification processes. */
void SetChainstateRebuildSafetyOverrides(ArgsManager& args, bool enabled);

/** Durably commit a successfully reconstructed chainstate and retire its
 * preserved pre-rebuild databases. No-op when no staged rebuild is active. */
bool FinalizeChainstateRebuild(ChainstateManager& chainman, bilingual_str& error);
} // namespace node

#endif // BITCOIN_NODE_CHAINSTATE_REBUILD_H
