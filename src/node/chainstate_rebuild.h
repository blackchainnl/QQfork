// Copyright (c) 2026 The Blackcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_CHAINSTATE_REBUILD_H
#define BITCOIN_NODE_CHAINSTATE_REBUILD_H

class ChainstateManager;
struct bilingual_str;

namespace node {
/** Durably commit a successfully reconstructed chainstate and retire its
 * preserved pre-rebuild databases. No-op when no staged rebuild is active. */
bool FinalizeChainstateRebuild(ChainstateManager& chainman, bilingual_str& error);
} // namespace node

#endif // BITCOIN_NODE_CHAINSTATE_REBUILD_H
