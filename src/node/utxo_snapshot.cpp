// Copyright (c) 2022 The Bitcoin Core developers
// Copyright (c) 2022 Blackcoin Core Developers
// Copyright (c) 2022 Blackcoin More Developers
// Copyright (c) 2022 Quantum Quasar Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <logging.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <txdb.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <validation.h>

#include <cassert>
#include <cstdio>
#include <exception>
#include <optional>
#include <string>

namespace node {

bool WriteSnapshotBaseBlockhash(Chainstate& snapshot_chainstate)
{
    AssertLockHeld(::cs_main);
    assert(snapshot_chainstate.m_from_snapshot_blockhash);

    const std::optional<fs::path> chaindir = snapshot_chainstate.CoinsDB().StoragePath();
    assert(chaindir); // Sanity check that chainstate isn't in-memory.
    const fs::path write_to = *chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const fs::path staged = fs::PathFromString(fs::PathToString(write_to) + ".new");

    // Never truncate the only durable snapshot pointer in place. A crash or
    // short write must leave the previously committed file available.
    std::error_code remove_ec;
    fs::remove(staged, remove_ec);

    FILE* file{fsbridge::fopen(staged, "wb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for writing: %s\n",
                  fs::PathToString(staged));
        return false;
    }
    try {
        afile << *snapshot_chainstate.m_from_snapshot_blockhash;
    } catch (const std::exception& e) {
        LogPrintf("[snapshot] failed to write staged base blockhash file %s: %s\n",
                  fs::PathToString(staged), e.what());
        return false;
    }

    const bool committed = FileCommit(afile.Get());
    const bool closed = afile.fclose() == 0;
    if (!committed || !closed) {
        LogPrintf("[snapshot] failed to durably commit base blockhash file %s\n",
                  fs::PathToString(staged));
        fs::remove(staged, remove_ec);
        return false;
    }
    if (!RenameOver(staged, write_to) || !DirectoryCommit(*chaindir)) {
        LogPrintf("[snapshot] failed to atomically install base blockhash file %s\n",
                  fs::PathToString(write_to));
        fs::remove(staged, remove_ec);
        return false;
    }
    return true;
}

std::optional<uint256> ReadSnapshotBaseBlockhash(fs::path chaindir)
{
    if (!fs::exists(chaindir)) {
        LogPrintf("[snapshot] cannot read base blockhash: no chainstate dir "
            "exists at path %s\n", fs::PathToString(chaindir));
        return std::nullopt;
    }
    const fs::path read_from = chaindir / node::SNAPSHOT_BLOCKHASH_FILENAME;
    const std::string read_from_str = fs::PathToString(read_from);

    if (!fs::exists(read_from)) {
        LogPrintf("[snapshot] snapshot chainstate dir is malformed! no base blockhash file "
            "exists at path %s. Try deleting %s and calling loadtxoutset again?\n",
            fs::PathToString(chaindir), read_from_str);
        return std::nullopt;
    }

    uint256 base_blockhash;
    FILE* file{fsbridge::fopen(read_from, "rb")};
    AutoFile afile{file};
    if (afile.IsNull()) {
        LogPrintf("[snapshot] failed to open base blockhash file for reading: %s\n",
            read_from_str);
        return std::nullopt;
    }
    try {
        afile >> base_blockhash;
    } catch (const std::exception& e) {
        LogPrintf("[snapshot] malformed base blockhash file %s: %s\n",
                  read_from_str, e.what());
        return std::nullopt;
    }

    if (std::fgetc(afile.Get()) != EOF) {
        LogPrintf("[snapshot] unexpected trailing data in %s\n", read_from_str);
        return std::nullopt;
    } else if (std::ferror(afile.Get())) {
        LogPrintf("[snapshot] i/o error reading %s\n", read_from_str);
        return std::nullopt;
    }
    return base_blockhash;
}

std::optional<fs::path> FindSnapshotChainstateDir(const fs::path& data_dir)
{
    fs::path possible_dir =
        data_dir / fs::u8path(strprintf("chainstate%s", SNAPSHOT_CHAINSTATE_SUFFIX));

    if (fs::exists(possible_dir)) {
        return possible_dir;
    }
    return std::nullopt;
}

} // namespace node
