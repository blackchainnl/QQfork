#!/usr/bin/env python3
#
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Copyright (c) 2020-2022 Blackcoin Core Developers
# Copyright (c) 2020-2022 Blackcoin More Developers
# Copyright (c) 2020-2022 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

import os
import re
import subprocess
import sys

EXPECTED_CIRCULAR_DEPENDENCIES = (
    "chainparamsbase -> common/args -> chainparamsbase",
    "node/blockstorage -> validation -> node/blockstorage",
    "node/utxo_snapshot -> validation -> node/utxo_snapshot",
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel",
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel",
    "qt/sendcoinsdialog -> qt/walletmodel -> qt/sendcoinsdialog",
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel",
    "wallet/wallet -> wallet/walletdb -> wallet/wallet",
    "kernel/coinstats -> validation -> kernel/coinstats",
    "kernel/mempool_persist -> validation -> kernel/mempool_persist",

    # Inherited v30.1.0 integration baseline. Removing these safely is tracked
    # by production issues #22 and #25.
    "addresstype -> script/solver -> addresstype",
    "addresstype -> script/solver -> script/interpreter -> addresstype",
    "chain -> chainparams -> shadow -> chain",
    "chainparams -> key_io -> chainparams",
    "consensus/tx_verify -> validation -> consensus/tx_verify",
    "consensus/tx_verify -> validation -> txmempool -> consensus/tx_verify",
    "consensus/tx_verify -> validation -> wallet/wallet -> consensus/tx_verify",
    "index/txindex -> node/blockstorage -> wallet/wallet -> index/txindex",
    "node/blockstorage -> wallet/wallet -> node/transaction -> node/blockstorage",
    "node/context -> validation -> wallet/wallet -> node/context",
    "node/miner -> wallet/staking -> node/miner",
    "node/miner -> wallet/wallet -> node/miner",
    "node/transaction -> validation -> wallet/wallet -> node/transaction",
    "node/transaction -> validation -> wallet/wallet -> psbt -> node/transaction",
    "pos -> validation -> pos",
    "pos -> validation -> wallet/wallet -> pos",
    "validation -> wallet/wallet -> validation",
    "wallet/fees -> wallet/wallet -> wallet/fees",
    "wallet/spend -> wallet/wallet -> wallet/spend",
    "wallet/staking -> wallet/wallet -> wallet/staking",

    # Added by the v30.1.1 shadow/demurrage integration and explicitly deferred
    # from alpha.1 under production issues #22 and #25.
    "chain -> chainparams -> shadow -> consensus/demurrage -> chain",
    "chainparams -> shadow -> chainparams",

    # Temporary, removed in followup https://github.com/bitcoin/bitcoin/pull/24230
    "index/base -> node/context -> net_processing -> index/blockfilterindex -> index/base",
)

CODE_DIR = "src"


def main():
    circular_dependencies = []
    exit_code = 0

    os.chdir(CODE_DIR)
    files = subprocess.check_output(
        ['git', 'ls-files', '--', '*.h', '*.cpp'],
        text=True,
    ).splitlines()

    command = [sys.executable, "../contrib/devtools/circular-dependencies.py", *files]
    dependencies_output = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        text=True,
    )

    for dependency_str in dependencies_output.stdout.rstrip().split("\n"):
        circular_dependencies.append(
            re.sub("^Circular dependency: ", "", dependency_str)
        )

    # Check for an unexpected dependencies
    for dependency in circular_dependencies:
        if dependency not in EXPECTED_CIRCULAR_DEPENDENCIES:
            exit_code = 1
            print(
                f'A new circular dependency in the form of "{dependency}" appears to have been introduced.\n',
                file=sys.stderr,
            )

    # Check for missing expected dependencies
    for expected_dependency in EXPECTED_CIRCULAR_DEPENDENCIES:
        if expected_dependency not in circular_dependencies:
            exit_code = 1
            print(
                f'Good job! The circular dependency "{expected_dependency}" is no longer present.',
            )
            print(
                f"Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in {__file__}",
            )
            print(
                "to make sure this circular dependency is not accidentally reintroduced.\n",
            )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
