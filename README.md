# Blackcoin, Quantum Quasar (Protocol V4)

Blackcoin is one of the original pure Proof-of-Stake cryptocurrencies (launched 2014).
**Quantum Quasar (Protocol V4)** is its post-quantum, participation-first upgrade: it adds
NIST-standardized quantum-safe signatures, a deterministic migration away from
quantum-vulnerable legacy outputs, and a set of reward and liveness mechanics designed to
turn passive holding into active network security, while **rewarding HODLers in full for
helping secure the chain**.

> **New here?** Read the Quantum Quasar White Paper
> ([PDF](doc/whitepaper-quantum-quasar.pdf) / [Markdown](doc/whitepaper-quantum-quasar.md))
> for the complete protocol specification with worked examples, exact consensus constants, and
> a community playbook. Legacy operators should read the [Transition Guide](TRANSITION_GUIDE.md)
> before upgrading. See the [Changelog](CHANGELOG.md) for what shipped in each release.

## What Quantum Quasar delivers

- **Quantum-safe signatures.** ML-DSA-44 (FIPS 204) via liboqs as the
  consensus-verified spending path for quantum migration (witness v16) and
  quantum cold-staking (v14). Witness v15 is frozen and reserved for a future EUTXO
  design, but v30.1.1 provides no supported v15 funding or spending workflow
  because it has no quantum ownership authorization. Consensus rejects v15
  funding and spending from Migration onward.
- **A bounded, one-click migration.** Gold Rush is followed by a scheduled
  **18-month** Migration phase in which holders can move legacy elliptic-curve
  coins into quantum-safe addresses with `migratetoquantum`. Legacy coins
  remain spendable during Gold Rush, but ordinary quantum funding does not
  activate until Migration. Final Lockout then closes the legacy spending path.
- **The Gold Rush.** A 180-day bonus-emission epoch (up to 51,437,700 BLK) paid to holders
  **through staking and mining**, split 50/50 between native PoS and a light, CPU-friendly
  Argon2id PoW lane.
- **Liveness demurrage.** Demurrage activates automatically at the first Final
  block. Eligible quantum coins that then remain inactive for more than six
  months slowly decay. Decayed principal is permanently burned when spent and
  is never paid to a miner, staker, treasury, or reward pool. A timely
  direct/tiered-v16 liveness attestation, ordinary spend, or successful cold-stake
  refresh keeps the applicable activity clock current.
- **Rich quantum staking.** Tiered self-staking, cold staking with owner/staker key
  separation, operator bonds, a per-pool decentralization cap, and conditional
  owner-wallet redelegation.
- **Advanced primitives.** RGB client-side asset commitments plus
  inspection-only EUTXO commitment decoding and wallet metadata. Do not fund a
  witness-v15 address in v30.1.1; its creation and spend RPCs intentionally
  fail.

## The V4 timeline (mainnet)

The mainnet lifecycle is height-authoritative. Median-time-past cannot advance,
delay, or reverse a production phase transition. Durations below are estimates
based on Blackcoin's 64-second target spacing; the listed heights are the
consensus boundaries.

| Phase | Mainnet heights | Approximate duration | Legacy spend? | v14/v16 funding and spending? | Gold Rush? |
|-------|-----------------|----------------------|:---:|:---:|:---:|
| Legacy | through 5,949,999 | - | Yes | No | No |
| Gold Rush | 5,950,000-6,192,999 | 180 days | Yes | No; shadow credits are locked | Yes |
| Migration | 6,193,000-6,921,999 | 540 days | Yes | Yes | No |
| Final Lockout | from 6,922,000 | permanent | No | Yes | No |

Witness v15 has no supported funding or spending workflow in any v30.1.1 phase.
From Migration onward, consensus rejects both v15 outputs and v15 spends. The
phase table's quantum column refers only to the authenticated v14 and v16 paths.

The 10,000 BLK Gold Rush whitelist snapshot is taken at height **5,945,000**. Full schedule
and constants are in the [white paper](doc/whitepaper-quantum-quasar.md).

Height **5,993,200** is also an operator upgrade boundary. v30.1.0 and
v30.1.1 continue to accept the same Gold Rush base chain, but v30.1.1 begins
the emission-neutral competing-claim reimbursement rule and therefore derives
different shadow recipients and balances from that height. Wallets, staking
and mining nodes, explorers, and indexers that consume the shadow ledger must
upgrade before the boundary. Do not reopen a wallet/datadir that has processed
post-boundary v30.1.1 state in v30.1.0; use the cold pre-upgrade copy for
rollback. Base-chain compatibility does not imply identical shadow state.

## Required v30.1.0 chainstate rebuild

v30.1.1 uses authenticated auxiliary-state schema 11 and normalizes historical
UTXO timestamps. An existing v30.1.0 datadir must not be used for staking or
mining under v30.1.1 until it has completed one explicit chainstate rebuild.
Back up every wallet, stop the old process completely, and run:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

`-reindex-chainstate` reconstructs state from local block files; it does not
retrieve block history that has already been pruned. The datadir must contain
the complete active-chain block data needed for the rebuild. If block files are
pruned or incomplete, set `prune=0` and use a full `-reindex` so the missing
history can be downloaded and the block index and chainstate rebuilt. Do not
delete wallet files or available block files. v30.1.1 checks required block
availability before staging and leaves the existing chainstate intact if known
pruned history makes a chainstate-only rebuild impossible.

The v30.1.1 beta supports archival `prune=0` operation only. Startup rejects a
nonzero `-prune` value on mainnet, testnet, and signet because this Blackcoin
branch does not have an audited proof-of-stake pruning and recovery path.
Nonzero values remain available only on regtest for test coverage. Keep
complete active-chain block files for authenticated Quantum Quasar replay.

Before moving either source chainstate, the protected rebuild scans its stable
directory topology and requires enough free space for at least the logical
size of the existing chainstate plus a 50 MiB safety reserve. A failed scan or
space check leaves the source in place without creating a rebuild journal.

The rebuilding process preserves the original chainstate in a journaled backup
and leaves that backup in place after reconstruction commits. Stop cleanly and
start once more without either reindex option so a separate process can verify
the replacement before retiring the backup. Do not request a full `-reindex`
between those two starts; v30.1.1 refuses that transition rather than risking
the preserved recovery point.

The v30.1.1 alpha does not claim power-loss-atomic directory renames on Windows.
Keep a cold datadir copy, use stable power, and do not force-stop or power-cycle
Windows during the rebuild or its verification restart. If startup reports a
chainstate-rebuild journal or backup-topology error, preserve the entire datadir
and restore the cold copy instead of deleting recovery files individually.

After synchronization, record and compare the height, best-block hash, UTXO
MuHash, and Gold Rush totals across a clean restart:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli gettxoutsetinfo muhash
blackcoin-cli getgoldrushstate
```

At or after the whitelist height, also require `getgoldrushstate.replay_state`
to report schema 11 with `present`, `marker_valid`, and `valid_for_tip` all
true. Keep the pre-upgrade wallet backup until the values and replay commitment
remain stable after a clean restart and a second offline chainstate rebuild.

## First run and data migration

On first run without `-datadir` or `-conf`, `blackcoind` and `blackcoin-qt` look for a legacy
`~/.blackmore` data directory. If it is the only legacy data directory, the node **copies**
it to `~/.blackcoin`, converts `blackmore.conf` to `blackcoin.conf`, leaves the original
intact, and writes a migration marker. If both `.blackcoin` and `.blackmore` exist, the GUI
prompts and headless startup safely keeps `.blackcoin` unless `-migratewallet=blackmore` is
supplied. Migration failures abort startup rather than loading the wrong wallet. Ensure there
is enough free disk for a full copy of the selected legacy directory and its backup.

> **Important:** ML-DSA quantum keys are **not** derived from your HD seed. **Back up your
> wallet again after creating any quantum address** (migration, staking, operator, or cold-stake), or a
> restore from an older backup will not recover those funds.

## Build

Protocol V4 consensus requires **liboqs 0.15.0** for ML-DSA quantum signatures. Release builds
must use the pinned dependency tree:

```bash
make -C depends
./autogen.sh
./configure --prefix="$PWD/depends/$(./depends/config.guess)"
make -j8
```

For local development only, an exact-version host liboqs can be used instead:

```bash
./autogen.sh
./configure --with-system-liboqs
make -j8
```

The primary binaries are `src/blackcoind`, `src/blackcoin-cli`, `src/blackcoin-wallet`, and
`src/qt/blackcoin-qt`.

## Test

```bash
# focused Blackcoin / Quantum Quasar checks
./src/test/test_blackcoin --run_test=shadow_tests,blackcoin_tests --catch_system_errors=no
python3 test/functional/feature_blackcoin_phase.py
python3 test/functional/rpc_goldrushinfo.py
python3 test/functional/rpc_rgb.py

# full functional suite
python3 test/functional/test_runner.py
```

## Relationship to Blackcoin More

Blackcoin Quantum Quasar is a fork of, and an advancement of,
[CoinBlack/blackcoin-more](https://github.com/CoinBlack/blackcoin-more). It targets the **same
Blackcoin network**, Quantum Quasar is a consensus upgrade for the existing chain, not a new
coin. All code here is MIT-licensed and **free to be re-incorporated upstream**; contributions
in either direction are welcome. Mainnet phase membership is height-authoritative. The
whitelist height, Gold Rush and Migration boundaries, and Final Lockout height are consensus
rules, so every node that wishes to remain on the same chain must use identical height values.
The retained timestamp anchors are nominal forecasts, not mainnet phase boundaries.

## Development notes

This repository still contains legacy Blackcoin compatibility names where they are protocol,
URI, historical, migration, or test-framework compatible. New user-facing code should use the
Blackcoin daemon, CLI, wallet, and configuration names.

## License

Blackcoin is released under the MIT license. See [COPYING](COPYING) for details.

Copyright (C) 2024-2026 Quantum Quasar Developers
Copyright (C) 2009-2026 Blackcoin Core Developers
Copyright (C) 2018-2026 Blackcoin More Developers
Copyright (C) 2014-2026 Blackcoin Developers
