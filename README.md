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

- **Quantum-safe signatures.** ML-DSA-44 (FIPS 204) via liboqs as a consensus-verified
  spending path, with new SegWit witness versions for quantum migration (v16), EUTXO smart
  contracts (v15), and quantum cold-staking (v14).
- **A bounded, one-click migration.** A generous **24-month** window to move legacy
  elliptic-curve coins into quantum-safe addresses with `migratetoquantum`, after which the
  legacy spending path closes, converting a permanent, network-wide vulnerability into a
  finite, individually-avoidable one.
- **The Gold Rush.** A 180-day bonus-emission epoch (up to 51,437,700 BLK) paid to holders
  **through staking and mining**, split 50/50 between native PoS and a light, CPU-friendly
  Argon2id PoW lane.
- **Liveness demurrage.** Quantum coins that remain inactive for more than six months
  slowly decay. Decayed principal is burned when spent and is never paid to a miner or
  staker. A timely liveness attestation, ordinary spend, or successful cold-stake refresh
  keeps the activity clock current.
- **Rich quantum staking.** Tiered self-staking, cold staking with owner/staker key
  separation, operator bonds, a per-pool decentralization cap, and autonomous redelegation.
- **Advanced primitives.** EUTXO smart-contract outputs and RGB client-side asset commitments.

## The V4 timeline (mainnet)

The mainnet lifecycle is height-authoritative. Median-time-past cannot advance,
delay, or reverse a production phase transition. Durations below are estimates
based on Blackcoin's 64-second target spacing; the listed heights are the
consensus boundaries.

| Phase | Mainnet heights | Approximate duration | Legacy spend? | Quantum spend? | Gold Rush? |
|-------|-----------------|----------------------|:---:|:---:|:---:|
| Legacy | through 5,949,999 | — | ✅ | ❌ | ❌ |
| Gold Rush | 5,950,000–6,192,999 | 180 days | ✅ | fundable, locked | ✅ |
| Migration | 6,193,000–6,921,999 | 540 days | ✅ | ✅ | ❌ |
| Final Lockout | from 6,922,000 | permanent | ❌ | ✅ | ❌ |

The 10,000 BLK Gold Rush whitelist snapshot is taken at height **5,945,000**. Full schedule
and constants are in the [white paper](doc/whitepaper-quantum-quasar.md).

## Required v30.1.0 chainstate rebuild

v30.1.1 uses authenticated auxiliary-state schema 11 and normalizes historical
UTXO timestamps. An existing v30.1.0 datadir must not be used for staking or
mining under v30.1.1 until it has completed one explicit chainstate rebuild.
Back up every wallet, stop the old process completely, and run:

```bash
blackcoind -datadir=/path/to/data -reindex-chainstate -daemonwait
```

`-reindex-chainstate` reconstructs state from local block files; it does not
retrieve block history that has already been pruned. The datadir must contain
the complete active-chain block data needed for the rebuild. If block files are
pruned or incomplete, set `prune=0` and use a full `-reindex` so the missing
history can be downloaded and the block index and chainstate rebuilt. Do not
delete wallet files or available block files.

After synchronization, record and compare the height, best-block hash, UTXO
MuHash, and Gold Rush totals across a clean restart:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli gettxoutsetinfo muhash
blackcoin-cli getgoldrushstate
```

Keep the pre-upgrade wallet backup until those values remain stable after the
clean restart.

## First run and data migration

On first run without `-datadir` or `-conf`, `blackcoind` and `blackcoin-qt` look for a legacy
`~/.blackmore` data directory. If it is the only legacy data directory, the node **copies**
it to `~/.blackcoin`, converts `blackmore.conf` to `blackcoin.conf`, leaves the original
intact, and writes a migration marker. If both `.blackcoin` and `.blackmore` exist, the GUI
prompts and headless startup safely keeps `.blackcoin` unless `-migratewallet=blackmore` is
supplied. Migration failures abort startup rather than loading the wrong wallet. Ensure there
is enough free disk for a full copy of the selected legacy directory and its backup.

> **Important:** ML-DSA quantum keys are **not** derived from your HD seed. **Back up your
> wallet again after creating any quantum address** (migration, staking, or cold-stake), or a
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
in either direction are welcome. Because the V4 activation time, whitelist height, Gold Rush
schedule, and migration deadline are consensus rules, any node that wishes to remain on the
same chain must run identical values.

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
