# Changelog

## v30.1.1

- Mainnet lifecycle decisions are height-authoritative: Gold Rush is
  5,950,000-6,192,999, Migration is 6,193,000-6,921,999, and Final Lockout
  begins at 6,922,000. During Gold Rush, quantum address generation and dry-run
  planning are available, but ordinary v14/v16 funding and spending are not.
- The emission-neutral competing-claim reimbursement rule begins at height
  5,993,200. Earlier Gold Rush blocks retain the v30.1.0 first-valid-claim
  allocation; upgraded shadow-ledger consumers intentionally derive the new
  canonical allocation only at and after that boundary.
- Gold Rush PoS allocation is enforced as one global accumulated pool split
  once across eligible active targets. Materialized payouts must sum exactly
  to the pool, including when multiple targets select the same payout script;
  dedicated apply-and-undo coverage prevents per-signaler multiplication or
  value loss.
- Demurrage activates automatically with the first Final block. Any
  nominal-minus-effective principal realized by a valid spend is permanently
  burned; it is not paid to a miner, staker, treasury, shadow pool, or claim
  participant. Cold-stake outputs are subject to the inactivity schedule, and
  mainnet configures no exempt scripts.
- Witness-v15 EUTXO funding and spending are frozen because the commitment does
  not authenticate a quantum owner. The creation RPCs intentionally fail.
  Decode/verify RPCs and persisted wallet metadata remain available only for
  inspection; users must not send BLK to v15 addresses.
- ML-DSA quantum keys are non-HD and are not derived from the wallet seed. A
  wallet backup must be newer than every quantum key it is expected to recover.
- Blackcoin Qt now detects an existing datadir that requires the mandatory
  authenticated chainstate rebuild before loading wallets. Its modal upgrade
  assistant can run the one-shot rebuild and verified normal restart
  automatically, or exit with platform-correct manual instructions. Staking,
  PoW, and autonomous quantum actions remain forced off until the replacement
  is reopened and verified; fresh and already-upgraded datadirs are not
  prompted.
- A wallet-authored Gold Rush PoW claim that leaves the local mempool remains
  quarantined with its exact input reserved. `getpowmininginfo` exposes live,
  quarantined, and total unresolved claim counts. The new
  `createshadowpowclaimresolution` RPC previews an exact-input, same-script
  on-chain conflict by default and signs only after explicit fee-and-conflict
  acknowledgement with a normally unlocked wallet. It never broadcasts,
  cannot guarantee peer acceptance or confirmation, and does not reimburse a
  confirmed resolution's base fee from the shadow ledger.
- Optional full circulating-supply scans are single-flight, bounded,
  progress-reporting, and cooperatively cancellable. The daemon, CLI RPC, and
  Qt resource guidance expose the same scoped qualification and refusal state;
  one-call consent cannot bypass critical integrity or storage protections.
- Final publication is fail-closed on a protected exact-source mainnet witness
  inventory. The artifact must bind the final binaries and connected-tip UTXO
  MuHash to a complete value-bearing witness-v2-through-v16 inventory and live
  shadow reconciliation, with either a zero bridge-review set or an approved
  disposition for every review outpoint.

## v30.1.0, Quantum Quasar production release

Protocol V4 (Quantum Quasar) hardening release. This is the intended mainnet
release of the Quantum Quasar upgrade. See
[doc/whitepaper-quantum-quasar.md](doc/whitepaper-quantum-quasar.md) for the full
protocol specification and [TRANSITION_GUIDE.md](TRANSITION_GUIDE.md) for operator
upgrade steps.

### Consensus

- Set the deterministic 10,000 BLK Gold Rush whitelist snapshot height to
  **5,945,000** (was 5,920,000), 5,000 blocks before Gold Rush rewards begin at
  height 5,950,000. This is a consensus parameter, all nodes must match it.

### Wallet GUI

- **Staking & Mining tab now opens instantly.** The first time the tab is shown it
  performs only a cheap, cached status update; the expensive Gold Rush, migration,
  cold-staking, RGB, and EUTXO-metadata detail panels load on demand behind a new
  **"Refresh details"** button (or automatically after a wallet-changing action).
  Removed the per-show full-wallet sweep and the live `GetStakeWeight()` coin scan
  from the first-show path, which lagged large wallets.
- **Unlock Wallet dialog** now offers two explicit, mutually-exclusive options:
  **"For Legacy Staking Only"** (mint legacy PoS blocks only) and **"Legacy and
  Quantum Staking"** (full unlock, required for quantum, Gold Rush, migration, and
  cold-staking actions). Replaces the single ambiguous "For staking only" checkbox;
  the two are laid out aligned with an exclusive selection.
- Earlier GUI performance work carried into this release: the periodic balance poll
  and its legacy/quantum breakdown run on the wallet worker thread (off the GUI
  thread), and the Account page loads on demand, keeping the interface responsive
  on wallets with tens of thousands of transactions.

### CLI

- Added `deladdressbook <address>` to remove a sending-address book entry from the
  CLI, matching the GUI's address-book delete (wallet-owned addresses are refused,
  as in the GUI).
- Added GUI controls for `redelegatequantumcoldstake` (with a dry-run preview of
  amount, fee, and projected pool share) and `optimizeutxoset` on the Staking &
  Mining page.

### Branding and documentation

- Copyright updated through **2026** and now lists **Quantum Quasar Developers** first
  across the splash screen, the About dialog, the license/`--version` output, the
  Debian packaging copyright, and all man pages, followed by Blackcoin Core (2009),
  Blackcoin More (2018), and Blackcoin (2014) Developers.
- Added a comprehensive Quantum Quasar white paper, an expanded README, and this
  changelog. Debian packaging now records this repository as upstream while
  acknowledging the CoinBlack/blackcoin-more fork lineage (all changes MIT and free
  to re-incorporate upstream).
- Regenerated man pages to the correct version and copyright.

## v30.0.0, Quantum Quasar (Protocol V4)

Major post-quantum protocol upgrade. Renumbered from the v26.2.x line to v30.0.0 to
reflect the scope of the protocol, wallet, staking, migration, and branding changes.
Highlights (full detail in the white paper):

- **Post-quantum cryptography.** ML-DSA-44 (FIPS 204) signatures via liboqs as a
  consensus-verified spending path, with a startup Known-Answer-Test. New SegWit
  witness versions: v16 quantum migration and v14 quantum cold-stake. Witness
  v15 was reserved for EUTXO work and is frozen in v30.1.1 pending a
  quantum-authenticated ownership design.
- **V4 phase schedule.** The original time anchors define nominal durations.
  v30.1.1 makes the mainnet Legacy -> Gold Rush (180 days) -> Migration (540
  days) -> Final Lockout schedule height-authoritative, after which legacy
  ECDSA spends are permanently disabled.
- **Gold Rush epoch.** Deterministic whitelist snapshot of ≥10,000 BLK accounts; a
  180-day bonus emission (580 BLK/block halving every 43,200 blocks, then a 463
  BLK/block tail, capped at 51,437,700 BLK) split 50/50 between PoS and a light
  1-MiB Argon2id PoW lane; claimed via QQSIGNAL/QQSPROOF control transactions.
- **Quantum migration.** `migratetoquantum` sweeps legacy coins into ML-DSA
  migration addresses; keys are stored before funds move. `migrategoldrushrewards`,
  `getmigrationstatus`, and full quantum-address RPCs.
- **Demurrage.** Liveness mechanism on eligible quantum outputs: a 6-month
  grace period, then quadratic decay to zero over 18 months. v30.1.1's approved
  rule permanently burns realized decay. Automatic ML-DSA liveness
  attestations keep eligible direct quantum outputs current; cold-stake
  delegation alone is not exempt, while a successful coinstake refreshes the
  recreated output.
- **Quantum staking.** Tiered self-staking with consensus-visible bonding/unbonding;
  cold staking with owner/staker key separation; 30-day operator bonds; a 20%
  per-pool policy cap; and autonomous, rate-limited redelegation.
- **Advanced primitives.** RGB client-side-validated asset commitments. The
  EUTXO witness-v15 datum/validator encoding and inspection metadata remain in
  the source, but v30.1.1 disables its creation, funding, and spending paths.
- **First-run data migration.** Copy-only import of a legacy `~/.blackmore` data
  directory into `~/.blackcoin`, leaving the original intact.
- **Rebranding** to Blackcoin daemon/CLI/wallet/Qt binaries with preserved
  legacy-compatible protocol, URI, and migration names.

## v26.2.0 (2024-12-18)
- Begin signalling for SegWit activation on mainnet on June 20, 2025

## v26.2.0-beta-2 (2024-11-20)
- Activated SegWit on testnet on Sep 23, 2024
- Changed miner activation window parameters for BIP9 soft fork deployment
- Updated derivation path with the BIP44 coin type for descriptor wallets
- Abandon coinstake transactions when orphaned (Peercoin commit `f6896a4`)
- Show P2PK addresses for coinstake transactions in RPC
- Show the reward value for coinstake transactions in RPC

## v26.2.0-beta-1 (2024-08-07)
- Updated to Bitcoin Core 26.2
- Activated Segwit on regtest
- New mempool.dat format (backport of Core's PR28207)

## v26.1.0-beta-1 (2024-05-24)
- Updated to Bitcoin Core 26.1
- Create V2 transactions by default
- Disconnect from peers older than version 70015
- Increased `DUST_RELAY_TX_FEE` and `DEFAULT_MIN_RELAY_TX_FEE` to 100000
- Eliminated segfault occurring after a power outage
- Enabled V2 P2P transport by default (backport of Core's PR29347 and 29058)
- Enabled `checkkernel` RPC call
- Only delete the PID file if we created it (backport of Core's PR28946)
- Set minimum UTXO value to be used for staking to 0.1 BLK (can be overridden with `-minstakingamount` parameter)

## v26.0.0-beta-1 (2024-02-12)
- Updated to Bitcoin Core 26.0
- Fixed a bug that prevented adding more inputs in the coinstake transaction for legacy wallets
- Fixed a bug causing inability to connect to fixed seeds
- Fixed reindexing

## v25.1.0-alpha-3 (2024-01-30)
- Set mainnet hard fork date to April 24, 2024
- Use virtual transaction size in minimum fee calculation
- Fixed a bug with header syncing between More 25.1 nodes
- Fixed windows build
- Enabled flushing of orphaned stakes also on wallet start
- Enabled staking with P2WPKH inputs

## v25.1.0-alpha-2 (2023-11-24)
- Fixed a bug with segfault on wallet close when staking is enabled
- Added full support for descriptor wallets, including staking
- Added support for staking with multiple wallets simultaneously
- Removed GUI staking warnings due to incompatibility with multiple staking threads
- Enabled `staking` RPC call
- Multiple minor changes to ThreadStakeMiner() algorithm

## v25.1.0-alpha-1 (2023-10-24)
- Updated to Bitcoin Core 25.1
- Removed OpenSSL
- Implemented maximum witness size policy (Peercoin RFC-0027)
- Added `optimizeutxoset` RPC method to simplify splitting coins for efficient staking (Peercoin PR711)
- Added a GUI warning if unable to stake

## v22.1.0-alpha-2 (2023-01-24)
- Flush orphaned stakes prior to each staking attempt
- Enabled checkpoints by default
- Added rolling checkpoints checks

## v22.1.0-alpha-1 (2023-01-20)
- Updated to Bitcoin Core 22.1

## v13.2.3 (2024-05-18)
- Create V2 transactions by default
- Disconnect from peers older than version 70015
- Increased `DEFAULT_MIN_RELAY_TX_FEE` to 100000

## v13.2.2 (2024-01-24)
- Set mainnet hard fork date to April 24, 2024
- Adjusted minimum fee calculations

## v13.2.1 (2023-07-04)
- Reduced the minimum fee after a fork
- Fixed a bug in the derivation of TxTime that could potentially lead to unplanned hard forks
- Fixed a segfault issue occurring during the initial sync

## v13.2.0 (2022-11-24)
- Changed versioning (backport of Core's PR20223)
- Testnet hard fork: Removed transaction timestamp
- Testnet hard fork: Increased transaction fees and set minimum transaction fee of 0.001 BLK
- Testnet hard fork: Enabled relative timelocks (OP_CHECKSEQUENCEVERIFY, BIP62, 112 and 113)
- Enabled compact block relay protocol (BIP152)
- Added an option to donate the specified percentage of staking rewards to the dev fund (20% by default)
- Set default `MAX_OP_RETURN_RELAY` to 223
- Removed `sendfreetransactions` argument
- Get rid of `AA_EnableHighDpiScaling` warning (backport of Core's PR16254)
- Updated multiple dependencies

## v2.13.2.9 (2022-02-24)
- Updated leveldb, which should resolve the "missing UTXO" staking issue
- Updated dependencies and ported build system from Bitcoin Core 0.20+
- Updated crypto and added CRC32 for ARM64
- Updated univalue to v1.0.3
- Updated to Qt v5.12.11
- Updated to OpenSSL v1.1.1m
- Added `getstakereport` RPC call
- Added `--use-sse2` to enable SSE2
- Code cleanup (headers, names, etc)

## v2.13.2.8 (2021-02-24)
- Immediately ban clients operating on forked chains older than nMaxReorganizationDepth
- Fixed IsDust() policy to allow atomic swaps
- Updated fixed seeds for mainnet and testnet
- Updated dependencies for MacOS

## v2.13.2.7 (2020-11-24)
- Dust mitigation in mempool (by JJ12880 from Radium Core) 
- Compile on MacOS Catalina
- Cross-compile MacOS with Xcode 11.3.1
- Updated dependencies for Windows x64, Linux x64, MacOS, ARM64, ARMv7
- Sign/verify compatibility with legacy clients 
- Increased dbcache to 450MB
- Disabled stake cache for now
- Updated fixed seeds for mainnet and testnet

## v2.13.2.6 (2020-07-21)
- Fix staking memory leak (by JJ12880 from Radium Core)
- Updated fixed seeds
- Added secondary Blackcoin DNS seeder

## v2.13.2.5 (2020-04-28)
- Updated Berkeley DB to 6.2.38
- Updated OpenSSL to 1.0.2u
- Updated fixed seeds
- Changed default port on regtest to 35714

## v2.13.2.4 (2019-11-11)
- Updated fixed seeds
- Added `burn` RPC call
- Set default `MAX_OP_RETURN_RELAY` to 15000
- Removed unit selector from status bar

## v2.13.2.3 (2019-04-02)
- Updated fixed seeds
- Some small fixes and refactorings
- Fixed wrongly displayed balances in GUI and RPC
- Added header spam filter (fake stake vulnerability fix)
- Added total balance in RPC call `getwalletinfo`

## v2.13.2.2 (2019-03-13)
- Updated dependencies
- Updated fixed seeds
- Some small fixes and updates
- Fixed `walletpassphrase` RPC call (wallet now can be unlocked for staking only)
- Allowed connections from peers with protocol version 60016
- Disabled BIP 152

## v2.13.2.1 (2018-12-03)
- Updated to Bitcoin Core 0.13.2
- Some small fixes and updates from Bitcoin Core 0.14.x branch
- Fixed testnet and regtest
- Added Qt 5.9 support for cross-compile
- Added Qt support for ARMv7
- Added out-of-sync modal window (backport of Core's PR8371, PR8802, PR8805, PR8906, PR8985, PR9088, PR9461, PR9462)
- Added support for nested commands and simple value queries in RPC console (backport of Core's PR7783)
- Added `abortrescan` RPC call (backport of Core's PR10208)
- Added `reservebalance` RPC call
- Removed SegWit
- Removed replace-by-fee
- Removed address indexes
- Removed relaying of double-spends
- Removed drivechain support using OP_COUNT_ACKS
- Proof-of-stake related code optimized and refactored

## v2.12.1.1 (2018-10-01)
- Rebranded to Blackcoin More
- Some small fixes and updates from Bitcoin Core 0.13.x branch
- Added "Use available balance" button in send coins dialog (backport of Core's PR11316)
- Added a button to open the config file in a text editor (backport of Core's PR9890)
- Added `uptime` RPC call (backport of Core's PR10400)
- Removed P2P alert system (backport of Core's PR7692)
