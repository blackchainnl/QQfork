# Blackcoin V4 Upgrade Guide

Blackcoin V4 is the Quantum Quasar protocol upgrade line for Blackcoin. It keeps
the existing chain history and wallet continuity while adding quantum migration
addresses, Gold Rush reward participation, staking changes, RGB tooling,
inspection-only EUTXO metadata, and first-run migration from older Blackcoin
data directories. Witness-v15 EUTXO has no supported funding or spending
workflow in v30.1.1, and consensus rejects v15 outputs and spends from Migration
onward.

This document describes the intended transition model for testing and operator
review. It is not a public-network activation notice.

## Transition Timeline

Mainnet uses a height-authoritative schedule. Gold Rush is height 5,950,000
through 6,192,999. The emission-neutral competing-claim rule begins at height
5,993,200. Migration is height 6,193,000 through 6,921,999. Final Lockout and
automatic demurrage begin at height 6,922,000. Nominal time anchors do not move
these production boundaries.

The V4 transition runs in phases.

1. Activation and bridge period.
   Upgraded nodes follow the legacy chain and accept legacy-compatible blocks.
   There is no day-one split from ordinary legacy ledger activity.

2. Gold Rush period, approximately six months.
   Upgraded wallets can participate in Gold Rush reward accounting while the
   base block flow remains legacy-compatible. Rewards are credited to quantum
   addresses on the upgraded ledger, but ML-DSA quantum spends and larger
   post-quantum script elements remain disabled until after the Gold Rush
   reward-height window.

3. Quantum migration period, approximately eighteen months after Gold Rush.
   Mature Gold Rush payouts are ordinary spendable quantum UTXOs; no fresh
   address move, expiry, or remigration is required. Users may optionally
   consolidate them and migrate remaining legacy value to quantum addresses.
   This is the hard-fork spend phase: legacy-only nodes do not validate ML-DSA
   quantum spends, so stake-majority coordination must be complete before this
   phase begins.

4. Final lockout.
   After the migration deadline, non-migrated legacy spends are disabled on the
   upgraded chain. Authenticated v14/v16 quantum outputs remain spendable under
   the new rules. Demurrage activates automatically on this same first Final
   block. Witness v15 remains frozen.

The full planned transition is approximately twenty-four months from the start
of Gold Rush through final lockout.

## Required two-start upgrade and rollback rehearsal

Do not treat a successful in-place startup as rollback evidence. Before a beta
artifact is used beyond an isolated canary, rehearse with a stopped v30.1.0
datadir and three separate copies: an immutable cold source, a disposable
v30.1.1 upgrade copy, and a rollback copy restored again from the cold source.
Never start v30.1.0 on the upgraded copy.

1. Verify the candidate artifact checksum and record its full source SHA. Stop
   v30.1.0 cleanly. Copy the complete datadir while it is stopped, then hash
   every wallet database. For every loaded wallet, record the public
   `getquantumkeyinventory` rows (address, public key, creation time, and backup
   state) and prove one existing legacy key with `signmessage`/`verifymessage`.
2. Clone the cold source into the disposable upgrade directory. Disable all
   networking, staking, mining, automatic signalling, redelegation, and
   automatic key creation. Start the candidate once with
   `-reindex-chainstate`. That isolated process must reach durable
   `COMMIT_READY`, retain the source chainstate backup, open no RPC/P2P/wallet
   services, and exit successfully.
3. Start the same candidate artifact a second time without a reindex flag. It
   must reopen and verify the replacement before deleting the source backup.
   Compare every wallet's quantum address/public-key inventory with step 1 and
   prove the same legacy key again. Run `backupwallet` to a new external path;
   this operation reopens the staged backup and makes every contained ML-DSA
   key sign and verify a fresh challenge before installation. Require
   `all_durably_stored=true`, `all_backed_up=true`, an unchanged key count, and
   the same address/public-key set. Stop cleanly and retain the upgraded copy
   only as evidence.
4. Create the rollback directory from the untouched cold source, not from any
   v30.1.1 file. Before startup, require its wallet-file hashes to match step 1
   byte for byte. Start the pinned v30.1.0 artifact with automation and
   networking disabled. Require the exact pre-upgrade quantum inventory and a
   fresh signature from the same legacy key, then stop cleanly.
5. Preserve the artifact hashes, commands, process exit codes, journal phases,
   pre/candidate/rollback inventories, wallet-file hashes, signature results,
   and backup paths in the release record. Any missing key, changed public key,
   unverified backup, service opened during the first start, source backup
   removed before the second start, or rollback file not sourced from the cold
   copy fails the rehearsal.

The repository's regtest recovery suite injects real process termination at
each durable migration and chainstate journal boundary. POSIX coverage also
applies a real per-process file-write quota after `BUILDING` is durable so the
replacement database fails during reconstruction and the next process must
restore the preserved source. Those tests establish the recovery mechanism;
they do not replace running this rehearsal with the exact release artifacts on
each supported platform.

## Gold Rush Participation

Gold Rush rewards are split between staking-based participation and Proof of Work
claim participation.

For staking participation, eligible wallets signal from a whitelisted legacy
address and bind the signal to a quantum payout address. The signal is recorded
on-chain and remains active for the configured look-back window. Active,
qualified signalers share the staking-side Gold Rush allocation evenly while
they remain eligible.

For Proof of Work participation, a wallet computes an Argon2id proof against the
current work parameters and broadcasts a `QQSPROOF` transaction. The transaction
authenticates the claimant with a legacy spend and specifies a quantum payout
address. If a staker includes a valid claim, the upgraded rules credit the
claim's reward to that quantum address. Claim transactions pay ordinary network
fees. Through height 5,993,199, replay preserves the v30.1.0 allocation rule so
already-mined shadow history is not reassigned. From the first scheduled Gold
Rush halving at height 5,993,200, the new v30.1.1 QQP3 rule authenticates an
origin height and parent hash and chooses a current-origin winner by the
transaction-order-independent rank-v1 rule. Current losers and eligible claims
included up to 64 blocks late receive their actual fee capped at 0.01 BLK. The
winner receives the fixed pool remainder; late-only blocks leave the
unreimbursed pool accumulated. Malformed, expired, origin-mismatched, and
over-limit claims receive nothing; the total credit never exceeds the existing
pool.

QQP4 adds an exact legacy fee-input outpoint, but it has a separate consensus
activation and is disabled on mainnet in this alpha/beta channel. Signalling
does not activate QQP4. A future QQP4 release must declare its activation
height and prove the Q3 late-claim transition through block, mempool, reorg,
and replay coverage before scheduling it.

This makes height 5,993,200 an upgrade deadline for every wallet, staking or
mining node, explorer, and indexer that consumes shadow state. v30.1.0 and
v30.1.1 remain compatible with the same Gold Rush base blocks, but their shadow
recipients and balances intentionally diverge from this height. Do not switch a
wallet/datadir that has processed post-boundary v30.1.1 state back to v30.1.0;
restore the cold pre-upgrade copy for rollback. “No base-chain fork” does not
mean “identical shadow ledger.”

The wallet exposes helper RPCs for both paths, including `getgoldrushstate`,
`getgoldrushinfo`, `sendshadowsignal`, `getshadowpowwork`,
`sendshadowpowclaim`, `setpowmining`, and `getpowmininginfo`.

### Explicit wallet automation and fleet-safe quantum payout bindings

v30.1.1 starts every optional local automation in the fail-closed state.
Automatic staking restart, PoW restart, QQSIGNAL submission, demurrage
attestations, cold-stake redelegation, and background ML-DSA key creation must
each be enabled explicitly. The GUI provides separate persistent controls and
consequence-specific confirmations. Headless operators can inspect the same
effective state with `getstakinginfo` and `getpowmininginfo`.

For a one-session headless start, control the loaded wallet explicitly:

```bash
blackcoin-cli -rpcwallet="Wallet Name" staking true
blackcoin-cli -rpcwallet="Wallet Name" setpowmining true 1 1 false
blackcoin-cli -rpcwallet="Wallet Name" getstakinginfo
blackcoin-cli -rpcwallet="Wallet Name" getpowmininginfo
```

The final `false` refuses new payout-key creation. For persistent daemon
behavior, add only the automations you actually authorize to the startup
command or configuration, for example `autostartstaking=1`,
`qqautoshadowsignal=1`, and a backed-up
`qqpospayoutaddress=blk1...`. Persistent PoW additionally uses `powmining=1`,
`powminingthreads=1`, `powminingcpu=1`, and a backed-up
`qqpowpayoutaddress=blk1...`. The GUI exposes the same runtime controls and
persistent choices in Staking & Mining.

Background key creation is off by default. Prefer binding every automatic path
to an existing backed-up key:

```ini
autostartstaking=0
powmining=0
qqautoshadowsignal=0
qqallowautokeycreation=0
qqpowpayoutaddress=blk1...
qqpospayoutaddress=blk1...
qqdemurragechangeaddress=blk1...
qqautoredelegate=0
qqautodemurrageattest=0
```

The three address options may use the same address. Each value must be an
ordinary direct v16 quantum address for the active network, not a tiered or
cold-stake contract address, and must be backed by a durably stored ML-DSA
private key in the wallet performing the operation. Address-book labels are
not used to resolve an explicit binding. Missing, repeated, invalid, contract,
or foreign-wallet values fail closed before key generation and return an
actionable wallet error. Keep one independently configured wallet per fleet
process; a loaded wallet that does not own the process-level binding cannot use
that automatic path.

Enabling `qqautoredelegate=1` also requires explicit
`qqallowautokeycreation=1`. Autonomous cold-stake redelegation currently
creates a new non-HD owner key, so startup rejects that automation unless key
creation has separately been authorized. The default-off key gate does not disable a user's explicit
`getnewquantumaddress` request. Keep the bindings in the node configuration so
they survive restart, and verify that the referenced key is present in every
wallet backup before enabling staking or mining.

During Gold Rush and Migration, keep `qqautodemurrageattest=0` unless the
operator expressly wants fee-paying attestation transactions. This switch returns before the automatic
attestation scheduler scans the wallet or constructs a transaction. Before
enabling it at Final activation, keep `qqdemurragechangeaddress` bound to an
existing backed-up key, restart with `qqautodemurrageattest=1`, and verify that
the wallet's quantum-key inventory has not changed. Manual attestation RPCs are
not disabled by this background-automation switch. Mandatory consensus
demurrage and permanent burn begin automatically at Final height 6,922,000 and
are not controlled by the optional wallet-attestation setting.

`setpowmining true 1 1 false` starts only when a configured or previously
stored payout key exists. If no payout exists, the call fails without creating
a key. `setpowmining true 1 1 true` is a separate one-call consent to create one
new non-HD payout key; if the result reports `created_payout_key=true`, back up
the wallet immediately.

## Quantum Addresses And Migration

Quantum migration addresses use ML-DSA keys and are distinct from legacy
addresses. During Gold Rush, users may create and back up quantum addresses and
use dry-run planning, but ordinary quantum funding and spending remain
disabled. Users should move funds during Migration, from height 6,193,000
through 6,921,999, before Final Lockout.

ML-DSA quantum keys are non-HD and are not derived from the wallet seed. Back
up the wallet after creating every quantum migration, staking, operator, or
cold-stake address. A backup made before a quantum key was created cannot
recover that key.

The primary wallet flow is:

1. Generate or select a wallet-backed quantum migration address.
2. Use `migratetoquantum` to build and send the migration transaction.
3. Confirm the migrated output is wallet-backed and spendable.
4. Treat matured Gold Rush payouts as ordinary quantum UTXOs. Optional
   consolidation is available, but it does not establish ownership and is not
   a prerequisite for spending, staking, or Final lockout.

Gold Rush reward outputs are intentionally locked until quantum witness spends
activate after the Gold Rush reward-height window. This keeps the Gold Rush
bridge legacy-compatible. After normal coinbase maturity, the payout is an
ordinary quantum UTXO and remains valid through Migration and Final.

Wallets and UI surfaces should clearly separate legacy receiving addresses from
quantum migration addresses so users do not confuse pre-migration legacy sends
with post-migration quantum custody.

## Staking Changes

V4 includes quantum cold-staking and staking policy changes intended to preserve
principal safety while improving operator distribution.

- Cold-stake principal preservation keeps delegated principal in the owner's
  spend branch while allowing the selected staking key to produce coinstakes.
- Stake-reward splitting pays the delegator and operator according to the
  consensus split for eligible cold-stake coinstakes.
- Tiered staking weights use a deterministic fixed-point curve for eligible
  quantum staking commitments.
- Automatic redelegation lets a normally unlocked private-key owner wallet move
  a safe, owner-spendable delegation only after the current operator has no
  observed wins for the clamped policy interval and a meaningfully better
  verified target is available. Rate limits, activation probation, and
  deterministic jitter also apply.
- The per-pool cap is wallet and policy guidance. It steers new delegations away
  from oversized operators when under-cap alternatives exist, but exceeding the
  cap does not trigger redelegation. If every verified target is over the cap,
  the bootstrap fallback may still select one. The cap is not a consensus
  defense and does not prevent solo staking or operator sub-pools.
- Cold-stake outputs remain subject to demurrage. A successful coinstake or
  owner spend/recreation refreshes the output; delegation by itself is not an
  exemption. Liveness attestations apply only to eligible direct/tiered v16
  keys and cannot refresh a cold-stake output.

## Demurrage And Liveness

Demurrage activates automatically at the first Final height after the
migration deadline. It applies to eligible direct, tiered, and cold-stake
quantum outputs; mainnet configures no exempt scripts. It is inactive during
Gold Rush and Migration. Wallet-backed liveness attestations can refresh
eligible direct/tiered v16 keys, but not cold-stake outputs. Automatic attempts
also require staking to be enabled, a normally unlocked private-key wallet, and
a safe spendable fee input. Successful cold-stake coinstakes refresh their
recreated outputs. Any realized decay is permanently burned, not paid to a
miner, staker, treasury, or reward pool.

Witness-v15 EUTXO commitments are not a usable activity path. v30.1.1 provides
no supported funding or spending workflow, and consensus rejects v15 outputs
and spends from Migration onward because the design lacks quantum ownership
authorization. Its decode, verification, and wallet-metadata surfaces are
inspection-only.

## Existing-node upgrade and chainstate rebuild

v30.1.1 changes the persisted shadow and demurrage state to authenticated
schema 12, recomputes the
canonical competing-claim result from height 5,993,200, and preserves v30.1.0
block-time provenance for transaction outputs across live validation and replay.
Operators upgrading from v30.1.0 must back up wallets and stop the old process
before relying on the node for staking or mining. Blackcoin Qt detects the
mandatory rebuild before loading wallets and offers to complete the protected
rebuild and verification restart automatically. Choosing the manual option
exits without changing chainstate and displays a platform-correct command that
preserves the selected datadir, network, and startup arguments.

Headless operators run one `-reindex-chainstate` process:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

That process exits automatically at the durable `COMMIT_READY` transition.
Start once normally without either reindex option. The second process verifies
the recorded tip and complete Coin commitment, retires the preserved source,
then restores the operator's automation settings before loading wallets. Do
not treat the temporary source backup as expendable before that verification:
it is retired only after verification succeeds, while failure or interruption
preserves the backup and journal for recovery. Do
not persist `reindex-chainstate=1` or `reindex=1` in configuration or settings;
v30.1.1 rejects both loop-forming configurations.

The rebuild requires complete active-chain block data for every height it must
replay. `-reindex-chainstate` uses local block files and does not fetch history
that pruning has deleted. If the datadir is pruned or its block files are
incomplete, set `prune=0` and use a full `-reindex` to redownload missing
history and rebuild both the block index and chainstate. Do not delete wallets
or available block files. Allow sufficient disk space and keep the pre-upgrade
backup until the rebuilt node has synchronized and passed a clean-restart
comparison.

Pruning is not supported by the v30.1.1 beta. Run archival and replay nodes
with `prune=0`. Mainnet, testnet, and signet startup reject nonzero `-prune`
because no Blackcoin proof-of-stake retention and recovery claim has passed the
release gate. Nonzero values remain available only on regtest for test
coverage. If historical blocks are missing, preserve wallets and all remaining
data, then use `prune=0 -reindex` to redownload full history.

v30.1.1 checks the saved chainstate tip and every ancestor through genesis
before wiping. If a known-pruned block is missing, startup stops with a full
`-reindex` instruction and leaves the existing chainstate intact. This check
also runs before an assumeUTXO snapshot is removed. It cannot predict a later
disk or checksum failure, so use a copied datadir for the first alpha test and
retain the original backup.

Before it creates a rebuild journal or moves a source database, v30.1.1 also
scans the chainstate directory and requires free space equal to at least its
logical size plus a 50 MiB safety reserve. An unreadable or unstable source
topology, including a symlink or special file, fails closed without moving the
source.

From rebuild start through verified cleanup, the process forces legacy
staking, Gold Rush PoW, automatic QQSIGNAL, demurrage attestation,
redelegation, and automatic quantum-key generation off in memory. It preserves
the original command-line, configuration, and settings values and restores
them only after the replacement passes verification. After `COMMIT_READY`, the
rebuilding process also refuses any queued active-chain connect or disconnect
until it exits, keeping the durable commitment stable for the verifier.

After the rebuild, record these RPC results:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli gettxoutsetinfo muhash
blackcoin-cli getgoldrushstate
```

In `getgoldrushstate`, require `replay_state.schema` to equal `12` and
`replay_state.present`, `marker_valid`, and `valid_for_tip` to all be `true` at
or after the whitelist height. Record its 64-hex-character `commitment`, marker
height, marker block hash, active height, and best-block hash. The UTXO MuHash
does not include zero-value internal markers; the replay commitment is the
separate proof that the pool, signals, whitelist, Gold Rush inventory, and
demurrage inventory match the same tip.

The rebuild process stops itself at `COMMIT_READY`; restart offline without
either reindex option. Confirm that
height, best-block hash, UTXO MuHash, Gold Rush totals, and the complete
`replay_state` object match byte-for-byte. For release-candidate qualification,
repeat once more with `-reindex-chainstate` at the same pinned tip and compare
again before enabling networking, staking, or mining.

Optional indexes have independent replay state. v30.1.1 automatically wipes
and rebuilds prerelease shadowindex schemas 4 and 5 as schema 6 and prerelease
coinstatsindex schema 2 as schema 3. The automatic index-only rebuild is enough
when complete active-chain block files are present; `-reindex-chainstate` does
not itself wipe either index. If required block files were pruned, disable the
affected index or restore full history with `prune=0` and `-reindex`.

This automatic repair does not extend to a wallet database created by a
prerelease source build that used the superseded height-5,950,000 canonical
claim rule. Such a wallet can retain a synthetic payout transaction whose base
block is still active even though corrected chainstate no longer contains that
payout. A normal rescan can add missing corrected payouts but does not remove
that obsolete confirmed synthetic record. Restore a wallet backup made before
running that prerelease (and verify that it contains every quantum key) before
rescanning from height 5,950,000. If no complete pre-prerelease wallet backup
exists, keep staking and spending disabled pending an explicit wallet repair.

After the authenticated Quantum Quasar namespace begins, a process or power
failure during a multi-batch chainstate flush also fails closed on restart and
requires `-reindex-chainstate`. A partial database flush cannot prove that every
auxiliary leaf reached disk merely because its rolling summary did. This trades
automatic crash recovery for deterministic reconstruction from block files.

`-reindex-chainstate` opens a newly wiped chainstate database and derives the
entire UTXO and auxiliary state from block files. Removal of obsolete v30.1.0
or prerelease demurrage records therefore does not depend on recognizing them
in place. The defensive pre-whitelist cleanup also recognizes authenticated
obsolete reserved records, but never deletes marker-shaped transaction outputs
at ordinary outpoints.

Wallet RPCs include `getdemurragewalletinfo`, `senddemurrageattestation`,
`sweepdemurragedecay`, and `getcirculatingsupply`.

## First-Run Data Directory Migration

On first run, if no explicit `-datadir` or `-conf` is supplied, `blackcoind` and
`blackcoin-qt` inspect the default data-directory locations for older Blackcoin
data.

No source is selected automatically. Whether one or both locations contain
data, `blackcoin-qt` shows the detected source and destination paths, explains
copy/backup and rollback behavior, and offers the applicable source or an
exit/manual choice. Exiting does not start a new migration, backup, or
retirement operation.

Headless `blackcoind` fails closed before starting a backup or import and prints
the exact applicable one-shot command. Use `-migratewallet=blackmore` to copy
the detected `.blackmore` tree into `.blackcoin` after verified recovery
backups, `-migratewallet=blackcoin` to keep a populated `.blackcoin` source
after verified backup, or `-migratewallet=none` to preserve verified backups
without importing or replacing wallet data. Pass the option on the command
line only and remove it after the successful first run; do not persist it in
`blackcoin.conf`.

Migration is copy-first and backup-preserving. If migration cannot complete
safely, startup aborts rather than creating or loading an empty or wrong wallet.
Operators should make sure the system has enough free disk space for the copied
data directory and backup material before first run.

## Build And Run

Build from the repository root:

```bash
./autogen.sh
./configure
make -j8
```

Useful binaries:

```bash
src/blackcoind
src/blackcoin-cli
src/blackcoin-wallet
src/qt/blackcoin-qt
```

For local testing, start with regtest or a private soak network. Do not use a
pre-release build as a public-network activation client until activation
parameters, release binaries, and operator instructions have been published.

Run core validation checks with:

```bash
make -C src -j8 check
python3 test/functional/test_runner.py
```
