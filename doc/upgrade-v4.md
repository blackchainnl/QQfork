# Blackcoin V4 Upgrade Guide

Blackcoin V4 is the Quantum Quasar protocol upgrade line for Blackcoin. It keeps
the existing chain history and wallet continuity while adding quantum migration
addresses, Gold Rush reward participation, staking changes, RGB/EUTXO
commitment tooling, and first-run migration from older Blackcoin data
directories.

This document describes the intended transition model for testing and operator
review. It is not a public-network activation notice.

## Transition Timeline

The V4 transition is designed to run in phases.

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
   upgraded chain. Quantum outputs remain spendable under the new rules.

The full planned transition is approximately twenty-four months from the start
of Gold Rush through final lockout.

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
Rush halving at height 5,993,200, if a custom block contains multiple valid
claims, v30.1.1 chooses the winner by a transaction-order-independent rank. Each
evaluated valid loser receives its actual fee capped at 0.01 BLK, and the winner
receives the fixed pool remainder. Malformed and over-limit claims receive
nothing; the total credit never exceeds the existing pool.

The wallet exposes helper RPCs for both paths, including `getgoldrushstate`,
`getgoldrushinfo`, `sendshadowsignal`, `getshadowpowwork`,
`sendshadowpowclaim`, `setpowmining`, and `getpowmininginfo`.

## Quantum Addresses And Migration

Quantum migration addresses use ML-DSA keys and are distinct from legacy
addresses. Users should create quantum addresses with the wallet RPCs and move
funds before the migration deadline.

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
- Autonomous redelegation lets an unlocked owner wallet move a delegation when
  the current operator has not won for the configured interval and a better
  verified target is available.
- The per-pool cap is wallet and policy guidance. It steers new delegations away
  from oversized operators when alternatives exist, but it is not a consensus
  defense and does not prevent solo staking or operator sub-pools.
- Cold-stake outputs remain subject to demurrage. A successful coinstake or
  authenticated liveness attestation refreshes activity; delegation by itself
  is not an exemption.

## Demurrage And Liveness

Demurrage activates automatically at the first Final height after the
migration deadline and applies only to direct quantum outputs that are not
exempt. It is inactive during Gold Rush and Migration. Wallet-backed liveness
attestations can refresh inactive quantum keys, and staking wallets can create
periodic attestations while staking.

## Existing-node upgrade and chainstate rebuild

v30.1.1 changes the persisted shadow and demurrage state to authenticated
schema 11, recomputes the
canonical competing-claim result from height 5,993,200, and preserves v30.1.0
block-time provenance for transaction outputs across live validation and replay.
Operators upgrading from
v30.1.0 must back up wallets, stop the daemon, and run one full
`-reindex-chainstate` before relying on the node for staking or mining:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

The rebuild requires complete active-chain block data for every height it must
replay. `-reindex-chainstate` uses local block files and does not fetch history
that pruning has deleted. If the datadir is pruned or its block files are
incomplete, set `prune=0` and use a full `-reindex` to redownload missing
history and rebuild both the block index and chainstate. Do not delete wallets
or available block files. Allow sufficient disk space and keep the pre-upgrade
backup until the rebuilt node has synchronized and passed a clean-restart
comparison.

v30.1.1 checks the saved chainstate tip and every ancestor through genesis
before wiping. If a known-pruned block is missing, startup stops with a full
`-reindex` instruction and leaves the existing chainstate intact. This check
also runs before an assumeUTXO snapshot is removed. It cannot predict a later
disk or checksum failure, so use a copied datadir for the first alpha test and
retain the original backup.

After the rebuild, record these RPC results:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli gettxoutsetinfo muhash
blackcoin-cli getgoldrushstate
```

In `getgoldrushstate`, require `replay_state.schema` to equal `11` and
`replay_state.present`, `marker_valid`, and `valid_for_tip` to all be `true` at
or after the whitelist height. Record its 64-hex-character `commitment`, marker
height, marker block hash, active height, and best-block hash. The UTXO MuHash
does not include zero-value internal markers; the replay commitment is the
separate proof that the pool, signals, whitelist, Gold Rush inventory, and
demurrage inventory match the same tip.

Stop cleanly and restart offline without either reindex option. Confirm that
height, best-block hash, UTXO MuHash, Gold Rush totals, and the complete
`replay_state` object match byte-for-byte. For release-candidate qualification,
repeat once more with `-reindex-chainstate` at the same pinned tip and compare
again before enabling networking, staking, or mining.

Optional indexes have independent replay state. v30.1.1 automatically wipes
and rebuilds prerelease shadowindex schema 4 as schema 5 and prerelease
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

If a legacy `~/.blackmore` directory exists and `.blackcoin` does not, the node
copies `.blackmore` to `.blackcoin`, converts `blackmore.conf` to
`blackcoin.conf`, removes copied lock files, leaves the original `.blackmore`
directory intact, and writes a durable migration marker.

If both `.blackcoin` and `.blackmore` contain data, `blackcoin-qt` prompts the
user to keep `.blackcoin` or import `.blackmore`. Headless `blackcoind` safely
keeps `.blackcoin` by default and preserves `.blackmore` under
`.blackcoin.backup`. Operators can explicitly choose with
`-migratewallet=blackmore`, `-migratewallet=blackcoin`, or
`-migratewallet=none`.

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
