30.1.1 Release Notes
====================

Blackcoin version 30.1.1 is the Quantum Quasar safety and deterministic-state
upgrade release.
Release binaries will be made available from:

  <https://github.com/Blackcoin-Dev/Blackcoin/releases>

This release includes the Blackcoin V4 feature set, including the V4 upgrade
path, quantum-address migration support, Gold Rush staking and PoW claim logic,
wallet/RPC hardening, and the release/package rename from legacy daemon/config
binary names to Blackcoin.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/Blackcoin-Dev/Blackcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://github.com/Blackcoin-Dev/Blackcoin/releases>

Beta 1 canary identity
======================

The v30.1.1 beta 1 packages are unpublished, unsigned canary artifacts. They
are not the signed v30.1.1 production release. A manual exact-SHA build accepts
only the `30.1.1-beta1` package label while the source remains configured as
`30.1.1rc1` with `CLIENT_VERSION_IS_RELEASE=false`.

Every downloadable canary archive name includes both
`Blackcoin-30.1.1-beta1` and the full 40-character source commit. The combined
Actions artifact is named
`unsigned-canary-30.1.1-beta1-<FULL_SOURCE_COMMIT>`. It contains a conspicuous
`UNSIGNED-CANARY` marker, an unsigned JSON manifest, unsigned SHA256 sums, exact
source-commit markers, and the two-builder byte-for-byte reproducibility report.

Confirm that the commit in every filename, source marker, manifest, and
reproducibility report is identical before testing. Then verify the included
`SHA256SUMS-UNSIGNED.txt` file. These checks detect corruption and identity
mismatches; they are not a signature and do not authenticate a production
release. Do not redistribute a beta archive without its marker, manifest,
checksums, and full source commit.

The production workflow remains separate. Only a signed `v30.1.1` tag may enter
that path, and it requires release-candidate zero, final release metadata,
production signing credentials, platform signatures, notarization, signed
checksums, an SPDX SBOM, and provenance attestations.

Known Beta 1 limitations
========================

This is a test-only prerelease, not a production recommendation. The safe
one-click first-launch rebuild assistant tracked in issue #30 is not included
in Beta 1; follow the explicit command-line rebuild procedure below.

A fee-paying Gold Rush PoW claim that leaves the local mempool remains
quarantined because a peer can retain and later confirm the base-valid
transaction. Its input is intentionally not released for spending or staking,
and the wallet's built-in PoW miner pauses while any such claim remains
unresolved. Automatic abandonment would create an unsafe double-spend race.
Use isolated canary wallets and expect this limitation while issues #6 and #26
remain open. A retained pre-QQP3 claim can still confirm late and pay a base fee
without receiving shadow credit.

Height 5,993,200 is a new v30.1.1 QQP3 shadow-ledger rule, not behavior deployed
in v30.1.0. Both versions can continue accepting the same base chain, but their
shadow allocations intentionally diverge from that height. Every miner,
explorer, and indexer that consumes shadow state must upgrade before it.

How to Upgrade
==============

Back up every wallet before upgrading. ML-DSA quantum keys are not derived from
the legacy HD seed, so the backup must be newer than every quantum address it
is expected to recover. Shut down every old daemon or GUI using the datadir and
wait for complete shutdown before replacing the binaries.

An existing v30.1.0 datadir requires one explicit authenticated schema-12
chainstate rebuild before staking or mining under v30.1.1. Blackcoin Qt detects this
condition before loading any wallet and offers two fail-closed choices:

- **Rebuild automatically** shuts down, launches exactly one protected
  `-reindex-chainstate` process, then launches one normal verification process
  after the durable commit. The datadir lock is released before each handoff.
- **Exit and rebuild manually** changes no chainstate and displays a command
  preserving the selected datadir, network, and other startup arguments.

Fresh datadirs and datadirs that already contain authenticated schema 12 do not
show the assistant. Headless operators can run the equivalent one-shot command:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

The rebuilding process exits automatically after it durably reaches
`COMMIT_READY`. Start once normally, without `-reindex-chainstate` or
`-reindex`; that process authenticates the replacement and retires the retained
source before wallets load. The temporary source backup is retired only after
that separate verification succeeds. A verification failure, shutdown, or
interruption preserves the backup and journal for recovery. Never put either reindex option in
`blackcoin.conf` or `settings.json`; v30.1.1 rejects a persistent true value to
prevent a rebuild loop.

`-reindex-chainstate` reads local block files and does not fetch history removed
by pruning. If block files are pruned or incomplete, set `prune=0` and use a
full `-reindex` to redownload missing history and rebuild both the block index
and chainstate. The client checks known block availability before staging and
leaves the existing chainstate intact when a chainstate-only rebuild is not
possible. Preserve wallet files and all available block files.

Pruning is not supported by this beta. Run Quantum Quasar archival and replay
nodes with `prune=0`. Mainnet, testnet, and signet startup reject nonzero
`-prune`; nonzero values remain regtest-only for test coverage. A datadir with
missing historical blocks cannot use `-reindex-chainstate`; preserve every
wallet and restart with `prune=0 -reindex` to redownload full history.

The protected rebuild checks free disk space before creating its journal or
moving a source database. It requires at least the existing chainstate's
logical size plus the normal 50 MiB safety reserve. Failure leaves the existing
chainstate at its original path.

Reconstruction is journaled. The first process retains the original chainstate
backup after committing the rebuilt state and immediately begins orderly
shutdown. The active chain and Coin set are immutable from that commit until
exit, so queued validation cannot stale the recorded commitment. A separate
process reopens and verifies the replacement before retiring the backup. A
full `-reindex` is intentionally refused while this verification restart is
pending.

During both reconstruction and the pending verification restart, staking,
Gold Rush PoW, automatic QQSIGNAL, demurrage attestation, redelegation, and
automatic quantum-key creation are forced off in memory. Existing command-line
and persistent values are restored only after verified cleanup and before
normal wallet loading; the assistant never rewrites those settings.

For this beta, sudden-power-loss durability of directory renames is not yet
claimed on Windows. Keep a cold datadir copy and stable power, and do not
force-stop Windows during either rebuild start. Preserve the full datadir if a
journal or backup-topology diagnostic appears.

After synchronization, record `getblockchaininfo`, `gettxoutsetinfo muhash`, and
`getgoldrushstate`. Stop cleanly, restart without a reindex option, and confirm
that height, best-block hash, UTXO MuHash, Gold Rush totals, and the schema-12
`replay_state` commitment match. At or after the whitelist height, `present`,
`marker_valid`, and `valid_for_tip` must all be true. Repeat one offline
chainstate rebuild comparison before enabling networking, staking, or mining.

Compatibility
==============

Blackcoin is supported and tested on operating systems
using the Linux kernel, macOS 11.0+, and Windows 7 and newer. Blackcoin
should also work on most other Unix-like systems but is not as
frequently tested on them. It is not recommended to use Blackcoin on
unsupported systems.

Notable changes
===============

### Native ARM64 sanitizer setup

The vendored crc32c ARM64 path now uses its `memcpy`-backed unaligned readers,
matching upstream commit `d3d60ac6e0f16780bcfcc825385e1d338801a558`.
This removes an alignment-UBSan stop in LevelDB setup without suppressing the
sanitizer or changing CRC32C results.

### Version line

- v30.1.1 continues the v30 protocol line and makes the authenticated
  auxiliary-state upgrade boundary explicit.

### Protocol transition

- V4 activation, Gold Rush, and quantum transition logic are included in the
  codebase so operators can review the full feature set before network activation.
- Gold Rush staking and PoW claim paths credit the upgraded shadow ledger to
  quantum addresses while preserving legacy-compatible base block rewards during
  the bridge period.
- Already-mined Gold Rush blocks retain v30.1.0 PoW-claim allocation exactly.
  Starting with the first scheduled halving at height 5,993,200, v30.1.1
  introduces the prospective QQP3 canonical rule, which ranks competing valid
  PoW claims independently of transaction order. v30.1.0 does not implement
  QQP3 or its origin-bound accounting. QQP3 binds the origin height and parent
  hash and remains eligible for
  the bounded late-inclusion path. Current-origin losers and eligible late
  claims recover their actual base fee up to 0.01 BLK from the fixed pool. Only
  a current-origin claim can
  win and reset the jackpot; a late-only block leaves the unreimbursed pool
  accumulated. Authenticated shadow replay commits to this boundary under
  schema 12.
- QQP4 exact-input binding is staged behind a separate consensus activation.
  It is disabled on mainnet in this beta channel (`INT_MAX`), and no readiness
  or version bit can activate it. A future activation must publish its own
  height and demonstrate the Q3 late-claim transition in block, mempool, reorg,
  and replay tests.
- Height 5,993,200 is an upgrade deadline for wallets, staking and mining
  nodes, explorers, and indexers that consume shadow state. v30.1.0 and
  v30.1.1 accept the same Gold Rush base blocks but intentionally derive
  different shadow recipients and balances from that boundary. Do not reopen a
  post-boundary v30.1.1 wallet/datadir in v30.1.0; restore the cold pre-upgrade
  copy for rollback. Base-chain compatibility does not imply identical shadow
  state.
- Optional shadowindex schema 10 and coinstatsindex schema 3 automatically
  invalidate and rebuild incompatible prerelease records derived with the
  superseded height-5,950,000 competing-claim boundary or incomplete
  proof-mode, spend-anchor, or claim-accounting classification. Shadowindex
  schema 10 persists at most 64 evaluated claim rows per block plus fixed
  disposition totals, origin/inclusion provenance, and (when QQP4 is
  separately active) exact fee-input provenance, and a deterministic commitment
  to the complete ordered note stream. The
  corresponding explorer response is versioned as
  `blackcoin.shadow.block.v3`; v2's unbounded per-note detail contract is not
  reused with different semantics.
- Ordinary v14/v16 quantum funding, ML-DSA spends, and larger post-quantum
  script elements remain disabled throughout Gold Rush and activate at
  Migration height 6,193,000. Gold Rush credits remain phase-locked until that
  boundary. Witness-v15 EUTXO funding and spending stay disabled in Migration
  and Final because v15 has no quantum ownership authorization.
- Mainnet phase changes are height-authoritative: Gold Rush ends at 6,192,999,
  Migration ends at 6,921,999, and Final Lockout plus permanent-burn demurrage
  begin automatically at 6,922,000. Readiness signalling does not vote these
  transitions into effect.
- Legacy data-directory migration remains copy-first and backup-preserving, but
  never auto-selects wallet data. The GUI presents source, destination,
  preservation, rollback, and exit/manual choices. Headless startup fails
  closed before backup or import until a one-shot command-line choice is given:
  `-migratewallet=blackmore`, `-migratewallet=blackcoin`, or
  `-migratewallet=none`. Remove the option after the successful first run.
- Version-2 transactions omit their legacy transaction-time field from the
  wire format. Mempool admission, block assembly, UTXO provenance, and block
  validation now use the serialized block context consistently so a locally
  constructed transaction cannot be treated differently from the identical
  transaction received from a peer.

### Wallet and RPC

- Optional local wallet automation is fail-closed in v30.1.1 when no prior
  explicit setting exists. Automatic staking restart, PoW restart, fee-paying
  QQSIGNAL submission, fee-paying demurrage attestations, cold-stake
  redelegation, and background non-HD quantum-key creation require explicit
  operator consent. The
  persistent switches are process-wide and apply to every eligible loaded
  wallet. The GUI exposes separate controls and consequence-specific
  confirmations; `getstakinginfo` and `getpowmininginfo` report effective
  automation state for CLI and daemon operators.
- New installs do not autostart staking without consent. To avoid silently
  changing an existing operator policy, an explicitly configured legacy
  `staking=1` remains autostart consent unless `autostartstaking` is set
  separately; an implicit default is never treated as consent. The staking RPC
  reports the effective value and its source.
- The live Gold Rush dashboard and `getpowmininginfo` expose the evaluated chain
  height, next shadow-reward height, exact reward window, runtime state, and
  persistent PoS/PoW/QQSIGNAL consent state.
- Commands whose primary purpose is not key creation no longer silently create
  a non-HD ML-DSA change, withdrawal, migration, sweep, or redelegation key.
  They accept an existing wallet-owned destination where applicable or require
  an explicit default-false `allow_new_quantum_key=true` authorization before
  any key, transaction, or wallet metadata is created. Dry-run, raw-funding,
  and PSBT-only flows never create wallet metadata. RPC failures state the
  exact retry option and successful key-creating calls return a backup warning.
  If an authorized non-HD key is durably written but later transaction
  construction or broadcast fails, the GUI/RPC error identifies the retained
  address and requires an immediate backup; failure is never reported as if no
  key were created.
- The ordinary Qt Send flow now refuses foreign/watch-only quantum change and
  asks a default-No question before authorizing at most one wallet-owned non-HD
  change key. Creation is deferred until coin selection proves positive change
  is required, so an exact no-change transaction creates no key. The dialog
  identifies any created address and explains that the key remains in the
  wallet even if preparation, later confirmation, or broadcast fails.
- Persistent staking and PoW autostart changes apply on the next wallet load or
  process restart and do not change the current runtime workers. Scheduler
  policy for QQSIGNAL, optional attestations, redelegation, and background key
  creation takes effect immediately for eligible loaded wallets; the GUI
  states that timing before consent and in its status summary.
- The GUI runtime staking switch now starts a missing PoS worker just like
  `staking true`. Disabling is non-blocking and idles the worker; re-enabling
  resumes it without creating duplicate threads.
- Mandatory consensus demurrage and permanent burn still begin automatically
  at Final height 6,922,000. The optional wallet attestation switch neither
  activates nor disables that consensus rule.
- `setpowmining` reuses a configured or previously stored wallet-owned payout
  key by default. If none exists, the RPC fails without creating a key unless
  its fourth `allow_new_payout_key` argument is `true` (or the operator already
  supplied `-qqallowautokeycreation=1`). A successful creation reports
  `created_payout_key=true` and requires an immediate wallet backup.
- Quantum address, Gold Rush, PoW miner, cold-staking, and RGB RPC surfaces are
  present for validation. EUTXO decode/verify and persisted-metadata RPCs remain
  available for inspection, while EUTXO creation, funding, and spending RPCs
  intentionally fail in v30.1.1.
- Demurrage removes nominal-minus-effective principal by permanent burn. The
  removed value is not paid to a miner, staker, treasury, shadow pool, or claim
  participant.
- The optional shadow index exposes versioned block, transaction, original
  outpoint, address, and exact-script history. `getshadowsupply` adds an
  explicitly synthetic lifecycle contract for scheduled, pooled, issued,
  locked, spendable, expired-unissued, nominal, effective, and burned value.
- `-zmqpubshadow` publishes versioned, deterministic connected/disconnected
  synthetic-ledger deltas after atomic index updates. The transport has fixed
  record/body bounds, preserves exact reorg order, and requires RPC bootstrap
  and reconciliation because synthetic transactions are not base-block Merkle
  members and are absent from ordinary compact filters.
- Shadow explorer RPCs reject concurrent and equal-tip ABA reorganizations
  instead of returning mixed-branch supply, script, outpoint, or negative
  lookup results.
- Wallet code includes migration and safety checks for the quantum transition
  path.
- Successful wallet broadcasts refresh mempool state before returning, which
  prevents rapid consecutive sends from observing stale spendability state.
- PoW claim creation pauses during reindex, import, or initial sync and
  rechecks the exact tip through commit. A claim that leaves the local mempool
  remains persisted and keeps its input reserved because a peer may still
  confirm it. In Beta 1, any unresolved quarantined claim pauses that wallet's
  built-in miner; distinct inputs do not bypass this wallet-wide safety gate.
  `abandontransaction` intentionally refuses a quarantined Gold Rush PoW claim,
  and its exact fee input remains reserved until an on-chain claim or conflict
  resolves the reservation.
- Wallet backups reject destinations that resolve to the wallet root itself,
  and failed wallet-dump imports clean up incomplete databases without
  terminating the wallet tool.

### Packaging

- The legacy daemon/config names have been replaced by Blackcoin
  names.
- Blackcoin remains the coin and network name.
- The v30.1.1 dependency, inherited-code provenance, P2P capability, and
  active-legacy delta review is recorded in the
  [dependency and security audit](v30.1.1-dependency-security-audit.md).
- Release SBOMs consume the fail-closed dependency security manifest, including
  resolved native/target aliases and every Qt source archive, so reviewed
  dependency sources are emitted with HTTPS provenance and SHA-256 values.
