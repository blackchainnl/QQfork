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

Alpha 1 canary identity
=======================

The v30.1.1 alpha 1 packages are unpublished, unsigned canary artifacts. They
are not the signed v30.1.1 production release. A manual exact-SHA build accepts
only the `30.1.1-alpha1` package label while the source remains configured as
`30.1.1rc1` with `CLIENT_VERSION_IS_RELEASE=false`.

Every downloadable canary archive name includes both
`Blackcoin-30.1.1-alpha1` and the full 40-character source commit. The combined
Actions artifact is named
`unsigned-canary-30.1.1-alpha1-<FULL_SOURCE_COMMIT>`. It contains a conspicuous
`UNSIGNED-CANARY` marker, an unsigned JSON manifest, unsigned SHA256 sums, exact
source-commit markers, and the two-builder byte-for-byte reproducibility report.

Confirm that the commit in every filename, source marker, manifest, and
reproducibility report is identical before testing. Then verify the included
`SHA256SUMS-UNSIGNED.txt` file. These checks detect corruption and identity
mismatches; they are not a signature and do not authenticate a production
release. Do not redistribute an alpha archive without its marker, manifest,
checksums, and full source commit.

The production workflow remains separate. Only a signed `v30.1.1` tag may enter
that path, and it requires release-candidate zero, final release metadata,
production signing credentials, platform signatures, notarization, signed
checksums, an SPDX SBOM, and provenance attestations.

How to Upgrade
==============

Back up every wallet before upgrading. ML-DSA quantum keys are not derived from
the legacy HD seed, so the backup must be newer than every quantum address it
is expected to recover. Shut down every old daemon or GUI using the datadir and
wait for complete shutdown before replacing the binaries.

An existing v30.1.0 datadir requires one explicit authenticated schema-11
chainstate rebuild before staking or mining under v30.1.1:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

`-reindex-chainstate` reads local block files and does not fetch history removed
by pruning. If block files are pruned or incomplete, set `prune=0` and use a
full `-reindex` to redownload missing history and rebuild both the block index
and chainstate. The client checks known block availability before staging and
leaves the existing chainstate intact when a chainstate-only rebuild is not
possible. Preserve wallet files and all available block files.

Reconstruction is journaled. The first process retains the original chainstate
backup after committing the rebuilt state. Stop it cleanly and start once
without a reindex option; that separate process reopens and verifies the
replacement before retiring the backup. A full `-reindex` is intentionally
refused while this verification restart is pending.

For this alpha, sudden-power-loss durability of directory renames is not yet
claimed on Windows. Keep a cold datadir copy and stable power, and do not
force-stop Windows during either rebuild start. Preserve the full datadir if a
journal or backup-topology diagnostic appears.

After synchronization, record `getblockchaininfo`, `gettxoutsetinfo muhash`, and
`getgoldrushstate`. Stop cleanly, restart without a reindex option, and confirm
that height, best-block hash, UTXO MuHash, Gold Rush totals, and the schema-11
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
  From the first scheduled halving at height 5,993,200, competing valid PoW
  claims are ranked independently of transaction order. Evaluated valid losers
  recover their actual base fee up to 0.01 BLK from the fixed pool, the canonical
  winner receives the remainder, and authenticated shadow replay commits to the
  activation boundary under schema 11.
- Optional shadowindex schema 6 and coinstatsindex schema 3 automatically
  invalidate and rebuild prerelease index records derived with the superseded
  height-5,950,000 competing-claim boundary or incomplete proof-mode
  classification.
- ML-DSA quantum spends, EUTXO spends, larger post-quantum script elements, and
  expanded block limits are deferred until after the Gold Rush reward-height
  window, during the migration/final-lockout phases.
- Legacy data-directory migration remains in place so existing Blackcoin users
  can move to Blackcoin without manually relocating wallet or chain data.

### Wallet and RPC

- Quantum address, Gold Rush, PoW miner, cold-staking, RGB, and EUTXO RPC
  surfaces are present for testnet validation.
- The optional shadow index exposes versioned block, transaction, original
  outpoint, address, and exact-script history. `getshadowsupply` adds an
  explicitly synthetic lifecycle contract for scheduled, pooled, issued,
  locked, spendable, expired-unissued, nominal, effective, and burned value.
- Wallet code includes migration and safety checks for the quantum transition
  path.

### Packaging

- The legacy daemon/config names have been replaced by Blackcoin
  names.
- Blackcoin remains the coin and network name.
- The v30.1.1 dependency, inherited-code provenance, P2P capability, and
  active-legacy delta review is recorded in the
  [dependency and security audit](v30.1.1-dependency-security-audit.md).
