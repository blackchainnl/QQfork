# Blackcoin Core 30.1.1

Blackcoin Core 30.1.1 is the Quantum Quasar safety and deterministic-state
upgrade for the existing Blackcoin chain. Gold Rush is already active from
height 5,950,000. This release preserves the legacy-compatible base chain
during Gold Rush while hardening wallet operation, authenticated shadow-state
replay, reward accounting, resource controls, and the later Migration and Final
boundaries.

## Verify the release before installing

Use only the immutable `v30.1.1` release. It is explicitly publisher-unsigned:
Blackcoin-Dev has no OpenPGP, Authenticode, Apple Developer ID, or notarization
credentials for this release. The source commit and annotated tag have no
Blackcoin-Dev OpenPGP signature. Windows packages have no Authenticode
signature. macOS applications carry only identity-free ad-hoc launch signatures
and are not notarized, so expect an operating-system warning or block until you
make an explicit local choice.

Read `Blackcoin-30.1.1-UNSIGNED-PRODUCTION.txt` and its machine-readable JSON
manifest. Record the exact source commit, then verify every file in the
unsigned `SHA256SUMS.txt`. Inspect the two-builder reproducibility report, SPDX
SBOM, in-toto provenance, GitHub OIDC build-provenance and SBOM attestations,
exact-source resource evidence, and mainnet quantum-witness inventory. These
controls detect substitution and improve traceability; they are not a
Blackcoin-Dev package signature.

## Mandatory upgrade procedure

Back up every wallet and preserve a cold datadir copy. ML-DSA quantum keys are
not derived from the legacy HD seed, so each backup must be newer than every
quantum address it is expected to recover. Stop every older daemon or GUI and
wait for complete shutdown before replacing binaries.

An existing v30.1.0 datadir requires one authenticated schema-12 chainstate
rebuild before staking or mining under v30.1.1. Blackcoin Qt detects this state
before loading wallets and offers either a protected automatic rebuild or an
exit with platform-correct manual instructions. Headless operators use:

```bash
blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
  -reindex-chainstate -daemonwait
```

The rebuild exits after a durable commit. Start once normally without either
reindex option so a separate process can verify the replacement before the
retained source backup is retired. Do not place a true reindex option in
`blackcoin.conf` or `settings.json`.

`-reindex-chainstate` cannot retrieve pruned history. v30.1.1 supports archival
`prune=0` only on mainnet, testnet, and signet. If required block files are
missing, preserve every wallet and available block file, set `prune=0`, and run
a full `-reindex` to redownload history. Keep a cold datadir copy and stable
power; v30.1.1 does not claim power-loss-atomic directory renames on Windows.

After synchronization, compare `getblockchaininfo`, `gettxoutsetinfo muhash`,
and `getgoldrushstate` across a clean restart. At or after the whitelist height,
the schema-12 `replay_state` must report `present`, `marker_valid`, and
`valid_for_tip` as true before enabling networking, staking, or mining.

## Consensus and shadow-ledger schedule

- Gold Rush: heights 5,950,000 through 6,192,999. Legacy spends remain valid;
  ordinary v14/v16 funding and spending remain disabled and shadow credits are
  locked.
- QQP3 competing-claim rule: height 5,993,200 onward. v30.1.1 and v30.1.0 can
  accept the same base blocks but intentionally derive different shadow
  allocations from this boundary.
- Migration: heights 6,193,000 through 6,921,999. Authenticated v14/v16 funding
  and spending activate and legacy holders can migrate.
- Final Lockout: height 6,922,000 onward. Legacy spends are rejected and
  permanent-burn demurrage activates automatically without a vote.

QQP4 exact-input proof binding remains disabled on mainnet at `INT_MAX`. No
readiness or version bit can activate it. Witness v15 remains frozen: v30.1.1
provides no funding or spending workflow, and consensus rejects v15 outputs
and spends from Migration onward.

Gold Rush PoS allocation is one global accumulated pool split once across all
eligible active targets. Materialized payouts must sum exactly to that pool,
including when multiple targets select the same payout script; dedicated
apply-and-undo coverage prevents per-signaler multiplication or value loss.

## Gold Rush claim safety

The wallet permits one unresolved wallet-authored fee-paying `QQSPROOF` at a
time. If a claim leaves the local mempool, the wallet quarantines it, reserves
its exact input, refuses generic abandonment, and pauses its built-in miner
because another peer may still confirm the original. `getpowmininginfo`
reports unresolved, live, and quarantined claim counts.

Advanced operators can preview a guided conflict with
`createshadowpowclaimresolution <claim_txid>`. The default dry run does not
sign. Signing requires a normally unlocked wallet, `dry_run=false`, and
`acknowledge_fee_and_conflict_risk=true`; the RPC still never broadcasts.
Review the returned fee, output, and warning before separately calling
`sendrawtransaction`. A confirmed resolution pays its base-chain fee without
shadow reimbursement. Peers retaining the original may reject the conflict,
confirmation is not guaranteed, and the input remains reserved until one side
confirms. After explicit broadcast and wallet recognition, ordinary wallet
rebroadcast may continue across restart. The Qt dashboard presents the same
warning and does not offer a
one-click conflict broadcast.

## Wallet, GUI, and operator safety

- Automatic staking restart, PoW restart, QQSIGNAL, demurrage attestations,
  redelegation, and background non-HD key creation require their own explicit
  operator consent. Runtime and persistent controls are reported separately.
- Commands that may create non-HD quantum change or payout keys fail closed or
  require an explicit default-false authorization. Back up immediately after
  any successful quantum key creation.
- Raw unstored quantum-key generation was removed. The global
  `createquantumkey` RPC is an unconditional fail-closed deprecated stub. Use
  wallet-scoped `getnewquantumaddress` so the key is stored and covered by the
  wallet's backup state. `-allowunsafequantumkeyrpc=1` is a process-wide expert
  opt-in only for wallet-scoped `dumpquantumkey`; export uses the selected
  normally unlocked wallet and rejects staking-only unlock. The flag does not
  disable networking, restrict RPC access, or make the process an offline key
  environment. Online operators should leave it disabled.
- The Qt Staking & Mining page moves expensive detail work off the GUI thread,
  coalesces refreshes, and exposes the same staking/mining state and consequence
  warnings available through RPC.
- Theme, palette, contrast, and runtime theme-transition fixes make light and
  dark modes readable across the primary wallet surfaces.

## Resource and publication gates

Optional full circulating-supply scans are single-flight, bounded,
progress-reporting, and cooperatively cancellable. Inspect
`getshadowresourceinfo`; use `abortcirculatingsupplyscan` to request a stop.
Explicit one-call consent outside the reviewed soft envelope cannot bypass the
critical integrity floor, storage reserve, absolute record/seek limits,
snapshot checks, overflow protection, shutdown, or cancellation. A successful
qualification is fixed-height and host-scoped and reports
`universal_consensus_bound=false`.

The publisher-unsigned release bundle must contain fresh exact-source
production resource evidence and an exact-source
connected-tip mainnet witness inventory. The
witness artifact binds the release daemon and CLI, UTXO MuHash, complete
value-bearing witness-v2-through-v16 inventory, and live shadow reconciliation,
with either no bridge-review outpoints or an approved disposition for every
outpoint. Missing, stale, tampered, scope-mismatched, or incomplete evidence is
not release authorization.

See [TRANSITION_GUIDE.md](../../TRANSITION_GUIDE.md), the
[detailed release notes](../release-notes.md), and the
[production gate](../v30.1.1-release-gate.md) for the full operator and release
contracts.
