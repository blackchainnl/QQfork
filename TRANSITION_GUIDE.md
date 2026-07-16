# Blackcoin Transition Guide

## Legacy Blackcoin Operators

Blackcoin is the Protocol V4 upgrade path for the legacy Blackcoin
network. v30.1.1 retains the existing chain history and introduces an explicit
upgrade boundary for v30.1.0 chainstate data.

## Current Schedule in Code

- The whitelist snapshot is fixed at height 5,945,000.
- Legacy rules remain active through height 5,949,999.
- Gold Rush is height 5,950,000 through 6,192,999, inclusive.
- The QQP3 canonical competing-claim rule (rank v1) begins at height
  5,993,200.
- QQP4 exact-input proofs have a separate consensus activation and are
  disabled on mainnet in v30.1.1.
- Quantum witness spends activate at Migration height 6,193,000.
- Migration is height 6,193,000 through 6,921,999, inclusive.
- Final lockout and automatic demurrage begin at height 6,922,000.

These mainnet heights are authoritative. The time values retained in the code
do not move a mainnet lifecycle boundary.

QQP4 is not selected by a readiness bit, version bit, or other signalling
state. A future QQP4 release must declare its consensus height separately from
the 5,993,200 QQP3 boundary and demonstrate the treatment of Q3 claims that
are still inside their late-inclusion window at that transition.

Use RPC to inspect the active schedule and wallet migration status:

```bash
blackcoin-cli getblockchaininfo
blackcoin-cli -rpcwallet=<wallet> getmigrationstatus
```

## Upgrade Test Flow

1. Back up every wallet. Quantum keys are not derived from the legacy HD seed,
   so the backup must be newer than every quantum address it is expected to
   recover.
2. Stop every v30.1.0 daemon or GUI using the datadir and wait for complete
   shutdown.
3. Install v30.1.1.
4. Run one explicit schema-12 rebuild before enabling staking or mining:

   ```bash
   blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
     -reindex-chainstate -daemonwait
   ```

5. Wait for synchronization, then record `getblockchaininfo`,
   `gettxoutsetinfo muhash`, and `getgoldrushstate`.
6. At or after the whitelist height, require `getgoldrushstate.replay_state`
   schema 12 with `present`, `marker_valid`, and `valid_for_tip` all true.
   Stop cleanly, restart without a reindex option, and confirm the height,
   best-block hash, UTXO MuHash, Gold Rush totals, and replay commitment match.
   Repeat one offline `-reindex-chainstate` comparison before enabling
   networking, staking, or mining.
7. Use `getmigrationstatus` to inspect remaining legacy funds.
8. Use `migratetoquantum` during the migration window when ready to move legacy
   wallet coins into ML-DSA-backed quantum migration outputs.

During Gold Rush, address generation and dry-run planning are available, but
ordinary v14/v16 funding and spending are disabled. Do not attempt to migrate
value until Migration begins at height 6,193,000.

The v30.1.1 rebuild is mandatory because the release changes authenticated
auxiliary-state schema, replays Gold Rush state from height 5,950,000, activates
canonical competing-claim accounting at height 5,993,200, and normalizes
historical UTXO timestamps. Normal startup refuses
an obsolete or unauthenticated chainstate instead of attempting an in-place
repair.

`-reindex-chainstate` reads local block files and cannot recover blocks already
deleted by pruning. It requires complete active-chain block data for the replay.
If the datadir is pruned or block files are incomplete, set `prune=0` and use a
full `-reindex` to redownload missing history and rebuild both the block index
and chainstate. v30.1.1 performs this availability check before wiping and
leaves the existing chainstate intact when known-pruned history is missing.
Preserve wallets and all available block files.

## Gold Rush

Gold Rush rewards are tracked in the upgraded Shadow Network ledger while the
base Blackcoin ledger remains legacy-compatible. Upgraded wallets publish
fee-paying, legacy-valid OP_RETURN transactions for Gold Rush participation;
legacy nodes can still relay and mine the underlying transactions, while
upgraded nodes interpret the `QQSIGNAL` and `QQSPROOF` payloads as shadow-ledger
credits.

Gold Rush reward credits are not spendable on the base legacy rules. Upgraded
nodes keep those credits in authenticated synthetic state and defer ordinary
v14/v16 funding and ML-DSA spending until the post-Gold-Rush Migration phase.
This keeps the Gold Rush bridge legacy-compatible; the hard-fork spend phase
begins when Migration starts. Witness-v15 EUTXO funding and spending do not
activate in Migration or Final: v30.1.1 freezes v15 because its commitment does
not authenticate a quantum owner.

Whitelisted recent PoS solvers signal with `QQSIGNAL` to link a qualifying
legacy address to a quantum migration payout address. Argon2id PoW claim
transactions use the `QQSPROOF` OP_RETURN payload, are not whitelist-gated, and
credit the PoW-side jackpot only to a quantum migration address. Neither path
requires an extra coinstake payout output, and Gold Rush credits do not increase
the legacy block subsidy during the compatibility bridge.

Small-balance PoW miners use `getshadowpowwork` to inspect the current Argon2id
target and `sendshadowpowclaim` from a wallet to grind and broadcast a claim.
The built-in miner can also be controlled with `setpowmining` and inspected
with `getpowmininginfo`. In the Qt GUI, use the Staking/Mining page to configure
the built-in Gold Rush PoW miner and copy its quantum payout address.

Only one unresolved wallet-authored `QQSPROOF` may be active per wallet. If a
claim leaves the local mempool, the wallet quarantines it, keeps its exact fee
input reserved, and pauses the built-in miner because a peer may still confirm
the original transaction. Do not use generic `abandontransaction` or attempt
to reuse the input. Inspect `getpowmininginfo` for the unresolved, live, and
quarantined counts.

An advanced operator may preview a guided on-chain conflict from the CLI or Qt
debug console:

```bash
blackcoin-cli -rpcwallet=<wallet> \
  createshadowpowclaimresolution <claim_txid>
```

The default is a dry run. To obtain a signed but unbroadcast transaction, the
wallet must be normally unlocked (not staking-only) and the operator must pass
`dry_run=false acknowledge_fee_and_conflict_risk=true`. Review the returned
fee, output, and warning before separately using `sendrawtransaction`. The
resolution spends the claim's exact input back to the same wallet script, but
peers retaining the original may reject it and confirmation is not guaranteed.
If the resolution confirms, its base fee is not reimbursed by the shadow
ledger. The wallet keeps the input reserved until one side confirms. The GUI
does not provide a one-click broadcast button for this irreversible choice.
After an explicit broadcast and wallet recognition, ordinary wallet rebroadcast
may continue across restart; this is a consequence of the prior broadcast, not
a new automatic authorization.

## Optional resource diagnostics

`getshadowresourceinfo` reports whether the optional full-supply diagnostic is
inside its fixed-height, host-scoped operating envelope. The scan is
single-flight and progress-reporting; `abortcirculatingsupplyscan` requests a
cooperative stop. Explicit one-call consent outside the reviewed soft envelope
does not override absolute record/seek limits, the integrity floor, the
storage reserve, snapshot consistency, overflow checks, shutdown, or
cancellation. These diagnostics do not change base validation, P2P, staking,
mining, shadow accounting, wallet state, or consensus.

## Validation Status

The V4 Gold Rush, quantum migration, cold-staking, autonomous redelegation,
tiered staking, stake-reward split, and permanent-burn demurrage paths are
implemented in this branch. Demurrage starts automatically at Final height
6,922,000; it is not activated by a vote, and burned principal is not paid to
miners, stakers, a treasury, or a reward pool. A source checkout or locally
compiled artifact is not the reviewed published release. Blackcoin-Dev has no
OpenPGP, Authenticode, Apple Developer ID, or notarization credentials for
v30.1.1. Operators should use only published binaries whose exact source
commit, annotated tag, `UNSIGNED-PRODUCTION` notices, unsigned checksums,
two-builder reproducibility report, SBOM, provenance, GitHub attestations, and
protected mainnet evidence verify, and should retain verified wallet backups
throughout the transition.
