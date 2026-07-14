# Blackcoin Transition Guide

## Legacy Blackcoin Operators

Blackcoin is the Protocol V4 upgrade path for the legacy Blackcoin
network. v30.1.1 retains the existing chain history and introduces an explicit
upgrade boundary for v30.1.0 chainstate data.

## Current Schedule in Code

- The whitelist snapshot is fixed at height 5,945,000.
- Legacy rules remain active through height 5,949,999.
- Gold Rush is height 5,950,000 through 6,192,999, inclusive.
- Quantum witness spends activate at Migration height 6,193,000.
- Migration is height 6,193,000 through 6,921,999, inclusive.
- Final lockout and automatic demurrage begin at height 6,922,000.

These mainnet heights are authoritative. The time values retained in the code
do not move a mainnet lifecycle boundary.

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
4. Run one explicit schema-11 rebuild before enabling staking or mining:

   ```bash
   blackcoind -datadir=/path/to/data -networkactive=0 -staking=0 \
     -reindex-chainstate -daemonwait
   ```

5. Wait for synchronization, then record `getblockchaininfo`,
   `gettxoutsetinfo muhash`, and `getgoldrushstate`.
6. At or after the whitelist height, require `getgoldrushstate.replay_state`
   schema 11 with `present`, `marker_valid`, and `valid_for_tip` all true.
   Stop cleanly, restart without a reindex option, and confirm the height,
   best-block hash, UTXO MuHash, Gold Rush totals, and replay commitment match.
   Repeat one offline `-reindex-chainstate` comparison for release-candidate
   qualification before enabling networking, staking, or mining.
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

## Validation Status

The V4 Gold Rush, quantum migration, cold-staking, autonomous redelegation,
tiered staking, stake-reward split, and permanent-burn demurrage paths are
implemented in this branch. Demurrage starts automatically at Final height
6,922,000; it is not activated by a vote, and burned principal is not paid to
miners, stakers, a treasury, or a reward pool. A source checkout, release
candidate, or alpha artifact is not a final mainnet release. Operators should
use only published binaries that have passed the v30.1.1 release gate, and
should retain verified wallet backups throughout the transition.
