# Shadow-ledger explorer interface

Blackcoin Core v30.1.1 provides an explorer-facing index for the synthetic
Quantum Quasar ledger. Enable it with:

```text
shadowindex=1
prune=0
```

`-shadowindex` is optional and disabled by default. The legacy
`getgoldrushblock` RPC remains available for compatibility, but new
integrations should use the versioned `getshadow*` schemas. The same index
retains base-chain witness-version inventory history for
`getquantumwitnessinventory`. If the index is disabled or still synchronizing,
the new RPCs return an explicit error rather than silently returning partial
history.

Initial index construction reads historical block files. A fully synchronized
index can continue following new blocks on a pruned node, but a later rebuild
cannot cross deleted block data. Explorer operators should therefore use
`-prune=0`. `-reindex` wipes and deterministically rebuilds the index.

v30.1.1 uses shadowindex schema 6. It automatically discards and rebuilds
prerelease schema-4 data, which classified historical claims under the
superseded height-5,950,000 activation, and schema-5 data, which lacked exact
wrong/unknown QQSPROOF mode dispositions. Coinstatsindex schema 3 performs the
same invalidation for prerelease schema-2 synthetic-payout statistics. This
index-only rebuild does not require a full block or chainstate reindex when all
active-chain block files remain available. A pruned operator without the
required history must disable the affected index or restore the history with a
full `-reindex`.

## Data model

A Gold Rush credit is a deterministic upgraded-ledger transaction anchored to
an active-chain base block. It is not a transaction in the base block's
transaction array and is not committed by that block's transaction Merkle
root. Every response states:

- `synthetic: true`
- `merkle_included: false`
- `base_anchor.height`, `base_anchor.blockhash`, `base_anchor.time`, and
  `base_anchor.claim_index`

The synthetic transaction ID and output index identify the actual quantum UTXO
in upgraded chainstate. The index stores active-chain lookup keys by base block,
synthetic transaction ID/outpoint, destination script, and spent outpoint. A
spend record includes its base block, transaction ID, transaction position, and
input position. Disconnecting a block atomically restores the prior spend and
attestation state; disconnecting the origin block removes the synthetic record.

Every observed `QQSPROOF` note is also indexed from the same canonical,
bounded accounting engine used by chainstate. The record identifies its source
transaction/output, canonical rank, decoded payout destination, actual base fee
when known, credited amount, exact disposition, and linked synthetic payout (if
one exists). The index does not reimplement winner selection or fee arithmetic.
Fee-paying `QQSPROOF` is a PoW-only channel. A payload carrying mode byte `1`
(`pos`) or an unknown mode remains ordinary base-block data but cannot consume,
clear, count, or retarget either shadow pool. `QQSIGNAL` plus a qualified
coinstake is the only PoS credit path.

Amounts are JSON numbers denominated in BLK with eight decimal places. Internal
accounting remains integer atomic units.

## RPCs

### `getshadowblock hash_or_height ( offset count claim_offset claim_count )`

Returns schema `blackcoin.shadow.block.v2`. `count` and `claim_count` are each
limited to 1,000. `offset`/`next_offset` page synthetic payouts;
`claim_offset`/`pow_claim_accounting.next_offset` independently page claim
records.
Continue with `next_offset` until it is `null`. Only active-chain blocks are
accepted, so an explorer detects a reorganization when a previously stored
anchor hash is rejected or no longer matches `getblockhash(height)`.

`pow_claim_accounting` reports winner, reimbursed-loser, and rejection counts,
plus exact winner, reimbursement, and combined credited totals. Stable claim
dispositions are `invalid_location`, `malformed_transaction`, `invalid_proof`,
`input_mismatch`, `invalid_base_fee`, `evaluation_limit`, `winner`, and
`reimbursed_loser`, with `wrong_mode_pos` and `unknown_mode` identifying the
two type-specific non-credit outcomes. A positive winner or reimbursed-loser
credit carries the exact synthetic transaction ID. Zero-fee valid losers
remain visible as `reimbursed_loser` records with zero credit and no synthetic
output.

On mainnet this canonical per-claim classification begins at height 5,993,200.
Earlier Gold Rush blocks intentionally reproduce the v30.1.0 first-valid-claim
allocation and therefore do not expose a retroactively invented canonical
winner or loser reimbursement.

Index construction authenticates the historical pool context while holding the
chain/view lock, then releases that lock before the shared Argon2 evaluator is
called. Missing undo/provenance is an index error, never a new base-block
invalidity.

### `getshadowtransaction synthetic_txid`

Returns schema `blackcoin.shadow.transaction.v1`. It reports current lifecycle
status, ordinary coinbase maturity, the Gold Rush phase lock, earliest spend
height, destination script/address, nominal and effective value, and exact
spend provenance. On mainnet, height-authoritative lifecycle boundaries make
`earliest_spend_height` exact. On a time-only test schedule it is a height lower
bound and `earliest_spend_height_exact` is false because MedianTimePast may
delay the phase transition.

Gold Rush payouts remain locked for the entire reward window. Once the Gold
Rush is over and ordinary maturity is satisfied, the original quantum output
is directly spendable. It does not expire at Final Lockout and does not require
a remigration transaction.

### `getshadowaddress address ( after_height after_txid count )`

Returns schema `blackcoin.shadow.address.v1`. The page is ordered by origin
height and synthetic transaction ID. `after_height` and `after_txid` form one
exclusive cursor and must be supplied together. Continue with the
`next_cursor.height` and `next_cursor.txid` values until `next_cursor` is
`null`. Spent payouts remain in address history with exact base-chain spend
provenance.

### `getshadowsupply ( include_effective max_records )`

Returns schema `blackcoin.shadow.supply.v1`. Issued, spent, and unspent nominal
totals are constant-time cumulative index values. Before demurrage activates,
the unspent effective total is identical to the unspent nominal total. After
activation, an exact current effective total requires evaluating live
attestation state for each unspent payout. That scan is optional and hard
capped by `max_records` (maximum 10,000,000). If the cap is reached, the RPC
sets `effective_amount_exact` to false and returns `null` for effective and
decayed unspent totals; it never labels a partial sum as total supply.

Demurrage decay is destroyed by consensus. It is not paid as a transaction fee
and is not redistributed. `spent_burned_amount` is the cumulative realized
burn. For unspent outputs, `unspent_projected_burn_amount` is the exact amount
that would be burned at the reported next-block valuation point when
`effective_amount_exact` is true.

### `getquantumwitnessinventory ( view offset count max_history_records )`

Returns schema `blackcoin.quantum.witness_inventory.v1`. The RPC scans an
immutable, flushed UTXO snapshot and enumerates every current active-chain,
value-bearing native witness output with witness version greater than 1. It
classifies exact `v14`, `v15`, `v16`, or `unknown` version buckets; exact
pre-Migration versus Migration-or-later origin; the detailed origin phase; and
recognized direct-quantum, EUTXO, quantum-cold-stake, or unknown bridge
handling. Authenticated synthetic Gold Rush payouts are reported separately
and are not misclassified as base-chain witness creations.

The default `utxos` view works without `-shadowindex`. With a synchronized
index, the response also reconciles current UTXOs against all base-block
witness-version >1 creations since genesis, including creations that were
later spent. Use `view="history"` to page those retained records and their exact
spend provenance. The index tip must contain the immutable UTXO snapshot tip;
otherwise the RPC asks the caller to retry instead of mixing branches.

`max_history_records` is a hard scan cap (maximum 10,000,000). When the cap is
reached, `history_scan_complete` and `history_aggregates_exact` are false,
historical aggregate totals and `total_records` are `null`, and the RPC never
labels the scanned prefix as complete history. Inventory buckets include both
an exact decimal-BLK JSON number and an `amount_atomic` decimal string, so
cumulative historical flow remains exact even when it exceeds the live money
supply.

## Reference ingestion and event contract

`feature_goldrush_coinstatsindex.py` is the executable reference ingestion
test. It:

1. records the active tip hash;
2. walks the configured reward-height range;
3. consumes every payout and claim-accounting page through their independent
   `next_offset` fields;
4. stores each synthetic transaction by ID and base anchor;
5. reconciles the enumerated count and nominal amount with `getshadowsupply`;
6. verifies spend metadata;
7. disconnects and reconnects origin and spend blocks; and
8. repeats the checks after restart, `-reindex`, and `-reindex-chainstate`.

This polling contract is the v1 event interface. An explorer treats a new
`(height, blockhash)` pair as `shadow.block.connected` and a changed hash at an
already ingested height as disconnect events down to the common ancestor,
followed by connected events for the replacement branch. Event consumers must
key idempotency by block hash plus synthetic transaction ID. A future ZMQ topic
may transport the same schema, but v30.1.1 does not advertise a notification it
cannot yet deliver reliably.

## Resource and failure boundaries

- Block payout and claim-accounting pages are independently capped at 1,000.
- Effective-supply scans are caller-controlled and hard capped.
- Synthetic payout records begin at the configured Gold Rush reward start
  height; earlier blocks return an empty shadow page. Quantum witness history
  begins at genesis.
- Corrupt or missing index entries produce RPC/index errors. They are never
  converted into base-chain consensus invalidity.
- The index contains active-chain history only. Orphan-branch records are
  removed during rewind and can be reconstructed if that branch later becomes
  active again.
