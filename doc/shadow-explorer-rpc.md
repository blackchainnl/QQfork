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

v30.1.1 uses shadowindex schema 7. Schema 5 invalidated prerelease data built
with the superseded height-5,950,000 claim boundary, schema 6 added proof-mode
classification, and schema 7 adds ordered spend anchors used by the bounded
event transport. Any recognized older shadowindex schema is discarded and
rebuilt automatically. Coinstatsindex schema 3 likewise invalidates its
prerelease schema-2 synthetic-payout statistics. These auxiliary-index rebuilds
do not require a full block or chainstate reindex when all active-chain block
files remain available. A pruned operator without the required history must
disable the affected index or restore the history with a full `-reindex`.

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

Every `getshadow*` response is bound to one active-tip and shadowindex
generation. The RPC captures the active hash, height, and monotonic live-index
revision before reading, then verifies the same values after assembling the
result. This rejects same-height and equal-total ABA reorganizations that would
otherwise look consistent. A concurrent connect, disconnect, or index rewind
returns an explicit `retry the request` error. Negative transaction/outpoint
lookups perform the same final check before returning “not found,” so a reorg
cannot create a silent false negative.

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
`wrong_mode_pos`, `unknown_mode`, `input_mismatch`, `invalid_base_fee`,
`evaluation_limit`, `winner`, and `reimbursed_loser`. A positive winner or
reimbursed-loser credit carries the exact synthetic transaction ID. Zero-fee
valid losers remain visible as `reimbursed_loser` records with zero credit and
no synthetic output.

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

### `getshadowscript scriptPubKey ( after_height after_txid count )`

Returns schema `blackcoin.shadow.script.v1` for one exact hexadecimal output
script. It uses the same stable ordering, exclusive cursor, and retained spend
provenance as `getshadowaddress`, but performs no address or descriptor
normalization. This is the authoritative history query for scripts that do not
have a standard address encoding. The page and every nested payout state
explicitly that the record is synthetic and is not included in a base-block
Merkle tree.

### `getshadowoutpoint synthetic_txid vout`

Returns schema `blackcoin.shadow.outpoint.v1`. An unspent payout is resolved by
the synthetic-transaction index. Once spent, the same original outpoint is
resolved by the persisted spent-outpoint index and retains the exact spending
block, transaction, transaction position, and input position. The
`lookup_index` field reports which index served the result. Disconnecting the
spend atomically changes the lookup back to `synthetic_transaction`; a restart
or index rebuild restores the same result for the active chain. Top-level
`height` and `bestblock` bind the lookup to the exact snapshot that served it.

### `getshadowsupply ( include_effective max_records )`

Returns schema `blackcoin.shadow.supply.v1`. Issued, spent, and unspent nominal
totals are constant-time cumulative index values. The additive lifecycle
contract is versioned separately as
`blackcoin.shadow.supply.lifecycle.v1`, so existing v1 fields retain their
names and meanings.

The `schedule` bucket distinguishes the configured height schedule, the amount
scheduled through the indexed height, value actually accrued into upgraded
state, and the remaining unaccrued schedule. The `pool` bucket reports exact
PoW and PoS amounts that accrued but were not issued. It separately identifies
the amount claimable in the next block and any pool value left unissued after
the reward-height window. That expired pool value is not a synthetic payout.

The `lifecycle` bucket divides every current unspent synthetic payout into
locked or spendable count, nominal amount, and current effective amount. During
Gold Rush the phase lock makes this classification constant-time. After every
payout is mature and before demurrage, the spendable classification is also
constant-time. Maturity boundaries and demurrage require a per-payout scan.
That scan is optional and hard capped by `max_records` (maximum 10,000,000).
When the cap is reached, `classification_exact` is false and lifecycle values
are `null`; a scanned prefix is never labeled as a total.

Before demurrage activates, the unspent effective total remains identical to
the unspent nominal total even if a caller declines a lifecycle scan. After
activation, an exact current effective total requires evaluating live
attestation state for each unspent payout. If that scan is disabled or capped,
`effective_amount_exact` is false and effective and decayed unspent totals are
`null`.

Demurrage decay is destroyed by consensus. It is not paid as a transaction fee
and is not redistributed. `spent_burned_amount` is the cumulative realized
burn. For unspent outputs, `unspent_projected_burn_amount` is the exact amount
that would be burned at the reported next-block valuation point when
`effective_amount_exact` is true. The `burn` bucket presents the same realized
amount with the projected unspent and combined totals.

Gold Rush payout outputs do not expire, so the lifecycle payout-expiry count
and amount are always zero. `getshadowsupply` is intentionally scoped to
synthetic Gold Rush payouts. Its `legacy` bucket therefore returns null legacy
spendable/locked amounts and names `getcirculatingsupply` as the authoritative
whole-UTXO-set source instead of silently mixing two accounting scopes.

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
8. repeats the checks after restart, incompatible-schema rebuild, `-reindex`,
   and `-reindex-chainstate`; and
9. forces an equal-tip ABA reorg while supply, script, and outpoint RPCs are in
   progress and requires an explicit retry instead of a mixed-branch result.

`interface_zmq_shadow.py` is the executable event-ingestion test. Enable the
transport with:

```text
shadowindex=1
prune=0
zmqpubshadow=tcp://127.0.0.1:28334
```

The multipart topic is `shadow`. Its body is deterministic UTF-8 JSON with schema
`blackcoin.shadow.event.v1`; the final frame is the notifier's little-endian
uint32 sequence. One event is emitted only after the index has atomically
applied or rewound the block. `shadow.block.connected` and
`shadow.block.disconnected` use the same block, credit, spend, provenance, and
exact-atomic-amount payload except for `event`, so disconnect is an exact
inverse. Credits are ordered by claim index. Spends are ordered by transaction
index and input index. Reorganizations publish former-branch disconnects from
tip to ancestor, followed by replacement-branch connects from ancestor to tip.

The transport does not replay history during startup, initial index build,
restart, or reindex. A reference consumer therefore:

1. subscribes to `shadow` and records the per-topic sequence;
2. bootstraps active block pages and cumulative supply through RPC;
3. applies only a connected event whose parent equals its stored tip;
4. applies disconnect events as exact inverse deltas;
5. keys idempotency by block hash plus synthetic transaction/outpoint; and
6. replays RPC pages from the last common ancestor after any sequence gap,
   reconnect, restart, parent mismatch, or periodic supply mismatch.

The in-memory ZMQ sequence restarts with the notifier. A publish failure removes
only that failed notifier. An over-limit or inconsistent delta is logged and
omitted. None of those failures rolls back the index, rejects the base block,
or changes consensus validity, so RPC reconciliation is mandatory rather than
an optional error-recovery enhancement.

Base-block BIP158 compact filters and ordinary Electrum transaction histories
cannot discover synthetic payout transaction IDs because those virtual
transactions are not members of the base block or its transaction Merkle tree.
A negative compact-filter match is therefore not evidence that a quantum
address received no Gold Rush credit. The v1 `shadow` topic closes that
discovery false negative without pretending that a synthetic credit has a base
transaction Merkle proof. Electrum servers and light-client backends must ingest
the topic, persist its separate synthetic history, and reconcile it with
`getshadowblock`, `getshadowaddress`, or `getshadowscript`. Base compact filters
remain unchanged and authoritative only for transactions actually serialized
in the base block.

## Resource and failure boundaries

- Block payout and claim-accounting pages are independently capped at 1,000.
- Effective-supply scans are caller-controlled and hard capped.
- Live event construction reads persisted delta anchors and point records; it
  never scans chainstate or the historical index. One event is capped at 4,096
  combined credits/spends and a 16 MiB JSON body. A valid block above that
  transport bound remains indexed and queryable by RPC.
- Synthetic payout records begin at the configured Gold Rush reward start
  height; earlier blocks return an empty shadow page. Quantum witness history
  begins at genesis.
- Corrupt or missing index entries produce RPC/index errors. They are never
  converted into base-chain consensus invalidity.
- Claim classification is all-or-nothing. Allocation, Argon2, or authenticated
  undo/provenance failure returns an index error with no partial page. The
  shared evaluator runs before an atomic index batch is built or written, and
  the index locator is not advanced; restart retries the identical block.
- The index contains active-chain history only. Orphan-branch records are
  removed during rewind and can be reconstructed if that branch later becomes
  active again.
