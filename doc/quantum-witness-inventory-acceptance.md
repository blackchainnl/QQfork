# Quantum witness inventory acceptance

Issue #14 cannot be closed from a count copied from a live RPC response. The
acceptance artifact must identify the exact candidate source and binaries, the
mainnet tip, and the complete UTXO snapshot on which the classification was
performed. It must also show either that no bridge-review outpoints exist or
record an approved disposition for every such outpoint.

The acceptance scope is every current, value-bearing native witness output with
witness version greater than 1. Exact v14 quantum-cold-stake and exact v16
direct-quantum programs are native formats only when their authenticated origin
is Migration or later. A pre-Migration exact v14/v16 outpoint was accepted
under the legacy unknown-witness rules and therefore needs an explicit bridge
decision. The review set is:

- every other witness version greater than 1;
- every v15 output, including the reserved but disabled EUTXO shape;
- every malformed v14 program; and
- every malformed v16 program; and
- every exact v14/v16 program created before Migration.

The inventory does not infer ownership or spendability from a script shape.
Each nonempty review-set disposition is therefore a release decision supported
by its own rationale and approval reference.

## Exact-beta mainnet procedure

Use an unmodified checkout at the exact proposed beta commit and binaries built
from that commit. Both binaries must emit the exact full 40-character source
commit on a separate source-identity line and must report a clean source tree;
the display version or release tag is not accepted as source identity. Prepare
a cold or snapshotted datadir from a fully synchronized, unpruned mainnet node;
no GUI, daemon, or other process may have that datadir open. The verifier starts
the supplied exact `blackcoind` itself on Linux, without daemonizing, on a
private random loopback RPC port. The daemon and CLI share a freshly generated
cookie in a verifier-owned mode-0700 temporary directory; user-supplied RPC
credentials cannot override it. The verifier binds the live PID's
`/proc/<pid>/exe` image hash to the prelaunch binary hash, then disables wallets,
staking, PoW mining, P2P, and listening while the immutable scans run. The
RPC-reported full build must match the exact source and binary. Merely pointing
an exact CLI at another resident node is not release evidence.

`-coinstatsindex=1` is recommended because the tool independently repeats the
MuHash query. The UTXO inventory itself does not require `-shadowindex`.

Write the artifact outside the source checkout so the checkout remains clean:

```bash
SOURCE_ROOT="$PWD"
SOURCE_SHA="$(git rev-parse HEAD)"
CLI="$PWD/src/blackcoin-cli"
DAEMON="$PWD/src/blackcoind"
DATADIR="/cold/snapshot/of/.blackcoin"

python3 contrib/devtools/quantum_witness_inventory_audit.py \
  --source-root "$SOURCE_ROOT" \
  --source-sha "$SOURCE_SHA" \
  --blackcoin-cli "$CLI" \
  --blackcoind "$DAEMON" \
  --datadir "$DATADIR" \
  --daemon-arg=-dbcache=4096 \
  --page-size=1000 \
  --max-records=100000 \
  --output="/tmp/blackcoin-witness-inventory-$SOURCE_SHA.json"
```

The command succeeds only on the immutable Blackcoin mainnet genesis, the exact
height-authoritative production schedule, and the currently active Gold Rush.
The cold snapshot must report fully synchronized, unpruned state with no header
gap. Every page must report the same height, tip hash, MuHash3072 commitment,
UTXO count, aggregates, and complete pagination. A separate
`gettxoutsetinfo muhash` result must match that same snapshot. A separate
`getcirculatingsupply` scan must also match the tip and UTXO count and must
reconcile every witness-scan synthetic exclusion with the authenticated issued,
spent, unspent, immature, and phase-locked shadow inventory. Any mismatch is a
failed run, not evidence that may be repaired by hand.

The successful artifact records:

- the full 40-character source commit and clean-checkout state;
- SHA-256 and version output for `blackcoind` and `blackcoin-cli`;
- the verifier-owned daemon PID, prelaunch executable SHA-256, Linux
  `/proc/<pid>/exe` image SHA-256, private authenticated RPC endpoint,
  RPC-reported source build, and disabled wallet/mining/network state;
- chain, genesis hash, protocol version, and subversion;
- current height, block hash, block time, UTXO MuHash, and UTXO count;
- the reported height-authoritative lifecycle schedule;
- every paged witness outpoint and aggregate classification; and
- the same-tip live synthetic shadow-ledger reconciliation; and
- an explicit zero review result or a disposition for every review outpoint.

The `evidence_payload_sha256` field hashes the canonical JSON object before that
field is inserted. Preserve the emitted JSON byte-for-byte as a release-gate
artifact.

## Nonzero review set

If any review-set outpoint exists, the command fails until `--dispositions`
names a JSON document bound to the exact source, network, tip, and UTXO MuHash.
Obtain the outpoint list by paging `getquantumwitnessinventory "utxos"` at that
same snapshot. The document has this form:

```json
{
  "schema": "blackcoin.quantum.witness_bridge_dispositions.v1",
  "source_commit": "FULL_40_CHARACTER_BETA_COMMIT",
  "network": "main",
  "snapshot": {
    "height": 0,
    "bestblock": "64_CHARACTER_BLOCK_HASH",
    "utxo_muhash": "64_CHARACTER_MUHASH"
  },
  "outpoints": {
    "TXID:VOUT": {
      "action": "APPROVED_EXPLICIT_ACTION",
      "rationale": "Record-supported reason for this exact outpoint.",
      "approval_ref": "PUBLIC_REVIEW_OR_DECISION_REFERENCE"
    }
  }
}
```

The outpoint keys must equal the review set exactly. Missing entries, extra
entries, placeholder text, another network, another source commit, or another
snapshot all fail. Rerun the full acceptance command with
`--dispositions=/path/to/dispositions.json`. If the tip changes, regenerate and
reapprove the dispositions against the new snapshot; do not edit only the tip
fields.

## Boundary evidence

`feature_quantum_activation_boundary.py` is the deterministic executable gate.
It verifies the final Gold Rush block and first Migration block for exact and
malformed v14/v15/v16 and other unknown witness outputs. v30.1.1 wallet,
mempool, relay, normal template, GUI, and RPC funding paths exclude those
ordinary outputs through the inclusive Gold Rush boundary. Base consensus must
still accept a legacy-valid direct block through that boundary; rejecting it
before G+1 would create the premature fork this release is intended to avoid.
The test therefore also proves that any such custom-block outpoint appears in
the immutable inventory and requires the appropriate bridge disposition.

The test pages and independently reconciles the UTXO inventory, then verifies
the final Migration block and first Final Lockout block. The live mainnet
artifact remains a separate exact-SHA release requirement because regtest
fixtures cannot prove the current mainnet UTXO set or the live shadow ledger.
During the ongoing 243,000-block Gold Rush, that artifact is partial-epoch
evidence only. It cannot be represented as evidence that the future epoch has
completed.
