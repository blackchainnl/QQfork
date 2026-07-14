# Quantum witness inventory acceptance

Issue #14 cannot be closed from a count copied from a live RPC response. The
acceptance artifact must identify the exact candidate source and binaries, the
mainnet tip, and the complete UTXO snapshot on which the classification was
performed. It must also show either that no bridge-review outpoints exist or
record an approved disposition for every such outpoint.

The acceptance scope is every current, value-bearing native witness output with
witness version greater than 1. Exact v14 quantum-cold-stake and exact v16
direct-quantum programs are native formats. The review set is:

- every other witness version greater than 1;
- every v15 output, including the reserved but disabled EUTXO shape;
- every malformed v14 program; and
- every malformed v16 program.

The inventory does not infer ownership or spendability from a script shape.
Each nonempty review-set disposition is therefore a release decision supported
by its own rationale and approval reference.

## Exact-beta mainnet procedure

Use an unmodified checkout at the exact proposed beta commit and binaries built
from that commit. The build version emitted by both binaries must contain the
first 12 characters of the exact commit and must not contain `-dirty`. Run the
tool against a fully synchronized, unpruned mainnet node. `-coinstatsindex=1` is
recommended because the tool independently repeats the MuHash query. The UTXO
inventory itself does not require `-shadowindex`.

Write the artifact outside the source checkout so the checkout remains clean:

```bash
SOURCE_ROOT="$PWD"
SOURCE_SHA="$(git rev-parse HEAD)"
CLI="$PWD/src/blackcoin-cli"
DAEMON="$PWD/src/blackcoind"
DATADIR="$HOME/.blackcoin"

python3 contrib/devtools/quantum_witness_inventory_audit.py \
  --source-root "$SOURCE_ROOT" \
  --source-sha "$SOURCE_SHA" \
  --blackcoin-cli "$CLI" \
  --blackcoind "$DAEMON" \
  --cli-arg="-datadir=$DATADIR" \
  --page-size=1000 \
  --max-records=100000 \
  --output="/tmp/blackcoin-witness-inventory-$SOURCE_SHA.json"
```

The command succeeds only when all pages report the same height, tip hash,
MuHash3072 commitment, UTXO count, aggregates, and complete pagination. It then
requires a separate `gettxoutsetinfo muhash` result to match that same snapshot
and requires the active tip to remain unchanged through the final check. A new
block or reorganization during any of those calls is a failed run, not evidence
that may be repaired by hand. Retry the complete command.

The successful artifact records:

- the full 40-character source commit and clean-checkout state;
- SHA-256 and version output for `blackcoind` and `blackcoin-cli`;
- chain, genesis hash, protocol version, and subversion;
- current height, block hash, block time, UTXO MuHash, and UTXO count;
- the reported height-authoritative lifecycle schedule;
- every paged witness outpoint and aggregate classification; and
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
malformed v14/v15/v16 and other unknown witness outputs. It checks both mempool
policy and direct-block consensus, pages and independently reconciles the UTXO
inventory, then verifies the final Migration block and first Final Lockout
block. The live mainnet artifact remains a separate exact-SHA release
requirement because regtest fixtures cannot prove that the current mainnet UTXO
set has a zero review set.
