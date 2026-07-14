# Mixed-version release gate

`sources.json` is the allowlist for historical binaries used by
`feature_goldrush_mixed_version.py`. The gate does not accept a binary selected
by filename, a moving download URL, or a locally installed daemon. It verifies
the remote Git object and records executable hashes in `provenance.json`.
Where an upstream x86-64 Linux release exists, the archive and both executable
members are independently SHA-256 pinned. Otherwise the gate fetches the exact
commit, confirms the version declared by `configure.ac`, and builds with that
source tree's pinned dependencies.

The v26.2.0 source is a lightweight tag and its published Linux release asset
is digest-pinned. The legacy release uses `blackmored` and `blackmore-cli`; the
installer verifies those exact members and exposes compatibility filenames to
the functional framework without modifying their bytes. The v30.1.0 source is an annotated tag
whose tag object and peeled commit are both pinned. CoinBlack did not publish a
v28.4.0 tag or GitHub release; the designated source is therefore the pinned
28.x branch commit that declares itself v28.4.0. Any movement of that branch
fails the provenance check until the manifest is deliberately reviewed and
updated. A proper immutable v28.4.0 tag would remove this provenance gap.

The functional test starts all four real daemons, checks their RPC versions,
relays blocks produced by every historical generation, then proves reorgs in
both directions and persistence across restart. The normative v26.2.0 and
candidate pair also produce signed proof-of-stake blocks carrying an ordinary
fee-paying transaction. Each unmodified wallet block relays byte-for-byte to
the opposite implementation. Both then accept the same re-signed block at the
deployed Gold Rush two-fee ceiling, reject the same one-satoshi-over block with
`bad-cs-amount`, reload the common tip, and continue ordinary synchronization.
It complements rather than replaces the synthetic legacy-policy fixtures.

The fee-ceiling fixture funds its staking inputs with serialized version-1
transactions so every implementation records the same input timestamp. The
known version-2 transaction clock seam is intentionally separate: the existing
clock-regression fixture in this test covers the historical v26/v28 behavior
and the deployed v30.1.0/candidate agreement.

To build and run locally on x86-64 Linux:

```sh
python3 ci/mixed-version/build_previous_releases.py \
  --output "$PWD/.ci/previous-releases" \
  --build-root "${TMPDIR:-/tmp}/blackcoin-previous-builds" \
  --host x86_64-pc-linux-gnu

PREVIOUS_RELEASES_DIR="$PWD/.ci/previous-releases" \
  python3 test/functional/test_runner.py --jobs=1 \
  feature_goldrush_mixed_version.py --previous-releases
```
