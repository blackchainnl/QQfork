# Blackcoin Core 30.1.1 Beta 2 replacement candidate

Blackcoin Core 30.1.1 Beta 2 is the proposed replacement for the withdrawn
Beta 1 canary. It is an unsigned, unnotarized test candidate, not a production
release or a fleet-rollout recommendation. Its source must remain configured
as `30.1.1rc2` with `CLIENT_VERSION_IS_RELEASE=false`.

## Beta 1 is withdrawn

Do not install, deploy, or reuse v30.1.1 Beta 1. Its exact source commit is
`b328d2263038cdddef46b9f427827aac9e83b513`. Two independent authenticated
schema-12 rebuilds stopped while connecting accepted historical mainnet block
4,272,172,
`41c4dbbe2a1238a4d1d901ec451b99dcbdd018746f6229b533a4f102b5840968`.
Beta 1 applied the later 500-block coinbase/coinstake maturity to a historical
coinstake spend at depth 182 and rejected it with
`bad-txns-premature-spend-of-coinbase`.

The affected Linux artifact SHA-256 is
`ae35e8bd3c7c549bfcc41e1dbd8a45733af80cf5ee8517e9db64c30ab6b59189`.
The immutable Beta 1 tag and assets remain available only as provenance. They
must not be relabeled, overwritten, or attached to the replacement release.

## Replacement rule and evidence

The replacement must restore the accepted pre-Protocol-V3.1 maturity behavior
through an explicit historical rule while retaining the independent v2
mempool-time repair. A one-transaction exception is not an acceptable release
correction.

The exact Beta 2 artifact is blocked until all of these conditions are met:

- deterministic coverage accepts the historical depth-182 coinstake spend and
  covers coinbase and coinstake behavior on both sides of the existing
  Protocol-V3.1 time predicate;
- the v2 mempool-time-unavailable regression remains green;
- the complete exact-source beta gate passes, including extended functional
  and soak coverage, native-platform vectors, sanitizers, the pinned fuzz
  corpus, unit/lint, and real mixed-version interoperability;
- two independent offline rebuilds from the preserved schema-11 mainnet
  snapshot exit zero and durably commit authenticated schema 12;
- both rebuilds agree on height, best block, UTXO MuHash, Gold Rush totals,
  replay-state commitment, and index state; and
- a normal restart without a reindex flag reports schema 12 with replay state
  `present`, `marker_valid`, and `valid_for_tip` all true.

No Beta 2 source commit or artifact hash is asserted in this source-tracked
note. The immutable `v30.1.1-beta2` prerelease page, full-SHA filenames,
unsigned canary manifest, source markers, reproducibility report, and unsigned
checksums must all identify the same frozen commit before public testing.

## Operator action

No live Beta 1 cutover occurred in the reported canary. Preserve every wallet,
the source datadir, the failed rebuild journals, and the original Beta 1
evidence. Do not use a failed Beta 1 chainstate. Wait for a newly built Beta 2
artifact and verify its exact source identity and unsigned checksums before
isolated testing.
