# Blackcoin Core 30.1.2

Blackcoin Core 30.1.2 is the production packaging correction for the Quantum
Quasar safety release. Gold Rush is already active. This version contains the
same runtime, wallet, staking, mining, GUI, shadow-ledger, Migration, Final,
and demurrage behavior reviewed for the unpublished 30.1.1 candidate. Its new
source changes are limited to version and release metadata plus
platform-independent provenance generation and verification.

## Why the version changed

The protected `v30.1.1` tag was created at source commit
`dffb457650f48848794120ef4661f0a8f0187e05`. Production run `29552432859`
completed 35 jobs successfully, including the complete functional,
sanitizer, fuzz, mixed-version, native-platform, resource, package, and
two-builder reproducibility work. Publication then failed before attestations
or GitHub release creation.

The Windows resource-evidence generator hashed CRLF working-tree bytes, while
the Linux publisher verified the canonical LF Git bytes. The manifest hashes
therefore differed even though the parsed source content was identical. No
30.1.1 draft, production release, assets, checksums, SBOM, or attestations were
published. The immutable 30.1.1 tag and failed workflow remain preserved as
the incident record.

30.1.2 hashes every tracked provenance and epoch-contract input from the exact
Git commit blob. Binary and benchmark-result hashes remain raw-byte hashes.
Regression coverage proves that LF and CRLF working trees produce identical
tracked-source evidence and that substituted or untracked inputs still fail
closed.

## Corrective validation scope

The release workflow verifies that the 30.1.2 source is a direct child of the
reviewed 30.1.1 source and rejects any runtime, consensus, wallet, GUI, P2P,
staking, mining, dependency, or build-recipe change. It records the exact
successful 30.1.1 core jobs as inherited evidence; those historical results
are not represented as tests run on the 30.1.2 SHA.

30.1.2 freshly runs the changed release-tool tests, source identity, workflow
and lint checks, canonical quantum provenance, all five native resource
evidence jobs, all five primary and verifier package builds, byte-for-byte
reproducibility, macOS ad-hoc validation, Windows unsigned and installer
equivalence checks, final publisher assembly, checksums, SBOM, in-toto
provenance, and GitHub attestations. No 30.1.1 package or invalid Windows
resource bundle is reused.

## Verify before installing

This release is publisher-unsigned. Blackcoin-Dev has no OpenPGP,
Authenticode, Apple Developer ID, or notarization credentials. Windows
packages have no Authenticode signature. macOS applications carry only
identity-free ad-hoc launch signatures and are not notarized.

Read `Blackcoin-30.1.2-UNSIGNED-PRODUCTION.txt` and its JSON manifest. Verify
`SHA256SUMS.txt`, the exact source commit, the reproducibility report, SPDX
SBOM, in-toto provenance, inherited-core evidence record, current native
resource evidence, and GitHub attestations before installing.

## Upgrade procedure and protocol behavior

Back up every wallet before replacing binaries. ML-DSA keys are not derived
from the legacy HD seed; the backup must be newer than every quantum address
it is expected to recover. Stop the old daemon or GUI completely before the
upgrade.

An existing 30.1.0 datadir still requires the authenticated schema-12
chainstate rebuild documented in [TRANSITION_GUIDE.md](../../TRANSITION_GUIDE.md).
A datadir already rebuilt and verified with a 30.1.1 beta does not require a
second rebuild solely because the package version is 30.1.2. Confirm
`getblockchaininfo`, `gettxoutsetinfo muhash`, `getgoldrushstate`, and schema-12
`replay_state` after a clean restart before enabling staking or mining.

The protocol schedule and operator safeguards are unchanged from the reviewed
30.1.1 candidate:

- Gold Rush is heights 5,950,000 through 6,192,999.
- QQP3 competing-claim allocation begins at height 5,993,200.
- Migration is heights 6,193,000 through 6,921,999.
- Final Lockout and permanent-burn demurrage begin at height 6,922,000.
- QQP4 remains disabled at `INT_MAX`, and witness v15 remains frozen.
- Quantum Gold Rush credits remain locked until the Gold Rush ends.

See [release-notes-30.1.1.md](release-notes-30.1.1.md) for the complete wallet,
staking, mining, GUI, claim-resolution, resource-control, and lifecycle change
record incorporated unchanged into 30.1.2.
