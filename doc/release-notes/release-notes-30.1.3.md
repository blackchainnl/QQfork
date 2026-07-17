# Blackcoin Core 30.1.3

Blackcoin Core 30.1.3 is the signed-source corrective production release for
the Quantum Quasar safety release. Gold Rush is already active. Runtime,
consensus, wallet, staking, mining, GUI, shadow-ledger, Migration, Final, and
demurrage behavior are unchanged from the reviewed 30.1.1 candidate and the
30.1.2 corrective source.

## Why the version changed

The immutable `v30.1.2` tag points to source commit
`b3223d3230f15ba3a7c55376ff7d1f06265feb05`. Production run `29576545405`
verified the target and inherited safety record, then stopped in the
release-tool gate. Two canonical-hashing regression tests edited tracked
fixture files without committing those edits. The generator correctly read
the exact committed Git blobs, so the tests continued to see the original
source and failed their drift assertions.

30.1.3 commits each fixture mutation before exercising the canonical Git-blob
hash. This aligns the tests with production provenance semantics. It does not
change executable, consensus, wallet, network, staking, mining, or GUI code.

The v30.1.2 run was canceled before package assembly, checksums, SBOM,
provenance attestations, asset upload, draft creation, or release publication.
No v30.1.2 production release or production asset exists. Its immutable tag,
workflow run, and logs remain preserved as the incident record.

## Source signing and package status

The exact 30.1.3 source commit and annotated `v30.1.3` tag are SSH-signed by
Blackcoin-Dev and verified by GitHub. Verify both Git signatures before using
the source or release assets. The registered signing-key fingerprint is
`SHA256:jAkpBudDw+ntWHSUx3e1KY+czAFjnlaPxQtRFtptL70`.

Those Git-object signatures do not code-sign package bytes. Windows packages
have no Authenticode signature. macOS applications carry only identity-free
ad-hoc launch signatures and are not Developer-ID signed or notarized. Verify
`SHA256SUMS.txt`, the exact signed source commit and tag, fresh package
structural checks, SPDX SBOM, in-toto provenance, and GitHub attestations
before installing.

## Corrective validation scope

The release workflow restricts the v30.1.3 delta to release metadata,
corrective gate orchestration, signature enforcement, and the two corrected
regression fixtures. Preserved successful v30.1.1 results may be recorded as
inherited unchanged-core evidence; they are not represented as tests executed
on the v30.1.3 SHA.

The quick path does not rerun duplicate-builder reproducibility on the 30.1.3
SHA. Any historical reproducibility result is labeled separately and is not
represented as current-source evidence. Package builds and structural package
validation are fresh for v30.1.3.

The v30.1.3 publication path still binds every produced package and integrity
record to the exact signed source commit and protected tag. No v30.1.1 or
v30.1.2 package, checksum, provenance statement, or release filename is reused
as a v30.1.3 asset.

## Upgrade procedure and protocol behavior

Back up every wallet before replacing binaries. ML-DSA keys are not derived
from the legacy HD seed; the backup must be newer than every quantum address
it is expected to recover. Stop the old daemon or GUI completely before the
upgrade.

An existing 30.1.0 datadir still requires the authenticated schema-12
chainstate rebuild documented in [TRANSITION_GUIDE.md](../../TRANSITION_GUIDE.md).
A datadir already rebuilt and verified with a 30.1.1 beta does not require a
second rebuild solely because the package version is 30.1.3. Confirm
`getblockchaininfo`, `gettxoutsetinfo muhash`, `getgoldrushstate`, and schema-12
`replay_state` after a clean restart before enabling staking or mining.

The protocol schedule and operator safeguards remain unchanged:

- Gold Rush is heights 5,950,000 through 6,192,999.
- QQP3 competing-claim allocation begins at height 5,993,200.
- Migration is heights 6,193,000 through 6,921,999.
- Final Lockout and permanent-burn demurrage begin at height 6,922,000.
- QQP4 remains disabled at `INT_MAX`, and witness v15 remains frozen.
- Quantum Gold Rush credits remain locked until the Gold Rush ends.

See [release-notes-30.1.1.md](release-notes-30.1.1.md) for the complete wallet,
staking, mining, GUI, claim-resolution, resource-control, and lifecycle change
record incorporated unchanged into 30.1.3.
