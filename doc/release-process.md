# Blackcoin Core release process

This is the release runbook for Blackcoin Core v30.1.1. A successful local
build is not release authorization. Production publication is allowed only for
the exact commit that satisfies the mandatory safety gate and the controls
below.

## Release classes

### Unsigned alpha canary

An alpha build begins as an initially unpublished, exact-commit test artifact
produced by a manual `workflow_dispatch` run of
`.github/workflows/build.yml`. Its package label is `30.1.1-alphaN`, its
filenames include the full source commit, and its bundle contains an unsigned
checksum file and an `UNSIGNED-CANARY` notice. The initial bundle is not a
tagged, signed, notarized, or production release.

The alpha path is for controlled operator testing. Do not attach an alpha to
the final `v30.1.1` tag, call it v30.1.1 final, or remove the canary notice.

### Unsigned beta candidate

A beta is also an initially unpublished, exact-commit test artifact produced
by the manual workflow. Its package label is `30.1.1-betaN`, the beta number
must equal the source release-candidate number, and every filename remains
bound to the full source commit. Unlike an alpha, the workflow does not start
the beta platform matrix until the exact commit passes the exhaustive
functional/soak suite, native macOS vectors, address/undefined/thread
sanitizers, pinned fuzz corpus, and the core unit, lint, critical, and real
mixed-version gates.

A beta remains unsigned, unnotarized, and unsuitable for a fleet rollout until
an isolated canary succeeds. It is initially unpublished and may become a
public GitHub prerelease only under the immutable public-beta controls below.
It may be prepared only after every P0/P1 implementation assigned to the beta
is present on the candidate branch; passing the beta workflow is evidence for
review, not permission to call the candidate production-ready.

### Optional public alpha prerelease

After the exact-SHA canary gate and operator verification pass, the project may
promote those unchanged bytes to a public GitHub prerelease. The first public
alpha uses the `v30.1.1-alpha1` tag and remains visibly classified as an
unsigned canary. Public prerelease promotion does not rerun or transform the
artifacts.

The public alpha release must satisfy all of these controls:

- the tag points to the exact source SHA recorded in every asset filename and
  canary manifest;
- immediately before promotion, the reviewer retains the response from
  `GET /repos/Blackcoin-Dev/Blackcoin/immutable-releases` and requires
  `enabled=true`. The repository returned `enabled=true` and
  `enforced_by_owner=false` on 2026-07-13; that observation does not replace the
  fresh prepublication check because repository settings are external state;
- GitHub `prerelease` is true and `latest` remains false;
- `signed=false`, `notarized=false` in the canary manifest remain unchanged.
  Its `published=false` value records that the build workflow did not publish
  the bundle when it generated that provenance record; the later GitHub
  prerelease page does not rewrite the original manifest;
- the `UNSIGNED-CANARY` warning, unsigned checksum manifest, full-SHA
  filenames, and operator-testing warning remain in the public bundle;
- the prerelease title and notes state that the artifacts are alpha test
  binaries, not v30.1.1 production binaries; and
- the tag and uploaded assets become immutable when published. Never move or
  recreate the tag and never replace an asset under an existing filename.

The public prerelease must never be marked latest, promoted to a production
release, or reused as the final `v30.1.1` release. A later alpha or production
build uses a new tag and new filenames.

An authorized public beta uses an immutable `v30.1.1-betaN` tag and the
unchanged `30.1.1-betaN` canary bundle. It must satisfy every public
prerelease control above, remain `prerelease=true` and `latest=false`, and
state that its full P0/P1 and operator validation is still in progress. A beta
tag or asset is never moved, replaced, or reused for the final release.

### Production v30.1.1

The only production publication event is a push of the signed annotated tag
`v30.1.1`. The tag must resolve to the signed Blackcoin-Dev commit that passed
the complete exact-SHA gate. The workflow rejects a lightweight tag, an
unsigned tag or commit, a different version, a release-candidate source
version, a non-Blackcoin-Dev identity, and an existing GitHub release.

## Roles and separation

At least two people participate in a production release:

- the release operator prepares the signed source commit and annotated tag;
- an independent reviewer approves the protected `production-release`
  environment after checking the gate and source identity; and
- an independent rebuilder verifies the published source and artifacts. The
  rebuilder must not reuse a primary builder workspace or dependency cache.

The repository administrator configures branch, tag, ruleset, and environment
protections. The release operator must not be able to bypass the independent
environment review.

## One-time repository controls

Repository administrators must configure and record all of these controls
before the production tag is pushed:

1. Protect the default branch. Require pull requests, the complete
   `.github/workflows/pr-gate.yml` result, resolved review conversations, and
   an independent approving review. Disable force pushes and deletion.
2. Protect `refs/tags/v30.1.1` against creation, update, and deletion except by
   the designated release role. Disable ruleset bypass, including
   administrator bypass.
3. Enable immutable GitHub releases. A published asset must never be replaced
   under the same tag or filename.
4. Restrict the `production-release` environment to `v30.1.1`, require an
   independent human reviewer, prevent self-review, and prevent administrator
   bypass.
5. Store signing and notarization material only as protected environment
   secrets or variables. Do not put credentials in source, logs, artifacts,
   repository-level variables visible to pull requests, or workflow inputs.
6. Record the release OpenPGP fingerprint on the protected default branch and
   publish the same fingerprint through an independently controlled Blackcoin
   communication channel. The fingerprint must match
   `RELEASE_GPG_FINGERPRINT` exactly.

GitHub repository rules and environment settings are external state. Source
code cannot prove that they are enabled. The independent reviewer must inspect
them immediately before approving production publication and retain that
evidence with the release record.

## Human-held production credentials

The production workflow fails closed unless the protected environment supplies
the complete list in `doc/v30.1.1-release-gate.md`. Those values include:

- the Blackcoin-Dev OpenPGP public and private key material and exact
  fingerprint;
- the Windows Authenticode certificate, password, certificate SHA-256, and
  RFC 3161 timestamp service;
- the macOS Developer ID certificate, password, certificate SHA-256, and
  signing identity; and
- the Apple team and notarization API credentials.

CI can verify use of these credentials but cannot create or approve them. A
production release is blocked until the project supplies, protects, and
independently documents the real keys and certificates.

## Candidate preparation

1. Freeze release scope. Resolve or explicitly defer every roadmap item.
   Production v30.1.1 requires all P0/P1 acceptance conditions assigned to the
   release; an alpha does not waive that production requirement.
2. Set `configure.ac` to version 30.1.1 with release candidate `0` and
   `_CLIENT_VERSION_IS_RELEASE` set to `true` only for the final production
   commit. Alpha and beta sources retain a nonzero release-candidate number
   and `_CLIENT_VERSION_IS_RELEASE=false`.
3. Finalize `doc/release-notes/release-notes-30.1.1.md`. Remove every
   `RELEASE_NOTES_NOT_FINAL` marker.
4. Run `python3 ci/release/test_release_tools.py`, repository lint, unit tests,
   and the focused functional tests locally. Local results are preliminary;
   GitHub must rerun the immutable commit.
5. Open a pull request from the Blackcoin-Dev branch. Record the exact 40-byte
   commit identifier. Do not amend, rebase, or otherwise change the commit
   after collecting release evidence.
6. Require every mandatory job to pass for that exact commit: unit and utility
   tests, full functional and soak coverage, mixed-version acceptance, native
   cryptographic vectors, sanitizer jobs, fuzz smoke, dependency provenance,
   resource benchmarks, wallet migration/recovery, replay, and reorg coverage.
7. Have the independent reviewer compare the result to
   `doc/v30.1.1-release-gate.md` and the open roadmap. A skipped, neutral,
   canceled, stale, or failed required job is not a pass.

## Alpha artifact procedure

1. Select the full candidate commit SHA, `30.1.1-alphaN` label, and required
   platform in the manual release workflow.
2. Wait for the exact-SHA alpha safety gate and both isolated builds.
3. Confirm the workflow reports byte-identical primary and verifier artifacts.
4. Download the `unsigned-canary-*` artifact. Verify its unsigned checksum
   manifest before installing it.
5. Keep the canary label and full source SHA in operator reports. Record the
   installation target, wallet backup identifier, start/end heights, and any
   failure. Never install canary artifacts without a separately verified wallet
   backup and rollback plan.
6. If public testing is authorized, create `v30.1.1-alpha1` at that exact SHA
   only after steps 1 through 5 pass. Upload the unchanged complete canary
   bundle to a GitHub release marked `prerelease`, with `latest` false.
7. Re-download the public assets and verify the unsigned checksum manifest.
   Compare every public byte with the locally verified canary bundle.
8. Confirm the public release page retains the unsigned/notarized warning and
   does not claim that the production gate, production signing, or notarization
   passed.
9. Freeze the public prerelease tag and assets. Corrections require a new alpha
   tag; they do not permit replacing the published bytes.

## Beta artifact procedure

1. Select the exact candidate SHA, matching `30.1.1-betaN` label, and required
   platform. Confirm the source release-candidate number is `N`.
2. Require the workflow's complete exact-SHA gate, including exhaustive
   functional/soak, native vectors, sanitizers, fuzz, mixed-version, critical,
   unit, and lint jobs. A skipped, canceled, neutral, stale, or failed job is
   not a pass.
3. Download the `unsigned-canary-*` bundle only after both isolated builders
   reproduce every selected artifact byte for byte. Verify the unsigned
   checksum manifest and its `prerelease_channel=beta` binding.
4. Install one isolated canary with verified wallet and datadir backups. Run
   the two-start upgrade, replay/reindex, restart, staking, wallet, GUI, and
   rollback checks required by the beta plan before any broader testing.
5. If public beta testing is authorized, create the immutable
   `v30.1.1-betaN` prerelease at that exact SHA, upload only the unchanged
   verified bundle, keep `latest=false`, then redownload and compare every
   public byte. Corrections require a new release-candidate number and tag.

## Production publication procedure

1. Import the documented Blackcoin-Dev release key in an isolated signing
   environment. Verify its full fingerprint against the protected repository
   record and independent communication channel.
2. Create a signed source commit with the exact Blackcoin-Dev name and email.
   Create a signed annotated `v30.1.1` tag pointing to that commit. Verify both
   objects locally with `git verify-commit` and `git verify-tag`.
3. Recheck branch/tag rules, immutable releases, and the protected environment.
   Confirm the designated release SHA does not already have a GitHub release.
4. Push only the signed tag. Do not manually upload release artifacts. The tag
   workflow reruns the complete production gate with `release_mode=true`.
5. The protected environment reviewer verifies the exact SHA, every mandatory
   job, credential fingerprints, and roadmap disposition before approval.
6. The workflow performs two isolated pinned-dependency builds for every
   target and compares each artifact byte for byte before signing. It then
   Authenticode-signs the Windows payload and installer, Developer-ID-signs and
   notarizes the macOS packages, and verifies each resulting signature.
7. The workflow emits an SPDX SBOM, in-toto provenance, source commit record,
   reproducibility report, exported release public key, detached provenance
   signature, and signed `SHA256SUMS.txt`.
8. The workflow creates the GitHub release as a draft, uploads the complete
   bundle once, and publishes only after all assembly and verification steps
   pass. It refuses to overwrite an existing release.

## Independent verification

Verification must begin from a clean machine and the independently obtained
OpenPGP fingerprint. Do not trust a public key only because it is stored next
to the signature it verifies.

1. Fetch `v30.1.1`, verify that it is an annotated tag, verify the tag and
   commit signatures, and record the peeled commit SHA.
2. Download every release asset. Import the release key only after its full
   fingerprint matches the independently published fingerprint.
3. Verify `SHA256SUMS.txt.asc`, then run `sha256sum --check --strict
   SHA256SUMS.txt` (or the platform equivalent).
4. Verify the detached in-toto provenance signature. Confirm that its subject
   inventory, repository, tag, and source commit match the downloaded release.
5. Inspect the SPDX SBOM and GitHub artifact attestations. Confirm the
   attestation subject hashes are present in the signed checksum manifest.
6. Verify Authenticode and RFC 3161 timestamp information for every Windows
   executable and installer. Extract the installer and confirm its embedded
   executables match the signed portable payload.
7. Verify Developer ID signatures, notarization tickets, and Gatekeeper
   assessment for both macOS architectures.
8. Run a clean pinned-dependency rebuild from the signed source. Compare the
   unsigned packages byte for byte with the reproducibility inventory. Record
   builder identity, operating system image, tool versions, source SHA, and
   resulting hashes in an independently signed rebuild attestation.

The two workflow build jobs are clean isolated rebuilds and detect
nondeterminism. The independent reviewer/rebuilder requirement adds a separate
trust domain; it cannot be satisfied merely by renaming two jobs in one
workflow.

## Release rollback and revocation

Rollback means stopping deployment and moving operators to a verified safe or
superseding release. It never means rewriting release history. Never delete,
move, or recreate the `v30.1.1` tag. Never replace a published asset or checksum
under an existing filename.

When a release defect is suspected:

1. Freeze new production workflow approvals and preserve the release, workflow
   logs, attestations, artifacts, and initial report.
2. Reproduce and classify the defect. Determine separately whether downgrade
   is safe for wallet format, chainstate format, shadow state, and consensus
   history. Do not recommend a downgrade until each compatibility question has
   a record-supported answer.
3. If operator action is required, publish a security advisory from the
   protected project account. State the affected source SHA and artifact
   hashes, observed risk, required operator action, and whether shutdown,
   backup, reindex, rescan, or wallet migration is required.
4. Remove the affected release's `latest` designation without deleting its tag
   or bytes. Preserve the original signed manifest as evidence.
5. Sign a revocation notice with the documented release key. Publish it through
   the security advisory and independent Blackcoin communication channel. A
   later release must include the notice and affected hashes in its signed
   bundle.
6. If downgrade is proven safe, direct operators only to an older release whose
   tag, source commit, checksums, and packages have been independently verified.
   If downgrade is not proven safe, direct operators to stop the affected
   process, preserve data and backups, and wait for the superseding build.
7. Prepare a new version from a new signed commit and new signed tag. Rerun the
   complete production gate. Do not reuse v30.1.1 filenames or signatures.
8. After recovery, rotate any credential whose confidentiality may have been
   affected and document the incident, decision points, operator impact, and
   permanent test or control added.

Before production publication, rehearse this procedure with an unsigned alpha.
The rehearsal must cover a failed gate before signing, a failed signing step,
a failed notarization, a draft-release upload failure, and a post-publication
defect. Confirm that no rehearsal can overwrite a tag or published asset.

## Production completion record

The release record must contain:

- exact source commit and signed annotated tag;
- required-job names and successful run identifiers;
- mixed-version binary provenance and hashes;
- upstream cryptographic-source provenance and vector results;
- benchmark results for every supported release architecture;
- primary, isolated verifier, and external rebuilder attestations;
- signed checksum manifest, SBOM, in-toto provenance, and platform signature
  verification output;
- repository rules and protected-environment review evidence; and
- the rollback rehearsal record and designated incident contacts.

Production v30.1.1 remains blocked if any item is absent, if the documented
OpenPGP fingerprint is not independently available, or if a required signing
or notarization credential is unavailable.
