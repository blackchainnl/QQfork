# Security Policy

## Supported Versions

Supported Blackcoin versions are listed in the repository release notes.
Source configured as v30.1.1 final is not an authenticated production binary:
trust only a published release whose signed tag, checksum manifest, platform
signatures, notarization, SBOM, and provenance verify against the independently
published release-key fingerprint.

## Protocol Safety Boundaries

Mainnet lifecycle transitions are height-authoritative. Gold Rush is height
5,950,000 through 6,192,999. The emission-neutral competing-claim rule begins
at height 5,993,200. Migration is height 6,193,000 through 6,921,999. Final
Lockout plus automatic demurrage begin at height 6,922,000. Readiness signalling
does not vote those transitions into effect.

Witness-v15 EUTXO is frozen and has no supported funding or spending workflow
in v30.1.1 because the commitment lacks quantum ownership authorization.
Consensus rejects v15 outputs and spends from Migration onward. Its
decode/verify and wallet metadata surfaces are inspection-only; users must not
send BLK to v15 addresses.
Demurrage realized by a valid spend is permanently burned and is not paid to
miners, stakers, a treasury, a shadow pool, or claim participants. See
the [launch disclosures](doc/v4-launch-disclosures.md) and
[demurrage economics audit](doc/v30.1.1-demurrage-economics.md).

ML-DSA quantum keys are non-HD and are not derived from the wallet seed. Back
up the wallet after every new quantum address or key. A backup made before a
quantum key was created cannot recover that key.

A wallet-authored Gold Rush PoW claim absent from the local mempool remains
quarantined because a peer may still confirm it. Its input stays reserved and
generic abandonment is refused. `createshadowpowclaimresolution` is an
explicit, non-broadcast conflict-construction tool, not a no-loss guarantee:
it previews by default, requires normal wallet unlock plus a separate fee and
conflict acknowledgement to sign, never broadcasts, and cannot guarantee peer
acceptance or confirmation. A confirmed resolution pays its displayed
base-chain fee without shadow reimbursement. After explicit broadcast and
wallet recognition, ordinary wallet rebroadcast may continue across restart.

Optional circulating-supply scans do not gate validation or consensus. They
are single-flight, bounded, cancellable diagnostics with a non-overridable
integrity floor and storage reserve. Production publication separately
requires a protected, fresh, exact-source mainnet witness inventory tied to a
connected-tip UTXO MuHash and live shadow reconciliation. A missing, stale,
tampered, scope-mismatched, or incompletely dispositioned artifact blocks
publication.

## Reporting a Vulnerability

Report security issues privately through the GitHub repository security
advisory flow when available:

<https://github.com/Blackcoin-Dev/Blackcoin/security/advisories>

If private advisories are unavailable, open a minimal public issue requesting a
private contact path. Do not include exploit details, private keys, wallet
contents, or transaction material in a public issue.
