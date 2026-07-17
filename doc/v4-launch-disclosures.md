# Blackcoin V4 Launch Disclosures

This document records design decisions and residual risks that should be visible to
reviewers before Blackcoin Core Protocol V4 (Quantum Quasar) is deployed.

## Gold Rush reward model

Gold Rush rewards are credited only to quantum migration addresses and remain
locked until the Gold Rush reward-height window ends. After normal maturity, a
payout is an ordinary direct quantum UTXO. No fresh-address move, expiry, or
remigration is required; optional consolidation is a wallet convenience only.

PoS Gold Rush eligibility is based on the deterministic whitelist snapshot. The
snapshot aggregates spendable balance by canonical spend target at the snapshot
height. Targets at or above the 10,000 BLK threshold can qualify for PoS Gold
Rush rewards after they actively signal and solve within the required lookback
window. Targets below the threshold do not qualify retroactively because of later
receipts.

PoS Gold Rush participation is split by eligible active target, not by inferred
human owner. This is intentional and deterministic, but it means the protocol
does not try to prove that two eligible targets are controlled by different
people.

## PoW Gold Rush claims

PoW Gold Rush claims are not whitelist-gated. A valid claim transaction contains
the proof and a quantum payout address, and the reward is credited to that
quantum address when an upgraded node validates the block.

Through height 5,993,199, the PoW side preserves v30.1.0's first-valid-claim
allocation. From height 5,993,200, competing valid claims are ranked
independently of transaction order under the QQP3 rank-v1 rule. QQP3 binds
height and parent hash, remains eligible for 64 later blocks on the same
branch, and reimburses current losers and eligible late claims their capped
base fee from the fixed pool. Only a
current-origin claim can win; late-only blocks preserve the pool remainder. Total shadow
issuance is unchanged. A well-resourced miner can still win more of the PoW
migration pool than a lightly provisioned miner. The PoW path exists to give
non-whitelisted and smaller holders a direct quantum-entry path, while the PoS
side remains snapshot-limited and equalized across active eligible targets.

QQP4 exact-input binding is a separate future consensus change. It is disabled
on mainnet in v30.1.1 and cannot be activated by readiness or
version-bit signalling. Before it is scheduled, its release must publish an
explicit height and a tested transition for QQP3 claims that remain eligible
for late inclusion.

## Wallet protections and consensus backstops

Wallet code treats several outputs as protected by default:

- Gold Rush quantum rewards while their phase lock is active;
- bonded or still-unbonding tiered quantum staking outputs;
- fully locked demurrage outputs;
- RGB seal outputs and any historical EUTXO-shaped outputs.

These wallet exclusions are not the security boundary. Consensus rules also
reject invalid raw spends for the critical cases:

- bonded tiered principal cannot be redirected outside the allowed covenant;
- fully locked demurrage outputs cannot be spent;
- phase-locked Gold Rush rewards cannot be spent before the Gold Rush boundary;
- witness-v15 EUTXO funding and spending are rejected after quantum activation.

The EUTXO wallet metadata and decode/verify RPCs are inspection-only in
v30.1.1. The create/fund/spend paths intentionally fail because the v15
commitment has no quantum ownership authorization. Users must not send BLK to a
v15 address.

The wallet also uses demurrage-adjusted effective input value for partially
decayed outputs during automatic and manual coin selection, so transaction
funding matches the value that consensus will recognize.

## Cold staking and pool share

The cold-staking pool cap is a wallet and policy coordination tool, not a
consensus-enforced security boundary. It helps wallets steer new delegations away
from already-large operators, but it does not prevent solo staking or multiple
operator identities. The consensus security model depends on the staking
covenant, the tiered stake weight rules, the reorganization limits, assumeutxo,
and weak-subjectivity checkpoints.

## Demurrage scope

Demurrage is post-migration and quantum-only. Mainnet activates it
automatically on the first Final block, height 6,922,000. It does not decay
legacy coins during Gold Rush or Migration. Direct, tiered, and cold-stake
quantum outputs are subject to the inactivity schedule; delegation alone is
not an exemption. Mainnet configures no exempt scripts. Realized decay is
permanently burned and cannot become a fee, subsidy, staking reward, treasury
transfer, shadow credit, or claim reimbursement.

## Closeout findings addressed

The final red-team pass identified six items that were handled before export:

- shadow emission cap rejection is atomic on connect and symmetric on disconnect;
- wallet exclusions have consensus backstop tests for raw crafted spends;
- the historical and post-activation PoW competing-claim rules are explicitly
  disclosed;
- partially decayed outputs use effective-value accounting in wallet funding.
- pre-Gold-Rush unknown-witness block behavior, signed transaction wire format,
  PoS kernel flags, and v30.1.0 block-time provenance were red-team checked
  against the designated legacy implementation;
- Final/demurrage activation is height-authoritative and survives restart,
  reorg, and `-reindex-chainstate`.
