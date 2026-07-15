#!/usr/bin/env python3
#
# Copyright (c) 2026 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Check Quantum Quasar operator documentation against production source."""

import argparse
import hashlib
import re
import sys
import uuid
from pathlib import Path


DEFAULT_ROOT = Path(__file__).resolve().parents[2]
RELEASE_MAINNET_HEIGHTS = {
    "MAINNET_SHADOW_REWARD_START_HEIGHT": 5_950_000,
    "MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT": 5_993_200,
    "MAINNET_SHADOW_REWARD_END_HEIGHT": 6_192_999,
    "MAINNET_QUANTUM_MIGRATION_END_HEIGHT": 6_921_999,
    "MAINNET_QUANTUM_FINAL_START_HEIGHT": 6_922_000,
}

FULL_PROTOCOL_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "SECURITY.md",
    "TRANSITION_GUIDE.md",
    "doc/whitepaper-quantum-quasar.md",
    "doc/upgrade-v4.md",
    "doc/release-notes.md",
)

PROTOCOL_SURFACE_DOCUMENTS = (
    "doc/shadow-explorer-rpc.md",
    "src/qt/quantumguides.cpp",
    "src/qt/stakingminingpage.cpp",
)

WALLET_RECOVERY_DOCUMENTS = (
    "doc/managing-wallets.md",
    "src/wallet/rpc/addresses.cpp",
    "src/wallet/rpc/backup.cpp",
)

CURRENT_BETA_OPERATOR_DOCUMENTS = (
    "README.md",
    "doc/release-notes.md",
)


def read_text(root, relative):
    return (root / relative).read_text(encoding="utf-8")


def normalized(text):
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[`*_]", "", text)
    return re.sub(r"\s+", " ", text).lower()


def formatted_height(value):
    return f"{value:,}"


def source_integer(root, relative, name, braced=False):
    path = root / relative
    text = path.read_text(encoding="utf-8")
    separator = r"\s*\{" if braced else r"\s*=\s*"
    suffix = r"\}" if braced else ""
    match = re.search(rf"\b{re.escape(name)}{separator}(\d+){suffix}", text)
    if not match:
        raise ValueError(f"cannot find integer {name} in {relative}")
    return int(match.group(1))


def source_asserted_integer(root, name):
    text = read_text(root, "src/shadow.h")
    match = re.search(
        rf"static_assert\(\s*{re.escape(name)}\s*==\s*(\d+)\s*\)\s*;",
        text,
    )
    if not match:
        raise ValueError(f"cannot find exact mainnet assertion for {name} in src/shadow.h")
    return int(match.group(1))


def require_fragment(failures, relative, text, fragment, description):
    if fragment not in text:
        failures.append(f"{relative}: missing {description}: {fragment}")


def require_regex(failures, relative, text, pattern, description):
    if re.search(pattern, text, re.IGNORECASE | re.DOTALL) is None:
        failures.append(f"{relative}: missing {description}")


def require_any(failures, relative, text, options, description):
    if not any(option in text for option in options):
        failures.append(f"{relative}: missing {description}")


def source_region(text, start, end, relative):
    start_offset = text.find(start)
    if start_offset < 0:
        raise ValueError(f"cannot find {start!r} in {relative}")
    end_offset = text.find(end, start_offset + len(start))
    if end_offset < 0:
        raise ValueError(f"cannot find {end!r} after {start!r} in {relative}")
    return text[start_offset:end_offset]


def check_mainnet_source(root, failures):
    heights = {
        name: source_asserted_integer(root, name)
        for name in RELEASE_MAINNET_HEIGHTS
    }
    for name, expected in RELEASE_MAINNET_HEIGHTS.items():
        if heights[name] != expected:
            failures.append(
                f"src/shadow.h: {name} is {heights[name]}, release schedule requires {expected}"
            )

    start = heights["MAINNET_SHADOW_REWARD_START_HEIGHT"]
    claims = heights["MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT"]
    gold_rush_end = heights["MAINNET_SHADOW_REWARD_END_HEIGHT"]
    migration_end = heights["MAINNET_QUANTUM_MIGRATION_END_HEIGHT"]
    final_start = heights["MAINNET_QUANTUM_FINAL_START_HEIGHT"]
    if not start < claims <= gold_rush_end < migration_end < final_start:
        failures.append("src/shadow.h: mainnet lifecycle assertions are not strictly ordered")
    if final_start != migration_end + 1:
        failures.append("src/shadow.h: Final Lockout does not immediately follow Migration")

    shadow = read_text(root, "src/shadow.h")
    for fragment in (
        "MAINNET_SHADOW_REWARD_START_HEIGHT + MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS",
        "MAINNET_SHADOW_REWARD_START_HEIGHT + MAINNET_SHADOW_GOLD_RUSH_BLOCKS - 1",
        "MAINNET_SHADOW_REWARD_END_HEIGHT + MAINNET_QUANTUM_MIGRATION_BLOCKS",
        "MAINNET_QUANTUM_MIGRATION_END_HEIGHT + 1",
    ):
        require_fragment(
            failures,
            "src/shadow.h",
            shadow,
            fragment,
            "derived production schedule expression",
        )

    chainparams = read_text(root, "src/kernel/chainparams.cpp")
    for fragment in (
        "consensus.nQuantumLifecycleStartHeight = MAINNET_SHADOW_REWARD_START_HEIGHT;",
        "consensus.nGoldRushEndHeight = MAINNET_SHADOW_REWARD_END_HEIGHT;",
        "consensus.nQuantumMigrationEndHeight = MAINNET_QUANTUM_MIGRATION_END_HEIGHT;",
        "consensus.nDemurrageActivationHeight = consensus.nQuantumMigrationEndHeight + 1;",
        "consensus.nDemurrageMinActivationHeight = consensus.nDemurrageActivationHeight;",
        "MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT;",
        "consensus.nShadowQQP4ActivationHeight = std::numeric_limits<int>::max();",
    ):
        require_fragment(
            failures,
            "src/kernel/chainparams.cpp",
            chainparams,
            fragment,
            "mainnet lifecycle wiring",
        )

    params = read_text(root, "src/consensus/params.h")
    for fragment in (
        "QQP2/QQP3 behavior at that historical",
        "default leaves QQP4 disabled until a separately announced hard fork",
        "bool IsShadowQQP4Active(int nHeight)",
    ):
        require_fragment(
            failures,
            "src/consensus/params.h",
            params,
            fragment,
            "independent QQP4 consensus activation",
        )
    demurrage_activation = source_region(
        params,
        "int EffectiveDemurrageActivationHeight() const",
        "int DemurrageBlocksPerMonth() const",
        "src/consensus/params.h",
    )
    require_fragment(
        failures,
        "src/consensus/params.h",
        demurrage_activation,
        "return nQuantumMigrationEndHeight + 1;",
        "automatic Final-bound demurrage activation",
    )
    demurrage_active = source_region(
        params,
        "bool IsDemurrageActive(",
        "QuantumQuasarPhase GetQuantumQuasarPhase(",
        "src/consensus/params.h",
    )
    for fragment in (
        "IsQuantumFinalLockout(nParentMedianTimePast, nHeight)",
        "nHeight >= EffectiveDemurrageActivationHeight()",
    ):
        require_fragment(
            failures,
            "src/consensus/params.h",
            demurrage_active,
            fragment,
            "automatic demurrage guard",
        )

    tx_verify = read_text(root, "src/consensus/tx_verify.cpp")
    check_inputs = source_region(
        tx_verify,
        "bool Consensus::CheckTxInputs(",
        "// Blackcoin: GetMinFee",
        "src/consensus/tx_verify.cpp",
    )
    for fragment in (
        "nValueIn += demurrage.effective_value;",
        "const CAmount txfee_aux = nValueIn - value_out;",
        "the burned\n        // remainder never becomes a transaction fee",
    ):
        require_fragment(
            failures,
            "src/consensus/tx_verify.cpp",
            check_inputs,
            fragment,
            "permanent-burn fee accounting",
        )
    if "demurrage.burned_value" in check_inputs:
        failures.append(
            "src/consensus/tx_verify.cpp: burned demurrage value must not enter fee accounting"
        )

    validation = read_text(root, "src/validation.cpp")
    for fragment in (
        'reject_reason = "eutxo-spend-disabled";',
        'reject_reason = "eutxo-output-disabled";',
    ):
        require_fragment(
            failures,
            "src/validation.cpp",
            validation,
            fragment,
            "frozen witness-v15 consensus rejection",
        )

    wallet = read_text(root, "src/wallet/wallet.cpp")
    new_quantum_key = source_region(
        wallet,
        "util::Result<CTxDestination> CWallet::GetNewQuantumDestination(",
        "util::Result<CTxDestination> CWallet::GetNewTieredQuantumDestination(",
        "src/wallet/wallet.cpp",
    )
    require_fragment(
        failures,
        "src/wallet/wallet.cpp",
        new_quantum_key,
        "ML_DSA::KeyGen(public_key, generated_private_key)",
        "independently generated ML-DSA key",
    )
    add_quantum_key = source_region(
        wallet,
        "util::Result<CTxDestination> CWallet::AddQuantumKey(",
        "util::Result<CTxDestination> CWallet::AddQuantumColdStakeDelegation(",
        "src/wallet/wallet.cpp",
    )
    require_fragment(
        failures,
        "src/wallet/wallet.cpp",
        add_quantum_key,
        "WriteQuantumKeyBackupState(witness_program, /*verified=*/false)",
        "new-key backup state initialization",
    )
    return heights


def appendix_integers(root):
    rows = {}
    for line in read_text(root, "doc/whitepaper-quantum-quasar.md").splitlines():
        match = re.match(r"^\| `([^`]+)` \| ([^|]+) \|", line)
        if not match:
            continue
        number = re.search(r"\d[\d,]*", match.group(2))
        if number:
            rows[match.group(1)] = int(number.group(0).replace(",", ""))
    return rows


def check_whitepaper_appendix(root, failures, heights):
    witness_header = "src/consensus/quantum_witness.h"
    address_header = "src/addresstype.h"
    redelegation_header = "src/wallet/redelegation.h"
    expected = {
        "QUANTUM_MIGRATION_PROGRAM_SIZE": source_integer(
            root, witness_header, "QUANTUM_MIGRATION_PROGRAM_SIZE"
        ),
        "QUANTUM_TIERED_PROGRAM_SIZE": source_integer(
            root, witness_header, "QUANTUM_TIERED_PROGRAM_SIZE"
        ),
        "QUANTUM_COLDSTAKE_PROGRAM_SIZE": source_integer(
            root, witness_header, "QUANTUM_COLDSTAKE_PROGRAM_SIZE"
        ),
        "EUTXO_PROGRAM_SIZE": source_integer(root, address_header, "EUTXO_PROGRAM_SIZE"),
        "SHADOW_REWARD_START_HEIGHT": heights["MAINNET_SHADOW_REWARD_START_HEIGHT"],
        "MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT": heights[
            "MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT"
        ],
        "SHADOW_REWARD_END_HEIGHT": heights["MAINNET_SHADOW_REWARD_END_HEIGHT"],
        "MAINNET_QUANTUM_MIGRATION_END_HEIGHT": heights[
            "MAINNET_QUANTUM_MIGRATION_END_HEIGHT"
        ],
        "MAINNET_QUANTUM_FINAL_START_HEIGHT": heights[
            "MAINNET_QUANTUM_FINAL_START_HEIGHT"
        ],
    }
    for member in (
        "trigger_multiplier",
        "min_trigger_blocks",
        "max_patience_blocks",
        "rate_limit_blocks",
        "probation_blocks",
        "stampede_jitter_blocks",
        "liveness_improvement_blocks",
    ):
        expected[f"QuantumRedelegationPolicy::{member}"] = source_integer(
            root, redelegation_header, member, braced=True
        )

    documented = appendix_integers(root)
    for symbol, source_value in expected.items():
        if symbol not in documented:
            failures.append(f"whitepaper Appendix A has no row for {symbol}")
        elif documented[symbol] != source_value:
            failures.append(
                f"whitepaper {symbol} is {documented[symbol]}, source is {source_value}"
            )


def check_schedule_document(root, failures, relative, heights):
    text = read_text(root, relative)
    lower = normalized(text)
    for name, value in heights.items():
        require_fragment(
            failures,
            relative,
            text,
            formatted_height(value),
            f"source-bound {name}",
        )
    require_any(
        failures,
        relative,
        lower,
        ("height-authoritative", "heights are authoritative", "exact height boundaries"),
        "statement that mainnet heights are authoritative",
    )


def check_v15_document(root, failures, relative):
    lower = normalized(read_text(root, relative))
    for word in ("v15", "fund", "spend"):
        require_fragment(failures, relative, lower, word, "frozen-v15 safety rule")
    require_any(
        failures,
        relative,
        lower,
        ("quantum ownership", "quantum owner"),
        "witness-v15 ownership defect",
    )
    require_any(
        failures,
        relative,
        lower,
        ("frozen", "disabled"),
        "statement that witness v15 is frozen or disabled",
    )


def check_burn_document(root, failures, relative):
    lower = normalized(read_text(root, relative))
    require_regex(
        failures,
        relative,
        lower,
        r"permanent(?:ly|-)?[^.]{0,80}burn|burn[^.]{0,80}permanent",
        "permanent demurrage burn",
    )
    require_regex(
        failures,
        relative,
        lower,
        r"(?:not|never) paid to (?:a )?miners?|no miner or staker receives",
        "statement that burned value is not paid to miners",
    )


def check_backup_document(root, failures, relative):
    lower = normalized(read_text(root, relative))
    require_fragment(failures, relative, lower, "backup", "quantum-key backup instruction")
    require_fragment(failures, relative, lower, "not derived", "non-HD derivation warning")
    require_fragment(failures, relative, lower, "recover", "old-backup recovery warning")
    require_any(
        failures,
        relative,
        lower,
        ("older backup", "backup made before", "backup from before", "backup must be newer"),
        "warning that pre-key backups cannot recover later keys",
    )


def check_documentation_surfaces(root, failures, heights):
    for relative in FULL_PROTOCOL_DOCUMENTS:
        check_schedule_document(root, failures, relative, heights)
        check_v15_document(root, failures, relative)
        check_burn_document(root, failures, relative)
        check_backup_document(root, failures, relative)

    for relative in PROTOCOL_SURFACE_DOCUMENTS:
        check_schedule_document(root, failures, relative, heights)
        check_v15_document(root, failures, relative)
        check_burn_document(root, failures, relative)

    for relative in WALLET_RECOVERY_DOCUMENTS:
        check_backup_document(root, failures, relative)

    blockchain_rpc = read_text(root, "src/rpc/blockchain.cpp")
    for field in (
        '"v4_activation_height"',
        '"gold_rush_end_height"',
        '"quantum_migration_end_height"',
        '"height_boundaries_authoritative"',
        '"competing_claim_rule_activation_height"',
    ):
        require_fragment(
            failures,
            "src/rpc/blockchain.cpp",
            blockchain_rpc,
            field,
            "source-bound lifecycle RPC field",
        )
    check_v15_document(root, failures, "src/rpc/blockchain.cpp")
    check_burn_document(root, failures, "src/rpc/blockchain.cpp")

    wallet_spend_rpc = read_text(root, "src/wallet/rpc/spend.cpp")
    for name, value in (
        ("first Migration block", heights["MAINNET_SHADOW_REWARD_END_HEIGHT"] + 1),
        ("last Migration block", heights["MAINNET_QUANTUM_MIGRATION_END_HEIGHT"]),
    ):
        require_fragment(
            failures,
            "src/wallet/rpc/spend.cpp",
            wallet_spend_rpc,
            formatted_height(value),
            f"source-derived {name} in migration RPC help",
        )
    check_v15_document(root, failures, "src/wallet/rpc/spend.cpp")


def check_pow_claim_documentation(root, failures, heights):
    replay_schema = source_integer(
        root, "src/shadow.cpp", "SHADOW_REPLAY_STATE_VERSION"
    )
    schema_pattern = rf"schema(?: is)?(?: version)?[- ]?{replay_schema}\b"
    for relative in (
        "README.md",
        "TRANSITION_GUIDE.md",
        "doc/release-notes.md",
        "doc/upgrade-v4.md",
        "doc/v30.1.1-competing-pow-claims.md",
    ):
        require_regex(
            failures,
            relative,
            read_text(root, relative),
            schema_pattern,
            f"source-bound shadow replay schema {replay_schema}",
        )

    validation = read_text(root, "src/validation.cpp")
    require_fragment(
        failures,
        "src/validation.cpp",
        validation,
        f"schema-{replay_schema} auxiliary checkpoint",
        "source-bound replay-rebuild diagnostic",
    )

    activation_height = formatted_height(
        heights["MAINNET_SHADOW_COMPETING_CLAIMS_ACTIVATION_HEIGHT"]
    )
    hardening = read_text(root, "doc/v30.1.1-cryptographic-hardening.md")
    require_regex(
        failures,
        "doc/v30.1.1-cryptographic-hardening.md",
        hardening,
        rf"before height {re.escape(activation_height)}[^.]*`QQP2`",
        "pre-boundary QQP2 rule",
    )
    require_regex(
        failures,
        "doc/v30.1.1-cryptographic-hardening.md",
        hardening,
        r"at and after\s+(?:the\s+)?QQP3 boundary[^.]*`QQP3`",
        "QQP3 rule at the existing competing-claim boundary",
    )
    require_regex(
        failures,
        "doc/v30.1.1-cryptographic-hardening.md",
        hardening,
        r"exact single legacy fee-input\s+outpoint",
        "QQP4 exact-input binding",
    )
    require_regex(
        failures,
        "doc/v30.1.1-cryptographic-hardening.md",
        hardening,
        r"separately scheduled consensus activation[^.]*disabled on mainnet",
        "mainnet-disabled separate QQP4 activation",
    )
    require_regex(
        failures,
        "doc/v30.1.1-cryptographic-hardening.md",
        hardening,
        r"cannot be activated by readiness or\s+version-bit signalling",
        "QQP4 non-readiness activation rule",
    )

    claim_rule = read_text(root, "doc/v30.1.1-competing-pow-claims.md")
    require_fragment(
        failures,
        "doc/v30.1.1-competing-pow-claims.md",
        claim_rule,
        "Generic `abandontransaction` intentionally refuses",
        "safe non-generic-abandon rule",
    )
    for fragment in (
        "This is the existing QQP3/rank-v1",
        "A readiness bit, version bit, or other signalling state cannot",
        "still eligible for late inclusion",
    ):
        require_fragment(
            failures,
            "doc/v30.1.1-competing-pow-claims.md",
            claim_rule,
            fragment,
            "QQP3/QQP4 activation separation",
        )
    release_notes = read_text(root, "doc/release-notes.md")
    require_fragment(
        failures,
        "doc/release-notes.md",
        release_notes,
        "`abandontransaction` intentionally refuses a quarantined",
        "safe quarantined-claim release note",
    )
    wallet_rpc = read_text(root, "src/wallet/rpc/transactions.cpp")
    require_fragment(
        failures,
        "src/wallet/rpc/transactions.cpp",
        wallet_rpc,
        "Gold Rush PoW QQSPROOF claims cannot be abandoned with this RPC.",
        "safe Gold Rush PoW abandonment RPC help",
    )


def check_release_status(root, failures):
    relative = "doc/v30.1.1-release-gate.md"
    text = read_text(root, relative)
    match = re.search(
        r"^\| #19 specification and documentation \| [^|]+ \| ([^|]+) \|",
        text,
        re.MULTILINE,
    )
    if not match:
        failures.append("release gate has no roadmap row for issue #19")
    elif match.group(1).strip() != "Partial":
        failures.append(
            "issue #19 must remain Partial until its production evidence matrix passes; "
            f"found {match.group(1).strip()}"
        )


def check_beta_channel_identity(root, failures):
    for relative in CURRENT_BETA_OPERATOR_DOCUMENTS:
        text = normalized(read_text(root, relative))
        if re.search(r"\balpha(?:\s*1|1)?\b", text):
            failures.append(
                f"{relative}: current beta operator document contains an alpha channel label"
            )

    release_notes = read_text(root, "doc/release-notes.md")
    for fragment in (
        "Beta 1 canary identity",
        "The v30.1.1 beta 1 packages are unpublished, unsigned canary artifacts.",
        "`30.1.1-beta1`",
        "`Blackcoin-30.1.1-beta1`",
        "`unsigned-canary-30.1.1-beta1-<FULL_SOURCE_COMMIT>`",
        "For this beta, sudden-power-loss durability",
    ):
        require_fragment(
            failures,
            "doc/release-notes.md",
            release_notes,
            fragment,
            "current beta 1 canary identity",
        )

    readme = read_text(root, "README.md")
    require_fragment(
        failures,
        "README.md",
        readme,
        "The v30.1.1 beta does not claim power-loss-atomic directory renames on Windows.",
        "current beta Windows recovery warning",
    )


def check_pdf_provenance(root, failures):
    whitepaper = root / "doc/whitepaper-quantum-quasar.md"
    pdf = root / "doc/whitepaper-quantum-quasar.pdf"
    generator = root / "contrib/devtools/gen-whitepaper-pdf.py"
    generator_bytes = generator.read_bytes()
    generator_text = generator_bytes.decode("utf-8")
    expected_creator = "Blackcoin gen-whitepaper-pdf.py (ReportLab)"
    expected_producer = "pypdf"

    creator = re.search(r'^DOC_CREATOR = "([^"]+)"$', generator_text, re.MULTILINE)
    producer = re.search(r'^DOC_PRODUCER = "([^"]+)"$', generator_text, re.MULTILINE)
    if not creator or creator.group(1) != expected_creator:
        failures.append("PDF generator Creator does not identify the ReportLab generator")
    if not producer or producer.group(1) != expected_producer:
        failures.append("PDF generator Producer does not identify pypdf")

    pdf_bytes = pdf.read_bytes()
    revision_digest = hashlib.sha256(
        whitepaper.read_bytes() + b"\0" + generator_bytes
    ).hexdigest()
    expected_instance = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"blackcoin-quantum-quasar-whitepaper:{revision_digest}",
        )
    )
    required = (
        f"<xmp:CreatorTool>{expected_creator}</xmp:CreatorTool>".encode(),
        f"<pdf:Producer>{expected_producer}</pdf:Producer>".encode(),
        b'x:xmptk="pypdf"',
        f"<xmpMM:InstanceID>uuid:{expected_instance}</xmpMM:InstanceID>".encode(),
    )
    for fragment in required:
        if fragment not in pdf_bytes:
            failures.append(
                "generated PDF metadata is stale or missing: "
                + fragment.decode("utf-8")
            )


def verify(root):
    failures = []
    try:
        heights = check_mainnet_source(root, failures)
        check_whitepaper_appendix(root, failures, heights)
        check_documentation_surfaces(root, failures, heights)
        check_pow_claim_documentation(root, failures, heights)
        check_release_status(root, failures)
        check_beta_channel_identity(root, failures)
        check_pdf_provenance(root, failures)
    except (OSError, ValueError) as error:
        failures.append(str(error))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    failures = verify(args.root.resolve())
    if failures:
        for failure in failures:
            print(f"quantum documentation invariant: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
