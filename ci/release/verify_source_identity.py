#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail closed unless release history and tag metadata use the team identity."""

import argparse
import re
import subprocess
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
EXPECTED_ACTOR = "Blackcoin-Dev"
EXPECTED_NAME = "Blackcoin-Dev"
EXPECTED_EMAIL = "298119138+Blackcoin-Dev@users.noreply.github.com"
TRUSTED_V30_1_0 = "f647dc75c9479c03e81414f145a8d233b60959c7"
PINNED_IDENTITY_EXCEPTIONS = {
    # Historical main-branch commit made by the same GitHub team account before
    # its numeric noreply address was configured. Keep this exception scoped to
    # the immutable commit; do not accept the legacy address generally.
    "4f87d05a741013d1e55fd9caa1c2a1cc4a6e570d": (
        "Blackcoin-Dev",
        "Blackcoin-Dev@users.noreply.github.com",
    ),
}
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
FINGERPRINT_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
ATTRIBUTION_TRAILER_RE = re.compile(r"^(?:co-authored-by|co-developed-by):", re.IGNORECASE)


def git(*args):
    return subprocess.run(
        ["git", *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


def resolved_commit(value):
    commit = git("rev-parse", f"{value}^{{commit}}")
    if not FULL_SHA_RE.fullmatch(commit):
        raise RuntimeError(f"{value} did not resolve to a full commit identifier")
    return commit


def verify_commit(commit):
    fields = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", commit).split("\0", 4)
    if len(fields) != 5:
        raise RuntimeError(f"cannot parse identity metadata for {commit}")
    author_name, author_email, committer_name, committer_email, message = fields
    expected = (EXPECTED_NAME, EXPECTED_EMAIL)
    pinned_expected = PINNED_IDENTITY_EXCEPTIONS.get(commit)
    author = (author_name, author_email)
    committer = (committer_name, committer_email)
    if author != expected and author != pinned_expected:
        raise RuntimeError(
            f"{commit} author is {author_name} <{author_email}>; expected the release team identity"
        )
    if committer != expected and committer != pinned_expected:
        raise RuntimeError(
            f"{commit} committer is {committer_name} <{committer_email}>; expected the release team identity"
        )
    if pinned_expected is not None and author != committer:
        raise RuntimeError(
            f"{commit} must use the same pinned release team identity for author and committer"
        )
    for line in message.splitlines():
        if ATTRIBUTION_TRAILER_RE.match(line.strip()):
            raise RuntimeError(f"{commit} contains an additional contributor-attribution trailer")


def verify_openpgp_signature(object_name, object_kind, expected_fingerprint):
    command = ["git", f"verify-{object_kind}", "--raw", object_name]
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    status_lines = [line.strip() for line in result.stdout.splitlines() if "[GNUPG:]" in line]
    invalid_markers = (" BADSIG ", " ERRSIG ", " EXPKEYSIG ", " REVKEYSIG ")
    if result.returncode != 0 or any(marker in f" {line} " for marker in invalid_markers for line in status_lines):
        raise RuntimeError(f"{object_name} does not have a valid OpenPGP signature")

    valid_fingerprints = set()
    for line in status_lines:
        marker = "[GNUPG:] VALIDSIG "
        if marker not in line:
            continue
        fields = line.split(marker, 1)[1].split()
        if fields:
            valid_fingerprints.add(fields[0].upper())
        # GnuPG appends the primary-key fingerprint when a signing subkey was used.
        if len(fields) >= 10:
            valid_fingerprints.add(fields[-1].upper())

    if expected_fingerprint not in valid_fingerprints:
        raise RuntimeError(
            f"{object_name} signature is not rooted in the configured Blackcoin-Dev release key"
        )


def verify_tag(tag, head, signing_fingerprint=None):
    ref = f"refs/tags/{tag}"
    if git("cat-file", "-t", ref) != "tag":
        raise RuntimeError(f"{tag} must be an annotated tag")
    if resolved_commit(ref) != head:
        raise RuntimeError(f"{tag} does not resolve to the gated commit {head}")
    tagger = git("for-each-ref", "--format=%(taggername)%00%(taggeremail)", ref).split("\0", 1)
    if len(tagger) != 2:
        raise RuntimeError(f"cannot parse tagger identity for {tag}")
    tagger_name, tagger_email = tagger
    tagger_email = tagger_email.removeprefix("<").removesuffix(">")
    if (tagger_name, tagger_email) != (EXPECTED_NAME, EXPECTED_EMAIL):
        raise RuntimeError(f"{tag} was not created with the release team identity")
    if signing_fingerprint:
        verify_openpgp_signature(tag, "tag", signing_fingerprint)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=TRUSTED_V30_1_0)
    parser.add_argument("--head", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--actor")
    parser.add_argument("--require-actor", action="store_true")
    parser.add_argument("--tag")
    parser.add_argument("--require-signatures", action="store_true")
    parser.add_argument("--signing-fingerprint")
    args = parser.parse_args()

    if args.repository != EXPECTED_REPOSITORY:
        raise RuntimeError(f"release repository must be {EXPECTED_REPOSITORY}")
    if args.require_actor and args.actor != EXPECTED_ACTOR:
        raise RuntimeError("release workflow must be initiated by the release team account")

    signing_fingerprint = (args.signing_fingerprint or "").replace(" ", "").upper()
    if args.require_signatures and not FINGERPRINT_RE.fullmatch(signing_fingerprint):
        raise RuntimeError("a full OpenPGP release-signing fingerprint is required")

    base = resolved_commit(args.base)
    head = resolved_commit(args.head)
    subprocess.run(["git", "merge-base", "--is-ancestor", base, head], check=True)
    commits = git("rev-list", "--reverse", f"{base}..{head}").splitlines()
    if not commits:
        raise RuntimeError("release range contains no commits after v30.1.0")
    for commit in commits:
        verify_commit(commit)
    if args.require_signatures:
        verify_openpgp_signature(head, "commit", signing_fingerprint)
    if args.tag:
        verify_tag(args.tag, head, signing_fingerprint if args.require_signatures else None)

    print(f"Verified {len(commits)} release commit(s) through {head}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"identity verification failed: {error}", file=sys.stderr)
        sys.exit(1)
