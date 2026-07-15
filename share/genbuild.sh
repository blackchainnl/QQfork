#!/bin/sh
# Copyright (c) 2012-2021 Blackcoin Core Developers
# Copyright (c) 2012-2021 Blackcoin More Developers
# Copyright (c) 2012-2021 Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C
if [ $# -gt 1 ]; then
    cd "$2" || exit 1
fi
if [ $# -gt 0 ]; then
    FILE="$1"
    shift
    if [ -f "$FILE" ]; then
        INFO="$(cat "$FILE")"
    fi
else
    echo "Usage: $0 <filename> <srcroot>"
    exit 1
fi

GIT_TAG=""
GIT_COMMIT=""
GIT_FULL_COMMIT=""
GIT_DIRTY=0
if [ "${BITCOIN_GENBUILD_NO_GIT}" != "1" ] && [ -e "$(command -v git)" ] && [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = "true" ]; then
    # clean 'dirty' status of touched files that haven't been modified
    git diff >/dev/null 2>/dev/null

    GIT_FULL_COMMIT=$(git rev-parse --verify HEAD 2>/dev/null)
    if ! printf '%s' "$GIT_FULL_COMMIT" | grep -Eq '^[0-9a-f]{40}$'; then
        GIT_FULL_COMMIT=""
    fi
    # A non-ignored untracked file can affect a local build just as much as a
    # tracked edit. Ignore only files covered by the repository's ignore rules.
    [ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || GIT_DIRTY=1

    # If latest commit is tagged and not dirty, use the tag as the display
    # version. The separate full source identity below remains present for
    # prerelease and final tags.
    RAWDESC=$(git describe --tags --exact-match HEAD 2>/dev/null)
    [ -n "$RAWDESC" ] && [ "$GIT_DIRTY" = "0" ] && GIT_TAG=$RAWDESC

    # otherwise generate suffix from git, i.e. string like "59887e8-dirty"
    GIT_COMMIT=$(git rev-parse --short=12 HEAD)
    [ "$GIT_DIRTY" = "0" ] || GIT_COMMIT="$GIT_COMMIT-dirty"
fi

if [ -n "$GIT_FULL_COMMIT" ]; then
    SOURCEINFO="#define BUILD_SOURCE_COMMIT \"$GIT_FULL_COMMIT\"
#define BUILD_SOURCE_DIRTY $GIT_DIRTY"
else
    SOURCEINFO="// No full source commit information available"
fi

if [ -n "$GIT_TAG" ]; then
    DISPLAYINFO="#define BUILD_GIT_TAG \"$GIT_TAG\""
elif [ -n "$GIT_COMMIT" ]; then
    DISPLAYINFO="#define BUILD_GIT_COMMIT \"$GIT_COMMIT\""
else
    DISPLAYINFO="// No display-version build information available"
fi
NEWINFO="$SOURCEINFO
$DISPLAYINFO"

# only update build.h if necessary
if [ "$INFO" != "$NEWINFO" ]; then
    echo "$NEWINFO" >"$FILE"
fi
