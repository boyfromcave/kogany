#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Fetch ycash6's node-bin.tgz into $1 from a trusted producer run, never from an arbitrary one
# (artifact poisoning, CodeQL actions/artifact-poisoning). Accepted only when every check holds:
#   - repository $YCASH6_REPO, workflow file .github/workflows/yellowback-tests.yml;
#   - the run's head_sha is exactly $YCASH6_REV (a full 40-hex commit id, pinned by the caller);
#   - the run's event is push, schedule or workflow_dispatch (never a pull_request of a fork);
#   - the producing job `build` concluded success;
#   - the downloaded artifact zip matches the sha256 digest GitHub recorded at upload, and the
#     tarball holds src/ycashd. (ycash6 publishes no SHA256SUMS for node-bin; the digest is the
#     integrity check until it does.)
# Optional $RUN_ID narrows the search to that one run (it must pass the same checks).
set -euo pipefail
dst=${1:?usage: fetch-ycash6-node-bin.sh <dir>}
: "${YCASH6_REPO:?}" "${YCASH6_REV:?}"
REV=$YCASH6_REV
case "$REV" in *[!0-9a-f]*|'') echo "::error::YCASH6_REV is not a commit id"; exit 1 ;; esac
[ ${#REV} -eq 40 ] || { echo "::error::YCASH6_REV is not a full commit id"; exit 1; }
case "$YCASH6_REPO" in boyfromcave/ycash6) ;; *) echo "::error::unexpected YCASH6_REPO $YCASH6_REPO"; exit 1 ;; esac
WF=.github/workflows/yellowback-tests.yml
trusted='select(.event == "push" or .event == "schedule" or .event == "workflow_dispatch")'
want="select(.head_sha == \"$REV\" and .path == \"$WF\" and .head_repository.full_name == \"$YCASH6_REPO\") | $trusted | .id"
if [ -n "${RUN_ID:-}" ]; then
  case "$RUN_ID" in *[!0-9]*) echo "::error::RUN_ID is not a run id"; exit 1 ;; esac
  runs=$(gh api "repos/$YCASH6_REPO/actions/runs/$RUN_ID" -q "$want")
else
  runs=$(gh api "repos/$YCASH6_REPO/actions/workflows/yellowback-tests.yml/runs?head_sha=$REV&per_page=20" \
    -q ".workflow_runs[] | $want")
fi
echo "ycash6 yellowback-tests.yml runs at $REV (push, schedule or dispatch): ${runs:-none}"
tmp=$(mktemp -d)
for r in $runs; do
  ok=$(gh api "repos/$YCASH6_REPO/actions/runs/$r/jobs?per_page=100" \
    -q '[.jobs[] | select(.name == "build" and .conclusion == "success")] | length')
  [ "$ok" = 1 ] || { echo "run $r: job build did not succeed"; continue; }
  for name in ycash6-node-bin node-bin; do
    art=$(gh api "repos/$YCASH6_REPO/actions/runs/$r/artifacts?name=$name" \
      -q '.artifacts[] | select(.expired == false) | "\(.id) \(.digest)"' | head -n1)
    [ -n "$art" ] || continue
    id=${art%% *}; digest=${art#* }
    case "$digest" in sha256:*) ;; *) echo "run $r, $name: no recorded digest"; continue ;; esac
    gh api "repos/$YCASH6_REPO/actions/artifacts/$id/zip" > "$tmp/a.zip"
    got=sha256:$(sha256sum "$tmp/a.zip" | cut -d' ' -f1)
    [ "$got" = "$digest" ] || { echo "::error::run $r, $name: digest $got != recorded $digest"; exit 1; }
    rm -rf "$tmp/x" && mkdir "$tmp/x" && unzip -q "$tmp/a.zip" -d "$tmp/x"
    [ -f "$tmp/x/node-bin.tgz" ] || { echo "run $r, $name: no node-bin.tgz"; continue; }
    tar -tzf "$tmp/x/node-bin.tgz" > "$tmp/list"
    grep -qx 'src/ycashd' "$tmp/list" || { echo "::error::run $r, $name: node-bin.tgz without src/ycashd"; exit 1; }
    mkdir -p "$dst" && mv "$tmp/x/node-bin.tgz" "$dst/node-bin.tgz"
    echo "ycashd: $YCASH6_REPO run $r ($name, $digest) at $REV" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
    exit 0
  done
done
echo "::error::no trusted node-bin of $YCASH6_REPO at $REV. Needed: a push, schedule or workflow_dispatch run of its $WF at exactly that commit whose build job succeeded and uploaded ycash6-node-bin or node-bin (node-bin.tgz), not yet expired. Dispatch it at $REV, or bump YCASH6_REV."
exit 1
