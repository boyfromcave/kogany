<!-- Copyright (c) 2026 The Ycash developers. Distributed under the MIT software license. -->

# Restoring a mainnet koganyd from a snapshot

A new `koganyd` syncs Ycash mainnet from genesis in about seven hours. A snapshot bundle is a
packed copy of another kogany node's state database at a block height `H`; restored into the
state directory, it lets the node start at `H` and sync only the blocks after it.

This page is the procedure. The bundle format is `kogany-state/2` (ycash-infra
`bundles/state/FORMAT.md`); the bundles are made with ycash-infra `bundles/state/mainnet/`.

## What is published

Two families, in a public object store. The newest height of each is named by a `latest` manifest:

| Family | Base URL | For |
| --- | --- | --- |
| pruned | `https://ycash-contributors-object-store.s3.us-east-1.amazonaws.com/snapshots/kogany-main-pruned` | a node run with `[state.storage_mode.pruned]`: raw transactions kept for the last 34,560 blocks (30 days). About 5.4 GB. |
| archive | `https://ycash-contributors-object-store.s3.us-east-1.amazonaws.com/snapshots/kogany-main` | an archive node (the default storage mode) or a pruned one. About 22 GB. |

Each height `<base>/<H>/` holds the tarball, `manifest.json`, `SHA256SUMS` (over the tarball and
the manifest) and `SHA256SUMS.minisig`, a minisign signature over `SHA256SUMS` by the Ycash
release key:

```
untrusted comment: minisign public key 02C923A6C593AF18
RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ
```

(the same key as ycash-infra `keys/ycash-release.pub`). The `main/` family in the same store
holds ycashd datadirs (`ycash-state/2`): koganyd cannot read them.

**The state format must match.** A bundle holds the database of one Zakura state format, named in
the manifest's `state_format` and in the latest manifest's path (`latest-30.2.0`). This tree
writes format 30.2.0 (`crates/zakura-state/src/constants.rs`, `DATABASE_FORMAT_VERSION` and the
minor and patch constants). A koganyd with another major version opens a different directory
(`state/v<major>/`) and ignores the bundle.

**Pruned is one-way.** A pruned bundle restores only into a node configured with
`[state.storage_mode.pruned]` and `tx_retention` of at least 10,000; koganyd refuses to open it
in archive mode ("this database has been pruned and cannot be opened in archive storage mode").
An archive bundle restores into either mode.

## Procedure

You need `curl`, `jq`, `minisign`, `shasum` (or `sha256sum` on Linux) and `tar`, and free space
for the tarball plus its unpacked size (pruned: 5.4 + 6.7 GB; archive: 22 + 24 GB).

1. Stop koganyd if it runs, and set the two paths. These are koganyd's defaults
   (README "Directories and files"); with a config file that sets `[state] cache_dir`, use that
   directory as `CACHE`.

   ```sh
   if [ "$(uname)" = Darwin ]; then
     CONF=$HOME/Library/Preferences/kogany.toml; CACHE=$HOME/Library/Caches/kogany
   else
     CONF=${XDG_CONFIG_HOME:-$HOME/.config}/kogany.toml; CACHE=${XDG_CACHE_HOME:-$HOME/.cache}/kogany
   fi
   ```

2. For a pruned bundle, configure pruned storage. This writes a new config file only if there is
   none; an existing one is left alone, and you add the section to it by hand.

   ```sh
   mkdir -p "$(dirname "$CONF")"
   if [ -e "$CONF" ]; then
     echo "$CONF exists: add [state.storage_mode.pruned] with tx_retention = 34560 to it"
   else
     printf '[state.storage_mode.pruned]\ntx_retention = 34560\n' > "$CONF"
   fi
   ```

3. Fetch the small files of the newest height, then the tarball, in an empty directory.
   `curl -C -` resumes an interrupted download.

   ```sh
   B=https://ycash-contributors-object-store.s3.us-east-1.amazonaws.com/snapshots/kogany-main-pruned
   H=$(curl -fsS $B/latest-30.2.0/manifest.json | jq -r .height)
   curl -fsS --remote-name-all $B/$H/{manifest.json,SHA256SUMS,SHA256SUMS.minisig}
   T=$(jq -r .tarball manifest.json)
   curl -fL -C - -O $B/$H/$T
   ```

   For the archive family, use `.../snapshots/kogany-main` as `B` and skip step 2.

4. Check the signature, then every file against it.

   ```sh
   minisign -Vm SHA256SUMS -P RWQYr5PFpiPJAigk86vf89bPYrJCXj5tskgRAPRYFsEXyciZo8dveOGQ
   shasum -a 256 -c SHA256SUMS          # Linux: sha256sum -c SHA256SUMS
   ```

   Both must succeed: `Signature and comment signature verified`, and `OK` for the tarball and
   `manifest.json`. The trusted comment names the release and height the bundle was cut from.

5. Replace the mainnet state and check its format. Run this as one block, in the shell where you
   ran steps 1 and 3 (it needs `CACHE` and `T`) and in the download directory (it reads
   `manifest.json`). It does nothing unless koganyd is stopped and the bundle's `state_format` is
   the one this koganyd writes (30.2.0). It moves the old mainnet state aside instead of deleting
   it, and touches nothing else: the testnet and regtest state, and any other format's
   `state/v<major>/`, stay as they are.

   ```sh
   if [ -z "${CACHE:-}" ] || [ -z "${T:-}" ]; then
     echo "set CACHE (step 1) and T (step 3) in this shell first"
   elif pgrep -x koganyd >/dev/null; then
     echo "koganyd is running: stop it first"
   elif [ "$(jq -r .state_format manifest.json)" != 30.2.0 ]; then
     echo "the bundle is for state format $(jq -r .state_format manifest.json), not 30.2.0"
   else
     OLD=old.$(date +%s)
     [ -e "${CACHE:?}/state/v30/mainnet" ] && mv "${CACHE:?}/state/v30/mainnet" "${CACHE:?}/state/v30/mainnet.$OLD"
     [ -e "${CACHE:?}/non_finalized_state/mainnet" ] && mv "${CACHE:?}/non_finalized_state/mainnet" "${CACHE:?}/non_finalized_state/mainnet.$OLD"
     mkdir -p "${CACHE:?}" && tar -xzf "$T" -C "${CACHE:?}" && cat "${CACHE:?}/state/v30/mainnet/version"
   fi
   ```

   The last line prints the restored `version`; it must equal the manifest's `state_format`,
   30.2.0. Once the node is up and the checks in step 6 pass, delete the moved-aside
   `state/v30/mainnet.old.*` and `non_finalized_state/mainnet.old.*` directories to free the
   space.

   The tarball holds `state/v30/mainnet/` (the RocksDB files) and `non_finalized_state/mainnet/`
   (one file per block above the finalized tip; `non_finalized_blocks` in the manifest), and no
   peer cache, identity, cookie or config.

6. Start koganyd and check the restored tip, with the RPC server on (`[rpc] listen_addr`, README
   "Running"). `koganyd start` runs in the foreground and holds its terminal, so start it in a
   second terminal:

   ```sh
   koganyd start
   ```

   Then, back in the first terminal (the download directory), query it. RPC cookie
   authentication is on by default: koganyd writes `user:password` to `.cookie` in its cache
   directory on mainnet (`$CACHE/.cookie`, README "Directories and files"; another directory
   if the config sets `[rpc] cookie_dir`), and `curl -u` sends it.

   ```sh
   curl -s -u "$(cat "$CACHE/.cookie")" -H 'content-type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' http://127.0.0.1:8832 \
     | jq '.result | {blocks, bestblockhash, pruned, pruneheight}'
   jq '{height, blockhash, lowest_retained_height}' manifest.json
   ```

   Before the node syncs on, `blocks` and `bestblockhash` equal the manifest's `height` and
   `blockhash`, and on a pruned node `pruneheight` equals `lowest_retained_height`. Then it
   downloads the blocks after `H` from its peers.

## What the checks prove, and what they do not

- The signature proves the bundle is the one the Ycash release key signed, byte for byte
  (`SHA256SUMS` covers the tarball and the manifest).
- koganyd does not re-verify the state below `H`: it trusts the restored database as it trusts
  its own. The bundle was written by one kogany node that synced and verified the chain itself.
  At a fixed height the manifest's `agrees_with` names the ycash6 statement whose block hash at `H`
  it was compared with; at the network tip it is `null`.
- To check the restored chain against another node, compare `getblockhash <H>` with a ycashd or
  a block explorer. Every block after `H` is verified as in any sync.
- The bundle's own `tree_sha256` (a hash over each file in the tarball) is checked by ycash-infra's
  `python3 -I bundles/state/verify.py --tree <dir>`; it is not needed for the restore.

## How long it takes

Measured on 2026-11-11 with the pruned bundle at 3,090,808 (5.44 GB), on an Apple-silicon Mac:
download 527 s (about 10 MB/s; the link sets this), `shasum` 14 s, `tar -xzf` 17 s, and koganyd
answered RPC 5 s after start, with the 1,000 non-finalized blocks restored. The archive bundle is
four times the size. A sync from genesis is about seven hours.

## When a check fails

- `shasum` prints `<file>: FAILED` and exits 1: the download is truncated or damaged. Delete
  that file and fetch it again (step 3). Do not extract it.
- `minisign` prints `Signature verification failed`: `SHA256SUMS` or its signature is not what
  the release key signed. Fetch both again; if it still fails, do not use the bundle and report
  it at <https://github.com/boyfromcave/kogany/issues>.
- The `version` file is not the manifest's `state_format`, or koganyd starts from genesis: the
  bundle is for another state format. Use the bundle whose `latest-<state_format>` matches your
  koganyd, or sync from genesis.
- koganyd refuses to start with "cannot be opened in archive storage mode": a pruned bundle in an
  archive node. Configure pruned storage (step 2), or restore an archive bundle.
- `blocks` or `bestblockhash` differ from the manifest before the node has synced on: stop it,
  move aside `state/v30/mainnet` and `non_finalized_state/mainnet` (step 5 does both; nothing
  else under `state/` or `non_finalized_state/`), and restore again from a checked tarball.

## Tested

Steps 3 to 6 were run on 2026-11-11 against the published pruned bundle at 3,090,808 with the
v1.8.0-ycash.beta1 `koganyd` (macOS), offline (no peers): signature and checksums verified, the
`version` file read 30.2.0, and `getblockchaininfo` answered `blocks` 3,090,808,
`bestblockhash` `0000027b407a9884c13c55e5aeaf47d035ac6c96794db5ade78c8b20a87f31a3`, `pruned`
true, `pruneheight` 3,055,249, as the manifest states; `getblock` below 3,055,249 answered
`Block not available (pruned data)`. The failure messages above were reproduced with a changed
checksum and a changed `SHA256SUMS`. The guards of step 5 (unset `CACHE` or `T`, a running
koganyd, another `state_format`) and its move-aside were then checked on a stand-in cache
directory, in bash and zsh: other networks' and other formats' state was left in place. The
archive bundle, and steps 1 and 2 on Linux, were not run.
