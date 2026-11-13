#!/usr/bin/env bash
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
#
# Packs one koganyd pre-release tarball (kogany-release.yml; run locally for a dry run):
#   kogany-release-package.sh <tag> <platform> <koganyd binary> <out dir>
# writes <out dir>/koganyd_<tag>_<platform>.tar.gz holding koganyd_<tag>_<platform>/ with
# koganyd, README.txt, LICENSE-APACHE, LICENSE-MIT and default_config_ycash.toml.
set -euo pipefail
tag=$1 platform=$2 bin=$3 out=$4
name="koganyd_${tag}_${platform}"
root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/$name" "$out"
install -m 0755 "$bin" "$work/$name/koganyd"
cp "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$work/$name/"
cp "$root/crates/zakurad/src/commands/default_config_ycash.toml" "$work/$name/"
case "$platform" in
  linux-*) runtime="Linux with glibc 2.39 or newer (Ubuntu 24.04 or newer); RocksDB is linked in statically.
The debug info is in koganyd_${tag}_${platform}.debug.tar.gz: unpack koganyd.debug beside koganyd
for file and line numbers in a backtrace" ;;
  macos-*) runtime="macOS 14 or newer on Apple silicon; RocksDB is linked in statically" ;;
  *) runtime="see kogany's README.md" ;;
esac
commit=$(git rev-parse HEAD)
cat > "$work/$name/README.txt" <<TXT
koganyd ${tag} (${platform})
=================================

koganyd is Kogany, a Ycash full node in Rust: the Ycash developers' fork of Zakura (a Zcash
full node, Zebra lineage), built with the \`ycash\` feature. It follows Ycash mainnet, the
Ycash testnets (fast, slow and legacy profiles) and Ycash regtest, and enforces the vault network upgrade and the
Ycash Yellowback (YED) rule module. Source: https://github.com/boyfromcave/kogany at ${commit}.

PRE-RELEASE. This is a beta for the Ycash testnets. kogany is not yet a qualified Ycash node
line (kogany plan K-19): do not run it for funds on mainnet, and expect breaking changes and
resyncs between pre-releases. Report problems at https://github.com/boyfromcave/kogany/issues.

Runtime: ${runtime}.

Ports (crates/zakura-chain/src/parameters/ycash.rs)
  network                                       config network =   P2P     RPC
  Ycash mainnet                                 "Mainnet"          8833    8832
  Ycash testnet, fast profile (testnet-yb-fast) "Testnet"          18833   18832
  Ycash testnet, slow profile                   "TestnetSlow"      18933   18932
  Ycash testnet, legacy profile                 "TestnetLegacy"    19033   19032
kogany never uses Zcash's ports. The RPC server is off until [rpc] listen_addr is set.
No testnet peer is built in: name one in initial_testnet_peers. The seeds (ycashd 6.22.0-beta2):
  fast   fastnet-seed.ycash.team:18833
  slow   slownet-seed.ycash.team:18933
  legacy legacy-seed.ycash.team:19033

macOS: the binaries are not notarized. Before the first run of a browser download, clear the
quarantine flag: xattr -dr com.apple.quarantine <this directory>

Getting started
  ./koganyd --version                      # the crate version and commit, 1.8.0-rc1+kogany.g<12-hex commit>;
                                           # the P2P user agent carries the release name (/koganyd:${tag#v}/)
  ./koganyd generate -o kogany.toml        # the default (mainnet) config; default_config_ycash.toml is the same skeleton
  ./koganyd start                          # Ycash mainnet

Testnet (fast profile): write testnet.toml with

  [network]
  network = "Testnet"
  listen_addr = "[::]"
  initial_testnet_peers = ["fastnet-seed.ycash.team:18833"]

  [rpc]
  listen_addr = "127.0.0.1:18832"

and run: ./koganyd -c testnet.toml start
For the slow or legacy profile set network = "TestnetSlow" or "TestnetLegacy", its seed and its
RPC port (kogany README.md "Networks, ports and identifiers").

Environment overrides use the ZAKURA_ prefix, e.g. ZAKURA_NETWORK__NETWORK=Testnet.
State lives in ~/.cache/kogany on Linux and ~/Library/Caches/kogany on macOS. The RPC cookie:
  mainnet            ~/.cache/kogany/.cookie             (macOS ~/Library/Caches/kogany/.cookie)
  test networks      ~/.cache/kogany/<network>/.cookie   (macOS ~/Library/Caches/kogany/<network>/.cookie)
                     <network> is the lowercase network name, e.g. ~/.cache/kogany/testnet/.cookie

RPCs: the stock Ycash RPCs, the vault primitive's set_* and vault_* RPCs and the Yellowback
yed_* RPCs, at rpcversion 9 (doc/ in the source tree has the contracts).

Licence: MIT or Apache-2.0, at your option (LICENSE-MIT, LICENSE-APACHE).
TXT
tar -czf "$out/$name.tar.gz" -C "$work" "$name"
tar -tzf "$out/$name.tar.gz"
