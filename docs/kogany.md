# kogany and these documents

The documents in this directory are upstream Zakura's: they describe Zakura, a Zcash full node,
and they still describe kogany's architecture (the crates, state, sync, the P2P stack and the RPC
server are Zakura's). Kogany (from the Japanese _kogane_, 黄金, "gold": the Ycash node with
vaults) is the Ycash developers' fork of Zakura; its `ycash` build,
`koganyd`, is a Ycash full node carrying the vault network upgrade and the Ycash Yellowback (YED)
rule module.

Where these documents name a Zcash value, a `koganyd` uses Ycash's instead:

| Zakura (Zcash) | kogany (Ycash) |
| --- | --- |
| package `zakura`, binary `zakurad`, user agent `/Zakura:<version>/` | package `kogany`, binary `koganyd`, user agent `/koganyd:<version>/` |
| version `1.7.0+<n>.g<sha>` (`<n>` since an upstream `v*` tag) | version `1.8.0-rc1+kogany.<n>.g<sha>` (`<n>` since `kogany-ycash-baseline`; see [Versioning](../README.md#versioning)) |
| config `zakura.toml`, cache directory `zakura/`, identity `~/.zakura` | config `kogany.toml`, cache directory `kogany/`, identity `~/.kogany` |
| P2P 8233 / 18233, RPC 8232 / 18232 | P2P 8833 / 18833 (`fast`) / 18933 (`slow`) / 18344 (regtest), RPC 8832 / 18832 / 18932 / 18832 ([Ports](../README.md#ports)) |
| Zcash's DNS seeders | `seed.ycash.xyz` (mainnet) |
| Zakura P2P v2 (`p2p_stack` `dual` or `zakura`) | legacy TCP only (decision K-11) |
| NU5, NU6, NU6.1, Orchard | not active on Ycash; the Ycash upgrade, then Blossom, Heartwood, Canopy, then Vault |
| `zs…`, `t1…` addresses | `ys…`, `s1…`, post-quantum `sq…`, Yellowback `yb…` |

[README.md](../README.md) has the full table, how to build and run each network, and the pointers
to the Yellowback and vault RPC documents in [`doc/`](../doc/).

## Where a `koganyd` behaves as ycashd does

The Yellowback parity gate (S5) runs ycash6's functional scripts against kogany; these node
behaviours follow ycashd's there, each against Zakura's own:

- **Peers.** `disconnectnode "ip:port"` closes the connections to that node (`-29` "Node not found
  in connected nodes" when there are none) and keeps its address out of the address book until
  `addnode` names it again, so it is not redialled (also when no connection was open: an `addnode`
  address stays in the book, where ycashd's `onetry` node is never redialled). `addnode "ip:port" onetry` dials a node now,
  where `add` of a known address waits out its two-minute reconnection delay. A gossiped address
  that ycashd's address manager refuses as not routable (loopback, RFC 1918 and the other reserved
  ranges, `CNetAddr::IsRoutable`) is not kept, so a regtest node connects only to the nodes
  `addnode` names; operator addresses (`addnode`, the initial peers, the disk cache) are kept
  whatever their range.
- **Reorgs and restarts.** The transactions of a block that leaves the best chain (a reorg, an
  `invalidateblock`) return to the mempool and are verified at the new tip, as ycashd's
  `DisconnectTip` resurrects them; the mempool keeps the last 100 best-chain blocks' transactions
  for this. The non-finalized blocks are written to the backup directory before each tip update,
  so a stopped node restarts at the tip it reported.
- **Templates.** `getblocktemplate` has no limit on unpaid ZIP-317 actions by default, as ycashd's
  `-blockunpaidactionlimit` default (`SIZE_MAX`): a transaction that pays the relay fee but less
  than the conventional fee, such as a post-quantum owner spend, is mined.
  `mining.block_unpaid_action_limit` sets the limit (`0`: Zakura's rule, ycashd
  `-blockunpaidactionlimit=0`).
- **The YED payout key.** A transparent P2PKH `mining.miner_address` is also the Yellowback payout
  key the coinbase tag names, as ycashd takes `-mineraddress` when no `-yellowbackpayoutaddress`
  is set. `mining.yellowback_payout_default = false` (ycashd `-yellowbackpayoutdefault=0`, default
  on) leaves the node without a payout key: it emits no tag and `yed_setquote` refuses
  `no-payout-address`, as a ycashd mining to its wallet does. A Yellowback-live node can then mine
  to a transparent address without naming a payout key.
- **Transaction relay.** An inv-announced transaction id the per-peer download cap
  (`MAX_INBOUND_CONCURRENCY_PER_PEER`, 5) refuses is kept, bounded, and requested again when a
  slot frees, as ycashd keeps every announced id in its request queue: a burst of announcements is
  fully downloaded.

## Where a `koganyd` answers differently from ycashd

These differences are kept: the RPC server is upstream Zakura's, and the wallet in front of a
`koganyd` (yewd, in yew's `yewd/`) gives users ycashd's answers.

- **Wrong argument counts.** A call with too few or too many arguments answers `-1`
  "Invalid params" (jsonrpsee, every method of `zakura-rpc` and `kogany-rpc`). ycashd checks the
  count in its RPC table before the handler and answers `-32602` "Not enough parameters for
  method `<m>`. Needed …" (or "Too many parameters …") followed by the method's help text. The
  beta2 decision (2026-11-12): the fix lives in the façade, not here. yewd
  answers ycashd's `-32602` with ycashd's help for every method it forwards to `koganyd`
  (`yewd/facade/src/ycashd_rpc.json`, the `forwarded` section). Clients that call `koganyd`
  directly see `-1`.
- **Wallet fields.** `koganyd` has no wallet. It omits `ismine` / `iswatchonly`
  (`validateaddress`, `z_validateaddress`), `wallet` (`vault_list` rows), the wallet half of
  `getinfo` (`balance`, `keypoolsize`, `keypoololdest`, `walletversion`) and
  `protectedByIndex: true` (`yed_getinfo`). yewd adds them from its wallet.
- **`getaddressbalance` has no `txcount`.** ycash6 added the count of distinct transactions
  (`src/rpc/misc.cpp`, before beta2); `koganyd` answers `balance` and `received` only.
- **Node fields from Zakura.** `getblockchaininfo` has no `upgrades.<id>.info`, `softforks`,
  `transactions`, `fullyNotified` or `initial_block_download_complete`, and adds
  `nsmValueBalanceZat`. `getnetworkinfo` has no `warningstimestamp`. `getmininginfo` has no
  `difficulty`, `errors`, `errorstimestamp`, `generate`, `genproclimit`, `localsolps` or
  `pooledtx`.

For post-quantum addresses (`sqf…`/`sqs…`, the YED `ybf…`/`ybs…`), the answers match ycashd's
field for field (2026-11-12, regtest, `koganyd` against ycash6 6.22.0-beta2):
`validateaddress` (with `pqscheme`, `pqschemename`, `pqkeyhash`), `z_validateaddress`
(see below),
`getaddressutxos` (with and without `chainInfo`), `getaddresstxids`, `getaddressdeltas`,
`getaddressmempool` (apart from `timestamp`, each node's own arrival time), `getaddressbalance`
(apart from `txcount`, above), `yed_listtokens`, `yed_getvault`, `yed_gettxinfo`, `yed_listvaults`,
`vault_decodescript`, `vault_list`, `set_getinfo` and `vault_getinfo`.

`z_validateaddress` of a post-quantum address answers `isvalid` true, `address`, `address_type`
and `type` `"pq"`, `pqscheme`, `pqschemename` and `pqkeyhash`, as ycashd does since the beta2
audit's L-4 fix (ycash6 #107, ycash-dd #176; before it, both nodes answered `isvalid` false).
What was measured, 2026-11-12: live on regtest, `crates/kogany-rpc/qa/rpc_ycash_parity.py`
asked `koganyd` (kogany #26) and ycash6 6.22.0-beta2 (`up/b2-wallet-followups-stack` @
82f90b2f9) `validateaddress` and `z_validateaddress` for 32 D-9 rows of
`testdata/yellowback/pq_address_vectors.json` (each network's `sqf…`/`sqs…`-style form of both
schemes, the YED forms, regtest's invalid rows); every field agreed except `z_validateaddress`'s
`ismine` for the two regtest addresses (see "Wallet fields"). The unit test in
`crates/zakura-rpc/src/methods/types/z_validate_address.rs` checks the answer for every vector
on all three networks. ycash-dd was not compared live; its answer has `type` but no
`address_type`.
