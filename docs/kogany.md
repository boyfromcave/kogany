# kogany and these documents

The documents in this directory are upstream Zakura's: they describe Zakura, a Zcash full node,
and they still describe kogany's architecture (the crates, state, sync, the P2P stack and the RPC
server are Zakura's). kogany is the Ycash developers' fork of Zakura; its `ycash` build,
`koganyd`, is a Ycash full node carrying the vault network upgrade and the Ycash Yellowback (YED)
rule module.

Where these documents name a Zcash value, a `koganyd` uses Ycash's instead:

| Zakura (Zcash) | kogany (Ycash) |
| --- | --- |
| package `zakura`, binary `zakurad`, user agent `/Zakura:<version>/` | package `kogany`, binary `koganyd`, user agent `/koganyd:<version>/` |
| version `1.7.0+<n>.g<sha>` (`<n>` since an upstream `v*` tag) | version `1.8.0-rc0+kogany.<n>.g<sha>` (`<n>` since `kogany-ycash-baseline`; see [Versioning](../README.md#versioning)) |
| config `zakura.toml`, cache directory `zakura/`, identity `~/.zakura` | config `kogany.toml`, cache directory `kogany/`, identity `~/.kogany` |
| P2P 8233 / 18233, RPC 8232 / 18232 | P2P 8833 / 18833 (`fast`) / 18933 (`slow`) / 18344 (regtest), RPC 8832 / 18832 / 18932 / 18832 |
| Zcash's DNS seeders | `seed.ycash.xyz` (mainnet) |
| Zakura P2P v2 (`p2p_stack` `dual` or `zakura`) | legacy TCP only (decision K-11) |
| NU5, NU6, NU6.1, Orchard | not active on Ycash; the Ycash upgrade, then Blossom, Heartwood, Canopy, then Vault |
| `zs…`, `t1…` addresses | `ys…`, `s1…`, post-quantum `sq…`, Yellowback `yb…` |

[README.md](../README.md) has the full table, how to build and run each network, and the pointers
to the Yellowback and vault RPC documents in [`doc/`](../doc/).
