# kogany mainnet sync gate: results (W1-Y4 / W1-Y8)

kogany (`zakurad --features ycash`, release build, Zakura state format 30.2.0) syncs Ycash
mainnet from live peers with the partial checkpoint list
`crates/zakura-chain/src/parameters/checkpoint/ycash-main-checkpoints.txt`, stopping at each
snapshot height H (`[state] debug_stop_at_height = H`). `qa/kogany_sync_gate.py` compares it with
a ycash6 node (65cb4ae0f) block by block up to H, resuming its state file
(`wt/.data/kogany-mainnet/gate/state.json`). After kogany stops, the cache is reopened by an
isolated instance (no peers) to finish the comparison through H and read `getblockchaininfo`.

The Y8 gate wants zero mismatches and zero rejected blocks.

| H | kogany tip | hash at H (kogany = ycash6) | compared through | mismatches | rejected | list reaches |
|---|---|---|---|---|---|---|
| 570,000 | 570,000 | `0000014fbc5917ba8bcacf3336faf588d86b32443aa3a490a587af5750c77ec5` | 570,000 | 3,922 (all RPC-encoding, below) | 0 | 763,686 (PARTIAL) |
| 1,100,006 | 1,100,006 | `00000388cfe0577f8f2264f001b8ae213f477571af4e873b7d27e54e612205d5` | 1,100,006 | 4,097 (4,094 RPC-encoding, 3 driver-side ZIP-221 off-by-one, below) | 0 | 1,519,286 (PARTIAL) |
