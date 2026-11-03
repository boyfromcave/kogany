# kogany: the Ycash Yellowback (YED) and vault upgrade review package

This is the review document the kogany plan asks for in chunk W9-d (workspace
`docs/plans/kogany/kogany-yellowback-plan.md` §3 W9, §4.1, §6). It covers what kogany carries
on top of Zakura to be a Ycash node with the vault network upgrade and the Yellowback rule
module, how big that delta is against the plan's budget, where it touches upstream files and
why, what shows that Zakura's own upgrades stayed dormant, what shows that kogany agrees with the
C++ lines, the parity sidecar `yewd`, the known gaps, and the §6 demonstration as far as recorded
runs carry it.

Ycash Yellowback (YED) is the system and YED its unit (workspace AGENTS.md rule 6). Decisions are
the Yellowback lead architect's. "Owner" appears only as the vault protocol term.

**Trees and commits.** Every figure and citation is at these commits unless a row names another.

| Tree | Branch | Commit |
|---|---|---|
| kogany | `vaults/kogany-compat` | `18650e75c` (2026-11-02) |
| kogany baselines | tags | `kogany-legacy` = Zakura `main` `2b062412c5`; `kogany-baseline` = `7924d1627` (W0); `kogany-ycash-baseline` = `82ca62e27` (W1 complete) |
| zakura-common-ycash (the common fork, K-2) | `vaults/kogany-compat` | `e5515523` (kogany pins `1e6d6aa4`; `zakura-common-ycash-legacy` = `bdbca121628d`) |
| ycash6 | `vaults/kogany-compat` | `fb22e4528` (the vectors and the oracle: `65cb4ae0f`) |
| ycash-dd | `vaults/kogany-compat` | `b74546671` |
| yew (`yewd` in `yew/yewd/`) | `vaults/kogany-compat` | `da37a5327` |
| lightwalletd-dd, chain-viz, hawkeye, x402-ycash, yolo, ycash-infra | `vaults/kogany-compat` | `384e11288`, `a6fe21993`, `114b5ae43`, `f0ac37a43`, `cfe46056c`, `c6647c489` |
| workspace | `vaults/kogany-compat` | `f1baa26` |

Paths without a repository name are kogany paths. `ycash6/…` is at `65cb4ae0f` unless a commit is
named. The plan's findings log is §9 (KF-01 … KF-85) and its mapping rows are workspace
`docs/mapping.md` §24 (M24-1 … M24-91).

---

## 1. State at this review (2026-11-02)

| Wave / chunk | State | Merge (kogany unless named) |
|---|---|---|
| W0 scaffolding | done | `7924d1627` (tag `kogany-baseline`), CI restructure `0e87abadc` |
| W1 Ycash on Zakura (Y0–Y9) | done except the testnet sync | Y1–Y3 `679d3870b`, Y5 `96a28eceb`, Y6 `5f38ea2aa`, Y9 `e62179e97`, Y4/Y8 `82ca62e27` (tag `kogany-ycash-baseline`), harness ycash6 `f4967b0d7` |
| W2 the Vault epoch | done | fork `7281d463`, `10b5d699f`, `f1d8220fd` |
| W3 script and post-quantum verification | done | fork `2773f4a4`, W3-b and W3-a in the baseline, `9498671a5`, `9d470fb7c`, `709195d08`, F-1 `997e83c3a` |
| W4 the vault primitive | done | `7a23a09da`, `4b8c75d3a`, `377ad54bd`, `298f813de`, `54788bef4` |
| W5 the YED rule module | done | `f30918149`, `9316a0c9d`, `980a6c342`, `f6b1db189`, `90edb0917`, `2804973bf` |
| W6 relay policy and mempool | done | `34bdc2729`, `f299e69a4`, `6b61bcc82` |
| W7 read RPCs | done | `c8d74c30e`, `5b31db972`, `52e9a4dba`, `ebde83aa7`, `37610d7f9`, live reads `25518495f` |
| W8 mining | done | `48007895c`, `d27a880fe` |
| W9-a ycash6 test rig | done | ycash6 `84672c619` |
| W9-b the whole suite mixed, three-way devnet | in flight | `kc/w9-mixed` (kogany, ycash6) |
| W9-c client legs | done (report-only legs) | `be2c5ce` (yew), `1ad0e8c`, `44a8a98`, `b8e9471`, `859fa68`, `576754d`, `cb19adb`; kogany `25518495f` |
| W9-d this review | this document | `kc/w9-review` |
| S0–S4 `yewd` | done (gates run on ycash6 `-disablewallet` backends) | yew `0c63678`, `3679eff`, `cd72fb4`, `85aec6f`, `da37a53` |
| S5 the parity gate | in flight | `kc/yewd-s5` (yew, ycash6) |
| KP-1 … KP-4 pruned kogany | done | `b6e077022`; ycash-infra `1181bfb`; lightwalletd-dd `c350515` |
| koganyd identity, Docker | done (Docker image not yet built) | `5582c1f87`, `18650e75c`; ycash-infra `c6647c4` |
| Upstream sync to Zakura `b44ec121d` | blocked on a common-fork sync (Common rc.2 → rc.4) | `kc/sync-zakura-20261102` |

---

## 2. Budget actuals (plan §4.1)

**Method.** `git diff --numstat` over the integration branch, each line counted once, classified
by path: the consensus path set is `qa/kogany-consensus-paths.txt` (the W0-d list audit leg (a)
reads); "upstream" is every other file under an upstream crate; "kogany crates" is
`crates/kogany-*`; "tests, qa, docs, data" is any test module or test directory, `qa/`,
`testdata/`, generated checkpoint lists, docs, CI, lock and config files. Production lines in
`crates/kogany-*/src` include their few inline test modules (326 lines, all in `kogany-rpc`).
New files inside an upstream crate are counted apart from edits to files that existed at
`kogany-legacy`, because the plan's touch budget estimated edits to upstream files and did not
expect new files in upstream crates. The per-wave rows sum each first-parent merge's own diff, so
they add to a little more than the end-to-end totals (a few lines were changed twice).

**The base.** The plan says "against `kogany-baseline`". That tag is the W0-b merge `7924d1627`,
which already holds the nine pinned vector files and three pure crates merged ahead of their
waves (KF-01): W3-b `kogany-pq` with its vendored C, W4-a's `kogany-vault` templates and acts,
W5-a's `kogany-yellowback` math and parameters. Measured from `kogany-baseline`, those 4,238
production lines and 7,204 lines of vendored C disappear. So the tables below measure from
`kogany-legacy` (= Zakura `2b062412c5`), and the last table gives both bases (KF-81).

### 2.1 Per wave, against the §4.1 estimates

| Wave | Upstream files edited, consensus / other | New files in upstream crates, consensus / other | §4.1 touch estimate | Touch actual (all four) | New `kogany-*` production | §4.1 estimate | Tests, qa, docs, data |
|---|---|---|---|---|---|---|---|
| W0 | +9 / +0 | 0 / +128 (CI ignore files) | CI/YAML only | +137 | 0 | 0 | +4,051 |
| W1 | +517 −74 / +284 −11 | +615 / +416 | 2.2–3.7k | **1,832** | 0 | ~0.3k | +11,809 (9,089 generated checkpoints) |
| W2 | +146 −18 / +50 −3 | +27 / +60 | 250–400 | **283** | 0 | 0 | +12,380 (10,664 pinned vectors) |
| W3 | +159 −6 / +36 | +463 / 0 | 500–800 | **658** | +810 (+7,204 vendored C) | ~0.5k + 6k | +8,424 |
| W3-c F-1 and W9-a F-6 (one merge) | +72 / +181 −5 | +16 / +335 | — | 604 | 0 | — | +468 |
| W4 | +213 −23 / +178 −4 | +973 / +164 | 600–900 | **1,528** (+70 % over the top) | +4,279 | 3–4k | +9,163 |
| W5 | +83 −12 / +108 −1 | +1,230 / +826 | ≤ 150 | **2,247** (15×) | +12,755 | 7.3–9.2k | +19,228 |
| W6 | +163 −14 / +333 −5 | +1,435 / +756 | 500–900 | **2,687** (3×) | +542 | 0.4–0.6k | +1,763 |
| W7 | +158 / +297 −22 | 0 / +2,568 | ≤ 150 | **3,023** (20×) | +9,120 | 2.6–3.5k | +11,595 |
| W8 | 0 / +223 −4 | 0 / +777 | 300–700 | **1,000** (+43 %) | +243 | 0.2k | +1,185 |
| KP-1…4 (pruning) | 0 / +16 | 0 / +32 | — | 48 | +250 | — | +231 |
| koganyd identity, Docker | +3 −1 / +199 −63 | +24 / +131 | — | 357 | 0 | — | +1,412 |
| CI restructure | 0 | 0 | — | 0 | 0 | — | +1,521 |

In the touch column, a bold figure more than 25 % above the estimate's top is the §4.1 stop rule:
"a wave that exceeds its touch budget by more than 25 % stops for a findings row and a
coordinator decision before it merges." W4, W5, W6, W7 and W8 crossed it; none stopped, because
the budget is report-only and the audit leg reports instead of failing. KF-82 is that findings
row, and the decision is the lead architect's at the W9 gate. The pattern explains the excess:
the integration code (the vault and YED column families and their write path in `zakura-state`,
the Ycash standardness and the vault mempool checks in `zakura-consensus`, the reject table, script
shapes and template code in `zakura-rpc`, the mempool re-check and retries in `zakurad`) went into
**new files inside upstream crates** rather than into `kogany-*` crates, because it needs those
crates' private types. Edits to files upstream already had are 3,431 lines in all, below the
plan's 4.8–7.7k estimate.

### 2.2 Totals, both bases

| Category | `kogany-legacy..HEAD` | `kogany-baseline..HEAD` | §4.1 estimate |
|---|---|---|---|
| Consensus-path files edited (43 files) | +1,452 / −77 | +1,450 / −84 | (part of the touch budget) |
| Consensus-path files new (16 files, without the 2 checkpoint lists) | +4,730 | +4,730 | — |
| Other upstream files edited (50 files) | +1,899 / −109 | +1,899 / −109 | (part of the touch budget) |
| Other upstream files new (20 files) | +6,143 | +6,015 | — |
| **Upstream touch, all four** | **14,224 / −186** | **14,094 / −193** | **4.8–7.7k** |
| New `kogany-*` crate production (80 files) | +27,618 | +23,415 | 14.5–18.5k |
| Vendored verify-only PQ C (`crates/kogany-pq/csrc/`, 21 files) | +7,204 | 0 | ~6k |
| `kogany-*` crate tests | +31,313 | +27,216 | (part of tests) |
| Upstream crate tests | +12,174 / −42 | | |
| `qa/` | +9,062 | | |
| `testdata/` (the nine pinned vectors, the mainnet blocks) | +11,178 | | |
| Generated checkpoint lists | +9,089 | | ~7k |
| Docs (including the `make spec` copies) | +7,006 | | |
| CI, config, lock files, Docker | +4,731 | | |
| Frozen paths changed | **2 files** (§3.3) | | 0 |
| Common-fork edits (`zakura-common-ycash-legacy..1e6d6aa4`) | production +1,233 / −28, tests and CI +6,145 | | 0.9–1.3k |

The `kogany-*` production by crate: `kogany-pq` 303 lines of Rust, `kogany-vault` 4,049,
`kogany-yellowback` 12,437, `kogany-rpc` 10,012 (plus 326 inline test lines). Against the plan's
waves, `kogany-vault` is inside W4's 3–4k, `kogany-yellowback` is a third above W5's 7.3–9.2k,
and `kogany-rpc` is three times W7's 2.6–3.5k: the live index reads (`yed/live_index.rs`), the
attestation pool and the reject-text work were larger than the survey assumed.

The common fork's production delta is 1,233 lines, inside its 0.9–1.3k estimate; the largest files
are `crates/zcash_protocol/src/consensus.rs` (+437, the Ycash and Vault rows, most of it tests in
the module) and `crates/zcash_script/src/vault.rs` (+375, the four opcodes).

---

## 3. The hook table

### 3.1 The four-part checks, by chunk

Each chunk that changed a file under the consensus path set, with the four-part check (AGENTS.md
rule 4) and the in-tier rung from its commit body. "X" is what ycash6 does and where, "Z" what
Zakura has and lacks, "W" the adaptation. A row marked _reconstructed_ had no four-part check in
any of its commit bodies; W9-d wrote it from the merge message and the diff (KF-80).

| Chunk | Commits (kc → merge) | X (ycash6) | Z (Zakura lacks) | W (adaptation) | Rung |
|---|---|---|---|---|---|
| W0-b, W1-Y0 | `1da36903e`, `ec6bfcf06` → `7924d1627` | patches every `zcash_*` crate to one librustzcash6 rev and learns the Ycash branch from the patched `zcash_protocol` | 25 Common crates locked from crates.io, no Ycash row | `[patch.crates-io]` over the whole closure at one fork rev; the conversion kept total by a placeholder arm (`parameters/network.rs`, `network_upgrade.rs`) | no rule change |
| W2-a | `b01242379` → `10b5d699f` | learns Vault from librustzcash6 `BranchId::Vault` | no Vault row | placeholder arms until W2-b, no height on any network | no rule change |
| W1-Y1 | `2186f3fc7`, `9b4c2ec6d` → `679d3870b` | Ycash identity in `CMainParams`/`CTestNet*Params` (`src/chainparams.cpp:87-690`), epoch IDs in `NetworkUpgradeInfo` (`src/consensus/upgrades.cpp:12-99`) | compile-time Zcash tables keyed on `Network::Mainnet`; no Ycash upgrade, no second chain profile | `NetworkUpgrade::Ycash` between Sapling and Blossom in every build; `cfg(feature = "ycash")` swaps of the tables; data in `parameters/ycash.rs`; one Sapling-era arm per exhaustive match (including the frozen `halo2.rs`) | parameters only; a runtime `Network::Ycash` would touch ~641 sites (K-5) |
| W1-Y2 | `abc9975c4` → `679d3870b` | checks solution size without context (`src/pow.cpp:155-191`), then against the height (`src/main.cpp:5757-5774`) | `Solution::check` binds (n, k) to the network, no 400-byte form (`work/equihash.rs:95-136` at the pin) | `Solution::Ycash([u8; 400])`, (n, k) from network and height, size never selects parameters; the header chain's policy takes the height | parameter selection in existing code |
| W1-Y3 | `c55956569` → `679d3870b` | YDF in `ContextualCheckBlock` (`src/main.cpp:6248-6286`) over `GetFoundersRewardScriptAtHeight` (`src/chainparams.cpp:1009-1072`) | founders' reward ends at the first halving; funding streams P2SH-only with fixed fractions (`block/check.rs:205-300`) | `ydf_reward_is_valid` in `subsidy_is_valid` under `ycash`, the lists in `parameters/ycash/ydf.rs`, founders' check skipped from the Ycash upgrade | rule port, no new rule design |
| W1-Y4 | `bf961d73a`, `d44d19f78`, `a453ff925`, `b5ba9b111` → `2f9b1af3b`, `a9d104d2b`, `82ca62e27`; `1eca93d3f` | _reconstructed:_ sparse checkpoints and the fork-block pin (`src/chainparams.cpp:131-132,242-283` at the pin) | a dense Zcash list, and Zcash-mainnet fast-sync artefacts (frontier grid, subtrees, VCT) | Ycash lists generated from a ycash6 node by `qa/kogany_checkpoints.py` with every ycashd pin asserted and never into the Vault epoch (M24-14); a `PARTIAL` list is accepted and blocks past it fail safe as `TooHigh`/`Finished` (`consensus/src/router.rs`, `checkpoint.rs`); the artefacts off on Ycash networks (`vct.rs`, `treestate_artifact.rs`, K-12) | data and a fail-safe; no rule change |
| W1-Y9 | `f62756ee4` → `e62179e97` | relay fee and standardness in `AcceptToMemoryPool` (`minRelayTxFee`, `PerSaplingOutputFees`, `IsStandardTx` gated on `RequireStandard()`, `IsExpiringSoonTx`, ZIP-317 limit off) | ZIP-317 `mempool_checks` only | `transaction/unmined/ycash_relay.rs` replaces the ZIP-317 call under `ycash`; storage-time policy in `zakurad` | relay policy, below every consensus rung |
| W2-b | `93cfe484c`, `ee6b52259` → `f1d8220fd` | Vault as a height-gated upgrade with its own branch ID; U-26 start-up refusals (`src/init.cpp:1541-1565`) | the enum order is the feature gate; `activation_height` falls back to the next upgrade (M24-1, M24-2); no schedule rule (M24-7) | `NetworkUpgrade::Vault` between Canopy and Nu5 with Canopy's behaviour in every match; `Network::is_vault_active` as the only Vault question (grep guard); U-26 as builder errors; unscheduled upgrades not observable | enum-variant data plus a parameter predicate |
| W3-c | `d65773dc8` → `9498671a5` | script flags from the height (`GetVaultScriptFlags`, `src/main.cpp:845`), `vault::SetSigChecker` over an immutable snapshot (`src/vault/checker.cpp`) | constant `P2SH \| CLTV` flags (`zakura-script/src/lib.rs:170` at the pin); `script::Request` = (tx, input) | `ScriptContext` (network, height, optional snapshot; `None` fails closed) through `script::Request`; flags from (network, height); `YcashSignatureChecker` in `zakura-script/src/ycash.rs` | verifier plumbing the opcode rung needs |
| W3-c F-1 | `7240ef2a3` → `997e83c3a` | `IsPQFalconActive` = Vault active and h ≥ `pqFalconHeight`, settable on regtest (`src/chainparams.cpp:921-988`) | no non-upgrade consensus height | `ConfiguredActivationHeights::pq_falcon` (`pq_falcon_height`), read through `Network::pq_falcon_height` | a network parameter |
| W3-d | `b5640ec44` → `9d470fb7c` | BIP68 via `CalculateSequenceLocks`/`ContextualCheckSequenceLocks` (`src/main.cpp:854,892-903`) | no sequence locks; the spent output's height is in `transparent::Utxo.height` | `zakura-state/src/service/check/sequence_locks.rs` at the block call site and the mempool branch | a transaction rule over an existing field, per-coin state already stored |
| W3-e | `755b3201a` → `709195d08` | `TX_PQPKH` in `Solver`, `CPQKeyID` in `ExtractDestination` (`src/script/standard.cpp:67,151`) | the solver's `ScriptKind` has no PQ form; `transparent::Address` none either | `YcashScriptKind` and `transparent::Destination` beside the upstream types; the act writer's zero key | policy and RPC input; the act fix aligns a primitive parser |
| W4-c | `6fdf33d30` → `4b8c75d3a` | set state in LevelDB with a 4,096-deep undo (`src/vault/db.*`), replayed on `-reindex` | one RocksDB write path; checkpoint commits skip contextual validation; no per-fork vault state | four column families with canonical keys, the transition in `prepare_block_batch` for every commit, `UpdateWith<VaultDelta>` on forks, format 30.1.0, `rollback` refusing past Vault | per-vault state (state rung) |
| W4-d | `eb73007c0` → `377ad54bd` | one snapshot after the parent for every script of a block (`src/main.cpp:3681-3691`), the acts applied sequentially (`:4344-4351`) | concurrent per-transaction verification; no chain state in the script request (M24-11, M24-15) | `ReadRequest::VaultSnapshot`/`Request::AwaitVaultSnapshot` by parent hash; `check::vault` rejecting at DoS 100; `vault_network_params` wired to the real height | none new (M24-15) |
| W4-d follow-ups | `787a51553`, `1a0b67e65` → `54788bef4` | `vault::CheckTx` over the tip snapshot at the next height in `AcceptToMemoryPool`, DoS 0 (10 for a byte-level act failure) (`src/main.cpp:2196-2202`) | the vault rules ran only in block validation | `zakura_state::vault::mempool_vault_check` in the verifier's mempool branch, `TransactionError::VaultRejected`, peer action `Ignore` | none new |
| W5-e | `0c0a97841` → `90edb0917` | the YED index in its own LevelDB with undo `U` 4,096 deep, `AbortNode` when it cannot evaluate (`src/main.cpp:4358`) | no module index, no undo on the write path, no abort hook | 19 `yed_*` column families plus `yed_undo`, `yed_rules`; `evaluate_block` in the same atomic batch; `YedEvaluationFailed` stops the node; format 30.2.0 | per-module state |
| W5-f | `71b1550cb` → `2804973bf` | registers `yellowback::Module` for `YED\0`, hands it ancestor hashes (`src/main.cpp:4348`), rejects at DoS 100 (`:4355-4359`) | inert `YED\0`, no ancestor hashes, no init-time global | `YedModule` built per transition with one node-wide `LruSigCache`; `check::yed` → `ValidateContextError::YedRejected`; the coinbase scriptSig handed to the module | module, per-module state |
| W6-a | `6e65d5a85`, `0ae02e8b1`, `d1077d640` → `34bdc2729` | _reconstructed:_ `IsStandardTx`/`AreInputsStandard` (`src/policy/policy.cpp:92,260`) gated on `RequireStandard()`, the Vault-era rules (YV act carrier to 1,200 bytes, V/I/PQPKH/PQCHANNEL standard, PQ dust, 9,000-byte PQ scriptSig, 20 sigops per `OP_CHECKPQSIG`) | the upstream mempool standardness knows none of them; P2PK classed by length | `transaction/check/ycash_standard.rs` (ycash only), the standard script flags on `ScriptContext`, the verifier pre-checks inputs only and storage keeps the output rules | relay policy |
| W6-b | `eeec0cba5`, `e9116007d` → `f299e69a4` | _reconstructed:_ the attested fee (`AttestedFeePolicy`, `src/policy/policy.cpp:482`) is read only by the wallet, the builders and `yed_getinfo`, never in `AcceptToMemoryPool`; the YED mempool check (`MempoolCheckReason`) refuses in `AcceptToMemoryPool` | no fee policy, no YED mempool check | `kogany_yellowback::fee` (pure), `[mempool]` keys with ycashd's init checks, `TransactionError::YedMempoolRejected` scored 0; relay stays at W1-Y9's rules | node and wallet policy |
| W6-c | `f63d227a5` → `6b61bcc82` | `RemoveInvalidVaultSpends`/`RecheckMempool` on every tip change (`src/main.cpp:4790,4846,4866`), the CLTV retry, `removeExpired` | the mempool re-verifies only on `Reset` (M24-21) | the verifier's vault and YED mempool checks, `tip_recheck` on `Grow`, eviction with descendants, ycashd's expiry and CLTV-retry semantics | relay policy and mempool bookkeeping |
| W7-b live reads, W9-c | `486275370` → `25518495f` | indexes a `TX_PQPKH` output under (P2PQPKH, Hash160(scheme ‖ keyHash)) in the insight index | `transparent::Address` has no post-quantum form | `transparent::Address::PayToPqKeyHash`, disk variants 6/7 | address index, not consensus |
| koganyd identity | `d3857f636` → `5582c1f87` | ycashd's own names (`.ycash`, `ycash.conf`, `ycashd`) | Zcash names for directories, binary and config | compile-time kogany names under `ycash` | node identity, not consensus |

### 3.2 Every file under the consensus path set

63 production files: 45 edited (the two `Cargo.toml` files included) and 18 new (the two
generated checkpoint lists included); §2's line counts leave the `Cargo.toml` files and the lists to
the config and data rows. The chunk labels match §3.1. Test files under the same paths are listed
after the table by count.

| File | | Lines | Chunks |
|---|---|---|---|
| `crates/zakura-chain/src/block/commitment.rs` | edit | +3 / −3 | Y1–Y3, W2-b |
| `crates/zakura-chain/src/parameters.rs` | edit | +6 / −0 | Y1–Y3, W2-b |
| `crates/zakura-chain/src/parameters/checkpoint/list.rs` | edit | +59 / −6 | Y4 |
| `crates/zakura-chain/src/parameters/checkpoint/ycash-main-checkpoints.txt` | new | +7,807 | Y4, Y8 (generated, 7,803 checkpoints) |
| `crates/zakura-chain/src/parameters/checkpoint/ycash-test-checkpoints.txt` | new | +1,282 | Y4 (generated) |
| `crates/zakura-chain/src/parameters/constants.rs` | edit | +2 / −0 | Y1–Y3 |
| `crates/zakura-chain/src/parameters/network.rs` | edit | +17 / −0 | W0-b/Y0, W2-a, Y1–Y3, W2-b |
| `crates/zakura-chain/src/parameters/network/error.rs` | edit | +12 / −0 | Y1–Y3, W2-b |
| `crates/zakura-chain/src/parameters/network/subsidy.rs` | edit | +21 / −0 | Y1–Y3 |
| `crates/zakura-chain/src/parameters/network/subsidy/constants/mainnet.rs` | edit | +3 / −0 | Y1–Y3 |
| `crates/zakura-chain/src/parameters/network/subsidy/constants/testnet.rs` | edit | +3 / −0 | Y1–Y3 |
| `crates/zakura-chain/src/parameters/network/testnet.rs` | edit | +172 / −1 | Y1–Y3, W2-b, Y4, W3-c F-1 |
| `crates/zakura-chain/src/parameters/network_upgrade.rs` | edit | +128 / −4 | W0-b/Y0, W2-a, Y1–Y3, W2-b, W3-c F-1 |
| `crates/zakura-chain/src/parameters/ycash.rs` | new | +238 | Y1–Y3, W2-b, identity |
| `crates/zakura-chain/src/parameters/ycash/ydf.rs` | new | +296 | Y1–Y3 |
| `crates/zakura-chain/src/transaction.rs` | edit | +2 / −0 | Y9 |
| `crates/zakura-chain/src/transaction/arbitrary.rs` | edit | +5 / −3 | Y1–Y3, W2-b |
| `crates/zakura-chain/src/transaction/unmined.rs` | edit | +8 / −0 | Y9 |
| `crates/zakura-chain/src/transaction/unmined/ycash_relay.rs` | new | +175 | Y9, W6-b |
| `crates/zakura-chain/src/transaction/unmined/zip317.rs` | edit | +5 / −0 | Y9 |
| `crates/zakura-chain/src/transparent.rs` | edit | +17 / −0 | W3-e, W7-b live/W9-c, identity |
| `crates/zakura-chain/src/transparent/address.rs` | edit | +141 / −0 | W7-b live/W9-c, identity |
| `crates/zakura-chain/src/transparent/destination.rs` | new | +88 | W3-e |
| `crates/zakura-chain/src/work/equihash.rs` | edit | +128 / −34 | Y1–Y3 |
| `crates/zakura-consensus/Cargo.toml` | edit | +16 / −0 | Y1–Y3, W3-e, W4-d, W6-a |
| `crates/zakura-consensus/src/block.rs` | edit | +34 / −1 | Y1–Y3, W4-d |
| `crates/zakura-consensus/src/block/check.rs` | edit | +46 / −3 | Y1–Y3 |
| `crates/zakura-consensus/src/checkpoint.rs` | edit | +7 / −1 | Y1–Y3, Y4 |
| `crates/zakura-consensus/src/error.rs` | edit | +82 / −0 | W4-d follow-ups, W6-c |
| `crates/zakura-consensus/src/primitives/halo2.rs` | edit (frozen) | +2 / −2 | Y1–Y3, W2-b |
| `crates/zakura-consensus/src/router.rs` | edit | +26 / −2 | Y4 |
| `crates/zakura-consensus/src/script.rs` | edit | +9 / −3 | W3-c |
| `crates/zakura-consensus/src/transaction.rs` | edit | +202 / −3 | Y1–Y3, W2-b, W3-c, W3-d, Y9, W4-d, W6-a, W4-d follow-ups, W6-c, W5-f |
| `crates/zakura-consensus/src/transaction/check.rs` | edit | +71 / −0 | W3-d, W3-e, W6-a |
| `crates/zakura-consensus/src/transaction/check/ycash_standard.rs` | new | +928 | W6-a, W6-c |
| `crates/zakura-consensus/src/transaction/vault_mempool.rs` | new | +405 | W6-c |
| `crates/zakura-header-chain/src/validation/context_free/pow_policy.rs` | edit | +10 / −3 | Y1–Y3 |
| `crates/zakura-header-chain/src/validation/context_free/trusted_anchor.rs` | edit | +1 / −1 | Y1–Y3 |
| `crates/zakura-header-chain/src/validation/prepare/pipeline.rs` | edit | +1 / −1 | Y1–Y3 |
| `crates/zakura-script/Cargo.toml` | edit | +5 / −0 | W3-c |
| `crates/zakura-script/src/lib.rs` | edit | +40 / −2 | W3-c, W6-a |
| `crates/zakura-script/src/ycash.rs` | new | +288 | W3-c, W6-a, W6-c, W3-c F-1 |
| `crates/zakura-state/src/service/check.rs` | edit | +7 / −0 | W3-d, W4-d, W5-f |
| `crates/zakura-state/src/service/check/sequence_locks.rs` | new | +134 | W3-d |
| `crates/zakura-state/src/service/check/vault.rs` | new | +75 | W4-d, W5-f |
| `crates/zakura-state/src/service/check/yed.rs` | new | +53 | W5-f |
| `crates/zakura-state/src/service/finalized_state.rs` | edit | +29 / −0 | W4-c, W5-e |
| `crates/zakura-state/src/service/finalized_state/disk_format/transparent.rs` | edit | +6 / −0 | W7-b live/W9-c |
| `crates/zakura-state/src/service/finalized_state/disk_format/upgrade.rs` | edit | +13 / −2 | W4-c, W5-e |
| `crates/zakura-state/src/service/finalized_state/disk_format/upgrade/add_vault_state.rs` | new | +87 | W4-c |
| `crates/zakura-state/src/service/finalized_state/disk_format/upgrade/add_yed_state.rs` | new | +86 | W5-e |
| `crates/zakura-state/src/service/finalized_state/treestate_artifact.rs` | edit | +8 / −0 | Y4 |
| `crates/zakura-state/src/service/finalized_state/vct.rs` | edit | +15 / −0 | Y4, Y4 fix `1eca93d3f` |
| `crates/zakura-state/src/service/finalized_state/vct_fast_sync_fixture.rs` | edit | +3 / −0 | Y1–Y3, W2-b, W3-c F-1 |
| `crates/zakura-state/src/service/finalized_state/zakura_db.rs` | edit | +4 / −0 | W4-c, W5-e |
| `crates/zakura-state/src/service/finalized_state/zakura_db/block.rs` | edit | +8 / −0 | W4-c, W5-e |
| `crates/zakura-state/src/service/finalized_state/zakura_db/rollback.rs` | edit | +37 / −0 | W4-c |
| `crates/zakura-state/src/service/finalized_state/zakura_db/vault.rs` | new | +606 | W4-c, W4-d, W5-f |
| `crates/zakura-state/src/service/finalized_state/zakura_db/yed.rs` | new | +841 | W5-e, W5-f, W3-c F-1 |
| `crates/zakura-state/src/service/non_finalized_state.rs` | edit | +31 / −1 | W4-c, W3-d, W5-e, W4-d, W5-f |
| `crates/zakura-state/src/service/non_finalized_state/chain.rs` | edit | +28 / −1 | W4-c, W5-e |
| `crates/zakura-state/src/service/non_finalized_state/chain/vault.rs` | new | +240 | W4-c |
| `crates/zakura-state/src/service/non_finalized_state/chain/yed.rs` | new | +190 | W5-e |

Test files under the consensus paths: 45 (25 edited, 20 new), +8,314 / −37 lines. The edited ones
are upstream tests that gained a Ycash or Vault arm, a height argument or a `vault: None` /
`ycash: None` field, plus eight RocksDB column-family snapshots (+23 names each); the reasons are
listed per file in the W1-Y1, W1-Y2 and W2-b commit bodies (`2186f3fc7`, `abc9975c4`,
`93cfe484c`). No upstream test function was deleted (§4).

**Forked-crate lock entries.** The six crates the audit compares (`zakura-protocol`,
`-primitives`, `-address`, `-transparent`, `-equihash` at `5.0.0-rc.2+ycash.1`,
`zakura-zcash-script` at `0.0.1`) are git-sourced from the fork at `1e6d6aa4`; their versions
equal `kogany-baseline`'s, only the rev moved (`qa/kogany_audit.py consensus-diff`).

### 3.3 Frozen files

`qa/kogany_audit.py frozen` against `kogany-legacy` reports two frozen files changed:

- `crates/zakura-consensus/src/primitives/halo2.rs`: the exhaustive match of
  `lazy_verifier_for` gains `Ycash` and `Vault` in the pre-NU6.2 arm (`:394-395`). The match is
  exhaustive, so a new `NetworkUpgrade` variant cannot compile without an arm; the arm is never
  reached on Ycash (no Orchard) and changes nothing on Zcash networks.
- `crates/zakura-consensus/tests/nu7_diff_dump.rs`: a test; the activation-heights literal gains
  `ycash`, `vault`, `pq_falcon` and the builder match gains two arms.

The plan's §3 W0-d says a non-zero frozen report is a §9 finding. The W1-Y1 commit named both
(`2186f3fc7`, "Frozen files touched"), but no §9 row recorded them until KF-79 here. Both are
forced by an exhaustive match on a new enum variant (M24-31's "wildcard-free" side), not edits of
Orchard, NU5–NU7 or Ironwood behaviour.

### 3.4 Upstream files outside the consensus path set

The rest of the upstream touch is RPC, network, mempool and tooling code (production `.rs` files
only):

| Crate | Files | Edited lines | New-file lines | Chunks |
|---|---|---|---|---|
| `zakura-rpc` | 19 | +642 / −30 | +2,978 | Y6, W2-b, W7-a, W7-c, W7-e, W8, Y8, live reads, koganyd |
| `zakurad` | 16 | +698 / −62 | +1,203 | Y9, W4-d, W6-b, W6-c, F-6, identity |
| `zakura-state` (outside `service/check`, `finalized_state`, `non_finalized_state`) | 11 | +326 / −2 | +920 | W4-c, W4-d, W5-e, W5-f, Y4 |
| `zakura-network` | 12 | +169 / −4 | +205 | Y5, W2-b, F-6, identity |
| `zakura-chain` (outside the consensus paths) | 5 | +27 / −3 | +60 | Y1, W2-b |
| `xtask` | 2 | +10 / −1 | +649 | W7-d (`check-rpc-artifacts`) |

---

## 4. Dormancy evidence

The plan's constraint is "gate, do not delete": Zakura's NU5–NU7 and Ironwood code stays compiled
and tested on the feature-off build (plan §2.5).

| Evidence | Result | Where recorded |
|---|---|---|
| Dormancy leg: every upstream test function at `kogany-legacy` still present | 6,580 at `kogany-legacy`, 7,137 at HEAD, **none missing** | `qa/kogany_audit.py dormancy`, run by W9-d at `18650e75c` |
| Naming and attribution greps over every added line and commit message | none | `qa/kogany_audit.py greps`, run by W9-d |
| Workflow classification and trigger policy | 18 runnable workflows, 32 off in `.github/workflows-off/`, all within the policy | `qa/kogany_audit.py workflows`, run by W9-d |
| Frozen-file report | 2 files, both exhaustive-match arms (§3.3) | `qa/kogany_audit.py frozen` |
| `zakura-chain` feature off | 528 + 9 doc tests | W0-b `1da36903e`, W1-Y0 `ec6bfcf06`, W2-a `b01242379` |
| The common fork's crates | feature off 195 passed; `ycash` 183 passed, 11 ignored (Zcash heights and encodings) | fork W2-a `7534e26c` |
| `zakura-rpc --lib` feature off with Vault present and dormant | 254 passed, the `nu6testnet` snapshot unchanged | `ee6b52259` |
| `zakura-script` upstream tests | the 40 upstream script tests unchanged | W3-c `d65773dc8` |
| The forked interpreter | upstream `test_vectors.rs` unchanged and green with the flags clear | fork W3-a `7879825f` |
| `zakurad components::mempool` feature off | 169 passed | W9-a F-6 `131fc9cbf` |
| A feature-off regression caught at a merge | nine upstream tests failed when K-12's `is_ycash_network` answered a fallback height on Zcash mainnet; fixed | `1eca93d3f` |
| `is_vault_active` false on every Zcash network at every boundary | `parameters::vault_tests` | W2-b `93cfe484c` |

**Feature-on exceptions** (upstream tests whose vectors are Zcash's, so they cannot pass in a
`ycash` build): `zakura-rpc --lib` fails 47 Zcash-vector tests with `--features ycash` (W7-c
`1f38e518f`); `components::mempool` fails six Zcash-mainnet storage vectors (`131fc9cbf`); three
upstream RPC tests and two ZIP-317 rejection tests are ignored under `ycash` (`481e27b04`,
`f62756ee4`); the fork ignores 11 under `ycash`. The dormancy claim is made on the feature-off
build only, as the plan defines it.

**macOS-only exceptions.** Three `zakura-network` tests
(`peer_set::initialize::tests::vectors::listener_*zcashd_compat*`) bind a non-127.0.0.1 loopback
alias and panic on macOS; they fail identically on the untouched `kogany-legacy` (KF-40).

**Not yet recorded:** a full feature-off `tests-unit` run (the three nextest shards) and
`zakura-e2e` at the integration tip. The merges record per-crate runs only. The gate run belongs
to the W9 gate (W9-b) or to kogany's CI once Actions are on (§7, gap 8).

---

## 5. Cross-line evidence

### 5.1 Ycash mainnet (W1-Y8)

kogany (`--features ycash`, release build, state format 30.2.0) synced Ycash mainnet from live
peers, genesis to 3,087,341, beside ycash6 6.22.0-rc1 (`qa/kogany-sync-results.md`,
`qa/kogany_sync_gate.py`, merge `82ca62e27`):

- block by block: **0 mismatches** in hash, `finalsaplingroot`, `blockcommitments` at every height,
  the ZIP-221 `chainhistoryroot` from Heartwood, `chainSupply` and the value pools;
- `z_gettreestate`: 643 samples, all identical;
- **0 rejected blocks**; hashes equal at the Ycash fork (570,000), Canopy (1,100,006), the YDF
  mandate end (2,275,000), 2,800,000, 3,079,999 (H_S) and the tip
  `0000002ba6d97af6474d3bac9b8b82da7b54568f47097871d429438b338461bf`;
- checkpoint list COMPLETE through 3,086,086, 7,803 checkpoints, every ycashd pin, no Vault epoch.

On the way, the driver found two RPC encodings (pre-Sapling `finalsaplingroot` and
`blockcommitments` in display order, `9c9f8aa00`; `z_gettreestate` trailing empty parents,
`0c1689137`) and one startup panic (`zakura-state` lacked the `ycash` feature, `b5ba9b111`); the
recheck at `9c9f8aa00` over 0..2,275,000 found 0 mismatches where 3,871 had been. The testnet sync
is not done (no Ycash testnet node).

### 5.2 State hashes on the shared regtest scripts

The mixed harness (ycash6 `qa/rpc-tests/test_framework/kogany.py`) compares, at every sync point,
each kogany follower's tip, `vault_getinfo` (statehash, dbtip, counts, lockedvalue) and
`yed_getstatehash` with ycashd's.

| Script or chain | Sync points | Equal to | Merge |
|---|---|---|---|
| `vault_rpc`, `vault_slashing` (recorded ycash6 chains) | every height | ycashd 6.22.0-rc1 statehash | W4-b `7a23a09da`, W4-c `4b8c75d3a` (restarts, forks at depth 1/2/7/30) |
| `vault_primitive` | 71 | ycashd | W4-d `377ad54bd`, `54788bef4` |
| `vault_slashing` (mixed) | 48 | ycashd | `54788bef4` |
| `vault_dos` | 85 | ycashd | `54788bef4` |
| `vault_undo_prune` | 14 | ycashd | `54788bef4` |
| `vault_pq_reorg` | sections A–B | ycashd | `54788bef4` |
| `vault_activation_restart` | passes with `KOGANY_PEER=2\|3\|5` | ycashd | ycash6 `c082d23ff` |
| `yellowback_golden.json` | 440 blocks applied, 22 rejected at DoS 100 with the C++ verdicts | pinned `stateHash` `ee6a9f15…` and totals | W5-d1 `980a6c342`, W5-f `2804973bf` |
| the pq chain | 168 blocks, six rejections | pinned `9bc637c4…` | `980a6c342` |
| `yellowback_lifecycle` | 191 | ycash6 **and** `yellowback_model.py` | W5-f `2804973bf` |
| `yellowback_activation_reorg` | 95 | ycash6 and the model | `2804973bf` |
| `yellowback_reorg_restart` | 97 | ycash6 and the model | `2804973bf` |
| `yellowback_claim` | 284 | ycash6 and the model | `2804973bf` |
| `yellowback_interm` | 185 | ycash6 and the model | `2804973bf` |
| `yellowback_fees` | 254 | ycash6 and the model | `2804973bf` |
| `yellowback_fees_reaccept` | 89 | ycash6 and the model | `2804973bf` |
| `yellowback_mining` | 222 | ycash6 and the model | `2804973bf` |
| `vault_refee` | 42 mempool points | ycashd's `getrawmempool` | W6-c `6b61bcc82` |
| `kogany_pruned_edge.py` (a depth-1,000 reorg at the retention edge) | 101 | the three state hashes | KP-2 ycash6 `f1dd9d456` |
| W9-a rig (`KOGANY_SIDECAR=1`, 20 target scripts) | per pair | each kogany against its own ycashd | ycash6 `84672c619`: 17 of 20 passed; `vault_policy` (fixed by F-1) and `mempool_limits` (fixed by F-6) since, `yellowback_chainviz` (relay latency) open |

### 5.3 Parity scripts

| Script | What | Result | Merge |
|---|---|---|---|
| `crates/kogany-rpc/qa/rpc_ycash_parity.py` | the lightwalletd-dd and yolo call sets, field by field, against ycashd on one chain | 133 calls (Y6); 140 calls (W7-c); every difference classified in `ACCEPTED` | `5f38ea2aa`, `52e9a4dba` |
| `crates/kogany-rpc/qa/rpc_stock_contract.py` | the W7-c stock shapes against ycashd `-disablewallet` | 57/57 | `52e9a4dba` |
| `crates/kogany-rpc/qa/mempool_ycash_parity.py` | mempool verdicts and points | 72 (Y9, three modes); 123 (W6-a, four modes); 143 points (W6-c tip mode); fees mode 11 points | `e62179e97`, `34bdc2729`, `6b61bcc82`, `f299e69a4` |
| `rpc_reject_parity` | reject texts byte for byte | 24/24 | `37610d7f9`, `6b61bcc82` |
| verbose script shapes | `getrawtransaction`/`getblock` `type`, `reqSigs`, `addresses`, asm | 34 calls, 0 differing fields | `37610d7f9` |
| `vault_policy` classes | the reject classes of the vault policy cases | 16/16 | `6b61bcc82` |
| `yellowback_rpc_contract_read.py --live` | every node-context `yed_*` method on a live chain with three seated attestors, against ycash6's answer | 73 calls, 0 differences; 26 of 27 `Contract.check` | `25518495f` |
| `vault_rpc_contract_read.py` | the read subset of the vault contract | matches (mock, W7-a; live, W4-d) | `c8d74c30e`, `377ad54bd` |
| `crates/kogany-rpc/qa/kogany_mines.py` | kogany templates solved by the (48,5) Python solver, accepted by ycashd by relay, the `YED!` tag after activation | 20 rounds across Vault activation | W8-c `d27a880fe` |
| `qa/fuzz/vault` verdict replay | the parsers' verdicts recorded once from ycash6 | 3,735 equal | W3-e `709195d08` |
| client legs (`kogany_client_legs.py`, the client repositories' `kogany-leg.sh`) | lightwalletd-dd, chain-viz, x402, YEW W1 | 18/18; chain-viz green; x402 5/5; YEW W1 green (at `25518495f`); lightwalletd-dd 3/3 (at `18650e75c`); Hawkeye: kogany followed all 219 blocks of `regtest_self_signing` | `25518495f`, `18650e75c`, hawkeye `b8e9471` |

---

## 6. The parity sidecar: `yewd`

`yewd` lives in the `yew` repository (`yew/yewd/`, K-22), a third shell on yew-core, with a
façade (`yewd-facade`, binary `yewd`), the wallet (`yewd-wallet`), the signer (`yewd-signer`, a
separate process on a Unix socket, K-24) and the request format (`yewd-proto`). Its plan section is
`yew/docs/plans/yewd-plan.md`; the signer protocol and policy are `yew/yewd/README.md` "The signer
(S2)" (`:177`) and `yew/yewd/proto/src/lib.rs`.

| Chunk | Served | Gate (as run) | Merge |
|---|---|---|---|
| S0 | the method table (every wallet method `-32601` until served), forwarding with the backend cookie, auth, `help`, `stop` | `check-yewd.sh`, 22 tests, a regtest round trip against ycashd | yew `0c63678` |
| S1 | 9 of the 47 Yellowback wallet RPCs, 10 stock wallet reads | the read gate twice on ycash6 `-disablewallet` + `yewd` with restarts and 2- and 10-block reorgs; `pq_wallet_vectors.json` replays through the signer | yew `3679eff` |
| S2 | 40 of 47 (all 22 vault, 18 of 25 `yed_*`), the `allowyedburn` guard | 28 build RPCs on chain against ycash6 `-disablewallet`, `statehash` and `yed_getstatehash` equal at every checkpoint; `vault_vectors` `acts[]`, `setSigMsgs[]`, `signatures[]`, `ownerSpends[]` byte for byte in the signer; the refusal tests | yew `cd72fb4` |
| S3 | 47 of 47; the attestor and cancel-cosign roles, imported keys | ycash6's attestor and cancel role scripts unchanged with role nodes as pairs, `yed_getstatehash` equal at every checkpoint; the 18 signable attestation vectors byte for byte | yew `85aec6f` |
| S4 | the 47, `z_importpqkey`, the 34 K-25 stock wallet RPCs, the raw helpers locally, Sapling in the signer | `vault_rpc_contract.py` (2 pairs) and `yellowback_rpc_contract.py` (6 pairs) pass unchanged; 144 arity checks, 85 help texts, 33 documented errors, 13 raw-helper answers equal ycashd's; `yellowback_sapling.py` passes with every node a pair | yew `da37a53` |
| S5 | the 48 wallet scripts on column 3, the three-way matrix | in flight (`kc/yewd-s5`) | — |

Every S-gate so far ran with **ycash6 `-disablewallet`** as the backend (the plan's
backend-agnostic route), not kogany: S4's record says so ("Not run here: the same on kogany").
`yewd/PIN` still names ycash6 `65cb4ae0f` and kogany `b90fc9b19`, which predate the W1 merges
(gap 19). The first kogany-backend runs are S5's.

The sidecar's own findings (F-S1-*, F-S2-1 … F-S2-9, F-S3-1 … F-S3-6, F-S4-1 … F-S4-12) are in
`yew/docs/plans/yewd-plan.md`; those that matter for the node or the plan are KF-63 … KF-68.

---

## 7. Known gaps

Collected from every merge message and the plan's §9; "open" means not done on any integration
branch at the commits above.

| # | Gap | Where | Next step by |
|---|---|---|---|
| 1 | **No Ycash testnet sync.** There is no Ycash testnet node, so the W1 gate's testnet half and §6's testnet sync are not run | `qa/kogany-sync-results.md` | W1 (open) |
| 2 | **`testnet-yb-slow` has no selector.** ycashd picks it with `-testnetprofile=slow` (`ycash6/src/chainparamsbase.cpp:26`); kogany has the network (`Network::new_ycash_testnet_slow`, `crates/zakura-chain/src/parameters/ycash.rs:129`) but no config key reaches it outside tests | M24-89 | open |
| 3 | **`invalidateblock` reaches one node.** Zakura's `invalidateblock` acts on the node it is sent to; mirroring a script's invalidate/reconsider on the followers is opt-in (`KOGANY_MIRROR_INVALIDATE`), and a restart that erases an invalidated branch needs the follower to mirror it before it reconnects (in flight on `kc/w9-mixed`) | M24-66 | W9-b |
| 4 | **`getaddressbalance.txcount`.** Zakura serves a zcashd 6.x field ycashd lacks; accepted as a difference (lightwalletd-dd reads `balance`) | `crates/kogany-rpc/qa/rpc_ycash_parity.py:131` | accepted |
| 5 | **`z_gettreestate` extra objects.** Zakura reports `sprout`, `orchard` and `ironwood` objects (empty pools on Ycash); accepted in the parity script. The Sapling `finalState` is byte-equal since `0c1689137` | `rpc_ycash_parity.py` `ACCEPTED` | accepted |
| 6 | **One address twice in `getaddressutxos`.** ycashd answers its UTXOs twice; kogany once, at the first position | `crates/zakura-rpc/src/methods/types/ycash.rs:446-448` | accepted |
| 7 | **Docker and kind not verified.** The Dockerfile ships `koganyd` since `18650e75c`, but no image was built from it; ycash-infra's `make image-koganyd` and the kind recipe have never run (their merges were render-only) | ycash-infra `2dafdd3`, `62f462e` | open |
| 8 | **GitHub Actions off** on kogany and the fork: nothing is enabled; the settings checklist is the workspace's `docs/plans/kogany/ci-design.md` §9 | KF-03, KF-69 | the lead architect |
| 9 | **The common fork's CI has never run** on GitHub, though the fork now exists there (`boyfromcave/zakura-common-ycash`, created 2026-11-02, `vaults/kogany-compat` = `e5515523`) | KF-78 | open |
| 10 | **Upstream sync blocked.** Zakura upstream `b44ec121d` bumps every Common crate to `5.0.0-rc.4`; plan §4.2 rule 7 needs a common-fork sync first (dry run: 102 conflicting stops of 185 commits) | `kc/sync-zakura-20261102` | open |
| 11 | **No two-reviewer record** for any consensus change: the coordinator merged `kc/*` branches directly, no PR carries the review gate | §8 below | the review gate |
| 12 | **Four-part checks missing** from the commit bodies of W1-Y4, W6-a and W6-b (reconstructed in §3.1) | KF-80 | recorded |
| 13 | **Touch budget exceeded** by more than 25 % in W4–W8 without the §4.1 stop | KF-82 | the lead architect |
| 14 | **Frozen-file report non-zero** (2 files, exhaustive arms) | KF-79 | recorded |
| 15 | **No set-spend dry run.** yewd cannot pre-check an unsigned set spend as ycashd's `ValidateSetSpend` does in-process (F-S2-3); proposed as an additive read, C++ lines first | KF-64 | open |
| 16 | **The façade's clock is not mocked** (`setmocktime` is forwarded to the node only, F-S4-11); H3/H4 (the indexer streams) untested; `signrawtransaction` with keys against kogany exercised once (F-S4-12) | KF-67 | S5 |
| 17 | **ycash-dd's vendored `hyper` 0.14.2 ≠ `Cargo.lock`'s 0.14.12**: an offline ycash-dd build fails | KF-37 | open |
| 18 | **K-23 deviation** (yewd reads blocks over node JSON-RPC, not lightwalletd-dd) awaits the lead architect's acceptance or an amended K-23 | KF-34 | the lead architect |
| 19 | **`yewd/PIN` stale**: ycash6 `65cb4ae0f`, kogany `b90fc9b19` | `yew/yewd/PIN` | S5 |
| 20 | **`yellowback_chainviz` in the W9-a rig**: relay latency | ycash6 `84672c619` | W9-b |
| 21 | **`split_network` keeps kogany on node 1's side**: Zakura has no `disconnectnode` (plan §5) | plan §5 | recorded |
| 22 | **kogany never solves (192,7)** (K-16); regtest PoW is shape-only on kogany | M24-20 | recorded |
| 23 | **Pruned nodes do not serve IBD**; lightwalletd-dd backends stay archive (decision 7) | M24-86 | by decision |
| 24 | **ubuntu-22.04 vs 24.04**: a 24.04 koganyd links librocksdb 8.9 and does not run on 22.04 | ci-design §8 item 4 | recorded |
| 25 | **`semgrep.yml` push trigger** and the workspace's `workspace-check.yml` without `vaults/kogany-compat` | ci-design §8 items 5, 9 | the lead architect |
| 26 | **599 inherited upstream branches** on `boyfromcave/kogany` await deletion by hand | workspace `docs/plans/kogany/kogany-branch-inventory.md` | the lead architect |
| 27 | **The roles without ycashd** (attestor `attest` mode, Hawkeye member, x402 `rpcWalletSigner` through the façade) are S5's; today's W9-c legs keep a ycash6 `connect=` sidecar for the wallet | §6 | S5 |
| 28 | **K-19(a)**: whether kogany becomes a qualified release line | plan §6 | the lead architect |

---

## 8. Review gate and release train

**Consensus review.** AGENTS.md rule 2 asks two reviewers independent of the author for every
changed line under the consensus paths, with the four-part check in the PR body. On
`vaults/kogany-compat` the coordinator merged agent branches directly; no PR exists, so no
reviewer is recorded for any of the 22 chunks in §3.1. The artefact the reviewers read is
`qa/kogany_audit.py consensus-diff` (`consensus-diff.md` and `consensus-diff.patch`: 108 files,
+23,604 / −121 against `kogany-baseline`, the 2 generated checkpoint lists included). The gate runs
when `vaults/kogany-compat` merges into `upgrade/vault` (plan §4.2 rule 0).

**Release train (prepared, not enabled; K-19).** Until K-19(a) is decided a train names kogany as
`kogany: none` (plan §5). The entry, once decided, is: `kogany` added to `COMPONENTS` in the
workspace's `scripts/release-train.py:55-56` with its commit on `upgrade/vault`; its contract copies
checked by `make spec-check` through `EXTRACT_SPEC_KOGANY_DIR` (kogany `doc/`, already written by
`make spec`); the artifact `koganyd-bin` at the train's kogany commit for rc-qualify; and the
three-way rc-qualify (`qa/yellowback-rc-crossline.py` with the kogany column, W9-b). `yewd` ships
inside `yew`, which the train already names.

---

## 9. The §6 demonstration transcript

Assembled from the runs the merges record. Each line says what was run, where, and with what
result; **[S5]** and **[W9-b]** mark what those in-flight chunks add. `pgrep -l ycashd` printing
nothing on the product host is S5's step: every run below still had a ycashd somewhere.

```
# Ycash node (§6 row 1)
qa/kogany_sync_gate.py (kogany 18650e75c's tree at 82ca62e27, ycash6 6.22.0-rc1 65cb4ae0f)
  mainnet genesis..3,087,341: 0 mismatches, 0 rejected, 643 tree states identical,
  tip 0000002ba6d97af6474d3bac9b8b82da7b54568f47097871d429438b338461bf on both
  testnet fast / slow: NOT RUN (no Ycash testnet node)

# Dormancy (row 2)
qa/kogany_audit.py dormancy frozen greps workflows        (W9-d, at 18650e75c)
  dormancy: 6580 upstream tests at kogany-legacy, 7137 at HEAD, none missing
  frozen:   2 files (halo2.rs exhaustive arm; nu7_diff_dump.rs test)   -> KF-79
  greps:    none        workflows: every workflow classified, within the policy
feature-off per-crate runs: zakura-chain 528+9, zakura-rpc --lib 254, zakurad mempool 169,
  fork crates 195, zakura-script 40 upstream tests unchanged
feature-off tests-unit (3 shards) + zakura-e2e at one commit: [W9-b]

# Oracle (row 3)
nine vector files, SHA-256 = testdata/yellowback/PIN = ycash6 65cb4ae0f (qa/yellowback-cross-line.py
  --this-line kogany: 9 identical); debug, --release and --profile ci-tests replays in
  kogany-pq, kogany-vault, kogany-yellowback, zakura-chain (sighash), zakura-script
golden chain: 440 applied, 22 rejected, stateHash ee6a9f15... and totals equal; pq chain 9bc637c4...
pq_wallet_vectors.json: N/A for kogany; replays in yewd-signer (S1)

# Equivalence (row 4)
mixed scripts with statehash / yed_getstatehash equal at every sync point (§5.2): vault_* 5 scripts,
  yellowback_* 8 scripts three-way with yellowback_model.py, vault_refee, kogany_pruned_edge
W9-a rig: 17 of 20 wallet scripts on kogany + ycash6 connect= (ycash6 84672c619)
all 58 scripts mixed, twice in a row: [W9-b]

# Devnet (row 5)
qa/yellowback-rc-crossline.py --kogany ... 5 rounds x 100 blocks, three-way, across activation,
  2- and 10-block reorgs and a kogany restart: [W9-b]

# Production (row 6)
crates/kogany-rpc/qa/kogany_mines.py: 20 rounds across Vault activation, every kogany template
  solved (48,5) outside the node, ycashd reaches every block by relay, YED! tag after activation
yolo tests/regtest.rs with YOLO_REGTEST_KOGANY: report-only entry (yolo 576754d, cfe4605)
negative verdict classes: KOGANY_REASON_MAP, rpc_reject_parity 24/24

# Clients (row 7)
lightwalletd-dd 3/3 (at 18650e75c), chain-viz green, x402 5/5, YEW W1 green, client legs 18/18
  (at 25518495f); hawkeye follow 219/219 blocks; ycash-infra nodeLine kogany: render-only

# Review package (row 8)
this document; mapping §24 M24-1..M24-91; two reviewers per consensus PR: NOT YET (§8)

# K-19(a) (row 9): the lead architect's decision, pending

# Parity, three-way matrix, roles without ycashd, signer boundary (rev 2 rows): [S5]
  so far: S4's contract suites pass unchanged with every node a yewd pair on ycash6 -disablewallet
  pgrep -l ycashd (empty) on the product host: [S5]

# V5-spec (K-21): merged (workspace e6e3eae, ycash6 e5dac3a30); vectors outside the manifest
```
