# Upstream sync `sync-zakura-20261102`

Plan §4.2 rule 7 (`docs/plans/kogany/kogany-yellowback-plan.md` in the Yellowback workspace).
Base: `vaults/kogany-compat` at `18650e75c`, then `0bb40c0ca` (the fork-sync-rc4 record). Pin:
`kogany-legacy` = `ref/zakura` = `2b062412c5`. Upstream: `zakura-core/zakura` `main` at
`b44ec121d` (fetched with the narrowed refspec of the branch inventory §6:
`+refs/heads/main:refs/remotes/upstream/main`, no tags), 20 commits past the pin.

**Result: merged.** The first attempt stopped before the merge because the range moves every
Common crate from `5.0.0-rc.2` to `5.0.0-rc.4`; the coordinator first synced the common fork
(`doc/fork-sync-rc4.md`: fork rev `04989544`, `5.0.0-rc.4+ycash.1`). The re-run on
`kc/sync-zakura-20261102`:

| Commit | What |
| --- | --- |
| `e21ae01c1` | merge of `origin/vaults/kogany-compat` (`0bb40c0ca`) |
| `6cc2f22a2` | **the upstream merge** `2b062412c5..b44ec121d`, 7 conflicts resolved (below) |
| `fd3d6bece` | the common-fork bump, its own commit (rule 8): rev `049895445b6f` on all 25 lines of the root `[patch.crates-io]` and of `qa/fuzz/vault`'s copy, both locks re-resolved |
| `1179cbc6e` | kogany's hooks carried to two call sites the merge added (they merged cleanly but did not compile) |

`6cc2f22a2` alone does not resolve (`Cargo.lock` is upstream's, which the rc.2 fork cannot
patch); the tree builds from `fd3d6bece` on.

## The upstream range `2b062412c5..b44ec121d`

| Commit | Subject |
| --- | --- |
| `0be1f4589` | fix(sync): request a gossiped block's missing parent through its existing download owner (#1873) |
| `ba009ef84` | fix(network): keep fresh block adverts from waiting on older broadcasts' upload slots (#1874) |
| `2cdce83cc` | perf(state): parallelize large parent input checks (#1908) |
| `379c531fc` | build(deps): pin Common to the merge of common#638 (Sapling cv as bytes) (#1907) |
| `aa4edd5fc` | fix(rpc)!: use a 6-hour tip-age window for getblocktemplate (#1911) |
| `7c4c54842` | perf(consensus): collect a block's transaction results outside Tokio's budget (#1909) |
| `7d3b5b9c7` | fix(sync): smooth recent sync progress over five samples (#1913) |
| `1f049cf08` | fix(sync): add a Mainnet download work floor for defense in depth (#1915) |
| `b138edf56` | chore(release): prepare v1.8.0-rc1 (#1917) |
| `dd739b1dd` | fix(network): keep block advertisement peers current (#1883) |
| `2bb5a3103` | feat(monitoring): alert on Mainnet difficulty headroom (#1918) |
| `0a1aa320c` | perf(rpc): reuse a retained template's transactions for an exact submission (#1902) |
| `c96f5e3b9` | fix(consensus): report the root cause when an NU5 block fails verification (#1914) |
| `281fbf94b` | perf(consensus): prepare Halo2 batches on a blocking thread (#1924) |
| `8a164df24` | perf(consensus): prepare Sapling batches off the async worker (#1934) |
| `eccae45e4` | perf(chain): look up network upgrades without rebuilding their maps (#1921) |
| `00a1ec30a` | fix(eos): target December 5 from current Mainnet progress (#1938) |
| `6d3883415` | perf(chain): read output addresses from the script bytes (#1895) |
| `2398c0924` | chore(deps): bump Common crates to 5.0.0-rc.4 (#1939) |
| `b44ec121d` | fix(network): use runtime cancellation token in peer-set driver (#1935) |

The upstream range touches 113 files and no file under `.github/`: no workflow was added, edited,
renamed or deleted, so `.github/workflows-off/` and `.github/kogany-workflows.txt` need nothing.

## The common-fork prerequisite

- `379c531fc` (#1907) moved upstream onto common#638 (Sapling `cv` kept as bytes,
  `CommitmentSum::try_sum` replaces the removed `Sum` impl); `2398c0924` (#1939) bumped every
  Common dependency to `=5.0.0-rc.4`. The fork at `1e6d6aa4` was `5.0.0-rc.2+ycash.1`, which
  cannot satisfy those requirements.
- Fork rev now pinned: `049895445b6fe7a9db20b484736008952a6d6d94` (fork commits `08d6ccb2`,
  `e5515523`, `04989544`; upstream Common `bdbca121..16437a9d`). `cargo update -p` of the 25
  patched crates, in the root and in `qa/fuzz/vault`: each crate appears once, as
  `5.0.0-rc.4+ycash.1` (`zakura-zcash-script` `0.0.1+ycash.1`, `zakura-sensei*` `0.1.0`) from the
  fork rev; `zakura-udon` and `zakura-bento` stay single from crates.io.
- `qa/supply-chain/config.toml`: upstream's rc.4 version, taken by the merge; nothing added.
- common#638 call sites in kogany code: none. No kogany line names `CommitmentSum`, the removed
  `Sum` impl or a Sapling `cv` decode; every crate checks with the feature on and off
  (`cargo check --locked --all-targets` of zakura-chain, -consensus, -state, -rpc, -script,
  -network, -header-chain, both ways, and `-p zakura`, `-p kogany-rpc --features ycash`).

## The rebase-ability measure (dry run, report-only)

Scratch worktree at `18650e75c`, `GIT_EDITOR=true git rebase upstream/main`. The rebase
linearises kogany's history: 185 non-merge commits (of 261, the 76 merges are dropped). At each
conflicting stop the conflicted files were recorded and the commit was skipped
(`git rebase --skip`) so the run reaches the end; the scratch worktree was then removed.

- **Conflicting stops: 102 of 185 commits; 111 distinct files.**
- The count is inflated by the skip: a skipped kogany commit makes every later kogany commit on
  the same kogany-only file conflict (for example `crates/kogany-rpc/src/lib.rs`, 7 stops, a file
  upstream never touched). The **genuine** conflicts, files both upstream and kogany changed,
  are 18:

- `Cargo.lock`
- `Cargo.toml`
- `crates/zakura-chain/Cargo.toml`
- `crates/zakura-chain/src/parameters/network_upgrade.rs`
- `crates/zakura-chain/src/transparent.rs`
- `crates/zakura-consensus/Cargo.toml`
- `crates/zakura-consensus/src/block.rs`
- `crates/zakura-consensus/src/primitives/halo2.rs`
- `crates/zakura-consensus/src/transaction.rs`
- `crates/zakura-consensus/src/transaction/tests.rs`
- `crates/zakura-rpc/Cargo.toml`
- `crates/zakura-rpc/src/methods.rs`
- `crates/zakura-state/src/request.rs`
- `crates/zakura-state/src/response.rs`
- `crates/zakura-state/src/service.rs`
- `crates/zakurad/Cargo.toml`
- `crates/zakurad/src/components/mempool.rs`
- `crates/zakurad/src/components/mempool/tests/prop.rs`

<details><summary>Every conflicted file, with the number of stops it appeared in</summary>

| File | Stops |
| --- | --- |
| `Cargo.lock` | 14 |
| `testdata/yellowback/CHECKLIST.md` | 9 |
| `crates/zakura-consensus/src/transaction/tests/bip68.rs` | 7 |
| `crates/kogany-rpc/src/lib.rs` | 7 |
| `crates/kogany-rpc/qa/rpc_ycash_parity.py` | 7 |
| `crates/kogany-rpc/Cargo.toml` | 7 |
| `crates/zakura-rpc/src/methods/types/ycash/tests.rs` | 6 |
| `crates/zakura-rpc/src/methods/types/ycash.rs` | 6 |
| `crates/zakura-consensus/src/transaction/check/ycash_standard.rs` | 6 |
| `crates/zakura-consensus/src/transaction.rs` | 6 |
| `crates/zakura-chain/src/parameters/network_upgrade.rs` | 6 |
| `crates/kogany-yellowback/src/lib.rs` | 6 |
| `crates/kogany-rpc/src/yed/live.rs` | 6 |
| `Cargo.toml` | 6 |
| `crates/zakurad/Cargo.toml` | 5 |
| `crates/kogany-rpc/src/yed/state.rs` | 5 |
| `crates/kogany-rpc/qa/mempool_ycash_parity.py` | 5 |
| `crates/zakurad/src/commands/start.rs` | 4 |
| `crates/zakura-state/src/request.rs` | 4 |
| `crates/zakura-rpc/src/methods/types/ycash_reject/tests.rs` | 4 |
| `crates/zakura-rpc/src/methods/types/ycash_reject.rs` | 4 |
| `crates/zakura-rpc/src/methods/types/get_block_template/ycash/tests.rs` | 4 |
| `crates/zakura-chain/src/parameters/ycash.rs` | 4 |
| `crates/zakurad/src/components/mempool.rs` | 3 |
| `crates/zakura-state/src/service.rs` | 3 |
| `crates/zakura-state/src/response.rs` | 3 |
| `crates/zakura-rpc/src/methods/types/get_block_template/ycash.rs` | 3 |
| `crates/zakura-rpc/src/methods.rs` | 3 |
| `crates/zakura-rpc/Cargo.toml` | 3 |
| `crates/zakura-consensus/src/transaction/vault_mempool.rs` | 3 |
| `crates/zakura-consensus/src/transaction/tests.rs` | 3 |
| `crates/zakura-consensus/src/transaction/check/ycash_standard/tests.rs` | 3 |
| `crates/zakura-consensus/src/error.rs` | 3 |
| `crates/kogany-rpc/src/yed/rpc.rs` | 3 |
| `crates/kogany-rpc/src/yed/mod.rs` | 3 |
| `crates/kogany-rpc/src/mining.rs` | 3 |
| `crates/zakurad/tests/kogany_regtest.rs` | 2 |
| `crates/zakurad/src/components/mempool/tip_recheck.rs` | 2 |
| `crates/zakura-state/src/service/write/vct_authentication_sweep/tests.rs` | 2 |
| `crates/zakura-state/src/service/write/tests/full_state_coherence.rs` | 2 |
| `crates/zakura-state/src/service/finalized_state/vct_fast_sync_fixture.rs` | 2 |
| `crates/zakura-state/src/service/finalized_state/tests/rollback.rs` | 2 |
| `crates/zakura-state/src/service/finalized_state/tests/prop.rs` | 2 |
| `crates/zakura-state/src/service/check/tests/vault.rs` | 2 |
| `crates/zakura-rpc/src/methods/types/transaction.rs` | 2 |
| `crates/zakura-network/src/zakura/testkit/cluster.rs` | 2 |
| `crates/zakura-network/src/ycash/tests.rs` | 2 |
| `crates/zakura-network/src/ycash.rs` | 2 |
| `crates/zakura-consensus/tests/nu7_diff_dump.rs` | 2 |
| `crates/zakura-consensus/src/primitives/halo2.rs` | 2 |
| `crates/zakura-consensus/src/block.rs` | 2 |
| `crates/zakura-chain/src/transparent/address.rs` | 2 |
| `crates/zakura-chain/src/transparent.rs` | 2 |
| `crates/zakura-chain/src/parameters/ycash/tests.rs` | 2 |
| `crates/zakura-chain/src/parameters/vault_tests.rs` | 2 |
| `crates/zakura-chain/src/parameters/network/testnet.rs` | 2 |
| `crates/zakura-chain/src/parameters/network.rs` | 2 |
| `crates/zakura-chain/Cargo.toml` | 2 |
| `crates/kogany-yellowback/src/state.rs` | 2 |
| `crates/kogany-rpc/src/yed/mock.rs` | 2 |
| `crates/kogany-rpc/src/yed/format.rs` | 2 |
| `crates/kogany-rpc/src/regtest.rs` | 2 |
| `crates/kogany-rpc/src/live.rs` | 2 |
| `crates/kogany-rpc/qa/yed_live_rig.py` | 2 |
| `.config/nextest.toml` | 2 |
| `kogany-audit-out/dormancy.md` | 1 |
| `kogany-audit-out/consensus-diff.patch` | 1 |
| `kogany-audit-out/consensus-diff.md` | 1 |
| `crates/zakurad/src/components/mempool/tests/prop.rs` | 1 |
| `crates/zakurad/src/application.rs` | 1 |
| `crates/zakura-state/src/service/vault.rs` | 1 |
| `crates/zakura-script/src/ycash.rs` | 1 |
| `crates/zakura-rpc/src/server/kogany_extension.rs` | 1 |
| `crates/zakura-rpc/src/methods/types/ycash_script.rs` | 1 |
| `crates/zakura-rpc/src/methods/types.rs` | 1 |
| `crates/zakura-rpc/src/lib.rs` | 1 |
| `crates/zakura-network/src/constants.rs` | 1 |
| `crates/zakura-consensus/src/transaction/tests/prop.rs` | 1 |
| `crates/zakura-consensus/src/transaction/check.rs` | 1 |
| `crates/zakura-consensus/Cargo.toml` | 1 |
| `crates/zakura-chain/src/transaction/arbitrary.rs` | 1 |
| `crates/zakura-chain/src/parameters/ycash_dormancy_tests.rs` | 1 |
| `crates/zakura-chain/src/parameters/tests.rs` | 1 |
| `crates/zakura-chain/src/parameters/network/error.rs` | 1 |
| `crates/zakura-chain/src/parameters.rs` | 1 |
| `crates/zakura-chain/src/local_genesis.rs` | 1 |
| `crates/kogany-yellowback/src/state/tx.rs` | 1 |
| `crates/kogany-yellowback/src/state/redeem.rs` | 1 |
| `crates/kogany-yellowback/src/codecs.rs` | 1 |
| `crates/kogany-yellowback/src/attest.rs` | 1 |
| `crates/kogany-yellowback/Cargo.toml` | 1 |
| `crates/kogany-vault/tests/vault_vectors.rs` | 1 |
| `crates/kogany-vault/src/state/overlay.rs` | 1 |
| `crates/kogany-vault/src/state.rs` | 1 |
| `crates/kogany-vault/src/lib.rs` | 1 |
| `crates/kogany-vault/src/act.rs` | 1 |
| `crates/kogany-rpc/tests/live_state.rs` | 1 |
| `crates/kogany-rpc/tests/decode_vectors.rs` | 1 |
| `crates/kogany-rpc/src/yed/types.rs` | 1 |
| `crates/kogany-rpc/src/macros.rs` | 1 |
| `crates/kogany-rpc/qa/yellowback_rpc_contract_read.py` | 1 |
| `crates/kogany-rpc/qa/rpc_verbose_parity.py` | 1 |
| `crates/kogany-rpc/qa/rpc_stock_contract.py` | 1 |
| `crates/kogany-rpc/qa/rpc_reject_parity.py` | 1 |
| `README.md` | 1 |
| `.github/workflows/kogany-yellowback.yml` | 1 |
| `.github/workflows/kogany-tests.yml` | 1 |
| `.github/workflows/kogany-mixed.yml` | 1 |
| `.github/workflows/kogany-client-legs.yml` | 1 |
| `.github/workflows/kogany-bin.yml` | 1 |
| `.github/README-kogany.md` | 1 |

</details>

## The merge: conflicts and how each was resolved

`git merge upstream/main`: 7 conflicted files, the rest merged cleanly. Upstream touched nothing
under `.github/`, so no workflow had to move to `.github/workflows-off/` or be classified.

| File | Conflict | Resolution |
| --- | --- | --- |
| `Cargo.lock` | Common crates rc.2 (fork git source) vs rc.4 (crates.io), and the in-repo version bumps | Upstream's in the merge commit; re-resolved by `cargo update -p` in the bump commit, never hand-merged |
| `crates/zakura-rpc/Cargo.toml` | upstream's `zakura-state` `12.0.0-rc0` against kogany's `kogany-vault`/`kogany-yellowback` optional deps | Upstream's version line; kogany's two deps kept |
| `crates/zakurad/Cargo.toml` | the same version line against kogany's `kogany-rpc` dep | Upstream's version; `kogany-rpc` kept. `crates/kogany-rpc/Cargo.toml`'s own `zakura-state` requirement moved `11.1.0-rc0` → `12.0.0-rc0` with it |
| `crates/zakura-chain/src/parameters/network_upgrade.rs` (consensus path) | `eccae45e4` adds `MAINNET_ACTIVATION_MAP` where kogany's `#[cfg(feature = "ycash")]` `CONSENSUS_BRANCH_IDS` table sits | Both kept, kogany's table first. The cached map reads `MAINNET_ACTIVATION_HEIGHTS`, which kogany already selects by `cfg(feature = "ycash")`, so the Ycash heights reach upstream's new `activation_map()` with no further hook |
| `crates/zakura-chain/src/transparent.rs` | `6d3883415` rewrites `address()` on the script bytes; kogany's W7-b `TX_PQPKH` branch sat before the old `TxOut::try_from` match | Upstream's body; kogany's `#[cfg(feature = "ycash")]` `pq_key_id()` block kept in front of it, unchanged |
| `crates/zakura-consensus/src/block.rs` (consensus path) | upstream's restructured verifier (`7c4c54842`, `c96f5e3b9`, `8a164df24`, `281fbf94b`) nests the body one level deeper | Upstream's file; kogany's four hooks re-applied unchanged at the new nesting: the `ycash_tests` module, `equihash_solution_is_valid`'s `height` argument, the W4-d vault snapshot fetch, the `tx::Request::Block` `vault_snapshot` field |
| `crates/zakura-rpc/src/methods.rs` | `0a1aa320c` re-nests `submitblock`'s decode-failure return; kogany's W7-e hook returns ycashd's -22 there | Upstream's nesting; kogany's `#[cfg(feature = "ycash")]` -22 return kept |

Two call sites the merge added cleanly, adapted in `1179cbc6e`:

- `crates/zakura-consensus/src/block/check.rs` `proof_of_work_is_valid` (upstream `0be1f4589`)
  called `equihash_solution_is_valid` without kogany's height argument; it now passes the
  `height` it already takes (Ycash's Equihash parameters are height-bound).
- `crates/zakura-consensus/src/transaction/tests.rs`, upstream `379c531fc`'s invalid Sapling `cv`
  test: `vault_snapshot: None` added to its `tx::Request::Block`, as in kogany's other test
  initialisers.

The consensus-diff against the new upstream tip shows only kogany hunks: per file, the
`git diff --numstat` of the consensus path set for `upstream/main..HEAD` equals that of
`2b062412c5..0bb40c0ca` (108 files) except `block/check.rs` and `transaction/tests.rs`, one line
each, the two adaptations above.

## Gates

On `1179cbc6e`, macOS, `CARGO_INCREMENTAL=0`, target dir `wt/.targets/sync-zakura`, the local
fork through `url.insteadOf`.

| Gate | Command | Result |
| --- | --- | --- |
| feature-off upstream suite | `cargo test --locked -p zakura-chain -p zakura-consensus -p zakura-state -p zakura-rpc -p zakura-script -p zakura-network --lib --no-fail-fast` | chain 546, consensus 324, state 847, rpc 261 pass; network 2071 pass, 3 fail (the known macOS `listener_*zcashd_compat*` tests); script 42 pass, 5 fail (pre-existing, below) |
| mempool | `cargo test --locked -p zakura --lib components::mempool` | pass |
| ycash legs | `cargo nextest run --locked --profile kogany-ycash -p <crate> --features <crate>/ycash` for zakura-chain, zakura-header-chain, zakura-consensus, zakura-network, zakura-rpc, kogany-rpc, zakura | all pass except zakura-rpc 29/30 (pre-existing, below) |
| vault fuzz verdicts | `cargo test --locked -p zakura-consensus --features ycash --test vault_fuzz_verdicts` | pass |
| kogany-regtest | `cargo nextest run --locked --profile kogany-regtest -p zakura --features ycash` | pass |
| kogany-rpc | `cargo test --locked -p kogany-rpc --features ycash` | pass |
| pure crates | `cargo test --locked [--release] -p kogany-pq -p kogany-vault -p kogany-yellowback` | pass, debug and release |
| RPC artifacts | `cargo run --locked -p xtask -- check-rpc-artifacts` | **fails, pre-existing** (below) |
| audit | `qa/kogany_audit.py --base upstream/main --upstream upstream/main all` | pass (consensus-diff: only kogany hunks plus the six forked-crate lock entries `5.0.0-rc.4` → `+ycash.1`; frozen: `halo2.rs`, `nu7_diff_dump.rs` as before). Against the default `kogany-legacy` it fails until the re-pin, as expected: greps reads upstream's own commit trailers in the range (`379c531fc`, `ba009ef84`) and dormancy counts 5 tests upstream itself deleted |
| mixed smoke | `KOGANY_LIVE=W1-Y1,W2-b,W5-f,W5-c,W3-c KOGANY_BIN=<koganyd> ZCASHD=wt/.bin/ycash6-65cb4ae0f/ycashd kogany_mixed_smoke.py --srcdir=wt/.bin/ycash6-65cb4ae0f` (from `wt/kc-ycash6-int`) | pass: 5 sync points, 5 vault and 5 YED state hashes, 2 verdicts |

Failures present on the base too (`0bb40c0ca`, checked in a scratch worktree), not caused by
the sync:

- `zakura-script` `ycash_tests` (5 tests) fail in a feature-off build: the module is compiled
  under `cfg(test)` alone, and zakura-script has no `ycash` feature to turn on the zakura-chain
  and zcash_script `ycash` behaviour they assert (`YcashUpgradeNeedsYcashBuild`, opcode 0xc2
  unknown).
- `zakura-rpc` `methods::tests::vault::templates_across_the_vault_activation_commit_to_the_chain_history_root`
  panics "HistoryTree does not exist for pre-Heartwood upgrades": `fake_history_tree` builds
  from Zcash Mainnet block 1,046,400, which is before Ycash Mainnet Heartwood (1,100,003).
- `check-rpc-artifacts`: `doc/kogany-rpc-openrpc.json` records the SHA-256 of the two contract
  copies from before `080dc1426` / `66cb769eb` regenerated them; `cargo xtask
  generate-rpc-artifacts` would update the two hashes. Left for the contract chunk's owner.
- The mixed smoke without `KOGANY_LIVE` stops at height 103 (block 104 `ScriptInvalid`): the
  follower is configured without the Ycash and Vault upgrades (`pending:W1-Y1`, `pending:W2-b`
  in its toml). The pre-sync `wt/.bin/koganyd/koganyd` (`5582c1f87`) fails identically.

## Re-pin (the coordinator's)

By the rule-1 procedure, after this branch merges: `ref/zakura` and `kogany-legacy` →
`b44ec121d6cf55f6596c29f1a31775553d218d18`, with `repos.yaml`, AGENTS.md (the layout line and the
kogany paragraph: "main @ 2b062412c5 (past v1.7.0)" becomes `b44ec121d`, v1.8.0-rc1), and the
mapping §24 citations re-taken at the new commit in the same change. After the re-pin the
audit's default base reads clean.
