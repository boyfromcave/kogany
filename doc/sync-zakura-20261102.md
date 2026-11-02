# Upstream sync `sync-zakura-20261102`: blocked on the common fork

Plan §4.2 rule 7 (`docs/plans/kogany/kogany-yellowback-plan.md` in the Yellowback workspace).
Base: `vaults/kogany-compat` at `18650e75c`. Pin: `kogany-legacy` = `ref/zakura` = `2b062412c5`.
Upstream: `zakura-core/zakura` `main` at `b44ec121d` (fetched with the narrowed refspec of the
branch inventory §6: `+refs/heads/main:refs/remotes/upstream/main`, no tags), 20 commits past the
pin.

**Result: the merge was not made.** The upstream range bumps every Common crate (the crates the
common fork `zakura-common-ycash` carries) from `5.0.0-rc.2` to `5.0.0-rc.4`. Rule 7 says such a
bump forces a sync of the common fork first; kogany's `[patch.crates-io]` pins those crates to
the fork at `1e6d6aa4` (`5.0.0-rc.2+ycash.1`), which cannot satisfy upstream's `=5.0.0-rc.4`
requirements. The sync stops here and is re-run after the fork is synced. The dry-run
rebase-ability measure and a trial merge (aborted, nothing committed) were recorded so the re-run
starts from a known conflict set.

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

## Why it is blocked: the Common crate bump

- `379c531fc` (#1907) moved upstream onto `zakura-core/common` after common#638 (Sapling `cv`
  kept as bytes) and changed `zakura-chain`/`zakura-consensus` code to that API
  (`CommitmentSum::try_sum` replaces the removed `Sum` impl).
- `2398c0924` (#1939) bumped every Common dependency to `=5.0.0-rc.4` from crates.io (root
  `Cargo.toml`, 12 crate manifests, `Cargo.lock`, `qa/supply-chain/config.toml`).
- The common fork is at `5.0.0-rc.2+ycash.1` (`1e6d6aa4`, on `zakura-common-ycash-legacy` =
  `bdbca121`, "prepare Common 5.0.0-rc.2"). Its local `upstream/main` is `0d85733b`
  (`5.0.0-rc.3`); `zakura-core/common` `main` is now `3596abb3` (seen with `git ls-remote`, not
  fetched), which carries rc.4.

What has to happen first (the coordinator's, not this chunk's): sync the common fork onto the
upstream Common commit that `5.0.0-rc.4` was published from, re-port the fork lines, version it
`5.0.0-rc.4+ycash.1`, and bump kogany's `[patch.crates-io]` rev in its own commit (rule 8). Then
re-run this sync on top of it.

Upstream's in-repo crate versions also move with `b138edf56` (v1.8.0-rc1: for example
`zakura-state` `11.1.0-rc0` → `12.0.0-rc0`). Those are path crates in this repository and need no
fork; they only show up as manifest conflicts below.

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

## The trial merge (aborted)

`git merge --no-commit --no-ff upstream/main` on `kc/sync-zakura-20261102`: 7 conflicted files,
everything else merged cleanly. Then `git merge --abort`. How each would be resolved on the
re-run:

| File | Conflict | Resolution |
| --- | --- | --- |
| `Cargo.lock` | Common crates rc.2 (fork git source) vs rc.4 (crates.io), and the in-repo version bumps | Regenerate after the fork bump (`cargo update -p` of the changed packages, `--locked` thereafter); never hand-merged |
| `crates/zakura-rpc/Cargo.toml` | upstream `zakura-state` `12.0.0-rc0` against kogany's `kogany-vault`/`kogany-yellowback` optional deps beside the `11.1.0-rc0` line | Take upstream's version line, keep kogany's two optional deps (hook) |
| `crates/zakurad/Cargo.toml` | the same `zakura-state` version line against kogany's `kogany-rpc` dep | Take upstream's version, keep `kogany-rpc` (hook) |
| `crates/zakura-chain/src/parameters/network_upgrade.rs` (consensus path) | `eccae45e4` adds `MAINNET_ACTIVATION_MAP` (a `LazyLock` map) where kogany inserted the `#[cfg(feature = "ycash")]` `CONSENSUS_BRANCH_IDS` table | Keep both, kogany's table first, then upstream's static. The cached map reads `MAINNET_ACTIVATION_HEIGHTS`, which kogany already splits by `cfg(feature = "ycash")` (re-exporting `super::ycash::MAINNET_ACTIVATION_HEIGHTS`), so the `ycash` heights flow through upstream's new `activation_map()` with no further hook |
| `crates/zakura-chain/src/transparent.rs` | `6d3883415` rewrites `address()` to match P2PKH/P2SH script bytes directly; kogany's hook (W7-b, the `TX_PQPKH` `pq_key_id()` branch) sits before the old `TxOut::try_from` match | Take upstream's new body, re-insert kogany's `#[cfg(feature = "ycash")]` `pq_key_id()` block before it unchanged |
| `crates/zakura-consensus/src/block.rs` (consensus path) | upstream's verifier restructuring (`7c4c54842`, `c96f5e3b9`, `8a164df24`, `281fbf94b`) against kogany's hooks in the block verifier body | Take upstream's body, re-apply each kogany hook from the chunk commit bodies (hook table); the consensus-diff report must then show only kogany hunks |
| `crates/zakura-rpc/src/methods.rs` | `0a1aa320c` (reuse a retained template on exact submission) re-nests `submitblock`'s decode-failure return; kogany's W7-e hook returns ycashd's -22 there | Take upstream's nesting, keep kogany's `#[cfg(feature = "ycash")]` -22 return at the new indentation |

## Gates

Not run: the merge was not made, so there is no merged tree to test (feature-off upstream suite,
the `kogany-ycash`/`kogany-regtest` nextest profiles, `kogany-rpc --features ycash`, the pure
crates in debug and release, `xtask check-rpc-artifacts`, `qa/kogany_audit.py all`, the mixed
smoke against ycash6). All run on the re-run.

## Re-pin

None now. After the re-run merges, the coordinator re-pins by the rule-1 procedure: `ref/zakura`
and `kogany-legacy` → `b44ec121d` (or the later tip the re-run merges), with `repos.yaml`,
AGENTS.md (the layout line and the kogany paragraph), and the mapping §24 citations in the same
change.
