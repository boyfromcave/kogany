# Common fork sync `fork-sync-rc4`: zakura-common-ycash onto Common 5.0.0-rc.4

Plan §4.2 rules 7 and 8 (`docs/plans/kogany/kogany-yellowback-plan.md` in the Yellowback
workspace). This unblocks the upstream sync recorded in `doc/sync-zakura-20261102.md`
(branch `kc/sync-zakura-20261102`): upstream Zakura `2b062412c5..b44ec121d` moves every Common
crate to `=5.0.0-rc.4` (`2398c0924`, #1939) and uses the API of common#638 (`379c531fc`, #1907).

## The fork side (done)

- **The Common commit rc.4 was published from: `16437a9d`** ("chore(release): prepare Common
  5.0.0-rc.4", #669) on `zakura-core/common` `main`. Proved with the fork's
  `scripts/verify_crates_io.py`, run in a pristine checkout of `16437a9d` with
  `--lock` = upstream Zakura `b44ec121d`'s `Cargo.lock`: all 25 crates kogany patches package
  file for file to their crates.io tarballs, every tarball's SHA-256 matches the lock, and every
  `5.0.0-rc.4` tarball's `.cargo_vcs_info.json` names `16437a9d9fc0`. `zakura-zcash-script 0.0.1`
  and the four `zakura-sensei*` 0.1.0 crates were published from `ca4c341e` (rc.1) and are still
  file-identical at `16437a9d`: upstream did not change them.
- **New fork rev: `049895445b6fe7a9db20b484736008952a6d6d94`**, branch `kc/fork-sync-rc4` of
  `boyfromcave/zakura-common-ycash` (pushed; the coordinator merges it into the fork's
  `vaults/kogany-compat`). It is a merge of `16437a9d` into the fork's `vaults/kogany-compat`
  (`e5515523`); no history was rewritten.
- Versions: every workspace crate `5.0.0-rc.4+ycash.1`; `zakura-zcash-script` `0.0.1+ycash.1`
  (it had no suffix before, although W3-a changed it); udon/bento unchanged (kogany keeps them
  from crates.io).
- Fork tests at the new rev, feature off and on, all green (`cargo test --locked -p
  zakura-protocol -p zakura-address -p zakura-transparent -p zakura-primitives -p
  zakura-zcash-script`, and the same with `--features
  zakura-protocol/ycash,zakura-address/ycash,zakura-transparent/ycash,zakura-primitives/ycash`),
  including `ycash_branch_ids_match_ycashd`, `ycash_activation_heights_match_ycashd` and the
  zcash_script vault vector replays. `cargo check --locked --workspace --all-targets` is green
  both ways, and so is `.github/scripts/check_workflow_triggers.py`. One new upstream test,
  `invalid_sapling_value_commitments_parse_and_fail_verification`, replays a Zcash Canopy
  transaction whose v4 sighash binds Zcash's Canopy branch ID, so it is ignored under `ycash`
  like the fork's other Zcash vectors.

Fork commits between the rev kogany pins now (`1e6d6aa4`) and the new rev:

| Commit | Subject |
| --- | --- |
| `08d6ccb2` | CI: nothing runs outside the fork's branches; ycash-check.yml (trigger policy, callable ycash gate) |
| `e5515523` | CI: the fork's workflows held to our branches; ycash-check.yml callable feature matrix |
| `04989544` | Merge Common 5.0.0-rc.4 (16437a9d) into the fork: 5.0.0-rc.4+ycash.1 |

Upstream Common commits the merge brings in (`bdbca121..16437a9d`): `cd74fe7d` (#659),
`0f4793be` (#638, Sapling `cv` as bytes, `CommitmentSum::try_sum`), `7f0d12d9` (#653), `0d85733b`
(rc.3, #663), `925958d8` (#522), `b7506f0a` (#664), `43123683` (#500), `64293e7c` (#668),
`d56a16a2` (#667), `16437a9d` (rc.4, #669).

## Why kogany is not bumped here

kogany at `18650e75c` still requires `=5.0.0-rc.2` for every Common crate (root `Cargo.toml`
`[workspace.dependencies]`). Cargo applies a `[patch.crates-io]` entry only when the patch's
version satisfies the requirement, and `5.0.0-rc.4+ycash.1` does not satisfy `=5.0.0-rc.2`. The
requirements move to `=5.0.0-rc.4` with upstream `2398c0924`, and kogany's code must move to the
common#638 API with upstream `379c531fc`: both arrive with the Zakura merge. So the bump lands in
the sync-zakura re-run, on its merge.

Trial (scratch, nothing committed): upstream Zakura `b44ec121d` with the patch block below and
`cargo update -p ...` resolves cleanly, every patched crate becomes
`5.0.0-rc.4+ycash.1 (...?rev=049895445b6f...)`, `zakura-udon` stays single from crates.io.
`cargo check -p zakura-chain` on that unforked tree stops at `E0004` (`NetworkUpgrade::Ycash` and
`::Vault` not covered), as expected: only kogany's tree matches those variants.

## What the sync-zakura re-run must do

1. Merge `upstream/main` (`b44ec121d`) as recorded in `doc/sync-zakura-20261102.md`. In the
   root `Cargo.toml`, take upstream's `=5.0.0-rc.4` requirements (all fifteen Common entries;
   `zcash_script` stays `=0.0.1`, which `0.0.1+ycash.1` satisfies) and keep kogany's own lines.
2. As its own commit after the merge (rule 8), replace the rev in every line of the root
   `[patch.crates-io]` block, and update its comment ("Every crate of the published 5.0.0-rc.2
   closure" becomes "5.0.0-rc.4"):

   ```toml
   zakura-address          = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-bellman          = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-bls12-381        = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-equihash         = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-halo2-gadgets    = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-halo2-poseidon   = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-halo2-proofs     = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-jubjub           = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-note-encryption  = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-orchard          = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-orchard-legacy   = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-pairing          = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-pasta-curves     = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-primitives       = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-protocol         = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-reddsa           = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-redjubjub        = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sapling-crypto   = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sensei           = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sensei-artifacts = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sensei-macros    = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sensei-shared    = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-sinsemilla       = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-transparent      = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   zakura-zcash-script     = { git = "https://github.com/boyfromcave/zakura-common-ycash", rev = "049895445b6fe7a9db20b484736008952a6d6d94" }
   ```

   The `[patch."https://github.com/boyfromcave/zakura-common-ycash"]` block (udon `=0.2.0`,
   bento `=0.1.0` from crates.io) stays as it is; the rc.4 lock still pins those versions.
   Put the same rev in `qa/fuzz/vault/Cargo.toml`'s copied patch block, which is behind the root
   today (`7534e26c`, the W2-a commit, while the root pins `1e6d6aa4`; its comment says to keep
   them equal).
3. Re-resolve the lock with the local fork (until cargo can fetch the fork from GitHub directly,
   export `CARGO_NET_GIT_FETCH_WITH_CLI=true GIT_CONFIG_COUNT=1
   GIT_CONFIG_KEY_0="url.file://$WS/zakura-common-ycash.insteadOf"
   GIT_CONFIG_VALUE_0="https://github.com/boyfromcave/zakura-common-ycash"`):

   ```sh
   cargo update -p zakura-address -p zakura-bellman -p zakura-bls12-381 -p zakura-equihash \
     -p zakura-halo2-gadgets -p zakura-halo2-poseidon -p zakura-halo2-proofs -p zakura-jubjub \
     -p zakura-note-encryption -p zakura-orchard -p zakura-orchard-legacy -p zakura-pairing \
     -p zakura-pasta-curves -p zakura-primitives -p zakura-protocol -p zakura-reddsa \
     -p zakura-redjubjub -p zakura-sapling-crypto -p zakura-sensei -p zakura-sensei-artifacts \
     -p zakura-sensei-macros -p zakura-sensei-shared -p zakura-sinsemilla -p zakura-transparent \
     -p zakura-zcash-script
   (cd qa/fuzz/vault && cargo update <the same -p list>)
   ```

   Check that the lock shows each of those crates once, as `5.0.0-rc.4+ycash.1` (or
   `0.0.1+ycash.1`, `0.1.0` for sensei) with source `git+https://github.com/boyfromcave/zakura-common-ycash?rev=049895445b6f...`,
   and `zakura-udon`/`zakura-bento*` once each from the registry.
4. The bump commit's message lists the three fork commits above (and names the upstream Common
   range `bdbca121..16437a9d`).
5. `qa/supply-chain/config.toml`: take upstream's rc.4 version (its Common exemptions move from
   `5.0.0-rc.2` to `5.0.0-rc.4`). kogany's copy carries no entry for the fork's git sources today;
   this chunk adds none.
6. Gates: `cargo check --locked -p zakura --features ycash`, `cargo test --locked -p
   zakura-chain --lib`, `qa/kogany_audit.py all`, then the sync-zakura gates of rule 7.
