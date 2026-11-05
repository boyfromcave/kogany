# kogany CI

kogany is the Ycash developers' fork of Zakura: the third Ycash node line, carrying the vault
network upgrade and the Ycash Yellowback (YED) rule module. This file says which GitHub Actions
workflows run on it, on which events, how the rest are kept from running, and which job re-runs
what. The decision is K-15 of the kogany plan (`docs/plans/kogany/kogany-yellowback-plan.md` in
the Yellowback workspace, §0 and §5); the cross-repository side is the workspace's
`docs/plans/kogany/ci-design.md`. [`kogany-workflows.txt`](kogany-workflows.txt) is the
authoritative list; `qa/kogany_audit.py workflows` enforces it.

## Triggers

The Yellowback lead architect's rule (2026-11-01): never trigger the Zakura jobs kogany does not
want, and nothing at all for a branch that is not kogany's. Every file in `.github/workflows/`
keeps to this policy, and the `workflows` leg of `kogany-audit.yml` fails when one does not:

| Event | Allowed |
| --- | --- |
| `push` | only with a `branches:` filter within `upgrade/vault` and `vaults/**`; no `branches-ignore`, no tag pushes |
| `pull_request` | only with a `branches:` filter (the base) within `upgrade/vault`, `vaults/**` and `kc/**` (agent branches are pushed without CI and tested by their pull request) |
| `schedule` | yes: GitHub runs it from the default branch, `upgrade/vault`, only |
| `workflow_dispatch`, `workflow_call` | yes (`workflow_call` only on `called` and `kogany` workflows) |
| anything else | no: in particular no `create` or `delete` (the inherited-branch cleanup deletes hundreds of branches), no `merge_group` (kogany has no merge queue), no `pull_request_target`, no `workflow_run` |

So a push to a `kc/*` branch, to one of the ~600 inherited upstream branches, or a branch
deletion starts nothing. The leg's tests (`qa/test_kogany_audit.py`, `TriggerPolicyTest`) pin
each of those cases. Upstream's own triggers in the kept workflows (`main`, `feat/**`,
`release/**`, the merge queue) are commented out, each with a `kogany (2026-11-01)` comment.

## Which workflows run

| State | Where | Workflows |
| --- | --- | --- |
| kept | `.github/workflows/` | `lint.yml`, `tests-unit.yml`, `zakura-e2e.yml`, `docs-check.yml`, `test-crates.yml`, `header-fuzz.yml`, `rpc-fuzz.yml`: trimmed in place, every edit commented |
| called | `.github/workflows/` | `zakura-cluster.yml` (reusable; `tests-unit.yml` and `zakura-e2e.yml` call it) |
| off | `.github/workflows-off/` | the other 32 upstream workflows: the DigitalOcean fleet and deploy jobs, the release pipeline, `ci-alerts`, `coverage`, `benchmarks`, `legacy-pages`, the cranelift pair, `cross-platform`, `history-growth`, `test-docker`, `zcashd-compat-regtest`, `changelog`, `semver-checks` |
| kogany | `.github/workflows/` | `kogany-audit.yml`, `kogany-build.yml`, `kogany-tests.yml`, `kogany-bin.yml`, `kogany-client-legs.yml`, `kogany-mixed.yml`, and the security CI `semgrep.yml`, `codeql.yml`, `secops.yml`, `code-scanning.yml` |

The trims, as K-15 states them:

- `lint.yml` and `tests-unit.yml` run on pull requests into kogany's branches and pushes to
  `upgrade/vault` and `vaults/**`. Neither runs nightly: `lint.yml`'s unused-deps job and
  `tests-unit.yml`'s release-profile and simulator jobs run on `workflow_dispatch` only.
  `tests-unit.yml`'s crates.io publish-graph check runs only in upstream's repository.
- `lint.yml`'s Python tests read some off workflows (`ci-alerts.yml`, the deploy and PR-node
  workflows) from `.github/workflows/`; one kogany step copies `.github/workflows-off/*.yml` back
  into that job's checkout first, so upstream's tests run unchanged. Nothing is committed, and no
  workflow can start from a runner's working tree.
- `zakura-e2e.yml` runs its regtest pr-gate on pull requests into kogany's branches; its long
  four-node modes and block-sync fuzz run weekly (Sunday). Pushes run nothing there.
- `docs-check.yml` runs on Markdown changes in kogany's pull requests and pushes.
- `test-crates.yml` runs weekly on the default branch and on dispatch only.
- `header-fuzz.yml` and `rpc-fuzz.yml` keep only the Sunday campaign.
- `.github/workflows/scripts/test_ci_alert.py` lists kogany's automatic workflows as alert
  exceptions: they report through code scanning, the run summary and artifacts.
- `.github/dependabot.yml` opens security updates only, grouped per ecosystem.

## Why the off workflows are moved to `.github/workflows-off/`

Until 2026-11-02 the off set stayed byte for byte in `.github/workflows/` and was to be disabled
in the repository's Actions settings, to keep upstream syncs conflict-free (plan §4.2 rule 7).
That left them one switch away from running: turning Actions on, or an upstream sync adding or
renaming a workflow (GitHub enables a new file by default), would start fleet deploys, release
jobs and `pull_request_target` handlers before anyone disabled them. The lead architect's
requirement is that they must never trigger, so kogany now uses the same mechanism as the common
fork (`zakura-common-ycash`, its `.github/README-ycash.md`):

- GitHub runs only files directly under `.github/workflows/`. A file in `.github/workflows-off/`
  cannot run, whatever the settings say; nothing has to be done in the settings, and no one can
  forget to.
- The files are moved unchanged (`git mv`), so git's rename detection carries an upstream edit to
  one of them across a merge of upstream. The rebase cost the settings approach avoided is a
  conflict only when upstream renames or deletes an off workflow, which the sync agent resolves
  by moving the file again (plan §4.2 rule 7).
- The `workflows` leg reports (report-only) an off file that differs from the upstream pin's copy
  (`qa/UPSTREAM_PIN`, below), expected only between an upstream merge and the re-pin.
- A workflow an upstream sync adds lands in `.github/workflows/`; the leg fails until it is
  classified, and its trigger policy fails it anyway unless its triggers are kogany's. The sync
  agent moves it off or trims it.

To turn an off workflow back on, `git mv` it back, trim its triggers to the policy and change its
state in `kogany-workflows.txt`, in one reviewed commit.

## Workflow and job map

Every kogany workflow uses: `permissions: {}` at the top and `contents: read` per job; a
`concurrency` group per workflow, event and ref (pull requests cancel superseded runs);
`fail-fast: false` on every matrix; `CARGO_INCREMENTAL=0`; a timeout on every job;
`workflow_dispatch`; and a Rust cache keyed per job, saved only from `upgrade/vault` and
`vaults/**` pushes (upstream saves only from `main`, which kogany never builds), restored
everywhere.

**Compartments.** No job of one check `needs:` another check, so a failure never skips an
unrelated job, and "Re-run failed jobs" re-runs exactly the failed ones. A matrix entry is its own
job. The only `needs:` are on a binary a job runs (`koganyd-bin`, `ycash6-node-bin`): re-running
a failed consumer reuses that run's artifact and does not rebuild it; re-running a failed build
re-runs its consumers.

| Workflow | Job (check name) | What it runs | Blocks | Re-runs alone | Duration (cold / cached) |
| --- | --- | --- | --- | --- | --- |
| `kogany-audit` | `audit self-test` | `qa/test_kogany_*.py` | yes | yes | 1 min |
| | `audit consensus-diff` | leg (a), the reviewers' patch artefact | report-only | yes | 1 min |
| | `audit frozen` | leg (b) | report-only | yes | 1 min |
| | `audit greps` | leg (e), naming and attribution | yes | yes | 1 min |
| | `audit dormancy` | no upstream test deleted | yes | yes | 1 min |
| | `audit workflows` | classification, placement, the trigger policy | yes | yes | 1 min |
| | `audit cross-line (c)` | `qa/yellowback-cross-line.py --this-line kogany` against ycash6 at `YCASH6_REV` (and `testdata/yellowback/PIN` naming that commit) | yes | yes | 1 min |
| | `audit vault-params (d)` | `cargo run -p zakura-chain --features ycash --example kogany_vault_params`, ycash6's `qa/yellowback-vault-params.py extract` at `YCASH6_REV`, `qa/kogany_vault_params.py compare` | yes | yes | 15 / 5 min |
| `kogany-build` | `check (ycash feature off)`, `check (… on)` | `cargo check -p kogany --all-targets` | yes | each | 25 / 8 min |
| | `clippy kogany-pure`, `kogany-rpc`, `zakura-chain`, `zakura-consensus`, `zakura-state`, `zakura-rpc-network`, `zakurad` | `cargo clippy --all-targets -D warnings`, ycash feature on (feature off is `lint.yml`'s) | yes | each | 5–35 / 3–10 min |
| | `rustfmt (kogany crates)` | `cargo fmt --check` over `kogany-*` | yes | yes | 1 min |
| `kogany-tests` | `kogany crates (dev / release / ci-tests)` | `kogany-pq`, `kogany-vault`, `kogany-yellowback` | yes | each | 5 / 2 min |
| | `<crate> (feature off)` for `zakura-chain`, `-state`, `-consensus`, `-rpc`, `-network` | nextest profile `all-tests` | yes | each | 20–45 / 8–20 min |
| | `<crate> (ycash)` for `zakura-chain`, `-header-chain`, `-consensus`, `-network`, `-rpc`, `kogany-rpc`, `zakura` | nextest profile `kogany-ycash` (the Ycash-gated tests: `.config/nextest.toml`) | yes | each | 20–50 / 8–20 min |
| | `vault fuzz verdicts` | the 3,735 ycash6 verdicts (W3-e) | yes | yes | 15 / 5 min |
| | `kogany-regtest (report-only)` | nextest profile `kogany-regtest` (W4-e) | no, until the W4 gate | yes | 40 / 15 min |
| `kogany-bin` | `koganyd-bin (ycash, dev)` | the `koganyd-bin` artifact (cross-line contract) | — | yes | 35 / 10 min |
| `kogany-client-legs` | `koganyd / koganyd-bin` (called `kogany-bin`) | this run's `koganyd-bin` | — | yes | 35 / 10 min |
| | `lightwalletd-dd`, `chain-viz`, `yolo` (each report-only) | the client unmodified at its pin against this run's koganyd (`crates/kogany-rpc/qa/kogany_client_legs.py`; yolo's `tests/regtest.rs` kogany mode with ycash6's node-bin) | no, until the lead architect flips one | each | 10–40 min |
| `kogany-mixed` | `koganyd / koganyd-bin`, `ycash6 node-bin` | the two binaries | — | each | 35 / 1 min |
| | `mixed node`, `vault`, `yed`, `fees`, `attest` | ycash6's `qa/kogany_mixed_shards.py run <group>`: `gate` scripts block, `report` scripts never fail the job (all `report` today) | its `gate` scripts | each | 30–120 min |

Blocking means a candidate for a required status check (see "Turning Actions on"); a
`continue-on-error` job never turns its run red. The durations are estimates for a
GitHub-hosted 4-core runner, not measurements: kogany's Actions first ran on 2026-11-02 (push 38f785543).

**The upstream pin.** The audit legs compare against the upstream Zakura commit the tree is
synced to, which `qa/UPSTREAM_PIN` names (since the 2026-11-02 sync, `b44ec121d`), not against
upstream's moving `main` (already past the sync, with tests the tree does not have yet) and not
against `kogany-legacy` until that branch is moved to the pin. An upstream sync bumps
`qa/UPSTREAM_PIN` in its merge; `kogany-legacy` is fast-forwarded to it afterwards (the audit
prints a note while they differ). `kogany-audit.yml` fetches the pin from zakura-core/zakura when
the checkout lacks it. The `greps` leg scans the lines added against the pin and only kogany's
commits, those reachable from neither the pin nor `upstream/main` (where that remote ref exists):
upstream's commits, merged by a sync, carry upstream's own trailers (co-author lines and the
like), which are not kogany's to fail on. The `dormancy` leg counts the tests at the pin, so a
test upstream itself deleted before the pin is not a kogany deletion.

**What runs where.** Locally (seconds, stdlib Python; run before every push): every audit leg
(`python3 qa/kogany_audit.py all`), its tests, the cross-line leg against a local ycash6 clone
(`--other-dir`), the vault-params comparison with a built example, `actionlint` and
`zizmor --offline --config contrib/secops/zizmor.yml .github/workflows/`. Only in CI (heavy
cargo): the build, clippy and test jobs, the client legs and the mixed shards. Locally they are
run by the chunk agents per crate (`-p`), never workspace-wide (the coordination brief).

`kogany-ycash` selects tests by name (`ycash`, `vault`, `bip68`, `yed`, `yellowback`, `kogany`,
`pq`, `falcon`, `slh`, `checkpoint::list`) plus the kogany test binaries; it is the ycash-feature
subset the chunk agents reported green, per crate. A crate whose subset is red on its first CI
run is a finding for the coordinator, not a reason to widen the filter.

## Cross-line contract

What kogany publishes and consumes (the workspace's `docs/plans/kogany/ci-design.md` §3, §5):

- **`koganyd-bin` (published; `zakurad-bin` until 2026-11-02).** `kogany-bin.yml`, a job of its own, on pushes to
  `upgrade/vault` and `vaults/**`, weekly (Saturday, so the default branch always has an unexpired
  one), on dispatch, and called by `kogany-client-legs.yml` and `kogany-mixed.yml`. Artifact
  `koganyd-bin` holding `koganyd-bin.tgz`: `koganyd` and `koganyd-bin.json` (`repository`,
  `commit`, `binary`, `features: ["ycash"]`, `profile: "dev"`, `runner`, `librocksdb`, `rustc`,
  `producer`), built by `cargo build --locked -p kogany --bin koganyd --features ycash` on
  ubuntu-24.04 (it links the runner's librocksdb: run it on ubuntu-24.04 with `librocksdb-dev`).
  Retention 30 days. Consumers (ycash6's `zakurad` job, yolo's kogany entry) search every
  workflow's push, schedule or dispatch runs at their pinned kogany commit and fall back to a
  build there. The rename is the one breaking change of the contract (the Yellowback lead
  architect, 2026-11-02: the Ycash node's binary is `koganyd`): a consumer downloads
  `koganyd-bin` and runs `koganyd` from a kogany pin at or after the rename, `zakurad-bin` and
  `zakurad` from an older one. A `--features ycash` build also produces a `zakurad` binary, which
  refuses to run (exit 2), so a consumer that builds at a new pin must run `target/debug/koganyd`.
- **`ycash6-node-bin` (consumed).** From a push, schedule or dispatch run of ycash6's
  `yellowback-tests.yml` at the commit kogany pins: artifact `ycash6-node-bin` (else its current
  name `node-bin`) holding `node-bin.tgz` with `src/ycashd` and `src/ycash-cli` at its root.
  `kogany-mixed.yml` takes the commit from its `ycash6_rev` input (default: the pin in the file)
  and optionally the run from `ycash6_run_id`, as `workflow_dispatch` or `workflow_call` inputs
  (a caller may pass the `YCASH6_ARTIFACT_TOKEN` secret), and runs the harness from ycash6 at that
  same commit. Both it and `kogany-client-legs.yml`'s yolo job (pinned `YCASH6_REV`) fetch through
  `.github/workflows/scripts/fetch-ycash6-node-bin.sh`, which accepts a run only when its workflow
  file is `yellowback-tests.yml` of `boyfromcave/ycash6`, its `head_sha` is the pin, its event is
  push, schedule or dispatch, and its `build` job succeeded, and checks the downloaded zip against
  the artifact's recorded sha256 digest (ycash6 publishes no `SHA256SUMS` for node-bin yet).
- **Pins kogany holds** (bumped by a reviewed commit, never a branch tip): `YCASH6_REV` in
  `kogany-audit.yml` (must equal `testdata/yellowback/PIN`'s source commit; the cross-line job
  checks it), `YCASH6_REV` in `kogany-mixed.yml` and `kogany-client-legs.yml`, `LWD_REV`, `CHAINVIZ_REV` and `YOLO_REV` in
  `kogany-client-legs.yml`.
- The sidecar (W9) and parity (S5) nightlies follow the `kogany-mixed.yml` pattern with ycash6's
  test rig and yew's `yewd-bin`; they are added, scheduled, once the default branch carries them.

## Turning Actions on

GitHub Actions are off on `boyfromcave/kogany` until the Yellowback lead architect turns them on.
Nothing has to be disabled first: the off set cannot run. When turning them on:

1. Prefer doing it after `vaults/kogany-compat` merges back into `upgrade/vault` (the W0 gate
   merge). Scheduled runs come from the default branch, `upgrade/vault`; until that merge it holds
   upstream's untrimmed workflows in `.github/workflows/` (nightly `lint`, `tests-unit`,
   `zakura-e2e`, the fleet and release workflows) and none of kogany's. If Actions must come on
   earlier, disable every workflow listed on `upgrade/vault` in the Actions UI first.
2. Settings → Actions → General: allow GitHub Actions and the actions the workflows use (every
   `uses:` is SHA-pinned, so "require full-length commit SHA" can be on); workflow permissions
   "Read repository contents"; require approval for outside contributors' pull requests;
   artifact and log retention at least 30 days (the `koganyd-bin` contract).
3. Settings → Code security: enable code scanning (the SARIF uploads) and Dependabot security
   updates. For `semgrep.yml`'s `sync` job, allow GitHub Actions to create pull requests
   (optionally the `SEMGREP_PR_TOKEN` secret, see `contrib/semgrep/README.md`).
4. Optional secret `YCASH6_ARTIFACT_TOKEN` (a fine-grained token with Actions: read on
   `boyfromcave/ycash6`), only if the job token cannot download ycash6's public artifacts.
5. Rulesets on `upgrade/vault` (`vaults/kogany-compat` is a record since 2026-11-05, never committed to), after the first green push run: the
   required checks are the blocking jobs above (`audit self-test`, `audit greps`,
   `audit dormancy`, `audit workflows`, `audit cross-line (c)`, `audit vault-params (d)`, both
   `check`, every `clippy`, `rustfmt (kogany crates)`, every `kogany crates`, `(feature off)` and
   `(ycash)` job, `vault fuzz verdicts`) and upstream's `test success` and lint checks. Add
   `kogany-regtest` at the W4 gate and a `mixed <group>` when its first script becomes `gate`.
6. Confirm one push run of `kogany-bin` published `koganyd-bin`, then set ycash6's repository
   variable `KOGANY_MIXED` (ci-design.md §9).

## Security CI

The same design as every Yellowback repository (`SECURITY-CI.md` of the ycash6 node line); the
workflows and scripts are copied from ycash6, with this repository's lists:

| Leg | Workflow / job | Blocks a pull request when | Accepting a finding |
| --- | --- | --- | --- |
| Semgrep | `semgrep.yml` | the PR adds a critical finding | `contrib/semgrep/accepted.json`, `contrib/semgrep/config.json` |
| CodeQL (`rust`, `python`, `actions`) | `codeql.yml` | never (code scanning shows new alerts) | `contrib/secops/code-scanning-dismissals.json` |
| zizmor | `secops.yml` `zizmor` | any finding | `contrib/secops/zizmor.yml`, or an inline `zizmor: ignore[rule]` with its reason |
| gitleaks | `secops.yml` `gitleaks` | a leak not accepted | `.gitleaksignore` (fingerprints, each under its reason), `.gitleaks.toml` |
| OSV-Scanner | `secops.yml` `osv-scanner` | a known vulnerability not accepted | `osv-scanner.toml` (reason and an expiry at most 90 days out) |
| cargo-deny | `secops.yml` `cargo-deny` | an advisory, ban or source not allowed | `contrib/secops/deny-node.toml` |
| Semgrep rule tests | `secops.yml` `semgrep-rules` | a rule test fails | `contrib/semgrep/rules/` |
| triage | `code-scanning.yml` | never | applies the dismissals file |
| Dependabot | `.github/dependabot.yml` | — | security updates only |

CodeQL reads `.github/codeql/codeql-config.yml`, which excludes, besides generated code: upstream
Zakura's operator tooling (`deploy/`, `scripts/zakura-metrics-dashboard.py`,
`scripts/pack-assets-crate.py`; path-injection, response-splitting, clear-text-storage,
overly-permissive-file and insecure-protocol alerts), which is not part of koganyd and is left as
upstream wrote it (none fixed upstream past `b44ec121d` as of 2026-11-02); and test code
(`**/tests/**`, `**/testdata/**`), whose fixed test vectors trip the hard-coded-salt rule by design.
gitleaks allows `qa/fuzz/vault/verdicts/` (hex fuzz vectors) in `.gitleaks.toml`.

Upstream's own checks stay beside these: `lint.yml` runs `cargo deny` with the root `deny.toml`,
`cargo vet` over `qa/supply-chain`, and its own pinned `zizmor`. kogany's zizmor configuration
is `contrib/secops/zizmor.yml` rather than `.github/zizmor.yml`, because upstream's zizmor would
discover that path. Checkov is not run: the Dockerfiles are upstream's release images, which
kogany does not publish.
