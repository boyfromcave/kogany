# kogany CI

kogany is the Ycash developers' fork of Zakura: the third Ycash node line, carrying the vault
network upgrade and the Ycash Yellowback (YED) rule module. This file says which GitHub Actions
workflows run on it, why, and how the rest are kept off. The decision is K-15 of the kogany plan
(`docs/plans/kogany/kogany-yellowback-plan.md` in the Yellowback workspace, §0 and §5).
[`kogany-workflows.txt`](kogany-workflows.txt) is the authoritative list; `qa/kogany_audit.py
workflows` fails when a workflow file is missing from it.

## Which workflows run

| State | Workflows | What changed |
| --- | --- | --- |
| kept | `lint.yml`, `tests-unit.yml`, `zakura-e2e.yml`, `docs-check.yml`, `test-crates.yml`, `header-fuzz.yml`, `rpc-fuzz.yml` | trimmed in place; every edit carries a `kogany (2026-11-01)` comment |
| called | `zakura-cluster.yml` | nothing (a reusable workflow `tests-unit.yml` and `zakura-e2e.yml` call) |
| off | the other 32 upstream workflows: the DigitalOcean fleet and deploy jobs, the release pipeline, `ci-alerts`, `coverage`, `benchmarks`, `legacy-pages`, the cranelift pair, `cross-platform`, `history-growth`, `test-docker`, `zcashd-compat-regtest`, `changelog`, `semver-checks` | nothing in the file; disabled in the repository settings |
| kogany | `kogany-yellowback.yml`, `semgrep.yml`, `codeql.yml`, `secops.yml`, `code-scanning.yml` | ours |

The trims, as K-15 states them:

- `lint.yml` and `tests-unit.yml` also run on pull requests into and pushes to `upgrade/vault`
  and `vaults/**`. Neither runs nightly: `lint.yml`'s unused-deps job and `tests-unit.yml`'s
  release-profile and simulator jobs run on `workflow_dispatch` only, so the nightly-failure
  issue is never opened. `tests-unit.yml`'s crates.io publish-graph check runs only in
  upstream's repository: kogany publishes no crate.
- `zakura-e2e.yml` runs its regtest pr-gate on pull requests into kogany's branches; its long
  four-node modes and block-sync fuzz run weekly (Sunday) instead of nightly.
- `docs-check.yml` also runs on pushes to kogany's branches.
- `test-crates.yml` runs weekly on the default branch, not on kogany's pull requests.
- `header-fuzz.yml` and `rpc-fuzz.yml` keep only the Sunday campaign.
- `.github/workflows/scripts/test_ci_alert.py` (upstream's check that every automatic workflow
  has an alert policy, run by `lint.yml`) lists kogany's five workflows as alert exceptions:
  they report through code scanning and the run summary, and `ci-alerts.yml` is off.
- `.github/dependabot.yml` opens security updates only, grouped per ecosystem.

## Why the off workflows are disabled in the settings, not deleted

kogany stays mergeable with upstream Zakura (plan §4.2 rule 7). A deleted or edited upstream
workflow conflicts on every upstream sync that touches it; most of the off workflows are edited
upstream often (the fleet and release jobs above all). Disabling a workflow in the repository's
Actions settings keeps the file byte for byte as upstream has it, needs one mechanism for all
32, survives every sync, and is reversible one workflow at a time, which is how K-15 turns jobs
back on. Several of them need secrets, self-hosted runners or a DigitalOcean account the fork
does not have, and would fail or queue if they ran.

The edits to the seven kept workflows are the exception: K-15 changes what they run, which no
setting can do. They are confined to the `on:` blocks and one `if:`, and each is commented.

A workflow an upstream sync adds is enabled by default on GitHub. `qa/kogany_audit.py
workflows` (the `audit` job of `kogany-yellowback.yml`, blocking) fails until it is classified
in `kogany-workflows.txt`; an `off` one is then disabled in the settings with the rest.

## Turning Actions on

GitHub Actions are disabled on `boyfromcave/kogany` by the Yellowback lead architect and stay
disabled until the lead architect decides otherwise. When they are turned on:

1. Disable the off set first, in the same session:

   ```bash
   python3 qa/kogany_audit.py workflows --print-disable | grep '^gh workflow disable' | sh
   ```

2. Scheduled workflows run from the default branch, which is `upgrade/vault`. Until
   `vaults/kogany-compat` merges back into it (the W0 gate), `upgrade/vault` holds upstream's
   untrimmed kept workflows (nightly `lint`, `tests-unit`, `zakura-e2e`, daily fuzzing) and none
   of kogany's. Either turn Actions on after that merge, or disable the kept workflows as well
   until then.
3. Settings → Code security: enable code scanning and Dependabot security updates. For
   `semgrep.yml`'s `sync` job, allow GitHub Actions to create pull requests (optionally the
   `SEMGREP_PR_TOKEN` secret, see `contrib/semgrep/README.md`).

What then runs, per event:

| Event | Workflows |
| --- | --- |
| pull request into `upgrade/vault` or `vaults/**` | `lint`, `tests-unit`, `zakura-e2e` (pr-gate), `docs-check` (Markdown paths), `kogany-yellowback`, `semgrep`, `codeql`, `secops` |
| push to `upgrade/vault` or `vaults/kogany-compat` | `lint`, `tests-unit`, `docs-check` (path-filtered), `kogany-yellowback`, `semgrep`, `codeql`, `secops`, `code-scanning` (when its dismissals change) |
| nightly | `semgrep` 02:17, `secops` 03:43, `code-scanning` 03:53 (UTC) |
| weekly | `codeql` Monday 04:41; Sunday: `header-fuzz` 05:13, `rpc-fuzz` 05:43, `test-crates` 06:23, `zakura-e2e` long modes 08:00 |

## kogany-yellowback.yml

| Job | Leg | Blocking |
| --- | --- | --- |
| `audit` | (a) consensus-diff: the consensus path set (`qa/kogany-consensus-paths.txt`) and the forked crates' `Cargo.lock` entries against tag `kogany-baseline` (else `kogany-legacy`); the patch is the reviewers' artefact | report-only |
| `audit` | (b) frozen-file: `qa/kogany-frozen-files.txt` (Orchard, Ironwood, NU5 to NU7) against `kogany-legacy` | report-only |
| `audit` | (e) naming and attribution greps over the lines and commits kogany adds | yes |
| `audit` | dormancy: no upstream test function deleted | yes |
| `audit` | workflows: every workflow classified | yes |
| `build` | `cargo check -p zakura`, `ycash` feature off | yes |
| `build` | the same with `--features ycash` | not until W1-Y1 adds the feature |

The logic is `qa/kogany_audit.py` (stdlib Python, `main(argv=None)`, tests in
`qa/test_kogany_audit.py`); run it locally with `python3 qa/kogany_audit.py all`. The reports go
to `kogany-audit-out/` and the step summary.

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

Upstream's own checks stay beside these: `lint.yml` runs `cargo deny` with the root `deny.toml`,
`cargo vet` over `qa/supply-chain`, and its own pinned `zizmor`. kogany's zizmor configuration
is `contrib/secops/zizmor.yml` rather than `.github/zizmor.yml`, because upstream's zizmor would
discover that path. Checkov is not run: the Dockerfiles are upstream's release images, which
kogany does not publish.
