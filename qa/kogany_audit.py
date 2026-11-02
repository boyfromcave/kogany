#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""kogany's audit legs (plan docs/plans/kogany/kogany-yellowback-plan.md §5; .github/README-kogany.md).

  qa/kogany_audit.py [--repo DIR] [--base REF] [--upstream REF] [--out DIR] <leg> [<leg> ...]

Legs (`all` runs every one; kogany-audit.yml runs each leg as its own job):

  consensus-diff  (a) report-only. The delta of the consensus path set
                  (qa/kogany-consensus-paths.txt) and of the forked crates' Cargo.lock entries,
                  against --base (default: tag kogany-baseline, else the upstream pin). Writes
                  consensus-diff.patch and consensus-diff.md: the artefact the two reviewers read.
  frozen          (b) report-only. Any delta of qa/kogany-frozen-files.txt against --upstream
                  (default: the upstream pin, below). A non-zero report is a plan §9 finding.
  greps           (e) blocking. The lines kogany adds against --upstream, and the messages of its
                  commits, must not carry the retired or upstream product names (AGENTS.md rule 6;
                  a path that cites an upstream file is allowed) or AI attribution (rule 8).
                  "Its commits" are those reachable from HEAD and from neither --upstream nor
                  upstream/main (when that remote ref exists): upstream's own commits, merged by a
                  sync, carry upstream's trailers (Co-Authored-By and the like) and are never ours.
  dormancy        blocking. No upstream Rust test function present at --upstream is missing at
                  HEAD (plan §2.5: every Zakura test, NU5-NU7 and Ironwood included, keeps running
                  on the feature-off build; a deleted one fails the gate).
  workflows       blocking. Every workflow file is classified in .github/kogany-workflows.txt and
                  lives where its state says (`off` in .github/workflows-off/, which GitHub never
                  runs; the rest in .github/workflows/), and every file in .github/workflows/
                  keeps to the trigger policy: events only push, pull_request, schedule,
                  workflow_dispatch and workflow_call (no create, delete, merge_group,
                  pull_request_target, workflow_run, ...); push only with a branches filter within
                  upgrade/vault and vaults/**; pull_request only with a branches filter within
                  upgrade/vault, vaults/** and kc/**; no branches-ignore, no tag pushes.

The upstream pin. --upstream (or KOGANY_AUDIT_UPSTREAM) names it explicitly; by default it is
the commit in qa/UPSTREAM_PIN, the upstream Zakura commit the tree is synced to, which an upstream
sync bumps in its merge (so a sync never leaves the greps leg scanning upstream's commits or the
dormancy leg counting tests upstream itself deleted). It must resolve: kogany-audit.yml fetches it
from zakura-core/zakura when the checkout lacks it. Without qa/UPSTREAM_PIN the default is the
kogany-legacy branch. When kogany-legacy resolves to another commit, the run says so (kogany-legacy
is moved to the pin after each sync) but does not fail.

The report-only legs exit 0 whatever they find (non-zero only on an error); the blocking legs exit
1 on a finding. Reports go to --out (default kogany-audit-out/) and to stdout; with
GITHUB_STEP_SUMMARY set, a summary is appended there too. Stdlib only.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys

CONSENSUS_PATHS = "qa/kogany-consensus-paths.txt"
FROZEN_FILES = "qa/kogany-frozen-files.txt"
WORKFLOW_MANIFEST = ".github/kogany-workflows.txt"
WORKFLOW_STATES = ("kept", "called", "off", "kogany")

# Leg (e). The names rule 6 retires, and the attribution rule 8 forbids. A match inside a path
# token (one with a `/` and no `://`) cites an upstream file and is allowed, as rule 6 allows; an
# attribution match never is. The patterns are written split so this file does not match itself.
NAMING = re.compile("|".join([
    "Digi" + "Dollar", "digi" + "dollar", "y" + "dollar", "YDollar".replace("YD", "Y" + "D"),
    r"\by" + "d_",
]))
ATTRIBUTION = re.compile("|".join([
    "Co-" + "Authored-By", "Clau" + "de", r"clau" + r"de\.ai", "Generated " + "with", "Anthro" + "pic",
]))
COMMIT_ATTRIBUTION = re.compile("|".join([
    "clau" + "de", "co-" + "authored", "anthro" + "pic", "generated " + "with",
]), re.IGNORECASE)
# Files that hold the patterns themselves.
GREP_EXEMPT = {"qa/kogany_audit.py", "qa/test_kogany_audit.py"}

TEST_ATTR = re.compile(r"#\[\s*(?:[\w:]+::)?test\b[^\]]*\]")
FN_DECL = re.compile(r"(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)")


class AuditError(Exception):
    pass


def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if check and r.returncode:
        raise AuditError("git %s: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def resolves(repo, ref):
    return subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "--quiet", ref + "^{commit}"],
                          capture_output=True, text=True).returncode == 0


def pick_ref(repo, explicit, candidates, what):
    if explicit:
        if not resolves(repo, explicit):
            raise AuditError("%s %r does not resolve" % (what, explicit))
        return explicit
    for ref in candidates:
        if resolves(repo, ref):
            return ref
    raise AuditError("no %s: none of %s resolves (fetch with tags and full history)" % (what, ", ".join(candidates)))


UPSTREAM_REFS = ("kogany-legacy", "origin/kogany-legacy", "refs/remotes/origin/kogany-legacy")
BASE_REFS = ("kogany-baseline", "refs/tags/kogany-baseline")
UPSTREAM_PIN = "qa/UPSTREAM_PIN"
# Upstream's moving branch, when the checkout has it: commits reachable from it are upstream's.
UPSTREAM_MAIN_REFS = ("upstream/main", "refs/remotes/upstream/main")


def read_upstream_pin(repo):
    """The commit qa/UPSTREAM_PIN names (comments and blanks dropped), or None without the file."""
    path = os.path.join(repo, UPSTREAM_PIN)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        shas = [l.split("#", 1)[0].strip() for l in f]
    shas = [x for x in shas if x]
    if len(shas) != 1 or not re.fullmatch(r"[0-9a-f]{40}", shas[0]):
        raise AuditError("%s must name exactly one full commit hash" % UPSTREAM_PIN)
    return shas[0]


def pick_upstream(repo, explicit):
    """--upstream, else qa/UPSTREAM_PIN, else kogany-legacy (module docstring, "The upstream pin")."""
    if explicit:
        return pick_ref(repo, explicit, (), "upstream pin")
    pin = read_upstream_pin(repo)
    if pin is None:
        return pick_ref(repo, None, UPSTREAM_REFS, "upstream pin")
    if not resolves(repo, pin):
        raise AuditError("the upstream pin %s (%s) is not in this checkout: fetch it with "
                         "`git fetch https://github.com/zakura-core/zakura.git %s`" % (pin, UPSTREAM_PIN, pin))
    for ref in UPSTREAM_REFS:
        if resolves(repo, ref):
            legacy = git(repo, "rev-parse", ref + "^{commit}").strip()
            if legacy != pin:
                print("note: %s is %s, not the upstream pin %s (%s); the audit uses the pin"
                      % (ref, legacy[:12], pin[:12], UPSTREAM_PIN), file=sys.stderr)
            break
    return pin


def read_list(repo, rel):
    """Path entries and `lock:` entries of a list file (comments and blanks dropped)."""
    paths, locks = [], []
    with open(os.path.join(repo, rel), encoding="utf-8") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith("lock:"):
                locks.append(line[len("lock:"):].strip())
            else:
                paths.append(line)
    return paths, locks


def matches(path, entries):
    for e in entries:
        if e.endswith("/"):
            if path.startswith(e):
                return True
        elif fnmatch.fnmatchcase(path, e):
            return True
    return False


def changed_files(repo, base, head="HEAD"):
    """[(status, path)] of `git diff base head`, renames split into delete + add."""
    out = git(repo, "diff", "--name-status", "--no-renames", base, head)
    rows = []
    for line in out.splitlines():
        status, path = line.split("\t", 1)
        rows.append((status[0], path))
    return rows


def lock_packages(text, names):
    """{name: [entry text]} for the Cargo.lock [[package]] entries of `names`."""
    found = {}
    for block in text.split("\n[[package]]\n")[1:]:
        m = re.search(r'^name = "([^"]+)"', block, re.M)
        if m and m.group(1) in names:
            found.setdefault(m.group(1), []).append(block.strip().split("\n\n")[0])
    return found


def show(repo, ref, path):
    r = subprocess.run(["git", "-C", repo, "show", "%s:%s" % (ref, path)], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else ""


def write(out, name, text):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, name), "w", encoding="utf-8") as f:
        f.write(text)


def summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


# --- (a) consensus-diff ------------------------------------------------------------------------

def leg_consensus_diff(repo, base, upstream, out, args):
    paths, locks = read_list(repo, CONSENSUS_PATHS)
    files = [(s, p) for s, p in changed_files(repo, base) if matches(p, paths)]
    patch = ""
    if files:
        patch = git(repo, "diff", "--no-renames", base, "HEAD", "--", *sorted({p for _, p in files}))
    before = lock_packages(show(repo, base, "Cargo.lock"), set(locks))
    after = lock_packages(show(repo, "HEAD", "Cargo.lock"), set(locks))
    lock_rows = []
    for name in locks:
        if before.get(name) != after.get(name):
            lock_rows.append("- `%s`: %s -> %s" % (
                name, " / ".join(e.split("\n")[1] for e in before.get(name, [])) or "absent",
                " / ".join(e.split("\n")[1] for e in after.get(name, [])) or "absent"))
    stat = git(repo, "diff", "--no-renames", "--stat=120", base, "HEAD", "--",
               *sorted({p for _, p in files})) if files else ""
    lines = ["## audit (a) consensus-diff (report-only)", "",
             "Base `%s` (%s), head `%s`; path set `%s`." % (
                 base, git(repo, "rev-parse", "--short=12", base).strip(),
                 git(repo, "rev-parse", "--short=12", "HEAD").strip(), CONSENSUS_PATHS), ""]
    if not files and not lock_rows:
        lines.append("Empty: no change to the consensus path set or the forked crates' lock entries.")
    else:
        lines += ["%d file(s) changed:" % len(files), "", "```", stat.rstrip(), "```", ""]
        if lock_rows:
            lines += ["Forked-crate Cargo.lock entries changed:", ""] + lock_rows
    report = "\n".join(lines) + "\n"
    write(out, "consensus-diff.md", report)
    write(out, "consensus-diff.patch", patch)
    print(report)
    summary(report)
    return 0


# --- (b) frozen ---------------------------------------------------------------------------------

def leg_frozen(repo, base, upstream, out, args):
    paths, _ = read_list(repo, FROZEN_FILES)
    files = [(s, p) for s, p in changed_files(repo, upstream) if matches(p, paths)]
    lines = ["## audit (b) frozen-file (report-only)", "",
             "Against `%s`; list `%s`." % (upstream, FROZEN_FILES), ""]
    if files:
        lines += ["%d frozen file(s) changed (a plan §9 finding each):" % len(files), ""]
        lines += ["- %s `%s`" % (s, p) for s, p in files]
    else:
        lines.append("Zero delta.")
    report = "\n".join(lines) + "\n"
    write(out, "frozen.md", report)
    print(report)
    summary(report)
    return 0


# --- (e) greps ----------------------------------------------------------------------------------

def citation_spans(line):
    """Spans of the path tokens in `line` (a `/` and no `://`): upstream-file citations."""
    spans = []
    for m in re.finditer(r"\S+", line):
        tok = m.group(0)
        if "/" in tok and "://" not in tok:
            spans.append(m.span())
    return spans


def line_findings(line):
    """The forbidden matches in one line, after the rule-6 citation allowance."""
    found = [m.group(0) for m in ATTRIBUTION.finditer(line)]
    cites = citation_spans(line)
    for m in NAMING.finditer(line):
        if not any(a <= m.start() and m.end() <= b for a, b in cites):
            found.append(m.group(0))
    return found


def added_lines(repo, upstream):
    """(path, line number, text) of every line HEAD adds against `upstream`."""
    out = git(repo, "diff", "--no-renames", "--no-color", "--unified=0", upstream, "HEAD")
    path, lineno = None, 0
    for raw in out.splitlines():
        if raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("@@"):
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and path is not None:
            yield path, lineno, raw[1:]
            lineno += 1


def leg_greps(repo, base, upstream, out, args):
    hits = []
    for path, lineno, text in added_lines(repo, upstream):
        if path in GREP_EXEMPT:
            continue
        for word in line_findings(text):
            hits.append("%s:%d: %r" % (path, lineno, word))
    # Only kogany's commits: not upstream's, which a sync merges with upstream's own trailers.
    excluded = [upstream] + [r for r in UPSTREAM_MAIN_REFS if resolves(repo, r)][:1]
    log = git(repo, "log", "--format=%H%x00%B%x00", "HEAD", *("^" + r for r in excluded))
    parts = log.split("\x00")
    for sha, body in zip(parts[0::2], parts[1::2]):
        sha = sha.strip()
        for m in COMMIT_ATTRIBUTION.finditer(body):
            hits.append("commit %s: %r" % (sha[:12], m.group(0)))
    lines = ["## audit (e) naming and attribution greps (blocking)", "",
             "Lines added against `%s`; commits reachable from HEAD and not from %s." % (
                 upstream, ", ".join("`%s`" % r for r in excluded)), ""]
    lines += ["%d finding(s):" % len(hits), ""] + ["- %s" % h for h in hits] if hits else ["None."]
    report = "\n".join(lines) + "\n"
    write(out, "greps.md", report)
    print(report)
    summary(report)
    return 1 if hits else 0


# --- dormancy -----------------------------------------------------------------------------------

def test_functions(text):
    """Names of the functions under a #[test]-style attribute (#[test], #[tokio::test], ...)."""
    names = []
    for m in TEST_ATTR.finditer(text):
        rest = text[m.end():]
        # Skip further attributes and comments between the test attribute and the fn.
        rest = re.sub(r"\A(?:\s|#\[[^\]]*\]|//[^\n]*\n)*", "", rest)
        d = FN_DECL.match(rest)
        if d:
            names.append(d.group(1))
    return names


def rust_tests(repo, ref):
    """{(crate dir, test name): count} for every crates/**.rs file at `ref`."""
    listing = git(repo, "ls-tree", "-r", "--name-only", ref, "--", "crates")
    paths = [p for p in listing.splitlines() if p.endswith(".rs")]
    tests = {}
    if not paths:
        return tests
    proc = subprocess.run(["git", "-C", repo, "cat-file", "--batch"], input="".join(
        "%s:%s\n" % (ref, p) for p in paths).encode(), capture_output=True, check=True)
    data, pos = proc.stdout, 0
    for p in paths:
        header_end = data.index(b"\n", pos)
        header = data[pos:header_end].split()
        size = int(header[2])
        body = data[header_end + 1:header_end + 1 + size].decode("utf-8", "replace")
        pos = header_end + 1 + size + 1
        crate = "/".join(p.split("/")[:2])
        for name in test_functions(body):
            tests[(crate, name)] = tests.get((crate, name), 0) + 1
    return tests


def leg_dormancy(repo, base, upstream, out, args):
    before, after = rust_tests(repo, upstream), rust_tests(repo, "HEAD")
    missing = sorted((k, n - after.get(k, 0)) for k, n in before.items() if after.get(k, 0) < n)
    lines = ["## dormancy: upstream tests kept (blocking)", "",
             "%d upstream test function(s) at `%s`, %d at HEAD." % (
                 sum(before.values()), upstream, sum(after.values())), ""]
    if missing:
        lines += ["%d upstream test(s) missing at HEAD:" % len(missing), ""]
        lines += ["- `%s` `%s`%s" % (c, n, "" if k == 1 else " (x%d)" % k) for (c, n), k in missing]
    else:
        lines.append("None missing.")
    report = "\n".join(lines) + "\n"
    write(out, "dormancy.md", report)
    print(report)
    summary(report)
    return 1 if missing else 0


# --- workflows ----------------------------------------------------------------------------------
#
# Where each state lives. GitHub runs only files directly under .github/workflows/, so an `off`
# workflow is moved, byte for byte, to .github/workflows-off/: inert whatever the repository's
# Actions settings say, and git's rename detection carries an upstream edit to it across a sync.
WORKFLOW_DIR = ".github/workflows"
WORKFLOW_OFF_DIR = ".github/workflows-off"
# The trigger policy (the lead architect, 2026-11-01; .github/README-kogany.md "Triggers"): nothing
# runs for a branch that is not ours. Pushes only to upgrade/vault and vaults/**; pull requests only
# into upgrade/vault, vaults/** and kc/**; no create/delete (the inherited-branch cleanup deletes
# hundreds of branches), no merge queue, no pull_request_target, no workflow_run fan-out.
ALLOWED_EVENTS = ("push", "pull_request", "schedule", "workflow_dispatch", "workflow_call")
PUSH_BRANCHES = ("upgrade/vault", "vaults/**")
PR_BRANCHES = ("upgrade/vault", "vaults/**", "kc/**")


def _yaml_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def _strip_comment(line):
    """`line` without a trailing `# comment` (outside quotes)."""
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i].rstrip()
    return line.rstrip()


def _flow_list(text):
    inner = text.strip()[1:-1]
    return [_yaml_scalar(x) for x in inner.split(",") if x.strip()]


def _inline(text):
    text = text.strip()
    if text.startswith("[") and text.endswith("]"):
        return _flow_list(text)
    if text == "{}":
        return {}
    if text in ("", "~", "null"):
        return None
    return _yaml_scalar(text)


def _block(lines, i, indent):
    """Parse the block of `lines` from `i` at `indent`: (value, next index). Mappings, block and
    flow lists and scalars: the subset GitHub workflow triggers use."""
    if i < len(lines) and lines[i][1].startswith("- "):
        items = []
        while i < len(lines) and lines[i][0] == indent and lines[i][1].startswith("- "):
            body = lines[i][1][2:]
            if ":" in body and not body.lstrip().startswith(("'", '"', "[")):
                # A mapping item: re-read it as a mapping at the item's inner indent.
                sub = [(indent + 2, body)]
                j = i + 1
                while j < len(lines) and lines[j][0] > indent:
                    sub.append(lines[j])
                    j += 1
                value, _ = _block(sub, 0, indent + 2)
                items.append(value)
                i = j
            else:
                items.append(_inline(body))
                i += 1
        return items, i
    mapping = {}
    while i < len(lines) and lines[i][0] == indent:
        text = lines[i][1]
        if ":" not in text:
            raise AuditError("unparsed workflow line %r" % text)
        key, rest = text.split(":", 1)
        key = _yaml_scalar(key)
        i += 1
        if rest.strip():
            mapping[key] = _inline(rest)
        elif i < len(lines) and lines[i][0] > indent:
            mapping[key], i = _block(lines, i, lines[i][0])
        else:
            mapping[key] = None
    return mapping, i


def workflow_triggers(text):
    """The `on:` value of a workflow file, as {event: config}. Stdlib only: a small reader of the
    YAML subset triggers are written in, which fails closed (AuditError) on anything else."""
    raw = text.splitlines()
    for n, line in enumerate(raw):
        m = re.match(r"""^(?:on|'on'|"on")\s*:(.*)$""", line)
        if not m:
            continue
        rest = _strip_comment(m.group(1)).strip()
        if rest:
            value = _inline(rest)
            if isinstance(value, list):
                return dict.fromkeys(value)
            if isinstance(value, str):
                return {value: None}
            raise AuditError("unparsed `on:` value %r" % rest)
        block = []
        for line2 in raw[n + 1:]:
            stripped = _strip_comment(line2)
            if not stripped.strip():
                continue
            ind = len(stripped) - len(stripped.lstrip(" "))
            if ind == 0:
                break
            block.append((ind, stripped.strip()))
        if not block:
            raise AuditError("empty `on:` block")
        value, end = _block(block, 0, block[0][0])
        if end != len(block) or not isinstance(value, dict):
            raise AuditError("unparsed `on:` block")
        return value
    raise AuditError("no `on:` key")


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def trigger_problems(name, triggers):
    """The trigger-policy violations of one workflow (an empty list when it complies)."""
    problems = []
    for event, config in triggers.items():
        if event not in ALLOWED_EVENTS:
            problems.append("%s: event `%s` is not allowed (only %s)" % (name, event, ", ".join(ALLOWED_EVENTS)))
            continue
        if event not in ("push", "pull_request"):
            continue
        allowed = PUSH_BRANCHES if event == "push" else PR_BRANCHES
        config = config if isinstance(config, dict) else {}
        if "branches-ignore" in config:
            problems.append("%s: `%s` uses branches-ignore (runs on every other branch)" % (name, event))
        if event == "push" and ("tags" in config or "tags-ignore" in config):
            problems.append("%s: `push` has a tags filter (kogany pushes no tag to build)" % name)
        branches = _as_list(config.get("branches"))
        if not branches:
            problems.append("%s: `%s` has no branches filter (runs on every branch)" % (name, event))
        for b in branches:
            # A pattern of the policy itself, or a plain branch name one of them covers.
            if not (b in allowed or (not set(b) & set("*?[]!+") and any(
                    fnmatch.fnmatchcase(b, a.replace("**", "*")) for a in allowed))):
                problems.append("%s: `%s` branch `%s` is not one of %s" % (name, event, b, ", ".join(allowed)))
    return problems


def read_manifest(repo):
    rows, errors = {}, []
    with open(os.path.join(repo, WORKFLOW_MANIFEST), encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split(None, 2)
            if len(fields) < 2 or fields[0] not in WORKFLOW_STATES:
                errors.append("%s:%d: expected '<%s> <file> <reason>'" % (WORKFLOW_MANIFEST, n, "|".join(WORKFLOW_STATES)))
                continue
            if fields[1] in rows:
                errors.append("%s:%d: %s listed twice" % (WORKFLOW_MANIFEST, n, fields[1]))
            rows[fields[1]] = (fields[0], fields[2] if len(fields) > 2 else "")
    return rows, errors


def leg_workflows(repo, base, upstream, out, args):
    rows, errors = read_manifest(repo)
    wf_dir, off_dir = os.path.join(repo, WORKFLOW_DIR), os.path.join(repo, WORKFLOW_OFF_DIR)

    def listing(d):
        return sorted(f for f in os.listdir(d) if f.endswith((".yml", ".yaml"))) if os.path.isdir(d) else []

    present, moved = listing(wf_dir), listing(off_dir)
    errors += ["%s/%s: not classified in %s" % (WORKFLOW_DIR, f, WORKFLOW_MANIFEST) for f in present if f not in rows]
    errors += ["%s/%s: not classified in %s" % (WORKFLOW_OFF_DIR, f, WORKFLOW_MANIFEST) for f in moved if f not in rows]
    for f, (state, _) in sorted(rows.items()):
        home, other = (moved, present) if state == "off" else (present, moved)
        home_dir = WORKFLOW_OFF_DIR if state == "off" else WORKFLOW_DIR
        if f in other:
            errors.append("%s: `%s` but in %s (an `off` workflow lives in %s/, every other in %s/)" % (
                f, state, WORKFLOW_OFF_DIR if state != "off" else WORKFLOW_DIR, WORKFLOW_OFF_DIR, WORKFLOW_DIR))
        elif f not in home:
            errors.append("%s: listed `%s` in %s but absent from %s/" % (f, state, WORKFLOW_MANIFEST, home_dir))
    # The trigger policy, on every file GitHub could run.
    for f in present:
        with open(os.path.join(wf_dir, f), encoding="utf-8") as fh:
            text = fh.read()
        try:
            triggers = workflow_triggers(text)
        except AuditError as e:
            errors.append("%s: triggers unreadable (%s)" % (f, e))
            continue
        errors += trigger_problems(f, triggers)
        if "workflow_call" in triggers and rows.get(f, ("",))[0] not in ("called", "kogany"):
            errors.append("%s: `workflow_call` on a `%s` workflow" % (f, rows.get(f, ("unclassified",))[0]))
    # Report-only: an `off` file should stay byte for byte upstream's, so a sync merges cleanly.
    drift = []
    for f in moved:
        theirs = show(repo, upstream, "%s/%s" % (WORKFLOW_DIR, f))
        with open(os.path.join(off_dir, f), encoding="utf-8") as fh:
            if theirs and fh.read() != theirs:
                drift.append(f)
    counts = {s: sum(1 for st, _ in rows.values() if st == s) for s in WORKFLOW_STATES}
    lines = ["## workflow classification and triggers (blocking)", "",
             "%d workflow file(s) in %s/, %d in %s/: %s." % (
                 len(present), WORKFLOW_DIR, len(moved), WORKFLOW_OFF_DIR,
                 ", ".join("%d %s" % (counts[s], s) for s in WORKFLOW_STATES)),
             "Trigger policy: push only to %s; pull requests only into %s; events only %s." % (
                 ", ".join(PUSH_BRANCHES), ", ".join(PR_BRANCHES), ", ".join(ALLOWED_EVENTS)), ""]
    lines += ["%d problem(s):" % len(errors), ""] + ["- %s" % e for e in errors] if errors else \
        ["Every workflow is classified, in its place, and within the trigger policy."]
    if drift:
        lines += ["", "Report-only: %d `off` file(s) differ from `%s` (expected only between an upstream "
                  "merge and the re-pin): %s" % (len(drift), upstream, ", ".join(drift))]
    report = "\n".join(lines) + "\n"
    write(out, "workflows.md", report)
    print(report)
    summary(report)
    return 1 if errors else 0


LEGS = {
    "consensus-diff": leg_consensus_diff,
    "frozen": leg_frozen,
    "greps": leg_greps,
    "dormancy": leg_dormancy,
    "workflows": leg_workflows,
}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("legs", nargs="+", choices=sorted(LEGS) + ["all"])
    ap.add_argument("--repo", default=None, help="the kogany checkout (default: this file's repository)")
    ap.add_argument("--base", default=os.environ.get("KOGANY_AUDIT_BASE"),
                    help="consensus-diff base (default: kogany-baseline, else the upstream pin)")
    ap.add_argument("--upstream", default=os.environ.get("KOGANY_AUDIT_UPSTREAM"),
                    help="the upstream pin (default: qa/UPSTREAM_PIN, else kogany-legacy)")
    ap.add_argument("--out", default="kogany-audit-out")
    args = ap.parse_args(argv)

    repo = args.repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo = git(repo, "rev-parse", "--show-toplevel").strip()
    legs = list(LEGS) if "all" in args.legs else args.legs
    try:
        upstream = pick_upstream(repo, args.upstream)
        base = pick_ref(repo, args.base, BASE_REFS, "consensus-diff base") if args.base or any(
            resolves(repo, r) for r in BASE_REFS) else upstream
        rc = 0
        for leg in legs:
            rc |= LEGS[leg](repo, base, upstream, args.out, args)
    except AuditError as e:
        print("kogany_audit.py: %s" % e, file=sys.stderr)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
