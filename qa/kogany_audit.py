#!/usr/bin/env python3
# Copyright (c) 2026 The Ycash developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php .
"""kogany's audit legs (plan docs/plans/kogany/kogany-yellowback-plan.md §5; .github/README-kogany.md).

  qa/kogany_audit.py [--repo DIR] [--base REF] [--upstream REF] [--out DIR] <leg> [<leg> ...]

Legs (`all` runs every one; kogany-yellowback.yml runs `all`):

  consensus-diff  (a) report-only. The delta of the consensus path set
                  (qa/kogany-consensus-paths.txt) and of the forked crates' Cargo.lock entries,
                  against --base (default: tag kogany-baseline, else kogany-legacy). Writes
                  consensus-diff.patch and consensus-diff.md: the artefact the two reviewers read.
  frozen          (b) report-only. Any delta of qa/kogany-frozen-files.txt against --upstream
                  (default kogany-legacy). A non-zero report is a plan §9 finding.
  greps           (e) blocking. The lines kogany adds against --upstream, and the messages of its
                  commits, must not carry the retired or upstream product names (AGENTS.md rule 6;
                  a path that cites an upstream file is allowed) or AI attribution (rule 8).
  dormancy        blocking. No upstream Rust test function present at --upstream is missing at
                  HEAD (plan §2.5: every Zakura test, NU5-NU7 and Ironwood included, keeps running
                  on the feature-off build; a deleted one fails the gate).
  workflows       blocking. Every file in .github/workflows is classified in
                  .github/kogany-workflows.txt and every entry exists. --print-disable prints the
                  `gh workflow disable` commands for the `off` entries.

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
BASE_REFS = ("kogany-baseline", "refs/tags/kogany-baseline") + UPSTREAM_REFS


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
    log = git(repo, "log", "--format=%H%x00%B%x00", "%s..HEAD" % upstream)
    parts = log.split("\x00")
    for sha, body in zip(parts[0::2], parts[1::2]):
        sha = sha.strip()
        for m in COMMIT_ATTRIBUTION.finditer(body):
            hits.append("commit %s: %r" % (sha[:12], m.group(0)))
    lines = ["## audit (e) naming and attribution greps (blocking)", "",
             "Lines and commits added against `%s`." % upstream, ""]
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
    wf_dir = os.path.join(repo, ".github", "workflows")
    present = sorted(f for f in os.listdir(wf_dir) if f.endswith((".yml", ".yaml")))
    errors += ["%s: not classified in %s" % (f, WORKFLOW_MANIFEST) for f in present if f not in rows]
    errors += ["%s: listed in %s but absent" % (f, WORKFLOW_MANIFEST) for f in rows if f not in present]
    counts = {s: sum(1 for st, _ in rows.values() if st == s) for s in WORKFLOW_STATES}
    lines = ["## workflow classification (blocking)", "",
             "%d workflow file(s): %s." % (len(present), ", ".join("%d %s" % (counts[s], s) for s in WORKFLOW_STATES)), ""]
    lines += ["%d problem(s):" % len(errors), ""] + ["- %s" % e for e in errors] if errors else ["Every workflow is classified."]
    report = "\n".join(lines) + "\n"
    write(out, "workflows.md", report)
    print(report)
    summary(report)
    if args.print_disable:
        for f, (state, _) in sorted(rows.items()):
            if state == "off":
                print("gh workflow disable %s --repo %s" % (f, args.github_repo))
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
                    help="consensus-diff base (default: kogany-baseline, else kogany-legacy)")
    ap.add_argument("--upstream", default=os.environ.get("KOGANY_AUDIT_UPSTREAM"),
                    help="the upstream pin (default: kogany-legacy)")
    ap.add_argument("--out", default="kogany-audit-out")
    ap.add_argument("--print-disable", action="store_true",
                    help="workflows: print `gh workflow disable` for every `off` entry")
    ap.add_argument("--github-repo", default="boyfromcave/kogany")
    args = ap.parse_args(argv)

    repo = args.repo or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    repo = git(repo, "rev-parse", "--show-toplevel").strip()
    legs = list(LEGS) if "all" in args.legs else args.legs
    try:
        upstream = pick_ref(repo, args.upstream, UPSTREAM_REFS, "upstream pin")
        base = pick_ref(repo, args.base, BASE_REFS, "consensus-diff base")
        rc = 0
        for leg in legs:
            rc |= LEGS[leg](repo, base, upstream, args.out, args)
    except AuditError as e:
        print("kogany_audit.py: %s" % e, file=sys.stderr)
        return 2
    return rc


if __name__ == "__main__":
    sys.exit(main())
