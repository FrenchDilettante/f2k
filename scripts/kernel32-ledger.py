#!/usr/bin/env python3
"""
Print the kernel32 contract ledger's per-group progress report.

The ledger (scripts/kernel32-ledger.yaml) maps every export of the
kernel32 surface to its API group, its contract status, and the host
scenarios that pin it (each enabled or not). The report shows, per
group: the exports, the contracts pinned, the scenarios dumped, the
scenarios enabled, the scenarios passing, and the unpinned list.

Statuses: `pinned` (behavior defined from the repository's sources, no
scenarios yet), `dumped` (scenarios written, not all enabled),
`enabled` (every scenario enabled), `unpinned` (a gap, with a one-line
`reason`). A group's own scenarios (the ones over all its members) sit
under the group.

By default the report reads the data file alone; the passing column
needs a run. Options:
  --check   also check the ledger against the scenario sources: every
            scenario listed exactly once under the entry its doc comment
            names, and enabled exactly when it carries no #[ignore]
  --run     run every scenario (disabled ones included) on the host and
            fill the passing column

Usage:
  kernel32-ledger.py [<ledger.yaml>] [--check] [--run]
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: run through the repository's .venv (.venv/bin/python), or"
             " install it: pip3 install --user --break-system-packages pyyaml"
             " (or apt install python3-yaml)")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = Path(__file__).resolve().parent / "kernel32-ledger.yaml"
STATUSES = ("pinned", "dumped", "enabled", "unpinned")
# The Rust module the scenarios live under, as cargo prints test paths.
SCENARIO_PATH = "compat::harness::groups"


def fail(context, message):
    sys.exit(f"{context}: {message}")


def check_tests(context, tests):
    """A test list: mappings with a name and an enabled flag."""
    if not isinstance(tests, list):
        fail(context, "'tests' must be a list")
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("name"), str) or not test["name"]:
            fail(context, "every test needs a 'name'")
        if not isinstance(test.get("enabled"), bool):
            fail(context, f"test {test['name']!r}: 'enabled' must be true or false")


def load_ledger(path):
    """Read and validate the ledger; fail fast on bad structure."""
    with open(path, encoding="utf-8") as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            fail(path, f"invalid YAML: {e}")
    if not isinstance(doc, dict):
        fail(path, "expected top-level 'groups' and 'exports'")
    groups, exports = doc.get("groups"), doc.get("exports")
    if not isinstance(groups, list) or not groups:
        fail(path, "expected a non-empty top-level 'groups' list")
    if not isinstance(exports, list) or not exports:
        fail(path, "expected a non-empty top-level 'exports' list")

    keys = []
    for group in groups:
        if not isinstance(group, dict) or not group.get("key"):
            fail(path, "every group needs a 'key'")
        key = group["key"]
        if key in keys:
            fail(path, f"duplicate group {key!r}")
        keys.append(key)
        for field in ("title", "module"):
            if not isinstance(group.get(field), str) or not group[field]:
                fail(path, f"group {key!r}: '{field}' must be a non-empty string")
        group.setdefault("tests", [])
        check_tests(f"{path}: group {key!r}", group["tests"])

    seen = set()
    for entry in exports:
        if not isinstance(entry, dict) or not entry.get("export"):
            fail(path, "every export entry needs an 'export'")
        name = entry["export"]
        context = f"{path}: export {name!r}"
        if name in seen:
            fail(path, f"duplicate export {name!r}")
        seen.add(name)
        if entry.get("group") not in keys:
            fail(context, f"unknown group {entry.get('group')!r}")
        status = entry.get("status")
        if status not in STATUSES:
            fail(context, f"'status' must be one of {', '.join(STATUSES)}")
        entry.setdefault("tests", [])
        check_tests(context, entry["tests"])
        tests = entry["tests"]
        enabled = [t["enabled"] for t in tests]
        if status == "unpinned":
            if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                fail(context, "an unpinned export needs a one-line 'reason'")
        elif status == "pinned" and tests:
            fail(context, "'pinned' has no scenarios yet: with scenarios it is 'dumped'")
        elif status == "dumped" and (not tests or all(enabled)):
            fail(context, "'dumped' needs scenarios, not all of them enabled")
        elif status == "enabled" and (not tests or not all(enabled)):
            fail(context, "'enabled' needs every scenario enabled")

    names = [t["name"] for g in groups for t in g["tests"]]
    names += [t["name"] for e in exports for t in e["tests"]]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        fail(path, f"scenarios listed twice: {duplicates}")
    return groups, exports


def scan_scenarios(path):
    """The scenarios of one group module: name -> (ledger reference, ignored).

    A scenario is a `#[test]` function; its doc comment names its ledger
    entry (`Ledger: group/Export.` or `Ledger: group.`), and a disabled
    one carries an `#[ignore = "ledger <entry>: <why>"]`.
    """
    scenarios = {}
    doc, attributes = [], []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("///"):
            if attributes:
                doc, attributes = [], []
            doc.append(stripped[3:].strip())
        elif stripped.startswith("#[") or (attributes and not stripped.startswith("fn ")
                                           and not stripped.startswith("pub fn ")):
            attributes.append(stripped)
        elif re.match(r"(pub )?fn \w+", stripped):
            name = re.match(r"(?:pub )?fn (\w+)", stripped).group(1)
            attrs = " ".join(attributes)
            if "#[test]" in attrs:
                text = " ".join(doc)
                found = re.search(r"Ledger: ([\w-]+(?:/\w+)?)\.", text)
                ignore = re.search(r'#\[ignore = "ledger ([\w-]+(?:/\w+)?):', attrs)
                scenarios[name] = (
                    found.group(1) if found else None,
                    "#[ignore" in attrs,
                    ignore.group(1) if ignore else None,
                )
            doc, attributes = [], []
        else:
            doc, attributes = [], []
    return scenarios


def check_sources(groups, exports):
    """The ledger against the scenario sources; the problems found."""
    problems = []
    listed = {}
    for group in groups:
        for test in group["tests"]:
            listed[test["name"]] = (group["key"], group["key"], test["enabled"])
    for entry in exports:
        for test in entry["tests"]:
            ref = f"{entry['group']}/{entry['export']}"
            listed[test["name"]] = (entry["group"], ref, test["enabled"])
    for group in groups:
        module = REPO_ROOT / group["module"]
        if not module.is_file():
            problems.append(f"group {group['key']}: no module {group['module']}")
            continue
        scenarios = scan_scenarios(module)
        for name, (ref, ignored, ignore_ref) in sorted(scenarios.items()):
            where = f"{group['module']}: {name}"
            if ref is None:
                problems.append(f"{where}: no 'Ledger: ...' in its doc comment")
                continue
            if ignored and ignore_ref != ref:
                problems.append(f"{where}: the ignore reason names {ignore_ref!r}, the doc {ref!r}")
            if name not in listed:
                problems.append(f"{where}: not in the ledger (doc names {ref})")
                continue
            owner, ledger_ref, enabled = listed[name]
            if owner != group["key"] or ledger_ref != ref:
                problems.append(f"{where}: the doc names {ref}, the ledger lists it under "
                                f"{ledger_ref}")
            if enabled == ignored:
                problems.append(f"{where}: ledger enabled={enabled} but the source "
                                f"{'ignores' if ignored else 'runs'} it")
        for name, (owner, ledger_ref, _) in listed.items():
            if owner == group["key"] and name not in scenarios:
                problems.append(f"{group['module']}: ledger scenario {name} ({ledger_ref}) "
                                f"does not exist")
    return problems


def run_scenarios():
    """Run every scenario on the host, disabled ones included; name -> passed.

    The same cargo invocation as `make run-tests`, narrowed to the
    scenario dump.
    """
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    triple = re.search(r"^host: (\S+)", host, re.M).group(1)
    env = dict(os.environ, CARGO_UNSTABLE_BUILD_STD="std")
    result = subprocess.run(
        ["cargo", "test", "--lib", "--target", triple, SCENARIO_PATH, "--", "--include-ignored"],
        cwd=REPO_ROOT / "kernel", env=env, capture_output=True, text=True,
    )
    outcomes = {}
    for line in result.stdout.splitlines():
        match = re.match(rf"test {re.escape(SCENARIO_PATH)}::\w+::(\w+) \.\.\. (ok|FAILED)$", line)
        if match:
            outcomes[match.group(1)] = match.group(2) == "ok"
    if not outcomes:
        print(result.stdout[-4000:], result.stderr[-4000:], sep="\n", file=sys.stderr)
        fail("--run", "the scenario run reported nothing (build failure?)")
    return outcomes


def report(groups, exports, outcomes):
    """Print the per-group table and the unpinned list."""
    header = ("group", "exports", "pinned", "unpinned", "dumped", "enabled", "passing")
    rows = []
    totals = [0] * 6
    for group in groups:
        members = [e for e in exports if e["group"] == group["key"]]
        tests = group["tests"] + [t for e in members for t in e["tests"]]
        counts = [
            len(members),
            sum(e["status"] != "unpinned" for e in members),
            sum(e["status"] == "unpinned" for e in members),
            len(tests),
            sum(t["enabled"] for t in tests),
            sum(outcomes.get(t["name"], False) for t in tests) if outcomes is not None else 0,
        ]
        totals = [a + b for a, b in zip(totals, counts)]
        rows.append((group["key"], *counts))
    rows.append(("total", *totals))

    def cells(row):
        name, *numbers = row
        shown = [str(n) for n in numbers]
        if outcomes is None:
            shown[-1] = "-"
        else:
            shown[-1] = f"{numbers[-1]}/{numbers[3]}"
        return [name, *shown]

    table = [list(header)] + [cells(row) for row in rows]
    widths = [max(len(r[i]) for r in table) for i in range(len(header))]
    for index, row in enumerate(table):
        if index == len(table) - 1:
            print("  ".join("-" * w for w in widths))
        print("  ".join(cell.ljust(w) if i == 0 else cell.rjust(w)
                        for i, (cell, w) in enumerate(zip(row, widths))))
    if outcomes is None:
        print("\n(passing: run with --run)")

    unpinned = [e for e in exports if e["status"] == "unpinned"]
    print(f"\nUnpinned ({len(unpinned)}):")
    for entry in unpinned:
        print(f"  {entry['group']}/{entry['export']}: {entry['reason'].strip()}")
    noted = [e for e in exports if e.get("note")]
    if noted:
        print(f"\nNotes ({len(noted)}):")
        for entry in noted:
            print(f"  {entry['group']}/{entry['export']}: {entry['note'].strip()}")


def main():
    parser = argparse.ArgumentParser(description="kernel32 contract ledger report")
    parser.add_argument("ledger", nargs="?", default=str(DEFAULT_LEDGER))
    parser.add_argument("--check", action="store_true",
                        help="check the ledger against the scenario sources")
    parser.add_argument("--run", action="store_true",
                        help="run the scenarios on the host to fill the passing column")
    args = parser.parse_args()

    groups, exports = load_ledger(args.ledger)
    if args.check:
        problems = check_sources(groups, exports)
        if problems:
            print("Ledger check failed:", *problems, sep="\n  ", file=sys.stderr)
            sys.exit(1)
        print("Ledger check: ok (the ledger matches the scenario sources)\n")
    outcomes = run_scenarios() if args.run else None
    report(groups, exports, outcomes)


if __name__ == "__main__":
    main()
