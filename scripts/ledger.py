#!/usr/bin/env python3
"""
Report the system DLLs' export ledger: every export of every spec
(userland/<dll>/exports.toml) with the status its evidence earns.

An export's evidence is the fixture blocks pinning it (`pinned_by`,
blocks of tests/<fixture>/output.txt) and the host scenarios pinning it
(`scenarios`: kernel32's host tests of its user-mode exports,
userland/kernel32/src/scenarios). A known gap is an expected-failure
test: a block pending in its fixture's fixture.toml, or a scenario
carrying #[ignore = "<gap id>: <why>"]; a gap id is a review finding's
(FS-1, GAP-OB-3) or the rebuild increment that closes it (B2). The
status is computed, never written:

  internal       an F2K-internal entry point (`internal = true`), not a
                 Windows 2000 export: counted apart, no evidence asked
  forward        forwarded to another module's export (impl.forward)
  unpinned       implemented, no evidence yet (the spec says why: `unpinned`)
  partial        some evidence is a known gap (a pending block, an ignored
                 scenario); the report quotes the gap ids
  host-only      every piece of evidence passes, but no fixture block pins it
  complete       every piece of evidence passes, a fixture block among them

Options:
  --check   check the specs against the repository: every pinned_by block
            exists in its fixture's capture, every scenario exists, every
            group scenario is named by some export, every implemented
            export has evidence or an `unpinned` reason (and no reason
            once it has evidence), every ignore and pending reason leads
            with a gap id
  --run     run every host scenario, ignored ones included: fails if an
            enabled one fails or an ignored one passes (its gap is fixed:
            remove the marker); fills the report's passing column

The ledger reads TOML through the standard library (tomllib): no PyYAML.

Usage:
  ledger.py [--check] [--run]
"""
import argparse
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SPECS = sorted((REPO_ROOT / "userland").glob("*/exports.toml"))
TESTS = REPO_ROOT / "tests"
# Where the scenarios live: (their directory, the module cargo prints their test paths under, the
# cargo test command's arguments and directory).
SCENARIO_SUITES = [
    # kernel32's user-mode exports.
    (REPO_ROOT / "userland" / "kernel32" / "src" / "scenarios", "scenarios",
     ["cargo", "test", "--manifest-path", "userland/kernel32/Cargo.toml", "--lib",
      "--target-dir", "target/userland-host"], REPO_ROOT),
]
SCENARIO_PATH = " or ".join(path for _, path, _, _ in SCENARIO_SUITES)
# A gap id: a finding's id (FS-1, K32-4), a recorded gap (GAP-OB-3), or the increment that
# closes a gap (B2, A4b).
GAP_ID = re.compile(r"^((?:GAP-)?[A-Z0-9]+-\d+[a-z]?|[A-C]\d+[ab]?):")
STATUSES = ("complete", "host-only", "partial", "unpinned", "forward", "internal")


def load_specs():
    """Every spec: (dll, groups, exports)."""
    specs = []
    for path in SPECS:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
        specs.append((path.parent.name, doc.get("group", []), doc.get("export", [])))
    return specs


def capture_blocks(fixture):
    """The block sections of a fixture's capture, its overrides.txt included (None when it has no
    capture)."""
    capture = TESTS / fixture / "output.txt"
    if not capture.is_file():
        return None
    sections = set()
    for path in (capture, TESTS / fixture / "overrides.txt"):
        if not path.is_file():
            continue
        for line in path.read_text(encoding="latin-1").splitlines():
            if line.startswith(">>> "):
                command = line[4:]
                sections.add(command.split(" ", 1)[1].split(" ")[0] if " " in command else "(default)")
    return sections


def pending_blocks(fixture):
    """The fixture's pending blocks: section -> reason ("*" for the whole fixture when ungated)."""
    declaration = TESTS / fixture / "fixture.toml"
    if not declaration.is_file():
        return {}
    with open(declaration, "rb") as f:
        doc = tomllib.load(f)
    pending = dict(doc.get("pending", {}))
    if doc.get("kind") == "sectioned" and not doc.get("gate", False):
        pending["*"] = doc.get("description", "the fixture is not gated yet")
    return pending


def scan_scenarios():
    """Every host scenario: name -> ignore reason (None when it runs)."""
    scenarios = {}
    # The group modules (mod.rs holds the structural checks, not scenarios).
    paths = [p for directory, _, _, _ in SCENARIO_SUITES for p in directory.glob("*.rs") if p.name != "mod.rs"]
    for path in sorted(paths):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"#\[test\]\n((?:#\[[^\]]*\]\n)*)(?:pub )?fn (\w+)\(", text):
            attributes, name = match.group(1), match.group(2)
            ignore = re.search(r'#\[ignore(?: = "((?:[^"\\]|\\.)*)")?\]', attributes, re.S)
            reason = None
            if ignore:
                reason = re.sub(r"\\\n\s*", "", ignore.group(1) or "(no reason)")
            scenarios[name] = reason
    return scenarios


def gap_of(reason):
    match = GAP_ID.match(reason or "")
    return match.group(1) if match else None


def status_of(export, scenarios, outcomes):
    """(status, gap ids) for one export."""
    implementation = export["impl"]
    if export.get("internal"):
        return "internal", []
    if "forward" in implementation:
        return "forward", []
    pinned = export.get("pinned_by", [])
    tests = export.get("scenarios", [])
    if not pinned and not tests:
        return "unpinned", []
    gaps = []
    for block in pinned:
        fixture, section = block.split("/", 1)
        pending = pending_blocks(fixture)
        for key in (section, "*"):
            if key in pending:
                gaps.append(gap_of(pending[key]) or f"{fixture}/{key} pending")
    for test in tests:
        reason = scenarios.get(test)
        if reason is not None:
            gaps.append(gap_of(reason) or f"{test} ignored")
        elif outcomes is not None and outcomes.get(test) is False:
            gaps.append(f"{test} fails")
    if gaps:
        return "partial", sorted(set(gaps))
    return ("complete" if pinned else "host-only"), []


def check(specs, scenarios):
    """The specs against the repository; the problems found."""
    problems = []
    named = set()
    blocks = {}
    for dll, _, exports in specs:
        for export in exports:
            where = f"{dll}/{export['name']}"
            for block in export.get("pinned_by", []):
                fixture, section = block.split("/", 1)
                if fixture not in blocks:
                    blocks[fixture] = capture_blocks(fixture)
                if blocks[fixture] is None:
                    problems.append(f"{where}: pinned_by {block}: tests/{fixture} has no capture")
                elif section != "*" and section not in blocks[fixture]:
                    problems.append(f"{where}: pinned_by {block}: no such block in tests/{fixture}/output.txt")
            for test in export.get("scenarios", []):
                named.add(test)
                if test not in scenarios:
                    problems.append(f"{where}: scenario {test} does not exist under {SCENARIO_PATH}")
            implemented = not export.get("internal") and "forward" not in export["impl"]
            evidence = export.get("pinned_by") or export.get("scenarios")
            if implemented and not evidence and not export.get("unpinned"):
                problems.append(f"{where}: implemented with no evidence: pin it (pinned_by, scenarios) "
                                f"or say why not (unpinned)")
            if evidence and export.get("unpinned"):
                problems.append(f"{where}: has evidence now: drop its `unpinned` reason")
    for name, reason in sorted(scenarios.items()):
        if name not in named:
            problems.append(f"scenario {name}: no export names it (add it to the export's `scenarios`)")
        if reason is not None and not gap_of(reason):
            problems.append(f"scenario {name}: an ignore reason leads with the gap id "
                            f"(\"K32-4: ...\"), not {reason!r}")
    for declaration in sorted(TESTS.glob("*/fixture.toml")):
        for section, reason in pending_blocks(declaration.parent.name).items():
            if section != "*" and not gap_of(reason):
                problems.append(f"{declaration.relative_to(REPO_ROOT)}: pending {section!r}: the reason "
                                f"leads with the gap id, not {reason!r}")
    return problems


def run_scenarios():
    """Run every scenario on the host, ignored ones included; name -> passed."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    triple = re.search(r"^host: (\S+)", host, re.M).group(1)
    env = dict(os.environ, CARGO_UNSTABLE_BUILD_STD="std")
    outcomes = {}
    for scenarios_dir, module, command, directory in SCENARIO_SUITES:
        # A suite with no group module yet has nothing to run.
        if not [p for p in scenarios_dir.glob("*.rs") if p.name != "mod.rs"]:
            continue
        result = subprocess.run(
            command + ["--target", triple, module, "--", "--include-ignored"],
            cwd=directory, env=env, capture_output=True, text=True,
        )
        found = 0
        for line in result.stdout.splitlines():
            match = re.match(rf"test {re.escape(module)}::(?:\w+::)*(\w+) \.\.\. (ok|FAILED)$", line)
            if match:
                outcomes[match.group(1)] = match.group(2) == "ok"
                found += 1
        if not found:
            print(result.stdout[-4000:], result.stderr[-4000:], sep="\n", file=sys.stderr)
            sys.exit(f"--run: the {module} scenario run reported nothing (build failure?)")
    return outcomes


def report(specs, scenarios, outcomes):
    for dll, groups, exports in specs:
        print(f"{dll}: {len(exports)} exports")
        if not exports:
            print()
            continue
        header = ("group", "exports", *STATUSES)
        rows, totals = [], [0] * (1 + len(STATUSES))
        for group in groups:
            members = [e for e in exports if e["group"] == group["key"]]
            counts = [len(members)] + [0] * len(STATUSES)
            for export in members:
                counts[1 + STATUSES.index(status_of(export, scenarios, outcomes)[0])] += 1
            totals = [a + b for a, b in zip(totals, counts)]
            rows.append([group["key"], *map(str, counts)])
        rows.append(["total", *map(str, totals)])
        table = [list(header)] + rows
        widths = [max(len(r[i]) for r in table) for i in range(len(header))]
        for index, row in enumerate(table):
            if index == len(table) - 1:
                print("  ".join("-" * w for w in widths))
            print("  ".join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(row, widths))))
        partial = [(e, status_of(e, scenarios, outcomes)[1]) for e in exports
                   if status_of(e, scenarios, outcomes)[0] == "partial"]
        if partial:
            print(f"\nPartial ({len(partial)}): the known gaps")
            for export, gaps in partial:
                print(f"  {export['group']}/{export['name']}: {', '.join(gaps)}")
        unpinned = [e for e in exports if status_of(e, scenarios, outcomes)[0] == "unpinned"]
        if unpinned:
            print(f"\nUnpinned ({len(unpinned)}):")
            for export in unpinned:
                print(f"  {export['group']}/{export['name']}: {export.get('unpinned', '(no reason)')}")
        noted = [e for e in exports if e.get("note")]
        if noted:
            print(f"\nNotes ({len(noted)}):")
            for export in noted:
                print(f"  {export['group']}/{export['name']}: {export['note']}")
        print()
    if outcomes is not None:
        passing = sum(outcomes.values())
        print(f"Scenarios: {passing}/{len(outcomes)} passing (ignored ones included)")


def main():
    parser = argparse.ArgumentParser(description="the system DLLs' export ledger")
    parser.add_argument("--check", action="store_true", help="check the specs against the repository")
    parser.add_argument("--run", action="store_true", help="run the host scenarios, ignored ones included")
    args = parser.parse_args()

    specs = load_specs()
    scenarios = scan_scenarios()
    if args.check:
        problems = check(specs, scenarios)
        if problems:
            print("Ledger check failed:", *problems, sep="\n  ", file=sys.stderr)
            sys.exit(1)
        print("Ledger check: ok (the specs match the captures and the scenarios)\n")
    outcomes = run_scenarios() if args.run else None
    report(specs, scenarios, outcomes)
    if outcomes is not None:
        fixed = sorted(n for n, r in scenarios.items() if r is not None and outcomes.get(n))
        broken = sorted(n for n, r in scenarios.items() if r is None and outcomes.get(n) is False)
        for name in fixed:
            print(f"ignored scenario {name} passes: its gap ({scenarios[name]}) is fixed: remove the marker",
                  file=sys.stderr)
        for name in broken:
            print(f"scenario {name} fails", file=sys.stderr)
        if fixed or broken:
            sys.exit(1)


if __name__ == "__main__":
    main()
