#!/usr/bin/env python3
"""
The system DLLs' compatibility: every export of every spec (userland/<dll>/exports.toml), and how
far the tests cover it.

The tests declare what they pin, as `dll.Export`: a corpus fixture's `[pins]`
(tests/<dll>/<fixture>/fixture.toml: per block section, "*" for every block of the fixture) and a host
scenario's `/// Pins:` doc lines (userland/kernel32/src/scenarios). An export's status comes from
its pinning tests' last results:

  unimplemented  its spec gives it no implementation                                    grey
  stubbed        its spec stubs it (impl.stub: it loads, and fails, logged), whatever   grey, a teal
                 its tests: not implemented yet, but in the works                       tint
  passing        implemented; a pinning test passed and none failed                     green
  failing        implemented; a pinning test failed                                     red
  uncovered      implemented; no pinning test passed: none pins it, or every one that   yellow
                 does is pending (an expected failure), skipped, or did not run

A forwarder (impl.forward) counts its target's pinning tests as its own: its target's code is what
runs. F2K-internal entry points (`internal = true`) are not Windows exports: the report leaves them
out.

The results are the last runs': the on-target suite's (target/test-results/pytest.json, which every
`make test` writes) and the host scenarios' (target/test-results/scenarios.json, which --run
writes). A report over a partial run says so.

Options:
  --check   check the pins against the repository: every pin names an export of a spec, every
            fixture's pinned section has a captured block, every scenario pins something, every
            ignore reason leads with a gap id and every pending block gives its reason; and the
            layering: every import of a DLL
            F2K builds is one Windows 2000's DLL makes too, from the same module (its import table,
            userland/<dll>/imports-<version>.txt, dumped by scripts/dump_exports.py), but for the
            stubs' log line, ntdll's DbgPrint (STUB_LOG_IMPORT)
  --run     run every host scenario, ignored ones included, and keep the results: fails if an
            enabled one fails or an ignored one passes (its gap is fixed: remove the marker)
  --report  write the HTML report (target/compat/report.html)

The summary (per DLL and API group) prints in every case. TOML is read with the standard library
(tomllib).

Usage:
  compat.py [--check] [--run] [--report]
"""
import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TESTS = REPO_ROOT / "tests"
sys.path.insert(0, str(TESTS))
import f2kboot  # noqa: E402  (the corpus's declarations and captures, read as the suite reads them)
import dump_exports  # noqa: E402  (the PE reader: the built DLLs' import tables)

SPECS = sorted((REPO_ROOT / "userland").glob("*/exports.toml"))
# The DLLs F2K builds (`make userland`), whose import tables --check holds against the real DLLs'.
BUILT_DLLS = REPO_ROOT / "target" / "userland" / "i686-f2k-pe" / "release"
RESULTS = REPO_ROOT / "target" / "test-results"
PYTEST_RESULTS = RESULTS / "pytest.json"
SCENARIO_RESULTS = RESULTS / "scenarios.json"
REPORT = REPO_ROOT / "target" / "compat" / "report.html"
# Where the scenarios live: (their directory, the module cargo prints their test paths under, the
# cargo test command's arguments and directory).
SCENARIO_SUITES = [
    # kernel32's user-mode exports.
    (REPO_ROOT / "userland" / "kernel32" / "src" / "scenarios", "scenarios",
     ["cargo", "test", "--manifest-path", "userland/kernel32/Cargo.toml", "--lib",
      "--target-dir", "target/userland-host"], REPO_ROOT),
]
# A scenario: its doc comment (the `/// Pins:` lines among it), #[test], its other attributes (an
# #[ignore] among them), its name.
SCENARIO = re.compile(r"((?:[ \t]*///.*\n)*)#\[test\]\n((?:#\[[^\]]*\]\n)*)(?:pub )?fn (\w+)\(")
# A gap id: a finding's id (FS-1, K32-4), a recorded gap (GAP-OB-3), or the increment that
# closes a gap (B2, A4b).
GAP_ID = re.compile(r"^((?:GAP-)?[A-Z0-9]+-\d+[a-z]?|[A-C]\d+[ab]?):")
STATUSES = ("passing", "failing", "uncovered", "stubbed", "unimplemented")


@dataclass
class Export:
    dll: str
    name: str
    group: str | None
    implemented: bool
    spec: dict
    # The tests pinning it: (label, outcome), outcome None when the test has no result.
    evidence: list = field(default_factory=list)

    @property
    def pin(self) -> str:
        return f"{self.dll}.{self.name}"

    @property
    def stubbed(self) -> bool:
        return "stub" in self.spec.get("impl", {})

    @property
    def status(self) -> str:
        if self.stubbed:
            return "stubbed"
        if not self.implemented:
            return "unimplemented"
        outcomes = [outcome for _, outcome in self.evidence]
        if "failed" in outcomes:
            return "failing"
        if "passed" in outcomes:
            return "passing"
        return "uncovered"


@dataclass
class Scenario:
    name: str
    path: Path
    pins: list[str]
    ignored: str | None


def load_specs():
    """Every spec: dll -> (groups, the non-internal exports by name)."""
    specs = {}
    for path in SPECS:
        with open(path, "rb") as f:
            doc = tomllib.load(f)
        dll = path.parent.name
        exports = {}
        for spec in doc.get("export", []):
            if spec.get("internal"):
                continue
            implemented = "impl" in spec and "stub" not in spec["impl"]
            exports[spec["name"]] = Export(dll, spec["name"], spec.get("group"), implemented, spec)
            # A system service's Zw alias: the same export under its second name (gather() gives it
            # the service's tests).
            if "zw_ordinal" in spec:
                alias = "Zw" + spec["name"][2:]
                exports[alias] = Export(dll, alias, spec.get("group"), True,
                                        dict(spec, name=alias, ordinal=spec["zw_ordinal"]))
        specs[dll] = (doc.get("group", []), exports)
    return specs


def corpus_fixtures():
    """The sectioned fixtures: name -> (declaration, captured blocks; None while awaited)."""
    fixtures = {}
    for name in sorted(f2kboot.fixture_directories()):
        declared = f2kboot.declaration(name)
        if declared.get("kind") != "sectioned":
            continue
        fixtures[name] = (declared, None if f2kboot.awaited(name) else f2kboot.read_capture(name))
    return fixtures


def scan_scenarios():
    """Every host scenario, by name."""
    scenarios = {}
    for directory, _, _, _ in SCENARIO_SUITES:
        for path in sorted(directory.glob("*.rs")):
            if path.name == "mod.rs":  # the shared helpers, no scenarios
                continue
            for match in SCENARIO.finditer(path.read_text(encoding="utf-8")):
                docs, attributes, name = match.groups()
                pins = [pin.strip() for line in docs.splitlines()
                        if (m := re.match(r"\s*/// Pins:(.*)", line)) for pin in m.group(1).split(",")]
                ignore = re.search(r'#\[ignore(?: = "((?:[^"\\]|\\.)*)")?\]', attributes, re.S)
                reason = re.sub(r"\\\n\s*", "", ignore.group(1) or "(no reason)") if ignore else None
                scenarios[name] = Scenario(name, path, [p for p in pins if p], reason)
    return scenarios


def gap_of(reason):
    match = GAP_ID.match(reason or "")
    return match.group(1) if match else None


def check(specs, fixtures, scenarios):
    """The pins against the repository; the problems found."""
    problems = []

    def unknown(pin):
        dll, _, name = pin.partition(".")
        if not f2kboot.PIN.fullmatch(pin):
            return "is not dll.Export"
        if dll not in specs:
            return f"names no spec (userland/{dll}/exports.toml)"
        if name not in specs[dll][1]:
            return f"is no export of userland/{dll}/exports.toml"
        return None

    for fixture, (declared, blocks) in fixtures.items():
        where = f"{f2kboot.fixture_directory(fixture).relative_to(REPO_ROOT)}/fixture.toml"
        names = None if blocks is None else {block.name for block in blocks}
        for section, pins in declared.get("pins", {}).items():
            if names is not None and section != "*" and section not in names:
                problems.append(f"{where}: pins {section!r}: no such block in its capture")
            for pin in pins:
                if (why := unknown(pin)) is not None:
                    problems.append(f"{where}: pins {section!r}: {pin} {why}")
        for section, reason in declared.get("pending", {}).items():
            if not reason.strip():
                problems.append(f"{where}: pending {section!r}: no reason given")
    for dll, (_, exports) in specs.items():
        for export in exports.values():
            if "impl" in export.spec and "ordinal" not in export.spec:
                problems.append(f"{export.pin}: implemented with no ordinal: every export is one of "
                                f"Windows 2000's (scripts/catalogue_exports.py), or internal")
    for scenario in scenarios.values():
        where = f"{scenario.path.relative_to(REPO_ROOT)}: scenario {scenario.name}"
        if not scenario.pins:
            problems.append(f"{where}: pins nothing (a `/// Pins: kernel32.<Name>` doc line)")
        for pin in scenario.pins:
            if (why := unknown(pin)) is not None:
                problems.append(f"{where}: pin {pin} {why}")
        if scenario.ignored is not None and not gap_of(scenario.ignored):
            problems.append(f"{where}: an ignore reason leads with the gap id (\"K32-4: ...\"), "
                            f"not {scenario.ignored!r}")
    return problems


def real_imports(dll):
    """Windows 2000's DLL's import table, from its dump: {module (lower case, no .dll): {import}};
    None without a dump."""
    dumps = sorted((REPO_ROOT / "userland" / dll).glob("imports-*.txt"))
    if not dumps:
        return None
    modules, module = {}, None
    for line in dumps[-1].read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            module = modules.setdefault(module_key(line[1:].split("]")[0]), set())
        else:
            module.add(line)
    return modules


def module_key(name):
    """A module's name as the loader compares it: without regard to case, `.dll` implied."""
    return name.lower().removesuffix(".dll")


# The layering's one exemption: the stub machinery's log line. Every
# DLL F2K builds logs its stubs' calls (their generated bodies, and the paths its code does not
# handle yet) through ntdll's DbgPrint, which Windows 2000's msvcrt and user32 never import (msvcrt
# imports kernel32 alone). Tolerated for every built DLL, that import alone; remove it to hold them
# to the real tables in full.
STUB_LOG_IMPORT = ("ntdll", "DbgPrint")


def layering(specs):
    """Every import of a DLL F2K builds, against Windows 2000's DLL's import table: an import the
    real DLL does not make (from that module) is code in the wrong place, the stub machinery's log
    line aside (STUB_LOG_IMPORT). The problems found."""
    problems = []
    for dll in specs:
        built = BUILT_DLLS / f"{dll}.dll"
        real = real_imports(dll)
        if not built.is_file() or real is None:
            if built.is_file():
                problems.append(f"{dll}.dll: no import table to hold it against (scripts/dump_exports.py)")
            continue
        for module, delayed, names in dump_exports.imports(dump_exports.Image(built.read_bytes())):
            names = [name for name in names if (module_key(module), name) != STUB_LOG_IMPORT]
            theirs = real.get(module_key(module))
            if theirs is None:
                if names:
                    problems.append(f"{dll}.dll imports from {module}, which Windows 2000's {dll}.dll never does")
                continue
            for name in names:
                if name not in theirs:
                    problems.append(f"{dll}.dll imports {module}!{name}, which Windows 2000's {dll}.dll "
                                    f"does not: the call belongs elsewhere")
    return problems


def run_scenarios(scenarios):
    """Run every scenario on the host, ignored ones included, and keep the results; the problems
    (an enabled scenario failing, an ignored one passing)."""
    host = subprocess.run(["rustc", "-vV"], capture_output=True, text=True, check=True).stdout
    triple = re.search(r"^host: (\S+)", host, re.M).group(1)
    env = dict(os.environ, CARGO_UNSTABLE_BUILD_STD="std")
    passed = {}
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
                passed[match.group(1)] = match.group(2) == "ok"
                found += 1
        if not found:
            print(result.stdout[-4000:], result.stderr[-4000:], sep="\n", file=sys.stderr)
            sys.exit(f"--run: the {module} scenario run reported nothing (build failure?)")
    outcomes, problems = {}, []
    for name, ok in sorted(passed.items()):
        ignored = scenarios[name].ignored if name in scenarios else None
        if ignored is None:
            outcomes[name] = "passed" if ok else "failed"
            if not ok:
                problems.append(f"scenario {name} fails")
        else:
            outcomes[name] = "passed" if ok else "xfailed"
            if ok:
                problems.append(f"ignored scenario {name} passes: its gap ({ignored}) is fixed: "
                                f"remove the marker")
    RESULTS.mkdir(parents=True, exist_ok=True)
    SCENARIO_RESULTS.write_text(json.dumps({
        "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tests": outcomes,
    }, indent=1) + "\n")
    return problems


def read_results(path):
    """A kept run's results (None when there is none)."""
    if not path.is_file():
        return None
    return json.loads(path.read_text())


def worst(outcomes):
    """A block's outcome over its runs (a section captured twice runs twice)."""
    for outcome in ("failed", "passed", "xfailed", "skipped"):
        if outcome in outcomes:
            return outcome
    return None


def gather(specs, fixtures, scenarios, pytest_run, scenario_run):
    """Attach each pinning test and its outcome to the export it pins; the run's gaps (blocks and
    scenarios with no result)."""
    by_block = {}
    for test in (pytest_run or {}).get("tests", {}).values():
        if "block" in test:
            by_block.setdefault(test["block"], []).append(test["outcome"])
    scenario_outcomes = (scenario_run or {}).get("tests", {})
    missing = {"blocks": [], "scenarios": []}

    def attach(pin, label, outcome):
        dll, _, name = pin.partition(".")
        export = specs.get(dll, ({}, {}))[1].get(name)
        if export is not None:
            export.evidence.append((label, outcome))

    for fixture, (declared, blocks) in fixtures.items():
        if blocks is None:
            continue
        names = list(dict.fromkeys(block.name for block in blocks))
        for name in names:
            if f"{fixture}/{name}" not in by_block:
                missing["blocks"].append(f"{fixture} {name}")
        for section, pins in declared.get("pins", {}).items():
            for name in names if section == "*" else [section]:
                outcome = worst(by_block.get(f"{fixture}/{name}", []))
                for pin in pins:
                    attach(pin, f"{fixture} {name}", outcome)
    for scenario in scenarios.values():
        outcome = scenario_outcomes.get(scenario.name)
        if outcome is None:
            missing["scenarios"].append(scenario.name)
        for pin in scenario.pins:
            attach(pin, f"scenario {scenario.name}", outcome)
    # A system service's Zw alias runs the service's stub: the service's tests pin it too.
    for _, exports in specs.values():
        for export in exports.values():
            if "zw_ordinal" in export.spec and export.name.startswith("Nt"):
                exports["Zw" + export.name[2:]].evidence = list(export.evidence)
    # A forwarder runs its target's code: its target's tests pin it too.
    for _, exports in specs.values():
        for export in exports.values():
            target = export.spec.get("impl", {}).get("forward")
            if target is None:
                continue
            module, _, name = target.partition(".")
            forwarded = specs.get(module.lower(), ({}, {}))[1].get(name)
            if forwarded is not None:
                export.evidence += [(f"{label} (via {forwarded.pin})", outcome)
                                    for label, outcome in forwarded.evidence]
    return missing


def summary(specs, missing, pytest_run, scenario_run):
    for dll, (groups, exports) in specs.items():
        print(f"{dll}: {len(exports)} exports")
        if not exports:
            print()
            continue
        header = ("group", "exports", *STATUSES)
        keys = [g["key"] for g in groups] + ([None] if any(e.group is None for e in exports.values()) else [])
        rows, totals = [], [0] * (1 + len(STATUSES))
        for key in keys:
            members = [e for e in exports.values() if e.group == key]
            if not members:
                continue
            counts = [len(members)] + [sum(e.status == s for e in members) for s in STATUSES]
            totals = [a + b for a, b in zip(totals, counts)]
            rows.append([key or "(catalogued)", *map(str, counts)])
        rows.append(["total", *map(str, totals)])
        table = [list(header)] + rows
        widths = [max(len(r[i]) for r in table) for i in range(len(header))]
        for index, row in enumerate(table):
            if index == len(table) - 1:
                print("  ".join("-" * w for w in widths))
            print("  ".join(c.ljust(w) if i == 0 else c.rjust(w) for i, (c, w) in enumerate(zip(row, widths))))
        failing = [e for e in exports.values() if e.status == "failing"]
        if failing:
            print(f"\nFailing ({len(failing)}):")
            for export in failing:
                tests = [label for label, outcome in export.evidence if outcome == "failed"]
                print(f"  {export.name}: {', '.join(tests)}")
        print()
    for what, run, gaps in (("on-target suite", pytest_run, missing["blocks"]),
                            ("host scenarios", scenario_run, missing["scenarios"])):
        if run is None:
            print(f"No {what} results yet: their pins count as not run.")
        elif gaps:
            print(f"The {what}'s last run ({run['finished']}) left {len(gaps)} out: their pins count as not run.")


# --- The HTML report -------------------------------------------------------------------------------

LABELS = {
    "passing": "Implemented, tested",
    "failing": "Implemented, a test fails",
    "uncovered": "Implemented, no passing test",
    "stubbed": "Stubbed (in the works)",
    "unimplemented": "Not implemented",
}
OUTCOME_WORDS = {"passed": "passed", "failed": "FAILED", "xfailed": "pending", "skipped": "skipped",
                 None: "not run"}

STYLE = """
:root {
  --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514c; --ink-3: #7a7970; --rule: #e1e0d9;
  --tile: #f0efea;
  --passing: #0ca30c; --failing: #d03b3b; --uncovered: #fab219; --unimplemented: #d9d8d0;
  --stubbed: #cfe3df;
  --mark-on-failing: #ffffff; --mark-on-uncovered: #0b0b0b; --tip: #ffffff;
  --ring: rgba(11,11,11,0.10);
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --ink: #f2f2ef; --ink-2: #b9b8b0; --ink-3: #8c8b83; --rule: #2c2c2a;
    --tile: #222220;
    --unimplemented: #3a3a37; --stubbed: #33504b; --tip: #242422; --ring: rgba(255,255,255,0.10);
  }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 0; background: var(--surface); color: var(--ink);
  font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { display: grid; grid-template-columns: 1fr auto; padding-bottom: 0 !important; }
main { margin: 0 auto; }
.container { padding: 16px; }
h1 { font-size: 20px; margin: 0 0 4px; }
h2 { font-size: 16px; margin: 32px 0 8px; }
.meta { color: var(--ink-2); margin: 0; grid-column: span 2; }
.banner { border: 1px solid var(--uncovered); border-left-width: 4px; padding: 8px 12px;
  margin: 0 0 16px; border-radius: 4px; }
.controls { display: flex; flex-wrap: wrap; gap: 12px 20px; align-items: center; margin: 0 0 16px;
  padding: 12px 0; border-bottom: 1px solid var(--rule); position: sticky; top: 0;
  background: var(--surface); z-index: 2; }
input[type=search] { font: inherit; padding: 4px 8px; min-width: 220px;
  border: 1px solid var(--rule); border-radius: 4px; background: var(--surface); color: var(--ink); }
.full-screen { display: flex; flex-direction: column; width: 100vw; height: 100vh; }
.flex-1 { flex: 1; min-height: 0; }
.key { width: 14px; height: 14px; border-radius: 3px; display: inline-flex; align-items: center;
  justify-content: center; font: 700 10px/1 system-ui, sans-serif; box-shadow: inset 0 0 0 1px var(--ring); }
.key.passing { background: var(--passing); }
.key.failing { background: var(--failing); color: var(--mark-on-failing); }
.key.uncovered { background: var(--uncovered); color: var(--mark-on-uncovered); }
.key.stubbed { background: var(--unimplemented); box-shadow: inset 0 0 0 1.5px var(--ink-2); }
.key.unimplemented { background: var(--unimplemented); }
#map { display: block; width: 100%; height: 100%; }
#map .tile { fill: var(--tile); stroke: var(--unimplemented); stroke-width: 2; }
#map .dll { font: 600 12px/1 system-ui, sans-serif; fill: var(--ink); }
#map .dll-count { font: 12px/1 system-ui, sans-serif; fill: var(--ink-2); font-variant-numeric: tabular-nums; }
#map rect.sq { cursor: pointer; }
#map .passing { fill: var(--passing); }
#map .failing { fill: var(--failing); }
#map .uncovered { fill: var(--uncovered); }
#map .stubbed { fill: var(--unimplemented); stroke: var(--ink-2); stroke-width: var(--stub-stroke, 1.5); }
#map .unimplemented { fill: var(--unimplemented); }
#map .glyph { font-weight: 700; font-family: system-ui, sans-serif; text-anchor: middle; dominant-baseline: central;
  pointer-events: none; }
#map .glyph.failing { fill: var(--mark-on-failing); }
#map .glyph.uncovered { fill: var(--mark-on-uncovered); }
#map .dim { opacity: 0.15; }
.scroll { overflow-x: auto; }
table.summary { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
table.summary td, table.summary th { padding: 4px 12px 4px 0; border-bottom: 1px solid var(--rule);
  text-align: right; }
table.summary td:first-child, table.summary th:first-child { text-align: left; }
details { margin-top: 12px; color: var(--ink-2); }
details table { border-collapse: collapse; margin-top: 8px; width: 100%; }
details td, details th { text-align: left; padding: 3px 12px 3px 0; border-bottom: 1px solid var(--rule);
  vertical-align: top; }
#tip { position: fixed; pointer-events: none; z-index: 10; max-width: 420px; padding: 8px 10px;
  background: var(--tip); color: var(--ink); border-radius: 6px; box-shadow: 0 2px 10px rgba(0,0,0,.18),
  0 0 0 1px var(--ring); display: none; }
#tip b { display: block; margin-bottom: 2px; }
#tip .st { color: var(--ink-2); }
@media (forced-colors: active) { .key { border: 1px solid CanvasText; } }
"""

# The treemap, drawn in the page from the report's data (the `data` script element): one rectangle
# per DLL, its area its export count, squarified to fill the map's place on screen, the DLLs
# touching; one square per export inside it, in name order, inside the rectangle's padding. Every
# square is the same size, the largest at which they all fit; it is redrawn when the size changes.
SCRIPT = """
const DATA = JSON.parse(document.getElementById('data').textContent);
const STATUSES = DATA.statuses, LABELS = DATA.labels;
const PAD = 4, LABEL = 18;
const SVG = 'http://www.w3.org/2000/svg';
const map = document.getElementById('map');
const tip = document.getElementById('tip');
const esc = s => String(s).replace(/[&<>]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;'}[c]));
const exports = [];
for (const dll of DATA.dlls) for (const x of dll.exports) exports.push(x);

// The DLLs' rectangles: a squarified treemap of the map's whole area (each DLL's area its export
// count; rows of rectangles laid along the shorter side, each row taking DLLs, largest first, while
// its worst aspect ratio improves), the edges snapped to whole pixels so the rectangles touch.
function squarify(values, W, H) {
  const total = values.reduce((a, v) => a + v, 0);
  const areas = values.map(v => v * W * H / total);
  const worst = (row, side) => {
    const sum = row.reduce((a, v) => a + v, 0), max = Math.max(...row), min = Math.min(...row);
    return Math.max(side * side * max / (sum * sum), sum * sum / (side * side * min));
  };
  const out = [];
  let x = 0, y = 0, w = W, h = H, i = 0;
  while (i < areas.length) {
    const side = Math.min(w, h);
    const row = [areas[i]];
    let j = i + 1;
    while (j < areas.length && worst([...row, areas[j]], side) <= worst(row, side)) row.push(areas[j++]);
    const sum = row.reduce((a, v) => a + v, 0);
    if (w >= h) {
      const across = sum / h;
      let at = y;
      for (const a of row) { out.push({x, y: at, w: across, h: a / across}); at += a / across; }
      x += across; w -= across;
    } else {
      const across = sum / w;
      let at = x;
      for (const a of row) { out.push({x: at, y, w: a / across, h: across}); at += a / across; }
      y += across; h -= across;
    }
    i = j;
  }
  return out.map(r => {
    const x0 = Math.round(r.x), y0 = Math.round(r.y);
    return {x: x0, y: y0, w: Math.round(r.x + r.w) - x0, h: Math.round(r.y + r.h) - y0};
  });
}

// The squares' pitch: the largest (to a fraction of a pixel, by bisection) at which every DLL's
// squares fit its rectangle, inside its padding and under its label. At each pitch tried, each
// DLL's area starts as what it needs there (its squares as a near-square block, its padding, its
// label), then a few rounds of reweighting give a DLL short of rows more area and a roomy one less,
// so the rectangles' leftover space evens out across the DLLs.
const gapOf = pitch => pitch >= 8 ? 2 : pitch >= 3 ? 1 : 0;
const columnsOf = (r, pitch) => Math.floor((r.w - 2 * PAD + gapOf(pitch)) / pitch);
const rowsOf = (r, pitch) => Math.floor((r.h - 2 * PAD - LABEL + gapOf(pitch)) / pitch);
function layoutAt(items, W, H, pitch) {
  let weights = items.map(item => {
    const side = (Math.sqrt(item.n) + 1) * pitch;
    return (side + 2 * PAD) * (side + 2 * PAD + LABEL);
  });
  for (let round = 0; round < 8; round++) {
    const rects = squarify(weights, W, H);
    const room = rects.map((r, k) => Math.max(0, columnsOf(r, pitch)) * Math.max(0, rowsOf(r, pitch)) >= items[k].n);
    if (room.every(Boolean)) return rects;
    weights = rects.map((r, k) => {
      const columns = Math.max(1, columnsOf(r, pitch));
      const needed = Math.ceil(items[k].n / columns) * pitch + 2 * PAD + LABEL;
      return weights[k] * Math.max(0.5, Math.min(2, needed / Math.max(1, r.h)));
    });
  }
  return null;
}
function fit(items, W, H) {
  const total = items.reduce((a, item) => a + item.n, 0);
  let low = 0.5, high = Math.sqrt(W * H / total), rects = null;
  for (let step = 0; step < 24; step++) {
    const pitch = (low + high) / 2, found = layoutAt(items, W, H, pitch);
    if (found) { low = pitch; rects = found; } else { high = pitch; }
  }
  // A screen too small for any: the smallest pitch tried, squares overflowing their rectangles.
  rects = rects || squarify(items.map(item => item.n), W, H);
  const pitch = low;
  return {rects, pitch, size: pitch - gapOf(pitch), columns: r => Math.max(1, columnsOf(r, pitch))};
}

function node(name, attrs, parent) {
  const el = document.createElementNS(SVG, name);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  parent.appendChild(el);
  return el;
}

// Draw the map to fill its place on screen, exactly.
let drawnSize = '';
function draw() {
  const box = map.getBoundingClientRect();
  const W = Math.floor(box.width), H = Math.floor(box.height);
  if (W < 1 || H < 1 || `${W}x${H}` === drawnSize) return;
  drawnSize = `${W}x${H}`;
  const items = DATA.dlls.map(d => ({dll: d, n: d.exports.length})).filter(item => item.n > 0)
    .sort((a, b) => b.n - a.n);
  const {rects, pitch, size, columns} = fit(items, W, H);
  map.replaceChildren();
  map.setAttribute('viewBox', `0 0 ${W} ${H}`);
  map.style.setProperty('--stub-stroke', size >= 8 ? 1.5 : 1);
  items.forEach((item, k) => {
    const r = rects[k], dll = item.dll, across = columns(r);
    node('rect', {class: 'tile', x: r.x, y: r.y, width: r.w, height: r.h}, map);
    const clip = node('clipPath', {id: 'clip-' + k}, map);
    node('rect', {x: r.x, y: r.y, width: r.w, height: r.h}, clip);
    const label = node('text', {class: 'dll', x: r.x + PAD, y: r.y + PAD + 12, 'clip-path': `url(#clip-${k})`}, map);
    label.textContent = dll.dll;
    node('tspan', {class: 'dll-count', dx: 6}, label).textContent = dll.exports.length;
    node('title', {}, label).textContent = dll.summary;
    dll.exports.forEach((x, n) => {
      const cx = r.x + PAD + (n % across) * pitch, cy = r.y + PAD + LABEL + Math.floor(n / across) * pitch;
      x.el = node('rect', {class: 'sq ' + x.s, x: cx, y: cy, width: size, height: size,
                           rx: Math.min(2, size / 4), 'data-index': x.index}, map);
      const glyph = DATA.marks[x.s];
      x.glyph = null;
      if (glyph && size >= 8) {
        x.glyph = node('text', {class: 'glyph ' + x.s, x: cx + size / 2, y: cy + size / 2,
                                'font-size': Math.round(size * 0.9)}, map);
        x.glyph.textContent = glyph;
      }
    });
  });
  filter();
}

function show(x, cx, cy) {
  const d = x.i;
  let h = '<b>' + esc(d.pin) + '</b><span class="st">' + esc(LABELS[x.s]) + '</span>';
  const facts = [d.ordinal && 'ordinal ' + d.ordinal, d.data && 'data', d.group && 'group: ' + d.group,
                 d.impl && 'impl: ' + d.impl, d.version && 'since NT ' + d.version].filter(Boolean);
  if (facts.length) h += '<div class="st">' + esc(facts.join(' · ')) + '</div>';
  if (d.note) h += '<div class="st">' + esc(d.note) + '</div>';
  if (d.tests) {
    h += '<div class="st">' + esc(d.tests) + '</div>';
  } else if (d.implemented) {
    h += '<div class="st">no test pins it</div>';
  }
  tip.innerHTML = h;
  tip.style.display = 'block';
  const r = tip.getBoundingClientRect();
  tip.style.left = Math.min(cx + 14, innerWidth - r.width - 8) + 'px';
  tip.style.top = (cy + 14 + r.height > innerHeight ? cy - r.height - 10 : cy + 14) + 'px';
}
// An export's name to the clipboard (a file: page may lack the async clipboard: the selection's
// copy then), confirmed in its tooltip.
function copy(x) {
  const name = x.n;
  const done = () => { tip.innerHTML = '<b>' + esc(name) + '</b><span class="st">copied</span>'; };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(name).then(done, () => fallback(name) && done());
  } else if (fallback(name)) {
    done();
  }
}
function fallback(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) {}
  area.remove();
  return ok;
}
const under = e => e.target.dataset && e.target.dataset.index !== undefined ? exports[e.target.dataset.index] : null;
map.addEventListener('mousemove', e => { const x = under(e); if (x) show(x, e.clientX, e.clientY); else tip.style.display = 'none'; });
map.addEventListener('mouseleave', () => tip.style.display = 'none');
map.addEventListener('click', e => { const x = under(e); if (x) copy(x); });

// The search dims the exports whose names don't match: the squares keep their places.
const search = document.getElementById('search');
function filter() {
  const q = search.value.trim().toLowerCase();
  for (const x of exports) {
    const dim = q !== '' && !x.n.toLowerCase().includes(q);
    x.el.classList.toggle('dim', dim);
    if (x.glyph) x.glyph.classList.toggle('dim', dim);
  }
}
search.addEventListener('input', filter);
let pending = 0;
addEventListener('resize', () => { cancelAnimationFrame(pending); pending = requestAnimationFrame(draw); });
draw();
"""


def render(specs, missing, pytest_run, scenario_run):
    """The report: every export of every DLL in one treemap (the page draws it from the data written
    here), a summary table per DLL, and each DLL's failing and uncovered exports as a table."""
    e = html.escape
    notes = []
    for what, run, gaps, how in (("on-target suite", pytest_run, missing["blocks"], "make test"),
                                 ("host scenarios", scenario_run, missing["scenarios"], "make compat")):
        if run is None:
            notes.append(f"No {what} results yet (<code>{how}</code>): the exports they pin show as uncovered.")
        elif gaps:
            # The blocks by fixture ("files: 12 of 30"), the scenarios by name.
            if what == "on-target suite":
                left = {}
                for gap in gaps:
                    left.setdefault(gap.split(" ", 1)[0], []).append(gap)
                shown = ", ".join(f"{fixture} ({len(blocks)})" for fixture, blocks in left.items())
            else:
                shown = ", ".join(gaps[:8]) + (", ..." if len(gaps) > 8 else "")
            notes.append(f"Partial run: the {what}'s last run left {len(gaps)} out: {e(shown)}. "
                         f"The exports only they pin show as uncovered.")
    when = lambda run: e(run["finished"][:16].replace("T", " "))  # noqa: E731
    runs = [f"on-target suite {when(pytest_run)}" if pytest_run else None,
            f"host scenarios {when(scenario_run)}" if scenario_run else None]
    data = {"statuses": STATUSES, "labels": LABELS, "marks": {s: mark(s) for s in STATUSES if mark(s)},
            "dlls": []}
    index = 0
    rows, attention = [], []
    for dll, (_, exports) in specs.items():
        ordered = sorted(exports.values(), key=lambda x: x.name.lower())
        counts = {s: sum(x.status == s for x in ordered) for s in STATUSES}
        entries = []
        for export in ordered:
            impl = export.spec.get("impl", {})
            info = {
                "pin": export.pin, "group": export.group,
                "impl": next((f"{k} {v}" for k, v in impl.items()), None),
                "ordinal": export.spec.get("ordinal"), "data": export.spec.get("data"),
                "version": export.spec.get("version"), "note": export.spec.get("note"),
                "implemented": export.implemented, "tests": tally(export.evidence),
            }
            entries.append({"n": export.name, "s": export.status, "index": index,
                            "i": {k: v for k, v in info.items() if v}})
            index += 1
        summary = f"{dll}.dll: {len(ordered)} exports · " + " · ".join(
            f"{counts[s]} {LABELS[s].lower()}" for s in STATUSES if counts[s])
        data["dlls"].append({"dll": dll, "summary": summary, "exports": entries})
        rows.append(f"<tr><td>{e(dll)}.dll</td><td>{len(ordered)}</td>"
                    + "".join(f"<td>{counts[s] or ''}</td>" for s in STATUSES) + "</tr>")
        failing = [x for x in ordered if x.status in ("failing", "uncovered")]
        if failing:
            attention.append(f"<details><summary>{e(dll)}.dll: {len(failing)} failing or uncovered</summary>"
                             "<table><tr><th>Export</th><th>Status</th><th>Pinning tests</th></tr>")
            for export in failing:
                tests = ", ".join(f"{label} ({OUTCOME_WORDS[outcome]})" for label, outcome in export.evidence)
                attention.append(f"<tr><td>{e(export.name)}</td><td>{LABELS[export.status]}</td>"
                                 f"<td>{e(tests) or 'none'}</td></tr>")
            attention.append("</table></details>")
    payload = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        '<meta name=viewport content="width=device-width, initial-scale=1">',
        f"<title>F2K DLL compatibility</title><style>{STYLE}</style></head><body>",
        "<main>",
        '<div class="full-screen">',
        '<header class="container">'
        "<h1>F2K DLL compatibility</h1>",
        '<input type="search" id="search" placeholder="Find an export" aria-label="Find an export">',
        f"<p class=meta>Results: {'; '.join(r for r in runs if r) or 'none'}.</p>",
        *(f"<p class=banner>{note}</p>" for note in notes),
        "</header>",
        '<div class="flex-1 container"><svg id=map role=img aria-label="Every export of every DLL, by status"></svg></div>',
        '</div>',
        '<div class="container">',
        "<h2>By DLL</h2><div class=scroll><table class=summary><tr><th>DLL</th><th>Exports</th>"
        + "".join(f"<th>{LABELS[s]}</th>" for s in STATUSES) + "</tr>",
        *rows,
        "</table></div>",
        *attention,
        '</div>',
        f"</main><div id=tip role=tooltip></div><script type=application/json id=data>{payload}</script>",
        f"<script>{SCRIPT}</script></body></html>",
    ]
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("".join(parts) + "\n")


def tally(evidence):
    """The pinning tests, counted by outcome ("14 tests: 13 passed, 1 pending"); None for none."""
    if not evidence:
        return None
    counts = {}
    for _, outcome in evidence:
        counts[OUTCOME_WORDS[outcome]] = counts.get(OUTCOME_WORDS[outcome], 0) + 1
    order = ["FAILED", "passed", "pending", "skipped", "not run"]
    words = ", ".join(f"{counts[word]} {word}" for word in order if word in counts)
    return f"{len(evidence)} test{'s' if len(evidence) != 1 else ''}: {words}"


def mark(status):
    """The glyph a square carries beside its colour (the problem states only)."""
    return {"failing": "×", "uncovered": "!"}.get(status, "")


def main():
    parser = argparse.ArgumentParser(description="the system DLLs' compatibility")
    parser.add_argument("--check", action="store_true", help="check the pins against the repository")
    parser.add_argument("--run", action="store_true", help="run the host scenarios, ignored ones included")
    parser.add_argument("--report", action="store_true", help=f"write the HTML report ({REPORT.relative_to(REPO_ROOT)})")
    args = parser.parse_args()

    specs = load_specs()
    fixtures = corpus_fixtures()
    scenarios = scan_scenarios()
    if args.check:
        problems = check(specs, fixtures, scenarios) + layering(specs)
        if problems:
            print("Compatibility check failed:", *problems, sep="\n  ", file=sys.stderr)
            sys.exit(1)
        print("Compatibility check: ok (every pin names an export, every pinned block is captured,"
              " every built DLL imports only what Windows 2000's does)\n")
    failures = run_scenarios(scenarios) if args.run else []
    pytest_run, scenario_run = read_results(PYTEST_RESULTS), read_results(SCENARIO_RESULTS)
    missing = gather(specs, fixtures, scenarios, pytest_run, scenario_run)
    summary(specs, missing, pytest_run, scenario_run)
    if args.report:
        render(specs, missing, pytest_run, scenario_run)
        print(f"Report: {REPORT}")
    for problem in failures:
        print(problem, file=sys.stderr)
    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
