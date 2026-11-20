"""scripts/compat.py's coverage logic, on specs and fixtures made up here: how pins reach exports
(through forwards too) and what the summary makes of them."""

import functools
import importlib.util
import sys
from types import SimpleNamespace

import f2kboot

SCRIPTS = f2kboot.REPO_ROOT / "scripts"


@functools.cache
def compat():
    sys.path.insert(0, str(SCRIPTS))  # compat.py's own imports (dump_exports) live beside it
    spec = importlib.util.spec_from_file_location("compat", SCRIPTS / "compat.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def export(dll, name, impl=None):
    """An export as load_specs makes it: `impl` its spec's inline table (None: not implemented)."""
    spec = {"name": name} if impl is None else {"name": name, "impl": impl}
    return compat().Export(dll, name, None, impl is not None and "stub" not in impl, spec)


def specs_of(*exports):
    """load_specs's shape: dll -> (groups, exports by name)."""
    specs = {}
    for each in exports:
        specs.setdefault(each.dll, ([], {}))[1][each.name] = each
    return specs


def fixture(pins, *names, **declared):
    """corpus_fixtures's entry for a fixture: its declaration (its pins, and `declared`'s fields),
    and its captured blocks, by name."""
    blocks = [SimpleNamespace(name=name, section=name) for name in names]
    return dict(declared, pins=pins), blocks


def heap_specs():
    """kernel32.HeapAlloc forwarded to ntdll.RtlAllocateHeap, ntdll's native."""
    return specs_of(
        export("kernel32", "HeapAlloc", {"forward": "NTDLL.RtlAllocateHeap"}),
        export("ntdll", "RtlAllocateHeap", {"native": "RtlAllocateHeap"}),
    )


def test_a_forwarders_pins_reach_its_target():
    """kernel32.HeapAlloc's blocks pin ntdll.RtlAllocateHeap, the code they run."""
    specs = heap_specs()
    fixtures = {"memory": fixture({"heap": ["kernel32.HeapAlloc"]}, "heap")}
    compat().gather(specs, fixtures, {}, None, None)
    target = specs["ntdll"][1]["RtlAllocateHeap"]
    assert [(e.label, e.via) for e in target.evidence] == [("memory heap (via kernel32.HeapAlloc)",
                                                           "kernel32.HeapAlloc")]
    assert target.forwarded_only
    assert target.forwarded_by == ["kernel32.HeapAlloc"]
    assert not specs["kernel32"][1]["HeapAlloc"].forwarded_only


def test_a_targets_pins_reach_its_forwarder():
    specs = heap_specs()
    fixtures = {"memory": fixture({"rtl": ["ntdll.RtlAllocateHeap"]}, "rtl")}
    compat().gather(specs, fixtures, {}, None, None)
    forwarder = specs["kernel32"][1]["HeapAlloc"]
    assert [e.label for e in forwarder.evidence] == ["memory rtl (via ntdll.RtlAllocateHeap)"]
    assert forwarder.forwarded_only


def test_a_block_pinning_both_counts_once_each():
    """A block pinning the forwarder and its target is one test of each, not two."""
    specs = heap_specs()
    fixtures = {"memory": fixture({"heap": ["kernel32.HeapAlloc", "ntdll.RtlAllocateHeap"],
                                   "more": ["kernel32.HeapAlloc"]}, "heap", "more")}
    run = {"tests": {"a": {"block": "memory/heap", "outcome": "passed"},
                     "b": {"block": "memory/more", "outcome": "passed"}}}
    compat().gather(specs, fixtures, {}, run, None)
    forwarder, target = specs["kernel32"][1]["HeapAlloc"], specs["ntdll"][1]["RtlAllocateHeap"]
    assert [e.test for e in forwarder.evidence] == ["memory/heap", "memory/more"]
    assert [e.test for e in target.evidence] == ["memory/heap", "memory/more"]
    assert compat().tally(target.evidence) == "2 tests: 2 passed"
    assert target.status == "passing" and not target.forwarded_only


def test_forwarders_of_one_target_share_its_tests():
    """Two exports forwarded to one target (one through a chain) each take the other's tests."""
    specs = specs_of(
        export("kernel32", "EnterCriticalSection", {"forward": "NTDLL.RtlEnterCriticalSection"}),
        export("other", "Enter", {"forward": "kernel32.EnterCriticalSection"}),
        export("ntdll", "RtlEnterCriticalSection", {"native": "RtlEnterCriticalSection"}),
    )
    fixtures = {"sync": fixture({"cs": ["kernel32.EnterCriticalSection"], "o": ["other.Enter"]}, "cs", "o")}
    compat().gather(specs, fixtures, {}, None, None)
    target = specs["ntdll"][1]["RtlEnterCriticalSection"]
    assert sorted(target.forwarded_by) == ["kernel32.EnterCriticalSection", "other.Enter"]
    assert sorted(e.test for e in target.evidence) == ["sync/cs", "sync/o"]
    assert sorted(e.test for e in specs["other"][1]["Enter"].evidence) == ["sync/cs", "sync/o"]


def test_a_forward_loop_or_a_missing_target_shares_nothing():
    specs = specs_of(
        export("a", "X", {"forward": "b.Y"}),
        export("b", "Y", {"forward": "a.X"}),
        export("a", "Z", {"forward": "nowhere.Z"}),
    )
    fixtures = {"f": fixture({"x": ["a.X"], "z": ["a.Z"]}, "x", "z")}
    compat().gather(specs, fixtures, {}, None, None)
    assert [e.test for e in specs["a"][1]["X"].evidence] == ["f/x"]
    assert specs["b"][1]["Y"].evidence == []
    assert [e.test for e in specs["a"][1]["Z"].evidence] == ["f/z"]


def test_the_summary_names_the_exports_pinned_only_through_a_forward(capsys):
    specs = heap_specs()
    fixtures = {"memory": fixture({"heap": ["kernel32.HeapAlloc"]}, "heap")}
    missing = compat().gather(specs, fixtures, {}, None, None)
    compat().summary(specs, missing, None, None)
    out = capsys.readouterr().out
    assert "Pinned: 1 of 1 implemented, 1 only through a forward: RtlAllocateHeap (via kernel32.HeapAlloc)" in out


# --- Depth: the natives' live tests ----------------------------------------------------------------


def native(dll, name, group=None):
    made = export(dll, name, {"native": name})
    made.group = group
    return made


def scenario(name, pins, ignored=None):
    return compat().Scenario(name, SCRIPTS / "scenarios.rs", pins, ignored)


def live_counts(specs):
    return {e.pin: len(e.live_tests) for _, exports in specs.values() for e in exports.values()}


def test_a_live_test_is_a_gated_block_neither_pending_nor_skipped_or_an_enabled_scenario():
    specs = specs_of(native("k", "A"), native("k", "B"), native("k", "C"), native("k", "D"))
    pin = ["k.A", "k.B"]
    fixtures = {
        "gated": fixture({"ok": pin, "todo": pin, "never": pin}, "ok", "todo", "never", gate=True,
                         pending={"todo": "waits"}, skip={"never": "refused"}),
        "worklist": fixture({"x": pin}, "x"),  # not gated: every block an expected failure
        "retaken": fixture({"y": pin}, "y", gate=True, retake="the capture moved"),
        "pends": fixture({"z": ["k.C"]}, "z", gate=True, pending={"z": "waits"}),
    }
    scenarios = {"on": scenario("on", ["k.A"]), "off": scenario("off", ["k.B", "k.D"], ignored="K32-1: gap")}
    compat().gather(specs, fixtures, scenarios, None, None)
    assert [e.test for e in specs["k"][1]["A"].live_tests] == ["gated/ok", "scenario on"]
    assert live_counts(specs) == {"k.A": 2, "k.B": 1, "k.C": 0, "k.D": 0}
    assert len(specs["k"][1]["B"].evidence) == 6  # pinned all the same, by tests that do not gate


def test_a_wildcard_pin_reaches_every_live_block():
    specs = specs_of(native("k", "A"))
    fixtures = {"f": fixture({"*": ["k.A"]}, "one", "two", "three", gate=True, pending={"three": "waits"})}
    compat().gather(specs, fixtures, {}, None, None)
    assert live_counts(specs) == {"k.A": 2}


def test_a_test_reaching_a_native_directly_and_through_a_forward_counts_once():
    specs = heap_specs()
    fixtures = {"memory": fixture({"heap": ["kernel32.HeapAlloc", "ntdll.RtlAllocateHeap"]}, "heap", gate=True)}
    compat().gather(specs, fixtures, {}, None, None)
    none, single = compat().shallow(specs["ntdll"][1])
    assert (none, [e.name for e in single]) == ([], ["RtlAllocateHeap"])
    # The forwarder is no native: depth counts natives alone.
    assert compat().shallow(specs["kernel32"][1]) == ([], [])


def test_depth_lists_the_shallow_natives_by_group():
    specs = specs_of(native("k", "Zed", "files"), native("k", "Alpha", "heap"), native("k", "Beta", "files"),
                     native("k", "Deep", "files"))
    groups = [{"key": "heap"}, {"key": "files"}]
    fixtures = {"f": fixture({"one": ["k.Beta", "k.Deep"], "two": ["k.Deep"]}, "one", "two", gate=True)}
    compat().gather(specs, fixtures, {}, None, None)
    none, single = compat().shallow(specs["k"][1])
    assert compat().depth_lines(groups, none, single) == [
        "  No live test (2):",
        "    heap (1): Alpha",
        "    files (1): Zed",
        "  One live test (1):",
        "    files (1): Beta [f one]",
    ]


def test_depth_lines_break_between_items():
    lines = compat().pack(["a" * 30, "b" * 30, "c" * 30, "d" * 120], "  g (4): ", "    ", width=80)
    assert lines == ["  g (4): " + "a" * 30 + ", " + "b" * 30 + ",", "    " + "c" * 30 + ",", "    " + "d" * 120]


def test_the_summary_counts_the_shallow_natives_and_depth_lists_them(capsys):
    specs = specs_of(native("k", "A"), native("k", "B"), export("k", "C", {"forward": "k.A"}))
    fixtures = {"f": fixture({"one": ["k.A"]}, "one", gate=True)}
    missing = compat().gather(specs, fixtures, {}, None, None)
    compat().summary(specs, missing, None, None)
    out = capsys.readouterr().out
    assert "Depth: of 2 natives, 1 have no live test, 1 have one (--depth lists them)" in out
    assert "No live test" not in out
    compat().summary(specs, missing, None, None, depth=True)
    out = capsys.readouterr().out
    assert "Depth: of 2 natives, 1 have no live test, 1 have one\n  No live test (1):\n" in out
    assert "    (no group) (1): A [f one]" in out
