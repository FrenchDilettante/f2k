#!/usr/bin/env python3
"""
Turn a boot's COM1 performance trace into a profiler.firefox.com profile.

The kernel's `perf-trace` cargo feature (kernel/src/perf.rs) samples the
interrupted context and its call stack on every interval interrupt, and the
boot's end dumps the samples on COM1:

    F2K: perf trace: 214 samples taken, 214 kept (the sample interval is 100144 100ns units)
    F2K: perf sample: t=1523092 cs=0x08 eip=0x80135f70 stack=0x8012a1d0,0x8013d063

This script parses those lines out of a boot's log (target/qemu/logs/<test>.log),
symbolizes the kernel pointers against the kernel ELF's symbol table (the ring-3
pointers keep their raw addresses; the fixtures carry no symbols), and writes a
profile in the Firefox Profiler's processed format, loadable at
profiler.firefox.com with "Load profile from file": the kernel's samples one
thread, the ring-3 samples another, the flame graph the call tree.

Usage:
  perf_profile.py <log> [--kernel <elf>] [-o <profile.json>]
"""
import argparse
import json
import re
import struct
import sys
import time
from bisect import bisect_right
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# The COM1 dump's shapes (kernel/src/perf.rs). The times are 100 ns units; a sample's `stack`
# names the callers' return addresses, nearest first (the leaf is the `eip` field).
HEADER = re.compile(r"^F2K: perf trace: (\d+) samples taken, (\d+) kept \(the sample interval is (\d+) 100ns units\)$")
SAMPLE = re.compile(
    r"^F2K: perf sample: t=(\d+) cs=(0x[0-9a-f]+) eip=(0x[0-9a-f]+)(?: stack=((?:0x[0-9a-f]+,)*0x[0-9a-f]+))?$"
)

# The kernel ELF's default place (the profile the suite's builds keep is under target/qemu/builds,
# but any built kernel names the same symbols).
DEFAULT_KERNEL = REPO / "target" / "x86-f2k" / "debug" / "f2k-kernel"

# The two profile categories, one per ring; their indexes into meta.categories.
KERNEL_CATEGORY = 0
RING3_CATEGORY = 1
CATEGORIES = [
    {"name": "F2K kernel", "color": "blue", "subcategories": ["Other"]},
    {"name": "Ring 3", "color": "purple", "subcategories": ["Other"]},
]

ONE_HUNDRED_NS = 10000  # per millisecond


def parse_trace(log_text: str) -> tuple[int, list[tuple[int, int, list[int]]]] | None:
    """The trace a boot's log carries: the sampling interval (100 ns units) and the samples
    (interrupt time, code segment, call stack leaf first), or None when the log carries no trace
    (a boot without the perf-trace feature)."""
    tick = None
    samples: list[tuple[int, int, list[int]]] = []
    for line in log_text.splitlines():
        if header := HEADER.match(line):
            tick = int(header.group(3))
            continue
        if sample := SAMPLE.match(line):
            stack = [int(frame, 16) for frame in (sample.group(4) or "").split(",") if frame]
            samples.append(
                (int(sample.group(1)), int(sample.group(2), 16), [int(sample.group(3), 16), *stack])
            )
    if tick is None:
        return None
    return tick, samples


def elf32_symbols(path: Path) -> list[tuple[int, int, str]]:
    """The ELF32 file's function symbols, sorted by address: (address, size, name)."""
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 1:
        raise ValueError(f"{path} is not an ELF32 file")
    sections_offset, = struct.unpack_from("<I", data, 0x20)
    section_size, section_count, = struct.unpack_from("<HH", data, 0x2E)
    sections = []
    for index in range(section_count):
        name, kind, _flags, _address, offset, size, _link, _info, _align, _entry = struct.unpack_from(
            "<10I", data, sections_offset + index * section_size
        )
        sections.append((kind, offset, size, _link))
    symbols: list[tuple[int, int, str]] = []
    for kind, offset, size, link in sections:
        if kind != 2:  # SHT_SYMTAB
            continue
        strings_offset, strings_size = sections[link][1], sections[link][2]
        strings = data[strings_offset : strings_offset + strings_size]
        for at in range(0, size, 16):  # Elf32_Sym: name, value, size, info, other, section
            name_at, value, sym_size, info, _other, _section = struct.unpack_from("<IIIBBH", data, offset + at)
            if info & 0xF != 2 or value == 0:  # STT_FUNC, an actual function
                continue
            end = strings.find(b"\0", name_at)
            name = strings[name_at:end].decode("utf-8", errors="replace")
            if name:
                symbols.append((value, sym_size, name))
    return sorted(symbols)


def rust_demangle(mangled: str) -> str:
    """The Rust manglings the kernel's symbols carry, readable:

    - the legacy format, `_ZN<segments>...E`: `_ZN10f2k_kernel7process4reap17h0123...E` ->
      `f2k_kernel::process::reap` (the disambiguator hash dropped);
    - the v0 format, `_R<tokens>`: `_RNvNtNtCs4kgb3nwRsvB_10f2k_kernel3mem7bootmem9boot_init` ->
      `f2k_kernel::mem::bootmem::boot_init` (the namespace and disambiguator tokens dropped).

    Both parsers are pragmatic: they keep the identifier segments and drop everything else, so a
    generic or closure symbol keeps its names even where its full shape is not decoded. Anything
    they do not recognize is returned as is."""
    if mangled.startswith("_ZN") and mangled.endswith("E"):
        return _demangle_legacy(mangled)
    if mangled.startswith("_R"):
        return _demangle_v0(mangled)
    return mangled


def _demangle_legacy(mangled: str) -> str:
    body = mangled[3:-1]
    parts = []
    at = 0
    while at < len(body):
        end = at
        while end < len(body) and body[end].isdigit():
            end += 1
        if end == at:
            return mangled  # a segment that does not start with its length
        count = int(body[at:end])
        if count == 0 or end + count > len(body):
            return mangled
        parts.append(body[end : end + count])
        at = end + count
    if parts and len(parts[-1]) == 17 and parts[-1].startswith("h"):
        parts.pop()  # the disambiguator: h<16 hex digits>
    return "::".join(parts)


def _demangle_v0(mangled: str) -> str:
    """The v0 grammar's identifier segments, `::`-joined. Tokens that are not identifiers (the
    namespace markers, the crate and disambiguator hashes, the binding and generic markers) are
    skipped; an identifier is `<decimal length><its characters>`."""
    body = mangled[2:]
    parts = []
    at = 0
    while at < len(body):
        char = body[at]
        if char.isdigit():
            end = at
            while end < len(body) and body[end].isdigit():
                end += 1
            count = int(body[at:end])
            if count == 0 or end + count > len(body):
                return mangled
            parts.append(body[end : end + count])
            at = end + count
        elif char in ("s", "B"):  # a disambiguator (s<base36>_) or a backref (B<base36>_)
            end = body.find("_", at)
            if end < 0:
                return mangled
            at = end + 1
        else:
            at += 1  # a namespace, binding, or generic marker
    return "::".join(parts) if parts else mangled


def symbolizer(symbols: list[tuple[int, int, str]]):
    """Name the instruction pointers: the containing function (the sample's offset inside it is
    dropped: without source lines the offset says nothing the flame graph can use, and it would
    fragment the same function into many bars)."""
    addresses = [address for address, _size, _name in symbols]

    def name_of(eip: int) -> str:
        at = bisect_right(addresses, eip) - 1
        if at < 0:
            return f"0x{eip:08x}"
        address, size, symbol = symbols[at]
        if size and eip - address >= size:
            return f"0x{eip:08x}"  # past the function's end: likely a padded area
        return rust_demangle(symbol)

    return name_of


class ProfileBuilder:
    """The processed profile's shared tables: strings, functions, frames, and the stack tree the
    samples name. The tables deduplicate: one frame per (name, category), one stack node per
    (parent stack, frame)."""

    def __init__(self) -> None:
        self.strings: list[str] = []
        self.string_at: dict[str, int] = {}
        self.funcs: list[int] = []  # each function's name, as a string index
        self.func_at: dict[str, int] = {}
        self.frames: list[tuple[int, int]] = []  # (function index, category)
        self.frame_at: dict[tuple[str, int], int] = {}
        self.stacks: list[tuple[int, int]] = []  # each stack node's (frame index, prefix offset)
        self.stack_at: dict[tuple[int, int | None], int] = {}  # (frame index, parent) -> stack index

    def string(self, text: str) -> int:
        if text not in self.string_at:
            self.string_at[text] = len(self.strings)
            self.strings.append(text)
        return self.string_at[text]

    def func(self, name: str) -> int:
        if name not in self.func_at:
            self.func_at[name] = len(self.funcs)
            self.funcs.append(self.string(name))
        return self.func_at[name]

    def frame(self, name: str, category: int) -> int:
        if (name, category) not in self.frame_at:
            self.frame_at[name, category] = len(self.frames)
            self.frames.append((self.func(name), category))
        return self.frame_at[name, category]

    def stack(self, names: list[str], category: int) -> int:
        """The stack node for a call stack named root first; returns the leaf's index. Shared
        prefixes share nodes: the tree is the deduplicated set of stacks. A node's prefix offset
        is how far back its parent is (0: the node is a root); parents are always inserted before
        their children, so the offset is fixed at insertion."""
        parent: int | None = None
        for name in names:
            frame = self.frame(name, category)
            if (frame, parent) not in self.stack_at:
                self.stack_at[frame, parent] = len(self.stacks)
                # A root's offset is 0 by the format's rule; a child's is its distance back.
                self.stacks.append(
                    (frame, 0 if parent is None else len(self.stacks) - parent)
                )
            parent = self.stack_at[frame, parent]
        assert parent is not None, "a sample's stack is never empty"
        return parent

    def build(self) -> dict:
        return {
            "frameTable": {
                "address": [0] * len(self.frames),
                "category": [category for _func, category in self.frames],
                "column": [0] * len(self.frames),
                "flags": [4] * len(self.frames),  # HasCategory: the frame names its ring's category
                "func": [func for func, _category in self.frames],
                "innerWindowID": [0] * len(self.frames),
                "length": len(self.frames),
                "lib": [0] * len(self.frames),
                "line": [0] * len(self.frames),
                "nativeSymbol": [0] * len(self.frames),
                "originalLocation": [0] * len(self.frames),
                "subcategory": [0] * len(self.frames),
            },
            "funcTable": {
                "columnNumber": [0] * len(self.funcs),
                "flags": [0] * len(self.funcs),
                "length": len(self.funcs),
                "lineNumber": [0] * len(self.funcs),
                "name": self.funcs,
                "originalLocation": [0] * len(self.funcs),
                "resource": [0] * len(self.funcs),
                "source": [0] * len(self.funcs),
            },
            "resourceTable": {"host": [], "length": 0, "name": [], "type": []},
            "nativeSymbols": {"address": [], "functionSize": [], "length": 0, "libIndex": [], "name": []},
            "sources": {"content": [], "filename": [], "id": [], "length": 0, "sourceMapURL": [], "startColumn": [], "startLine": []},
            "sourceLocationTable": {"column": [], "length": 0, "line": [], "source": []},
            "stackTable": {
                "frame": [frame for frame, _offset in self.stacks],
                "prefixOffset": [offset for _frame, offset in self.stacks],
                "length": len(self.stacks),
            },
            "stringArray": self.strings,
        }


def thread(name: str, tid: int, is_main: bool, samples: list[tuple[int, int]], origin: int) -> dict:
    """One thread of the profile: the ring's samples as (time, stack) pairs. `origin` is the
    profile's first sample's time (100 ns units), so each thread's track starts where its first
    sample actually landed."""
    deltas = [round((samples[0][0] - origin) / ONE_HUNDRED_NS, 4)]
    for (before, _), (now, _) in zip(samples, samples[1:]):
        deltas.append(round((now - before) / ONE_HUNDRED_NS, 4))
    return {
        "isMainThread": is_main,
        "markers": {"category": [], "data": [], "endTime": [], "length": 0, "name": [], "phase": [], "startTime": []},
        "name": name,
        "pausedRanges": [],
        "pid": "0",
        "processName": "F2K boot",
        "processShutdownTime": None,
        "processStartupTime": 0,
        "processType": "default",
        "registerTime": 0,
        "samples": {
            "length": len(samples),
            "stack": [stack for _time, stack in samples],
            "threadCPUDelta": [0] * len(samples),
            "timeDeltas": deltas,
            "weight": [1] * len(samples),
            "weightType": "samples",
        },
        "showMarkersInTimeline": False,
        "tid": tid,
        "unregisterTime": None,
    }


def build_profile(samples: list[tuple[int, int, list[int]]], tick: int, name_of) -> dict:
    """The whole profile: the kernel's samples and the ring-3 samples as one process's two
    threads, over the boot's time. Each sample's call stack (leaf first) becomes a path through
    the shared stack tree."""
    builder = ProfileBuilder()
    kernel: list[tuple[int, int]] = []
    ring3: list[tuple[int, int]] = []
    for interrupt_time, cs, frames in samples:
        if cs & 3 == 3:
            names = [f"ring 3: 0x{frame:08x}" for frame in frames]
            ring3.append((interrupt_time, builder.stack(list(reversed(names)), RING3_CATEGORY)))
        else:
            names = [name_of(frame) for frame in frames]
            kernel.append((interrupt_time, builder.stack(list(reversed(names)), KERNEL_CATEGORY)))
    origin = samples[0][0] if samples else 0
    threads = []
    if kernel:
        threads.append(thread("Kernel (ring 0)", 0, True, kernel, origin))
    if ring3:
        threads.append(thread("Ring 3 (user)", 1, False, ring3, origin))
    return {
        "meta": {
            "categories": CATEGORIES,
            "extensions": {"baseURL": [], "id": [], "length": 0, "name": []},
            "interval": tick / ONE_HUNDRED_NS,
            "markerSchema": [],
            "oscpu": "x86 (F2K under QEMU)",
            "pausedRanges": [],
            "preprocessedProfileVersion": 75,
            "processType": 0,
            "product": "F2K",
            "sampleUnits": {"eventDelay": "ms", "threadCPUDelta": "µs", "time": "ms"},
            "sourceCodeIsNotOnSearchfox": True,
            "startTime": int(time.time() * 1000),
            "symbolicated": True,
            "usesOnlyOneStackType": True,
            "version": 24,
        },
        "libs": [],
        "pages": [],
        "profilerOverhead": [],
        "shared": builder.build(),
        "threads": threads,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log", type=Path, help="a boot's COM1 log (the perf trace's lines)")
    parser.add_argument("--kernel", type=Path, default=DEFAULT_KERNEL, help="the kernel ELF to symbolize against")
    parser.add_argument("-o", "--output", type=Path, default=None, help="the profile to write (default: beside the log, .json)")
    args = parser.parse_args(argv)

    trace = parse_trace(args.log.read_text(errors="replace"))
    if trace is None:
        print(f"{args.log}: no perf trace (the boot was not built with the perf-trace feature)", file=sys.stderr)
        return 1
    tick, samples = trace
    if not samples:
        print(f"{args.log}: the trace is empty", file=sys.stderr)
        return 1
    name_of = symbolizer(elf32_symbols(args.kernel))
    profile = build_profile(samples, tick, name_of)
    output = args.output or args.log.with_suffix(".json")
    output.write_text(json.dumps(profile, indent=1))
    kept = sum(len(t["samples"]["stack"]) for t in profile["threads"])
    print(f"{output}: {kept} samples, {len(profile['shared']['funcTable']['name'])} functions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
