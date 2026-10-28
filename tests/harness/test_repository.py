"""Checks on the repository's own files (no QEMU)."""
import re
import subprocess
import zlib
from pathlib import Path

import pytest

import f2kboot

BATCH_FILES = sorted(f2kboot.TESTS.rglob("*.bat"))


@pytest.mark.parametrize("path", BATCH_FILES, ids=lambda p: str(p.relative_to(f2kboot.REPO_ROOT)))
def test_batch_files_keep_crlf_line_endings(path: Path):
    """cmd.exe misreads LF-only batch files (it can resume mid-line between its reads), which mangles
    commands: the Windows 2000 scripts must keep CRLF on every line."""
    data = path.read_bytes()
    bare_lf = data.count(b"\n") - data.count(b"\r\n")
    assert bare_lf == 0, f"{bare_lf} line(s) end in a bare LF"


# --- The corpus fixtures' declarations, sources, captures and binaries ---------------------------

TESTS = f2kboot.TESTS
# Every fixture, by name, in its DLL's directory (tests/<dll>/<name>/); f2kboot refuses a name two
# groups declare, so a duplicate fails here, at collection.
DECLARED = sorted(f2kboot.fixture_directories())
# The sectioned fixtures declared ahead of their real-machine files (f2kboot.awaited) are left out
# of the checks on those files.
SECTIONED = [name for name in DECLARED
             if f2kboot.declaration(name)["kind"] == "sectioned" and not f2kboot.awaited(name)]
# The fixtures built on common/f2kt.h: their section table lists them (and --list prints it).
LISTED = [name for name in SECTIONED
          if '"../common/f2kt.h"' in (f2kboot.fixture_directory(name) / f"{name}.c").read_text()]
# Set once tests/build.bat has rebuilt every fixture: a binary without its source stamp then fails
# instead of skipping, and the binaries' --list (their section tables) is the checked-in source's.
REQUIRE_SOURCE_STAMPS = False
DECLARATION_KEYS = {"description", "kind", "gate", "timeout", "masks", "retake", "pending", "pins",
                    "screenshots"}


def declared_sections(fixture: str) -> set[str]:
    """The sections a fixture's source declares: its f2kt.h section table, or bare's modes."""
    source = (f2kboot.fixture_directory(fixture) / f"{fixture}.c").read_text(encoding="latin-1")
    if fixture in LISTED:
        table = re.search(r"section_t sections\[\] = \{(.*?)\n\};", source, re.S).group(1)
        return set(re.findall(r'\{\s*"([\w-]+)",', table))
    return {"(default)"} | set(re.findall(r'str_eq\(mode, "([\w-]+)"\)', source))


@pytest.mark.parametrize("fixture", DECLARED)
def test_fixture_declarations_read(fixture: str):
    """A declaration holds only the fields the reader knows (f2kboot), and a sectioned fixture has
    a capture while a smoke one has none."""
    declared = f2kboot.declaration(fixture)
    assert set(declared) <= DECLARATION_KEYS, set(declared) - DECLARATION_KEYS
    assert declared["kind"] in ("sectioned", "smoke")
    if declared["kind"] == "sectioned" and f2kboot.awaited(fixture):
        return  # declared ahead of its program and capture: none of them is there
    if declared["kind"] == "sectioned":
        missing = [path.name for path in f2kboot.real_machine_files(fixture) if not path.is_file()]
        assert not missing, f"the real-machine files come together: {missing} missing"
    directory = f2kboot.fixture_directory(fixture)
    assert (directory / f"{fixture}.exe").is_file()
    assert (directory / "output.txt").is_file() == (declared["kind"] == "sectioned")


@pytest.mark.parametrize("fixture", SECTIONED)
def test_captures_match_their_sources(fixture: str):
    """Every section the source declares has a captured block (output.txt, or overrides.txt for the
    ones the capture script cannot take), every block names a declared section, every pending
    block exists, and every mask still matches a line of its own section's block."""
    blocks = f2kboot.read_capture(fixture)
    captured = {block.section.split(" ")[0] for block in blocks}
    declared = declared_sections(fixture)
    assert declared - captured == set(), "declared sections without a block"
    assert captured - declared == set(), "blocks naming no declared section"
    declaration = f2kboot.declaration(fixture)
    assert set(declaration.get("pending", {})) <= {block.section for block in blocks}, (
        "pending blocks that do not exist"
    )
    by_section = {block.section: block for block in blocks}
    for section, masks in declaration.get("masks", {}).items():
        assert section in by_section, f"masks for a section with no block: {section!r}"
        for mask in masks:
            pattern = f2kboot.mask_pattern(mask)
            assert any(pattern.fullmatch(line) for line in by_section[section].lines), (
                f"the mask matches no line of {section!r}: {mask!r}"
            )


@pytest.mark.parametrize("fixture", SECTIONED)
def test_pending_blocks_give_their_reason(fixture: str):
    """Every pending block says why it is still on the work list ("not yet implemented")."""
    for section, reason in f2kboot.declaration(fixture).get("pending", {}).items():
        assert reason.strip(), f"{section!r}: no reason given"


def test_the_capture_script_lists_bares_modes():
    """bare has no section table: capture.bat lists its modes, which must be bare.c's."""
    script = (TESTS / "capture.bat").read_text(encoding="latin-1")
    listed = set(re.search(r"for %%M in \(([^)]*)\) do call :cap bare\.exe", script).group(1).split())
    assert listed | {"(default)"} == declared_sections("bare")


def source_stamp(fixture: str) -> str:
    """The stamp build.bat computes (common/srcsum.c): the CRC-32 of the source and f2kt.h, LF."""
    data = b"".join(
        path.read_bytes().replace(b"\r\n", b"\n")
        for path in (f2kboot.fixture_directory(fixture) / f"{fixture}.c", TESTS / "common" / "f2kt.h")
    )
    return f"0x{zlib.crc32(data):08X}"


@pytest.mark.parametrize("fixture", LISTED)
def test_binaries_are_built_from_the_checked_in_source(fixture: str):
    """A binary carries the stamp of the source it was built from (F2KT-SOURCE-CRC, common/f2kt.h):
    it must be the checked-in source's, so its section table (--list), and its behavior, are the
    source's. The capture records the stamp of the binary it ran."""
    binary = (f2kboot.fixture_directory(fixture) / f"{fixture}.exe").read_bytes()
    found = re.search(rb"F2KT-SOURCE-CRC=(0x[0-9A-F]{8}|unknown)", binary)
    if found is None or found.group(1) == b"unknown":
        if REQUIRE_SOURCE_STAMPS:
            pytest.fail(f"{fixture}.exe carries no source stamp: rebuild it with tests/build.bat")
        pytest.skip(f"{fixture}.exe predates the source stamp (rebuild with tests/build.bat)")
    assert found.group(1).decode() == source_stamp(fixture), "the binary is stale: rebuild it"
    capture = f2kboot.fixture_directory(fixture) / "output.txt"
    header = capture.read_text(encoding="latin-1").split(">>> ", 1)[0]
    recorded = re.search(r"F2KT-SOURCE-CRC=(0x[0-9A-F]{8})", header)
    assert recorded is None or recorded.group(1) == found.group(1).decode(), (
        "the capture was taken with another binary: recapture it"
    )


def test_the_corpus_names_are_8_3_and_distinct():
    """The disk build puts every sectioned fixture's program and its companions (the other programs
    and the DLLs beside it, and the DLLs in its subdirectories) in \\CORPUS, by their upper-cased
    names (the Makefile's corpus loop): each must be an 8.3 name, and no two may meet, or one would
    replace another. An awaited fixture's program counts by its name already."""
    def is_8_3(part: str) -> bool:
        stem, dot, extension = part.partition(".")
        return 1 <= len(stem) <= 8 and len(extension) <= 3 and "." not in extension and " " not in part

    seen: dict[str, str] = {}
    for fixture in DECLARED:
        if f2kboot.declaration(fixture)["kind"] != "sectioned":
            continue
        directory = f2kboot.fixture_directory(fixture)
        names = {f"{fixture}.exe"} | {
            path.relative_to(directory).as_posix()
            for pattern in ("*.exe", "*.dll", "*/*.dll") for path in directory.glob(pattern)
        }
        for name in sorted(names):
            placed = name.upper()
            assert all(is_8_3(part) for part in placed.split("/")), f"{fixture}: {name} is not 8.3"
            assert placed not in seen, f"{fixture}'s {name} meets {seen[placed]}'s in \\CORPUS"
            seen[placed] = fixture


def test_the_pins_check_out():
    """The tests' pins agree with the export specs and the captures (scripts/compat.py --check):
    every pin names an export of a spec, every pinned section has a captured block, every
    scenario pins something, every gap's reason leads with its id."""
    import sys

    result = subprocess.run(
        [sys.executable, str(f2kboot.REPO_ROOT / "scripts" / "compat.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_check_all_runs_the_test_systems():
    """`make check-all` is the one command a change is verified with: the host unit tests, the
    pins' check and the host scenarios, and the on-target suite, in that order (fastest first)."""
    plan = subprocess.run(["make", "-n", "check-all"], cwd=f2kboot.REPO_ROOT, capture_output=True,
                          text=True, check=True).stdout
    steps = ["cargo test --lib", "scripts/compat.py --check --run", "pytest tests"]
    at = [plan.find(step) for step in steps]
    assert all(index >= 0 for index in at), dict(zip(steps, at))
    assert at == sorted(at), "the steps run fastest first"


# --- Kernel memory safety ------------------------------------------------------------------------

# The kernel's raw memory forms: volatile reads and writes, and slices built from raw parts. Once a
# process runs, the kernel touches user memory only through the fault-tolerant copy
# (`user::syscall::read_user` / `write_user`): a program owns every page of its own, the TEB and the
# parameters page included, and a raw access to such a page would reach it outside the copy's
# containment. The files below use the raw forms on memory that is not the program's, or before
# any program runs; a new file needs its reason here (or the copy instead).
RAW_ACCESS_ALLOWED = {
    "kernel/src/boot/cmdline.rs": "the Multiboot command line, read at boot before any process",
    "kernel/src/cm/mod.rs": "the registry's arena, a kernel static: its names, classes and value"
    " data",
    "kernel/src/cpu/gdt.rs": "the kernel's own descriptor table",
    "kernel/src/cpu/idt.rs": "the kernel's own interrupt table",
    "kernel/src/hw/vga.rs": "the text screen's cells, device memory through the kernel window",
    "kernel/src/mem/bootmem.rs": "the boot memory map and the frame database, before any process",
    "kernel/src/mem/paging.rs": "the page tables and frames, through the kernel's own windows",
    "kernel/src/perf.rs": "(perf-trace builds only) the frame-pointer walk of a sampled stack, each"
    " frame checked against the kernel window or the process's regions first",
    "kernel/src/sched/startup.rs": "a new thread's kernel gate stack",
    "kernel/src/user/syscall.rs": "the copy primitives themselves and the attribution flag",
    "kernel/src/user/shared.rs": "the shared data page through the kernel's own mapping of its frame",
}
RAW_FORMS = ("read_volatile", "write_volatile", "from_raw_parts")


def kernel_code_lines():
    """Each kernel source file's path (repository-relative) and its lines outside line comments."""
    for path in sorted((f2kboot.REPO_ROOT / "kernel" / "src").rglob("*.rs")):
        relative = str(path.relative_to(f2kboot.REPO_ROOT))
        lines = path.read_text().splitlines()
        yield relative, [(number, line) for number, line in enumerate(lines, start=1)
                         if not line.lstrip().startswith("//")]


def test_raw_memory_access_stays_off_user_memory():
    """Raw memory forms appear only in the files that touch memory no program owns: everything else
    reaches user memory through the fault-tolerant copy."""
    found = {relative for relative, lines in kernel_code_lines()
             if any(form in line for _, line in lines for form in RAW_FORMS)}
    unexpected = sorted(found - set(RAW_ACCESS_ALLOWED))
    assert not unexpected, (
        f"raw memory forms in {unexpected}: reach user memory through read_user/write_user, "
        "or add the file to RAW_ACCESS_ALLOWED with the reason its memory is not a program's"
    )
    stale = sorted(set(RAW_ACCESS_ALLOWED) - found)
    assert not stale, f"RAW_ACCESS_ALLOWED names files without raw forms any more: {stale}"


# The user page-table entries' writers: the address-space manager alone. Everything else maps,
# commits, guards and releases user pages through `mem::vm` (`map_prepared`, `map_zeroed`,
# `commit`, `plant_guard`, `decommit`, `release`), so every user page lies in a region and every
# frame's release goes through the one place that knows which entries own one.
PTE_WRITERS = {"kernel/src/mem/vm.rs", "kernel/src/mem/paging.rs"}
PTE_FORMS = ("set_user_pte(", "user_pte(", ".set_entry(", "map_user_page(")


def test_only_the_address_space_writes_user_entries():
    """The raw user-entry access appears only in `mem::vm` and the `paging` primitives under it."""
    found = [f"{relative}:{number}" for relative, lines in kernel_code_lines()
             if relative not in PTE_WRITERS
             for number, line in lines if any(form in line for form in PTE_FORMS)]
    assert not found, f"user page-table entries written outside mem::vm: {found}"


# --- The process record ---------------------------------------------------------------------------

# The `current_mut()` call sites in the kernel: each hands out an aliasable `&'static mut Process`
# (explicit borrows retire them). The count may only go down.
CURRENT_MUT_SITES = 3


def test_current_mut_call_sites_only_go_down():
    """New code takes the process part it needs as a parameter instead of reaching for the
    `&'static mut` singleton; the recorded count is the ceiling, lowered as sites go."""
    call = re.compile(r"(?<!fn )\bcurrent_mut\(\)")
    sites = sum(
        len(call.findall(path.read_text()))
        for path in (f2kboot.REPO_ROOT / "kernel" / "src").rglob("*.rs")
    )
    assert sites <= CURRENT_MUT_SITES, (
        f"{sites} current_mut() call sites, above the ceiling of {CURRENT_MUT_SITES}: pass the "
        "process part the code needs as a parameter instead"
    )
    assert sites == CURRENT_MUT_SITES, (
        f"{sites} current_mut() call sites, below the recorded {CURRENT_MUT_SITES}: lower "
        f"CURRENT_MUT_SITES in tests/harness/test_repository.py to {sites} so the ratchet holds"
    )


# --- The system DLLs as Windows 2000 builds them --------------------------------------------------

import tomllib


def dll_exports(dll: str) -> list[dict]:
    """A DLL's implemented and stubbed exports (its spec's catalogued records, without an impl,
    left out)."""
    spec = tomllib.loads((f2kboot.REPO_ROOT / "userland" / dll / "exports.toml").read_text())
    return [export for export in spec["export"] if "impl" in export]


# The DLLs F2K builds: the userland workspace's crates with an export spec (ntdll, kernel32, msvcrt,
# advapi32, user32), by module name.
BUILT_DLLS = sorted(path.parent.name for path in (f2kboot.REPO_ROOT / "userland").glob("*/exports.toml")
                    if (path.parent / "Cargo.toml").is_file())


def test_no_export_is_a_kernel_served_win32_service():
    """Every kernel32 export is kernel32's own code over ntdll: the kernel serves no Win32 service
    and has no Win32 layer (kernel/src/compat), and the specs' transitional kinds (impl service,
    legacy and floor, served from 0x2000, and the unimplemented stubs) are gone: exportgen no longer
    reads them. Only Windows 2000's system services (impl syscall) enter the kernel: ntdll's, and
    user32's and gdi32's win32k calls."""
    transitional = [
        f"{spec.parent.name}/{export['name']}"
        for spec in sorted((f2kboot.REPO_ROOT / "userland").glob("*/exports.toml"))
        for export in tomllib.loads(spec.read_text())["export"]
        if {"service", "legacy", "floor", "unimplemented"} & set(export.get("impl", {}))
    ]
    assert not transitional, (
        f"exports served by the kernel as Win32 services, or stubs: {transitional}: write them in "
        "the DLL's user-mode code over ntdll's system services"
    )
    assert not (f2kboot.REPO_ROOT / "kernel" / "src" / "compat").exists(), (
        "kernel/src/compat is back: the kernel speaks NT; Win32 is kernel32's user-mode code"
    )


def test_the_spec_lists_every_fixture_import():
    """Every import of every corpus fixture names a DLL F2K builds and an export its spec
    implements or stubs, so every fixture loads: the loader stops at the first missing import. A
    fixture's own companion DLLs (beside it, as dllmain's) are its own.
    hellogui imports gdi32, which F2K does not have."""
    exported = {dll: {e["name"] for e in dll_exports(dll)} for dll in BUILT_DLLS}
    for exe in sorted(TESTS.glob("*/*/*.exe")):
        if exe.parent.name == "hellogui":
            continue
        companions = {path.name.lower() for path in exe.parent.rglob("*.dll")}
        for module, names in pe_imports(exe).items():
            if module in companions:
                continue
            dll = module.removesuffix(".dll")
            assert dll in exported, f"{exe.name} imports from {module}, which F2K does not build"
            missing = sorted(set(names) - exported[dll])
            assert not missing, f"{exe.name} imports {missing} from {module}"


def pe_rva_reader(data: bytes):
    """A PE file's dword reader, its RVA-to-offset map, and its optional header's offset."""
    word = lambda at: int.from_bytes(data[at:at + 4], "little")
    pe = word(0x3C)
    optional = pe + 24
    sections = int.from_bytes(data[pe + 6:pe + 8], "little")
    header = optional + int.from_bytes(data[pe + 20:pe + 22], "little")
    table = []
    for index in range(sections):
        entry = header + 40 * index
        table.append((word(entry + 12), max(word(entry + 8), word(entry + 16)), word(entry + 20),
                      word(entry + 36), word(entry + 16)))

    def offset(rva: int) -> int:
        for va, size, raw, _, _ in table:
            if va <= rva < va + size:
                return rva - va + raw
        raise ValueError(f"RVA {rva:#x} is in no section")

    return word, offset, optional, table


def pe_imports(path: Path) -> dict[str, list[str]]:
    """A PE image's imports: module (lower case) -> imported names (`#n` for an ordinal)."""
    data = path.read_bytes()
    word, offset, optional, _ = pe_rva_reader(data)
    imports_rva = word(optional + 96 + 8)
    found: dict[str, list[str]] = {}
    at = offset(imports_rva) if imports_rva else None
    while at is not None and word(at + 12):
        name_at = offset(word(at + 12))
        module = data[name_at:data.index(b"\0", name_at)].decode().lower()
        thunk = offset(word(at) or word(at + 16))
        names = found.setdefault(module, [])
        while word(thunk):
            entry = word(thunk)
            if entry & 0x8000_0000:
                names.append(f"#{entry & 0xFFFF}")
            else:
                hint_at = offset(entry) + 2
                names.append(data[hint_at:data.index(b"\0", hint_at)].decode())
            thunk += 4
        at += 20
    return found


def int2eh_pairs(path: Path) -> int:
    """How many `int 2Eh` byte pairs a DLL's executable sections hold."""
    data = path.read_bytes()
    _, _, _, table = pe_rva_reader(data)
    return sum(
        data[raw:raw + size].count(b"\xcd\x2e")
        for _, _, raw, characteristics, size in table
        if characteristics & 0x2000_0000  # IMAGE_SCN_MEM_EXECUTE
    )


def built_dll(builder, dll: str) -> Path:
    builder([])
    return f2kboot.REPO_ROOT / "target" / "userland" / "i686-f2k-pe" / "release" / f"{dll}.dll"


def test_kernel32_imports_nothing_but_ntdll(builder):
    """kernel32.dll's imports name ntdll.dll at most: Windows 2000's kernel32 imports ntdll alone."""
    modules = set(pe_imports(built_dll(builder, "kernel32")))
    assert modules <= {"ntdll.dll"}, modules


# The DLLs that enter the kernel through win32k's services, as Windows 2000's do: their own stubs,
# on win32k's numbers (table 1: 0x1000 to 0x1FFF).
WIN32K_CLIENTS = {"user32", "gdi32"}


def win32k_stubs(path: Path) -> int:
    """How many win32k service stubs a DLL's executable sections hold: `mov eax, <0x1000-0x1FFF>`,
    `lea edx, [esp+4]`, `int 2Eh`."""
    data = path.read_bytes()
    _, _, _, table = pe_rva_reader(data)
    stub = re.compile(rb"\xb8[\x00-\xff][\x10-\x1f]\x00\x00\x8d\x54\x24\x04\xcd\x2e", re.S)
    return sum(
        len(stub.findall(data[raw:raw + size]))
        for _, _, raw, characteristics, size in table
        if characteristics & 0x2000_0000  # IMAGE_SCN_MEM_EXECUTE
    )


@pytest.mark.parametrize("dll", [dll for dll in BUILT_DLLS if dll != "ntdll"])
def test_the_dlls_enter_the_kernel_as_windows_2000s_do(builder, dll: str):
    """Windows 2000's DLLs above ntdll enter the kernel only as theirs do: user32 and gdi32 through
    win32k's services alone (every `int 2Eh` in their code is one of their stubs on a win32k
    number), every other DLL never (no `int 2Eh`: its exports are user-mode code over ntdll)."""
    path = built_dll(builder, dll)
    gates = int2eh_pairs(path)
    if dll in WIN32K_CLIENTS:
        stubs = win32k_stubs(path)
        assert gates == stubs, (
            f"{gates - stubs} of {dll}'s {gates} int 2Eh byte pairs are no win32k stub's"
        )
    else:
        assert gates == 0, f"{gates} int 2Eh byte pairs in {dll}'s code"
