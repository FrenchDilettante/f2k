"""Checks on the repository's own files (no QEMU)."""
import re
import subprocess
import zlib
from pathlib import Path

import pytest

import f2kboot

BATCH_FILES = sorted((f2kboot.REPO_ROOT / "tests").rglob("*.bat"))


@pytest.mark.parametrize("path", BATCH_FILES, ids=lambda p: str(p.relative_to(f2kboot.REPO_ROOT)))
def test_batch_files_keep_crlf_line_endings(path: Path):
    """cmd.exe misreads LF-only batch files (it can resume mid-line between its reads), which mangles
    commands: the Windows 2000 scripts must keep CRLF on every line."""
    data = path.read_bytes()
    bare_lf = data.count(b"\n") - data.count(b"\r\n")
    assert bare_lf == 0, f"{bare_lf} line(s) end in a bare LF"


# --- The corpus fixtures' declarations, sources, captures and binaries ---------------------------

TESTS = f2kboot.REPO_ROOT / "tests"
DECLARED = sorted(path.parent.name for path in TESTS.glob("*/fixture.toml"))
SECTIONED = [name for name in DECLARED if f2kboot.declaration(name)["kind"] == "sectioned"]
# The fixtures built on common/f2kt.h: their section table lists them (and --list prints it).
LISTED = [name for name in SECTIONED if '"../common/f2kt.h"' in (TESTS / name / f"{name}.c").read_text()]
# Set once tests/build.bat has rebuilt every fixture: a binary without its source stamp then fails
# instead of skipping, and the binaries' --list (their section tables) is the checked-in source's.
REQUIRE_SOURCE_STAMPS = False
DECLARATION_KEYS = {"description", "kind", "gate", "timeout", "masks", "retake", "pending"}


def declared_sections(fixture: str) -> set[str]:
    """The sections a fixture's source declares: its f2kt.h section table, or bare's modes."""
    source = (TESTS / fixture / f"{fixture}.c").read_text(encoding="latin-1")
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
    assert (TESTS / fixture / f"{fixture}.exe").is_file()
    assert (TESTS / fixture / "output.txt").is_file() == (declared["kind"] == "sectioned")


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
def test_pending_blocks_name_their_increment(fixture: str):
    """Every pending block says which rebuild increment enables it (`<increment>: <subsystem>`),
    so an increment knows the entries it removes."""
    for section, reason in f2kboot.declaration(fixture).get("pending", {}).items():
        assert re.match(r"[A-C]\d+: \S", reason), f"{section!r}: {reason!r} names no increment"


def test_the_capture_script_lists_bares_modes():
    """bare has no section table: capture.bat lists its modes, which must be bare.c's."""
    script = (TESTS / "capture.bat").read_text(encoding="latin-1")
    listed = set(re.search(r"for %%M in \(([^)]*)\) do call :cap bare\.exe", script).group(1).split())
    assert listed | {"(default)"} == declared_sections("bare")


def source_stamp(fixture: str) -> str:
    """The stamp build.bat computes (common/srcsum.c): the CRC-32 of the source and f2kt.h, LF."""
    data = b"".join(
        path.read_bytes().replace(b"\r\n", b"\n")
        for path in (TESTS / fixture / f"{fixture}.c", TESTS / "common" / "f2kt.h")
    )
    return f"0x{zlib.crc32(data):08X}"


@pytest.mark.parametrize("fixture", LISTED)
def test_binaries_are_built_from_the_checked_in_source(fixture: str):
    """A binary carries the stamp of the source it was built from (F2KT-SOURCE-CRC, common/f2kt.h):
    it must be the checked-in source's, so its section table (--list), and its behavior, are the
    source's. The capture records the stamp of the binary it ran."""
    binary = (TESTS / fixture / f"{fixture}.exe").read_bytes()
    found = re.search(rb"F2KT-SOURCE-CRC=(0x[0-9A-F]{8}|unknown)", binary)
    if found is None or found.group(1) == b"unknown":
        if REQUIRE_SOURCE_STAMPS:
            pytest.fail(f"{fixture}.exe carries no source stamp: rebuild it with tests/build.bat")
        pytest.skip(f"{fixture}.exe predates the source stamp (rebuild with tests/build.bat)")
    assert found.group(1).decode() == source_stamp(fixture), "the binary is stale: rebuild it"
    header = (TESTS / fixture / "output.txt").read_text(encoding="latin-1").split(">>> ", 1)[0]
    recorded = re.search(r"F2KT-SOURCE-CRC=(0x[0-9A-F]{8})", header)
    assert recorded is None or recorded.group(1) == found.group(1).decode(), (
        "the capture was taken with another binary: recapture it"
    )


def test_check_all_runs_the_test_systems():
    """`make check-all` is the one command a change is verified with: the host unit tests, then
    the on-target suite (fastest first)."""
    plan = subprocess.run(["make", "-n", "check-all"], cwd=f2kboot.REPO_ROOT, capture_output=True,
                          text=True, check=True).stdout
    steps = ["cargo test --lib", "pytest tests"]
    at = [plan.find(step) for step in steps]
    assert all(index >= 0 for index in at), dict(zip(steps, at))
    assert at == sorted(at), "the steps run fastest first"
