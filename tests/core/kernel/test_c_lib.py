"""c_lib - the kernel's memory routines, read from the built kernel ELF (no boot).

Every struct move, array zeroing and user-memory buffer in the kernel goes through memcpy, memset and
memmove, and the kernel crate builds unoptimized under every test profile (Cargo.toml's dev-opt keeps
it at opt-level 0). Written as Rust loops, those symbols cost a range step and two pointer
precondition checks per byte: NtCreateThread took about 6 ms under QEMU, a new thread about 3 ms to
reach its start routine, and sched's yield block — whose verdicts assume those windows are far
shorter than a clock tick — passed about one boot in three, depending on where the tick fell. The
routines are therefore the string instructions (kernel/src/c_lib.rs); this pins that the symbols
the kernel links are those routines, not compiled loops.

    uv run pytest tests/core/kernel/test_c_lib.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

import f2kboot

sys.path.insert(0, str(f2kboot.REPO_ROOT / "scripts"))
import perf_profile  # noqa: E402

# Each routine and the string instruction it is: rep movsb (F3 A4), rep stosb (F3 AA).
ROUTINES = {
    "memcpy": b"\xf3\xa4",
    "memmove": b"\xf3\xa4",
    "memset": b"\xf3\xaa",
}

# The routines are a few dozen bytes (memmove, the longest, is under 50); an unoptimized Rust loop
# with its calls to the range and pointer helpers is several times that.
MAX_ROUTINE_BYTES = 64


def code_at(path: Path, address: int, size: int) -> bytes:
    """`size` bytes of the ELF32 file's loaded image at virtual `address`, through the allocated
    section holding it."""
    data = path.read_bytes()
    sections_offset, = struct.unpack_from("<I", data, 0x20)
    section_size, section_count = struct.unpack_from("<HH", data, 0x2E)
    for index in range(section_count):
        _name, kind, flags, base, offset, length, *_ = struct.unpack_from(
            "<10I", data, sections_offset + index * section_size
        )
        # SHT_PROGBITS, SHF_ALLOC: a section of the loaded image with contents in the file.
        if kind == 1 and flags & 0x2 and base <= address and address + size <= base + length:
            return data[offset + address - base : offset + address - base + size]
    raise LookupError(f"{address:#x}+{size} is in no loaded section of {path}")


@pytest.fixture(scope="module")
def kernel(builder) -> Path:
    """The kernel ELF the suite boots (the default feature set)."""
    return builder([]).kernel


@pytest.mark.parametrize("name", ROUTINES)
def test_memory_routine_is_a_string_instruction(kernel: Path, name: str):
    symbols = {symbol: (address, size) for address, size, symbol in perf_profile.elf32_symbols(kernel)}
    assert name in symbols, f"{name} is not a function symbol of the kernel"
    address, size = symbols[name]
    assert 0 < size <= MAX_ROUTINE_BYTES, (
        f"{name} is {size} bytes: a compiled loop, not the string-instruction routine"
    )
    code = code_at(kernel, address, size)
    assert ROUTINES[name] in code, f"{name} has no {ROUTINES[name].hex(' ')} (its rep string instruction)"
