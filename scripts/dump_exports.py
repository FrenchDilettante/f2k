#!/usr/bin/env python3
"""
Dump a real DLL's export table: the facts its userland/<dll>/exports.toml is catalogued from.

Each DLL given (copied off a real machine: the binaries themselves never enter the repository)
writes userland/<dll>/exports-<file version>.txt, one line per export, in ordinal order:

  <ordinal> <name>                 a function
  <ordinal> <name> data            an export in a section without code (a variable)
  <ordinal> <name> -> <target>     forwarded to another module's export (MODULE.Export)
  <ordinal> -                      exported by ordinal only

after a provenance header: the file version (its version resource), the image's link timestamp and
the file's SHA-256. The dumps are a step on the way, not a record: once folded into the spec, they
go.

The parser reads PE32 with the standard library only (no pefile).

Usage:
  dump_exports.py <dll>... [--out DIR]   (DIR/<dll>/exports-<version>.txt; DIR defaults to userland)
"""
import argparse
import hashlib
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_CNT_CODE: a section holding code.
CODE = 0x2000_0000 | 0x0000_0020
# VS_FIXEDFILEINFO's signature, at the head of the version resource's value.
FIXED_FILE_INFO = struct.pack("<I", 0xFEEF04BD)


class Image:
    """A PE32 image's sections and directories, read off its file."""

    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not an MZ executable")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("no PE header")
        _, sections, self.timestamp, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
        optional = pe + 24
        if struct.unpack_from("<H", data, optional)[0] != 0x10B:
            raise ValueError("not PE32")
        self.directories = [struct.unpack_from("<II", data, optional + 96 + 8 * i) for i in range(16)]
        self.sections = []
        for i in range(sections):
            _, virtual_size, rva, raw_size, raw, _, _, _, _, flags = struct.unpack_from(
                "<8sIIIIIIHHI", data, optional + optional_size + 40 * i)
            self.sections.append((rva, max(virtual_size, raw_size), raw, flags))

    def section_of(self, rva: int):
        return next((s for s in self.sections if s[0] <= rva < s[0] + s[1]), None)

    def offset(self, rva: int) -> int:
        section = self.section_of(rva)
        if section is None:
            raise ValueError(f"RVA {rva:#x} is in no section")
        return rva - section[0] + section[2]

    def string(self, rva: int) -> str:
        start = self.offset(rva)
        return self.data[start:self.data.index(b"\0", start)].decode("ascii")


def exports(image: Image):
    """The export table: (dll name, [(ordinal, name or None, forward target or None, data)])."""
    rva, size = image.directories[0]
    if not rva:
        raise ValueError("no export table")
    at = image.offset(rva)
    _, _, _, _, name, base, functions, names, function_rva, name_rva, ordinal_rva = struct.unpack_from(
        "<IIHHIIIIIII", image.data, at)
    named = {}
    for i in range(names):
        pointer = struct.unpack_from("<I", image.data, image.offset(name_rva) + 4 * i)[0]
        index = struct.unpack_from("<H", image.data, image.offset(ordinal_rva) + 2 * i)[0]
        named[index] = image.string(pointer)
    entries = []
    for index in range(functions):
        target = struct.unpack_from("<I", image.data, image.offset(function_rva) + 4 * index)[0]
        if not target:
            continue  # a hole in the ordinal range
        forward = image.string(target) if rva <= target < rva + size else None
        section = None if forward else image.section_of(target)
        data = forward is None and section is not None and not section[3] & CODE
        entries.append((base + index, named.get(index), forward, data))
    return image.string(name), entries


def file_version(image: Image) -> str | None:
    """The file version of the version resource (RT_VERSION's VS_FIXEDFILEINFO), None without
    one."""
    rva, _ = image.directories[2]
    if not rva:
        return None
    root = image.offset(rva)

    def entries(directory: int):
        """A resource directory's entries: (id or None for a named one, offset, is a subdirectory)."""
        named, ids = struct.unpack_from("<HH", image.data, directory + 12)
        for i in range(named + ids):
            name, at = struct.unpack_from("<II", image.data, directory + 16 + 8 * i)
            yield (None if name & 0x8000_0000 else name), root + (at & 0x7FFF_FFFF), bool(at & 0x8000_0000)

    # The type (RT_VERSION, 16), then its first name and first language: the data entry.
    found = next((at for id, at, sub in entries(root) if id == 16 and sub), None)
    for _ in range(2):
        if found is None:
            return None
        found = next((at for _, at, sub in entries(found)), None)
    data_rva, size = struct.unpack_from("<II", image.data, found)
    start = image.offset(data_rva)
    # VS_VERSIONINFO: its header and key, then VS_FIXEDFILEINFO (its signature first).
    at = image.data.find(FIXED_FILE_INFO, start, start + size)
    if at < 0:
        return None
    ms, ls = struct.unpack_from("<II", image.data, at + 8)
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def dump(path: Path, out: Path | None) -> Path:
    data = path.read_bytes()
    image = Image(data)
    name, entries = exports(image)
    version = file_version(image) or "unversioned"
    dll = name.lower().removesuffix(".dll")
    target = (out or REPO_ROOT / "userland") / dll / f"exports-{version}.txt"
    lines = [
        f"# {name} {version}: its export table, dumped by scripts/dump_exports.py",
        f"# linked {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(image.timestamp))} UTC, "
        f"sha256 {hashlib.sha256(data).hexdigest()}",
        f"# {len(entries)} exports: <ordinal> <name> [data | -> forward]",
    ]
    for ordinal, export, forward, is_data in entries:
        line = f"{ordinal} {export or '-'}"
        if forward:
            line += f" -> {forward}"
        elif is_data:
            line += " data"
        lines.append(line)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(lines) + "\n")
    return target


def main():
    parser = argparse.ArgumentParser(description="dump real DLLs' export tables")
    parser.add_argument("dlls", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, help="the directory to write <dll>/ into (default userland/)")
    args = parser.parse_args()
    for path in args.dlls:
        try:
            print(dump(path, args.out))
        except (ValueError, OSError, struct.error) as error:
            sys.exit(f"{path}: {error}")


if __name__ == "__main__":
    main()
