#!/usr/bin/env python3
"""
pe_deps.py - an executable's DLL dependencies as a TOML file, and its icon as an .ico.

Run against any PE image (an SP4 executable copied off the real machine, a corpus fixture's
binary, anything MZ/PE): one TOML per image is written, listing the image's facts and every
module its import tables name - the load-time table and the delay-load table, each in its
table's order - with the names each module is imported by (`#<ordinal>` for an import by
ordinal). A GUI image's icon (RT_GROUP_ICON with its RT_ICON images) is extracted to a real
.ico file with --icons.

The TOMLs are facts about binaries, like tests/core/hello/imports.txt: the binaries themselves
never enter the repository (they are copied off the real machine and kept outside it), only
these fact files are committed. They feed the progress reports scripts/compat.py's data wants
to grow into: which real programs' dependency sets F2K can already serve.

The parser reads PE32 and PE32+ with the standard library only (no pefile); the import walk is
scripts/dump_exports.py's, including the delay-load table's old-form (address, not RVA) thunks.

Usage:
  pe_deps.py <pe>... [--out DIR] [--icons] [--all-icons]

  <pe>...     the images to read; each TOML records the image's file name (never its location)
  --out DIR   where the TOMLs go (default: tests/compat/)
  --icons     also write each image's icon to DIR/icons/<name>.ico; without it the TOML's
              [icon] table is omitted
  --all-icons with --icons, write every RT_GROUP_ICON (further ones as <name>.<n>.ico);
              by default only the first group is written

Example (every SP4 binary copied off the real machine into some local directory):
  python3 f2k/scripts/pe_deps.py --icons /path/to/copies/*.exe
"""
import argparse
import hashlib
import json
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
# Where the TOMLs go by default: tests/compat/, beside the README that documents them.
DEFAULT_OUT = REPO_ROOT / "tests" / "compat"

# The image's directories, by index in the optional header's data directory array.
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_DELAY_IMPORT = 0, 1, 2, 13
# A section holding code (an export there is a function, not a variable).
CODE = 0x2000_0000 | 0x0000_0020
# The resource types this script reads.
RT_ICON, RT_GROUP_ICON = 3, 14

MACHINES = {0x014C: "i386", 0x8664: "amd64", 0x01C0: "arm"}
SUBSYSTEMS = {
    1: "native", 2: "gui", 3: "console", 5: "os2", 7: "posix", 9: "windows-ce",
}


class PeError(ValueError):
    pass


class Image:
    """A PE image's headers, sections and directories, read off its file."""

    def __init__(self, data: bytes):
        self.data = data
        if data[:2] != b"MZ":
            raise PeError("not an MZ executable")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe:pe + 4] != b"PE\0\0":
            raise PeError("no PE header")
        self.machine, sections, self.timestamp = struct.unpack_from("<HHI", data, pe + 4)
        optional = pe + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic == 0x10B:  # PE32
            self.base = struct.unpack_from("<I", data, optional + 28)[0]
            directories_at = optional + 96
        elif magic == 0x20B:  # PE32+
            self.base = struct.unpack_from("<Q", data, optional + 24)[0]
            directories_at = optional + 112
        else:
            raise PeError(f"optional header magic {magic:#x} is neither PE32 nor PE32+")
        self.subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        self.directories = [
            struct.unpack_from("<II", data, directories_at + 8 * i) for i in range(16)
        ]
        self.sections = []
        for i in range(sections):
            _, virtual_size, rva, raw_size, raw, _, _, _, _, flags = struct.unpack_from(
                "<8sIIIIIIHHI", data, optional + optional_size + 40 * i)
            self.sections.append((rva, max(virtual_size, raw_size), raw, flags))

    def offset(self, rva: int) -> int:
        for rva0, size, raw, _ in self.sections:
            if rva0 <= rva < rva0 + size:
                return rva - rva0 + raw
        raise PeError(f"RVA {rva:#x} is in no section")

    def string(self, rva: int) -> str:
        start = self.offset(rva)
        return self.data[start:self.data.index(b"\0", start)].decode("ascii")

    def word(self, rva: int) -> int:
        return struct.unpack_from("<I", self.data, self.offset(rva))[0]


def thunks(image: Image, rva: int, shift: int = 0) -> list[str]:
    """The names a zero-terminated thunk array imports: `name`, or `#ordinal` for an import by
    ordinal (the top bit set). A name's thunk is its IMAGE_IMPORT_BY_NAME's RVA, `shift` more for
    an address (an old-form delay-load table's)."""
    names = []
    while (thunk := image.word(rva)) != 0:
        names.append(f"#{thunk & 0xFFFF}" if thunk & 0x8000_0000 else image.string(thunk - shift + 2))
        rva += 4
    return names


def imports(image: Image) -> list[tuple[str, bool, list[str]]]:
    """The import tables: [(module, delay-loaded, [import])], the load-time table's modules first,
    then the delay-load table's, each in its table's order."""
    modules = []
    rva, _ = image.directories[DIR_IMPORT]
    while rva:
        # IMAGE_IMPORT_DESCRIPTOR: the names' thunks, the bind timestamp, the forwarder chain,
        # the module's name, the IAT; a zero one ends the table.
        names, bound, _, name, iat = struct.unpack_from("<IIIII", image.data, image.offset(rva))
        if not name:
            break
        if not names and bound:
            raise PeError(f"{image.string(name)}: bound, with no import names to read")
        modules.append((image.string(name), False, thunks(image, names or iat)))
        rva += 20
    rva, _ = image.directories[DIR_DELAY_IMPORT]
    while rva:
        # ImgDelayDescr: attributes, the module's name, its HMODULE's place, the IAT, the names'
        # thunks, ...; a zero one ends the table. Without dlattrRva (bit 0, the old form, as
        # Visual C++ 6 links it) the fields are addresses, not RVAs.
        attributes, name, _, _, names = struct.unpack_from("<IIIII", image.data, image.offset(rva))
        if not name:
            break
        shift = 0 if attributes & 1 else image.base
        modules.append((image.string(name - shift), True, thunks(image, names - shift, shift)))
        rva += 32
    return modules


def resource_entries(image: Image, directory: int, root: int):
    """A resource directory's entries: (the raw name word, offset from the resource root, is a
    subdirectory). The name word's high bit marks a string name; see [`resource_name`]."""
    named, ids = struct.unpack_from("<HH", image.data, directory + 12)
    for i in range(named + ids):
        name, at = struct.unpack_from("<II", image.data, directory + 16 + 8 * i)
        yield name, root + (at & 0x7FFF_FFFF), bool(at & 0x8000_0000)


def resource_name(image: Image, name_word: int, root: int) -> int | str:
    """A resource entry's name: its id, or its string (a named entry's word is the string's RVA
    from the resource root) - numeric strings as the integers they name, as group-icon entries
    reference their RT_ICON images by id."""
    if not name_word & 0x8000_0000:
        return name_word
    at = root + (name_word & 0x7FFF_FFFF)
    length = struct.unpack_from("<H", image.data, at)[0]
    text = image.data[at + 2:at + 2 + 2 * length].decode("utf-16-le")
    return int(text) if text.isdecimal() else text


def resource_data(image: Image, rva: int, size: int, want_type: int) -> dict[int | str, bytes]:
    """The data blobs of the resources of one type, by their name: type -> name -> language
    -> IMAGE_RESOURCE_DATA_ENTRY. Only the first language of each name is taken."""
    found: dict[int | str, bytes] = {}
    root = image.offset(rva)
    type_dir = next((at for name, at, sub in resource_entries(image, root, root)
                     if name == want_type and sub), None)
    if type_dir is None:
        return found
    for name_word, name_dir, _ in resource_entries(image, type_dir, root):
        key = resource_name(image, name_word, root)
        # The name directory's entries are the languages, leaves pointing at the data entry.
        data_at = next((at for _, at, sub in resource_entries(image, name_dir, root) if not sub),
                       None)
        if data_at is None:
            continue
        data_rva, data_size = struct.unpack_from("<II", image.data, data_at)
        found[key] = image.data[image.offset(data_rva):image.offset(data_rva) + data_size]
    return found


def extract_icons(image: Image) -> list[bytes]:
    """Each RT_GROUP_ICON resource as a complete .ico file's bytes: the group's directory rewritten
    with the RT_ICON images' file offsets, then the images. Empty when the image has no icon."""
    rva, size = image.directories[DIR_RESOURCE]
    if not rva:
        return []
    icons = resource_data(image, rva, size, RT_ICON)
    groups = resource_data(image, rva, size, RT_GROUP_ICON)
    files = []
    for group in groups.values():
        reserved, kind, count = struct.unpack_from("<HHH", group, 0)
        if reserved != 0 or kind != 1 or count == 0:
            continue
        entries, blobs = [], []
        for i in range(count):
            width, height, colors, _, planes, bitcount, nbytes, icon_id = struct.unpack_from(
                "<BBBBHHIH", group, 6 + 14 * i)
            blob = icons.get(icon_id)
            if blob is None or len(blob) < nbytes:
                break
            entries.append((width, height, colors, planes, bitcount, blob[:nbytes]))
            blobs.append(blob[:nbytes])
        if not entries:
            continue
        # An .ico: ICONDIR (type 1), then 16-byte entries whose last word is the image's file
        # offset, then the images themselves.
        header = struct.pack("<HHH", 0, 1, len(entries))
        offset = 6 + 16 * len(entries)
        directory = b""
        for width, height, colors, planes, bitcount, blob in entries:
            directory += struct.pack(
                "<BBBBHHII", width, height, colors, 0, planes, bitcount, len(blob), offset)
            offset += len(blob)
        files.append(header + directory + b"".join(blobs))
    return files


def toml_string(value: str) -> str:
    # JSON's basic-string escaping is valid TOML.
    return json.dumps(value)


def write_toml(path: Path, source: str, image: Image, module_imports, icons: list[tuple[Path, int]]):
    linked = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(image.timestamp))
    sha256 = hashlib.sha256(image.data).hexdigest()
    lines = [
        f"# {Path(source).name}: its DLL dependencies, written by scripts/pe_deps.py.",
        f"# Copied off the real machine; sha256 {sha256[:16]}..., linked {linked}.",
        "# Regenerate: python3 f2k/scripts/pe_deps.py <image> [--icons]",
        "",
        "[image]",
        f"file = {toml_string(Path(source).name)}",
        f"kind = {toml_string('dll' if source.lower().endswith('.dll') else 'exe')}",
        f"machine = {toml_string(MACHINES.get(image.machine, hex(image.machine)))}",
        f"subsystem = {toml_string(SUBSYSTEMS.get(image.subsystem, str(image.subsystem)))}",
        f"base = {toml_string(f'0x{image.base:08X}')}",
        f"size_bytes = {len(image.data)}",
        f"link_timestamp = {toml_string(linked)}",
        f"sha256 = {toml_string(sha256)}",
        "",
    ]
    if icons:
        lines += [
            "[icon]",
            "files = [" + ", ".join(toml_string(f"icons/{icon.name}") for icon, _ in icons) + "]",
            f"images = {sum(count for _, count in icons)}",
            "",
        ]
    for module, delay, names in module_imports:
        lines.append("[[imports]]")
        lines.append(f"dll = {toml_string(module)}")
        lines.append(f"delay = {'true' if delay else 'false'}")
        lines.append("names = [" + ", ".join(toml_string(n) for n in names) + "]")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("pe", nargs="+", type=Path, help="the PE images to read")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="where the TOMLs go (default: tests/compat/)")
    parser.add_argument("--icons", action="store_true",
                        help="also extract each image's icon to <out>/icons/<name>.ico")
    parser.add_argument("--all-icons", action="store_true",
                        help="with --icons, every group icon, not only the first")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    icons_dir = args.out / "icons"
    written, failed = [], []
    for pe in args.pe:
        source = pe.name
        try:
            data = pe.read_bytes()
            image = Image(data)
            module_imports = imports(image)
        except (OSError, PeError, struct.error, UnicodeDecodeError, ValueError) as error:
            print(f"{pe}: skipped ({error})", file=sys.stderr)
            failed.append(pe)
            continue
        icons = []
        if args.icons:
            icons_dir.mkdir(exist_ok=True)
            blobs = extract_icons(image)
            if not args.all_icons:
                blobs = blobs[:1]
            for i, blob in enumerate(blobs):
                icon = icons_dir / f"{pe.stem}.ico" if i == 0 else icons_dir / f"{pe.stem}.{i}.ico"
                icon.write_bytes(blob)
                icons.append((icon, struct.unpack_from("<H", blob, 4)[0]))
        toml = args.out / f"{pe.stem}.toml"
        write_toml(toml, source, image, module_imports, icons)
        n_delay = sum(1 for _, delay, _ in module_imports if delay)
        print(f"{pe.name}: {len(module_imports)} modules "
              f"({n_delay} delay-loaded), {sum(len(n) for _, _, n in module_imports)} imports, "
              f"{len(icons)} icon group(s) -> {toml.name}")
        written.append(toml)
    if not written:
        print("no images read", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
