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

The PE reader is scripts/pe.py's (the standard library only, no pefile), its import walk
including the delay-load table's old-form (address, not RVA) thunks.

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
import struct
import sys
import time
from pathlib import Path

from pe import Image, PeError, imports, resource_data
from specs import toml_string

REPO_ROOT = Path(__file__).resolve().parent.parent
# Where the TOMLs go by default: tests/compat/, beside the README that documents them.
DEFAULT_OUT = REPO_ROOT / "tests" / "compat"

# The resource types this script reads.
RT_ICON, RT_GROUP_ICON = 3, 14

MACHINES = {0x014C: "i386", 0x8664: "amd64", 0x01C0: "arm"}
SUBSYSTEMS = {
    1: "native", 2: "gui", 3: "console", 5: "os2", 7: "posix", 9: "windows-ce",
}


def extract_icons(image: Image) -> list[bytes]:
    """Each RT_GROUP_ICON resource as a complete .ico file's bytes: the group's directory rewritten
    with the RT_ICON images' file offsets, then the images. Empty when the image has no icon."""
    icons = resource_data(image, RT_ICON)
    groups = resource_data(image, RT_GROUP_ICON)
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
