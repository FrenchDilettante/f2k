#!/usr/bin/env python3
"""
Dump a real module's export and import tables: the facts its spec (userland/<dll>/exports.toml,
kernel/exports.toml, kernel/hal_exports.toml) is catalogued from, and the modules it calls into.

Each module given (copied off a real machine: the binaries themselves never enter the
repository) writes exports-<file version>.txt, one line per export, in ordinal order — under
userland/<name>/, or, for a kernel-mode image (native subsystem: ntoskrnl.exe, hal.dll, a .sys),
at the kernel root as <name>-exports-<file version>.txt, beside its spec:

  <ordinal> <name>                 a function
  <ordinal> <name> data            an export in a section without code (a variable)
  <ordinal> <name> -> <target>     forwarded to another module's export (MODULE.Export)
  <ordinal> -                      exported by ordinal only

and imports-<file version>.txt beside it, its import table: each module it imports from, in
the table's order and spelled as the image spells it, then that module's imports, one per line:

  [<module>]                       a module the loader binds at load time
  [<module>] delay                 a delay-loaded module (bound on its first call)
  <name>                           an import by name
  #<ordinal>                       an import by ordinal

Each file starts with a provenance header: the file version (its version resource), the image's
link timestamp and the file's SHA-256. The export dumps are a step on the way, not a record: once
folded into the spec, they go.

The PE reader is scripts/pe.py's (the standard library only, no pefile); a PE32+ image is refused.

Usage:
  dump_exports.py <module>... [--out DIR]   (DIR/<name>/{exports,imports}-<version>.txt; without --out,
                                            userland/<name>/ for a user-mode image, the kernel root
                                            as <name>-{exports,imports}-<version>.txt for a native one)
"""
import argparse
import hashlib
import struct
import sys
import time
from pathlib import Path

from pe import DIR_RESOURCE, Image, PeError, exports, imports, resource_entries

REPO_ROOT = Path(__file__).resolve().parent.parent
# VS_FIXEDFILEINFO's signature, at the head of the version resource's value.
FIXED_FILE_INFO = struct.pack("<I", 0xFEEF04BD)


def file_version(image: Image) -> str | None:
    """The file version of the version resource (RT_VERSION's VS_FIXEDFILEINFO), None without
    one."""
    rva, _ = image.directories[DIR_RESOURCE]
    if not rva:
        return None
    root = image.offset(rva)
    # The type (RT_VERSION, 16, an id: a named entry's word has its high bit set), then its first
    # name and first language: the data entry.
    found = next((at for name, at, sub in resource_entries(image, root, root) if name == 16 and sub),
                 None)
    for _ in range(2):
        if found is None:
            return None
        found = next((at for _, at, sub in resource_entries(image, found, root)), None)
    data_rva, size = struct.unpack_from("<II", image.data, found)
    start = image.offset(data_rva)
    # VS_VERSIONINFO: its header and key, then VS_FIXEDFILEINFO (its signature first).
    at = image.data.find(FIXED_FILE_INFO, start, start + size)
    if at < 0:
        return None
    ms, ls = struct.unpack_from("<II", image.data, at + 8)
    return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"


def dump(path: Path, out: Path | None) -> list[Path]:
    data = path.read_bytes()
    image = Image(data)
    if image.plus:
        raise PeError("not PE32")
    name, entries = exports(image)
    version = file_version(image) or "unversioned"
    stem = name.lower()
    for ext in (".dll", ".exe", ".sys"):
        stem = stem.removesuffix(ext)
    if out is not None:
        directory, prefix = out / stem, ""
    elif image.subsystem == 1:
        # A kernel-mode image (ntoskrnl.exe, hal.dll, a .sys): its dumps sit at the kernel root,
        # beside its spec (kernel/exports.toml, kernel/hal_exports.toml), not in a directory of
        # their own.
        directory, prefix = REPO_ROOT / "kernel", f"{stem}-"
    else:
        directory, prefix = REPO_ROOT / "userland" / stem, ""
    provenance = (
        f"# linked {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(image.timestamp))} UTC, "
        f"sha256 {hashlib.sha256(data).hexdigest()}"
    )
    lines = [
        f"# {name} {version}: its export table, dumped by scripts/dump_exports.py",
        provenance,
        f"# {len(entries)} exports: <ordinal> <name> [data | -> forward]",
    ]
    for ordinal, export, forward, is_data in entries:
        line = f"{ordinal} {export or '-'}"
        if forward:
            line += f" -> {forward}"
        elif is_data:
            line += " data"
        lines.append(line)
    modules = imports(image)
    import_lines = [
        f"# {name} {version}: its import table, dumped by scripts/dump_exports.py",
        provenance,
        f"# {len(modules)} modules, {sum(len(names) for _, _, names in modules)} imports:"
        " [<module>] [delay], then <name> | #<ordinal>",
    ]
    for module, delayed, names in modules:
        import_lines.append(f"[{module}]" + (" delay" if delayed else ""))
        import_lines.extend(names)
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for kind, text in (("exports", lines), ("imports", import_lines)):
        target = directory / f"{prefix}{kind}-{version}.txt"
        target.write_text("\n".join(text) + "\n")
        written.append(target)
    return written


def main():
    parser = argparse.ArgumentParser(description="dump real DLLs' export and import tables")
    parser.add_argument("dlls", nargs="+", type=Path)
    parser.add_argument("--out", type=Path,
                        help="the directory to write <name>/ into (default: userland/<name>/, the kernel root for a native image)")
    args = parser.parse_args()
    for path in args.dlls:
        try:
            for target in dump(path, args.out):
                print(target)
        except (ValueError, OSError, struct.error) as error:
            sys.exit(f"{path}: {error}")


if __name__ == "__main__":
    main()
