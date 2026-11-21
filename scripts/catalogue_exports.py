#!/usr/bin/env python3
"""
Catalogue a module's real export table into its spec: fold userland/<dll>/exports-<version>.txt or
kernel/<module>-exports-<version>.txt (written by scripts/dump_exports.py from the platform's own
module) into the module's spec: userland/<dll>/exports.toml, or, for the kernel's modules, the spec
at the kernel root beside the dump (kernel/exports.toml for ntoskrnl, kernel/hal_exports.toml for
hal).

Each module's directory holds one dump (folding several versions of a module together is not
designed yet); its module name and file version are recorded as the dump gives them, in the
heading of the spec's catalogued section. For each module:

- every export of the spec must be in the dump's table (an F2K-internal one excepted), and a
  forwarder exactly where the DLL forwards, to the same target: otherwise nothing is written;
- each implemented export gets the table's ordinal (`ordinal`), a system service its Zw alias's
  too (`zw_ordinal`);
- every other export of the table is appended as a catalogued record (name, ordinal, `data` for a
  variable, a note where the DLL forwards it), in ordinal order, under the spec's closing
  section; a spec that does not exist yet is created with them alone.

A rerun adds only what is missing. Once folded, the dumps go.

Usage:
  catalogue_exports.py [<module>...]     (default: every module holding a dump: userland/<dll>/,
                                         kernel/<module>-exports-<version>.txt)
"""
import argparse
import re
import sys
import tomllib
from pathlib import Path

from specs import toml_string, zw_alias

REPO_ROOT = Path(__file__).resolve().parent.parent
# The kernel modules' specs sit at the kernel root, beside their dumps (kernel/<module>-*-<ver>.txt).
KERNEL_SPECS = {"ntoskrnl": REPO_ROOT / "kernel" / "exports.toml",
                "hal": REPO_ROOT / "kernel" / "hal_exports.toml"}
# The catalogued section's heading (the dump's DLL name and version follow it).
CATALOGUED_HEADING = "# --- not implemented yet: the rest of "


def read_dump(path: Path):
    """A dump: ("<DLL name> <file version>", {name: (ordinal, forward target or None, data)}).
    An export the DLL gives only an ordinal is keyed by its "#<ordinal>" name, so the spec can
    hold it as a catalogued record (and an import by ordinal can resolve against it)."""
    lines = path.read_text().splitlines()
    source = re.match(r"# (\S+ \S+):", lines[0]).group(1)
    table = {}
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split()
        ordinal, name = int(fields[0]), fields[1]
        if name == "-":
            name = f"#{ordinal}"
        forward = fields[3] if len(fields) > 3 and fields[2] == "->" else None
        table[name] = (ordinal, forward, fields[2:] == ["data"])
    return source, table


def pending_dumps():
    """Every pending export dump: {module name: the dump file}. Userland dumps sit in the DLL's
    directory (userland/<dll>/exports-<version>.txt); the kernel modules' at the kernel root,
    beside their specs (kernel/<module>-exports-<version>.txt). One dump per module."""
    found = {}
    paths = sorted((REPO_ROOT / "userland").glob("*/exports-*.txt")) + \
        sorted((REPO_ROOT / "kernel").glob("*-exports-*.txt"))
    for path in paths:
        module = path.parent.name if path.parent != REPO_ROOT / "kernel" \
            else path.name.split("-exports-", 1)[0]
        if module in found:
            sys.exit(f"{module}: {found[module].name} and {path.name}: one dump per module (folding "
                     f"several versions of a module together is not designed yet)")
        found[module] = path
    return found


def spec_of(module, dump: Path) -> Path:
    """The module's spec: userland/<dll>/exports.toml, or the kernel root's for the kernel
    modules."""
    if dump.parent == REPO_ROOT / "kernel":
        spec = KERNEL_SPECS.get(module)
        if spec is None:
            sys.exit(f"{module}: no spec at the kernel root for it (kernel/exports.toml, "
                     f"kernel/hal_exports.toml)")
        return spec
    return dump.parent / "exports.toml"


def check(dll, spec, table):
    """The spec against the platform's table; the problems found."""
    problems = []
    for export in spec.get("export", []):
        name = export["name"]
        if export.get("internal"):
            continue
        if name not in table:
            problems.append(f"{dll}.{name}: not in the dump's table")
            continue
        ordinal, forward, data = table[name]
        ours = export.get("impl", {}).get("forward")
        if "impl" in export and ours != forward:
            problems.append(f"{dll}.{name}: the DLL "
                            + (f"forwards it to {forward}" if forward else "exports its own code")
                            + (f", F2K forwards it to {ours}" if ours else ", F2K's is its own code"))
        if export.get("ordinal") not in (None, ordinal):
            problems.append(f"{dll}.{name}: ordinal {export['ordinal']}, the dump's is {ordinal}")
        if "syscall" in export.get("impl", {}) and zw_alias(name) not in table:
            problems.append(f"{dll}.{name}: the DLL has no {zw_alias(name)}")
    return problems


def fold(text, spec, source, table):
    """The spec's text with the platform's ordinals added and the rest of its table appended."""
    declared = {export["name"]: export for export in spec.get("export", [])}
    aliases = {zw_alias(name) for name, export in declared.items() if "syscall" in export.get("impl", {})}
    # The ordinals, after each implemented record's impl line.
    out, current = [], None
    for line in text.split("\n"):
        out.append(line)
        match = re.match(r'name = "(\w+)"$', line)
        if match:
            current = declared.get(match.group(1))
        if current is not None and line.startswith("impl = ") and not current.get("internal"):
            name = current["name"]
            if "ordinal" not in current:
                out.append(f"ordinal = {table[name][0]}")
            if "syscall" in current["impl"] and "zw_ordinal" not in current:
                out.append(f"zw_ordinal = {table[zw_alias(name)][0]}")
    text = "\n".join(out)
    missing = sorted((entry[0], name, entry) for name, entry in table.items()
                     if name not in declared and name not in aliases)
    if not missing:
        return text
    records = []
    for ordinal, name, (_, forward, data) in missing:
        record = f'\n[[export]]\nname = "{name}"\nordinal = {ordinal}\n'
        if data:
            record += "data = true\n"
        if forward:
            record += f"note = {toml_string(f'forwarded to {forward}')}\n"
        records.append(record)
    if CATALOGUED_HEADING not in text:
        heading = f"{CATALOGUED_HEADING}{source}'s export table, by ordinal "
        text = text.rstrip("\n") + "\n\n" + heading.ljust(99, "-") + "\n"
    return text.rstrip("\n") + "\n" + "".join(records)


def new_spec(source):
    name = source.split()[0]
    return (
        f"# {name}'s exports: the one source every list of them derives from (the format is\n"
        f"# kernel32's, documented in userland/kernel32/exports.toml).\n#\n"
        f"# None is implemented yet: each record is catalogued from {source}'s export table\n"
        f"# (scripts/catalogue_exports.py): its name and ordinal. Implementing one gives it its group,\n"
        f"# prototype and implementation.\n"
    )


def main():
    parser = argparse.ArgumentParser(description="fold real export tables into the specs")
    parser.add_argument("modules", nargs="*")
    args = parser.parse_args()
    dumps = pending_dumps()
    modules = args.modules or sorted(dumps)
    plans, problems = [], []
    for module in dict.fromkeys(modules):
        if module not in dumps:
            sys.exit(f"{module}: no export dump for it (scripts/dump_exports.py)")
        source, table = read_dump(dumps[module])
        path = spec_of(module, dumps[module])
        if path.is_file():
            text = path.read_text()
            spec = tomllib.loads(text)
        else:
            text, spec = new_spec(source), {}
        problems += check(module, spec, table)
        plans.append((path, text, spec, source, table))
    if problems:
        sys.exit("Not catalogued: the specs disagree with their dumps:\n  " + "\n  ".join(problems))
    for path, text, spec, source, table in plans:
        folded = fold(text, spec, source, table)
        tomllib.loads(folded)
        path.write_text(folded)
        print(f"{path.relative_to(REPO_ROOT)}: {len(table)} exports in {source}'s table")


if __name__ == "__main__":
    main()
