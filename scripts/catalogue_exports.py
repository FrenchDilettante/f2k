#!/usr/bin/env python3
"""
Catalogue a DLL's real export table into its spec: fold userland/<dll>/exports-<version>.txt (written
by scripts/dump_exports.py from the platform's own DLL) into userland/<dll>/exports.toml.

Each DLL's directory holds one dump (folding several versions of a DLL together is not designed
yet); its DLL name and file version are recorded as the dump gives them, in the heading of the
spec's catalogued section. For each DLL:

- every export of the spec must be in the dump's table (an F2K-internal one excepted), and a
  forwarder exactly where the DLL forwards, to the same target: otherwise nothing is written;
- each implemented export gets the table's ordinal (`ordinal`), a system service its Zw alias's
  too (`zw_ordinal`);
- every other export of the table is appended as a catalogued record (name, ordinal, `data` for a
  variable, a note where the DLL forwards it), in ordinal order, under the spec's closing
  section; a spec that does not exist yet is created with them alone.

A rerun adds only what is missing. Once folded, the dumps go.

Usage:
  catalogue_exports.py [<dll>...]     (default: every userland/<dll>/ holding a dump)
"""
import argparse
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
USERLAND = REPO_ROOT / "userland"
# The catalogued section's heading (the dump's DLL name and version follow it).
CATALOGUED_HEADING = "# --- not implemented yet: the rest of "


def read_dump(path: Path):
    """A dump: ("<DLL name> <file version>", {name: (ordinal, forward target or None, data)})."""
    lines = path.read_text().splitlines()
    source = re.match(r"# (\S+ \S+):", lines[0]).group(1)
    table = {}
    for line in lines:
        if line.startswith("#") or not line.strip():
            continue
        fields = line.split()
        ordinal, name = int(fields[0]), fields[1]
        if name == "-":
            sys.exit(f"{path}: ordinal {ordinal} has no name: the specs catalogue named exports only")
        forward = fields[3] if len(fields) > 3 and fields[2] == "->" else None
        table[name] = (ordinal, forward, fields[2:] == ["data"])
    return source, table


def the_dump(directory: Path):
    """The directory's dump: (source, table)."""
    dumps = sorted(directory.glob("exports-*.txt"))
    if len(dumps) != 1:
        sys.exit(f"{directory}: {len(dumps)} dumps; one per DLL (folding several versions of a DLL "
                 f"together is not designed yet)")
    return read_dump(dumps[0])


def zw_alias(name: str) -> str:
    return "Zw" + name[2:]


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


def toml_string(text: str) -> str:
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
    parser.add_argument("dlls", nargs="*")
    args = parser.parse_args()
    dlls = args.dlls or sorted(p.parent.name for p in USERLAND.glob("*/exports-*.txt"))
    plans, problems = [], []
    for dll in dict.fromkeys(dlls):
        directory = USERLAND / dll
        source, table = the_dump(directory)
        path = directory / "exports.toml"
        if path.is_file():
            text = path.read_text()
            spec = tomllib.loads(text)
        else:
            text, spec = new_spec(source), {}
        problems += check(dll, spec, table)
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
