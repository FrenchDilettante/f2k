# compat — real binaries' dependency sets

One TOML per PE image copied off the real Windows 2000 machine (SP4).
The binaries themselves never enter the repository; only these fact files are committed, like `tests/core/hello/imports.txt`.
Each TOML records the image's facts (file name, kind, machine, subsystem, base, size, link timestamp, sha256) and every module its import tables name — load-time and delay-loaded — with the names each module is imported by.
A GUI image's icon is extracted beside them, in `icons/`.

Written by `scripts/pe_deps.py` (stdlib only, PE32 and PE32+); regenerate after copying more binaries off the real machine:

```text
python3 f2k/scripts/pe_deps.py --icons /path/to/the/copies/*.exe
```

or against any single executable:

```text
python3 f2k/scripts/pe_deps.py --icons path/to/program.exe
```

(`--all-icons` writes every RT_GROUP_ICON, not only the first; `--out` defaults to this directory.)

A DLL tracked here is a compatibility target: F2K runs the real DLL, copied off the machine, instead of building its own.
`scripts/compat.py` leaves its spec out of the treemap and shows it as a card among the programs; a program importing from it links to that card, and those imports stay out of the program's coverage.
`mfc42u.toml` is the one so far, converted from MFC42u.DLL 6.0.9586.0's import-table dump (no copy of the binary was at hand: regenerate it with `pe_deps.py` when there is).

Purpose: the dependency sets are the input to progress reports — which real programs' import closures F2K can already serve, module by module, name by name — alongside `scripts/compat.py`'s export-coverage report (`make compat-report`).
Cross-check: `cmd.toml` matches the measured cmd.exe import closure exactly (104 kernel32, 70 msvcrt, 11 advapi32, 4 user32 load-time; SHELL32/MPR delay-loaded).
