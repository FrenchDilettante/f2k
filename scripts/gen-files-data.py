#!/usr/bin/env python3
"""
Generate the files fixture's data tree (tests/kernel32/files/DATA).

Every byte is defined here, so the fixture verifies what it reads
without a golden copy: BIG.BIN's byte i is i % 251, the EXACT files'
bytes follow their own formulas, the text files are fixed strings.
The tree is committed (the real Windows 2000 machine copies it as is);
rerun this only to change it, and keep tests/kernel32/files/files.c in step.

Two attributes git cannot carry are set where the tree is used:
RDONLY.TXT is read-only and HIDDEN.TXT is hidden (tests/kernel32/files/setup.bat
on the real machine, mattrib in the disk build).

Usage:
  gen-files-data.py [<output dir>]   (default: tests/kernel32/files/DATA)
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

FILES = {
    "SMALL.TXT": b"F2K files fixture: small text\r\n",
    "BIG.BIN": bytes(i % 251 for i in range(150000)),
    "EMPTY.DAT": b"",
    "EXACT512.BIN": bytes((i * 7) & 0xFF for i in range(512)),
    "EXACT4K.BIN": bytes((i * 13) & 0xFF for i in range(4096)),
    "RDONLY.TXT": b"read-only\r\n",
    "HIDDEN.TXT": b"hidden\r\n",
    "Long File Name.txt": b"long name\r\n",
    "SUB/DEEP/LEAF.TXT": b"leaf\r\n",
}


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "tests/kernel32/files/DATA"
    for name, data in FILES.items():
        path = out / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    print(f"{out}: {len(FILES)} files")


if __name__ == "__main__":
    main()
