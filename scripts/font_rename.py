#!/usr/bin/env python3
"""
The renamed copy of Wine's Tahoma that the ttfont fixture loads (tests/gdi32/ttfont/f2ktahom.ttf).

The real machine the fixtures are captured on has Microsoft's own Tahoma installed. A fixture asking
GDI for "Tahoma" would get that font, not Wine's, and the capture would describe a font F2K never
reads. So the fixture loads a copy of fonts/tahoma.ttf whose `name` table calls it something else,
privately (AddFontResourceExW with FR_PRIVATE), and asks for it by that name: the capture is then
Windows 2000's font engine on the very bytes F2K reads.

The copy differs from fonts/tahoma.ttf only by its names. In every platform's records:

- name ID 1 (the family), 3 (the unique identifier) and 4 (the full name) read "F2K Tahoma";
- name ID 6 (the PostScript name) reads "F2KTahoma".

Every other name record keeps its string, and every other table its bytes. The `name` table's
strings are stored afresh, in its records' order. The tables keep their order in the file, each
at a four-byte boundary and zero-padded; those after the `name` table move by the change in its
length.
The `name` table's checksum in the table directory, and `head`'s checkSumAdjustment over the whole
file, are recomputed as the OpenType specification's "Table directory" and `head` chapters
describe.

The LGPL lets the font be modified; this script, with fonts/tahoma.sfd, is the copy's source.

Usage: font_rename.py [source.ttf [output.ttf]], by default fonts/tahoma.ttf into
tests/gdi32/ttfont/f2ktahom.ttf. tests/harness/test_fonts.py checks the committed copy is this
script's output.
"""

import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "fonts" / "tahoma.ttf"
OUTPUT = REPO_ROOT / "tests" / "gdi32" / "ttfont" / "f2ktahom.ttf"

# The names the copy carries, by name ID.
FAMILY = "F2K Tahoma"
POSTSCRIPT = "F2KTahoma"
NAMES = {1: FAMILY, 3: FAMILY, 4: FAMILY, 6: POSTSCRIPT}

# The OpenType specification's constant for head.checkSumAdjustment: 0xB1B0AFBA minus the whole
# file's checksum, taken with the adjustment itself zero.
CHECKSUM_MAGIC = 0xB1B0AFBA
# head.checkSumAdjustment's offset in the `head` table.
ADJUSTMENT_OFFSET = 8

PLATFORM_UNICODE = 0
PLATFORM_MACINTOSH = 1
PLATFORM_WINDOWS = 3


def checksum(data: bytes) -> int:
    """The OpenType table checksum: the sum of the big-endian 32-bit words, zero-padded to a
    whole word, modulo 2^32."""
    padded = data + b"\0" * (-len(data) % 4)
    return sum(struct.unpack(f">{len(padded) // 4}I", padded)) & 0xFFFFFFFF


def encode(platform: int, encoding: int, text: str) -> bytes:
    """A name string in its record's encoding: UTF-16BE for the Unicode and Windows platforms,
    Mac Roman for the Macintosh platform's Roman encoding (the names here are ASCII)."""
    if platform in (PLATFORM_UNICODE, PLATFORM_WINDOWS):
        return text.encode("utf-16-be")
    if platform == PLATFORM_MACINTOSH and encoding == 0:
        return text.encode("mac_roman")
    raise ValueError(f"a name record in platform {platform}, encoding {encoding}: not handled")


def tables(data: bytes) -> list[tuple[bytes, int, int, int]]:
    """The table directory's records, in its order: (tag, checksum, offset, length)."""
    version, count = struct.unpack(">IH", data[:6])
    if version != 0x00010000:
        raise ValueError(f"not a TrueType-outline font (sfnt version {version:#010x})")
    return [struct.unpack(">4sIII", data[12 + 16 * i:28 + 16 * i]) for i in range(count)]


def renamed_name_table(table: bytes, names: dict[int, str]) -> bytes:
    """A format 0 `name` table with the records of `names`' IDs replaced, every other record's
    string kept: the records in their order, and their strings stored in that order, each once
    (the source's storage, whose order and slack are FontForge's, is not kept)."""
    form, count, storage = struct.unpack(">HHH", table[:6])
    if form != 0:
        raise ValueError(f"name table format {form}: only format 0 is handled")
    records = []
    for index in range(count):
        platform, encoding, language, name_id, length, offset = struct.unpack(
            ">6H", table[6 + 12 * index:18 + 12 * index])
        string = table[storage + offset:storage + offset + length]
        if name_id in names:
            string = encode(platform, encoding, names[name_id])
        records.append((platform, encoding, language, name_id, string))
    header = struct.pack(">HHH", form, count, 6 + 12 * count)
    directory = b""
    strings = b""
    for platform, encoding, language, name_id, string in records:
        directory += struct.pack(">6H", platform, encoding, language, name_id, len(string), len(strings))
        strings += string
    return header + directory + strings


def rebuilt(data: bytes, names: dict[int, str]) -> bytes:
    """The font with its `name` table's records for `names` replaced: the tables in their file
    order, each four-byte aligned and zero-padded, the directory's offsets, lengths and the
    `name` checksum updated, and head.checkSumAdjustment recomputed."""
    records = tables(data)
    contents = {tag: data[offset:offset + length] for tag, _, offset, length in records}
    sums = {tag: table_sum for tag, table_sum, _, _ in records}
    contents[b"name"] = renamed_name_table(contents[b"name"], names)
    sums[b"name"] = checksum(contents[b"name"])
    head = bytearray(contents[b"head"])
    head[ADJUSTMENT_OFFSET:ADJUSTMENT_OFFSET + 4] = b"\0\0\0\0"
    contents[b"head"] = bytes(head)

    directory_end = 12 + 16 * len(records)
    offsets = {}
    body = b""
    for tag, _, _, _ in sorted(records, key=lambda record: record[2]):
        offsets[tag] = directory_end + len(body)
        body += contents[tag] + b"\0" * (-len(contents[tag]) % 4)
    directory = data[:12] + b"".join(
        struct.pack(">4sIII", tag, sums[tag], offsets[tag], len(contents[tag])) for tag, _, _, _ in records)
    font = bytearray(directory + body)
    adjustment = (CHECKSUM_MAGIC - checksum(bytes(font))) & 0xFFFFFFFF
    at = offsets[b"head"] + ADJUSTMENT_OFFSET
    font[at:at + 4] = struct.pack(">I", adjustment)
    return bytes(font)


def renamed(data: bytes) -> bytes:
    """The fixture's copy of `data`: named "F2K Tahoma" (NAMES)."""
    return rebuilt(data, NAMES)


def main(argv: list[str]) -> int:
    source = Path(argv[1]) if len(argv) > 1 else SOURCE
    output = Path(argv[2]) if len(argv) > 2 else OUTPUT
    output.write_bytes(renamed(source.read_bytes()))
    print(f"{source} -> {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
