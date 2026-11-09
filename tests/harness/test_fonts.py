"""The ttfont fixture's renamed copy of Wine's Tahoma (scripts/font_rename.py): the committed copy
is the script's output from fonts/tahoma.ttf, and differs from it only by its names."""

import importlib.util
import struct

import f2kboot

SCRIPT = f2kboot.REPO_ROOT / "scripts" / "font_rename.py"


def font_rename():
    spec = importlib.util.spec_from_file_location("font_rename", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def name_records(module, data: bytes) -> dict[tuple[int, int, int, int], bytes]:
    """A font's name records' strings, by (platform, encoding, language, name ID)."""
    offset, length = next((offset, length) for tag, _, offset, length in module.tables(data) if tag == b"name")
    table = data[offset:offset + length]
    _, count, storage = struct.unpack(">HHH", table[:6])
    records = {}
    for index in range(count):
        platform, encoding, language, name_id, size, at = struct.unpack(">6H", table[6 + 12 * index:18 + 12 * index])
        records[platform, encoding, language, name_id] = table[storage + at:storage + at + size]
    return records


def test_the_committed_copy_is_the_scripts_output():
    """tests/gdi32/ttfont/f2ktahom.ttf is what `uv run scripts/font_rename.py` writes."""
    module = font_rename()
    assert module.OUTPUT.read_bytes() == module.renamed(module.SOURCE.read_bytes()), (
        f"{module.OUTPUT.name} is stale: rerun scripts/font_rename.py"
    )


def test_the_copy_differs_only_by_its_names():
    """Every table but `name` keeps its bytes (head but its checksum adjustment), every name record
    outside IDs 1, 3, 4 and 6 keeps its string, and those read the new names in each platform's
    encoding."""
    module = font_rename()
    source = module.SOURCE.read_bytes()
    copy = module.renamed(source)
    before = {tag: source[offset:offset + length] for tag, _, offset, length in module.tables(source)}
    after = {tag: copy[offset:offset + length] for tag, _, offset, length in module.tables(copy)}
    assert [tag for tag, *_ in module.tables(source)] == [tag for tag, *_ in module.tables(copy)]
    for tag in before:
        if tag == b"name":
            continue
        if tag == b"head":
            at = module.ADJUSTMENT_OFFSET
            assert before[tag][:at] + before[tag][at + 4:] == after[tag][:at] + after[tag][at + 4:]
            continue
        assert before[tag] == after[tag], tag
    old, new = name_records(module, source), name_records(module, copy)
    assert list(old) == list(new)
    for key, string in new.items():
        platform, encoding, _, name_id = key
        expected = module.NAMES.get(name_id)
        if expected is None:
            assert string == old[key], key
        else:
            assert string == module.encode(platform, encoding, expected), key


def test_the_copys_checksums_hold():
    """Each table's directory checksum is its bytes' (head's taken with its adjustment zero), and
    the whole file sums to the specification's constant."""
    module = font_rename()
    copy = module.renamed(module.SOURCE.read_bytes())
    for tag, table_sum, offset, length in module.tables(copy):
        table = bytearray(copy[offset:offset + length])
        if tag == b"head":
            table[module.ADJUSTMENT_OFFSET:module.ADJUSTMENT_OFFSET + 4] = b"\0\0\0\0"
        assert module.checksum(bytes(table)) == table_sum, tag
        assert offset % 4 == 0, tag
    assert module.checksum(copy) == module.CHECKSUM_MAGIC


def test_rebuilding_with_no_new_name_keeps_every_other_table_in_place():
    """The writer itself: with no name replaced, every table but `name` (whose strings it stores
    afresh) lands where the source has it, so the layout is the source's."""
    module = font_rename()
    source = module.SOURCE.read_bytes()
    copy = module.rebuilt(source, {})
    assert name_records(module, source) == name_records(module, copy)
    order = sorted(module.tables(source), key=lambda record: record[2])
    name_at = [tag for tag, *_ in order].index(b"name")
    unmoved = {tag for tag, *_ in order[:name_at]}
    for (tag, _, offset, length), (_, _, new_offset, new_length) in zip(module.tables(source), module.tables(copy)):
        assert length == new_length or tag == b"name", tag
        if tag in unmoved:
            assert offset == new_offset, tag
