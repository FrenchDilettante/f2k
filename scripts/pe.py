"""
pe.py - the scripts' PE reader: an image's headers, sections and directories, its export and import
tables, and its resources, read off its file with the standard library only (no pefile).

It reads PE32 and PE32+ headers (`Image.plus` tells them apart); the import walk reads 32-bit
thunks, so a PE32+ image's import tables are not read right. Its users: scripts/pe_deps.py (an
executable's dependencies and icon), scripts/dump_exports.py (a real DLL's export and import
tables), scripts/compat.py (the built DLLs' import tables) and tests/harness/test_repository.py
(the corpus fixtures' imports).
"""
import struct

# The image's directories, by index in the optional header's data directory array.
DIR_EXPORT, DIR_IMPORT, DIR_RESOURCE, DIR_DELAY_IMPORT = 0, 1, 2, 13
# IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_CNT_CODE: a section holding code (an export there is a
# function, not a variable).
CODE = 0x2000_0000 | 0x0000_0020


class PeError(ValueError):
    """The file is not a PE image, or not one this reader can read."""


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
            self.plus = False
            self.base = struct.unpack_from("<I", data, optional + 28)[0]
            directories_at = optional + 96
        elif magic == 0x20B:  # PE32+
            self.plus = True
            self.base = struct.unpack_from("<Q", data, optional + 24)[0]
            directories_at = optional + 112
        else:
            raise PeError(f"optional header magic {magic:#x} is neither PE32 nor PE32+")
        self.subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        self.directories = [
            struct.unpack_from("<II", data, directories_at + 8 * i) for i in range(16)
        ]
        # Each section: (its RVA, its size in memory or on file, whichever is larger, its file
        # offset, its characteristics).
        self.sections = []
        for i in range(sections):
            _, virtual_size, rva, raw_size, raw, _, _, _, _, flags = struct.unpack_from(
                "<8sIIIIIIHHI", data, optional + optional_size + 40 * i)
            self.sections.append((rva, max(virtual_size, raw_size), raw, flags))

    def section_of(self, rva: int):
        """The section holding `rva`, None for none."""
        return next((s for s in self.sections if s[0] <= rva < s[0] + s[1]), None)

    def offset(self, rva: int) -> int:
        section = self.section_of(rva)
        if section is None:
            raise PeError(f"RVA {rva:#x} is in no section")
        return rva - section[0] + section[2]

    def string(self, rva: int) -> str:
        start = self.offset(rva)
        return self.data[start:self.data.index(b"\0", start)].decode("ascii")

    def word(self, rva: int) -> int:
        return struct.unpack_from("<I", self.data, self.offset(rva))[0]


def exports(image: Image):
    """The export table: (dll name, [(ordinal, name or None, forward target or None, data)])."""
    rva, size = image.directories[DIR_EXPORT]
    if not rva:
        raise PeError("no export table")
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


def thunks(image: Image, rva: int, shift: int = 0) -> list[str]:
    """The names a zero-terminated thunk array imports: `name`, or `#ordinal` for an import by
    ordinal (the top bit set). A name's thunk is its IMAGE_IMPORT_BY_NAME's RVA, `shift` more for
    an address (an old-form delay-load table's)."""
    names = []
    while (thunk := image.word(rva)) != 0:
        # IMAGE_IMPORT_BY_NAME: a hint (a halfword), then the name.
        names.append(f"#{thunk & 0xFFFF}" if thunk & 0x8000_0000 else image.string(thunk - shift + 2))
        rva += 4
    return names


def imports(image: Image) -> list[tuple[str, bool, list[str]]]:
    """The import tables: [(module, delay-loaded, [import])], the load-time table's modules first,
    then the delay-load table's, each in its table's order and spelled as the image spells it."""
    modules = []
    rva, _ = image.directories[DIR_IMPORT]
    while rva:
        # IMAGE_IMPORT_DESCRIPTOR: the names' thunks (OriginalFirstThunk), the bind timestamp, the
        # forwarder chain, the module's name, the IAT (FirstThunk); a zero one ends the table.
        names, bound, _, name, iat = struct.unpack_from("<IIIII", image.data, image.offset(rva))
        if not name:
            break
        if not names and bound:
            # An image without the names' array has only its IAT, which binding overwrote with
            # addresses: the names are gone.
            raise PeError(f"{image.string(name)}: bound, with no import names to read")
        modules.append((image.string(name), False, thunks(image, names or iat)))
        rva += 20
    rva, _ = image.directories[DIR_DELAY_IMPORT]
    while rva:
        # ImgDelayDescr: its attributes, the module's name, its HMODULE's place, the IAT, the names'
        # thunks, the bound IAT, the unload IAT, the timestamp; a zero one ends the table. Without
        # dlattrRva (bit 0, the old form, as Visual C++ 6 links it) the fields are addresses, not
        # RVAs.
        attributes, name, _, _, names = struct.unpack_from("<IIIII", image.data, image.offset(rva))
        if not name:
            break
        shift = 0 if attributes & 1 else image.base
        modules.append((image.string(name - shift), True, thunks(image, names - shift, shift)))
        rva += 32
    return modules


def resource_entries(image: Image, directory: int, root: int):
    """A resource directory's entries (`directory` and `root`, the resource root's, file offsets):
    (the raw name word, the entry's file offset, is a subdirectory). The name word's high bit
    marks a string name; see `resource_name`."""
    named, ids = struct.unpack_from("<HH", image.data, directory + 12)
    for i in range(named + ids):
        name, at = struct.unpack_from("<II", image.data, directory + 16 + 8 * i)
        yield name, root + (at & 0x7FFF_FFFF), bool(at & 0x8000_0000)


def resource_name(image: Image, name_word: int, root: int) -> int | str:
    """A resource entry's name: its id, or its string (a named entry's word is the string's offset
    from the resource root) - numeric strings as the integers they name, as group-icon entries
    reference their RT_ICON images by id."""
    if not name_word & 0x8000_0000:
        return name_word
    at = root + (name_word & 0x7FFF_FFFF)
    length = struct.unpack_from("<H", image.data, at)[0]
    text = image.data[at + 2:at + 2 + 2 * length].decode("utf-16-le")
    return int(text) if text.isdecimal() else text


def resource_data(image: Image, want_type: int) -> dict[int | str, bytes]:
    """The data blobs of the resources of one type, by their name: type -> name -> language
    -> IMAGE_RESOURCE_DATA_ENTRY. Only the first language of each name is taken; empty when the
    image has no resources."""
    found: dict[int | str, bytes] = {}
    rva, _ = image.directories[DIR_RESOURCE]
    if not rva:
        return found
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
