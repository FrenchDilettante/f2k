"""scripts/catalogue_exports.py's TOML strings: whatever a note holds (a quotation mark, a backslash,
a control character, a character past the BMP), the string it writes is valid TOML and reads back
as the text."""

import importlib.util
import tomllib

import f2kboot

SCRIPT = f2kboot.REPO_ROOT / "scripts" / "catalogue_exports.py"


def catalogue_exports():
    spec = importlib.util.spec_from_file_location("catalogue_exports", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_toml_strings_read_back_as_their_text():
    """Each text, written as a note's value, parses and reads back unchanged."""
    module = catalogue_exports()
    texts = [
        "forwarded to NTDLL.RtlAllocateHeap",
        'a "quoted" name',
        "a back\\slash",
        "two\nlines",
        "tab\there, carriage\rreturn",
        "".join(chr(code) for code in range(0x20)) + "\x7f",
        "café \U0001F600",
        "",
    ]
    for text in texts:
        assert tomllib.loads(f"note = {module.toml_string(text)}\n") == {"note": text}, repr(text)
