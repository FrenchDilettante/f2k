"""
specs.py - the rules the scripts share over the export specs (userland/<dll>/exports.toml) and the
TOML files they write: a system service's Zw alias, a module's name as the loader compares it, and
a TOML basic string.

Its users: scripts/catalogue_exports.py, scripts/compat.py and scripts/pe_deps.py.
"""


def zw_alias(name: str) -> str:
    """A system service's second name: NtClose's ZwClose (both export the same stub)."""
    return "Zw" + name[2:]


def module_key(name: str) -> str:
    """A module's name as the loader compares it: without regard to case, `.dll` implied."""
    return name.lower().removesuffix(".dll")


# The characters a TOML basic string must escape, and their escapes: the quotation mark, the
# backslash, and the control characters (U+0000 to U+001F and U+007F; tab may stand as it is, but
# is escaped too), the ones with a short escape by it.
TOML_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def toml_string(text: str) -> str:
    """`text` as a TOML basic string: every character as it is but those TOML must escape."""
    def escaped(char: str) -> str:
        if char in TOML_ESCAPES:
            return TOML_ESCAPES[char]
        if ord(char) < 0x20 or ord(char) == 0x7F:
            return f"\\u{ord(char):04X}"
        return char
    return '"' + "".join(escaped(char) for char in text) + '"'
