//! Case-insensitive name comparison, as NT makes it: one upcase rule for every name the kernel and
//! the native DLLs compare without regard to case (object names, registry keys and values, file
//! names on FAT, device and module names, the current directory, the profile files' sections and
//! keys).
//!
//! NT's rule is RtlUpcaseUnicodeChar's: the upcase table of l_intl.nls, which the kernel, ntdll and
//! the file systems all fold through. kernel32's default casing (LCMapStringW's LCMAP_UPPERCASE,
//! CharUpperW) reads the same table, so [`upcase`] is [`cp1252::map_case`]'s upper direction, which
//! the casing captures pin: every letter of Latin-1 and Latin Extended-A, ÿ, œ, š and ž among them
//! (Inside Windows 2000 confirms the four), and Greek's, Cyrillic's and the fullwidth Latin
//! letters.
//!
//! The atom tables are the exception: they compare names with the C runtime's `_wcsicmp`, ASCII
//! letters alone ([`atom_upcase`]).

use core::cmp::Ordering;

use crate::cp1252;

/// `unit` upper-cased as NT's case-insensitive comparisons fold it (RtlUpcaseUnicodeChar).
pub fn upcase(unit: u16) -> u16 {
    cp1252::map_case(unit, true)
}

/// Whether two names are the same, without regard to case (RtlEqualUnicodeString with
/// CaseInSensitive).
pub fn eq_ignore_case(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| upcase(x) == upcase(y))
}

/// Two names' order without regard to case: unit by unit, each upper-cased, a name before the
/// longer names it begins (RtlCompareUnicodeString with CaseInSensitive).
pub fn cmp_ignore_case(a: &[u16], b: &[u16]) -> Ordering {
    a.iter()
        .map(|&unit| upcase(unit))
        .cmp(b.iter().map(|&unit| upcase(unit)))
}

/// Whether `units` spell `text`, without regard to case.
pub fn eq_ignore_case_str(units: &[u16], text: &str) -> bool {
    units
        .iter()
        .map(|&unit| upcase(unit))
        .eq(text.encode_utf16().map(upcase))
}

/// `unit` upper-cased as Windows 2000's atom tables fold it: ASCII letters alone. The atom capture
/// shows it: a global atom named with é is not found as É.
pub fn atom_upcase(unit: u16) -> u16 {
    match unit {
        0x61..=0x7A => unit - 0x20,
        _ => unit,
    }
}

/// Whether two atom names are the same, as the atom tables match them ([`atom_upcase`]).
pub fn same_atom_name(a: impl IntoIterator<Item = u16>, b: impl IntoIterator<Item = u16>) -> bool {
    a.into_iter()
        .map(atom_upcase)
        .eq(b.into_iter().map(atom_upcase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::wide;

    /// The four letters Inside Windows 2000 names beyond Latin-1's block: ÿ, œ, š and ž upcase to
    /// Ÿ, Œ, Š and Ž.
    #[test]
    fn upcase_covers_the_four_letters_beyond_latin_1() {
        assert_eq!(upcase(0xFF), 0x178);
        assert_eq!(upcase(0x153), 0x152);
        assert_eq!(upcase(0x161), 0x160);
        assert_eq!(upcase(0x17E), 0x17D);
        for capital in [0x178, 0x152, 0x160, 0x17D] {
            assert_eq!(upcase(capital), capital);
        }
    }

    /// Latin-1's small letters upcase to their capitals (sharp s has none and stays; so does the
    /// division sign), and Latin Extended-A's to theirs, but for the dotless i, kra, the
    /// apostrophe n and the long s, which have no capital of their own.
    #[test]
    fn upcase_covers_latin_1_and_extended_a() {
        for unit in 0x61..=0x7A {
            assert_eq!(upcase(unit), unit - 0x20);
        }
        for unit in (0xE0..=0xFE).filter(|&unit| unit != 0xF7) {
            assert_eq!(upcase(unit), unit - 0x20, "U+{unit:04X}");
        }
        assert_eq!(
            (upcase(0xDF), upcase(0xF7), upcase(0xB5)),
            (0xDF, 0xF7, 0xB5)
        );
        for unit in 0x100..=0x17F {
            let capital = upcase(unit);
            if matches!(unit, 0x131 | 0x138 | 0x149 | 0x17F) {
                assert_eq!(capital, unit, "U+{unit:04X}");
            } else {
                assert!(capital == unit || capital == unit - 1, "U+{unit:04X}");
                assert_eq!(upcase(capital), capital, "U+{unit:04X}");
            }
        }
    }

    #[test]
    fn names_compare_through_upcase() {
        assert!(eq_ignore_case(&wide("Mašina"), &wide("MAŠINA")));
        assert!(eq_ignore_case(&wide("œuvre ÿ ž"), &wide("ŒUVRE Ÿ Ž")));
        assert!(!eq_ignore_case(&wide("Masina"), &wide("Mašina")));
        assert!(!eq_ignore_case(&wide("abc"), &wide("abcd")));
        assert!(eq_ignore_case_str(&wide("ŠKODA"), "škoda"));
        assert!(!eq_ignore_case_str(&wide("SKODA"), "škoda"));
        assert_eq!(cmp_ignore_case(&wide("šb"), &wide("Ša")), Ordering::Greater);
        assert_eq!(cmp_ignore_case(&wide("ab"), &wide("AB")), Ordering::Equal);
        assert_eq!(cmp_ignore_case(&wide("ab"), &wide("ABC")), Ordering::Less);
        // Underscore sits between the cases: folded upward, "_" follows "A".
        assert_eq!(cmp_ignore_case(&wide("_"), &wide("a")), Ordering::Greater);
    }

    #[test]
    fn atom_names_fold_ascii_alone() {
        let units = |text: &str| wide(text).into_iter();
        assert!(same_atom_name(units("Class"), units("CLASS")));
        assert!(!same_atom_name(units("é"), units("É")));
        assert!(!same_atom_name(units("š"), units("Š")));
        assert!(!same_atom_name(units("ab"), units("abc")));
    }
}
