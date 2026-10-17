//! String comparison for CompareStringA/W: the platform's linguistic order, modeled for the Latin
//! range.
//!
//! The platform compares strings by sort key, level by level: first the characters' primary
//! weights (symbols before digits before letters, letters without regard to case or accent), then
//! their accents, then their case (lower before upper), and last — in the default word sort — the
//! hyphen and the apostrophe, which the word sort leaves out of the first three levels so that
//! "co-op" sorts beside "coop" (after it, being otherwise equal). SORT_STRINGSORT treats those two
//! as ordinary symbols instead. The flags drop levels: NORM_IGNORECASE the case, NORM_IGNORENONSPACE
//! the accents, NORM_IGNORESYMBOLS the symbols altogether.
//!
//! The model: Latin-1 letters fold onto their base letter at the primary level and keep their own
//! code as the accent weight; symbols order by code point among themselves; characters past the
//! Latin range order by code point after the letters. Every locale compares the same.

/// NORM_IGNORECASE.
pub const NORM_IGNORECASE: u32 = 0x0000_0001;
/// NORM_IGNORENONSPACE.
pub const NORM_IGNORENONSPACE: u32 = 0x0000_0002;
/// NORM_IGNORESYMBOLS.
pub const NORM_IGNORESYMBOLS: u32 = 0x0000_0004;
/// SORT_STRINGSORT.
pub const SORT_STRINGSORT: u32 = 0x0000_1000;
/// NORM_IGNOREKANATYPE.
pub const NORM_IGNOREKANATYPE: u32 = 0x0001_0000;
/// NORM_IGNOREWIDTH.
pub const NORM_IGNOREWIDTH: u32 = 0x0002_0000;
/// Every flag the comparison accepts.
pub const VALID_FLAGS: u32 = NORM_IGNORECASE
    | NORM_IGNORENONSPACE
    | NORM_IGNORESYMBOLS
    | SORT_STRINGSORT
    | NORM_IGNOREKANATYPE
    | NORM_IGNOREWIDTH;

/// CSTR_LESS_THAN, CSTR_EQUAL, CSTR_GREATER.
pub const CSTR_LESS_THAN: u32 = 1;
pub const CSTR_EQUAL: u32 = 2;
pub const CSTR_GREATER: u32 = 3;

/// The primary groups, in sort order.
const SYMBOL: u32 = 1 << 16;
const DIGIT: u32 = 2 << 16;
const LETTER: u32 = 3 << 16;
const BEYOND: u32 = 4 << 16;

/// One character's weights.
#[derive(Clone, Copy)]
struct Weights {
    /// The primary weight; none for a character the word sort leaves to the last level.
    primary: Option<u32>,
    /// The accent weight (the character's own code for an accented letter, zero otherwise).
    accent: u32,
    /// The case weight: 1 for upper case.
    case: u32,
}

/// A Latin letter's base letter (lower case), whether it is upper case, and its accent weight
/// (zero for a plain letter; the lower-case form's code for an accented one, so that case pairs
/// share it); none for a non-letter.
fn latin_letter(c: u32) -> Option<(u8, bool, u32)> {
    // The bases of U+00C0..U+00FF; NUL marks the two non-letters (× and ÷).
    const BASES: &[u8; 64] = b"aaaaaaaceeeeiiiidnooooo\0ouuuuyts\
aaaaaaaceeeeiiiidnooooo\0ouuuuyty";
    match c {
        0x41..=0x5A => Some((c as u8 + 0x20, true, 0)),
        0x61..=0x7A => Some((c as u8, false, 0)),
        0xC0..=0xFF => {
            let base = BASES[c as usize - 0xC0];
            // ß (U+00DF) is lower case; the rest of the first half is upper case.
            (base != 0).then_some((base, c < 0xDF, c | 0x20))
        }
        // The cp1252 extras: Œ œ Š š Ÿ Ž ž.
        0x152 | 0x153 => Some((b'o', c == 0x152, 0x153)),
        0x160 | 0x161 => Some((b's', c == 0x160, 0x161)),
        0x178 => Some((b'y', true, 0xFF)),
        0x17D | 0x17E => Some((b'z', c == 0x17D, 0x17E)),
        _ => None,
    }
}

fn weights(c: u32, flags: u32) -> Weights {
    let word_sort = flags & SORT_STRINGSORT == 0;
    if word_sort && (c == u32::from(b'-') || c == u32::from(b'\'') || c == 0xAD) {
        return Weights {
            primary: None,
            accent: 0,
            case: 0,
        };
    }
    if let Some((base, upper, accent)) = latin_letter(c) {
        return Weights {
            primary: Some(LETTER | u32::from(base)),
            accent,
            case: u32::from(upper),
        };
    }
    let primary = match c {
        0x30..=0x39 => DIGIT | c,
        0x00..=0xBF | 0xD7 | 0xF7 => SYMBOL | c,
        _ => BEYOND | c,
    };
    Weights {
        primary: Some(primary),
        accent: 0,
        case: 0,
    }
}

/// Compare two strings of Unicode code units under `flags` (already validated): CSTR_LESS_THAN,
/// CSTR_EQUAL or CSTR_GREATER.
#[cfg(test)]
pub fn compare(a: &[u32], b: &[u32], flags: u32) -> u32 {
    compare_with(&|i| a[i], a.len(), &|i| b[i], b.len(), flags)
}

/// [`compare`] over code units read through accessors (by index, below the length): the strings
/// are read where they are, as often as the levels need, never copied.
pub fn compare_with(
    a: &dyn Fn(usize) -> u32,
    a_len: usize,
    b: &dyn Fn(usize) -> u32,
    b_len: usize,
    flags: u32,
) -> u32 {
    let keep = |w: &Weights| {
        w.primary
            .is_some_and(|p| flags & NORM_IGNORESYMBOLS == 0 || p & 0xFFFF_0000 != SYMBOL)
    };
    let wa = alloc_free::Weighed::new(a, a_len, flags);
    let wb = alloc_free::Weighed::new(b, b_len, flags);

    // Level 1: the primary weights of the characters kept.
    let order = wa
        .iter()
        .filter(keep)
        .map(|w| w.primary)
        .cmp(wb.iter().filter(keep).map(|w| w.primary));
    // Level 2: accents; level 3: case — over the same characters.
    let order = order.then_with(|| {
        if flags & NORM_IGNORENONSPACE != 0 {
            return core::cmp::Ordering::Equal;
        }
        wa.iter()
            .filter(keep)
            .map(|w| w.accent)
            .cmp(wb.iter().filter(keep).map(|w| w.accent))
    });
    let order = order.then_with(|| {
        if flags & NORM_IGNORECASE != 0 {
            return core::cmp::Ordering::Equal;
        }
        wa.iter()
            .filter(keep)
            .map(|w| w.case)
            .cmp(wb.iter().filter(keep).map(|w| w.case))
    });
    // Level 4 (word sort): the hyphens and apostrophes left out, by position then character; a
    // string carrying them sorts after one without.
    let order = order.then_with(|| {
        if flags & NORM_IGNORESYMBOLS != 0 {
            return core::cmp::Ordering::Equal;
        }
        let specials = |w: &alloc_free::Weighed| {
            w.iter()
                .enumerate()
                .filter(|(_, w)| w.primary.is_none())
                .map(|(i, _)| i)
                .collect_fixed()
        };
        let (sa, sb) = (specials(&wa), specials(&wb));
        match (sa.is_empty(), sb.is_empty()) {
            (true, true) => core::cmp::Ordering::Equal,
            (false, true) => core::cmp::Ordering::Greater,
            (true, false) => core::cmp::Ordering::Less,
            (false, false) => sa.cmp(&sb),
        }
    });
    match order {
        core::cmp::Ordering::Less => CSTR_LESS_THAN,
        core::cmp::Ordering::Equal => CSTR_EQUAL,
        core::cmp::Ordering::Greater => CSTR_GREATER,
    }
}

/// The weights of a string, computed on the fly (the kernel has no allocator for a sort key).
mod alloc_free {
    use super::{weights, Weights};

    pub struct Weighed<'a> {
        unit: &'a dyn Fn(usize) -> u32,
        len: usize,
        flags: u32,
    }

    impl<'a> Weighed<'a> {
        pub fn new(unit: &'a dyn Fn(usize) -> u32, len: usize, flags: u32) -> Self {
            Weighed { unit, len, flags }
        }

        pub fn iter(&self) -> impl Iterator<Item = Weights> + '_ {
            (0..self.len).map(move |i| weights((self.unit)(i), self.flags))
        }
    }

    /// The positions of a string's left-out characters, the first few of them (enough to order
    /// any real pair).
    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    pub struct Positions {
        count: usize,
        positions: [usize; 16],
    }

    impl Positions {
        pub fn is_empty(&self) -> bool {
            self.count == 0
        }
    }

    pub trait CollectFixed {
        fn collect_fixed(self) -> Positions;
    }

    impl<I: Iterator<Item = usize>> CollectFixed for I {
        fn collect_fixed(self) -> Positions {
            let mut out = Positions {
                count: 0,
                positions: [usize::MAX; 16],
            };
            for position in self.take(16) {
                out.positions[out.count] = position;
                out.count += 1;
            }
            out
        }
    }
}

use alloc_free::CollectFixed;

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str, flags: u32) -> u32 {
        let a: Vec<u32> = a.chars().map(u32::from).collect();
        let b: Vec<u32> = b.chars().map(u32::from).collect();
        compare(&a, &b, flags)
    }

    /// The runtime capture's five comparisons.
    #[test]
    fn the_captured_comparisons() {
        assert_eq!(cmp("apple", "Banana", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("abc", "ABC", NORM_IGNORECASE), CSTR_EQUAL);
        assert_eq!(cmp("abc", "ABC", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("co-op", "coop", 0), CSTR_GREATER);
        assert_eq!(cmp("co-op", "coop", SORT_STRINGSORT), CSTR_LESS_THAN);
    }

    /// The groups: symbols before digits before letters; a prefix sorts first; accents after the
    /// base letter, and dropped by NORM_IGNORENONSPACE.
    #[test]
    fn the_levels_order() {
        assert_eq!(cmp("!", "0", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("9", "a", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("ab", "abc", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("", "", 0), CSTR_EQUAL);
        assert_eq!(cmp("e", "\u{e9}", 0), CSTR_LESS_THAN);
        assert_eq!(cmp("\u{e9}", "f", 0), CSTR_LESS_THAN, "an accent is not a primary difference");
        assert_eq!(cmp("e", "\u{e9}", NORM_IGNORENONSPACE), CSTR_EQUAL);
        assert_eq!(cmp("\u{c9}", "\u{e9}", NORM_IGNORECASE), CSTR_EQUAL);
        assert_eq!(cmp("a b", "ab", NORM_IGNORESYMBOLS), CSTR_EQUAL);
    }
}
