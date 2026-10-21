//! Environment blocks, as ntdll's environment functions edit and read them
//! (RtlSetEnvironmentVariable, RtlQueryEnvironmentVariable_U, RtlExpandEnvironmentStrings_U):
//! UTF-16 `NAME=value` entries, each NUL-terminated, a final NUL after the last (an empty block is
//! two NULs).
//!
//! Names compare without regard to case (upper-cased through code page 1252's case map, as the
//! platform upcases them) and keep the spelling they were set with. A name ends at its first `=`
//! past its first character (a leading `=` is part of the name, as in the drive-directory entries).
//! A new variable goes in at its sorted place, by its upper-cased name, as Windows 2000 keeps the
//! block sorted; a replaced one stays where it was.

use crate::cp1252::map_case;

const EQUALS: u16 = b'=' as u16;
const PERCENT: u16 = b'%' as u16;

/// Why a set is refused: the name is not one, or the block has no room (the caller grows it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvError {
    /// Empty, or an `=` past its first character.
    InvalidName,
    /// The edited block needs this many units, its final NUL included.
    NeedsRoom(usize),
}

/// The block's length in units, its final NUL included (an empty block's two NULs count).
pub fn block_length(block: &[u16]) -> usize {
    let mut at = 0;
    loop {
        let end = block[at..]
            .iter()
            .position(|&unit| unit == 0)
            .map_or(block.len(), |i| at + i);
        if end == at {
            // The final NUL; an empty block's first entry is empty too.
            return (at + 1).max(2).min(block.len());
        }
        at = end + 1;
        if at >= block.len() {
            return block.len();
        }
    }
}

/// The entries: (start, end) of each `NAME=value`, terminator excluded.
fn entries(block: &[u16]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut at = 0;
    core::iter::from_fn(move || {
        let end = at + block.get(at..)?.iter().position(|&unit| unit == 0)?;
        if end == at {
            return None;
        }
        let entry = (at, end);
        at = end + 1;
        Some(entry)
    })
}

/// An entry's name: up to its first `=` past the first unit.
fn name_of(entry: &[u16]) -> &[u16] {
    let split = entry
        .iter()
        .skip(1)
        .position(|&unit| unit == EQUALS)
        .map_or(entry.len(), |i| i + 1);
    &entry[..split]
}

fn upper(unit: u16) -> u16 {
    map_case(unit, true)
}

/// Compare two names as the platform does: upper-cased, unit by unit.
fn compare(a: &[u16], b: &[u16]) -> core::cmp::Ordering {
    a.iter().map(|&u| upper(u)).cmp(b.iter().map(|&u| upper(u)))
}

/// Whether `name` is a variable name.
pub fn valid_name(name: &[u16]) -> bool {
    !name.is_empty() && !name[1..].contains(&EQUALS) && !name.contains(&0)
}

/// The value of `name` in `block`, if set.
pub fn query<'b>(block: &'b [u16], name: &[u16]) -> Option<&'b [u16]> {
    entries(block).find_map(|(start, end)| {
        let entry = &block[start..end];
        let entry_name = name_of(entry);
        (entry_name.len() < entry.len() && compare(entry_name, name).is_eq())
            .then(|| &entry[entry_name.len() + 1..])
    })
}

/// Set `name` to `value` in `block` (its room: `block.len()` units), or delete it for none
/// (deleting an unset name succeeds). The block is edited in place; NeedsRoom when it does not fit,
/// the block unchanged.
pub fn set(block: &mut [u16], name: &[u16], value: Option<&[u16]>) -> Result<(), EnvError> {
    if !valid_name(name) {
        return Err(EnvError::InvalidName);
    }
    let used = block_length(block);
    let found =
        entries(block).find(|&(start, end)| compare(name_of(&block[start..end]), name).is_eq());
    // Where the entry goes (an existing one's place, else its sorted place), and what it frees.
    let (at, removed) = match found {
        Some((start, end)) => (start, end + 1 - start),
        None => {
            let place = entries(block)
                .find(|&(start, end)| compare(name_of(&block[start..end]), name).is_gt())
                .map_or(used - 1, |(start, _)| start);
            (place, 0)
        }
    };
    let Some(value) = value else {
        if removed != 0 {
            block.copy_within(at + removed..used, at);
            // An emptied block keeps its two NULs.
            if used - removed < 2 {
                block[0] = 0;
                block[1] = 0;
            }
        }
        return Ok(());
    };
    let added = name.len() + 1 + value.len() + 1;
    // An empty block's first NUL is its (empty) first entry's: the new entry takes its place.
    let empty = found.is_none() && used == 2 && block[0] == 0;
    let needed = if empty {
        added + 1
    } else {
        used - removed + added
    };
    if needed > block.len() {
        return Err(EnvError::NeedsRoom(needed));
    }
    let at = if empty { 0 } else { at };
    let tail = if empty { 1 } else { at + removed };
    let tail_len = used - tail;
    let new_tail = at + added;
    block.copy_within(tail..tail + tail_len, new_tail);
    block[at..at + name.len()].copy_from_slice(name);
    block[at + name.len()] = EQUALS;
    let value_at = at + name.len() + 1;
    block[value_at..value_at + value.len()].copy_from_slice(value);
    block[value_at + value.len()] = 0;
    Ok(())
}

/// Expand `%NAME%` references in `source` through `block`: a set name becomes its value, any other
/// reference (and a `%` with no closing one) stays as written. The expansion goes to `out`, a unit
/// at a time.
pub fn expand(block: &[u16], source: &[u16], mut out: impl FnMut(u16)) {
    let mut at = 0;
    while at < source.len() {
        let unit = source[at];
        if unit != PERCENT {
            out(unit);
            at += 1;
            continue;
        }
        let Some(close) = source[at + 1..]
            .iter()
            .position(|&u| u == PERCENT)
            .map(|i| at + 1 + i)
        else {
            source[at..].iter().for_each(|&u| out(u));
            return;
        };
        let name = &source[at + 1..close];
        match (!name.is_empty()).then(|| query(block, name)).flatten() {
            Some(value) => {
                value.iter().for_each(|&u| out(u));
                at = close + 1;
            }
            None => {
                // The reference stays as written, its closing `%` with it.
                out(PERCENT);
                name.iter().for_each(|&u| out(u));
                out(PERCENT);
                at = close + 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::string::String;
    use std::vec::Vec;

    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// A block of `room` units holding `entries`.
    fn block(entries: &[&str], room: usize) -> Vec<u16> {
        let mut block = Vec::new();
        for entry in entries {
            block.extend(wide(entry));
            block.push(0);
        }
        if entries.is_empty() {
            block.push(0);
        }
        block.push(0);
        block.resize(room, 0xCCCC);
        block
    }

    fn listed(block: &[u16]) -> Vec<String> {
        entries(block)
            .map(|(s, e)| String::from_utf16(&block[s..e]).unwrap())
            .collect()
    }

    /// The runtime capture's sequence: set, read back by either case, replace, delete.
    #[test]
    fn a_variable_sets_replaces_and_deletes() {
        let mut env = block(&[], 64);
        assert_eq!(block_length(&env), 2);
        set(&mut env, &wide("F2KTEST"), Some(&wide("first"))).unwrap();
        assert_eq!(query(&env, &wide("f2ktest")), Some(&wide("first")[..]));
        set(&mut env, &wide("OTHER"), Some(&wide("x"))).unwrap();
        set(&mut env, &wide("F2KTEST"), Some(&wide("second value"))).unwrap();
        assert_eq!(
            listed(&env),
            ["F2KTEST=second value", "OTHER=x"],
            "replaced in place, sorted"
        );
        set(&mut env, &wide("A"), Some(&wide("1"))).unwrap();
        assert_eq!(listed(&env), ["A=1", "F2KTEST=second value", "OTHER=x"]);
        set(&mut env, &wide("F2KTEST"), None).unwrap();
        assert_eq!(listed(&env), ["A=1", "OTHER=x"]);
        set(&mut env, &wide("NOSUCH"), None).unwrap();
        set(&mut env, &wide("A"), None).unwrap();
        set(&mut env, &wide("OTHER"), None).unwrap();
        assert_eq!(block_length(&env), 2, "emptied: two NULs");
        assert_eq!(&env[..2], &[0, 0]);
        // A prefix is not a match; an empty value is a value.
        set(&mut env, &wide("AB"), Some(&[])).unwrap();
        assert_eq!(query(&env, &wide("A")), None);
        assert_eq!(query(&env, &wide("AB")), Some(&[][..]));
    }

    /// Names: empty or carrying an `=` past the first character are refused; a leading `=` is part
    /// of the name. A set that does not fit says how much room it needs, the block unchanged.
    #[test]
    fn names_are_validated_and_room_is_asked() {
        let mut env = block(&[], 16);
        assert_eq!(
            set(&mut env, &wide(""), Some(&wide("v"))),
            Err(EnvError::InvalidName)
        );
        assert_eq!(
            set(&mut env, &wide("A=B"), Some(&wide("v"))),
            Err(EnvError::InvalidName)
        );
        set(&mut env, &wide("=C:"), Some(&wide("C:\\"))).unwrap();
        assert_eq!(query(&env, &wide("=c:")), Some(&wide("C:\\")[..]));
        let before = env.clone();
        assert_eq!(
            set(&mut env, &wide("LONG"), Some(&wide("0123456789"))),
            Err(EnvError::NeedsRoom(25))
        );
        assert_eq!(env, before);
    }

    fn expanded(source: &str) -> String {
        let env = block(&["F2KCRT=crt value"], 64);
        let mut out = Vec::new();
        expand(&env, &wide(source), |u| out.push(u));
        String::from_utf16(&out).unwrap()
    }

    /// The capture's expansion, and the literal cases.
    #[test]
    fn references_expand_or_stay() {
        assert_eq!(
            expanded("[%F2KCRT%] [%F2KNOSUCH%]"),
            "[crt value] [%F2KNOSUCH%]"
        );
        assert_eq!(expanded("[%F2KCRT%] [%F2KNOSUCH%]").len() + 1, 26);
        assert_eq!(expanded("100%"), "100%");
        assert_eq!(expanded("%%"), "%%");
        assert_eq!(expanded("%f2kcrt%"), "crt value");
        assert_eq!(expanded("a %f2kcrt"), "a %f2kcrt", "a reference left open");
        assert_eq!(expanded("%f2kcrt%%f2kcrt%"), "crt valuecrt value");
        assert_eq!(
            expanded("%x%f2kcrt%"),
            "%x%f2kcrt%",
            "an unset reference's closing % stays its own"
        );
    }
}
