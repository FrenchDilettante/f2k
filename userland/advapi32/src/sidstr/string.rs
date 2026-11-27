//! The SID's string form, both ways: ConvertSidToStringSidA/W print it ("S-1-..."), and
//! ConvertStringSidToSidA/W parse it back. The W print is ntdll's RtlConvertSidToUnicodeString
//! through the [`super::services`] seam, copied into a fresh block of the process heap for the
//! caller; the A wrapper narrows that wide string. The parse is advapi32's own over the string's
//! units (see [`parse_sid_string`]); the SID it makes is a block of the process heap, which the
//! caller frees with LocalFree or FreeSid.

use rtl::heap::ProcessHeap as _;
// ERROR_INVALID_PARAMETER: a null argument. ERROR_INVALID_SID: a string that is not a SID.
// ERROR_NOT_ENOUGH_MEMORY: no room for a SID or a string.
use rtl::winerror::{ERROR_INVALID_PARAMETER, ERROR_INVALID_SID, ERROR_NOT_ENOUGH_MEMORY};

use super::{SID_HEADER, SID_MAX_SUB_AUTHORITIES};

/// A parsed SID string: its revision, its identifier authority's six bytes, and its
/// sub-authorities with how many of the array they fill.
type ParsedSid = (u8, [u8; 6], ([u32; SID_MAX_SUB_AUTHORITIES], usize));
use crate::imports::{self as nt, ProcessHeap};
use crate::token::{bool_of, failed, optional_ansi, optional_wide};
use crate::Out;

/// A number in the string form: an optional `0x`/`0X` prefix reads it in hex, otherwise in
/// `default_base`; the digits up to the first that is not one of the base's, wrapping at 32
/// bits. The value, the base used and the units consumed; none for no digits.
fn parse_number(units: &[u16], default_base: u32) -> Option<(u32, u32, usize)> {
    let (base, at) = match (units.first(), units.get(1)) {
        (Some(&first), Some(&second))
            if first == u16::from(b'0') && second | 0x20 == u16::from(b'x') =>
        {
            (16, 2)
        }
        _ => (default_base, 0),
    };
    let mut value = 0u32;
    let mut count = at;
    while let Some(&unit) = units.get(count) {
        let Some(digit) = char::from_u32(u32::from(unit)).and_then(|c| c.to_digit(base)) else {
            break;
        };
        value = value.wrapping_mul(base).wrapping_add(digit);
        count += 1;
    }
    if count == at {
        return None;
    }
    Some((value, base, count))
}

/// The string form of a SID, "S-1-5-32-544", parsed whole: 'S' (either case), '-', the revision,
/// '-', the identifier authority, then one or more '-'-separated sub-authorities, nothing left
/// over. A `0x` prefix on a number reads it in hex; without one the revision's base applies to
/// the rest. The authority keeps its low 32 bits. The revision, the authority's six bytes and
/// the sub-authorities (15 at most); none for a malformed string.
fn parse_sid_string(units: &[u16]) -> Option<ParsedSid> {
    if *units.first()? | 0x20 != u16::from(b's') || units.get(1) != Some(&u16::from(b'-')) {
        return None;
    }
    let (revision, base, used) = parse_number(&units[2..], 10)?;
    let mut at = 2 + used;
    // After the revision and the authority a '-' must follow, with more after it: at least one
    // sub-authority is required.
    if units.get(at) != Some(&u16::from(b'-')) || units.get(at + 1).is_none() {
        return None;
    }
    at += 1;
    let (authority, _, used) = parse_number(&units[at..], base)?;
    at += used;
    if units.get(at) != Some(&u16::from(b'-')) || units.get(at + 1).is_none() {
        return None;
    }
    let mut subs = [0u32; SID_MAX_SUB_AUTHORITIES];
    let mut count = 0;
    loop {
        at += 1; // past the '-'
        let (value, _, used) = parse_number(&units[at..], base)?;
        if count == subs.len() {
            return None; // more sub-authorities than a SID holds
        }
        subs[count] = value;
        count += 1;
        at += used;
        match units.get(at) {
            None => break,
            Some(&unit) if unit == u16::from(b'-') => {
                units.get(at + 1)?; // a SID does not end with '-'
            }
            _ => return None, // not the whole string consumed
        }
    }
    let mut authority_bytes = [0u8; 6];
    authority_bytes[2..].copy_from_slice(&authority.to_be_bytes());
    Some((revision as u8, authority_bytes, (subs, count)))
}

/// ConvertStringSidToSid's work over `units`: parse the whole string, make the SID in a block of
/// the process heap, its address into `place`. The error the call fails with.
fn string_to_sid(units: &[u16], place: &mut Out<'_, *mut u8>) -> Result<(), u32> {
    let (revision, authority, (subs, count)) = parse_sid_string(units).ok_or(ERROR_INVALID_SID)?;
    let size = SID_HEADER + 4 * count;
    let block = ProcessHeap::allocate(size);
    if block.is_null() {
        return Err(ERROR_NOT_ENOUGH_MEMORY);
    }
    // SAFETY: the heap's new block of `size` bytes, ours until the caller frees it.
    let bytes = unsafe { core::slice::from_raw_parts_mut(block, size) };
    bytes[0] = revision;
    bytes[1] = count as u8;
    bytes[2..SID_HEADER].copy_from_slice(&authority);
    for (index, sub) in subs.iter().take(count).enumerate() {
        bytes[SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4]
            .copy_from_slice(&sub.to_le_bytes());
    }
    place.set(block);
    Ok(())
}

/// ConvertSidToStringSid's W form, shared by the A wrapper: the SID's printed form in a block of
/// the process heap (zeroed, the terminator in it), its address into `string_sid`. FALSE with
/// ERROR_INVALID_PARAMETER for a null SID or place, the conversion's status as the last error
/// when the SID does not print (ERROR_INVALID_SID), ERROR_NOT_ENOUGH_MEMORY when the heap has
/// no room; TRUE with the last error ERROR_SUCCESS on success.
///
/// ConvertStringSidToSidW: the stringized SID parsed into a SID in a block of the process heap,
/// its address into `sid` (freed by the caller with LocalFree). FALSE with
/// ERROR_INVALID_PARAMETER for a null string or place, ERROR_INVALID_SID for a string that is
/// not a SID (the whole string must be one), ERROR_NOT_ENOUGH_MEMORY when the heap has no room;
/// TRUE with the last error ERROR_SUCCESS on success.
///
/// # Safety
///
/// `string_sid` is null or a NUL-terminated UTF-16 string the call may read; `sid` the caller's
/// place for the address.
#[unsafe(export_name = "f2k_export_ConvertStringSidToSidW")]
pub unsafe extern "system" fn convert_string_sid_to_sid_w(
    string_sid: *const u16,
    sid: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's string and place.
    let (text, mut place) = unsafe { (optional_wide(string_sid), Out::optional(sid)) };
    let (Some(text), Some(place)) = (text, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let result = string_to_sid(text, place);
    if result.is_ok() {
        nt::set_last_error(0);
    }
    bool_of(result)
}

/// ConvertStringSidToSidA: the ANSI string converted to UTF-16, then the W form's parse.
///
/// # Safety
///
/// As ConvertStringSidToSidW's, for a narrow string.
#[unsafe(export_name = "f2k_export_ConvertStringSidToSidA")]
pub unsafe extern "system" fn convert_string_sid_to_sid_a(
    string_sid: *const u8,
    sid: *mut *mut u8,
) -> u32 {
    // SAFETY: the caller's string and place.
    let (text, mut place) = unsafe { (optional_ansi(string_sid), Out::optional(sid)) };
    let (Some(text), Some(place)) = (text, place.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let converted = match nt::ansi_to_unicode(text) {
        Ok(wide) => wide,
        Err(status) => return failed(status),
    };
    let units = converted.counted();
    let result = string_to_sid(units.units(), place);
    if result.is_ok() {
        nt::set_last_error(0);
    }
    bool_of(result)
}

#[cfg(test)]
mod tests {
    use rtl::testing::{wide, wide_z};

    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// The SID of `authority` and `subs`: S-1-<authority>-<subs...>.
    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// The bytes of the NUL-terminated narrow string at `block`.
    fn narrow_of(block: *const u8) -> Vec<u8> {
        // SAFETY: the tests pass blocks they got back, NUL-terminated.
        unsafe { rtl::cstr::bytes_until_nul(block) }.to_vec()
    }

    /// The units of the NUL-terminated wide string at `block`.
    fn wide_of(block: *const u16) -> Vec<u16> {
        // SAFETY: as `narrow_of`'s.
        unsafe { rtl::cstr::units_until_nul(block) }.to_vec()
    }

    /// ConvertSidToStringSidA/W print S-1-5-32-544 as a NUL-terminated string in a heap block
    /// (TRUE, the last error ERROR_SUCCESS); a null SID or place is FALSE with
    /// ERROR_INVALID_PARAMETER (87), a SID that does not print (a wrong revision) FALSE with
    /// ERROR_INVALID_SID (1337).
    #[test]

    /// ConvertStringSidToSidA/W parse "S-1-5-32-544" into the SID's bytes in a heap block (TRUE,
    /// the last error ERROR_SUCCESS); a `0x` prefix reads a number in hex; a string that is not
    /// a whole SID (no sub-authority, a bad start, trailing garbage, a trailing '-', empty) is
    /// FALSE with ERROR_INVALID_SID (1337); a null string or place FALSE with
    /// ERROR_INVALID_PARAMETER (87). The round trip prints the same string back.
    #[test]
    fn a_string_sid_parses_a_and_w_and_round_trips() {
        let admins = sid(5, &[32, 544]);
        let text_w = wide_z("S-1-5-32-544");
        let mut out: *mut u8 = core::ptr::null_mut();
        arm();
        let ok = unsafe { convert_string_sid_to_sid_w(text_w.as_ptr(), &mut out) };
        assert_eq!((ok, last_error()), (1, 0));
        // SAFETY: the block the call made, 16 bytes.
        assert_eq!(unsafe { core::slice::from_raw_parts(out, 16) }, &admins[..]);
        let mut printed: *mut u16 = core::ptr::null_mut();
        arm();
        assert_eq!(unsafe { crate::sid::convert_sid_to_string_sid_w(out, &mut printed) }, 1);
        assert_eq!(wide_of(printed), wide("S-1-5-32-544"));
        // SAFETY: the blocks the calls made, freed once.
        unsafe { ProcessHeap::free(printed.cast()) };
        unsafe { ProcessHeap::free(out) };
        let text_a = b"S-1-5-32-544\0";
        let mut out: *mut u8 = core::ptr::null_mut();
        arm();
        let ok = unsafe { convert_string_sid_to_sid_a(text_a.as_ptr(), &mut out) };
        assert_eq!((ok, last_error()), (1, 0));
        // SAFETY: as above.
        assert_eq!(unsafe { core::slice::from_raw_parts(out, 16) }, &admins[..]);
        // SAFETY: as above.
        unsafe { ProcessHeap::free(out) };
        // Hex numbers: the prefix on any of them reads that number in hex.
        let hex_w = wide_z("S-1-0x5-0x20-0x220");
        let mut out: *mut u8 = core::ptr::null_mut();
        arm();
        assert_eq!(
            (
                unsafe { convert_string_sid_to_sid_w(hex_w.as_ptr(), &mut out) },
                last_error()
            ),
            (1, 0)
        );
        // SAFETY: as above.
        assert_eq!(unsafe { core::slice::from_raw_parts(out, 16) }, &admins[..]);
        // SAFETY: as above.
        unsafe { ProcessHeap::free(out) };
        for bad in [
            wide_z("S-1-5"),         // no sub-authority
            wide_z("X-1-5-32"),      // not an S-
            wide_z("S-1-5-32-544x"), // trailing garbage
            wide_z("S-1-5-32-"),     // a trailing '-'
            wide_z("S--1-5-32"),     // an empty revision
            wide_z(""),              // empty
        ] {
            let mut out: *mut u8 = core::ptr::null_mut();
            arm();
            let ok = unsafe { convert_string_sid_to_sid_w(bad.as_ptr(), &mut out) };
            assert_eq!(
                (ok, last_error(), out.is_null()),
                (0, 1337, true),
                "{bad:?}"
            );
        }
        let mut out: *mut u8 = core::ptr::null_mut();
        arm();
        let ok = unsafe { convert_string_sid_to_sid_w(core::ptr::null(), &mut out) };
        assert_eq!((ok, last_error()), (0, 87));
        arm();
        let ok = unsafe { convert_string_sid_to_sid_a(b"S-1-5\0".as_ptr(), &mut out) };
        assert_eq!((ok, last_error()), (0, 1337));
    }
}
