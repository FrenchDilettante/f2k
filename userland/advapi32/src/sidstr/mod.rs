//! The SID's string form and its parts, as a program that prints or parses a SID, asks for one
//! of its fields, copies or compares it, or builds one of the well-known ones makes them:
//! ConvertSidToStringSidA/W, ConvertStringSidToSidA/W, GetSidIdentifierAuthority,
//! GetSidSubAuthority, GetSidSubAuthorityCount, GetSidLengthRequired, CopySid, EqualPrefixSid,
//! IsWellKnownSid, CreateWellKnownSid and AllocateLocallyUniqueId.
//!
//! - [`parts`]: the field pointers, the length, the copy and the prefix comparison.
//!
//! The printed form is made by ntdll's conversion (RtlConvertSidToUnicodeString, through the
//! [`services`] seam, which allocates the wide string on the process heap), copied into a fresh
//! block for the caller; the A wrapper narrows that wide string. The parse is advapi32's own over
//! the string's units; the SID it makes is a block of the process heap, which the caller frees
//! with LocalFree or FreeSid. The field pointers, the length, the copy and the prefix comparison
//! are ntdll's Rtl* helpers too, each pass-through here; a failed one maps its status to the last
//! error and the call answers FALSE. The well-known SIDs are the public fixed table (types 0 to
//! 37); F2K has no domain SID, so the account types past them answer ERROR_INVALID_PARAMETER.
//! AllocateLocallyUniqueId hands ids out of advapi32's own counter: F2K serves no
//! locally-unique-id service, so there is none to call.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::nt::Luid;
// ERROR_INVALID_PARAMETER: a null argument.
use rtl::winerror::ERROR_INVALID_PARAMETER;

use crate::imports::{self as nt};
use crate::{caller_bytes, Out};

pub mod parts;

/// A SID's header: revision, sub-authority count, the six-byte identifier authority; then a
/// dword per sub-authority.
const SID_HEADER: usize = 8;
/// The most sub-authorities a SID holds.
const SID_MAX_SUB_AUTHORITIES: usize = 15;
/// STATUS_INVALID_SID, which rtl::status does not carry (the host stand-ins answer it).
#[cfg_attr(not(test), allow(dead_code))]
const STATUS_INVALID_SID: u32 = 0xC000_0078;

// --- The ntdll Rtl* SID helpers' seam ------------------------------------------------------
//
// Declared once here: as ntdll imports on the target, as stand-ins on the host.

#[cfg(all(target_arch = "x86", not(test)))]
#[allow(non_snake_case)]
mod raw {
    use rtl::string::UnicodeString;

    #[link(name = "ntdll", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn RtlConvertSidToUnicodeString(
            string: *mut UnicodeString,
            sid: *const u8,
            allocate: u32,
        ) -> u32;
        pub fn RtlFreeUnicodeString(string: *mut UnicodeString);
        pub fn RtlIdentifierAuthoritySid(sid: *const u8) -> usize;
        pub fn RtlSubAuthoritySid(sid: *const u8, index: u32) -> usize;
        pub fn RtlSubAuthorityCountSid(sid: *const u8) -> usize;
        pub fn RtlLengthRequiredSid(count: u32) -> u32;
        pub fn RtlCopySid(length: u32, destination: *mut u8, source: *const u8) -> u32;
        pub fn RtlEqualPrefixSid(sid1: *const u8, sid2: *const u8) -> u32;
    }
}

/// The host tests' stand-ins: the same helpers over the test's own buffers, answering the same
/// statuses (the string conversion formats and allocates on the stand-in heap).
#[cfg(test)]
#[allow(non_snake_case, clippy::missing_safety_doc)]
pub(crate) mod host {
    use rtl::status::{
        STATUS_BUFFER_OVERFLOW,
        STATUS_BUFFER_TOO_SMALL,
        STATUS_INVALID_PARAMETER,
        STATUS_NO_MEMORY,
        STATUS_SUCCESS,
    };
    use rtl::string::UnicodeString;

    use super::{SID_HEADER, SID_MAX_SUB_AUTHORITIES, STATUS_INVALID_SID};
    pub use crate::imports::host::{process_heap, RtlAllocateHeap, RtlFreeUnicodeString};

    /// The SID at `sid`, its header and its count's sub-authorities.
    ///
    /// # Safety
    ///
    /// `sid` is a readable SID; its count says how long it is.
    unsafe fn sid_slice(sid: *const u8) -> &'static [u8] {
        // SAFETY: the caller's SID header is readable.
        let header = unsafe { core::slice::from_raw_parts(sid, SID_HEADER) };
        // SAFETY: the SID holds its count's sub-authorities.
        unsafe { core::slice::from_raw_parts(sid, SID_HEADER + 4 * usize::from(header[1])) }
    }

    pub unsafe extern "system" fn RtlIdentifierAuthoritySid(sid: *const u8) -> usize {
        sid as usize + 2
    }

    pub unsafe extern "system" fn RtlSubAuthoritySid(sid: *const u8, index: u32) -> usize {
        sid as usize + SID_HEADER + 4 * index as usize
    }

    pub unsafe extern "system" fn RtlSubAuthorityCountSid(sid: *const u8) -> usize {
        sid as usize + 1
    }

    pub unsafe extern "system" fn RtlLengthRequiredSid(count: u32) -> u32 {
        (SID_HEADER + 4 * count as usize) as u32
    }

    pub unsafe extern "system" fn RtlEqualPrefixSid(sid1: *const u8, sid2: *const u8) -> u32 {
        // SAFETY: the caller's two SIDs.
        let (a, b) = unsafe { (sid_slice(sid1), sid_slice(sid2)) };
        let prefix = SID_HEADER + 4 * usize::from(a[1].min(b[1]).saturating_sub(1));
        u32::from(
            a[0] == b[0]
                && a[1] == b[1]
                && a[2..SID_HEADER] == b[2..SID_HEADER]
                && a[..prefix] == b[..prefix],
        )
    }

    pub unsafe extern "system" fn RtlCopySid(
        length: u32,
        destination: *mut u8,
        source: *const u8,
    ) -> u32 {
        if source.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        // SAFETY: the caller's source SID.
        let source = unsafe { sid_slice(source) };
        if source.len() > length as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        // SAFETY: the destination holds `length` bytes, the source its own.
        unsafe { core::ptr::copy_nonoverlapping(source.as_ptr(), destination, source.len()) };
        STATUS_SUCCESS
    }

    /// Append `value` to `units[..*len]` in decimal, or in uppercase hex when `hex`.
    fn push_number(units: &mut [u16], len: &mut usize, mut value: u64, hex: bool) {
        let radix = if hex { 16u64 } else { 10u64 };
        let mut digits = [0u16; 20];
        let mut count = 0;
        loop {
            let digit = (value % radix) as u16;
            digits[count] = if digit < 10 {
                b'0' as u16 + digit
            } else {
                b'A' as u16 + digit - 10
            };
            count += 1;
            value /= radix;
            if value == 0 {
                break;
            }
        }
        for index in (0..count).rev() {
            units[*len] = digits[index];
            *len += 1;
        }
    }

    /// The SID's printed form, "S-1-...", as UTF-16 units in `units`: the authority in decimal
    /// when its top two bytes are zero, in uppercase hex otherwise, then one decimal
    /// sub-authority each after a '-'. The units written.
    fn sid_to_units(sid: &[u8], units: &mut [u16]) -> usize {
        const S: [u16; 4] = [b'S' as u16, b'-' as u16, b'1' as u16, b'-' as u16];
        let mut len = 0;
        units[..4].copy_from_slice(&S);
        len += 4;
        let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
        if sid[2] != 0 || sid[3] != 0 {
            push_number(units, &mut len, authority, true);
        } else {
            push_number(units, &mut len, authority as u32 as u64, false);
        }
        for index in 0..usize::from(sid[1]) {
            units[len] = b'-' as u16;
            len += 1;
            let at = SID_HEADER + 4 * index;
            push_number(
                units,
                &mut len,
                u64::from(u32::from_le_bytes(sid[at..at + 4].try_into().unwrap())),
                false,
            );
        }
        len
    }

    pub unsafe extern "system" fn RtlConvertSidToUnicodeString(
        string: *mut UnicodeString,
        sid: *const u8,
        allocate: u32,
    ) -> u32 {
        if sid.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        // SAFETY: the caller's SID, its header readable.
        let header = unsafe { core::slice::from_raw_parts(sid, SID_HEADER) };
        if header[0] != 1 || usize::from(header[1]) > SID_MAX_SUB_AUTHORITIES {
            return STATUS_INVALID_SID;
        }
        // SAFETY: the SID holds its count's sub-authorities.
        let sid = unsafe { sid_slice(sid) };
        let mut units = [0u16; 256];
        let len = sid_to_units(sid, &mut units);
        // SAFETY: the caller's string.
        let out = unsafe { &mut *string };
        if allocate != 0 {
            let byte_count = (len + 1) * 2;
            // SAFETY: a plain allocation on the stand-in heap.
            let buffer = unsafe { RtlAllocateHeap(process_heap(), 0, byte_count) };
            if buffer.is_null() {
                return STATUS_NO_MEMORY;
            }
            // SAFETY: the block holds `byte_count` bytes, the units theirs.
            unsafe {
                let target = core::slice::from_raw_parts_mut(buffer, byte_count);
                for (index, unit) in units.iter().take(len + 1).enumerate() {
                    target[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
            out.buffer = buffer.cast();
            out.maximum_length = byte_count as u16;
            out.length = (byte_count - 2) as u16;
        } else {
            let byte_count = len * 2;
            if byte_count >= usize::from(out.maximum_length) {
                return STATUS_BUFFER_OVERFLOW;
            }
            // SAFETY: the string's buffer holds its room.
            unsafe {
                let target = core::slice::from_raw_parts_mut(out.buffer.cast::<u8>(), byte_count);
                for (index, unit) in units.iter().take(len).enumerate() {
                    target[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
            out.length = byte_count as u16;
        }
        STATUS_SUCCESS
    }
}

#[cfg(test)]
use host as raw;

/// The safe wrappers over the seam: ntdll's Rtl* SID helpers.
pub(crate) mod services {
    use rtl::status::NtStatus;
    use rtl::string::UnicodeString;

    use super::raw;

    /// RtlConvertSidToUnicodeString: the SID's printed form into `string`, its buffer allocated
    /// on the process heap when `allocate`.
    pub fn convert_sid_to_unicode_string(
        string: &mut UnicodeString,
        sid: *const u8,
        allocate: bool,
    ) -> NtStatus {
        // SAFETY: the string is the local's, the SID the caller's.
        NtStatus(unsafe { raw::RtlConvertSidToUnicodeString(string, sid, u32::from(allocate)) })
    }

    /// RtlFreeUnicodeString: a string the conversion allocated, freed.
    pub fn free_unicode_string(string: &mut UnicodeString) {
        // SAFETY: the string is one the conversion allocated.
        unsafe { raw::RtlFreeUnicodeString(string) }
    }

    /// RtlIdentifierAuthoritySid: the address of the SID's identifier authority.
    pub fn identifier_authority_sid(sid: *const u8) -> usize {
        // SAFETY: the caller's SID.
        unsafe { raw::RtlIdentifierAuthoritySid(sid) }
    }

    /// RtlSubAuthoritySid: the address of the SID's `index`'th sub-authority.
    pub fn sub_authority_sid(sid: *const u8, index: u32) -> usize {
        // SAFETY: the caller's SID.
        unsafe { raw::RtlSubAuthoritySid(sid, index) }
    }

    /// RtlSubAuthorityCountSid: the address of the SID's sub-authority count.
    pub fn sub_authority_count_sid(sid: *const u8) -> usize {
        // SAFETY: the caller's SID.
        unsafe { raw::RtlSubAuthorityCountSid(sid) }
    }

    /// RtlLengthRequiredSid: the bytes a SID of `count` sub-authorities takes.
    pub fn length_required_sid(count: u32) -> u32 {
        // SAFETY: no pointers.
        unsafe { raw::RtlLengthRequiredSid(count) }
    }

    /// RtlCopySid: the source SID copied into the destination buffer of `length` bytes.
    pub fn copy_sid(length: u32, destination: *mut u8, source: *const u8) -> NtStatus {
        // SAFETY: the caller's buffer and SID.
        NtStatus(unsafe { raw::RtlCopySid(length, destination, source) })
    }

    /// RtlEqualPrefixSid: whether the two SIDs are equal except for the last sub-authority.
    pub fn equal_prefix_sid(sid1: *const u8, sid2: *const u8) -> u32 {
        // SAFETY: the caller's two SIDs.
        unsafe { raw::RtlEqualPrefixSid(sid1, sid2) }
    }
}

// --- The SID's bytes ---------------------------------------------------------------------------

/// The bytes the SID at the start of `bytes` takes, by its count (none for a count past the
/// most, or bytes too few for it).
fn sid_of(bytes: &[u8]) -> Option<&[u8]> {
    let count = *bytes.get(1)? as usize;
    if count > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    bytes.get(..SID_HEADER + 4 * count)
}

/// The caller's SID at `sid`: none for null.
///
/// # Safety
///
/// `sid` is null or a SID the call may read (its count says how long).
unsafe fn caller_sid<'a>(sid: *const u8) -> Option<&'a [u8]> {
    if sid.is_null() {
        return None;
    }
    // SAFETY: a SID's header is eight bytes, its count among them.
    let header = unsafe { caller_bytes(sid, SID_HEADER) }?;
    let count = usize::from(header[1]).min(SID_MAX_SUB_AUTHORITIES);
    // SAFETY: the SID holds its count's sub-authorities.
    unsafe { caller_bytes(sid, SID_HEADER + 4 * count) }
}

// --- AllocateLocallyUniqueId -------------------------------------------------------------------

/// The locally unique ids advapi32 hands out: from past the reserved low range (the system
/// logon's id among them), the high part always zero.
static NEXT_LUID: AtomicU32 = AtomicU32::new(0x0002_0000);

/// AllocateLocallyUniqueId: a fresh locally unique id into `luid` (its low part from advapi32's
/// own counter, its high part zero); the last error untouched on success,
/// ERROR_INVALID_PARAMETER for a null place.
///
/// # Safety
///
/// `luid` is null or a LUID the call may write.
#[unsafe(export_name = "f2k_export_AllocateLocallyUniqueId")]
pub unsafe extern "system" fn allocate_locally_unique_id(luid: *mut Luid) -> u32 {
    // SAFETY: the caller's place for the id.
    let mut place = unsafe { Out::optional(luid) };
    let Some(place) = place.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let low = NEXT_LUID.fetch_add(1, Ordering::Relaxed);
    place.set(Luid {
        low_part: low,
        high_part: 0,
    });
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// AllocateLocallyUniqueId writes a fresh id (the low part one past the last, the high part
    /// zero), TRUE with the last error untouched; a null place is FALSE with
    /// ERROR_INVALID_PARAMETER (87).
    #[test]
    fn a_luid_is_handed_out() {
        let mut luid = Luid {
            low_part: 0xF2F2,
            high_part: -1,
        };
        arm();
        let ok = unsafe { allocate_locally_unique_id(&mut luid) };
        assert_eq!((ok, last_error()), (1, 0xF2F2));
        assert_eq!(luid.high_part, 0);
        assert_ne!(luid.low_part, 0);
        let first = luid.low_part;
        let ok = unsafe { allocate_locally_unique_id(&mut luid) };
        assert_eq!((ok, luid.low_part), (1, first + 1));
        arm();
        let ok = unsafe { allocate_locally_unique_id(core::ptr::null_mut()) };
        assert_eq!((ok, last_error()), (0, 87));
    }
}
