//! The SID helpers: validation, lengths, comparisons, allocation, copying and printing.

use super::*;

// --- SID helpers ------------------------------------------------------------------------

/// A SID's length in bytes, from its header `h` (revision, count, authority).
pub(crate) fn sid_len_of(h: &[u8]) -> usize {
    SID_HEADER + 4 * usize::from(h[1])
}

/// Whether a SID's header `h` is structurally valid.
pub(crate) fn sid_header_valid(h: &[u8]) -> bool {
    (h[0] & 0x0f) == SID_REVISION && h[1] <= SID_MAX_SUB_AUTHORITIES
}

/// The SID at `sid`, its header and its sub-authorities.
///
/// # Safety
///
/// `sid` is a readable SID; its count says how long it is.
pub(crate) unsafe fn sid_slice(sid: *const u8) -> &'static [u8] {
    // SAFETY: the caller's SID header is readable.
    let header = unsafe { bytes(sid, SID_HEADER) };
    // SAFETY: the SID holds its count's sub-authorities.
    unsafe { bytes(sid, sid_len_of(header)) }
}

/// RtlValidSid: whether the SID at `sid` is structurally valid.
#[unsafe(export_name = "f2k_export_RtlValidSid")]
pub unsafe extern "system" fn rtl_valid_sid(sid: *const u8) -> u32 {
    if sid.is_null() {
        return 0;
    }
    // SAFETY: the caller's SID, its header readable.
    u32::from(sid_header_valid(unsafe { bytes(sid, SID_HEADER) }))
}

/// RtlEqualSid: whether two SIDs are equal, byte for byte.
#[unsafe(export_name = "f2k_export_RtlEqualSid")]
pub unsafe extern "system" fn rtl_equal_sid(sid1: *const u8, sid2: *const u8) -> u32 {
    // SAFETY: the caller's two SIDs.
    let (a, b) = unsafe { (sid_slice(sid1), sid_slice(sid2)) };
    u32::from(a[0] == b[0] && a[1] == b[1] && a == b)
}

/// RtlEqualPrefixSid: whether two SIDs are equal except for the last sub-authority.
#[unsafe(export_name = "f2k_export_RtlEqualPrefixSid")]
pub unsafe extern "system" fn rtl_equal_prefix_sid(sid1: *const u8, sid2: *const u8) -> u32 {
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

/// RtlLengthRequiredSid: the bytes a SID of `count` sub-authorities takes.
#[unsafe(export_name = "f2k_export_RtlLengthRequiredSid")]
pub unsafe extern "system" fn rtl_length_required_sid(count: u32) -> u32 {
    (SID_HEADER + 4 * count as usize) as u32
}

/// RtlAllocateAndInitializeSid: a SID of `authority` and `count` sub-authorities (eight at most)
/// in a block of the process heap, its address written to `sid`.
#[unsafe(export_name = "f2k_export_RtlAllocateAndInitializeSid")]
pub unsafe extern "system" fn rtl_allocate_and_initialize_sid(
    authority: *const u8,
    count: u8,
    sub0: u32,
    sub1: u32,
    sub2: u32,
    sub3: u32,
    sub4: u32,
    sub5: u32,
    sub6: u32,
    sub7: u32,
    sid: *mut *mut u8,
) -> u32 {
    if count > 8 {
        return STATUS_INVALID_SID;
    }
    let Some(at) = heap_alloc(SID_HEADER + 4 * usize::from(count)) else {
        return STATUS_NO_MEMORY;
    };
    let subs = [sub0, sub1, sub2, sub3, sub4, sub5, sub6, sub7];
    // SAFETY: the block holds the SID; the caller's authority holds six bytes.
    unsafe {
        let out = bytes_mut(at as *mut u8, SID_HEADER + 4 * usize::from(count));
        out[0] = SID_REVISION;
        out[1] = count;
        out[2..SID_HEADER].copy_from_slice(bytes(authority, 6));
        for (index, sub) in subs.iter().enumerate().take(usize::from(count)) {
            out[SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4]
                .copy_from_slice(&sub.to_le_bytes());
        }
        sid.write_unaligned(at as *mut u8);
    }
    STATUS_SUCCESS
}

/// RtlInitializeSid: a SID's header (revision 1, the authority, the count) in `sid`; its
/// sub-authorities are set separately.
#[unsafe(export_name = "f2k_export_RtlInitializeSid")]
pub unsafe extern "system" fn rtl_initialize_sid(
    sid: *mut u8,
    authority: *const u8,
    count: u8,
) -> u32 {
    if count > SID_MAX_SUB_AUTHORITIES {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's SID header and authority.
    unsafe {
        let out = bytes_mut(sid, SID_HEADER);
        out[0] = SID_REVISION;
        out[1] = count;
        out[2..SID_HEADER].copy_from_slice(bytes(authority, 6));
    }
    STATUS_SUCCESS
}

/// RtlFreeSid: a SID RtlAllocateAndInitializeSid made, given back to the process heap; null on
/// success, the SID itself when the heap refused.
#[unsafe(export_name = "f2k_export_RtlFreeSid")]
pub unsafe extern "system" fn rtl_free_sid(sid: *mut u8) -> usize {
    if heap_free(sid as usize) {
        0
    } else {
        sid as usize
    }
}

/// RtlIdentifierAuthoritySid: the address of the SID's identifier authority.
#[unsafe(export_name = "f2k_export_RtlIdentifierAuthoritySid")]
pub unsafe extern "system" fn rtl_identifier_authority_sid(sid: *const u8) -> usize {
    sid as usize + 2
}

/// RtlSubAuthoritySid: the address of the SID's `index`'th sub-authority.
#[unsafe(export_name = "f2k_export_RtlSubAuthoritySid")]
pub unsafe extern "system" fn rtl_sub_authority_sid(sid: *const u8, index: u32) -> usize {
    sid as usize + SID_HEADER + 4 * index as usize
}

/// RtlSubAuthorityCountSid: the address of the SID's sub-authority count.
#[unsafe(export_name = "f2k_export_RtlSubAuthorityCountSid")]
pub unsafe extern "system" fn rtl_sub_authority_count_sid(sid: *const u8) -> usize {
    sid as usize + 1
}

/// RtlLengthSid: the SID's length in bytes.
#[unsafe(export_name = "f2k_export_RtlLengthSid")]
pub unsafe extern "system" fn rtl_length_sid(sid: *const u8) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    sid_len_of(unsafe { bytes(sid, SID_HEADER) }) as u32
}

/// RtlCopySid: the source SID copied into the destination buffer of `length` bytes.
#[unsafe(export_name = "f2k_export_RtlCopySid")]
pub unsafe extern "system" fn rtl_copy_sid(
    length: u32,
    destination: *mut u8,
    source: *const u8,
) -> u32 {
    // SAFETY: the caller's source SID.
    let source = unsafe { sid_slice(source) };
    if source.len() > length as usize {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the destination holds `length` bytes, the source its own.
    unsafe { bytes_mut(destination, source.len()) }.copy_from_slice(source);
    STATUS_SUCCESS
}

/// RtlCopySidAndAttributesArray: `count` SID_AND_ATTRIBUTES entries copied into the target array,
/// the SIDs themselves packed dword-aligned into the target SID buffer.
#[unsafe(export_name = "f2k_export_RtlCopySidAndAttributesArray")]
pub unsafe extern "system" fn rtl_copy_sid_and_attributes_array(
    count: u32,
    source: *const SidAndAttributes,
    target_buffer_size: u32,
    target_array: *mut SidAndAttributes,
    target_sid: *mut u8,
    next_target_sid: *mut *mut u8,
    remaining: *mut u32,
) -> u32 {
    let mut next = target_sid as usize;
    let mut left = target_buffer_size;
    for index in 0..count as usize {
        // SAFETY: the caller's arrays hold `count` entries.
        let entry = unsafe { &*source.add(index) };
        // SAFETY: the entry's SID.
        let sid = unsafe { sid_slice(entry.sid as *const u8) };
        let aligned = (sid.len() + 3) & !3;
        if sid.len() > left as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        left -= aligned as u32;
        // SAFETY: the target array holds `count` entries, the SID buffer `target_buffer_size`.
        unsafe {
            target_array.add(index).write_unaligned(SidAndAttributes {
                sid: next,
                attributes: entry.attributes,
            });
            bytes_mut(next as *mut u8, sid.len()).copy_from_slice(sid);
        }
        next += aligned;
    }
    // SAFETY: the caller's out parameters.
    unsafe {
        next_target_sid.write_unaligned(next as *mut u8);
        remaining.write_unaligned(left);
    }
    STATUS_SUCCESS
}

/// Append `value` to `units[..*len]` in decimal, or in hex (uppercase) when `hex`.
pub(crate) fn push_number(units: &mut [u16], len: &mut usize, mut value: u64, hex: bool) {
    let mut digits = [0u16; 20];
    let mut count = 0;
    loop {
        let digit = (value % if hex { 16 } else { 10 }) as u16;
        digits[count] = if digit < 10 {
            b'0' as u16 + digit
        } else {
            b'A' as u16 + digit - 10
        };
        count += 1;
        value /= if hex { 16 } else { 10 };
        if value == 0 {
            break;
        }
    }
    for index in (0..count).rev() {
        units[*len] = digits[index];
        *len += 1;
    }
}

/// The SID's printed form, "S-1-...", as UTF-16 units in `units[..*len]`: the authority in decimal
/// when it fits a dword, in hex otherwise, then one decimal sub-authority each.
pub(crate) fn sid_to_units(sid: &[u8], units: &mut [u16], len: &mut usize) {
    const S: &[u16] = &[b'S' as u16, b'-' as u16, b'1' as u16, b'-' as u16];
    units[*len..*len + 4].copy_from_slice(S);
    *len += 4;
    let authority = u64::from_be_bytes([0, 0, sid[2], sid[3], sid[4], sid[5], sid[6], sid[7]]);
    if sid[2] != 0 || sid[3] != 0 {
        push_number(units, len, authority, true);
    } else {
        push_number(units, len, authority as u32 as u64, false);
    }
    for index in 0..usize::from(sid[1]) {
        units[*len] = b'-' as u16;
        *len += 1;
        let at = SID_HEADER + 4 * index;
        push_number(
            units,
            len,
            u32::from_le_bytes(sid[at..at + 4].try_into().unwrap()) as u64,
            false,
        );
    }
}

/// RtlConvertSidToUnicodeString: the SID's printed form into `string`, the buffer allocated from
/// the process heap when `allocate` is set.
#[unsafe(export_name = "f2k_export_RtlConvertSidToUnicodeString")]
pub unsafe extern "system" fn rtl_convert_sid_to_unicode_string(
    string: *mut UnicodeString<usize>,
    sid: *const u8,
    allocate: u32,
) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    let header = unsafe { bytes(sid, SID_HEADER) };
    if !sid_header_valid(header) || header[0] != SID_REVISION {
        return STATUS_INVALID_SID;
    }
    // SAFETY: the SID holds its count's sub-authorities.
    let sid = unsafe { sid_slice(sid) };
    let mut units = [0u16; 256];
    let mut len = 0;
    sid_to_units(sid, &mut units, &mut len);
    // SAFETY: the caller's string.
    let out = unsafe { &mut *string };
    if allocate != 0 {
        let byte_count = (len + 1) * 2;
        let Some(buffer) = heap_alloc(byte_count) else {
            return STATUS_NO_MEMORY;
        };
        // SAFETY: the block holds `byte_count`, the units their own.
        unsafe {
            let target = bytes_mut(buffer as *mut u8, byte_count);
            for (index, unit) in units.iter().take(len + 1).enumerate() {
                target[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        out.buffer = buffer;
        out.maximum_length = byte_count as u16;
        out.length = (byte_count - 2) as u16;
    } else {
        let byte_count = len * 2;
        if byte_count >= out.maximum_length as usize {
            return STATUS_BUFFER_OVERFLOW;
        }
        // SAFETY: the string's buffer holds its maximum length.
        let target = unsafe { bytes_mut(out.buffer as *mut u8, byte_count) };
        for (index, unit) in units.iter().take(len).enumerate() {
            target[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
        }
        out.length = byte_count as u16;
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

    #[test]
    fn a_sid_validates_by_its_header() {
        let sid = admins();
        assert_eq!(unsafe { rtl_valid_sid(sid.as_ptr()) }, 1);
        assert_eq!(unsafe { rtl_valid_sid(core::ptr::null()) }, 0);
        let mut bad = sid;
        bad[0] = 2;
        assert_eq!(unsafe { rtl_valid_sid(bad.as_ptr()) }, 0);
        bad[0] = 0x11; // the low nibble is the revision
        assert_eq!(unsafe { rtl_valid_sid(bad.as_ptr()) }, 1);
        bad[1] = 16;
        assert_eq!(unsafe { rtl_valid_sid(bad.as_ptr()) }, 0);
    }

    #[test]
    fn sid_lengths_comparisons_and_pointers() {
        let sid = admins();
        let mut other = sid;
        other[15] = 45; // the last sub-authority's low byte
        assert_eq!(unsafe { rtl_length_sid(sid.as_ptr()) }, 16);
        assert_eq!(unsafe { rtl_length_required_sid(2) }, 16);
        assert_eq!(unsafe { rtl_equal_sid(sid.as_ptr(), sid.as_ptr()) }, 1);
        assert_eq!(unsafe { rtl_equal_sid(sid.as_ptr(), other.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rtl_equal_prefix_sid(sid.as_ptr(), other.as_ptr()) },
            1
        );
        other[11] = 31; // the first sub-authority differs
        assert_eq!(
            unsafe { rtl_equal_prefix_sid(sid.as_ptr(), other.as_ptr()) },
            0
        );
    }

    #[test]
    fn a_sid_allocates_initializes_copies_and_frees() {
        let mut out = core::ptr::null_mut();
        let status = unsafe {
            rtl_allocate_and_initialize_sid(
                NT_AUTHORITY.as_ptr(),
                2,
                32,
                544,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut out,
            )
        };
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(unsafe { sid_slice(out) }, &admins()[..]);
        assert_eq!(
            unsafe { rtl_identifier_authority_sid(out) },
            out as usize + 2
        );
        assert_eq!(
            unsafe { rtl_sub_authority_count_sid(out) },
            out as usize + 1
        );
        assert_eq!(unsafe { rtl_sub_authority_sid(out, 1) }, out as usize + 12);
        assert_eq!(dword((out as *const u8).wrapping_add(12)), 544);
        let mut dest = [0u8; 16];
        assert_eq!(
            unsafe { rtl_copy_sid(15, dest.as_mut_ptr(), out) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            unsafe { rtl_copy_sid(16, dest.as_mut_ptr(), out) },
            STATUS_SUCCESS
        );
        assert_eq!(&dest, &admins());
        assert_eq!(
            unsafe {
                rtl_allocate_and_initialize_sid(
                    NT_AUTHORITY.as_ptr(),
                    9,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    &mut out,
                )
            },
            STATUS_INVALID_SID
        );
        assert_eq!(unsafe { rtl_free_sid(out) }, 0);
        let mut sid = [0xFFu8; 16];
        assert_eq!(
            unsafe { rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 2) },
            STATUS_SUCCESS
        );
        assert_eq!(&sid[..8], &[1, 2, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&sid[8..], &[0xFF; 8]);
        assert_eq!(
            unsafe { rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 16) },
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn a_sid_prints_as_s_1_dash() {
        let sid = admins();
        let mut units = [0u16; 64];
        let mut len = 0;
        sid_to_units(&sid, &mut units, &mut len);
        let text: String = units[..len].iter().map(|&u| u as u8 as char).collect();
        assert_eq!(text, "S-1-5-32-544");
        // A 48-bit authority prints in hex, uppercase, no prefix; one that fits a dword in
        // decimal.
        let mut big = [0u8; 12];
        big[0] = 1;
        big[1] = 1;
        big[2..8].copy_from_slice(&[1, 0, 0, 0, 0, 0]);
        big[8..12].copy_from_slice(&7u32.to_le_bytes());
        let mut len = 0;
        sid_to_units(&big, &mut units, &mut len);
        let text: String = units[..len].iter().map(|&u| u as u8 as char).collect();
        assert_eq!(text, "S-1-10000000000-7");
        big[2..8].copy_from_slice(&[0, 0, 0, 1, 0x23, 0x45]);
        let mut len = 0;
        sid_to_units(&big, &mut units, &mut len);
        let text: String = units[..len].iter().map(|&u| u as u8 as char).collect();
        assert_eq!(text, "S-1-74565-7");
        // Through the export, into a caller buffer: 12 units, 24 bytes.
        let mut buffer = [0u16; 64];
        let mut string = UnicodeString::<usize> {
            length: 0,
            maximum_length: 128,
            buffer: buffer.as_mut_ptr() as usize,
        };
        assert_eq!(
            unsafe { rtl_convert_sid_to_unicode_string(&mut string, sid.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        assert_eq!(string.length, 24);
        let text: String = buffer[..12].iter().map(|&u| u as u8 as char).collect();
        assert_eq!(text, "S-1-5-32-544");
        // A buffer exactly the string's size overflows: room for the NUL is required.
        string.maximum_length = 24;
        assert_eq!(
            unsafe { rtl_convert_sid_to_unicode_string(&mut string, sid.as_ptr(), 0) },
            STATUS_BUFFER_OVERFLOW
        );
        // Allocation from the heap works too.
        let mut allocated = UnicodeString::<usize>::default();
        assert_eq!(
            unsafe { rtl_convert_sid_to_unicode_string(&mut allocated, sid.as_ptr(), 1) },
            STATUS_SUCCESS
        );
        assert_eq!(allocated.length, 24);
        assert_eq!(allocated.maximum_length, 26);
        let text: String = unsafe { bytes(allocated.buffer as *const u8, 26) }
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
            .collect();
        assert_eq!(text, "S-1-5-32-544\0");
        assert!(heap_free(allocated.buffer));
        let mut bad = sid;
        bad[0] = 7;
        assert_eq!(
            unsafe { rtl_convert_sid_to_unicode_string(&mut string, bad.as_ptr(), 0) },
            STATUS_INVALID_SID
        );
    }

    #[test]
    fn sid_and_attributes_arrays_copy_packed() {
        let admins = admins();
        let world = world();
        let source = [
            SidAndAttributes {
                sid: admins.as_ptr() as usize,
                attributes: 7,
            },
            SidAndAttributes {
                sid: world.as_ptr() as usize,
                attributes: 0,
            },
        ];
        let mut target = [SidAndAttributes::default(); 2];
        let mut buffer = [0u8; 64];
        let mut next = core::ptr::null_mut();
        let mut remaining = 0u32;
        assert_eq!(
            unsafe {
                rtl_copy_sid_and_attributes_array(
                    2,
                    source.as_ptr(),
                    64,
                    target.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    &mut next,
                    &mut remaining,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(target[0].attributes, 7);
        assert_eq!(
            unsafe { sid_slice(target[0].sid as *const u8) },
            &admins[..]
        );
        assert_eq!(unsafe { sid_slice(target[1].sid as *const u8) }, &world[..]);
        // The SIDs are packed dword-aligned: 16 then 12, so the next is 28 in and 36 left.
        assert_eq!(next as usize - buffer.as_ptr() as usize, 28);
        assert_eq!(remaining, 36);
        // A buffer too small for the second SID fails.
        let mut next = core::ptr::null_mut();
        let mut remaining = 0u32;
        assert_eq!(
            unsafe {
                rtl_copy_sid_and_attributes_array(
                    2,
                    source.as_ptr(),
                    20,
                    target.as_mut_ptr(),
                    buffer.as_mut_ptr(),
                    &mut next,
                    &mut remaining,
                )
            },
            STATUS_BUFFER_TOO_SMALL
        );
    }
}

