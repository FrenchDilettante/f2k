//! The security buffer helpers (`Rtl*` over security descriptors, ACLs, ACEs and SIDs): the
//! user-mode routines that read and write a caller's buffers only. Windows 2000's ntdll answers
//! them here; advapi32 and kernel32 build their security calls on them.
//!
//! The layouts are the public ones: a SID is a revision, a sub-authority count, a six-byte
//! identifier authority and one dword per sub-authority; an ACL is an eight-byte header followed
//! by its ACEs; an ACE is a four-byte header, a mask and its SID(s); a security descriptor is a
//! four-byte header followed by its owner, group, SACL and DACL — pointers in absolute form,
//! dword offsets from the descriptor in self-relative form.
//!
//! A few routines allocate from the process heap (the SID `RtlAllocateAndInitializeSid` makes, the
//! descriptor `RtlCopySecurityDescriptor` copies) and three reach the token services
//! (`RtlAdjustPrivilege`, `RtlNewSecurityGrantedAccess`, `RtlDefaultNpAcl`); in the host tests
//! those seams stand in (a host allocator, no services), so the tests pin the buffer logic.

use rtl::nt::UnicodeString;
use rtl::pod::Pod;
#[cfg_attr(test, allow(unused_imports))]
use rtl::status::{
    STATUS_BUFFER_OVERFLOW,
    STATUS_BUFFER_TOO_SMALL,
    STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER,
    STATUS_INVALID_PARAMETER_1,
    STATUS_INVALID_PARAMETER_2,
    STATUS_NOT_ALL_ASSIGNED,
    STATUS_NO_MEMORY,
    STATUS_PRIVILEGE_NOT_HELD,
    STATUS_REVISION_MISMATCH,
    STATUS_SUCCESS,
};

// Statuses the security helpers answer that rtl::status does not carry yet.
#[cfg(not(test))]
const STATUS_NO_TOKEN: u32 = 0xC000_007C;
const STATUS_INVALID_ACL: u32 = 0xC000_0077;
const STATUS_INVALID_SID: u32 = 0xC000_0078;
const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;
const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058;
const STATUS_ALLOTTED_SPACE_EXCEEDED: u32 = 0xC000_0099;
const STATUS_BAD_DESCRIPTOR_FORMAT: u32 = 0xC000_00E7;

// SID: revision 1, at most 15 sub-authorities, an 8-byte header.
const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const SID_HEADER: usize = 8;
// ACE types, the only compound type, and the object-ACE flag bits.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 6;
const SYSTEM_AUDIT_OBJECT_ACE_TYPE: u8 = 7;
const COMPOUND_ACE_IMPERSONATION: u16 = 1;
const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;
const VALID_INHERIT_FLAGS: u32 = 0x1F;
const SUCCESSFUL_ACCESS_ACE_FLAG: u32 = 0x40;
const FAILED_ACCESS_ACE_FLAG: u32 = 0x80;
// ACL revisions 2 to 4; an ACE list is appended at MAXULONG.
const MIN_ACL_REVISION: u32 = 2;
const MAX_ACL_REVISION: u32 = 4;
const ACL_REVISION: u32 = 2;
const ACL_REVISION3: u32 = 3;
const MAXULONG: u32 = u32::MAX;
// A security descriptor's revision, its control bits, the ones a caller may set, and the
// SECURITY_INFORMATION bits RtlValidRelativeSecurityDescriptor may require.
const SECURITY_DESCRIPTOR_REVISION: u8 = 1;
const SE_OWNER_DEFAULTED: u16 = 0x0001;
const SE_GROUP_DEFAULTED: u16 = 0x0002;
const SE_DACL_PRESENT: u16 = 0x0004;
const SE_DACL_DEFAULTED: u16 = 0x0008;
const SE_SACL_PRESENT: u16 = 0x0010;
const SE_SACL_DEFAULTED: u16 = 0x0020;
const SE_DACL_UNTRUSTED: u16 = 0x0040;
const SE_SERVER_SECURITY: u16 = 0x0080;
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_SACL_PROTECTED: u16 = 0x2000;
const SE_RM_CONTROL_VALID: u16 = 0x4000;
const SE_SELF_RELATIVE: u16 = 0x8000;
// The bits RtlSetControlSecurityDescriptor accepts as bits of interest; the present, defaulted,
// self-relative and RM bits are not settable through it.
const SE_VALID_CONTROL_BITS: u16 = SE_DACL_UNTRUSTED
    | SE_SERVER_SECURITY
    | SE_DACL_AUTO_INHERIT_REQ
    | SE_SACL_AUTO_INHERIT_REQ
    | SE_DACL_AUTO_INHERITED
    | SE_SACL_AUTO_INHERITED
    | SE_DACL_PROTECTED
    | SE_SACL_PROTECTED;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const GROUP_SECURITY_INFORMATION: u32 = 0x2;
const ACL_REVISION_INFORMATION: u32 = 1;
const ACL_SIZE_INFORMATION: u32 = 2;
// Well-known identifier authorities.
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
const WORLD_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 1];
// Access and token constants, used only by the token-touching exports in the target build:
// the right only SeSecurityPrivilege buys, the privilege attributes and number, TokenOwner,
// the pseudo-handles, well-known sub-authorities.
#[cfg(not(test))]
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
#[cfg(not(test))]
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
#[cfg(not(test))]
const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
#[cfg(not(test))]
const SE_SECURITY_PRIVILEGE: u32 = 26;
#[cfg(not(test))]
const PRIVILEGE_SET_ALL_NECESSARY: u32 = 1;
#[cfg(not(test))]
const TOKEN_OWNER: u32 = 4;
#[cfg(not(test))]
const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
#[cfg(not(test))]
const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
#[cfg(not(test))]
const SECURITY_WORLD_RID: u32 = 0;
#[cfg(not(test))]
const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;
#[cfg(not(test))]
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;
#[cfg(not(test))]
const DOMAIN_ALIAS_RID_ADMINS: u32 = 544;

/// An ACL: revision, spare byte, size in bytes, ACE count, spare word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acl {
    revision: u8,
    sbz1: u8,
    size: u16,
    ace_count: u16,
    sbz2: u16,
}
// SAFETY: eight bytes of integers, no padding, every bit pattern valid.
unsafe impl Pod for Acl {}

/// An ACE's header: type, flags, size in bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AceHeader {
    ace_type: u8,
    ace_flags: u8,
    ace_size: u16,
}
// SAFETY: four bytes of integers, no padding.
unsafe impl Pod for AceHeader {}

/// A SECURITY_DESCRIPTOR in absolute form: header, then owner, group, SACL, DACL pointers. `P`
/// is the pointer size (`u32` in a 32-bit process's memory).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityDescriptor<P = usize> {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: P,
    group: P,
    sacl: P,
    dacl: P,
}
// SAFETY: the 32-bit form is 20 bytes of integers, no padding.
unsafe impl Pod for SecurityDescriptor<u32> {}

/// A SECURITY_DESCRIPTOR_RELATIVE: the same header, the four components as dword offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityDescriptorRelative {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: u32,
    group: u32,
    sacl: u32,
    dacl: u32,
}
// SAFETY: 20 bytes of integers, no padding.
unsafe impl Pod for SecurityDescriptorRelative {}

/// A SID_AND_ATTRIBUTES: a SID pointer and its attributes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SidAndAttributes<P = usize> {
    sid: P,
    attributes: u32,
}
// SAFETY: the 32-bit form is 8 bytes of integers, no padding.
unsafe impl Pod for SidAndAttributes<u32> {}

/// A GENERIC_MAPPING: the four generic access rights.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenericMapping {
    generic_read: u32,
    generic_write: u32,
    generic_execute: u32,
    generic_all: u32,
}
// SAFETY: 16 bytes of integers, no padding.
unsafe impl Pod for GenericMapping {}

/// An RTL_ACE_DATA, one entry of the list RtlCreateAndSetSD builds a descriptor from.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AceData<P = usize> {
    ace_type: u8,
    inherit_flags: u8,
    ace_flags: u8,
    mask: u32,
    sid: P,
}

// --- Small readers over caller buffers -------------------------------------------------

/// The value of `T` at `at`, at any alignment.
fn read<T: Copy>(at: *const u8) -> T {
    // SAFETY: the caller's buffer holds a T at `at` (its contract), read unaligned.
    unsafe { (at as *const T).read_unaligned() }
}

/// Write `value` at `at`, at any alignment.
fn write<T: Copy>(at: *mut u8, value: T) {
    // SAFETY: the caller's buffer holds a T at `at` (its contract), written unaligned.
    unsafe { (at as *mut T).write_unaligned(value) }
}

/// The `n` bytes at `at`.
///
/// # Safety
///
/// `at` is readable for `n` bytes for the call.
unsafe fn bytes<'a>(at: *const u8, n: usize) -> &'a [u8] {
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(at, n) }
}

/// The `n` bytes at `at`, writable.
///
/// # Safety
///
/// `at` is writable for `n` bytes for the call, and nothing else uses them.
unsafe fn bytes_mut<'a>(at: *mut u8, n: usize) -> &'a mut [u8] {
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts_mut(at, n) }
}

/// The dword at `at`.
fn dword(at: *const u8) -> u32 {
    read::<u32>(at)
}

/// Write a dword at `at`.
fn set_dword(at: *mut u8, value: u32) {
    write(at, value);
}

/// The word at `at`.
fn word(at: *const u8) -> u16 {
    read::<u16>(at)
}

// --- The process heap and the system services: the target's, stand-ins in the host tests --

/// `size` bytes of the process heap, or none when the heap has no room.
#[cfg(not(test))]
fn heap_alloc(size: usize) -> Option<usize> {
    rtl::sys::process_heap().alloc(&rtl::sys::Native, 0, size)
}

/// Give a heap block back; whether the heap took it.
#[cfg(not(test))]
fn heap_free(at: usize) -> bool {
    rtl::sys::process_heap().free(&rtl::sys::Native, 0, at)
}

/// `size` bytes of the host's allocator in the tests, zeroed, the size kept before the block.
#[cfg(test)]
fn heap_alloc(size: usize) -> Option<usize> {
    let size = size.max(1);
    let layout = std::alloc::Layout::from_size_align(size + 8, 8).ok()?;
    // SAFETY: a nonzero layout.
    let block = unsafe { std::alloc::alloc_zeroed(layout) };
    if block.is_null() {
        return None;
    }
    // SAFETY: the block holds at least eight bytes.
    unsafe { (block as *mut usize).write(size) };
    Some(block as usize + 8)
}

/// Give a test heap block back.
#[cfg(test)]
fn heap_free(at: usize) -> bool {
    if at == 0 {
        return false;
    }
    // SAFETY: `at` is a block heap_alloc answered, not freed since.
    unsafe {
        let start = (at - 8) as *mut u8;
        let size = (start as *const usize).read();
        std::alloc::dealloc(
            start,
            std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
        );
    }
    true
}

/// A system service on the target, by its Windows 2000 number.
#[cfg(not(test))]
fn service(number: u32, args: &[u32]) -> u32 {
    // SAFETY: the service's arguments, laid out by the caller.
    unsafe { rtl::sys::system_service(number, args) }
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
#[cfg_attr(test, allow(dead_code))]
fn service(_number: u32, _args: &[u32]) -> u32 {
    unimplemented!("no system services on the host")
}

/// The address of `value`, as a service's argument block carries it.
#[cfg(not(test))]
fn address<T>(value: &T) -> u32 {
    core::ptr::from_ref(value) as u32
}

/// The address of `value`, for a service that writes it.
#[cfg(not(test))]
fn address_mut<T>(value: &mut T) -> u32 {
    core::ptr::from_mut(value) as u32
}

// --- SID helpers ------------------------------------------------------------------------

/// A SID's length in bytes, from its header `h` (revision, count, authority).
fn sid_len_of(h: &[u8]) -> usize {
    SID_HEADER + 4 * usize::from(h[1])
}

/// Whether a SID's header `h` is structurally valid.
fn sid_header_valid(h: &[u8]) -> bool {
    (h[0] & 0x0f) == SID_REVISION && h[1] <= SID_MAX_SUB_AUTHORITIES
}

/// The SID at `sid`, its header and its sub-authorities.
///
/// # Safety
///
/// `sid` is a readable SID; its count says how long it is.
unsafe fn sid_slice(sid: *const u8) -> &'static [u8] {
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
fn push_number(units: &mut [u16], len: &mut usize, mut value: u64, hex: bool) {
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
fn sid_to_units(sid: &[u8], units: &mut [u16], len: &mut usize) {
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

// --- ACL and ACE helpers ----------------------------------------------------------------

/// The ACL header at `at`.
fn acl_of(at: *const u8) -> Acl {
    read::<Acl>(at)
}

/// The ACE header at `at`.
fn ace_of(at: *const u8) -> AceHeader {
    read::<AceHeader>(at)
}

/// Whether the SID header at `at` is well formed; `at` must hold eight readable bytes.
fn sid_head_ok(at: usize) -> bool {
    // SAFETY: the caller's ACE holds the SID header at `at`.
    let h = unsafe { bytes(at as *const u8, SID_HEADER) };
    h[0] == SID_REVISION && h[1] <= SID_MAX_SUB_AUTHORITIES
}

/// Whether the ACL at `at` is structurally valid: its revision, size and every ACE in it.
fn valid_acl(at: *const u8) -> bool {
    let header = acl_of(at);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return false;
    }
    if !header.size.is_multiple_of(2) || header.size < 8 {
        return false;
    }
    let base = at as usize;
    let end = base + usize::from(header.size);
    let mut offset = 8;
    for _ in 0..header.ace_count {
        let ace = base + offset;
        if ace + 4 >= end {
            return false;
        }
        let head = ace_of(ace as *const u8);
        if !head.ace_size.is_multiple_of(2) || ace + usize::from(head.ace_size) > end {
            return false;
        }
        match head.ace_type {
            // A known ACE: header, mask, then the SID, all inside the ACE.
            0..=3 => {
                if !head.ace_size.is_multiple_of(4) || !sid_head_ok(ace + 8) {
                    return false;
                }
                // SAFETY: the ACE holds the SID's header.
                let len = sid_len_of(unsafe { bytes((ace + 8) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 8 + len {
                    return false;
                }
            }
            // A compound ACE: two SIDs after the compound type.
            4 => {
                if u32::from(header.revision) < ACL_REVISION3
                    || !head.ace_size.is_multiple_of(4)
                    || head.ace_size < 24
                    || word((ace + 8) as *const u8) != COMPOUND_ACE_IMPERSONATION
                    || !sid_head_ok(ace + 12)
                {
                    return false;
                }
                // SAFETY: the ACE holds the first SID.
                let len1 = sid_len_of(unsafe { bytes((ace + 12) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + len1 + 12 || !sid_head_ok(ace + 12 + len1) {
                    return false;
                }
                // SAFETY: the ACE holds the second SID's header.
                let len2 = sid_len_of(unsafe { bytes((ace + 12 + len1) as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + len1 + len2 {
                    return false;
                }
            }
            // An object ACE: its flags say which GUIDs it carries before the SID.
            5..=8 => {
                if u32::from(header.revision) < MAX_ACL_REVISION || !head.ace_size.is_multiple_of(4)
                {
                    return false;
                }
                let flags = dword((ace + 8) as *const u8);
                let mut guids = 0;
                if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
                    guids += 16;
                }
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
                    guids += 16;
                }
                let sid = ace + 12 + guids;
                if usize::from(head.ace_size) < 12 + guids + SID_HEADER || !sid_head_ok(sid) {
                    return false;
                }
                // SAFETY: the ACE holds the SID's header.
                let len = sid_len_of(unsafe { bytes(sid as *const u8, SID_HEADER) });
                if usize::from(head.ace_size) < 12 + guids + len {
                    return false;
                }
            }
            _ => {}
        }
        offset += usize::from(head.ace_size);
    }
    true
}

/// The first free byte in the ACL at `at`: `None` when the ACL is ill-formed, `Some(None)` when
/// it is full, else `Some(Some(address))`.
fn first_free(at: *const u8) -> Option<Option<usize>> {
    let header = acl_of(at);
    let base = at as usize;
    let end = base + usize::from(header.size);
    let mut offset = 8;
    for _ in 0..header.ace_count {
        let ace = base + offset;
        if ace >= end {
            return None;
        }
        offset += usize::from(ace_of(ace as *const u8).ace_size);
    }
    Some(if base + offset <= end {
        Some(base + offset)
    } else {
        None
    })
}

/// Shift the `to_size` bytes at `to` up by `from_size`, then copy `from` over the front.
///
/// # Safety
///
/// `to` holds `to_size + from_size` writable bytes, `from` holds `from_size` readable ones.
unsafe fn add_data(from: *const u8, from_size: usize, to: *mut u8, to_size: usize) {
    // SAFETY: the caller's contract; the ranges overlap, so a memmove.
    unsafe { core::ptr::copy(to, to.add(from_size), to_size) };
    // SAFETY: the caller's contract; the ranges no longer overlap.
    unsafe { core::ptr::copy_nonoverlapping(from, to, from_size) };
}

/// Remove `remove_size` bytes at `data` from a run of `total_size`, zeroing the tail.
///
/// # Safety
///
/// `data` holds `total_size` writable bytes.
unsafe fn delete_data(data: *mut u8, remove_size: usize, total_size: usize) {
    // SAFETY: the caller's contract; the ranges overlap, so a memmove.
    unsafe { core::ptr::copy(data.add(remove_size), data, total_size - remove_size) };
    // SAFETY: the caller's contract.
    unsafe { core::ptr::write_bytes(data.add(total_size - remove_size), 0, remove_size) };
}

/// RtlCreateAcl: an empty ACL of `length` bytes at `acl`, at `revision`.
#[unsafe(export_name = "f2k_export_RtlCreateAcl")]
pub unsafe extern "system" fn rtl_create_acl(acl: *mut u8, length: u32, revision: u32) -> u32 {
    if length < 8 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&revision) || length > 0xFFFF {
        return STATUS_INVALID_PARAMETER;
    }
    write(
        acl,
        Acl {
            revision: revision as u8,
            sbz1: 0,
            size: (length & 0xfffc) as u16,
            ace_count: 0,
            sbz2: 0,
        },
    );
    STATUS_SUCCESS
}

/// RtlValidAcl: whether the ACL at `acl` is structurally valid.
#[unsafe(export_name = "f2k_export_RtlValidAcl")]
pub unsafe extern "system" fn rtl_valid_acl(acl: *const u8) -> u32 {
    u32::from(valid_acl(acl))
}

/// RtlQueryInformationAcl: the ACL's revision or size information into `info`.
#[unsafe(export_name = "f2k_export_RtlQueryInformationAcl")]
pub unsafe extern "system" fn rtl_query_information_acl(
    acl: *const u8,
    info: *mut u8,
    info_length: u32,
    class: u32,
) -> u32 {
    let header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    match class {
        ACL_REVISION_INFORMATION => {
            if info_length < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            set_dword(info, u32::from(header.revision));
        }
        ACL_SIZE_INFORMATION => {
            if info_length < 12 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            let Some(free) = first_free(acl) else {
                return STATUS_INVALID_PARAMETER;
            };
            let in_use = free.map_or(usize::from(header.size), |at| at - acl as usize);
            set_dword(info, u32::from(header.ace_count));
            set_dword(info.wrapping_add(4), in_use as u32);
            set_dword(info.wrapping_add(8), header.size as u32 - in_use as u32);
        }
        _ => return STATUS_INVALID_INFO_CLASS,
    }
    STATUS_SUCCESS
}

/// RtlSetInformationAcl: set the ACL's revision (never lowered) from `info`.
#[unsafe(export_name = "f2k_export_RtlSetInformationAcl")]
pub unsafe extern "system" fn rtl_set_information_acl(
    acl: *mut u8,
    info: *const u8,
    info_length: u32,
    class: u32,
) -> u32 {
    let mut header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    match class {
        ACL_REVISION_INFORMATION => {
            if info_length < 4 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            let revision = dword(info);
            if revision < u32::from(header.revision) {
                return STATUS_INVALID_PARAMETER;
            }
            header.revision = revision as u8;
            write(acl, header);
        }
        _ => return STATUS_INVALID_INFO_CLASS,
    }
    STATUS_SUCCESS
}

/// RtlAddAce: the ACE list at `ace_list` inserted into the ACL at `starting_index` (the end when
/// `MAXULONG`).
#[unsafe(export_name = "f2k_export_RtlAddAce")]
pub unsafe extern "system" fn rtl_add_ace(
    acl: *mut u8,
    ace_revision: u32,
    starting_index: u32,
    ace_list: *const u8,
    ace_list_length: u32,
) -> u32 {
    if !valid_acl(acl) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_PARAMETER;
    };
    let header = acl_of(acl);
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    // Walk the list: well formed (it ends exactly at its length), each type allowed by the
    // revision.
    let list = ace_list as usize;
    let end = list + ace_list_length as usize;
    let mut at = list;
    let mut count = 0u32;
    while at < end {
        let head = ace_of(at as *const u8);
        match head.ace_type {
            0..=3 => {}
            4 if ace_revision < ACL_REVISION3 => return STATUS_INVALID_PARAMETER,
            5..=8 if ace_revision < MAX_ACL_REVISION => return STATUS_INVALID_PARAMETER,
            _ => {}
        }
        at += usize::from(head.ace_size);
        count += 1;
    }
    if at > end {
        return STATUS_INVALID_PARAMETER;
    }
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_list_length as usize > acl as usize + usize::from(header.size) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // The insert position: `starting_index` ACEs in, capped at the count.
    let mut position = acl as usize + 8;
    for _ in 0..starting_index.min(u32::from(header.ace_count)) {
        position += usize::from(ace_of(position as *const u8).ace_size);
    }
    // SAFETY: the list fits (checked above); the tail moves within the ACL.
    unsafe {
        add_data(
            ace_list,
            ace_list_length as usize,
            position as *mut u8,
            free - position,
        )
    };
    let mut header = acl_of(acl);
    header.ace_count += count as u16;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlDeleteAce: the ACE at `index` removed from the ACL.
#[unsafe(export_name = "f2k_export_RtlDeleteAce")]
pub unsafe extern "system" fn rtl_delete_ace(acl: *mut u8, index: u32) -> u32 {
    if !valid_acl(acl) {
        return STATUS_INVALID_PARAMETER;
    }
    let header = acl_of(acl);
    if index >= u32::from(header.ace_count) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_PARAMETER;
    };
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    let mut at = acl as usize + 8;
    for _ in 0..index {
        at += usize::from(ace_of(at as *const u8).ace_size);
    }
    let size = usize::from(ace_of(at as *const u8).ace_size);
    // SAFETY: the ACE is inside the ACL, the run up to the first free byte too.
    unsafe { delete_data(at as *mut u8, size, free - at) };
    let mut header = acl_of(acl);
    header.ace_count -= 1;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlGetAce: the address of the ACE at `index`, written to `ace`.
#[unsafe(export_name = "f2k_export_RtlGetAce")]
pub unsafe extern "system" fn rtl_get_ace(acl: *const u8, index: u32, ace: *mut *mut u8) -> u32 {
    let header = acl_of(acl);
    if !(MIN_ACL_REVISION..=MAX_ACL_REVISION).contains(&u32::from(header.revision)) {
        return STATUS_INVALID_PARAMETER;
    }
    if index >= u32::from(header.ace_count) {
        return STATUS_INVALID_PARAMETER;
    }
    let base = acl as usize;
    let end = base + usize::from(header.size);
    let mut at = base + 8;
    for _ in 0..index {
        if at >= end {
            return STATUS_INVALID_PARAMETER;
        }
        at += usize::from(ace_of(at as *const u8).ace_size);
    }
    if at >= end {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's out parameter.
    unsafe { ace.write_unaligned(at as *mut u8) };
    STATUS_SUCCESS
}

/// RtlFirstFreeAce: the address of the first free byte in the ACL, written to `first_free`;
/// false when the ACL is ill-formed.
#[unsafe(export_name = "f2k_export_RtlFirstFreeAce")]
pub unsafe extern "system" fn rtl_first_free_ace(acl: *const u8, out: *mut *mut u8) -> u32 {
    match first_free(acl) {
        None => 0,
        Some(free) => {
            // SAFETY: the caller's out parameter.
            unsafe { out.write_unaligned(free.map_or(core::ptr::null_mut(), |at| at as *mut u8)) };
            1
        }
    }
}

/// Add a known ACE (allowed, denied or audit) to the ACL at `acl`.
fn add_known_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
    new_type: u8,
) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    if unsafe { rtl_valid_sid(sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION || ace_revision > MAX_ACL_REVISION {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    let mut tested = flags & !VALID_INHERIT_FLAGS;
    if tested != 0 {
        if new_type == SYSTEM_AUDIT_ACE_TYPE {
            tested &= !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
        }
        if tested != 0 {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SID's header is readable.
    let sid_len = unsafe { sid_len_of(bytes(sid, SID_HEADER)) };
    let ace_size = 8 + sid_len;
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: new_type,
            ace_flags: flags as u8,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    // SAFETY: the ACE holds the SID; the source is the caller's SID.
    unsafe { bytes_mut((free + 8) as *mut u8, sid_len).copy_from_slice(sid_slice(sid)) };
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// Add an object ACE to the ACL at `acl`, the GUIDs it carries placed before the SID.
#[allow(clippy::too_many_arguments)]
fn add_known_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    new_type: u8,
) -> u32 {
    // SAFETY: the caller's SID, its header readable.
    if unsafe { rtl_valid_sid(sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION || ace_revision != MAX_ACL_REVISION {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    let mut tested = flags & !VALID_INHERIT_FLAGS;
    if tested != 0 {
        if new_type == SYSTEM_AUDIT_ACE_TYPE || new_type == SYSTEM_AUDIT_OBJECT_ACE_TYPE {
            tested &= !(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG);
        }
        if tested != 0 {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SID's header is readable.
    let sid_len = unsafe { sid_len_of(bytes(sid, SID_HEADER)) };
    let mut ace_size = 12 + sid_len;
    let mut object_flags = 0;
    if !object_type.is_null() {
        object_flags |= ACE_OBJECT_TYPE_PRESENT;
        ace_size += 16;
    }
    if !inherited_object_type.is_null() {
        object_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
        ace_size += 16;
    }
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: new_type,
            ace_flags: flags as u8,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    set_dword((free + 8) as *mut u8, object_flags);
    let mut at = free + 12;
    // SAFETY: the caller's GUIDs hold 16 bytes each; the ACE holds them and the SID.
    unsafe {
        if !object_type.is_null() {
            bytes_mut(at as *mut u8, 16).copy_from_slice(bytes(object_type, 16));
            at += 16;
        }
        if !inherited_object_type.is_null() {
            bytes_mut(at as *mut u8, 16).copy_from_slice(bytes(inherited_object_type, 16));
            at += 16;
        }
        bytes_mut(at as *mut u8, sid_len).copy_from_slice(sid_slice(sid));
    }
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

/// RtlAddAccessAllowedAce: an allowed ACE for `sid` appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedAce")]
pub unsafe extern "system" fn rtl_add_access_allowed_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, 0, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
}

/// RtlAddAccessAllowedAceEx: as RtlAddAccessAllowedAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedAceEx")]
pub unsafe extern "system" fn rtl_add_access_allowed_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
}

/// RtlAddAccessAllowedObjectAce: an allowed object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAccessAllowedObjectAce")]
pub unsafe extern "system" fn rtl_add_access_allowed_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_ALLOWED_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddAccessDeniedAce: a denied ACE for `sid` appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedAce")]
pub unsafe extern "system" fn rtl_add_access_denied_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, 0, mask, sid, ACCESS_DENIED_ACE_TYPE)
}

/// RtlAddAccessDeniedAceEx: as RtlAddAccessDeniedAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedAceEx")]
pub unsafe extern "system" fn rtl_add_access_denied_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    sid: *const u8,
) -> u32 {
    add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_DENIED_ACE_TYPE)
}

/// RtlAddAccessDeniedObjectAce: a denied object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAccessDeniedObjectAce")]
pub unsafe extern "system" fn rtl_add_access_denied_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
) -> u32 {
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, ACCESS_DENIED_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            ACCESS_DENIED_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddAuditAccessAce: an audit ACE appended, its success/failure flags from the booleans.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessAce")]
pub unsafe extern "system" fn rtl_add_audit_access_ace(
    acl: *mut u8,
    ace_revision: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    let mut flags = 0;
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
}

/// RtlAddAuditAccessAceEx: as RtlAddAuditAccessAce, with inherit flags.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessAceEx")]
pub unsafe extern "system" fn rtl_add_audit_access_ace_ex(
    acl: *mut u8,
    ace_revision: u32,
    mut flags: u32,
    mask: u32,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
}

/// RtlAddAuditAccessObjectAce: an audit object ACE appended; with no GUIDs, a plain ACE.
#[unsafe(export_name = "f2k_export_RtlAddAuditAccessObjectAce")]
pub unsafe extern "system" fn rtl_add_audit_access_object_ace(
    acl: *mut u8,
    ace_revision: u32,
    mut flags: u32,
    mask: u32,
    object_type: *const u8,
    inherited_object_type: *const u8,
    sid: *const u8,
    audit_success: u32,
    audit_failure: u32,
) -> u32 {
    if audit_success != 0 {
        flags |= SUCCESSFUL_ACCESS_ACE_FLAG;
    }
    if audit_failure != 0 {
        flags |= FAILED_ACCESS_ACE_FLAG;
    }
    if object_type.is_null() && inherited_object_type.is_null() {
        add_known_ace(acl, ace_revision, flags, mask, sid, SYSTEM_AUDIT_ACE_TYPE)
    } else {
        add_known_object_ace(
            acl,
            ace_revision,
            flags,
            mask,
            object_type,
            inherited_object_type,
            sid,
            SYSTEM_AUDIT_OBJECT_ACE_TYPE,
        )
    }
}

/// RtlAddCompoundAce: a compound ACE of the server and client SIDs appended to the ACL.
#[unsafe(export_name = "f2k_export_RtlAddCompoundAce")]
pub unsafe extern "system" fn rtl_add_compound_ace(
    acl: *mut u8,
    ace_revision: u32,
    compound_type: u8,
    mask: u32,
    server_sid: *const u8,
    client_sid: *const u8,
) -> u32 {
    // SAFETY: the caller's two SIDs, their headers readable.
    if unsafe { rtl_valid_sid(server_sid) } == 0 || unsafe { rtl_valid_sid(client_sid) } == 0 {
        return STATUS_INVALID_SID;
    }
    let header = acl_of(acl);
    if u32::from(header.revision) > MAX_ACL_REVISION
        || !(ACL_REVISION3..=MAX_ACL_REVISION).contains(&ace_revision)
    {
        return STATUS_REVISION_MISMATCH;
    }
    let new_revision = u32::from(header.revision).max(ace_revision) as u8;
    if !valid_acl(acl) {
        return STATUS_INVALID_ACL;
    }
    let Some(free) = first_free(acl) else {
        return STATUS_INVALID_ACL;
    };
    // SAFETY: the SIDs' headers are readable.
    let server_len = unsafe { sid_len_of(bytes(server_sid, SID_HEADER)) };
    let client_len = unsafe { sid_len_of(bytes(client_sid, SID_HEADER)) };
    let ace_size = 12 + client_len + server_len;
    let free = free.unwrap_or(acl as usize + usize::from(header.size));
    if free + ace_size > acl as usize + usize::from(header.size) {
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }
    write(
        free as *mut u8,
        AceHeader {
            ace_type: ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            ace_flags: 0,
            ace_size: ace_size as u16,
        },
    );
    set_dword((free + 4) as *mut u8, mask);
    write((free + 8) as *mut u8, compound_type as u16);
    write((free + 10) as *mut u8, 0u16);
    // SAFETY: the ACE holds both SIDs; the sources are the caller's.
    unsafe {
        bytes_mut((free + 12) as *mut u8, server_len).copy_from_slice(sid_slice(server_sid));
        bytes_mut((free + 12 + server_len) as *mut u8, client_len)
            .copy_from_slice(sid_slice(client_sid));
    }
    let mut header = acl_of(acl);
    header.ace_count += 1;
    header.revision = new_revision;
    write(acl, header);
    STATUS_SUCCESS
}

// --- Security descriptor helpers ----------------------------------------------------------

/// The control word of the SD at `at`.
fn sd_control(at: *const u8) -> u16 {
    word(at.wrapping_add(2))
}

/// The four component fields of the SD at `at`: dword offsets when self-relative, pointers
/// otherwise (read in the form the control bits say, so a relative SD is not over-read).
fn sd_fields(at: *const u8) -> [usize; 4] {
    if sd_control(at) & SE_SELF_RELATIVE != 0 {
        let rel: SecurityDescriptorRelative = read(at);
        [
            rel.owner as usize,
            rel.group as usize,
            rel.sacl as usize,
            rel.dacl as usize,
        ]
    } else {
        let abs: SecurityDescriptor = read(at);
        [abs.owner, abs.group, abs.sacl, abs.dacl]
    }
}

/// The address of the component `field` of the SD at `base`: an offset when self-relative.
fn sd_addr(base: usize, field: usize, self_relative: bool) -> usize {
    if self_relative {
        base + field
    } else {
        field
    }
}

/// The SD's components: their addresses and their long-aligned sizes (zero when absent). The
/// fields are owner, group, SACL, DACL; the first two are SIDs, the last two ACLs.
fn query_sd(at: *const u8) -> ([usize; 4], [usize; 4]) {
    let self_relative = sd_control(at) & SE_SELF_RELATIVE != 0;
    let base = at as usize;
    let fields = sd_fields(at);
    let mut addrs = [0usize; 4];
    let mut sizes = [0usize; 4];
    for index in 0..4 {
        if fields[index] != 0 {
            let addr = sd_addr(base, fields[index], self_relative);
            addrs[index] = addr;
            // SAFETY: the component's header is readable.
            let len = unsafe {
                if index < 2 {
                    sid_len_of(bytes(addr as *const u8, SID_HEADER))
                } else {
                    usize::from(acl_of(addr as *const u8).size)
                }
            };
            sizes[index] = (len + 3) & !3;
        }
    }
    (addrs, sizes)
}

/// Validate an offset into a self-relative SD of `length` bytes holding at least `min` bytes:
/// the room left, or none when the offset is inside the header, past the end, short or
/// unaligned.
fn sd_offset_ok(offset: u32, length: u32, min: u32) -> Option<u32> {
    if offset < 20 || offset >= length || length - offset < min || !offset.is_multiple_of(4) {
        return None;
    }
    Some(length - offset)
}

/// RtlCreateSecurityDescriptor: an empty absolute SD at `sd`, at `revision` (1).
#[unsafe(export_name = "f2k_export_RtlCreateSecurityDescriptor")]
pub unsafe extern "system" fn rtl_create_security_descriptor(sd: *mut u8, revision: u32) -> u32 {
    if revision != u32::from(SECURITY_DESCRIPTOR_REVISION) {
        return STATUS_UNKNOWN_REVISION;
    }
    // SAFETY: the caller's buffer holds a SECURITY_DESCRIPTOR.
    unsafe { core::ptr::write_bytes(sd, 0, core::mem::size_of::<SecurityDescriptor>()) };
    write(
        sd,
        SecurityDescriptor::<usize> {
            revision: SECURITY_DESCRIPTOR_REVISION,
            ..Default::default()
        },
    );
    STATUS_SUCCESS
}

/// RtlValidSecurityDescriptor: whether the SD at `sd` is structurally valid.
#[unsafe(export_name = "f2k_export_RtlValidSecurityDescriptor")]
pub unsafe extern "system" fn rtl_valid_security_descriptor(sd: *const u8) -> u32 {
    if read::<u8>(sd) != SECURITY_DESCRIPTOR_REVISION {
        return 0;
    }
    let self_relative = sd_control(sd) & SE_SELF_RELATIVE != 0;
    let base = sd as usize;
    for (index, field) in sd_fields(sd).iter().enumerate() {
        if *field == 0 {
            continue;
        }
        let at = sd_addr(base, *field, self_relative);
        // SAFETY: the component is the caller's.
        let ok = unsafe {
            if index < 2 {
                rtl_valid_sid(at as *const u8) == 1
            } else {
                valid_acl(at as *const u8)
            }
        };
        if !ok {
            return 0;
        }
    }
    1
}

/// RtlValidRelativeSecurityDescriptor: whether the self-relative SD of `length` bytes at `sd`
/// holds its components within its buffer, and the ones `required` names.
#[unsafe(export_name = "f2k_export_RtlValidRelativeSecurityDescriptor")]
pub unsafe extern "system" fn rtl_valid_relative_security_descriptor(
    sd: *const u8,
    length: u32,
    required: u32,
) -> u32 {
    if length < 20 {
        return 0;
    }
    let rel: SecurityDescriptorRelative = read(sd);
    if rel.revision != SECURITY_DESCRIPTOR_REVISION || rel.control & SE_SELF_RELATIVE == 0 {
        return 0;
    }
    let base = sd as usize;
    for (index, offset) in [rel.owner, rel.group].iter().enumerate() {
        if *offset == 0 {
            if required & [OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION][index] != 0 {
                return 0;
            }
            continue;
        }
        let Some(max) = sd_offset_ok(*offset, length, SID_HEADER as u32) else {
            return 0;
        };
        let sid = base + *offset as usize;
        if !sid_head_ok(sid) {
            return 0;
        }
        // SAFETY: the SD holds the SID's header.
        let len = sid_len_of(unsafe { bytes(sid as *const u8, SID_HEADER) });
        if max < len as u32 {
            return 0;
        }
    }
    for (index, offset) in [rel.sacl, rel.dacl].iter().enumerate() {
        let present = [SE_SACL_PRESENT, SE_DACL_PRESENT][index];
        if rel.control & present == 0 || *offset == 0 {
            continue;
        }
        let Some(max) = sd_offset_ok(*offset, length, 8) else {
            return 0;
        };
        let acl = base + *offset as usize;
        if max < u32::from(acl_of(acl as *const u8).size) || !valid_acl(acl as *const u8) {
            return 0;
        }
    }
    1
}

/// RtlLengthSecurityDescriptor: the bytes the SD at `sd` takes, its components aligned.
#[unsafe(export_name = "f2k_export_RtlLengthSecurityDescriptor")]
pub unsafe extern "system" fn rtl_length_security_descriptor(sd: *const u8) -> u32 {
    let base = if sd_control(sd) & SE_SELF_RELATIVE != 0 {
        core::mem::size_of::<SecurityDescriptorRelative>()
    } else {
        core::mem::size_of::<SecurityDescriptor>()
    };
    let (_, sizes) = query_sd(sd);
    (base + sizes.iter().sum::<usize>()) as u32
}

/// RtlGetControlSecurityDescriptor: the SD's control word and revision out.
#[unsafe(export_name = "f2k_export_RtlGetControlSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_control_security_descriptor(
    sd: *const u8,
    control: *mut u16,
    revision: *mut u32,
) -> u32 {
    let rev = read::<u8>(sd);
    // SAFETY: the caller's out parameters; the revision is always written.
    unsafe { revision.write_unaligned(u32::from(rev)) };
    if rev != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    // SAFETY: the caller's out parameter.
    unsafe { control.write_unaligned(sd_control(sd)) };
    STATUS_SUCCESS
}

/// RtlSetControlSecurityDescriptor: the control bits of `interest` set to `to_set`.
#[unsafe(export_name = "f2k_export_RtlSetControlSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_control_security_descriptor(
    sd: *mut u8,
    interest: u16,
    to_set: u16,
) -> u32 {
    if interest & !SE_VALID_CONTROL_BITS != 0 || to_set & !interest != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let at = sd.wrapping_add(2);
    write(at, (word(at) & !interest) | to_set);
    STATUS_SUCCESS
}

/// RtlSetAttributesSecurityDescriptor: set the control bits (no bit can be cleared through it),
/// the SD's revision out.
#[unsafe(export_name = "f2k_export_RtlSetAttributesSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_attributes_security_descriptor(
    sd: *mut u8,
    control: u16,
    revision: *mut u32,
) -> u32 {
    let rev = read::<u8>(sd);
    // SAFETY: the caller's out parameter; the revision is always written.
    unsafe { revision.write_unaligned(u32::from(rev)) };
    if rev != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let bits = control & SE_VALID_CONTROL_BITS;
    rtl_set_control_security_descriptor(sd, bits, bits)
}

/// Set the DACL (`dacl` true) or SACL of the absolute SD at `sd`.
fn set_acl_sd(
    sd: *mut u8,
    dacl: bool,
    present_bit: u16,
    defaulted_bit: u16,
    present: u32,
    acl: *const u8,
    defaulted: u32,
) -> u32 {
    let mut view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    if view.control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if present != 0 {
        view.control |= present_bit;
        if dacl {
            view.dacl = acl as usize;
        } else {
            view.sacl = acl as usize;
        }
        view.control &= !defaulted_bit;
        if defaulted != 0 {
            view.control |= defaulted_bit;
        }
    } else {
        view.control &= !present_bit;
    }
    write(sd, view);
    STATUS_SUCCESS
}

/// Get the DACL (`dacl` true) or SACL of the SD at `sd`.
fn get_acl_sd(
    sd: *const u8,
    dacl: bool,
    present_bit: u16,
    defaulted_bit: u16,
    present: *mut u32,
    acl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    let view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let is_present = view.control & present_bit != 0;
    // SAFETY: the caller's out parameter.
    unsafe { present.write_unaligned(u32::from(is_present)) };
    if is_present {
        let self_relative = view.control & SE_SELF_RELATIVE != 0;
        let field = if dacl { view.dacl } else { view.sacl };
        let addr = sd_addr(sd as usize, field, self_relative);
        // SAFETY: the caller's out parameters.
        unsafe {
            acl.write_unaligned(addr as *mut u8);
            defaulted.write_unaligned(u32::from(view.control & defaulted_bit != 0));
        }
    }
    STATUS_SUCCESS
}

/// Set the owner (`owner` true) or group of the absolute SD at `sd`.
fn set_sid_sd(sd: *mut u8, owner: bool, defaulted_bit: u16, sid: *const u8, defaulted: u32) -> u32 {
    let mut view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    if view.control & SE_SELF_RELATIVE != 0 {
        return STATUS_INVALID_SECURITY_DESCR;
    }
    if owner {
        view.owner = sid as usize;
    } else {
        view.group = sid as usize;
    }
    view.control &= !defaulted_bit;
    if defaulted != 0 {
        view.control |= defaulted_bit;
    }
    write(sd, view);
    STATUS_SUCCESS
}

/// Get the owner (`owner` true) or group of the SD at `sd`.
fn get_sid_sd(
    sd: *const u8,
    owner: bool,
    defaulted_bit: u16,
    sid: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    let view: SecurityDescriptor = read(sd);
    if view.revision != SECURITY_DESCRIPTOR_REVISION {
        return STATUS_UNKNOWN_REVISION;
    }
    let self_relative = view.control & SE_SELF_RELATIVE != 0;
    let field = if owner { view.owner } else { view.group };
    let addr = sd_addr(sd as usize, field, self_relative);
    // SAFETY: the caller's out parameters.
    unsafe {
        sid.write_unaligned(addr as *mut u8);
        defaulted.write_unaligned(u32::from(view.control & defaulted_bit != 0));
    }
    STATUS_SUCCESS
}

/// RtlSetDaclSecurityDescriptor: set the absolute SD's DACL.
#[unsafe(export_name = "f2k_export_RtlSetDaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_dacl_security_descriptor(
    sd: *mut u8,
    present: u32,
    dacl: *mut u8,
    defaulted: u32,
) -> u32 {
    set_acl_sd(
        sd,
        true,
        SE_DACL_PRESENT,
        SE_DACL_DEFAULTED,
        present,
        dacl,
        defaulted,
    )
}

/// RtlGetDaclSecurityDescriptor: get the SD's DACL.
#[unsafe(export_name = "f2k_export_RtlGetDaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_dacl_security_descriptor(
    sd: *const u8,
    present: *mut u32,
    dacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_acl_sd(
        sd,
        true,
        SE_DACL_PRESENT,
        SE_DACL_DEFAULTED,
        present,
        dacl,
        defaulted,
    )
}

/// RtlSetSaclSecurityDescriptor: set the absolute SD's SACL.
#[unsafe(export_name = "f2k_export_RtlSetSaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_sacl_security_descriptor(
    sd: *mut u8,
    present: u32,
    sacl: *mut u8,
    defaulted: u32,
) -> u32 {
    set_acl_sd(
        sd,
        false,
        SE_SACL_PRESENT,
        SE_SACL_DEFAULTED,
        present,
        sacl,
        defaulted,
    )
}

/// RtlGetSaclSecurityDescriptor: get the SD's SACL.
#[unsafe(export_name = "f2k_export_RtlGetSaclSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_sacl_security_descriptor(
    sd: *const u8,
    present: *mut u32,
    sacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_acl_sd(
        sd,
        false,
        SE_SACL_PRESENT,
        SE_SACL_DEFAULTED,
        present,
        sacl,
        defaulted,
    )
}

/// RtlSetOwnerSecurityDescriptor: set the absolute SD's owner.
#[unsafe(export_name = "f2k_export_RtlSetOwnerSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_owner_security_descriptor(
    sd: *mut u8,
    owner: *const u8,
    defaulted: u32,
) -> u32 {
    set_sid_sd(sd, true, SE_OWNER_DEFAULTED, owner, defaulted)
}

/// RtlGetOwnerSecurityDescriptor: get the SD's owner.
#[unsafe(export_name = "f2k_export_RtlGetOwnerSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_owner_security_descriptor(
    sd: *const u8,
    owner: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_sid_sd(sd, true, SE_OWNER_DEFAULTED, owner, defaulted)
}

/// RtlSetGroupSecurityDescriptor: set the absolute SD's group.
#[unsafe(export_name = "f2k_export_RtlSetGroupSecurityDescriptor")]
pub unsafe extern "system" fn rtl_set_group_security_descriptor(
    sd: *mut u8,
    group: *const u8,
    defaulted: u32,
) -> u32 {
    set_sid_sd(sd, false, SE_GROUP_DEFAULTED, group, defaulted)
}

/// RtlGetGroupSecurityDescriptor: get the SD's group.
#[unsafe(export_name = "f2k_export_RtlGetGroupSecurityDescriptor")]
pub unsafe extern "system" fn rtl_get_group_security_descriptor(
    sd: *const u8,
    group: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    get_sid_sd(sd, false, SE_GROUP_DEFAULTED, group, defaulted)
}

/// RtlGetSecurityDescriptorRMControl: the RM control byte out, when the valid bit is set.
#[unsafe(export_name = "f2k_export_RtlGetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn rtl_get_security_descriptor_rm_control(
    sd: *const u8,
    rm_control: *mut u8,
) -> u32 {
    let control = sd_control(sd);
    // SAFETY: the caller's out parameter.
    unsafe {
        rm_control.write_unaligned(if control & SE_RM_CONTROL_VALID != 0 {
            read::<u8>(sd.wrapping_add(1))
        } else {
            0
        })
    };
    u32::from(control & SE_RM_CONTROL_VALID != 0)
}

/// RtlSetSecurityDescriptorRMControl: set or clear the RM control byte and its valid bit.
#[unsafe(export_name = "f2k_export_RtlSetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn rtl_set_security_descriptor_rm_control(
    sd: *mut u8,
    rm_control: *const u8,
) {
    let at = sd.wrapping_add(2);
    if !rm_control.is_null() {
        write(at, word(at) | SE_RM_CONTROL_VALID);
        // SAFETY: the caller's byte.
        write(sd.wrapping_add(1), read::<u8>(rm_control));
    } else {
        write(at, word(at) & !SE_RM_CONTROL_VALID);
        write(sd.wrapping_add(1), 0u8);
    }
}

/// RtlMakeSelfRelativeSD: a copy of the SD at `sd` (either form) in self-relative form in
/// `out`, whose size is in `buffer_length` (the required size out, when too small).
#[unsafe(export_name = "f2k_export_RtlMakeSelfRelativeSD")]
pub unsafe extern "system" fn rtl_make_self_relative_sd(
    sd: *const u8,
    out: *mut u8,
    buffer_length: *mut u32,
) -> u32 {
    let (addrs, sizes) = query_sd(sd);
    let header = core::mem::size_of::<SecurityDescriptorRelative>();
    let allocation = header + sizes.iter().sum::<usize>();
    // SAFETY: the caller's size.
    if allocation > unsafe { *buffer_length } as usize {
        // SAFETY: the caller's size.
        unsafe { buffer_length.write_unaligned(allocation as u32) };
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the out buffer holds `allocation` bytes.
    unsafe {
        core::ptr::write_bytes(out, 0, allocation);
        // The header: revision, sbz1, control.
        core::ptr::copy_nonoverlapping(sd, out, 4);
        let mut field = out as usize + header;
        // SACL, DACL, owner, group, in that order, at dword offsets 12, 16, 4, 8.
        for (index, offset) in [(2usize, 12usize), (3, 16), (0, 4), (1, 8)] {
            let at = out.wrapping_add(offset);
            if sizes[index] > 0 {
                core::ptr::copy_nonoverlapping(
                    addrs[index] as *const u8,
                    field as *mut u8,
                    sizes[index],
                );
                write(at, (field - out as usize) as u32);
                field += sizes[index];
            } else {
                write(at, 0u32);
            }
        }
        let at = out.wrapping_add(2);
        write(at, word(at) | SE_SELF_RELATIVE);
    }
    STATUS_SUCCESS
}

/// RtlAbsoluteToSelfRelativeSD: as RtlMakeSelfRelativeSD, for an absolute SD only.
#[unsafe(export_name = "f2k_export_RtlAbsoluteToSelfRelativeSD")]
pub unsafe extern "system" fn rtl_absolute_to_self_relative_sd(
    sd: *const u8,
    out: *mut u8,
    buffer_length: *mut u32,
) -> u32 {
    if sd_control(sd) & SE_SELF_RELATIVE != 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    rtl_make_self_relative_sd(sd, out, buffer_length)
}

/// RtlSelfRelativeToAbsoluteSD: the self-relative SD at `sd` expanded into absolute form, its
/// components copied into the caller's buffers, whose sizes are in the `*_size` words.
#[unsafe(export_name = "f2k_export_RtlSelfRelativeToAbsoluteSD")]
pub unsafe extern "system" fn rtl_self_relative_to_absolute_sd(
    sd: *const u8,
    out: *mut u8,
    out_size: *mut u32,
    dacl: *mut u8,
    dacl_size: *mut u32,
    sacl: *mut u8,
    sacl_size: *mut u32,
    owner: *mut u8,
    owner_size: *mut u32,
    group: *mut u8,
    group_size: *mut u32,
) -> u32 {
    if sd_control(sd) & SE_SELF_RELATIVE == 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    let (addrs, sizes) = query_sd(sd);
    // SAFETY: the caller's size words.
    let wanted = [
        core::mem::size_of::<SecurityDescriptor>(),
        sizes[3],
        sizes[2],
        sizes[0],
        sizes[1],
    ];
    let given = unsafe {
        [*out_size, *dacl_size, *sacl_size, *owner_size, *group_size].map(|v| v as usize)
    };
    if wanted
        .iter()
        .zip(given.iter())
        .any(|(need, have)| need > have)
    {
        // SAFETY: the caller's size words, the required sizes out.
        unsafe {
            *out_size = wanted[0] as u32;
            *dacl_size = wanted[1] as u32;
            *sacl_size = wanted[2] as u32;
            *owner_size = wanted[3] as u32;
            *group_size = wanted[4] as u32;
        }
        return STATUS_BUFFER_TOO_SMALL;
    }
    let mut view = SecurityDescriptor {
        revision: read::<u8>(sd),
        sbz1: read::<u8>(sd.wrapping_add(1)),
        control: sd_control(sd) & !SE_SELF_RELATIVE,
        ..SecurityDescriptor::default()
    };
    // SAFETY: the out buffer holds a SECURITY_DESCRIPTOR.
    unsafe { core::ptr::write_bytes(out, 0, core::mem::size_of::<SecurityDescriptor>()) };
    write(out, view);
    // The components into the caller's buffers, in owner, group, SACL, DACL order.
    for (index, buffer) in [(0, owner), (1, group), (2, sacl), (3, dacl)] {
        if addrs[index] != 0 {
            // SAFETY: the component holds its SID or ACL header.
            let len = unsafe {
                if index < 2 {
                    sid_len_of(bytes(addrs[index] as *const u8, SID_HEADER))
                } else {
                    usize::from(acl_of(addrs[index] as *const u8).size)
                }
            };
            // SAFETY: the buffers hold their sizes (checked above), the components theirs.
            unsafe { core::ptr::copy_nonoverlapping(addrs[index] as *const u8, buffer, len) };
            view = read::<SecurityDescriptor>(out);
            match index {
                0 => view.owner = buffer as usize,
                1 => view.group = buffer as usize,
                2 => view.sacl = buffer as usize,
                _ => view.dacl = buffer as usize,
            }
            write(out, view);
        }
    }
    STATUS_SUCCESS
}

/// RtlSelfRelativeToAbsoluteSD2: the self-relative SD at `sd` converted in place to absolute
/// form, the buffer's size in `buffer_size` (the required size out, when too small).
#[unsafe(export_name = "f2k_export_RtlSelfRelativeToAbsoluteSD2")]
pub unsafe extern "system" fn rtl_self_relative_to_absolute_sd2(
    sd: *mut u8,
    buffer_size: *mut u32,
) -> u32 {
    if sd.is_null() {
        return STATUS_INVALID_PARAMETER_1;
    }
    if buffer_size.is_null() {
        return STATUS_INVALID_PARAMETER_2;
    }
    if sd_control(sd) & SE_SELF_RELATIVE == 0 {
        return STATUS_BAD_DESCRIPTOR_FORMAT;
    }
    let (addrs, sizes) = query_sd(sd);
    let base = sd as usize;
    let body = core::mem::size_of::<SecurityDescriptor>();
    let header = core::mem::size_of::<SecurityDescriptorRelative>();
    let delta = body - header;
    if delta == 0 {
        // The two forms are the same size: just point the fields at the components.
        let mut view: SecurityDescriptor = read(sd);
        view.control &= !SE_SELF_RELATIVE;
        view.owner = addrs[0];
        view.group = addrs[1];
        view.sacl = addrs[2];
        view.dacl = addrs[3];
        write(sd, view);
        return STATUS_SUCCESS;
    }
    let align = core::mem::align_of::<usize>();
    let end = addrs
        .iter()
        .zip(sizes)
        .filter(|(addr, size)| **addr != 0 && *size != 0)
        .map(|(addr, size)| *addr + size)
        .max()
        .unwrap_or(0);
    let mut required = body;
    if end != 0 {
        required += (end - (base + header) + align - 1) & !(align - 1);
    }
    // SAFETY: the caller's size.
    if required > unsafe { *buffer_size } as usize {
        // SAFETY: the caller's size.
        unsafe { buffer_size.write_unaligned(required as u32) };
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the buffer holds `required` bytes; the components move up past the header.
    unsafe {
        if end != 0 {
            core::ptr::copy(
                (base + header) as *const u8,
                (base + body) as *mut u8,
                required - body,
            );
        }
        let mut view: SecurityDescriptor = read(sd);
        view.control &= !SE_SELF_RELATIVE;
        view.owner = if addrs[0] != 0 { addrs[0] + delta } else { 0 };
        view.group = if addrs[1] != 0 { addrs[1] + delta } else { 0 };
        view.sacl = if addrs[2] != 0 { addrs[2] + delta } else { 0 };
        view.dacl = if addrs[3] != 0 { addrs[3] + delta } else { 0 };
        write(sd, view);
    }
    STATUS_SUCCESS
}

/// RtlCopySecurityDescriptor: a heap copy of the SD at `input` (either form), contiguous, its
/// address written to `output`.
#[unsafe(export_name = "f2k_export_RtlCopySecurityDescriptor")]
pub unsafe extern "system" fn rtl_copy_security_descriptor(
    input: *const u8,
    output: *mut *mut u8,
) -> u32 {
    let (_, sizes) = query_sd(input);
    let total = core::mem::size_of::<SecurityDescriptor>() + sizes.iter().sum::<usize>();
    let Some(block) = heap_alloc(total) else {
        return STATUS_NO_MEMORY;
    };
    // SAFETY: the block holds `total` bytes, the input its SD.
    unsafe {
        core::ptr::copy_nonoverlapping(input, block as *mut u8, total);
        output.write_unaligned(block as *mut u8);
    }
    STATUS_SUCCESS
}

// --- Access masks, privileges, and the routines that reach the token services -------------

/// RtlAreAllAccessesGranted: whether `granted` has every bit of `desired`.
#[unsafe(export_name = "f2k_export_RtlAreAllAccessesGranted")]
pub unsafe extern "system" fn rtl_are_all_accesses_granted(granted: u32, desired: u32) -> u32 {
    u32::from(!granted & desired == 0)
}

/// RtlAreAnyAccessesGranted: whether `granted` has any bit of `desired`.
#[unsafe(export_name = "f2k_export_RtlAreAnyAccessesGranted")]
pub unsafe extern "system" fn rtl_are_any_accesses_granted(granted: u32, desired: u32) -> u32 {
    u32::from(granted & desired != 0)
}

/// The target's RtlAdjustPrivilege, over the token services.
#[cfg(not(test))]
fn adjust_privilege(privilege: u32, enable: u32, client: u32, was_enabled: *mut u32) -> u32 {
    use rtl::nt::access::{TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY};
    use rtl::sys::nr;
    let access = TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY;
    let mut token = 0u32;
    let status = if client != 0 {
        service(
            nr::NtOpenThreadToken,
            &[CURRENT_THREAD, access, 0, address_mut(&mut token)],
        )
    } else {
        service(
            nr::NtOpenProcessToken,
            &[CURRENT_PROCESS, access, address_mut(&mut token)],
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    // A TOKEN_PRIVILEGES with one entry: count, LUID, attributes.
    let mut new = [0u8; 16];
    set_dword(new.as_mut_ptr(), 1);
    new[4..8].copy_from_slice(&privilege.to_le_bytes());
    set_dword(
        new.as_mut_ptr().wrapping_add(12),
        if enable != 0 { SE_PRIVILEGE_ENABLED } else { 0 },
    );
    let mut old = [0u8; 16];
    let mut length = 0u32;
    let mut status = service(
        nr::NtAdjustPrivilegesToken,
        &[
            token,
            0,
            address(&new),
            16,
            address_mut(&mut old),
            address_mut(&mut length),
        ],
    );
    service(nr::NtClose, &[token]);
    if status == STATUS_NOT_ALL_ASSIGNED {
        status = STATUS_PRIVILEGE_NOT_HELD;
    }
    if status == STATUS_SUCCESS {
        let was = if dword(old.as_ptr()) == 0 {
            enable != 0
        } else {
            dword(old.as_ptr().wrapping_add(12)) & SE_PRIVILEGE_ENABLED != 0
        };
        // SAFETY: the caller's out parameter.
        unsafe { was_enabled.write_unaligned(u32::from(was)) };
    }
    status
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
fn adjust_privilege(_: u32, _: u32, _: u32, _: *mut u32) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlAdjustPrivilege: enable or disable `privilege` in the thread's or the process's token,
/// whether it was enabled out.
#[unsafe(export_name = "f2k_export_RtlAdjustPrivilege")]
pub unsafe extern "system" fn rtl_adjust_privilege(
    privilege: u32,
    enable: u32,
    client: u32,
    was_enabled: *mut u32,
) -> u32 {
    adjust_privilege(privilege, enable, client, was_enabled)
}

/// The target's RtlNewSecurityGrantedAccess, over the token services.
#[cfg(not(test))]
fn new_security_granted_access(
    desired: u32,
    privileges: *mut u8,
    length: *mut u32,
    token: u32,
    mapping: *const GenericMapping,
    remaining: *mut u32,
) -> u32 {
    use rtl::nt::access::{GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, TOKEN_QUERY};
    use rtl::sys::nr;
    let (token, passed) = if token != 0 {
        (token, true)
    } else {
        let mut handle = 0u32;
        let status = service(
            nr::NtOpenThreadToken,
            &[CURRENT_THREAD, TOKEN_QUERY, 1, address_mut(&mut handle)],
        );
        if status != STATUS_SUCCESS {
            return status;
        }
        (handle, false)
    };
    let mut desired = desired;
    if !mapping.is_null() {
        let map: GenericMapping = read(mapping as *const u8);
        if desired & GENERIC_READ != 0 {
            desired |= map.generic_read;
        }
        if desired & GENERIC_WRITE != 0 {
            desired |= map.generic_write;
        }
        if desired & GENERIC_EXECUTE != 0 {
            desired |= map.generic_execute;
        }
        if desired & GENERIC_ALL != 0 {
            desired |= map.generic_all;
        }
        desired &= !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    }
    // SAFETY: the caller's out parameter.
    unsafe { remaining.write_unaligned(desired) };
    let mut result = 0u32;
    if desired & ACCESS_SYSTEM_SECURITY != 0 {
        // A PRIVILEGE_SET asking for SeSecurityPrivilege.
        let mut request = [0u8; 20];
        set_dword(request.as_mut_ptr(), 1);
        set_dword(
            request.as_mut_ptr().wrapping_add(4),
            PRIVILEGE_SET_ALL_NECESSARY,
        );
        request[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
        let status = service(
            nr::NtPrivilegeCheck,
            &[token, address(&request), address_mut(&mut result)],
        );
        if !passed {
            service(nr::NtClose, &[token]);
        }
        if status != STATUS_SUCCESS {
            return status;
        }
        if result == 0 {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        desired &= !ACCESS_SYSTEM_SECURITY;
        // SAFETY: the caller's out parameter.
        unsafe { remaining.write_unaligned(desired) };
    } else if !passed {
        service(nr::NtClose, &[token]);
    }
    // SAFETY: the caller's size.
    if 16 > unsafe { *length } {
        // SAFETY: the caller's size.
        unsafe { length.write_unaligned(16) };
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller's PRIVILEGE_SET holds 16 bytes.
    unsafe {
        let set = bytes_mut(privileges, 16);
        set[..4].copy_from_slice(&u32::from(result != 0).to_le_bytes());
        if result != 0 {
            set[8..12].copy_from_slice(&SE_SECURITY_PRIVILEGE.to_le_bytes());
            set[12..16].copy_from_slice(&SE_PRIVILEGE_USED_FOR_ACCESS.to_le_bytes());
        }
    }
    STATUS_SUCCESS
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
fn new_security_granted_access(
    _: u32,
    _: *mut u8,
    _: *mut u32,
    _: u32,
    _: *const GenericMapping,
    _: *mut u32,
) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlNewSecurityGrantedAccess: the access a create may grant, the privilege set used out.
#[unsafe(export_name = "f2k_export_RtlNewSecurityGrantedAccess")]
pub unsafe extern "system" fn rtl_new_security_granted_access(
    desired: u32,
    privileges: *mut u8,
    length: *mut u32,
    token: u32,
    mapping: *const GenericMapping,
    remaining: *mut u32,
) -> u32 {
    new_security_granted_access(desired, privileges, length, token, mapping, remaining)
}

/// The target's RtlDefaultNpAcl, over the token services: the default named-pipe ACL (SYSTEM,
/// Administrators and the token's owner: all; Everyone: read).
#[cfg(not(test))]
fn default_np_acl(acl_out: *mut *mut u8) -> u32 {
    use rtl::nt::access::{GENERIC_ALL, GENERIC_READ, TOKEN_QUERY};
    use rtl::sys::nr;
    // SAFETY: the caller's out parameter.
    unsafe { acl_out.write_unaligned(core::ptr::null_mut()) };
    let mut token = 0u32;
    let mut status = service(
        nr::NtOpenThreadToken,
        &[CURRENT_THREAD, TOKEN_QUERY, 1, address_mut(&mut token)],
    );
    if status == STATUS_NO_TOKEN {
        status = service(
            nr::NtOpenProcessToken,
            &[CURRENT_PROCESS, TOKEN_QUERY, address_mut(&mut token)],
        );
    }
    if status != STATUS_SUCCESS {
        return status;
    }
    let mut returned = 0u32;
    status = service(
        nr::NtQueryInformationToken,
        &[token, TOKEN_OWNER, 0, 0, address_mut(&mut returned)],
    );
    if status == STATUS_BUFFER_TOO_SMALL {
        let Some(owner_block) = heap_alloc(returned as usize) else {
            service(nr::NtClose, &[token]);
            return STATUS_NO_MEMORY;
        };
        status = service(
            nr::NtQueryInformationToken,
            &[
                token,
                TOKEN_OWNER,
                owner_block as u32,
                returned,
                address_mut(&mut returned),
            ],
        );
        if status == STATUS_SUCCESS {
            // SAFETY: the block holds the TOKEN_OWNER.
            let owner = read::<usize>(owner_block as *const u8);
            // SAFETY: the owner is a SID.
            let owner_len = unsafe { sid_len_of(bytes(owner as *const u8, SID_HEADER)) };
            let acl_size = 8 + 3 * 12 + owner_len + 16;
            if let Some(acl) = heap_alloc(acl_size) {
                let acl = acl as *mut u8;
                // SAFETY: the block is the ACL the descriptor's out parameter carries.
                unsafe {
                    rtl_create_acl(acl, acl_size as u32, ACL_REVISION);
                    let mut sid = [0u8; 16];
                    rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 1);
                    set_dword(sid.as_mut_ptr().wrapping_add(8), SECURITY_LOCAL_SYSTEM_RID);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, sid.as_ptr());
                    rtl_initialize_sid(sid.as_mut_ptr(), NT_AUTHORITY.as_ptr(), 2);
                    set_dword(
                        sid.as_mut_ptr().wrapping_add(8),
                        SECURITY_BUILTIN_DOMAIN_RID,
                    );
                    set_dword(sid.as_mut_ptr().wrapping_add(12), DOMAIN_ALIAS_RID_ADMINS);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, sid.as_ptr());
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_ALL, owner as *const u8);
                    rtl_initialize_sid(sid.as_mut_ptr(), WORLD_AUTHORITY.as_ptr(), 1);
                    set_dword(sid.as_mut_ptr().wrapping_add(8), SECURITY_WORLD_RID);
                    rtl_add_access_allowed_ace(acl, ACL_REVISION, GENERIC_READ, sid.as_ptr());
                    acl_out.write_unaligned(acl);
                }
            } else {
                status = STATUS_NO_MEMORY;
            }
        }
        heap_free(owner_block);
    }
    service(nr::NtClose, &[token]);
    if status != STATUS_SUCCESS {
        // SAFETY: the caller's out parameter.
        let made = unsafe { *acl_out };
        if !made.is_null() {
            heap_free(made as usize);
            // SAFETY: the caller's out parameter.
            unsafe { acl_out.write_unaligned(core::ptr::null_mut()) };
        }
    }
    status
}

/// The tests have no kernel: the token-touching routines are not exercised there.
#[cfg(test)]
fn default_np_acl(_: *mut *mut u8) -> u32 {
    unimplemented!("no system services on the host")
}

/// RtlDefaultNpAcl: the default named-pipe ACL in a heap block, its address out.
#[unsafe(export_name = "f2k_export_RtlDefaultNpAcl")]
pub unsafe extern "system" fn rtl_default_np_acl(acl_out: *mut *mut u8) -> u32 {
    default_np_acl(acl_out)
}

/// RtlCreateAndSetSD: an absolute SD in a heap block from the ACE data list, owner and group,
/// its address out.
#[unsafe(export_name = "f2k_export_RtlCreateAndSetSD")]
pub unsafe extern "system" fn rtl_create_and_set_sd(
    ace_data: *const AceData,
    ace_count: u32,
    owner: *const u8,
    group: *const u8,
    new_descriptor: *mut *mut u8,
) -> u32 {
    let mut dacl_size = 8usize;
    let mut sacl_size = 8usize;
    let mut max_ace = 0usize;
    for index in 0..ace_count as usize {
        // SAFETY: the caller's list holds `ace_count` entries.
        let entry = unsafe { &*ace_data.add(index) };
        // SAFETY: the entry's SID.
        let len = unsafe { sid_len_of(bytes(entry.sid as *const u8, SID_HEADER)) };
        let ace_size = len + 8;
        match entry.ace_type {
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => dacl_size += ace_size,
            SYSTEM_AUDIT_ACE_TYPE => sacl_size += ace_size,
            _ => return STATUS_INVALID_PARAMETER,
        }
        max_ace = max_ace.max(ace_size);
    }
    let header = core::mem::size_of::<SecurityDescriptor>();
    let mut size = header;
    if dacl_size != 8 {
        size += dacl_size;
    }
    if sacl_size != 8 {
        size += sacl_size;
    }
    let Some(sd) = heap_alloc(size) else {
        return STATUS_NO_MEMORY;
    };
    let mut status = STATUS_SUCCESS;
    let mut dacl = 0usize;
    let mut sacl = 0usize;
    let mut current = sd + header;
    if dacl_size != 8 {
        dacl = current;
        current += dacl_size;
        status = rtl_create_acl(dacl as *mut u8, dacl_size as u32, ACL_REVISION);
    }
    if status == STATUS_SUCCESS && sacl_size != 8 {
        sacl = current;
        current += sacl_size;
        status = rtl_create_acl(sacl as *mut u8, sacl_size as u32, ACL_REVISION);
    }
    let _ = current;
    let scratch = if max_ace > 0 {
        heap_alloc(max_ace)
    } else {
        None
    };
    if status == STATUS_SUCCESS && max_ace > 0 && scratch.is_none() {
        status = STATUS_NO_MEMORY;
    }
    if status == STATUS_SUCCESS {
        for index in 0..ace_count as usize {
            // SAFETY: the caller's list holds `ace_count` entries.
            let entry = unsafe { &*ace_data.add(index) };
            // SAFETY: the entry's SID.
            let len = unsafe { sid_len_of(bytes(entry.sid as *const u8, SID_HEADER)) };
            let ace_size = len + 8;
            let ace = scratch.unwrap() as *mut u8;
            write(
                ace,
                AceHeader {
                    ace_type: entry.ace_type,
                    ace_flags: entry.ace_flags | entry.inherit_flags,
                    ace_size: ace_size as u16,
                },
            );
            set_dword(ace.wrapping_add(4), entry.mask);
            // SAFETY: the scratch block holds the ACE; the entry's SID holds its own.
            unsafe {
                bytes_mut(ace.wrapping_add(8), len)
                    .copy_from_slice(sid_slice(entry.sid as *const u8))
            };
            let acl = if entry.ace_type == SYSTEM_AUDIT_ACE_TYPE {
                sacl
            } else {
                dacl
            };
            status = rtl_add_ace(acl as *mut u8, ACL_REVISION, MAXULONG, ace, ace_size as u32);
            if status != STATUS_SUCCESS {
                break;
            }
        }
    }
    if status == STATUS_SUCCESS {
        status =
            rtl_create_security_descriptor(sd as *mut u8, u32::from(SECURITY_DESCRIPTOR_REVISION));
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_owner_security_descriptor(sd as *mut u8, owner, 0);
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_group_security_descriptor(sd as *mut u8, group, 0);
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_dacl_security_descriptor(
            sd as *mut u8,
            1,
            if dacl != 0 {
                dacl as *mut u8
            } else {
                core::ptr::null_mut()
            },
            0,
        );
    }
    if status == STATUS_SUCCESS {
        status = rtl_set_sacl_security_descriptor(sd as *mut u8, 0, core::ptr::null_mut(), 0);
    }
    if let Some(block) = scratch {
        heap_free(block);
    }
    if status == STATUS_SUCCESS {
        // SAFETY: the caller's out parameter.
        unsafe { new_descriptor.write_unaligned(sd as *mut u8) };
    } else {
        heap_free(sd);
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BUILTIN\Administrators, S-1-5-32-544.
    fn admins() -> [u8; 16] {
        let mut sid = [0u8; 16];
        sid[0] = 1;
        sid[1] = 2;
        sid[2..8].copy_from_slice(&NT_AUTHORITY);
        sid[8..12].copy_from_slice(&32u32.to_le_bytes());
        sid[12..16].copy_from_slice(&544u32.to_le_bytes());
        sid
    }

    /// Everyone, S-1-1-0.
    fn world() -> [u8; 12] {
        let mut sid = [0u8; 12];
        sid[0] = 1;
        sid[1] = 1;
        sid[2..8].copy_from_slice(&WORLD_AUTHORITY);
        sid
    }

    #[test]
    fn the_layouts_are_the_public_sizes() {
        assert_eq!(core::mem::size_of::<Acl>(), 8);
        assert_eq!(core::mem::size_of::<AceHeader>(), 4);
        assert_eq!(core::mem::size_of::<SecurityDescriptorRelative>(), 20);
        assert_eq!(core::mem::size_of::<SecurityDescriptor<u32>>(), 20);
        assert_eq!(core::mem::size_of::<SidAndAttributes<u32>>(), 8);
        assert_eq!(core::mem::size_of::<GenericMapping>(), 16);
        let acl = Acl {
            revision: 2,
            sbz1: 0,
            size: 64,
            ace_count: 3,
            sbz2: 0,
        };
        assert_eq!(acl.as_bytes(), &[2, 0, 64, 0, 3, 0, 0, 0]);
        assert_eq!(Acl::from_bytes(&[2, 0, 64, 0, 3, 0, 0, 0]), Some(acl));
    }

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

    #[test]
    fn an_acl_creates_validates_and_edits_aces() {
        let mut buffer = [0u8; 128];
        let acl = buffer.as_mut_ptr();
        assert_eq!(
            unsafe { rtl_create_acl(acl, 7, 2) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 64, 1) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 64, 5) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_create_acl(acl, 0x1_0004, 2) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(unsafe { rtl_create_acl(acl, 66, 2) }, STATUS_SUCCESS);
        let header = acl_of(acl);
        assert_eq!((header.revision, header.size, header.ace_count), (2, 64, 0));
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // An allowed ACE for the admins, then a denied one for Everyone.
        let sid = admins();
        let everyone = world();
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 0x1234, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_denied_ace(acl, 2, 0xFF, everyone.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!((acl_of(acl).ace_count, acl_of(acl).size), (2, 64));
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // Get them back: the first at acl+8, the second past it (24 then 20 bytes).
        let mut ace = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace as usize - acl as usize, 8);
        assert_eq!(
            ace_of(ace as *const u8),
            AceHeader {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                ace_flags: 0,
                ace_size: 24,
            }
        );
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 0x1234);
        assert_eq!(
            unsafe { sid_slice((ace as *const u8).wrapping_add(8)) },
            &sid[..]
        );
        assert_eq!(unsafe { rtl_get_ace(acl, 1, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace_of(ace as *const u8).ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(
            unsafe { rtl_get_ace(acl, 2, &mut ace) },
            STATUS_INVALID_PARAMETER
        );
        // First free is past the second ACE; size info says so.
        let mut free = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_first_free_ace(acl, &mut free) }, 1);
        assert_eq!(free as usize - acl as usize, 8 + 24 + 20);
        let mut info = [0u8; 12];
        assert_eq!(
            unsafe { rtl_query_information_acl(acl, info.as_mut_ptr(), 12, ACL_SIZE_INFORMATION) },
            STATUS_SUCCESS
        );
        assert_eq!(&info, &[2, 0, 0, 0, 52, 0, 0, 0, 12, 0, 0, 0]);
        assert_eq!(
            unsafe {
                rtl_query_information_acl(acl, info.as_mut_ptr(), 4, ACL_REVISION_INFORMATION)
            },
            STATUS_SUCCESS
        );
        assert_eq!(&info[..4], &[2, 0, 0, 0]);
        assert_eq!(
            unsafe { rtl_query_information_acl(acl, info.as_mut_ptr(), 12, 7) },
            STATUS_INVALID_INFO_CLASS
        );
        // Set the revision up to 4, not down.
        let revision = 4u32;
        assert_eq!(
            unsafe {
                rtl_set_information_acl(
                    acl,
                    revision.to_le_bytes().as_ptr(),
                    4,
                    ACL_REVISION_INFORMATION,
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 4);
        let low = 2u32;
        assert_eq!(
            unsafe {
                rtl_set_information_acl(
                    acl,
                    low.to_le_bytes().as_ptr(),
                    4,
                    ACL_REVISION_INFORMATION,
                )
            },
            STATUS_INVALID_PARAMETER
        );
        // Delete the first ACE: the second moves up.
        assert_eq!(unsafe { rtl_delete_ace(acl, 0) }, STATUS_SUCCESS);
        assert_eq!(acl_of(acl).ace_count, 1);
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(ace_of(ace as *const u8).ace_type, ACCESS_DENIED_ACE_TYPE);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        assert_eq!(unsafe { rtl_delete_ace(acl, 1) }, STATUS_INVALID_PARAMETER);
    }

    #[test]
    fn adding_aces_checks_their_inputs() {
        let mut buffer = [0u8; 64];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 64, 2) }, STATUS_SUCCESS);
        let sid = admins();
        let mut bad = sid;
        bad[0] = 9;
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, bad.as_ptr()) },
            STATUS_INVALID_SID
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 5, 1, sid.as_ptr()) },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace_ex(acl, 2, 0x20, 1, sid.as_ptr()) },
            STATUS_INVALID_PARAMETER
        );
        // Audit flags are fine on an audit ACE.
        assert_eq!(
            unsafe { rtl_add_audit_access_ace(acl, 2, 1, sid.as_ptr(), 1, 1) },
            STATUS_SUCCESS
        );
        assert_eq!(ace_of((acl as usize + 8) as *const u8).ace_flags, 0xC0);
        // Room: 64 - 8 - 24 = 32 bytes left, one more ACE of 24 fits, the next does not.
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_ALLOTTED_SPACE_EXCEEDED
        );
        // An ill-formed ACL is rejected.
        let mut broken = [0u8; 64];
        broken[0] = 2;
        broken[2..4].copy_from_slice(&64u16.to_le_bytes());
        broken[4..6].copy_from_slice(&1u16.to_le_bytes()); // one ACE, none present
        assert_eq!(unsafe { rtl_valid_acl(broken.as_ptr()) }, 0);
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(broken.as_mut_ptr(), 2, 1, sid.as_ptr()) },
            STATUS_INVALID_ACL
        );
    }

    #[test]
    fn an_ace_list_inserts_at_an_index() {
        let mut buffer = [0u8; 128];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 128, 2) }, STATUS_SUCCESS);
        let sid = admins();
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl, 2, 1, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_denied_ace(acl, 2, 2, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        // A one-ACE list inserted at index 0.
        let mut list = [0u8; 24];
        write(
            list.as_mut_ptr(),
            AceHeader {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                ace_flags: 0,
                ace_size: 24,
            },
        );
        set_dword(list.as_mut_ptr().wrapping_add(4), 0x77);
        unsafe { bytes_mut(list.as_mut_ptr().wrapping_add(8), 16).copy_from_slice(&sid) };
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, 0, list.as_ptr(), 24) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).ace_count, 3);
        let mut ace = core::ptr::null_mut();
        assert_eq!(unsafe { rtl_get_ace(acl, 0, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 0x77); // the inserted one, at 0
        assert_eq!(unsafe { rtl_get_ace(acl, 2, &mut ace) }, STATUS_SUCCESS);
        assert_eq!(dword((ace as *const u8).wrapping_add(4)), 2); // the old denied one, at the end
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // A list that overruns its length is rejected; a type the revision forbids too.
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, MAXULONG, list.as_ptr(), 25) },
            STATUS_INVALID_PARAMETER
        );
        let mut object = [0u8; 48];
        write(
            object.as_mut_ptr(),
            AceHeader {
                ace_type: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                ace_flags: 0,
                ace_size: 48,
            },
        );
        // No GUID flags, so the SID sits right after the flags word, at +12.
        unsafe { bytes_mut(object.as_mut_ptr().wrapping_add(12), 16).copy_from_slice(&sid) };
        assert_eq!(
            unsafe { rtl_add_ace(acl, 2, MAXULONG, object.as_ptr(), 48) },
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            unsafe { rtl_add_ace(acl, 4, MAXULONG, object.as_ptr(), 48) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 4);
        assert_eq!(
            unsafe { rtl_add_ace(acl, 4, MAXULONG, list.as_ptr(), 24) },
            STATUS_BUFFER_TOO_SMALL
        );
    }

    #[test]
    fn compound_and_object_aces_append() {
        let mut buffer = [0u8; 256];
        let acl = buffer.as_mut_ptr();
        assert_eq!(unsafe { rtl_create_acl(acl, 256, 2) }, STATUS_SUCCESS);
        let server = admins();
        let client = world();
        // A compound ACE needs revision 3.
        assert_eq!(
            unsafe { rtl_add_compound_ace(acl, 2, 1, 0x55, server.as_ptr(), client.as_ptr()) },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe { rtl_add_compound_ace(acl, 3, 1, 0x55, server.as_ptr(), client.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(acl_of(acl).revision, 3);
        let ace = (acl as usize + 8) as *const u8;
        assert_eq!(ace_of(ace).ace_type, ACCESS_ALLOWED_COMPOUND_ACE_TYPE);
        assert_eq!(ace_of(ace).ace_size, 12 + 12 + 16);
        assert_eq!(word(ace.wrapping_add(8)), COMPOUND_ACE_IMPERSONATION);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(12)) }, &server[..]);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(12 + 16)) }, &client[..]);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // An object ACE with one GUID needs revision 4.
        let guid = [0xABu8; 16];
        assert_eq!(
            unsafe {
                rtl_add_access_allowed_object_ace(
                    acl,
                    3,
                    0,
                    1,
                    guid.as_ptr(),
                    core::ptr::null(),
                    server.as_ptr(),
                )
            },
            STATUS_REVISION_MISMATCH
        );
        assert_eq!(
            unsafe {
                rtl_add_access_allowed_object_ace(
                    acl,
                    4,
                    0,
                    1,
                    guid.as_ptr(),
                    core::ptr::null(),
                    server.as_ptr(),
                )
            },
            STATUS_SUCCESS
        );
        let ace = (acl as usize + 8 + 40) as *const u8;
        assert_eq!(ace_of(ace).ace_type, ACCESS_ALLOWED_OBJECT_ACE_TYPE);
        assert_eq!(ace_of(ace).ace_size, 12 + 16 + 16);
        assert_eq!(dword(ace.wrapping_add(8)), ACE_OBJECT_TYPE_PRESENT);
        assert_eq!(unsafe { bytes(ace.wrapping_add(12), 16) }, &guid[..]);
        assert_eq!(unsafe { sid_slice(ace.wrapping_add(28)) }, &server[..]);
        assert_eq!(unsafe { rtl_valid_acl(acl) }, 1);
        // No GUIDs: a plain ACE.
        assert_eq!(
            unsafe {
                rtl_add_access_denied_object_ace(
                    acl,
                    4,
                    0,
                    2,
                    core::ptr::null(),
                    core::ptr::null(),
                    client.as_ptr(),
                )
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            ace_of((acl as usize + 8 + 40 + 44) as *const u8).ace_type,
            ACCESS_DENIED_ACE_TYPE
        );
    }

    #[test]
    fn a_descriptor_creates_sets_and_gets() {
        let mut buffer = [0u8; 64];
        let sd = buffer.as_mut_ptr();
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd, 2) },
            STATUS_UNKNOWN_REVISION
        );
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd, 1) },
            STATUS_SUCCESS
        );
        let view: SecurityDescriptor = read(sd);
        assert_eq!(
            (
                view.revision,
                view.control,
                view.owner,
                view.group,
                view.sacl,
                view.dacl
            ),
            (1, 0, 0, 0, 0, 0)
        );
        assert_eq!(unsafe { rtl_valid_security_descriptor(sd) }, 1);
        let sid = admins();
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(sd, sid.as_ptr(), 1) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_group_security_descriptor(sd, sid.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        let mut owner = core::ptr::null_mut();
        let mut defaulted = 0u32;
        assert_eq!(
            unsafe { rtl_get_owner_security_descriptor(sd, &mut owner, &mut defaulted) },
            STATUS_SUCCESS
        );
        assert_eq!(owner as usize, sid.as_ptr() as usize);
        assert_eq!(defaulted, 1);
        let mut group = core::ptr::null_mut();
        assert_eq!(
            unsafe { rtl_get_group_security_descriptor(sd, &mut group, &mut defaulted) },
            STATUS_SUCCESS
        );
        assert_eq!(defaulted, 0);
        // The DACL.
        let mut acl_buffer = [0u8; 64];
        assert_eq!(
            unsafe { rtl_create_acl(acl_buffer.as_mut_ptr(), 64, 2) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl_buffer.as_mut_ptr(), 2, 0xFFFF, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_dacl_security_descriptor(sd, 1, acl_buffer.as_mut_ptr(), 1) },
            STATUS_SUCCESS
        );
        let mut present = 0u32;
        let mut dacl = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_get_dacl_security_descriptor(sd, &mut present, &mut dacl, &mut defaulted)
            },
            STATUS_SUCCESS
        );
        assert_eq!(
            (present, dacl as usize, defaulted),
            (1, acl_buffer.as_ptr() as usize, 1)
        );
        assert_eq!(unsafe { rtl_valid_security_descriptor(sd) }, 1);
        // Length: header + aligned owner + aligned group + aligned ACL.
        let expect = core::mem::size_of::<SecurityDescriptor>() + 16 + 16 + 64;
        assert_eq!(
            unsafe { rtl_length_security_descriptor(sd) } as usize,
            expect
        );
        // Control get/set, and the RM control byte.
        let mut control = 0u16;
        let mut revision = 0u32;
        assert_eq!(
            unsafe { rtl_get_control_security_descriptor(sd, &mut control, &mut revision) },
            STATUS_SUCCESS
        );
        assert_eq!(
            (control, revision),
            (SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_OWNER_DEFAULTED, 1)
        );
        assert_eq!(
            unsafe {
                rtl_set_control_security_descriptor(sd, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
            },
            STATUS_SUCCESS
        );
        assert_eq!(sd_control(sd) & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        assert_eq!(
            unsafe { rtl_set_control_security_descriptor(sd, SE_DACL_PROTECTED, 0) },
            STATUS_SUCCESS
        );
        assert_eq!(sd_control(sd) & SE_DACL_PROTECTED, 0);
        // SE_OWNER_DEFAULTED is not a settable bit.
        assert_eq!(
            unsafe { rtl_set_control_security_descriptor(sd, 0x0001, 0x0001) },
            STATUS_INVALID_PARAMETER
        );
        let mut rm = 0u8;
        assert_eq!(
            unsafe { rtl_get_security_descriptor_rm_control(sd, &mut rm) },
            0
        );
        assert_eq!(rm, 0);
        unsafe { rtl_set_security_descriptor_rm_control(sd, &0x5A) };
        assert_eq!(
            unsafe { rtl_get_security_descriptor_rm_control(sd, &mut rm) },
            1
        );
        assert_eq!(rm, 0x5A);
        // A bad revision is reported, and the revision out always.
        buffer[0] = 7;
        assert_eq!(
            unsafe { rtl_get_control_security_descriptor(sd, &mut control, &mut revision) },
            STATUS_UNKNOWN_REVISION
        );
        assert_eq!(revision, 7);
        assert_eq!(
            unsafe { rtl_set_dacl_security_descriptor(sd, 1, acl_buffer.as_mut_ptr(), 0) },
            STATUS_UNKNOWN_REVISION
        );
        buffer[0] = 1;
        assert_eq!(buffer[0], 1);
        // A self-relative SD cannot be set through the absolute setters.
        let mut rel = [0u8; 20];
        rel[0] = 1;
        write(rel.as_mut_ptr().wrapping_add(2), SE_SELF_RELATIVE);
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(rel.as_mut_ptr(), sid.as_ptr(), 0) },
            STATUS_INVALID_SECURITY_DESCR
        );
    }

    #[test]
    fn self_relative_descriptors_validate_and_round_trip() {
        // An absolute SD with owner, group and DACL.
        let mut buffer = [0u8; 256];
        let sd = buffer.as_mut_ptr();
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd, 1) },
            STATUS_SUCCESS
        );
        let owner = admins();
        let group = world();
        let mut acl_buffer = [0u8; 64];
        assert_eq!(
            unsafe { rtl_create_acl(acl_buffer.as_mut_ptr(), 64, 2) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl_buffer.as_mut_ptr(), 2, 1, owner.as_ptr()) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(sd, owner.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_group_security_descriptor(sd, group.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_dacl_security_descriptor(sd, 1, acl_buffer.as_mut_ptr(), 0) },
            STATUS_SUCCESS
        );
        // To self-relative: header + dacl 64 + owner 16 + group 12 = 112.
        let mut relative = [0u8; 256];
        let mut length = 256u32;
        assert_eq!(
            unsafe { rtl_absolute_to_self_relative_sd(sd, relative.as_mut_ptr(), &mut length) },
            STATUS_SUCCESS
        );
        let rel: SecurityDescriptorRelative = read(relative.as_ptr());
        assert_eq!(rel.revision, 1);
        assert!(rel.control & SE_SELF_RELATIVE != 0);
        assert_eq!((rel.sacl, rel.dacl, rel.owner, rel.group), (0, 20, 84, 100));
        assert_eq!(
            unsafe { rtl_length_security_descriptor(relative.as_ptr()) } as usize,
            20 + 64 + 16 + 12
        );
        assert_eq!(
            unsafe { rtl_valid_relative_security_descriptor(relative.as_ptr(), 112, 0) },
            1
        );
        // A required owner missing fails; an empty one passes without the requirement.
        let empty = SecurityDescriptorRelative {
            revision: 1,
            control: SE_SELF_RELATIVE,
            ..Default::default()
        };
        let mut empty_buf = [0u8; 20];
        write(empty_buf.as_mut_ptr(), empty);
        assert_eq!(
            unsafe {
                rtl_valid_relative_security_descriptor(
                    empty_buf.as_ptr(),
                    20,
                    OWNER_SECURITY_INFORMATION,
                )
            },
            0
        );
        assert_eq!(
            unsafe { rtl_valid_relative_security_descriptor(empty_buf.as_ptr(), 20, 0) },
            1
        );
        // A short buffer, or an offset inside the header, fails.
        assert_eq!(
            unsafe { rtl_valid_relative_security_descriptor(relative.as_ptr(), 50, 0) },
            0
        );
        let mut bad = relative;
        write(bad.as_mut_ptr().wrapping_add(16), 4u32); // DACL offset inside the header
        assert_eq!(
            unsafe { rtl_valid_relative_security_descriptor(bad.as_ptr(), 112, 0) },
            0
        );
        // An absolute SD is rejected by the absolute-only conversion; a relative one by the
        // self-relative-only query.
        let mut length = 256u32;
        assert_eq!(
            unsafe {
                rtl_absolute_to_self_relative_sd(
                    relative.as_ptr(),
                    buffer.as_mut_ptr(),
                    &mut length,
                )
            },
            STATUS_BAD_DESCRIPTOR_FORMAT
        );
        // Too small a buffer: the required size comes out.
        let mut length = 10u32;
        assert_eq!(
            unsafe { rtl_make_self_relative_sd(sd, relative.as_mut_ptr(), &mut length) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(length, 112);
        // Back to absolute, into caller buffers.
        let mut out = [0u8; 64];
        let mut dacl_out = [0u8; 64];
        let mut owner_out = [0u8; 16];
        let mut group_out = [0u8; 12];
        let sizes = (64u32, 64u32, 8u32, 16u32, 12u32);
        let (mut out_size, mut dacl_size, mut sacl_size, mut owner_size, mut group_size) = sizes;
        assert_eq!(
            unsafe {
                rtl_self_relative_to_absolute_sd(
                    relative.as_ptr(),
                    out.as_mut_ptr(),
                    &mut out_size,
                    dacl_out.as_mut_ptr(),
                    &mut dacl_size,
                    core::ptr::null_mut(),
                    &mut sacl_size,
                    owner_out.as_mut_ptr(),
                    &mut owner_size,
                    group_out.as_mut_ptr(),
                    &mut group_size,
                )
            },
            STATUS_SUCCESS
        );
        let view: SecurityDescriptor = read(out.as_ptr());
        assert!(view.control & SE_SELF_RELATIVE == 0);
        assert_eq!(view.owner, owner_out.as_ptr() as usize);
        assert_eq!(&owner_out, &owner);
        assert_eq!(&group_out, &group);
        assert_eq!(view.dacl, dacl_out.as_ptr() as usize);
        assert_eq!(&dacl_out[..8], &acl_buffer[..8]);
        assert_eq!(unsafe { rtl_valid_security_descriptor(out.as_ptr()) }, 1);
        // Sizes too small: the required sizes come out.
        let (mut out_size, mut dacl_size, mut sacl_size, mut owner_size, mut group_size) =
            (4u32, 4u32, 4u32, 4u32, 4u32);
        assert_eq!(
            unsafe {
                rtl_self_relative_to_absolute_sd(
                    relative.as_ptr(),
                    out.as_mut_ptr(),
                    &mut out_size,
                    dacl_out.as_mut_ptr(),
                    &mut dacl_size,
                    core::ptr::null_mut(),
                    &mut sacl_size,
                    owner_out.as_mut_ptr(),
                    &mut owner_size,
                    group_out.as_mut_ptr(),
                    &mut group_size,
                )
            },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(
            (out_size, dacl_size, sacl_size, owner_size, group_size),
            (
                core::mem::size_of::<SecurityDescriptor>() as u32,
                64,
                0,
                16,
                12
            )
        );
        // The in-place conversion.
        let mut inplace = relative;
        let mut size = 256u32;
        assert_eq!(
            unsafe { rtl_self_relative_to_absolute_sd2(inplace.as_mut_ptr(), &mut size) },
            STATUS_SUCCESS
        );
        assert!(sd_control(inplace.as_ptr()) & SE_SELF_RELATIVE == 0);
        // A copy of the descriptor is one contiguous heap block.
        let mut copy = core::ptr::null_mut();
        assert_eq!(
            unsafe { rtl_copy_security_descriptor(relative.as_ptr(), &mut copy) },
            STATUS_SUCCESS
        );
        assert_eq!(unsafe { bytes(copy as *const u8, 112) }, &relative[..112]);
        assert!(heap_free(copy as usize));
    }

    #[test]
    fn create_and_set_sd_builds_a_descriptor() {
        let owner = admins();
        let group = world();
        let entries = [
            AceData {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0xF0,
                sid: owner.as_ptr() as usize,
            },
            AceData {
                ace_type: SYSTEM_AUDIT_ACE_TYPE,
                inherit_flags: 0,
                ace_flags: 0,
                mask: 0x10,
                sid: group.as_ptr() as usize,
            },
        ];
        let mut out = core::ptr::null_mut();
        assert_eq!(
            unsafe {
                rtl_create_and_set_sd(
                    entries.as_ptr(),
                    2,
                    owner.as_ptr(),
                    group.as_ptr(),
                    &mut out,
                )
            },
            STATUS_SUCCESS
        );
        let view: SecurityDescriptor = read(out as *const u8);
        assert_eq!(view.revision, 1);
        assert_eq!(view.owner, owner.as_ptr() as usize);
        assert_eq!(view.group, group.as_ptr() as usize);
        assert!(view.control & SE_DACL_PRESENT != 0);
        assert!(view.control & SE_SACL_PRESENT == 0);
        assert_eq!(
            unsafe { rtl_valid_security_descriptor(out as *const u8) },
            1
        );
        let dacl = view.dacl as *const u8;
        assert_eq!(acl_of(dacl).ace_count, 1);
        let header = core::mem::size_of::<SecurityDescriptor>();
        let sacl = (out as usize + header + 8 + 24) as *const u8;
        assert_eq!(acl_of(sacl).ace_count, 1);
        assert!(heap_free(out as usize));
        // An unknown ACE type is rejected.
        let bad = [AceData {
            ace_type: 9,
            sid: owner.as_ptr() as usize,
            ..AceData::default()
        }];
        assert_eq!(
            unsafe {
                rtl_create_and_set_sd(bad.as_ptr(), 1, owner.as_ptr(), group.as_ptr(), &mut out)
            },
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn access_masks_compare() {
        assert_eq!(unsafe { rtl_are_all_accesses_granted(0xF0, 0x10) }, 1);
        assert_eq!(unsafe { rtl_are_all_accesses_granted(0xF0, 0x100) }, 0);
        assert_eq!(unsafe { rtl_are_any_accesses_granted(0xF0, 0x100) }, 0);
        assert_eq!(unsafe { rtl_are_any_accesses_granted(0xF0, 0x10) }, 1);
    }
}
