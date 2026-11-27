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

/// Write `value` as a BOOLEAN out parameter at `at`: a single byte, leaving the
/// rest of the caller's dword alone (the get routines' flag outs are bytes).
fn set_boolean(at: *mut u32, value: bool) {
    // SAFETY: the caller's out parameter holds a byte to write.
    unsafe { (at as *mut u8).write_unaligned(u8::from(value)) };
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

// The helpers are split by structure: SIDs, ACLs and ACEs, security descriptors (and their
// absolute/self-relative conversion), and the access-mask comparisons with the few routines
// that reach the token services. Each submodule carries its own tests.
pub(crate) mod access;
pub(crate) mod aces;
pub(crate) mod acl;
pub(crate) mod convert;
pub(crate) mod object;
pub(crate) mod sd;
pub(crate) mod sid;

pub(crate) use aces::*;
pub(crate) use acl::*;
pub(crate) use sd::*;
pub(crate) use sid::*;

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// BUILTIN\Administrators, S-1-5-32-544.
    pub(crate) fn admins() -> [u8; 16] {
        let mut sid = [0u8; 16];
        sid[0] = 1;
        sid[1] = 2;
        sid[2..8].copy_from_slice(&NT_AUTHORITY);
        sid[8..12].copy_from_slice(&32u32.to_le_bytes());
        sid[12..16].copy_from_slice(&544u32.to_le_bytes());
        sid
    }

    /// Everyone, S-1-1-0.
    pub(crate) fn world() -> [u8; 12] {
        let mut sid = [0u8; 12];
        sid[0] = 1;
        sid[1] = 1;
        sid[2..8].copy_from_slice(&WORLD_AUTHORITY);
        sid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

