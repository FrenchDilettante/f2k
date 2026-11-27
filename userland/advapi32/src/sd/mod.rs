//! The security descriptor calls: InitializeSecurityDescriptor, IsValidSecurityDescriptor,
//! GetSecurityDescriptorLength/Control, the Dacl/Sacl/Owner/Group getters and setters, the
//! RMControl pair, SetSecurityDescriptorControl and MakeSelfRelativeSD, as Windows 2000's
//! advapi32 answers them. The builders over trustee and access lists are in [`build`], the
//! string conversions in [`sddl`].
//!
//! A security descriptor is winnt.h's: a revision, a reserved byte, a control word, then four
//! dword fields (owner, group, SACL, DACL) — absolute addresses in the absolute form, offsets
//! from the descriptor's own address in the self-relative form. The fields hold pointers, so on
//! the host the tests run on each takes a whole pointer's width where the target takes a dword
//! (as [`crate::sid::PTR`]); [`SD_HEADER`] is the header's storage, [`SD_TARGET_HEADER`] its size
//! on the target, which is what the lengths report.

pub(crate) mod build;
pub(crate) mod sddl;
#[cfg(test)]
mod tests;

use rtl::heap::ProcessHeap as _;
use rtl::pod::Pod;
use rtl::stub::Memory as _;
use rtl::winerror::{
    ERROR_INVALID_DATA, ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER,
};

use crate::acl::{caller_acl, ACL_HEADER};
use crate::acl::edit::valid_acl;
use crate::imports::{self as nt, ProcessHeap, Probed};
use crate::sid::{
    caller_sid, ptr_field, set_ptr_field, valid_sid, ERROR_INVALID_SECURITY_DESCR,
    ERROR_UNKNOWN_REVISION, PTR, SID_HEADER,
};
use crate::{caller_bytes, caller_bytes_mut, Out};

// --- The security descriptor's layout (winnt.h's) ----------------------------------------------

/// The security descriptor's revision (SECURITY_DESCRIPTOR_REVISION).
pub(crate) const SD_REVISION: u8 = 1;
/// The header's size on the target: the revision, the reserved byte, the control word, and four
/// dword fields.
pub(crate) const SD_TARGET_HEADER: usize = 20;
/// The header's storage: each of the four fields takes a pointer's width on the host.
pub(crate) const SD_HEADER: usize = 4 + 4 * PTR;

const SD_REV: usize = 0;
const SD_SBZ1: usize = 1;
const SD_CONTROL: usize = 2;

/// The offset of the `index`th field: owner, group, SACL, DACL.
pub(crate) const fn sd_field(index: usize) -> usize {
    4 + index * PTR
}
/// The fields' indices.
pub(crate) const FIELD_OWNER: usize = 0;
pub(crate) const FIELD_GROUP: usize = 1;
pub(crate) const FIELD_SACL: usize = 2;
pub(crate) const FIELD_DACL: usize = 3;

// --- The control bits (winnt.h's SE_*) ----------------------------------------------------------

pub(crate) const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub(crate) const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub(crate) const SE_DACL_PRESENT: u16 = 0x0004;
pub(crate) const SE_DACL_DEFAULTED: u16 = 0x0008;
pub(crate) const SE_SACL_PRESENT: u16 = 0x0010;
pub(crate) const SE_SACL_DEFAULTED: u16 = 0x0020;
#[allow(dead_code)]
pub(crate) const SE_DACL_UNTRUSTED: u16 = 0x0040;
#[allow(dead_code)]
pub(crate) const SE_SERVER_SECURITY: u16 = 0x0080;
pub(crate) const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub(crate) const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub(crate) const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub(crate) const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub(crate) const SE_DACL_PROTECTED: u16 = 0x1000;
pub(crate) const SE_SACL_PROTECTED: u16 = 0x2000;
pub(crate) const SE_RM_CONTROL_VALID: u16 = 0x4000;
pub(crate) const SE_SELF_RELATIVE: u16 = 0x8000;

/// The control bits SetSecurityDescriptorControl may touch.
pub(crate) const SE_VALID_CONTROL_BITS: u32 = 0x3FC0;

/// The SECURITY_INFORMATION bits the string conversion takes.
pub(crate) const OWNER_SECURITY_INFORMATION: u32 = 0x1;
pub(crate) const GROUP_SECURITY_INFORMATION: u32 = 0x2;
pub(crate) const DACL_SECURITY_INFORMATION: u32 = 0x4;
pub(crate) const SACL_SECURITY_INFORMATION: u32 = 0x8;

/// Long-align a size (to a dword).
pub(crate) const fn long_align(size: usize) -> usize {
    (size + 3) & !3
}

// --- Small readers and writers ------------------------------------------------------------------

pub(crate) fn control(sd: &[u8]) -> u16 {
    u16::read_from(sd, SD_CONTROL).unwrap_or(0)
}

fn set_control(sd: &mut [u8], value: u16) {
    if let Some(slot) = sd.get_mut(SD_CONTROL..SD_CONTROL + 2) {
        slot.copy_from_slice(&value.to_le_bytes());
    }
}

/// The value of the `index`th field: an absolute address, or an offset when self-relative.
pub(crate) fn sd_field_value(sd: &[u8], index: usize) -> usize {
    ptr_field(sd, sd_field(index)).unwrap_or(0)
}

fn set_sd_field_value(sd: &mut [u8], index: usize, value: usize) {
    set_ptr_field(sd, sd_field(index), value);
}

/// The caller's security descriptor: none for null.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read.
pub(crate) unsafe fn caller_sd<'a>(sd: *const u8) -> Option<&'a [u8]> {
    // SAFETY: the caller's security descriptor's header.
    unsafe { caller_bytes(sd, SD_HEADER) }
}

/// The caller's security descriptor, writable.
///
/// # Safety
///
/// As [`caller_sd`]'s, for one the call may also write.
pub(crate) unsafe fn caller_sd_mut<'a>(sd: *mut u8) -> Option<&'a mut [u8]> {
    // SAFETY: the caller's security descriptor's header.
    unsafe { caller_bytes_mut(sd, SD_HEADER) }
}

/// The address of the `index`th component: the field's value when the descriptor is absolute,
/// the descriptor's own address plus the offset when self-relative; none when the field is zero
/// or — for the ACL fields — the PRESENT flag is clear.
pub(crate) fn component_addr(base: usize, sd: &[u8], index: usize) -> Option<usize> {
    let present_bit = match index {
        FIELD_SACL => SE_SACL_PRESENT,
        FIELD_DACL => SE_DACL_PRESENT,
        _ => 0,
    };
    if present_bit != 0 && control(sd) & present_bit == 0 {
        return None;
    }
    let field = sd_field_value(sd, index);
    if field == 0 {
        return None;
    }
    Some(if control(sd) & SE_SELF_RELATIVE != 0 {
        base + field
    } else {
        field
    })
}

/// Whether the `len` bytes at `at` are readable: probed at both ends (the probe answers for the
/// whole page range in practice; the lowest 64 KiB are never mapped).
fn readable(at: usize, len: usize) -> bool {
    len == 0 || (Probed.readable(at) && Probed.readable(at + len - 1))
}

/// The SID at `at`, probed first: none when its bytes cannot be read. The validity check reads
/// the descriptor's components under a guard on the platform, answering "not valid" where a read
/// faults, so the probe stands in for the guard here.
///
/// # Safety
///
/// The component's address resolves into memory the call may read.
pub(crate) unsafe fn guarded_sid<'a>(at: usize) -> Option<&'a [u8]> {
    if !readable(at, SID_HEADER) {
        return None;
    }
    // SAFETY: the probe found the header readable.
    let sid = unsafe { caller_sid(at as *const u8) }?;
    if !readable(at, sid.len()) {
        return None;
    }
    Some(sid)
}

/// The ACL at `at`, probed first, as [`guarded_sid`].
///
/// # Safety
///
/// As [`guarded_sid`]'s.
unsafe fn guarded_acl<'a>(at: usize) -> Option<&'a [u8]> {
    if !readable(at, ACL_HEADER) {
        return None;
    }
    // SAFETY: the probe found the header readable.
    let acl = unsafe { caller_acl(at as *const u8) }?;
    if !readable(at, acl.len()) {
        return None;
    }
    Some(acl)
}

/// The SID component `index` of the descriptor at `base`, read whole (its count says how long).
///
/// # Safety
///
/// The descriptor and its component are readable.
unsafe fn component_sid<'a>(base: usize, sd: &[u8], index: usize) -> Option<&'a [u8]> {
    let at = component_addr(base, sd, index)?;
    // SAFETY: the component's address resolves into memory the call may read.
    unsafe { caller_sid(at as *const u8) }
}

/// The ACL component `index` of the descriptor at `base`, read whole (its header's size says
/// how long).
///
/// # Safety
///
/// As [`component_sid`]'s.
unsafe fn component_acl<'a>(base: usize, sd: &[u8], index: usize) -> Option<&'a [u8]> {
    let at = component_addr(base, sd, index)?;
    // SAFETY: the component's address resolves into memory the call may read.
    unsafe { caller_acl(at as *const u8) }
}

/// Whether the descriptor at `base` is valid: revision 1, and every component it names (owner
/// and group when their fields are non-zero, the ACLs when their PRESENT flag is set) well
/// formed. The components are read probed, as the platform's validity check reads them under a
/// guard: one whose bytes cannot be read makes the descriptor invalid, not a fault.
pub(crate) fn valid_sd(base: usize, sd: &[u8]) -> bool {
    if !readable(base, SD_TARGET_HEADER) || sd.first() != Some(&SD_REVISION) {
        return false;
    }
    // SAFETY: the descriptor's components are read as it names them, probed.
    unsafe {
        // A component the descriptor names but whose bytes cannot be read makes it invalid: the
        // platform's check reads them under a guard and answers "not valid" where the read faults.
        for index in [FIELD_OWNER, FIELD_GROUP] {
            match component_addr(base, sd, index) {
                None => {}
                Some(at) => match guarded_sid(at) {
                    Some(sid) if valid_sid(sid) => {}
                    _ => return false,
                },
            }
        }
        if control(sd) & SE_DACL_PRESENT != 0 {
            match component_addr(base, sd, FIELD_DACL).and_then(|at| guarded_acl(at)) {
                Some(dacl) if valid_acl(dacl) => {}
                _ => return false,
            }
        }
        if control(sd) & SE_SACL_PRESENT != 0 {
            match component_addr(base, sd, FIELD_SACL).and_then(|at| guarded_acl(at)) {
                Some(sacl) if valid_acl(sacl) => {}
                _ => return false,
            }
        }
    }
    true
}

/// The descriptor's length on the target: the header plus each component it names, long-aligned.
///
/// # Safety
///
/// The descriptor's components are read as it names them.
pub(crate) unsafe fn sd_length(base: usize, sd: &[u8]) -> usize {
    let mut sum = SD_TARGET_HEADER;
    // SAFETY: as [`valid_sd`]'s.
    unsafe {
        if let Some(owner) = component_sid(base, sd, FIELD_OWNER) {
            sum += long_align(owner.len());
        }
        if let Some(group) = component_sid(base, sd, FIELD_GROUP) {
            sum += long_align(group.len());
        }
        if let Some(dacl) = component_acl(base, sd, FIELD_DACL) {
            sum += long_align(dacl.len().max(ACL_HEADER));
        }
        if let Some(sacl) = component_acl(base, sd, FIELD_SACL) {
            sum += long_align(sacl.len().max(ACL_HEADER));
        }
    }
    sum
}

/// The components' sizes the packing needs: (owner, group, sacl, dacl) byte slices, for the
/// components the descriptor names.
///
/// # Safety
///
/// As [`valid_sd`]'s.
pub(crate) unsafe fn sd_components(base: usize, sd: &[u8]) -> [Option<&[u8]>; 4] {
    // SAFETY: as [`valid_sd`]'s.
    unsafe {
        [
            component_sid(base, sd, FIELD_OWNER),
            component_sid(base, sd, FIELD_GROUP),
            component_acl(base, sd, FIELD_SACL),
            component_acl(base, sd, FIELD_DACL),
        ]
    }
}

/// The total of the header and the long-aligned component sizes.
pub(crate) fn packed_size(components: &[Option<&[u8]>; 4]) -> usize {
    let mut sum = SD_TARGET_HEADER;
    for component in components.iter().flatten() {
        sum += long_align(component.len());
    }
    sum
}

/// A growable buffer of `T` on the process heap (the DLL's code has no allocator): doubled when
/// it runs out of room, freed when dropped. Its methods answer none when the heap has no room.
struct HeapVec<T: Copy> {
    block: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> HeapVec<T> {
    /// An empty buffer.
    fn new() -> Self {
        Self {
            block: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    /// A buffer of `len` zeroed values (the heap's blocks come zeroed).
    fn zeroed(len: usize) -> Option<Self> {
        let mut buffer = Self::new();
        buffer.reserve(len)?;
        buffer.len = len;
        Some(buffer)
    }

    /// The values it holds.
    fn len(&self) -> usize {
        self.len
    }

    /// Whether it holds none.
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The values, as a slice.
    fn as_slice(&self) -> &[T] {
        if self.len == 0 {
            &[]
        } else {
            // SAFETY: the block holds `len` values, ours until dropped.
            unsafe { core::slice::from_raw_parts(self.block, self.len) }
        }
    }

    /// The values, as a writable slice.
    fn as_mut_slice(&mut self) -> &mut [T] {
        if self.len == 0 {
            &mut []
        } else {
            // SAFETY: as `as_slice`'s, writable.
            unsafe { core::slice::from_raw_parts_mut(self.block, self.len) }
        }
    }

    /// Room for `extra` more values.
    fn reserve(&mut self, extra: usize) -> Option<()> {
        let needed = self.len.checked_add(extra)?;
        if needed <= self.cap {
            return Some(());
        }
        let mut cap = self.cap.max(16);
        while cap < needed {
            cap = cap.checked_mul(2)?;
        }
        let block = ProcessHeap::allocate(cap * core::mem::size_of::<T>());
        if block.is_null() {
            return None;
        }
        if !self.block.is_null() {
            // SAFETY: the old block's `len` values copied into the new one; both ours, the old
            // freed once.
            unsafe {
                core::ptr::copy_nonoverlapping(self.block, block.cast::<T>(), self.len);
                ProcessHeap::free(self.block.cast());
            }
        }
        self.block = block.cast();
        self.cap = cap;
        Some(())
    }

    /// `value` added at the end.
    fn push(&mut self, value: T) -> Option<()> {
        self.reserve(1)?;
        // SAFETY: the block has room for one more.
        unsafe { self.block.add(self.len).write(value) };
        self.len += 1;
        Some(())
    }

    /// `values` added at the end.
    fn extend_from_slice(&mut self, values: &[T]) -> Option<()> {
        self.reserve(values.len())?;
        // SAFETY: room for all of them in the block.
        unsafe {
            core::ptr::copy_nonoverlapping(values.as_ptr(), self.block.add(self.len), values.len())
        };
        self.len += values.len();
        Some(())
    }

    /// The values of `iter` added at the end.
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) -> Option<()> {
        for value in iter {
            self.push(value)?;
        }
        Some(())
    }
}

impl<T: Copy> Default for HeapVec<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> Drop for HeapVec<T> {
    fn drop(&mut self) {
        if !self.block.is_null() {
            // SAFETY: the block is one `allocate` answered, not freed since.
            unsafe { ProcessHeap::free(self.block.cast()) };
        }
    }
}

impl<T: Copy> core::ops::Deref for HeapVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> core::ops::DerefMut for HeapVec<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

// --- The exports --------------------------------------------------------------------------------

/// InitializeSecurityDescriptor: the descriptor at `sd` zeroed, its revision set to 1
/// (another revision: ERROR_UNKNOWN_REVISION); the last error untouched on success. A null
/// descriptor faults where the zeroing writes, as the platform's unprobed write does.
///
/// # Safety
///
/// `sd` is null or a writable security descriptor's header.
#[unsafe(export_name = "f2k_export_InitializeSecurityDescriptor")]
pub unsafe extern "system" fn initialize_security_descriptor(
    sd: *mut u8,
    revision: u32,
) -> u32 {
    if revision != u32::from(SD_REVISION) {
        nt::set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    // SAFETY: the caller's descriptor.
    let buffer = unsafe { caller_bytes_mut(sd, SD_HEADER) };
    let Some(buffer) = buffer else {
        // A null descriptor: the header's write faults the caller.
        unsafe { sd.write(0) };
        unreachable!("the write above faults")
    };
    buffer.fill(0);
    buffer[SD_REV] = SD_REVISION;
    1
}

/// IsValidSecurityDescriptor: whether the descriptor at `sd` is valid; ERROR_INVALID_SECURITY_DESCR
/// when not (a null included).
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read.
#[unsafe(export_name = "f2k_export_IsValidSecurityDescriptor")]
pub unsafe extern "system" fn is_valid_security_descriptor(sd: *const u8) -> u32 {
    // SAFETY: the caller's descriptor.
    let buffer = unsafe { caller_sd(sd) };
    if buffer.is_some_and(|sd| valid_sd(sd.as_ptr() as usize, sd)) {
        1
    } else {
        nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
        0
    }
}

/// GetSecurityDescriptorLength: the bytes the descriptor at `sd` takes, its components included.
/// A null descriptor faults where the revision is read.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorLength")]
pub unsafe extern "system" fn get_security_descriptor_length(sd: *const u8) -> u32 {
    // SAFETY: the caller's descriptor.
    let buffer = unsafe { caller_sd(sd) };
    let Some(buffer) = buffer else {
        // A null descriptor: the revision's read faults the caller. The read is volatile so
        // the fault is the read's, not the optimizer's (a plain read of a null pointer is
        // undefined behavior, which the optimizer turns into a trap).
        unsafe { core::ptr::read_volatile(sd) };
        unreachable!("the read above faults")
    };
    // SAFETY: the descriptor's components are read as it names them.
    let length = unsafe { sd_length(sd as usize, buffer) };
    length as u32
}

/// GetSecurityDescriptorControl: the descriptor's control word into `control` and its revision
/// into `revision` (the revision always written; another revision: ERROR_UNKNOWN_REVISION).
/// A null descriptor faults where its header is read.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read; the out parameters the caller's
/// places.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorControl")]
pub unsafe extern "system" fn get_security_descriptor_control(
    sd: *const u8,
    control_out: *mut u16,
    revision: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and places.
    let (buffer, mut control_out, mut revision) = unsafe {
        (
            caller_sd(sd),
            Out::optional(control_out),
            Out::optional(revision),
        )
    };
    let Some(buffer) = buffer else {
        // A null descriptor: the revision's read faults the caller. The read is volatile so
        // the fault is the read's, not the optimizer's (a plain read of a null pointer is
        // undefined behavior, which the optimizer turns into a trap).
        unsafe { core::ptr::read_volatile(sd) };
        unreachable!("the read above faults")
    };
    if let Some(revision) = revision.as_mut() {
        revision.set(u32::from(buffer[SD_REV]));
    }
    if buffer[SD_REV] != SD_REVISION {
        nt::set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    if let Some(control_out) = control_out.as_mut() {
        control_out.set(control(buffer));
    }
    1
}

/// SetSecurityDescriptorControl: the control bits of `interest` replaced by `to_set` (bits
/// outside the valid set, or `to_set` bits outside `interest`: ERROR_INVALID_PARAMETER).
///
/// # Safety
///
/// `sd` is null or a writable security descriptor's header.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorControl")]
pub unsafe extern "system" fn set_security_descriptor_control(
    sd: *mut u8,
    interest: u32,
    to_set: u32,
) -> u32 {
    let interest = (interest as u16) as u32;
    let to_set = (to_set as u16) as u32;
    if interest & !SE_VALID_CONTROL_BITS != 0 || to_set & !interest != 0 {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    // SAFETY: the caller's descriptor.
    let buffer = unsafe { caller_sd_mut(sd) };
    let Some(buffer) = buffer else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let current = u32::from(control(buffer));
    set_control(buffer, ((current & !interest) | to_set) as u16);
    1
}

/// The getters' shared body: the component's address (resolved for the form) into `out`, the
/// PRESENT flag (for the ACL fields) and the DEFAULTED flag into their places. The revision
/// outside 1 is ERROR_UNKNOWN_REVISION.
///
/// # Safety
///
/// As the getters'.
#[allow(clippy::too_many_arguments)]
unsafe fn get_component(
    sd: *const u8,
    index: usize,
    present_bit: u16,
    defaulted_bit: u16,
    present_out: *mut u32,
    out: *mut *mut u8,
    defaulted_out: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and places.
    let (buffer, mut present_out, mut out, mut defaulted_out) = unsafe {
        (
            caller_sd(sd),
            Out::optional(present_out),
            Out::optional(out),
            Out::optional(defaulted_out),
        )
    };
    let (Some(buffer), Some(out)) = (buffer, out.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if buffer[SD_REV] != SD_REVISION {
        nt::set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    let current = control(buffer);
    if let Some(present_out) = present_out.as_mut() {
        present_out.set(u32::from(current & present_bit != 0));
    }
    // SAFETY: the component's address resolves into memory the call may read.
    let at = component_addr(sd as usize, buffer, index);
    out.set(at.map_or(core::ptr::null_mut(), |at| at as *mut u8));
    if let Some(defaulted_out) = defaulted_out.as_mut() {
        defaulted_out.set(u32::from(current & defaulted_bit != 0));
    }
    1
}

/// The setters' shared body: the component's field set to `value` (the DEFAULTED flag per
/// `defaulted`); for the ACL fields, `present` 0 clears only the PRESENT flag. The revision
/// outside 1 is ERROR_UNKNOWN_REVISION, a self-relative descriptor ERROR_INVALID_SECURITY_DESCR.
///
/// # Safety
///
/// As the setters'.
unsafe fn set_component(
    sd: *mut u8,
    index: usize,
    present_bit: u16,
    defaulted_bit: u16,
    present: u32,
    value: *const u8,
    defaulted: u32,
) -> u32 {
    // SAFETY: the caller's descriptor.
    let buffer = unsafe { caller_sd_mut(sd) };
    let Some(buffer) = buffer else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    if buffer[SD_REV] != SD_REVISION {
        nt::set_last_error(ERROR_UNKNOWN_REVISION);
        return 0;
    }
    let mut current = control(buffer);
    if current & SE_SELF_RELATIVE != 0 {
        nt::set_last_error(ERROR_INVALID_SECURITY_DESCR);
        return 0;
    }
    if present_bit != 0 && present == 0 {
        // Only the PRESENT flag is cleared.
        current &= !present_bit;
        set_control(buffer, current);
        return 1;
    }
    if present_bit != 0 {
        current |= present_bit;
    }
    if defaulted != 0 {
        current |= defaulted_bit;
    } else {
        current &= !defaulted_bit;
    }
    set_control(buffer, current);
    set_sd_field_value(buffer, index, value as usize);
    1
}

/// GetSecurityDescriptorDacl: the DACL's presence, address and defaulted flag.
///
/// # Safety
///
/// `sd` is a security descriptor the call may read; the rest the caller's places.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorDacl")]
pub unsafe extern "system" fn get_security_descriptor_dacl(
    sd: *const u8,
    present: *mut u32,
    dacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    unsafe {
        get_component(
            sd,
            FIELD_DACL,
            SE_DACL_PRESENT,
            SE_DACL_DEFAULTED,
            present,
            dacl,
            defaulted,
        )
    }
}

/// SetSecurityDescriptorDacl: the DACL field and flags (a null `present` clears only the PRESENT
/// flag).
///
/// # Safety
///
/// As the getter's, `dacl` a DACL the call may read.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorDacl")]
pub unsafe extern "system" fn set_security_descriptor_dacl(
    sd: *mut u8,
    present: u32,
    dacl: *const u8,
    defaulted: u32,
) -> u32 {
    unsafe {
        set_component(
            sd,
            FIELD_DACL,
            SE_DACL_PRESENT,
            SE_DACL_DEFAULTED,
            present,
            dacl,
            defaulted,
        )
    }
}

/// GetSecurityDescriptorSacl: as the DACL getter, for the SACL.
///
/// # Safety
///
/// As the DACL getter's.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorSacl")]
pub unsafe extern "system" fn get_security_descriptor_sacl(
    sd: *const u8,
    present: *mut u32,
    sacl: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    unsafe {
        get_component(
            sd,
            FIELD_SACL,
            SE_SACL_PRESENT,
            SE_SACL_DEFAULTED,
            present,
            sacl,
            defaulted,
        )
    }
}

/// SetSecurityDescriptorSacl: as the DACL setter, for the SACL.
///
/// # Safety
///
/// As the DACL setter's.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorSacl")]
pub unsafe extern "system" fn set_security_descriptor_sacl(
    sd: *mut u8,
    present: u32,
    sacl: *const u8,
    defaulted: u32,
) -> u32 {
    unsafe {
        set_component(
            sd,
            FIELD_SACL,
            SE_SACL_PRESENT,
            SE_SACL_DEFAULTED,
            present,
            sacl,
            defaulted,
        )
    }
}

/// GetSecurityDescriptorOwner: the owner's address and defaulted flag.
///
/// # Safety
///
/// As the DACL getter's.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorOwner")]
pub unsafe extern "system" fn get_security_descriptor_owner(
    sd: *const u8,
    owner: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    unsafe {
        get_component(
            sd,
            FIELD_OWNER,
            0,
            SE_OWNER_DEFAULTED,
            core::ptr::null_mut(),
            owner,
            defaulted,
        )
    }
}

/// SetSecurityDescriptorOwner: the owner field and defaulted flag.
///
/// # Safety
///
/// As the DACL setter's, `owner` a SID the call may read.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorOwner")]
pub unsafe extern "system" fn set_security_descriptor_owner(
    sd: *mut u8,
    owner: *const u8,
    defaulted: u32,
) -> u32 {
    unsafe { set_component(sd, FIELD_OWNER, 0, SE_OWNER_DEFAULTED, 1, owner, defaulted) }
}

/// GetSecurityDescriptorGroup: as the owner getter, for the group.
///
/// # Safety
///
/// As the DACL getter's.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorGroup")]
pub unsafe extern "system" fn get_security_descriptor_group(
    sd: *const u8,
    group: *mut *mut u8,
    defaulted: *mut u32,
) -> u32 {
    unsafe {
        get_component(
            sd,
            FIELD_GROUP,
            0,
            SE_GROUP_DEFAULTED,
            core::ptr::null_mut(),
            group,
            defaulted,
        )
    }
}

/// SetSecurityDescriptorGroup: as the owner setter, for the group.
///
/// # Safety
///
/// As the DACL setter's.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorGroup")]
pub unsafe extern "system" fn set_security_descriptor_group(
    sd: *mut u8,
    group: *const u8,
    defaulted: u32,
) -> u32 {
    unsafe { set_component(sd, FIELD_GROUP, 0, SE_GROUP_DEFAULTED, 1, group, defaulted) }
}

/// GetSecurityDescriptorRMControl: the resource-manager control byte into `rm`; the error code
/// itself as the answer — ERROR_INVALID_DATA (and a zero byte) when the valid bit is clear.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read; `rm` the caller's byte.
#[unsafe(export_name = "f2k_export_GetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn get_security_descriptor_rm_control(
    sd: *const u8,
    rm: *mut u8,
) -> u32 {
    // SAFETY: the caller's descriptor and byte.
    let (buffer, mut rm) = unsafe { (caller_sd(sd), Out::optional(rm)) };
    let (Some(buffer), Some(rm)) = (buffer, rm.as_mut()) else {
        return ERROR_INVALID_PARAMETER;
    };
    if control(buffer) & SE_RM_CONTROL_VALID == 0 {
        rm.set(0);
        return ERROR_INVALID_DATA;
    }
    rm.set(buffer[SD_SBZ1]);
    0
}

/// SetSecurityDescriptorRMControl: the resource-manager control byte from `rm` (the valid bit
/// set), or the valid bit cleared for a null `rm`; the answer is always ERROR_SUCCESS.
///
/// # Safety
///
/// `sd` is null or a writable descriptor; `rm` null or the caller's byte.
#[unsafe(export_name = "f2k_export_SetSecurityDescriptorRMControl")]
pub unsafe extern "system" fn set_security_descriptor_rm_control(
    sd: *mut u8,
    rm: *const u8,
) -> u32 {
    // SAFETY: the caller's descriptor and byte.
    let (buffer, rm) = unsafe { (caller_sd_mut(sd), caller_bytes(rm, 1)) };
    let Some(buffer) = buffer else {
        return ERROR_INVALID_PARAMETER;
    };
    let mut current = control(buffer);
    match rm {
        Some(byte) => {
            buffer[SD_SBZ1] = byte[0];
            current |= SE_RM_CONTROL_VALID;
        }
        None => {
            current &= !SE_RM_CONTROL_VALID;
        }
    }
    set_control(buffer, current);
    0
}

/// MakeSelfRelativeSD: the descriptor at `absolute` packed into `relative` in the self-relative
/// form (the components copied after the header, the fields their offsets, SE_SELF_RELATIVE
/// set); when the room `length` points at is short, the size needed goes there and the last
/// error is ERROR_INSUFFICIENT_BUFFER.
///
/// # Safety
///
/// `absolute` is null or a security descriptor the call may read; `relative` null or
/// `*length` writable bytes; `length` the caller's place for the room.
#[unsafe(export_name = "f2k_export_MakeSelfRelativeSD")]
pub unsafe extern "system" fn make_self_relative_sd(
    absolute: *const u8,
    relative: *mut u8,
    length: *mut u32,
) -> u32 {
    // SAFETY: the caller's descriptor and place.
    let (source, mut room) = unsafe { (caller_sd(absolute), Out::optional(length)) };
    let (Some(source), Some(room)) = (source, room.as_mut()) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the source's components are read as it names them.
    let components = unsafe { sd_components(absolute as usize, source) };
    let needed = packed_size(&components);
    if relative.is_null() || room.get() < needed as u32 {
        room.set(needed as u32);
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // The storage is the header plus the components; on the host the header's fields take more
    // room than on the target, so the buffer read covers the whole of it.
    let used = SD_HEADER + components.iter().flatten().map(|c| long_align(c.len())).sum::<usize>();
    // SAFETY: the caller's buffer of `used` bytes at least.
    let out = unsafe { caller_bytes_mut(relative, used.max(needed)) };
    let Some(out) = out else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    out.fill(0);
    out[..4].copy_from_slice(&source[..4]);
    // The components are packed SACL, DACL, owner, group, at running long-aligned offsets.
    let mut running = SD_HEADER;
    for index in [FIELD_SACL, FIELD_DACL, FIELD_OWNER, FIELD_GROUP] {
        if let Some(component) = &components[index] {
            running = long_align(running);
            out[running..running + component.len()].copy_from_slice(component);
            set_sd_field_value(out, index, running);
            running += long_align(component.len());
        }
    }
    let mut current = control(out);
    current |= SE_SELF_RELATIVE;
    set_control(out, current);
    room.set(needed as u32);
    1
}
