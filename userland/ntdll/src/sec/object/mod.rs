//! The security-object wrappers: the routines that answer for an object's stored security
//! descriptor, split by shape — the query and set wrappers over the security-object services on
//! the object's handle (`mod.rs`), the in-memory descriptor lifecycle (`create`), and the
//! impersonation no-op with the LUID helpers (`luid`).
//!
//! The query and set wrappers are passthroughs of the services: the caller names the parts in its
//! SECURITY_INFORMATION and the service does the work (a query fills a self-relative descriptor
//! and reports its size, a set merges the named parts into the stored one). The generic mapping
//! and the token arguments the public contract carries are the service's own concern — the
//! service maps generic rights and checks the caller's token itself — so the wrappers leave them
//! alone.
//!
//! In the host tests the two services stand in over a mock object store (see `mock`), so the
//! tests pin the argument forwarding, the status and out-parameter flow, and a set-then-query
//! round trip.

use super::*;

// The SECURITY_INFORMATION bits past the owner and group ones mod.rs carries.
#[cfg(test)]
const DACL_SECURITY_INFORMATION: u32 = 0x4;
#[cfg(test)]
const SACL_SECURITY_INFORMATION: u32 = 0x8;

mod create;
mod luid;

// --- The security-object services: the target's gate, the host tests' mock -------------------

/// The target's NtQuerySecurityObject, over the service gate.
#[cfg(not(test))]
fn secobj_query(handle: u32, info: u32, descriptor: *mut u8, length: u32, needed: *mut u32) -> u32 {
    use rtl::sys::nr;
    service(
        nr::NtQuerySecurityObject,
        &[handle, info, descriptor as u32, length, needed as u32],
    )
}

/// The host tests' stand-in: the mock store's answer.
#[cfg(test)]
fn secobj_query(handle: u32, info: u32, descriptor: *mut u8, length: u32, needed: *mut u32) -> u32 {
    mock::query(handle, info, descriptor, length, needed)
}

/// The target's NtSetSecurityObject, over the service gate.
#[cfg(not(test))]
fn secobj_set(handle: u32, info: u32, descriptor: *const u8) -> u32 {
    use rtl::sys::nr;
    service(nr::NtSetSecurityObject, &[handle, info, descriptor as u32])
}

/// The host tests' stand-in: the mock store's merge.
#[cfg(test)]
fn secobj_set(handle: u32, info: u32, descriptor: *const u8) -> u32 {
    mock::set(handle, info, descriptor)
}

// --- The wrappers over the services -----------------------------------------------------------

/// RtlQuerySecurityObject: the object `handle`'s stored descriptor of the `info` parts into
/// `resultant` (of `descriptor_length` bytes), the size the answer takes into `return_length` —
/// a passthrough of the query service.
#[unsafe(export_name = "f2k_export_RtlQuerySecurityObject")]
pub unsafe extern "system" fn rtl_query_security_object(
    object_handle: u32,
    security_information: u32,
    resultant_descriptor: *mut u8,
    descriptor_length: u32,
    return_length: *mut u32,
) -> u32 {
    secobj_query(
        object_handle,
        security_information,
        resultant_descriptor,
        descriptor_length,
        return_length,
    )
}

/// RtlSetSecurityObject: the object `handle`'s descriptor of the `security_information` parts
/// replaced with `modification_descriptor`'s — a passthrough of the set service.
#[unsafe(export_name = "f2k_export_RtlSetSecurityObject")]
pub unsafe extern "system" fn rtl_set_security_object(
    security_information: u32,
    modification_descriptor: *const u8,
    object_handle: u32,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    secobj_set(object_handle, security_information, modification_descriptor)
}

/// RtlSetSecurityObjectEx: as RtlSetSecurityObject; the auto-inherit flags name no extra part in
/// F2K, the set service merges the parts `security_information` names.
#[unsafe(export_name = "f2k_export_RtlSetSecurityObjectEx")]
pub unsafe extern "system" fn rtl_set_security_object_ex(
    security_information: u32,
    modification_descriptor: *const u8,
    object_handle: u32,
    _auto_inherit_flags: u32,
    _generic_mapping: *const u8,
    _token: u32,
) -> u32 {
    secobj_set(object_handle, security_information, modification_descriptor)
}

// --- The host tests' mock of the two services ---------------------------------------------------

/// The host stand-in for the security-object services: a per-handle store of an object's
/// control word and its four parts (owner, group, SACL, DACL, each present or not), answering
/// queries with a self-relative descriptor of the named parts and merging sets into the store.
/// It also records every call's argument block, so the tests pin what the wrappers forwarded.
#[cfg(test)]
mod mock {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use rtl::status::{STATUS_ACCESS_VIOLATION, STATUS_INVALID_HANDLE};

    use super::*;

    /// The query service's call tag, the set service's.
    pub(crate) const QUERY: u32 = 1;
    pub(crate) const SET: u32 = 2;

    /// One object's stored state.
    struct Object {
        control: u16,
        parts: [Option<Vec<u8>>; 4],
    }

    static OBJECTS: Mutex<BTreeMap<u32, Object>> = Mutex::new(BTreeMap::new());
    static CALLS: Mutex<Vec<(u32, Vec<u32>)>> = Mutex::new(Vec::new());
    /// The tests share the store, so each mock-using test holds this lock for its whole body.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// The SECURITY_INFORMATION bit of each part, in the parts' order (owner, group, SACL, DACL).
    const BITS: [u32; 4] = [
        OWNER_SECURITY_INFORMATION,
        GROUP_SECURITY_INFORMATION,
        SACL_SECURITY_INFORMATION,
        DACL_SECURITY_INFORMATION,
    ];
    /// The control bit a present ACL part carries.
    const PRESENT: [u16; 4] = [0, 0, SE_SACL_PRESENT, SE_DACL_PRESENT];
    /// The control bit a defaulted part carries.
    const DEFAULTED: [u16; 4] = [
        SE_OWNER_DEFAULTED,
        SE_GROUP_DEFAULTED,
        SE_SACL_DEFAULTED,
        SE_DACL_DEFAULTED,
    ];

    /// The whole-test lock a mock-using test holds.
    pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap()
    }

    /// Clear the store and the recorded calls.
    pub(crate) fn reset() {
        OBJECTS.lock().unwrap().clear();
        CALLS.lock().unwrap().clear();
    }

    /// Install an object: its control word and its four parts (owner, group, SACL, DACL).
    pub(crate) fn add_object(handle: u32, control: u16, parts: [Option<Vec<u8>>; 4]) {
        OBJECTS
            .lock()
            .unwrap()
            .insert(handle, Object { control, parts });
    }

    /// The recorded calls: the service tag and its argument block.
    pub(crate) fn calls() -> Vec<(u32, Vec<u32>)> {
        CALLS.lock().unwrap().clone()
    }

    /// The mock query: the answer a fresh self-relative descriptor of the named parts takes,
    /// into `needed` on success and when the buffer is too short (STATUS_BUFFER_TOO_SMALL,
    /// nothing written); an unknown handle is STATUS_INVALID_HANDLE and writes nothing.
    pub(crate) fn query(
        handle: u32,
        info: u32,
        descriptor: *mut u8,
        length: u32,
        needed: *mut u32,
    ) -> u32 {
        CALLS.lock().unwrap().push((
            QUERY,
            vec![handle, info, descriptor as u32, length, needed as u32],
        ));
        if needed.is_null() {
            return STATUS_ACCESS_VIOLATION;
        }
        let objects = OBJECTS.lock().unwrap();
        let Some(object) = objects.get(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let mut control = SE_SELF_RELATIVE;
        let mut body: Vec<u8> = Vec::new();
        let mut offsets = [0u32; 4];
        for index in 0..4 {
            if info & BITS[index] == 0 {
                continue;
            }
            control |= object.control & (PRESENT[index] | DEFAULTED[index]);
            if let Some(part) = &object.parts[index] {
                while body.len() % 4 != 0 {
                    body.push(0);
                }
                offsets[index] = (20 + body.len()) as u32;
                body.extend_from_slice(part);
            }
        }
        let size = 20 + body.len();
        // SAFETY: the caller's out word.
        unsafe { needed.write_unaligned(size as u32) };
        if size > length as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let header = SecurityDescriptorRelative {
            revision: 1,
            sbz1: 0,
            control,
            owner: offsets[0],
            group: offsets[1],
            sacl: offsets[2],
            dacl: offsets[3],
        };
        // SAFETY: the caller's buffer holds `size` bytes.
        unsafe {
            write(descriptor, header);
            core::ptr::copy_nonoverlapping(body.as_ptr(), descriptor.add(20), body.len());
        }
        STATUS_SUCCESS
    }

    /// The mock set: the parts `info` names taken from the caller's descriptor (either form)
    /// into the object's stored parts; an unknown handle is STATUS_INVALID_HANDLE, a null
    /// descriptor STATUS_ACCESS_VIOLATION.
    pub(crate) fn set(handle: u32, info: u32, descriptor: *const u8) -> u32 {
        CALLS
            .lock()
            .unwrap()
            .push((SET, vec![handle, info, descriptor as u32]));
        if descriptor.is_null() {
            return STATUS_ACCESS_VIOLATION;
        }
        let mut objects = OBJECTS.lock().unwrap();
        let Some(object) = objects.get_mut(&handle) else {
            return STATUS_INVALID_HANDLE;
        };
        let control = sd_control(descriptor);
        let (addrs, sizes) = query_sd(descriptor);
        for index in 0..4 {
            if info & BITS[index] == 0 {
                continue;
            }
            object.parts[index] = if addrs[index] != 0 {
                // SAFETY: the part holds its aligned size of bytes.
                Some(unsafe { bytes(addrs[index] as *const u8, sizes[index]) }.to_vec())
            } else {
                None
            };
            if index >= 2 {
                object.control = (object.control & !PRESENT[index]) | (control & PRESENT[index]);
            }
        }
        STATUS_SUCCESS
    }
}
#[cfg(test)]
pub(crate) mod fixtures {
    //! The descriptor builders the tests of this module and of `create` share.

    use super::*;

    pub(crate) fn absolute_sd(owner: &[u8], group: &[u8], dacl: Option<&[u8]>) -> Vec<u8> {
        let mut sd = vec![0u8; 64];
        assert_eq!(
            unsafe { rtl_create_security_descriptor(sd.as_mut_ptr(), 1) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_owner_security_descriptor(sd.as_mut_ptr(), owner.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_set_group_security_descriptor(sd.as_mut_ptr(), group.as_ptr(), 0) },
            STATUS_SUCCESS
        );
        if let Some(dacl) = dacl {
            assert_eq!(
                unsafe {
                    rtl_set_dacl_security_descriptor(
                        sd.as_mut_ptr(),
                        1,
                        dacl.as_ptr() as *mut u8,
                        0,
                    )
                },
                STATUS_SUCCESS
            );
        }
        sd
    }

    pub(crate) fn dacl_with(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut acl = vec![0u8; 64];
        assert_eq!(
            unsafe { rtl_create_acl(acl.as_mut_ptr(), 64, 2) },
            STATUS_SUCCESS
        );
        assert_eq!(
            unsafe { rtl_add_access_allowed_ace(acl.as_mut_ptr(), 2, mask, sid.as_ptr()) },
            STATUS_SUCCESS
        );
        acl
    }
}

#[cfg(test)]
mod tests {
    use rtl::status::STATUS_INVALID_HANDLE;

    use super::fixtures::{absolute_sd, dacl_with};
    use super::*;
    use crate::sec::test_support::*;

    fn object_with_owner_and_dacl() -> (Vec<u8>, Vec<u8>) {
        let owner = admins().to_vec();
        let dacl = dacl_with(0x0012_019F, &world());
        mock::add_object(
            0x40,
            SE_DACL_PRESENT,
            [Some(owner.clone()), None, None, Some(dacl.clone())],
        );
        (owner, dacl)
    }

    #[test]
    fn a_query_forwards_its_arguments_and_reports_the_size() {
        let _guard = mock::test_lock();
        mock::reset();
        let (owner, dacl) = object_with_owner_and_dacl();
        let mut buffer = [0u8; 256];
        let mut needed = 0u32;
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        // Too small a buffer: the size comes out, nothing is written.
        assert_eq!(
            unsafe { rtl_query_security_object(0x40, info, buffer.as_mut_ptr(), 0, &mut needed) },
            STATUS_BUFFER_TOO_SMALL
        );
        assert_eq!(needed, 20 + 16 + 64);
        assert_eq!(&buffer[..20], &[0u8; 20]);
        // Enough room: the self-relative answer with the two named parts.
        assert_eq!(
            unsafe { rtl_query_security_object(0x40, info, buffer.as_mut_ptr(), 256, &mut needed) },
            STATUS_SUCCESS
        );
        assert_eq!(needed, 100);
        let header: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(header.revision, 1);
        assert!(header.control & SE_SELF_RELATIVE != 0);
        assert!(header.control & SE_DACL_PRESENT != 0);
        assert_eq!((header.owner, header.group, header.sacl), (20, 0, 0));
        assert_eq!(header.dacl, 20 + 16);
        assert_eq!(&buffer[20..36], &owner[..]);
        assert_eq!(&buffer[36..100], &dacl[..]);
        // What the wrapper forwarded: the handle, the info, the buffer, the length, the out word.
        let calls = mock::calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0],
            (
                mock::QUERY,
                vec![
                    0x40,
                    info,
                    buffer.as_mut_ptr() as u32,
                    0,
                    &mut needed as *mut u32 as u32
                ]
            )
        );
        assert_eq!(
            calls[1].1,
            vec![
                0x40,
                info,
                buffer.as_mut_ptr() as u32,
                256,
                &mut needed as *mut u32 as u32
            ]
        );
    }

    #[test]
    fn a_query_of_an_unknown_handle_writes_nothing() {
        let _guard = mock::test_lock();
        mock::reset();
        let mut buffer = [0u8; 64];
        let mut needed = 0xDEAD_BEEF;
        assert_eq!(
            unsafe {
                rtl_query_security_object(
                    0x99,
                    DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr(),
                    64,
                    &mut needed,
                )
            },
            STATUS_INVALID_HANDLE
        );
        assert_eq!(needed, 0xDEAD_BEEF);
        // A null out word is refused before the handle is looked at.
        assert_eq!(
            unsafe {
                rtl_query_security_object(
                    0x40,
                    DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr(),
                    64,
                    core::ptr::null_mut(),
                )
            },
            rtl::status::STATUS_ACCESS_VIOLATION
        );
    }

    #[test]
    fn a_set_then_a_query_round_trips_the_named_parts() {
        let _guard = mock::test_lock();
        mock::reset();
        let (owner, _dacl) = object_with_owner_and_dacl();
        // A modification naming the DACL and the owner.
        let new_dacl = dacl_with(0x0010_0000, &world());
        let modification = absolute_sd(&admins(), &world(), Some(&new_dacl));
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    0x40,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_SUCCESS
        );
        // The set forwarded the handle, the info and the descriptor.
        let calls = mock::calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            (
                mock::SET,
                vec![
                    0x40,
                    DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                    modification.as_ptr() as u32
                ]
            )
        );
        // Query the DACL back: the answer holds the modification's ACL.
        let mut buffer = [0u8; 256];
        let mut needed = 0u32;
        assert_eq!(
            unsafe {
                rtl_query_security_object(
                    0x40,
                    DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr(),
                    256,
                    &mut needed,
                )
            },
            STATUS_SUCCESS
        );
        let header: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(header.dacl, 20);
        assert_eq!(&buffer[20..20 + 64], &new_dacl[..]);
        // And the owner, still the stored one until a set names it: it was named, so it is the
        // modification's owner.
        assert_eq!(
            unsafe {
                rtl_query_security_object(
                    0x40,
                    OWNER_SECURITY_INFORMATION,
                    buffer.as_mut_ptr(),
                    256,
                    &mut needed,
                )
            },
            STATUS_SUCCESS
        );
        let header: SecurityDescriptorRelative = read(buffer.as_ptr());
        assert_eq!(header.owner, 20);
        assert_eq!(&buffer[20..36], &owner[..]);
    }

    #[test]
    fn the_set_variants_and_their_error_paths() {
        let _guard = mock::test_lock();
        mock::reset();
        object_with_owner_and_dacl();
        let modification = absolute_sd(&admins(), &world(), None);
        // The Ex variant forwards the same way.
        assert_eq!(
            unsafe {
                rtl_set_security_object_ex(
                    GROUP_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    0x40,
                    0,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_SUCCESS
        );
        let calls = mock::calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0],
            (
                mock::SET,
                vec![
                    0x40,
                    GROUP_SECURITY_INFORMATION,
                    modification.as_ptr() as u32
                ]
            )
        );
        // An unknown handle, and a null descriptor.
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    GROUP_SECURITY_INFORMATION,
                    modification.as_ptr(),
                    0x99,
                    core::ptr::null(),
                    0,
                )
            },
            STATUS_INVALID_HANDLE
        );
        assert_eq!(
            unsafe {
                rtl_set_security_object(
                    GROUP_SECURITY_INFORMATION,
                    core::ptr::null(),
                    0x40,
                    core::ptr::null(),
                    0,
                )
            },
            rtl::status::STATUS_ACCESS_VIOLATION
        );
    }
}
