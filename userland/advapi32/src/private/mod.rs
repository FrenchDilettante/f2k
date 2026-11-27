//! The private-object security calls and the SecurityInfoEx calls, as Windows 2000's advapi32
//! runs them: CreatePrivateObjectSecurity(Ex), Get/SetPrivateObjectSecurity(Ex),
//! DestroyPrivateObjectSecurity, ConvertToAutoInheritPrivateObjectSecurity ([`objects`]), and
//! Get/SetSecurityInfoExA/W ([`infoex`]).
//!
//! A private object is a protected server's own object, so its security descriptor lives in the
//! server's memory, not in a kernel object: the seven private-object calls are pure user-mode
//! work over the local [`crate::sd`] helpers and the process heap (see [`objects`]). The
//! SecurityInfoEx calls take a kernel object's handle instead and go over ntdll's
//! NtQuerySecurityObject / NtSetSecurityObject on it (see [`infoex`]).
//!
//! The descriptors here are read and written through the shared helpers below: a caller's
//! descriptor is read by its header and resolved into its components (owner, group, SACL, DACL,
//! in that field order), and written back as a self-relative descriptor — the header (revision,
//! control, the four fields), then each present component long-aligned, its offset recorded in
//! its field. The fields take a pointer's width in memory, so the header's storage is wider on
//! the host than on the target; the sizes the calls report are the target's (the 20-byte header).

pub(crate) mod infoex;
pub(crate) mod objects;

use crate::sd::{
    caller_sd, long_align, packed_size, sd_components, sd_field, valid_sd, SD_HEADER, SD_REVISION,
    FIELD_DACL, FIELD_GROUP, FIELD_OWNER, FIELD_SACL, SE_DACL_DEFAULTED, SE_DACL_PRESENT,
    SE_GROUP_DEFAULTED, SE_OWNER_DEFAULTED, SE_SACL_DEFAULTED, SE_SACL_PRESENT, SE_SELF_RELATIVE,
};
use crate::filesec::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
};
use crate::sid::set_ptr_field;

/// ERROR_BAD_PROVIDER: F2K runs no security providers (public value).
pub(crate) const ERROR_BAD_PROVIDER: u32 = 1204;

/// SEF_DACL_AUTO_INHERIT, the Ex forms' auto-inherit flag for the DACL (public value).
pub(crate) const SEF_DACL_AUTO_INHERIT: u32 = 0x01;
/// SEF_SACL_AUTO_INHERIT, for the SACL (public value).
pub(crate) const SEF_SACL_AUTO_INHERIT: u32 = 0x02;

/// The SECURITY_INFORMATION bit of each descriptor field, in field order (owner, group, SACL,
/// DACL): the public values 1, 2, 8, 4.
pub(crate) const FIELD_INFO: [u32; 4] = [
    OWNER_SECURITY_INFORMATION,
    GROUP_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION,
    DACL_SECURITY_INFORMATION,
];

/// The control bits a query propagates for the `index`th field: its PRESENT and DEFAULTED bits.
pub(crate) fn propagate_bits(source: u16, index: usize) -> u16 {
    match index {
        FIELD_DACL => source & (SE_DACL_PRESENT | SE_DACL_DEFAULTED),
        FIELD_SACL => source & (SE_SACL_PRESENT | SE_SACL_DEFAULTED),
        FIELD_OWNER => source & SE_OWNER_DEFAULTED,
        _ => source & SE_GROUP_DEFAULTED,
    }
}

/// The caller's security descriptor at `sd` as (its address, its header), or none for a null or
/// unreadable one.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read.
pub(crate) unsafe fn read_sd<'a>(sd: *const u8) -> Option<(usize, &'a [u8])> {
    // SAFETY: the caller's descriptor's header.
    let header = unsafe { caller_sd(sd) }?;
    Some((sd as usize, header))
}

/// The validated components (owner, group, SACL, DACL) of the descriptor at `base`, or none when
/// it is no valid descriptor.
///
/// # Safety
///
/// The descriptor and its components are readable.
pub(crate) unsafe fn sd_parts<'a>(
    base: usize,
    header: &'a [u8],
) -> Option<[Option<&'a [u8]>; 4]> {
    if !valid_sd(base, header) {
        return None;
    }
    // SAFETY: as `valid_sd`'s.
    Some(unsafe { sd_components(base, header) })
}

/// The validated components (owner, group, SACL, DACL) of the descriptor at `sd` — all none for a
/// null one, or none when it is no valid descriptor.
///
/// # Safety
///
/// `sd` is null or a security descriptor the call may read.
pub(crate) unsafe fn read_parts<'a>(sd: *const u8) -> Option<[Option<&'a [u8]>; 4]> {
    // SAFETY: the caller's descriptor.
    match unsafe { read_sd(sd) } {
        // SAFETY: the descriptor's components are read as it names them.
        Some((base, header)) => unsafe { sd_parts(base, header) },
        None if sd.is_null() => Some([None, None, None, None]),
        None => None,
    }
}

/// The bytes a self-relative descriptor takes in memory: the header's storage plus each present
/// component, long-aligned.
pub(crate) fn storage_size(parts: &[Option<&[u8]>; 4]) -> usize {
    SD_HEADER + parts.iter().flatten().map(|part| long_align(part.len())).sum::<usize>()
}

/// Write a self-relative descriptor into `out` (zeroed first): revision 1, the control word with
/// SE_SELF_RELATIVE forced, then each present component in field order, long-aligned, its offset
/// recorded in its field. The bytes used.
pub(crate) fn write_self_relative(
    out: &mut [u8],
    mut control_bits: u16,
    parts: &[Option<&[u8]>; 4],
) -> usize {
    out.fill(0);
    out[0] = SD_REVISION;
    control_bits |= SE_SELF_RELATIVE;
    out[2..4].copy_from_slice(&control_bits.to_le_bytes());
    let mut at = SD_HEADER;
    for index in [FIELD_OWNER, FIELD_GROUP, FIELD_SACL, FIELD_DACL] {
        if let Some(part) = parts[index] {
            at = long_align(at);
            out[at..at + part.len()].copy_from_slice(part);
            set_ptr_field(out, sd_field(index), at);
            at += long_align(part.len());
        }
    }
    at
}

/// The PRESENT bits the `parts` give the control word.
pub(crate) fn present_bits(parts: &[Option<&[u8]>; 4]) -> u16 {
    let mut bits = 0;
    if parts[FIELD_DACL].is_some() {
        bits |= SE_DACL_PRESENT;
    }
    if parts[FIELD_SACL].is_some() {
        bits |= SE_SACL_PRESENT;
    }
    bits
}

/// The size a self-relative descriptor of the `parts` reports on the target: the 20-byte header
/// plus each present component, long-aligned.
pub(crate) fn target_size(parts: &[Option<&[u8]>; 4]) -> usize {
    packed_size(parts)
}

/// The shared fixtures for the submodules' tests: SID, ACL and descriptor builders, and readers.
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use crate::acl::{ACCESS_ALLOWED_ACE_TYPE, ACL_HEADER, KNOWN_ACE_FIXED};
    use crate::sd::control;

    /// A SID's bytes, S-1-`authority`-`subs...`.
    pub(crate) fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// A valid ACL with one access-allowed ACE for `for_sid` (the full mask).
    pub(crate) fn acl(for_sid: &[u8]) -> Vec<u8> {
        let ace = KNOWN_ACE_FIXED + for_sid.len();
        let size = ACL_HEADER + ace;
        let mut bytes = vec![2, 0];
        bytes.extend((size as u16).to_le_bytes());
        bytes.extend(1u16.to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
        bytes.push(ACCESS_ALLOWED_ACE_TYPE);
        bytes.push(0);
        bytes.extend((ace as u16).to_le_bytes());
        bytes.extend(0xFFFF_FFFFu32.to_le_bytes());
        bytes.extend_from_slice(for_sid);
        bytes
    }

    /// A self-relative descriptor in the storage layout, built by the module's own writer.
    pub(crate) fn priv_sd(
        control_bits: u16,
        owner: Option<&[u8]>,
        group: Option<&[u8]>,
        sacl: Option<&[u8]>,
        dacl: Option<&[u8]>,
    ) -> Vec<u8> {
        let parts = [owner, group, sacl, dacl];
        let mut out = vec![0u8; storage_size(&parts)];
        write_self_relative(&mut out, control_bits, &parts);
        out
    }

    /// The components of the descriptor at `ptr`, read back.
    pub(crate) fn parts_of(ptr: usize) -> [Option<Vec<u8>>; 4] {
        // SAFETY: the test's own descriptor.
        let (base, header) = unsafe { read_sd(ptr as *const u8) }.unwrap();
        // SAFETY: its components are read as it names them.
        unsafe { sd_parts(base, header) }
            .unwrap()
            .map(|part| part.map(|bytes| bytes.to_vec()))
    }

    /// The control word of the descriptor at `ptr`.
    pub(crate) fn control_of(ptr: usize) -> u16 {
        // SAFETY: the test's own descriptor.
        control(unsafe { read_sd(ptr as *const u8) }.unwrap().1)
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::sd::{sd_field, SD_TARGET_HEADER, SE_DACL_AUTO_INHERIT_REQ};
    use crate::sid::{ptr_field, valid_sid, ERROR_INVALID_ACL, ERROR_INVALID_SECURITY_DESCR};
    use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY, ERROR_INVALID_SID};

    /// The error codes and flag values are the platform's public ones, and each descriptor field
    /// carries its SECURITY_INFORMATION bit (owner 1, group 2, SACL 8, DACL 4).
    #[test]
    fn the_constants_are_the_platforms() {
        assert_eq!(ERROR_BAD_PROVIDER, 1204);
        assert_eq!((SEF_DACL_AUTO_INHERIT, SEF_SACL_AUTO_INHERIT), (0x01, 0x02));
        assert_eq!(FIELD_INFO, [1, 2, 8, 4]);
        assert_eq!(
            (ERROR_INVALID_PARAMETER, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ENOUGH_MEMORY),
            (87, 122, 8)
        );
        assert_eq!(
            (ERROR_INVALID_SID, ERROR_INVALID_ACL, ERROR_INVALID_SECURITY_DESCR),
            (1337, 1336, 1338)
        );
        assert_eq!(ERROR_INVALID_HANDLE, 6);
        assert_eq!(valid_sid(&sid(5, &[32, 544])), true);
    }

    /// A self-relative descriptor is written header first (revision, control with
    /// SE_SELF_RELATIVE forced, zeroed fields), then each present component in field order
    /// (owner, group, SACL, DACL), long-aligned, its offset recorded in its field; the written
    /// descriptor reads back whole and valid.
    #[test]
    fn a_self_relative_descriptor_is_written_in_field_order() {
        let owner = sid(5, &[32, 544]);
        let group = sid(1, &[]);
        let dacl = acl(&sid(1, &[]));
        let parts: [Option<&[u8]>; 4] = [Some(&owner), Some(&group), None, Some(&dacl)];
        let bytes = priv_sd(
            SE_DACL_PRESENT | SE_DACL_AUTO_INHERIT_REQ,
            Some(&owner),
            Some(&group),
            None,
            Some(&dacl),
        );
        assert_eq!(bytes.len(), storage_size(&parts));
        assert_eq!(bytes[0], SD_REVISION);
        assert_eq!(
            u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_AUTO_INHERIT_REQ
        );
        let owner_at = ptr_field(&bytes, sd_field(FIELD_OWNER)).unwrap();
        let group_at = ptr_field(&bytes, sd_field(FIELD_GROUP)).unwrap();
        let sacl_at = ptr_field(&bytes, sd_field(FIELD_SACL)).unwrap();
        let dacl_at = ptr_field(&bytes, sd_field(FIELD_DACL)).unwrap();
        assert_eq!(sacl_at, 0, "no SACL given");
        assert_eq!(
            (owner_at, group_at, dacl_at),
            (SD_HEADER, SD_HEADER + 16, SD_HEADER + 24),
            "long-aligned after the header, in field order"
        );
        assert_eq!(&bytes[owner_at..owner_at + 16], &owner[..]);
        assert_eq!(&bytes[group_at..group_at + 8], &group[..]);
        assert_eq!(&bytes[dacl_at..dacl_at + dacl.len()], &dacl[..]);
        let ptr = bytes.as_ptr() as usize;
        // SAFETY: the test's own descriptor.
        // SAFETY: the test's own descriptor.
        assert!(unsafe { valid_sd(ptr, read_sd(ptr as *const u8).unwrap().1) });
        assert_eq!(
            parts_of(ptr),
            [Some(owner.clone()), Some(group.clone()), None, Some(dacl.clone())]
        );
        // The sizes: the target's 20-byte header plus the aligned components.
        assert_eq!(target_size(&parts), SD_TARGET_HEADER + 16 + 8 + dacl.len());
        assert_eq!(
            present_bits(&[Some(&owner), None, None, Some(&dacl)]),
            SE_DACL_PRESENT
        );
        assert_eq!(present_bits(&[None, None, None, Some(&dacl)]), SE_DACL_PRESENT);
        assert_eq!(present_bits(&[None, None, Some(&dacl), None]), SE_SACL_PRESENT);
        // The propagation of each field's PRESENT/DEFAULTED bits.
        assert_eq!(
            propagate_bits(SE_DACL_PRESENT | SE_DACL_DEFAULTED | SE_SACL_PRESENT, FIELD_DACL),
            SE_DACL_PRESENT | SE_DACL_DEFAULTED
        );
        assert_eq!(
            propagate_bits(SE_DACL_PRESENT | SE_OWNER_DEFAULTED, FIELD_OWNER),
            SE_OWNER_DEFAULTED
        );
        assert_eq!(
            propagate_bits(SE_GROUP_DEFAULTED | SE_SACL_DEFAULTED, FIELD_GROUP),
            SE_GROUP_DEFAULTED
        );
    }
}
