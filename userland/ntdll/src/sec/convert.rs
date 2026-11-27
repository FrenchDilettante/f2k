//! The absolute and self-relative descriptor conversions and the descriptor copy.

use super::*;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sec::test_support::*;

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
}
