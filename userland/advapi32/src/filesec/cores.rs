//! The security info calls' cores: the read that answers with the object's own descriptor
//! where the kernel keeps the blank one, the split into the out places, the buffer protocol, and
//! the named (file) and Ex forms' open-then-answer shapes.

use super::*;

/// Read the object `handle`'s descriptor of the `info` parts into a heap block: sized, then read
/// whole — `blank` builds the descriptor to answer with where the kernel keeps the blank one
/// (every object starts with it; F2K's files keep no security descriptor, the current process
/// answers with its token's). The block, or the error code (also the last error).
pub(crate) fn read_object_sd(
    handle: u32,
    info: u32,
    blank: impl FnOnce() -> Option<HeapBlock>,
) -> Result<HeapBlock, u32> {
    let mut needed = 0u32;
    // SAFETY: no descriptor and no length; the service writes the local's size.
    let status =
        unsafe { query_security_object(handle, info, core::ptr::null_mut(), 0, &mut needed) };
    if status.0 != STATUS_BUFFER_TOO_SMALL && !status.is_success() {
        return Err(fail(status));
    }
    let size = needed.max(1) as usize;
    let mut kernel = match HeapBlock::new(size) {
        Some(block) => block,
        None => {
            nt::set_last_error(ERROR_NOT_ENOUGH_MEMORY);
            return Err(ERROR_NOT_ENOUGH_MEMORY);
        }
    };
    // SAFETY: the block is the descriptor's buffer of `needed` bytes, the local the size.
    let status = unsafe {
        query_security_object(
            handle,
            info,
            kernel.bytes_mut().as_mut_ptr(),
            needed,
            &mut needed,
        )
    };
    if !status.is_success() {
        return Err(fail(status));
    }
    if defaults::is_blank_sd(kernel.bytes()) {
        if let Some(own) = blank() {
            return Ok(own);
        }
    }
    Ok(kernel)
}

/// Answer the caller's buffer protocol with the descriptor `bytes`: what fits of it copied into
/// `descriptor` of `length` bytes, its whole size into `needed`, ERROR_INSUFFICIENT_BUFFER and
/// FALSE when the buffer is short, TRUE when it all fit (the last error untouched on success).
pub(crate) fn give_sd(descriptor: *mut u8, length: u32, needed: *mut u32, bytes: &[u8]) -> u32 {
    let copy = (length as usize).min(bytes.len());
    // SAFETY: the caller's buffer of `length` bytes and its size; the copy stays inside the
    // buffer.
    unsafe {
        if !descriptor.is_null() && copy > 0 {
            if let Some(buffer) = caller_bytes_mut(descriptor, copy) {
                buffer.copy_from_slice(&bytes[..copy]);
            }
        }
        if let Some(mut out) = Out::optional(needed) {
            out.set(bytes.len() as u32);
        }
    }
    if (length as usize) < bytes.len() {
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        0
    } else {
        1
    }
}

/// GetSecurityInfo's core: the object `handle`'s descriptor of the `info` parts, read whole and
/// split into `outs`. The error code, also the last error on a failure.
pub(crate) fn get_security_info_core(handle: u32, info: u32, outs: &mut Outs<'_>) -> u32 {
    let sd_block = match read_object_sd(handle, info, || defaults::file_sd(info)) {
        Ok(block) => block,
        Err(code) => return code,
    };
    // A success leaves the sizing query's error as the last error.
    nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
    let bytes = sd_block.bytes();
    let base = bytes.as_ptr() as usize;
    give_part(
        outs.owner.as_mut(),
        base,
        bytes,
        OFFSET_OWNER,
        info & OWNER_SECURITY_INFORMATION != 0,
    );
    give_part(
        outs.group.as_mut(),
        base,
        bytes,
        OFFSET_GROUP,
        info & GROUP_SECURITY_INFORMATION != 0,
    );
    give_part(
        outs.dacl.as_mut(),
        base,
        bytes,
        OFFSET_DACL,
        info & DACL_SECURITY_INFORMATION != 0,
    );
    give_part(
        outs.sacl.as_mut(),
        base,
        bytes,
        OFFSET_SACL,
        info & SACL_SECURITY_INFORMATION != 0,
    );
    if let Some(sd) = outs.sd.as_mut() {
        // The descriptor block is the caller's now (freed with LocalFree).
        sd.set(base);
        core::mem::forget(sd_block);
    }
    ERROR_SUCCESS
}

/// SetSecurityInfo's core: the object `handle`'s descriptor of the `info` parts set to the
/// caller's `descriptor`, handed to the service in the self-relative form it takes. The error
/// code, also the last error on a failure.
pub(crate) fn set_security_info_core(handle: u32, info: u32, descriptor: *const u8) -> u32 {
    // SAFETY: the caller's descriptor.
    let status = unsafe { defaults::set_object_sd(handle, info, descriptor) };
    if status.is_success() {
        ERROR_SUCCESS
    } else {
        fail(status)
    }
}

/// GetNamedSecurityInfo's core: the named object opened with the query access, then
/// GetSecurityInfo's core on its handle. The error code; an open failure's status is the code,
/// the last error left alone.
pub(crate) fn named_get(name: &Counted, object_type: u32, info: u32, outs: &mut Outs<'_>) -> u32 {
    if object_type != SE_FILE_OBJECT {
        return ERROR_INVALID_PARAMETER;
    }
    let handle = match open_named(name, query_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => return nt::dos_error(status),
    };
    let code = get_security_info_core(handle, info, outs);
    let _ = nt::close(handle);
    code
}

/// SetNamedSecurityInfo's core: the named object opened with the set access, a self-relative
/// descriptor assembled from the components the mask names, set on its handle. The error code.
pub(crate) fn named_set(
    name: &Counted,
    object_type: u32,
    info: u32,
    owner: *const u8,
    group: *const u8,
    dacl: *const u8,
    sacl: *const u8,
) -> u32 {
    if object_type != SE_FILE_OBJECT {
        return ERROR_INVALID_PARAMETER;
    }
    let handle = match open_named(name, set_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => return nt::dos_error(status),
    };
    // The caller's components are read (probed as the service would read them).
    // SAFETY: the caller's components.
    let _ = unsafe {
        (
            caller_sid(owner),
            caller_sid(group),
            caller_acl(dacl),
            caller_acl(sacl),
        )
    };
    // F2K's files keep no security descriptor to set: the open succeeds, the set answers
    // ERROR_INVALID_FUNCTION.
    let _ = nt::close(handle);
    nt::set_last_error(ERROR_INVALID_FUNCTION);
    ERROR_INVALID_FUNCTION
}

/// GetFileSecurity's core: the named file opened with the query access, its descriptor of the
/// `info` parts into the caller's `descriptor` of `length` bytes, its size into `needed`: TRUE,
/// or FALSE with the status's error as the last error.
pub(crate) fn file_get(
    name: &Counted,
    info: u32,
    descriptor: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    let handle = match open_named(name, query_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => {
            fail(status);
            return 0;
        }
    };
    let sd_block = match read_object_sd(handle, info, || defaults::file_sd(info)) {
        Ok(block) => block,
        Err(_) => {
            let _ = nt::close(handle);
            return 0;
        }
    };
    let code = give_sd(descriptor, length, needed, sd_block.bytes());
    let _ = nt::close(handle);
    code
}

/// SetFileSecurity's core: the named file opened with the set access, its descriptor of the
/// `info` parts set to the caller's `descriptor`: TRUE, or FALSE with the status's error as the
/// last error.
pub(crate) fn file_set(name: &Counted, info: u32, descriptor: *const u8) -> u32 {
    let handle = match open_named(name, set_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => {
            fail(status);
            return 0;
        }
    };
    // F2K's files keep no security descriptor to set: the open succeeds, the set fails.
    let _ = (info, descriptor);
    let _ = nt::close(handle);
    nt::set_last_error(ERROR_INVALID_FUNCTION);
    0
}

// --- The caller's strings

/// The caller's NUL-terminated string at `text`, its terminator left out (the empty string for
/// null).
///
/// # Safety
///
/// `text` is null, or an aligned NUL-terminated string the call may read for `'a`.
pub(crate) unsafe fn wide_text<'a>(text: *const u16) -> &'a [u16] {
    if text.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { cstr::units_until_nul(text) }
}

/// The caller's NUL-terminated ANSI string at `text`, its terminator left out (the empty string
/// for null).
///
/// # Safety
///
/// `text` is null, or a NUL-terminated string the call may read for `'a`.
pub(crate) unsafe fn ansi_text<'a>(text: *const u8) -> &'a [u8] {
    if text.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe { cstr::bytes_until_nul(text) }
}

/// The ANSI string `text` as a counted Unicode string: the error when the conversion fails.
pub(crate) fn wide(text: &[u8]) -> Result<nt::Wide, u32> {
    nt::ansi_to_unicode(text).map_err(nt::dos_error)
}

/// The Ex forms' out places: the access and audit lists, the owner and group names.
pub(crate) struct ExOuts<'a> {
    access: Option<Out<'a, usize>>,
    audit: Option<Out<'a, usize>>,
    owner: Option<Out<'a, usize>>,
    group: Option<Out<'a, usize>>,
}

/// The caller's four Ex out places at `access_list` through `group` (null for none).
///
/// # Safety
///
/// The pointers are the caller's places for pointers, or null.
pub(crate) unsafe fn ex_outs<'a>(
    access_list: *mut usize,
    audit_list: *mut usize,
    owner: *mut usize,
    group: *mut usize,
) -> ExOuts<'a> {
    // SAFETY: the caller's places.
    unsafe {
        ExOuts {
            access: Out::optional(access_list),
            audit: Out::optional(audit_list),
            owner: Out::optional(owner),
            group: Out::optional(group),
        }
    }
}

/// The SID at `offset` of the descriptor `bytes`, if it is one.
fn sid_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    let count = usize::from(*bytes.get(offset + 1)?);
    bytes.get(offset..offset + crate::sid::sid_len(count))
}

/// A heap block holding `text` as a NUL-terminated string — narrow, or wide when `wide` — its
/// address for the caller's out place (the caller frees it with LocalFree).
fn text_block(text: &[u16], wide: bool) -> Option<usize> {
    let mut block = if wide {
        HeapBlock::new(2 * (text.len() + 1))?
    } else {
        HeapBlock::new(text.len() + 1)?
    };
    let at = block.bytes().as_ptr() as usize;
    if wide {
        for (index, unit) in text.iter().chain([&0]).enumerate() {
            block.bytes_mut()[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
        }
    } else {
        for (index, unit) in text.iter().chain([&0]).enumerate() {
            block.bytes_mut()[index] = *unit as u8;
        }
    }
    core::mem::forget(block);
    Some(at)
}

/// GetNamedSecurityInfoEx's core: the named file opened with the query access, its descriptor
/// read, the access list out (an empty one: the file's descriptor has no DACL), the audit list
/// left NULL, the owner and group as their SIDs' text. ERROR_NONE_MAPPED is left as the last
/// error (no account names behind the SIDs); ERROR_INVALID_PARAMETER when every out place is
/// null. The error code; an open failure's status is the code, the last error left alone.
pub(crate) fn ex_get(
    name: &Counted,
    object_type: u32,
    info: u32,
    outs: &mut ExOuts<'_>,
    wide: bool,
) -> u32 {
    if object_type != SE_FILE_OBJECT {
        return ERROR_INVALID_PARAMETER;
    }
    if outs.access.is_none() && outs.audit.is_none() && outs.owner.is_none() && outs.group.is_none()
    {
        return ERROR_INVALID_PARAMETER;
    }
    let handle = match open_named(name, query_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => return nt::dos_error(status),
    };
    let code = match read_object_sd(handle, info, || defaults::file_sd(info)) {
        Ok(sd_block) => {
            let bytes = sd_block.bytes();
            // The access list: an empty converted list (cEntries 0, no entries).
            if let Some(access) = outs.access.as_mut() {
                if let Some(list) = HeapBlock::new(4 + crate::sid::PTR) {
                    access.set(list.bytes().as_ptr() as usize);
                    core::mem::forget(list);
                }
            }
            // The owner and group names: their SIDs' text.
            for (out, at) in [
                (outs.owner.as_mut(), OFFSET_OWNER),
                (outs.group.as_mut(), OFFSET_GROUP),
            ] {
                if let Some(out) = out {
                    let offset = u32::read_from(bytes, at).unwrap_or(0) as usize;
                    if let Some(text) = sid_at(bytes, offset).and_then(defaults::sid_string) {
                        if let Some(at) = text_block(&text, wide) {
                            out.set(at);
                        }
                    }
                }
            }
            nt::set_last_error(ERROR_NONE_MAPPED);
            ERROR_SUCCESS
        }
        Err(code) => code,
    };
    let _ = nt::close(handle);
    code
}

/// SetNamedSecurityInfoEx's core: the named file opened with the set access, then answered
/// ERROR_INVALID_FUNCTION with 1008 as the last error (F2K's files keep no security descriptor
/// to set). The error code; an open failure's status is the code, the last error left alone.
pub(crate) fn ex_set(name: &Counted, object_type: u32, info: u32) -> u32 {
    if object_type != SE_FILE_OBJECT {
        return ERROR_INVALID_PARAMETER;
    }
    let handle = match open_named(name, set_access_mask(info)) {
        Ok(handle) => handle,
        Err(status) => return nt::dos_error(status),
    };
    let _ = nt::close(handle);
    nt::set_last_error(ERROR_NO_TOKEN);
    ERROR_INVALID_FUNCTION
}

#[cfg(test)]
mod tests {
    use super::exports::*;
    use super::testkit::*;
    use super::*;

    /// Where the kernel keeps the blank descriptor (every object starts with it), the file
    /// calls answer with the file's own: the owner and group out, the size the header and two
    /// SIDs take.
    #[test]
    fn the_blank_descriptor_is_answered_with_the_files_own() {
        reset();
        // The blank descriptor the kernel keeps: the header alone, self-relative, the DACL
        // present but null.
        let mut blank = self_relative(0, 0, 0, 0, 20);
        blank[2..4].copy_from_slice(&0x8004u16.to_le_bytes());
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(blank.clone()));
        let (mut p0, mut p1, mut p2, mut p3, mut p4) = (0usize, 0, 0, 0, 0);
        let mut outs = Outs {
            owner: Some(Out::from(&mut p0)),
            group: Some(Out::from(&mut p1)),
            dacl: Some(Out::from(&mut p2)),
            sacl: Some(Out::from(&mut p3)),
            sd: Some(Out::from(&mut p4)),
        };
        let code = get_security_info_core(0x58, WANT, &mut outs);
        assert_eq!((code, last_error()), (ERROR_SUCCESS, 122));
        assert_ne!(p4, 0);
        // SAFETY: the block the call handed out.
        let bytes = unsafe { core::slice::from_raw_parts(p4 as *const u8, 52) };
        assert_eq!(bytes.len(), 52);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 0x8000);
        assert_eq!((p0, p1), (p4 + 20, p4 + 36), "the owner and group out");
        assert_eq!(p2, 0, "no DACL");
        // SAFETY: our own block.
        unsafe { ProcessHeap::free(p4 as *mut u8) };

        // GetFileSecurity sizes the file's own descriptor: 52, and a byte short copies what fits.
        reset();
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(blank.clone()));
        let name = wide_z("filesec.tmp");
        let mut buffer = [0xCCu8; 64];
        let mut need = 0xF2F2_F2F2u32;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, core::ptr::null_mut(), 0, &mut need)
        };
        assert_eq!((ok, last_error(), need), (0, 122, 52));
        let mut need2 = 51;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, buffer.as_mut_ptr(), 51, &mut need2)
        };
        assert_eq!((ok, last_error(), need2, buffer[0]), (0, 122, 52, 1));
        let mut need3 = 52;
        arm();
        let ok = unsafe {
            get_file_security_w(name.as_ptr(), WANT, buffer.as_mut_ptr(), 52, &mut need3)
        };
        assert_eq!((ok, last_error(), need3), (1, 0xF2F2, 52));
        assert_eq!(u16::from_le_bytes([buffer[2], buffer[3]]), 0x8000);
    }

    /// GetSecurityInfo sizes the descriptor first (the sizing query's error left as the last
    /// error), reads it whole, and splits it; a failed service's status is the code and the last
    /// error, with no second query.
    #[test]
    fn get_security_info_sizes_reads_and_splits() {
        reset();
        let sd_bytes = self_relative(20, 28, 0, 36, 52);
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd_bytes.clone()));
        let (mut p0, mut p1, mut p2, mut p3, mut p4) = (0usize, 0, 0, 0, 0);
        let mut outs = Outs {
            owner: Some(Out::from(&mut p0)),
            group: Some(Out::from(&mut p1)),
            dacl: Some(Out::from(&mut p2)),
            sacl: Some(Out::from(&mut p3)),
            sd: Some(Out::from(&mut p4)),
        };
        let code = get_security_info_core(0x58, WANT, &mut outs);
        assert_eq!(code, ERROR_SUCCESS);
        assert_eq!(last_error(), 122, "the sizing query's error is left");
        assert_eq!(
            host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [
                ("NtQuerySecurityObject", 0x58, WANT, 0),
                ("NtQuerySecurityObject", 0x58, WANT, 52)
            ]
        );
        let sd = p4;
        assert_ne!(sd, 0);
        // SAFETY: the block the call handed out.
        let bytes = unsafe { core::slice::from_raw_parts(sd as *const u8, 52) };
        assert_eq!(&bytes[..], &sd_bytes[..]);
        assert_eq!((p0, p1, p2, p3), (sd + 20, sd + 28, sd + 36, 0));
        // SAFETY: our own block.
        unsafe { ProcessHeap::free(sd as *mut u8) };

        reset();
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0008));
        arm();
        let mut outs = Outs {
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
            sd: None,
        };
        let code = get_security_info_core(0x58, WANT, &mut outs);
        assert_eq!((code, last_error()), (6, 6));
        assert_eq!(
            host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [("NtQuerySecurityObject", 0x58, WANT, 0)],
            "no second query"
        );
    }

    /// SetSecurityInfo hands the handle and the descriptor to the service: the code, the last
    /// error on a failure, untouched on a success.
    #[test]
    fn set_security_info_goes_to_the_service() {
        reset();
        // A self-relative descriptor goes to the service as it is.
        let mut descriptor = vec![0u8; 64];
        descriptor[0] = 1;
        descriptor[2..4].copy_from_slice(&SE_SELF_RELATIVE.to_le_bytes());
        arm();
        assert_eq!(
            set_security_info_core(0x58, DACL_SECURITY_INFORMATION, descriptor.as_ptr()),
            ERROR_SUCCESS
        );
        assert_eq!(last_error(), 0xF2F2, "untouched on success");
        host::SEC_SET_STATUS.with(|status| status.set(0xC000_0022));
        arm();
        assert_eq!(
            set_security_info_core(0x58, DACL_SECURITY_INFORMATION, descriptor.as_ptr()),
            5
        );
        assert_eq!(last_error(), 5);
        assert_eq!(
            host::SEC_CALLS.with(|calls| calls.borrow().clone()),
            [("NtSetSecurityObject", 0x58, DACL_SECURITY_INFORMATION, 0); 2]
        );
    }
}
