//! The registry key security calls: RegGetKeySecurity and RegSetKeySecurity, as Windows 2000's
//! advapi32 runs them: the HKEY mapped to its NT key handle (the predefined keys' kept handles,
//! as the registry calls do), then ntdll's NtQuerySecurityObject / NtSetSecurityObject on it,
//! with the registry key object's security. The calls return the error code and leave the last
//! error alone; the caller's buffer, its length (the size's value in) and the size out go
//! straight to the service, which probes them.

use rtl::status::{STATUS_BUFFER_TOO_SMALL, STATUS_KEY_DELETED, STATUS_SUCCESS};
use rtl::winerror::{ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER, ERROR_SUCCESS};

use crate::defaults;
use crate::imports::{self as nt};
use crate::registry;
use crate::{filesec, Out};

/// The key's deleted-mark check: a key deleted under its open handle answers STATUS_KEY_DELETED
/// to any query of its own information (class 0), which the calls report as its error code
/// (ERROR_KEY_DELETED) before any security service call. Any other answer is left to the
/// service itself.
fn deleted(key: u32) -> Option<u32> {
    let mut information = [0u8; 64];
    let answer = nt::query_key(key, 0, &mut information);
    (answer.status.0 == STATUS_KEY_DELETED).then(|| nt::dos_error(answer.status))
}

/// RegGetKeySecurity: the key `key`'s security descriptor of the `info` parts into the caller's
/// `descriptor`, its size in `*size` and out again: the error code (ERROR_INVALID_HANDLE for a
/// null key, ERROR_INVALID_PARAMETER for no size). A null descriptor is the size query: the
/// service writes the size the descriptor takes into `*size` and its buffer-too-small status is
/// reported as success; a success reports the length the caller gave, as the call's RPC link
/// returns the marshalled buffer's length.
///
/// # Safety
///
/// `descriptor` holds `*size` bytes; `size` is the caller's place for the size in and out.
#[unsafe(export_name = "f2k_export_RegGetKeySecurity")]
pub unsafe extern "system" fn reg_get_key_security(
    key: u32,
    info: u32,
    descriptor: *mut u8,
    size: *mut u32,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    // SAFETY: the caller's size.
    let mut size_out = unsafe { Out::optional(size) };
    let Some(size_out) = size_out.as_mut() else {
        return ERROR_INVALID_PARAMETER;
    };
    let length = size_out.get();
    let key = match registry::map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    if let Some(code) = deleted(key) {
        return code;
    }
    if descriptor.is_null() {
        // The size query: no buffer and no length, the size out only.
        // SAFETY: the caller's size, handed to the service.
        let status = unsafe { filesec::query_security_object(key, info, descriptor, 0, size) };
        return match status.0 {
            STATUS_SUCCESS | STATUS_BUFFER_TOO_SMALL => ERROR_SUCCESS,
            _ => nt::dos_error(status),
        };
    }
    // SAFETY: the caller's buffer of `length` bytes and size, handed to the service.
    let status = unsafe { filesec::query_security_object(key, info, descriptor, length, size) };
    if status.is_success() {
        // The registry call answers over its RPC link, whose marshalled descriptor keeps the
        // caller's buffer length on a success; the descriptor's own size is what the size query
        // above reported. So a success reports the length the caller gave.
        size_out.set(length);
    }
    nt::dos_error(status)
}

/// RegSetKeySecurity: the key `key`'s security descriptor of the `info` parts set to the caller's
/// `descriptor`: the error code. The descriptor goes to the service in the self-relative form,
/// an absolute one converted into a block of the process heap.
///
/// # Safety
///
/// `descriptor` is the caller's security descriptor (the service probes and reads it).
#[unsafe(export_name = "f2k_export_RegSetKeySecurity")]
pub unsafe extern "system" fn reg_set_key_security(
    key: u32,
    info: u32,
    descriptor: *const u8,
) -> u32 {
    if key == 0 {
        return ERROR_INVALID_HANDLE;
    }
    let key = match registry::map(key) {
        Ok(key) => key,
        Err(code) => return code,
    };
    if let Some(code) = deleted(key) {
        return code;
    }
    // SAFETY: the caller's descriptor.
    let status = unsafe { set_descriptor(key, info, descriptor) };
    nt::dos_error(status)
}

/// The caller's descriptor to the service in the self-relative form the service takes: an
/// absolute one converted into a heap block first, a self-relative one as it is.
///
/// # Safety
///
/// `descriptor` is the caller's security descriptor.
unsafe fn set_descriptor(key: u32, info: u32, descriptor: *const u8) -> rtl::status::NtStatus {
    // SAFETY: the caller's descriptor.
    unsafe { defaults::set_object_sd(key, info, descriptor) }
}

#[cfg(test)]
mod tests {
    use rtl::winerror::ERROR_SUCCESS;

    use super::*;
    use crate::filesec::host;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    fn reset() {
        host::SEC_REPLY
            .with(|reply| *reply.borrow_mut() = Err(rtl::status::STATUS_NOT_IMPLEMENTED));
        host::SEC_SET_STATUS.with(|status| status.set(0));
        host::SEC_CALLS.with(|calls| calls.borrow_mut().clear());
    }

    /// A self-relative SD, 28 bytes with the owner at 20.
    fn sd_bytes() -> Vec<u8> {
        let mut bytes = vec![0u8; 28];
        bytes[0] = 1;
        bytes[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&20u32.to_le_bytes());
        bytes
    }

    const WANT: u32 = 0x7; // owner | group | DACL

    /// The key's handle goes to the service with the caller's buffer, length and size; the
    /// error code is the status's, and the last error is left alone.
    #[test]
    fn get_key_security_passes_the_buffer_through() {
        reset();
        let sd = sd_bytes();
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Ok(sd.clone()));
        let mut buffer = [0xCCu8; 64];
        // The size query: a null buffer with the caller's size as the length.
        let mut need = 0xF2F2_F2F2u32;
        arm();
        let code = unsafe { reg_get_key_security(0x1234, WANT, core::ptr::null_mut(), &mut need) };
        assert_eq!((code, last_error(), need), (ERROR_SUCCESS, 0xF2F2, 28));
        // A byte short: ERROR_INSUFFICIENT_BUFFER, the size told again, nothing written.
        let mut need2 = 27;
        arm();
        let code = unsafe { reg_get_key_security(0x1234, WANT, buffer.as_mut_ptr(), &mut need2) };
        assert_eq!((code, last_error(), need2), (122, 0xF2F2, 28));
        assert_eq!(buffer[0], 0xCC, "the buffer untouched");
        // The size asked for: the descriptor in the buffer.
        let mut need3 = 28;
        arm();
        let code = unsafe { reg_get_key_security(0x1234, WANT, buffer.as_mut_ptr(), &mut need3) };
        assert_eq!((code, last_error(), need3), (ERROR_SUCCESS, 0xF2F2, 28));
        assert_eq!(&buffer[..28], &sd[..]);
        let calls = host::SEC_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(
            calls,
            [
                ("NtQuerySecurityObject", 0x1234, WANT, 0),
                ("NtQuerySecurityObject", 0x1234, WANT, 27),
                ("NtQuerySecurityObject", 0x1234, WANT, 28),
            ]
        );
    }

    /// A key deleted under its open handle: the key's own information answers STATUS_KEY_DELETED,
    /// and both calls report its error code (ERROR_KEY_DELETED) before any security service call.
    #[test]
    fn a_deleted_key_answers_error_key_deleted() {
        reset();
        crate::imports::host::KEY_REPLY
            .with(|reply| *reply.borrow_mut() = Err(rtl::status::STATUS_KEY_DELETED));
        let mut buffer = [0xCCu8; 64];
        let mut need = 64;
        arm();
        let code = unsafe { reg_get_key_security(0x1234, WANT, buffer.as_mut_ptr(), &mut need) };
        assert_eq!((code, last_error()), (1018, 0xF2F2));
        arm();
        let code = unsafe { reg_set_key_security(0x1234, WANT, buffer.as_ptr()) };
        assert_eq!((code, last_error()), (1018, 0xF2F2));
        assert!(
            host::SEC_CALLS.with(|calls| calls.borrow().is_empty()),
            "no security service call"
        );
        crate::imports::host::KEY_REPLY
            .with(|reply| *reply.borrow_mut() = Err(rtl::status::STATUS_NOT_IMPLEMENTED));
    }

    /// RegSetKeySecurity converts an absolute descriptor into a self-relative heap block before
    /// the service: the block holds the header with SE_SELF_RELATIVE set and each component at
    /// its recorded offset.
    #[test]
    fn an_absolute_descriptor_is_converted_to_self_relative() {
        reset();
        let admins = {
            let mut bytes = vec![1, 2, 0, 0, 0, 0, 0, 5];
            bytes.extend(32u32.to_le_bytes());
            bytes.extend(544u32.to_le_bytes());
            bytes
        };
        let mut sd = vec![0u8; 64];
        sd[0] = 1;
        sd[2..4].copy_from_slice(&0x0000u16.to_le_bytes()); // absolute, nothing present
        sd[4..12].copy_from_slice(&(admins.as_ptr() as usize).to_le_bytes()); // owner pointer
                                                                              // SAFETY: the test's
                                                                              // descriptor.
        let block =
            unsafe { defaults::self_relative_block(sd.as_ptr()) }.expect("a valid absolute SD");
        let bytes = block.bytes();
        assert_eq!(bytes[0], 1, "the revision");
        assert_eq!(
            u16::from_le_bytes([bytes[2], bytes[3]]) & crate::sd::SE_SELF_RELATIVE,
            crate::sd::SE_SELF_RELATIVE,
            "self-relative now"
        );
        let owner_off = usize::from_le_bytes(bytes[4..12].try_into().unwrap());
        assert_eq!(
            owner_off,
            crate::sd::SD_HEADER,
            "the owner at the header's end"
        );
        assert_eq!(&bytes[owner_off..owner_off + admins.len()], &admins[..]);
        // A self-relative descriptor is handed to the service as it is.
        let mut rel = vec![0u8; 32];
        rel[0] = 1;
        rel[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
        arm();
        let code = unsafe { reg_set_key_security(0x1234, WANT, rel.as_ptr()) };
        assert_eq!((code, last_error()), (ERROR_SUCCESS, 0xF2F2));
        let calls = host::SEC_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(calls, [("NtSetSecurityObject", 0x1234, WANT, 0)]);
    }

    /// The error paths: a null key and no size answer locally; a bogus or closed handle is the
    /// service's STATUS_INVALID_HANDLE; a refused set is its status's error; none of them
    /// touches the last error.
    #[test]
    fn the_error_paths_map_the_status() {
        reset();
        // SAFETY: null and test buffers.
        unsafe {
            assert_eq!(
                reg_get_key_security(0, WANT, core::ptr::null_mut(), core::ptr::null_mut()),
                ERROR_INVALID_HANDLE
            );
            assert_eq!(
                reg_get_key_security(0x1234, WANT, core::ptr::null_mut(), core::ptr::null_mut()),
                ERROR_INVALID_PARAMETER
            );
            assert_eq!(
                reg_set_key_security(0, WANT, core::ptr::null()),
                ERROR_INVALID_HANDLE
            );
        }
        host::SEC_REPLY.with(|reply| *reply.borrow_mut() = Err(0xC000_0008));
        let mut buffer = [0u8; 64];
        let mut need = 64;
        arm();
        let code = unsafe { reg_get_key_security(0x1234, WANT, buffer.as_mut_ptr(), &mut need) };
        assert_eq!((code, last_error()), (6, 0xF2F2));
        host::SEC_SET_STATUS.with(|status| status.set(0xC000_0022));
        let sd = sd_bytes();
        arm();
        let code = unsafe { reg_set_key_security(0x1234, WANT, sd.as_ptr()) };
        assert_eq!((code, last_error()), (5, 0xF2F2));
        let calls = host::SEC_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(
            calls,
            [
                ("NtQuerySecurityObject", 0x1234, WANT, 64),
                ("NtSetSecurityObject", 0x1234, WANT, 0),
            ]
        );
        // A predefined key that cannot be opened is the open's error, before any service call.
        reset();
        arm();
        let mut need = 64;
        let code =
            unsafe { reg_get_key_security(0x8000_0004, WANT, buffer.as_mut_ptr(), &mut need) };
        assert_eq!((code, last_error()), (ERROR_INVALID_HANDLE, 0xF2F2));
        assert!(host::SEC_CALLS.with(|calls| calls.borrow().is_empty()));
    }

    /// RegSetKeySecurity hands the mapped key handle and the descriptor to the service.
    #[test]
    fn set_key_security_goes_to_the_service() {
        reset();
        let sd = sd_bytes();
        arm();
        let code = unsafe { reg_set_key_security(0x1234, WANT, sd.as_ptr()) };
        assert_eq!((code, last_error()), (ERROR_SUCCESS, 0xF2F2));
        let calls = host::SEC_CALLS.with(|calls| calls.borrow().clone());
        assert_eq!(calls, [("NtSetSecurityObject", 0x1234, WANT, 0)]);
    }
}
