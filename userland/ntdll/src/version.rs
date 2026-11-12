//! The version checks (`rtl::version`): VerSetConditionMask, which kernel32's forwards to, and
//! RtlVerifyVersionInfo, kernel32's VerifyVersionInfoW and A's work, against the system's version
//! as RtlGetVersion reports it.

use rtl::version::{self, Refusal, VersionInfo};

/// STATUS_INVALID_PARAMETER and STATUS_REVISION_MISMATCH.
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;

/// OSVERSIONINFOEXW, whose fields after the size a check reads (the size, its first dword, is not
/// checked, as on Windows 2000).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OsVersionInfoExW {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    csd_version: [u16; 128],
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
    reserved: u8,
}

/// VerSetConditionMask (see [`version::set_condition_mask`]); the condition is a BYTE, its low
/// byte.
#[unsafe(export_name = "f2k_export_VerSetConditionMask")]
pub extern "system" fn ver_set_condition_mask(mask: u64, types: u32, condition: u32) -> u64 {
    version::set_condition_mask(mask, types, condition as u8)
}

/// RtlVerifyVersionInfo: whether the system's version meets the conditions `mask` holds for
/// `types` against the caller's OSVERSIONINFOEXW (see [`version::verify`]).
///
/// # Safety
///
/// `info` points at an OSVERSIONINFOEXW (a bad pointer faults the caller).
#[unsafe(export_name = "f2k_export_RtlVerifyVersionInfo")]
pub unsafe extern "system" fn rtl_verify_version_info(
    info: *const OsVersionInfoExW,
    types: u32,
    mask: u64,
) -> u32 {
    // SAFETY: the caller's structure (the contract), read unaligned.
    let info = unsafe { info.read_unaligned() };
    let wanted = VersionInfo {
        major: info.major,
        minor: info.minor,
        build: info.build,
        platform: info.platform,
        service_pack_major: info.service_pack_major,
        service_pack_minor: info.service_pack_minor,
        suite_mask: info.suite_mask,
        product_type: info.product_type,
    };
    match version::verify(&rtl::sys::system_version(), &wanted, types, mask) {
        Ok(()) => 0,
        Err(Refusal::NoType) => STATUS_INVALID_PARAMETER,
        Err(Refusal::Mismatch) => STATUS_REVISION_MISMATCH,
    }
}
