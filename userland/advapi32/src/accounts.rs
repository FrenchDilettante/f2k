//! The account lookups: LookupAccountNameA/W, LookupAccountSidA/W, GetWindowsAccountDomainSid,
//! GetSiteSidFromToken and GetMangledSiteSid, as Windows 2000's advapi32 answers them on a machine
//! with no account database behind the well-known names: the well-known names resolve to their
//! SIDs and back, everything else is ERROR_NONE_MAPPED, and there is no account domain or site
//! SID to find (the domain of a well-known account is the empty string).

use rtl::array_vec::ArrayVec;
use rtl::edge::{InStr, InWStr};
use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_SID, ERROR_IO_PENDING};

use crate::imports::{self as nt};
use crate::sd::build::{kind_name, kind_of_sid, name_kind, wide_name_kind};
use crate::sid::{
    caller_sid,
    sid_len,
    sid_parts_bytes,
    well_known_sid,
    ERROR_NONE_MAPPED,
    MAX_SUB_AUTHORITIES,
    SID_HEADER,
};
use crate::{caller_bytes_mut, Out};

// The Win32 error GetWindowsAccountDomainSid reports for an account with no domain behind it
// (rtl::winerror does not carry it), by its public value.
const ERROR_NO_ACCOUNT_DOMAIN: u32 = 1257;
// The HRESULT GetMangledSiteSid returns for a SID that is no site SID: the win32 ERROR_INVALID_SID
// wrapped as an HRESULT.
const HRESULT_FROM_INVALID_SID: u32 = 0x8007_0539;
// SidTypeWellKnownGroup: the account type a well-known account answers a lookup with.
const SID_TYPE_WELL_KNOWN_GROUP: u32 = 5;

/// The most bytes a SID takes: its header and the most sub-authorities.
const SID_MAX: usize = SID_HEADER + 4 * MAX_SUB_AUTHORITIES;

/// The SID bytes of a well-known kind.
fn well_known_bytes(kind: u32) -> Option<ArrayVec<u8, SID_MAX>> {
    let parts = well_known_sid(kind, None)?;
    let mut bytes = ArrayVec::new();
    bytes.try_extend_default(sid_len(parts.count)).ok()?;
    sid_parts_bytes(&parts, &mut bytes);
    Some(bytes)
}

/// Write the empty referenced-domain name (a lone terminator) into the caller's domain buffer and
/// 1 into its count place: no domain behind a well-known account. `wide` selects the wide buffer
/// (the count is in units either way).
///
/// # Safety
///
/// `domain` is null or the caller's domain buffer; `cch_domain` its count place or null.
unsafe fn write_empty_domain(wide: bool, domain: *mut u8, cch_domain: *mut u32) {
    // SAFETY: the caller's buffer and place.
    unsafe {
        if wide {
            if let Some(slot) = caller_bytes_mut(domain, 2) {
                slot.copy_from_slice(&0u16.to_le_bytes());
            }
        } else if let Some(slot) = caller_bytes_mut(domain, 1) {
            slot[0] = 0;
        }
        if let Some(mut cch) = Out::optional(cch_domain) {
            cch.set(1);
        }
    }
}

/// The body of LookupAccountNameA/W: the well-known `kind`'s SID into the caller's buffers, or the
/// size it needs when they are short. The last error ERROR_SUCCESS on the answer,
/// ERROR_INSUFFICIENT_BUFFER on the size query. `wide` selects the wide domain buffer.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
unsafe fn lookup_name(
    wide: bool,
    kind: u32,
    sid: *mut u8,
    cb_sid: *mut u32,
    domain: *mut u8,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let Some(bytes) = well_known_bytes(kind) else {
        nt::set_last_error(ERROR_NONE_MAPPED);
        return 0;
    };
    let len = bytes.len();
    // SAFETY: the caller's places.
    let (cb, pe_use) = unsafe { (Out::optional(cb_sid), Out::optional(pe_use)) };
    let room = !sid.is_null() && cb.as_ref().map_or(true, |cb| cb.get() >= len as u32);
    if !room {
        if let Some(mut cb) = cb {
            cb.set(len as u32);
        }
        // SAFETY: the caller's domain buffer and place.
        unsafe { write_empty_domain(wide, domain, cch_domain) };
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's SID buffer, with room for the SID.
    if let Some(buffer) = unsafe { caller_bytes_mut(sid, len) } {
        buffer.copy_from_slice(&bytes);
    }
    if let Some(mut cb) = cb {
        cb.set(len as u32);
    }
    // SAFETY: the caller's domain buffer and place.
    unsafe { write_empty_domain(wide, domain, cch_domain) };
    if let Some(mut use_) = pe_use {
        use_.set(SID_TYPE_WELL_KNOWN_GROUP);
    }
    nt::set_last_error(0);
    1
}

/// The body of LookupAccountSidA/W: the account name of the well-known SID `sid` into the caller's
/// buffers, or the size the name needs when they are short. The last error ERROR_IO_PENDING on the
/// answer, ERROR_INSUFFICIENT_BUFFER on the size query, ERROR_NONE_MAPPED for a SID no well-known
/// account holds. `wide` selects the wide name and domain buffers (the counts in units).
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
unsafe fn lookup_sid(
    wide: bool,
    sid: &[u8],
    name: *mut u8,
    cch_name: *mut u32,
    domain: *mut u8,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let Some(kind) = kind_of_sid(sid) else {
        nt::set_last_error(ERROR_NONE_MAPPED);
        return 0;
    };
    // The kind came from the well-known names, so it has a name.
    let text = kind_name(kind).expect("a kind of the names has a name");
    let needed = if wide {
        text.encode_utf16().count() + 1
    } else {
        text.len() + 1
    };
    // SAFETY: the caller's places.
    let (cch, pe_use) = unsafe { (Out::optional(cch_name), Out::optional(pe_use)) };
    let room = !name.is_null() && cch.as_ref().map_or(true, |cch| cch.get() >= needed as u32);
    if !room {
        if let Some(mut cch) = cch {
            cch.set(needed as u32);
        }
        // SAFETY: the caller's domain buffer and place.
        unsafe { write_empty_domain(wide, domain, cch_domain) };
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's name buffer, with room for the name and its terminator.
    unsafe {
        if wide {
            if let Some(buffer) = caller_bytes_mut(name, 2 * needed) {
                for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
                    buffer[2 * index..2 * index + 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
        } else if let Some(buffer) = caller_bytes_mut(name, needed) {
            buffer[..text.len()].copy_from_slice(text.as_bytes());
            buffer[text.len()] = 0;
        }
    }
    if let Some(mut cch) = cch {
        cch.set(needed as u32);
    }
    // SAFETY: the caller's domain buffer and place.
    unsafe { write_empty_domain(wide, domain, cch_domain) };
    if let Some(mut use_) = pe_use {
        use_.set(SID_TYPE_WELL_KNOWN_GROUP);
    }
    nt::set_last_error(ERROR_IO_PENDING);
    1
}

/// LookupAccountNameA: the well-known account `name` (a narrow string) resolved to its SID.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_LookupAccountNameA")]
pub unsafe extern "system" fn lookup_account_name_a(
    system: *const u8,
    name: *const u8,
    sid: *mut u8,
    cb_sid: *mut u32,
    domain: *mut u8,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let _ = system;
    // SAFETY: the caller's name.
    let name = unsafe { InStr::optional(name) };
    match name.and_then(|name| name_kind(name.bytes())) {
        Some(kind) => {
            // SAFETY: the caller's buffers and places.
            unsafe { lookup_name(false, kind, sid, cb_sid, domain, cch_domain, pe_use) }
        }
        None => {
            nt::set_last_error(ERROR_NONE_MAPPED);
            0
        }
    }
}

/// LookupAccountNameW: as [`lookup_account_name_a`], for a wide name and wide domain buffer.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_LookupAccountNameW")]
pub unsafe extern "system" fn lookup_account_name_w(
    system: *const u16,
    name: *const u16,
    sid: *mut u8,
    cb_sid: *mut u32,
    domain: *mut u16,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let _ = system;
    // SAFETY: the caller's name.
    let name = unsafe { InWStr::optional(name) };
    match name.and_then(|name| wide_name_kind(name.units())) {
        Some(kind) => {
            // SAFETY: the caller's buffers and places.
            unsafe {
                lookup_name(
                    true,
                    kind,
                    sid,
                    cb_sid,
                    domain as *mut u8,
                    cch_domain,
                    pe_use,
                )
            }
        }
        None => {
            nt::set_last_error(ERROR_NONE_MAPPED);
            0
        }
    }
}

/// LookupAccountSidA: the account name of the SID `sid` (a narrow name out).
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_LookupAccountSidA")]
pub unsafe extern "system" fn lookup_account_sid_a(
    system: *const u8,
    sid: *const u8,
    name: *mut u8,
    cch_name: *mut u32,
    domain: *mut u8,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let _ = system;
    // SAFETY: the caller's SID.
    match unsafe { caller_sid(sid) } {
        Some(sid) => {
            // SAFETY: the caller's buffers and places.
            unsafe { lookup_sid(false, sid, name, cch_name, domain, cch_domain, pe_use) }
        }
        None => {
            nt::set_last_error(ERROR_INVALID_SID);
            0
        }
    }
}

/// LookupAccountSidW: as [`lookup_account_sid_a`], for a wide name and domain buffer.
///
/// # Safety
///
/// The pointers are the caller's, as the export's kinds say.
#[unsafe(export_name = "f2k_export_LookupAccountSidW")]
pub unsafe extern "system" fn lookup_account_sid_w(
    system: *const u16,
    sid: *const u8,
    name: *mut u16,
    cch_name: *mut u32,
    domain: *mut u16,
    cch_domain: *mut u32,
    pe_use: *mut u32,
) -> u32 {
    let _ = system;
    // SAFETY: the caller's SID.
    match unsafe { caller_sid(sid) } {
        Some(sid) => {
            // SAFETY: the caller's buffers and places.
            unsafe {
                lookup_sid(
                    true,
                    sid,
                    name as *mut u8,
                    cch_name,
                    domain as *mut u8,
                    cch_domain,
                    pe_use,
                )
            }
        }
        None => {
            nt::set_last_error(ERROR_INVALID_SID);
            0
        }
    }
}

/// GetWindowsAccountDomainSid: no account domain in F2K, so no domain SID for any account: the
/// last error 1257 and FALSE, the out places untouched.
///
/// # Safety
///
/// `sid` is null or a SID the call may read; the out pointers the caller's places.
#[unsafe(export_name = "f2k_export_GetWindowsAccountDomainSid")]
pub unsafe extern "system" fn get_windows_account_domain_sid(
    sid: *const u8,
    domain_sid: *mut u8,
    cb_domain_sid: *mut u32,
) -> u32 {
    let _ = (domain_sid, cb_domain_sid);
    // SAFETY: the caller's SID.
    match unsafe { caller_sid(sid) } {
        Some(_) => {
            nt::set_last_error(ERROR_NO_ACCOUNT_DOMAIN);
            0
        }
        None => {
            nt::set_last_error(ERROR_INVALID_SID);
            0
        }
    }
}

/// GetSiteSidFromToken: F2K's tokens carry no site SID: success with none found, the last error
/// and the out place untouched.
///
/// # Safety
///
/// `site_sid` is the caller's place for the site SID.
#[unsafe(export_name = "f2k_export_GetSiteSidFromToken")]
pub unsafe extern "system" fn get_site_sid_from_token(token: u32, site_sid: *mut u8) -> u32 {
    let _ = (token, site_sid);
    0
}

/// GetMangledSiteSid: no site SID to mangle: the HRESULT of ERROR_INVALID_SID, the last error and
/// the out place untouched.
///
/// # Safety
///
/// `sid` is null or a SID the call may read; `mangled` the caller's place for the mangled SID.
#[unsafe(export_name = "f2k_export_GetMangledSiteSid")]
pub unsafe extern "system" fn get_mangled_site_sid(sid: *const u8, mangled: *mut u8) -> u32 {
    let _ = mangled;
    // SAFETY: the caller's SID, read where the call reads it.
    let _ = unsafe { caller_sid(sid) };
    HRESULT_FROM_INVALID_SID
}

#[cfg(test)]
mod tests {
    use rtl::testing::sec::sid;
    use rtl::testing::wide_z;

    use super::*;
    use crate::testkit::{arm, last_error};

    /// LookupAccountNameA for a well-known name: the size query reports the SID's size and the
    /// domain's one unit and leaves the account type untouched; with room the SID is written, the
    /// type is the well-known group, and the last error is ERROR_SUCCESS.
    #[test]
    fn lookup_account_name_a_resolves_everyone() {
        let name = b"Everyone\0";
        let mut buffer = vec![0xCCu8; 64];
        let mut cb: u32 = 0;
        let mut dom = vec![0xCCu8; 128];
        let mut cch: u32 = 0;
        let mut use_: u32 = 0xF2F2;
        arm();
        let ret = unsafe {
            lookup_account_name_a(
                core::ptr::null(),
                name.as_ptr(),
                core::ptr::null_mut(),
                &mut cb,
                dom.as_mut_ptr(),
                &mut cch,
                &mut use_,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(last_error(), ERROR_INSUFFICIENT_BUFFER);
        assert_eq!(cb, 12, "S-1-1-0's size");
        assert_eq!(cch, 1);
        assert_eq!(dom[0], 0, "the empty domain");
        assert_eq!(use_, 0xF2F2, "the type untouched");

        let mut cb: u32 = 64;
        arm();
        let ret = unsafe {
            lookup_account_name_a(
                core::ptr::null(),
                name.as_ptr(),
                buffer.as_mut_ptr(),
                &mut cb,
                dom.as_mut_ptr(),
                &mut cch,
                &mut use_,
            )
        };
        assert_eq!(ret, 1);
        assert_eq!(last_error(), 0);
        assert_eq!(&buffer[..12], &sid(1, &[0])[..], "S-1-1-0 written");
        assert_eq!(cb, 12);
        assert_eq!(use_, SID_TYPE_WELL_KNOWN_GROUP);

        // The wide form resolves the wide name.
        let wname = wide_z("Everyone");
        let mut cb: u32 = 64;
        let mut domw = vec![0xCCu16; 128];
        let mut cch: u32 = 128;
        arm();
        let ret = unsafe {
            lookup_account_name_w(
                core::ptr::null(),
                wname.as_ptr(),
                buffer.as_mut_ptr(),
                &mut cb,
                domw.as_mut_ptr(),
                &mut cch,
                &mut use_,
            )
        };
        assert_eq!(ret, 1);
        assert_eq!(last_error(), 0);
        assert_eq!(&buffer[..12], &sid(1, &[0])[..]);
        assert_eq!(domw[0], 0);
        assert_eq!(cch, 1);

        // An unknown name maps to nothing.
        let unknown = b"NoSuchAccount\0";
        let mut cb: u32 = 64;
        arm();
        let ret = unsafe {
            lookup_account_name_a(
                core::ptr::null(),
                unknown.as_ptr(),
                buffer.as_mut_ptr(),
                &mut cb,
                core::ptr::null_mut(),
                &mut cch,
                &mut use_,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(last_error(), ERROR_NONE_MAPPED);
    }

    /// LookupAccountSidA/W for a well-known SID: the account name written with its terminator, the
    /// type the well-known group, the last error ERROR_IO_PENDING; an unknown SID maps to nothing.
    #[test]
    fn lookup_account_sid_unresolves_everyone() {
        let everyone = sid(1, &[0]);
        let mut name = vec![0xCCu8; 128];
        let mut cch: u32 = 128;
        let mut dom = vec![0xCCu8; 128];
        let mut cch_dom: u32 = 128;
        let mut use_: u32 = 0xF2F2;
        arm();
        let ret = unsafe {
            lookup_account_sid_a(
                core::ptr::null(),
                everyone.as_ptr(),
                name.as_mut_ptr(),
                &mut cch,
                dom.as_mut_ptr(),
                &mut cch_dom,
                &mut use_,
            )
        };
        assert_eq!(ret, 1);
        assert_eq!(last_error(), ERROR_IO_PENDING);
        assert_eq!(&name[..9], b"Everyone\0");
        assert_eq!(cch, 9);
        assert_eq!(dom[0], 0);
        assert_eq!(cch_dom, 1);
        assert_eq!(use_, SID_TYPE_WELL_KNOWN_GROUP);

        let mut namew = vec![0xCCu16; 128];
        let mut cch: u32 = 128;
        arm();
        let ret = unsafe {
            lookup_account_sid_w(
                core::ptr::null(),
                everyone.as_ptr(),
                namew.as_mut_ptr(),
                &mut cch,
                core::ptr::null_mut(),
                &mut cch_dom,
                &mut use_,
            )
        };
        assert_eq!(ret, 1);
        assert_eq!(&namew[..9], &wide_z("Everyone")[..]);
        assert_eq!(cch, 9);

        // An account-domain SID no well-known account holds.
        let account = sid(5, &[21, 1, 2, 3, 1000]);
        arm();
        let ret = unsafe {
            lookup_account_sid_a(
                core::ptr::null(),
                account.as_ptr(),
                name.as_mut_ptr(),
                &mut cch,
                core::ptr::null_mut(),
                &mut cch_dom,
                &mut use_,
            )
        };
        assert_eq!(ret, 0);
        assert_eq!(last_error(), ERROR_NONE_MAPPED);
    }

    /// GetWindowsAccountDomainSid: no domain SID for any account, the last error 1257, the size
    /// place untouched. GetSiteSidFromToken: success with no site SID, nothing touched.
    /// GetMangledSiteSid: the HRESULT of ERROR_INVALID_SID, nothing touched.
    #[test]
    fn the_domain_and_site_queries_find_nothing() {
        let admins = sid(5, &[32, 544]);
        let mut domain = vec![0xCCu8; 64];
        let mut cb: u32 = 0xF2F2;
        arm();
        let ret = unsafe {
            get_windows_account_domain_sid(admins.as_ptr(), domain.as_mut_ptr(), &mut cb)
        };
        assert_eq!(ret, 0);
        assert_eq!(last_error(), ERROR_NO_ACCOUNT_DOMAIN);
        assert_eq!(cb, 0xF2F2, "the size untouched");
        assert_eq!(domain, vec![0xCCu8; 64], "the domain SID untouched");

        let mut site: usize = 0xF2F2;
        arm();
        let ret = unsafe { get_site_sid_from_token(0, &mut site as *mut usize as *mut u8) };
        assert_eq!(ret, 0);
        assert_eq!(last_error(), 0xF2F2, "no error touched");
        assert_eq!(site, 0xF2F2, "the site SID untouched");

        let everyone = sid(1, &[0]);
        let mut mangled: usize = 0xF2F2;
        arm();
        let ret = unsafe {
            get_mangled_site_sid(everyone.as_ptr(), &mut mangled as *mut usize as *mut u8)
        };
        assert_eq!(ret, HRESULT_FROM_INVALID_SID);
        assert_eq!(last_error(), 0xF2F2, "no error touched");
        assert_eq!(mangled, 0xF2F2, "the mangled SID untouched");
    }
}
