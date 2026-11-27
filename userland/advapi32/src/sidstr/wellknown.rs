//! The well-known SIDs: CreateWellKnownSid builds one of the public fixed table (types 0 to 37)
//! into the caller's buffer, IsWellKnownSid compares the caller's SID against one. F2K has no
//! domain SID, so the account types past the table answer ERROR_INVALID_PARAMETER.

// ERROR_INSUFFICIENT_BUFFER: the buffer too small for the SID. ERROR_INVALID_PARAMETER: a bad
// type, or a null place.
use rtl::winerror::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER};

use super::{caller_sid, sid_of, SID_HEADER, SID_MAX_SUB_AUTHORITIES};
use crate::imports::{self as nt};
use crate::{caller_bytes_mut, Out};

/// The well-known SID types (the public WELL_KNOWN_SID_TYPE values 0 to 37): each its identifier
/// authority and its sub-authorities. The account types past them take a domain SID, which F2K
/// has none of.
const WELL_KNOWN: [(u8, &[u32]); 38] = [
    (0, &[0]),       // null: S-1-0-0
    (1, &[0]),       // world: S-1-1-0
    (2, &[0]),       // local: S-1-2-0
    (3, &[0]),       // creator owner: S-1-3-0
    (4, &[1]),       // creator group: S-1-3-1
    (5, &[2]),       // creator owner server: S-1-3-2
    (6, &[3]),       // creator group server: S-1-3-3
    (5, &[]),        // NT authority: S-1-5
    (5, &[1]),       // dialup: S-1-5-1
    (5, &[2]),       // network: S-1-5-2
    (5, &[3]),       // batch: S-1-5-3
    (5, &[4]),       // interactive: S-1-5-4
    (5, &[6]),       // service: S-1-5-6
    (5, &[7]),       // anonymous: S-1-5-7
    (5, &[8]),       // proxy: S-1-5-8
    (5, &[9]),       // enterprise controllers: S-1-5-9
    (5, &[10]),      // self: S-1-5-10
    (5, &[11]),      // authenticated users: S-1-5-11
    (5, &[12]),      // restricted: S-1-5-12
    (5, &[13]),      // terminal server: S-1-5-13
    (5, &[14]),      // remote logon: S-1-5-14
    (5, &[5]),       // logon ids: S-1-5-5
    (5, &[18]),      // local system: S-1-5-18
    (5, &[19]),      // local service: S-1-5-19
    (5, &[20]),      // network service: S-1-5-20
    (5, &[32]),      // builtin domain: S-1-5-32
    (5, &[32, 544]), // builtin administrators: S-1-5-32-544
    (5, &[32, 545]), // builtin users: S-1-5-32-545
    (5, &[32, 546]), // builtin guests: S-1-5-32-546
    (5, &[32, 547]), // builtin power users: S-1-5-32-547
    (5, &[32, 548]), // builtin account operators: S-1-5-32-548
    (5, &[32, 549]), // builtin system operators: S-1-5-32-549
    (5, &[32, 550]), // builtin print operators: S-1-5-32-550
    (5, &[32, 551]), // builtin backup operators: S-1-5-32-551
    (5, &[32, 552]), // builtin replicator: S-1-5-32-552
    (5, &[32, 554]), // pre-windows-2000 compatible access: S-1-5-32-554
    (5, &[32, 555]), // remote desktop users: S-1-5-32-555
    (5, &[32, 556]), // network configuration operators: S-1-5-32-556
];

/// The most bytes a SID takes: the header and 15 sub-authorities.
const SID_MOST: usize = SID_HEADER + 4 * SID_MAX_SUB_AUTHORITIES;

/// The bytes of the well-known SID of `authority` and `subs` into `out`, its length out: the
/// revision 1, the count, the authority, the sub-authorities.
fn well_known_bytes(authority: u8, subs: &[u32], out: &mut [u8; SID_MOST]) -> usize {
    out[0] = 1;
    out[1] = subs.len() as u8;
    out[2..SID_HEADER].copy_from_slice(&[0, 0, 0, 0, 0, authority]);
    for (index, sub) in subs.iter().enumerate() {
        out[SID_HEADER + 4 * index..SID_HEADER + 4 * index + 4].copy_from_slice(&sub.to_le_bytes());
    }
    SID_HEADER + 4 * subs.len()
}

/// CreateWellKnownSid: the well-known SID of `well_known_sid_type` (0 to 37) into `sid`, a buffer
/// of `*cb_sid` bytes: when there is no room (or no buffer), FALSE with ERROR_INSUFFICIENT_BUFFER
/// and the required size in `*cb_sid`; otherwise TRUE with the SID written, the size in
/// `*cb_sid` and the last error untouched. A type past the table answers FALSE with
/// ERROR_INVALID_PARAMETER.
///
/// # Safety
///
/// `sid` is null or a buffer of `*cb_sid` bytes the call may write; `cb_sid` the caller's place
/// for the size. `domain_sid` is unused (the account types past the table need one, and F2K has
/// no domain SID).
#[unsafe(export_name = "f2k_export_CreateWellKnownSid")]
pub unsafe extern "system" fn create_well_known_sid(
    well_known_sid_type: u32,
    _domain_sid: *const u8,
    sid: *mut u8,
    cb_sid: *mut u32,
) -> u32 {
    let Some(&(authority, subs)) = WELL_KNOWN.get(well_known_sid_type as usize) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    // SAFETY: the caller's place for the size.
    let mut cb = unsafe { Out::optional(cb_sid) };
    let Some(cb) = cb.as_mut() else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let required = (SID_HEADER + 4 * subs.len()) as u32;
    if sid.is_null() || cb.get() < required {
        cb.set(required);
        nt::set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    // SAFETY: the caller's buffer of `required` bytes.
    let Some(bytes) = (unsafe { caller_bytes_mut(sid, required as usize) }) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    let mut built = [0u8; SID_MOST];
    let len = well_known_bytes(authority, subs, &mut built);
    bytes.copy_from_slice(&built[..len]);
    cb.set(required);
    1
}

/// IsWellKnownSid: whether `sid` is the well-known SID of `well_known_sid_type` (0 to 37),
/// compared byte for byte; the last error ERROR_SUCCESS on a valid type (a type past the table
/// answers FALSE with ERROR_INVALID_PARAMETER).
///
/// # Safety
///
/// `sid` is null or a SID the call may read.
#[unsafe(export_name = "f2k_export_IsWellKnownSid")]
pub unsafe extern "system" fn is_well_known_sid(sid: *const u8, well_known_sid_type: u32) -> u32 {
    let Some(&(authority, subs)) = WELL_KNOWN.get(well_known_sid_type as usize) else {
        nt::set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    };
    nt::set_last_error(0);
    let mut built = [0u8; SID_MOST];
    let len = well_known_bytes(authority, subs, &mut built);
    // SAFETY: the caller's SID, or null.
    let caller = unsafe { caller_sid(sid) };
    u32::from(caller.is_some_and(|bytes| sid_of(bytes) == Some(&built[..len])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::LAST_ERROR;

    fn last_error() -> u32 {
        LAST_ERROR.with(|error| error.get())
    }

    fn arm() {
        LAST_ERROR.with(|error| error.set(0xF2F2));
    }

    /// The SID of `authority` and `subs`: S-1-<authority>-<subs...>.
    fn sid(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut bytes = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for sub in subs {
            bytes.extend(sub.to_le_bytes());
        }
        bytes
    }

    /// CreateWellKnownSid asks for the size first (FALSE, ERROR_INSUFFICIENT_BUFFER 122, the
    /// required size in *cbSid, even with no buffer), then builds the SID into a roomy buffer
    /// (TRUE, the last error untouched, the size in *cbSid): BuiltinAdministrators is
    /// S-1-5-32-544, World is S-1-1-0; a type past the table is FALSE with ERROR_INVALID_PARAMETER
    /// (87). IsWellKnownSid compares against the built one: TRUE with the last error
    /// ERROR_SUCCESS for a match, FALSE for a mismatch, 87 for a bad type.
    #[test]
    fn well_known_sids_build_and_match() {
        let mut buffer = [0xCCu8; 256];
        let mut len = 0u32;
        arm();
        let ok = unsafe {
            create_well_known_sid(26, core::ptr::null(), core::ptr::null_mut(), &mut len)
        };
        assert_eq!((ok, last_error(), len), (0, 122, 16), "the size query");
        len = 256;
        arm();
        let ok =
            unsafe { create_well_known_sid(26, core::ptr::null(), buffer.as_mut_ptr(), &mut len) };
        assert_eq!((ok, last_error(), len), (1, 0xF2F2, 16));
        assert_eq!(&buffer[..16], &sid(5, &[32, 544])[..]);
        len = 256;
        arm();
        let ok =
            unsafe { create_well_known_sid(1, core::ptr::null(), buffer.as_mut_ptr(), &mut len) };
        assert_eq!((ok, last_error(), len), (1, 0xF2F2, 12));
        assert_eq!(&buffer[..12], &sid(1, &[0])[..]);
        len = 256;
        arm();
        let ok =
            unsafe { create_well_known_sid(99, core::ptr::null(), buffer.as_mut_ptr(), &mut len) };
        assert_eq!((ok, last_error()), (0, 87));
        let world = sid(1, &[0]);
        let admins = sid(5, &[32, 544]);
        arm();
        assert_eq!(
            (
                unsafe { is_well_known_sid(world.as_ptr(), 1) },
                last_error()
            ),
            (1, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { is_well_known_sid(admins.as_ptr(), 26) },
                last_error()
            ),
            (1, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { is_well_known_sid(world.as_ptr(), 26) },
                last_error()
            ),
            (0, 0)
        );
        arm();
        assert_eq!(
            (
                unsafe { is_well_known_sid(admins.as_ptr(), 99) },
                last_error()
            ),
            (0, 87)
        );
    }
}
