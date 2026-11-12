//! The version checks, as ntdll's VerSetConditionMask and RtlVerifyVersionInfo make them
//! (kernel32's VerSetConditionMask forwards to the first, its VerifyVersionInfoW and A call the
//! second).
//!
//! A condition mask holds three bits per type of check, the type's bit number choosing the field
//! (VER_MINORVERSION, bit 0, the lowest three bits; VER_MAJORVERSION, bit 1, the next three), and
//! its top bit set once any condition is in it. The checks compare the system's version with the
//! caller's under each type's condition: the major and minor versions and the service pack's
//! numbers together, in that order, under the first of them the types name; the build number, the
//! platform and the product type each alone; the suite mask by its bits.

/// The types of check (VerifyVersionInfo's dwTypeMask bits).
pub const VER_MINORVERSION: u32 = 0x01;
pub const VER_MAJORVERSION: u32 = 0x02;
pub const VER_BUILDNUMBER: u32 = 0x04;
pub const VER_PLATFORMID: u32 = 0x08;
pub const VER_SERVICEPACKMINOR: u32 = 0x10;
pub const VER_SERVICEPACKMAJOR: u32 = 0x20;
pub const VER_SUITENAME: u32 = 0x40;
pub const VER_PRODUCT_TYPE: u32 = 0x80;

/// The conditions.
pub const VER_EQUAL: u8 = 1;
pub const VER_GREATER: u8 = 2;
pub const VER_GREATER_EQUAL: u8 = 3;
pub const VER_LESS: u8 = 4;
pub const VER_LESS_EQUAL: u8 = 5;
pub const VER_AND: u8 = 6;
pub const VER_OR: u8 = 7;

/// The mask's top bit: a condition was set in it.
const CONDITIONS_SET: u64 = 1 << 63;

/// VerSetConditionMask: `condition`'s three bits OR'd into the slot of `types`' highest type (one
/// type per call; a later condition for the same type ORs into the same slot), and the top bit
/// set. No type leaves the mask as it is.
pub fn set_condition_mask(mask: u64, types: u32, condition: u8) -> u64 {
    if types == 0 {
        return mask;
    }
    let shift = 3 * (31 - types.leading_zeros());
    let bits = u64::from(condition & 7);
    // A slot past the mask's 63 condition bits takes nothing (the capture shows bit 8's, at 24;
    // the types end at bit 7).
    let slot = if shift < 63 { bits << shift } else { 0 };
    mask | CONDITIONS_SET | slot
}

/// The condition `mask` holds for type `bit` (its bit number).
fn condition(mask: u64, bit: u32) -> u8 {
    (mask >> (3 * bit) & 7) as u8
}

/// The version facts a check compares: the system's (the PEB's and the shared data page's), or the
/// caller's OSVERSIONINFOEX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VersionInfo {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub platform: u32,
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
}

/// Why a check failed: a type mask naming no check (STATUS_INVALID_PARAMETER), or a version that
/// does not meet the conditions (STATUS_REVISION_MISMATCH).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    NoType,
    Mismatch,
}

/// Whether `system` meets `condition` against `wanted`. A comparison's condition only: no
/// condition (0), or VER_AND and VER_OR, check nothing here.
///
/// VER_LESS lets an equal value through, as the real machine's capture shows ("major < 5" holds
/// on Windows 2000, version 5); VER_GREATER does not.
fn compare(system: u32, wanted: u32, condition: u8) -> bool {
    match condition {
        VER_EQUAL => system == wanted,
        VER_GREATER => system > wanted,
        VER_GREATER_EQUAL => system >= wanted,
        VER_LESS | VER_LESS_EQUAL => system <= wanted,
        _ => true,
    }
}

/// RtlVerifyVersionInfo: whether `system` meets each of `types`' conditions in `mask` against
/// `wanted`. A type whose condition is none is not checked.
pub fn verify(
    system: &VersionInfo,
    wanted: &VersionInfo,
    types: u32,
    mask: u64,
) -> Result<(), Refusal> {
    if types == 0 {
        return Err(Refusal::NoType);
    }
    // The major and minor versions and the service pack's numbers, compared as one version: the
    // first field that differs decides, under the condition of the first type named.
    let ordered = [
        (VER_MAJORVERSION, 1, system.major, wanted.major),
        (VER_MINORVERSION, 0, system.minor, wanted.minor),
        (
            VER_SERVICEPACKMAJOR,
            5,
            u32::from(system.service_pack_major),
            u32::from(wanted.service_pack_major),
        ),
        (
            VER_SERVICEPACKMINOR,
            4,
            u32::from(system.service_pack_minor),
            u32::from(wanted.service_pack_minor),
        ),
    ];
    let mut named = ordered.iter().filter(|(ty, ..)| types & ty != 0);
    if let Some(&(_, bit, ..)) = named.clone().next() {
        let leading = condition(mask, bit);
        let decided = named
            .find(|(_, _, sys, want)| sys != want)
            .map_or((0, 0), |&(_, _, sys, want)| (sys, want));
        if !compare(decided.0, decided.1, leading) {
            return Err(Refusal::Mismatch);
        }
    }
    let alone = [
        (VER_BUILDNUMBER, 2, system.build, wanted.build),
        (VER_PLATFORMID, 3, system.platform, wanted.platform),
        (
            VER_PRODUCT_TYPE,
            7,
            u32::from(system.product_type),
            u32::from(wanted.product_type),
        ),
    ];
    for &(ty, bit, sys, want) in &alone {
        if types & ty != 0 && !compare(sys, want, condition(mask, bit)) {
            return Err(Refusal::Mismatch);
        }
    }
    if types & VER_SUITENAME != 0 {
        let (sys, want) = (system.suite_mask, wanted.suite_mask);
        let met = match condition(mask, 6) {
            VER_AND => sys & want == want,
            VER_OR => want == 0 || sys & want != 0,
            _ => true,
        };
        if !met {
            return Err(Refusal::Mismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mask(types: u32, condition: u8) -> u64 {
        set_condition_mask(0, types, condition)
    }

    #[test]
    fn masks_match_the_capture() {
        assert_eq!(
            mask(VER_MAJORVERSION, VER_GREATER_EQUAL),
            0x8000_0000_0000_0018
        );
        assert_eq!(mask(VER_MINORVERSION, VER_EQUAL), 0x8000_0000_0000_0001);
        assert_eq!(mask(VER_BUILDNUMBER, VER_LESS_EQUAL), 0x8000_0000_0000_0140);
        assert_eq!(mask(VER_PLATFORMID, VER_EQUAL), 0x8000_0000_0000_0200);
        assert_eq!(
            mask(VER_SERVICEPACKMINOR, VER_GREATER),
            0x8000_0000_0000_2000
        );
        assert_eq!(mask(VER_SERVICEPACKMAJOR, VER_LESS), 0x8000_0000_0002_0000);
        assert_eq!(mask(VER_SUITENAME, VER_AND), 0x8000_0000_0018_0000);
        assert_eq!(mask(VER_PRODUCT_TYPE, VER_OR), 0x8000_0000_00E0_0000);
        let ge = mask(VER_MAJORVERSION, VER_GREATER_EQUAL);
        assert_eq!(
            set_condition_mask(ge, VER_MAJORVERSION, VER_LESS),
            0x8000_0000_0000_0038
        );
        assert_eq!(
            mask(VER_MAJORVERSION | VER_MINORVERSION, VER_EQUAL),
            0x8000_0000_0000_0008
        );
        assert_eq!(mask(0, VER_EQUAL), 0);
        assert_eq!(mask(VER_MAJORVERSION, 0), 0x8000_0000_0000_0000);
        assert_eq!(mask(VER_MAJORVERSION, 8), 0x8000_0000_0000_0000);
        assert_eq!(mask(0x100, VER_EQUAL), 0x8000_0000_0100_0000);
    }

    const SYSTEM: VersionInfo = VersionInfo {
        major: 5,
        minor: 0,
        build: 2195,
        platform: 2,
        service_pack_major: 4,
        service_pack_minor: 0,
        suite_mask: 0,
        product_type: 1,
    };

    fn check(types: u32, mask: u64, wanted: VersionInfo) -> Result<(), Refusal> {
        verify(&SYSTEM, &wanted, types, mask)
    }

    fn version(major: u32, minor: u32, sp: u16) -> VersionInfo {
        VersionInfo {
            major,
            minor,
            service_pack_major: sp,
            ..VersionInfo::default()
        }
    }

    #[test]
    fn checks_match_the_capture() {
        let major = |c| mask(VER_MAJORVERSION, c);
        assert_eq!(
            check(VER_MAJORVERSION, major(VER_EQUAL), version(5, 0, 0)),
            Ok(())
        );
        assert_eq!(
            check(VER_MAJORVERSION, major(VER_EQUAL), version(4, 0, 0)),
            Err(Refusal::Mismatch)
        );
        assert_eq!(
            check(VER_MAJORVERSION, major(VER_LESS), version(5, 0, 0)),
            Ok(())
        );
        assert_eq!(
            check(VER_MAJORVERSION, major(VER_GREATER), version(4, 0, 0)),
            Ok(())
        );
        let both = set_condition_mask(
            major(VER_GREATER_EQUAL),
            VER_MINORVERSION,
            VER_GREATER_EQUAL,
        );
        let mm = VER_MAJORVERSION | VER_MINORVERSION;
        assert_eq!(check(mm, both, version(5, 1, 0)), Err(Refusal::Mismatch));
        assert_eq!(check(mm, both, version(4, 90, 0)), Ok(()));
        let three = set_condition_mask(both, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
        let mms = mm | VER_SERVICEPACKMAJOR;
        assert_eq!(check(mms, three, version(5, 0, 4)), Ok(()));
        assert_eq!(check(mms, three, version(5, 0, 5)), Err(Refusal::Mismatch));
        assert_eq!(check(mms, three, version(4, 0, 6)), Ok(()));
        let build = VersionInfo {
            build: 2195,
            ..VersionInfo::default()
        };
        assert_eq!(
            check(VER_BUILDNUMBER, mask(VER_BUILDNUMBER, VER_GREATER), build),
            Err(Refusal::Mismatch)
        );
        assert_eq!(
            check(0, major(VER_EQUAL), version(5, 0, 0)),
            Err(Refusal::NoType)
        );
        assert_eq!(check(VER_MAJORVERSION, 0, version(5, 0, 0)), Ok(()));
        assert_eq!(
            check(
                VER_MAJORVERSION,
                mask(VER_MINORVERSION, VER_EQUAL),
                version(5, 0, 0)
            ),
            Ok(())
        );
    }
}
