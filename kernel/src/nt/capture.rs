//! The security services' captures of the caller's buffers: a security descriptor, a SID, an
//! object type list and a GENERIC_MAPPING, each probed and read from the caller's memory and
//! validated before a service acts on it. The access checks (`nt::seccheck`), the audit alarms
//! (`nt::audit`) and the token services (`nt::token`, `nt::token_ops`) share them.

use rtl::array_vec::ArrayVec;

use super::call::UserAddr;
use crate::se;
use crate::sec::sd::{self, Memory};
use crate::sec::{self, GenericMapping, Guid, Owned};
use crate::status::*;

/// The most object types a captured list holds.
pub const MAX_TYPE_LIST: usize = 128;
/// An OBJECT_TYPE_LIST entry's bytes: its level, a spare word and its GUID's address.
const TYPE_ENTRY: usize = 8;
/// The highest level an entry may name.
const MAX_LEVEL: u16 = 4;

/// The caller's address space as a descriptor-capture seam: the probe checks the alignment the
/// read needs, then that the range is the caller's.
struct UserMemory;

impl Memory for UserMemory {
    fn probe(&self, addr: u32, align: u32, len: u32) -> Result<(), NtStatus> {
        if addr % align != 0 {
            return Err(sd::STATUS_DATATYPE_MISALIGNMENT);
        }
        UserAddr(addr).probe(len)?;
        Ok(())
    }

    fn read(&self, addr: u32, align: u32, buf: &mut [u8]) -> Result<(), NtStatus> {
        if addr % align != 0 {
            return Err(sd::STATUS_DATATYPE_MISALIGNMENT);
        }
        UserAddr(addr).read(buf)?;
        Ok(())
    }
}

/// The security descriptor at `at`, captured self-relative into a fresh buffer (None for a
/// null pointer): every range probed, each part sized from its own header and validated.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))] // the services using it are the target's
pub fn capture_sd(at: UserAddr) -> Result<Option<Owned>, NtStatus> {
    if at.is_null() {
        return Ok(None);
    }
    let mem = UserMemory;
    let len = sd::length(&mem, at.raw()).ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut out = sec::allocate(len as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let mut written = 0u32;
    let status = sd::capture(
        &mem,
        at.raw(),
        true,
        false,
        sec::bytes_mut(&mut out),
        &mut written,
    );
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    Ok(Some(out))
}

/// The SID at `ptr` (None for a null pointer, as for the access checks' optional
/// PrincipalSelfSid), read and validated: an unmapped one faults (STATUS_ACCESS_VIOLATION), a
/// malformed one is STATUS_INVALID_SID.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))] // the services using it are the target's
pub fn read_sid(ptr: UserAddr) -> Result<Option<se::SidBytes>, NtStatus> {
    if ptr.is_null() {
        return Ok(None);
    }
    let mut header = [0u8; 2];
    ptr.read(&mut header)?;
    if header[0] & 0x0F != sec::REVISION || usize::from(header[1]) > sec::MAX_SUB_AUTHORITIES {
        return Err(sd::STATUS_INVALID_SID);
    }
    let mut sid = se::SidBytes::new();
    sid.try_extend_default(sec::length_required(usize::from(header[1])))
        .map_err(|_| sd::STATUS_INVALID_SID)?;
    ptr.read(sid.as_mut_slice())?;
    if !sec::sid::is_valid(sid.as_slice()) {
        return Err(sd::STATUS_INVALID_SID);
    }
    Ok(Some(sid))
}

/// The SID at the caller's address `ptr` where one is required (a token structure's SID
/// pointer), as [`read_sid`] reads it, but a null pointer faults (STATUS_ACCESS_VIOLATION), as
/// the dereference does on Windows 2000.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))] // the services using it are the target's
pub fn read_required_sid(ptr: u32) -> Result<se::SidBytes, NtStatus> {
    read_sid(UserAddr(ptr))?.ok_or(STATUS_ACCESS_VIOLATION)
}

/// The caller's object type list at `list`, `count` entries, captured as its GUIDs in order: a
/// null list with a count, or a level past the maximum, is STATUS_INVALID_PARAMETER, a list too
/// long for the capture STATUS_INSUFFICIENT_RESOURCES.
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))] // the services using it are the target's
pub fn capture_type_list(
    list: UserAddr,
    count: u32,
) -> Result<ArrayVec<Guid, MAX_TYPE_LIST>, NtStatus> {
    let mut guids = ArrayVec::new();
    if count == 0 {
        return Ok(guids);
    }
    if list.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if count as usize > MAX_TYPE_LIST {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let bytes = count as usize * TYPE_ENTRY;
    list.probe(bytes as u32)?;
    let mut entries = sec::allocate(bytes).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    list.read(sec::bytes_mut(&mut entries))?;
    let entries = sec::bytes(&entries);
    for i in 0..count as usize {
        let at = i * TYPE_ENTRY;
        if u16::from_le_bytes([entries[at], entries[at + 1]]) > MAX_LEVEL {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let guid_at = UserAddr(u32::from_le_bytes(
            entries[at + 4..at + 8].try_into().unwrap(),
        ));
        let mut raw = [0u8; 16];
        guid_at.read(&mut raw)?;
        guids.push(Guid {
            data1: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
            data2: u16::from_le_bytes(raw[4..6].try_into().unwrap()),
            data3: u16::from_le_bytes(raw[6..8].try_into().unwrap()),
            data4: raw[8..16].try_into().unwrap(),
        });
    }
    Ok(guids)
}

/// The GENERIC_MAPPING at `at`, read whole (16 bytes).
#[cfg_attr(not(target_arch = "x86"), allow(dead_code))] // the services using it are the target's
pub fn read_mapping(at: UserAddr) -> Result<GenericMapping, NtStatus> {
    at.probe(16)?;
    let mut raw = [0u8; 16];
    at.read(&mut raw)?;
    Ok(GenericMapping {
        generic_read: u32::from_le_bytes(raw[0..4].try_into().unwrap()),
        generic_write: u32::from_le_bytes(raw[4..8].try_into().unwrap()),
        generic_execute: u32::from_le_bytes(raw[8..12].try_into().unwrap()),
        generic_all: u32::from_le_bytes(raw[12..16].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::user::syscall::host::{install, Installed, UserMemory as HostMemory};

    /// Where the staged caller memory starts; everything outside it faults.
    const AT: u32 = 0x0060_0000;

    /// The caller's memory: `bytes` mapped from [`AT`].
    struct Mapped {
        bytes: Vec<u8>,
    }

    impl Mapped {
        /// The staged bytes `len` from `pointer`, when they are all mapped.
        fn span(&self, pointer: u32, len: usize) -> Result<core::ops::Range<usize>, NtStatus> {
            let start = pointer.wrapping_sub(AT) as usize;
            match start.checked_add(len) {
                Some(end) if pointer >= AT && end <= self.bytes.len() => Ok(start..end),
                _ => Err(STATUS_ACCESS_VIOLATION),
            }
        }
    }

    impl HostMemory for Mapped {
        fn read(&self, pointer: u32, out: &mut [u8]) -> Result<(), NtStatus> {
            let range = self.span(pointer, out.len())?;
            out.copy_from_slice(&self.bytes[range]);
            Ok(())
        }

        fn write(&mut self, pointer: u32, data: &[u8]) -> Result<(), NtStatus> {
            let range = self.span(pointer, data.len())?;
            self.bytes[range].copy_from_slice(data);
            Ok(())
        }
    }

    /// Install `bytes` as the caller's memory at [`AT`].
    fn stage(bytes: Vec<u8>) -> Installed {
        install(Rc::new(RefCell::new(Mapped { bytes })))
    }

    /// S-1-5-18 (LocalSystem): revision 1, one sub-authority, NT authority.
    const SYSTEM: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    #[test]
    fn read_sid_takes_a_valid_sid_and_answers_none_for_null() {
        let _memory = stage(SYSTEM.to_vec());
        assert_eq!(read_sid(UserAddr(0)), Ok(None));
        assert_eq!(
            read_sid(UserAddr(AT)).unwrap().unwrap().as_slice(),
            &SYSTEM[..]
        );
        assert_eq!(read_required_sid(AT).unwrap().as_slice(), &SYSTEM[..]);
    }

    #[test]
    fn a_required_sid_faults_on_a_null_pointer() {
        let _memory = stage(SYSTEM.to_vec());
        assert_eq!(read_required_sid(0), Err(STATUS_ACCESS_VIOLATION));
    }

    #[test]
    fn read_sid_refuses_a_malformed_or_unmapped_sid() {
        let mut bad_revision = SYSTEM;
        bad_revision[0] = 2;
        let _memory = stage(bad_revision.to_vec());
        assert_eq!(read_sid(UserAddr(AT)), Err(sd::STATUS_INVALID_SID));
        let mut too_many = SYSTEM;
        too_many[1] = 16;
        let _memory = stage(too_many.to_vec());
        assert_eq!(read_sid(UserAddr(AT)), Err(sd::STATUS_INVALID_SID));
        // The header says one sub-authority, but the SID runs off the mapped bytes.
        let _memory = stage(SYSTEM[..10].to_vec());
        assert_eq!(read_sid(UserAddr(AT)), Err(STATUS_ACCESS_VIOLATION));
    }

    #[test]
    fn capture_type_list_reads_each_entrys_guid() {
        // One entry at AT (level 0, its GUID at AT + 8), the GUID after it.
        let mut bytes = vec![0u8; 8];
        bytes[4..8].copy_from_slice(&(AT + 8).to_le_bytes());
        bytes.extend_from_slice(&[1, 0, 0, 0, 2, 0, 3, 0, 4, 5, 6, 7, 8, 9, 10, 11]);
        let _memory = stage(bytes.clone());
        let guids = capture_type_list(UserAddr(AT), 1).unwrap();
        assert_eq!(guids.len(), 1);
        assert_eq!(
            (
                guids[0].data1,
                guids[0].data2,
                guids[0].data3,
                guids[0].data4
            ),
            (1, 2, 3, [4, 5, 6, 7, 8, 9, 10, 11])
        );
        // A level past the maximum.
        bytes[0] = (MAX_LEVEL + 1) as u8;
        let _memory = stage(bytes);
        assert_eq!(
            capture_type_list(UserAddr(AT), 1).unwrap_err(),
            STATUS_INVALID_PARAMETER
        );
    }

    #[test]
    fn capture_type_list_checks_the_count_before_the_memory() {
        assert!(capture_type_list(UserAddr(0), 0).unwrap().is_empty());
        assert_eq!(
            capture_type_list(UserAddr(0), 1).unwrap_err(),
            STATUS_INVALID_PARAMETER
        );
        assert_eq!(
            capture_type_list(UserAddr(AT), MAX_TYPE_LIST as u32 + 1).unwrap_err(),
            STATUS_INSUFFICIENT_RESOURCES
        );
        // Nothing mapped: the entries fault.
        assert_eq!(
            capture_type_list(UserAddr(AT), 1).unwrap_err(),
            STATUS_ACCESS_VIOLATION
        );
    }

    #[test]
    fn read_mapping_reads_the_four_masks_in_order() {
        let bytes: Vec<u8> = [0x8000_0000u32, 0x4000_0000, 0x2000_0000, 0x1000_0000]
            .iter()
            .flat_map(|mask| mask.to_le_bytes())
            .collect();
        let _memory = stage(bytes);
        let mapping = read_mapping(UserAddr(AT)).unwrap();
        assert_eq!(
            (
                mapping.generic_read,
                mapping.generic_write,
                mapping.generic_execute,
                mapping.generic_all
            ),
            (0x8000_0000, 0x4000_0000, 0x2000_0000, 0x1000_0000)
        );
        assert_eq!(
            read_mapping(UserAddr(AT + 4)).unwrap_err(),
            STATUS_ACCESS_VIOLATION
        );
    }

    #[test]
    fn capture_sd_answers_none_for_null_and_faults_on_unmapped_memory() {
        assert_eq!(capture_sd(UserAddr(0)).map(|sd| sd.is_none()), Ok(true));
        assert_eq!(
            capture_sd(UserAddr(AT)).map(|_| ()),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}
