//! The locally-unique-id service: NtAllocateLocallyUniqueId, which hands out the ids a
//! privilege or a logon session is named by (advapi32's AllocateLocallyUniqueId is Win32
//! code over it, as on Windows 2000).
//!
//! The ids come from one kernel counter: the low dword counts up from past the reserved low
//! range, the high dword always zero, so every id is unique for the boot. The service only
//! writes the caller's LUID, so it runs on the host builds too (the host tests install a
//! user memory for it).

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::nt::Luid;
use rtl::pod::Pod;

use super::call::{NtCall, NtResult, UserAddr};
use crate::status::*;

/// The first id handed out: past the reserved low range (the system logon's id among them).
#[cfg_attr(not(test), allow(dead_code))] // read through the service below
pub const FIRST_LUID: u32 = 0x0002_0000;

/// The id source: the next one to hand out.
#[cfg_attr(not(test), allow(dead_code))] // read through the service below
static NEXT_LUID: AtomicU32 = AtomicU32::new(FIRST_LUID);

/// The next locally unique id: the counter's current value, then one on (its high part
/// always zero).
#[cfg_attr(not(test), allow(dead_code))] // read through the service below
pub fn allocate() -> Luid {
    Luid {
        low_part: NEXT_LUID.fetch_add(1, Ordering::Relaxed),
        high_part: 0,
    }
}

/// NtAllocateLocallyUniqueId: a fresh locally unique id written into the caller's LUID.
/// A null place, or one the caller's memory refuses, is STATUS_ACCESS_VIOLATION.
#[cfg_attr(not(test), allow(dead_code))] // wired to its export when the spec flips
pub fn allocate_locally_unique_id(_: &mut NtCall, luid: UserAddr) -> NtResult {
    if luid.is_null() {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    luid.write(allocate().as_bytes())?;
    Ok(STATUS_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::TrapFrame;
    use crate::user::syscall::host::{install, UserMemory};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Mapped user memory at [BASE, BASE + len): anything else faults.
    const BASE: u32 = 0x0040_0000;

    struct Page(Vec<u8>);

    impl UserMemory for Page {
        fn read(&self, pointer: u32, bytes: &mut [u8]) -> Result<(), NtStatus> {
            let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            bytes.copy_from_slice(
                self.0
                    .get(at..at + bytes.len())
                    .ok_or(STATUS_ACCESS_VIOLATION)?,
            );
            Ok(())
        }

        fn write(&mut self, pointer: u32, bytes: &[u8]) -> Result<(), NtStatus> {
            let at = pointer.checked_sub(BASE).ok_or(STATUS_ACCESS_VIOLATION)? as usize;
            self.0
                .get_mut(at..at + bytes.len())
                .ok_or(STATUS_ACCESS_VIOLATION)?
                .copy_from_slice(bytes);
            Ok(())
        }
    }

    /// The seed: the first id's low part starts past the reserved range.
    #[test]
    fn the_seed_is_past_the_reserved_range() {
        assert_eq!(FIRST_LUID, 0x0002_0000);
    }

    /// Ids count up by one, the high part always zero (the counter is global, so the
    /// assertions are relative).
    #[test]
    fn ids_count_up_with_a_zero_high_part() {
        let a = allocate();
        let b = allocate();
        assert_eq!(b.low_part, a.low_part.wrapping_add(1));
        assert_eq!((a.high_part, b.high_part), (0, 0));
    }

    /// NtAllocateLocallyUniqueId writes a fresh id into the caller's LUID and answers
    /// STATUS_SUCCESS; a null place, or one past the mapped page, is
    /// STATUS_ACCESS_VIOLATION.
    #[test]
    fn the_service_writes_a_fresh_id() {
        let page = Rc::new(RefCell::new(Page(vec![0u8; 0x100])));
        let _installed = install(page.clone());
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            allocate_locally_unique_id(&mut call, UserAddr(BASE)),
            Ok(STATUS_SUCCESS)
        );
        let mut raw = [0u8; 8];
        UserAddr(BASE).read(&mut raw).unwrap();
        let first = Luid::from_bytes(&raw).unwrap();
        assert_eq!(first.high_part, 0);
        assert_eq!(
            allocate_locally_unique_id(&mut call, UserAddr(BASE + 8)),
            Ok(STATUS_SUCCESS)
        );
        UserAddr(BASE + 8).read(&mut raw).unwrap();
        let second = Luid::from_bytes(&raw).unwrap();
        assert_eq!(second.low_part, first.low_part.wrapping_add(1));
        assert_eq!(second.high_part, 0);
        assert_eq!(
            allocate_locally_unique_id(&mut call, UserAddr(0)),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(
            allocate_locally_unique_id(&mut call, UserAddr(BASE + 0x1000)),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }

    /// With no user memory installed, every write faults the same way.
    #[test]
    fn an_unmapped_place_faults() {
        let mut frame = TrapFrame::default();
        let mut passive = crate::level::passive_for_test();
        let mut call = NtCall::new(&mut frame, &mut passive);
        assert_eq!(
            allocate_locally_unique_id(&mut call, UserAddr(BASE)),
            Err(STATUS_ACCESS_VIOLATION)
        );
    }
}
