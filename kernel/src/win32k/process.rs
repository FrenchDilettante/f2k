//! The window manager's per-process records: what win32k keeps for each process that holds its
//! objects, as Windows 2000's win32k keeps a W32PROCESS (its PROCESSINFO) beside each EPROCESS.
//! F2K's record holds the count of the process's USER objects, which the per-process quota bounds
//! ([`super::quota`]); slot-pool slices 13 and 18 add the GDI objects' count and the class lists.
//!
//! The records are a side table of the slot pool ([`crate::slots::SideTable`]) keyed by the
//! process object's index (a class [`Owner`]), made a page at a time as processes come: a record
//! is ensured at its process's first counted object and kept, reset at the process's end. The
//! table lives in the user handle table ([`super::handle::UserHandles`]), whose inserts and closes
//! are the only changes to the counts (Windows 2000's HMAllocObject and HMFreeObject), under the
//! window manager's lock.
//!
//! The service (F2K's argument list, see [`crate::win32k`]; Windows 2000's number):
//!
//! - NtUserGetGuiResources (0x118A): GetGuiResources's GR_USEROBJECTS, the USER objects a process
//!   holds (0 for a process that holds none, or never made one).

use rtl::winerror::ERROR_NO_MORE_USER_HANDLES;

use super::class::Owner;
use crate::slots::{Exhausted, Pages, Record, SideTable, PAGE};
use crate::status::*;

/// GetGuiResources's flag for the USER objects a process holds.
pub const GR_USEROBJECTS: u32 = 1;

/// The status a create refused by the quota or the handle table's ceiling answers:
/// ERROR_NO_MORE_USER_HANDLES (1158) in a FACILITY_NTWIN32 status, which user32 hands to
/// GetLastError as is (no NTSTATUS has 1158 for its RtlNtStatusToDosError mapping, and Windows
/// 2000's win32k sets the last error itself).
pub const NO_MORE_USER_HANDLES: NtStatus = NtStatus::from_win32(ERROR_NO_MORE_USER_HANDLES);

/// One process's record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct W32Process {
    /// The USER objects the process holds: its windows, menus, accelerator tables, cursors and
    /// icons, each counted from its handle's insert to its close.
    pub user_objects: u32,
}

// SAFETY: `write_fresh` writes a whole record.
unsafe impl Record for W32Process {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(W32Process::default()) };
    }
}

/// Records to a chunk: one page's worth (each entry carries its u32 index ahead of the record).
const RECORDS_PER_CHUNK: usize = PAGE / (4 + core::mem::size_of::<W32Process>());

const _: () = assert!(SideTable::<W32Process, RECORDS_PER_CHUNK>::CHUNK_PAGES == 1);

/// Why a process may not take one more USER object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The process holds its quota's worth (ERROR_NO_MORE_USER_HANDLES).
    Quota,
    /// No page was left for the process's record (ERROR_NOT_ENOUGH_MEMORY).
    NoMemory,
}

/// The per-process records, by process index.
pub struct W32Processes {
    table: SideTable<W32Process, RECORDS_PER_CHUNK>,
}

impl W32Processes {
    /// No record made, no page held.
    pub const fn new() -> Self {
        W32Processes {
            table: SideTable::new(),
        }
    }

    /// The USER objects the process `process` holds: 0 for one with no record.
    pub fn user_objects(&self, process: Owner) -> u32 {
        self.table
            .get(u32::from(process))
            .map_or(0, |record| record.user_objects)
    }

    /// Whether the process `process` may take one more USER object under `quota`, its record made
    /// if it had none: the check Windows 2000's HMAllocObject makes before it takes a handle.
    pub fn may_take_user_object(
        &mut self,
        process: Owner,
        quota: u32,
        pages: &impl Pages,
    ) -> Result<(), Refusal> {
        let index = u32::from(process);
        self.table.ensure(index, pages).map_err(|why| match why {
            Exhausted::NoPages | Exhausted::Limit => Refusal::NoMemory,
        })?;
        if self.user_objects(process) >= quota {
            return Err(Refusal::Quota);
        }
        Ok(())
    }

    /// The process `process` took a USER object (after [`W32Processes::may_take_user_object`]).
    pub fn took_user_object(&mut self, process: Owner) {
        if let Some(record) = self.table.get_mut(u32::from(process)) {
            record.user_objects += 1;
        }
    }

    /// The process `process` let a USER object go: its handle closed.
    pub fn gave_user_object(&mut self, process: Owner) {
        if let Some(record) = self.table.get_mut(u32::from(process)) {
            debug_assert!(
                record.user_objects > 0,
                "a USER object counted at its insert"
            );
            record.user_objects = record.user_objects.saturating_sub(1);
        }
    }

    /// The process `process` has ended: its record starts afresh for the next process at its
    /// index.
    pub fn end(&mut self, process: Owner) {
        if let Some(record) = self.table.get_mut(u32::from(process)) {
            *record = W32Process::default();
        }
    }
}

impl Default for W32Processes {
    fn default() -> Self {
        Self::new()
    }
}

// --- The service
// ----------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::nt::object::{reference_process, PROCESS_QUERY_INFORMATION};
    use crate::win32k::queue::with_manager;

    /// NtUserGetGuiResources(Process, Flags, Count): the USER objects the process `process` names
    /// holds (GR_USEROBJECTS) into `count`; the handle opened with PROCESS_QUERY_INFORMATION
    /// (STATUS_ACCESS_DENIED without it, STATUS_INVALID_HANDLE for a handle naming none) or the
    /// current-process pseudo-handle. STATUS_INVALID_PARAMETER for another flag: user32 answers
    /// GR_GDIOBJECTS itself until the GDI objects are counted (slot-pool slice 13).
    pub fn get_gui_resources(
        call: &mut NtCall,
        process: Handle,
        flags: u32,
        count: UserPtr<u32>,
    ) -> NtResult {
        if flags != GR_USEROBJECTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let owner = reference_process(process.raw(), PROCESS_QUERY_INFORMATION)?
            .id()
            .index;
        let answer = with_manager(call.passive(), |m| {
            m.windows.handles.processes().user_objects(owner)
        });
        count.write(answer)?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the service answers nothing (the host
// tests drive the records themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};

    pub fn get_gui_resources(_: &mut NtCall, _: Handle, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::get_gui_resources;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win32k::test_pages;

    /// A process with no record holds nothing; a record is made at the first check, counts up and
    /// down, refuses at the quota, and starts afresh at the process's end.
    #[test]
    fn a_record_counts_and_refuses_at_the_quota() {
        let mut p = W32Processes::new();
        assert_eq!(p.user_objects(3), 0);
        for _ in 0..5 {
            assert_eq!(p.may_take_user_object(3, 5, test_pages::current()), Ok(()));
            p.took_user_object(3);
        }
        assert_eq!(p.user_objects(3), 5);
        assert_eq!(
            p.may_take_user_object(3, 5, test_pages::current()),
            Err(Refusal::Quota)
        );
        assert_eq!(p.user_objects(7), 0, "another process's count is its own");
        p.gave_user_object(3);
        assert_eq!(p.may_take_user_object(3, 5, test_pages::current()), Ok(()));
        p.end(3);
        assert_eq!(p.user_objects(3), 0);
    }

    /// No page for a record: the check refuses for memory, not the quota.
    #[test]
    fn no_page_no_record() {
        let mut p = W32Processes::new();
        test_pages::budget(0);
        assert_eq!(
            p.may_take_user_object(1, 10, test_pages::current()),
            Err(Refusal::NoMemory)
        );
        test_pages::unlimited();
        assert_eq!(p.may_take_user_object(1, 10, test_pages::current()), Ok(()));
    }

    /// A record past the first chunk: processes at high indices have records of their own.
    #[test]
    fn records_reach_past_the_first_chunk() {
        let mut p = W32Processes::new();
        let far = RECORDS_PER_CHUNK as Owner * 3 + 1;
        assert_eq!(
            p.may_take_user_object(far, 10, test_pages::current()),
            Ok(())
        );
        p.took_user_object(far);
        assert_eq!(p.user_objects(far), 1);
        assert_eq!(p.user_objects(1), 0);
    }

    /// The refusal's status carries ERROR_NO_MORE_USER_HANDLES to user32.
    #[test]
    fn the_refusal_carries_1158() {
        assert_eq!(rtl::status::dos_error(NO_MORE_USER_HANDLES.0), 1158);
    }
}
