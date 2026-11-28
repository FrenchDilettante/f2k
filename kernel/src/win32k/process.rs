//! The window manager's per-process records: what win32k keeps for each process that holds its
//! objects, as Windows 2000's win32k keeps a W32PROCESS (its PROCESSINFO) beside each EPROCESS.
//! F2K's record holds the counts of the process's USER objects and GDI objects, which the
//! per-process quotas bound ([`super::quota`]), and the heads of its two class lists, private and
//! public (Windows 2000's PROCESSINFO.pclsPrivateList and pclsPublicList).
//!
//! The records are a side table of the slot pool ([`crate::slots::SideTable`]) keyed by the
//! process object's index (a class [`Owner`]), made a page at a time as processes come: a record
//! is ensured at its process's first counted object or first class and kept, each count reset at
//! the process's end, its class lists emptied by it. The window manager's own record is at the
//! System process's index ([`crate::ob::SYSTEM_PROCESS_INDEX`], the class owner
//! [`super::class::SYSTEM_OWNER`]), which no program's process takes. The table takes no lock of
//! its own (a side table's records are made and found without one), and its fields are atomic:
//! the class lists change under the window manager's lock alone; each count under its own table's
//! lock, the USER count
//! under the window manager's by the user handle table ([`super::handle::UserHandles`], as
//! Windows 2000's HMAllocObject and HMFreeObject count it inside the USER lock), the GDI count
//! under the GDI handle table's ([`super::gdi`], as Windows 2000's GDI moves its W32PROCESS
//! count with interlocked operations, outside the USER lock). A check and its raise under the
//! same lock are exact; a reader (GetGuiResources) takes neither lock.
//!
//! The service (F2K's argument list, see [`crate::win32k`]; Windows 2000's number):
//!
//! - NtUserGetGuiResources (0x118A): GetGuiResources's GR_GDIOBJECTS, the GDI objects a process
//!   holds, or GR_USEROBJECTS, its USER objects (0 for a process that holds none, or never made
//!   one). The stock objects are no process's, and count for none.

use core::sync::atomic::{AtomicU32, Ordering};

use rtl::winerror::ERROR_NO_MORE_USER_HANDLES;

use super::class::{ClassId, Owner};
use crate::slots::{Exhausted, Pages, Record, SideTable, PAGE};
use crate::status::*;

/// GetGuiResources's flag for the GDI objects a process holds.
pub const GR_GDIOBJECTS: u32 = 0;

/// GetGuiResources's flag for the USER objects a process holds.
pub const GR_USEROBJECTS: u32 = 1;

/// The status a create refused by the quota or the handle table's ceiling answers:
/// ERROR_NO_MORE_USER_HANDLES (1158) in a FACILITY_NTWIN32 status, which user32 hands to
/// GetLastError as is (no NTSTATUS has 1158 for its RtlNtStatusToDosError mapping, and Windows
/// 2000's win32k sets the last error itself).
pub const NO_MORE_USER_HANDLES: NtStatus = NtStatus::from_win32(ERROR_NO_MORE_USER_HANDLES);

/// One process's record.
#[derive(Debug, Default)]
pub struct W32Process {
    /// The USER objects the process holds: its windows, menus, accelerator tables, cursors and
    /// icons, each counted from its handle's insert to its close (under the window manager's
    /// lock).
    pub user_objects: AtomicU32,
    /// The GDI objects the process holds: its DCs, brushes, bitmaps, fonts and regions, each
    /// counted from its GDI handle's insert to its delete or the process's end (under the GDI
    /// table's lock).
    pub gdi_objects: AtomicU32,
    /// The heads of the process's private and public class lists ([`ClassList`]), each a class
    /// id's word (zero: an empty list), changed under the window manager's lock.
    classes: [AtomicU32; 2],
}

/// Which of a process's two class lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassList {
    /// Its private classes: its own modules' alone.
    Private = 0,
    /// Its public classes (CS_GLOBALCLASS, and the server-side registrations made for it).
    Public = 1,
}

/// A class list's head as its record's word: the id's index and uniqueness, zero for none (a
/// class's uniqueness is never zero).
fn class_word(head: Option<ClassId>) -> u32 {
    head.map_or(0, |id| {
        debug_assert_ne!(id.uniq, 0, "a class id's uniqueness starts at 1");
        u32::from(id.index) | u32::from(id.uniq) << 16
    })
}

/// The class list's head a record's word holds.
fn class_of(word: u32) -> Option<ClassId> {
    (word != 0).then(|| ClassId::new(word as u16, (word >> 16) as u16))
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

/// Which of a record's counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Objects {
    /// The USER objects' ([`W32Process::user_objects`]).
    User,
    /// The GDI objects' ([`W32Process::gdi_objects`]).
    Gdi,
}

impl Objects {
    fn of(self, record: &W32Process) -> &AtomicU32 {
        match self {
            Objects::User => &record.user_objects,
            Objects::Gdi => &record.gdi_objects,
        }
    }
}

/// Why a process may not take one more object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The process holds its quota's worth.
    Quota,
    /// No page was left for the process's record (ERROR_NOT_ENOUGH_MEMORY).
    NoMemory,
}

/// The per-process records, by process index.
pub struct W32Processes {
    table: SideTable<W32Process, RECORDS_PER_CHUNK>,
    /// One past the highest index ensured: the records a walk visits lie below it.
    end: AtomicU32,
}

impl W32Processes {
    /// No record made, no page held.
    pub const fn new() -> Self {
        W32Processes {
            table: SideTable::new(),
            end: AtomicU32::new(0),
        }
    }

    /// The record of the process `process`, made if it had none: NoMemory when no page is left.
    pub fn make(&self, process: Owner, pages: &impl Pages) -> Result<(), Refusal> {
        let index = u32::from(process);
        self.table.ensure(index, pages).map_err(|why| match why {
            Exhausted::NoPages | Exhausted::Limit => Refusal::NoMemory,
        })?;
        self.end.fetch_max(index + 1, Ordering::Relaxed);
        Ok(())
    }

    /// The head of the process `process`'s class list `list`: none for an empty list, or a
    /// process with no record.
    pub fn classes(&self, process: Owner, list: ClassList) -> Option<ClassId> {
        let record = self.table.get(u32::from(process))?;
        class_of(record.classes[list as usize].load(Ordering::Relaxed))
    }

    /// Set the head of the process `process`'s class list `list`, under the window manager's
    /// lock.
    ///
    /// # Panics
    ///
    /// The process has no record ([`W32Processes::make`], before its first class).
    pub fn set_classes(&self, process: Owner, list: ClassList, head: Option<ClassId>) {
        let record = self
            .table
            .get(u32::from(process))
            .expect("a class owner's record made at its registration");
        record.classes[list as usize].store(class_word(head), Ordering::Relaxed);
    }

    /// Every process that has a record, by index.
    pub fn owners(&self) -> impl Iterator<Item = Owner> + '_ {
        (0..self.end.load(Ordering::Relaxed))
            .filter(|&index| self.table.get(index).is_some())
            .map(|index| index as Owner)
    }

    /// How many objects of `objects`' kind the process `process` holds: 0 for one with no
    /// record.
    pub fn count(&self, objects: Objects, process: Owner) -> u32 {
        self.table
            .get(u32::from(process))
            .map_or(0, |record| objects.of(record).load(Ordering::Relaxed))
    }

    /// The USER objects the process `process` holds.
    pub fn user_objects(&self, process: Owner) -> u32 {
        self.count(Objects::User, process)
    }

    /// The GDI objects the process `process` holds.
    pub fn gdi_objects(&self, process: Owner) -> u32 {
        self.count(Objects::Gdi, process)
    }

    /// Whether the process `process` may take one more object of `objects`' kind under `quota`,
    /// its record made if it had none: the check Windows 2000's HMAllocObject (and GDI's handle
    /// allocation) makes before it takes a handle. The caller holds the lock its kind's count is
    /// changed under, until its [`W32Processes::took`].
    pub fn may_take(
        &self,
        objects: Objects,
        process: Owner,
        quota: u32,
        pages: &impl Pages,
    ) -> Result<(), Refusal> {
        self.make(process, pages)?;
        if self.count(objects, process) >= quota {
            return Err(Refusal::Quota);
        }
        Ok(())
    }

    /// The process `process` took an object of `objects`' kind (after
    /// [`W32Processes::may_take`]).
    pub fn took(&self, objects: Objects, process: Owner) {
        if let Some(record) = self.table.get(u32::from(process)) {
            objects.of(record).fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The process `process` let an object of `objects`' kind go: its handle closed.
    pub fn gave(&self, objects: Objects, process: Owner) {
        if let Some(record) = self.table.get(u32::from(process)) {
            // Under the lock its kind's count is changed under: no other change meanwhile.
            let count = objects.of(record);
            let before = count.load(Ordering::Relaxed);
            debug_assert!(before > 0, "an object counted at its insert");
            count.store(before.saturating_sub(1), Ordering::Relaxed);
        }
    }

    /// The process `process` has ended, its objects of `objects`' kind gone: that count starts
    /// afresh for the next process at its index.
    pub fn end(&self, objects: Objects, process: Owner) {
        if let Some(record) = self.table.get(u32::from(process)) {
            objects.of(record).store(0, Ordering::Relaxed);
        }
    }

    /// GetGuiResources's answer for the process `process`: the count `flags` names
    /// (GR_GDIOBJECTS, GR_USEROBJECTS), STATUS_INVALID_PARAMETER for another flag.
    pub fn gui_resources(&self, process: Owner, flags: u32) -> Result<u32, NtStatus> {
        match flags {
            GR_GDIOBJECTS => Ok(self.gdi_objects(process)),
            GR_USEROBJECTS => Ok(self.user_objects(process)),
            _ => Err(STATUS_INVALID_PARAMETER),
        }
    }
}

impl Default for W32Processes {
    fn default() -> Self {
        Self::new()
    }
}

/// The kernel's records: every process's, shared by the user handle table and the GDI table.
#[cfg(target_arch = "x86")]
pub static PROCESSES: W32Processes = W32Processes::new();

/// The kernel's records ([`PROCESSES`]).
#[cfg(target_arch = "x86")]
pub fn processes() -> &'static W32Processes {
    &PROCESSES
}

/// A host test's records: a set of its own for each table that asks, so the tests running at
/// once count apart (leaked: a test's few pages).
#[cfg(not(target_arch = "x86"))]
pub fn processes() -> &'static W32Processes {
    std::boxed::Box::leak(std::boxed::Box::new(W32Processes::new()))
}

// --- The service
// ----------------------------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{Handle, NtCall, NtResult, UserPtr};
    use crate::nt::object::{reference_process, PROCESS_QUERY_INFORMATION};

    /// NtUserGetGuiResources(Process, Flags, Count): the GDI objects (GR_GDIOBJECTS) or the USER
    /// objects (GR_USEROBJECTS) the process `process` names holds into `count`; the handle opened
    /// with PROCESS_QUERY_INFORMATION (STATUS_ACCESS_DENIED without it, STATUS_INVALID_HANDLE for
    /// a handle naming none) or the current-process pseudo-handle. STATUS_INVALID_PARAMETER for
    /// another flag. The counts are read without a lock: a count another thread moves meanwhile
    /// is read before or after.
    pub fn get_gui_resources(
        _call: &mut NtCall,
        process: Handle,
        flags: u32,
        count: UserPtr<u32>,
    ) -> NtResult {
        if flags != GR_GDIOBJECTS && flags != GR_USEROBJECTS {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let owner = reference_process(process.raw(), PROCESS_QUERY_INFORMATION)?
            .id()
            .index;
        let answer = processes().gui_resources(owner, flags)?;
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
    use Objects::{Gdi, User};

    use super::*;
    use crate::win32k::test_pages;

    /// A process with no record holds nothing; a record is made at the first check, counts up and
    /// down, refuses at the quota, and starts afresh at the process's end.
    #[test]
    fn a_record_counts_and_refuses_at_the_quota() {
        let p = W32Processes::new();
        assert_eq!(p.user_objects(3), 0);
        for _ in 0..5 {
            assert_eq!(p.may_take(User, 3, 5, test_pages::current()), Ok(()));
            p.took(User, 3);
        }
        assert_eq!(p.user_objects(3), 5);
        assert_eq!(
            p.may_take(User, 3, 5, test_pages::current()),
            Err(Refusal::Quota)
        );
        assert_eq!(p.user_objects(7), 0, "another process's count is its own");
        p.gave(User, 3);
        assert_eq!(p.may_take(User, 3, 5, test_pages::current()), Ok(()));
        p.end(User, 3);
        assert_eq!(p.user_objects(3), 0);
    }

    /// The USER and GDI counts are apart: each refuses at its own quota, and each process's end
    /// resets only its own.
    #[test]
    fn the_gdi_count_is_its_own() {
        let p = W32Processes::new();
        for _ in 0..3 {
            assert_eq!(p.may_take(Gdi, 2, 3, test_pages::current()), Ok(()));
            p.took(Gdi, 2);
        }
        p.took(User, 2);
        assert_eq!(
            p.may_take(Gdi, 2, 3, test_pages::current()),
            Err(Refusal::Quota)
        );
        assert_eq!(p.may_take(User, 2, 3, test_pages::current()), Ok(()));
        assert_eq!((p.gdi_objects(2), p.user_objects(2)), (3, 1));
        p.end(Gdi, 2);
        assert_eq!((p.gdi_objects(2), p.user_objects(2)), (0, 1));
    }

    /// GetGuiResources's answers: GR_GDIOBJECTS the GDI count, GR_USEROBJECTS the USER count, 0
    /// for a process that never made one, and another flag refused.
    #[test]
    fn gui_resources_answers_each_count() {
        let p = W32Processes::new();
        assert_eq!(p.gui_resources(4, GR_GDIOBJECTS), Ok(0));
        assert_eq!(p.gui_resources(4, GR_USEROBJECTS), Ok(0));
        p.may_take(Gdi, 4, 10, test_pages::current()).unwrap();
        p.took(Gdi, 4);
        p.took(Gdi, 4);
        p.took(User, 4);
        assert_eq!(p.gui_resources(4, GR_GDIOBJECTS), Ok(2));
        assert_eq!(p.gui_resources(4, GR_USEROBJECTS), Ok(1));
        assert_eq!(p.gui_resources(4, 2), Err(STATUS_INVALID_PARAMETER));
    }

    /// No page for a record: the check refuses for memory, not the quota.
    #[test]
    fn no_page_no_record() {
        let p = W32Processes::new();
        test_pages::budget(0);
        assert_eq!(
            p.may_take(User, 1, 10, test_pages::current()),
            Err(Refusal::NoMemory)
        );
        test_pages::unlimited();
        assert_eq!(p.may_take(User, 1, 10, test_pages::current()), Ok(()));
    }

    /// A record past the first chunk: processes at high indices have records of their own.
    #[test]
    fn records_reach_past_the_first_chunk() {
        let p = W32Processes::new();
        let far = RECORDS_PER_CHUNK as Owner * 3 + 1;
        assert_eq!(p.may_take(User, far, 10, test_pages::current()), Ok(()));
        p.took(User, far);
        assert_eq!(p.user_objects(far), 1);
        assert_eq!(p.user_objects(1), 0);
    }

    /// The class lists: empty for a process with no record, each list its own, a record found by
    /// the walk once made, and the walk past the first chunk.
    #[test]
    fn the_class_lists_are_kept_in_the_record() {
        let p = W32Processes::new();
        let far = RECORDS_PER_CHUNK as Owner * 2 + 5;
        assert_eq!(p.classes(3, ClassList::Private), None);
        assert_eq!(p.owners().count(), 0);
        p.make(3, test_pages::current()).unwrap();
        p.make(far, test_pages::current()).unwrap();
        let class = ClassId::new(7, 0xFFFE);
        p.set_classes(3, ClassList::Public, Some(class));
        assert_eq!(p.classes(3, ClassList::Public), Some(class));
        assert_eq!(p.classes(3, ClassList::Private), None);
        p.set_classes(far, ClassList::Private, Some(ClassId::new(0, 1)));
        assert_eq!(p.classes(far, ClassList::Private), Some(ClassId::new(0, 1)));
        let owners = p.owners().collect::<std::vec::Vec<_>>();
        assert!(owners.contains(&3) && owners.last() == Some(&far));
        assert!(
            !owners.contains(&(RECORDS_PER_CHUNK as Owner)),
            "a chunk never made"
        );
        p.set_classes(3, ClassList::Public, None);
        assert_eq!(p.classes(3, ClassList::Public), None);
    }

    /// The refusal's status carries ERROR_NO_MORE_USER_HANDLES to user32.
    #[test]
    fn the_refusal_carries_1158() {
        assert_eq!(rtl::status::dos_error(NO_MORE_USER_HANDLES.0), 1158);
    }
}
