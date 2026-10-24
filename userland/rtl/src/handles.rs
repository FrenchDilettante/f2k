//! Handle tables: RtlInitializeHandleTable, RtlAllocateHandle, RtlFreeHandle and RtlIsValidHandle's
//! work, as Windows 2000's ntdll keeps the tables its callers own — kernel32's Local and Global
//! memory takes its movable blocks' handle entries from one.
//!
//! A table (RTL_HANDLE_TABLE, 0x20 bytes on the target, the caller's memory) holds the maximum
//! number of entries, an entry's size, two reserved dwords, then the free list's head
//! (FreeHandles), the first entry (CommittedHandles), the end of the committed entries
//! (UnCommittedHandles) and the end of the reservation (MaxReservedHandles). The entries are the
//! table's own virtual memory: reserved whole (`maximum * size` bytes) at the first allocation and
//! committed a page at a time as the free list runs dry. An entry's first dword is its flags while
//! it is in use — bit 0, RTL_HANDLE_ALLOCATED, the owner sets it — and the next free entry's
//! address (zero at the list's end) while it is free; the rest of an entry is the owner's.
//!
//! Initializing a table only records its shape, so it cannot fail; the reservation is made when the
//! first entry is asked for.

use core::mem::size_of;

use crate::heap::{Vm, PAGE};

/// An entry's flag while it is in use: RTL_HANDLE_ALLOCATED.
pub const ALLOCATED: usize = 0x0001;

/// RTL_HANDLE_TABLE.
#[repr(C)]
#[derive(Default)]
pub struct HandleTable {
    pub maximum_number_of_handles: u32,
    pub size_of_handle_table_entry: u32,
    pub reserved: [u32; 2],
    pub free_handles: usize,
    pub committed_handles: usize,
    pub uncommitted_handles: usize,
    pub max_reserved_handles: usize,
}

#[cfg(target_arch = "x86")]
const _: () = assert!(size_of::<HandleTable>() == 0x20);

/// The word at `at`: an entry's first.
fn read(at: usize) -> usize {
    // SAFETY: the callers read only committed entries of the table.
    unsafe { (at as *const usize).read() }
}

fn write(at: usize, value: usize) {
    // SAFETY: the callers write only committed entries of the table.
    unsafe { (at as *mut usize).write(value) }
}

impl HandleTable {
    /// RtlInitializeHandleTable: an empty table of up to `maximum` entries of `size` bytes each.
    pub fn initialize(&mut self, maximum: u32, size: u32) {
        *self = HandleTable {
            maximum_number_of_handles: maximum,
            size_of_handle_table_entry: size,
            ..HandleTable::default()
        };
    }

    fn entry_size(&self) -> usize {
        self.size_of_handle_table_entry as usize
    }

    /// RtlAllocateHandle: a free entry, its first dword cleared (the owner sets
    /// RTL_HANDLE_ALLOCATED and fills the rest), and its index; none when the table is full,
    /// its memory cannot be had, or its entries cannot hold the free list's link.
    pub fn allocate(&mut self, vm: &impl Vm) -> Option<(usize, u32)> {
        if self.free_handles == 0 {
            self.grow(vm)?;
        }
        let entry = self.free_handles;
        self.free_handles = read(entry);
        write(entry, 0);
        let index = (entry - self.committed_handles) / self.entry_size();
        Some((entry, index as u32))
    }

    /// The free list refilled: the reservation made at the first need, then the next page of it
    /// committed, its whole entries linked in order.
    fn grow(&mut self, vm: &impl Vm) -> Option<()> {
        let size = self.entry_size();
        if size < size_of::<usize>() || !size.is_multiple_of(size_of::<usize>()) {
            return None;
        }
        if self.committed_handles == 0 {
            let bytes = (self.maximum_number_of_handles as usize)
                .checked_mul(size)
                .filter(|&bytes| bytes != 0)?
                .checked_next_multiple_of(PAGE)?;
            let base = vm.reserve(bytes)?;
            self.committed_handles = base;
            self.uncommitted_handles = base;
            self.max_reserved_handles = base + self.maximum_number_of_handles as usize * size;
        }
        let start = self.uncommitted_handles;
        if start + size > self.max_reserved_handles {
            return None;
        }
        // The page holding the next entry's end, and the entries it completes.
        let page = (start + size - 1) / PAGE * PAGE;
        let end = (page + PAGE).min(self.max_reserved_handles);
        let first_page = start / PAGE * PAGE;
        if !vm.commit(first_page, (end - first_page).next_multiple_of(PAGE)) {
            return None;
        }
        let count = (end - start) / size;
        for index in 0..count {
            let entry = start + index * size;
            let next = if index + 1 < count { entry + size } else { 0 };
            write(entry, next);
        }
        self.free_handles = start;
        self.uncommitted_handles = start + count * size;
        Some(())
    }

    /// RtlIsValidHandle: whether `entry` is one of the table's committed entries, in use.
    pub fn is_valid(&self, entry: usize) -> bool {
        let size = self.entry_size();
        entry >= self.committed_handles
            && entry < self.uncommitted_handles
            && size != 0
            && (entry - self.committed_handles).is_multiple_of(size)
            && read(entry) & ALLOCATED != 0
    }

    /// RtlFreeHandle: the entry in use back on the free list, its bytes cleared; FALSE for what is
    /// not one ([`HandleTable::is_valid`]).
    pub fn free(&mut self, entry: usize) -> bool {
        if !self.is_valid(entry) {
            return false;
        }
        // SAFETY: a committed entry of the table, its size's bytes.
        unsafe { core::ptr::write_bytes(entry as *mut u8, 0, self.entry_size()) };
        write(entry, self.free_handles);
        self.free_handles = entry;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::tests::Host;

    const WORD: usize = size_of::<usize>();

    fn table(maximum: u32) -> HandleTable {
        let mut table = HandleTable::default();
        table.initialize(maximum, 2 * WORD as u32);
        table
    }

    /// Initializing records the shape and reserves nothing; the first entry reserves the table's
    /// whole span and commits its first page, whose entries are handed out in order.
    #[test]
    fn entries_come_from_the_reservation_in_order() {
        let host = Host::new();
        let mut table = table(1000);
        assert_eq!(table.committed_handles, 0);
        assert!(host.live.borrow().is_empty(), "nothing reserved yet");
        let (first, index) = table.allocate(&host).unwrap();
        assert_eq!(index, 0);
        assert_eq!(first, table.committed_handles);
        assert_eq!(
            table.max_reserved_handles - table.committed_handles,
            1000 * 2 * WORD
        );
        assert_eq!(
            table.uncommitted_handles - first,
            PAGE,
            "one page committed"
        );
        assert_eq!(read(first), 0, "the link cleared");
        let (second, index) = table.allocate(&host).unwrap();
        assert_eq!((second - first, index), (2 * WORD, 1));
    }

    /// An entry is valid while its owner marks it allocated; freeing one puts it first on the free
    /// list, cleared; a stray address, a misaligned one, or a freed entry is refused.
    #[test]
    fn validity_follows_the_allocated_flag() {
        let host = Host::new();
        let mut table = table(64);
        let (entry, _) = table.allocate(&host).unwrap();
        assert!(!table.is_valid(entry), "the owner has not marked it");
        write(entry, ALLOCATED | 0x0003_0000);
        write(entry + WORD, 0x1234);
        assert!(table.is_valid(entry));
        assert!(!table.is_valid(entry + WORD), "inside an entry");
        assert!(!table.is_valid(0x10));
        assert!(table.free(entry));
        assert!(!table.is_valid(entry));
        assert!(!table.free(entry), "freed twice");
        assert_eq!(read(entry + WORD), 0, "cleared");
        assert_eq!(table.allocate(&host).unwrap().0, entry, "reused first");
    }

    /// A page's entries spent, the next page is committed; the table's maximum spent, none is
    /// handed out; a commit refused hands none out either.
    #[test]
    fn the_table_grows_a_page_at_a_time_to_its_maximum() {
        let host = Host::new();
        let per_page = PAGE / (2 * WORD);
        let mut full = table(per_page as u32 + 3);
        for expected in 0..per_page as u32 + 3 {
            assert_eq!(full.allocate(&host).unwrap().1, expected);
        }
        assert_eq!(full.allocate(&host), None, "full");
        let mut table = table(8);
        *host.commit_budget.borrow_mut() = 0;
        assert_eq!(table.allocate(&host), None, "no memory");
    }

    /// Entries that cannot hold the free list's link make no table.
    #[test]
    fn entries_too_small_are_refused() {
        let host = Host::new();
        let mut table = HandleTable::default();
        table.initialize(16, 2);
        assert_eq!(table.allocate(&host), None);
    }
}
