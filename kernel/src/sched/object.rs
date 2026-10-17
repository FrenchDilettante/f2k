//! The handle table: the per-process indirection between the Win32 handle values programs pass
//! around and the kernel's objects.
//!
//! One table per process, a fixed slot array: each slot holds a live object (an event, a semaphore,
//! a mutex, a thread, or an open file) or nothing. The handle value encodes its slot as the index shifted left two — the platform's
//! documented shape, a multiple of four with the low tag bits ignored on lookup — and slot zero is
//! never handed out, so the first handle is 4 and no valid handle is zero or the all-ones
//! pseudo-handle. Freed slots are reused most-recently-freed-first.
//!
//! The subset keeps only the table discipline: no reference counting in the table itself (a close
//! releases only the slot — a waiter parked on the object stays parked; the process's object pools
//! reclaim a record once no slot names it, [`HandleTable::references`]), no security, no quota, no
//! named objects. The table's owner is the
//! process record, so the process exit empties it by dropping the record. An open file's state is a
//! record of the process's own (`fs::file`), which the slot names by index: the close hands the
//! released slot back so the process can release that record with it.

use crate::sched::wait::Waitable;

/// The table's slot capacity. Exhaustion is a program-visible failure (the create returns no
/// handle), not a bug.
pub const HANDLE_SLOTS: usize = 1024;

/// A handle's slot index: the value shifted right two (the low two tag bits are ignored on decode).
pub const HANDLE_SHIFT: u32 = 2;

/// One table slot: what it holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    /// An event object, by its waitable header.
    Event(*mut Waitable),
    /// A thread object (waitable at its termination), by its waitable header.
    Thread(*mut Waitable),
    /// A semaphore, by its waitable header.
    Semaphore(*mut Waitable),
    /// A mutex, by its waitable header.
    Mutex(*mut Waitable),
    /// A waitable timer, by its waitable header.
    Timer(*mut Waitable),
    /// An open file: the index of the process's open-file record.
    File(usize),
    /// A directory search (FindFirstFileA): the index of the process's search record.
    Find(usize),
    /// A file mapping (CreateFileMappingA): the index of the process's mapping record.
    Section(usize),
}

impl Slot {
    /// The waitable header of a waitable object; none for an open file (the subset does not wait on
    /// files).
    pub fn waitable(self) -> Option<*mut Waitable> {
        match self {
            Slot::Event(waitable)
            | Slot::Thread(waitable)
            | Slot::Semaphore(waitable)
            | Slot::Mutex(waitable)
            | Slot::Timer(waitable) => Some(waitable),
            Slot::File(_) | Slot::Find(_) | Slot::Section(_) => None,
        }
    }
}

/// A process's handle table.
pub struct HandleTable {
    /// The slots, by index. Slot 0 exists but is never allocated.
    slots: [Option<Slot>; HANDLE_SLOTS],
    /// The freed-slot stack, most recently freed on top.
    freed: [u32; HANDLE_SLOTS],
    /// How many freed indices are on the stack.
    freed_top: usize,
    /// The next never-used index.
    next_fresh: u32,
}

impl HandleTable {
    /// An empty table; no `init` needed (no self-referential state).
    pub const fn empty() -> Self {
        HandleTable {
            slots: [None; HANDLE_SLOTS],
            freed: [0; HANDLE_SLOTS],
            freed_top: 0,
            next_fresh: 1,
        }
    }

    /// Write an empty table at `table`, element by element: by value the table would pass through
    /// the caller's stack, and it is larger than a kernel stack has room for.
    ///
    /// # Safety
    ///
    /// `table` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    pub unsafe fn write_empty(table: *mut HandleTable) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let slots = addr_of_mut!((*table).slots) as *mut Option<Slot>;
            let freed = addr_of_mut!((*table).freed) as *mut u32;
            for index in 0..HANDLE_SLOTS {
                slots.add(index).write(None);
                freed.add(index).write(0);
            }
            addr_of_mut!((*table).freed_top).write(0);
            addr_of_mut!((*table).next_fresh).write(1);
        }
    }

    /// Insert `slot`, returning its handle. Null when every slot is taken.
    pub fn insert(&mut self, slot: Slot) -> u32 {
        let index = if self.freed_top > 0 {
            self.freed_top -= 1;
            self.freed[self.freed_top]
        } else if (self.next_fresh as usize) < HANDLE_SLOTS {
            let index = self.next_fresh;
            self.next_fresh += 1;
            index
        } else {
            return 0;
        };
        self.slots[index as usize] = Some(slot);
        index << HANDLE_SHIFT
    }

    /// Whether every slot is taken: the next insert would return no handle.
    pub fn is_full(&self) -> bool {
        self.freed_top == 0 && self.next_fresh as usize >= HANDLE_SLOTS
    }

    /// The slot a handle names, or none. The low tag bits are ignored; a closed or out-of-range
    /// handle is a miss.
    pub fn lookup(&self, handle: u32) -> Option<Slot> {
        let index = (handle >> HANDLE_SHIFT) as usize;
        if index == 0 || index >= HANDLE_SLOTS {
            return None;
        }
        self.slots[index]
    }

    /// Release the slot a handle names, returning what it held. None when the handle names nothing
    /// (a double close, a foreign value). The object itself lives on: only the table's claim ends.
    pub fn close(&mut self, handle: u32) -> Option<Slot> {
        let slot = self.lookup(handle)?;
        let index = (handle >> HANDLE_SHIFT) as usize;
        self.slots[index] = None;
        self.freed[self.freed_top] = index as u32;
        self.freed_top += 1;
        Some(slot)
    }

    /// Empty the table: the process-exit step, releasing every slot's claim at once (the objects
    /// themselves die with the process's teardown).
    pub fn clear(&mut self) {
        // SAFETY: a live table, written in place (it is larger than a kernel stack has room for).
        unsafe { HandleTable::write_empty(self) };
    }

    /// How many slots name the waitable object `waitable` (an object a slot names is still
    /// referenced: its record is not reclaimed).
    pub fn references(&self, waitable: *mut Waitable) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.and_then(Slot::waitable) == Some(waitable))
            .count()
    }

    /// How many slots hold exactly `slot` (the handles naming one record).
    pub fn count(&self, slot: Slot) -> usize {
        self.slots.iter().filter(|held| **held == Some(slot)).count()
    }

    /// How many slots are taken.
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::wait::Waitable;

    fn event_slot() -> Slot {
        // SAFETY: the test leaks the header at its final address.
        let waitable = Box::leak(Box::new(Waitable::new(
            crate::sched::wait::WaitKind::NotificationEvent,
            0,
        )));
        Slot::Event(waitable as *mut Waitable)
    }

    // --- Group A: encoding, allocation, reuse -------------------------------

    /// The encoding: handles are multiples of four, slot zero is never handed out (the first handle
    /// is 4), and no valid handle collides with zero or the all-ones pseudo-handle.
    #[test]
    fn handles_are_index_shifted_left_two() {
        let mut table = HandleTable::empty();
        let h1 = table.insert(event_slot());
        let h2 = table.insert(event_slot());
        assert_eq!(h1, 4);
        assert_eq!(h2, 8);
        assert_eq!(h1 & 0x3, 0);
        assert_ne!(h1, 0);
        assert_ne!(h1, u32::MAX);
        assert_eq!(table.live(), 2);
    }

    /// A table written in place over a used one is the empty table.
    #[test]
    fn a_table_written_in_place_is_empty() {
        let mut table = Box::new(HandleTable::empty());
        table.insert(event_slot());
        table.close(4);
        table.insert(event_slot());
        // SAFETY: the box is a valid, aligned table; it holds nothing that needs dropping.
        unsafe { HandleTable::write_empty(&mut *table) };
        assert_eq!(table.live(), 0);
        assert_eq!(table.insert(event_slot()), 4);
        assert_eq!(table.insert(event_slot()), 8);
    }

    /// A freed slot is reused before a fresh one, the most recently freed first; the closed value
    /// decodes to nothing in between.
    #[test]
    fn freed_slots_reuse_most_recently_freed_first() {
        let mut table = HandleTable::empty();
        let h1 = table.insert(event_slot());
        let h2 = table.insert(event_slot());
        let h3 = table.insert(event_slot());
        assert_eq!((h1, h2, h3), (4, 8, 12));

        assert!(table.close(h2).is_some());
        assert!(table.close(h1).is_some());
        assert_eq!(table.lookup(h1), None, "the closed value is a miss");
        assert_eq!(table.lookup(h2), None);

        // Most recently freed (h1's slot) comes back first.
        assert_eq!(table.insert(event_slot()), h1);
        assert_eq!(table.insert(event_slot()), h2);
        // Then fresh indices continue.
        assert_eq!(table.insert(event_slot()), h3 + 4);
        assert_eq!(table.live(), 4);
    }

    /// Lookup: the low two tag bits are ignored, a miss is a miss — zero, out-of-range, and the
    /// all-ones pseudo-handle all name nothing.
    #[test]
    fn lookup_ignores_tag_bits_and_misses_cleanly() {
        let mut table = HandleTable::empty();
        let handle = table.insert(event_slot());
        assert!(table.lookup(handle).is_some());
        assert!(
            table.lookup(handle | 0x3).is_some(),
            "the tag bits are ignored"
        );
        assert_eq!(table.lookup(0), None);
        assert_eq!(table.lookup(u32::MAX), None);
        assert_eq!(table.lookup((HANDLE_SLOTS as u32) << HANDLE_SHIFT), None);
    }

    /// Exhaustion: a full table's create returns no handle, and the table stays consistent (closes
    /// keep working).
    #[test]
    fn a_full_table_refuses_inserts() {
        let mut table = HandleTable::empty();
        assert!(!table.is_full());
        for _ in 1..HANDLE_SLOTS {
            assert_ne!(table.insert(event_slot()), 0);
        }
        assert_eq!(table.live(), HANDLE_SLOTS - 1, "slot 0 never allocated");
        assert!(table.is_full());
        assert_eq!(table.insert(event_slot()), 0, "exhausted: no handle");

        // A close frees a slot again.
        assert!(table.close(4).is_some());
        assert!(!table.is_full());
        assert_eq!(table.insert(event_slot()), 4);
        assert!(table.is_full());
    }

    /// The process-exit step: the table empties in one step.
    #[test]
    fn clear_empties_every_slot() {
        let mut table = HandleTable::empty();
        table.insert(event_slot());
        table.insert(event_slot());
        assert_eq!(table.live(), 2);
        table.clear();
        assert_eq!(table.live(), 0);
        assert_eq!(table.lookup(4), None);
        // And the table works again after.
        assert_eq!(table.insert(event_slot()), 4);
    }

    /// A double close is refused: the slot was already released.
    #[test]
    fn a_double_close_is_refused() {
        let mut table = HandleTable::empty();
        let handle = table.insert(event_slot());
        assert!(table.close(handle).is_some());
        assert_eq!(table.close(handle), None, "the second close finds nothing");
    }

    // --- Group B: file slots ------------------------------------------------

    /// File slots share the table with the waitable objects: inserted, looked up by their record
    /// index, and handed back by the close (the process releases the record with it). A file has no
    /// waitable header.
    #[test]
    fn file_slots_insert_look_up_and_close() {
        let mut table = HandleTable::empty();
        let event = table.insert(event_slot());
        let file = table.insert(Slot::File(3));
        assert_eq!(file, 8);
        assert_eq!(table.lookup(file), Some(Slot::File(3)));
        assert_eq!(table.lookup(file | 0x3), Some(Slot::File(3)));
        assert_eq!(Slot::File(3).waitable(), None);
        assert!(table.lookup(event).unwrap().waitable().is_some());

        assert_eq!(table.close(file), Some(Slot::File(3)), "the released slot");
        assert_eq!(table.lookup(file), None);
        assert_eq!(table.close(file), None);
        assert_eq!(table.insert(Slot::File(0)), file, "the slot is reused");
        assert_eq!(table.live(), 2);
    }

    /// The process-exit step releases file slots with everything else.
    #[test]
    fn clear_releases_file_slots() {
        let mut table = HandleTable::empty();
        table.insert(Slot::File(0));
        table.insert(Slot::File(1));
        table.clear();
        assert_eq!(table.live(), 0);
        assert_eq!(table.lookup(4), None);
    }
}
