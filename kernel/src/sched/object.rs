//! The handle table: the per-process indirection between the Win32 handle values programs pass
//! around and the kernel's objects.
//!
//! One table per process, a fixed slot array: each slot holds an entry — what the handle names
//! (an object, by its id; or one of the process's own records), the access it was granted, and
//! whether it is inherited — or nothing. The handle value encodes its slot as the index shifted
//! left two — the platform's documented shape, a multiple of four with the low tag bits ignored on
//! lookup — and slot zero is never handed out, so the first handle is 4 and no valid handle is
//! zero or the all-ones pseudo-handle. Freed slots are reused most-recently-freed-first.
//!
//! The table keeps only the slot discipline: the objects' counts are the object manager's (see
//! [`crate::ob`]), which the process keeps in step with every insert and close. The table's owner
//! is the process record; the process's exit closes every handle through the object manager.

/// The table's slot capacity. Exhaustion is a program-visible failure (the create returns no
/// handle), not a bug.
pub const HANDLE_SLOTS: usize = 1024;

/// A handle's slot index: the value shifted right two (the low two tag bits are ignored on decode).
pub const HANDLE_SHIFT: u32 = 2;

/// A process's handle table, of entries `E` (the kernel's are [`crate::ob::Entry`]).
pub struct HandleTable<E: Copy = crate::ob::Entry> {
    /// The slots, by index. Slot 0 exists but is never allocated.
    slots: [Option<E>; HANDLE_SLOTS],
    /// The freed-slot stack, most recently freed on top.
    freed: [u32; HANDLE_SLOTS],
    /// How many freed indices are on the stack.
    freed_top: usize,
    /// The next never-used index.
    next_fresh: u32,
}

impl<E: Copy> HandleTable<E> {
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
    pub unsafe fn write_empty(table: *mut HandleTable<E>) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; every field is written.
        unsafe {
            let slots = addr_of_mut!((*table).slots) as *mut Option<E>;
            let freed = addr_of_mut!((*table).freed) as *mut u32;
            for index in 0..HANDLE_SLOTS {
                slots.add(index).write(None);
                freed.add(index).write(0);
            }
            addr_of_mut!((*table).freed_top).write(0);
            addr_of_mut!((*table).next_fresh).write(1);
        }
    }

    /// Insert `entry`, returning its handle. Null when every slot is taken.
    pub fn insert(&mut self, entry: E) -> u32 {
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
        self.slots[index as usize] = Some(entry);
        index << HANDLE_SHIFT
    }

    /// Whether every slot is taken: the next insert would return no handle.
    pub fn is_full(&self) -> bool {
        self.freed_top == 0 && self.next_fresh as usize >= HANDLE_SLOTS
    }

    /// The entry a handle names, or none. The low tag bits are ignored; a closed or out-of-range
    /// handle is a miss.
    pub fn lookup(&self, handle: u32) -> Option<E> {
        let index = (handle >> HANDLE_SHIFT) as usize;
        if index == 0 || index >= HANDLE_SLOTS {
            return None;
        }
        self.slots[index]
    }

    /// Release the slot a handle names, returning what it held. None when the handle names nothing
    /// (a double close, a foreign value). What the entry named is the caller's to release.
    pub fn close(&mut self, handle: u32) -> Option<E> {
        let entry = self.lookup(handle)?;
        let index = (handle >> HANDLE_SHIFT) as usize;
        self.slots[index] = None;
        self.freed[self.freed_top] = index as u32;
        self.freed_top += 1;
        Some(entry)
    }

    /// Empty the table, handing every entry it held to `release` (the process-exit step: every
    /// handle closes at once). The table starts over afterwards.
    pub fn drain(&mut self, mut release: impl FnMut(E)) {
        for index in 1..HANDLE_SLOTS {
            if let Some(entry) = self.slots[index].take() {
                release(entry);
            }
        }
        // SAFETY: a live table, written in place (it is larger than a kernel stack has room for).
        unsafe { HandleTable::write_empty(self) };
    }

    /// How many slots hold an entry `which` accepts.
    pub fn count(&self, which: impl Fn(&E) -> bool) -> usize {
        self.slots
            .iter()
            .flatten()
            .filter(|entry| which(entry))
            .count()
    }

    /// How many slots are taken.
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::{Entry, ObjectId, ObjectType, Target};

    fn event_entry() -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::Event,
                index: 0,
                generation: 0,
            },
            0,
            false,
        )
    }

    fn file_entry(index: usize, access: u32, inherit: bool) -> Entry {
        Entry {
            target: Target::File(index),
            access,
            inherit,
        }
    }

    // --- Group A: encoding, allocation, reuse -------------------------------

    /// The encoding: handles are multiples of four, slot zero is never handed out (the first handle
    /// is 4), and no valid handle collides with zero or the all-ones pseudo-handle.
    #[test]
    fn handles_are_index_shifted_left_two() {
        let mut table: HandleTable = HandleTable::empty();
        let h1 = table.insert(event_entry());
        let h2 = table.insert(event_entry());
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
        let mut table: Box<HandleTable> = Box::new(HandleTable::empty());
        table.insert(event_entry());
        table.close(4);
        table.insert(event_entry());
        // SAFETY: the box is a valid, aligned table; it holds nothing that needs dropping.
        unsafe { HandleTable::write_empty(&mut *table) };
        assert_eq!(table.live(), 0);
        assert_eq!(table.insert(event_entry()), 4);
        assert_eq!(table.insert(event_entry()), 8);
    }

    /// A freed slot is reused before a fresh one, the most recently freed first; the closed value
    /// decodes to nothing in between.
    #[test]
    fn freed_slots_reuse_most_recently_freed_first() {
        let mut table: HandleTable = HandleTable::empty();
        let h1 = table.insert(event_entry());
        let h2 = table.insert(event_entry());
        let h3 = table.insert(event_entry());
        assert_eq!((h1, h2, h3), (4, 8, 12));

        assert!(table.close(h2).is_some());
        assert!(table.close(h1).is_some());
        assert_eq!(table.lookup(h1), None, "the closed value is a miss");
        assert_eq!(table.lookup(h2), None);

        // Most recently freed (h1's slot) comes back first.
        assert_eq!(table.insert(event_entry()), h1);
        assert_eq!(table.insert(event_entry()), h2);
        // Then fresh indices continue.
        assert_eq!(table.insert(event_entry()), h3 + 4);
        assert_eq!(table.live(), 4);
    }

    /// Lookup: the low two tag bits are ignored, a miss is a miss — zero, out-of-range, and the
    /// all-ones pseudo-handle all name nothing.
    #[test]
    fn lookup_ignores_tag_bits_and_misses_cleanly() {
        let mut table: HandleTable = HandleTable::empty();
        let handle = table.insert(event_entry());
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
        let mut table: Box<HandleTable> = Box::new(HandleTable::empty());
        assert!(!table.is_full());
        for _ in 1..HANDLE_SLOTS {
            assert_ne!(table.insert(event_entry()), 0);
        }
        assert_eq!(table.live(), HANDLE_SLOTS - 1, "slot 0 never allocated");
        assert!(table.is_full());
        assert_eq!(table.insert(event_entry()), 0, "exhausted: no handle");

        // A close frees a slot again.
        assert!(table.close(4).is_some());
        assert!(!table.is_full());
        assert_eq!(table.insert(event_entry()), 4);
        assert!(table.is_full());
    }

    /// The process-exit step: the table hands every entry back and empties in one step.
    #[test]
    fn drain_hands_back_every_entry() {
        let mut table: HandleTable = HandleTable::empty();
        table.insert(event_entry());
        table.insert(file_entry(3, 1, false));
        let mut released = Vec::new();
        table.drain(|entry| released.push(entry.target));
        assert_eq!(released.len(), 2);
        assert!(released.contains(&Target::File(3)));
        assert_eq!(table.live(), 0);
        assert_eq!(table.lookup(4), None);
        // And the table works again after.
        assert_eq!(table.insert(event_entry()), 4);
    }

    /// A double close is refused: the slot was already released.
    #[test]
    fn a_double_close_is_refused() {
        let mut table: HandleTable = HandleTable::empty();
        let handle = table.insert(event_entry());
        assert!(table.close(handle).is_some());
        assert_eq!(table.close(handle), None, "the second close finds nothing");
    }

    // --- Group B: entries ----------------------------------------------------

    /// An entry carries its access and inheritance with what it names, and the count finds the
    /// entries naming one record.
    #[test]
    fn entries_carry_access_and_inheritance() {
        let mut table: HandleTable = HandleTable::empty();
        let file = table.insert(file_entry(3, 0x8000_0000, true));
        let again = table.insert(file_entry(3, 0x4000_0000, false));
        table.insert(event_entry());
        let entry = table.lookup(file | 0x3).unwrap();
        assert_eq!((entry.access, entry.inherit), (0x8000_0000, true));
        let target = Target::File(3);
        assert_eq!(table.count(|entry| entry.target == target), 2);
        table.close(again);
        assert_eq!(table.count(|entry| entry.target == target), 1);
        assert_eq!(entry.object_id(), None, "a file record is no object");
    }

    /// File entries share the table with the objects: inserted, looked up by their record index,
    /// and handed back by the close (the process releases the record with it).
    #[test]
    fn file_entries_insert_look_up_and_close() {
        let mut table: HandleTable = HandleTable::empty();
        let event = table.insert(event_entry());
        let file = table.insert(file_entry(3, 0, false));
        assert_eq!(file, 8);
        assert_eq!(
            table.lookup(file).map(|entry| entry.target),
            Some(Target::File(3))
        );
        assert!(table.lookup(event).unwrap().object_id().is_some());

        assert_eq!(
            table.close(file).map(|entry| entry.target),
            Some(Target::File(3)),
            "the released slot"
        );
        assert_eq!(table.lookup(file), None);
        assert_eq!(table.close(file), None);
        assert_eq!(
            table.insert(file_entry(0, 0, false)),
            file,
            "the slot is reused"
        );
        assert_eq!(table.live(), 2);
    }
}
