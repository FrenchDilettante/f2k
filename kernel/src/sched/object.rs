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

    /// Change the entry a handle names in place with `change`; false when the handle names
    /// nothing (the low tag bits ignored, as on lookup).
    pub fn update(&mut self, handle: u32, change: impl FnOnce(E) -> E) -> bool {
        let Some(entry) = self.lookup(handle) else {
            return false;
        };
        self.slots[(handle >> HANDLE_SHIFT) as usize] = Some(change(entry));
        true
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

    /// Fill this table, a fresh one, with the entries of `parent` that `admit` takes, each in the
    /// slot it holds there — so it has the same handle value — as a child process's table inherits
    /// its creator's inheritable handles (the documented inheritance: same values, same access).
    /// `admit` sees every entry once, in slot order, and counts what it takes. The slots left free
    /// below the highest one taken go first to the table's next inserts, lowest first. Returns how
    /// many entries were taken.
    ///
    /// # Panics
    ///
    /// The table is not fresh: a slot was already handed out.
    pub fn inherit_from(
        &mut self,
        parent: &HandleTable<E>,
        mut admit: impl FnMut(&E) -> bool,
    ) -> usize {
        assert!(
            self.freed_top == 0 && self.next_fresh == 1,
            "a table inherits only while fresh"
        );
        let mut taken = 0;
        for index in 1..HANDLE_SLOTS {
            if let Some(entry) = parent.slots[index].filter(|entry| admit(entry)) {
                self.slots[index] = Some(entry);
                self.next_fresh = index as u32 + 1;
                taken += 1;
            }
        }
        // The gaps below the highest slot taken, highest pushed first: the lowest is on top.
        for index in (1..self.next_fresh as usize).rev() {
            if self.slots[index].is_none() {
                self.freed[self.freed_top] = index as u32;
                self.freed_top += 1;
            }
        }
        taken
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
    use crate::ob::{Entry, ObjectId, ObjectType};

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

    fn file_entry(index: u16, access: u32, inherit: bool) -> Entry {
        Entry::object(
            ObjectId {
                kind: ObjectType::File,
                index,
                generation: 0,
            },
            access,
            inherit,
        )
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

    /// A child's table inherits its creator's inheritable handles at their own values, with their
    /// access, and nothing else; its own handles then fill the gaps below them, lowest first,
    /// before fresh slots past them (the spawn fixture's probe: placeholders left out of the
    /// inheritance leave room below the inherited handle for the child's own).
    #[test]
    fn a_child_inherits_the_inheritable_handles_at_their_values() {
        let mut parent: Box<HandleTable> = Box::new(HandleTable::empty());
        let hole = parent.insert(event_entry());
        let kept = parent.insert(file_entry(1, 0x8000_0000, true));
        let left = parent.insert(file_entry(2, 0x4000_0000, false));
        let last = parent.insert(file_entry(3, 0x0012_0089, true));
        assert_eq!((hole, kept, left, last), (4, 8, 12, 16));
        let mut child: Box<HandleTable> = Box::new(HandleTable::empty());
        let mut seen = Vec::new();
        let taken = child.inherit_from(&parent, |entry| {
            seen.push(*entry);
            entry.inherit
        });
        assert_eq!(taken, 2);
        assert_eq!(seen.len(), 4, "every entry is offered once");
        assert_eq!(child.lookup(kept), parent.lookup(kept));
        assert_eq!(child.lookup(last), Some(file_entry(3, 0x0012_0089, true)));
        assert_eq!(child.lookup(hole), None);
        assert_eq!(child.lookup(left), None);
        assert_eq!(child.live(), 2);
        // The child's own: the gaps below, lowest first, then past the inherited ones.
        assert_eq!(child.insert(event_entry()), hole);
        assert_eq!(child.insert(event_entry()), left);
        assert_eq!(child.insert(event_entry()), last + 4);
    }

    /// Nothing inheritable: the child's table is a fresh one.
    #[test]
    fn a_child_with_nothing_to_inherit_starts_fresh() {
        let mut parent: Box<HandleTable> = Box::new(HandleTable::empty());
        parent.insert(event_entry());
        let mut child: Box<HandleTable> = Box::new(HandleTable::empty());
        assert_eq!(child.inherit_from(&parent, |entry| entry.inherit), 0);
        assert_eq!(child.insert(event_entry()), 4);
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
        assert!(released.contains(&file_entry(3, 0, false).target));
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

    /// An update changes the entry in place, at its value; a handle naming nothing is refused.
    #[test]
    fn an_entry_is_updated_in_place() {
        let mut table: HandleTable = HandleTable::empty();
        let handle = table.insert(file_entry(1, 0x8000_0000, false));
        assert!(table.update(handle | 3, |entry| Entry {
            inherit: true,
            ..entry
        }));
        assert_eq!(table.lookup(handle), Some(file_entry(1, 0x8000_0000, true)));
        assert!(!table.update(handle + 4, |entry| entry));
        table.close(handle);
        assert!(!table.update(handle, |entry| entry), "a closed handle");
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
        let target = file_entry(3, 0, false).target;
        assert_eq!(table.count(|entry| entry.target == target), 2);
        table.close(again);
        assert_eq!(table.count(|entry| entry.target == target), 1);
        assert_eq!(
            entry.object_id(),
            Some(ObjectId {
                kind: ObjectType::File,
                index: 3,
                generation: 0
            })
        );
    }
}
