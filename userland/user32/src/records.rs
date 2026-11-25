//! The records user32 keeps for windows beside the window manager's: an edit's state block
//! ([`crate::edit`]), a dialog's procedure and font ([`crate::dialog`]), a window's UI state and
//! its icons ([`crate::message`]). Each kind is a [`Table`] of the process's, as many records as it
//! has windows of that kind: a block of the process heap grown as records come and cut as they go,
//! freed when the last goes. Windows 2000 has no such limit (it hangs the same state off the
//! window: an edit's PED and a dialog's DLG through the window's extra bytes, the icons as its
//! internal properties, the UI state in its WND).
//!
//! F2K keeps them here rather than on the window because the window can be gone before the messages
//! of its destruction reach its procedure: win32k sends WM_DESTROY and WM_NCDESTROY to a window of
//! the destroying thread's own through a callback, the window still there, but queues them for a
//! window of another thread's and frees the window first. Its procedure's WM_NCDESTROY finds its
//! record here by the handle either way, and drops it.
//!
//! A record is `W` words (pointer-sized: a block's address among them), the window's handle first;
//! a table holds one record per window. The process's threads share a table under user32's lock
//! ([`crate::imports::UserLock`]); the host tests' stand-in window managers are each thread's own,
//! so there each thread has its own records. The work done under the lock calls nothing that could
//! run a window procedure, so a procedure running nested inside another (a send to the thread's own
//! window, a window destroyed from its own handler) never finds a table held.

use rtl::pod::Pod;

use crate::imports::HeapBlock;

/// The records a table's first block holds; each growth doubles it.
const FIRST: usize = 16;

/// A table's records: `W` words each, the window's handle first, in a block of the process heap
/// (none while there are none), in no particular order.
pub struct Records<const W: usize> {
    block: Option<HeapBlock>,
    count: usize,
}

// SAFETY: the block is the table's alone (no other value names it), so moving the records to
// another thread moves the block with them.
unsafe impl<const W: usize> Send for Records<W> {}

impl<const W: usize> Default for Records<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const W: usize> Records<W> {
    /// A record's bytes.
    const SIZE: usize = core::mem::size_of::<usize>() * W;

    /// No records, no block.
    pub const fn new() -> Self {
        Records {
            block: None,
            count: 0,
        }
    }

    /// How many records there are.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// How many records the block has room for (0: no block).
    pub fn capacity(&self) -> usize {
        self.block
            .as_ref()
            .map_or(0, |block| block.bytes().len() / Self::SIZE)
    }

    /// The record at `index` (below the count).
    fn at(&self, index: usize) -> [usize; W] {
        self.block
            .as_ref()
            .and_then(|block| <[usize; W]>::read_from(block.bytes(), index * Self::SIZE))
            .unwrap_or([0; W])
    }

    /// The record at `index` (below the capacity) written.
    fn put(&mut self, index: usize, record: [usize; W]) {
        if let Some(block) = self.block.as_mut() {
            let at = index * Self::SIZE;
            if let Some(bytes) = block.bytes_mut().get_mut(at..at + Self::SIZE) {
                bytes.copy_from_slice(record.as_bytes());
            }
        }
    }

    /// Where `window`'s record is.
    fn position(&self, window: usize) -> Option<usize> {
        if window == 0 {
            return None;
        }
        (0..self.count).find(|&index| self.at(index)[0] == window)
    }

    /// The block made room for `capacity` records (the records kept); false when the heap has no
    /// room, the block as it was.
    fn resize(&mut self, capacity: usize) -> bool {
        if capacity == 0 {
            self.block = None;
            return true;
        }
        let Some(mut block) = HeapBlock::new(capacity * Self::SIZE) else {
            return false;
        };
        if let Some(old) = self.block.as_ref() {
            let used = self.count * Self::SIZE;
            block.bytes_mut()[..used].copy_from_slice(&old.bytes()[..used]);
        }
        self.block = Some(block);
        true
    }

    /// `window`'s record (its handle first); none for a window without one, or 0.
    pub fn get(&self, window: usize) -> Option<[usize; W]> {
        self.position(window).map(|index| self.at(index))
    }

    /// `record` kept for the window its first word names, in place of the one it had; false when
    /// the heap has no room for another record (nothing changed).
    pub fn set(&mut self, record: [usize; W]) -> bool {
        if record[0] == 0 {
            return false;
        }
        if let Some(index) = self.position(record[0]) {
            self.put(index, record);
            return true;
        }
        if self.count == self.capacity() && !self.resize((2 * self.count).max(FIRST)) {
            return false;
        }
        self.put(self.count, record);
        self.count += 1;
        true
    }

    /// `window`'s record, no longer kept; the block cut when a quarter of it is left in use, freed
    /// with the last record.
    pub fn take(&mut self, window: usize) -> Option<[usize; W]> {
        let index = self.position(window)?;
        let record = self.at(index);
        self.count -= 1;
        let last = self.at(self.count);
        self.put(index, last);
        let capacity = self.capacity();
        if self.count == 0 {
            self.block = None;
        } else if capacity > FIRST && 4 * self.count <= capacity {
            // A failed cut keeps the bigger block.
            let _ = self.resize(capacity / 2);
        }
        Some(record)
    }

    /// The records `keep` refuses dropped (each removed as [`Records::take`] removes it).
    pub fn retain(&mut self, mut keep: impl FnMut(&[usize; W]) -> bool) {
        let mut index = 0;
        while index < self.count {
            let record = self.at(index);
            if keep(&record) {
                index += 1;
            } else {
                let _ = self.take(record[0]);
            }
        }
    }
}

/// A process's table of records of one kind: [`Records`] shared by its threads under user32's
/// lock.
#[cfg(all(target_arch = "x86", not(test)))]
pub struct Table<const W: usize> {
    records: rtl::sync::Locked<Records<W>, crate::imports::UserLock>,
}

#[cfg(all(target_arch = "x86", not(test)))]
impl<const W: usize> Table<W> {
    /// An empty table.
    pub const fn new() -> Self {
        Table {
            records: rtl::sync::Locked::new(crate::imports::UserLock, Records::new()),
        }
    }

    /// Run `body` over the records, under the lock: what it answers. `body` calls nothing that
    /// could run a window procedure (or reach the table again).
    pub fn with<R>(&self, body: impl FnOnce(&mut Records<W>) -> R) -> R {
        self.records.with(body)
    }
}

impl<const W: usize> Default for Table<W> {
    fn default() -> Self {
        Self::new()
    }
}

/// The host tests' table: each test thread's own records (its stand-in window manager's handles
/// are its own).
#[cfg(test)]
pub struct Table<const W: usize> {
    records: std::sync::Mutex<std::vec::Vec<(std::thread::ThreadId, Records<W>)>>,
}

#[cfg(test)]
impl<const W: usize> Table<W> {
    /// An empty table.
    pub const fn new() -> Self {
        Table {
            records: std::sync::Mutex::new(std::vec::Vec::new()),
        }
    }

    /// Run `body` over the calling thread's records: what it answers.
    pub fn with<R>(&self, body: impl FnOnce(&mut Records<W>) -> R) -> R {
        let thread = std::thread::current().id();
        let mut all = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = match all.iter().position(|(owner, _)| *owner == thread) {
            Some(index) => index,
            None => {
                all.push((thread, Records::new()));
                all.len() - 1
            }
        };
        let answer = body(&mut all[index].1);
        if all[index].1.is_empty() {
            all.swap_remove(index);
        }
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records come and go past any fixed size: each found by its window, the block grown, cut and
    /// freed with the last.
    #[test]
    fn records_grow_and_go() {
        let mut records = Records::<3>::new();
        assert_eq!(records.capacity(), 0);
        for window in 1..=1000usize {
            assert!(records.set([window, window * 2, window * 3]));
        }
        assert_eq!(records.len(), 1000);
        assert!(records.capacity() >= 1000);
        assert_eq!(records.get(500), Some([500, 1000, 1500]));
        assert!(records.set([500, 7, 8]));
        assert_eq!(records.len(), 1000);
        assert_eq!(records.get(500), Some([500, 7, 8]));
        assert_eq!(records.get(0), None);
        assert_eq!(records.get(1001), None);
        for window in (1..=1000usize).rev().step_by(2) {
            assert!(records.take(window).is_some());
        }
        assert_eq!(records.len(), 500);
        assert_eq!(records.get(999), Some([999, 1998, 2997]));
        assert_eq!(records.get(1000), None);
        records.retain(|record| record[0] % 4 != 1);
        assert_eq!(records.len(), 250);
        assert_eq!(records.get(5), None);
        assert_eq!(records.get(7), Some([7, 14, 21]));
        for window in 1..=1000 {
            let _ = records.take(window);
        }
        assert_eq!((records.len(), records.capacity()), (0, 0));
        assert!(!records.set([0, 1, 2]));
    }

    /// A table's records are the calling thread's, and leave nothing behind once taken.
    #[test]
    fn a_table_holds_each_threads_records() {
        static TABLE: Table<2> = Table::new();
        TABLE.with(|records| assert!(records.set([0x20, 1])));
        std::thread::spawn(|| {
            TABLE.with(|records| {
                assert_eq!(records.get(0x20), None);
                assert!(records.set([0x20, 2]));
            });
            TABLE.with(|records| assert_eq!(records.take(0x20), Some([0x20, 2])));
        })
        .join()
        .unwrap();
        TABLE.with(|records| assert_eq!(records.take(0x20), Some([0x20, 1])));
        assert!(TABLE.records.lock().unwrap().is_empty());
    }
}
