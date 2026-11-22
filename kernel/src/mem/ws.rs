//! The per-process working set: the pages of one process's address space that are resident in
//! memory, as a pure structure over plain entry values.
//!
//! The set is a fixed-capacity table of entries kept in least-recently-used order, index 0 the
//! least recently used: an insert or a touch moves its entry to the recent end, and
//! [`WorkingSet::trim_to`] selects eviction candidates from the old end. Each entry carries the
//! page's base address, a state (resident, or locked in the set — a trim never selects a locked
//! entry), an aging counter, and a touched flag the aging scan consumes.
//!
//! The limits are a minimum and a maximum entry count. [`WorkingSet::set_limits`] refuses a
//! minimum above the maximum, or a maximum above the table's capacity, and [`WorkingSet::trim_to`]
//! never evicts below the minimum. A fault can bring the set past the maximum —
//! [`WorkingSet::insert`] only refuses when the table itself is full — and a trim brings it back.
//!
//! The structure reaches nothing else: no frames, no page tables. Moving pages between the set
//! and memory's lists is the glue that consumes [`WorkingSet::trim_to`]'s selection.

use super::paging::PAGE_SIZE;

/// The entry table's capacity: the most pages one working set tracks.
pub const CAPACITY: usize = 1024;

/// The aging counter's ceiling: the counter saturates here.
pub const MAX_AGE: u8 = 7;

/// An entry's state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WsState {
    /// Resident in the working set; a trim may select it.
    Resident,
    /// Locked in the working set: the page stays resident and a trim never selects it.
    Locked,
}

/// One working-set entry: a page address and its state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WsEntry {
    /// The page's base address, page-aligned.
    pub va: u32,
    /// The entry's state.
    pub state: WsState,
    /// The aging counter: reset to 0 by a touch, raised by an aging scan, saturating at
    /// [`MAX_AGE`].
    pub age: u8,
    /// Whether the page was used since the last aging scan: set by a touch, cleared by the scan.
    pub touched: bool,
}

/// Why [`WorkingSet::set_limits`] refused new limits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LimitsError {
    /// The minimum is above the maximum.
    MinAboveMax,
    /// The maximum is above the entry table's [`CAPACITY`].
    MaxAboveCapacity,
}

/// One process's working set.
pub struct WorkingSet {
    /// The entries, least recently used first; the first `count` slots are in use.
    entries: [Option<WsEntry>; CAPACITY],
    /// How many slots are in use.
    count: usize,
    /// The minimum entry count: a trim never evicts below it.
    min: usize,
    /// The maximum entry count.
    max: usize,
}

impl WorkingSet {
    /// The empty set, with no limits: minimum 0, maximum the table's capacity.
    pub const fn new() -> Self {
        WorkingSet {
            entries: [None; CAPACITY],
            count: 0,
            min: 0,
            max: CAPACITY,
        }
    }

    /// The empty set with limits `min`/`max`; [`LimitsError`] when they do not hold.
    pub fn with_limits(min: usize, max: usize) -> Result<Self, LimitsError> {
        let mut ws = Self::new();
        ws.set_limits(min, max)?;
        Ok(ws)
    }

    /// Set the limits. Refuses a minimum above the maximum, or a maximum above the table's
    /// capacity.
    pub fn set_limits(&mut self, min: usize, max: usize) -> Result<(), LimitsError> {
        if min > max {
            return Err(LimitsError::MinAboveMax);
        }
        if max > CAPACITY {
            return Err(LimitsError::MaxAboveCapacity);
        }
        self.min = min;
        self.max = max;
        Ok(())
    }

    /// The minimum entry count.
    pub fn min(&self) -> usize {
        self.min
    }

    /// The maximum entry count.
    pub fn max(&self) -> usize {
        self.max
    }

    /// How many pages the set holds.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Whether the set holds no pages.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the set holds page `va`.
    pub fn contains(&self, va: u32) -> bool {
        self.find(va).is_some()
    }

    /// The entry for page `va`, when the set holds it.
    pub fn get(&self, va: u32) -> Option<&WsEntry> {
        self.find(va).map(|i| self.entries[i].as_ref().unwrap())
    }

    /// The entries, least recently used first.
    pub fn iter(&self) -> impl Iterator<Item = &WsEntry> {
        self.entries[..self.count]
            .iter()
            .map(|slot| slot.as_ref().unwrap())
    }

    /// Bring page `va` into the set: a new entry at the recent end, or a touch of the existing
    /// one. False when the table is full and the page is not already in it.
    ///
    /// # Panics
    ///
    /// `va` is not page-aligned.
    pub fn insert(&mut self, va: u32) -> bool {
        assert_eq!(va % PAGE_SIZE, 0, "working-set address not page-aligned");
        if let Some(i) = self.find(va) {
            self.touch_at(i);
            return true;
        }
        if self.count == CAPACITY {
            return false;
        }
        self.entries[self.count] = Some(WsEntry {
            va,
            state: WsState::Resident,
            age: 0,
            touched: true,
        });
        self.count += 1;
        true
    }

    /// Take page `va` out of the set, returning its entry; None when the set does not hold it.
    pub fn remove(&mut self, va: u32) -> Option<WsEntry> {
        let i = self.find(va)?;
        let entry = self.entries[i].take().unwrap();
        self.entries.copy_within(i + 1..self.count, i);
        self.count -= 1;
        Some(entry)
    }

    /// Mark page `va` used: its age resets and it moves to the recent end. False when the set
    /// does not hold it.
    pub fn touch(&mut self, va: u32) -> bool {
        match self.find(va) {
            Some(i) => {
                self.touch_at(i);
                true
            }
            None => false,
        }
    }

    /// Lock page `va` in the set: a trim will not select it. False when the set does not hold it.
    pub fn lock(&mut self, va: u32) -> bool {
        self.set_state(va, WsState::Locked)
    }

    /// Unlock page `va`: an ordinary eviction candidate again. False when the set does not hold
    /// it.
    pub fn unlock(&mut self, va: u32) -> bool {
        self.set_state(va, WsState::Resident)
    }

    /// One aging scan: entries touched since the last scan keep age 0 (and the flag clears);
    /// every other entry's counter rises by one, saturating at [`MAX_AGE`].
    pub fn age_scan(&mut self) {
        for slot in &mut self.entries[..self.count] {
            let entry = slot.as_mut().unwrap();
            if entry.touched {
                entry.touched = false;
                entry.age = 0;
            } else if entry.age < MAX_AGE {
                entry.age += 1;
            }
        }
    }

    /// Whether the set holds more than the maximum — the state a trim answers.
    pub fn over_max(&self) -> bool {
        self.count > self.max
    }

    /// Evict entries down to `target` — never below the minimum — least recently used first and
    /// skipping locked entries, writing each evicted page's address into `out` and returning how
    /// many were written. `out` must be long enough for the eviction: every evicted entry is
    /// reported.
    pub fn trim_to(&mut self, target: usize, out: &mut [u32]) -> usize {
        let target = target.max(self.min).min(self.count);
        let want = self.count - target;
        let mut evicted = 0;
        let mut read = 0;
        let mut write = 0;
        while read < self.count {
            let entry = self.entries[read].unwrap();
            if evicted < want && evicted < out.len() && entry.state != WsState::Locked {
                out[evicted] = entry.va;
                evicted += 1;
            } else {
                self.entries[write] = Some(entry);
                write += 1;
            }
            read += 1;
        }
        for slot in &mut self.entries[write..self.count] {
            *slot = None;
        }
        self.count = write;
        evicted
    }

    /// The slot of page `va`, when the set holds it.
    fn find(&self, va: u32) -> Option<usize> {
        self.entries[..self.count]
            .iter()
            .position(|slot| matches!(slot, Some(entry) if entry.va == va))
    }

    /// Move the entry at slot `i` to the recent end and reset its age.
    fn touch_at(&mut self, i: usize) {
        let mut entry = self.entries[i].take().unwrap();
        entry.age = 0;
        entry.touched = true;
        self.entries.copy_within(i + 1..self.count, i);
        self.entries[self.count - 1] = Some(entry);
    }

    /// Set the state of page `va`; false when the set does not hold it.
    fn set_state(&mut self, va: u32, state: WsState) -> bool {
        match self.find(va) {
            Some(i) => {
                self.entries[i].as_mut().unwrap().state = state;
                true
            }
            None => false,
        }
    }
}

impl Default for WorkingSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Page `n`'s base address.
    fn page(n: u32) -> u32 {
        n * PAGE_SIZE
    }

    /// The virtual addresses of the set, least recently used first.
    fn order(ws: &WorkingSet) -> Vec<u32> {
        ws.iter().map(|e| e.va).collect()
    }

    /// Insert adds entries, and a repeat insert of the same page touches it instead of adding a
    /// second entry: the page moves to the recent end.
    #[test]
    fn insert_adds_entries_and_a_repeat_insert_touches_instead() {
        let mut ws = WorkingSet::new();
        assert!(ws.is_empty());
        assert!(ws.insert(page(1)));
        assert!(ws.insert(page(2)));
        assert!(ws.insert(page(3)));
        assert_eq!(ws.len(), 3);
        assert!(!ws.is_empty());
        assert!(ws.contains(page(2)));
        assert!(!ws.contains(page(9)));
        let entry = ws.get(page(2)).unwrap();
        assert_eq!(entry.va, page(2));
        assert_eq!(entry.state, WsState::Resident);
        assert_eq!(entry.age, 0);

        assert!(ws.insert(page(2)));
        assert_eq!(ws.len(), 3, "a repeat insert does not grow the set");
        assert_eq!(order(&ws), [page(1), page(3), page(2)]);
    }

    /// Remove takes the entry out and returns it, frees its slot for reuse, and reports an
    /// absent page as None; the surviving order is kept.
    #[test]
    fn remove_returns_the_entry_and_frees_its_slot() {
        let mut ws = WorkingSet::new();
        for n in 1..=4 {
            ws.insert(page(n));
        }
        ws.touch(page(2));
        let removed = ws.remove(page(3)).unwrap();
        assert_eq!(removed.va, page(3));
        assert_eq!(removed.state, WsState::Resident);
        assert!(!ws.contains(page(3)));
        assert_eq!(ws.len(), 3);
        assert_eq!(ws.remove(page(3)), None, "already gone");
        assert_eq!(order(&ws), [page(1), page(4), page(2)]);

        assert!(ws.insert(page(5)), "the freed slot is reusable");
        assert_eq!(ws.len(), 4);
        assert!(ws.contains(page(5)));
    }

    /// The limits refuse a minimum above the maximum and a maximum above the table's capacity;
    /// equal limits are fine, and the defaults are no minimum, full capacity.
    #[test]
    fn limits_refuse_min_above_max_and_max_above_capacity() {
        let mut ws = WorkingSet::new();
        assert_eq!((ws.min(), ws.max()), (0, CAPACITY));
        assert!(WorkingSet::with_limits(10, 100).is_ok());
        let limited = WorkingSet::with_limits(10, 100).unwrap();
        assert_eq!((limited.min(), limited.max()), (10, 100));
        assert_eq!(ws.set_limits(101, 100), Err(LimitsError::MinAboveMax));
        assert_eq!(
            ws.set_limits(0, CAPACITY + 1),
            Err(LimitsError::MaxAboveCapacity)
        );
        assert_eq!(ws.set_limits(50, 50), Ok(()), "min == max is allowed");
        assert_eq!((ws.min(), ws.max()), (50, 50));
        assert_eq!(ws.len(), 0, "setting limits touches nothing");
    }

    /// A full table refuses the next insert, but a page already in the set still touches.
    #[test]
    fn a_full_table_refuses_the_next_insert() {
        let mut ws = WorkingSet::new();
        for n in 0..CAPACITY as u32 {
            assert!(ws.insert(page(n + 1)));
        }
        assert_eq!(ws.len(), CAPACITY);
        assert!(!ws.insert(page(CAPACITY as u32 + 1)));
        assert!(ws.insert(page(1)), "already in the set");
        assert_eq!(ws.len(), CAPACITY);
    }

    /// Faults can push the set past the maximum; a trim to the maximum brings it back, evicting
    /// the oldest pages.
    #[test]
    fn faults_can_push_the_set_past_the_maximum_until_a_trim() {
        let mut ws = WorkingSet::with_limits(2, 5).unwrap();
        for n in 1..=8 {
            assert!(ws.insert(page(n)));
        }
        assert_eq!(ws.len(), 8);
        assert!(ws.over_max());
        let mut out = [0u32; 8];
        let evicted = ws.trim_to(ws.max(), &mut out);
        assert_eq!(evicted, 3);
        assert_eq!(&out[..evicted], &[page(1), page(2), page(3)]);
        assert_eq!(ws.len(), 5);
        assert!(!ws.over_max());
        assert_eq!(order(&ws), [page(4), page(5), page(6), page(7), page(8)]);
    }

    /// Trim selects least recently used first: touches reorder, and the evicted addresses come
    /// out oldest-first, leaving the recent tail in place.
    #[test]
    fn trim_evicts_least_recently_used_first() {
        let mut ws = WorkingSet::with_limits(0, 100).unwrap();
        for n in 1..=6 {
            ws.insert(page(n));
        }
        ws.touch(page(2));
        ws.touch(page(4));
        assert_eq!(
            order(&ws),
            [page(1), page(3), page(5), page(6), page(2), page(4)]
        );
        let mut out = [0u32; 6];
        let evicted = ws.trim_to(2, &mut out);
        assert_eq!(evicted, 4);
        assert_eq!(&out[..evicted], &[page(1), page(3), page(5), page(6)]);
        assert_eq!(order(&ws), [page(2), page(4)]);
    }

    /// A trim never goes below the minimum, whatever the target says.
    #[test]
    fn trim_never_goes_below_the_minimum() {
        let mut ws = WorkingSet::with_limits(3, 10).unwrap();
        for n in 1..=5 {
            ws.insert(page(n));
        }
        let mut out = [0u32; 5];
        let evicted = ws.trim_to(0, &mut out);
        assert_eq!(evicted, 2, "down to the minimum of 3, not to 0");
        assert_eq!(&out[..evicted], &[page(1), page(2)]);
        assert_eq!(ws.len(), 3);
        assert_eq!(order(&ws), [page(3), page(4), page(5)]);
    }

    /// Locked entries are never selected for eviction; the trim takes the unlocked ones past
    /// them, and a fully locked set trims nothing.
    #[test]
    fn trim_skips_locked_entries() {
        let mut ws = WorkingSet::with_limits(0, 10).unwrap();
        for n in 1..=4 {
            ws.insert(page(n));
        }
        assert!(ws.lock(page(1)));
        assert!(ws.lock(page(3)));
        let mut out = [0u32; 4];
        let evicted = ws.trim_to(1, &mut out);
        assert_eq!(evicted, 2);
        assert_eq!(&out[..evicted], &[page(2), page(4)]);
        assert_eq!(ws.len(), 2);
        assert_eq!(ws.get(page(1)).unwrap().state, WsState::Locked);
        assert_eq!(ws.get(page(3)).unwrap().state, WsState::Locked);

        let mut locked = WorkingSet::new();
        for n in 1..=3 {
            locked.insert(page(n));
            assert!(locked.lock(page(n)));
        }
        let mut out = [0u32; 3];
        assert_eq!(locked.trim_to(0, &mut out), 0, "nothing evictable");
        assert_eq!(locked.len(), 3);
    }

    /// A trim to the current size or above evicts nothing and leaves the buffer alone.
    #[test]
    fn trim_at_or_above_the_size_evicts_nothing() {
        let mut ws = WorkingSet::with_limits(0, 10).unwrap();
        for n in 1..=4 {
            ws.insert(page(n));
        }
        let mut out = [0u32; 4];
        assert_eq!(ws.trim_to(4, &mut out), 0);
        assert_eq!(ws.trim_to(9, &mut out), 0);
        assert_eq!(ws.len(), 4);
        assert_eq!(out, [0; 4], "no eviction, no write");
        assert_eq!(order(&ws), [page(1), page(2), page(3), page(4)]);
    }

    /// A touch resets the entry's age and moves it to the recent end, and the next trim follows
    /// that same order.
    #[test]
    fn touch_resets_the_age_and_moves_the_entry_to_the_recent_end() {
        let mut ws = WorkingSet::with_limits(0, 10).unwrap();
        ws.insert(page(1));
        ws.insert(page(2));
        ws.insert(page(3));
        ws.age_scan();
        ws.age_scan();
        assert!(
            ws.iter().all(|e| e.age == 1),
            "two scans past the insert's touch"
        );

        assert!(ws.touch(page(1)));
        assert_eq!(ws.get(page(1)).unwrap().age, 0);
        assert!(ws.get(page(1)).unwrap().touched);
        assert_eq!(order(&ws), [page(2), page(3), page(1)]);

        ws.age_scan();
        assert_eq!(ws.get(page(1)).unwrap().age, 0, "touched this round");
        assert_eq!(ws.get(page(2)).unwrap().age, 2);
        assert_eq!(ws.get(page(3)).unwrap().age, 2);

        let mut out = [0u32; 3];
        assert_eq!(ws.trim_to(1, &mut out), 2);
        assert_eq!(&out[..2], &[page(2), page(3)]);
        assert!(ws.contains(page(1)));
    }

    /// The aging scan raises every untouched entry's counter by one and saturates at MAX_AGE.
    #[test]
    fn the_aging_scan_raises_untouched_counters_and_saturates() {
        let mut ws = WorkingSet::new();
        ws.insert(page(1));
        assert!(ws.get(page(1)).unwrap().touched, "a fresh entry is touched");
        ws.age_scan();
        assert_eq!(ws.get(page(1)).unwrap().age, 0, "touched this round");
        assert!(
            !ws.get(page(1)).unwrap().touched,
            "the scan cleared the flag"
        );
        ws.age_scan();
        assert_eq!(ws.get(page(1)).unwrap().age, 1);
        for _ in 0..20 {
            ws.age_scan();
        }
        assert_eq!(ws.get(page(1)).unwrap().age, MAX_AGE, "saturated");
    }

    /// Lock and unlock flip the entry's state in place; a locked entry can still be removed
    /// outright, and absent pages report false.
    #[test]
    fn lock_and_unlock_flip_the_state() {
        let mut ws = WorkingSet::new();
        assert!(!ws.lock(page(1)), "absent");
        ws.insert(page(1));
        assert!(ws.lock(page(1)));
        assert_eq!(ws.get(page(1)).unwrap().state, WsState::Locked);
        assert!(ws.unlock(page(1)));
        assert_eq!(ws.get(page(1)).unwrap().state, WsState::Resident);
        assert!(!ws.unlock(page(2)), "absent");

        assert!(ws.lock(page(1)));
        let removed = ws.remove(page(1)).unwrap();
        assert_eq!(
            removed.state,
            WsState::Locked,
            "remove works on a locked entry"
        );
        assert!(!ws.contains(page(1)));
    }

    /// An empty set is inert: every lookup misses, every mutation reports nothing, and a trim
    /// evicts nothing.
    #[test]
    fn an_empty_set_is_inert() {
        let mut ws = WorkingSet::new();
        assert!(ws.is_empty());
        assert_eq!(ws.len(), 0);
        assert!(!ws.contains(page(1)));
        assert_eq!(ws.get(page(1)), None);
        assert_eq!(ws.remove(page(1)), None);
        assert!(!ws.touch(page(1)));
        assert!(!ws.over_max());
        assert_eq!(ws.iter().count(), 0);
        let mut out = [0u32; 1];
        assert_eq!(ws.trim_to(0, &mut out), 0);
        assert_eq!(out, [0], "no eviction, no write");
        ws.age_scan();
        assert!(ws.is_empty());
    }

    /// An unaligned address is refused on insert.
    #[test]
    fn an_unaligned_insert_is_refused() {
        let mut ws = WorkingSet::new();
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ws.insert(0x123)));
        assert!(refused.is_err(), "an unaligned insert is refused");
        assert!(ws.is_empty());
    }
}
