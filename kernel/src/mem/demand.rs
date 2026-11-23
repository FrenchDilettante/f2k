//! Applying a page fault the entry alone can resolve: the demand-paging half of the fault path.
//!
//! [`apply`] reads the faulting page's entry, asks [`fault::resolve`] what the access resolves
//! to, and applies it: a demand-zero page — committed, never touched — gets a zeroed frame
//! mapped present, with the protection the entry records; a transition page — its frame named,
//! off its working set — is taken back off its backing list and mapped present again, no I/O; a
//! copy-on-write page is severed and a guard page fired, as the address-space manager has always
//! done ([`vm::copy_on_write`], [`vm::fire_guard`]); anything else — a section's page, a
//! paging-file page, no entry at all — is left to the exception path ([`super::backing`]). True
//! when the page is mapped and the faulting access resumes.
//!
//! When a demand-zero map finds no frame, the fault path relieves pressure first: the vector-14
//! hook trims the current process's working set ([`super::wstrim::relieve_pressure`], LRU-oldest
//! first; the staged write-out of the victims it selects is [`target`] on the target) and the
//! allocation is retried once. Without a frame after that the fault stands, the entry as it was.

use super::fault::{self, Resolution};
use super::vm::{self, Pages, PAGE, USER_HIGH};

/// The frame's place in an entry: bits 12-31.
const FRAME_MASK: u32 = 0xFFFF_F000;

/// The base protection an entry's index bits record.
fn protect_of(entry: u32) -> u32 {
    vm::soft_protect(entry)
}

/// Classify the faulting access at `va` — `write` for a store, `user` when it came from ring 3 —
/// and map the page when the resolution is one that needs no exception and no I/O: a demand-zero
/// page's zeroed frame ([`vm::map_demand_zero`]), a transition page's named frame
/// ([`vm::map_named_frame`]) — the entries are the address-space manager's to write. True when
/// the page is mapped now and the access can resume; false when the resolution is anything else
/// (copy-on-write, guard, a section's page, a paging-file page, nothing at all) or no frame was
/// left for a demand-zero page, in which case the entry is as it was. The caller's own paths take
/// the rest.
pub fn map(pages: &mut impl Pages, va: u32, write: bool, user: bool) -> bool {
    map_with(pages, va, write, user, &mut || false)
}

/// [`map`], with a pressure-relief hook: when a demand-zero map finds no frame, `relieve` runs
/// once (a page-out pass over the frame database) and the allocation is retried once. False when
/// no frame was left even then.
pub fn map_with(
    pages: &mut impl Pages,
    va: u32,
    write: bool,
    user: bool,
    relieve: &mut impl FnMut() -> bool,
) -> bool {
    if va >= USER_HIGH {
        return false;
    }
    let page = va & !(PAGE - 1);
    let entry = pages.entry(page);
    match fault::resolve(entry, write, user) {
        Resolution::DemandZero => {
            let protect = protect_of(entry);
            if vm::map_demand_zero(pages, page, protect) {
                return true;
            }
            // No frame left: relieve pressure once, then retry the allocation once.
            if !relieve() {
                return false;
            }
            vm::map_demand_zero(pages, page, protect)
        }
        Resolution::Transition => {
            let frame = entry & FRAME_MASK;
            // The frame is on a backing list: take it back into use before mapping it again.
            pages.activate_frame(frame);
            vm::map_named_frame(pages, page, frame, protect_of(entry));
            true
        }
        _ => false,
    }
}

/// Classify the faulting access at `va` — `write` for a store, `user` when it came from ring 3 —
/// and apply what it resolves to (see the module notes): [`map_with`] for the demand-zero and
/// transition pages, [`vm::copy_on_write`] and [`vm::fire_guard`] for the copy-on-write and guard
/// pages, as the address-space manager has always done. True when the fault was resolved and the
/// access can resume; false when nothing resolved it (the fault stands). (The fault path runs
/// [`apply_with`]; the host tests drive this one.)
#[cfg_attr(not(test), allow(dead_code))]
pub fn apply(pages: &mut impl Pages, va: u32, write: bool, user: bool) -> bool {
    apply_with(pages, va, write, user, &mut || false)
}

/// [`apply`], with the pressure-relief hook the fault path passes (see [`map_with`]).
pub fn apply_with(
    pages: &mut impl Pages,
    va: u32,
    write: bool,
    user: bool,
    relieve: &mut impl FnMut() -> bool,
) -> bool {
    if map_with(pages, va, write, user, relieve) {
        return true;
    }
    if va >= USER_HIGH {
        return false;
    }
    let page = va & !(PAGE - 1);
    match fault::resolve(pages.entry(page), write, user) {
        Resolution::CopyOnWrite => vm::copy_on_write(pages, va),
        Resolution::Guard => vm::fire_guard(pages, va),
        _ => false,
    }
}

/// One 4 MiB chunk of the user range: a page directory entry's span, 1024 pages.
// Host-test helper: the target's relief walks the working set, not the user range.
#[cfg_attr(not(test), allow(dead_code))]
pub const CHUNK: u32 = 4 * 1024 * 1024;

/// Walk the user pages `[start, end)` in order, visiting each with `visit` until it returns
/// false. A 4 MiB chunk whose table `chunk_live` says is absent is skipped whole — one read
/// per chunk instead of 1024 — so a scan over a large reservation costs the chunks, not the
/// pages. Returns where the walk stopped.
// Host-test helper: the target's relief walks the working set, not the user range.
#[cfg_attr(not(test), allow(dead_code))]
pub fn walk_pages(
    start: u32,
    end: u32,
    mut chunk_live: impl FnMut(u32) -> bool,
    mut visit: impl FnMut(u32) -> bool,
) -> u32 {
    let mut va = start;
    while va < end {
        if (va & (CHUNK - 1)) == 0 && !chunk_live(va) {
            va += CHUNK;
            continue;
        }
        if !visit(va) {
            va += PAGE;
            break;
        }
        va += PAGE;
    }
    va
}

/// Fill `victims` with the present pages of `[start, end)` — up to `victims.len()` — reading
/// each entry through `entry` and skipping chunks as [`walk_pages`] does. Returns how many were
/// found and where the walk stopped.
// Host-test helper: the target's relief walks the working set, not the user range.
#[cfg_attr(not(test), allow(dead_code))]
pub fn scan_pages(
    victims: &mut [super::backing::Victim],
    start: u32,
    end: u32,
    entry: impl Fn(u32) -> u32,
    mut chunk_live: impl FnMut(u32) -> bool,
) -> (usize, u32) {
    let mut count = 0;
    let stop = walk_pages(start, end, |va| chunk_live(va), |va| {
        if count >= victims.len() {
            return false;
        }
        let e = entry(va);
        let frame = e & vm::PTE_FRAME_MASK;
        if e & vm::PTE_PRESENT != 0 && frame != 0 {
            let protect = vm::decode(e)
                .map(|(_, protect)| protect)
                .unwrap_or_else(|| vm::soft_protect(e));
            victims[count] = super::backing::Victim { va, frame, protect };
            count += 1;
        }
        true
    });
    (count, stop)
}

// --- The staged fault driver (target) -----------------------------------------------------------
//
// The paging file's disk I/O waits on the disk interrupt, so it cannot run inside a borrow of
// the memory manager's database (borrowed at the high level, interrupts masked): the fault path
// reaches the database at the interrupted level, so a pass alternates short database borrows with
// paging-file holds — unlink a frame and copy its page out, write the slot through the file, release
// the frame to Standby — never holding both. The relief is working-set driven: the vector-14 hook
// (user::seh) runs [`crate::mem::wstrim::relieve_pressure`] over the current process's working set
// and records the victims it selects here; this module writes them out in groups. The backing arms'
// staging ([`crate::mem::backing`]'s PageFile and Section resolutions) is driven from here as well.

#[cfg(target_arch = "x86")]
pub mod target {
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

    use super::super::frame::{FrameId, FrameState, UnlinkOutcome};
    use crate::mem::pageout::{self, SlotId, PAGE_SIZE};
    use crate::mem::pagingfile::with_paging_file;
    use crate::mem::vm::{self, CurrentPages, Pages, PAGE};
    use crate::mem::{self, Parts};

    /// How many victims one relief selects at most: the trim batch the hook relieves with.
    pub const BATCH: usize = 256;

    /// One victim of the relieve, as the trim's `resolve` recorded it: the page's base address,
    /// the frame its entry named (a physical address) and its recorded protection — committed to
    /// the write-out by the trim's `evict_dirty`.
    #[derive(Clone, Copy)]
    struct Victim {
        va: u32,
        frame: u32,
        protect: u32,
        committed: bool,
    }

    /// The victims of the current relieve, while the hook holds the one-at-a-time guard.
    static mut VICTIMS: [Victim; BATCH] =
        [Victim { va: 0, frame: 0, protect: 0, committed: false }; BATCH];
    static VICTIM_COUNT: AtomicUsize = AtomicUsize::new(0);
    static VICTIM_CURSOR: AtomicUsize = AtomicUsize::new(0);

    /// One relief at a time: a fault arriving while a relieve waits on the disk I/O finds it busy.
    static RELIEF_BUSY: AtomicBool = AtomicBool::new(false);

    /// The victims array, while the relieve holds RELIEF_BUSY.
    fn victims() -> &'static mut [Victim; BATCH] {
        // SAFETY: RELIEF_BUSY is held for the whole relieve, so the array has one user.
        unsafe { &mut *core::ptr::addr_of_mut!(VICTIMS) }
    }

    /// Begin a relief: false when one is already running. The victim queue starts empty.
    pub fn try_begin_relieve() -> bool {
        if RELIEF_BUSY
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        VICTIM_COUNT.store(0, Ordering::Relaxed);
        VICTIM_CURSOR.store(0, Ordering::Relaxed);
        true
    }

    /// End the relieve, releasing the one-at-a-time guard.
    pub fn end_relieve() {
        RELIEF_BUSY.store(false, Ordering::Release);
    }

    /// Record a victim the trim's `resolve` decoded: its page, frame and protection, waiting for
    /// its `evict_dirty` to commit it to the write-out.
    pub fn record_victim(va: u32, frame: u32, protect: u32) {
        let count = VICTIM_COUNT.load(Ordering::Relaxed);
        if count < BATCH {
            victims()[count] = Victim { va, frame, protect, committed: false };
            VICTIM_COUNT.store(count + 1, Ordering::Release);
        }
    }

    /// Commit the resolved victim `frame` to the write-out (the trim's `evict_dirty` callback):
    /// its page goes to a fresh paging-file slot below, so the slot it already holds is not used
    /// — a resident page holds none.
    pub fn queue_dirty(frame: FrameId, slot: SlotId) {
        let _ = slot;
        let count = VICTIM_COUNT.load(Ordering::Acquire);
        for victim in &mut victims()[..count] {
            if !victim.committed && victim.frame / PAGE == frame {
                victim.committed = true;
                return;
            }
        }
    }

    /// The write-out's group size: pages per transfer (and per database borrow's copy-out). A
    /// group's slots are one run in the file, so one store operation writes them all.
    const GROUP: usize = 64;

    /// Take the next group of committed victims into the batch's front slots: how many, up to the
    /// group size. Zero when the queue is drained.
    fn take_batch() -> usize {
        let cursor = VICTIM_CURSOR.load(Ordering::Relaxed);
        let count = VICTIM_COUNT.load(Ordering::Acquire);
        let victims = victims();
        let mut out = 0;
        let mut at = cursor;
        while at < count && out < GROUP {
            if victims[at].committed {
                victims[out] = victims[at];
                out += 1;
            }
            at += 1;
        }
        VICTIM_CURSOR.store(at, Ordering::Release);
        out
    }

    /// Write the queued victims out to paging-file slots, in groups (see the module notes), and
    /// free their frames: each committed victim is evicted — its frame to the Modified list, its
    /// entry softened to a transition one naming the frame — and each group's pages are written
    /// as one transfer. Returns how many frames went to Standby.
    pub fn write_out_queued() -> u32 {
        let mut freed = 0;
        loop {
            let count = take_batch();
            if count == 0 {
                break;
            }
            let mut kept = 0;
            for index in 0..count {
                let victim = victims()[index];
                if evict(victim) {
                    victims()[kept] = victim;
                    kept += 1;
                }
            }
            if kept > 0 {
                freed += write_out_batch(kept);
            }
        }
        freed
    }

    /// Evict one victim: its frame to the Modified list (when it is still in use and unshared),
    /// its entry softened to a transition one naming the frame. True when evicted. The frame moves
    /// first and the entry after: until the entry is softened the page stays reachable through it,
    /// and no wait runs between the two steps.
    fn evict(victim: Victim) -> bool {
        let fid = victim.frame / PAGE;
        let mut queued = false;
        mem::with_database(|db| {
            let Parts { frames, .. } = db.parts();
            if frames.entry(fid).share_count > 0 {
                return;
            }
            // The entry as it is now, inside the borrow: one re-faulted meanwhile names another
            // frame, and is left alone.
            let entry = CurrentPages.entry(victim.va);
            if entry & vm::PTE_PRESENT == 0 || vm::backing_payload(entry) != victim.frame {
                return;
            }
            if frames.entry(fid).state != FrameState::Active {
                return;
            }
            pageout::to_modified(frames, fid);
            queued = true;
        });
        if !queued {
            return false;
        }
        vm::soften_to_transition(&mut CurrentPages, victim.va, victim.frame, victim.protect);
        true
    }

    /// The page buffers a staged transfer copies through: the disk I/O waits (a switch can happen
    /// inside it), so a buffer is claimed for the transfer, not borrowed from a stack.
    const BUF_COUNT: usize = 4;
    static BUF_CLAIMS: AtomicU8 = AtomicU8::new(0);
    static mut BUFS: [[u8; PAGE_SIZE]; BUF_COUNT] = [[0; PAGE_SIZE]; BUF_COUNT];

    /// A claimed page buffer; released on drop.
    pub struct PageBuf {
        index: usize,
    }

    impl PageBuf {
        /// Claim one of the buffers; none when all are in flight.
        pub fn claim() -> Option<PageBuf> {
            let mut claims = BUF_CLAIMS.load(Ordering::Acquire);
            loop {
                let bit = (!claims).trailing_zeros() as usize;
                if bit >= BUF_COUNT {
                    return None;
                }
                match BUF_CLAIMS.compare_exchange(
                    claims,
                    claims | (1 << bit),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => return Some(PageBuf { index: bit }),
                    Err(current) => claims = current,
                }
            }
        }

        /// The buffer, mutable.
        pub fn as_mut(&mut self) -> &mut [u8; PAGE_SIZE] {
            // SAFETY: the index is claimed in BUF_CLAIMS until the drop, so the buffer has one
            // user at a time.
            unsafe { &mut (*core::ptr::addr_of_mut!(BUFS))[self.index] }
        }

        /// The buffer, shared.
        pub fn as_ref(&self) -> &[u8; PAGE_SIZE] {
            // SAFETY: as `as_mut`.
            unsafe { &(*core::ptr::addr_of!(BUFS))[self.index] }
        }
    }

    impl Drop for PageBuf {
        fn drop(&mut self) {
            BUF_CLAIMS.fetch_and(!(1 << self.index), Ordering::Release);
        }
    }

    /// The batch buffer a group's pages are copied through: the disk I/O waits (a switch can
    /// happen inside it), so the pages are copied out of the frames under a database borrow
    /// into this, not borrowed from a stack.
    static mut BATCH_BUF: [u8; GROUP * PAGE_SIZE] = [0; GROUP * PAGE_SIZE];

    /// The batch buffer, while the relieve holds RELIEF_BUSY (one user at a time).
    fn batch_all() -> &'static mut [u8; GROUP * PAGE_SIZE] {
        // SAFETY: RELIEF_BUSY is held for the whole relieve, so the buffer has one user at a time.
        unsafe { &mut *core::ptr::addr_of_mut!(BATCH_BUF) }
    }

    /// Page `index` of the batch buffer, while the relieve holds RELIEF_BUSY.
    fn batch_page(index: usize) -> &'static mut [u8] {
        &mut batch_all()[index * PAGE_SIZE..(index + 1) * PAGE_SIZE]
    }

    /// Pages `start..start + count` of the batch buffer, while the relieve holds RELIEF_BUSY.
    fn batch_range(start: usize, count: usize) -> &'static [u8] {
        &batch_all()[start * PAGE_SIZE..(start + count) * PAGE_SIZE]
    }

    /// Write the batch's `count` evicted pages out to paging-file slots, in one transfer, staged
    /// around the paging file's lock (see the module notes): the frames unlinked from the Modified
    /// list and their pages copied into the batch buffer under one database borrow, the run of
    /// slots allocated (the file grown when no run is long enough) and written through the file in
    /// one operation, the frames released to Standby, the entries rewritten to name their slots. A
    /// page re-faulted while its write was in flight keeps its frame and its slot goes back.
    /// Returns how many frames went to Standby.
    fn write_out_batch(count: usize) -> u32 {
        let mut copied = [false; GROUP];
        let mut page_of = [0u32; GROUP];
        // Step 1: unlink each still-Modified frame and copy its page out, compacted.
        let mut total = 0usize;
        mem::with_database(|db| {
            let Parts { frames, scratch, .. } = db.parts();
            for index in 0..count {
                let victim = victims()[index];
                let fid = victim.frame / PAGE;
                if frames.entry(fid).state != FrameState::Modified {
                    continue;
                }
                if frames.unlink(fid) != UnlinkOutcome::Unlinked {
                    continue;
                }
                scratch.read_frame(victim.frame, 0, batch_page(total));
                copied[index] = true;
                page_of[index] = total as u32;
                total += 1;
            }
        });
        if total == 0 {
            return 0;
        }
        // Step 2: a run of slots for the batch — grown when the file is full, shrunk when no run
        // that long is free, so a fragmented file still takes the pages, in smaller transfers.
        // Each try takes the file in its own hold: the disk I/O waits, and no database borrow is
        // held across one.
        let mut want = total as u64;
        let mut extended = false;
        let first = loop {
            if let Some(first) = with_paging_file(|file| file.allocate_slots(want)).flatten() {
                break first;
            }
            if !extended {
                extended = true;
                if with_paging_file(|file| file.extend().is_ok()).unwrap_or(false) {
                    continue;
                }
            }
            if want > 1 {
                want /= 2;
                continue;
            }
            // No room at all: the frames go back on the Modified list, their entries still
            // transition ones naming their frames.
            put_back(count, &copied, FrameState::Modified);
            return 0;
        };
        // Step 2b: the run is written as one transfer.
        let written = with_paging_file(|file| {
            match file.write_pages(first, batch_range(0, want as usize)) {
                Ok(()) => true,
                Err(_) => {
                    for slot in first..first + want {
                        if file.is_allocated(slot) {
                            file.free_slot(slot);
                        }
                    }
                    false
                }
            }
        })
        .unwrap_or(false);
        if !written {
            put_back(count, &copied, FrameState::Modified);
            return 0;
        }
        // Step 3: each copied page's frame — to Standby when its entry still is the transition
        // one this pass wrote (the page is out), back to Modified when it was not written (the
        // run shrank) — and its entry rewritten to name its slot, unless the page was re-faulted
        // while the write was in flight: then the frame holds the page again and the slot goes
        // back.
        let mut freed = 0;
        for index in 0..count {
            if !copied[index] {
                continue;
            }
            let victim = victims()[index];
            let fid = victim.frame / PAGE;
            if page_of[index] >= want as u32 {
                mem::with_database(|db| db.parts().frames.release(fid, FrameState::Modified));
                continue;
            }
            let slot = first + u64::from(page_of[index]);
            let current = CurrentPages.entry(victim.va);
            if vm::backing_tag(current) == vm::TAG_TRANSITION
                && vm::backing_payload(current) == victim.frame
            {
                mem::with_database(|db| db.parts().frames.release(fid, FrameState::Standby));
                vm::name_page_file(&mut CurrentPages, victim.va, slot as u32, victim.protect);
                freed += 1;
            } else if current & vm::PTE_PRESENT != 0 && vm::backing_payload(current) == victim.frame {
                // Re-faulted while the write was in flight: the frame is in use again (its entry
                // is present, naming it); the slot goes back.
                let _ = with_paging_file(|file| {
                    if file.is_allocated(slot) {
                        file.free_slot(slot);
                    }
                });
            } else {
                // The entry no longer names the frame at all (decommitted meanwhile): the frame
                // goes back to the pool, and the slot with it.
                mem::with_database(|db| {
                    let frames = db.parts().frames;
                    if frames.entry(fid).state.is_list_state() {
                        frames.unlink(fid);
                    }
                    if frames.unshare(fid) {
                        frames.release(fid, FrameState::Free);
                    }
                });
                let _ = with_paging_file(|file| {
                    if file.is_allocated(slot) {
                        file.free_slot(slot);
                    }
                });
            }
        }
        freed
    }

    /// Put the copied pages' frames of the batch back on `state`'s list.
    fn put_back(count: usize, copied: &[bool; GROUP], state: FrameState) {
        mem::with_database(|db| {
            let Parts { frames, .. } = db.parts();
            for index in 0..count {
                if copied[index] {
                    frames.release(victims()[index].frame / PAGE, state);
                }
            }
        });
    }
}
#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::pte::{self, PteKind};
    use crate::mem::vm::{PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY};

    /// The old four-argument call: no relief runs.
    fn apply4(pages: &mut Fake, va: u32, write: bool, user: bool) -> bool {
        apply(pages, va, write, user)
    }

    /// The protection index's place in a test entry: bits 9-11.
    const INDEX_SHIFT: u32 = 9;

    /// The frame a transition entry names.
    const FRAME: u32 = 0x0050_0000;

    /// Page tables as a map, frames numbered from 1 MiB: their extra holders, their words and
    /// their contents (a frame's first word stands for its contents), the frames given back, and
    /// how many more frames there are to give (none: no end).
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
        activated: Vec<u32>,
        holders: HashMap<u32, u32>,
        words: HashMap<(u32, u32), u32>,
        budget: Option<u32>,
        grants: std::rc::Rc<std::cell::Cell<u32>>,
    }

    impl Pages for Fake {
        fn entry(&self, va: u32) -> u32 {
            *self.entries.get(&va).unwrap_or(&0)
        }

        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }

        fn zeroed_frame(&mut self) -> Option<u32> {
            if self.grants.get() > 0 {
                self.grants.set(self.grants.get() - 1);
            } else if let Some(budget) = &mut self.budget {
                *budget = budget.checked_sub(1)?;
            }
            self.next += 1;
            Some(0x0010_0000 + self.next * PAGE)
        }

        fn free_frame(&mut self, frame: u32) {
            match self.holders.get_mut(&frame) {
                Some(extra) if *extra > 0 => *extra -= 1,
                _ => self.freed.push(frame),
            }
        }

        fn share_frame(&mut self, frame: u32) {
            *self.holders.entry(frame).or_default() += 1;
        }

        fn frame_shared(&self, frame: u32) -> bool {
            self.holders.get(&frame).is_some_and(|&extra| extra > 0)
        }

        fn copy_frame(&mut self, from: u32, to: u32) {
            let word = self.frame_word(from, 0);
            self.set_frame_word(to, 0, word);
        }

        fn frame_word(&self, frame: u32, index: u32) -> u32 {
            *self.words.get(&(frame, index)).unwrap_or(&0)
        }

        fn set_frame_word(&mut self, frame: u32, index: u32, value: u32) {
            self.words.insert((frame, index), value);
        }

        fn activate_frame(&mut self, frame: u32) {
            self.activated.push(frame);
        }
    }

    /// Plant an entry in the fake tables.
    fn plant(pages: &mut Fake, va: u32, entry: u32) {
        pages.entries.insert(va, entry);
    }

    /// A committed, never touched page at `page`: a demand-zero entry, as a commit writes it.
    fn demand_zero(pages: &mut Fake, page: u32, protect: u32) {
        plant(pages, page, pte::encode(PteKind::DemandZero, 0, protect));
    }

    /// A page evicted to a backing list: the frame named, the transition tag set, the
    /// protection in the index bits — the entry a fault reads as a transition page.
    fn transition(pages: &mut Fake, page: u32, frame: u32, protect: u32) {
        let index = match protect {
            vm::PAGE_READONLY => 1,
            vm::PAGE_READWRITE => 2,
            vm::PAGE_WRITECOPY => 3,
            _ => 2,
        };
        plant(pages, page, fault::TRANSITION | frame | (index << INDEX_SHIFT));
    }

    /// A demand-zero page's first touch — a read or a write, from ring 3 or the kernel — maps a
    /// zeroed frame present with the recorded protection, and the access resumes.
    #[test]
    fn a_demand_zero_page_faults_in_a_zeroed_frame() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READWRITE);
        assert!(apply4(&mut pages, page + 0x10, false, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::Present);
        assert!(pte::writable(entry));
        let (_, frame, protect) = pte::decode(entry).unwrap();
        assert_ne!(frame, 0);
        assert_eq!(protect, PAGE_READWRITE);
        assert_eq!(pages.frame_word(frame, 0), 0, "the frame is zeroed");
        // From the kernel, and on a write, the same.
        demand_zero(&mut pages, page + PAGE, PAGE_READWRITE);
        assert!(apply4(&mut pages, page + PAGE, true, false));
        assert_eq!(pte::classify(pages.entry(page + PAGE)), PteKind::Present);
        // A fault on the now-present page stands unresolved.
        assert!(!apply4(&mut pages, page, true, true));
    }

    /// A demand-zero read-only page fills on a read; a write to it is the violation, and the
    /// entry is untouched.
    #[test]
    fn a_demand_zero_read_only_page_refuses_a_write() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READONLY);
        assert!(apply4(&mut pages, page, false, true));
        let (_, frame, protect) = pte::decode(pages.entry(page)).unwrap();
        assert_eq!((pte::classify(pages.entry(page)), protect), (PteKind::Present, PAGE_READONLY));
        assert!(!pte::writable(pages.entry(page)));
        assert_ne!(frame, 0);
        demand_zero(&mut pages, page + PAGE, PAGE_READONLY);
        let before = pages.entry(page + PAGE);
        assert!(!apply4(&mut pages, page + PAGE, true, true));
        assert_eq!(pages.entry(page + PAGE), before, "nothing was mapped");
    }

    /// A demand-zero copy-on-write page fills held copy-on-write: the frame is mapped, but
    /// read-only to the hardware, the first write severing it.
    #[test]
    fn a_demand_zero_copy_on_write_page_fills_held_back() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_WRITECOPY);
        assert!(apply4(&mut pages, page, true, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::CopyOnWrite);
        assert!(!pte::writable(entry));
        assert_eq!(pte::decode(entry).unwrap().2, PAGE_WRITECOPY);
    }

    /// A demand-zero page with no frame left is not applied: the fault stands, the entry as it
    /// was.
    #[test]
    fn a_demand_zero_page_without_a_frame_stands() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READWRITE);
        pages.budget = Some(0);
        let before = pages.entry(page);
        assert!(!apply4(&mut pages, page, false, true));
        assert_eq!(pages.entry(page), before);
        assert_eq!(pte::classify(pages.entry(page)), PteKind::DemandZero);
    }

    /// A transition page is mapped present again from its named frame, no I/O and no new frame,
    /// on a read and on a write; a write its protection refuses is the violation.
    #[test]
    fn a_transition_page_maps_its_named_frame() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        transition(&mut pages, page, FRAME, PAGE_READWRITE);
        assert!(apply4(&mut pages, page, false, true));
        let entry = pages.entry(page);
        assert_eq!(pte::classify(entry), PteKind::Present);
        assert_eq!(pte::decode(entry), Some((PteKind::Present, FRAME, PAGE_READWRITE)));
        assert!(pte::writable(entry));
        assert!(pages.freed.is_empty(), "the frame was not given back");

        transition(&mut pages, page + PAGE, FRAME, PAGE_READONLY);
        assert!(apply4(&mut pages, page + PAGE, false, true));
        assert_eq!(
            pte::decode(pages.entry(page + PAGE)),
            Some((PteKind::Present, FRAME, PAGE_READONLY))
        );
        // A write the recorded protection refuses stands.
        transition(&mut pages, page + 2 * PAGE, FRAME, PAGE_READONLY);
        let before = pages.entry(page + 2 * PAGE);
        assert!(!apply4(&mut pages, page + 2 * PAGE, true, true));
        assert_eq!(pages.entry(page + 2 * PAGE), before);
        // A copy-on-write transition page fills held back.
        transition(&mut pages, page + 3 * PAGE, FRAME, PAGE_WRITECOPY);
        assert!(apply4(&mut pages, page + 3 * PAGE, true, true));
        assert_eq!(pte::classify(pages.entry(page + 3 * PAGE)), PteKind::CopyOnWrite);
    }

    /// A present copy-on-write page written is severed, as the address-space manager always did.
    #[test]
    fn a_copy_on_write_page_is_severed() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        plant(&mut pages, page, vm::encode(FRAME, PAGE_WRITECOPY));
        pages.holders.insert(FRAME, 1);
        assert!(apply4(&mut pages, page, true, true));
        let (frame, protect) = vm::decode(pages.entry(page)).unwrap();
        assert_ne!(frame, FRAME, "a copy was made for the process");
        assert_eq!(protect, PAGE_READWRITE);
        assert!(!pages.frame_shared(FRAME));
    }

    /// A guard page touched fires once, as the address-space manager always did.
    #[test]
    fn a_guard_page_fires() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        plant(&mut pages, page, vm::encode(FRAME, PAGE_READWRITE | PAGE_GUARD));
        assert!(apply4(&mut pages, page, false, true));
        assert_eq!(
            vm::decode(pages.entry(page)),
            Some((FRAME, PAGE_READWRITE)),
            "the guard flag is spent"
        );
    }

    /// Nothing resolves an uncommitted page, a no-access page, a write to a present read-only
    /// page, or an address outside the application range; the entry is left alone.
    #[test]
    fn the_unresolved_faults_stand() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        assert!(!apply4(&mut pages, page, false, true), "no entry");
        demand_zero(&mut pages, page, PAGE_NOACCESS);
        assert!(!apply4(&mut pages, page, false, true), "a no-access page");
        plant(&mut pages, page, vm::encode(FRAME, PAGE_READONLY));
        assert!(!apply4(&mut pages, page, true, true), "a write to a read-only page");
        assert!(!apply4(&mut pages, USER_HIGH, false, true), "outside the application range");
        assert!(!apply4(&mut pages, USER_HIGH + 0x1000, true, true));
    }

    /// A demand-zero page with no frame left stands until the relief hook frees one: with the
    /// hook returning false the fault stands and the entry is as it was; with it returning true
    /// (a frame freed) the allocation is retried once and the page maps — and a second no-frame
    /// fault after a relief that freed nothing still stands.
    #[test]
    fn a_demand_zero_page_retries_once_after_relief() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        demand_zero(&mut pages, page, PAGE_READWRITE);
        pages.budget = Some(0);
        let before = pages.entry(page);
        let mut ran = 0;
        let relieved = apply_with(&mut pages, page, false, true, &mut || {
            ran += 1;
            false
        });
        assert!(!relieved, "the relief freed nothing");
        assert_eq!(ran, 1, "the relief ran once");
        assert_eq!(pages.entry(page), before, "the entry is as it was");

        // The relief frees a frame this time: the retry maps the page.
        let grants = pages.grants.clone();
        let mut freed = false;
        let relieved = apply_with(&mut pages, page, true, true, &mut || {
            freed = true;
            grants.set(1);
            true
        });
        assert!(relieved && freed);
        assert_eq!(pte::classify(pages.entry(page)), PteKind::Present);
        assert!(pte::writable(pages.entry(page)));
        assert_eq!(grants.get(), 0, "the frame the retry took was the relief's");
    }

    /// A transition page's frame is taken back off its backing list before the page is mapped
    /// present again (the fake records the activation), with no I/O and no new frame.
    #[test]
    fn a_transition_page_activates_its_named_frame() {
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        transition(&mut pages, page, FRAME, PAGE_READWRITE);
        assert!(apply4(&mut pages, page, false, true));
        assert_eq!(pages.activated, vec![FRAME]);
        assert_eq!(
            pte::decode(pages.entry(page)),
            Some((PteKind::Present, FRAME, PAGE_READWRITE))
        );
        assert!(pages.freed.is_empty());
    }

    /// A present entry's frame and protection: what a scan reads off a page.
    fn present(va: u32, frame: u32, protect: u32) -> u32 {
        super::vm::encode(frame, protect) | (1 << 5) | (1 << 6)
    }

    /// A walk over a range whose chunks all have tables visits every page, in order.
    #[test]
    fn a_walk_visits_every_page_when_every_chunk_has_a_table() {
        let mut seen = Vec::new();
        let stop = walk_pages(0x1000, 0x1000 + 3 * PAGE, |_| true, |va| {
            seen.push(va);
            true
        });
        assert_eq!(seen, vec![0x1000, 0x1000 + PAGE, 0x1000 + 2 * PAGE]);
        assert_eq!(stop, 0x1000 + 3 * PAGE);
    }

    /// A walk skips a 4 MiB chunk whose table is absent whole: the pages inside are never read,
    /// and the walk resumes at the next chunk — one `chunk_live` read per chunk, not 1024.
    #[test]
    fn a_walk_skips_a_chunk_with_no_table_whole() {
        let mut chunk_reads = Vec::new();
        let mut seen = Vec::new();
        let start = CHUNK; // a chunk boundary
        let stop = walk_pages(start, start + 2 * CHUNK + PAGE, |va| {
            chunk_reads.push(va);
            va != start + CHUNK // the second chunk has no table
        }, |va| {
            seen.push(va);
            true
        });
        assert_eq!(chunk_reads, vec![start, start + CHUNK, start + 2 * CHUNK]);
        // The first chunk's 1024 pages were visited, the middle chunk's none, the third's first.
        let mut expected: Vec<u32> = (0..CHUNK / PAGE).map(|i| start + i * PAGE).collect();
        expected.push(start + 2 * CHUNK);
        assert_eq!(seen, expected);
        assert_eq!(stop, start + 2 * CHUNK + PAGE);
    }

    /// A scan collects the present pages of the chunks that have tables and skips the rest,
    /// stopping where the victims filled.
    #[test]
    fn a_scan_skips_chunkless_chunks_and_collects_present_pages() {
        use crate::mem::backing::Victim;
        let mut victims = [Victim { va: 0, frame: 0, protect: 0 }; 4];
        let entries = |va: u32| -> u32 {
            match va {
                0x2000 => present(0x2000, 0x0010_0000, PAGE_READWRITE),
                0x3000 => present(0x3000, 0x0020_0000, PAGE_READONLY),
                0x4000 => present(0x4000, 0x0030_0000, PAGE_READWRITE),
                va if va == 2 * CHUNK => present(2 * CHUNK, 0x0040_0000, PAGE_READWRITE),
                _ => 0,
            }
        };
        // The second chunk (at CHUNK) has no table: its pages are never read.
        let (count, stop) = scan_pages(&mut victims, 0, 2 * CHUNK + PAGE, entries, |va| va != CHUNK);
        assert_eq!(count, 4);
        assert_eq!(victims[0].va, 0x2000);
        assert_eq!(victims[0].frame, 0x0010_0000);
        assert_eq!(victims[0].protect, PAGE_READWRITE);
        assert_eq!(victims[1].va, 0x3000);
        assert_eq!(victims[2].va, 0x4000);
        assert_eq!(victims[3].va, 2 * CHUNK);
        assert_eq!(stop, 2 * CHUNK + PAGE);
        // With room for only two, the scan stops where the victims filled.
        let mut two = [Victim { va: 0, frame: 0, protect: 0 }; 2];
        let (count, stop) = scan_pages(&mut two, 0, 2 * CHUNK + PAGE, entries, |va| va != CHUNK);
        assert_eq!(count, 2);
        // The walk stops one page past the one where the victims filled.
        assert_eq!(stop, 0x4000 + PAGE);
    }
}
