//! Page-out in frame terms: eviction onto the frame database's Standby/Modified lists, a
//! threshold-triggered writer policy, and page-out/page-in against a backing-store trait.
//!
//! Eviction ([`to_standby`], [`to_modified`], [`to_modified_no_write`]) moves an in-use frame onto
//! one of the frame database's lists. The writer ([`PageWriter`]) queues dirty frames in eviction
//! order and, when a threshold trips ([`WriterPolicy::plan`]), writes a batch out, oldest first:
//! a page-out unlinks the frame from the Modified list, copies its page to a fresh backing-store
//! slot through [`PagingIo`], and releases the frame to Standby; a page-in reads a slot back into
//! a frame and releases the slot. The store holds one slot per page ([`SlotId`]; 0 is reserved);
//! the paging-file slice implements [`PagingIo`], tests use a fake. Frame contents are reached
//! through a [`FrameMemory`] accessor, so this module is pure bookkeeping: no unsafe, no hardware.

use super::frame::{FrameDb, FrameHooks, FrameId, FrameState, UnlinkOutcome};
use super::vm::PAGE;

/// Page size in bytes: the unit of every backing-store slot and frame-page access.
pub const PAGE_SIZE: usize = PAGE as usize;

/// A backing-store slot: one page.
pub type SlotId = u32;

/// The reserved slot value; never a valid slot.
pub const INVALID_SLOT: SlotId = 0;

/// Why a backing-store page transfer failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageIoError {
    /// The transfer failed; a failed write leaves the slot's contents undefined.
    Io,
}

/// The backing store's page-level I/O. The paging-file slice implements this over the boot
/// volume's paging file; tests use an in-memory fake.
pub trait PagingIo {
    /// Allocate a slot, or none when the store is full.
    fn allocate_slot(&mut self) -> Option<SlotId>;
    /// Write `page` (exactly [`PAGE_SIZE`] bytes) into `slot`.
    fn write(&mut self, slot: SlotId, page: &[u8]) -> Result<(), PageIoError>;
    /// Read `slot` into `page` (exactly [`PAGE_SIZE`] bytes).
    fn read(&mut self, slot: SlotId, page: &mut [u8]) -> Result<(), PageIoError>;
    /// Release `slot` back to the store.
    fn free_slot(&mut self, slot: SlotId);
}

/// Access to a frame's page contents. The kernel maps the frame into its scratch window; tests
/// use a flat per-frame page table (the fake frame source).
pub trait FrameMemory {
    /// Copy the frame's page into `page`.
    fn read_page(&mut self, frame: FrameId, page: &mut [u8]);
    /// Copy `page` into the frame's page.
    fn write_page(&mut self, frame: FrameId, page: &[u8]);
}

/// Why a page-out failed. On every failure the frame is left back on the Modified list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageOutError {
    /// The frame is not on the Modified list.
    NotModified,
    /// The frame has an I/O transfer in flight; it was left untouched on the list.
    Busy,
    /// The backing store has no free slot.
    NoSlot,
    /// The write failed; the slot was released and the frame went back to Modified.
    WriteFailed,
}

/// Why a page-in failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageInError {
    /// The frame is not an in-use, off-list frame.
    NotActive,
    /// The slot is [`INVALID_SLOT`].
    InvalidSlot,
    /// The read failed; the frame and the slot are left unchanged.
    ReadFailed,
}

/// Assert the frame is in use (off-list) and release it onto `state`'s list.
fn evict<H: FrameHooks>(db: &mut FrameDb<H>, frame: FrameId, state: FrameState) {
    assert_eq!(
        db.entry(frame).state,
        FrameState::Active,
        "evicting a frame that is not in use"
    );
    db.release(frame, state);
}

/// Move an in-use frame to the Standby list: a clean page evicted from its last mapping.
pub fn to_standby<H: FrameHooks>(db: &mut FrameDb<H>, frame: FrameId) {
    evict(db, frame, FrameState::Standby);
}

/// Move an in-use frame to the Modified list: a dirty page awaiting write-out.
pub fn to_modified<H: FrameHooks>(db: &mut FrameDb<H>, frame: FrameId) {
    evict(db, frame, FrameState::Modified);
}

/// Move an in-use frame to the ModifiedNoWrite list: dirty, but write-back is suppressed.
pub fn to_modified_no_write<H: FrameHooks>(db: &mut FrameDb<H>, frame: FrameId) {
    evict(db, frame, FrameState::ModifiedNoWrite);
}

/// Write one modified frame's page out to a fresh backing-store slot and move the frame to
/// Standby. Returns the slot holding the page; the caller records it where the page's mapping
/// can find it again (its soft page-table entry). On failure the frame is back on the Modified
/// list and no slot is held.
pub fn page_out<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
    db: &mut FrameDb<H>,
    io: &mut Io,
    mem: &mut Mem,
    buf: &mut [u8; PAGE_SIZE],
    frame: FrameId,
) -> Result<SlotId, PageOutError> {
    if db.entry(frame).state != FrameState::Modified {
        return Err(PageOutError::NotModified);
    }
    match db.unlink(frame) {
        UnlinkOutcome::Unlinked => {}
        UnlinkOutcome::Busy => return Err(PageOutError::Busy),
    }
    let slot = match io.allocate_slot() {
        Some(slot) => slot,
        None => {
            db.release(frame, FrameState::Modified);
            return Err(PageOutError::NoSlot);
        }
    };
    mem.read_page(frame, buf);
    match io.write(slot, buf) {
        Ok(()) => {
            db.release(frame, FrameState::Standby);
            Ok(slot)
        }
        Err(_) => {
            io.free_slot(slot);
            db.release(frame, FrameState::Modified);
            Err(PageOutError::WriteFailed)
        }
    }
}

/// Read `slot` back into the in-use `frame` and release the slot. The frame stays Active for the
/// caller to map. On a failed read the frame and slot are unchanged, so the caller can retry or
/// drop the backing with [`free_backing`].
pub fn page_in<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
    db: &mut FrameDb<H>,
    io: &mut Io,
    mem: &mut Mem,
    buf: &mut [u8; PAGE_SIZE],
    frame: FrameId,
    slot: SlotId,
) -> Result<(), PageInError> {
    if db.entry(frame).state != FrameState::Active {
        return Err(PageInError::NotActive);
    }
    if slot == INVALID_SLOT {
        return Err(PageInError::InvalidSlot);
    }
    io.read(slot, buf).map_err(|_| PageInError::ReadFailed)?;
    mem.write_page(frame, buf);
    io.free_slot(slot);
    Ok(())
}

/// Release a backing slot without any I/O, for a page whose backing is dropped (a standby page
/// overwritten or freed without being read back). [`INVALID_SLOT`] is a no-op.
pub fn free_backing<Io: PagingIo>(io: &mut Io, slot: SlotId) {
    if slot != INVALID_SLOT {
        io.free_slot(slot);
    }
}

/// The writer's thresholds. A pass runs when the available-frame count falls below `free_goal`
/// or the modified-list length reaches `modified_max`; a triggered pass writes out
/// `modified_count - modified_min` pages (at least one), capped at `batch_max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterPolicy {
    /// Available-frame goal: a pass runs below this count.
    pub free_goal: u32,
    /// Upper threshold on the modified list: a pass runs at or above this many modified pages.
    pub modified_max: u32,
    /// Lower threshold: a triggered pass writes the modified list down to this many pages.
    pub modified_min: u32,
    /// At most this many pages per pass.
    pub batch_max: u32,
}

/// A writer decision: whether to run a pass now and how many pages it writes out. The pass takes
/// the queued frames oldest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterPlan {
    /// Whether a write-out pass should run now.
    pub run: bool,
    /// How many modified pages the pass writes out (0 when `run` is false).
    pub count: u32,
}

/// What one writer pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PassReport {
    /// Frames written out and moved to Standby.
    pub written: u32,
    /// Frames whose page-out failed; back on the Modified list, re-queued at the tail.
    pub failed: u32,
    /// Queued frames no longer on the Modified list; dropped from the queue.
    pub skipped: u32,
}

impl WriterPolicy {
    /// Typical thresholds for a small-RAM machine.
    pub const TYPICAL: WriterPolicy = WriterPolicy::new(64, 512, 64, 128);

    /// Thresholds for the given goals; `modified_min` must not exceed `modified_max` and a pass
    /// always writes at least one page.
    pub const fn new(free_goal: u32, modified_max: u32, modified_min: u32, batch_max: u32) -> Self {
        assert!(
            modified_min <= modified_max,
            "modified_min must not exceed modified_max"
        );
        assert!(batch_max >= 1, "batch_max must be at least one");
        WriterPolicy {
            free_goal,
            modified_max,
            modified_min,
            batch_max,
        }
    }

    /// Decide the next pass from the available-frame count and the modified-list length.
    pub fn plan(&self, free_frames: u32, modified_count: u32) -> WriterPlan {
        let triggered = modified_count > 0
            && (free_frames < self.free_goal || modified_count >= self.modified_max);
        if !triggered {
            return WriterPlan {
                run: false,
                count: 0,
            };
        }
        let down_to = modified_count.saturating_sub(self.modified_min).max(1);
        WriterPlan {
            run: true,
            count: down_to.min(self.batch_max).min(modified_count),
        }
    }
}

/// The modified-page writer: the dirty frames queued in eviction order, plus the policy. The
/// queue is caller-owned storage, borrowed for the writer's lifetime like the frame database's
/// table (the kernel's is a static over the whole frame range; tests leak a small slice).
pub struct PageWriter {
    queue: &'static mut [FrameId],
    head: usize,
    len: usize,
    policy: WriterPolicy,
}

impl PageWriter {
    /// A writer over `queue` with the given `policy`. The queue must hold a full `modified_max`
    /// batch, so a policy-driven pass never overflows it.
    pub fn new(queue: &'static mut [FrameId], policy: WriterPolicy) -> Self {
        assert!(
            policy.modified_max as usize <= queue.len(),
            "the writer queue must hold a full modified_max batch"
        );
        PageWriter {
            queue,
            head: 0,
            len: 0,
            policy,
        }
    }

    /// The writer's thresholds.
    pub fn policy(&self) -> &WriterPolicy {
        &self.policy
    }

    /// Frames currently queued for write-out.
    pub fn queued(&self) -> usize {
        self.len
    }

    /// Append at the tail of the ring buffer.
    fn push(&mut self, frame: FrameId) {
        assert!(
            self.len < self.queue.len(),
            "writer queue full: run a pass first"
        );
        let idx = (self.head + self.len) % self.queue.len();
        self.queue[idx] = frame;
        self.len += 1;
    }

    /// Take the head of the ring buffer (the oldest queued frame).
    fn pop(&mut self) -> Option<FrameId> {
        if self.len == 0 {
            return None;
        }
        let frame = self.queue[self.head];
        self.head = (self.head + 1) % self.queue.len();
        self.len -= 1;
        Some(frame)
    }

    /// Evict a clean page to Standby.
    pub fn evict_clean<H: FrameHooks>(&mut self, db: &mut FrameDb<H>, frame: FrameId) {
        to_standby(db, frame);
    }

    /// Evict a dirty page to the Modified list and queue it at the tail, so a pass writes the
    /// oldest dirty page first.
    pub fn evict_dirty<H: FrameHooks>(&mut self, db: &mut FrameDb<H>, frame: FrameId) {
        to_modified(db, frame);
        self.push(frame);
    }

    /// Evict a dirty page whose write-back is suppressed; it is not queued.
    pub fn evict_no_write<H: FrameHooks>(&mut self, db: &mut FrameDb<H>, frame: FrameId) {
        to_modified_no_write(db, frame);
    }

    /// The writer's decision for the given counts.
    pub fn plan(&self, free_frames: u32, modified_count: u32) -> WriterPlan {
        self.policy.plan(free_frames, modified_count)
    }

    /// Run one pass, decided from the database's current counts.
    pub fn run_pass<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
        &mut self,
        db: &mut FrameDb<H>,
        io: &mut Io,
        mem: &mut Mem,
        buf: &mut [u8; PAGE_SIZE],
    ) -> PassReport {
        let plan = self
            .policy
            .plan(db.available(), db.list_total(FrameState::Modified));
        self.run_planned(db, io, mem, buf, plan)
    }

    /// Run a decided pass: write out up to `plan.count` queued frames, oldest first.
    pub fn run_planned<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
        &mut self,
        db: &mut FrameDb<H>,
        io: &mut Io,
        mem: &mut Mem,
        buf: &mut [u8; PAGE_SIZE],
        plan: WriterPlan,
    ) -> PassReport {
        let mut report = PassReport::default();
        let mut remaining = if plan.run { plan.count } else { 0 };
        while remaining > 0 {
            let Some(frame) = self.pop() else { break };
            remaining -= 1;
            if db.entry(frame).state != FrameState::Modified {
                report.skipped += 1;
                continue;
            }
            match page_out(db, io, mem, buf, frame) {
                Ok(_slot) => report.written += 1,
                Err(_) => {
                    // page_out left the frame back on the Modified list; retry it later.
                    report.failed += 1;
                    self.push(frame);
                }
            }
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::frame::{
        ColorTables,
        FrameEntry,
        NoHooks,
        UnlinkOutcome,
        DEFAULT_COLOR_COUNT,
        PRIMARY_COLOR,
    };

    const TABLE: usize = 64;

    fn new_db() -> FrameDb<NoHooks> {
        let table: &'static mut [FrameEntry] =
            Box::leak(vec![FrameEntry::new(); TABLE].into_boxed_slice());
        let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
        FrameDb::new(table, buckets, DEFAULT_COLOR_COUNT, NoHooks)
    }

    fn new_writer(policy: WriterPolicy) -> PageWriter {
        let queue: &'static mut [FrameId] = Box::leak(vec![0; 256].into_boxed_slice());
        PageWriter::new(queue, policy)
    }

    /// Shorthand so plan asserts stay on one line.
    fn want_plan(run: bool, count: u32) -> WriterPlan {
        WriterPlan { run, count }
    }

    /// Shorthand so pass-report asserts stay on one line.
    fn want_report(written: u32, failed: u32, skipped: u32) -> PassReport {
        PassReport {
            written,
            failed,
            skipped,
        }
    }

    /// The fake backing store: one page per slot, slot 0 reserved. A slot is allocated before
    /// its page is written, so a failed write still leaves the slot held (and releasable).
    struct FakeIo {
        allocated: Vec<bool>,
        pages: Vec<Option<[u8; PAGE_SIZE]>>,
        fail_writes: bool,
        fail_reads: bool,
        write_order: Vec<SlotId>,
        freed: Vec<SlotId>,
    }

    impl FakeIo {
        fn new(capacity: u32) -> Self {
            FakeIo {
                allocated: vec![false; capacity as usize + 1], // slot 0 never used
                pages: vec![None; capacity as usize + 1],
                fail_writes: false,
                fail_reads: false,
                write_order: Vec::new(),
                freed: Vec::new(),
            }
        }

        fn used_slots(&self) -> usize {
            self.allocated.iter().filter(|&&a| a).count()
        }

        fn page(&self, slot: SlotId) -> [u8; PAGE_SIZE] {
            self.pages[slot as usize].expect("slot holds a page")
        }
    }

    impl PagingIo for FakeIo {
        fn allocate_slot(&mut self) -> Option<SlotId> {
            (1..self.allocated.len() as SlotId)
                .find(|&s| !self.allocated[s as usize])
                .inspect(|&s| self.allocated[s as usize] = true)
        }

        fn write(&mut self, slot: SlotId, page: &[u8]) -> Result<(), PageIoError> {
            assert_eq!(page.len(), PAGE_SIZE);
            assert!(self.allocated[slot as usize], "writing an unallocated slot");
            if self.fail_writes {
                return Err(PageIoError::Io);
            }
            self.pages[slot as usize] = Some(<[u8; PAGE_SIZE]>::try_from(page).unwrap());
            self.write_order.push(slot);
            Ok(())
        }

        fn read(&mut self, slot: SlotId, page: &mut [u8]) -> Result<(), PageIoError> {
            assert_eq!(page.len(), PAGE_SIZE);
            if self.fail_reads {
                return Err(PageIoError::Io);
            }
            let data = self.pages[slot as usize].ok_or(PageIoError::Io)?;
            page.copy_from_slice(&data);
            Ok(())
        }

        fn free_slot(&mut self, slot: SlotId) {
            assert!(slot != INVALID_SLOT && self.allocated[slot as usize]);
            self.allocated[slot as usize] = false;
            self.pages[slot as usize] = None;
            self.freed.push(slot);
        }
    }

    /// The fake frame source: a flat page per frame.
    struct FakeMem {
        pages: Vec<[u8; PAGE_SIZE]>,
    }

    impl FakeMem {
        fn new() -> Self {
            FakeMem {
                pages: vec![[0u8; PAGE_SIZE]; TABLE],
            }
        }

        fn fill(&mut self, frame: FrameId, byte: u8) {
            self.pages[frame as usize] = [byte; PAGE_SIZE];
        }

        fn pattern() -> [u8; PAGE_SIZE] {
            let mut page = [0u8; PAGE_SIZE];
            for (i, b) in page.iter_mut().enumerate() {
                *b = i as u8;
            }
            page
        }

        fn fill_pattern(&mut self, frame: FrameId) {
            self.pages[frame as usize] = Self::pattern();
        }

        fn page(&self, frame: FrameId) -> [u8; PAGE_SIZE] {
            self.pages[frame as usize]
        }
    }

    impl FrameMemory for FakeMem {
        fn read_page(&mut self, frame: FrameId, page: &mut [u8]) {
            assert_eq!(page.len(), PAGE_SIZE);
            page.copy_from_slice(&self.pages[frame as usize]);
        }

        fn write_page(&mut self, frame: FrameId, page: &[u8]) {
            assert_eq!(page.len(), PAGE_SIZE);
            self.pages[frame as usize].copy_from_slice(page);
        }
    }

    /// The common fixture: a database, a fake store, a fake frame source, a page buffer.
    struct Rig {
        db: FrameDb<NoHooks>,
        io: FakeIo,
        mem: FakeMem,
        buf: [u8; PAGE_SIZE],
    }

    impl Rig {
        fn new(io_capacity: u32) -> Self {
            Rig {
                db: new_db(),
                io: FakeIo::new(io_capacity),
                mem: FakeMem::new(),
                buf: [0u8; PAGE_SIZE],
            }
        }

        fn out(&mut self, frame: FrameId) -> Result<SlotId, PageOutError> {
            page_out(
                &mut self.db,
                &mut self.io,
                &mut self.mem,
                &mut self.buf,
                frame,
            )
        }

        fn page_in(&mut self, frame: FrameId, slot: SlotId) -> Result<(), PageInError> {
            page_in(
                &mut self.db,
                &mut self.io,
                &mut self.mem,
                &mut self.buf,
                frame,
                slot,
            )
        }
    }

    #[test]
    fn eviction_moves_a_frame_onto_the_matching_list() {
        let mut db = new_db();
        to_standby(&mut db, 3);
        assert_eq!(db.entry(3).state, FrameState::Standby);
        assert_eq!(db.list_total(FrameState::Standby), 1);
        assert_eq!(db.available(), 1);

        to_modified(&mut db, 4);
        assert_eq!(db.entry(4).state, FrameState::Modified);
        assert_eq!(db.list_total(FrameState::Modified), 1);
        assert_eq!(db.available(), 1, "a modified page is not available");

        to_modified_no_write(&mut db, 5);
        assert_eq!(db.entry(5).state, FrameState::ModifiedNoWrite);
        assert_eq!(db.list_total(FrameState::ModifiedNoWrite), 1);
        assert_eq!(db.audit(), Ok(()));
    }

    #[test]
    #[should_panic(expected = "not in use")]
    fn evicting_a_listed_frame_panics() {
        let mut db = new_db();
        to_standby(&mut db, 3);
        to_modified(&mut db, 3);
    }

    #[test]
    fn writer_plan_runs_below_the_free_goal() {
        let policy = WriterPolicy::new(10, 100, 4, 8);
        // 9 available < goal 10: run, writing 20 modified down towards 4, capped by batch 8.
        assert_eq!(policy.plan(9, 20), want_plan(true, 8));
    }

    #[test]
    fn writer_plan_runs_at_the_modified_max_but_stays_idle_between_thresholds() {
        let policy = WriterPolicy::new(10, 16, 4, 64);
        // Free frames are fine (500 >= goal 10); the modified list at its max triggers the pass.
        assert_eq!(policy.plan(500, 16), want_plan(true, 12));
        assert_eq!(policy.plan(500, 15), want_plan(false, 0));
        assert_eq!(policy.plan(50, 0), want_plan(false, 0), "nothing to write");
    }

    #[test]
    fn writer_plan_caps_the_batch_and_writes_at_least_one() {
        let policy = WriterPolicy::new(10, 100, 4, 3);
        assert_eq!(policy.plan(9, 20), want_plan(true, 3));
        assert_eq!(policy.plan(9, 5), want_plan(true, 1));
        assert_eq!(policy.plan(9, 1), want_plan(true, 1));
        let wide = WriterPolicy::new(1, 100, 0, 100);
        assert_eq!(
            wide.plan(0, 3),
            want_plan(true, 3),
            "never more than modified"
        );
    }

    #[test]
    #[should_panic(expected = "modified_min")]
    fn policy_rejects_min_above_max() {
        WriterPolicy::new(1, 4, 5, 1);
    }

    #[test]
    #[should_panic(expected = "batch_max")]
    fn policy_rejects_an_empty_batch() {
        WriterPolicy::new(1, 4, 1, 0);
    }

    #[test]
    #[should_panic(expected = "queue")]
    fn writer_rejects_a_queue_smaller_than_modified_max() {
        let queue: &'static mut [FrameId] = Box::leak(vec![0; 4].into_boxed_slice());
        PageWriter::new(queue, WriterPolicy::new(1, 8, 1, 1));
    }

    #[test]
    fn page_out_writes_the_page_and_moves_the_frame_to_standby() {
        let mut rig = Rig::new(4);
        rig.mem.fill(7, 0xAB);
        to_modified(&mut rig.db, 7);
        let slot = rig.out(7).expect("page-out");
        assert_ne!(slot, INVALID_SLOT);
        assert_eq!(rig.io.page(slot), [0xAB; PAGE_SIZE]);
        assert_eq!(rig.db.entry(7).state, FrameState::Standby);
        assert_eq!(rig.db.list_total(FrameState::Modified), 0);
        assert_eq!(rig.db.available(), 1, "a standby page is available again");
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn page_out_without_a_free_slot_leaves_the_frame_modified() {
        let mut rig = Rig::new(0); // no slots at all
        to_modified(&mut rig.db, 7);
        assert_eq!(rig.out(7), Err(PageOutError::NoSlot));
        assert_eq!(rig.db.entry(7).state, FrameState::Modified);
        assert_eq!(rig.io.used_slots(), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn page_out_write_failure_releases_the_slot_and_returns_to_modified() {
        let mut rig = Rig::new(2);
        rig.io.fail_writes = true;
        to_modified(&mut rig.db, 7);
        assert_eq!(rig.out(7), Err(PageOutError::WriteFailed));
        assert_eq!(rig.db.entry(7).state, FrameState::Modified);
        assert_eq!(
            rig.io.freed.len(),
            1,
            "the slot taken for the failed write is released"
        );
        assert_eq!(rig.io.used_slots(), 0);
        assert!(
            rig.io.allocate_slot().is_some(),
            "the released slot is reusable"
        );
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn page_out_rejects_a_frame_that_is_not_modified() {
        let mut rig = Rig::new(2);
        to_standby(&mut rig.db, 7);
        assert_eq!(rig.out(7), Err(PageOutError::NotModified));
        assert_eq!(rig.db.entry(7).state, FrameState::Standby);

        to_modified_no_write(&mut rig.db, 8);
        assert_eq!(
            rig.out(8),
            Err(PageOutError::NotModified),
            "never written out"
        );

        assert_eq!(
            rig.out(9),
            Err(PageOutError::NotModified),
            "an in-use frame is off-list"
        );
        assert_eq!(rig.io.used_slots(), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn page_out_then_page_in_restores_the_bytes_and_releases_the_slot() {
        let mut rig = Rig::new(4);

        // A dirty page with a known pattern is evicted and written out.
        rig.mem.fill_pattern(7);
        to_modified(&mut rig.db, 7);
        let slot = rig.out(7).expect("page-out");
        assert_eq!(rig.db.entry(7).state, FrameState::Standby);

        // The frame is reused for something else and zeroed.
        let frame = rig.db.allocate_zeroed(PRIMARY_COLOR);
        assert_eq!(frame, 7, "the only standby frame is reused");
        rig.mem.fill(frame, 0);

        // The page is faulted back in from its slot.
        rig.page_in(frame, slot).expect("page-in");
        assert_eq!(
            rig.mem.page(frame),
            FakeMem::pattern(),
            "the round trip preserves the bytes"
        );
        assert!(rig.io.freed.contains(&slot), "page-in releases the slot");
        assert_eq!(rig.io.used_slots(), 0);
        assert_eq!(
            rig.io.allocate_slot(),
            Some(slot),
            "the released slot is reusable"
        );
        assert_eq!(rig.db.entry(frame).state, FrameState::Active);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn page_in_read_failure_leaves_frame_and_slot_untouched() {
        let mut rig = Rig::new(4);
        rig.mem.fill(7, 0x5A);
        to_modified(&mut rig.db, 7);
        let slot = rig.out(7).expect("page-out");

        let frame = rig.db.allocate_zeroed(PRIMARY_COLOR);
        rig.mem.fill(frame, 0xEE);
        rig.io.fail_reads = true;
        assert_eq!(rig.page_in(frame, slot), Err(PageInError::ReadFailed));
        assert_eq!(
            rig.mem.page(frame),
            [0xEE; PAGE_SIZE],
            "the frame is unchanged"
        );
        assert_eq!(rig.io.used_slots(), 1, "the slot is kept for a retry");
        assert!(rig.io.freed.is_empty());
    }

    #[test]
    fn page_in_rejects_a_listed_frame_and_the_invalid_slot() {
        let mut rig = Rig::new(2);
        to_standby(&mut rig.db, 7);
        assert_eq!(rig.page_in(7, 1), Err(PageInError::NotActive));
        // Frame 8 was never listed: it is in use.
        assert_eq!(rig.page_in(8, INVALID_SLOT), Err(PageInError::InvalidSlot));
    }

    #[test]
    fn free_backing_releases_a_slot_without_io() {
        let mut io = FakeIo::new(2);
        let slot = io.allocate_slot().unwrap();
        io.write(slot, &[0x55; PAGE_SIZE]).unwrap();
        free_backing(&mut io, slot);
        assert_eq!(io.used_slots(), 0);
        assert_eq!(io.freed, vec![slot]);
        free_backing(&mut io, INVALID_SLOT);
        assert_eq!(io.freed.len(), 1, "the invalid slot is a no-op");
    }

    #[test]
    fn a_pass_writes_the_oldest_modified_pages_first() {
        let mut rig = Rig::new(8);
        let policy = WriterPolicy::new(20, 100, 0, 2); // batch of 2
        let mut writer = new_writer(policy);

        // Some free frames, so the free count alone does not trigger a pass.
        for f in 20..50u32 {
            rig.db.release(f, FrameState::Free);
        }
        assert_eq!(rig.db.available(), 30);

        for (i, f) in [10u32, 11, 12].iter().enumerate() {
            rig.mem.fill(*f, 0xA0 + i as u8);
            writer.evict_dirty(&mut rig.db, *f);
        }
        assert_eq!(writer.queued(), 3);

        // Free frames are fine and the modified list is below its max: the policy stays idle.
        let plan = writer.plan(rig.db.available(), rig.db.list_total(FrameState::Modified));
        assert_eq!(plan, want_plan(false, 0));

        let report = writer.run_planned(
            &mut rig.db,
            &mut rig.io,
            &mut rig.mem,
            &mut rig.buf,
            want_plan(true, 2),
        );
        assert_eq!(report, want_report(2, 0, 0));
        assert_eq!(
            rig.io.page(rig.io.write_order[0]),
            [0xA0; PAGE_SIZE],
            "frame 10 went first"
        );
        assert_eq!(
            rig.io.page(rig.io.write_order[1]),
            [0xA1; PAGE_SIZE],
            "then frame 11"
        );
        assert_eq!(rig.db.entry(10).state, FrameState::Standby);
        assert_eq!(rig.db.entry(11).state, FrameState::Standby);
        assert_eq!(
            rig.db.entry(12).state,
            FrameState::Modified,
            "not in this batch"
        );
        assert_eq!(writer.queued(), 1);
        assert_eq!(rig.db.audit(), Ok(()));

        // Draw the available count below the goal; the next pass picks up the remaining frame.
        while rig.db.available() >= 20 {
            rig.db.allocate(PRIMARY_COLOR);
        }
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, want_report(1, 0, 0));
        assert_eq!(rig.db.entry(12).state, FrameState::Standby);
        assert_eq!(writer.queued(), 0);
        assert_eq!(rig.db.list_total(FrameState::Modified), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn run_pass_follows_the_policy_thresholds() {
        let mut rig = Rig::new(8);
        let policy = WriterPolicy::new(10, 100, 2, 8);
        let mut writer = new_writer(policy);
        for f in [10u32, 11, 12] {
            writer.evict_dirty(&mut rig.db, f);
        }
        // 0 available < goal 10: run, writing 3 modified down towards 2 -> 1 page.
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, want_report(1, 0, 0));
        assert_eq!(rig.db.list_total(FrameState::Modified), 2);
        // 1 available < 10: one more page down to the floor; then the last one (at least one).
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, want_report(1, 0, 0));
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, want_report(1, 0, 0));
        assert_eq!(rig.db.list_total(FrameState::Modified), 0);
        assert_eq!(writer.queued(), 0);
        // Nothing left modified: the policy goes idle even below the free goal.
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, PassReport::default());
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn a_pass_skips_frames_no_longer_modified_and_requeues_failures() {
        let mut rig = Rig::new(8);
        let policy = WriterPolicy::new(100, 100, 0, 10);
        let mut writer = new_writer(policy);
        rig.mem.fill(10, 0x10);
        rig.mem.fill(12, 0x12);
        writer.evict_dirty(&mut rig.db, 10);
        writer.evict_dirty(&mut rig.db, 11);
        writer.evict_dirty(&mut rig.db, 12);
        // Frame 11 is re-activated behind the writer's back.
        assert_eq!(rig.db.unlink(11), UnlinkOutcome::Unlinked);

        rig.io.fail_writes = true;
        let plan = want_plan(true, 3);
        let report = writer.run_planned(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf, plan);
        assert_eq!(report, want_report(0, 2, 1));
        assert_eq!(rig.db.entry(10).state, FrameState::Modified);
        assert_eq!(rig.db.entry(12).state, FrameState::Modified);
        assert_eq!(writer.queued(), 2, "the failures are re-queued");

        rig.io.fail_writes = false;
        let plan = want_plan(true, 2);
        let report = writer.run_planned(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf, plan);
        assert_eq!(report, want_report(2, 0, 0));
        assert_eq!(
            rig.io.page(rig.io.write_order[0]),
            [0x10; PAGE_SIZE],
            "oldest failure first"
        );
        assert_eq!(rig.io.page(rig.io.write_order[1]), [0x12; PAGE_SIZE]);
        assert_eq!(rig.db.list_total(FrameState::Modified), 0);
        assert_eq!(writer.queued(), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn a_pass_with_a_full_store_fails_the_rest_and_keeps_them_queued() {
        let mut rig = Rig::new(1); // one slot
        let policy = WriterPolicy::new(100, 100, 0, 10);
        let mut writer = new_writer(policy);
        writer.evict_dirty(&mut rig.db, 10);
        writer.evict_dirty(&mut rig.db, 11);
        let plan = want_plan(true, 2);
        let report = writer.run_planned(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf, plan);
        assert_eq!(report, want_report(1, 1, 0));
        assert_eq!(rig.db.entry(10).state, FrameState::Standby);
        assert_eq!(
            rig.db.entry(11).state,
            FrameState::Modified,
            "no slot: back to modified"
        );
        assert_eq!(writer.queued(), 1);

        // Free the written slot; the next pass completes the second frame.
        let written_slot = rig.io.write_order[0];
        free_backing(&mut rig.io, written_slot);
        let plan = want_plan(true, 1);
        let report = writer.run_planned(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf, plan);
        assert_eq!(report, want_report(1, 0, 0));
        assert_eq!(rig.db.list_total(FrameState::Modified), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }

    #[test]
    fn the_writer_evicts_clean_and_no_write_pages_without_queueing_them() {
        let mut rig = Rig::new(8);
        let policy = WriterPolicy::new(100, 100, 0, 10);
        let mut writer = new_writer(policy);
        writer.evict_clean(&mut rig.db, 10);
        writer.evict_no_write(&mut rig.db, 11);
        assert_eq!(rig.db.entry(10).state, FrameState::Standby);
        assert_eq!(rig.db.entry(11).state, FrameState::ModifiedNoWrite);
        assert_eq!(writer.queued(), 0);

        // Available (1) is below the goal, but nothing is on the modified list: idle.
        let report = writer.run_pass(&mut rig.db, &mut rig.io, &mut rig.mem, &mut rig.buf);
        assert_eq!(report, PassReport::default());
        assert_eq!(
            rig.db.entry(11).state,
            FrameState::ModifiedNoWrite,
            "never written out"
        );
        assert_eq!(rig.io.used_slots(), 0);
        assert_eq!(rig.db.audit(), Ok(()));
    }
}
