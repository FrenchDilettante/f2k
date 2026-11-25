//! Backing-store page-in and pressure relief: the fault resolutions that need I/O — a private
//! page's slot in the paging file, a section's page — plus the page-out pass that makes room.
//!
//! The entries are the address-space manager's to write ([`vm::Pages`]); a soft entry carries its
//! backing in its tag and payload bits: [`vm::TAG_PAGE_FILE`] names the paging-file slot (counted
//! from one) holding a private page that was paged out, [`vm::TAG_PROTOTYPE`] names a section's
//! page (its index), and [`vm::TAG_TRANSITION`] names the frame a page still holds on a backing
//! list (mapped back by [`super::demand`], no I/O).
//!
//! [`apply`] applies the two I/O arms: [`page_file_in`] decodes the slot from the entry and reads
//! it back into a fresh frame through [`pageout::page_in`], [`section_in`] reads the section's
//! page from its backing; each maps the page present with the entry's protection. When no frame
//! is left, the relief hook runs once and the allocation is retried once.
//!
//! The relief itself is working-set driven and lives with the fault path: the vector-14 hook in
//! `user::seh` runs [`super::wstrim::relieve_pressure`] over the current process's working set,
//! and the staged page-out of the victims it selects is [`super::demand::target`] on the target.
//! [`relieve_pass`] below is the host-tested twin of that pass over an explicit page range.

// The pure arms are driven by the host tests; the target runs its own staged driver (the level
// rules split a pass around the paging file's lock), so on the target build they see only tests.
#![cfg_attr(not(test), allow(dead_code))]

use super::frame::{FrameDb, FrameHooks, FrameState};
use super::pageout::{self, FrameMemory, PageWriter, PagingIo, SlotId, PAGE_SIZE};
use super::phys::PhysAddr;
use super::vm::{self, Pages, PAGE};

/// The paging-file slot a [`vm::TAG_PAGE_FILE`] entry names (bits 12-31 hold it counted from one).
pub fn slot_of(entry: u32) -> SlotId {
    vm::backing_payload(entry) >> 12
}

/// The section page index a [`vm::TAG_PROTOTYPE`] entry names (bits 12-31 hold it).
pub fn section_index_of(entry: u32) -> u32 {
    vm::backing_payload(entry) >> 12
}

/// Where a section's page comes from on a fault: its bytes, a page at a time.
pub trait SectionPages {
    /// Section page `index` into `buf` (a whole page; bytes past the backing's end read as zero).
    /// False on an I/O failure.
    fn read_page(&mut self, index: u32, buf: &mut [u8; PAGE_SIZE]) -> bool;
}

/// The PageFile arm: decode the slot from the entry, read it back from the store into a fresh
/// frame ([`pageout::page_in`], which releases the slot), and map the page present with the
/// entry's protection. When no frame is left, `relieve` runs once and the allocation is retried
/// once; false when no frame was left even then, or the read failed (the frame is given back, the
/// entry as it was).
pub fn page_file_in<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
    db: &mut FrameDb<H>,
    io: &mut Io,
    mem: &mut Mem,
    buf: &mut [u8; PAGE_SIZE],
    pages: &mut impl Pages,
    page: u32,
    entry: u32,
    relieve: &mut impl FnMut() -> bool,
) -> bool {
    let slot = slot_of(entry);
    let protect = vm::soft_protect(entry);
    let frame = match fresh_frame(pages, relieve) {
        Some(frame) => frame,
        None => return false,
    };
    if pageout::page_in(db, io, mem, buf, PhysAddr::new(frame).pfn(), slot).is_err() {
        pages.free_frame(frame);
        return false;
    }
    vm::map_named_frame(pages, page, frame, protect);
    true
}

/// The Section arm: read the section's page `index` from `source` into a fresh frame and map the
/// page present with the entry's protection (a copy-on-write protection maps held back, so the
/// first write severs it through [`super::demand`]). Same relief-and-retry for the frame; false
/// when the read failed (the frame is given back, the entry as it was).
pub fn section_in<S: SectionPages>(
    pages: &mut impl Pages,
    source: &mut S,
    page: u32,
    entry: u32,
    relieve: &mut impl FnMut() -> bool,
) -> bool {
    let index = section_index_of(entry);
    let protect = vm::soft_protect(entry);
    let frame = match fresh_frame(pages, relieve) {
        Some(frame) => frame,
        None => return false,
    };
    let mut buf = [0u8; PAGE_SIZE];
    if !source.read_page(index, &mut buf) {
        pages.free_frame(frame);
        return false;
    }
    pages.fill_frame(frame, &buf);
    vm::map_named_frame(pages, page, frame, protect);
    true
}

/// A fresh zeroed frame, or none: when the allocator finds none, `relieve` runs once and the
/// allocation is retried once.
fn fresh_frame(pages: &mut impl Pages, relieve: &mut impl FnMut() -> bool) -> Option<u32> {
    if let Some(frame) = pages.zeroed_frame() {
        return Some(frame);
    }
    if !relieve() {
        return None;
    }
    pages.zeroed_frame()
}

/// One victim of a relief pass: a page evicted from its mapping.
#[derive(Clone, Copy, Debug)]
pub struct Victim {
    /// The page's base address.
    pub va: u32,
    /// The frame its entry named.
    pub frame: u32,
    /// The protection its entry recorded.
    pub protect: u32,
}

/// One pressure-relief pass over the pages `[start, end)`: every present, unshared page of a
/// private region (`private(va)`) found there is evicted into `victims` — its entry softened to a
/// transition one, its frame marked modified ([`pageout::to_modified`]) and queued to `writer` —
/// and the writer pass then writes the queued pages out to the store, each entry becoming a
/// paging-file one naming the slot its page holds (a page re-faulted meanwhile keeps its frame and
/// the slot is released). Returns how many frames the pass made available (moved to Standby).
pub fn relieve_pass<H: FrameHooks, Io: PagingIo, Mem: FrameMemory>(
    db: &mut FrameDb<H>,
    pages: &mut impl Pages,
    io: &mut Io,
    mem: &mut Mem,
    buf: &mut [u8; PAGE_SIZE],
    writer: &mut PageWriter,
    start: u32,
    end: u32,
    private: &impl Fn(u32) -> bool,
    want: u32,
    victims: &mut [Victim],
) -> u32 {
    // Phase 1: find the victims.
    let mut count = 0;
    let mut va = start;
    while va < end && count < victims.len() && db.available() < want {
        let entry = pages.entry(va);
        if entry & vm::PTE_PRESENT != 0 {
            let frame = entry & vm::PTE_FRAME_MASK;
            if frame != 0 && !pages.frame_shared(frame) && private(va) {
                let protect = vm::decode(entry)
                    .map(|(_, protect)| protect)
                    .unwrap_or_else(|| vm::soft_protect(entry));
                victims[count] = Victim { va, frame, protect };
                count += 1;
            }
        }
        va += PAGE;
    }
    // Evict: the frame to the Modified list and the writer's queue, the entry softened.
    let mut kept = 0;
    for index in 0..count {
        let victim = victims[index];
        let fid = PhysAddr::new(victim.frame).pfn();
        match db.entry(fid).state {
            FrameState::Active => writer.evict_dirty(db, fid),
            FrameState::Modified => writer.requeue(fid),
            _ => continue,
        }
        vm::soften_to_transition(pages, victim.va, victim.frame, victim.protect);
        victims[kept] = victim;
        kept += 1;
    }
    // Phase 2: the writer pass, each written-out page's entry rewritten to name its slot.
    let plan = writer
        .policy()
        .plan(db.available(), db.list_total(FrameState::Modified));
    let mut freed = 0u32;
    writer.run_planned_report(db, io, mem, buf, plan, &mut |fid, slot| {
        let frame = fid.addr().get();
        let Some(victim) = victims[..kept].iter().find(|victim| victim.frame == frame) else {
            return false;
        };
        let current = pages.entry(victim.va);
        if vm::backing_tag(current) == vm::TAG_TRANSITION && vm::backing_payload(current) == frame {
            vm::name_page_file(pages, victim.va, slot, victim.protect);
            freed += 1;
            true
        } else {
            false
        }
    });
    freed
}

/// Apply a faulting access at `va` whose resolution needs backing-store I/O — `write` for a
/// store, `user` when it came from ring 3: the PageFile and Section arms above. True when the page
/// is mapped present now and the access can resume. On the target this runs the staged driver
/// ([`target`]); on host builds the arms are pure and the tests drive them directly.
pub fn apply(
    pages: &mut impl Pages,
    va: u32,
    write: bool,
    user: bool,
    relieve: &mut impl FnMut() -> bool,
) -> bool {
    #[cfg(target_arch = "x86")]
    {
        target::apply(pages, va, write, user, relieve)
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = (pages, va, write, user, relieve);
        false
    }
}

// --- The staged backing arms (target) -----------------------------------------------------------
//
// The PageFile and Section arms' staging on the target, driven from here: the paging file's
// disk I/O cannot run inside a borrow of the memory manager's database (see
// [`crate::mem::demand::target`]), so each arm stages around the paging file's lock. The relief
// itself lives there — it is what a demand map runs when no frame is left.

#[cfg(target_arch = "x86")]
pub mod target {
    use super::{section_index_of, slot_of};
    use crate::mem::demand::target::PageBuf;
    use crate::mem::fault::{self, Resolution};
    use crate::mem::pageout::PAGE_SIZE;
    use crate::mem::pagingfile::{with_paging_file, PagingFileIo};
    use crate::mem::vm::{self, Kind, Pages, PAGE, USER_HIGH};

    /// A fresh zeroed frame, or none: when the allocator finds none, `relieve` runs once and the
    /// allocation is retried once.
    fn fresh_frame(pages: &mut impl Pages, relieve: &mut impl FnMut() -> bool) -> Option<u32> {
        if let Some(frame) = pages.zeroed_frame() {
            return Some(frame);
        }
        if !relieve() {
            return None;
        }
        pages.zeroed_frame()
    }

    /// The PageFile arm on the target: the slot's page read back into a fresh frame through the
    /// paging file (staged: the slot is read into a claimed buffer and released, then the buffer
    /// is copied into the frame), the page mapped present with the entry's protection.
    fn page_file_in(
        pages: &mut impl Pages,
        page: u32,
        entry: u32,
        relieve: &mut impl FnMut() -> bool,
    ) -> bool {
        let slot = slot_of(entry);
        let protect = vm::soft_protect(entry);
        let Some(frame) = fresh_frame(pages, relieve) else {
            return false;
        };
        let mut buf = match PageBuf::claim() {
            Some(buf) => buf,
            None => {
                pages.free_frame(frame);
                return false;
            }
        };
        let read = with_paging_file(|file| {
            let slot = u64::from(slot);
            if !file.is_allocated(slot) {
                return false;
            }
            if file.read_page(slot, buf.as_mut()).is_err() {
                return false;
            }
            file.free_slot(slot);
            true
        })
        .unwrap_or(false);
        if !read {
            pages.free_frame(frame);
            return false;
        }
        pages.fill_frame(frame, buf.as_ref());
        vm::map_named_frame(pages, page, frame, protect);
        true
    }

    /// What a section's page is read from on a fault: the section of the view holding `page`.
    struct SectionInfo {
        paging_file: bool,
        file: crate::fs::fat32::lookup::File,
        record: Option<crate::fs::file::FileRecordId>,
    }

    impl SectionInfo {
        /// The section of the view whose region holds `page`; none for an address no data view
        /// holds (an image's view is mapped eagerly).
        fn of_page(page: u32) -> Option<SectionInfo> {
            let process = crate::process::pool::address_space();
            let mapping = process.with_space(|space| {
                let region = space.region_at(page)?;
                if !matches!(region.kind, Kind::Mapped(_)) {
                    return None;
                }
                space.view_at(region.base)
            })?;
            let crate::ob::Mapping::Section(id) = mapping else {
                return None;
            };
            let (paging_file, file, file_object) = crate::ob::locked(|directory| {
                directory
                    .section(id)
                    .map(|section| (section.paging_file, section.file, section.file_object))
            })?;
            let record = file_object.and_then(|object| {
                crate::ob::locked(|directory| directory.file(object).and_then(|file| file.disk()))
            });
            Some(SectionInfo {
                paging_file,
                file,
                record,
            })
        }

        /// Section page `index` into `buf`: a paging-file section's page comes from the store (a
        /// fresh slot reads as zeros); a file's from the file at the page's offset, the rest of
        /// the page zero.
        fn read_page(&self, index: u32, buf: &mut [u8; PAGE_SIZE]) -> bool {
            if self.paging_file {
                with_paging_file(|file| {
                    let Some(slot) = file.allocate_slot() else {
                        return false;
                    };
                    let read = file.read_page(slot, buf);
                    if file.is_allocated(slot) {
                        file.free_slot(slot);
                    }
                    read.is_ok()
                })
                .unwrap_or(false)
            } else {
                let file = match self.record {
                    Some(record) => crate::fs::io::file_at(record),
                    None => self.file,
                };
                let offset = index * PAGE;
                let len = file.size.saturating_sub(offset).min(PAGE) as usize;
                len > 0 && crate::fs::io::read_file_at(&file, offset, &mut buf[..len]).is_some()
            }
        }
    }

    /// The Section arm on the target: the section's page `index` read from its backing (staged
    /// like the PageFile arm's), copied into a fresh frame, mapped present with the entry's
    /// protection.
    fn section_in(
        pages: &mut impl Pages,
        page: u32,
        entry: u32,
        relieve: &mut impl FnMut() -> bool,
    ) -> bool {
        let index = section_index_of(entry);
        let protect = vm::soft_protect(entry);
        let Some(section) = SectionInfo::of_page(page) else {
            return false;
        };
        let Some(frame) = fresh_frame(pages, relieve) else {
            return false;
        };
        let mut buf = match PageBuf::claim() {
            Some(buf) => buf,
            None => {
                pages.free_frame(frame);
                return false;
            }
        };
        buf.as_mut().fill(0);
        if !section.read_page(index, buf.as_mut()) {
            pages.free_frame(frame);
            return false;
        }
        pages.fill_frame(frame, buf.as_ref());
        vm::map_named_frame(pages, page, frame, protect);
        true
    }

    /// Apply a faulting access at `va` whose resolution needs backing-store I/O (see the module
    /// notes): the PageFile and Section arms. True when the page is mapped present now.
    pub fn apply(
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
            Resolution::PageFile => page_file_in(pages, page, entry, relieve),
            Resolution::Section => section_in(pages, page, entry, relieve),
            _ => false,
        }
    }

    // The store's adapter, kept for the paths that run whole inside one paging-file hold.
    #[allow(dead_code)]
    fn store() -> PagingFileIo {
        PagingFileIo
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::mem::frame::{ColorTables, FrameEntry, NoHooks, PRIMARY_COLOR};
    use crate::mem::pageout::{PageIoError, WriterPolicy};
    use crate::mem::phys::Pfn;
    use crate::mem::vm::{PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, USER_LOW};

    /// The frame table's size: frame ids 1..TABLE.
    const TABLE: usize = 64;

    fn new_db() -> FrameDb<NoHooks> {
        let table: &'static mut [FrameEntry] =
            Box::leak(vec![FrameEntry::new(); TABLE].into_boxed_slice());
        let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
        FrameDb::new(
            table,
            buckets,
            crate::mem::frame::DEFAULT_COLOR_COUNT,
            NoHooks,
        )
    }

    /// Page tables as a map; frames numbered from 1 (physical = frame * PAGE), with a budget and
    /// a grants cell a relief closure can free frames through, the frames given back, the frames
    /// activated, and the frame pages filled.
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
        activated: Vec<u32>,
        filled: HashMap<u32, Vec<u8>>,
        holders: HashMap<u32, u32>,
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
            Some(self.next * PAGE)
        }

        fn free_frame(&mut self, frame: u32) {
            self.freed.push(frame);
        }

        fn share_frame(&mut self, frame: u32) {
            *self.holders.entry(frame).or_default() += 1;
        }

        fn frame_shared(&self, frame: u32) -> bool {
            self.holders.get(&frame).is_some_and(|&extra| extra > 0)
        }

        fn copy_frame(&mut self, from: u32, to: u32) {
            let page = self.filled.get(&from).cloned().unwrap_or_default();
            self.filled.insert(to, page);
        }

        fn frame_word(&self, frame: u32, index: u32) -> u32 {
            let Some(page) = self.filled.get(&frame) else {
                return 0;
            };
            let at = index as usize * 4;
            u32::from_le_bytes(page[at..at + 4].try_into().unwrap())
        }

        fn set_frame_word(&mut self, frame: u32, index: u32, value: u32) {
            let page = self
                .filled
                .entry(frame)
                .or_insert_with(|| vec![0; PAGE as usize]);
            let at = index as usize * 4;
            page[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }

        fn activate_frame(&mut self, frame: u32) {
            self.activated.push(frame);
        }
    }

    /// The fake backing store: one page per slot, slot 0 reserved.
    struct FakeIo {
        allocated: Vec<bool>,
        pages: Vec<Option<[u8; PAGE_SIZE]>>,
        fail_reads: bool,
        freed: Vec<SlotId>,
    }

    impl FakeIo {
        fn new(capacity: u32) -> Self {
            FakeIo {
                allocated: vec![false; capacity as usize + 1],
                pages: vec![None; capacity as usize + 1],
                fail_reads: false,
                freed: Vec::new(),
            }
        }

        fn plant(&mut self, slot: SlotId, byte: u8) {
            self.allocated[slot as usize] = true;
            self.pages[slot as usize] = Some([byte; PAGE_SIZE]);
        }

        fn page(&self, slot: SlotId) -> [u8; PAGE_SIZE] {
            self.pages[slot as usize].expect("slot holds a page")
        }
    }

    impl PagingIo for FakeIo {
        fn allocate_slot(&mut self) -> Option<SlotId> {
            (1..self.allocated.len() as SlotId)
                .find(|&slot| !self.allocated[slot as usize])
                .inspect(|&slot| self.allocated[slot as usize] = true)
        }

        fn write(&mut self, slot: SlotId, page: &[u8]) -> Result<(), PageIoError> {
            assert!(self.allocated[slot as usize]);
            self.pages[slot as usize] = Some(<[u8; PAGE_SIZE]>::try_from(page).unwrap());
            Ok(())
        }

        fn read(&mut self, slot: SlotId, page: &mut [u8]) -> Result<(), PageIoError> {
            if self.fail_reads {
                return Err(PageIoError::Io);
            }
            let data = self.pages[slot as usize].ok_or(PageIoError::Io)?;
            page.copy_from_slice(&data);
            Ok(())
        }

        fn free_slot(&mut self, slot: SlotId) {
            self.allocated[slot as usize] = false;
            self.pages[slot as usize] = None;
            self.freed.push(slot);
        }
    }

    /// The fake frame source: a flat page per frame id.
    struct FakeMem {
        pages: Vec<[u8; PAGE_SIZE]>,
    }

    impl FakeMem {
        fn new() -> Self {
            FakeMem {
                pages: vec![[0u8; PAGE_SIZE]; TABLE],
            }
        }

        fn fill(&mut self, fid: u32, byte: u8) {
            self.pages[fid as usize] = [byte; PAGE_SIZE];
        }
    }

    impl FrameMemory for FakeMem {
        fn read_page(&mut self, frame: Pfn, page: &mut [u8]) {
            page.copy_from_slice(&self.pages[frame.index()]);
        }

        fn write_page(&mut self, frame: Pfn, page: &[u8]) {
            self.pages[frame.index()].copy_from_slice(page);
        }
    }

    /// A fake section: a byte "file" whose page `index` is read at `index * PAGE`, zero past its
    /// end.
    struct FakeSection {
        file: Vec<u8>,
        fail: bool,
    }

    impl SectionPages for FakeSection {
        fn read_page(&mut self, index: u32, buf: &mut [u8; PAGE_SIZE]) -> bool {
            if self.fail {
                return false;
            }
            buf.fill(0);
            let offset = index as usize * PAGE as usize;
            let len = self.file.len().saturating_sub(offset).min(PAGE_SIZE);
            if len > 0 {
                buf[..len].copy_from_slice(&self.file[offset..offset + len]);
            }
            true
        }
    }

    fn new_writer() -> PageWriter {
        let queue: &'static mut [Pfn] = Box::leak(vec![Pfn::ZERO; 64].into_boxed_slice());
        PageWriter::new(queue, WriterPolicy::new(1000, 64, 0, 64))
    }

    /// A paging-file entry: slot `slot` counted from one, with `protect`.
    fn page_file_entry(slot: SlotId, protect: u32) -> u32 {
        vm::encode_backing(vm::TAG_PAGE_FILE, slot << 12, protect)
    }

    /// A prototype entry: section page `index`, with `protect`.
    fn prototype_entry(index: u32, protect: u32) -> u32 {
        vm::encode_backing(vm::TAG_PROTOTYPE, index << 12, protect)
    }

    /// The slot and section index a soft entry names decode from its payload.
    #[test]
    fn soft_payloads_decode_to_their_slots_and_indices() {
        assert_eq!(slot_of(page_file_entry(7, PAGE_READWRITE)), 7);
        assert_eq!(section_index_of(prototype_entry(0x10, PAGE_READONLY)), 0x10);
        assert_eq!(
            vm::backing_tag(page_file_entry(7, PAGE_READWRITE)),
            vm::TAG_PAGE_FILE
        );
        assert_eq!(
            vm::soft_protect(page_file_entry(7, PAGE_READWRITE)),
            PAGE_READWRITE
        );
    }

    /// The PageFile arm: a paged-out page's slot is read back into a fresh frame (the slot
    /// released), and the page is mapped present with the entry's protection; with no frame left
    /// the relief runs once and the allocation is retried; a failed read gives the frame back and
    /// leaves the entry as it was.
    #[test]
    fn a_paging_file_page_is_read_back_and_mapped() {
        let mut db = new_db();
        let mut io = FakeIo::new(8);
        let mut mem = FakeMem::new();
        let mut buf = [0u8; PAGE_SIZE];
        let mut pages = Fake::default();
        let page = 0x0040_0000;

        io.plant(3, 0xAB);
        pages
            .entries
            .insert(page, page_file_entry(3, PAGE_READWRITE));
        let entry = pages.entry(page);
        assert!(page_file_in(
            &mut db,
            &mut io,
            &mut mem,
            &mut buf,
            &mut pages,
            page,
            entry,
            &mut || false,
        ));
        let entry = pages.entry(page);
        let (frame, protect) = vm::decode(entry).unwrap();
        assert_eq!(protect, PAGE_READWRITE);
        assert!(vm::PTE_PRESENT & entry != 0);
        assert_eq!(
            mem.pages[(frame / PAGE) as usize],
            [0xAB; PAGE_SIZE],
            "the slot's bytes"
        );
        assert_eq!(io.freed, vec![3], "page-in releases the slot");
        assert!(pages.freed.is_empty());

        // No frame left: the relief hook runs once; with it freeing a frame the retry maps.
        let page = 0x0041_0000;
        io.plant(4, 0xCD);
        pages
            .entries
            .insert(page, page_file_entry(4, PAGE_READONLY));
        pages.budget = Some(0);
        let grants = pages.grants.clone();
        let before = pages.entry(page);
        assert!(!page_file_in(
            &mut db,
            &mut io,
            &mut mem,
            &mut buf,
            &mut pages,
            page,
            before,
            &mut || false,
        ));
        assert_eq!(
            pages.entry(page),
            before,
            "the relief freed nothing: the fault stands"
        );
        assert!(page_file_in(
            &mut db,
            &mut io,
            &mut mem,
            &mut buf,
            &mut pages,
            page,
            before,
            &mut || {
                grants.set(1);
                true
            },
        ));
        let (frame, protect) = vm::decode(pages.entry(page)).unwrap();
        assert_eq!(protect, PAGE_READONLY);
        assert_eq!(mem.pages[(frame / PAGE) as usize], [0xCD; PAGE_SIZE]);
        assert_eq!(grants.get(), 0);

        // A failed read gives the frame back and leaves the entry as it was.
        let page = 0x0042_0000;
        io.plant(5, 0xEE);
        io.fail_reads = true;
        pages.budget = None;
        pages
            .entries
            .insert(page, page_file_entry(5, PAGE_READWRITE));
        let before = pages.entry(page);
        let taken = pages.next + 1;
        assert!(!page_file_in(
            &mut db,
            &mut io,
            &mut mem,
            &mut buf,
            &mut pages,
            page,
            before,
            &mut || false,
        ));
        assert_eq!(pages.entry(page), before);
        assert_eq!(pages.freed, vec![taken * PAGE], "the frame was given back");
        assert!(
            io.freed.contains(&5) == false,
            "the slot was not released on a failed read"
        );
    }

    /// The Section arm: the section's page is read from its backing at the page's index into a
    /// fresh frame and mapped present with the entry's protection; a copy-on-write protection
    /// maps held back; a failed read gives the frame back.
    #[test]
    fn a_section_page_is_read_from_its_backing_and_mapped() {
        let mut pages = Fake::default();
        let mut source = FakeSection {
            file: (0..0x2800u32).map(|i| (i % 251) as u8).collect(),
            fail: false,
        };
        let page = 0x0040_0000;

        // Section page 2: file offset 0x2000, 0x800 bytes of file there, the rest zero.
        pages
            .entries
            .insert(page, prototype_entry(2, PAGE_READONLY));
        let entry = pages.entry(page);
        assert!(section_in(
            &mut pages,
            &mut source,
            page,
            entry,
            &mut || false,
        ));
        let entry = pages.entry(page);
        let (frame, protect) = vm::decode(entry).unwrap();
        assert_eq!(protect, PAGE_READONLY);
        let filled = pages.filled.get(&frame).expect("the frame was filled");
        assert_eq!(&filled[..0x800], &source.file[0x2000..0x2800]);
        assert!(
            filled[0x800..].iter().all(|&b| b == 0),
            "zero past the file's end"
        );

        // A copy-on-write page maps held back: present, but not hardware-writable.
        let page = 0x0041_0000;
        pages
            .entries
            .insert(page, prototype_entry(1, PAGE_WRITECOPY));
        let entry = pages.entry(page);
        assert!(section_in(
            &mut pages,
            &mut source,
            page,
            entry,
            &mut || false,
        ));
        let entry = pages.entry(page);
        assert_eq!(vm::decode(entry).unwrap().1, PAGE_WRITECOPY);
        assert_eq!(entry & vm::PTE_PRESENT != 0, true);
        assert_eq!(entry & 0b10 != 0, false, "read-only to the hardware");

        // A failed read gives the frame back and leaves the entry as it was.
        source.fail = true;
        let page = 0x0042_0000;
        pages
            .entries
            .insert(page, prototype_entry(0, PAGE_READWRITE));
        let before = pages.entry(page);
        let taken = pages.next + 1;
        assert!(!section_in(
            &mut pages,
            &mut source,
            page,
            before,
            &mut || false,
        ));
        assert_eq!(pages.entry(page), before);
        assert_eq!(pages.freed, vec![taken * PAGE]);

        // No frame left: the relief frees one and the retry maps the page.
        source.fail = false;
        pages.budget = Some(0);
        let grants = pages.grants.clone();
        let page = 0x0043_0000;
        pages
            .entries
            .insert(page, prototype_entry(0, PAGE_READWRITE));
        let entry = pages.entry(page);
        assert!(section_in(
            &mut pages,
            &mut source,
            page,
            entry,
            &mut || {
                grants.set(1);
                true
            },
        ));
        assert!(vm::PTE_PRESENT & pages.entry(page) != 0);
    }

    /// A relief pass under pressure: present private pages are evicted — entries softened to
    /// transition ones, frames to the Modified list and queued — and the writer pass writes them
    /// out to slots, the frames going to Standby (available again) and the entries becoming
    /// paging-file ones; shared and non-private pages are left alone; the pages round-trip back
    /// in byte for byte.
    #[test]
    fn a_relief_pass_pages_private_pages_out_to_slots() {
        let mut db = new_db();
        let mut io = FakeIo::new(16);
        let mut mem = FakeMem::new();
        let mut buf = [0u8; PAGE_SIZE];
        let mut pages = Fake::default();
        let mut writer = new_writer();

        // Some frames available (20..30); the "process" holds frames 1..7, its pages at
        // 0x40..0x46_0000.
        for fid in 20..30u32 {
            db.release(Pfn::new(fid), crate::mem::frame::FrameState::Free);
        }
        assert_eq!(db.available(), 10);
        let base = 0x0040_0000u32;
        for page in 0..4u32 {
            let fid = page + 1;
            mem.fill(fid, 0xA0 + page as u8);
            pages
                .entries
                .insert(base + page * PAGE, vm::encode(fid * PAGE, PAGE_READWRITE));
        }
        // A shared page (a section's frame) and a non-private page are not evicted.
        mem.fill(6, 0x77);
        pages
            .entries
            .insert(base + 4 * PAGE, vm::encode(6 * PAGE, PAGE_READWRITE));
        pages.holders.insert(6 * PAGE, 1);
        mem.fill(7, 0x88);
        pages
            .entries
            .insert(base + 5 * PAGE, vm::encode(7 * PAGE, PAGE_READWRITE));
        let private = |va: u32| va < base + 5 * PAGE; // the last page is not private

        let mut victims = [Victim {
            va: 0,
            frame: 0,
            protect: 0,
        }; 8];
        let freed = relieve_pass(
            &mut db,
            &mut pages,
            &mut io,
            &mut mem,
            &mut buf,
            &mut writer,
            USER_LOW,
            base + 6 * PAGE,
            &private,
            100,
            &mut victims,
        );
        assert_eq!(freed, 4, "the four private unshared pages went out");
        assert_eq!(db.available(), 10 + 4, "their frames are available again");
        for page in 0..4u32 {
            let entry = pages.entry(base + page * PAGE);
            assert_eq!(vm::backing_tag(entry), vm::TAG_PAGE_FILE, "page {page}");
            let slot = slot_of(entry);
            assert_ne!(slot, 0);
            assert_eq!(
                io.page(slot),
                [0xA0 + page as u8; PAGE_SIZE],
                "the page's bytes"
            );
            assert_eq!(
                db.entry(Pfn::new(page + 1)).state,
                crate::mem::frame::FrameState::Standby,
                "page {page}'s frame is on Standby"
            );
        }
        // The shared and non-private pages keep their present entries.
        assert_eq!(
            pages.entry(base + 4 * PAGE),
            vm::encode(6 * PAGE, PAGE_READWRITE)
        );
        assert_eq!(
            pages.entry(base + 5 * PAGE),
            vm::encode(7 * PAGE, PAGE_READWRITE)
        );
        assert_eq!(writer.queued(), 0);
        assert_eq!(db.audit(), Ok(()));

        // The pages page back in byte for byte (fresh frames come from past the evicted ones).
        pages.next = 40;
        for page in 0..4u32 {
            let va = base + page * PAGE;
            let entry = pages.entry(va);
            let before = entry;
            assert!(page_file_in(
                &mut db,
                &mut io,
                &mut mem,
                &mut buf,
                &mut pages,
                va,
                before,
                &mut || false,
            ));
            let (frame, _) = vm::decode(pages.entry(va)).unwrap();
            assert_eq!(
                mem.pages[(frame / PAGE) as usize],
                [0xA0 + page as u8; PAGE_SIZE]
            );
            assert_eq!(vm::backing_tag(pages.entry(va)), 0, "present again");
        }
        assert_eq!(db.audit(), Ok(()));
    }

    /// A relief pass leaves a page alone whose frame is not in use (re-faulted meanwhile): it is
    /// skipped, not evicted, and no slot is taken for it.
    #[test]
    fn a_relief_pass_skips_frames_no_longer_in_use() {
        let mut db = new_db();
        let mut io = FakeIo::new(8);
        let mut mem = FakeMem::new();
        let mut buf = [0u8; PAGE_SIZE];
        let mut pages = Fake::default();
        let mut writer = new_writer();
        for fid in 3..6u32 {
            db.release(Pfn::new(fid), crate::mem::frame::FrameState::Free);
        }
        let base = 0x0040_0000u32;
        // Frame 1 is in use and mapped; frame 2's page is present but the frame went to Standby
        // behind the entry's back (re-faulted elsewhere).
        mem.fill(1, 0x11);
        pages.entries.insert(base, vm::encode(PAGE, PAGE_READWRITE));
        mem.fill(2, 0x22);
        pages
            .entries
            .insert(base + PAGE, vm::encode(2 * PAGE, PAGE_READWRITE));
        db.release(Pfn::new(2), crate::mem::frame::FrameState::Standby);

        let mut victims = [Victim {
            va: 0,
            frame: 0,
            protect: 0,
        }; 8];
        let freed = relieve_pass(
            &mut db,
            &mut pages,
            &mut io,
            &mut mem,
            &mut buf,
            &mut writer,
            USER_LOW,
            base + 2 * PAGE,
            &|_| true,
            100,
            &mut victims,
        );
        assert_eq!(freed, 1, "only the in-use frame was written out");
        assert_eq!(vm::backing_tag(pages.entry(base)), vm::TAG_PAGE_FILE);
        assert_eq!(
            pages.entry(base + PAGE),
            vm::encode(2 * PAGE, PAGE_READWRITE),
            "the standby frame's entry is untouched"
        );
        assert_eq!(
            db.entry(Pfn::new(2)).state,
            crate::mem::frame::FrameState::Standby
        );
        assert_eq!(db.audit(), Ok(()));
    }
}
