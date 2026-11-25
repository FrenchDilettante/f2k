//! The user address space: reservations, committed pages and their protections — what VirtualAlloc,
//! VirtualFree, VirtualProtect and VirtualQuery see — and the one writer of user page-table
//! entries.
//!
//! A process's address space is a table of regions — each a reservation `[base, base + size)` with
//! the protection it was allocated with and a kind (private memory, a mapped view, an image) — and
//! the page tables,
//! which hold each page's state, as [`pte`] classifies it. A committed page the program may touch
//! is usually a present entry naming its frame; its exact protection rides in the entry's three
//! software bits (zero meaning "read-write if writable, else read-only", for entries written before
//! the protection was recorded). A committed page not mapped yet is a demand-zero entry: the
//! committed marker, no frame — the first touch faults a zeroed frame in. A committed page the
//! program may not touch — PAGE_NOACCESS, or a guard page — is a non-present entry that still names
//! its frame, marked as committed, its protection (the guard flag apart) in the same bits. An
//! uncommitted page has no entry.
//!
//! Every user page lies in a region: the loader seeds the image and the system areas before it maps
//! anything, and every mapping, commit, guard and release goes through [`AddressSpace`], so a
//! query, a release and the teardown all see every page. `paging` keeps only the raw entry access,
//! reached through the [`Pages`] seam ([`CurrentPages`] on target, an in-memory fake in the tests).
//!
//! Reservations start on the 64 KiB allocation granularity and cover whole pages; a reservation
//! without an address takes the lowest free range that fits. An eager commit
//! ([`AddressSpace::commit`], the kernel's own pages: stacks) maps and zeroes its pages; a demand
//! commit ([`AddressSpace::commit_demand`], the services' MEM_COMMIT) only writes demand-zero
//! entries — committing a committed page keeps its contents and takes the new protection either
//! way. A query reports the page's region and the run of pages after it in the same state and
//! protection, within the region; outside every region it reports free memory up to the next
//! region.
//!
//! Region kinds are what a query reports as the type; the services (`nt::memory`, `nt::section`)
//! decide what each kind refuses. A view's kind carries its maximum ([`Maximum`], NT's VAD holds
//! the same against its section): what its pages may be given, and whether a writable protection
//! writes its section or stays copy-on-write.
//!
//! A frame may have several holders: a data section, or an image file's segment, owns its frames
//! ([`SectionFrames`]), and each view of it maps them too; a system DLL's pages are the kernel's,
//! each process mapping them. The frame database counts the holders; a page's release drops its own
//! hold, and the frame goes back only with the last. Copy-on-write pages (PAGE_WRITECOPY, an
//! image's writable sections and FILE_MAP_COPY views) are read-only to the hardware: the first
//! write makes the page private — a copy of a frame other holders still map, or the frame itself
//! when it is the page's alone — and the page turns read-write, as the platform reports it
//! ([`copy_on_write`]). A writable protection given to a page whose frame others hold is
//! copy-on-write in fact, unless the page is a view's that may write its section
//! ([`Maximum::Write`]): the system DLLs' pages, an image's, the shared data page and a
//! copy-on-write or read-only view's section stay as their holders made them.

use super::pte::{self, PteKind};
use super::quota::CommitQuota;

/// The page size and the allocation granularity.
pub const PAGE: u32 = 0x1000;
pub const GRANULARITY: u32 = 0x1_0000;
/// The application range: from 64 KiB up to (not including) the last 64 KiB below 2 GiB.
pub const USER_LOW: u32 = 0x0001_0000;
pub const USER_HIGH: u32 = 0x7FFF_0000;

/// The protections.
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_WRITECOPY: u32 = 0x08;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
pub const PAGE_GUARD: u32 = 0x100;
pub const PAGE_NOCACHE: u32 = 0x200;

/// The states and kinds a query reports.
pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const MEM_FREE: u32 = 0x1_0000;
pub const MEM_PRIVATE: u32 = 0x2_0000;
pub const MEM_MAPPED: u32 = 0x4_0000;
pub const MEM_IMAGE: u32 = 0x100_0000;

/// The page-table entry bits.
const PRESENT: u32 = 1 << 0;
const WRITE: u32 = 1 << 1;
const USER: u32 = 1 << 2;
/// A non-present entry's committed marker and guard flag (the CPU ignores a non-present entry's
/// other bits).
const COMMITTED: u32 = 1 << 1;
const GUARD: u32 = 1 << 2;
/// The protection index's place: the software bits.
const INDEX_SHIFT: u32 = 9;
/// The frame/payload field's shift: bits 12-31.
const FRAME_SHIFT: u32 = 12;
const FRAME_MASK: u32 = 0xFFFF_F000;

/// The present bit, as the soft-entry helpers read it.
pub const PTE_PRESENT: u32 = PRESENT;
/// The hardware write bit on a present entry (the committed marker on a non-present one).
pub const PTE_WRITE: u32 = WRITE;
/// The hardware dirty bit on a present entry: set by the processor on a write, clear when the
/// manager maps the page. A writable page with it clear is clean — its frame's contents are the
/// page's only copy, so the frame may go to standby without a page-out.
pub const PTE_DIRTY: u32 = 1 << 6;
/// The frame/payload field's mask (bits 12-31), as the soft-entry helpers read it.
pub const PTE_FRAME_MASK: u32 = FRAME_MASK;

/// A non-present entry's backing tags (bits 3-5, as [`super::fault`] marks them): the page is off
/// its mapping and its backing is named — a frame on a backing list ([`TAG_TRANSITION`]), a slot
/// in the paging file ([`TAG_PAGE_FILE`]), or a section's page ([`TAG_PROTOTYPE`]).
pub const TAG_TRANSITION: u32 = super::fault::TRANSITION;
pub const TAG_PROTOTYPE: u32 = super::fault::PROTOTYPE;
pub const TAG_PAGE_FILE: u32 = super::fault::PAGE_FILE;
/// All the backing tags.
const SOFT_TAGS: u32 = TAG_TRANSITION | TAG_PROTOTYPE | TAG_PAGE_FILE;

/// The entry's backing tag: one of the `TAG_` bits, or zero for a hard (present, committed or
/// uncommitted) entry. On a present entry bits 3-5 are the hardware's cache and accessed bits,
/// not a tag, so the tags read only on a non-present one — a soft entry is never present.
pub fn backing_tag(entry: u32) -> u32 {
    if entry & PTE_PRESENT != 0 {
        0
    } else {
        entry & SOFT_TAGS
    }
}

/// A soft entry's payload (bits 12-31): the named frame, or the paging-file slot / section page
/// index shifted up into the field.
pub fn backing_payload(entry: u32) -> u32 {
    entry & FRAME_MASK
}

/// The base protection a soft entry records in its protection index bits.
pub fn soft_protect(entry: u32) -> u32 {
    base_of((entry >> INDEX_SHIFT) & 7)
}

/// The soft entry for a page backed by `tag` with `payload` (a frame, or a slot/index shifted up)
/// and `protect`: the CPU ignores a non-present entry's bits, so they carry the page's state.
pub fn encode_backing(tag: u32, payload: u32, protect: u32) -> u32 {
    debug_assert!(tag != 0 && tag & !SOFT_TAGS == 0, "one backing tag");
    debug_assert!(payload & !FRAME_MASK == 0, "the payload is page-aligned");
    tag | payload | (index_of(protect & 0xFF) << INDEX_SHIFT)
}

/// Whether the entry says the page is committed: a hard committed entry, or a soft backing one (a
/// view's page is committed with its view; a paged-out private page keeps its commit charge).
pub fn committed_entry(entry: u32) -> bool {
    pte::committed(entry) || backing_tag(entry) != 0
}

/// Whether a protection is one a program may pass: one base protection, optionally guarded or
/// uncached (a guarded no-access page is not one).
pub fn valid_protect(protect: u32) -> bool {
    let base = protect & 0xFF;
    base.is_power_of_two()
        && protect & !(0xFF | PAGE_GUARD | PAGE_NOCACHE) == 0
        && !(base == PAGE_NOACCESS && protect & PAGE_GUARD != 0)
}

/// The protection index of a base protection (1-7 present, 0 no-access).
fn index_of(base: u32) -> u32 {
    match base {
        PAGE_READONLY => 1,
        PAGE_READWRITE => 2,
        PAGE_WRITECOPY => 3,
        PAGE_EXECUTE => 4,
        PAGE_EXECUTE_READ => 5,
        PAGE_EXECUTE_READWRITE => 6,
        PAGE_EXECUTE_WRITECOPY => 7,
        _ => 0,
    }
}

fn base_of(index: u32) -> u32 {
    match index {
        1 => PAGE_READONLY,
        2 => PAGE_READWRITE,
        3 => PAGE_WRITECOPY,
        4 => PAGE_EXECUTE,
        5 => PAGE_EXECUTE_READ,
        6 => PAGE_EXECUTE_READWRITE,
        7 => PAGE_EXECUTE_WRITECOPY,
        _ => PAGE_NOACCESS,
    }
}

/// Whether a base protection lets the hardware write: a copy-on-write page does not, its first
/// write faulting into the copy.
fn writable(base: u32) -> bool {
    matches!(base, PAGE_READWRITE | PAGE_EXECUTE_READWRITE)
}

/// The protection a copy-on-write page takes once written: none for any other.
fn written(base: u32) -> Option<u32> {
    match base {
        PAGE_WRITECOPY => Some(PAGE_READWRITE),
        PAGE_EXECUTE_WRITECOPY => Some(PAGE_EXECUTE_READWRITE),
        _ => None,
    }
}

/// The copy-on-write protection a writable one becomes (its guard and cache bits kept): none for a
/// protection the hardware does not write through.
fn copy_on_write_of(protect: u32) -> Option<u32> {
    let base = match protect & 0xFF {
        PAGE_READWRITE => PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE => PAGE_EXECUTE_WRITECOPY,
        _ => return None,
    };
    Some(protect & !0xFF | base)
}

/// The entry for a committed page of `frame` with `protect`.
pub fn encode(frame: u32, protect: u32) -> u32 {
    let base = protect & 0xFF;
    let index = index_of(base) << INDEX_SHIFT;
    if base == PAGE_NOACCESS || protect & PAGE_GUARD != 0 {
        let guard = if protect & PAGE_GUARD != 0 { GUARD } else { 0 };
        frame | COMMITTED | guard | index
    } else {
        frame | PRESENT | USER | if writable(base) { WRITE } else { 0 } | index
    }
}

/// A committed page's frame and protection, from its entry; none for an uncommitted page.
pub fn decode(entry: u32) -> Option<(u32, u32)> {
    let index = (entry >> INDEX_SHIFT) & 7;
    if entry & PRESENT != 0 {
        let protect = match index {
            0 if entry & WRITE != 0 => PAGE_READWRITE,
            0 => PAGE_READONLY,
            index => base_of(index),
        };
        Some((entry & FRAME_MASK, protect))
    } else if entry & COMMITTED != 0 {
        let guard = if entry & GUARD != 0 { PAGE_GUARD } else { 0 };
        Some((entry & FRAME_MASK, base_of(index) | guard))
    } else {
        None
    }
}

/// Whether an entry names a frame the process owns (the teardown's question): a present page, or a
/// committed one it may not touch — a demand-zero page is committed but names no frame until its
/// first touch.
pub fn names_frame(entry: u32) -> bool {
    (entry & PRESENT != 0 || entry & COMMITTED != 0) && entry & FRAME_MASK != 0
}

/// Resolve a write fault on the present page at `va`, if it is a copy-on-write page: its frame made
/// the page's own — copied when other holders still map it (a section's, a view's, the kernel's DLL
/// page), kept when it is the page's alone — and the page read-write. False for any other page (the
/// fault stands), or when no frame is left for the copy.
pub fn copy_on_write(pages: &mut impl Pages, va: u32) -> bool {
    if va >= USER_HIGH {
        return false;
    }
    let page = page_down(va);
    let entry = pages.entry(page);
    let Some((frame, protect)) = decode(entry) else {
        return false;
    };
    let Some(now) = written(protect & 0xFF).filter(|_| entry & PRESENT != 0) else {
        return false;
    };
    let frame = if pages.frame_shared(frame) {
        let Some(copy) = pages.zeroed_frame() else {
            return false;
        };
        pages.copy_frame(frame, copy);
        pages.free_frame(frame);
        copy
    } else {
        frame
    };
    // The page-fault handler's fast path resolves a write to a copy-on-write page here, without
    // the dispatch (user/seh.rs) that notes the fault, so the sever notes itself: the total, and
    // the copy-on-write kind (the counts are read for nonzero, not exact).
    #[cfg(target_arch = "x86")]
    crate::mem::faultstats::note_fault(entry, true, true);
    pages.set_entry(page, encode(frame, now | protect & !0xFF));
    true
}

/// The entry a committed page that holds no frame of its own yet (a demand page) takes under
/// `protect`: still committed, still without a frame — guarded when `protect` asks — so its
/// first touch faults a zeroed frame in (or fires the guard).
fn demand_entry(protect: u32) -> u32 {
    if protect & PAGE_GUARD != 0 {
        pte::encode(PteKind::Guard, 0, protect)
    } else {
        pte::encode(PteKind::DemandZero, 0, protect)
    }
}

/// Map the demand-zero page at `page` to a fresh zeroed frame, present with `protect`: the first
/// touch of a committed page, resolved on the entry alone. False when no frame is left, the entry
/// as it was.
pub fn map_demand_zero(pages: &mut impl Pages, page: u32, protect: u32) -> bool {
    let Some(frame) = pages.zeroed_frame() else {
        return false;
    };
    pages.set_entry(page, encode(frame, protect));
    true
}

/// Map the page at `page` present to the `frame` its entry names, with `protect`: a page back
/// from a backing list, no I/O — or a page just filled from its backing (a page-in's last step).
pub fn map_named_frame(pages: &mut impl Pages, page: u32, frame: u32, protect: u32) {
    pages.set_entry(page, encode(frame, protect));
}

/// Soften the entry at `va` to a transition one: the page's frame named in the payload, its
/// protection in the index bits. The page is evicted from its mapping while its frame sits on a
/// backing list, and a fault on it maps the named frame back ([`map_named_frame`], no I/O).
pub fn soften_to_transition(pages: &mut impl Pages, va: u32, frame: u32, protect: u32) {
    pages.set_entry(
        page_down(va),
        encode_backing(TAG_TRANSITION, frame, protect),
    );
}

/// Rewrite the entry at `va` to a paging-file one: the page's bytes sit in the slot `slot`
/// (counted from one) and its frame is free — the page-out's last step; a fault on the page
/// reads the slot back.
pub fn name_page_file(pages: &mut impl Pages, va: u32, slot: u32, protect: u32) {
    pages.set_entry(
        page_down(va),
        encode_backing(TAG_PAGE_FILE, slot << FRAME_SHIFT, protect),
    );
}

/// Fire the guard page at `va`, if the page there is one: it keeps its protection and frame,
/// without the guard flag (the access that touched it then raises STATUS_GUARD_PAGE_VIOLATION,
/// once, unless it grows a stack). A guard page committed without a frame yet stays committed
/// and unmapped: the retried access faults its zeroed frame in.
pub fn fire_guard(pages: &mut impl Pages, va: u32) -> bool {
    if va >= USER_HIGH {
        return false;
    }
    let page = page_down(va);
    match decode(pages.entry(page)) {
        Some((frame, protect)) if protect & PAGE_GUARD != 0 => {
            let protect = protect & !PAGE_GUARD;
            let entry = if frame != 0 {
                encode(frame, protect)
            } else {
                demand_entry(protect)
            };
            pages.set_entry(page, entry);
            true
        }
        _ => false,
    }
}

/// What a region is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Private,
    /// A mapped view: its pages map its section's frames, as far as its maximum lets them.
    Mapped(Maximum),
    Image,
    /// Private memory the kernel seeded and maps itself (the TEBs, the PEB, the shared data
    /// page): MEM_PRIVATE to a query, but secured, as Windows 2000's PEB and TEB VADs are — no
    /// program commits, frees or reprotects its pages, so the kernel's own maps there always find
    /// their pages as it left them.
    System,
}

impl Kind {
    fn mem_type(self) -> u32 {
        match self {
            Kind::Private | Kind::System => MEM_PRIVATE,
            Kind::Mapped(_) => MEM_MAPPED,
            Kind::Image => MEM_IMAGE,
        }
    }
}

/// A data view's maximum protection, settled when it is mapped from its section's protection, the
/// access its section handle was granted and the view's own protection (`nt::section`): what a
/// protection change may give its pages, as Windows 2000's MiProtectVirtualMemory checks a view's
/// against its section (MmCompatibleProtectionMask). A data section never executes, so no view
/// takes an executable protection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Maximum {
    /// The section's frames are the view's to write: a read-write section, through a handle
    /// granted SECTION_MAP_WRITE, in a view not mapped copy-on-write.
    Write,
    /// A copy-on-write view of such a section: a writable protection is taken, but stays
    /// copy-on-write, so a write lands in a page of the process's own.
    CopyOnWrite,
    /// A view of a section made read-only or copy-on-write, or through a handle without
    /// SECTION_MAP_WRITE: no writable protection (STATUS_SECTION_PROTECTION); copy-on-write is.
    Read,
}

impl Maximum {
    /// Whether a view of this maximum may take `protect` (its guard and cache bits aside).
    pub fn allows(self, protect: u32) -> bool {
        match protect & 0xFF {
            PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY => true,
            PAGE_READWRITE => self != Maximum::Read,
            _ => false,
        }
    }
}

/// Where a reservation without an address goes: the lowest free range below `end`, or with
/// `top_down` the highest (NtAllocateVirtualMemory's ZeroBits and MEM_TOP_DOWN).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Placement {
    pub end: u32,
    pub top_down: bool,
}

/// The most zero bits a placement takes (Windows 2000's MM_MAXIMUM_ZERO_BITS).
pub const MAXIMUM_ZERO_BITS: u32 = 21;

impl Placement {
    /// Anywhere in the application range, lowest first.
    pub const ANYWHERE: Placement = Placement {
        end: USER_HIGH,
        top_down: false,
    };

    /// The placement of a reservation whose base must have its `zero_bits` high bits clear (none:
    /// anywhere), top-down or not; none past [`MAXIMUM_ZERO_BITS`]. The highest address is
    /// 0xFFFFFFFF shifted right by the zero bits, as Windows 2000 takes it, within the application
    /// range.
    pub fn of(zero_bits: u32, top_down: bool) -> Option<Placement> {
        if zero_bits > MAXIMUM_ZERO_BITS {
            return None;
        }
        let end = match zero_bits {
            0 => USER_HIGH,
            bits => ((u32::MAX >> bits) as u64 + 1).min(USER_HIGH as u64) as u32,
        };
        Some(Placement { end, top_down })
    }
}

/// One reservation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Region {
    pub base: u32,
    pub size: u32,
    pub alloc_protect: u32,
    pub kind: Kind,
}

/// Why an operation failed (each service reports it as its own status: `nt::memory`,
/// `nt::section`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmError {
    /// The range is taken, not reserved, not committed, or not a region's base.
    InvalidAddress,
    /// A zero size, or a range outside the application range.
    InvalidParameter,
    /// No free range, no region record, or no frame.
    NoMemory,
}

/// What a query reports (MEMORY_BASIC_INFORMATION).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Info {
    pub base: u32,
    pub allocation_base: u32,
    pub allocation_protect: u32,
    pub size: u32,
    pub state: u32,
    pub protect: u32,
    pub mem_type: u32,
}

/// The page tables and the frame database, as the address space reaches them.
pub trait Pages {
    /// The entry for user page `va`.
    fn entry(&self, va: u32) -> u32;
    /// Write the entry for user page `va`.
    fn set_entry(&mut self, va: u32, entry: u32);
    /// A zeroed frame, or none when memory is exhausted. Its allocator is its one holder.
    fn zeroed_frame(&mut self) -> Option<u32>;
    /// Drop one holder of a frame: the frame goes back with its last.
    fn free_frame(&mut self, frame: u32);
    /// Count one more holder of a frame (a view mapping its section's frame).
    fn share_frame(&mut self, frame: u32);
    /// Whether a frame has holders besides the one asking.
    fn frame_shared(&self, frame: u32) -> bool;
    /// Copy a frame's contents into another.
    fn copy_frame(&mut self, from: u32, to: u32);
    /// Word `index` of a frame holding words (a section's frame table).
    fn frame_word(&self, frame: u32, index: u32) -> u32;
    /// Write word `index` of such a frame.
    fn set_frame_word(&mut self, frame: u32, index: u32, value: u32);
    /// Take the frame a transition entry names back into use: off its backing list, when it is on
    /// one, and with the entry's hold ([`FrameDb::share`]) dropped — the frame the entry held
    /// against reallocation is the mapping's again. No-op when the frame is not listed and
    /// unheld.
    fn activate_frame(&mut self, frame: u32) {
        let _ = frame;
    }
    /// Fill a fresh frame's whole page from `bytes` (a page-in's read): word by word through the
    /// frame-word seam by default.
    fn fill_frame(&mut self, frame: u32, bytes: &[u8]) {
        for (index, word) in bytes.chunks_exact(4).enumerate() {
            self.set_frame_word(
                frame,
                index as u32,
                u32::from_le_bytes(word.try_into().expect("four bytes")),
            );
        }
    }
    /// Release the backing-store slot a dropped paging-file entry named.
    fn discard_backing(&mut self, slot: u32) {
        let _ = slot;
    }
    /// Link a section's new frame to the slot `slot` of the frame table `table` naming it: the
    /// back-link a cached image segment's frame keeps on Standby ([`SectionFrames::park`]).
    fn link_frame(&mut self, frame: u32, table: u32, slot: u32) {
        let _ = (frame, table, slot);
    }
    /// A parked segment's frame back into use for slot `slot` of `table`: true when it still is
    /// that slot's — taken off Standby, a soft fault with no read — false when the allocator handed
    /// it out to another use meanwhile (the slot then names nothing of the segment's).
    fn reclaim_frame(&mut self, frame: u32, table: u32, slot: u32) -> bool {
        let _ = (frame, table, slot);
        true
    }
    /// A segment's last reference went: it drops its hold on its frame for the cache. With no
    /// other holder the frame waits on Standby, still linked to its slot (true); with one, the
    /// frame stays with it, the segment's hold dropped (false).
    fn cache_frame(&mut self, frame: u32) -> bool {
        self.free_frame(frame);
        false
    }
}

/// How many regions a process can hold: the kernel's own areas (about a dozen), and every
/// reservation, thread stack, heap segment, big block and view the program makes. A fixed table:
/// exhausting it is the program's ERROR_NOT_ENOUGH_MEMORY.
pub const REGIONS: usize = 1024;

fn page_down(va: u32) -> u32 {
    va & !(PAGE - 1)
}

fn page_up(va: u64) -> u64 {
    (va + PAGE as u64 - 1) & !(PAGE as u64 - 1)
}

/// How many mapped views a process can hold at once: every DLL a program loads is one (an
/// explorer-class program maps forty and more), and every MapViewOfFile. A full table refuses the
/// map (STATUS_NO_MEMORY). The table is the process's own, in its record, so one process filling
/// it takes nothing from another.
pub const VIEWS: usize = 128;

/// One mapped view: its region's base, the section offset it maps from (zero for an image), and
/// what it maps — a data section, or an image's segment — whose frames it maps (the view holds a
/// reference on it for as long as it is mapped).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct View {
    pub base: u32,
    pub offset: u32,
    pub mapping: crate::ob::Mapping,
}

/// A process's regions, its mapped views (on NT, the VADs a view's section hangs off), and its
/// commit quota. All `None` is the empty space, with nothing charged.
pub struct AddressSpace {
    regions: [Option<Region>; REGIONS],
    views: [Option<View>; VIEWS],
    /// The process's commit charge against the system's commit limit (see [`super::quota`]),
    /// taken from the limit when the space is made for a process ([`Self::reset`]): a commit
    /// charges it, a decommit or release discharges it. Guarded by the space's own lock, like the
    /// regions and views.
    pub quota: CommitQuota,
}

impl AddressSpace {
    /// The empty space: a process record's from the kernel's build on (the pool's records are
    /// built at compile time), and the tests'.
    pub const fn new() -> AddressSpace {
        AddressSpace {
            regions: [None; REGIONS],
            views: [None; VIEWS],
            quota: CommitQuota::new(0),
        }
    }

    /// Write the empty space at `space`, element by element: the in-place form of [`Self::new`],
    /// for a space built inside a process record at its final address (by value it would pass
    /// through the caller's stack).
    ///
    /// # Safety
    ///
    /// `space` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    pub unsafe fn write_empty(space: *mut AddressSpace) {
        use core::ptr::addr_of_mut;
        // SAFETY: the caller's contract; both tables are written element by element.
        unsafe {
            let regions = addr_of_mut!((*space).regions) as *mut Option<Region>;
            for index in 0..REGIONS {
                regions.add(index).write(None);
            }
            let views = addr_of_mut!((*space).views) as *mut Option<View>;
            for index in 0..VIEWS {
                views.add(index).write(None);
            }
            addr_of_mut!((*space).quota).write(CommitQuota::new(0));
        }
    }

    /// Whether another view can be recorded.
    pub fn has_view_room(&self) -> bool {
        self.views.iter().any(Option::is_none)
    }

    /// Record the view just mapped at `base` from `offset` of `mapping`, in the same hold of the
    /// space as the check for room: false when the table is full — another thread of the process
    /// took its last record since the mapper looked — and the view's region is released then, its
    /// pages' holds with it, so the mapper is left nothing to undo but the reference it took for
    /// the view.
    pub fn record_view(
        &mut self,
        pages: &mut impl Pages,
        base: u32,
        offset: u32,
        mapping: crate::ob::Mapping,
    ) -> bool {
        if self.add_view_at(base, offset, mapping) {
            return true;
        }
        let _ = self.release(pages, base);
        false
    }

    /// Record a view mapped at `base` of `mapping` (from offset zero); false when the view table
    /// is full.
    pub fn add_view(&mut self, base: u32, mapping: crate::ob::Mapping) -> bool {
        self.add_view_at(base, 0, mapping)
    }

    /// Record a view mapped at `base` from `offset` of `mapping`; false when the view table is
    /// full.
    pub fn add_view_at(&mut self, base: u32, offset: u32, mapping: crate::ob::Mapping) -> bool {
        match self.views.iter_mut().find(|view| view.is_none()) {
            Some(slot) => {
                *slot = Some(View {
                    base,
                    offset,
                    mapping,
                });
                true
            }
            None => false,
        }
    }

    /// What the view at `base` maps; none when no view starts there.
    pub fn view_at(&self, base: u32) -> Option<crate::ob::Mapping> {
        self.views
            .iter()
            .flatten()
            .find(|view| view.base == base)
            .map(|view| view.mapping)
    }

    /// Forget the view at `base`, returning it whole; none when no view starts there.
    pub fn take_view(&mut self, base: u32) -> Option<View> {
        self.views
            .iter_mut()
            .find(|view| view.is_some_and(|view| view.base == base))?
            .take()
    }

    /// Forget every view, handing each to `release` — its base, for its pages to go, and what it
    /// mapped, for the reference the view held.
    pub fn drop_views(&mut self, mut release: impl FnMut(View)) {
        for slot in self.views.iter_mut() {
            if let Some(view) = slot.take() {
                release(view);
            }
        }
    }

    /// The bytes every region reserves together (VM_COUNTERS' VirtualSize).
    pub fn reserved_size(&self) -> u32 {
        self.regions
            .iter()
            .flatten()
            .map(|region| region.size)
            .sum()
    }

    /// Empty the space in place, whatever it held (by value it would pass the caller's stack): a
    /// process record taken for a new process. The commit quota starts over at the system's
    /// commit limit ([`super::system_commit_limit`]).
    pub fn reset(&mut self) {
        self.regions.fill(None);
        self.views.fill(None);
        self.quota = CommitQuota::new(super::system_commit_limit());
    }

    /// The region containing `va`.
    pub fn region_at(&self, va: u32) -> Option<Region> {
        self.regions
            .iter()
            .flatten()
            .find(|r| va >= r.base && va - r.base < r.size)
            .copied()
    }

    /// Whether `[base, end)` meets any region.
    fn overlaps(&self, base: u32, end: u64) -> bool {
        self.regions
            .iter()
            .flatten()
            .any(|r| (base as u64) < r.base as u64 + r.size as u64 && (r.base as u64) < end)
    }

    /// A granularity-aligned base where `size` bytes fit between the regions, below `placement`'s
    /// end: the lowest, or the highest for a top-down placement.
    fn free_range(&self, size: u32, placement: Placement) -> Option<u32> {
        let end = placement.end as u64;
        let meets = |candidate: u64| {
            self.regions.iter().flatten().filter(move |r| {
                candidate < r.base as u64 + r.size as u64
                    && (r.base as u64) < candidate + size as u64
            })
        };
        if placement.top_down {
            let mut candidate = end.checked_sub(size as u64)? & !(GRANULARITY as u64 - 1);
            loop {
                if candidate < USER_LOW as u64 {
                    return None;
                }
                match meets(candidate).map(|r| r.base as u64).min() {
                    None => return Some(candidate as u32),
                    Some(below) => {
                        candidate = below.checked_sub(size as u64)? & !(GRANULARITY as u64 - 1);
                    }
                }
            }
        }
        let mut candidate = USER_LOW as u64;
        loop {
            if candidate + size as u64 > end {
                return None;
            }
            match meets(candidate)
                .map(|r| r.base as u64 + r.size as u64)
                .max()
            {
                None => return Some(candidate as u32),
                Some(past) => {
                    candidate = past.div_ceil(GRANULARITY as u64) * GRANULARITY as u64;
                }
            }
        }
    }

    /// Record a region exactly as given (the kernel's own areas: the image, stacks, staged pages).
    pub fn insert(&mut self, region: Region) -> Result<(), VmError> {
        if self.overlaps(region.base, region.base as u64 + region.size as u64) {
            return Err(VmError::InvalidAddress);
        }
        let slot = self
            .regions
            .iter_mut()
            .find(|r| r.is_none())
            .ok_or(VmError::NoMemory)?;
        *slot = Some(region);
        Ok(())
    }

    /// Reserve `size` bytes at `address` (rounded down to the granularity, the end up to a page)
    /// or, without one, at the lowest free range. Returns the region's base.
    pub fn reserve(
        &mut self,
        address: Option<u32>,
        size: u32,
        protect: u32,
        kind: Kind,
    ) -> Result<u32, VmError> {
        self.reserve_placed(address, Placement::ANYWHERE, size, protect, kind)
    }

    /// [`reserve`](Self::reserve), a reservation without an address taking a free range as
    /// `placement` places it.
    pub fn reserve_placed(
        &mut self,
        address: Option<u32>,
        placement: Placement,
        size: u32,
        protect: u32,
        kind: Kind,
    ) -> Result<u32, VmError> {
        if size == 0 {
            return Err(VmError::InvalidParameter);
        }
        let (base, end) = match address {
            Some(address) => {
                let base = address & !(GRANULARITY - 1);
                (base, page_up(address as u64 + size as u64))
            }
            None => {
                let rounded = page_up(size as u64);
                if rounded > (USER_HIGH - USER_LOW) as u64 {
                    return Err(VmError::NoMemory);
                }
                let base = self
                    .free_range(rounded as u32, placement)
                    .ok_or(VmError::NoMemory)?;
                (base, base as u64 + rounded)
            }
        };
        if base < USER_LOW || end > USER_HIGH as u64 {
            return Err(VmError::InvalidParameter);
        }
        if self.overlaps(base, end) {
            return Err(VmError::InvalidAddress);
        }
        self.insert(Region {
            base,
            size: (end - base as u64) as u32,
            alloc_protect: protect,
            kind,
        })?;
        Ok(base)
    }

    /// The pages `[address, address + size)` covers, rounded out to pages, when they lie in one
    /// region.
    fn span(&self, address: u32, size: u32) -> Result<(Region, u32, u32), VmError> {
        let start = page_down(address);
        let end = page_up(address as u64 + size.max(1) as u64);
        let region = self.region_at(start).ok_or(VmError::InvalidAddress)?;
        if end > region.base as u64 + region.size as u64 {
            return Err(VmError::InvalidAddress);
        }
        Ok((region, start, end as u32))
    }

    /// Commit the pages `[address, address + size)` covers with `protect`: fresh pages zeroed,
    /// committed ones keeping their contents. They must lie in one region. Returns the first page.
    /// All or nothing, as Windows 2000's commit charges the whole range before it touches a page:
    /// the fresh pages' frames are all taken first, so running out of them
    /// (ERROR_NOT_ENOUGH_MEMORY) gives back those taken and leaves every page as it was.
    pub fn commit(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
        protect: u32,
    ) -> Result<u32, VmError> {
        let (region, start, end) = self.span(address, size)?;
        // The frames, chained through their first words until they are mapped.
        let mut chain = 0;
        let mut taken = 0;
        let mut va = start;
        while va < end {
            if decode(pages.entry(va)).is_none() {
                let Some(frame) = pages.zeroed_frame() else {
                    release_chain(pages, chain, taken);
                    return Err(VmError::NoMemory);
                };
                pages.set_frame_word(frame, 0, chain);
                (chain, taken) = (frame, taken + 1);
            }
            va += PAGE;
        }
        let mut va = start;
        while va < end {
            let (frame, protect) = match decode(pages.entry(va)) {
                Some((frame, _)) => (frame, settle(region.kind, pages, frame, protect)),
                None => {
                    let frame = chain;
                    chain = pages.frame_word(frame, 0);
                    pages.set_frame_word(frame, 0, 0);
                    (frame, protect)
                }
            };
            pages.set_entry(va, encode(frame, protect));
            va += PAGE;
        }
        Ok(start)
    }

    /// How many pages of `[address, address + size)` are not committed yet (the charge a commit
    /// of the range takes). They must lie in one region.
    pub fn uncommitted_pages(
        &self,
        pages: &impl Pages,
        address: u32,
        size: u32,
    ) -> Result<u32, VmError> {
        let (_, start, end) = self.span(address, size)?;
        let mut fresh = 0;
        let mut va = start;
        while va < end {
            if !committed_entry(pages.entry(va)) {
                fresh += 1;
            }
            va += PAGE;
        }
        Ok(fresh)
    }

    /// Commit the pages `[address, address + size)` covers with `protect` as demand: charged, not
    /// mapped — each fresh page's entry is a demand-zero one (a guarded protection a guard one),
    /// and the first touch faults a zeroed frame in. A page already committed keeps its contents
    /// and frame and takes the new protection. They must lie in one region. Returns the first page
    /// and how many pages were freshly committed (the commit's charge); no frame is taken, so
    /// nothing can run out halfway.
    pub fn commit_demand(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
        protect: u32,
    ) -> Result<(u32, u32), VmError> {
        let (region, start, end) = self.span(address, size)?;
        let mut fresh = 0;
        let mut va = start;
        while va < end {
            let entry = pages.entry(va);
            if !committed_entry(entry) {
                fresh += 1;
                pages.set_entry(va, demand_entry(protect));
            } else if backing_tag(entry) != 0 {
                // A paged-out or view page keeps its backing; it takes the new protection.
                pages.set_entry(
                    va,
                    encode_backing(backing_tag(entry), backing_payload(entry), protect),
                );
            } else {
                match pte::decode(entry) {
                    // Already committed but still without a frame: re-protect the entry itself.
                    Some((_, 0, _)) => {
                        pages.set_entry(va, demand_entry(protect));
                    }
                    Some((_, frame, _)) => {
                        let protect = settle(region.kind, pages, frame, protect);
                        pages.set_entry(va, encode(frame, protect));
                    }
                    None => unreachable!("committed above"),
                }
            }
            va += PAGE;
        }
        Ok((start, fresh))
    }

    /// Decommit the pages `[address, address + size)` covers (size zero: the whole region, from its
    /// base). They must lie in one region. Returns how many of them were committed (the charge
    /// the decommit discharges).
    pub fn decommit(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
    ) -> Result<u32, VmError> {
        let (start, end) = if size == 0 {
            let region = self.region_at(address).ok_or(VmError::InvalidAddress)?;
            if region.base != address {
                return Err(VmError::InvalidAddress);
            }
            (region.base, region.base + region.size)
        } else {
            let (_, start, end) = self.span(address, size)?;
            (start, end)
        };
        Ok(self.drop_pages(pages, start, end))
    }

    /// Clear the entries of `[start, end)`, each committed page dropping its hold on its frame —
    /// an inaccessible or guarded page's too: it still names its frame when it has one (a frame
    /// other holders still map stays with them); a demand page — demand-zero, or a guard
    /// committed without a frame — names none. A soft entry goes with its backing: a transition
    /// entry's frame (off its list, then freed), a paging-file entry's slot released, a
    /// prototype entry's nothing (a view's page holds no frame until it is faulted in). Returns
    /// how many pages were committed (the charge the drop discharges; a view's prototype pages
    /// were never charged).
    fn drop_pages(&self, pages: &mut impl Pages, start: u32, end: u32) -> u32 {
        let mut charged = 0;
        let mut va = start;
        while va < end {
            let entry = pages.entry(va);
            if committed_entry(entry) {
                pages.set_entry(va, 0);
                match backing_tag(entry) {
                    TAG_PAGE_FILE => {
                        pages.discard_backing(backing_payload(entry) >> FRAME_SHIFT);
                        charged += 1;
                    }
                    TAG_TRANSITION => {
                        pages.free_frame(backing_payload(entry));
                        charged += 1;
                    }
                    TAG_PROTOTYPE => {}
                    _ => {
                        if let Some((_, frame, _)) = pte::decode(entry) {
                            if frame != 0 {
                                pages.free_frame(frame);
                            }
                        }
                        charged += 1;
                    }
                }
            }
            va += PAGE;
        }
        charged
    }

    /// Release the region based at `address`: its pages decommitted (a view's frames stay with
    /// their section) and the reservation gone. Returns the region and how many of its pages were
    /// committed (the charge the release discharges).
    pub fn release(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
    ) -> Result<(Region, u32), VmError> {
        let slot = self
            .regions
            .iter_mut()
            .find(|r| r.is_some_and(|r| r.base == address))
            .ok_or(VmError::InvalidAddress)?;
        let region = slot.take().unwrap();
        let charged = self.drop_pages(pages, region.base, region.base + region.size);
        Ok((region, charged))
    }

    /// Give every committed page of the pages `[address, address + size)` covers `protect`. They
    /// must lie in one region and all be committed — a demand-zero page among them takes the new
    /// protection without being mapped. Returns the first page's old protection.
    pub fn protect(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
        protect: u32,
    ) -> Result<u32, VmError> {
        let (region, start, end) = self.span(address, size)?;
        let mut old = None;
        let mut va = start;
        while va < end {
            let entry = pages.entry(va);
            if !committed_entry(entry) {
                return Err(VmError::InvalidAddress);
            }
            let was = if backing_tag(entry) != 0 {
                soft_protect(entry)
            } else {
                pte::decode(entry).expect("committed above").2
            };
            old.get_or_insert(was);
            va += PAGE;
        }
        let mut va = start;
        while va < end {
            let entry = pages.entry(va);
            if backing_tag(entry) != 0 {
                // A paged-out or view page keeps its backing; it takes the new protection.
                pages.set_entry(
                    va,
                    encode_backing(backing_tag(entry), backing_payload(entry), protect),
                );
            } else {
                match pte::decode(entry) {
                    // Committed but still without a frame: re-protect the entry itself.
                    Some((_, 0, _)) => {
                        pages.set_entry(va, demand_entry(protect));
                    }
                    Some((_, frame, _)) => {
                        let protect = settle(region.kind, pages, frame, protect);
                        pages.set_entry(va, encode(frame, protect));
                    }
                    None => unreachable!("checked above"),
                }
            }
            va += PAGE;
        }
        Ok(old.unwrap())
    }

    /// Map `frame` — a page the kernel prepared itself, its contents already written — at the page
    /// holding `va`, committed with `protect`. The page must lie in a region and hold no frame yet:
    /// every user page belongs to a region, so a query, a release and the teardown all see it.
    pub fn map_frame(
        &mut self,
        pages: &mut impl Pages,
        va: u32,
        frame: u32,
        protect: u32,
    ) -> Result<(), VmError> {
        let page = page_down(va);
        if self.region_at(page).is_none() || committed_entry(pages.entry(page)) {
            return Err(VmError::InvalidAddress);
        }
        pages.set_entry(page, encode(frame, protect));
        Ok(())
    }

    /// Map a not-yet-backed page at `va` with the soft entry `entry` — a view's page before its
    /// first touch, whose backing (the section's file, the paging file's store) the fault path
    /// reads it in from. The page must lie in a region and hold no entry yet.
    pub fn map_soft(&mut self, pages: &mut impl Pages, va: u32, entry: u32) -> Result<(), VmError> {
        let page = page_down(va);
        if self.region_at(page).is_none() || committed_entry(pages.entry(page)) {
            return Err(VmError::InvalidAddress);
        }
        pages.set_entry(page, entry);
        Ok(())
    }

    /// Map `frame`, which another holder owns (a section's, the kernel's), at the page holding `va`
    /// with `protect`: one more holder of it. The page must lie in a region and hold no frame yet.
    pub fn map_shared(
        &mut self,
        pages: &mut impl Pages,
        va: u32,
        frame: u32,
        protect: u32,
    ) -> Result<(), VmError> {
        self.map_frame(pages, va, frame, protect)?;
        pages.share_frame(frame);
        Ok(())
    }

    /// The frame committed at the page holding `va` (accessible or not), if any.
    pub fn frame_at(&self, pages: &impl Pages, va: u32) -> Option<u32> {
        decode(pages.entry(page_down(va))).map(|(frame, _)| frame)
    }

    /// Plant a guard page at the page holding `va`: a zeroed frame committed read-write and
    /// guarded, so the first touch fires it. Nothing is planted — false — outside every region,
    /// over a page that already holds a frame, or without a frame to spare.
    pub fn plant_guard(&mut self, pages: &mut impl Pages, va: u32) -> bool {
        self.plant_page(pages, va, true)
    }

    /// Plant a stack's page at the page holding `va`: a zeroed frame committed read-write, guarded
    /// when `guarded` asks (a guard page), plain otherwise (the stack's last room, committed when
    /// it overflows). Nothing is planted — false — outside every region, over a page that already
    /// holds a frame, or without a frame to spare.
    pub fn plant_page(&mut self, pages: &mut impl Pages, va: u32, guarded: bool) -> bool {
        let page = page_down(va);
        if self.region_at(page).is_none() || decode(pages.entry(page)).is_some() {
            return false;
        }
        let protect = if guarded {
            PAGE_READWRITE | PAGE_GUARD
        } else {
            PAGE_READWRITE
        };
        match pages.zeroed_frame() {
            Some(frame) => {
                pages.set_entry(page, encode(frame, protect));
                true
            }
            None => false,
        }
    }

    /// What a query of `address` reports.
    pub fn query(&self, pages: &impl Pages, address: u32) -> Info {
        let start = page_down(address);
        let Some(region) = self.region_at(start) else {
            let next = self
                .regions
                .iter()
                .flatten()
                .filter(|r| r.base > start)
                .map(|r| r.base)
                .min()
                .unwrap_or(USER_HIGH);
            return Info {
                base: start,
                allocation_base: 0,
                allocation_protect: 0,
                size: next.saturating_sub(start),
                state: MEM_FREE,
                protect: PAGE_NOACCESS,
                mem_type: 0,
            };
        };
        let state_of = |va: u32| {
            let entry = pages.entry(va);
            match pte::decode(entry) {
                Some((_, _, protect)) => (MEM_COMMIT, protect),
                // A soft backing entry (a view's untouched page, a paged-out page) is committed,
                // with the protection its index bits record.
                None if backing_tag(entry) != 0 => (MEM_COMMIT, soft_protect(entry)),
                None => (MEM_RESERVE, 0),
            }
        };
        let first = state_of(start);
        let end = region.base + region.size;
        let mut va = start + PAGE;
        while va < end && state_of(va) == first {
            va += PAGE;
        }
        Info {
            base: start,
            allocation_base: region.base,
            allocation_protect: region.alloc_protect,
            size: va - start,
            state: first.0,
            protect: first.1,
            mem_type: region.kind.mem_type(),
        }
    }
}

/// Give back the `count` frames chained from `chain` through their first words (a commit that ran
/// out of frames).
fn release_chain(pages: &mut impl Pages, mut chain: u32, count: u32) {
    for _ in 0..count {
        let next = pages.frame_word(chain, 0);
        pages.free_frame(chain);
        chain = next;
    }
}

/// The protection a committed page of a `kind` region holding `frame` takes when given `protect`:
/// a writable protection over a frame others hold (a system DLL's page, an image's, the shared data
/// page, a section's frame) is copy-on-write, so the write stays the process's — unless the page is
/// a view's that may write its section ([`Maximum::Write`]). A page already made the process's own
/// takes the protection as given.
fn settle(kind: Kind, pages: &impl Pages, frame: u32, protect: u32) -> u32 {
    match copy_on_write_of(protect) {
        Some(copy) if kind != Kind::Mapped(Maximum::Write) && pages.frame_shared(frame) => copy,
        _ => protect,
    }
}

/// How many frame tables a section holds: each a frame of 1024 frame addresses, 4 MiB of section.
pub const SECTION_TABLES: usize = 64;
/// The largest section: what its frame tables can name.
pub const SECTION_MAX: u64 = SECTION_TABLES as u64 * 1024 * PAGE as u64;

/// A section's frames, page by page: the section is their first holder, each view mapping one a
/// further holder. They are named in frame tables — frames of 1024 frame addresses each — made as
/// the pages are first needed (an entry or a table not yet made is zero).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SectionFrames {
    tables: [u32; SECTION_TABLES],
}

impl SectionFrames {
    /// No frames yet.
    pub const fn empty() -> SectionFrames {
        SectionFrames {
            tables: [0; SECTION_TABLES],
        }
    }

    /// The frame of the section's page `index`, made when it is not yet: a zeroed frame `fill` may
    /// write. ERROR_NOT_ENOUGH_MEMORY past the largest section or without a frame.
    pub fn frame(
        &mut self,
        pages: &mut impl Pages,
        index: u32,
        fill: impl FnOnce(u32),
    ) -> Result<u32, VmError> {
        self.make(pages, index, fill, false)
    }

    /// An image segment's [`SectionFrames::frame`]: a frame it makes is linked to its slot, the
    /// back-link its caching keeps ([`SectionFrames::park`]).
    pub fn image_frame(
        &mut self,
        pages: &mut impl Pages,
        index: u32,
        fill: impl FnOnce(u32),
    ) -> Result<u32, VmError> {
        self.make(pages, index, fill, true)
    }

    fn make(
        &mut self,
        pages: &mut impl Pages,
        index: u32,
        fill: impl FnOnce(u32),
        link: bool,
    ) -> Result<u32, VmError> {
        let (table, slot) = ((index / 1024) as usize, index % 1024);
        if table >= SECTION_TABLES {
            return Err(VmError::NoMemory);
        }
        if self.tables[table] == 0 {
            self.tables[table] = pages.zeroed_frame().ok_or(VmError::NoMemory)?;
        }
        let existing = pages.frame_word(self.tables[table], slot);
        if existing != 0 {
            return Ok(existing);
        }
        let frame = pages.zeroed_frame().ok_or(VmError::NoMemory)?;
        fill(frame);
        pages.set_frame_word(self.tables[table], slot, frame);
        if link {
            pages.link_frame(frame, self.tables[table], slot);
        }
        Ok(frame)
    }

    /// The frame of the section's page `index`, when it is made (a file's section reads its page
    /// only when it is not).
    pub fn made(&self, pages: &impl Pages, index: u32) -> Option<u32> {
        let table = *self.tables.get((index / 1024) as usize)?;
        (table != 0)
            .then(|| pages.frame_word(table, index % 1024))
            .filter(|&frame| frame != 0)
    }

    /// The section is gone: it drops its hold on every frame it made (a frame a view still maps
    /// stays with the view), and gives its tables back.
    pub fn release(&mut self, pages: &mut impl Pages) {
        for table in self.tables.iter_mut().filter(|table| **table != 0) {
            for slot in 0..1024 {
                let frame = pages.frame_word(*table, slot);
                if frame != 0 {
                    pages.free_frame(frame);
                }
            }
            pages.free_frame(*table);
            *table = 0;
        }
    }

    /// Run `keep` over every frame the first `count` pages name (the frame, its table and its
    /// slot there), emptying each slot whose frame it does not keep. Returns how many it kept.
    fn sift<P: Pages>(
        &mut self,
        pages: &mut P,
        count: u32,
        mut keep: impl FnMut(&mut P, u32, u32, u32) -> bool,
    ) -> u32 {
        let mut kept = 0;
        let count = count.min(SECTION_TABLES as u32 * 1024);
        for index in 0..count {
            let (table, slot) = (self.tables[(index / 1024) as usize], index % 1024);
            if table == 0 {
                continue;
            }
            let frame = pages.frame_word(table, slot);
            if frame == 0 {
                continue;
            }
            if keep(pages, frame, table, slot) {
                kept += 1;
            } else {
                pages.set_frame_word(table, slot, 0);
            }
        }
        kept
    }

    /// An image segment's last reference went and it stays cached, its first `count` pages the
    /// image's: it parks its frames, each going to Standby with its back-link — the allocator may
    /// take it, [`SectionFrames::revive`] takes it back — and keeps its tables. A frame another
    /// holder still has stays with it, its slot emptied. Returns how many frames wait on Standby.
    pub fn park(&mut self, pages: &mut impl Pages, count: u32) -> u32 {
        self.sift(pages, count, |pages, frame, _, _| pages.cache_frame(frame))
    }

    /// A parked segment is referenced again: each frame still its own comes back into use from
    /// Standby (no read); a slot whose frame the allocator took meanwhile is emptied, its page made
    /// again when a view needs it. Returns how many frames came back.
    pub fn revive(&mut self, pages: &mut impl Pages, count: u32) -> u32 {
        self.sift(pages, count, |pages, frame, table, slot| {
            pages.reclaim_frame(frame, table, slot)
        })
    }

    /// A parked segment is purged: each frame still its own goes back (off Standby), its tables
    /// with them; a frame the allocator took meanwhile is no longer the segment's to give.
    pub fn release_parked(&mut self, pages: &mut impl Pages, count: u32) {
        self.revive(pages, count);
        self.release(pages);
    }
}

/// Map `frame`, prepared by the kernel, at `va` in `space` — the running process's — with
/// `protect`: the kernel's own areas (the image, the stacks' first pages, the TEB, the parameters,
/// the stubs), each mapped once inside its region.
#[cfg(target_arch = "x86")]
pub fn map_prepared(space: &mut AddressSpace, va: u32, frame: u32, protect: u32) {
    space
        .map_frame(&mut CurrentPages, va, frame, protect)
        .expect("the kernel's own pages map once, inside their regions");
}

/// A zeroed frame of the kernel's, mapped at `va` in `space` (the running process's) with
/// `protect`: the frame, for the caller to fill.
#[cfg(target_arch = "x86")]
pub fn map_zeroed(space: &mut AddressSpace, va: u32, protect: u32) -> u32 {
    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, &[]);
    map_prepared(space, va, frame, protect);
    frame
}

/// The live page tables — the running thread's address-space process's: its own process's, or
/// while attached the one it attached to (see [`crate::sched::attach`]) — and the frame database.
#[cfg(target_arch = "x86")]
pub struct CurrentPages;

#[cfg(target_arch = "x86")]
impl Pages for CurrentPages {
    fn entry(&self, va: u32) -> u32 {
        crate::mem::paging::user_pte(va)
    }

    fn set_entry(&mut self, va: u32, entry: u32) {
        crate::mem::paging::set_user_pte(va, entry);
    }

    fn zeroed_frame(&mut self) -> Option<u32> {
        // A reserve stays with the kernel: a program that exhausts memory gets an error, never the
        // kernel a panic.
        const KERNEL_RESERVE: u32 = 256;
        let frame = crate::mem::bootmem::with_frame_db(|db| {
            if db.available() <= KERNEL_RESERVE {
                return None;
            }
            db.try_allocate(crate::mem::frame::PRIMARY_COLOR)
        })?;
        let phys = frame * PAGE;
        crate::mem::paging::init_frame(phys, 0, &[]);
        Some(phys)
    }

    fn free_frame(&mut self, frame: u32) {
        crate::mem::bootmem::with_frame_db(|db| {
            let fid = frame / PAGE;
            // A frame on a backing list (a transition entry's, dropped without being read back)
            // comes off it first.
            let listed = matches!(
                db.entry(fid).state,
                crate::mem::frame::FrameState::Standby
                    | crate::mem::frame::FrameState::Modified
                    | crate::mem::frame::FrameState::ModifiedNoWrite
            );
            if listed {
                db.unlink(fid);
            }
            // A transition entry's frame came off its list still holding the entry's hold: with
            // the hold dropped the frame has no holder left, so it goes back to the pool.
            if db.unshare(fid) || (listed && db.entry(fid).share_count == 0) {
                db.release(fid, crate::mem::frame::FrameState::Free);
            }
        });
    }

    fn share_frame(&mut self, frame: u32) {
        crate::mem::bootmem::with_frame_db(|db| db.share(frame / PAGE));
    }

    fn frame_shared(&self, frame: u32) -> bool {
        crate::mem::bootmem::with_frame_db(|db| db.entry(frame / PAGE).share_count > 0)
    }

    fn copy_frame(&mut self, from: u32, to: u32) {
        crate::mem::paging::copy_frame(from, to);
    }

    fn frame_word(&self, frame: u32, index: u32) -> u32 {
        crate::mem::paging::read_frame_word(frame, index as usize)
    }

    fn set_frame_word(&mut self, frame: u32, index: u32, value: u32) {
        crate::mem::paging::write_frame(frame, index as usize * 4, &value.to_le_bytes());
    }

    fn activate_frame(&mut self, frame: u32) {
        crate::mem::bootmem::with_frame_db(|db| {
            let fid = frame / PAGE;
            if matches!(
                db.entry(fid).state,
                crate::mem::frame::FrameState::Standby
                    | crate::mem::frame::FrameState::Modified
                    | crate::mem::frame::FrameState::ModifiedNoWrite
            ) {
                db.unlink(fid);
            }
            // The transition entry the frame was held for is being re-faulted: its hold drops.
            db.unshare(fid);
        });
    }

    fn fill_frame(&mut self, frame: u32, bytes: &[u8]) {
        crate::mem::paging::write_frame(frame, 0, bytes);
    }

    fn link_frame(&mut self, frame: u32, table: u32, slot: u32) {
        let prototype = crate::mem::frame::Prototype::new(table / PAGE, slot);
        crate::mem::bootmem::with_frame_db(|db| db.link_prototype(frame / PAGE, prototype));
    }

    fn reclaim_frame(&mut self, frame: u32, table: u32, slot: u32) -> bool {
        let prototype = crate::mem::frame::Prototype::new(table / PAGE, slot);
        crate::mem::bootmem::with_frame_db(|db| db.reclaim_prototype(frame / PAGE, prototype))
    }

    fn cache_frame(&mut self, frame: u32) -> bool {
        crate::mem::bootmem::with_frame_db(|db| db.park_prototype(frame / PAGE))
    }

    fn discard_backing(&mut self, slot: u32) {
        let _ = crate::mem::pagingfile::with_paging_file(|file| {
            let slot = u64::from(slot);
            if file.is_allocated(slot) {
                file.free_slot(slot);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Page tables as a map, frames numbered from 1 MiB: their extra holders, their words and their
    /// contents (a frame's first word stands for its contents), the frames given back, the backing
    /// slots released, the frames activated off a list, and how many more frames there are to give
    /// (none: no end).
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
        discarded: Vec<u32>,
        activated: Vec<u32>,
        holders: HashMap<u32, u32>,
        words: HashMap<(u32, u32), u32>,
        budget: Option<u32>,
    }

    impl Pages for Fake {
        fn entry(&self, va: u32) -> u32 {
            *self.entries.get(&va).unwrap_or(&0)
        }

        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }

        fn zeroed_frame(&mut self) -> Option<u32> {
            if let Some(budget) = &mut self.budget {
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

        fn discard_backing(&mut self, slot: u32) {
            self.discarded.push(slot);
        }
    }

    /// The views a space records: one per base, found by its base, the table's capacity enforced,
    /// and every one handed back (with its section) when the space goes.
    #[test]
    fn the_space_records_its_views() {
        use crate::ob::{Mapping, ObjectId, ObjectType, SegmentId};
        let section = |index| {
            Mapping::Section(ObjectId {
                kind: ObjectType::Section,
                index,
                generation: 0,
            })
        };
        let mut space = Box::new(AddressSpace::new());
        assert!(space.add_view_at(0x30_0000, 0, section(1)));
        assert!(space.add_view_at(0x31_0000, 0x10000, section(2)));
        assert_eq!(
            space.take_view(0x30_1000),
            None,
            "a view is named by its base"
        );
        let taken = space.take_view(0x30_0000).unwrap();
        assert_eq!((taken.offset, taken.mapping), (0, section(1)));
        assert_eq!(space.take_view(0x30_0000), None, "a view goes once");
        for index in 1..VIEWS as u16 {
            assert!(space.add_view_at(0x40_0000 + index as u32 * 0x1_0000, 0, section(3)));
        }
        assert!(!space.has_view_room());
        assert!(
            !space.add_view_at(0x7000_0000, 0, section(4)),
            "the table is full"
        );
        let image = Mapping::Image(SegmentId {
            index: 5,
            generation: 1,
        });
        assert_eq!(
            space.take_view(0x41_0000).map(|v| v.mapping),
            Some(section(3))
        );
        assert!(
            space.add_view_at(0x41_0000, 0, image),
            "an image's view maps its segment"
        );
        let mut released = Vec::new();
        space.drop_views(|view| released.push(view.mapping));
        assert_eq!(released.len(), VIEWS);
        assert_eq!(
            released
                .iter()
                .filter(|&&mapping| mapping == section(2))
                .count(),
            1
        );
        assert_eq!(
            released.iter().filter(|&&mapping| mapping == image).count(),
            1
        );
        assert!(space.has_view_room() && space.take_view(0x31_0000).is_none());
    }

    /// A guard page fires once, keeping its base protection and frame.
    #[test]
    fn a_guard_page_fires_once() {
        let mut pages = Fake::default();
        pages.set_entry(0x1_0000, encode(0x20_0000, PAGE_READWRITE | PAGE_GUARD));
        assert!(fire_guard(&mut pages, 0x1_0123));
        assert_eq!(
            decode(pages.entry(0x1_0000)),
            Some((0x20_0000, PAGE_READWRITE))
        );
        assert!(!fire_guard(&mut pages, 0x1_0000));
        assert!(!fire_guard(&mut pages, 0x2_0000));
    }

    /// A guard page committed without a frame of its own (a demand commit's guard entry) fires
    /// too: the guard flag goes, the page stays committed and unmapped — its retried access
    /// faults a zeroed frame in — and it does not fire again.
    #[test]
    fn a_frameless_guard_page_fires_once_into_a_demand_page() {
        let mut pages = Fake::default();
        pages.set_entry(
            0x1_0000,
            pte::encode(PteKind::Guard, 0, PAGE_READWRITE | PAGE_GUARD),
        );
        assert!(fire_guard(&mut pages, 0x1_0123));
        let entry = pages.entry(0x1_0000);
        assert_eq!(pte::classify(entry), PteKind::DemandZero);
        assert_eq!(pte::decode(entry).unwrap().2, PAGE_READWRITE);
        assert!(!fire_guard(&mut pages, 0x1_0000));
    }

    /// Pages over a real frame database (frame ids 1..TABLE, physical = id * PAGE), its frames'
    /// words in a map: the image cache's parking, revival and the allocator's repurposing as the
    /// kernel's [`CurrentPages`] runs them.
    struct DbPages {
        db: crate::mem::frame::FrameDb,
        words: HashMap<(u32, u32), u32>,
    }

    impl DbPages {
        /// A database whose every frame is free.
        fn new() -> DbPages {
            use crate::mem::frame::{ColorTables, FrameDb, FrameEntry, NoHooks};
            const TABLE: usize = 32;
            let table: &'static mut [FrameEntry] =
                Box::leak(vec![FrameEntry::new(); TABLE].into_boxed_slice());
            let buckets: &'static mut ColorTables = Box::leak(Box::new(ColorTables::new()));
            let mut db = FrameDb::new(
                table,
                buckets,
                crate::mem::frame::DEFAULT_COLOR_COUNT,
                NoHooks,
            );
            db.release_run(1..TABLE as u32, crate::mem::frame::FrameState::Free);
            DbPages {
                db,
                words: HashMap::new(),
            }
        }

        fn state(&self, frame: u32) -> crate::mem::frame::FrameState {
            self.db.entry(frame / PAGE).state
        }

        /// Another use takes every frame the allocator has, standby ones included.
        fn exhaust(&mut self) -> Vec<u32> {
            let mut taken = Vec::new();
            while let Some(fid) = self.db.try_allocate(crate::mem::frame::PRIMARY_COLOR) {
                taken.push(fid * PAGE);
            }
            taken
        }
    }

    impl Pages for DbPages {
        fn entry(&self, _va: u32) -> u32 {
            0
        }

        fn set_entry(&mut self, _va: u32, _entry: u32) {}

        fn zeroed_frame(&mut self) -> Option<u32> {
            let fid = self.db.try_allocate(crate::mem::frame::PRIMARY_COLOR)?;
            self.words.retain(|&(frame, _), _| frame != fid * PAGE);
            Some(fid * PAGE)
        }

        fn free_frame(&mut self, frame: u32) {
            if self.db.unshare(frame / PAGE) {
                self.db
                    .release(frame / PAGE, crate::mem::frame::FrameState::Free);
            }
        }

        fn share_frame(&mut self, frame: u32) {
            self.db.share(frame / PAGE);
        }

        fn frame_shared(&self, frame: u32) -> bool {
            self.db.entry(frame / PAGE).share_count > 0
        }

        fn copy_frame(&mut self, _from: u32, _to: u32) {}

        fn frame_word(&self, frame: u32, index: u32) -> u32 {
            *self.words.get(&(frame, index)).unwrap_or(&0)
        }

        fn set_frame_word(&mut self, frame: u32, index: u32, value: u32) {
            self.words.insert((frame, index), value);
        }

        fn link_frame(&mut self, frame: u32, table: u32, slot: u32) {
            let prototype = crate::mem::frame::Prototype::new(table / PAGE, slot);
            self.db.link_prototype(frame / PAGE, prototype);
        }

        fn reclaim_frame(&mut self, frame: u32, table: u32, slot: u32) -> bool {
            let prototype = crate::mem::frame::Prototype::new(table / PAGE, slot);
            self.db.reclaim_prototype(frame / PAGE, prototype)
        }

        fn cache_frame(&mut self, frame: u32) -> bool {
            self.db.park_prototype(frame / PAGE)
        }
    }

    /// A cached image's frames wait on Standby, still available to the allocator, and its revival
    /// takes them back as they were: no page is made (read) again.
    #[test]
    fn a_cached_image_revives_without_reading() {
        use crate::mem::frame::FrameState;
        let mut pages = DbPages::new();
        let mut image = SectionFrames::empty();
        let mut reads = 0;
        let frames: Vec<u32> = (0..3)
            .map(|page| image.image_frame(&mut pages, page, |_| reads += 1).unwrap())
            .collect();
        pages.set_frame_word(frames[1], 0, 0x5A5A);
        let available = pages.db.available();

        assert_eq!(image.park(&mut pages, 3), 3, "every frame parked");
        assert!(frames
            .iter()
            .all(|&frame| pages.state(frame) == FrameState::Standby));
        assert_eq!(pages.db.available(), available + 3, "available again");
        assert_eq!(image.made(&pages, 1), Some(frames[1]), "still named");

        assert_eq!(image.revive(&mut pages, 3), 3, "every frame came back");
        assert!(frames
            .iter()
            .all(|&frame| pages.state(frame) == FrameState::Active));
        assert_eq!(pages.db.available(), available);
        for (page, &frame) in frames.iter().enumerate() {
            assert_eq!(
                image.image_frame(&mut pages, page as u32, |_| reads += 1),
                Ok(frame)
            );
        }
        assert_eq!(reads, 3, "nothing read again");
        assert_eq!(pages.frame_word(frames[1], 0), 0x5A5A, "the page as it was");
        assert!(pages.db.audit().is_ok());
    }

    /// The allocator may take a cached image's frames: the frame loses its link to the segment's
    /// slot, so the revival finds the slot no longer its own, empties it, and the page is made
    /// again when a view needs it — the frame's new user is never handed to the segment.
    #[test]
    fn a_cached_frame_the_allocator_takes_is_no_longer_the_images() {
        use crate::mem::frame::FrameState;
        let mut pages = DbPages::new();
        let mut image = SectionFrames::empty();
        let frames: Vec<u32> = (0..2)
            .map(|page| image.image_frame(&mut pages, page, |_| ()).unwrap())
            .collect();
        image.park(&mut pages, 2);
        // Another use takes every frame, the parked ones last (Standby comes after Free).
        let taken = pages.exhaust();
        assert!(frames.iter().all(|frame| taken.contains(frame)));
        // It gives one back, to the free list; the other stays in use.
        pages.free_frame(frames[0]);
        assert_eq!(pages.state(frames[0]), FrameState::Free);

        assert_eq!(image.revive(&mut pages, 2), 0, "neither is the image's");
        assert_eq!(image.made(&pages, 0), None, "the slots are emptied");
        assert_eq!(image.made(&pages, 1), None);
        assert_eq!(
            pages.state(frames[1]),
            FrameState::Active,
            "left to its user"
        );
        // The page is made again from a fresh frame.
        let mut reads = 0;
        let again = image.image_frame(&mut pages, 0, |_| reads += 1).unwrap();
        assert_eq!(reads, 1);
        assert_ne!(again, frames[1]);
        assert!(pages.db.audit().is_ok());
    }

    /// A cached image purged (its file deleted, cut or written, or its record needed) gives back
    /// the frames still its own, and its tables, and nothing it no longer owns.
    #[test]
    fn a_purged_image_gives_back_only_its_own_frames() {
        use crate::mem::frame::FrameState;
        let mut pages = DbPages::new();
        let free = pages.db.available();
        let mut image = SectionFrames::empty();
        let frames: Vec<u32> = (0..3)
            .map(|page| image.image_frame(&mut pages, page, |_| ()).unwrap())
            .collect();
        image.park(&mut pages, 3);
        // One parked frame goes to another use, which keeps it.
        let mut taken = Vec::new();
        while let Some(fid) = pages.db.try_allocate(crate::mem::frame::PRIMARY_COLOR) {
            taken.push(fid * PAGE);
            if taken.contains(&frames[0]) {
                break;
            }
        }
        for &frame in taken.iter().filter(|&&frame| frame != frames[0]) {
            pages.free_frame(frame);
        }

        image.release_parked(&mut pages, 3);
        assert_eq!(pages.state(frames[0]), FrameState::Active, "its user's");
        assert_eq!(pages.state(frames[1]), FrameState::Free);
        assert_eq!(pages.state(frames[2]), FrameState::Free);
        assert_eq!(
            pages.db.available(),
            free - 1,
            "everything but the taken frame is back, the table too"
        );
        assert_eq!(pages.db.list_total(FrameState::Standby), 0);
        assert!(pages.db.audit().is_ok());
    }

    /// A section's frames are made once, as first needed, and held by the section and by each view
    /// mapping them: a view's release leaves them to the section, the section's leaves them to the
    /// views still mapping them, and the last holder gives each back (its tables with the section).
    #[test]
    fn section_frames_go_with_their_last_holder() {
        let mut vm = space();
        let mut pages = Fake::default();
        let mut section = SectionFrames::empty();
        let mut filled = 0;
        let first = section.frame(&mut pages, 0, |_| filled += 1).unwrap();
        assert_eq!(
            section.frame(&mut pages, 0, |_| filled += 1),
            Ok(first),
            "made once"
        );
        assert_eq!(filled, 1);
        assert_eq!(section.made(&pages, 0), Some(first));
        assert_eq!(section.made(&pages, 1), None);
        let one = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        let two = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        vm.map_shared(&mut pages, one, first, PAGE_READWRITE)
            .unwrap();
        vm.map_shared(&mut pages, two, first, PAGE_READONLY)
            .unwrap();
        assert_eq!(vm.query(&pages, one).mem_type, MEM_MAPPED);
        vm.release(&mut pages, one).unwrap();
        assert!(
            !pages.freed.contains(&first),
            "the section and the other view still hold it"
        );
        section.release(&mut pages);
        assert!(
            !pages.freed.contains(&first),
            "the other view still maps it"
        );
        assert_eq!(pages.freed.len(), 1, "the section's table went with it");
        vm.release(&mut pages, two).unwrap();
        assert!(pages.freed.contains(&first), "its last holder gave it back");
        assert_eq!(
            section.frame(&mut Fake::default(), (SECTION_TABLES * 1024) as u32, |_| ()),
            Err(VmError::NoMemory),
            "past the largest section"
        );
    }

    /// A copy-on-write page is read-only to the hardware; its first write turns it read-write — on
    /// its own frame when no one else holds it, on a copy when a section still maps the frame.
    #[test]
    fn copy_on_write_makes_the_page_its_own() {
        let mut vm = space();
        let mut pages = Fake::default();

        // Alone: the frame stays, the protection turns.
        let image = vm
            .reserve(None, PAGE, PAGE_EXECUTE_WRITECOPY, Kind::Image)
            .unwrap();
        vm.map_frame(&mut pages, image, 0x0050_0000, PAGE_WRITECOPY)
            .unwrap();
        assert!(copy_on_write(&mut pages, image + 0x10));
        assert_eq!(
            decode(pages.entry(image)),
            Some((0x0050_0000, PAGE_READWRITE))
        );
        assert!(
            !copy_on_write(&mut pages, image),
            "a read-write page is not copy-on-write"
        );

        // Shared: a copy of the contents, the original left to its other holder.
        let mut section = SectionFrames::empty();
        let frame = section.frame(&mut pages, 0, |_| ()).unwrap();
        pages.set_frame_word(frame, 0, 77);
        let view = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        vm.map_shared(&mut pages, view, frame, PAGE_WRITECOPY)
            .unwrap();
        assert!(copy_on_write(&mut pages, view));
        let (copy, protect) = decode(pages.entry(view)).unwrap();
        assert_ne!(copy, frame);
        assert_eq!((protect, pages.frame_word(copy, 0)), (PAGE_READWRITE, 77));
        assert!(
            !pages.frame_shared(frame),
            "the view let go of the section's frame"
        );
        assert!(!pages.freed.contains(&frame));
    }

    /// A page whose frame the kernel shares into every process (a system DLL's, the shared data
    /// page) given a writable protection is copy-on-write instead: the first write copies it, the
    /// kernel's frame untouched. A view's writable page writes its section.
    #[test]
    fn writable_protections_over_shared_frames_copy_on_write() {
        let mut vm = space();
        let mut pages = Fake::default();
        let dll = vm
            .reserve(None, PAGE, PAGE_EXECUTE_WRITECOPY, Kind::Image)
            .unwrap();
        pages.holders.insert(0x0060_0000, 0);
        vm.map_shared(&mut pages, dll, 0x0060_0000, PAGE_EXECUTE_READ)
            .unwrap();
        assert_eq!(
            vm.protect(&mut pages, dll, PAGE, PAGE_EXECUTE_READWRITE),
            Ok(PAGE_EXECUTE_READ)
        );
        assert_eq!(vm.query(&pages, dll).protect, PAGE_EXECUTE_WRITECOPY);
        assert!(copy_on_write(&mut pages, dll));
        let (copy, protect) = decode(pages.entry(dll)).unwrap();
        assert_ne!(copy, 0x0060_0000, "the kernel's frame is not written");
        assert_eq!(protect, PAGE_EXECUTE_READWRITE);
        // Its own now: a further protection is what it says.
        vm.protect(&mut pages, dll, PAGE, PAGE_READWRITE).unwrap();
        assert_eq!(vm.query(&pages, dll).protect, PAGE_READWRITE);

        let view = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        pages.holders.insert(0x0061_0000, 0);
        vm.map_shared(&mut pages, view, 0x0061_0000, PAGE_READONLY)
            .unwrap();
        vm.protect(&mut pages, view, PAGE, PAGE_READWRITE).unwrap();
        assert_eq!(vm.query(&pages, view).protect, PAGE_READWRITE);
    }

    /// The reserved size counts every reservation.
    #[test]
    fn the_reserved_size_counts_every_reservation() {
        let mut vm = space();
        vm.reserve(None, 0x3000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.reserve(None, 0x1_0000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(vm.reserved_size(), 0x1_3000);
    }

    fn space() -> Box<AddressSpace> {
        Box::new(AddressSpace::new())
    }

    /// The capture's reserve, commit, decommit and release sequence, region by region.
    #[test]
    fn the_captured_virtual_sequence() {
        let mut vm = space();
        let mut pages = Fake::default();
        let one = vm.reserve(None, 1, PAGE_NOACCESS, Kind::Private).unwrap();
        assert_eq!(one % GRANULARITY, 0);
        let info = vm.query(&pages, one);
        assert_eq!(
            (
                info.state,
                info.protect,
                info.mem_type,
                info.size,
                info.allocation_protect
            ),
            (MEM_RESERVE, 0, MEM_PRIVATE, 0x1000, PAGE_NOACCESS)
        );
        vm.release(&mut pages, one).unwrap();
        assert_eq!(vm.query(&pages, one).state, MEM_FREE);

        let mib = vm
            .reserve(None, 0x10_0000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(
            vm.commit(&mut pages, mib + 0x1_0000, 0x2000, PAGE_READWRITE),
            Ok(mib + 0x1_0000)
        );
        assert_eq!(vm.query(&pages, mib).size, 0x1_0000);
        let committed = vm.query(&pages, mib + 0x1_0000);
        assert_eq!(
            (committed.state, committed.protect, committed.size),
            (MEM_COMMIT, PAGE_READWRITE, 0x2000)
        );
        assert_eq!(vm.query(&pages, mib + 0x1_2000).size, 0xEE000);
        vm.decommit(&mut pages, mib + 0x1_0000, 0x2000).unwrap();
        assert_eq!(
            vm.query(&pages, mib + 0x1_0000).size,
            0xF0000,
            "the reserved run after the decommit"
        );
        assert_eq!(pages.freed.len(), 2);

        assert_eq!(
            vm.release(&mut pages, mib + 0x1000),
            Err(VmError::InvalidAddress),
            "not the base"
        );
        vm.release(&mut pages, mib).unwrap();

        assert_eq!(
            vm.reserve(Some(0x2000_0000), 0x1000, PAGE_READWRITE, Kind::Private),
            Ok(0x2000_0000)
        );
        assert_eq!(
            vm.reserve(Some(0x2000_0000), 0x1000, PAGE_READWRITE, Kind::Private),
            Err(VmError::InvalidAddress)
        );
        // A reserve-and-commit commits the whole reservation, from the rounded-down base.
        let at = vm
            .reserve(Some(0x3000_1234), 0x1000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(at, 0x3000_0000);
        let size = vm.region_at(at).unwrap().size;
        vm.commit(&mut pages, at, size, PAGE_READWRITE).unwrap();
        assert_eq!(
            vm.query(&pages, at).size,
            0x3000,
            "its region: the start rounded down, the end up"
        );
        assert_eq!(
            vm.commit(&mut pages, 0x4000_0000, 0x1000, PAGE_READWRITE),
            Err(VmError::InvalidAddress)
        );
        assert_eq!(
            vm.reserve(None, 0, PAGE_READWRITE, Kind::Private),
            Err(VmError::InvalidParameter)
        );
        assert_eq!(
            vm.reserve(Some(0x8000_0000), 0x1000, PAGE_READWRITE, Kind::Private),
            Err(VmError::InvalidParameter)
        );
    }

    /// Protections: the entry keeps the exact protection, a no-access or guard page keeps its frame
    /// without being present, and a protect over an uncommitted page fails.
    #[test]
    fn protections_round_trip_through_the_entries() {
        for protect in [
            PAGE_READONLY,
            PAGE_READWRITE,
            PAGE_WRITECOPY,
            PAGE_EXECUTE,
            PAGE_EXECUTE_READ,
            PAGE_EXECUTE_READWRITE,
            PAGE_EXECUTE_WRITECOPY,
            PAGE_NOACCESS,
            PAGE_READWRITE | PAGE_GUARD,
        ] {
            assert_eq!(
                decode(encode(0x0050_0000, protect)),
                Some((0x0050_0000, protect)),
                "{protect:#x}"
            );
            assert!(names_frame(encode(0x0050_0000, protect)), "{protect:#x}");
        }
        assert_eq!(encode(0x0050_0000, PAGE_NOACCESS) & PRESENT, 0);
        assert_eq!(
            encode(0x0050_0000, PAGE_READWRITE | PAGE_GUARD) & PRESENT,
            0
        );
        // Copy-on-write pages are read-only to the hardware.
        assert_eq!(encode(0x0050_0000, PAGE_WRITECOPY) & WRITE, 0);
        assert_eq!(encode(0x0050_0000, PAGE_EXECUTE_WRITECOPY) & WRITE, 0);
        assert_ne!(encode(0x0050_0000, PAGE_READWRITE) & WRITE, 0);
        assert_eq!(
            decode(0x0050_0000 | PRESENT | WRITE | USER),
            Some((0x0050_0000, PAGE_READWRITE)),
            "an entry without a recorded protection"
        );
        assert_eq!(
            decode(0x0050_0000 | PRESENT | USER),
            Some((0x0050_0000, PAGE_READONLY))
        );
        assert_eq!(decode(0), None);
        assert!(!names_frame(0));

        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x4000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit(&mut pages, base, 0x2000, PAGE_READWRITE).unwrap();
        assert_eq!(
            vm.protect(&mut pages, base, 0x1000, PAGE_READONLY),
            Ok(PAGE_READWRITE)
        );
        assert_eq!(vm.query(&pages, base).protect, PAGE_READONLY);
        assert_eq!(vm.query(&pages, base).size, 0x1000);
        assert_eq!(
            vm.protect(&mut pages, base, 0x3000, PAGE_READONLY),
            Err(VmError::InvalidAddress),
            "past the committed range"
        );
        assert!(valid_protect(PAGE_READWRITE | PAGE_GUARD));
        assert!(
            !valid_protect(0x3) && !valid_protect(0) && !valid_protect(PAGE_NOACCESS | PAGE_GUARD)
        );
    }

    /// The kernel's own pages map only inside a region and only over an empty page; a guard is
    /// planted the same way, and a decommit gives back a page the program made inaccessible too
    /// (its frame is still the process's).
    #[test]
    fn kernel_pages_map_inside_regions() {
        let mut vm = space();
        let mut pages = Fake::default();
        vm.insert(Region {
            base: 0x31_0000,
            size: 0x2000,
            alloc_protect: PAGE_READWRITE,
            kind: Kind::Private,
        })
        .unwrap();
        assert_eq!(
            vm.map_frame(&mut pages, 0x31_0000, 0x0050_0000, PAGE_READWRITE),
            Ok(())
        );
        assert_eq!(vm.frame_at(&pages, 0x31_0123), Some(0x0050_0000));
        assert_eq!(
            vm.map_frame(&mut pages, 0x31_0000, 0x0051_0000, PAGE_READWRITE),
            Err(VmError::InvalidAddress),
            "already mapped"
        );
        assert_eq!(
            vm.map_frame(&mut pages, 0x40_0000, 0x0051_0000, PAGE_READWRITE),
            Err(VmError::InvalidAddress),
            "outside every region"
        );
        assert!(vm.plant_guard(&mut pages, 0x31_1000));
        assert_eq!(
            vm.query(&pages, 0x31_1000).protect,
            PAGE_READWRITE | PAGE_GUARD
        );
        assert!(!vm.plant_guard(&mut pages, 0x31_1000), "already planted");
        assert!(
            !vm.plant_guard(&mut pages, 0x40_0000),
            "outside every region"
        );

        // The program sets the mapped page no-access: a decommit still gives its frame back.
        vm.protect(&mut pages, 0x31_0000, 0x1000, PAGE_NOACCESS)
            .unwrap();
        vm.decommit(&mut pages, 0x31_0000, 0x1000).unwrap();
        assert!(pages.freed.contains(&0x0050_0000));
        assert_eq!(vm.frame_at(&pages, 0x31_0000), None);

        // A release gives back the guard's frame with the region.
        let guard = vm.frame_at(&pages, 0x31_1000).unwrap();
        vm.release(&mut pages, 0x31_0000).unwrap();
        assert!(pages.freed.contains(&guard));
        assert_eq!(vm.query(&pages, 0x31_0000).state, MEM_FREE);
    }

    /// A program reserving in a loop gets its reservations until the table is full, well past the
    /// few hundred a smaller table allowed; the next one is ERROR_NOT_ENOUGH_MEMORY.
    #[test]
    fn the_region_table_holds_a_thousand_reservations() {
        let mut vm = space();
        for i in 0..12 {
            vm.insert(Region {
                base: 0x7000_0000 + i * GRANULARITY,
                size: PAGE,
                alloc_protect: PAGE_READWRITE,
                kind: Kind::Private,
            })
            .unwrap();
        }
        let mut reserved = 0;
        while vm
            .reserve(None, GRANULARITY, PAGE_READWRITE, Kind::Private)
            .is_ok()
        {
            reserved += 1;
        }
        assert_eq!(reserved, REGIONS - 12);
        assert!(reserved > 1000);
        assert_eq!(
            vm.reserve(None, GRANULARITY, PAGE_READWRITE, Kind::Private),
            Err(VmError::NoMemory)
        );
    }

    /// Unaddressed reservations take the lowest free granule past the regions; free memory reports
    /// up to the next region.
    #[test]
    fn reservations_fill_the_gaps() {
        let mut vm = space();
        let pages = Fake::default();
        vm.insert(Region {
            base: 0x2_0000,
            size: 0x1000,
            alloc_protect: PAGE_READWRITE,
            kind: Kind::Private,
        })
        .unwrap();
        assert_eq!(
            vm.reserve(None, 0x1000, PAGE_READWRITE, Kind::Private),
            Ok(0x1_0000)
        );
        assert_eq!(
            vm.reserve(None, 0x2_0000, PAGE_READWRITE, Kind::Private),
            Ok(0x3_0000)
        );
        let free = vm.query(&pages, 0x2_1000);
        assert_eq!(
            (free.state, free.protect, free.size, free.allocation_base),
            (MEM_FREE, PAGE_NOACCESS, 0xF000, 0)
        );
    }

    /// The kernel empties a space in place: every record ends up empty, whatever was there.
    #[test]
    fn the_empty_space_is_written_in_place() {
        let mut vm = space();
        vm.reserve(None, 0x1000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        let section = crate::ob::Mapping::Section(crate::ob::ObjectId {
            kind: crate::ob::ObjectType::Section,
            index: 1,
            generation: 0,
        });
        assert!(vm.add_view(0x30_0000, section));
        vm.reset();
        assert_eq!(vm.region_at(USER_LOW), None);
        assert_eq!(
            vm.query(&Fake::default(), USER_LOW).size,
            USER_HIGH - USER_LOW
        );
        assert!(vm.has_view_room());
    }

    /// A commit is all or nothing: one that runs out of frames midway gives back every frame it
    /// took, commits no page, and leaves the committed pages it covered as they were (their
    /// protection too); with the frames to spare it commits the range, its fresh pages zeroed.
    #[test]
    fn a_commit_that_runs_out_of_frames_commits_nothing() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x8000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit(&mut pages, base + 0x2000, PAGE, PAGE_READONLY)
            .unwrap();
        let kept = vm.frame_at(&pages, base + 0x2000).unwrap();
        pages.set_frame_word(kept, 0, 42);
        pages.budget = Some(3);
        assert_eq!(
            vm.commit(&mut pages, base, 0x8000, PAGE_READWRITE),
            Err(VmError::NoMemory)
        );
        assert_eq!(pages.freed.len(), 3, "the frames it took went back");
        assert_eq!(pages.budget, Some(0));
        for page in (0..8).filter(|&page| page != 2) {
            assert_eq!(vm.frame_at(&pages, base + page * PAGE), None, "page {page}");
        }
        let info = vm.query(&pages, base + 0x2000);
        assert_eq!(
            (info.state, info.protect, info.size),
            (MEM_COMMIT, PAGE_READONLY, PAGE)
        );
        assert_eq!(pages.frame_word(kept, 0), 42);
        assert_eq!(vm.query(&pages, base).size, 0x2000);

        // Seven fresh pages, seven frames: the commit is whole.
        pages.budget = Some(7);
        assert_eq!(
            vm.commit(&mut pages, base, 0x8000, PAGE_READWRITE),
            Ok(base)
        );
        let info = vm.query(&pages, base);
        assert_eq!(
            (info.state, info.protect, info.size),
            (MEM_COMMIT, PAGE_READWRITE, 0x8000)
        );
        assert_eq!(
            pages.frame_word(kept, 0),
            42,
            "a committed page keeps its contents"
        );
        for page in (0..8).filter(|&page| page != 2) {
            let frame = vm.frame_at(&pages, base + page * PAGE).unwrap();
            assert_eq!(pages.frame_word(frame, 0), 0, "page {page} is zeroed");
        }
        assert_eq!(pages.budget, Some(0));
    }

    /// Placements: a reservation without an address takes the lowest free range below the zero
    /// bits' limit, or the highest with top-down; the zero bits go up to 21.
    #[test]
    fn placements_bound_and_order_the_free_ranges() {
        let mut vm = space();
        let pages = Fake::default();
        assert_eq!(Placement::of(0, false), Some(Placement::ANYWHERE));
        assert_eq!(Placement::of(1, false), Some(Placement::ANYWHERE));
        assert_eq!(
            Placement::of(2, true),
            Some(Placement {
                end: 0x4000_0000,
                top_down: true
            })
        );
        assert_eq!(Placement::of(21, false).map(|p| p.end), Some(0x800));
        assert_eq!(Placement::of(22, false), None);

        let top = Placement {
            top_down: true,
            ..Placement::ANYWHERE
        };
        let high = vm
            .reserve_placed(None, top, 0x3000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(high, USER_HIGH - GRANULARITY);
        let next = vm
            .reserve_placed(None, top, 0x1_8000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(next, high - 0x2_0000, "the highest granule it fits below");
        let below = Placement::of(2, true).unwrap();
        assert_eq!(
            vm.reserve_placed(None, below, PAGE, PAGE_READWRITE, Kind::Private),
            Ok(0x3FFF_0000)
        );
        assert_eq!(
            vm.reserve_placed(
                None,
                Placement::of(3, false).unwrap(),
                PAGE,
                PAGE_READWRITE,
                Kind::Private
            ),
            Ok(USER_LOW)
        );
        assert_eq!(
            vm.reserve_placed(
                Some(0x7000_0000),
                below,
                PAGE,
                PAGE_READWRITE,
                Kind::Private
            ),
            Ok(0x7000_0000),
            "an address given is taken as given"
        );
        assert_eq!(
            vm.reserve_placed(
                None,
                Placement::of(21, false).unwrap(),
                PAGE,
                PAGE_READWRITE,
                Kind::Private
            ),
            Err(VmError::NoMemory),
            "no room below 2 KiB"
        );
        assert_eq!(
            vm.reserve_placed(
                None,
                Placement::of(21, true).unwrap(),
                PAGE,
                PAGE_READWRITE,
                Kind::Private
            ),
            Err(VmError::NoMemory)
        );
        assert_eq!(vm.query(&pages, high).state, MEM_RESERVE);
    }

    /// A view recorded once its pages are mapped: when another thread took the table's last
    /// record meanwhile, the view's region goes, its pages' holds on the section's frames with it.
    #[test]
    fn a_view_the_table_has_no_room_for_goes() {
        use crate::ob::{Mapping, ObjectId, ObjectType};
        let section = Mapping::Section(ObjectId {
            kind: ObjectType::Section,
            index: 1,
            generation: 0,
        });
        let mut vm = space();
        let mut pages = Fake::default();
        for index in 0..VIEWS as u32 {
            assert!(vm.add_view(0x4000_0000 + index * GRANULARITY, section));
        }
        let view = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        pages.holders.insert(0x0070_0000, 0);
        vm.map_shared(&mut pages, view, 0x0070_0000, PAGE_READWRITE)
            .unwrap();
        assert!(!vm.record_view(&mut pages, view, 0, section));
        assert_eq!(vm.query(&pages, view).state, MEM_FREE);
        assert!(!pages.frame_shared(0x0070_0000), "the view's hold went");
        assert!(!pages.freed.contains(&0x0070_0000), "the section keeps it");
        vm.take_view(0x4000_0000);
        let view = vm
            .reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        assert!(vm.record_view(&mut pages, view, 0x20000, section));
        assert_eq!(vm.view_at(view), Some(section));
        assert_eq!(
            vm.take_view(view).map(|v| (v.offset, v.mapping)),
            Some((0x20000, section))
        );
    }

    /// A demand commit charges instead of mapping: fresh pages get demand-zero entries, no frame
    /// is taken (the commit goes with none to spare), and the fresh count is the commit's charge;
    /// recommitting over committed pages keeps them and charges nothing; a mapped page a demand
    /// commit covers keeps its frame and contents.
    #[test]
    fn a_demand_commit_charges_and_writes_demand_zero_entries() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x8000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        assert_eq!(vm.uncommitted_pages(&pages, base, 0x8000), Ok(8));
        assert_eq!(
            vm.uncommitted_pages(&pages, base + 0x9000, PAGE),
            Err(VmError::InvalidAddress),
            "past the region"
        );
        pages.budget = Some(0);
        let (start, fresh) = vm
            .commit_demand(&mut pages, base + 0x2000, 0x4000, PAGE_READWRITE)
            .unwrap();
        assert_eq!((start, fresh), (base + 0x2000, 4));
        assert_eq!(pages.budget, Some(0), "no frame was taken");
        for page in 2..6 {
            let entry = pages.entry(base + page * PAGE);
            assert_eq!(pte::classify(entry), PteKind::DemandZero, "page {page}");
            assert_eq!(pte::decode(entry).unwrap().2, PAGE_READWRITE);
        }
        assert_eq!(pages.entry(base), 0, "outside the range stays reserved");
        // Recommit over the committed pages: nothing fresh, the entries take the new protection.
        let (start, fresh) = vm
            .commit_demand(&mut pages, base + 0x2000, 0x4000, PAGE_READONLY)
            .unwrap();
        assert_eq!((start, fresh), (base + 0x2000, 0));
        for page in 2..6 {
            let entry = pages.entry(base + page * PAGE);
            assert_eq!(pte::classify(entry), PteKind::DemandZero);
            assert_eq!(pte::decode(entry).unwrap().2, PAGE_READONLY);
        }
        // A mapped page a demand commit covers keeps its frame and contents.
        pages.budget = None;
        vm.commit(&mut pages, base, 0x2000, PAGE_READWRITE).unwrap();
        let frame = vm.frame_at(&pages, base).unwrap();
        pages.set_frame_word(frame, 0, 42);
        let (_, fresh) = vm
            .commit_demand(&mut pages, base, 0x1000, PAGE_READONLY)
            .unwrap();
        assert_eq!(fresh, 0);
        assert_eq!(vm.frame_at(&pages, base), Some(frame));
        assert_eq!(pages.frame_word(frame, 0), 42);
        let info = vm.query(&pages, base);
        assert_eq!(
            (info.state, info.protect, info.size),
            (MEM_COMMIT, PAGE_READONLY, PAGE)
        );
        // A guarded protection commits as a guard entry.
        vm.commit_demand(&mut pages, base + 0x6000, PAGE, PAGE_READWRITE | PAGE_GUARD)
            .unwrap();
        assert_eq!(pte::classify(pages.entry(base + 0x6000)), PteKind::Guard);
    }

    /// A query over the demand entries: the committed run reports MEM_COMMIT with the recorded
    /// protection, the reserved run past it MEM_RESERVE with none, and an entry of every other
    /// committed kind (a transition one naming its frame) reports committed too.
    #[test]
    fn a_query_reports_over_the_new_entry_kinds() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x1_0000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, base, 0x4000, PAGE_READWRITE)
            .unwrap();
        let head = vm.query(&pages, base);
        assert_eq!(
            (head.state, head.protect, head.size, head.mem_type),
            (MEM_COMMIT, PAGE_READWRITE, 0x4000, MEM_PRIVATE)
        );
        let middle = vm.query(&pages, base + 0x4000);
        assert_eq!(
            (middle.state, middle.protect, middle.size),
            (MEM_RESERVE, 0, 0xC000)
        );
        // A transition-kind entry (committed, its frame named, not present) is committed.
        pages.set_entry(
            base + 0x8000,
            pte::encode(PteKind::Transition, 0x0070_0000, PAGE_READONLY),
        );
        let at = vm.query(&pages, base + 0x8000);
        assert_eq!(
            (at.state, at.protect, at.size),
            (MEM_COMMIT, PAGE_READONLY, PAGE)
        );
        // A guard entry reports its protection with the guard flag.
        pages.set_entry(
            base + 0x9000,
            pte::encode(PteKind::Guard, 0x0071_0000, PAGE_READWRITE | PAGE_GUARD),
        );
        let guard = vm.query(&pages, base + 0x9000);
        assert_eq!(
            (guard.state, guard.protect),
            (MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD)
        );
    }

    /// A decommit and a release return how many pages were committed (the charge they discharge)
    /// and free only the frames the entries name: a demand-zero page's decommit frees nothing, a
    /// mapped page's does.
    #[test]
    fn a_decommit_and_release_discharge_and_free_only_named_frames() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x8000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, base, 0x4000, PAGE_READWRITE)
            .unwrap();
        vm.commit(&mut pages, base + 0x4000, 0x2000, PAGE_READWRITE)
            .unwrap();
        let mapped = vm.frame_at(&pages, base + 0x4000).unwrap();
        assert_eq!(vm.decommit(&mut pages, base, 0x4000).unwrap(), 4);
        assert_eq!(pages.entry(base), 0, "the demand-zero entries went");
        assert!(pages.freed.is_empty(), "no frame was named");
        assert_eq!(vm.decommit(&mut pages, base + 0x4000, 0x2000).unwrap(), 2);
        assert_eq!(pages.freed.len(), 2, "the mapped pages' frames went back");
        assert!(pages.freed.contains(&mapped));
        assert_eq!(
            vm.decommit(&mut pages, base, 0x8000).unwrap(),
            0,
            "nothing left committed"
        );
        vm.commit_demand(&mut pages, base, 0x8000, PAGE_READWRITE)
            .unwrap();
        let (region, charged) = vm.release(&mut pages, base).unwrap();
        assert_eq!((region.base, charged), (base, 8));
        assert_eq!(vm.query(&pages, base).state, MEM_FREE);
        assert_eq!(pages.freed.len(), 2, "the demand-zero pages freed nothing");
        // A release of a region with mapped pages frees them and counts them.
        let base = vm
            .reserve(None, 0x2000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit(&mut pages, base, 0x2000, PAGE_READWRITE).unwrap();
        let frames: Vec<u32> = (0..2)
            .map(|page| vm.frame_at(&pages, base + page * PAGE).unwrap())
            .collect();
        let (_, charged) = vm.release(&mut pages, base).unwrap();
        assert_eq!(charged, 2);
        for frame in frames {
            assert!(pages.freed.contains(&frame));
        }
    }

    /// A protect over demand-zero pages rewrites their entries with the new protection without
    /// mapping them, and reports the old one; a protect over an uncommitted page still fails.
    #[test]
    fn a_protect_over_demand_zero_pages_rewrites_the_entries() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x4000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, base, 0x2000, PAGE_READWRITE)
            .unwrap();
        assert_eq!(
            vm.protect(&mut pages, base, 0x2000, PAGE_READONLY),
            Ok(PAGE_READWRITE)
        );
        for page in 0..2 {
            let entry = pages.entry(base + page * PAGE);
            assert_eq!(pte::classify(entry), PteKind::DemandZero);
            assert_eq!(pte::decode(entry).unwrap().2, PAGE_READONLY);
        }
        assert_eq!(vm.query(&pages, base).protect, PAGE_READONLY);
        assert_eq!(vm.query(&pages, base).size, 0x2000);
        assert_eq!(
            vm.protect(&mut pages, base + 0x2000, PAGE, PAGE_NOACCESS),
            Err(VmError::InvalidAddress),
            "the reserved page is not committed"
        );
    }

    /// The capture's transition chain at the region table: each protect over committed pages
    /// reports the first page's old protection and rewrites every entry — a frameless demand page
    /// re-protected in place, a mapped page keeping its frame and contents through a no-access —
    /// and a protect whose range touches an uncommitted page fails whole, changing nothing.
    #[test]
    fn a_protect_transition_chain_reports_each_old_protection() {
        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x4000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, base, 0x4000, PAGE_READONLY)
            .unwrap();
        assert_eq!(
            vm.protect(&mut pages, base, 0x4000, PAGE_READWRITE),
            Ok(PAGE_READONLY)
        );
        assert_eq!(
            vm.protect(&mut pages, base, 0x4000, PAGE_NOACCESS),
            Ok(PAGE_READWRITE)
        );
        assert_eq!(vm.query(&pages, base).protect, PAGE_NOACCESS);
        assert_eq!(
            vm.protect(&mut pages, base, 0x4000, PAGE_EXECUTE_READ),
            Ok(PAGE_NOACCESS)
        );
        assert_eq!(
            vm.protect(&mut pages, base, 0x4000, 0x40),
            Ok(PAGE_EXECUTE_READ)
        );
        assert_eq!(vm.query(&pages, base).protect, PAGE_EXECUTE_READWRITE);
        assert_eq!(
            vm.protect(&mut pages, base, 0x4000, PAGE_READWRITE),
            Ok(0x40)
        );
        assert_eq!(vm.query(&pages, base).protect, PAGE_READWRITE);
        // The entries were rewritten each time, still demand-zero (no frame taken).
        for page in 0..4 {
            let entry = pages.entry(base + page * PAGE);
            assert_eq!(pte::classify(entry), PteKind::DemandZero, "page {page}");
            assert_eq!(pte::decode(entry).unwrap().2, PAGE_READWRITE);
        }

        // A mapped page keeps its frame and contents through the transitions.
        let mapped = vm
            .reserve(None, 0x2000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit(&mut pages, mapped, 0x2000, PAGE_READWRITE)
            .unwrap();
        let frame = vm.frame_at(&pages, mapped).unwrap();
        pages.set_frame_word(frame, 0, 9);
        assert_eq!(
            vm.protect(&mut pages, mapped, 0x2000, PAGE_NOACCESS),
            Ok(PAGE_READWRITE)
        );
        assert_eq!(vm.frame_at(&pages, mapped), Some(frame), "still its frame");
        assert_eq!(pages.frame_word(frame, 0), 9, "contents kept");
        assert_eq!(vm.query(&pages, mapped).protect, PAGE_NOACCESS);

        // A range touching an uncommitted page fails whole: the committed pages keep their
        // protection and entries.
        assert_eq!(
            vm.protect(&mut pages, base, 0x6000, PAGE_READONLY),
            Err(VmError::InvalidAddress),
            "past the region"
        );
        let half = vm
            .reserve(None, 0x4000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, half, 0x2000, PAGE_READWRITE)
            .unwrap();
        assert_eq!(
            vm.protect(&mut pages, half, 0x4000, PAGE_READONLY),
            Err(VmError::InvalidAddress),
            "the reserved half is not committed"
        );
        assert_eq!(vm.query(&pages, half).protect, PAGE_READWRITE);
        assert_eq!(pte::decode(pages.entry(half)).unwrap().2, PAGE_READWRITE);
    }

    /// A soft backing entry round trips: its tag, its payload and its protection, and it counts as
    /// committed — a query over a view's untouched page reports MEM_COMMIT with the recorded
    /// protection, a commit charge does not count it again, and a decommit of a paging-file page
    /// releases its slot while a transition page's frame goes back.
    #[test]
    fn soft_entries_round_trip_and_count_as_committed() {
        for (tag, payload) in [
            (TAG_TRANSITION, 0x0070_0000u32),
            (TAG_PAGE_FILE, 5u32 << 12),
            (TAG_PROTOTYPE, 0x10u32 << 12),
        ] {
            let entry = encode_backing(tag, payload, PAGE_READONLY);
            assert_eq!(backing_tag(entry), tag);
            assert_eq!(backing_payload(entry), payload);
            assert_eq!(soft_protect(entry), PAGE_READONLY);
            assert!(committed_entry(entry));
            assert!(!pte::committed(entry), "a soft entry carries no commit bit");
            assert_eq!(
                encode_backing(tag, payload, PAGE_WRITECOPY) >> INDEX_SHIFT & 7,
                3
            );
        }

        let mut vm = space();
        let mut pages = Fake::default();
        let base = vm
            .reserve(None, 0x4000, PAGE_READWRITE, Kind::Mapped(Maximum::Write))
            .unwrap();
        // A view's untouched pages: prototype entries naming their section page indices.
        vm.map_soft(
            &mut pages,
            base,
            encode_backing(TAG_PROTOTYPE, 0x10 << 12, PAGE_READONLY),
        )
        .unwrap();
        vm.map_soft(
            &mut pages,
            base + PAGE,
            encode_backing(TAG_PROTOTYPE, 0x11 << 12, PAGE_READONLY),
        )
        .unwrap();
        assert_eq!(
            vm.uncommitted_pages(&pages, base, 0x2000),
            Ok(0),
            "already committed"
        );
        let info = vm.query(&pages, base);
        assert_eq!(
            (info.state, info.protect, info.size, info.mem_type),
            (MEM_COMMIT, PAGE_READONLY, 0x2000, MEM_MAPPED)
        );
        // A protect over them rewrites the protection, keeping the tag and payload.
        assert_eq!(
            vm.protect(&mut pages, base, 0x2000, PAGE_READWRITE),
            Ok(PAGE_READONLY)
        );
        assert_eq!(
            pages.entry(base),
            encode_backing(TAG_PROTOTYPE, 0x10 << 12, PAGE_READWRITE)
        );
        // A decommit clears them and charges nothing (a view's pages were never charged).
        assert_eq!(vm.decommit(&mut pages, base, 0x2000).unwrap(), 0);
        assert_eq!(pages.entry(base), 0);

        // A paged-out private page: its decommit releases the slot and discharges the charge.
        let base = vm
            .reserve(None, 0x2000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        vm.commit_demand(&mut pages, base, 0x2000, PAGE_READWRITE)
            .unwrap();
        pages.set_entry(base, encode_backing(TAG_PAGE_FILE, 7 << 12, PAGE_READWRITE));
        pages.set_entry(
            base + PAGE,
            encode_backing(TAG_TRANSITION, 0x0070_0000, PAGE_READWRITE),
        );
        assert_eq!(vm.uncommitted_pages(&pages, base, 0x2000), Ok(0));
        assert_eq!(vm.decommit(&mut pages, base, 0x2000).unwrap(), 2);
        assert_eq!(pages.entry(base), 0);
        assert_eq!(
            pages.discarded,
            vec![7],
            "the paging-file slot was released"
        );
        assert_eq!(
            pages.freed,
            vec![0x0070_0000],
            "the transition frame went back"
        );
        // A recommit over a paged-out page keeps its backing and charges nothing fresh.
        pages.set_entry(base, encode_backing(TAG_PAGE_FILE, 7 << 12, PAGE_READWRITE));
        let (_, fresh) = vm
            .commit_demand(&mut pages, base, PAGE, PAGE_READONLY)
            .unwrap();
        assert_eq!(fresh, 0);
        assert_eq!(
            pages.entry(base),
            encode_backing(TAG_PAGE_FILE, 7 << 12, PAGE_READONLY),
            "the slot rides along, re-protected"
        );
        // map_soft refuses a page outside every region or one already holding an entry.
        assert_eq!(
            vm.map_soft(
                &mut pages,
                0x6000_0000,
                encode_backing(TAG_PROTOTYPE, 0, PAGE_READONLY)
            ),
            Err(VmError::InvalidAddress)
        );
        assert_eq!(
            vm.map_soft(
                &mut pages,
                base,
                encode_backing(TAG_PROTOTYPE, 0, PAGE_READONLY)
            ),
            Err(VmError::InvalidAddress)
        );
    }

    /// The hardware's accessed and dirty bits (bits 5-6) on a present entry are not backing
    /// tags: a present page the CPU has touched still reads as present with no tag, and stays
    /// committed — only a non-present entry carries a tag.
    #[test]
    fn a_present_entry_with_the_hardware_bits_set_reads_as_present() {
        use crate::mem::pte::{self, PteKind};
        for hardware_bits in [0x20, 0x40, 0x60] {
            let entry = encode(0x0070_0000, PAGE_READWRITE) | hardware_bits;
            assert_ne!(entry & PTE_PRESENT, 0);
            assert_eq!(backing_tag(entry), 0, "no tag on a present entry");
            assert!(committed_entry(entry));
            assert_eq!(pte::classify(entry), PteKind::Present);
            assert_eq!(
                pte::decode(entry),
                Some((PteKind::Present, 0x0070_0000, PAGE_READWRITE))
            );
        }
    }

    /// The page-out's entry steps: softening a present page to a transition one names its frame
    /// and keeps its protection (a fault on it resolves to a transition page), and naming a
    /// paging-file slot rewrites it to a PageFile one (a fault resolves to the slot) — both on
    /// the page holding the address, and both still committed.
    #[test]
    fn the_page_out_entry_steps_write_soft_entries() {
        use crate::mem::fault::{self, Resolution};
        let mut pages = Fake::default();
        let page = 0x0040_0000;
        pages.set_entry(page, encode(0x0070_0000, PAGE_READWRITE));
        soften_to_transition(&mut pages, page + 0x10, 0x0070_0000, PAGE_READWRITE);
        let entry = pages.entry(page);
        assert_eq!(backing_tag(entry), TAG_TRANSITION);
        assert_eq!(backing_payload(entry), 0x0070_0000);
        assert_eq!(soft_protect(entry), PAGE_READWRITE);
        assert!(committed_entry(entry));
        assert_eq!(
            fault::resolve(entry, false, true),
            Resolution::Transition,
            "a read fault resolves the named frame back in"
        );
        name_page_file(&mut pages, page + 0x20, 9, PAGE_READONLY);
        let entry = pages.entry(page);
        assert_eq!(entry, encode_backing(TAG_PAGE_FILE, 9 << 12, PAGE_READONLY));
        assert_eq!(fault::resolve(entry, false, true), Resolution::PageFile);
        assert_eq!(
            fault::resolve(entry, true, true),
            Resolution::Raise,
            "a write to a read-only slot stands"
        );
        // A write to a read-write slot resolves the slot too.
        name_page_file(&mut pages, page, 3, PAGE_READWRITE);
        assert_eq!(
            fault::resolve(pages.entry(page), true, true),
            Resolution::PageFile
        );
    }
}
