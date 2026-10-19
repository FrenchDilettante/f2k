//! The user address space: reservations, committed pages and their protections — what VirtualAlloc,
//! VirtualFree, VirtualProtect and VirtualQuery see — and the one writer of user page-table entries.
//!
//! A process's address space is a table of regions — each a reservation `[base, base + size)` with
//! the protection it was allocated with and a kind (private memory, a mapped view, an image) — and
//! the page tables,
//! which hold each page's state: a page is committed when its entry names a frame. A committed page
//! the program may touch is a present entry; its exact protection rides in the entry's three
//! software bits (zero meaning "read-write if writable, else read-only", for entries written before
//! the protection was recorded). A committed page it may not touch — PAGE_NOACCESS, or a guard page
//! — is a non-present entry that still names its frame, marked as committed, its protection (the
//! guard flag apart) in the same bits. An uncommitted page has no entry.
//!
//! Every user page lies in a region: the loader seeds the image and the system areas before it maps
//! anything, and every mapping, commit, guard and release goes through [`AddressSpace`], so a query,
//! a release and the teardown all see every page. `paging` keeps only the raw entry access, reached
//! through the [`Pages`] seam ([`CurrentPages`] on target, an in-memory fake in the tests).
//!
//! Reservations start on the 64 KiB allocation granularity and cover whole pages; a reservation
//! without an address takes the lowest free range that fits. Commits zero their pages; committing a
//! committed page keeps its contents and takes the new protection. A query reports the page's
//! region and the run of pages after it in the same state and protection, within the region; outside
//! every region it reports free memory up to the next region.
//!
//! Region kinds are metadata (what a query reports as the type); the services (`nt::memory`,
//! `nt::section`) decide what each kind refuses.
//!
//! A frame may have several holders: a section owns its frames ([`SectionFrames`]), and each view of
//! it maps them too; a system DLL's pages are the kernel's, each process mapping them. The frame
//! database counts the holders; a page's release drops its own hold, and the frame goes back only
//! with the last. Copy-on-write pages (PAGE_WRITECOPY, an image's writable sections and
//! FILE_MAP_COPY views) are read-only to the hardware: the first write makes the page private — a
//! copy of a frame other holders still map, or the frame itself when it is the page's alone — and the
//! page turns read-write, as the platform reports it ([`copy_on_write`]). A writable protection given
//! to a page whose frame others hold, outside a view, is copy-on-write in fact: the system DLLs'
//! pages, and the shared data page, stay the kernel's.

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
const FRAME_MASK: u32 = 0xFFFF_F000;

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
/// committed one it may not touch.
pub fn names_frame(entry: u32) -> bool {
    entry & PRESENT != 0 || entry & COMMITTED != 0
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
    pages.set_entry(page, encode(frame, now | protect & !0xFF));
    true
}

/// Fire the guard page at `va`, if the page there is one: it keeps its protection, without the
/// guard flag (the access that touched it then raises STATUS_GUARD_PAGE_VIOLATION, once, unless it
/// grows a stack).
pub fn fire_guard(pages: &mut impl Pages, va: u32) -> bool {
    if va >= USER_HIGH {
        return false;
    }
    let page = page_down(va);
    match decode(pages.entry(page)) {
        Some((frame, protect)) if protect & PAGE_GUARD != 0 => {
            pages.set_entry(page, encode(frame, protect & !PAGE_GUARD));
            true
        }
        _ => false,
    }
}

/// What a region is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Private,
    /// A mapped view: its pages map its section's frames.
    Mapped,
    Image,
}

impl Kind {
    fn mem_type(self) -> u32 {
        match self {
            Kind::Private => MEM_PRIVATE,
            Kind::Mapped => MEM_MAPPED,
            Kind::Image => MEM_IMAGE,
        }
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

impl Info {
    /// The structure's 28 bytes.
    pub fn to_bytes(self) -> [u8; 28] {
        let words = [
            self.base,
            self.allocation_base,
            self.allocation_protect,
            self.size,
            self.state,
            self.protect,
            self.mem_type,
        ];
        let mut bytes = [0u8; 28];
        for (i, word) in words.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        bytes
    }
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

/// How many mapped views a process can hold at once.
pub const VIEWS: usize = 32;

/// One mapped view: its region's base, and the section object whose frames it maps (the view holds
/// a reference on it for as long as it is mapped).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct View {
    pub base: u32,
    pub section: crate::ob::ObjectId,
}

/// A process's regions, and its mapped views (on NT, the VADs a view's section hangs off). All
/// `None` is the empty space.
pub struct AddressSpace {
    regions: [Option<Region>; REGIONS],
    views: [Option<View>; VIEWS],
}

impl AddressSpace {
    /// The empty space (the tests build it by value; the kernel writes it in place).
    #[cfg(test)]
    pub const fn new() -> AddressSpace {
        AddressSpace {
            regions: [None; REGIONS],
            views: [None; VIEWS],
        }
    }

    /// Whether another view can be recorded.
    pub fn has_view_room(&self) -> bool {
        self.views.iter().any(Option::is_none)
    }

    /// Record a view mapped at `base` of `section`; false when the view table is full.
    pub fn add_view(&mut self, base: u32, section: crate::ob::ObjectId) -> bool {
        match self.views.iter_mut().find(|view| view.is_none()) {
            Some(slot) => {
                *slot = Some(View { base, section });
                true
            }
            None => false,
        }
    }

    /// Forget the view at `base`, returning the section it mapped; none when no view starts there.
    pub fn take_view(&mut self, base: u32) -> Option<crate::ob::ObjectId> {
        let slot = self
            .views
            .iter_mut()
            .find(|view| view.is_some_and(|view| view.base == base))?;
        slot.take().map(|view| view.section)
    }

    /// Forget every view (the address space goes, and its pages with it), handing each view's
    /// section to `release` for the reference the view held.
    pub fn drop_views(&mut self, mut release: impl FnMut(crate::ob::ObjectId)) {
        for slot in self.views.iter_mut() {
            if let Some(view) = slot.take() {
                release(view.section);
            }
        }
    }

    /// The bytes every region reserves together (VM_COUNTERS' VirtualSize).
    pub fn reserved_size(&self) -> u32 {
        self.regions.iter().flatten().map(|region| region.size).sum()
    }

    /// Write the empty space at `space`, region by region (by value it would pass the caller's
    /// stack).
    ///
    /// # Safety
    ///
    /// `space` is valid for writes and aligned; its previous contents are overwritten.
    pub unsafe fn write_empty(space: *mut AddressSpace) {
        // SAFETY: the caller's contract; every record is written.
        unsafe {
            let regions = core::ptr::addr_of_mut!((*space).regions) as *mut Option<Region>;
            for index in 0..REGIONS {
                regions.add(index).write(None);
            }
            core::ptr::addr_of_mut!((*space).views).write([None; VIEWS]);
        }
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

    /// The lowest granularity-aligned base where `size` bytes fit between the regions.
    fn free_range(&self, size: u32) -> Option<u32> {
        let mut candidate = USER_LOW as u64;
        loop {
            let end = candidate + size as u64;
            if end > USER_HIGH as u64 {
                return None;
            }
            match self
                .regions
                .iter()
                .flatten()
                .filter(|r| candidate < r.base as u64 + r.size as u64 && (r.base as u64) < end)
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

    /// Reserve `size` bytes at `address` (rounded down to the granularity, the end up to a page) or,
    /// without one, at the lowest free range. Returns the region's base.
    pub fn reserve(
        &mut self,
        address: Option<u32>,
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
                let base = self.free_range(rounded as u32).ok_or(VmError::NoMemory)?;
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
    pub fn commit(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
        protect: u32,
    ) -> Result<u32, VmError> {
        let (region, start, end) = self.span(address, size)?;
        let mut va = start;
        while va < end {
            let (frame, protect) = match decode(pages.entry(va)) {
                Some((frame, _)) => (frame, settle(region.kind, pages, frame, protect)),
                None => match pages.zeroed_frame() {
                    Some(frame) => (frame, protect),
                    None => return Err(VmError::NoMemory),
                },
            };
            pages.set_entry(va, encode(frame, protect));
            va += PAGE;
        }
        Ok(start)
    }

    /// Decommit the pages `[address, address + size)` covers (size zero: the whole region, from its
    /// base). They must lie in one region.
    pub fn decommit(
        &mut self,
        pages: &mut impl Pages,
        address: u32,
        size: u32,
    ) -> Result<(), VmError> {
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
        self.drop_pages(pages, start, end);
        Ok(())
    }

    /// Clear the entries of `[start, end)`, each page dropping its hold on its frame — an
    /// inaccessible or guarded page's too: it still names its frame (a frame other holders still
    /// map stays with them).
    fn drop_pages(&self, pages: &mut impl Pages, start: u32, end: u32) {
        let mut va = start;
        while va < end {
            if let Some((frame, _)) = decode(pages.entry(va)) {
                pages.set_entry(va, 0);
                pages.free_frame(frame);
            }
            va += PAGE;
        }
    }

    /// Release the region based at `address`: its pages decommitted (a view's frames stay with
    /// their section) and the reservation gone.
    pub fn release(&mut self, pages: &mut impl Pages, address: u32) -> Result<Region, VmError> {
        let slot = self
            .regions
            .iter_mut()
            .find(|r| r.is_some_and(|r| r.base == address))
            .ok_or(VmError::InvalidAddress)?;
        let region = slot.take().unwrap();
        self.drop_pages(pages, region.base, region.base + region.size);
        Ok(region)
    }

    /// Give every committed page of the pages `[address, address + size)` covers `protect`. They
    /// must lie in one region and all be committed. Returns the first page's old protection.
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
            let (_, was) = decode(pages.entry(va)).ok_or(VmError::InvalidAddress)?;
            old.get_or_insert(was);
            va += PAGE;
        }
        let mut va = start;
        while va < end {
            let (frame, _) = decode(pages.entry(va)).unwrap();
            let protect = settle(region.kind, pages, frame, protect);
            pages.set_entry(va, encode(frame, protect));
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
        if self.region_at(page).is_none() || decode(pages.entry(page)).is_some() {
            return Err(VmError::InvalidAddress);
        }
        pages.set_entry(page, encode(frame, protect));
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

    /// Plant a guard page at the page holding `va`: a zeroed frame committed read-write and guarded,
    /// so the first touch fires it. Nothing is planted — false — outside every region, over a page
    /// that already holds a frame, or without a frame to spare.
    pub fn plant_guard(&mut self, pages: &mut impl Pages, va: u32) -> bool {
        let page = page_down(va);
        if self.region_at(page).is_none() || decode(pages.entry(page)).is_some() {
            return false;
        }
        match pages.zeroed_frame() {
            Some(frame) => {
                pages.set_entry(page, encode(frame, PAGE_READWRITE | PAGE_GUARD));
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
        let state_of = |va: u32| match decode(pages.entry(va)) {
            Some((_, protect)) => (MEM_COMMIT, protect),
            None => (MEM_RESERVE, 0),
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

/// The protection a committed page of a `kind` region holding `frame` takes when given `protect`:
/// outside a view, a writable protection over a frame others hold (a system DLL's page, the shared
/// data page, a section's frame a copy-on-write view mapped) is copy-on-write, so the write stays the
/// process's; a view's writable pages write its section.
fn settle(kind: Kind, pages: &impl Pages, frame: u32, protect: u32) -> u32 {
    match copy_on_write_of(protect) {
        Some(copy) if kind != Kind::Mapped && pages.frame_shared(frame) => copy,
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
        Ok(frame)
    }

    /// The frame of the section's page `index`, when it is made (a file's section reads its page
    /// only when it is not; a file's section is not served yet).
    #[cfg_attr(target_arch = "x86", allow(dead_code))]
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

/// The running process's page tables and the frame database.
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
            (db.available() > KERNEL_RESERVE).then(|| db.allocate(crate::mem::frame::PRIMARY_COLOR))
        })?;
        let phys = frame * PAGE;
        crate::mem::paging::init_frame(phys, 0, &[]);
        Some(phys)
    }
    fn free_frame(&mut self, frame: u32) {
        crate::mem::bootmem::with_frame_db(|db| {
            if db.unshare(frame / PAGE) {
                db.release(frame / PAGE, crate::mem::frame::FrameState::Free);
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
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Page tables as a map, frames numbered from 1 MiB: their extra holders, their words and their
    /// contents (a frame's first word stands for its contents), and the frames given back.
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
        holders: HashMap<u32, u32>,
        words: HashMap<(u32, u32), u32>,
    }

    impl Pages for Fake {
        fn entry(&self, va: u32) -> u32 {
            *self.entries.get(&va).unwrap_or(&0)
        }
        fn set_entry(&mut self, va: u32, entry: u32) {
            self.entries.insert(va, entry);
        }
        fn zeroed_frame(&mut self) -> Option<u32> {
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
    }

    /// The views a space records: one per base, found by its base, the table's capacity enforced,
    /// and every one handed back (with its section) when the space goes.
    #[test]
    fn the_space_records_its_views() {
        use crate::ob::{ObjectId, ObjectType};
        let section = |index| ObjectId {
            kind: ObjectType::Section,
            index,
            generation: 0,
        };
        let mut space = Box::new(AddressSpace::new());
        assert!(space.add_view(0x30_0000, section(1)));
        assert!(space.add_view(0x31_0000, section(2)));
        assert_eq!(
            space.take_view(0x30_1000),
            None,
            "a view is named by its base"
        );
        assert_eq!(space.take_view(0x30_0000), Some(section(1)));
        assert_eq!(space.take_view(0x30_0000), None, "a view goes once");
        for index in 1..VIEWS as u16 {
            assert!(space.add_view(0x40_0000 + index as u32 * 0x1_0000, section(3)));
        }
        assert!(!space.has_view_room());
        assert!(!space.add_view(0x7000_0000, section(4)), "the table is full");
        let mut released = Vec::new();
        space.drop_views(|section| released.push(section.index));
        assert_eq!(released.len(), VIEWS);
        assert_eq!(released.iter().filter(|&&index| index == 2).count(), 1);
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
        let one = vm.reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped).unwrap();
        let two = vm.reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped).unwrap();
        vm.map_shared(&mut pages, one, first, PAGE_READWRITE).unwrap();
        vm.map_shared(&mut pages, two, first, PAGE_READONLY).unwrap();
        assert_eq!(vm.query(&pages, one).mem_type, MEM_MAPPED);
        vm.release(&mut pages, one).unwrap();
        assert!(
            !pages.freed.contains(&first),
            "the section and the other view still hold it"
        );
        section.release(&mut pages);
        assert!(!pages.freed.contains(&first), "the other view still maps it");
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
        let view = vm.reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped).unwrap();
        vm.map_shared(&mut pages, view, frame, PAGE_WRITECOPY).unwrap();
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

        let view = vm.reserve(None, PAGE, PAGE_READWRITE, Kind::Mapped).unwrap();
        pages.holders.insert(0x0061_0000, 0);
        vm.map_shared(&mut pages, view, 0x0061_0000, PAGE_READONLY)
            .unwrap();
        vm.protect(&mut pages, view, PAGE, PAGE_READWRITE).unwrap();
        assert_eq!(vm.query(&pages, view).protect, PAGE_READWRITE);
    }

    /// A query's 28 bytes are MEMORY_BASIC_INFORMATION's dwords in order.
    #[test]
    fn an_info_is_the_structures_bytes() {
        let info = Info {
            base: 1,
            allocation_base: 2,
            allocation_protect: 3,
            size: 4,
            state: 5,
            protect: 6,
            mem_type: 7,
        };
        let bytes = info.to_bytes();
        assert_eq!(&bytes[..8], &[1, 0, 0, 0, 2, 0, 0, 0]);
        assert_eq!(&bytes[24..], &[7, 0, 0, 0]);
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

    /// The kernel writes the empty space in place: every record ends up empty, whatever was there.
    #[test]
    fn the_empty_space_is_written_in_place() {
        let mut vm = space();
        vm.reserve(None, 0x1000, PAGE_READWRITE, Kind::Private)
            .unwrap();
        // SAFETY: the box is valid, aligned and owned here.
        unsafe { AddressSpace::write_empty(&mut *vm) };
        assert_eq!(vm.region_at(USER_LOW), None);
        assert_eq!(
            vm.query(&Fake::default(), USER_LOW).size,
            USER_HIGH - USER_LOW
        );
        assert!(vm.has_view_room());
    }
}
