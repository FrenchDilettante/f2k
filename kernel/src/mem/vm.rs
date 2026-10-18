//! The user address space: reservations, committed pages and their protections, and the one writer
//! of user page-table entries.
//!
//! A process's address space is a table of regions — each a reservation `[base, base + size)` with
//! the protection it was allocated with and a kind (private memory, an image) — and the page tables,
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
//! Region kinds are metadata (what a query reports as the type), never refusal policy.

// The query, protect, decommit and guard operations are the virtual-memory services' (none is served
// yet); the host tests pin them now.
#![cfg_attr(target_arch = "x86", allow(dead_code))]

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

/// What a region is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Private,
    Image,
}

impl Kind {
    fn mem_type(self) -> u32 {
        match self {
            Kind::Private => MEM_PRIVATE,
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

/// Why an operation failed (each caller reports it as its own failure).
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
    /// A zeroed frame, or none when memory is exhausted.
    fn zeroed_frame(&mut self) -> Option<u32>;
    /// Give a frame back.
    fn free_frame(&mut self, frame: u32);
}

/// How many regions a process can hold: the kernel's own areas (about a dozen), and every
/// reservation, thread stack, heap segment and big block the program makes. A fixed table:
/// exhausting it is the program's ERROR_NOT_ENOUGH_MEMORY.
pub const REGIONS: usize = 1024;

fn page_down(va: u32) -> u32 {
    va & !(PAGE - 1)
}

fn page_up(va: u64) -> u64 {
    (va + PAGE as u64 - 1) & !(PAGE as u64 - 1)
}

/// A process's regions. All `None` is the empty space.
pub struct AddressSpace {
    regions: [Option<Region>; REGIONS],
}

impl AddressSpace {
    /// The empty space (the tests build it by value; the kernel writes it in place).
    #[cfg(test)]
    pub const fn new() -> AddressSpace {
        AddressSpace {
            regions: [None; REGIONS],
        }
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
        let (_, start, end) = self.span(address, size)?;
        let mut va = start;
        while va < end {
            let frame = match decode(pages.entry(va)) {
                Some((frame, _)) => frame,
                None => match pages.zeroed_frame() {
                    Some(frame) => frame,
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

    /// Clear the entries of `[start, end)`, giving back each committed page's frame — an
    /// inaccessible or guarded page's too: it still names its frame.
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

    /// Release the region based at `address`: its pages decommitted and the reservation gone.
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
        let (_, start, end) = self.span(address, size)?;
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
            db.release(frame / PAGE, crate::mem::frame::FrameState::Free);
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Page tables as a map, frames numbered from 1 MiB, and the frames given back.
    #[derive(Default)]
    struct Fake {
        entries: HashMap<u32, u32>,
        next: u32,
        freed: Vec<u32>,
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
            self.freed.push(frame);
        }
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
    }
}
