//! Bus-master DMA and MMIO mapping (the hardware layer's L6): the common buffers a bus-master
//! device and the CPU share, and the device register ranges mapped into kernel space.
//!
//! **Common buffers** ([`allocate_common_buffer`], HalAllocateCommonBuffer's core): memory the
//! device DMAs to and from by *bus address*, one logical address for the whole buffer. F2K takes
//! it from the nonpaged pool ([`super::pool`]), whose pages are mapped in every address space,
//! over a physically contiguous run of frames below 4 GiB (dmabuf's capture: buffers of 1, 3 and
//! 16 pages are physically contiguous, below 4 GiB, their logical address
//! MmGetPhysicalAddress(the virtual one)), and translates it to its bus address through the page
//! tables ([`DmaBus::translate`]). On this platform no IOMMU sits between the devices and memory,
//! so the bus address is the physical address — identity — and the translation is a page-table
//! walk; the record is checked contiguous page by page. Other DMA buffers' pages need not be
//! contiguous: the scatter/gather split ([`scatter_gather`]) turns a virtual range into the
//! element list a scatter/gather device walks, merging the runs whose bus addresses are
//! contiguous. No cache flush is needed: x86 bus-master DMA is cache-coherent (the caches snoop
//! the bus). The live buffers sit in a fixed [`CommonBufferRegistry`]: HalFreeCommonBuffer names
//! one by its length, logical address and virtual address, so the record is the handle.
//!
//! **MMIO mapping** ([`MmioMappings`], MmMapIoSpace's core): a device's register range, a physical
//! address range, maps into the reserved [`layout::MMIO`] region — its page tables made at boot and
//! shared by every address space, so the mapping is visible from any thread — page by page, with
//! the caches disabled (PCD) unless the caller asks for cached. The region's pages are handed out
//! lowest free run first, and a mapping records itself so it can be released.
//!
//! The pure cores run in the host tests over fake page tables and a fake store; on target the
//! seams are the page tables themselves ([`paging::translate_kernel_address`]), the pool's
//! contiguous blocks, and the registry under its lock — see the `target` module, whose thin
//! entry points (`allocate`, `free`, `map_io_space`) the HAL's export bodies call, the first two
//! through the same cores.

// The scatter/gather split and the unmap paths serve the slices that consume them (the
// scatter/gather HAL entries, MmUnmapIoSpace); the target build sees only the HAL bodies' calls.
#![cfg_attr(not(test), allow(dead_code))]

use super::layout::Region;
use super::paging::PAGE_SIZE;
use super::pool::pages_for;

// --- The public contract's types -------------------------------------------------------------

/// The documented `SCATTER_GATHER_ELEMENT`: one element of a scatter/gather list — a run of
/// physically contiguous memory the device can transfer in one go, by bus address.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScatterGatherElement {
    /// The run's first byte, as a bus (physical) address.
    pub address: u64,
    /// The run's length in bytes.
    pub length: u32,
    /// `ULONG_PTR` padding (32-bit on the target).
    pub reserved: usize,
}

// --- Scatter/gather over the page tables -----------------------------------------------------

/// Split the buffer at kernel virtual `va`, `length` bytes, into scatter/gather elements over
/// `bus` (its page-table translation to bus addresses, none when a page is not mapped): one
/// element per run of pages whose bus addresses are contiguous, so a physically contiguous buffer
/// is a single element. The elements are written to `out`; the count written is returned. None
/// when a page of the buffer fails to translate or `out` cannot hold the elements.
pub fn scatter_gather(
    bus: &impl DmaBus,
    va: u32,
    length: usize,
    out: &mut [ScatterGatherElement],
) -> Option<usize> {
    if length == 0 {
        return Some(0);
    }
    let mut count = 0usize;
    let mut cursor = va;
    let mut remaining = length;
    while remaining > 0 {
        let page_va = cursor & !(PAGE_SIZE - 1);
        let offset = (cursor - page_va) as u64;
        let bus = bus.translate(page_va)? + offset;
        let take = ((PAGE_SIZE as u64 - offset) as usize).min(remaining);
        let extend = count > 0 && {
            let last = &out[count - 1];
            last.address + last.length as u64 == bus
                && (last.length as u64) + take as u64 <= u32::MAX as u64
        };
        if extend {
            out[count - 1].length += take as u32;
        } else {
            let slot = out.get_mut(count)?;
            *slot = ScatterGatherElement {
                address: bus,
                length: take as u32,
                reserved: 0,
            };
            count += 1;
        }
        cursor += take as u32;
        remaining -= take;
    }
    Some(count)
}

// --- Common buffers --------------------------------------------------------------------------

/// A live common buffer's record: `length` bytes at kernel virtual `va`, physically contiguous
/// from bus address `bus`. The record is the handle HalFreeCommonBuffer names (by length, bus
/// address and virtual address), and the pool block behind `va` lives exactly as long as the
/// record does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommonBuffer {
    pub va: u32,
    pub bus: u64,
    pub length: u32,
}

/// How many common buffers may be live at once.
pub const COMMON_BUFFER_CAPACITY: usize = 16;

/// The live common buffers, a fixed table. Insert fails (handing the record back) when full;
/// removal names a buffer by its length, bus address and virtual address.
pub struct CommonBufferRegistry {
    slots: [Option<CommonBuffer>; COMMON_BUFFER_CAPACITY],
}

impl CommonBufferRegistry {
    /// An empty registry.
    pub const fn new() -> Self {
        CommonBufferRegistry {
            slots: [None; COMMON_BUFFER_CAPACITY],
        }
    }

    /// Record a live buffer; the record back when the table is full.
    pub fn insert(&mut self, buffer: CommonBuffer) -> Result<(), CommonBuffer> {
        for slot in &mut self.slots {
            if slot.is_none() {
                *slot = Some(buffer);
                return Ok(());
            }
        }
        Err(buffer)
    }

    /// Remove and return the buffer named by `length`, `bus_address` and `va`; none when no such
    /// buffer is live.
    pub fn remove(&mut self, length: u32, bus_address: u64, va: u32) -> Option<CommonBuffer> {
        for slot in &mut self.slots {
            if matches!(slot, Some(buffer) if buffer.length == length
                && buffer.bus == bus_address
                && buffer.va == va)
            {
                return slot.take();
            }
        }
        None
    }

    /// How many buffers are live.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

/// Where the live common buffers are recorded: a [`CommonBufferRegistry`] itself in the host
/// tests, the kernel's under its lock on target (each step takes the lock alone, so the store's
/// pool steps never run inside it).
pub trait CommonBufferTable {
    /// Record a live buffer; the record back when the table is full.
    fn insert(&mut self, buffer: CommonBuffer) -> Result<(), CommonBuffer>;

    /// Remove and return the buffer named by `length`, `bus_address` and `va`.
    fn remove(&mut self, length: u32, bus_address: u64, va: u32) -> Option<CommonBuffer>;
}

impl CommonBufferTable for CommonBufferRegistry {
    fn insert(&mut self, buffer: CommonBuffer) -> Result<(), CommonBuffer> {
        CommonBufferRegistry::insert(self, buffer)
    }

    fn remove(&mut self, length: u32, bus_address: u64, va: u32) -> Option<CommonBuffer> {
        CommonBufferRegistry::remove(self, length, bus_address, va)
    }
}

/// The bus's side of DMA: the page-table translation to bus addresses. On target this is the
/// platform itself; the host tests supply a fake page table. (No cache maintenance: x86
/// bus-master DMA is coherent with the caches.)
pub trait DmaBus {
    /// The bus address of the byte at kernel virtual `va`; none when its page is not mapped.
    fn translate(&self, va: u32) -> Option<u64>;
}

/// Where a common buffer's memory comes from: the nonpaged pool's physically contiguous blocks
/// on target, a fake in the host tests. The store owns the memory between `allocate` and
/// `release`.
pub trait CommonBufferStore {
    /// Allocate `bytes` of kernel memory over physically contiguous frames and return its
    /// virtual base; none when none is free.
    fn allocate(&mut self, bytes: usize) -> Option<u32>;

    /// Give back what `allocate` returned for `buffer`.
    fn release(&mut self, buffer: &CommonBuffer);
}

/// The first bus address past the 32-bit bus a common buffer must lie below.
const BUS_LIMIT: u64 = 1 << 32;

/// Build a buffer's record from its virtual base, through `bus`: every page of the range must
/// translate, each to the frame right after the previous one's (physically contiguous, so the one
/// logical address covers the buffer), and the range must end below 4 GiB. None otherwise.
pub fn common_buffer_record(bus: &impl DmaBus, va: u32, length: u32) -> Option<CommonBuffer> {
    let first = bus.translate(va)?;
    let pages = pages_for(length as usize) as u32;
    for page in 1..pages {
        if bus.translate(va + page * PAGE_SIZE)? != first + (page * PAGE_SIZE) as u64 {
            return None;
        }
    }
    (first + (pages * PAGE_SIZE) as u64 <= BUS_LIMIT).then_some(CommonBuffer {
        va,
        bus: first,
        length,
    })
}

/// HalAllocateCommonBuffer's core: a common buffer of `length` bytes over `store`, translated
/// through `bus` and recorded in `registry`. Returns the record — the virtual pointer is
/// `record.va`, the bus address `record.bus`. None when the store has no room, the block is not
/// physically contiguous below 4 GiB, or the registry is full; what was allocated is given back.
pub fn allocate_common_buffer(
    store: &mut impl CommonBufferStore,
    bus: &impl DmaBus,
    registry: &mut impl CommonBufferTable,
    length: u32,
) -> Option<CommonBuffer> {
    if length == 0 {
        return None;
    }
    let va = store.allocate(length as usize)?;
    let record = match common_buffer_record(bus, va, length) {
        Some(record) => record,
        None => {
            store.release(&CommonBuffer { va, bus: 0, length });
            return None;
        }
    };
    match registry.insert(record) {
        Ok(()) => Some(record),
        Err(record) => {
            store.release(&record);
            None
        }
    }
}

/// HalFreeCommonBuffer's core: remove the buffer named by `length`, `bus_address` and `va` (what
/// the allocation handed out) from `registry` and give the memory back through `store`. An
/// unknown name frees nothing.
pub fn free_common_buffer(
    store: &mut impl CommonBufferStore,
    registry: &mut impl CommonBufferTable,
    length: u32,
    bus_address: u64,
    va: u32,
) {
    if let Some(record) = registry.remove(length, bus_address, va) {
        store.release(&record);
    }
}

// --- MMIO mapping ----------------------------------------------------------------------------

/// How many MMIO mappings may be live at once.
pub const MMIO_CAPACITY: usize = 32;

/// The most directory entries a [`MmioMappings`] region spans (the bitmap is sized for it).
const MAX_ENTRIES: usize = 32;

/// The bitmap's words: one bit per page of the region.
const WORDS: usize = MAX_ENTRIES * 1024 / 64;

/// A reserved run of the MMIO region, before its pages are mapped: `pages` from `first_page`,
/// covering the physical range from `phys` (`bytes` long). `va` is the address the caller hands
/// out: the run's start plus `phys`'s page offset, naming the exact first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MmioReservation {
    pub va: u32,
    pub first_page: usize,
    pub pages: usize,
    pub phys: u32,
    pub bytes: u32,
    pub cache_enable: bool,
}

/// The allocator over a reserved kernel region: which of its pages are taken (lowest free run
/// first, as the pool's ledger hands runs out) and, for the MMIO region, the live mappings so a
/// mapping can be released. Pure over the region; the page mapping itself is the caller's (`map`/
/// `unmap` take the page callbacks, [`reserve_pages`] leaves the mapping to the caller). It
/// serves the MMIO region and the modules region alike.
pub struct MmioMappings {
    region: Region,
    taken: [u64; WORDS],
    slots: [Option<MmioReservation>; MMIO_CAPACITY],
}

impl MmioMappings {
    /// An empty allocator over `region`.
    ///
    /// # Panics
    ///
    /// The region spans more than [`MAX_ENTRIES`] directory entries.
    pub const fn new(region: Region) -> Self {
        assert!(
            region.entries <= MAX_ENTRIES,
            "a reserved region too wide for its bitmap"
        );
        MmioMappings {
            region,
            taken: [0; WORDS],
            slots: [None; MMIO_CAPACITY],
        }
    }

    fn is_taken(&self, page: usize) -> bool {
        self.taken[page / 64] & (1 << (page % 64)) != 0
    }

    fn mark(&mut self, page: usize, taken: bool) {
        let bit = 1 << (page % 64);
        if taken {
            self.taken[page / 64] |= bit;
        } else {
            self.taken[page / 64] &= !bit;
        }
    }

    /// The region's page count.
    pub fn pages(&self) -> usize {
        self.region.entries * 1024
    }

    /// Take the lowest free run of `pages` pages, marking them taken: for a region whose pages the
    /// caller maps itself (the modules region, whose pages the `.sys` loader maps frame by frame).
    /// Returns the run's first page index; none when no free run fits. [`unreserve_pages`] gives
    /// the run back.
    pub fn reserve_pages(&mut self, pages: usize) -> Option<usize> {
        if pages == 0 || pages > self.pages() {
            return None;
        }
        let mut run = 0;
        let mut first = None;
        for page in 0..self.pages() {
            if self.is_taken(page) {
                run = 0;
                continue;
            }
            run += 1;
            if run == pages {
                first = Some(page + 1 - pages);
                break;
            }
        }
        let first = first?;
        for page in first..first + pages {
            self.mark(page, true);
        }
        Some(first)
    }

    /// Give back the run [`reserve_pages`] took.
    ///
    /// # Panics
    ///
    /// A page of the run is free already.
    pub fn unreserve_pages(&mut self, first: usize, pages: usize) {
        for page in first..first + pages {
            assert!(self.is_taken(page), "unreserving a free region page");
            self.mark(page, false);
        }
    }

    /// Reserve the run of pages covering the physical range from `physical` (`bytes` long,
    /// page-aligned out both ends): `pages` pages from the lowest free run, recorded in the
    /// mapping table. None when the mapping table is full, no free run fits, the range is empty,
    /// or the address is past the 32-bit bus — and then no page is taken.
    pub fn reserve(
        &mut self,
        physical: u64,
        bytes: u32,
        cache_enable: bool,
    ) -> Option<MmioReservation> {
        if bytes == 0 || physical >= 1 << 32 {
            return None;
        }
        // The record's slot first: a full table must not leave the run marked taken.
        let slot = self.slots.iter().position(|slot| slot.is_none())?;
        let phys = physical as u32;
        let offset = phys % PAGE_SIZE;
        let pages = ((offset as u64 + bytes as u64).div_ceil(PAGE_SIZE as u64)) as usize;
        // `reserve_pages` marks the run taken.
        let first = self.reserve_pages(pages)?;
        let reservation = MmioReservation {
            va: self.region.start + first as u32 * PAGE_SIZE + offset,
            first_page: first,
            pages,
            phys,
            bytes,
            cache_enable,
        };
        self.slots[slot] = Some(reservation);
        Some(reservation)
    }

    /// How many of the region's pages are taken.
    pub fn taken_pages(&self) -> usize {
        self.taken
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    /// Map the reserved range: call `map_page(va, phys_page, cache_enable)` for each page of the
    /// reservation, then return the address handed out. The reservation stays live.
    pub fn map(
        &mut self,
        physical: u64,
        bytes: u32,
        cache_enable: bool,
        mut map_page: impl FnMut(u32, u32, bool),
    ) -> Option<u32> {
        let reservation = self.reserve(physical, bytes, cache_enable)?;
        for i in 0..reservation.pages as u32 {
            map_page(
                self.region.start + (reservation.first_page as u32 + i) * PAGE_SIZE,
                (reservation.phys & !(PAGE_SIZE - 1)) + i * PAGE_SIZE,
                cache_enable,
            );
        }
        Some(reservation.va)
    }

    /// Release the mapping at `va` (as [`map`] returned it): `unmap_page(va)` for each of its
    /// pages, the pages freed, the record dropped. None when no mapping sits at `va`.
    pub fn unmap(&mut self, va: u32, mut unmap_page: impl FnMut(u32)) -> Option<MmioReservation> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|r| r.va == va))?;
        let reservation = self.slots[index]
            .take()
            .expect("the slot was found present");
        for i in 0..reservation.pages {
            self.mark(reservation.first_page + i, false);
            unmap_page(self.region.start + (reservation.first_page as u32 + i as u32) * PAGE_SIZE);
        }
        Some(reservation)
    }

    /// How many mappings are live.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

// --- On target: the real bus, the pool, the locked state -------------------------------------

#[cfg(target_arch = "x86")]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::level::{self, High, LevelCell};
    use crate::mem::{layout, paging, pool};

    /// The platform's bus: identity translation through the current directory's page tables (the
    /// kernel half's tables are shared, so this is every address space's answer).
    pub struct PlatformBus;

    impl DmaBus for PlatformBus {
        fn translate(&self, va: u32) -> Option<u64> {
            paging::translate_kernel_address(va).map(|phys| phys as u64)
        }
    }

    /// The nonpaged pool as the common buffers' store: a physically contiguous block's pages are
    /// the buffer, and the registry's record owns the block — `release` hands it back by its
    /// address.
    pub struct PoolStore;

    impl CommonBufferStore for PoolStore {
        fn allocate(&mut self, bytes: usize) -> Option<u32> {
            let block = pool::allocate_contiguous(bytes)?;
            let va = block.virtual_address();
            // The record takes the block over; `release` gives it back through `release_block`.
            core::mem::forget(block);
            Some(va)
        }

        fn release(&mut self, buffer: &CommonBuffer) {
            pool::release_block(buffer.va, buffer.length as usize);
        }
    }

    /// The DMA state: the common-buffer registry and the MMIO mappings. At the high level like the
    /// memory manager's database; the pool steps a buffer's allocation and release take run
    /// outside this lock (that lock is the database's own), so the two never nest.
    pub struct DmaState {
        registry: CommonBufferRegistry,
        mmio: MmioMappings,
    }

    static DMA: LevelCell<High, DmaState> = LevelCell::new(DmaState {
        registry: CommonBufferRegistry::new(),
        mmio: MmioMappings::new(layout::MMIO),
    });

    /// The kernel's registry as the cores' table: each step raised to the lock's level alone, so
    /// the store's pool steps between them run outside it.
    struct LockedRegistry;

    impl CommonBufferTable for LockedRegistry {
        fn insert(&mut self, buffer: CommonBuffer) -> Result<(), CommonBuffer> {
            level::raised::<High, _>(|high| DMA.get(high).registry.insert(buffer))
        }

        fn remove(&mut self, length: u32, bus_address: u64, va: u32) -> Option<CommonBuffer> {
            level::raised::<High, _>(|high| DMA.get(high).registry.remove(length, bus_address, va))
        }
    }

    /// HalAllocateCommonBuffer: a physically contiguous common buffer of `length` bytes over the
    /// pool, translated to its bus address ([`allocate_common_buffer`] over the kernel's seams).
    /// The record, or none when the pool or the registry is full.
    pub fn allocate(length: u32) -> Option<CommonBuffer> {
        allocate_common_buffer(&mut PoolStore, &PlatformBus, &mut LockedRegistry, length)
    }

    /// HalFreeCommonBuffer: free the buffer named by `length`, `bus_address` and `va`
    /// ([`free_common_buffer`] over the kernel's seams); an unknown name frees nothing.
    pub fn free(length: u32, bus_address: u64, va: u32) {
        free_common_buffer(&mut PoolStore, &mut LockedRegistry, length, bus_address, va)
    }

    /// MmMapIoSpace: map `bytes` of physical memory from `physical` into the MMIO region, cached
    /// or not (uncached mappings get PCD, so device writes reach the hardware). The region's run
    /// is reserved under the DMA lock, then its pages mapped (the region's tables are shared by
    /// every address space, so the mapping lands in all of them). The virtual address, naming the
    /// exact first byte; none when the range is empty, past the 32-bit bus, or does not fit.
    pub fn map_io_space(physical: u64, bytes: u32, cache_enable: bool) -> Option<u32> {
        let reservation = level::raised::<High, _>(|high| {
            DMA.get(high).mmio.reserve(physical, bytes, cache_enable)
        })?;
        for i in 0..reservation.pages as u32 {
            paging::map_mmio_page(
                layout::MMIO.start + (reservation.first_page as u32 + i) * PAGE_SIZE,
                (reservation.phys & !(PAGE_SIZE - 1)) + i * PAGE_SIZE,
                cache_enable,
            );
        }
        Some(reservation.va)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::vec::Vec;

    use super::*;

    /// A fake page table: virtual page -> physical frame, with a bus that translates through it.
    struct FakeBus {
        pages: BTreeMap<u32, u64>,
    }

    impl FakeBus {
        fn new() -> Self {
            FakeBus {
                pages: BTreeMap::new(),
            }
        }

        /// Map virtual page `va_page` to physical frame `frame`.
        fn map_page(&mut self, va_page: u32, frame: u64) {
            self.pages.insert(va_page, frame);
        }
    }

    impl DmaBus for FakeBus {
        fn translate(&self, va: u32) -> Option<u64> {
            let page = va & !(PAGE_SIZE - 1);
            self.pages
                .get(&page)
                .map(|frame| *frame + (va - page) as u64)
        }
    }

    /// A fake store: hands out pages from a fake pool region, mapping each in the bus's page
    /// table to the next scripted frame (the frames control contiguity), and records what it
    /// releases. With `hole`, the last page of an allocation stays unmapped.
    struct FakeStore {
        bus: *mut FakeBus,
        next_va: *mut u32,
        frames: Vec<u64>,
        hole: bool,
        released: Vec<CommonBuffer>,
    }

    impl FakeStore {
        fn new(bus: &mut FakeBus, next_va: &mut u32) -> Self {
            FakeStore {
                bus,
                next_va,
                frames: Vec::new(),
                hole: false,
                released: Vec::new(),
            }
        }

        /// Script the frame the next allocated page maps to.
        fn with_frame(mut self, frame: u64) -> Self {
            self.frames.push(frame);
            self
        }

        /// Leave the allocation's last page unmapped in the bus's table.
        fn with_hole(mut self) -> Self {
            self.hole = true;
            self
        }
    }

    impl CommonBufferStore for FakeStore {
        fn allocate(&mut self, bytes: usize) -> Option<u32> {
            let pages = pages_for(bytes);
            if self.frames.len() < pages {
                return None;
            }
            // SAFETY: the test's one counter, alive for the whole test.
            let va = unsafe { *self.next_va };
            for page in 0..pages {
                let frame = self.frames.remove(0);
                if !(self.hole && page == pages - 1) {
                    // SAFETY: the test's one bus, alive for the whole test.
                    unsafe { &mut *self.bus }.map_page(va + page as u32 * PAGE_SIZE, frame);
                }
            }
            // SAFETY: as above.
            unsafe { *self.next_va = va + pages as u32 * PAGE_SIZE };
            Some(va)
        }

        fn release(&mut self, buffer: &CommonBuffer) {
            self.released.push(*buffer);
        }
    }

    /// A physically contiguous two-page buffer splits to one element; a non-contiguous one to
    /// one per page, split at the page boundary with the last partial; an unmapped page or a
    /// too-small output fails.
    #[test]
    fn scatter_gather_splits_and_merges_over_the_page_table() {
        let mut bus = FakeBus::new();
        // va 0x1000_0000: three contiguous frames (0x200_0000, 0x200_1000, 0x200_2000), then a
        // page mapped elsewhere (0x400_0000).
        bus.map_page(0x1000_0000, 0x200_0000);
        bus.map_page(0x1000_1000, 0x200_1000);
        bus.map_page(0x1000_2000, 0x200_2000);
        bus.map_page(0x1000_3000, 0x400_0000);

        let mut out = [ScatterGatherElement {
            address: 0,
            length: 0,
            reserved: 0,
        }; 8];

        // A run over the three contiguous pages, partial last page: one element.
        let count = scatter_gather(&bus, 0x1000_0000, 0x2800, &mut out).unwrap();
        assert_eq!(count, 1);
        assert_eq!(out[0].address, 0x200_0000);
        assert_eq!(out[0].length, 0x2800);

        // Past the contiguous run: two elements, the second starting at 0x400_0000.
        let count = scatter_gather(&bus, 0x1000_0800, 0x3800, &mut out).unwrap();
        assert_eq!(count, 2);
        assert_eq!((out[0].address, out[0].length), (0x200_0800, 0x2800));
        assert_eq!((out[1].address, out[1].length), (0x400_0000, 0x1000));

        // A va offset inside the first page lands in the element's address.
        let count = scatter_gather(&bus, 0x1000_0ABC, 0x100, &mut out).unwrap();
        assert_eq!(count, 1);
        assert_eq!((out[0].address, out[0].length), (0x200_0ABC, 0x100));

        // An unmapped page fails the whole split.
        assert_eq!(scatter_gather(&bus, 0x1000_0000, 0x5000, &mut out), None);
        // A too-small output fails.
        let mut small = [ScatterGatherElement {
            address: 0,
            length: 0,
            reserved: 0,
        }; 1];
        assert_eq!(scatter_gather(&bus, 0x1000_0800, 0x3800, &mut small), None);
        // An empty buffer splits to nothing.
        assert_eq!(scatter_gather(&bus, 0x1000_0000, 0, &mut out), Some(0));
    }

    /// The registry records, finds by length and bus address, refuses a full table, and a
    /// removed buffer is gone.
    #[test]
    fn the_common_buffer_registry_records_and_removes() {
        let mut registry = CommonBufferRegistry::new();
        let buffer = CommonBuffer {
            va: 0xFEC0_0000,
            bus: 0x1234_0000,
            length: 0x1000,
        };
        assert_eq!(registry.insert(buffer), Ok(()));
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.remove(0x1000, 0x1234_0000, 0xFEC0_1000),
            None,
            "the wrong virtual address"
        );
        assert_eq!(
            registry.remove(0x2000, 0x1234_0000, 0xFEC0_0000),
            None,
            "wrong length"
        );
        assert_eq!(
            registry.remove(0x1000, 0x1234_0000, 0xFEC0_0000),
            Some(buffer),
            "named by length, bus address and virtual address"
        );
        assert_eq!(
            registry.remove(0x1000, 0x1234_0000, 0xFEC0_0000),
            None,
            "gone now"
        );
        for i in 0..COMMON_BUFFER_CAPACITY {
            let record = CommonBuffer {
                va: 0xFEC0_0000 + i as u32 * PAGE_SIZE,
                bus: 0x1000 + i as u64,
                length: 0x1000,
            };
            assert_eq!(registry.insert(record), Ok(()));
        }
        let overflow = CommonBuffer {
            va: 0xA000_0000,
            bus: 0xFFFF,
            length: 1,
        };
        assert_eq!(registry.insert(overflow), Err(overflow), "a full table");
    }

    /// A common buffer allocates over the store, translates to its bus address, and frees back
    /// through the store by length, bus address and virtual address; a full store, an unmapped
    /// page, a full registry, a block that is not physically contiguous and one reaching past
    /// 4 GiB each fail with the allocation given back. dmabuf's capture
    /// (tests/hal/dmabuf/output.txt, `common`) pins the shape: buffers of 1, 3 and 16 pages,
    /// "physically contiguous: yes, below 4 GiB: yes", the logical address the physical one of
    /// the virtual address.
    #[test]
    fn common_buffers_allocate_translate_and_free_over_the_seams() {
        let mut bus = FakeBus::new();
        let mut registry = CommonBufferRegistry::new();
        let mut next_va = 0xFEC0_0000u32;

        // dmabuf's three sizes over contiguous frames: one logical address, the first byte's.
        for pages in [1u32, 3, 16] {
            let base = 0x0050_0000 + pages as u64 * 0x10_0000;
            let mut store = FakeStore::new(&mut bus, &mut next_va);
            for page in 0..pages {
                store = store.with_frame(base + (page * PAGE_SIZE) as u64);
            }
            let length = pages * PAGE_SIZE;
            let record = allocate_common_buffer(&mut store, &bus, &mut registry, length).unwrap();
            assert_eq!(record.bus, base, "{pages} pages: the first frame's address");
            assert_eq!(record.va % PAGE_SIZE, 0, "page-aligned");
            for page in 0..pages {
                assert_eq!(
                    bus.translate(record.va + page * PAGE_SIZE),
                    Some(record.bus + (page * PAGE_SIZE) as u64),
                    "{pages} pages: physically contiguous"
                );
            }
            free_common_buffer(&mut store, &mut registry, length, record.bus, record.va);
            assert_eq!(store.released, [record]);
            assert_eq!(registry.len(), 0);
        }

        // Two contiguous pages, kept: a second buffer lands past the first.
        let mut store = FakeStore::new(&mut bus, &mut next_va)
            .with_frame(0x500_0000)
            .with_frame(0x500_1000);
        let record = allocate_common_buffer(&mut store, &bus, &mut registry, 0x2000).unwrap();
        assert_eq!(record.bus, 0x500_0000);
        assert_eq!(record.length, 0x2000);
        let mut store = FakeStore::new(&mut bus, &mut next_va).with_frame(0x600_0000);
        let record2 = allocate_common_buffer(&mut store, &bus, &mut registry, 0x1000).unwrap();
        assert_eq!(
            record2.va,
            record.va + 0x2000,
            "the fake store's next free page"
        );
        assert_eq!(record2.bus, 0x600_0000);
        assert_eq!(registry.len(), 2);

        // Free names it by length, bus address and virtual address; a wrong virtual address
        // frees nothing.
        free_common_buffer(&mut store, &mut registry, 0x2000, 0x500_0000, record2.va);
        assert!(store.released.is_empty());
        free_common_buffer(&mut store, &mut registry, 0x2000, 0x500_0000, record.va);
        assert_eq!(registry.len(), 1);
        assert_eq!(store.released, [record]);
        free_common_buffer(&mut store, &mut registry, 0x2000, 0x500_0000, record.va);
        assert_eq!(store.released.len(), 1, "gone now");

        // A store with no frames left fails cleanly.
        let mut empty = FakeStore::new(&mut bus, &mut next_va);
        assert_eq!(
            allocate_common_buffer(&mut empty, &bus, &mut registry, 0x1000),
            None
        );
        assert!(empty.released.is_empty());

        // A page that does not translate fails and gives the block back.
        let mut holed = FakeStore::new(&mut bus, &mut next_va)
            .with_frame(0x700_0000)
            .with_frame(0x700_1000)
            .with_hole();
        assert_eq!(
            allocate_common_buffer(&mut holed, &bus, &mut registry, 0x2000),
            None
        );
        assert_eq!(
            holed.released.len(),
            1,
            "the half-translated block went back"
        );

        // Frames that are not contiguous fail: one logical address could not cover them.
        let mut scattered = FakeStore::new(&mut bus, &mut next_va)
            .with_frame(0x710_0000)
            .with_frame(0x720_0000);
        assert_eq!(
            allocate_common_buffer(&mut scattered, &bus, &mut registry, 0x2000),
            None
        );
        assert_eq!(scattered.released.len(), 1, "the scattered block went back");

        // A run reaching past 4 GiB fails.
        let mut high = FakeStore::new(&mut bus, &mut next_va)
            .with_frame(0xFFFF_F000)
            .with_frame(0x1_0000_0000);
        assert_eq!(
            allocate_common_buffer(&mut high, &bus, &mut registry, 0x2000),
            None
        );
        assert_eq!(high.released.len(), 1);
        assert_eq!(registry.len(), 1, "nothing was recorded");

        // A full registry fails and gives the block back.
        while registry.len() < COMMON_BUFFER_CAPACITY {
            let n = registry.len();
            registry
                .insert(CommonBuffer {
                    va: 0xB000_0000 + n as u32 * PAGE_SIZE,
                    bus: 0x9000_0000 + n as u64,
                    length: 0x1000,
                })
                .unwrap();
        }
        let mut store = FakeStore::new(&mut bus, &mut next_va).with_frame(0x800_0000);
        assert_eq!(
            allocate_common_buffer(&mut store, &bus, &mut registry, 0x1000),
            None
        );
        assert_eq!(store.released.len(), 1);

        // A zero length allocates nothing.
        assert_eq!(
            allocate_common_buffer(&mut store, &bus, &mut registry, 0),
            None
        );
    }

    /// MMIO mappings reserve the lowest free run covering the physical range (page-aligned out
    /// both ends), hand out the exact byte's address, map each page with the cache flag, release
    /// on unmap, and fail when the region is full, the range empty, or the address off the bus.
    #[test]
    fn mmio_ranges_map_into_the_reserved_region() {
        let region = Region {
            start: 0xC280_0000,
            entries: 2,
        };
        let mut mmio = MmioMappings::new(region);
        assert_eq!(mmio.pages(), 2048);

        let mut mapped: Vec<(u32, u32, bool)> = Vec::new();
        // 0xE000_0800 + 0x1000 spans pages 0xE000_0000 and 0xE000_1000: two pages, va at +0x800.
        let va = mmio
            .map(0xE000_0800, 0x1000, false, |va, phys, cache| {
                mapped.push((va, phys, cache));
            })
            .unwrap();
        assert_eq!(va, 0xC280_0800);
        assert_eq!(
            mapped,
            [
                (0xC280_0000, 0xE000_0000, false),
                (0xC280_1000, 0xE000_1000, false)
            ]
        );
        assert_eq!(mmio.len(), 1);

        // A cached mapping records the flag.
        let va2 = mmio
            .map(0xF000_0000, 0x2000, true, |va, phys, cache| {
                mapped.push((va, phys, cache));
            })
            .unwrap();
        assert_eq!(va2, 0xC280_2000, "the next free run");
        assert_eq!(mapped[2], (0xC280_2000, 0xF000_0000, true));
        assert_eq!(mapped[3], (0xC280_3000, 0xF000_1000, true));

        // Unmap releases the pages and calls back per page; the run is reused.
        let mut unmapped: Vec<u32> = Vec::new();
        let released = mmio.unmap(va, |page| unmapped.push(page)).unwrap();
        assert_eq!(released.pages, 2);
        assert_eq!(unmapped, [0xC280_0000, 0xC280_1000]);
        assert_eq!(mmio.len(), 1);
        assert_eq!(mmio.unmap(va, |_| ()), None, "gone now");
        let va3 = mmio.map(0xE100_0000, 0x2000, false, |_, _, _| ()).unwrap();
        assert_eq!(va3, 0xC280_0000, "the freed run is taken again");

        // An empty range, an off-bus address, and a full region fail.
        assert_eq!(mmio.map(0xE000_0000, 0, false, |_, _, _| ()), None);
        assert_eq!(mmio.map(0x1_0000_0000, 0x1000, false, |_, _, _| ()), None);
        let tiny = Region {
            start: 0xD000_0000,
            entries: 1,
        };
        let mut full = MmioMappings::new(tiny);
        assert!(full.map(0xE000_0000, 0x1000, false, |_, _, _| ()).is_some());
        assert_eq!(
            full.map(0xE001_0000, 0x400_0000, false, |_, _, _| ()),
            None,
            "the rest of the 4 MiB is taken"
        );
        // A range wider than the region fails.
        assert_eq!(full.map(0xE000_0000, 0x500_0000, false, |_, _, _| ()), None);
    }

    /// A full mapping table refuses a reservation without taking its pages, and a reservation
    /// marks its run once: unmapping it frees exactly that run.
    #[test]
    fn a_full_mapping_table_leaks_no_pages() {
        let region = Region {
            start: 0xC280_0000,
            entries: 1,
        };
        let mut mmio = MmioMappings::new(region);
        let mut vas = Vec::new();
        for i in 0..MMIO_CAPACITY as u64 {
            vas.push(
                mmio.map(0xE000_0000 + i * 0x1000, 0x1000, false, |_, _, _| ())
                    .unwrap(),
            );
        }
        assert_eq!(mmio.taken_pages(), MMIO_CAPACITY);
        assert_eq!(
            mmio.reserve(0xF000_0000, 0x3000, false),
            None,
            "the table is full"
        );
        assert_eq!(
            mmio.taken_pages(),
            MMIO_CAPACITY,
            "the refused run was not taken"
        );
        for va in vas {
            mmio.unmap(va, |_| ()).unwrap();
        }
        assert_eq!(mmio.taken_pages(), 0, "every run given back");
        assert_eq!(mmio.len(), 0);
    }

    /// The MMIO region in the layout holds what the target's mappings assume: page-aligned, wide
    /// enough for the bitmap, and clear of the other regions.
    #[test]
    fn the_mmio_region_is_sized_for_the_allocator() {
        use crate::mem::layout;
        assert!(layout::MMIO.start % layout::ENTRY_SPAN == 0);
        assert!(layout::MMIO.entries <= MAX_ENTRIES);
        assert_eq!(WORDS, MAX_ENTRIES * 1024 / 64);
        assert!(crate::mem::layout::MODULES.entries <= MAX_ENTRIES);
        assert!(layout::MMIO.holds(layout::MMIO.start));
        assert!(!layout::MMIO.holds(layout::MMIO.end() as u32));
    }
}
