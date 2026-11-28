//! The paging file: the boot volume's disposable backing store for pages paged out of memory.
//!
//! The boot takes over the file an earlier boot (or the disk's build) left, making one only when
//! there is none — its contents are never needed across boots, so it carries no header, there is
//! no recovery and nothing is cleared — sized from the volume's free space, and laid out
//! as a flat array of 4 KiB pages: slot `s` lives at byte offset `s * 4096`. Slot 0 is reserved
//! and never handed out, so a zero slot index reads as "no page". Which slots are allocated is
//! kept in an in-memory bitmap; the disk I/O itself goes through [`PageStore`], which the kernel
//! wires to the boot volume's file layer and host tests drive over a RAM disk.
//!
//! The file grows in fixed chunks ([`PagingFile::extend`]) when the allocator runs out, which is
//! also what raises the commit limit: the limit is memory plus the paging file's size in pages
//! ([`PagingFile::pages`]).

// The boot wires the module to the boot volume's file layer (the target half below); the parts
// nothing calls yet on the target build see only the host tests' calls.
#![cfg_attr(not(test), allow(dead_code))]

use super::pageout::{PageIoError, PagingIo, SlotId, INVALID_SLOT};
use super::paging::PAGE_SIZE;

/// One page of the paging file, and of its slot index space: 4 KiB.
pub const PAGE_BYTES: usize = PAGE_SIZE as usize;
/// A page-sized buffer.
pub type Page = [u8; PAGE_BYTES];

/// The largest paging file the bitmap covers: 65536 pages (256 MiB). Larger sizes are capped.
pub const MAX_PAGES: u64 = 1 << 16;
/// The bitmap's words.
pub const MAX_WORDS: usize = (MAX_PAGES as usize + 63) / 64;
/// How many pages one [`PagingFile::extend`] adds: 1024 (4 MiB).
pub const EXTEND_PAGES: u64 = 1024;

/// The free space the paging file leaves the boot volume's other users, in bytes: the volume
/// keeps this much of its free space for the files written beside the paging file.
pub const FREE_SPACE_RESERVE_BYTES: u64 = 8 * 1024 * 1024;

/// The paging file's size at boot, at most, in pages: 2048 (8 MiB). A boot that finds no file
/// makes it, and on this volume a cluster is one sector, so its length costs the device one
/// allocation per 512 bytes — the boot keeps the file to what it can afford to write and lets it
/// grow in [`EXTEND_PAGES`] chunks (which is also what raises the commit limit) when the allocator
/// runs out of room; the next boot cuts it back to this size, as Windows 2000 shrinks a paging
/// file back to its initial size.
pub const BOOT_MAX_PAGES: u64 = 2048;

/// The paging file's size in bytes from the volume's free space: whole pages of what the reserve
/// leaves, capped at the boot's [`BOOT_MAX_PAGES`] (and so at the bitmap's [`MAX_PAGES`]).
pub fn size_from_free_space(free_bytes: u64) -> u64 {
    let usable = free_bytes.saturating_sub(FREE_SPACE_RESERVE_BYTES);
    (usable / PAGE_BYTES as u64).min(BOOT_MAX_PAGES) * PAGE_BYTES as u64
}

/// The boot's sizing, from the volume's free space and the machine's physical memory: the paging
/// file's size in bytes, and the commit limit the boot then sets — physical memory plus the file.
pub fn boot_sizing(free_bytes: u64, ram_bytes: u64) -> (u64, u64) {
    let size = size_from_free_space(free_bytes);
    (size, ram_bytes.saturating_add(size))
}

/// The store's refusal of a paging-file operation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    /// The page read or write failed on the store.
    Io,
    /// The store has no room for the length asked (the volume is full).
    NoSpace,
}

/// The paging file's disk side: whole-page reads and writes at byte offsets, and setting the
/// file's length. The kernel's adapter wires this to the paging file on the boot volume (kept
/// across boots, or made empty by the boot that found none, which a first [`PageStore::set_len`]
/// then sizes); host tests drive it over a RAM disk.
pub trait PageStore {
    /// Read the page at byte `offset` into `page`.
    fn read_at(&mut self, offset: u64, page: &mut Page) -> Result<(), StoreError>;
    /// Write `page` at byte `offset`.
    fn write_at(&mut self, offset: u64, page: &Page) -> Result<(), StoreError>;
    /// Write `data` — whole pages, starting at byte `offset` — as one operation when the store
    /// can move them in a single run (a file layer does): the default writes page by page
    /// through [`Self::write_at`].
    fn write_at_many(&mut self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
        assert!(
            !data.is_empty() && data.len() % PAGE_BYTES == 0,
            "whole pages"
        );
        for (index, page) in data.chunks_exact(PAGE_BYTES).enumerate() {
            let page: &Page = page.try_into().expect("a whole page");
            self.write_at(offset + index as u64 * PAGE_BYTES as u64, page)?;
        }
        Ok(())
    }

    /// Read whole pages starting at byte `offset` into `data` as one operation when the store can
    /// move them in a single run (a file layer does): the default reads page by page through
    /// [`Self::read_at`].
    fn read_at_many(&mut self, offset: u64, data: &mut [u8]) -> Result<(), StoreError> {
        assert!(
            !data.is_empty() && data.len() % PAGE_BYTES == 0,
            "whole pages"
        );
        for (index, page) in data.chunks_exact_mut(PAGE_BYTES).enumerate() {
            let page: &mut Page = page.try_into().expect("a whole page");
            self.read_at(offset + index as u64 * PAGE_BYTES as u64, page)?;
        }
        Ok(())
    }

    /// Set the file's length to `len` bytes; a growth's contents are undefined (no slot is read
    /// before it is written).
    fn set_len(&mut self, len: u64) -> Result<(), StoreError>;
}

/// The paging file: a store plus the in-memory bitmap of allocated slots.
pub struct PagingFile<S> {
    store: S,
    /// Slot bitmap: bit `s` set means slot `s` is taken. Bits at or beyond `pages` are kept set,
    /// so a clear bit always names a slot inside the file; bit 0 stays set (the reserved slot).
    bitmap: [u64; MAX_WORDS],
    /// The file's length in pages; the slots are `0..pages`.
    pages: u64,
    /// How many slots are allocated.
    used: u64,
    /// The lowest slot that may be free; every slot below it is taken.
    next: u64,
}

/// Clear bitmap bits `[start, end)`, never slot 0 (it stays reserved).
fn clear_bits(bitmap: &mut [u64], start: u64, end: u64) {
    for slot in start.max(1)..end {
        bitmap[(slot / 64) as usize] &= !(1u64 << (slot % 64));
    }
}

impl<S: PageStore> PagingFile<S> {
    /// Create the paging file fresh at `size` bytes (rounded up to whole pages, capped at
    /// [`MAX_PAGES`]): the store is asked to make the file that long, and slots `1..pages` start
    /// free. The store's refusal comes back as the error.
    pub fn create(mut store: S, size: u64) -> Result<PagingFile<S>, StoreError> {
        let pages = Self::pages_for(size);
        store.set_len(pages * PAGE_BYTES as u64)?;
        Ok(Self::with_pages(store, pages))
    }

    /// Take over the paging file an earlier boot (or setup) left, `current` bytes long, at `size`
    /// bytes (rounded and capped as [`Self::create`]'s): the store is asked for the new length only
    /// when it differs — a longer file is cut back, a shorter one grown — and nothing is written
    /// otherwise, the old contents being never read before they are written. Every slot but the
    /// reserved one starts free. The store's refusal comes back as the error.
    pub fn reuse(mut store: S, current: u64, size: u64) -> Result<PagingFile<S>, StoreError> {
        let pages = Self::pages_for(size);
        if current != pages * PAGE_BYTES as u64 {
            store.set_len(pages * PAGE_BYTES as u64)?;
        }
        Ok(Self::with_pages(store, pages))
    }

    /// `size` bytes in whole pages, capped at [`MAX_PAGES`].
    fn pages_for(size: u64) -> u64 {
        size.div_ceil(PAGE_BYTES as u64).min(MAX_PAGES)
    }

    /// The file over a store already `pages` long: slots `1..pages` free, slot 0 reserved.
    fn with_pages(store: S, pages: u64) -> PagingFile<S> {
        let mut bitmap = [u64::MAX; MAX_WORDS];
        // Every bit starts set; the file's own slots come out free, slot 0 staying reserved.
        clear_bits(&mut bitmap, 1, pages);
        PagingFile {
            store,
            bitmap,
            pages,
            used: 0,
            next: 1,
        }
    }

    /// The file's length in pages: its size in pages for the commit limit.
    pub fn pages(&self) -> u64 {
        self.pages
    }

    /// The file's size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.pages * PAGE_BYTES as u64
    }

    /// How many slots the file can hand out: `pages - 1`, slot 0 being reserved.
    pub fn capacity(&self) -> u64 {
        self.pages.saturating_sub(1)
    }

    /// How many slots are allocated now.
    pub fn used(&self) -> u64 {
        self.used
    }

    /// How many slots are still free.
    pub fn free_slots(&self) -> u64 {
        self.capacity() - self.used
    }

    /// Whether slot `slot` is taken (slot 0 always reads as taken: it is reserved).
    pub fn is_allocated(&self, slot: u64) -> bool {
        slot < self.pages && self.bitmap[(slot / 64) as usize] & (1 << (slot % 64)) != 0
    }

    /// The store behind the file.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store behind the file, mutable.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Take the lowest free slot: its index. None when every slot is taken.
    pub fn allocate_slot(&mut self) -> Option<u64> {
        let words = self.words();
        let mut word = (self.next / 64) as usize;
        while word < words {
            let bits = self.bitmap[word];
            if bits != u64::MAX {
                let bit = (!bits).trailing_zeros() as u64;
                let slot = word as u64 * 64 + bit;
                debug_assert!(slot < self.pages, "a clear bit always lies inside the file");
                self.bitmap[word] |= 1 << bit;
                self.used += 1;
                self.next = slot + 1;
                return Some(slot);
            }
            word += 1;
        }
        None
    }

    /// Take a run of `count` contiguous free slots, for one multi-page transfer: the run's
    /// first slot, or none when the file holds no run that long (grow it first with
    /// [`Self::extend`], whose fresh chunk is one long run).
    pub fn allocate_slots(&mut self, count: u64) -> Option<u64> {
        assert!(count >= 1, "a run of slots is at least one");
        let mut run_start = 0u64;
        let mut run = 0u64;
        for slot in 1..self.pages {
            if self.is_allocated(slot) {
                run = 0;
                continue;
            }
            if run == 0 {
                run_start = slot;
            }
            run += 1;
            if run == count {
                for taken in run_start..run_start + count {
                    self.bitmap[(taken / 64) as usize] |= 1 << (taken % 64);
                }
                self.used += count;
                self.next = run_start + count;
                return Some(run_start);
            }
        }
        None
    }

    /// Write `data` — whole pages — into the run of allocated slots starting at `first`, as one
    /// store operation at the run's first offset.
    ///
    /// # Panics
    /// `data` is empty or not whole pages, or one of the run's slots is not allocated.
    pub fn write_pages(&mut self, first: u64, data: &[u8]) -> Result<(), StoreError> {
        assert!(
            !data.is_empty() && data.len() % PAGE_BYTES == 0,
            "a multi-page write moves whole pages"
        );
        for index in 0..(data.len() / PAGE_BYTES) as u64 {
            assert!(
                self.is_allocated(first + index),
                "slot {} of the run is not allocated",
                first + index
            );
        }
        self.store.write_at_many(first * PAGE_BYTES as u64, data)
    }

    /// Read the run of allocated slots starting at `first` into `data` — whole pages — as one
    /// store operation at the run's first offset (a clustered page-in).
    ///
    /// # Panics
    /// `data` is empty or not whole pages, or one of the run's slots is not allocated.
    pub fn read_pages(&mut self, first: u64, data: &mut [u8]) -> Result<(), StoreError> {
        assert!(
            !data.is_empty() && data.len() % PAGE_BYTES == 0,
            "a multi-page read moves whole pages"
        );
        for index in 0..(data.len() / PAGE_BYTES) as u64 {
            assert!(
                self.is_allocated(first + index),
                "slot {} of the run is not allocated",
                first + index
            );
        }
        self.store.read_at_many(first * PAGE_BYTES as u64, data)
    }

    /// Give slot `slot` back.
    ///
    /// # Panics
    ///
    /// `slot` is not an allocated slot (0, past the file's end, free, or a double free).
    pub fn free_slot(&mut self, slot: u64) {
        assert!(
            slot >= 1 && self.is_allocated(slot),
            "free of paging-file slot {slot} that is not allocated"
        );
        let word = (slot / 64) as usize;
        self.bitmap[word] &= !(1 << (slot % 64));
        self.used -= 1;
        if slot < self.next {
            self.next = slot;
        }
    }

    /// Grow the file by [`EXTEND_PAGES`] pages (up to [`MAX_PAGES`]): the store is asked for the
    /// new length first, then the new slots join the bitmap as free. Returns the file's new
    /// length in pages, or the store's refusal — the file is then unchanged.
    pub fn extend(&mut self) -> Result<u64, StoreError> {
        let grow = EXTEND_PAGES.min(MAX_PAGES - self.pages);
        if grow == 0 {
            return Err(StoreError::NoSpace);
        }
        let pages = self.pages + grow;
        self.store.set_len(pages * PAGE_BYTES as u64)?;
        clear_bits(&mut self.bitmap, self.pages, pages);
        self.pages = pages;
        Ok(pages)
    }

    /// Read slot `slot`'s page into `page`.
    ///
    /// # Panics
    ///
    /// `slot` is not an allocated slot.
    pub fn read_page(&mut self, slot: u64, page: &mut Page) -> Result<(), StoreError> {
        let offset = self.slot_offset(slot);
        self.store.read_at(offset, page)
    }

    /// Write `page` into slot `slot`.
    ///
    /// # Panics
    ///
    /// `slot` is not an allocated slot.
    pub fn write_page(&mut self, slot: u64, page: &Page) -> Result<(), StoreError> {
        let offset = self.slot_offset(slot);
        self.store.write_at(offset, page)
    }

    /// Slot `slot`'s byte offset in the file.
    ///
    /// # Panics
    ///
    /// `slot` is not an allocated slot.
    fn slot_offset(&self, slot: u64) -> u64 {
        assert!(
            slot >= 1 && self.is_allocated(slot),
            "paging-file slot {slot} is not an allocated slot"
        );
        slot * PAGE_BYTES as u64
    }

    /// The bitmap's live words.
    fn words(&self) -> usize {
        (self.pages as usize + 63) / 64
    }
}

/// The paging file as a [`PagingIo`] — the page-out/page-in store's page-level I/O over a file the
/// caller holds: slot allocation, reads and writes (each page at its slot's byte offset,
/// `slot * PAGE_BYTES`), and slot release. The boot's paging file runs this over the boot volume's
/// file layer through [`target::PagingFileIo`]; the host tests drive it over a RAM disk.
pub struct FileIo<'a, S: PageStore> {
    file: &'a mut PagingFile<S>,
}

impl<'a, S: PageStore> FileIo<'a, S> {
    /// The adapter over `file`.
    pub fn new(file: &'a mut PagingFile<S>) -> Self {
        FileIo { file }
    }
}

impl<S: PageStore> PagingIo for FileIo<'_, S> {
    fn allocate_slot(&mut self) -> Option<SlotId> {
        self.file.allocate_slot().map(|slot| slot as SlotId)
    }

    fn write(&mut self, slot: SlotId, page: &[u8]) -> Result<(), PageIoError> {
        let page: &Page = page.try_into().map_err(|_| PageIoError::Io)?;
        self.file
            .write_page(u64::from(slot), page)
            .map_err(|_| PageIoError::Io)
    }

    fn read(&mut self, slot: SlotId, page: &mut [u8]) -> Result<(), PageIoError> {
        let page: &mut Page = page.try_into().map_err(|_| PageIoError::Io)?;
        self.file
            .read_page(u64::from(slot), page)
            .map_err(|_| PageIoError::Io)
    }

    fn free_slot(&mut self, slot: SlotId) {
        if slot != INVALID_SLOT {
            self.file.free_slot(u64::from(slot));
        }
    }
}

// --- The boot volume's file layer (target) ------------------------------------------------------
//
// The kernel wires the paging file to a file on the boot volume: [`BootVolumeStore`] adapts the
// volume's file layer to [`PageStore`] — whole-page reads and writes at byte offsets and setting
// the file's length, each operation inside the volume's own locked section — and [`boot_create`]
// takes over (or makes) the file at boot and sets the commit limit from it. Page I/O goes straight
// to the device along the file's runs ([`Extents`], made again whenever the length changes), with
// no chain walk and no directory-entry update, as Windows 2000's paging I/O does; a file in too
// many pieces for the map goes through the file layer. The system holds the file open for its life,
// sharing nothing, so no process opens it (its pages are other processes' memory and stale disk
// contents).

#[cfg(target_arch = "x86")]
mod target {
    use super::{boot_sizing, FileIo, Page, PageStore, PagingFile, StoreError, PAGE_BYTES};
    use crate::block::lock::DeviceLock;
    use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_SYSTEM};
    use crate::fs::fat32::extent::Extents;
    use crate::fs::fat32::lookup::{self, File};
    use crate::fs::fat32::read;
    use crate::fs::fat32::volume::with_boot_volume;
    use crate::fs::fat32::write::{self, Fill};
    use crate::fs::file::{with_records, FileRecordId, ACCESS_READ, ACCESS_WRITE};
    use crate::mem::pageout::{PageIoError, PagingIo, SlotId, INVALID_SLOT};
    use crate::status::{NtStatus, STATUS_DISK_FULL};

    /// The paging file's name in the boot volume's root directory.
    pub const PAGING_FILE_NAME: &[u8] = b"pagefile.sys";

    /// The store's refusal from the file layer's status: a full volume is no room for the length
    /// asked, anything else is an I/O failure.
    fn store_error(status: NtStatus) -> StoreError {
        if status == STATUS_DISK_FULL {
            StoreError::NoSpace
        } else {
            StoreError::Io
        }
    }

    /// The system's open of the paging file: it reads and writes, sharing nothing.
    const SYSTEM_ACCESS: u8 = ACCESS_READ | ACCESS_WRITE;

    /// The paging file on the boot volume: the store over its directory entry, kept by the boot
    /// ([`boot_create`]). Every operation runs inside the volume's locked section, so the store
    /// itself holds nothing but the entry, the system's open of it and the map of its runs.
    pub struct BootVolumeStore {
        file: File,
        /// The system's open of the file ([`crate::fs::file::FileRecords::open_system`]), held for
        /// the system's life: every other open of the file is refused. Its record follows the
        /// entry as the store changes it.
        record: FileRecordId,
        /// The file's runs as of its last length change; none when it has too many.
        extents: Option<Extents>,
    }

    impl BootVolumeStore {
        /// The open record follows the entry the store just changed.
        fn publish(&self) {
            let file = self.file;
            with_records(|records| records.get_mut(self.record).file = file);
        }

        /// The map, when it covers `len` bytes at `offset`.
        fn mapped(&self, offset: u64, len: usize) -> Option<&Extents> {
            self.extents
                .as_ref()
                .filter(|extents| extents.covers(offset, len))
        }

        /// Write `data` at `offset` straight to the device along the map; none when unmapped.
        fn write_direct(&self, offset: u64, data: &[u8]) -> Option<Result<(), StoreError>> {
            let extents = self.mapped(offset, data.len())?;
            let written = with_boot_volume(|volume| {
                extents.split(offset, data.len(), |lba, range| {
                    volume.write_in_place(lba, &data[range])
                })
            });
            Some(
                written
                    .ok_or(StoreError::Io)
                    .and_then(|w| w.map_err(store_error)),
            )
        }
    }

    impl PageStore for BootVolumeStore {
        fn read_at(&mut self, offset: u64, page: &mut Page) -> Result<(), StoreError> {
            if let Some(extents) = self.mapped(offset, page.len()) {
                return with_boot_volume(|volume| {
                    extents.split(offset, page.len(), |lba, range| {
                        volume.read_sectors(lba, &mut page[range])
                    })
                })
                .ok_or(StoreError::Io)?
                .map_err(store_error);
            }
            let offset = u32::try_from(offset).map_err(|_| StoreError::Io)?;
            let count = with_boot_volume(|volume| read::read_at(volume, &self.file, offset, page))
                .ok_or(StoreError::Io)?
                .map_err(store_error)?;
            if count != page.len() {
                return Err(StoreError::Io);
            }
            Ok(())
        }

        fn read_at_many(&mut self, offset: u64, data: &mut [u8]) -> Result<(), StoreError> {
            if let Some(extents) = self.mapped(offset, data.len()) {
                return with_boot_volume(|volume| {
                    extents.split(offset, data.len(), |lba, range| {
                        volume.read_sectors(lba, &mut data[range])
                    })
                })
                .ok_or(StoreError::Io)?
                .map_err(store_error);
            }
            for (index, page) in data.chunks_exact_mut(PAGE_BYTES).enumerate() {
                let page: &mut Page = page.try_into().map_err(|_| StoreError::Io)?;
                self.read_at(offset + (index * PAGE_BYTES) as u64, page)?;
            }
            Ok(())
        }

        fn write_at(&mut self, offset: u64, page: &Page) -> Result<(), StoreError> {
            if let Some(written) = self.write_direct(offset, page) {
                return written;
            }
            let offset = u32::try_from(offset).map_err(|_| StoreError::Io)?;
            let written =
                with_boot_volume(|volume| write::write_at(volume, &mut self.file, offset, page))
                    .ok_or(StoreError::Io)?;
            self.publish();
            written.map_err(store_error)
        }

        fn write_at_many(&mut self, offset: u64, data: &[u8]) -> Result<(), StoreError> {
            if let Some(written) = self.write_direct(offset, data) {
                return written;
            }
            let offset = u32::try_from(offset).map_err(|_| StoreError::Io)?;
            let written =
                with_boot_volume(|volume| write::write_at(volume, &mut self.file, offset, data))
                    .ok_or(StoreError::Io)?;
            self.publish();
            written.map_err(store_error)
        }

        fn set_len(&mut self, len: u64) -> Result<(), StoreError> {
            let len = u32::try_from(len).map_err(|_| StoreError::NoSpace)?;
            let file = &mut self.file;
            let (set, extents) = with_boot_volume(|volume| {
                let set = write::set_size_with(volume, file, len, Fill::Unwritten);
                (set, Extents::of(volume, file).ok().flatten())
            })
            .ok_or(StoreError::Io)?;
            self.extents = extents;
            self.publish();
            set.map_err(store_error)
        }
    }

    /// The system's one paging file, made at boot — none before it, or on a boot with no volume
    /// or no room — behind the lock that serializes its users.
    static PAGING_FILE: DeviceLock<Option<PagingFile<BootVolumeStore>>> = DeviceLock::new(None);

    /// Run `body` on the paging file, serialized against its other users; none when the boot made
    /// none.
    pub fn with_paging_file<R>(
        body: impl FnOnce(&mut PagingFile<BootVolumeStore>) -> R,
    ) -> Option<R> {
        crate::process::threads::critical_region(|| {
            PAGING_FILE.with(|file| file.as_mut().map(body))
        })
    }

    /// One store operation's outcome as the page-out slice's I/O error: no file, or the store's
    /// refusal, is an I/O failure.
    fn io_result(outcome: Option<Result<(), StoreError>>) -> Result<(), PageIoError> {
        match outcome {
            Some(Ok(())) => Ok(()),
            _ => Err(PageIoError::Io),
        }
    }

    /// The system's one paging file as a [`PagingIo`]: each operation runs through
    /// [`with_paging_file`], so the store is reached serialized — and never while the caller
    /// borrows the memory manager's database (the level rules: the file's disk I/O waits, the
    /// database is borrowed at the high level). The page-out slice's relief and page-in stage
    /// their transfers around this adapter.
    pub struct PagingFileIo;

    impl PagingIo for PagingFileIo {
        fn allocate_slot(&mut self) -> Option<SlotId> {
            with_paging_file(|file| file.allocate_slot())
                .flatten()
                .map(|slot| slot as SlotId)
        }

        fn write(&mut self, slot: SlotId, page: &[u8]) -> Result<(), PageIoError> {
            let page: &Page = page.try_into().map_err(|_| PageIoError::Io)?;
            io_result(with_paging_file(|file| {
                file.write_page(u64::from(slot), page)
            }))
        }

        fn read(&mut self, slot: SlotId, page: &mut [u8]) -> Result<(), PageIoError> {
            let page: &mut Page = page.try_into().map_err(|_| PageIoError::Io)?;
            io_result(with_paging_file(|file| {
                file.read_page(u64::from(slot), page)
            }))
        }

        fn free_slot(&mut self, slot: SlotId) {
            if slot != INVALID_SLOT {
                let _ = with_paging_file(|file| {
                    let slot = u64::from(slot);
                    if file.is_allocated(slot) {
                        file.free_slot(slot);
                    }
                });
            }
        }
    }

    /// The same store through a file the caller already holds: [`FileIo`] over it, for the paths
    /// that run inside one [`with_paging_file`] hold.
    pub fn io_of(file: &mut PagingFile<BootVolumeStore>) -> FileIo<'_, BootVolumeStore> {
        FileIo::new(file)
    }

    /// The paging file's attributes, as the memory manager's create sets them.
    const ATTRIBUTES: u8 = ATTR_HIDDEN | ATTR_SYSTEM;

    /// The file named [`PAGING_FILE_NAME`] an earlier boot (or the disk's build, as Windows 2000's
    /// setup leaves one) left on the volume, with its runs; none when there is none, or the name
    /// is a directory's.
    fn existing() -> Option<(File, Option<Extents>)> {
        with_boot_volume(|volume| match lookup::lookup(volume, PAGING_FILE_NAME) {
            Ok(file) if !file.directory => {
                let extents = Extents::of(volume, &file).ok().flatten();
                Some((file, extents))
            }
            _ => None,
        })
        .flatten()
    }

    /// Make the paging file's entry, empty, in the volume's root.
    fn create_entry() -> Option<File> {
        with_boot_volume(|volume| -> Result<File, NtStatus> {
            let mut file = File::plain(0, 0, false);
            file.attributes = ATTRIBUTES;
            file.times = crate::fs::io::now();
            write::create_entry(
                volume,
                volume.layout().root_cluster,
                PAGING_FILE_NAME,
                &mut file,
            )?;
            Ok(file)
        })?
        .ok()
    }

    /// Set up the paging file on the boot volume — reusing the one an earlier boot (or the disk's
    /// build) left, made only when there is none — sized from the volume's free space (see
    /// [`super::size_from_free_space`]; the old file's clusters count as free, being the paging
    /// file's to keep), and set the system's commit limit to physical memory plus the file's size.
    /// As Windows 2000's memory manager does (MmCreatePagingFile, which SMSS calls at each boot),
    /// an old file longer than the size is cut back, a shorter one grown, and its contents are
    /// never cleared: no slot is read before it is written. Boot context, after the volume's mount.
    /// A boot with no volume, or whose volume cannot hold the file, leaves the limit at physical
    /// memory.
    pub fn boot_create() {
        PAGING_FILE.init();
        let existing = existing();
        let free_bytes = with_boot_volume(|volume| {
            let cluster = u64::from(volume.layout().sectors_per_cluster) * 512;
            let kept = existing.as_ref().map_or(0, |(file, _)| {
                u64::from(file.size).div_ceil(cluster) * cluster
            });
            volume
                .free_clusters()
                .map(|free| u64::from(free) * cluster + kept)
        });
        let Some(Ok(free_bytes)) = free_bytes else {
            return;
        };
        // Physical memory while the limit is unset: the boot's physical pages.
        let ram_bytes = crate::mem::system_commit_limit();
        let (size, limit) = boot_sizing(free_bytes, ram_bytes);

        let (mut file, extents) = match existing {
            Some(existing) => existing,
            None => match create_entry() {
                Some(file) => (file, None),
                None => return,
            },
        };
        let current = u64::from(file.size);
        if file.attributes != ATTRIBUTES {
            // The create's attributes, as Windows 2000's supersede of the old file sets them.
            file.attributes = ATTRIBUTES;
            if with_boot_volume(|volume| write::update_entry(volume, &file)) != Some(Ok(())) {
                return;
            }
        }
        // The memory manager's open of the file (IoCreateFile with SL_OPEN_PAGING_FILE), held for
        // the system's life: no process opens the file after it.
        let Ok(record) = with_records(|records| records.open_system(file, SYSTEM_ACCESS)) else {
            return;
        };
        let store = BootVolumeStore {
            file,
            record,
            extents,
        };
        let file = match PagingFile::reuse(store, current, size) {
            Ok(file) => file,
            Err(_) => {
                with_records(|records| {
                    let _ = records.cleanup(record, SYSTEM_ACCESS, 0, false);
                    records.close(record);
                });
                return;
            }
        };
        crate::mem::set_system_commit_limit(limit);
        let (pages, mib) = (file.pages(), size / (1024 * 1024));
        PAGING_FILE.with(|slot| *slot = Some(file));
        // Leave the volume as the boot found it: the file's writes are all on disk, so the flush
        // counts its free clusters into FSInfo and marks it clean (nothing to do when the old file
        // was kept as it was), and a shutdown later finds nothing to write.
        let _ = with_boot_volume(|volume| volume.flush());
        crate::klog!(
            File,
            "mem",
            "paging file: {pages} pages ({mib} MiB), commit limit {} pages",
            limit / 4096
        );
    }
}

#[cfg(target_arch = "x86")]
pub use target::{boot_create, with_paging_file, PagingFileIo};

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    /// The boot sizes the file from the volume's free space — the reserve stays free, the rest
    /// goes in whole pages up to the boot's cap — and sets the commit limit to physical memory
    /// plus the file.
    #[test]
    fn the_boot_sizes_the_file_from_the_free_space_and_sets_the_limit() {
        let mib = 1024 * 1024;
        let (size, limit) = boot_sizing(44 * mib + 123, 32 * mib);
        assert_eq!(
            size,
            BOOT_MAX_PAGES * PAGE_BYTES as u64,
            "the boot's cap binds on a roomy volume"
        );
        assert_eq!(size % PAGE_BYTES as u64, 0);
        assert_eq!(limit, 32 * mib + size, "RAM plus the paging file");
        assert_eq!(limit - 32 * mib, size);

        // A volume with less free than the cap takes what it has past the reserve, in whole pages.
        let (size, limit) = boot_sizing(FREE_SPACE_RESERVE_BYTES + 10_000, 32 * mib);
        assert_eq!(size, 2 * PAGE_BYTES as u64);
        assert_eq!(limit, 32 * mib + 2 * PAGE_BYTES as u64);

        // A nearly full volume: nothing past the reserve, so no file, and the limit is RAM alone.
        let (size, limit) = boot_sizing(FREE_SPACE_RESERVE_BYTES, 32 * mib);
        assert_eq!((size, limit), (0, 32 * mib));
        let (size, limit) = boot_sizing(1024, 32 * mib);
        assert_eq!((size, limit), (0, 32 * mib));
    }

    /// A volume with more free space than the boot's cap: the file stops at the cap, which stays
    /// under the bitmap's.
    #[test]
    fn the_file_is_capped_at_the_boots_cap() {
        let mib = 1024 * 1024;
        assert!(BOOT_MAX_PAGES <= MAX_PAGES);
        let (size, limit) = boot_sizing(u64::MAX, 32 * mib);
        assert_eq!(size, BOOT_MAX_PAGES * PAGE_BYTES as u64);
        assert_eq!(limit, 32 * mib + BOOT_MAX_PAGES * PAGE_BYTES as u64);

        let (size, _) = boot_sizing(
            FREE_SPACE_RESERVE_BYTES + (MAX_PAGES + 5) * PAGE_BYTES as u64,
            0,
        );
        assert_eq!(
            size,
            BOOT_MAX_PAGES * PAGE_BYTES as u64,
            "the boot's cap binds before the bitmap's"
        );
    }

    /// A RAM disk as the store: a byte buffer that grows on `set_len` (zero-filling), refuses
    /// every operation while `fail` is set, caps its length at `max`, and records the offsets
    /// read and written.
    struct RamDisk {
        data: Vec<u8>,
        max: u64,
        fail: bool,
        reads: Vec<u64>,
        writes: Vec<u64>,
        /// The lengths `set_len` was asked for, in order.
        lens: Vec<u64>,
    }

    impl RamDisk {
        fn new(max: u64) -> RamDisk {
            RamDisk {
                data: Vec::new(),
                max,
                fail: false,
                reads: Vec::new(),
                writes: Vec::new(),
                lens: Vec::new(),
            }
        }

        /// A disk holding an earlier boot's file: `pages` pages of `byte`.
        fn holding(pages: u64, byte: u8) -> RamDisk {
            let mut disk = RamDisk::new(u64::MAX);
            disk.data = vec![byte; pages as usize * PAGE_BYTES];
            disk
        }
    }

    impl PageStore for RamDisk {
        fn read_at(&mut self, offset: u64, page: &mut Page) -> Result<(), StoreError> {
            if self.fail {
                return Err(StoreError::Io);
            }
            let start = offset as usize;
            let end = start + PAGE_BYTES;
            if end > self.data.len() {
                return Err(StoreError::Io);
            }
            self.reads.push(offset);
            page.copy_from_slice(&self.data[start..end]);
            Ok(())
        }

        fn write_at(&mut self, offset: u64, page: &Page) -> Result<(), StoreError> {
            if self.fail {
                return Err(StoreError::Io);
            }
            let start = offset as usize;
            let end = start + PAGE_BYTES;
            if end > self.data.len() {
                return Err(StoreError::Io);
            }
            self.writes.push(offset);
            self.data[start..end].copy_from_slice(page);
            Ok(())
        }

        fn set_len(&mut self, len: u64) -> Result<(), StoreError> {
            if self.fail {
                return Err(StoreError::Io);
            }
            if len > self.max {
                return Err(StoreError::NoSpace);
            }
            self.lens.push(len);
            self.data.resize(len as usize, 0);
            Ok(())
        }
    }

    /// A page filled with `byte`.
    fn page(byte: u8) -> Page {
        [byte; PAGE_BYTES]
    }

    /// The file is made at the rounded-up size, empty, with slot 0 reserved and the rest free.
    #[test]
    fn create_sizes_the_file_in_whole_pages() {
        let file = PagingFile::create(RamDisk::new(u64::MAX), 10_000).unwrap();
        assert_eq!(file.pages(), 3);
        assert_eq!(file.size_bytes(), 3 * PAGE_BYTES as u64);
        assert_eq!(
            file.store().data.len(),
            3 * PAGE_BYTES,
            "the store was asked for the length"
        );
        assert_eq!(file.capacity(), 2, "slot 0 is reserved");
        assert_eq!(file.used(), 0);
        assert_eq!(file.free_slots(), 2);
        assert!(file.is_allocated(0), "slot 0 reads as taken");
        assert!(!file.is_allocated(1));
        assert!(!file.is_allocated(2));
        assert!(!file.is_allocated(3), "past the file's end reads as free");

        let file = PagingFile::create(RamDisk::new(u64::MAX), 2 * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.pages(), 2, "a whole-page size is not rounded further");
        assert_eq!(file.capacity(), 1);
    }

    /// A create the store refuses comes back as its error.
    #[test]
    fn create_can_be_refused_by_the_store() {
        let disk = RamDisk::new(2 * PAGE_BYTES as u64);
        assert_eq!(
            PagingFile::create(disk, 3 * PAGE_BYTES as u64)
                .err()
                .unwrap(),
            StoreError::NoSpace
        );
        let mut disk = RamDisk::new(u64::MAX);
        disk.fail = true;
        assert_eq!(
            PagingFile::create(disk, PAGE_BYTES as u64).err().unwrap(),
            StoreError::Io
        );
    }

    /// An earlier boot's file of the right length is taken over as it is: no length is set and
    /// nothing written, its old contents left in place, and every slot but the reserved one free.
    #[test]
    fn reuse_keeps_a_file_of_the_right_length_untouched() {
        let size = 8 * PAGE_BYTES as u64;
        let mut file = PagingFile::reuse(RamDisk::holding(8, 0xC5), size, size).unwrap();
        assert_eq!(file.pages(), 8);
        assert!(file.store().lens.is_empty(), "the length was kept");
        assert!(file.store().writes.is_empty(), "nothing was written");
        assert!(
            file.store().data.iter().all(|&byte| byte == 0xC5),
            "the old contents were not cleared"
        );
        assert_eq!((file.used(), file.free_slots()), (0, 7));
        assert_eq!(file.allocate_slot(), Some(1), "slot 0 stays reserved");
        file.write_page(1, &page(0x11)).unwrap();
        let mut back = page(0);
        file.read_page(1, &mut back).unwrap();
        assert_eq!(back, page(0x11));
    }

    /// A longer file is cut back to the size and a shorter one grown, the kept part's old bytes
    /// left alone; a length off the page grid is set to whole pages.
    #[test]
    fn reuse_cuts_a_longer_file_back_and_grows_a_shorter_one() {
        let page_bytes = PAGE_BYTES as u64;
        let file =
            PagingFile::reuse(RamDisk::holding(12, 0xC5), 12 * page_bytes, 8 * page_bytes).unwrap();
        assert_eq!(file.pages(), 8);
        assert_eq!(file.store().lens, [8 * page_bytes], "cut back to the size");
        assert_eq!(file.store().data.len(), 8 * PAGE_BYTES);
        assert!(file.store().data.iter().all(|&byte| byte == 0xC5));
        assert!(!file.is_allocated(8), "past the new end is no slot");

        let file =
            PagingFile::reuse(RamDisk::holding(4, 0xC5), 4 * page_bytes, 8 * page_bytes).unwrap();
        assert_eq!(file.pages(), 8);
        assert_eq!(file.store().lens, [8 * page_bytes], "grown to the size");
        assert_eq!(file.free_slots(), 7);
        assert!(file.store().writes.is_empty(), "the growth writes nothing");

        let file = PagingFile::reuse(RamDisk::holding(4, 0), 4 * page_bytes - 100, 4 * page_bytes)
            .unwrap();
        assert_eq!(file.store().lens, [4 * page_bytes], "whole pages");

        let mut disk = RamDisk::holding(4, 0);
        disk.max = 6 * page_bytes;
        assert_eq!(
            PagingFile::reuse(disk, 4 * page_bytes, 8 * page_bytes)
                .err()
                .unwrap(),
            StoreError::NoSpace,
            "a growth the store refuses comes back as its error"
        );
    }

    /// Sizes past the bitmap's capacity are capped.
    #[test]
    fn the_size_is_capped_at_the_bitmap() {
        let file = PagingFile::create(RamDisk::new(u64::MAX), (MAX_PAGES + 8) * PAGE_BYTES as u64)
            .unwrap();
        assert_eq!(file.pages(), MAX_PAGES);
        assert_eq!(file.capacity(), MAX_PAGES - 1);
        assert_eq!(file.size_bytes(), MAX_PAGES * PAGE_BYTES as u64);
    }

    /// An empty file hands out nothing but can still grow.
    #[test]
    fn an_empty_file_hands_out_nothing() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 0).unwrap();
        assert_eq!(file.pages(), 0);
        assert_eq!(file.capacity(), 0);
        assert_eq!(file.allocate_slot(), None);
        assert_eq!(file.extend().unwrap(), EXTEND_PAGES);
        assert_eq!(file.capacity(), EXTEND_PAGES - 1);
        assert_eq!(
            file.allocate_slot(),
            Some(1),
            "slot 0 stays reserved after a growth from empty"
        );
    }

    /// Allocation takes the lowest free slot, never slot 0, and a freed slot is reused first.
    #[test]
    fn allocation_takes_the_lowest_free_slot_and_never_slot_zero() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 8 * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.allocate_slot(), Some(1));
        assert_eq!(file.allocate_slot(), Some(2));
        assert_eq!(file.allocate_slot(), Some(3));
        assert_eq!(file.used(), 3);
        assert!(file.is_allocated(1) && file.is_allocated(2) && file.is_allocated(3));
        assert!(!file.is_allocated(4));
        file.free_slot(2);
        assert_eq!(
            file.allocate_slot(),
            Some(2),
            "the freed slot is the lowest free one"
        );
        assert_eq!(file.used(), 3);

        let mut tiny = PagingFile::create(RamDisk::new(u64::MAX), PAGE_BYTES as u64).unwrap();
        assert_eq!(
            tiny.capacity(),
            0,
            "a one-page file holds only the reserved slot"
        );
        assert_eq!(tiny.allocate_slot(), None);
    }

    /// Every slot comes out exactly once, in order, across a bitmap word boundary; then None.
    #[test]
    fn exhaustion_hands_out_every_slot_once_then_none() {
        let pages = 130; // past the first bitmap word
        let mut file =
            PagingFile::create(RamDisk::new(u64::MAX), pages * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.capacity(), pages - 1);
        let mut slots = Vec::new();
        while let Some(slot) = file.allocate_slot() {
            assert!(slot >= 1 && slot < pages);
            slots.push(slot);
        }
        assert_eq!(slots.len(), (pages - 1) as usize);
        for (i, slot) in slots.iter().enumerate() {
            assert_eq!(*slot, i as u64 + 1, "slots come out in order");
        }
        assert_eq!(file.used(), file.capacity());
        assert_eq!(file.free_slots(), 0);
        assert_eq!(file.allocate_slot(), None);
        // frees in different words are both reused, lowest first
        file.free_slot(65);
        file.free_slot(1);
        assert_eq!(file.allocate_slot(), Some(1));
        assert_eq!(file.allocate_slot(), Some(65));
        assert_eq!(file.allocate_slot(), None);
    }

    /// A run of contiguous slots comes out whole, lowest first, across the bitmap's word
    /// boundary; a fragmented bitmap hands out none that long, and freed slots join runs again.
    #[test]
    fn a_run_of_slots_is_allocated_contiguously() {
        let pages = 70; // past the first bitmap word, so runs cross it
        let mut file =
            PagingFile::create(RamDisk::new(u64::MAX), pages * PAGE_BYTES as u64).unwrap();
        assert_eq!(
            file.allocate_slots(3),
            Some(1),
            "the first run starts at slot 1"
        );
        assert!(file.is_allocated(1) && file.is_allocated(3) && !file.is_allocated(4));
        assert_eq!(file.used(), 3);
        while file.allocate_slot() != Some(64) {}
        file.free_slot(64);
        assert_eq!(file.allocate_slot(), Some(64));
        assert_eq!(
            file.allocate_slots(4),
            Some(65),
            "slots 65-68 are the lowest free run"
        );
        assert_eq!(
            file.allocate_slots(pages),
            None,
            "no run spans the taken slots"
        );
        for slot in [1, 2, 3] {
            file.free_slot(slot);
        }
        assert_eq!(file.allocate_slots(3), Some(1));
    }

    /// A multi-page write lands at the run's first offset, whole pages through the store (the
    /// default moves them one page per call, at the slots' offsets).
    #[test]
    fn a_multi_page_write_lands_at_the_runs_first_offset() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 8 * PAGE_BYTES as u64).unwrap();
        let first = file.allocate_slots(3).unwrap();
        let mut data = vec![0u8; 3 * PAGE_BYTES];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        file.write_pages(first, &data).unwrap();
        assert_eq!(
            file.store().writes,
            vec![
                PAGE_BYTES as u64,
                2 * PAGE_BYTES as u64,
                3 * PAGE_BYTES as u64
            ]
        );
        let mut page = [0u8; PAGE_BYTES];
        file.read_page(2, &mut page).unwrap();
        assert_eq!(&page[..], &data[PAGE_BYTES..2 * PAGE_BYTES]);
    }

    /// A multi-page read takes the run from its first offset (the default reads one page per
    /// call, at the slots' offsets) and refuses a run with a slot that is not allocated.
    #[test]
    fn a_multi_page_read_takes_the_run_from_its_first_offset() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 8 * PAGE_BYTES as u64).unwrap();
        let first = file.allocate_slots(3).unwrap();
        let mut data = vec![0u8; 3 * PAGE_BYTES];
        for (index, byte) in data.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        file.write_pages(first, &data).unwrap();
        let mut back = vec![0u8; 3 * PAGE_BYTES];
        file.read_pages(first, &mut back).unwrap();
        assert_eq!(back, data);
        assert_eq!(
            file.store().reads,
            vec![
                PAGE_BYTES as u64,
                2 * PAGE_BYTES as u64,
                3 * PAGE_BYTES as u64
            ]
        );
        file.free_slot(3);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            file.read_pages(first, &mut back)
        }));
        assert!(refused.is_err(), "slot 3 of the run is free");
    }

    /// Freeing a slot that is not allocated is refused.
    #[test]
    fn freeing_a_slot_that_is_not_allocated_panics() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 4 * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.allocate_slot(), Some(1));
        for bad in [0u64, 2, 4, 100] {
            let refused =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| file.free_slot(bad)));
            assert!(refused.is_err(), "free of slot {bad} is refused");
        }
        file.free_slot(1);
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| file.free_slot(1)));
        assert!(refused.is_err(), "a double free is refused");
    }

    /// An extension grows the file on the store and frees the new slots; a refused extension
    /// leaves the file unchanged.
    #[test]
    fn extend_grows_the_file_and_frees_the_new_slots() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 4 * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.allocate_slot(), Some(1));
        assert_eq!(file.allocate_slot(), Some(2));
        assert_eq!(file.allocate_slot(), Some(3));
        assert_eq!(file.allocate_slot(), None);
        let pages = file.extend().unwrap();
        assert_eq!(pages, 4 + EXTEND_PAGES);
        assert_eq!(file.pages(), pages);
        assert_eq!(file.size_bytes(), pages * PAGE_BYTES as u64);
        assert_eq!(file.store().data.len(), pages as usize * PAGE_BYTES);
        assert_eq!(file.capacity(), pages - 1);
        assert_eq!(file.used(), 3, "the taken slots stay taken");
        assert_eq!(file.free_slots(), pages - 1 - 3);
        assert_eq!(
            file.allocate_slot(),
            Some(4),
            "allocation continues past the old end"
        );

        file.store_mut().fail = true;
        assert_eq!(
            file.extend(),
            Err(StoreError::Io),
            "a failing store refuses the growth"
        );
        assert_eq!(file.pages(), pages, "the file is unchanged");
        assert_eq!(file.used(), 4);
        assert_eq!(file.allocate_slot(), Some(5), "the bitmap is unchanged");
    }

    /// An extension at the bitmap's cap has no room; one near it grows only to the cap.
    #[test]
    fn extend_at_the_bitmap_cap_has_no_room() {
        let mut file =
            PagingFile::create(RamDisk::new(u64::MAX), MAX_PAGES * PAGE_BYTES as u64).unwrap();
        assert_eq!(file.extend(), Err(StoreError::NoSpace));
        assert_eq!(file.pages(), MAX_PAGES);

        let mut file =
            PagingFile::create(RamDisk::new(u64::MAX), (MAX_PAGES - 10) * PAGE_BYTES as u64)
                .unwrap();
        assert_eq!(
            file.extend().unwrap(),
            MAX_PAGES,
            "the growth stops at the cap"
        );
    }

    /// A page round-trips byte for byte, at its slot's offset in the store.
    #[test]
    fn a_page_round_trips_byte_for_byte() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 2 * PAGE_BYTES as u64).unwrap();
        let slot = file.allocate_slot().unwrap();
        let mut pattern = [0u8; PAGE_BYTES];
        for (i, b) in pattern.iter_mut().enumerate() {
            *b = (i as u32).wrapping_mul(7) as u8;
        }
        file.write_page(slot, &pattern).unwrap();
        assert_eq!(
            file.store().writes,
            [slot * PAGE_BYTES as u64],
            "written at the slot's offset"
        );
        let start = slot as usize * PAGE_BYTES;
        assert_eq!(&file.store().data[start..start + PAGE_BYTES], &pattern);
        let mut back = [0u8; PAGE_BYTES];
        file.read_page(slot, &mut back).unwrap();
        assert_eq!(back, pattern);
        assert_eq!(
            file.store().reads,
            [slot * PAGE_BYTES as u64],
            "read at the slot's offset"
        );
    }

    /// Writes and reads land at their own slots' offsets; a never-written slot reads as the
    /// fresh file's zeros; contents survive an extension; a re-taken slot takes a new write.
    #[test]
    fn pages_round_trip_through_the_store_at_their_offsets() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 8 * PAGE_BYTES as u64).unwrap();
        for _ in 0..7 {
            file.allocate_slot();
        }
        file.write_page(1, &page(0x11)).unwrap();
        file.write_page(5, &page(0x55)).unwrap();
        file.write_page(7, &page(0x77)).unwrap();
        assert_eq!(
            file.store().writes,
            [1, 5, 7].map(|s| s * PAGE_BYTES as u64)
        );

        let mut buf = page(0);
        file.read_page(1, &mut buf).unwrap();
        assert_eq!(buf, page(0x11));
        file.read_page(5, &mut buf).unwrap();
        assert_eq!(buf, page(0x55));
        file.read_page(7, &mut buf).unwrap();
        assert_eq!(buf, page(0x77));
        assert_eq!(file.store().reads, [1, 5, 7].map(|s| s * PAGE_BYTES as u64));

        file.read_page(3, &mut buf).unwrap();
        assert_eq!(buf, page(0), "a never-written slot reads as zeros");

        file.extend().unwrap();
        file.read_page(7, &mut buf).unwrap();
        assert_eq!(buf, page(0x77), "contents survive an extension");

        file.free_slot(5);
        assert_eq!(file.allocate_slot(), Some(5));
        file.write_page(5, &page(0xAA)).unwrap();
        file.read_page(5, &mut buf).unwrap();
        assert_eq!(buf, page(0xAA));
    }

    /// The [`FileIo`] adapter over the file: slots come out one at a time past the reserved one,
    /// each page is written and read at its slot's byte offset (`slot * PAGE_BYTES`), a freed slot
    /// is reused, the invalid slot is a no-op, and a failing store comes back as an I/O error.
    #[test]
    fn the_paging_io_adapter_moves_pages_at_their_slots_offsets() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 8 * PAGE_BYTES as u64).unwrap();

        let first = FileIo::new(&mut file).allocate_slot().unwrap();
        assert_eq!(first, 1, "slot 0 stays reserved");
        FileIo::new(&mut file).write(first, &page(0x42)).unwrap();
        assert_eq!(
            file.store().writes,
            [u64::from(first) * PAGE_BYTES as u64],
            "the page went to its slot's offset"
        );

        let mut back = page(0);
        FileIo::new(&mut file).read(first, &mut back).unwrap();
        assert_eq!(back, page(0x42), "the page came back byte for byte");
        assert_eq!(
            file.store().reads,
            [u64::from(first) * PAGE_BYTES as u64],
            "read at the slot's offset"
        );

        // A second slot lands at its own offset.
        let second = FileIo::new(&mut file).allocate_slot().unwrap();
        assert_eq!(second, 2);
        FileIo::new(&mut file).write(second, &page(0x77)).unwrap();
        assert_eq!(
            file.store().writes[1],
            u64::from(second) * PAGE_BYTES as u64
        );

        // A freed slot is handed out again, lowest first; the invalid slot frees nothing.
        FileIo::new(&mut file).free_slot(first);
        assert_eq!(FileIo::new(&mut file).allocate_slot(), Some(first));
        FileIo::new(&mut file).free_slot(INVALID_SLOT);
        assert_eq!(file.used(), 2);

        // A failing store comes back as an I/O error, from the read and the write alike.
        file.store_mut().fail = true;
        let mut back = page(0);
        assert_eq!(
            FileIo::new(&mut file).read(second, &mut back),
            Err(PageIoError::Io)
        );
        assert_eq!(
            FileIo::new(&mut file).write(second, &back),
            Err(PageIoError::Io)
        );
        assert_eq!(file.used(), 2, "both slots still held");
    }

    /// Reading or writing a slot that is not allocated is refused; a failing store comes back
    /// as its error.
    #[test]
    fn reading_or_writing_a_slot_that_is_not_allocated_panics() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), 4 * PAGE_BYTES as u64).unwrap();
        let slot = file.allocate_slot().unwrap();
        for bad in [0u64, 2, 4, 1000] {
            let mut buf = page(0);
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                file.read_page(bad, &mut buf)
            }));
            assert!(refused.is_err(), "read of slot {bad} is refused");
            let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                file.write_page(bad, &buf)
            }));
            assert!(refused.is_err(), "write of slot {bad} is refused");
        }
        file.write_page(slot, &page(1)).unwrap();

        file.store_mut().fail = true;
        let mut buf = page(0);
        assert_eq!(file.read_page(slot, &mut buf), Err(StoreError::Io));
        assert_eq!(file.write_page(slot, &buf), Err(StoreError::Io));
    }
}
