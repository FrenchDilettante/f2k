//! The paging file: the boot volume's disposable backing store for pages paged out of memory.
//!
//! The file is created fresh at each boot — its contents are never needed across boots, so it
//! carries no header and there is no recovery — sized from the volume's free space, and laid out
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

use super::paging::PAGE_SIZE;

/// One page of the paging file, and of its slot index space: 4 KiB.
pub const PAGE_BYTES: usize = PAGE_SIZE as usize;
/// A page-sized buffer.
pub type Page = [u8; PAGE_BYTES];

/// The largest paging file the bitmap covers: 65536 pages (256 MiB). Larger sizes are capped.
pub const MAX_PAGES: u64 = 1 << 16;
/// The bitmap's words.
const MAX_WORDS: usize = (MAX_PAGES as usize + 63) / 64;
/// How many pages one [`PagingFile::extend`] adds: 1024 (4 MiB).
pub const EXTEND_PAGES: u64 = 1024;

/// The free space the paging file leaves the boot volume's other users, in bytes: the volume
/// keeps this much of its free space for the files written beside the paging file.
pub const FREE_SPACE_RESERVE_BYTES: u64 = 8 * 1024 * 1024;

/// The largest paging file the boot makes fresh, in pages: 2048 (8 MiB). The file is made anew at
/// every boot and on this volume a cluster is one sector, so its length costs the device one
/// allocation per 512 bytes — the boot keeps the file to what it can afford to write and lets it
/// grow in [`EXTEND_PAGES`] chunks (which is also what raises the commit limit) when the allocator
/// runs out of room.
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
/// file's length. The kernel's adapter wires this to the paging file on the boot volume (made
/// fresh at each boot, so a fresh store's first [`PageStore::set_len`] creates the file); host
/// tests drive it over a RAM disk.
pub trait PageStore {
    /// Read the page at byte `offset` into `page`.
    fn read_at(&mut self, offset: u64, page: &mut Page) -> Result<(), StoreError>;
    /// Write `page` at byte `offset`.
    fn write_at(&mut self, offset: u64, page: &Page) -> Result<(), StoreError>;
    /// Set the file's length to `len` bytes, zero-filling any growth.
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
        let pages = size.div_ceil(PAGE_BYTES as u64).min(MAX_PAGES);
        store.set_len(pages * PAGE_BYTES as u64)?;
        let mut bitmap = [u64::MAX; MAX_WORDS];
        // Every bit starts set; the file's own slots come out free, slot 0 staying reserved.
        clear_bits(&mut bitmap, 1, pages);
        Ok(PagingFile {
            store,
            bitmap,
            pages,
            used: 0,
            next: 1,
        })
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

// --- The boot volume's file layer (target) ------------------------------------------------------
//
// The kernel wires the paging file to a file on the boot volume: [`BootVolumeStore`] adapts the
// volume's file layer to [`PageStore`] — whole-page reads and writes at byte offsets and setting
// the file's length, each operation inside the volume's own locked section — and [`boot_create`]
// makes the file fresh at boot and sets the commit limit from it.

#[cfg(target_arch = "x86")]
mod target {
    use super::{boot_sizing, Page, PageStore, PagingFile, StoreError};
    use crate::block::lock::DeviceLock;
    use crate::fs::fat32::dirent::{ATTR_HIDDEN, ATTR_SYSTEM};
    use crate::fs::fat32::lookup::{self, File};
    use crate::fs::fat32::read;
    use crate::fs::fat32::volume::with_boot_volume;
    use crate::fs::fat32::write;
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

    /// The paging file on the boot volume: the store over its directory entry, kept by the boot
    /// ([`boot_create`]). Every operation runs inside the volume's locked section, so the store
    /// itself holds nothing but the entry.
    pub struct BootVolumeStore {
        file: File,
    }

    impl PageStore for BootVolumeStore {
        fn read_at(&mut self, offset: u64, page: &mut Page) -> Result<(), StoreError> {
            let offset = u32::try_from(offset).map_err(|_| StoreError::Io)?;
            let count = with_boot_volume(|volume| read::read_at(volume, &self.file, offset, page))
                .ok_or(StoreError::Io)?
                .map_err(store_error)?;
            if count != page.len() {
                return Err(StoreError::Io);
            }
            Ok(())
        }

        fn write_at(&mut self, offset: u64, page: &Page) -> Result<(), StoreError> {
            let offset = u32::try_from(offset).map_err(|_| StoreError::Io)?;
            with_boot_volume(|volume| write::write_at(volume, &mut self.file, offset, page))
                .ok_or(StoreError::Io)?
                .map_err(store_error)
        }

        fn set_len(&mut self, len: u64) -> Result<(), StoreError> {
            let len = u32::try_from(len).map_err(|_| StoreError::NoSpace)?;
            with_boot_volume(|volume| write::set_size(volume, &mut self.file, len))
                .ok_or(StoreError::Io)?
                .map_err(store_error)
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

    /// Take the entry named [`PAGING_FILE_NAME`] off the volume, when it is a file: the paging
    /// file is made fresh at each boot, so one left by an earlier boot goes first.
    fn remove_existing() {
        let _ = with_boot_volume(|volume| match lookup::lookup(volume, PAGING_FILE_NAME) {
            Ok(file) if !file.directory => write::delete(volume, &file),
            _ => Ok(()),
        });
    }

    /// Make the paging file fresh on the boot volume — sized from the volume's free space (see
    /// [`super::size_from_free_space`]) — and set the system's commit limit to physical memory
    /// plus the file's size. Boot context, after the volume's mount. A boot with no volume, or
    /// whose volume cannot hold the file, leaves the limit at physical memory.
    pub fn boot_create() {
        PAGING_FILE.init();
        let free_bytes = with_boot_volume(|volume| {
            let cluster = u64::from(volume.layout().sectors_per_cluster) * 512;
            volume.free_clusters().map(|free| u64::from(free) * cluster)
        });
        let Some(Ok(free_bytes)) = free_bytes else {
            return;
        };
        // Physical memory while the limit is unset: the frame database's whole size.
        let ram_bytes = crate::mem::system_commit_limit();
        let (size, limit) = boot_sizing(free_bytes, ram_bytes);

        remove_existing();
        let store = match with_boot_volume(|volume| -> Result<BootVolumeStore, NtStatus> {
            let mut file = File::plain(0, 0, false);
            file.attributes = ATTR_HIDDEN | ATTR_SYSTEM;
            file.times = crate::fs::io::now();
            write::create_entry(
                volume,
                volume.layout().root_cluster,
                PAGING_FILE_NAME,
                &mut file,
            )?;
            Ok(BootVolumeStore { file })
        }) {
            Some(Ok(store)) => store,
            _ => return,
        };
        let file = match PagingFile::create(store, size) {
            Ok(file) => file,
            Err(_) => {
                remove_existing();
                return;
            }
        };
        crate::mem::set_system_commit_limit(limit);
        let pages = file.pages();
        PAGING_FILE.with(|slot| *slot = Some(file));
        // Leave the volume as the boot found it: the file's writes are all on disk, so the flush
        // counts its free clusters into FSInfo and marks it clean, and a shutdown later finds
        // nothing to write.
        let _ = with_boot_volume(|volume| volume.flush());
        crate::serial_println!(
            "F2K: paging file: {} pages ({} MiB), commit limit {} pages",
            pages,
            size / (1024 * 1024),
            limit / 4096
        );
    }
}

#[cfg(target_arch = "x86")]
pub use target::boot_create;

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// The boot sizes the file from the volume's free space — the reserve stays free, the rest
    /// goes in whole pages up to the boot's cap — and sets the commit limit to physical memory
    /// plus the file.
    #[test]
    fn the_boot_sizes_the_file_from_the_free_space_and_sets_the_limit() {
        let mib = 1024 * 1024;
        let (size, limit) = boot_sizing(44 * mib + 123, 32 * mib);
        assert_eq!(size, BOOT_MAX_PAGES * PAGE_BYTES as u64, "the boot's cap binds on a roomy volume");
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

        let (size, _) =
            boot_sizing(FREE_SPACE_RESERVE_BYTES + (MAX_PAGES + 5) * PAGE_BYTES as u64, 0);
        assert_eq!(size, BOOT_MAX_PAGES * PAGE_BYTES as u64, "the boot's cap binds before the bitmap's");
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
    }

    impl RamDisk {
        fn new(max: u64) -> RamDisk {
            RamDisk {
                data: Vec::new(),
                max,
                fail: false,
                reads: Vec::new(),
                writes: Vec::new(),
            }
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
        assert_eq!(file.store().data.len(), 3 * PAGE_BYTES, "the store was asked for the length");
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
            PagingFile::create(disk, 3 * PAGE_BYTES as u64).err().unwrap(),
            StoreError::NoSpace
        );
        let mut disk = RamDisk::new(u64::MAX);
        disk.fail = true;
        assert_eq!(
            PagingFile::create(disk, PAGE_BYTES as u64).err().unwrap(),
            StoreError::Io
        );
    }

    /// Sizes past the bitmap's capacity are capped.
    #[test]
    fn the_size_is_capped_at_the_bitmap() {
        let file =
            PagingFile::create(RamDisk::new(u64::MAX), (MAX_PAGES + 8) * PAGE_BYTES as u64).unwrap();
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
        assert_eq!(file.allocate_slot(), Some(1), "slot 0 stays reserved after a growth from empty");
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
        assert_eq!(file.allocate_slot(), Some(2), "the freed slot is the lowest free one");
        assert_eq!(file.used(), 3);

        let mut tiny = PagingFile::create(RamDisk::new(u64::MAX), PAGE_BYTES as u64).unwrap();
        assert_eq!(tiny.capacity(), 0, "a one-page file holds only the reserved slot");
        assert_eq!(tiny.allocate_slot(), None);
    }

    /// Every slot comes out exactly once, in order, across a bitmap word boundary; then None.
    #[test]
    fn exhaustion_hands_out_every_slot_once_then_none() {
        let pages = 130; // past the first bitmap word
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), pages * PAGE_BYTES as u64).unwrap();
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
        let refused =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| file.free_slot(1)));
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
        assert_eq!(file.allocate_slot(), Some(4), "allocation continues past the old end");

        file.store_mut().fail = true;
        assert_eq!(file.extend(), Err(StoreError::Io), "a failing store refuses the growth");
        assert_eq!(file.pages(), pages, "the file is unchanged");
        assert_eq!(file.used(), 4);
        assert_eq!(file.allocate_slot(), Some(5), "the bitmap is unchanged");
    }

    /// An extension at the bitmap's cap has no room; one near it grows only to the cap.
    #[test]
    fn extend_at_the_bitmap_cap_has_no_room() {
        let mut file = PagingFile::create(RamDisk::new(u64::MAX), MAX_PAGES * PAGE_BYTES as u64)
            .unwrap();
        assert_eq!(file.extend(), Err(StoreError::NoSpace));
        assert_eq!(file.pages(), MAX_PAGES);

        let mut file =
            PagingFile::create(RamDisk::new(u64::MAX), (MAX_PAGES - 10) * PAGE_BYTES as u64)
                .unwrap();
        assert_eq!(file.extend().unwrap(), MAX_PAGES, "the growth stops at the cap");
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
        assert_eq!(file.store().writes, [slot * PAGE_BYTES as u64], "written at the slot's offset");
        let start = slot as usize * PAGE_BYTES;
        assert_eq!(&file.store().data[start..start + PAGE_BYTES], &pattern);
        let mut back = [0u8; PAGE_BYTES];
        file.read_page(slot, &mut back).unwrap();
        assert_eq!(back, pattern);
        assert_eq!(file.store().reads, [slot * PAGE_BYTES as u64], "read at the slot's offset");
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
        assert_eq!(file.store().writes, [1, 5, 7].map(|s| s * PAGE_BYTES as u64));

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
