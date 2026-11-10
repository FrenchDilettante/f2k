//! The RAM disk: a disk whose sectors are physical memory, the disk image a boot loader loaded
//! beside the kernel as a Multiboot module named `f2k-disk` (QEMU's `-initrd`). The boot registers
//! it ahead of the IDE disk, so its first partition is the boot volume; FAT32, the file objects and
//! the image sections run over it as they run over the IDE disk.
//!
//! It is a test device, as the Windows 2000 DDK's RAM disk sample (a disk backed by nonpaged
//! memory) is a sample: the QEMU boots of the test suite read their disk from memory instead of
//! through the IDE controller's per-sector interrupts. Its frames are the module's, withheld from
//! the frame database at boot (`mem::bootmem::disk_module`), and are reached through the scratch
//! window a page at a time, never mapped whole: the image (64 MiB) lies past the kernel image
//! window.
//!
//! **A deliberate deviation:** it describes itself as the IDE disk does, a fixed ATA disk that
//! takes writes, and answers a cache flush as flushed, so a program cannot tell the two apart (a
//! truthful device would report a virtual bus). Writes land in the frames and vanish with the boot,
//! as a QEMU snapshot's do.

use core::ops::Range;

use super::{check_request, BlockDevice, BusType, CacheFlush, DeviceInfo, DeviceKind};
use crate::status::NtStatus;

/// Bytes per sector.
const SECTOR_SIZE: u32 = 512;
/// Bytes per page: one access through [`PhysicalMemory`] never crosses a page boundary.
const PAGE_SIZE: u64 = 4096;

/// Physical memory, read and written a piece at a time, each piece inside one page: the scratch
/// window on the target, a byte buffer in the host tests.
pub trait PhysicalMemory: Sync {
    /// Copy the `out.len()` bytes at physical `address` into `out`.
    fn read(&self, address: u32, out: &mut [u8]);
    /// Copy `bytes` to physical `address`.
    fn write(&self, address: u32, bytes: &[u8]);
}

/// A disk over the physical bytes of a boot module.
pub struct RamDisk<M> {
    memory: M,
    /// The image's first byte's physical address.
    base: u32,
    sectors: u64,
}

impl<M: PhysicalMemory> RamDisk<M> {
    /// A disk over the module bytes `bytes`, through `memory`: its whole sectors (a trailing
    /// partial sector is not the disk's). None when the module holds no whole sector.
    pub fn over(memory: M, bytes: Range<u32>) -> Option<Self> {
        let sectors = u64::from(bytes.end.checked_sub(bytes.start)? / SECTOR_SIZE);
        (sectors != 0).then_some(RamDisk {
            memory,
            base: bytes.start,
            sectors,
        })
    }

    /// The pieces of the run of `len` bytes from sector `lba`, each inside one page: its physical
    /// address and its offset in the caller's buffer, with its length. The run is on the disk
    /// ([`check_request`] has passed), so every address fits in 32 bits.
    fn pieces(&self, lba: u64, len: usize) -> impl Iterator<Item = (u32, Range<usize>)> {
        let start = u64::from(self.base) + lba * u64::from(SECTOR_SIZE);
        let mut offset = 0;
        core::iter::from_fn(move || {
            if offset == len {
                return None;
            }
            let address = start + offset as u64;
            let room = (PAGE_SIZE - address % PAGE_SIZE) as usize;
            let piece = offset..offset + room.min(len - offset);
            offset = piece.end;
            Some((address as u32, piece))
        })
    }
}

impl<M: PhysicalMemory> BlockDevice for RamDisk<M> {
    /// The IDE disk's description (see the module's deviation): a fixed ATA disk, writable.
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            kind: DeviceKind::Disk,
            bus: BusType::Ata,
            sector_size: SECTOR_SIZE,
            sectors: self.sectors,
            removable: false,
            read_only: false,
        }
    }

    /// Copy the run out of the module's frames, a page's piece at a time. A sector lies in one
    /// page when the module starts on a page boundary (Multiboot loaders page-align modules when
    /// asked to, and the boot loader asks), so a one-sector request is one access.
    fn read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        for (address, piece) in self.pieces(lba, buffer.len()) {
            self.memory.read(address, &mut buffer[piece]);
        }
        Ok(())
    }

    /// Copy the run into the module's frames, a page's piece at a time.
    fn write(&self, lba: u64, buffer: &[u8]) -> Result<(), NtStatus> {
        check_request(&self.info(), lba, buffer)?;
        for (address, piece) in self.pieces(lba, buffer.len()) {
            self.memory.write(address, &buffer[piece]);
        }
        Ok(())
    }

    /// Nothing is held back: every write is in the frames when it returns. Answers flushed, as the
    /// IDE disk it stands in for does (see the module's deviation).
    fn flush_cache(&self) -> Result<CacheFlush, NtStatus> {
        Ok(CacheFlush::Flushed)
    }
}

// --- The boot's RAM disk (target) ---------------------------------------------------------------

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::sync::InitOnce;

    /// Physical memory through the scratch window: each piece copied under the memory manager's
    /// database, the window pointed at the piece's frame.
    pub struct ScratchMemory;

    impl PhysicalMemory for ScratchMemory {
        fn read(&self, address: u32, out: &mut [u8]) {
            let offset = (address % PAGE_SIZE as u32) as usize;
            crate::mem::paging::read_frame(address - offset as u32, offset, out);
        }

        fn write(&self, address: u32, bytes: &[u8]) {
            let offset = (address % PAGE_SIZE as u32) as usize;
            crate::mem::paging::write_frame(address - offset as u32, offset, bytes);
        }
    }

    /// The boot's RAM disk: none when the boot loader loaded no disk module.
    static RAM_DISK: InitOnce<Option<RamDisk<ScratchMemory>>> = InitOnce::new();

    /// Make the RAM disk over the disk module the boot memory plan withheld, if there is one, and
    /// report it on COM1. Boot context, once, after the frame database and the scratch window are
    /// in place.
    pub fn init() {
        let disk = crate::mem::bootmem::disk_module().and_then(|bytes| {
            let start = bytes.start;
            let disk = RamDisk::over(ScratchMemory, bytes)?;
            crate::serial_println!(
                "F2K: ram disk: {} sectors from the boot module at {:#010x}",
                disk.sectors,
                start
            );
            Some(disk)
        });
        RAM_DISK.set(disk);
    }

    /// The RAM disk as a block device, if the boot has one.
    pub fn block_device() -> Option<&'static dyn BlockDevice> {
        RAM_DISK
            .get()
            .as_ref()
            .map(|disk| disk as &'static dyn BlockDevice)
    }
}

#[cfg(target_arch = "x86")]
pub use target::{block_device, init};

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::status::STATUS_INVALID_PARAMETER;

    /// Physical memory as a byte buffer from physical `base`, which counts its accesses and refuses
    /// one that crosses a page boundary or leaves the buffer.
    struct Frames {
        base: u32,
        bytes: Mutex<Vec<u8>>,
        accesses: Mutex<Vec<(u32, usize)>>,
    }

    impl Frames {
        /// `len` bytes from `base`, each byte a function of its address.
        fn patterned(base: u32, len: usize) -> Self {
            Frames {
                base,
                bytes: Mutex::new((0..len).map(|index| pattern(base + index as u32)).collect()),
                accesses: Mutex::new(Vec::new()),
            }
        }

        /// The buffer's range for an access of `len` bytes at `address`, checked and counted.
        fn access(&self, address: u32, len: usize) -> Range<usize> {
            assert!(len != 0, "an empty access");
            assert_eq!(
                address as u64 / PAGE_SIZE,
                (address as u64 + len as u64 - 1) / PAGE_SIZE,
                "the access at {address:#x} (+{len:#x}) crosses a page boundary"
            );
            self.accesses.lock().unwrap().push((address, len));
            let start = (address - self.base) as usize;
            start..start + len
        }

        fn accesses(&self) -> Vec<(u32, usize)> {
            core::mem::take(&mut self.accesses.lock().unwrap())
        }
    }

    impl PhysicalMemory for &'static Frames {
        fn read(&self, address: u32, out: &mut [u8]) {
            let range = self.access(address, out.len());
            out.copy_from_slice(&self.bytes.lock().unwrap()[range]);
        }

        fn write(&self, address: u32, bytes: &[u8]) {
            let range = self.access(address, bytes.len());
            self.bytes.lock().unwrap()[range].copy_from_slice(bytes);
        }
    }

    /// A physical byte's value in the patterned frames.
    fn pattern(address: u32) -> u8 {
        (address ^ address >> 9 ^ address >> 17) as u8
    }

    fn frames(base: u32, len: usize) -> &'static Frames {
        Box::leak(Box::new(Frames::patterned(base, len)))
    }

    /// The disk is the module's whole sectors; a trailing partial sector is not the disk's, and a
    /// module without a whole sector is no disk. It describes itself as the IDE disk.
    #[test]
    fn the_disk_is_the_modules_whole_sectors() {
        let memory = frames(0x40_0000, 0x3000);
        let disk = RamDisk::over(memory, 0x40_0000..0x40_2A00).unwrap();
        assert_eq!(
            disk.info(),
            DeviceInfo {
                kind: DeviceKind::Disk,
                bus: BusType::Ata,
                sector_size: 512,
                sectors: 21,
                removable: false,
                read_only: false,
            }
        );
        assert!(RamDisk::over(memory, 0x40_0000..0x40_01FF).is_none());
        assert!(RamDisk::over(memory, 0x40_0200..0x40_0000).is_none());
        assert_eq!(disk.flush_cache(), Ok(CacheFlush::Flushed));
    }

    /// A read returns the module's bytes at the run's offset; on a page-aligned module each sector
    /// is one access, and a run across pages is split at their boundaries.
    #[test]
    fn a_read_copies_the_run_a_page_at_a_time() {
        let base = 0x80_0000;
        let memory = frames(base, 0x4000);
        let disk = RamDisk::over(memory, base..base + 0x4000).unwrap();
        let mut sector = [0u8; 512];
        assert_eq!(disk.read(9, &mut sector), Ok(()));
        let expected: Vec<u8> = (0..512).map(|i| pattern(base + 9 * 512 + i)).collect();
        assert_eq!(sector.to_vec(), expected);
        assert_eq!(memory.accesses(), [(base + 9 * 512, 512)]);

        let mut run = vec![0u8; 12 * 512];
        assert_eq!(disk.read(4, &mut run), Ok(()));
        let expected: Vec<u8> = (0..12 * 512).map(|i| pattern(base + 4 * 512 + i)).collect();
        assert_eq!(run, expected);
        assert_eq!(
            memory.accesses(),
            [(base + 4 * 512, 4 * 512), (base + 0x1000, 0x1000)]
        );
    }

    /// A module that starts inside a page is read across the page boundaries all the same, every
    /// access inside one page.
    #[test]
    fn an_unaligned_module_is_split_at_page_boundaries() {
        let base = 0x80_0100;
        let memory = frames(base, 0x3000);
        let disk = RamDisk::over(memory, base..base + 0x3000).unwrap();
        let mut run = vec![0u8; 16 * 512];
        assert_eq!(disk.read(3, &mut run), Ok(()));
        let expected: Vec<u8> = (0..16 * 512).map(|i| pattern(base + 3 * 512 + i)).collect();
        assert_eq!(run, expected);
        // From 0x800700: the rest of its page, a whole page, and the run's last 0x700 bytes.
        assert_eq!(
            memory.accesses(),
            [(0x80_0700, 0x900), (0x80_1000, 0x1000), (0x80_2000, 0x700)]
        );
    }

    /// A write lands in the frames and reads back; the frames around it are untouched.
    #[test]
    fn a_write_lands_in_the_frames() {
        let base = 0x100_0000;
        let memory = frames(base, 0x2000);
        let disk = RamDisk::over(memory, base..base + 0x2000).unwrap();
        let data: Vec<u8> = (0..3 * 512).map(|i| (i * 7) as u8).collect();
        assert_eq!(disk.write(6, &data), Ok(()));
        assert_eq!(
            memory.accesses(),
            [(base + 6 * 512, 2 * 512), (base + 0x1000, 512)]
        );
        let mut back = vec![0u8; 3 * 512];
        assert_eq!(disk.read(6, &mut back), Ok(()));
        assert_eq!(back, data);
        let mut before = [0u8; 512];
        assert_eq!(disk.read(5, &mut before), Ok(()));
        let expected: Vec<u8> = (0..512).map(|i| pattern(base + 5 * 512 + i)).collect();
        assert_eq!(before.to_vec(), expected);
        let mut after = [0u8; 512];
        assert_eq!(disk.read(9, &mut after), Ok(()));
        let expected: Vec<u8> = (0..512).map(|i| pattern(base + 9 * 512 + i)).collect();
        assert_eq!(after.to_vec(), expected);
    }

    /// A run that leaves the disk is refused before any access, a read's buffer and the frames
    /// untouched.
    #[test]
    fn a_run_off_the_disk_is_refused_untouched() {
        let base = 0x40_0000;
        let memory = frames(base, 0x2000);
        let disk = RamDisk::over(memory, base..base + 0x2000).unwrap();
        let mut buffer = vec![0xAAu8; 2 * 512];
        assert_eq!(disk.read(15, &mut buffer), Err(STATUS_INVALID_PARAMETER));
        assert!(buffer.iter().all(|&byte| byte == 0xAA));
        assert_eq!(disk.write(15, &buffer), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(disk.write(u64::MAX, &buffer), Err(STATUS_INVALID_PARAMETER));
        assert!(memory.accesses().is_empty());
        assert_eq!(disk.read(14, &mut buffer), Ok(()), "the last two sectors");
    }

    /// The disk carries a partition table the registry walks like the IDE disk's.
    #[test]
    fn the_registry_scans_it_like_a_disk() {
        use crate::block::partition::mbr;
        use crate::block::registry::{scan, Registry, Scan};

        let base = 0x200_0000;
        let memory = frames(base, 64 * 512);
        let disk: &'static RamDisk<&'static Frames> = Box::leak(Box::new(
            RamDisk::over(memory, base..base + 64 * 512).unwrap(),
        ));
        assert_eq!(disk.write(0, &mbr(&[(0, 0x80, 0x0C, 8, 40)])), Ok(()));
        let mut registry = Registry::new();
        let (_, result) = scan(&mut registry, disk);
        assert_eq!(result, Scan::Partitions(1));
    }
}
