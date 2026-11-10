//! Multiboot 1 boot-time memory information.
//!
//! Two layers:
//! - pure, host-testable logic: the information structure's fields, the boot memory plan (which
//!   memory picture applies, which frames it releases, whether the trampoline's run is free), the
//!   memory-map record stream turned into usable frame ranges, and the module list (the disk image
//!   a boot loader loaded beside the kernel, [`DISK_MODULE`]);
//! - the loader-provided structures, read by the kernel from the physical address passed in EBX,
//!   each read bounded by the boot identity window before it is made ([`readable_len`]).
//!
//! Every value the loader provides is read from byte slices with explicit little-endian reads: the
//! records are packed, unaligned and variable-size, and the information structure may be cut short
//! by the window, its missing fields then reading as absent.

use core::mem::offset_of;
use core::ops::Range;

use super::frame::FrameId;

/// Multiboot information structure flags.
pub mod flags {
    /// `mem_lower` / `mem_upper` are valid.
    pub const MEM_INFO: u32 = 1 << 0;
    /// `cmdline` is valid.
    pub const CMDLINE: u32 = 1 << 2;
    /// `mods_count` / `mods_addr` are valid.
    pub const MODS: u32 = 1 << 3;
    /// `mmap_length` / `mmap_addr` are valid.
    pub const MMAP: u32 = 1 << 6;
}

/// The memory-map lengths kept: a map buffer this long or longer is not taken as one (the
/// specification sets no bound; a loader's map is a few dozen records of 24 bytes).
pub const MAP_LENGTH_LIMIT: usize = 0x10_0000;

/// Memory-map record type: usable RAM.
pub const MEMORY_AVAILABLE: u32 = 1;

/// The module records kept: a list claiming more is read only this far (a loader's list is a few
/// records).
pub const MODULE_LIMIT: u32 = 64;

/// The bytes of a module's command line read: a longer one is cut here (a disk module's is its
/// path and its name).
pub const MODULE_COMMAND_LINE_LIMIT: usize = 256;

/// The name the disk image's module carries as a word of its command line: QEMU's `-initrd "<path>
/// f2k-disk"`, GRUB's `module <path> f2k-disk`, Limine's `module_cmdline: f2k-disk`.
pub const DISK_MODULE: &[u8] = b"f2k-disk";

/// Smallest well-formed memory-map record payload: `size` (4 bytes, excluded from itself), base
/// (8), length (8), type (4).
const MIN_RECORD_PAYLOAD: u32 = 20;

/// The Multiboot 1 information structure the loader points EBX at. Only the fields F2K reads are
/// listed; offsets are part of the Multiboot 1 contract. The boot reads it as bytes
/// ([`InfoBytes`]), at these fields' offsets.
#[repr(C)]
#[derive(Default)]
pub struct MultibootInfo {
    pub flags: u32,
    /// KiB of usable memory below 1 MiB.
    pub mem_lower: u32,
    /// KiB of usable memory above 1 MiB.
    pub mem_upper: u32,
    pub boot_device: u32,
    pub cmdline: u32,
    pub mods_count: u32,
    pub mods_addr: u32,
    pub syms0: u32,
    pub syms1: u32,
    pub syms2: u32,
    pub syms3: u32,
    /// Length in bytes of the memory-map record stream at `mmap_addr`.
    pub mmap_length: u32,
    /// Physical address of the memory-map record stream.
    pub mmap_addr: u32,
}

/// One record of the module list at `mods_addr` (Multiboot 1's module structure): the module's
/// bytes are physical `[start, end)`, its command line the NUL-terminated string at `string`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Module {
    pub start: u32,
    pub end: u32,
    pub string: u32,
    pub reserved: u32,
}

/// A module record's size.
pub const MODULE_RECORD: usize = core::mem::size_of::<Module>();

impl Module {
    /// The module's bytes, physical; none when it holds none.
    pub fn bytes(&self) -> Option<Range<u32>> {
        (self.start < self.end).then_some(self.start..self.end)
    }

    /// The frames holding any byte of the module.
    pub fn frames(&self) -> Range<FrameId> {
        self.start / 4096..self.end.div_ceil(4096)
    }
}

/// The records of the module list `list` (its bytes, `mods_count` records long or cut short), in
/// order; a partial record at the end is none.
pub fn module_records(list: &[u8]) -> impl Iterator<Item = Module> + '_ {
    list.chunks_exact(MODULE_RECORD).map(|record| Module {
        start: read_u32(record, offset_of!(Module, start)).unwrap_or(0),
        end: read_u32(record, offset_of!(Module, end)).unwrap_or(0),
        string: read_u32(record, offset_of!(Module, string)).unwrap_or(0),
        reserved: read_u32(record, offset_of!(Module, reserved)).unwrap_or(0),
    })
}

/// Whether the module command line `line` (its bytes up to its NUL, or all of them) holds `name`
/// as a whitespace-separated word.
pub fn names(line: &[u8], name: &[u8]) -> bool {
    let line = line.split(|&byte| byte == 0).next().unwrap_or(&[]);
    line.split(u8::is_ascii_whitespace).any(|word| word == name)
}

/// A validated run of usable frames: `first`, `first + 1`, ..., `first + count - 1`, where every
/// frame is 4 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsableRange {
    pub first: FrameId,
    pub count: u32,
}

impl UsableRange {
    /// Iterate the frame numbers of this range.
    pub fn frames(&self) -> impl Iterator<Item = FrameId> {
        self.first..self.first + self.count
    }

    /// Whether `frame` is one of this range's.
    pub fn holds(&self, frame: FrameId) -> bool {
        frame >= self.first && frame - self.first < self.count
    }
}

/// How many bytes of `[addr, addr + len)` lie inside the window `[0, window_end)`, counted from
/// `addr`: `len` cut at the window's end, none when `addr` lies outside it. Every read of loader
/// memory is this long and no longer.
pub fn readable_len(addr: u32, len: usize, window_end: u64) -> usize {
    let room = window_end.saturating_sub(u64::from(addr));
    (len as u64).min(room) as usize
}

/// The bytes of the information structure that could be read (see [`readable_len`]): a field they
/// do not wholly hold reads as absent, and so does one whose flag is clear.
#[derive(Clone, Copy)]
pub struct InfoBytes<'a>(pub &'a [u8]);

impl InfoBytes<'_> {
    fn field(self, offset: usize) -> Option<u32> {
        read_u32(self.0, offset)
    }

    /// The flags; none set when the bytes do not hold them.
    pub fn flags(self) -> u32 {
        self.field(offset_of!(MultibootInfo, flags)).unwrap_or(0)
    }

    /// The field at `offset`, when `flag` says it is valid.
    fn flagged(self, flag: u32, offset: usize) -> Option<u32> {
        if self.flags() & flag == 0 {
            return None;
        }
        self.field(offset)
    }

    /// `mem_upper`: KiB of usable memory from 1 MiB on.
    pub fn mem_upper(self) -> Option<u32> {
        self.flagged(flags::MEM_INFO, offset_of!(MultibootInfo, mem_upper))
    }

    /// `cmdline`: the command line's physical address.
    pub fn cmdline(self) -> Option<u32> {
        self.flagged(flags::CMDLINE, offset_of!(MultibootInfo, cmdline))
    }

    /// The module list's `(mods_addr, mods_count)`, as the structure states them.
    pub fn modules(self) -> Option<(u32, u32)> {
        let addr = self.flagged(flags::MODS, offset_of!(MultibootInfo, mods_addr))?;
        let count = self.flagged(flags::MODS, offset_of!(MultibootInfo, mods_count))?;
        Some((addr, count))
    }

    /// The memory map's `(mmap_addr, mmap_length)`, as the structure states them.
    pub fn mmap(self) -> Option<(u32, u32)> {
        let addr = self.flagged(flags::MMAP, offset_of!(MultibootInfo, mmap_addr))?;
        let len = self.flagged(flags::MMAP, offset_of!(MultibootInfo, mmap_length))?;
        Some((addr, len))
    }
}

/// The memory picture a boot takes, from the information structure alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemorySource {
    /// The memory map, wholly inside the window: `len` bytes at `addr`.
    Map { addr: u32, len: usize },
    /// No usable map: `kib` KiB of memory from 1 MiB on (`mem_upper`).
    UpperMemory { kib: u32 },
}

/// The memory picture the information structure offers, every value bounded before it is trusted:
/// the map when its flag is set and its buffer is non-empty, at a non-zero address, shorter than
/// [`MAP_LENGTH_LIMIT`] and wholly inside the window `[0, window_end)`; otherwise the `mem_upper`
/// hint when its flag is set and it is non-zero; otherwise none. A map that crosses the window's
/// end is refused whole rather than cut: a reservation record past the cut could cover a frame an
/// earlier available record lists.
pub fn memory_source(info: InfoBytes, window_end: u64) -> Option<MemorySource> {
    if let Some((addr, len)) = info.mmap() {
        let len = len as usize;
        if addr != 0
            && len != 0
            && len < MAP_LENGTH_LIMIT
            && readable_len(addr, len, window_end) == len
        {
            return Some(MemorySource::Map { addr, len });
        }
    }
    match info.mem_upper() {
        Some(kib) if kib != 0 => Some(MemorySource::UpperMemory { kib }),
        _ => None,
    }
}

/// What the boot does with physical memory: which frames it releases to the frame database and
/// whether the real-mode trampoline's run can be reserved, decided from the loader's structures
/// alone ([`memory_source`], then [`BootMemoryPlan::new`] over the map's bytes).
pub struct BootMemoryPlan<'a> {
    /// The memory map's bytes; none when the `mem_upper` fallback applies.
    map: Option<&'a [u8]>,
    /// The fallback's one region from 1 MiB on; none with a map (or a hint too small to hold a
    /// frame).
    upper: Option<UsableRange>,
    /// The frames the kernel image occupies.
    kernel: Range<FrameId>,
    /// The frames a boot module occupies (the disk image's), none by default.
    module: Range<FrameId>,
    /// The frame table's capacity.
    max_frames: usize,
}

impl<'a> BootMemoryPlan<'a> {
    /// The plan for the memory picture `source` ([`memory_source`]), whose map's bytes, when it
    /// names one, are `map` (the `len` bytes at its `addr`; ignored under the fallback). The kernel
    /// image's frames `kernel` are never released, nor any frame at or past `max_frames`.
    pub fn new(
        source: MemorySource,
        map: &'a [u8],
        kernel: Range<FrameId>,
        max_frames: usize,
    ) -> Self {
        let (map, upper) = match source {
            MemorySource::Map { .. } => (Some(map), None),
            // No memory map: usable memory is one region starting at 1 MiB.
            MemorySource::UpperMemory { kib } => (
                None,
                usable_frames_in(0x10_0000, u64::from(kib) * 1024, max_frames),
            ),
        };
        BootMemoryPlan {
            map,
            upper,
            kernel,
            module: 0..0,
            max_frames,
        }
    }

    /// The plan, its frames `module` (a boot module's, which the kernel keeps reading) withheld as
    /// the kernel image's are: never released.
    pub fn withholding(self, module: Range<FrameId>) -> Self {
        BootMemoryPlan { module, ..self }
    }

    /// Whether the plan follows the memory map (rather than the `mem_upper` fallback).
    pub fn uses_map(&self) -> bool {
        self.map.is_some()
    }

    /// The usable frame ranges, in the map's record order (the fallback's one region otherwise).
    /// Ranges may overlap each other: each frame is released once, by the first.
    pub fn ranges(&self) -> impl Iterator<Item = UsableRange> + '_ {
        usable_ranges(self.map.unwrap_or(&[]), self.max_frames).chain(self.upper)
    }

    /// Whether a frame of a usable range is released: not the kernel image's nor the withheld
    /// module's, and not covered by a reservation record.
    pub fn releases(&self, frame: FrameId) -> bool {
        !self.kernel.contains(&frame)
            && !self.module.contains(&frame)
            && !self.map.is_some_and(|map| frame_is_reserved(map, frame))
    }

    /// Whether every frame of `run` is released, so the run can be taken out of the free lists
    /// whole. Under the fallback no run is: it vouches for no frame below 1 MiB.
    pub fn reserves(&self, mut run: Range<FrameId>) -> bool {
        self.uses_map()
            && run.all(|frame| self.releases(frame) && self.ranges().any(|r| r.holds(frame)))
    }
}

fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let b = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    Some(read_u32(buf, off)? as u64 | (read_u32(buf, off + 4)? as u64) << 32)
}

/// Convert one available region (byte granularity) into usable frames.
///
/// The base is rounded up to 4 KiB; the end is rounded down and clamped to the frame table's
/// capacity. Frame 0 (the real-mode interrupt vector area) is never handed out. Returns `None` for
/// regions that hold no whole usable frame.
pub fn usable_frames_in(base: u64, len: u64, max_frames: usize) -> Option<UsableRange> {
    if len == 0 {
        return None;
    }
    let end = base.checked_add(len)?;
    let end = end.min(max_frames as u64 * 4096);
    let base_up = base.checked_add(4095)? & !4095u64;
    if end <= base_up {
        return None;
    }
    let mut first = (base_up / 4096) as FrameId;
    let mut count = ((end - base_up) / 4096) as u32;
    if first == 0 {
        // Frame 0 holds the IVT and BIOS data area; keep it.
        first = 1;
        count = count.saturating_sub(1);
    }
    if count == 0 {
        return None;
    }
    Some(UsableRange { first, count })
}

/// Iterator over the records of a memory-map record stream: (base, length, type) per record, in
/// record order. Stops at the first malformed or truncated record rather than guessing.
pub struct Records<'a> {
    buf: &'a [u8],
    off: usize,
}

/// The records of the memory-map record stream at `MultibootInfo::mmap_addr`.
pub fn records(map: &[u8]) -> Records<'_> {
    Records { buf: map, off: 0 }
}

impl<'a> Iterator for Records<'a> {
    type Item = (u64, u64, u32);

    fn next(&mut self) -> Option<(u64, u64, u32)> {
        let size = read_u32(self.buf, self.off)?;
        // Malformed or truncated record: stop rather than guess.
        if size < MIN_RECORD_PAYLOAD {
            return None;
        }
        let entry_end = self.off.checked_add(4 + size as usize)?;
        if entry_end > self.buf.len() {
            return None;
        }
        let base = read_u64(self.buf, self.off + 4)?;
        let len = read_u64(self.buf, self.off + 12)?;
        let kind = read_u32(self.buf, self.off + 20)?;
        self.off = entry_end;
        Some((base, len, kind))
    }
}

/// Parse the memory-map record stream (the buffer at `MultibootInfo::mmap_addr`) and yield the
/// usable frame ranges of every available region, in record order. Ranges may overlap each other
/// or a reserved record: firmware maps do both. [`frame_is_reserved`] answers the second; the
/// caller's frame database answers the first.
pub fn usable_ranges(map: &[u8], max_frames: usize) -> impl Iterator<Item = UsableRange> + '_ {
    records(map)
        .filter(|&(_, _, kind)| kind == MEMORY_AVAILABLE)
        .filter_map(move |(base, len, _)| usable_frames_in(base, len, max_frames))
}

/// Whether any record that is not available RAM covers any byte of `frame`. A frame an available
/// record also lists is still not free to use: the reservation wins.
pub fn frame_is_reserved(map: &[u8], frame: FrameId) -> bool {
    let start = frame as u64 * 4096;
    let end = start + 4096;
    records(map).any(|(base, len, kind)| {
        kind != MEMORY_AVAILABLE && len != 0 && base < end && base.saturating_add(len) > start
    })
}

/// The structure's bytes, as a loader lays them out: the host tests' loader memory.
#[cfg(test)]
impl MultibootInfo {
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let fields = [
            self.flags,
            self.mem_lower,
            self.mem_upper,
            self.boot_device,
            self.cmdline,
            self.mods_count,
            self.mods_addr,
            self.syms0,
            self.syms1,
            self.syms2,
            self.syms3,
            self.mmap_length,
            self.mmap_addr,
        ];
        let bytes: Vec<u8> = fields
            .iter()
            .flat_map(|field| field.to_le_bytes())
            .collect();
        assert_eq!(bytes.len(), core::mem::size_of::<MultibootInfo>());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::frame::MAX_FRAMES;

    /// The host tests' boot identity window: physical memory `[0, WINDOW)`, as one buffer.
    const WINDOW: usize = 0x4000;

    /// The kernel image's frames, as the boot's plan sees them.
    const KERNEL: Range<FrameId> = 0x100..0x200;

    /// Loader memory: the window's bytes, with `bytes` placed at each `(address, bytes)`.
    fn memory(placed: &[(u32, &[u8])]) -> Vec<u8> {
        let mut memory = vec![0u8; WINDOW];
        for &(addr, bytes) in placed {
            memory[addr as usize..][..bytes.len()].copy_from_slice(bytes);
        }
        memory
    }

    /// `[addr, addr + len)` of `memory`, cut at the window's end as the boot cuts its reads: a
    /// read past the buffer would panic here.
    fn read(memory: &[u8], addr: u32, len: usize) -> &[u8] {
        let len = readable_len(addr, len, memory.len() as u64);
        if len == 0 {
            return &[];
        }
        &memory[addr as usize..][..len]
    }

    /// What the boot does with the information structure at `info_addr` in `memory`: its two reads,
    /// each cut at the window, and the plan over them.
    fn plan_in(memory: &[u8], info_addr: u32) -> Option<BootMemoryPlan<'_>> {
        let info = read(memory, info_addr, core::mem::size_of::<MultibootInfo>());
        let source = memory_source(InfoBytes(info), memory.len() as u64)?;
        let map = match source {
            MemorySource::Map { addr, len } => {
                let map = read(memory, addr, len);
                assert_eq!(map.len(), len, "a map the source vouches for is read whole");
                map
            }
            MemorySource::UpperMemory { .. } => &[],
        };
        Some(BootMemoryPlan::new(source, map, KERNEL, MAX_FRAMES))
    }

    /// An information structure offering a map of `len` bytes at `addr` and a `mem_upper` hint of
    /// `kib` KiB.
    fn info_with_map(addr: u32, len: u32, kib: u32) -> Vec<u8> {
        MultibootInfo {
            flags: flags::MMAP | flags::MEM_INFO,
            mem_upper: kib,
            mmap_addr: addr,
            mmap_length: len,
            ..MultibootInfo::default()
        }
        .to_bytes()
    }

    /// The fallback's one region: `kib` KiB from 1 MiB on.
    fn upper_region(kib: u32) -> Vec<UsableRange> {
        vec![UsableRange {
            first: 0x100,
            count: kib / 4,
        }]
    }

    /// A map that fits the window is followed: its available records become the plan's ranges.
    #[test]
    fn a_sound_map_is_followed() {
        let map = [
            record(0, 0x9_FC00, MEMORY_AVAILABLE),
            record(0x10_0000, 0x10_0000, MEMORY_AVAILABLE),
        ]
        .concat();
        let memory = memory(&[
            (0x100, &info_with_map(0x200, map.len() as u32, 4096)),
            (0x200, &map),
        ]);
        let plan = plan_in(&memory, 0x100).unwrap();
        assert!(plan.uses_map());
        assert_eq!(
            plan.ranges().collect::<Vec<_>>(),
            [
                UsableRange {
                    first: 1,
                    count: 158
                },
                UsableRange {
                    first: 0x100,
                    count: 0x100
                }
            ]
        );
    }

    /// A record whose size runs past the map's buffer ends the walk: the records before it count,
    /// nothing past the buffer is read.
    #[test]
    fn a_record_crossing_the_buffer_end_stops_the_walk() {
        let mut map = record(0x10_0000, 0x1000, MEMORY_AVAILABLE);
        map.extend_from_slice(&60u32.to_le_bytes()); // claims 60 bytes, holds 20
        map.extend_from_slice(&record(0x20_0000, 0x1000, MEMORY_AVAILABLE)[4..]);
        let memory = memory(&[
            (0x100, &info_with_map(0x200, map.len() as u32, 0)),
            (0x200, &map),
        ]);
        let plan = plan_in(&memory, 0x100).unwrap();
        assert_eq!(
            plan.ranges().collect::<Vec<_>>(),
            [UsableRange {
                first: 0x100,
                count: 1
            }]
        );
    }

    /// A payload below the 20-byte minimum ends the walk at that record.
    #[test]
    fn a_short_payload_stops_the_walk() {
        let mut map = record(0x10_0000, 0x1000, MEMORY_AVAILABLE);
        map.extend_from_slice(&16u32.to_le_bytes());
        map.extend_from_slice(&record(0x20_0000, 0x1000, MEMORY_AVAILABLE)[4..]);
        map.extend(record(0x30_0000, 0x1000, MEMORY_AVAILABLE));
        assert_eq!(records(&map).count(), 1);
        assert_eq!(usable_ranges(&map, MAX_FRAMES).count(), 1);
    }

    /// Base/length pairs at the top of the 64-bit space: no overflow, no wrap to frame 0, and a
    /// reservation there covers nothing low.
    #[test]
    fn records_at_the_top_of_the_address_space_wrap_to_nothing() {
        let map = [
            record(0xFFFF_FFFF_FFFF_F000, 0x1000, MEMORY_AVAILABLE), // ends at exactly 2^64
            record(0xFFFF_FFFF_FFFF_0000, 0x2_0000, MEMORY_AVAILABLE), // would wrap to 0x10000
            record(0x1000, u64::MAX, MEMORY_AVAILABLE),              // would wrap to 0xFFF
            record(u64::MAX - 10, 100, 2),                           // reserved, would wrap
        ]
        .concat();
        assert_eq!(records(&map).count(), 4);
        assert_eq!(usable_ranges(&map, MAX_FRAMES).count(), 0);
        for frame in 0..0x20 {
            assert!(!frame_is_reserved(&map, frame), "frame {frame:#x}");
        }
    }

    /// A map outside the window, or one crossing its end, is no map: the `mem_upper` fallback
    /// applies, and the map's bytes are never read.
    #[test]
    fn a_map_outside_the_window_takes_the_fallback() {
        let map = record(0x10_0000, 0x1000, MEMORY_AVAILABLE);
        for (addr, len) in [
            (WINDOW as u32, map.len() as u32),     // starts at the window's end
            (0x8000_0000, map.len() as u32),       // far outside
            (WINDOW as u32 - 8, map.len() as u32), // crosses the end
            (0x200, u32::MAX),                     // crosses it by far
            (u32::MAX - 3, map.len() as u32),      // wraps the 32-bit space
            (0x200, MAP_LENGTH_LIMIT as u32),      // oversized
        ] {
            let memory = memory(&[(0x100, &info_with_map(addr, len, 1024)), (0x200, &map)]);
            let plan = plan_in(&memory, 0x100).unwrap();
            assert!(!plan.uses_map(), "map at {addr:#x} (+{len:#x})");
            assert_eq!(plan.ranges().collect::<Vec<_>>(), upper_region(1024));
        }
        // Oversized in a window that would hold it.
        let info = info_with_map(0x200, MAP_LENGTH_LIMIT as u32, 1024);
        assert_eq!(
            memory_source(InfoBytes(&info), 1 << 32),
            Some(MemorySource::UpperMemory { kib: 1024 })
        );
        let info = info_with_map(0x200, MAP_LENGTH_LIMIT as u32 - 1, 1024);
        assert_eq!(
            memory_source(InfoBytes(&info), 1 << 32),
            Some(MemorySource::Map {
                addr: 0x200,
                len: MAP_LENGTH_LIMIT - 1
            })
        );
    }

    /// Flags claiming a map at address 0, or of length 0: no map.
    #[test]
    fn an_empty_map_claim_takes_the_fallback() {
        for (addr, len) in [(0, 24), (0x200, 0), (0, 0)] {
            let memory = memory(&[(0x100, &info_with_map(addr, len, 2048))]);
            let plan = plan_in(&memory, 0x100).unwrap();
            assert!(!plan.uses_map());
            assert_eq!(plan.ranges().collect::<Vec<_>>(), upper_region(2048));
        }
    }

    /// No sound map and no usable hint: no memory information at all, which the boot refuses.
    #[test]
    fn without_any_memory_information_there_is_no_plan() {
        let only_bad_map = MultibootInfo {
            flags: flags::MMAP | flags::MEM_INFO,
            mmap_addr: 0x8000_0000,
            mmap_length: 24,
            mem_upper: 0,
            ..MultibootInfo::default()
        };
        let hint_unflagged = MultibootInfo {
            mem_upper: 4096,
            ..MultibootInfo::default()
        };
        for info in [only_bad_map, hint_unflagged, MultibootInfo::default()] {
            let memory = memory(&[(0x100, &info.to_bytes())]);
            assert!(plan_in(&memory, 0x100).is_none());
        }
        // The structure itself outside the window: nothing is read, no plan.
        assert!(plan_in(&memory(&[]), WINDOW as u32).is_none());
        assert!(plan_in(&memory(&[]), u32::MAX).is_none());
    }

    /// A structure the window cuts short: the fields it holds count, the rest read as absent.
    #[test]
    fn fields_past_the_window_read_as_absent() {
        let info = info_with_map(0x200, 24, 1024);
        let at = WINDOW - 12; // flags, mem_lower and mem_upper fit
        let memory = memory(&[(at as u32, &info[..12])]);
        let bytes = InfoBytes(read(&memory, at as u32, info.len()));
        assert_eq!(bytes.0.len(), 12);
        assert_eq!(bytes.mem_upper(), Some(1024));
        assert_eq!(bytes.mmap(), None);
        assert_eq!(bytes.cmdline(), None);
        let plan = plan_in(&memory, at as u32).unwrap();
        assert!(!plan.uses_map());
        assert_eq!(plan.ranges().collect::<Vec<_>>(), upper_region(1024));
    }

    /// Reads are cut at the window's end and never wrap.
    #[test]
    fn reads_are_cut_at_the_window() {
        assert_eq!(readable_len(0x100, 0x20, 0x4000), 0x20);
        assert_eq!(readable_len(0x3FF0, 0x20, 0x4000), 0x10);
        assert_eq!(readable_len(0x4000, 0x20, 0x4000), 0);
        assert_eq!(readable_len(u32::MAX, usize::MAX, 0x4000), 0);
        assert_eq!(readable_len(0, usize::MAX, 0x4000), 0x4000);
    }

    /// The plan withholds the kernel image's frames and the reserved ones.
    #[test]
    fn the_plan_withholds_the_kernel_and_reservations() {
        let map = [
            record(0, 0x80_0000, MEMORY_AVAILABLE),
            record(0x30_0000, 0x1000, 2),
        ]
        .concat();
        let memory = memory(&[
            (0x100, &info_with_map(0x200, map.len() as u32, 0)),
            (0x200, &map),
        ]);
        let plan = plan_in(&memory, 0x100).unwrap();
        assert!(plan.releases(0xFF));
        assert!(!plan.releases(0x100) && !plan.releases(0x1FF));
        assert!(plan.releases(0x200));
        assert!(!plan.releases(0x300));
        assert!(plan.releases(0x301));
    }

    /// A withheld module's frames are kept as the kernel's are, every frame holding any of its
    /// bytes; the frames around it are released, and a run over it is not reservable.
    #[test]
    fn the_plan_withholds_the_module() {
        let map = record(0, 0x80_0000, MEMORY_AVAILABLE);
        let memory = memory(&[
            (0x100, &info_with_map(0x200, map.len() as u32, 0)),
            (0x200, &map),
        ]);
        let module = Module {
            start: 0x40_0800,
            end: 0x50_0001,
            ..Module::default()
        };
        assert_eq!(module.frames(), 0x400..0x501);
        let plan = plan_in(&memory, 0x100)
            .unwrap()
            .withholding(module.frames());
        assert!(plan.releases(0x3FF));
        assert!(!plan.releases(0x400) && !plan.releases(0x500));
        assert!(plan.releases(0x501));
        assert!(!plan.reserves(0x3FF..0x401));
        assert!(!plan.releases(0x100), "the kernel's are still withheld");
    }

    /// The module list's records, in order: a partial record at the end is none, and an empty
    /// module holds no bytes.
    #[test]
    fn the_module_list_is_read_record_by_record() {
        let list: Vec<u8> = [
            [0x40_0000u32, 0x80_0000, 0x1234, 0],
            [0x90_0000, 0x90_0000, 0x5678, 0],
        ]
        .iter()
        .flatten()
        .flat_map(|field| field.to_le_bytes())
        .chain([1, 2, 3])
        .collect();
        let modules: Vec<Module> = module_records(&list).collect();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].bytes(), Some(0x40_0000..0x80_0000));
        assert_eq!(modules[0].string, 0x1234);
        assert_eq!(modules[1].bytes(), None);
        assert_eq!(MODULE_RECORD, 16);
    }

    /// The module list is offered only when its flag is set.
    #[test]
    fn the_module_list_needs_its_flag() {
        let mut info = MultibootInfo {
            mods_count: 1,
            mods_addr: 0x9000,
            ..MultibootInfo::default()
        };
        assert_eq!(InfoBytes(&info.to_bytes()).modules(), None);
        info.flags = flags::MODS;
        assert_eq!(InfoBytes(&info.to_bytes()).modules(), Some((0x9000, 1)));
        assert_eq!(
            InfoBytes(&info.to_bytes()[..24]).modules(),
            None,
            "cut short"
        );
    }

    /// The disk module is named by a word of its command line, up to its NUL: QEMU's path and name,
    /// Limine's name alone; a word that merely holds the name does not count.
    #[test]
    fn a_module_is_named_by_a_word_of_its_command_line() {
        assert!(names(b"/tmp/disk.img f2k-disk\0", DISK_MODULE));
        assert!(names(b"f2k-disk", DISK_MODULE));
        assert!(names(b"f2k-disk\0garbage", DISK_MODULE));
        assert!(names(b"  f2k-disk\tother", DISK_MODULE));
        assert!(!names(b"/tmp/f2k-disk.img\0", DISK_MODULE));
        assert!(!names(b"/tmp/disk.img\0 f2k-disk", DISK_MODULE));
        assert!(!names(b"", DISK_MODULE));
    }

    /// The trampoline's run is reservable only when the map lists all of it as available, nothing
    /// reserves any of it, and the kernel holds none of it; never under the fallback.
    #[test]
    fn the_run_is_reservable_only_when_the_map_frees_all_of_it() {
        let run = 0x90..0x9B;
        let plan_for = |records: &[Vec<u8>], test: &dyn Fn(&BootMemoryPlan) -> bool| {
            let map = records.concat();
            let memory = memory(&[
                (0x100, &info_with_map(0x200, map.len() as u32, 4096)),
                (0x200, &map),
            ]);
            test(&plan_in(&memory, 0x100).unwrap())
        };
        let low = record(0, 0x9_FC00, MEMORY_AVAILABLE);
        assert!(plan_for(&[low.clone()], &|plan| plan.reserves(run.clone())));
        // A reservation inside the run.
        assert!(!plan_for(
            &[low.clone(), record(0x9_5000, 0x10, 2)],
            &|plan| { plan.reserves(run.clone()) }
        ));
        // Available memory that stops short of the run's end.
        assert!(!plan_for(
            &[record(0, 0x9_A000, MEMORY_AVAILABLE)],
            &|plan| { plan.reserves(run.clone()) }
        ));
        // A run the kernel image holds.
        assert!(!plan_for(
            &[record(0, 0x40_0000, MEMORY_AVAILABLE)],
            &|plan| { plan.reserves(0x100..0x10B) }
        ));
        // The fallback vouches for nothing below 1 MiB.
        let memory = memory(&[(0x100, &info_with_map(0, 0, 4096))]);
        assert!(!plan_in(&memory, 0x100).unwrap().reserves(run.clone()));
    }

    /// Build one memory-map record: size, base, length, type.
    fn record(base: u64, len: u64, kind: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&20u32.to_le_bytes());
        v.extend_from_slice(&base.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&kind.to_le_bytes());
        v
    }

    /// A base within a page of the top of the 64-bit space rounds up past it: no frames, no
    /// overflow (and no wrap to frame 0).
    #[test]
    fn a_base_near_the_top_of_the_address_space_yields_nothing() {
        assert!(usable_frames_in(0xFFFF_FFFF_FFFF_F001, 1, MAX_FRAMES).is_none());
        assert!(usable_frames_in(u64::MAX - 10, 5, MAX_FRAMES).is_none());
    }

    /// Reserved records win over available ones: a frame either kind covers is reserved; partial
    /// coverage counts; empty records and available records reserve nothing.
    #[test]
    fn reserved_records_cover_the_frames_they_touch() {
        let mut map = Vec::new();
        map.extend(record(0x10_0000, 0x10_0000, MEMORY_AVAILABLE));
        map.extend(record(0x10_8000, 0x1000, 2));
        map.extend(record(0x11_0800, 0x10, 3)); // inside one frame, unaligned
        map.extend(record(0x12_0000, 0, 2)); // empty
        assert!(!frame_is_reserved(&map, 0x100));
        assert!(frame_is_reserved(&map, 0x108));
        assert!(!frame_is_reserved(&map, 0x109));
        assert!(frame_is_reserved(&map, 0x110));
        assert!(!frame_is_reserved(&map, 0x120));
        assert_eq!(records(&map).count(), 4);
    }

    #[test]
    fn aligned_available_region_becomes_frames() {
        let range = usable_frames_in(0x2000, 0x3000, MAX_FRAMES).unwrap();
        assert_eq!(range, UsableRange { first: 2, count: 3 });
    }

    #[test]
    fn unaligned_base_rounds_up_end_rounds_down() {
        // [0x2FFF, 0x4001): whole frames are 0x3000 and 0x3FFF.
        let range = usable_frames_in(0x2FFF, 0x1002, MAX_FRAMES).unwrap();
        assert_eq!(range, UsableRange { first: 3, count: 1 });
    }

    #[test]
    fn frame_zero_is_never_handed_out() {
        let range = usable_frames_in(0, 0x9000, MAX_FRAMES).unwrap();
        assert_eq!(range, UsableRange { first: 1, count: 8 });
    }

    #[test]
    fn region_clamped_to_table_capacity() {
        // Frame 256 (1 MiB) onwards, table holds 300 frames.
        let range = usable_frames_in(0x100000, 0x10_0000, 300).unwrap();
        assert_eq!(
            range,
            UsableRange {
                first: 256,
                count: 44
            }
        );
    }

    #[test]
    fn degenerate_regions_yield_nothing() {
        assert!(usable_frames_in(0x2000, 0, MAX_FRAMES).is_none());
        assert!(usable_frames_in(0x2F00, 0x100, MAX_FRAMES).is_none()); // no whole frame
        assert!(usable_frames_in(0x1_0000_0000, 0x1000, MAX_FRAMES).is_none()); // beyond 4 GiB
        assert!(usable_frames_in(u64::MAX, 2, MAX_FRAMES).is_none()); // would overflow
    }

    #[test]
    fn iterator_yields_available_records_in_order() {
        let mut map = Vec::new();
        map.extend(record(0, 0x9FC00, MEMORY_AVAILABLE));
        map.extend(record(0x9FC00, 0x6400, 2)); // reserved
        map.extend(record(0x100000, 0x1000, MEMORY_AVAILABLE));
        let ranges: Vec<UsableRange> = usable_ranges(&map, MAX_FRAMES).collect();
        assert_eq!(
            ranges,
            vec![
                UsableRange {
                    first: 1,
                    count: 158
                },
                UsableRange {
                    first: 256,
                    count: 1
                },
            ]
        );
    }

    #[test]
    fn truncated_record_stops_parsing() {
        let full = record(0x100000, 0x2000, MEMORY_AVAILABLE);
        let cut = &full[..10]; // mid-record
        assert_eq!(usable_ranges(cut, MAX_FRAMES).count(), 0);

        // A record whose size exceeds the remaining buffer stops parsing.
        let mut map = Vec::new();
        map.extend_from_slice(&40u32.to_le_bytes()); // claims 40-byte payload
        map.extend_from_slice(&0x100000u64.to_le_bytes());
        assert_eq!(usable_ranges(&map, MAX_FRAMES).count(), 0);
    }

    #[test]
    fn malformed_size_stops_parsing() {
        let mut map = Vec::new();
        map.extend_from_slice(&4u32.to_le_bytes()); // payload below minimum
        map.extend_from_slice(&0u64.to_le_bytes());
        map.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(usable_ranges(&map, MAX_FRAMES).count(), 0);
    }

    #[test]
    fn empty_map_yields_nothing() {
        assert_eq!(usable_ranges(&[], MAX_FRAMES).count(), 0);
    }
}
