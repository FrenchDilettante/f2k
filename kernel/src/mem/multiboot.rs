//! Multiboot 1 boot-time memory information.
//!
//! Two layers:
//! - pure, host-testable logic: parsing the memory-map record stream and turning available regions
//!   into usable frame ranges;
//! - the loader-provided structures, read by the kernel from the physical address passed in EBX.
//!
//! Memory-map records are packed, unaligned and variable-size, so they are parsed from byte slices
//! with explicit little-endian reads rather than struct casts.

use super::frame::FrameId;

/// Multiboot information structure flags.
pub mod flags {
    /// `mem_lower` / `mem_upper` are valid.
    pub const MEM_INFO: u32 = 1 << 0;
    /// `mmap_length` / `mmap_addr` are valid.
    pub const MMAP: u32 = 1 << 6;
}

/// Memory-map record type: usable RAM.
pub const MEMORY_AVAILABLE: u32 = 1;

/// Smallest well-formed memory-map record payload: `size` (4 bytes, excluded from itself), base
/// (8), length (8), type (4).
const MIN_RECORD_PAYLOAD: u32 = 20;

/// The Multiboot 1 information structure the loader points EBX at. Only the fields F2K reads are
/// listed; offsets are part of the Multiboot 1 contract.
#[repr(C)]
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
    let base_up = (base + 4095) & !4095u64;
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

/// Iterator over the usable frame ranges of a memory-map record stream.
pub struct UsableRanges<'a> {
    buf: &'a [u8],
    off: usize,
    max_frames: usize,
}

/// Parse the memory-map record stream (the buffer at `MultibootInfo::mmap_addr`) and yield the
/// usable frame ranges of every available region, in record order.
pub fn usable_ranges(map: &[u8], max_frames: usize) -> UsableRanges<'_> {
    UsableRanges {
        buf: map,
        off: 0,
        max_frames,
    }
}

impl<'a> Iterator for UsableRanges<'a> {
    type Item = UsableRange;

    fn next(&mut self) -> Option<UsableRange> {
        while let Some(size) = read_u32(self.buf, self.off) {
            // Malformed or truncated record: stop rather than guess.
            if size < MIN_RECORD_PAYLOAD {
                return None;
            }
            let entry_end = self.off + 4 + size as usize;
            if entry_end > self.buf.len() {
                return None;
            }
            let base = read_u64(self.buf, self.off + 4)?;
            let len = read_u64(self.buf, self.off + 12)?;
            let kind = read_u32(self.buf, self.off + 20)?;
            self.off = entry_end;
            if kind == MEMORY_AVAILABLE {
                if let Some(range) = usable_frames_in(base, len, self.max_frames) {
                    return Some(range);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::frame::MAX_FRAMES;

    /// Build one memory-map record: size, base, length, type.
    fn record(base: u64, len: u64, kind: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&20u32.to_le_bytes());
        v.extend_from_slice(&base.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.extend_from_slice(&kind.to_le_bytes());
        v
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
