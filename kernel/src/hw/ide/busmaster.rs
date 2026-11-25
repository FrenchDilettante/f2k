//! The controller's bus master: the physical region descriptor table a DMA command moves its
//! sectors by, and the command protocol over the bus master's registers.
//!
//! A PCI IDE controller (Intel's PIIX, and every controller of the SFF-8038i layout) moves a READ
//! DMA's or WRITE DMA's sectors itself, from or to memory the descriptor table names: each entry
//! a physical run of memory, word-aligned, an even number of bytes, at most 64 KiB and not
//! crossing a 64 KiB boundary, the last entry marked. The device then interrupts once, when the
//! whole command is done, where a PIO command interrupts once per DRQ block and the processor
//! moves every word through the data port. Windows 2000's atapi/pciidex use it whenever the
//! controller and the drive both support it.
//!
//! [`descriptors`] builds a table from a buffer's physical runs; it refuses (none) a buffer the
//! engine cannot reach — a run above 4 GiB (the table's addresses are 32 bits, whatever a
//! physical address's width: [`crate::mem::phys`]), an odd address or length, or more entries
//! than the table holds — and the caller moves that buffer by PIO instead.

/// One descriptor: the run's physical address, and its byte count (0 meaning 64 KiB) with the
/// end-of-table mark in bit 31.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Descriptor {
    pub address: u32,
    pub count_and_end: u32,
}

impl Descriptor {
    /// Bit 31 of the second dword: the table's last entry.
    pub const END: u32 = 0x8000_0000;

    /// The descriptor's two little-endian dwords, as the engine reads them.
    pub fn bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[..4].copy_from_slice(&self.address.to_le_bytes());
        bytes[4..].copy_from_slice(&self.count_and_end.to_le_bytes());
        bytes
    }
}

/// The largest run one descriptor moves, and the boundary none may cross.
const RUN_LIMIT: u64 = 0x1_0000;

/// The descriptor table for a transfer over `runs` (physical address and length, in order): the
/// runs split at 64 KiB boundaries, the last entry marked. The count written into `table`; none
/// when the engine cannot reach a run (above 4 GiB, or an odd address or length) or the table is
/// too small.
pub fn descriptors(
    runs: impl IntoIterator<Item = (u64, u32)>,
    table: &mut [Descriptor],
) -> Option<usize> {
    let mut count = 0;
    for (address, length) in runs {
        if address % 2 != 0 || length % 2 != 0 {
            return None;
        }
        let end = address.checked_add(u64::from(length))?;
        if end > 1 << 32 {
            return None;
        }
        let mut at = address;
        while at < end {
            let boundary = (at / RUN_LIMIT + 1) * RUN_LIMIT;
            let next = boundary.min(end);
            let bytes = (next - at) as u32;
            *table.get_mut(count)? = Descriptor {
                address: at as u32,
                count_and_end: bytes & 0xFFFF,
            };
            count += 1;
            at = next;
        }
    }
    if count == 0 {
        return None;
    }
    table[count - 1].count_and_end |= Descriptor::END;
    Some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A run inside one 64 KiB window is one descriptor, marked last.
    #[test]
    fn a_run_is_one_descriptor() {
        let mut table = [Descriptor::default(); 4];
        assert_eq!(descriptors([(0x0012_3000, 4096)], &mut table), Some(1));
        assert_eq!(
            table[0],
            Descriptor {
                address: 0x0012_3000,
                count_and_end: 0x8000_1000,
            }
        );
        assert_eq!(
            table[0].bytes(),
            [0x00, 0x30, 0x12, 0x00, 0x00, 0x10, 0x00, 0x80]
        );
    }

    /// A run crossing a 64 KiB boundary splits there; a whole 64 KiB window counts as 0.
    #[test]
    fn runs_split_at_64_kib_boundaries() {
        let mut table = [Descriptor::default(); 8];
        let count = descriptors([(0x0001_F000, 0x1_2000), (0x0040_0000, 512)], &mut table);
        assert_eq!(count, Some(4));
        assert_eq!(
            table[..4],
            [
                Descriptor {
                    address: 0x0001_F000,
                    count_and_end: 0x1000,
                },
                Descriptor {
                    address: 0x0002_0000,
                    count_and_end: 0,
                },
                Descriptor {
                    address: 0x0003_0000,
                    count_and_end: 0x1000,
                },
                Descriptor {
                    address: 0x0040_0000,
                    count_and_end: Descriptor::END | 512,
                },
            ]
        );
    }

    /// What the engine cannot reach is refused: memory above 4 GiB, an odd address or length, a
    /// table too small, no run at all.
    #[test]
    fn unreachable_buffers_are_refused() {
        let mut table = [Descriptor::default(); 2];
        assert_eq!(descriptors([(0x1_0000_0000, 512)], &mut table), None);
        assert_eq!(descriptors([(0xFFFF_FF00, 512)], &mut table), None);
        assert_eq!(descriptors([(0x1001, 512)], &mut table), None);
        assert_eq!(descriptors([(0x1000, 511)], &mut table), None);
        assert_eq!(
            descriptors([(0x1000, 512), (0x3000, 512), (0x5000, 512)], &mut table),
            None
        );
        assert_eq!(descriptors([], &mut table), None);
        assert_eq!(descriptors([(0xFFFF_FE00, 512)], &mut table), Some(1));
    }
}
