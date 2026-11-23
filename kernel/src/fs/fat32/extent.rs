//! A file's clusters as runs of consecutive sectors: retrieval pointers a caller keeps to move the
//! file's data straight between memory and the device, with no chain walk — as Windows 2000's
//! paging I/O reaches the paging file. The map is a snapshot: whoever changes the file's chain
//! makes it again.

use core::ops::Range;

use super::fat::FatEntry;
use super::lookup::File;
use super::volume::Volume;
use crate::status::{NtStatus, STATUS_FILE_CORRUPT_ERROR};

/// The most runs a map holds: a file in more pieces gets none.
pub const MAX_RUNS: usize = 16;

/// Consecutive sectors of a file, from `lba`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Run {
    pub lba: u64,
    pub sectors: u64,
}

/// A file's first `bytes` bytes as runs, in file order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Extents {
    runs: [Run; MAX_RUNS],
    count: usize,
    bytes: u64,
}

impl Extents {
    /// Map `file`'s clusters up to its size, walking its chain once: none when they take more
    /// than [`MAX_RUNS`] runs. A chain that ends early or leaves the volume is corruption.
    pub fn of(volume: &mut Volume, file: &File) -> Result<Option<Extents>, NtStatus> {
        let layout = *volume.layout();
        let sectors = u64::from(layout.sectors_per_cluster);
        let clusters = u64::from(file.size).div_ceil(sectors * 512);
        let mut extents = Extents {
            runs: [Run::default(); MAX_RUNS],
            count: 0,
            bytes: u64::from(file.size),
        };
        let mut cluster = file.first_cluster;
        for index in 0..clusters {
            if !layout.is_data_cluster(cluster) {
                return Err(STATUS_FILE_CORRUPT_ERROR);
            }
            let lba = layout.cluster_lba(cluster);
            match extents.runs[..extents.count].last_mut() {
                Some(run) if run.lba + run.sectors == lba => run.sectors += sectors,
                _ if extents.count == MAX_RUNS => return Ok(None),
                _ => {
                    extents.runs[extents.count] = Run { lba, sectors };
                    extents.count += 1;
                }
            }
            if index + 1 < clusters {
                cluster = match volume.fat_entry(cluster)? {
                    FatEntry::Next(next) => next,
                    _ => return Err(STATUS_FILE_CORRUPT_ERROR),
                };
            }
        }
        Ok(Some(extents))
    }

    pub fn runs(&self) -> &[Run] {
        &self.runs[..self.count]
    }

    /// Whether `[offset, offset + len)` is mapped and starts and ends on sector boundaries.
    pub fn covers(&self, offset: u64, len: usize) -> bool {
        let len = len as u64;
        offset % 512 == 0 && len % 512 == 0 && offset.saturating_add(len) <= self.bytes
    }

    /// Run `io` over `[offset, offset + len)` (which the map [`covers`](Self::covers)) one run's
    /// piece at a time: each piece's first LBA and its range within the span.
    pub fn split<E>(
        &self,
        offset: u64,
        len: usize,
        mut io: impl FnMut(u64, Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        assert!(self.covers(offset, len), "a span the map does not cover");
        let mut sector = offset / 512;
        let mut done = 0usize;
        for run in self.runs() {
            if done == len {
                break;
            }
            if sector >= run.sectors {
                sector -= run.sectors;
                continue;
            }
            let take = ((run.sectors - sector) * 512).min((len - done) as u64) as usize;
            io(run.lba + sector, done..done + take)?;
            done += take;
            sector = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::super::fixtures::Crafted;
    use super::super::lookup::lookup;
    use super::*;

    fn mapped(crafted: &Crafted, size: u32) -> Result<Option<Extents>, NtStatus> {
        let mut volume = Volume::mount(crafted.writable()).unwrap();
        let mut file = lookup(&mut volume, b"PAGE.SYS").unwrap();
        file.size = size;
        Extents::of(&mut volume, &file)
    }

    fn with_file(spc: u8, chain: &[u32], size: u32) -> Crafted {
        let mut crafted = Crafted::new(spc, 40);
        crafted
            .directory(
                2,
                &[super::super::fixtures::record(
                    b"PAGE    SYS",
                    0x26,
                    chain[0],
                    size,
                )],
            )
            .chain(chain);
        crafted
    }

    /// A contiguous chain is one run; a break starts the next, and two clusters that meet again
    /// join.
    #[test]
    fn a_chain_maps_to_its_runs() {
        let crafted = with_file(1, &[3, 4, 5, 9, 10, 20], 6 * 512);
        let extents = mapped(&crafted, 6 * 512).unwrap().unwrap();
        let lba = |cluster: u64| 2 + (cluster - 2);
        assert_eq!(
            extents.runs(),
            &[
                Run {
                    lba: lba(3),
                    sectors: 3
                },
                Run {
                    lba: lba(9),
                    sectors: 2
                },
                Run {
                    lba: lba(20),
                    sectors: 1
                },
            ]
        );

        let crafted = with_file(4, &[3, 4, 5], 3 * 2048);
        let extents = mapped(&crafted, 3 * 2048).unwrap().unwrap();
        assert_eq!(
            extents.runs(),
            &[Run {
                lba: 2 + 4,
                sectors: 12
            }]
        );
    }

    /// Only the clusters the size covers are mapped; an empty file has no runs, and a chain that
    /// ends before its size is corruption.
    #[test]
    fn the_map_stops_at_the_size() {
        let crafted = with_file(1, &[3, 4, 8], 3 * 512);
        assert_eq!(mapped(&crafted, 1000).unwrap().unwrap().runs().len(), 1);
        assert_eq!(mapped(&crafted, 0).unwrap().unwrap().runs(), &[]);
        assert_eq!(mapped(&crafted, 4 * 512), Err(STATUS_FILE_CORRUPT_ERROR));
    }

    /// A file in more pieces than the map holds gets none, and its I/O stays on the file layer.
    #[test]
    fn a_file_in_too_many_pieces_has_no_map() {
        let chain: Vec<u32> = (0..=MAX_RUNS as u32).map(|n| 3 + 2 * n).collect();
        let crafted = with_file(1, &chain, chain.len() as u32 * 512);
        assert_eq!(mapped(&crafted, chain.len() as u32 * 512), Ok(None));
        let fits = (chain.len() as u32 - 1) * 512;
        assert_eq!(
            mapped(&crafted, fits).unwrap().unwrap().runs().len(),
            MAX_RUNS
        );
    }

    /// A span is split at the runs' breaks, each piece at its LBA; only whole sectors inside the
    /// size are covered.
    #[test]
    fn a_span_splits_at_the_breaks() {
        let crafted = with_file(1, &[3, 4, 5, 9, 10, 20], 6 * 512);
        let extents = mapped(&crafted, 6 * 512).unwrap().unwrap();
        let mut pieces = Vec::new();
        extents
            .split(512, 4 * 512, |lba, range| {
                pieces.push((lba, range));
                Ok::<(), ()>(())
            })
            .unwrap();
        assert_eq!(pieces, [(4, 0..1024), (9, 1024..2048)]);

        assert!(extents.covers(0, 6 * 512));
        assert!(!extents.covers(512, 6 * 512), "past the size");
        assert!(!extents.covers(100, 512), "off a sector boundary");
        assert!(!extents.covers(0, 100));
    }
}
