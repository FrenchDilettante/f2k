//! File reads: a file's bytes, cluster by cluster along its chain, into a caller buffer.
//!
//! The size bounds the read: the last cluster's sectors past the size are not read, and the last
//! sector's tail past it is not copied. Each step reads one cluster's needed sectors and asks the
//! FAT reader for the next cluster; an end that arrives before the size is satisfied, a free or
//! bad entry mid-chain, or a link outside the volume is corruption, reported as a status.

use super::fat::FatEntry;
use super::lookup::File;
use super::volume::Volume;
use crate::status::{
    nt_success, NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_FILE_CORRUPT_ERROR, STATUS_SUCCESS,
};

/// Read `file` (a file, not a directory) into the start of `buffer`, which must hold its size.
/// Returns an NT status; on failure the buffer's contents are unspecified.
#[must_use]
pub fn read(volume: &mut Volume, file: &File, buffer: &mut [u8]) -> NtStatus {
    assert!(!file.directory, "a directory is not read as a file");
    let size = file.size as usize;
    if buffer.len() < size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let layout = *volume.layout();
    let cluster_bytes = layout.sectors_per_cluster as usize * 512;
    let mut cluster = file.first_cluster;
    let mut done = 0;
    while done < size {
        if !layout.is_data_cluster(cluster) {
            return STATUS_FILE_CORRUPT_ERROR;
        }
        let lba = layout.cluster_lba(cluster);
        let take = cluster_bytes.min(size - done);
        let whole = take / 512 * 512;
        if whole > 0 {
            let status = volume.device().read(lba, &mut buffer[done..done + whole]);
            if !nt_success(status) {
                return status;
            }
        }
        let tail = take - whole;
        if tail > 0 {
            let mut sector = [0u8; 512];
            let status = volume
                .device()
                .read(lba + (whole / 512) as u64, &mut sector);
            if !nt_success(status) {
                return status;
            }
            buffer[done + whole..done + take].copy_from_slice(&sector[..tail]);
        }
        done += take;
        if done == size {
            break;
        }
        cluster = match volume.fat_entry(cluster) {
            Ok(FatEntry::Next(next)) => next,
            Ok(FatEntry::EndOfChain | FatEntry::Free | FatEntry::Bad | FatEntry::Corrupt(_)) => {
                return STATUS_FILE_CORRUPT_ERROR
            }
            Err(status) => return status,
        };
    }
    STATUS_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{file_bytes, Counting, Crafted};
    use super::*;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    fn file(first_cluster: u32, size: u32) -> File {
        File {
            first_cluster,
            size,
            directory: false,
        }
    }

    /// A crafted volume holding `bytes` along `chain` (1-sector clusters).
    fn volume_with(bytes: &[u8], chain: &[u32]) -> Volume {
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(chain);
        for (cluster, piece) in chain.iter().zip(bytes.chunks(512)) {
            crafted.cluster(*cluster, piece);
        }
        Volume::mount(crafted.device()).unwrap()
    }

    /// A chain read in order — here out of cluster order, 5 -> 3 -> 9 — delivers the file's bytes.
    #[test]
    fn the_chain_delivers_the_file_in_order() {
        let bytes = file_bytes(3 * 512);
        let mut volume = volume_with(&bytes, &[5, 3, 9]);
        let mut buffer = vec![0u8; bytes.len()];
        assert_eq!(
            read(&mut volume, &file(5, 1536), &mut buffer),
            STATUS_SUCCESS
        );
        assert_eq!(buffer, bytes);
    }

    /// A size that is not a whole number of sectors reads only the needed bytes of the last
    /// sector: the buffer past the size is left alone.
    #[test]
    fn the_last_sector_is_trimmed_to_the_size() {
        let bytes = file_bytes(2 * 512);
        let mut volume = volume_with(&bytes, &[4, 5]);
        let mut buffer = vec![0xAAu8; 1024];
        assert_eq!(
            read(&mut volume, &file(4, 700), &mut buffer),
            STATUS_SUCCESS
        );
        assert_eq!(&buffer[..700], &bytes[..700]);
        assert!(buffer[700..].iter().all(|&byte| byte == 0xAA));
    }

    /// With 4-sector clusters, the last cluster reads only the sectors the size reaches: a
    /// 2600-byte file is one full cluster (2048 bytes), then one whole sector and a 40-byte tail.
    #[test]
    fn a_partial_last_cluster_reads_only_its_needed_sectors() {
        let bytes = file_bytes(4096);
        let mut crafted = Crafted::new(4, 8);
        crafted
            .chain(&[3, 6])
            .cluster(3, &bytes[..2048])
            .cluster(6, &bytes[2048..]);
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        let before = device.reads();
        let mut buffer = vec![0u8; 2600];
        assert_eq!(
            read(&mut volume, &file(3, 2600), &mut buffer),
            STATUS_SUCCESS
        );
        assert_eq!(buffer, bytes[..2600]);
        // The first cluster, the FAT sector, the second cluster's whole sector, its tail sector.
        assert_eq!(device.reads() - before, 4);
    }

    /// One cluster read per step, and the FAT sector once (cached): a 3-cluster file reads three
    /// clusters and one FAT sector.
    #[test]
    fn one_cluster_per_chain_step() {
        let bytes = file_bytes(3 * 512);
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[3, 4, 5]);
        for (index, cluster) in [3u32, 4, 5].into_iter().enumerate() {
            crafted.cluster(cluster, &bytes[index * 512..(index + 1) * 512]);
        }
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        let before = device.reads();
        let mut buffer = vec![0u8; 1536];
        assert_eq!(
            read(&mut volume, &file(3, 1536), &mut buffer),
            STATUS_SUCCESS
        );
        assert_eq!(device.reads() - before, 3 + 1);
    }

    /// An empty file reads nothing, whatever its first cluster says.
    #[test]
    fn an_empty_file_reads_nothing() {
        let mut volume = volume_with(&[], &[3]);
        assert_eq!(read(&mut volume, &file(0, 0), &mut []), STATUS_SUCCESS);
    }

    /// A buffer smaller than the file is refused before any read; a larger one is fine.
    #[test]
    fn a_small_buffer_is_refused() {
        let bytes = file_bytes(1024);
        let mut volume = volume_with(&bytes, &[3, 4]);
        assert_eq!(
            read(&mut volume, &file(3, 1024), &mut [0u8; 1023]),
            STATUS_BUFFER_TOO_SMALL
        );
        let mut big = vec![0u8; 4096];
        assert_eq!(read(&mut volume, &file(3, 1024), &mut big), STATUS_SUCCESS);
        assert_eq!(&big[..1024], &bytes[..]);
    }

    /// The corrupt chains: an end before the size is satisfied, a free entry and a bad entry
    /// mid-chain, a link outside the volume, and a first cluster outside it.
    #[test]
    fn broken_chains_are_corrupt() {
        let bytes = file_bytes(3 * 512);
        let corrupt = |change: &dyn Fn(&mut Crafted), first: u32| {
            let mut crafted = Crafted::new(1, 16);
            crafted.chain(&[3, 4, 5]);
            change(&mut crafted);
            let mut volume = Volume::mount(crafted.device()).unwrap();
            let mut buffer = vec![0u8; bytes.len()];
            read(&mut volume, &file(first, 1536), &mut buffer)
        };
        assert_eq!(
            corrupt(
                &|c| {
                    c.fat(4, 0x0FFF_FFFF);
                },
                3
            ),
            STATUS_FILE_CORRUPT_ERROR,
            "early end"
        );
        assert_eq!(
            corrupt(
                &|c| {
                    c.fat(4, 0);
                },
                3
            ),
            STATUS_FILE_CORRUPT_ERROR,
            "free"
        );
        assert_eq!(
            corrupt(
                &|c| {
                    c.fat(4, 0x0FFF_FFF7);
                },
                3
            ),
            STATUS_FILE_CORRUPT_ERROR,
            "bad"
        );
        assert_eq!(
            corrupt(
                &|c| {
                    c.fat(4, 1);
                },
                3
            ),
            STATUS_FILE_CORRUPT_ERROR,
            "out of range"
        );
        assert_eq!(
            corrupt(
                &|c| {
                    c.fat(4, 200_000);
                },
                3
            ),
            STATUS_FILE_CORRUPT_ERROR,
            "past the end"
        );
        assert_eq!(
            corrupt(&|_| {}, 1),
            STATUS_FILE_CORRUPT_ERROR,
            "first cluster"
        );
        assert_eq!(corrupt(&|_| {}, 3), STATUS_SUCCESS, "the intact chain");
    }

    /// A device failure mid-read surfaces as the device's status.
    #[test]
    fn a_device_failure_surfaces() {
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[3, 4]);
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        device.fail(true);
        assert_eq!(
            read(&mut volume, &file(3, 1024), &mut [0u8; 1024]),
            STATUS_IO_DEVICE_ERROR
        );
    }

    #[test]
    #[should_panic(expected = "not read as a file")]
    fn reading_a_directory_is_a_contract_violation() {
        let mut volume = volume_with(&[], &[3]);
        let directory = File {
            first_cluster: 2,
            size: 0,
            directory: true,
        };
        let _ = read(&mut volume, &directory, &mut []);
    }
}
