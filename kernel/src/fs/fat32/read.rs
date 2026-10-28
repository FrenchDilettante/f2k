//! File reads: a file's bytes, cluster by cluster along its chain, into a caller buffer.
//!
//! A read is a span of the file — an offset and a length — bounded by the size: the clusters before
//! the offset's are skipped through the FAT reader without being read, and within a cluster only
//! the sectors the span touches are read; a sector the span covers partly is read whole and only
//! its covered bytes copied. An end that arrives before the size is satisfied, a free or bad entry
//! mid-chain, or a link outside the volume is corruption, reported as a status.

use super::check;
use super::fat::FatEntry;
use super::lookup::File;
use super::volume::Volume;
use crate::status::{NtStatus, STATUS_BUFFER_TOO_SMALL, STATUS_FILE_CORRUPT_ERROR, STATUS_SUCCESS};

/// Read `file` (a file, not a directory) into the start of `buffer`, which must hold its size.
/// Returns an NT status; on failure the buffer's contents are unspecified.
#[must_use]
pub fn read(volume: &mut Volume, file: &File, buffer: &mut [u8]) -> NtStatus {
    assert!(!file.directory, "a directory is not read as a file");
    let size = file.size as usize;
    if buffer.len() < size {
        return STATUS_BUFFER_TOO_SMALL;
    }
    match read_at(volume, file, 0, &mut buffer[..size]) {
        Ok(_) => STATUS_SUCCESS,
        Err(status) => status,
    }
}

/// Read `file` (a file, not a directory) from byte `offset` into the start of `buffer`: as many
/// bytes as the buffer holds, or as remain before the end — none at or past it. Returns how many
/// bytes were read; on failure the buffer's contents are unspecified.
pub fn read_at(
    volume: &mut Volume,
    file: &File,
    offset: u32,
    buffer: &mut [u8],
) -> Result<usize, NtStatus> {
    assert!(!file.directory, "a directory is not read as a file");
    let count = buffer.len().min(file.size.saturating_sub(offset) as usize);
    if count == 0 {
        return Ok(0);
    }
    let layout = *volume.layout();
    let cluster_bytes = layout.sectors_per_cluster as usize * 512;
    let offset = offset as usize;
    let mut cluster = file.first_cluster;
    for _ in 0..offset / cluster_bytes {
        cluster = next_cluster(volume, cluster)?;
    }
    let mut within = offset % cluster_bytes;
    let mut done = 0;
    loop {
        if !layout.is_data_cluster(cluster) {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        let take = (cluster_bytes - within).min(count - done);
        read_span(
            volume,
            layout.cluster_lba(cluster),
            within,
            &mut buffer[done..done + take],
        )?;
        done += take;
        if done == count {
            return Ok(count);
        }
        cluster = next_cluster(volume, cluster)?;
        within = 0;
    }
}

/// The cluster after `cluster` in its chain; anything but a next link is corruption here, since the
/// file's size says the chain goes on.
fn next_cluster(volume: &mut Volume, cluster: u32) -> Result<u32, NtStatus> {
    if !volume.layout().is_data_cluster(cluster) {
        return Err(STATUS_FILE_CORRUPT_ERROR);
    }
    match volume.fat_entry(cluster)? {
        FatEntry::Next(next) => Ok(next),
        FatEntry::EndOfChain | FatEntry::Free | FatEntry::Bad | FatEntry::Corrupt(_) => {
            Err(STATUS_FILE_CORRUPT_ERROR)
        }
    }
}

/// Read the bytes from `start` within the cluster at `lba` into `out`: whole sectors straight into
/// it in one device read, a partly covered sector through a bounce sector.
fn read_span(volume: &Volume, lba: u64, start: usize, out: &mut [u8]) -> Result<(), NtStatus> {
    let mut at = start;
    let mut done = 0;
    while done < out.len() {
        let sector = lba + (at / 512) as u64;
        let within = at % 512;
        let remaining = out.len() - done;
        let take = if within == 0 && remaining >= 512 {
            let whole = remaining / 512 * 512;
            check(volume.device().read(sector, &mut out[done..done + whole]))?;
            whole
        } else {
            let mut bounce = [0u8; 512];
            check(volume.device().read(sector, &mut bounce))?;
            let take = (512 - within).min(remaining);
            out[done..done + take].copy_from_slice(&bounce[within..within + take]);
            take
        };
        done += take;
        at += take;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::fixtures::{file_bytes, Counting, Crafted};
    use super::*;
    use crate::status::STATUS_IO_DEVICE_ERROR;

    fn file(first_cluster: u32, size: u32) -> File {
        File::plain(first_cluster, size, false)
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
        let directory = File::plain(2, 0, true);
        let _ = read(&mut volume, &directory, &mut []);
    }

    // --- The positioned read ---------------------------------------------------

    /// A 3-cluster file of 1-sector clusters along 5 -> 3 -> 9, 1400 bytes (the last cluster
    /// trimmed), and its bytes.
    fn positioned() -> (Volume, File, Vec<u8>) {
        let bytes = file_bytes(3 * 512);
        (volume_with(&bytes, &[5, 3, 9]), file(5, 1400), bytes)
    }

    fn read_span_of(volume: &mut Volume, file: &File, offset: u32, count: usize) -> Vec<u8> {
        let mut buffer = vec![0xAAu8; count];
        let moved = read_at(volume, file, offset, &mut buffer).unwrap();
        buffer.truncate(moved);
        buffer
    }

    /// A span inside one cluster, unaligned at both ends.
    #[test]
    fn a_span_within_a_cluster() {
        let (mut volume, file, bytes) = positioned();
        assert_eq!(read_span_of(&mut volume, &file, 2, 2), &bytes[2..4]);
        assert_eq!(
            read_span_of(&mut volume, &file, 0x3C, 4),
            &bytes[0x3C..0x40]
        );
        assert_eq!(read_span_of(&mut volume, &file, 600, 100), &bytes[600..700]);
    }

    /// A span crossing cluster boundaries, the chain followed out of cluster order.
    #[test]
    fn a_span_across_clusters() {
        let (mut volume, file, bytes) = positioned();
        assert_eq!(read_span_of(&mut volume, &file, 500, 30), &bytes[500..530]);
        assert_eq!(
            read_span_of(&mut volume, &file, 100, 1200),
            &bytes[100..1300]
        );
        assert_eq!(read_span_of(&mut volume, &file, 0, 1400), &bytes[..1400]);
    }

    /// The last cluster is trimmed to the size: a request reaching past the end delivers the
    /// prefix before it, and the buffer past what was moved is left alone.
    #[test]
    fn a_request_crossing_the_end_delivers_the_prefix() {
        let (mut volume, file, bytes) = positioned();
        let mut buffer = vec![0xAAu8; 100];
        assert_eq!(read_at(&mut volume, &file, 1350, &mut buffer), Ok(50));
        assert_eq!(&buffer[..50], &bytes[1350..1400]);
        assert!(buffer[50..].iter().all(|&byte| byte == 0xAA));
        assert_eq!(
            read_span_of(&mut volume, &file, 1399, 4),
            &bytes[1399..1400]
        );
    }

    /// At or past the end, and for an empty request, nothing moves and nothing is read.
    #[test]
    fn nothing_moves_at_or_past_the_end() {
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[5, 3, 9]);
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        let before = device.reads();
        let sized = file(5, 1400);
        let mut buffer = [0xAAu8; 8];
        assert_eq!(read_at(&mut volume, &sized, 1400, &mut buffer), Ok(0));
        assert_eq!(read_at(&mut volume, &sized, 5000, &mut buffer), Ok(0));
        assert_eq!(read_at(&mut volume, &sized, u32::MAX, &mut buffer), Ok(0));
        assert_eq!(read_at(&mut volume, &sized, 0, &mut []), Ok(0));
        assert_eq!(read_at(&mut volume, &file(0, 0), 0, &mut buffer), Ok(0));
        assert_eq!(buffer, [0xAA; 8]);
        assert_eq!(device.reads(), before, "no device read");
    }

    /// The skip walks the chain without reading the skipped clusters: a span in the third cluster
    /// reads its one sector and the (cached) FAT sector.
    #[test]
    fn skipped_clusters_are_not_read() {
        let bytes = file_bytes(3 * 512);
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[5, 3, 9]);
        for (cluster, piece) in [5u32, 3, 9].iter().zip(bytes.chunks(512)) {
            crafted.cluster(*cluster, piece);
        }
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        let before = device.reads();
        assert_eq!(
            read_span_of(&mut volume, &file(5, 1536), 1100, 10),
            &bytes[1100..1110]
        );
        assert_eq!(device.reads() - before, 1 + 1);
    }

    /// Multi-sector clusters: a span starting mid-sector in one cluster and ending mid-sector in
    /// the next reads its partial sectors through the bounce, its whole ones directly.
    #[test]
    fn multi_sector_clusters_read_only_the_span() {
        let bytes = file_bytes(4096);
        let mut crafted = Crafted::new(4, 8);
        crafted
            .chain(&[3, 6])
            .cluster(3, &bytes[..2048])
            .cluster(6, &bytes[2048..]);
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        let file = file(3, 4000);
        let before = device.reads();
        // 1000..2600: sector 1's tail (bounce), sectors 2-3 (one read), the FAT sector, then the
        // second cluster's first sector and the head of its second (bounce).
        assert_eq!(
            read_span_of(&mut volume, &file, 1000, 1600),
            &bytes[1000..2600]
        );
        assert_eq!(device.reads() - before, 5);
        assert_eq!(
            read_span_of(&mut volume, &file, 3990, 50),
            &bytes[3990..4000]
        );
    }

    /// The corrupt chains, identical to the whole-file read's, whether the break lies in the
    /// skipped part of the chain or in the span itself; a span before the break still reads.
    #[test]
    fn broken_chains_are_corrupt_mid_walk() {
        let positioned_read = |change: &dyn Fn(&mut Crafted), offset: u32| {
            let mut crafted = Crafted::new(1, 16);
            crafted.chain(&[3, 4, 5]);
            change(&mut crafted);
            let mut volume = Volume::mount(crafted.device()).unwrap();
            read_at(&mut volume, &file(3, 1536), offset, &mut [0u8; 16])
        };
        for (value, what) in [
            (0x0FFF_FFFF, "early end"),
            (0, "free"),
            (0x0FFF_FFF7, "bad"),
            (1, "out of range"),
            (200_000, "past the end"),
        ] {
            let change = move |c: &mut Crafted| {
                c.fat(4, value);
            };
            assert_eq!(
                positioned_read(&change, 1100),
                Err(STATUS_FILE_CORRUPT_ERROR),
                "{what}, skipped"
            );
            assert_eq!(
                positioned_read(&change, 1020),
                Err(STATUS_FILE_CORRUPT_ERROR),
                "{what}, in the span"
            );
            assert_eq!(
                positioned_read(&change, 600),
                Ok(16),
                "{what}, before the break"
            );
        }
        assert_eq!(positioned_read(&|_| {}, 1100), Ok(16), "the intact chain");

        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[3, 4, 5]);
        let mut volume = Volume::mount(crafted.device()).unwrap();
        assert_eq!(
            read_at(&mut volume, &file(1, 1536), 1100, &mut [0u8; 16]),
            Err(STATUS_FILE_CORRUPT_ERROR),
            "first cluster"
        );
    }

    /// A device failure mid-span surfaces as the device's status.
    #[test]
    fn a_device_failure_surfaces_from_a_span() {
        let mut crafted = Crafted::new(1, 16);
        crafted.chain(&[3, 4]);
        let device = Counting::over(crafted.device());
        let mut volume = Volume::mount(device).unwrap();
        device.fail(true);
        assert_eq!(
            read_at(&mut volume, &file(3, 1024), 600, &mut [0u8; 4]),
            Err(STATUS_IO_DEVICE_ERROR)
        );
    }
}
