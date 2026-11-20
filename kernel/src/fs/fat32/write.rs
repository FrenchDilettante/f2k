//! Writes: cluster allocation, file data and sizes, and directory entries — creating (with long
//! names), updating, removing and renaming them, and directories themselves.
//!
//! Every FAT change goes to all the FAT copies (see [`Volume::set_fat_entry`]). A cluster is zeroed
//! when it is allocated, so a file's growth reads as zeros, and so does a new directory's tail (its
//! records are end markers). A file that grows past its old end has the bytes between zeroed too:
//! the old last cluster may still hold what a truncation left there.
//!
//! An entry is named as Windows 2000 names it on FAT: a name that is a valid 8.3 name is its own
//! 8.3 name, upper-cased — with no long name when its base and its extension are each in one case
//! (a lower-case one marked by the NT case bits), and with a long name holding the case when a part
//! mixes cases (or has a lower-case letter outside ASCII, which the case bits do not restore); any
//! other name gets long-name records and a generated 8.3 alias — the name upper-cased, spaces and
//! extra dots dropped, invalid bytes as `_`, the base cut to six bytes and `~N` appended, the
//! extension cut to three, with the lowest N no other entry of the directory uses. Both are stored
//! in code page 437 (see [`super::path`]): a name is a valid 8.3 one only when 437 holds each of
//! its characters, and an alias takes a character's best fit, or `_` when 437 has none.

use rtl::cp1252::{map_case, MB_TO_WC};
use rtl::pod::Pod;

use super::dir::{decode_byte, walk};
use super::dirent::{
    checksum,
    decode,
    LongPart,
    RawDirEntry,
    RawLongEntry,
    Record,
    RecordBytes,
    Times,
    ATTR_LONG_NAME,
    CASE_LOWER_BASE,
    CASE_LOWER_EXTENSION,
    DELETED,
    DOT,
    DOT_DOT,
    ENTRY_SIZE,
    LAST_LONG_PART,
    PART_UNITS,
};
use super::fat::FatEntry;
use super::lookup::{File, LookupError};
use super::path::{oem_upper_fit, short_form};
use super::volume::Volume;
use crate::status::{
    NtStatus,
    STATUS_ACCESS_DENIED,
    STATUS_DISK_FULL,
    STATUS_FILE_CORRUPT_ERROR,
    STATUS_OBJECT_NAME_INVALID,
};

/// The value that ends a chain.
const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
/// The long name's longest form, in units.
const MAX_LONG: usize = 255;

fn cluster_bytes(volume: &Volume) -> u32 {
    volume.layout().sectors_per_cluster * 512
}

fn corrupt(_: LookupError) -> NtStatus {
    STATUS_FILE_CORRUPT_ERROR
}

/// The cluster after `cluster` in its chain, or none at its end; anything else is corruption.
fn next(volume: &mut Volume, cluster: u32) -> Result<Option<u32>, NtStatus> {
    if !volume.layout().is_data_cluster(cluster) {
        return Err(STATUS_FILE_CORRUPT_ERROR);
    }
    match volume.fat_entry(cluster)? {
        FatEntry::Next(next) => Ok(Some(next)),
        FatEntry::EndOfChain => Ok(None),
        _ => Err(STATUS_FILE_CORRUPT_ERROR),
    }
}

/// The chain's `n`th cluster (0: the first).
fn nth(volume: &mut Volume, first: u32, n: u32) -> Result<u32, NtStatus> {
    let mut cluster = first;
    for _ in 0..n {
        cluster = next(volume, cluster)?.ok_or(STATUS_FILE_CORRUPT_ERROR)?;
    }
    if !volume.layout().is_data_cluster(cluster) {
        return Err(STATUS_FILE_CORRUPT_ERROR);
    }
    Ok(cluster)
}

/// The chain's last cluster and its length in clusters.
fn last(volume: &mut Volume, first: u32) -> Result<(u32, u32), NtStatus> {
    let mut cluster = first;
    let mut count = 1;
    for _ in 0..volume.layout().cluster_count {
        match next(volume, cluster)? {
            Some(following) => {
                cluster = following;
                count += 1;
            }
            None => return Ok((cluster, count)),
        }
    }
    Err(STATUS_FILE_CORRUPT_ERROR)
}

/// Write zeros over `cluster`.
fn zero_cluster(volume: &mut Volume, cluster: u32) -> Result<(), NtStatus> {
    let first = volume.layout().cluster_lba(cluster);
    for offset in 0..volume.layout().sectors_per_cluster as u64 {
        volume.write_sector(first + offset, &[0; 512])?;
    }
    Ok(())
}

/// Allocate a free cluster, zeroed, ending its chain — linked after `previous` when there is one.
/// A link that fails gives the cluster back (best effort), so it is not lost.
pub fn allocate(volume: &mut Volume, previous: Option<u32>) -> Result<u32, NtStatus> {
    let count = volume.layout().cluster_count;
    let start = volume.next_free().clamp(2, count + 1);
    for step in 0..count {
        let cluster = 2 + (start - 2 + step) % count;
        if volume.fat_entry(cluster)? == FatEntry::Free {
            zero_cluster(volume, cluster)?;
            volume.set_fat_entry(cluster, END_OF_CHAIN)?;
            if let Some(previous) = previous {
                if let Err(status) = volume.set_fat_entry(previous, cluster) {
                    let _ = volume.set_fat_entry(cluster, 0);
                    return Err(status);
                }
            }
            volume.set_next_free(cluster + 1);
            return Ok(cluster);
        }
    }
    Err(STATUS_DISK_FULL)
}

/// Free the chain starting at `first` (none for 0).
pub fn free_chain(volume: &mut Volume, first: u32) -> Result<(), NtStatus> {
    let mut cluster = first;
    for _ in 0..volume.layout().cluster_count {
        if !volume.layout().is_data_cluster(cluster) {
            return Ok(());
        }
        let following = volume.fat_entry(cluster)?;
        volume.set_fat_entry(cluster, 0)?;
        volume.set_next_free(volume.next_free().min(cluster));
        match following {
            FatEntry::Next(next) => cluster = next,
            _ => return Ok(()),
        }
    }
    Err(STATUS_FILE_CORRUPT_ERROR)
}

/// The clusters a growth linked onto a chain: the first of them, and the cluster they follow
/// (none: they are the whole chain).
#[derive(Clone, Copy)]
struct Growth {
    tail: Option<u32>,
    added: u32,
}

impl Growth {
    /// Give the clusters back: the chain ends where it did before the growth.
    fn give_back(self, volume: &mut Volume) -> Result<(), NtStatus> {
        if let Some(tail) = self.tail {
            volume.set_fat_entry(tail, END_OF_CHAIN)?;
        }
        free_chain(volume, self.added)
    }
}

/// Grow `file`'s chain to cover `bytes`: all of it or, when the volume runs out (or a device write
/// fails), none — the clusters taken so far are given back and the chain ends where it did. The
/// clusters added, when it needed any.
fn reserve(volume: &mut Volume, file: &mut File, bytes: u32) -> Result<Option<Growth>, NtStatus> {
    let size = cluster_bytes(volume);
    let needed = bytes.div_ceil(size);
    let (tail, mut have) = if file.first_cluster == 0 {
        (None, 0)
    } else {
        let (tail, have) = last(volume, file.first_cluster)?;
        (Some(tail), have)
    };
    if have >= needed {
        return Ok(None);
    }
    let added = allocate(volume, tail)?;
    let growth = Growth { tail, added };
    let mut end = added;
    while have + 1 < needed {
        match allocate(volume, Some(end)) {
            Ok(cluster) => end = cluster,
            Err(status) => {
                growth.give_back(volume)?;
                return Err(status);
            }
        }
        have += 1;
    }
    if tail.is_none() {
        file.first_cluster = added;
    }
    Ok(Some(growth))
}

/// Write `data` at byte `offset` of `file`, whose chain covers the span: whole sectors written
/// directly, partial ones read, patched and written back.
fn write_span(volume: &mut Volume, file: &File, offset: u32, data: &[u8]) -> Result<(), NtStatus> {
    let size = cluster_bytes(volume);
    let mut cluster = nth(volume, file.first_cluster, offset / size)?;
    let mut position = offset;
    let mut done = 0;
    while done < data.len() {
        let within = position % size;
        let lba = volume.layout().cluster_lba(cluster) + (within / 512) as u64;
        let at = (within % 512) as usize;
        let take = (512 - at).min(data.len() - done);
        let mut sector = [0u8; 512];
        if take != 512 {
            volume.read_sector(lba, &mut sector)?;
        }
        sector[at..at + take].copy_from_slice(&data[done..done + take]);
        volume.write_sector(lba, &sector)?;
        done += take;
        position += take as u32;
        if done < data.len() && position % size == 0 {
            cluster = next(volume, cluster)?.ok_or(STATUS_FILE_CORRUPT_ERROR)?;
        }
    }
    Ok(())
}

/// Zero `file`'s bytes `[from, to)` within its chain.
fn zero_span(volume: &mut Volume, file: &File, from: u32, to: u32) -> Result<(), NtStatus> {
    let zeros = [0u8; 512];
    let mut at = from;
    while at < to {
        let take = (to - at).min(512 - at % 512);
        write_span(volume, file, at, &zeros[..take as usize])?;
        at += take;
    }
    Ok(())
}

/// Grow `file` to `size`: its chain extended (fresh clusters are zeros), and the bytes past the old
/// end in its old last cluster zeroed. All of it or, on a failure, none: the clusters added are
/// given back. The clusters added, for a caller whose later step fails to give back.
fn grow(volume: &mut Volume, file: &mut File, size: u32) -> Result<Option<Growth>, NtStatus> {
    // What the old chain covers, in u64: a size near 4 GiB rounds up past u32.
    let had = if file.first_cluster == 0 {
        0
    } else {
        let cluster = u64::from(cluster_bytes(volume));
        u64::from(file.size).div_ceil(cluster) * cluster
    };
    let before = file.first_cluster;
    let growth = reserve(volume, file, size)?;
    let zero_to = u64::from(size).min(had) as u32;
    if let Err(status) = zero_span(volume, file, file.size, zero_to) {
        if let Some(growth) = growth {
            let _ = growth.give_back(volume);
        }
        file.first_cluster = before;
        return Err(status);
    }
    file.size = size;
    Ok(growth)
}

/// Write `data` at byte `offset` of `file` (a file), growing it as the write needs (a gap before
/// the offset reads as zeros), and record its entry. A failure gives back the clusters the write
/// added and leaves `file` as it was: the caller does not keep it, so clusters it alone named
/// would be lost.
pub fn write_at(
    volume: &mut Volume,
    file: &mut File,
    offset: u32,
    data: &[u8],
) -> Result<(), NtStatus> {
    if data.is_empty() {
        return Ok(());
    }
    let end = offset
        .checked_add(data.len() as u32)
        .ok_or(STATUS_DISK_FULL)?;
    let before = *file;
    let growth = if end > file.size {
        grow(volume, file, end)?
    } else {
        None
    };
    let written = write_span(volume, file, offset, data).and_then(|()| update_entry(volume, file));
    if let Err(status) = written {
        if let Some(growth) = growth {
            let _ = growth.give_back(volume);
        }
        *file = before;
        return Err(status);
    }
    Ok(())
}

/// Set `file`'s size: a shrink frees the clusters past the new end, a growth adds zeros. Records
/// its entry — a shrink before it trims the chain, so a crash in between leaves clusters past the
/// size (lost to chkdsk), never a size past the chain's end. A growth whose entry cannot be
/// recorded gives its clusters back and leaves `file` as it was.
pub fn set_size(volume: &mut Volume, file: &mut File, size: u32) -> Result<(), NtStatus> {
    if size >= file.size {
        let before = *file;
        let growth = if size > file.size {
            grow(volume, file, size)?
        } else {
            None
        };
        if let Err(status) = update_entry(volume, file) {
            if let Some(growth) = growth {
                let _ = growth.give_back(volume);
            }
            *file = before;
            return Err(status);
        }
        return Ok(());
    }
    let needed = size.div_ceil(cluster_bytes(volume));
    let first = file.first_cluster;
    // The tail is found before anything changes: a broken chain fails the call untouched.
    let tail = if needed == 0 {
        None
    } else {
        Some(nth(volume, first, needed - 1)?)
    };
    file.size = size;
    if tail.is_none() {
        file.first_cluster = 0;
    }
    update_entry(volume, file)?;
    match tail {
        None => free_chain(volume, first),
        Some(tail) => match next(volume, tail)? {
            Some(rest) => {
                volume.set_fat_entry(tail, END_OF_CHAIN)?;
                free_chain(volume, rest)
            }
            None => Ok(()),
        },
    }
}

// --- Directory records ------------------------------------------------------------------------

/// Where record `index` of the directory starting at `first` lives: its sector and its place among
/// the sector's records.
fn record_at(volume: &mut Volume, first: u32, index: u32) -> Result<(u64, usize), NtStatus> {
    const PER_SECTOR: u32 = 512 / ENTRY_SIZE as u32;
    let per_cluster = volume.layout().sectors_per_cluster * PER_SECTOR;
    let cluster = nth(volume, first, index / per_cluster)?;
    let within = index % per_cluster;
    Ok((
        volume.layout().cluster_lba(cluster) + (within / PER_SECTOR) as u64,
        (within % PER_SECTOR) as usize,
    ))
}

fn read_record(volume: &mut Volume, first: u32, index: u32) -> Result<RecordBytes, NtStatus> {
    let (lba, slot) = record_at(volume, first, index)?;
    let mut sector = [0u8; 512];
    volume.read_sector(lba, &mut sector)?;
    Ok(sector.as_chunks::<ENTRY_SIZE>().0[slot])
}

fn write_record(
    volume: &mut Volume,
    first: u32,
    index: u32,
    record: &RecordBytes,
) -> Result<(), NtStatus> {
    let (lba, slot) = record_at(volume, first, index)?;
    let mut sector = [0u8; 512];
    volume.read_sector(lba, &mut sector)?;
    sector.as_chunks_mut::<ENTRY_SIZE>().0[slot] = *record;
    volume.write_sector(lba, &sector)
}

/// Patch a record's fields from `file`: attributes, first cluster, size (none for a directory),
/// times.
fn patch(record: &mut RawDirEntry, file: &File) {
    record.attr = file.attributes;
    record.set_times(&file.times);
    record.set_first_cluster(file.first_cluster);
    record.size.set(if file.directory { 0 } else { file.size });
}

/// Record `file`'s attributes, first cluster, size and times in its entry (the root has none).
pub fn update_entry(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    if file.parent_cluster == 0 {
        return Ok(());
    }
    let mut record = RawDirEntry::read(&read_record(volume, file.parent_cluster, file.index)?);
    patch(&mut record, file);
    write_record(volume, file.parent_cluster, file.index, &record.bytes())
}

/// The index of the first run of `count` free records (deleted, or at and past the end) of the
/// directory starting at `first`, the directory grown by fresh clusters when it has none.
fn free_run(volume: &mut Volume, first: u32, count: u32) -> Result<u32, NtStatus> {
    let per_cluster = cluster_bytes(volume) / ENTRY_SIZE as u32;
    let mut cluster = first;
    let mut index = 0u32;
    let (mut start, mut run) = (0u32, 0u32);
    let mut ended = false;
    for _ in 0..volume.layout().cluster_count {
        // The first cluster comes from the directory's entry, which may be corrupt.
        if !volume.layout().is_data_cluster(cluster) {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        let lba = volume.layout().cluster_lba(cluster);
        for sector_index in 0..volume.layout().sectors_per_cluster as u64 {
            let mut sector = [0u8; 512];
            volume.read_sector(lba + sector_index, &mut sector)?;
            for bytes in sector.as_chunks::<ENTRY_SIZE>().0 {
                let record = decode(bytes);
                ended |= record == Record::End;
                if ended || record == Record::Deleted {
                    if run == 0 {
                        start = index;
                    }
                    run += 1;
                    if run == count {
                        return Ok(start);
                    }
                } else {
                    run = 0;
                }
                index += 1;
            }
        }
        match next(volume, cluster)? {
            Some(following) => cluster = following,
            None => {
                // Grow: each fresh cluster is all end markers.
                if run == 0 {
                    start = index;
                }
                while run < count {
                    cluster = allocate(volume, Some(cluster))?;
                    run += per_cluster;
                }
                return Ok(start);
            }
        }
    }
    Err(STATUS_FILE_CORRUPT_ERROR)
}

/// Whether the directory starting at `first` has an entry whose stored 8.3 name is `name`.
fn short_taken(volume: &mut Volume, first: u32, name: &[u8; 11]) -> Result<bool, NtStatus> {
    let mut taken = false;
    walk(volume, first, |listed| {
        taken = listed.entry.name == *name;
        !taken
    })
    .map_err(corrupt)?;
    Ok(taken)
}

/// The NT case bits a valid 8.3 name needs, or none when a part mixes cases or has a lower-case
/// letter outside ASCII, which the bits do not restore (a long name holds the case then).
fn case_bits(name: &[u8]) -> Option<u8> {
    let (base, extension) = match name.iter().position(|&b| b == b'.') {
        Some(dot) => (&name[..dot], &name[dot + 1..]),
        None => (name, &[][..]),
    };
    // Whether a byte outside ASCII is a letter in lower (or upper) case.
    let cased = |byte: u8, lower: bool| {
        let unit = MB_TO_WC[byte as usize];
        !byte.is_ascii() && map_case(unit, lower) != unit
    };
    let part = |part: &[u8], lower_bit: u8| {
        if part.iter().any(|&b| cased(b, true)) {
            return None;
        }
        let lower = part.iter().any(u8::is_ascii_lowercase);
        let upper = part
            .iter()
            .any(|&b| b.is_ascii_uppercase() || cased(b, false));
        match (lower, upper) {
            (true, true) => None,
            (true, false) => Some(lower_bit),
            _ => Some(0),
        }
    };
    Some(part(base, CASE_LOWER_BASE)? | part(extension, CASE_LOWER_EXTENSION)?)
}

/// The basis of a generated 8.3 alias: the base (up to 8 bytes) and the extension (up to 3). A
/// character code page 437 cannot hold, even by best fit, is left out (the fswrite capture:
/// `\x80uro.txt` is `URO~1.TXT`).
fn alias_basis(name: &[u8]) -> ([u8; 8], usize, [u8; 3], usize) {
    let fold = |byte: u8| -> Option<u8> {
        match byte {
            b' ' | b'.' => None,
            b'+' | b',' | b';' | b'=' | b'[' | b']' => Some(b'_'),
            _ => oem_upper_fit(byte),
        }
    };
    let trimmed = {
        let start = name.iter().position(|&b| b != b'.').unwrap_or(name.len());
        &name[start..]
    };
    let (base, extension) = match trimmed.iter().rposition(|&b| b == b'.') {
        Some(dot) => (&trimmed[..dot], &trimmed[dot + 1..]),
        None => (trimmed, &[][..]),
    };
    let (mut b, mut bl) = ([b' '; 8], 0);
    for byte in base.iter().filter_map(|&byte| fold(byte)) {
        if bl == 8 {
            break;
        }
        b[bl] = byte;
        bl += 1;
    }
    let (mut e, mut el) = ([b' '; 3], 0);
    for byte in extension.iter().filter_map(|&byte| fold(byte)) {
        if el == 3 {
            break;
        }
        e[el] = byte;
        el += 1;
    }
    (b, bl, e, el)
}

/// A generated 8.3 alias for `name` in the directory starting at `first`.
fn alias(volume: &mut Volume, first: u32, name: &[u8]) -> Result<[u8; 11], NtStatus> {
    let (base, base_len, extension, extension_len) = alias_basis(name);
    let base_len = base_len.max(1);
    for n in 1..=999_999u32 {
        let mut digits = [0u8; 7];
        let mut len = 0;
        let mut value = n;
        while value > 0 {
            digits[len] = b'0' + (value % 10) as u8;
            value /= 10;
            len += 1;
        }
        let keep = base_len.min(8 - 1 - len);
        let mut stored = [b' '; 11];
        for (i, &byte) in base[..keep].iter().enumerate() {
            stored[i] = if byte == b' ' { b'_' } else { byte };
        }
        stored[keep] = b'~';
        for i in 0..len {
            stored[keep + 1 + i] = digits[len - 1 - i];
        }
        stored[8..8 + extension_len].copy_from_slice(&extension[..extension_len]);
        if !short_taken(volume, first, &stored)? {
            return Ok(stored);
        }
    }
    Err(STATUS_OBJECT_NAME_INVALID)
}

/// A short record.
fn short_record(name: &[u8; 11], case: u8, file: &File) -> RecordBytes {
    let mut record = RawDirEntry::zeroed();
    record.set_short_name(name);
    record.nt_res = case;
    patch(&mut record, file);
    record.bytes()
}

/// Make a new entry named `name` in the directory starting at `parent` for `file` (its first
/// cluster, size, attributes and times); the entry's identity is filled in. The caller has checked
/// that no entry answers to the name. The long-name parts go first and the 8.3 record last, which
/// makes the entry; when a write fails, the records written before it are marked deleted again
/// (best effort), so no orphaned part keeps their places.
pub fn create_entry(
    volume: &mut Volume,
    parent: u32,
    name: &[u8],
    file: &mut File,
) -> Result<(), NtStatus> {
    if name.is_empty() || name.len() > MAX_LONG {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let (stored, case, long) = match short_form(name) {
        Some(stored) => match case_bits(name) {
            Some(case) => (stored, case, false),
            None => (stored, 0, true),
        },
        None => (alias(volume, parent, name)?, 0, true),
    };
    let parts = if long {
        name.len().div_ceil(PART_UNITS)
    } else {
        0
    };
    let start = free_run(volume, parent, parts as u32 + 1)?;
    let mut entry = *file;
    entry.parent_cluster = parent;
    entry.index = start + parts as u32;
    let mut written = 0;
    let mut write = |volume: &mut Volume, record: &RecordBytes| {
        write_record(volume, parent, start + written, record)?;
        written += 1;
        Ok(())
    };
    let made = (|| {
        if long {
            let mut units = [0xFFFFu16; 20 * PART_UNITS];
            for (unit, &byte) in units.iter_mut().zip(name) {
                *unit = decode_byte(byte);
            }
            if name.len() % PART_UNITS != 0 {
                units[name.len()] = 0;
            }
            let sum = checksum(&stored);
            let chunks = units.as_chunks::<PART_UNITS>().0;
            for order in (1..=parts).rev() {
                let part = LongPart {
                    order: order as u8,
                    last: order == parts,
                    checksum: sum,
                    units: chunks[order - 1],
                };
                write(volume, &part.record().bytes())?;
            }
        }
        write(volume, &short_record(&stored, case, &entry))
    })();
    if let Err(status) = made {
        for index in start..start + written {
            let mut record = [0; ENTRY_SIZE];
            record[0] = DELETED;
            let _ = write_record(volume, parent, index, &record);
        }
        return Err(status);
    }
    *file = entry;
    Ok(())
}

/// The most records an entry has: twenty long-name parts and its 8.3 record.
const MAX_RECORDS: usize = 21;

/// An entry's records as they were: the long name's parts then the 8.3 record, `count` of them
/// ending at record `last` of the directory starting at `parent`, kept whole (the 8.3 record
/// first, then the parts backwards) so a removal, or records written over them since, can be
/// undone.
struct Entry {
    parent: u32,
    last: u32,
    count: u32,
    records: [RecordBytes; MAX_RECORDS],
}

impl Entry {
    /// `file`'s entry's records, read (nothing is written): its 8.3 record and the long-name parts
    /// before it that carry its checksum.
    fn of(volume: &mut Volume, file: &File) -> Result<Entry, NtStatus> {
        let mut entry = Entry {
            parent: file.parent_cluster,
            last: file.index,
            count: 1,
            records: [[0; ENTRY_SIZE]; MAX_RECORDS],
        };
        entry.records[0] = read_record(volume, file.parent_cluster, file.index)?;
        let sum = checksum(&RawDirEntry::read(&entry.records[0]).short_name());
        while entry.count <= file.index && (entry.count as usize) < MAX_RECORDS {
            let bytes = read_record(volume, file.parent_cluster, file.index - entry.count)?;
            let part = RawLongEntry::read(&bytes);
            if part.attr != ATTR_LONG_NAME || part.ord == DELETED || part.checksum != sum {
                break;
            }
            entry.records[entry.count as usize] = bytes;
            entry.count += 1;
            if part.ord & LAST_LONG_PART != 0 {
                break;
            }
        }
        Ok(entry)
    }

    /// Mark the records deleted, the 8.3 record first: its write is the removal (a failure there
    /// changes nothing). A long-name part that fails after it stays as an orphaned part, which a
    /// walk ignores, so the removal stands.
    fn remove(&self, volume: &mut Volume) -> Result<(), NtStatus> {
        for k in 0..self.count {
            let mut bytes = self.records[k as usize];
            bytes[0] = DELETED;
            let written = write_record(volume, self.parent, self.last - k, &bytes);
            if k == 0 {
                written?;
            }
        }
        Ok(())
    }

    /// Put the records back as they were, the 8.3 record last (best effort: this undoes a step
    /// that already failed, so a further failure has no one to report to).
    fn restore(&self, volume: &mut Volume) {
        for k in (0..self.count).rev() {
            let _ = write_record(
                volume,
                self.parent,
                self.last - k,
                &self.records[k as usize],
            );
        }
    }
}

/// Remove `file`'s entry: its 8.3 record and the long-name records before it marked deleted. Its
/// clusters stay.
pub fn remove_entry(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    Entry::of(volume, file)?.remove(volume)
}

/// Delete `file`: its entry removed and its clusters freed.
pub fn delete(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    remove_entry(volume, file)?;
    if file.first_cluster != 0 {
        free_chain(volume, file.first_cluster)?;
    }
    Ok(())
}

/// Whether the directory starting at `directory` is the one starting at `ancestor` or lies
/// beneath it: its `..` records followed up to the root. A `..` record that is none, or a chain of
/// them that loops, is corruption.
fn within(volume: &mut Volume, ancestor: u32, mut directory: u32) -> Result<bool, NtStatus> {
    let root = volume.layout().root_cluster;
    for _ in 0..volume.layout().cluster_count {
        if directory == ancestor {
            return Ok(true);
        }
        if directory == root || directory == 0 {
            return Ok(false);
        }
        let up = RawDirEntry::read(&read_record(volume, directory, 1)?);
        if up.short_name() != DOT_DOT {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        directory = up.first_cluster();
    }
    Err(STATUS_FILE_CORRUPT_ERROR)
}

/// Give `file` the name `name` in the directory starting at `parent` (its own or another),
/// replacing `replacing` — an entry of that directory answering to the name, which the caller has
/// found may go — when there is one: a new entry for the same clusters, the old one removed, a
/// directory moved elsewhere having its `..` record follow, and the replaced entry's clusters
/// freed. Returns the entry's new identity.
///
/// A directory never moves into itself or beneath itself (STATUS_ACCESS_DENIED: FastFat refuses to
/// rename a directory with an open file beneath it, and the I/O manager's open of the target's
/// directory is one). Everything is checked and read before anything is written, and every step
/// that fails undoes the ones before it: the call fails with the old names in place, or succeeds
/// with the new — never a name lost, nor two entries sharing clusters. The replaced entry's
/// clusters are freed last, once the rename stands; a failure there leaves them lost (to chkdsk),
/// not shared.
pub fn rename(
    volume: &mut Volume,
    file: &File,
    parent: u32,
    name: &[u8],
    replacing: Option<&File>,
) -> Result<File, NtStatus> {
    if name.is_empty() || name.len() > MAX_LONG {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let moves_directory =
        file.directory && parent != file.parent_cluster && file.first_cluster != 0;
    if moves_directory && within(volume, file.first_cluster, parent)? {
        return Err(STATUS_ACCESS_DENIED);
    }
    let source = Entry::of(volume, file)?;
    let replaced = match replacing {
        Some(replacing) => Some(Entry::of(volume, replacing)?),
        None => None,
    };
    let dotdot = if moves_directory {
        Some(read_record(volume, file.first_cluster, 1)?)
    } else {
        None
    };
    // The replaced entry goes first, its records and its 8.3 name free for the new entry, as when
    // the name was free (restored if a later step fails).
    if let Some(replaced) = &replaced {
        replaced.remove(volume)?;
    }
    let undo_replace = |volume: &mut Volume| {
        if let Some(replaced) = &replaced {
            replaced.restore(volume);
        }
    };
    let mut moved = *file;
    if let Err(status) = create_entry(volume, parent, name, &mut moved) {
        undo_replace(volume);
        return Err(status);
    }
    let undo_create = |volume: &mut Volume| {
        let _ = remove_entry(volume, &moved);
        undo_replace(volume);
    };
    if let Some(old) = dotdot {
        let mut up = RawDirEntry::read(&old);
        up.set_first_cluster(if parent == volume.layout().root_cluster {
            0
        } else {
            parent
        });
        if let Err(status) = write_record(volume, file.first_cluster, 1, &up.bytes()) {
            undo_create(volume);
            return Err(status);
        }
    }
    if let Err(status) = source.remove(volume) {
        if let Some(old) = dotdot {
            let _ = write_record(volume, file.first_cluster, 1, &old);
        }
        undo_create(volume);
        return Err(status);
    }
    if let Some(replacing) = replacing {
        let _ = free_chain(volume, replacing.first_cluster);
    }
    Ok(moved)
}

/// Make a directory named `name` in the directory starting at `parent`, with `times`: a fresh
/// cluster holding its `.` and `..` records.
pub fn make_directory(
    volume: &mut Volume,
    parent: u32,
    name: &[u8],
    times: Times,
) -> Result<File, NtStatus> {
    let cluster = allocate(volume, None)?;
    let mut directory = File::plain(cluster, 0, true);
    directory.times = times;
    let up = if parent == volume.layout().root_cluster {
        0
    } else {
        parent
    };
    let mut up_file = File::plain(up, 0, true);
    up_file.times = times;
    let made = write_record(volume, cluster, 0, &short_record(&DOT, 0, &directory))
        .and_then(|()| write_record(volume, cluster, 1, &short_record(&DOT_DOT, 0, &up_file)))
        .and_then(|()| create_entry(volume, parent, name, &mut directory));
    if let Err(status) = made {
        free_chain(volume, cluster)?;
        return Err(status);
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::super::dir::is_empty;
    use super::super::fixtures::{file_bytes, Crafted, Crashing};
    use super::super::lookup::{lookup, root};
    use super::super::read::read_at;
    use super::*;

    fn volume(clusters: usize) -> Volume {
        Volume::mount(Crafted::new(1, clusters).writable()).unwrap()
    }

    fn new_file(volume: &mut Volume, name: &[u8]) -> File {
        let parent = root(volume).first_cluster;
        let mut file = File::plain(0, 0, false);
        file.attributes = 0x20;
        create_entry(volume, parent, name, &mut file).unwrap();
        file
    }

    fn contents(volume: &mut Volume, path: &[u8]) -> Vec<u8> {
        let file = lookup(volume, path).unwrap();
        let mut out = vec![0u8; file.size as usize];
        read_at(volume, &file, 0, &mut out).unwrap();
        out
    }

    /// A file written in pieces across clusters reads back; its entry records the size.
    #[test]
    fn writes_grow_a_file_across_clusters() {
        let mut v = volume(40);
        let mut file = new_file(&mut v, b"DATA.BIN");
        let bytes = file_bytes(5000);
        for (i, piece) in bytes.chunks(777).enumerate() {
            write_at(&mut v, &mut file, (i * 777) as u32, piece).unwrap();
        }
        assert_eq!(lookup(&mut v, b"DATA.BIN").unwrap().size, 5000);
        assert_eq!(contents(&mut v, b"DATA.BIN"), bytes);
    }

    /// A write past the end leaves zeros in the gap, even where a truncation left old bytes.
    #[test]
    fn gaps_and_regrowth_read_as_zeros() {
        let mut v = volume(40);
        let mut file = new_file(&mut v, b"GAP.BIN");
        write_at(&mut v, &mut file, 0, &[0xAA; 1500]).unwrap();
        set_size(&mut v, &mut file, 100).unwrap();
        set_size(&mut v, &mut file, 1400).unwrap();
        write_at(&mut v, &mut file, 3000, b"far").unwrap();
        let data = contents(&mut v, b"GAP.BIN");
        assert_eq!(data.len(), 3003);
        assert!(data[..100].iter().all(|&b| b == 0xAA));
        assert!(data[100..3000].iter().all(|&b| b == 0));
        assert_eq!(&data[3000..], b"far");
    }

    /// Truncation to zero frees the chain; the clusters come back for the next file.
    #[test]
    fn truncation_frees_clusters() {
        let mut v = volume(12);
        let mut file = new_file(&mut v, b"BIG.BIN");
        write_at(&mut v, &mut file, 0, &file_bytes(4000)).unwrap();
        let first = file.first_cluster;
        set_size(&mut v, &mut file, 0).unwrap();
        assert_eq!(file.first_cluster, 0);
        assert_eq!(v.fat_entry(first).unwrap(), FatEntry::Free);
        v.set_next_free(2);
        let mut other = new_file(&mut v, b"NEXT.BIN");
        write_at(&mut v, &mut other, 0, b"x").unwrap();
        assert_eq!(other.first_cluster, first);
    }

    fn free_clusters(volume: &mut Volume) -> u32 {
        let max = volume.layout().max_cluster();
        (2..=max)
            .filter(|&cluster| volume.fat_entry(cluster) == Ok(FatEntry::Free))
            .count() as u32
    }

    /// Disk full: a write needing more clusters than the volume has free fails with nothing
    /// allocated, whether they would have been a new file's first or a growing file's next
    /// (otherwise the first ones would leak). What fits is still written.
    #[test]
    fn a_write_that_does_not_fit_allocates_nothing() {
        let mut v = Volume::mount(Crafted::full(6).writable()).unwrap();
        assert_eq!(free_clusters(&mut v), 5);
        let mut file = new_file(&mut v, b"NEW.BIN");
        assert_eq!(
            write_at(&mut v, &mut file, 0, &[1; 6 * 512]),
            Err(STATUS_DISK_FULL)
        );
        assert_eq!((file.first_cluster, file.size), (0, 0));
        assert_eq!(
            free_clusters(&mut v),
            5,
            "the new file's clusters were given back"
        );
        let entry = lookup(&mut v, b"NEW.BIN").unwrap();
        assert_eq!((entry.first_cluster, entry.size), (0, 0));

        write_at(&mut v, &mut file, 0, &[1; 1024]).unwrap();
        assert_eq!(free_clusters(&mut v), 3);
        assert_eq!(
            write_at(&mut v, &mut file, 1024, &[2; 4 * 512]),
            Err(STATUS_DISK_FULL)
        );
        assert_eq!(
            free_clusters(&mut v),
            3,
            "the growth's clusters were given back"
        );
        assert_eq!(last(&mut v, file.first_cluster).unwrap().1, 2);
        assert_eq!(contents(&mut v, b"NEW.BIN"), [1; 1024]);

        write_at(&mut v, &mut file, 1024, &[2; 3 * 512]).unwrap();
        assert_eq!(free_clusters(&mut v), 0);
        assert_eq!(contents(&mut v, b"NEW.BIN").len(), 1024 + 3 * 512);
    }

    /// A write or a growth with one of its device writes failing — each in turn — fails with the
    /// clusters it took given back and the file as it was (its caller keeps the old copy, so
    /// clusters only the new one named were lost): a new file's first write, an existing file's
    /// growth, and a size set past the end.
    #[test]
    fn a_failed_growth_gives_its_clusters_back() {
        for case in 0..3 {
            for n in 0.. {
                let crashing = Crashing::over(Crafted::full(12).writable());
                let mut v = Volume::mount(crashing).unwrap();
                let mut file = new_file(&mut v, b"GROW.BIN");
                if case != 0 {
                    write_at(&mut v, &mut file, 0, &[1; 700]).unwrap();
                }
                let (before, free) = (file, free_clusters(&mut v));
                crashing.fail_write(n);
                let grown = match case {
                    0 => write_at(&mut v, &mut file, 0, &file_bytes(3 * 512)),
                    1 => write_at(&mut v, &mut file, 1500, &file_bytes(1000)),
                    _ => set_size(&mut v, &mut file, 3000),
                };
                if grown.is_err() {
                    assert_eq!(file, before, "case {case}, write {n}");
                    assert_eq!(free_clusters(&mut v), free, "case {case}, write {n}");
                    let entry = lookup(&mut v, b"GROW.BIN").unwrap();
                    assert_eq!(
                        (entry.first_cluster, entry.size),
                        (before.first_cluster, before.size)
                    );
                }
                if !crashing.failed() {
                    assert!(grown.is_ok());
                    break;
                }
            }
        }
    }

    /// A file whose size rounds up past 4 GiB (its last cluster's end) grows without overflowing:
    /// the volume has not the room, so STATUS_DISK_FULL, nothing taken.
    #[test]
    fn a_growth_near_4_gib_does_not_overflow() {
        let mut crafted = Crafted::full(4);
        crafted
            .directory(
                2,
                &[super::super::fixtures::record(
                    b"HUGE    BIN",
                    0x20,
                    3,
                    0xFFFF_FE01,
                )],
            )
            .chain(&[3]);
        let mut v = Volume::mount(crafted.writable()).unwrap();
        let mut file = lookup(&mut v, b"HUGE.BIN").unwrap();
        let free = free_clusters(&mut v);
        assert_eq!(set_size(&mut v, &mut file, u32::MAX), Err(STATUS_DISK_FULL));
        assert_eq!(
            write_at(&mut v, &mut file, 0xFFFF_FFF0, &[1; 15]),
            Err(STATUS_DISK_FULL)
        );
        assert_eq!(free_clusters(&mut v), free);
        assert_eq!(file.size, 0xFFFF_FE01);
    }

    /// A shrink records the smaller size before it frees the clusters past it: a crash after any
    /// of its writes leaves an entry whose size its chain covers (otherwise the chain would be
    /// trimmed first, leaving a size past the chain's end).
    #[test]
    fn a_shrink_records_the_size_before_trimming() {
        for budget in 0.. {
            let crashing = Crashing::over(Crafted::new(1, 20).writable());
            let mut v = Volume::mount(crashing).unwrap();
            let mut file = new_file(&mut v, b"SHRINK.BIN");
            write_at(&mut v, &mut file, 0, &file_bytes(5 * 512)).unwrap();
            crashing.crash_after(budget);
            set_size(&mut v, &mut file, 512).unwrap();
            let mut after = Volume::mount(crashing.image()).unwrap();
            let entry = lookup(&mut after, b"SHRINK.BIN").unwrap();
            let (_, chain) = last(&mut after, entry.first_cluster).unwrap();
            let size = entry.size;
            assert!(
                size <= chain * 512,
                "after {budget} writes: size {size} over {chain} clusters"
            );
            if crashing.dropped() == 0 {
                assert_eq!((entry.size, chain), (512, 1));
                break;
            }
        }
    }

    /// A corrupt directory entry fails the call instead of panicking the kernel: creating
    /// an entry or a directory in a subdirectory whose entry names cluster 0, 1, or one past the
    /// volume is corruption, and the new directory's cluster is given back.
    #[test]
    fn creating_in_a_corrupt_directory_is_corruption() {
        for bad in [0, 1, 70_002, 0x0123_4567] {
            let mut crafted = Crafted::new(1, 8);
            crafted.directory(
                2,
                &[super::super::fixtures::record(b"SUB        ", 0x10, bad, 0)],
            );
            let mut v = Volume::mount(crafted.writable()).unwrap();
            let sub = lookup(&mut v, b"SUB").unwrap();
            let mut file = File::plain(0, 0, false);
            assert_eq!(
                create_entry(&mut v, sub.first_cluster, b"NEW.TXT", &mut file),
                Err(STATUS_FILE_CORRUPT_ERROR),
                "cluster {bad:#x}"
            );
            assert_eq!(
                make_directory(
                    &mut v,
                    sub.first_cluster,
                    b"A Long Directory",
                    Times::default()
                )
                .err(),
                Some(STATUS_FILE_CORRUPT_ERROR)
            );
            assert_eq!(v.fat_entry(3), Ok(FatEntry::Free));
        }
    }

    /// A long name gets long-name records and a generated alias; both find it, and a second one
    /// with the same basis takes ~2. A lower-case 8.3 name keeps its case without a long name.
    #[test]
    fn names_long_and_short() {
        let mut v = volume(20);
        new_file(&mut v, b"A Long Created Name.txt");
        new_file(&mut v, b"A Long Created Other.txt");
        assert!(lookup(&mut v, b"ALONGC~1.TXT").is_ok());
        assert!(lookup(&mut v, b"a long created name.TXT").is_ok());
        assert_eq!(
            lookup(&mut v, b"ALONGC~2.TXT").unwrap().index,
            lookup(&mut v, b"A Long Created Other.txt").unwrap().index
        );
        let lower = new_file(&mut v, b"crt.txt");
        assert_eq!(lookup(&mut v, b"CRT.TXT").unwrap().index, lower.index);
        let mut seen = Vec::new();
        let root_cluster = root(&v).first_cluster;
        walk(&mut v, root_cluster, |listed| {
            let mut name = [0u8; 255];
            let n = listed.name(&mut name);
            seen.push(String::from_utf8_lossy(&name[..n]).into_owned());
            true
        })
        .unwrap();
        assert_eq!(
            seen,
            [
                "A Long Created Name.txt",
                "A Long Created Other.txt",
                "crt.txt"
            ]
        );
    }

    /// The names a listing shows for the root's entries: the long (or case-applied) name and the
    /// 8.3 name as stored.
    fn listing(volume: &mut Volume) -> Vec<(String, String)> {
        let mut seen = Vec::new();
        let root_cluster = root(volume).first_cluster;
        walk(volume, root_cluster, |listed| {
            let (mut name, mut short) = ([0u8; 255], [0u8; 12]);
            let (n, s) = (listed.name(&mut name), listed.short_name(&mut short));
            seen.push((
                String::from_utf8_lossy(&name[..n]).into_owned(),
                String::from_utf8_lossy(&short[..s]).into_owned(),
            ));
            true
        })
        .unwrap();
        seen
    }

    /// A valid 8.3 name with a part in mixed case keeps the name itself, upper-cased, as its 8.3
    /// name beside a long name that holds the case — no `~N` alias: the FAT specification's
    /// numeric-tail rule (fatgen103: no tail when the name fits 8.3 without a lossy conversion and
    /// the basis collides with no short name — and none can, since an entry answers to its short
    /// name in any case), and FastFat's name selection. A long name with the same basis still
    /// starts at `~1`.
    #[test]
    fn a_mixed_case_8_3_name_is_its_own_short_name() {
        let mut v = volume(20);
        new_file(&mut v, b"Readme.txt");
        new_file(&mut v, b"NOTES.Txt");
        new_file(&mut v, b"MiXeD");
        new_file(&mut v, b"Readme file.txt");
        assert_eq!(
            listing(&mut v),
            [
                ("Readme.txt".into(), "README.TXT".into()),
                ("NOTES.Txt".into(), "NOTES.TXT".into()),
                ("MiXeD".into(), "MIXED".into()),
                ("Readme file.txt".into(), "README~1.TXT".into()),
            ]
        );
        for name in [&b"README.TXT"[..], b"readme.txt", b"notes.txt", b"mixed"] {
            assert!(
                lookup(&mut v, name).is_ok(),
                "{:?}",
                core::str::from_utf8(name)
            );
        }
    }

    /// Short names go to disk in code page 437. A valid 8.3 name with a 1252 letter is
    /// stored upper-cased in 437: alone when it is in upper case, beside a long name holding the
    /// case when a letter outside ASCII is in lower case (the NT case bits restore ASCII letters
    /// only). An alias folds through Unicode too, a character 437 lacks left out (the fswrite
    /// capture).
    #[test]
    fn short_names_are_stored_in_code_page_437() {
        let mut v = volume(20);
        for name in [
            &b"CAF\xC9.TXT"[..],
            b"caf\xE9s.txt",
            b"\x80uro.txt",
            b"\xE4rger file.txt",
        ] {
            new_file(&mut v, name);
        }
        let mut stored = Vec::new();
        let root_cluster = root(&v).first_cluster;
        walk(&mut v, root_cluster, |listed| {
            stored.push((
                listed.entry.name,
                listed.entry.case,
                listed.long_name().is_some(),
            ));
            true
        })
        .unwrap();
        assert_eq!(
            stored,
            [
                (*b"CAF\x90    TXT", 0, false),
                (*b"CAF\x90S   TXT", 0, true),
                (*b"URO~1   TXT", 0, true),
                (*b"\x8ERGERF~1TXT", 0, true),
            ]
        );
        assert_eq!(
            lookup(&mut v, b"caf\xE9.txt").unwrap().index,
            stored_index(&mut v, b"CAF\xC9.TXT")
        );
    }

    fn stored_index(volume: &mut Volume, name: &[u8]) -> u32 {
        lookup(volume, name).unwrap().index
    }

    /// Deleting an entry frees its records for reuse; a rename moves it, a directory's `..` too.
    #[test]
    fn delete_rename_and_directories() {
        let mut v = volume(30);
        let root_cluster = root(&v).first_cluster;
        let mut file = new_file(&mut v, b"A Long Created Name.txt");
        write_at(&mut v, &mut file, 0, b"long").unwrap();
        let dir = make_directory(&mut v, root_cluster, b"SUB", Times::default()).unwrap();
        assert!(is_empty(&mut v, dir.first_cluster).unwrap());
        let moved = rename(&mut v, &file, dir.first_cluster, b"MOVED.TXT", None).unwrap();
        assert_eq!(
            lookup(&mut v, b"A Long Created Name.txt"),
            Err(LookupError::NotFound)
        );
        assert_eq!(contents(&mut v, b"SUB\\MOVED.TXT"), b"long");
        assert!(!is_empty(&mut v, dir.first_cluster).unwrap());
        delete(&mut v, &moved).unwrap();
        assert!(is_empty(&mut v, dir.first_cluster).unwrap());
        let inner = make_directory(&mut v, dir.first_cluster, b"INNER", Times::default()).unwrap();
        let inner = rename(&mut v, &inner, root_cluster, b"OUTER", None).unwrap();
        assert!(lookup(&mut v, b"OUTER\\..\\SUB").is_ok());
        assert_eq!(
            read_record(&mut v, inner.first_cluster, 1).unwrap()[26],
            0,
            "`..` names the root"
        );
    }

    /// The entries of the directory starting at `cluster`, but its dot records: each one's name
    /// and first cluster.
    fn entries(volume: &mut Volume, cluster: u32) -> Vec<(String, u32)> {
        let mut seen = Vec::new();
        walk(volume, cluster, |listed| {
            if !listed.dot {
                let mut name = [0u8; 255];
                let n = listed.name(&mut name);
                seen.push((
                    String::from_utf8_lossy(&name[..n]).into_owned(),
                    listed.entry.first_cluster,
                ));
            }
            true
        })
        .unwrap();
        seen
    }

    /// Every entry of the tree beneath the directory starting at `cluster`, each with its path and
    /// first cluster; panics on two entries sharing a first cluster (a cross-link).
    fn tree(volume: &mut Volume, cluster: u32) -> Vec<(String, u32)> {
        let mut all = Vec::new();
        let mut pending = vec![(String::new(), cluster)];
        while let Some((path, cluster)) = pending.pop() {
            for (name, first) in entries(volume, cluster) {
                let path = format!("{path}\\{name}");
                if lookup(volume, path[1..].as_bytes()).unwrap().directory {
                    pending.push((path.clone(), first));
                }
                all.push((path, first));
            }
        }
        let mut clusters: Vec<u32> = all.iter().map(|&(_, c)| c).filter(|&c| c != 0).collect();
        clusters.sort();
        let count = clusters.len();
        clusters.dedup();
        assert_eq!(clusters.len(), count, "two entries share clusters: {all:?}");
        all.sort();
        all
    }

    /// A directory never moves into itself or beneath itself (a cycle that would cut the subtree
    /// off the root): STATUS_ACCESS_DENIED, nothing changed. Moving one up out of it is a rename
    /// like any other.
    #[test]
    fn a_directory_never_moves_beneath_itself() {
        let mut v = volume(30);
        let root_cluster = root(&v).first_cluster;
        let a = make_directory(&mut v, root_cluster, b"A", Times::default()).unwrap();
        let b = make_directory(&mut v, a.first_cluster, b"B", Times::default()).unwrap();
        let c = make_directory(&mut v, b.first_cluster, b"C", Times::default()).unwrap();
        let before = tree(&mut v, root_cluster);
        for (parent, name) in [
            (a.first_cluster, &b"A"[..]),
            (a.first_cluster, b"Moved"),
            (b.first_cluster, b"A"),
            (c.first_cluster, b"Moved Deep"),
        ] {
            assert_eq!(
                rename(&mut v, &a, parent, name, None),
                Err(STATUS_ACCESS_DENIED)
            );
            assert_eq!(
                rename(&mut v, &b, c.first_cluster, name, None),
                Err(STATUS_ACCESS_DENIED)
            );
        }
        assert_eq!(tree(&mut v, root_cluster), before);
        assert!(lookup(&mut v, b"A\\B\\C\\..\\..\\..\\A").is_ok());

        rename(&mut v, &c, a.first_cluster, b"C2", None).unwrap();
        rename(&mut v, &b, root_cluster, b"B2", None).unwrap();
        assert!(lookup(&mut v, b"A\\C2\\..\\..\\B2").is_ok());
    }

    /// A file of `bytes` named `name` in the directory starting at `parent`.
    fn file_in(volume: &mut Volume, parent: u32, name: &[u8], bytes: &[u8]) -> File {
        let mut file = File::plain(0, 0, false);
        file.attributes = 0x20;
        create_entry(volume, parent, name, &mut file).unwrap();
        write_at(volume, &mut file, 0, bytes).unwrap();
        file
    }

    /// A replacing rename that cannot make its new entry (the directory full, the volume too)
    /// fails with the replaced file still there, whole: the old order deleted it first.
    #[test]
    fn a_replacing_rename_that_fails_keeps_the_replaced_file() {
        let mut v = Volume::mount(Crafted::full(3).writable()).unwrap();
        let root_cluster = root(&v).first_cluster;
        let source = file_in(&mut v, root_cluster, b"SOURCE.TXT", b"source");
        let target = file_in(&mut v, root_cluster, b"TARGET.TXT", b"target");
        for i in 0..14 {
            file_in(&mut v, root_cluster, format!("F{i}").as_bytes(), b"");
        }
        let before = tree(&mut v, root_cluster);
        assert_eq!(
            rename(
                &mut v,
                &source,
                root_cluster,
                b"A long replacing name.txt",
                Some(&target)
            ),
            Err(STATUS_DISK_FULL)
        );
        assert_eq!(tree(&mut v, root_cluster), before);
        assert_eq!(contents(&mut v, b"TARGET.TXT"), b"target");
        assert_eq!(contents(&mut v, b"SOURCE.TXT"), b"source");
    }

    /// A rename with one of its writes failing — each in turn — fails with the old names in place
    /// (`..` too), or succeeds with the new (when the failing write only tidied up), never with an
    /// entry lost or two sharing clusters: a file renamed to a long name in another directory, a
    /// directory moved, and a file replacing another.
    #[test]
    fn a_rename_with_a_failing_write_keeps_the_old_names_or_the_new() {
        enum Case {
            File,
            Directory,
            Replace,
        }
        for case in [Case::File, Case::Directory, Case::Replace] {
            for n in 0.. {
                let crashing = Crashing::over(Crafted::new(1, 30).writable());
                let mut v = Volume::mount(crashing).unwrap();
                let root_cluster = root(&v).first_cluster;
                let dir = make_directory(&mut v, root_cluster, b"DIR", Times::default()).unwrap();
                let file = file_in(&mut v, root_cluster, b"A Long Source Name.txt", b"source");
                let moving =
                    make_directory(&mut v, root_cluster, b"MOVING", Times::default()).unwrap();
                file_in(&mut v, moving.first_cluster, b"IN.TXT", b"inside");
                let target = file_in(&mut v, dir.first_cluster, b"Target Name.txt", b"target");
                let old = tree(&mut v, root_cluster);
                crashing.fail_write(n);
                let (renamed, path, new_path) = match case {
                    Case::File => (
                        rename(
                            &mut v,
                            &file,
                            dir.first_cluster,
                            b"Moved Long Name.txt",
                            None,
                        ),
                        "A Long Source Name.txt",
                        "DIR\\Moved Long Name.txt",
                    ),
                    Case::Directory => (
                        rename(&mut v, &moving, dir.first_cluster, b"Moved Directory", None),
                        "MOVING\\IN.TXT",
                        "DIR\\Moved Directory\\IN.TXT",
                    ),
                    Case::Replace => (
                        rename(
                            &mut v,
                            &file,
                            dir.first_cluster,
                            b"target name.TXT",
                            Some(&target),
                        ),
                        "A Long Source Name.txt",
                        "DIR\\target name.TXT",
                    ),
                };
                let failed = crashing.failed();
                let mut after = Volume::mount(crashing.image()).unwrap();
                let now = tree(&mut after, root_cluster);
                let expected = if matches!(case, Case::Directory) {
                    b"inside"
                } else {
                    b"source"
                };
                match renamed {
                    Err(_) => {
                        assert!(failed);
                        assert_eq!(now, old, "write {n} failed: the old names");
                        assert_eq!(contents(&mut after, path.as_bytes()), expected);
                        if matches!(case, Case::Replace) {
                            assert_eq!(contents(&mut after, b"DIR\\TARGET~1.TXT"), b"target");
                        }
                    }
                    Ok(_) => {
                        assert_eq!(
                            lookup(&mut after, path.as_bytes()),
                            Err(LookupError::NotFound),
                            "write {n}: the old name is gone"
                        );
                        assert_eq!(contents(&mut after, new_path.as_bytes()), expected);
                        if matches!(case, Case::Directory) {
                            assert!(
                                lookup(&mut after, b"DIR\\Moved Directory\\..\\..\\DIR").is_ok()
                            );
                        }
                    }
                }
                if !failed {
                    break;
                }
            }
        }
    }

    /// A directory grows by a cluster when its records run out.
    #[test]
    fn a_directory_grows() {
        let mut v = volume(60);
        let root_cluster = root(&v).first_cluster;
        let dir = make_directory(&mut v, root_cluster, b"BIGDIR", Times::default()).unwrap();
        for i in 0..40 {
            let name = format!("F{i:03}.TXT");
            let mut file = File::plain(0, 0, false);
            create_entry(&mut v, dir.first_cluster, name.as_bytes(), &mut file).unwrap();
            write_at(&mut v, &mut file, 0, b"entry").unwrap();
        }
        let mut count = 0;
        walk(&mut v, dir.first_cluster, |listed| {
            count += usize::from(!listed.dot);
            true
        })
        .unwrap();
        assert_eq!(count, 40);
        assert_eq!(contents(&mut v, b"BIGDIR\\F039.TXT"), b"entry");
    }
}
