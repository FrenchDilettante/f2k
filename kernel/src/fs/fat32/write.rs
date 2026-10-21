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

use super::dir::{decode_byte, walk};
use super::dirent::{
    checksum,
    Times,
    ATTR_LONG_NAME,
    CASE_LOWER_BASE,
    CASE_LOWER_EXTENSION,
    ENTRY_SIZE,
};
use super::fat::FatEntry;
use super::lookup::{File, LookupError};
use super::path::{oem_upper_fit, short_form};
use super::volume::Volume;
use crate::status::{
    NtStatus,
    STATUS_DISK_FULL,
    STATUS_FILE_CORRUPT_ERROR,
    STATUS_OBJECT_NAME_INVALID,
};

/// The value that ends a chain.
const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
/// Units per long-name record.
const PART_UNITS: usize = 13;
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
pub fn allocate(volume: &mut Volume, previous: Option<u32>) -> Result<u32, NtStatus> {
    let count = volume.layout().cluster_count;
    let start = volume.next_free().clamp(2, count + 1);
    for step in 0..count {
        let cluster = 2 + (start - 2 + step) % count;
        if volume.fat_entry(cluster)? == FatEntry::Free {
            zero_cluster(volume, cluster)?;
            volume.set_fat_entry(cluster, END_OF_CHAIN)?;
            if let Some(previous) = previous {
                volume.set_fat_entry(previous, cluster)?;
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

/// Grow `file`'s chain to cover `bytes`: all of it or, when the volume runs out (or a device write
/// fails), none — the clusters taken so far are given back and the chain ends where it did.
fn reserve(volume: &mut Volume, file: &mut File, bytes: u32) -> Result<(), NtStatus> {
    let size = cluster_bytes(volume);
    let needed = bytes.div_ceil(size);
    let (tail, mut have) = if file.first_cluster == 0 {
        (None, 0)
    } else {
        let (tail, have) = last(volume, file.first_cluster)?;
        (Some(tail), have)
    };
    if have >= needed {
        return Ok(());
    }
    let added = allocate(volume, tail)?;
    let mut end = added;
    while have + 1 < needed {
        match allocate(volume, Some(end)) {
            Ok(cluster) => end = cluster,
            Err(status) => {
                if let Some(tail) = tail {
                    volume.set_fat_entry(tail, END_OF_CHAIN)?;
                }
                free_chain(volume, added)?;
                return Err(status);
            }
        }
        have += 1;
    }
    if tail.is_none() {
        file.first_cluster = added;
    }
    Ok(())
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
/// end in its old last cluster zeroed.
fn grow(volume: &mut Volume, file: &mut File, size: u32) -> Result<(), NtStatus> {
    let had = if file.first_cluster == 0 {
        0
    } else {
        file.size.div_ceil(cluster_bytes(volume)) * cluster_bytes(volume)
    };
    reserve(volume, file, size)?;
    zero_span(volume, file, file.size, size.min(had))?;
    file.size = size;
    Ok(())
}

/// Write `data` at byte `offset` of `file` (a file), growing it as the write needs (a gap before
/// the offset reads as zeros), and record its entry.
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
    if end > file.size {
        grow(volume, file, end)?;
    }
    write_span(volume, file, offset, data)?;
    update_entry(volume, file)
}

/// Set `file`'s size: a shrink frees the clusters past the new end, a growth adds zeros. Records
/// its entry — a shrink before it trims the chain, so a crash in between leaves clusters past the
/// size (lost to chkdsk), never a size past the chain's end.
pub fn set_size(volume: &mut Volume, file: &mut File, size: u32) -> Result<(), NtStatus> {
    if size >= file.size {
        if size > file.size {
            grow(volume, file, size)?;
        }
        return update_entry(volume, file);
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

/// Where record `index` of the directory starting at `first` lives: its sector and byte offset.
fn record_at(volume: &mut Volume, first: u32, index: u32) -> Result<(u64, usize), NtStatus> {
    let per_cluster = cluster_bytes(volume) / ENTRY_SIZE as u32;
    let cluster = nth(volume, first, index / per_cluster)?;
    let byte = (index % per_cluster) * ENTRY_SIZE as u32;
    Ok((
        volume.layout().cluster_lba(cluster) + (byte / 512) as u64,
        (byte % 512) as usize,
    ))
}

fn read_record(volume: &mut Volume, first: u32, index: u32) -> Result<[u8; 32], NtStatus> {
    let (lba, at) = record_at(volume, first, index)?;
    let mut sector = [0u8; 512];
    volume.read_sector(lba, &mut sector)?;
    let mut record = [0u8; 32];
    record.copy_from_slice(&sector[at..at + 32]);
    Ok(record)
}

fn write_record(
    volume: &mut Volume,
    first: u32,
    index: u32,
    record: &[u8; 32],
) -> Result<(), NtStatus> {
    let (lba, at) = record_at(volume, first, index)?;
    let mut sector = [0u8; 512];
    volume.read_sector(lba, &mut sector)?;
    sector[at..at + 32].copy_from_slice(record);
    volume.write_sector(lba, &sector)
}

/// Patch a record's fields from `file`: attributes, first cluster, size (none for a directory),
/// times.
fn patch(record: &mut [u8; 32], file: &File) {
    let t = &file.times;
    record[11] = file.attributes;
    record[13] = t.create_hundredths;
    record[14..16].copy_from_slice(&t.create_time.to_le_bytes());
    record[16..18].copy_from_slice(&t.create_date.to_le_bytes());
    record[18..20].copy_from_slice(&t.access_date.to_le_bytes());
    record[20..22].copy_from_slice(&((file.first_cluster >> 16) as u16).to_le_bytes());
    record[22..24].copy_from_slice(&t.write_time.to_le_bytes());
    record[24..26].copy_from_slice(&t.write_date.to_le_bytes());
    record[26..28].copy_from_slice(&(file.first_cluster as u16).to_le_bytes());
    let size = if file.directory { 0 } else { file.size };
    record[28..32].copy_from_slice(&size.to_le_bytes());
}

/// Record `file`'s attributes, first cluster, size and times in its entry (the root has none).
pub fn update_entry(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    if file.parent_cluster == 0 {
        return Ok(());
    }
    let mut record = read_record(volume, file.parent_cluster, file.index)?;
    patch(&mut record, file);
    write_record(volume, file.parent_cluster, file.index, &record)
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
            for record in sector.chunks_exact(ENTRY_SIZE) {
                ended |= record[0] == 0x00;
                if ended || record[0] == 0xE5 {
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

/// The basis of a generated 8.3 alias: the base (up to 8 bytes) and the extension (up to 3).
fn alias_basis(name: &[u8]) -> ([u8; 8], usize, [u8; 3], usize) {
    let fold = |byte: u8| -> Option<u8> {
        match byte {
            b' ' | b'.' => None,
            b'+' | b',' | b';' | b'=' | b'[' | b']' => Some(b'_'),
            _ => Some(oem_upper_fit(byte).unwrap_or(b'_')),
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
fn short_record(name: &[u8; 11], case: u8, file: &File) -> [u8; 32] {
    let mut record = [0u8; 32];
    record[..11].copy_from_slice(name);
    if record[0] == 0xE5 {
        record[0] = 0x05;
    }
    record[12] = case;
    patch(&mut record, file);
    record
}

/// Make a new entry named `name` in the directory starting at `parent` for `file` (its first
/// cluster, size, attributes and times); the entry's identity is filled in. The caller has checked
/// that no entry answers to the name.
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
    if long {
        let mut units = [0xFFFFu16; 20 * PART_UNITS];
        for (unit, &byte) in units.iter_mut().zip(name) {
            *unit = decode_byte(byte);
        }
        if name.len() % PART_UNITS != 0 {
            units[name.len()] = 0;
        }
        let sum = checksum(&stored);
        let offsets = (1..11)
            .step_by(2)
            .chain((14..26).step_by(2))
            .chain((28..32).step_by(2));
        let offsets: [usize; 13] = {
            let mut all = [0usize; 13];
            for (slot, offset) in all.iter_mut().zip(offsets) {
                *slot = offset;
            }
            all
        };
        for order in (1..=parts).rev() {
            let mut record = [0u8; 32];
            record[0] = order as u8 | if order == parts { 0x40 } else { 0 };
            record[11] = ATTR_LONG_NAME;
            record[13] = sum;
            for (i, &offset) in offsets.iter().enumerate() {
                let unit = units[(order - 1) * PART_UNITS + i];
                record[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            }
            write_record(volume, parent, start + (parts - order) as u32, &record)?;
        }
    }
    file.parent_cluster = parent;
    file.index = start + parts as u32;
    write_record(
        volume,
        parent,
        file.index,
        &short_record(&stored, case, file),
    )
}

/// Remove `file`'s entry: its 8.3 record and the long-name records before it marked deleted. Its
/// clusters stay.
pub fn remove_entry(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    let mut record = read_record(volume, file.parent_cluster, file.index)?;
    let mut stored = [0u8; 11];
    stored.copy_from_slice(&record[..11]);
    if stored[0] == 0x05 {
        stored[0] = 0xE5;
    }
    let sum = checksum(&stored);
    record[0] = 0xE5;
    write_record(volume, file.parent_cluster, file.index, &record)?;
    let mut index = file.index;
    while index > 0 {
        index -= 1;
        let mut part = read_record(volume, file.parent_cluster, index)?;
        if part[11] != ATTR_LONG_NAME || part[0] == 0xE5 || part[13] != sum {
            break;
        }
        let last = part[0] & 0x40 != 0;
        part[0] = 0xE5;
        write_record(volume, file.parent_cluster, index, &part)?;
        if last {
            break;
        }
    }
    Ok(())
}

/// Delete `file`: its entry removed and its clusters freed.
pub fn delete(volume: &mut Volume, file: &File) -> Result<(), NtStatus> {
    remove_entry(volume, file)?;
    if file.first_cluster != 0 {
        free_chain(volume, file.first_cluster)?;
    }
    Ok(())
}

/// Give `file` the name `name` in the directory starting at `parent` (its own or another): a new
/// entry for the same clusters, the old one removed — a directory moved elsewhere has its `..`
/// record follow. Returns the entry's new identity.
pub fn rename(
    volume: &mut Volume,
    file: &File,
    parent: u32,
    name: &[u8],
) -> Result<File, NtStatus> {
    let mut moved = *file;
    create_entry(volume, parent, name, &mut moved)?;
    remove_entry(volume, file)?;
    if file.directory && parent != file.parent_cluster && file.first_cluster != 0 {
        let mut dotdot = read_record(volume, file.first_cluster, 1)?;
        let target = if parent == volume.layout().root_cluster {
            0
        } else {
            parent
        };
        dotdot[20..22].copy_from_slice(&((target >> 16) as u16).to_le_bytes());
        dotdot[26..28].copy_from_slice(&(target as u16).to_le_bytes());
        write_record(volume, file.first_cluster, 1, &dotdot)?;
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
    let made = write_record(
        volume,
        cluster,
        0,
        &short_record(b".          ", 0, &directory),
    )
    .and_then(|()| {
        write_record(
            volume,
            cluster,
            1,
            &short_record(b"..         ", 0, &up_file),
        )
    })
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
    /// only). An alias folds through Unicode too, a character 437 lacks becoming `_`.
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
                (*b"_URO~1  TXT", 0, true),
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
        let moved = rename(&mut v, &file, dir.first_cluster, b"MOVED.TXT").unwrap();
        assert_eq!(
            lookup(&mut v, b"A Long Created Name.txt"),
            Err(LookupError::NotFound)
        );
        assert_eq!(contents(&mut v, b"SUB\\MOVED.TXT"), b"long");
        assert!(!is_empty(&mut v, dir.first_cluster).unwrap());
        delete(&mut v, &moved).unwrap();
        assert!(is_empty(&mut v, dir.first_cluster).unwrap());
        let inner = make_directory(&mut v, dir.first_cluster, b"INNER", Times::default()).unwrap();
        let inner = rename(&mut v, &inner, root_cluster, b"OUTER").unwrap();
        assert!(lookup(&mut v, b"OUTER\\..\\SUB").is_ok());
        assert_eq!(
            read_record(&mut v, inner.first_cluster, 1).unwrap()[26],
            0,
            "`..` names the root"
        );
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
