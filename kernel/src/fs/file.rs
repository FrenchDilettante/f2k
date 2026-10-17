//! Open files: the per-process records behind file handles — which file, and where the next read
//! starts — and the seek arithmetic over them.
//!
//! A process keeps a fixed set of records; a handle-table slot names one by index — a duplicated
//! handle names the same record, sharing its position — and the last handle's close (or the
//! process's end) releases it. A record holds the file as the lookup found it, the position, and
//! the access and sharing the open asked for: an open is refused when it and an open already in
//! place on the same entry exclude each other (the platform's share-access check). A directory
//! opens too (backup semantics), for its metadata. Positions are 64-bit, as Win32 file pointers
//! are; files themselves stay within FAT32's 32-bit sizes.

use super::fat32::lookup::File;

/// How many files a process can hold open at once. Exhaustion is a program-visible failure (the
/// open returns no handle), not a bug.
pub const OPEN_FILES: usize = 128;

/// The access an open asks for, as the share check reads it; the share mode uses the same bits
/// (FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE).
pub const ACCESS_READ: u8 = 1;
pub const ACCESS_WRITE: u8 = 2;
pub const ACCESS_DELETE: u8 = 4;

/// Where a seek's distance is measured from: the documented `dwMoveMethod` values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeekMethod {
    /// From the start of the file (`FILE_BEGIN`).
    Begin,
    /// From the current position (`FILE_CURRENT`).
    Current,
    /// From the end of the file (`FILE_END`).
    End,
}

impl SeekMethod {
    /// Decode a raw move method; none for a value the ABI does not name.
    pub fn from_raw(raw: u32) -> Option<SeekMethod> {
        match raw {
            0 => Some(SeekMethod::Begin),
            1 => Some(SeekMethod::Current),
            2 => Some(SeekMethod::End),
            _ => None,
        }
    }
}

/// One open file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OpenFile {
    /// The file, as the lookup found it.
    pub file: File,
    /// Where the next read starts; may lie past the end (a read there moves nothing).
    pub position: u64,
    /// The access the open was granted ([`ACCESS_READ`] and kin).
    pub access: u8,
    /// The sharing the open allows others (the same bits).
    pub share: u8,
}

impl OpenFile {
    /// A file opened at its start for reading, shared every way.
    #[cfg(test)]
    pub fn new(file: File) -> OpenFile {
        OpenFile::with(file, ACCESS_READ, ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE)
    }

    /// A file opened at its start with `access` and `share`.
    pub fn with(file: File, access: u8, share: u8) -> OpenFile {
        OpenFile {
            file,
            position: 0,
            access,
            share,
        }
    }

    /// Whether this open is of the same entry as `file`.
    pub fn same_entry(&self, file: &File) -> bool {
        self.file.parent_cluster == file.parent_cluster
            && self.file.index == file.index
            && self.file.first_cluster == file.first_cluster
    }

    /// Whether this open and a new one asking `access` and allowing `share` exclude each other: one
    /// asks for what the other does not share. An open asking none of the three shares with
    /// everything.
    pub fn excludes(&self, access: u8, share: u8) -> bool {
        (access & !self.share) != 0 || (self.access & !share) != 0
    }

    /// The position `distance` bytes from where `method` says; none for a target before the start
    /// (or past the signed 64-bit range Win32 pointers live in). Past the end is legal.
    pub fn seek_target(&self, distance: i64, method: SeekMethod) -> Option<u64> {
        let base = match method {
            SeekMethod::Begin => 0,
            SeekMethod::Current => self.position as i64,
            SeekMethod::End => self.file.size as i64,
        };
        let target = base.checked_add(distance)?;
        u64::try_from(target).ok()
    }

    /// Move the position `distance` bytes from where `method` says, returning the new position. A
    /// target before the start is refused and the position stays. Past the end is legal.
    #[cfg(test)]
    pub fn seek(&mut self, distance: i64, method: SeekMethod) -> Option<u64> {
        let target = self.seek_target(distance, method)?;
        self.position = target;
        Some(target)
    }

    /// How many bytes a read of `count` at the position moves: what remains before the end, at
    /// most `count`; nothing at or past the end.
    pub fn available(&self, count: u32) -> u32 {
        (self.file.size as u64)
            .saturating_sub(self.position)
            .min(count as u64) as u32
    }
}

/// Why an open found no record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpenError {
    /// An open of the same entry excludes it (ERROR_SHARING_VIOLATION).
    Sharing,
    /// Every record is taken.
    Full,
}

/// A process's open-file records.
pub struct OpenFiles {
    records: [Option<OpenFile>; OPEN_FILES],
}

impl OpenFiles {
    /// No file open (the tests build processes by value; the kernel writes the set in place).
    #[cfg(test)]
    pub const fn empty() -> Self {
        OpenFiles {
            records: [None; OPEN_FILES],
        }
    }

    /// Write the empty set at `files`, record by record (by value it would pass the caller's
    /// stack).
    ///
    /// # Safety
    ///
    /// `files` is valid for writes and aligned; its previous contents are overwritten, not dropped.
    pub unsafe fn write_empty(files: *mut OpenFiles) {
        // SAFETY: the caller's contract; every record is written.
        unsafe {
            let records = core::ptr::addr_of_mut!((*files).records) as *mut Option<OpenFile>;
            for index in 0..OPEN_FILES {
                records.add(index).write(None);
            }
        }
    }

    /// Open `file` at its start for reading, shared every way (see [`OpenFiles::open_with`]).
    #[cfg(test)]
    pub fn open(&mut self, file: File) -> Option<usize> {
        self.open_with(file, ACCESS_READ, ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE)
            .ok()
    }

    /// Open `file` at its start with `access` and `share` in the lowest free record, returning
    /// its index. Refused with [`OpenError::Sharing`] when an open of the same entry already in
    /// place excludes it, [`OpenError::Full`] when every record is taken.
    pub fn open_with(&mut self, file: File, access: u8, share: u8) -> Result<usize, OpenError> {
        if self
            .records
            .iter()
            .flatten()
            .any(|open| open.same_entry(&file) && open.excludes(access, share))
        {
            return Err(OpenError::Sharing);
        }
        let index = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(OpenError::Full)?;
        self.records[index] = Some(OpenFile::with(file, access, share));
        Ok(index)
    }

    /// The open file at `index`, which a live handle names.
    pub fn get_mut(&mut self, index: usize) -> &mut OpenFile {
        self.records[index]
            .as_mut()
            .expect("a file handle names a live record")
    }

    /// Release the record at `index`: its handle was closed.
    pub fn release(&mut self, index: usize) {
        assert!(
            self.records[index].take().is_some(),
            "release of a free file record"
        );
    }

    /// Release every record: the process-exit step.
    pub fn clear(&mut self) {
        for record in self.records.iter_mut() {
            *record = None;
        }
    }

    /// How many records are taken (the tests' audit).
    #[cfg(test)]
    pub fn live(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(size: u32) -> File {
        File::plain(3, size, false)
    }

    /// The documented move methods decode; anything else is refused.
    #[test]
    fn move_methods_decode() {
        assert_eq!(SeekMethod::from_raw(0), Some(SeekMethod::Begin));
        assert_eq!(SeekMethod::from_raw(1), Some(SeekMethod::Current));
        assert_eq!(SeekMethod::from_raw(2), Some(SeekMethod::End));
        assert_eq!(SeekMethod::from_raw(3), None);
        assert_eq!(SeekMethod::from_raw(u32::MAX), None);
    }

    /// Each method measures from its own base: the start, the current position, the end.
    #[test]
    fn seeks_measure_from_their_method_base() {
        let mut open = OpenFile::new(file(1000));
        assert_eq!(open.position, 0);
        assert_eq!(open.seek(0x3C, SeekMethod::Begin), Some(0x3C));
        assert_eq!(open.seek(4, SeekMethod::Current), Some(0x40));
        assert_eq!(
            open.seek(0, SeekMethod::Current),
            Some(0x40),
            "the position query"
        );
        assert_eq!(open.seek(0, SeekMethod::End), Some(1000));
        assert_eq!(open.seek(0, SeekMethod::Begin), Some(0));
        assert_eq!(open.position, 0);
    }

    /// A negative distance moves back; a target before the start is refused and the position
    /// stays where it was.
    #[test]
    fn negative_distances_and_the_start() {
        let mut open = OpenFile::new(file(1000));
        assert_eq!(open.seek(-10, SeekMethod::End), Some(990));
        assert_eq!(open.seek(-90, SeekMethod::Current), Some(900));
        assert_eq!(
            open.seek(-900, SeekMethod::Current),
            Some(0),
            "exactly the start"
        );
        assert_eq!(open.seek(-1, SeekMethod::Current), None);
        assert_eq!(open.seek(-1, SeekMethod::Begin), None);
        assert_eq!(open.seek(-1001, SeekMethod::End), None);
        assert_eq!(open.position, 0, "a refused seek leaves the position");
    }

    /// Past the end is a legal position, and reads there move nothing.
    #[test]
    fn past_the_end_is_legal() {
        let mut open = OpenFile::new(file(1000));
        assert_eq!(open.seek(500, SeekMethod::End), Some(1500));
        assert_eq!(open.available(10), 0);
        assert_eq!(
            open.seek(i32::MAX as i64, SeekMethod::Begin),
            Some(i32::MAX as u64)
        );
    }

    /// Positions are 64-bit: past 4 GiB is a position, and reads there move nothing; only the
    /// signed 64-bit range bounds them.
    #[test]
    fn positions_are_64_bit() {
        let mut open = OpenFile::new(file(u32::MAX - 10));
        assert_eq!(open.seek(10, SeekMethod::End), Some(u32::MAX as u64));
        assert_eq!(open.seek(1, SeekMethod::Current), Some(1 << 32));
        assert_eq!(open.available(100), 0);
        assert_eq!(open.seek(i64::MAX, SeekMethod::Current), None);
        assert_eq!(open.position, 1 << 32, "a refused seek leaves the position");
    }

    /// A read moves what remains before the end, at most the request: all of it, the prefix that
    /// fits, or nothing at the end.
    #[test]
    fn reads_take_what_remains() {
        let mut open = OpenFile::new(file(100));
        assert_eq!(open.available(40), 40);
        open.position = 90;
        assert_eq!(open.available(40), 10, "the prefix before the end");
        open.position = 100;
        assert_eq!(open.available(40), 0, "at the end");
        assert_eq!(OpenFile::new(file(0)).available(4), 0, "an empty file");
    }

    /// Records: the lowest free one first, reused after a release, refused when all are taken,
    /// and all released at once by the exit step.
    #[test]
    fn records_open_release_and_clear() {
        let mut files = OpenFiles::empty();
        assert_eq!(files.open(file(1)), Some(0));
        assert_eq!(files.open(file(2)), Some(1));
        files.get_mut(1).position = 7;
        files.release(0);
        assert_eq!(files.live(), 1);
        assert_eq!(files.open(file(3)), Some(0), "the freed record");
        assert_eq!(files.get_mut(0).position, 0, "a fresh open starts at zero");
        assert_eq!(files.get_mut(1).position, 7);

        while files.open(file(4)).is_some() {}
        assert_eq!(
            files.live(),
            OPEN_FILES,
            "refused only when every record is taken"
        );
        files.clear();
        assert_eq!(files.live(), 0);
        assert_eq!(files.open(file(5)), Some(0));
    }

    #[test]
    #[should_panic(expected = "free file record")]
    fn a_double_release_is_a_contract_violation() {
        let mut files = OpenFiles::empty();
        let index = files.open(file(1)).unwrap();
        files.release(index);
        files.release(index);
    }

    /// The share check: an open without sharing excludes any second open, and a second open that
    /// shares nothing is excluded by any first; reads that share reads coexist; an open asking no
    /// data access excludes nobody, and other entries are never consulted.
    #[test]
    fn opens_respect_each_others_sharing() {
        let mut files = OpenFiles::empty();
        let all = ACCESS_READ | ACCESS_WRITE | ACCESS_DELETE;
        let first = files.open_with(file(1), ACCESS_READ, 0).unwrap();
        assert_eq!(files.open_with(file(1), ACCESS_READ, all), Err(OpenError::Sharing));
        assert_eq!(files.open_with(file(1), 0, all), Ok(1), "no data access");
        files.release(first);
        files.open_with(file(1), ACCESS_READ, ACCESS_READ).unwrap();
        assert!(files.open_with(file(1), ACCESS_READ, ACCESS_READ).is_ok());
        assert_eq!(files.open_with(file(1), ACCESS_READ, 0), Err(OpenError::Sharing), "exclusive");
        let mut other = file(1);
        other.index = 9;
        assert!(files.open_with(other, ACCESS_READ, 0).is_ok(), "another entry");
    }
}
