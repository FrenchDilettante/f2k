//! Open files: the per-process records behind file handles — which file, and where the next read
//! starts — and the seek arithmetic over them.
//!
//! A process keeps a fixed set of records; a handle-table slot names one by index, and closing the
//! handle (or ending the process) releases it. The files are read-only: a record holds the file's
//! first cluster and size as the lookup found them, plus the position. Positions are 32-bit — the
//! subset has no 64-bit offsets.

use super::fat32::lookup::File;

/// How many files a process can hold open at once. Exhaustion is a program-visible failure (the
/// open returns no handle), not a bug.
pub const OPEN_FILES: usize = 8;

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
    pub position: u32,
}

impl OpenFile {
    /// A file opened at its start.
    pub fn new(file: File) -> OpenFile {
        assert!(!file.directory, "a directory is not opened as a file");
        OpenFile { file, position: 0 }
    }

    /// Move the position `distance` bytes from where `method` says, returning the new position. A
    /// target before the start, or past what 32 bits hold, is refused and the position stays.
    /// Past the end is legal.
    pub fn seek(&mut self, distance: i32, method: SeekMethod) -> Option<u32> {
        let base = match method {
            SeekMethod::Begin => 0,
            SeekMethod::Current => self.position,
            SeekMethod::End => self.file.size,
        };
        let target = u32::try_from(base as i64 + distance as i64).ok()?;
        self.position = target;
        Some(target)
    }

    /// How many bytes a read of `count` at the position moves: what remains before the end, at
    /// most `count`; nothing at or past the end.
    pub fn available(&self, count: u32) -> u32 {
        self.file.size.saturating_sub(self.position).min(count)
    }
}

/// A process's open-file records.
pub struct OpenFiles {
    records: [Option<OpenFile>; OPEN_FILES],
}

impl OpenFiles {
    /// No file open.
    pub const fn empty() -> Self {
        OpenFiles {
            records: [None; OPEN_FILES],
        }
    }

    /// Open `file` at its start in the lowest free record, returning its index; none when every
    /// record is taken.
    pub fn open(&mut self, file: File) -> Option<usize> {
        let index = self.records.iter().position(Option::is_none)?;
        self.records[index] = Some(OpenFile::new(file));
        Some(index)
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
        *self = OpenFiles::empty();
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
        File {
            first_cluster: 3,
            size,
            directory: false,
        }
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
            open.seek(i32::MAX, SeekMethod::Begin),
            Some(i32::MAX as u32)
        );
    }

    /// A target past what 32 bits hold is refused (no 64-bit offsets).
    #[test]
    fn positions_stay_within_32_bits() {
        let mut open = OpenFile::new(file(u32::MAX - 10));
        assert_eq!(open.seek(10, SeekMethod::End), Some(u32::MAX));
        assert_eq!(open.seek(1, SeekMethod::Current), None);
        assert_eq!(open.position, u32::MAX);
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

    #[test]
    #[should_panic(expected = "not opened as a file")]
    fn opening_a_directory_is_a_contract_violation() {
        OpenFile::new(File {
            first_cluster: 2,
            size: 0,
            directory: true,
        });
    }
}
