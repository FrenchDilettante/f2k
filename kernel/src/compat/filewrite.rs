//! The write side of the file API: file data and sizes (WriteFile and SetEndOfFile on files),
//! creating files (for CreateFileA), deleting, renaming and copying them, directories, attributes
//! and times — over the boot volume's write layer (`fs::fat32::write`).
//!
//! The volume is taken only once every user argument has been copied in: a fault in a user copy
//! ends the process, which must not happen while it holds the volume. After a change to an entry,
//! every open record of it is refreshed, so other handles see the new size, clusters, name.
//!
//! The FAT timestamps are local time, which is UTC here; a new entry is stamped with the current
//! time, and a write stamps its file's last-write time.

use crate::compat::error::*;
use crate::fs::fat32::dirent::Times;
use crate::fs::fat32::lookup::File;
use crate::user::TrapFrame;

/// FILE_ATTRIBUTE_ARCHIVE, and the attributes a program may set (read-only, hidden, system,
/// archive).
pub const ATTRIBUTE_ARCHIVE: u8 = 0x20;
pub const SETTABLE_ATTRIBUTES: u8 = 0x27;

/// The chunk file bytes move through.
const CHUNK: usize = 4096;

/// A write layer status as the Win32 error it reports.
fn win32(status: crate::status::NtStatus) -> u32 {
    match status {
        crate::status::STATUS_DISK_FULL => ERROR_DISK_FULL,
        crate::status::STATUS_FILE_CORRUPT_ERROR => ERROR_FILE_CORRUPT,
        crate::status::STATUS_OBJECT_NAME_INVALID => ERROR_INVALID_NAME,
        _ => ERROR_IO_DEVICE,
    }
}

/// Times stamped now: all three, the creation's hundredths included.
pub fn times_at(filetime: u64) -> Times {
    let (date, time, hundredths) = crate::compat::time::fat_from_filetime(filetime);
    Times {
        create_hundredths: hundredths,
        create_time: time,
        create_date: date,
        access_date: date,
        write_time: time,
        write_date: date,
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::compat::fileapi::{locate, resolve_arg};
    use crate::compat::path::VolumePath;
    use crate::fs::fat32::dirent::{ATTR_DIRECTORY, ATTR_READ_ONLY};
    use crate::fs::fat32::volume::{with_boot_volume, Volume};
    use crate::fs::fat32::write;
    use crate::fs::file::{ACCESS_DELETE, ACCESS_WRITE};
    use crate::user::syscall::{read_user, write_user};

    /// The current time's stamps.
    pub fn now() -> Times {
        times_at(crate::compat::time::system_filetime())
    }

    /// Run `body` on the boot volume, its status as a Win32 error.
    fn on_volume<R>(body: impl FnOnce(&mut Volume) -> Result<R, crate::status::NtStatus>) -> Result<R, u32> {
        with_boot_volume(body).ok_or(ERROR_PATH_NOT_FOUND)?.map_err(win32)
    }

    /// Every open record of `old` now sees `new`.
    fn refresh(old: &File, new: &File) {
        crate::process::current_mut().open_files().refresh(old, new);
    }

    /// The directory a new entry of `path` goes in: ERROR_PATH_NOT_FOUND when it is not one.
    fn parent_of(path: &VolumePath) -> Result<File, u32> {
        let parent = path.parent();
        let mut parent_path = VolumePath::root();
        if !parent.is_empty() {
            parent_path.push_path(parent).map_err(|_| ERROR_PATH_NOT_FOUND)?;
        }
        match locate(&parent_path) {
            Ok(file) if file.directory => Ok(file),
            _ => Err(ERROR_PATH_NOT_FOUND),
        }
    }

    /// Create a file at `path` (whose lookup found nothing) with `attributes`: its entry, stamped
    /// now, archive set.
    pub fn create_file(path: &VolumePath, attributes: u8) -> Result<File, u32> {
        let parent = parent_of(path)?;
        let mut file = File::plain(0, 0, false);
        file.attributes = attributes & SETTABLE_ATTRIBUTES | ATTRIBUTE_ARCHIVE;
        file.times = now();
        on_volume(|volume| write::create_entry(volume, parent.first_cluster, path.file_name(), &mut file))?;
        Ok(file)
    }

    /// Truncate an open record's file to nothing (CREATE_ALWAYS, TRUNCATE_EXISTING).
    pub fn truncate(handle: u32) -> Result<(), u32> {
        let open = crate::process::current_mut().file_mut(handle).ok_or(ERROR_INVALID_HANDLE)?;
        let old = open.file;
        let mut file = old;
        file.times.write_date = now().write_date;
        file.times.write_time = now().write_time;
        on_volume(|volume| write::set_size(volume, &mut file, 0))?;
        refresh(&old, &file);
        Ok(())
    }

    /// The last close of a file opened to be deleted on close.
    pub fn delete_closed(file: &File) {
        let _ = on_volume(|volume| write::delete(volume, file));
    }

    /// WriteFile on a file handle: the caller's bytes at the position, the file growing as needed;
    /// the count written. ERROR_ACCESS_DENIED for a handle without write access.
    pub fn write_file(handle: u32, buffer: u32, count: u32) -> Result<u32, u32> {
        let open = crate::process::current_mut().file_mut(handle).ok_or(ERROR_INVALID_HANDLE)?;
        if open.access & ACCESS_WRITE == 0 {
            return Err(ERROR_ACCESS_DENIED);
        }
        let mut chunk = [0u8; CHUNK];
        let mut done = 0u32;
        while done < count {
            let take = (count - done).min(CHUNK as u32) as usize;
            read_user(buffer.wrapping_add(done), &mut chunk[..take]).map_err(|_| ERROR_NOACCESS)?;
            let open = crate::process::current_mut().file_mut(handle).ok_or(ERROR_INVALID_HANDLE)?;
            let position = u32::try_from(open.position).map_err(|_| ERROR_DISK_FULL)?;
            let old = open.file;
            let mut file = old;
            let stamp = now();
            file.times.write_date = stamp.write_date;
            file.times.write_time = stamp.write_time;
            on_volume(|volume| write::write_at(volume, &mut file, position, &chunk[..take]))?;
            refresh(&old, &file);
            let open = crate::process::current_mut().file_mut(handle).ok_or(ERROR_INVALID_HANDLE)?;
            open.position += take as u64;
            done += take as u32;
        }
        Ok(count)
    }

    /// SetEndOfFile: the file ends at the handle's position (shrunk, or grown with zeros).
    pub fn set_end_of_file(handle: u32) -> Result<u32, u32> {
        let open = crate::process::current_mut().file_mut(handle).ok_or(ERROR_INVALID_HANDLE)?;
        if open.file.directory {
            return Err(ERROR_INVALID_HANDLE);
        }
        if open.access & ACCESS_WRITE == 0 {
            return Err(ERROR_ACCESS_DENIED);
        }
        let size = u32::try_from(open.position).map_err(|_| ERROR_DISK_FULL)?;
        let old = open.file;
        let mut file = old;
        on_volume(|volume| write::set_size(volume, &mut file, size))?;
        refresh(&old, &file);
        Ok(1)
    }

    /// Whether `file` can go away now: no open record of it, or every one sharing delete.
    fn closable(file: &File) -> bool {
        crate::process::current_mut().open_files().all_share(file, ACCESS_DELETE)
    }

    pub fn delete_file(args: &[u32]) -> Result<u32, u32> {
        let path = resolve_arg(args[0])?;
        let file = locate(&path)?;
        if file.directory || file.attributes & ATTR_READ_ONLY != 0 {
            return Err(ERROR_ACCESS_DENIED);
        }
        if crate::process::current_mut().open_files().is_open(&file) {
            return Err(ERROR_SHARING_VIOLATION);
        }
        on_volume(|volume| write::delete(volume, &file))?;
        Ok(1)
    }

    pub fn move_file(args: &[u32]) -> Result<u32, u32> {
        let from = resolve_arg(args[0])?;
        let to = resolve_arg(args[1])?;
        let file = locate(&from)?;
        if from.is_root() {
            return Err(ERROR_ACCESS_DENIED);
        }
        if locate(&to).is_ok() {
            return Err(ERROR_ALREADY_EXISTS);
        }
        let parent = parent_of(&to)?;
        if !closable(&file) {
            return Err(ERROR_SHARING_VIOLATION);
        }
        let moved = on_volume(|volume| write::rename(volume, &file, parent.first_cluster, to.file_name()))?;
        refresh(&file, &moved);
        Ok(1)
    }

    pub fn copy_file(args: &[u32]) -> Result<u32, u32> {
        let (from, to, fail_if_exists) = (resolve_arg(args[0])?, resolve_arg(args[1])?, args[2] != 0);
        let source = locate(&from)?;
        if source.directory {
            return Err(ERROR_ACCESS_DENIED);
        }
        let mut target = match locate(&to) {
            Ok(_) if fail_if_exists => return Err(ERROR_FILE_EXISTS),
            Ok(existing) if existing.directory || existing.attributes & ATTR_READ_ONLY != 0 => {
                return Err(ERROR_ACCESS_DENIED)
            }
            Ok(existing) => {
                if crate::process::current_mut().open_files().is_open(&existing) {
                    return Err(ERROR_SHARING_VIOLATION);
                }
                existing
            }
            Err(ERROR_FILE_NOT_FOUND) => create_file(&to, source.attributes)?,
            Err(error) => return Err(error),
        };
        target.attributes = source.attributes & SETTABLE_ATTRIBUTES | ATTRIBUTE_ARCHIVE;
        target.times.write_date = source.times.write_date;
        target.times.write_time = source.times.write_time;
        on_volume(|volume| {
            write::set_size(volume, &mut target, 0)?;
            let mut chunk = [0u8; 512];
            let mut offset = 0;
            while offset < source.size {
                let read = crate::fs::fat32::read::read_at(volume, &source, offset, &mut chunk)?;
                write::write_at(volume, &mut target, offset, &chunk[..read])?;
                offset += read as u32;
            }
            write::update_entry(volume, &target)
        })?;
        crate::user::teb::set_last_error(0);
        Ok(1)
    }

    pub fn create_directory(args: &[u32]) -> Result<u32, u32> {
        let path = resolve_arg(args[0])?;
        match locate(&path) {
            Ok(_) => Err(ERROR_ALREADY_EXISTS),
            Err(ERROR_FILE_NOT_FOUND) => {
                let parent = parent_of(&path)?;
                on_volume(|volume| write::make_directory(volume, parent.first_cluster, path.file_name(), now()))?;
                Ok(1)
            }
            Err(error) => Err(error),
        }
    }

    pub fn remove_directory(args: &[u32]) -> Result<u32, u32> {
        let path = resolve_arg(args[0])?;
        let file = locate(&path)?;
        if path.is_root() {
            return Err(ERROR_ACCESS_DENIED);
        }
        if !file.directory {
            return Err(ERROR_DIRECTORY);
        }
        if !on_volume(|volume| write::is_empty(volume, &file))? {
            return Err(ERROR_DIR_NOT_EMPTY);
        }
        if crate::process::current_mut().open_files().is_open(&file) {
            return Err(ERROR_SHARING_VIOLATION);
        }
        on_volume(|volume| write::delete(volume, &file))?;
        Ok(1)
    }

    pub fn set_file_attributes(args: &[u32]) -> Result<u32, u32> {
        let path = resolve_arg(args[0])?;
        let file = locate(&path)?;
        if path.is_root() {
            return Err(ERROR_ACCESS_DENIED);
        }
        let mut updated = file;
        updated.attributes = file.attributes & ATTR_DIRECTORY | args[1] as u8 & SETTABLE_ATTRIBUTES;
        on_volume(|volume| write::update_entry(volume, &updated))?;
        refresh(&file, &updated);
        Ok(1)
    }

    pub fn set_file_time(args: &[u32]) -> Result<u32, u32> {
        let open = crate::process::current_mut().file_mut(args[0]).ok_or(ERROR_INVALID_HANDLE)?;
        if open.access & ACCESS_WRITE == 0 {
            return Err(ERROR_ACCESS_DENIED);
        }
        let old = open.file;
        let read_time = |pointer: u32| -> Result<Option<Times>, u32> {
            if pointer == 0 {
                return Ok(None);
            }
            let mut bytes = [0u8; 8];
            read_user(pointer, &mut bytes).map_err(|_| ERROR_NOACCESS)?;
            Ok(Some(times_at(u64::from_le_bytes(bytes))))
        };
        let (created, accessed, written) = (read_time(args[1])?, read_time(args[2])?, read_time(args[3])?);
        let mut file = old;
        if let Some(t) = created {
            file.times.create_date = t.create_date;
            file.times.create_time = t.create_time;
            file.times.create_hundredths = t.create_hundredths;
        }
        if let Some(t) = accessed {
            file.times.access_date = t.access_date;
        }
        if let Some(t) = written {
            file.times.write_date = t.write_date;
            file.times.write_time = t.write_time;
        }
        on_volume(|volume| write::update_entry(volume, &file))?;
        refresh(&old, &file);
        Ok(1)
    }

    pub fn system_time_to_file_time(args: &[u32]) -> Result<u32, u32> {
        let mut bytes = [0u8; 16];
        read_user(args[0], &mut bytes).map_err(|_| ERROR_NOACCESS)?;
        let time = crate::compat::time::SystemTime::from_bytes(&bytes);
        let filetime = crate::compat::time::filetime_from_system_time(time).ok_or(ERROR_INVALID_PARAMETER)?;
        write_user(args[1], &filetime.to_le_bytes()).map_err(|_| ERROR_NOACCESS)?;
        Ok(1)
    }
}

#[cfg(target_arch = "x86")]
pub use target::{create_file, delete_closed, set_end_of_file, truncate, write_file};

#[cfg(not(target_arch = "x86"))]
pub fn delete_closed(_file: &File) {}

/// The registry's entries: each body on the target, a failure on the host (never dispatched).
macro_rules! services {
    ($($name:ident => $body:ident),* $(,)?) => {
        $(
            pub fn $name(frame: &mut TrapFrame, args: &[u32]) {
                #[cfg(target_arch = "x86")]
                crate::compat::fileapi::serve(frame, 0, || target::$body(args));
                #[cfg(not(target_arch = "x86"))]
                {
                    let _ = args;
                    frame.eax = 0;
                }
            }
        )*
    };
}

services! {
    svc_delete_file_a => delete_file,
    svc_move_file_a => move_file,
    svc_copy_file_a => copy_file,
    svc_create_directory_a => create_directory,
    svc_remove_directory_a => remove_directory,
    svc_set_file_attributes_a => set_file_attributes,
    svc_set_file_time => set_file_time,
    svc_system_time_to_file_time => system_time_to_file_time,
}
