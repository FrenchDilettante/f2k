//! NtQueryDirectoryFile: a directory's entries matching its search's expression (see
//! [`crate::fs::search`]), as many as the buffer holds (or one), each record eight-byte aligned
//! after the one before, the search resuming where the last query stopped.
//!
//! The first query names the expression (none: every name), later ones continue it (their name is
//! not consulted), and RestartScan starts over. A search that never matched is STATUS_NO_SUCH_FILE,
//! one that has run out STATUS_NO_MORE_FILES. An entry whose name does not fit is cut
//! (STATUS_BUFFER_OVERFLOW), the search past it. Entries match by their long name, then their 8.3
//! name; a listing reports the 8.3 name beside a long one only.

use rtl::nt::UnicodeString;
use rtl::text::upcase;

use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{check_access, cluster_bytes, complete, completion_event, file_object, signal};
use super::info::{self, Entry, Listing, ListingClass};
use super::{expression_length, resume_search};
use crate::fs::fat32::dir::{decode_byte, walk, Listed};
use crate::fs::fat32::lookup::File;
use crate::fs::fat32::path::MAX_NAME;
use crate::fs::file::{rights, Context, IoState};
use crate::fs::search::{matches, Search, MAX_EXPRESSION};
use crate::status::*;

/// The most a query copies out at once (a listing buffer's worth: FindFirstFile's is 4 KiB).
const MAX_BUFFER: usize = 0x4000;

/// A listed entry's name units into `out`: its long name, else its 8.3 name with the NT case bits.
fn name_units(listed: &Listed, out: &mut [u16; MAX_NAME]) -> usize {
    if let Some(long) = listed.long_name() {
        out[..long.len()].copy_from_slice(long);
        return long.len();
    }
    let mut bytes = [0u8; MAX_NAME];
    let length = listed.name(&mut bytes);
    for (unit, &byte) in out.iter_mut().zip(&bytes[..length]) {
        *unit = decode_byte(byte);
    }
    length
}

/// A listed entry's stored 8.3 name's units into `out`.
fn short_units(listed: &Listed, out: &mut [u16; 12]) -> usize {
    let mut bytes = [0u8; 12];
    let length = listed.short_name(&mut bytes);
    for (unit, &byte) in out.iter_mut().zip(&bytes[..length]) {
        *unit = decode_byte(byte);
    }
    length
}

/// Whether a listed entry matches a folded expression: by its long name, else its 8.3 name.
fn entry_matches(listed: &Listed, expression: &[u16]) -> bool {
    let mut units = [0u16; MAX_NAME];
    let length = name_units(listed, &mut units);
    units[..length]
        .iter_mut()
        .for_each(|unit| *unit = upcase(*unit));
    if matches(expression, &units[..length]) {
        return true;
    }
    if listed.long_name().is_none() {
        return false;
    }
    let mut short = [0u16; 12];
    let length = short_units(listed, &mut short);
    short[..length]
        .iter_mut()
        .for_each(|unit| *unit = upcase(*unit));
    matches(expression, &short[..length])
}

/// NtQueryDirectoryFile, of a directory opened for listing (FILE_LIST_DIRECTORY), in
/// FileDirectoryInformation, FileFullDirectoryInformation, FileBothDirectoryInformation or
/// FileNamesInformation.
#[allow(clippy::too_many_arguments)]
fn query_directory_file_held(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
    single: bool,
    file_name: UserAddr,
    restart: bool,
) -> NtResult {
    let class = ListingClass::try_from(class)?;
    info::check_length(class.fixed_size(), length)?;
    io_status.probe(8)?;
    information.probe(length)?;
    let object = file_object(handle.raw())?;
    check_access(&object, rights::FILE_READ_DATA)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let event = completion_event(&object, event.raw())?;
    // The object's device lists: a disk directory's entries; a disk file has none to list, and a
    // pipe's end none either (only the named-pipe file system's root, which no open reaches yet,
    // lists pipes).
    let directory: File = match object.context {
        Context::Disk(record) => crate::fs::io::file_at(record),
        Context::Pipe(_) | Context::Null | Context::Device(_) => {
            return Err(STATUS_INVALID_PARAMETER)
        }
    };
    if !directory.directory {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // The search is the object's: taken and moved under its lock, as a read or a write moves its
    // position, so a listing through another handle to the object waits for this one. Returns the
    // answer and the bytes it delivered; a fault in the caller's memory fails the call outright.
    let (result, used) = crate::fs::io::serialized(&object, |held| {
        list(
            held,
            class,
            information,
            (length as usize).min(MAX_BUFFER),
            single,
            file_name,
            restart,
            &directory,
        )
    })?;
    let (code, information) = match result {
        Ok(code) => (code, used as u32),
        Err(code) => (code, 0),
    };
    complete(io_status, code, information);
    signal(&object, event);
    // A cut entry is a warning: the status fails the call, the record still delivered.
    if code == STATUS_BUFFER_OVERFLOW {
        return Err(code);
    }
    result
}

/// One listing step of the object's search (see [`query_directory_file_held`]), its entries in
/// `class` from the search's next record on into the caller's `information`, at most `room` bytes.
/// Returns the answer and the bytes delivered; a fault in the caller's memory is the error.
#[allow(clippy::too_many_arguments)]
fn list(
    held: &mut IoState,
    class: ListingClass,
    information: UserAddr,
    room: usize,
    single: bool,
    file_name: UserAddr,
    restart: bool,
    directory: &File,
) -> Result<(NtResult, usize), NtStatus> {
    // The search: made by the first query, of its name (a UNICODE_STRING) or of every name.
    let search = resume_search(&mut held.search, restart, || {
        let mut units = [0u16; MAX_EXPRESSION];
        let mut expression = None;
        if !file_name.is_null() {
            let string = file_name.cast::<UnicodeString<u32>>().read()?;
            let name = &mut units[..expression_length(string.length)?];
            UserAddr(string.buffer).read_units(name)?;
            expression = (!name.is_empty()).then_some(&*name);
        }
        Ok(Search::new(expression))
    })?;
    let expression = search.expression();
    let mut buffer = [0u8; MAX_BUFFER];
    let cluster = cluster_bytes();
    // The entries that fit, from the search's next record on, and the next record index.
    let mut listing = Listing::new(class, &mut buffer[..room], single);
    let mut next = search.next;
    let walked = crate::fs::fat32::volume::with_boot_volume(|volume| {
        walk(volume, directory.first_cluster, |listed| {
            if listed.index < search.next || !entry_matches(listed, expression) {
                return true;
            }
            if !listing.has_room() {
                return false;
            }
            let mut name = [0u16; MAX_NAME];
            let name_length = name_units(listed, &mut name);
            let mut short = [0u16; 12];
            let short_length = if listed.long_name().is_some() {
                short_units(listed, &mut short)
            } else {
                0
            };
            let file = File::of(listed, directory.first_cluster);
            let entry = Entry {
                index: listed.index,
                file,
                allocation: info::allocation(&file, cluster),
                name: &name[..name_length],
                short: &short[..short_length],
            };
            // An entry that does not fit after another waits for the next query; the first one
            // comes back cut.
            if !listing.add(&entry) {
                return false;
            }
            next = listed.index + 1;
            !listing.done()
        })
    });
    let used = listing.used();
    let result = match walked {
        Some(Ok(())) => {
            let answered = search.answered || listing.any();
            if let Some(state) = held.search.as_mut() {
                state.next = next;
                state.answered = answered;
            }
            let status = info::listing_status(listing.any(), listing.cut(), search.answered);
            if status.is_ok() {
                information.write(&buffer[..used])?;
            }
            status
        }
        Some(Err(_)) | None => Err(STATUS_FILE_CORRUPT_ERROR),
    };
    Ok((result, used))
}

/// NtQueryDirectoryFile (see [`query_directory_file_held`]), as one critical region.
#[allow(clippy::too_many_arguments)]
pub fn query_directory_file(
    call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    context: UserAddr,
    io_status: UserAddr,
    information: UserAddr,
    length: u32,
    class: u32,
    single: bool,
    file_name: UserAddr,
    restart: bool,
) -> NtResult {
    // The call holds its file object (a reference) across the volume's critical regions: run it
    // inside one of its own, so a termination requested meanwhile ends the thread only once the
    // reference has gone (an inner region's end would end it with the reference still held).
    crate::process::threads::critical_region(|| {
        query_directory_file_held(
            call,
            handle,
            event,
            routine,
            context,
            io_status,
            information,
            length,
            class,
            single,
            file_name,
            restart,
        )
    })
}
