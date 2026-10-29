//! The process parameters a new process starts with: RtlCreateProcessParameters builds the block
//! kernel32's CreateProcess hands the new process, RtlDestroyProcessParameters frees it. The block
//! is one allocation of virtual memory (NtAllocateVirtualMemory), laid out by `rtl::params`:
//! denormalized, its strings' buffers offsets from its start, so that it reads the same wherever it
//! is copied. What the caller leaves out comes from the calling process's own block, under the PEB
//! lock: its DLL search path and current directory, its environment; the command line defaults to
//! the image's path. The new process normalizes the block it was handed early in its
//! initialization ([`normalize_own_parameters`], RtlNormalizeProcessParams: the offsets made
//! addresses); RtlDeNormalizeProcessParams does the reverse.
//!
//! The process's own block is ntdll's to read and change under the PEB lock
//! ([`with_own_parameters`]: the current directory, the environment's address), but for its image's
//! path, which nothing changes after the process's creation ([`image_path_name`]). Its other
//! fields (the standard handles, the console's) are kernel32's, read and written in place.

use core::mem::size_of;

use rtl::params::{self, CountedString, CurrentDirectory, ProcessParameters, Strings};
use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use rtl::string::UnicodeString;
use rtl::sys;

/// The virtual-memory calls' constants.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;

/// The fields of the calling process's own block that change under the PEB lock (its current
/// directory, its environment's address) and its DLL search path, which nothing changes after the
/// block's creation: each a borrow of its own field (the block's other fields are kernel32's, read
/// and written in place without the lock), for as long as [`with_own_parameters`] holds the lock.
pub(crate) struct OwnParameters<'a> {
    pub current_directory: &'a mut CurrentDirectory<usize>,
    pub environment: &'a mut usize,
    pub dll_path: &'a CountedString<usize>,
}

impl OwnParameters<'_> {
    /// The current directory's DOS path (with its trailing separator).
    pub fn current_path(&self) -> &[u16] {
        own_units(&self.current_directory.dos_path)
    }

    /// The current directory's handle (zero for none).
    pub fn current_handle(&self) -> u32 {
        self.current_directory.handle as u32
    }

    /// Whether a DOS path of `length` units fits the current directory's room with its terminator.
    pub fn current_path_fits(&self, length: usize) -> bool {
        2 * (length + 1) <= usize::from(self.current_directory.dos_path.maximum_length)
    }

    /// Make `path` (which [`Self::current_path_fits`]) the current directory's DOS path,
    /// terminated, and `handle` its handle.
    pub fn set_current_directory(&mut self, path: &[u16], handle: u32) {
        let string = &mut self.current_directory.dos_path;
        let room = usize::from(string.maximum_length) / 2;
        assert!(
            path.len() < room,
            "the current directory's room holds the path"
        );
        // SAFETY: a normalized block's string: its buffer, inside the block's pages and aligned
        // for its units, holds its room, which only this borrow (the PEB lock's) changes.
        let buffer = unsafe { core::slice::from_raw_parts_mut(string.buffer as *mut u16, room) };
        buffer[..path.len()].copy_from_slice(path);
        buffer[path.len()] = 0;
        string.length = (2 * path.len()) as u16;
        self.current_directory.handle = handle as usize;
    }
}

/// Run `body` over the calling process's own block (see [`OwnParameters`]), under the PEB lock.
pub(crate) fn with_own_parameters<R>(body: impl FnOnce(&mut OwnParameters<'_>) -> R) -> R {
    crate::process::peb_lock().with(&sys::Native, || {
        let block = sys::process_parameters();
        // SAFETY: the PEB's ProcessParameters points at the process's block, mapped for its whole
        // life and normalized by its first thread before anything reads it; the fields borrowed
        // change only under the PEB lock, held while the borrows live, and the DLL path never
        // after the block's creation. No borrow covers the fields kernel32 writes in place.
        let mut own = unsafe {
            OwnParameters {
                current_directory: &mut (*block).current_directory,
                environment: &mut (*block).environment,
                dll_path: &(*block).dll_path,
            }
        };
        body(&mut own)
    })
}

/// The process's own ImagePathName: the program's full path, set at the process's creation and
/// never changed after it.
pub(crate) fn image_path_name() -> &'static CountedString<usize> {
    // SAFETY: the process parameters are mapped for the process's whole life, and nothing changes
    // their ImagePathName after the process's creation.
    unsafe { &(*sys::process_parameters()).image_path_name }
}

/// The units of the process's own ImagePathName.
pub(crate) fn image_path() -> &'static [u16] {
    own_units(image_path_name())
}

/// The units of a string of the process's own (normalized) block, borrowed with the string.
fn own_units(string: &CountedString<usize>) -> &[u16] {
    if string.buffer == 0 || string.length < 2 {
        return &[];
    }
    // SAFETY: a normalized block's string: its buffer, inside the block's pages and aligned for
    // its units, holds its length, unchanged while the string is borrowed.
    unsafe {
        core::slice::from_raw_parts(string.buffer as *const u16, usize::from(string.length) / 2)
    }
}

/// A string of the process's own (normalized) block, as bytes, borrowed with the string.
fn own_string(string: &CountedString<usize>) -> &[u8] {
    if string.buffer == 0 || string.length == 0 {
        return &[];
    }
    // SAFETY: a normalized block's string: its buffer, inside the block's pages, holds its length,
    // unchanged while the string is borrowed.
    unsafe { core::slice::from_raw_parts(string.buffer as *const u8, string.length as usize) }
}

/// A UNICODE_STRING argument's bytes (its Length), none for a null one.
///
/// # Safety
///
/// `string` is null or a UNICODE_STRING whose buffer holds its length.
unsafe fn given<'a>(string: *const UnicodeString) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract.
    let string = unsafe { string.as_ref() }?;
    if string.buffer.is_null() || string.length == 0 {
        return Some(&[]);
    }
    // SAFETY: as above.
    Some(unsafe { core::slice::from_raw_parts(string.buffer as *const u8, string.length as usize) })
}

/// RtlCreateProcessParameters: a new block in `*parameters`, holding the image's path, the DLL
/// search path, the current directory and the command line (each the calling process's own when
/// null; the command line the image's path), the window title, desktop and shell information and
/// the C runtime's data (empty when null), and `environment` (the calling process's when null),
/// denormalized; the standard handles and the startup values are zero, the caller's to set.
/// STATUS_INVALID_PARAMETER without an image path or a place for the block; the allocation's
/// status when it fails.
///
/// # Safety
///
/// `parameters` is null or writable; each string is null or a UNICODE_STRING whose buffer holds its
/// length.
#[allow(clippy::too_many_arguments)]
#[unsafe(export_name = "f2k_export_RtlCreateProcessParameters")]
pub unsafe extern "system" fn rtl_create_process_parameters(
    parameters: *mut *mut ProcessParameters<usize>,
    image_path_name: *const UnicodeString,
    dll_path: *const UnicodeString,
    current_directory: *const UnicodeString,
    command_line: *const UnicodeString,
    environment: usize,
    window_title: *const UnicodeString,
    desktop_info: *const UnicodeString,
    shell_info: *const UnicodeString,
    runtime_data: *const UnicodeString,
) -> u32 {
    // SAFETY: the caller's slot and strings.
    let (out, image_path_name, dll_path, current_directory, command_line) = unsafe {
        (
            parameters.as_mut(),
            given(image_path_name),
            given(dll_path),
            given(current_directory),
            given(command_line),
        )
    };
    // SAFETY: as above.
    let (window_title, desktop_info, shell_info, runtime_data) = unsafe {
        (
            given(window_title),
            given(desktop_info),
            given(shell_info),
            given(runtime_data),
        )
    };
    let (Some(out), Some(image_path_name)) = (out, image_path_name) else {
        return STATUS_INVALID_PARAMETER;
    };
    with_own_parameters(|own| {
        let strings = Strings {
            current_directory: current_directory
                .unwrap_or_else(|| own_string(&own.current_directory.dos_path)),
            dll_path: dll_path.unwrap_or_else(|| own_string(own.dll_path)),
            image_path_name,
            command_line: command_line.unwrap_or(image_path_name),
            window_title,
            desktop_info,
            shell_info,
            runtime_data,
        };
        let environment = if environment == 0 {
            *own.environment
        } else {
            environment
        };
        let base = match sys::allocate_virtual_memory(
            0,
            strings.block_size(),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        ) {
            Ok(base) => base,
            Err(status) => return status,
        };
        // SAFETY: a fresh, page-aligned and zeroed allocation of the block's size, the calling
        // process's alone: the structure at its start, the strings' room right after it.
        let (header, tail) = unsafe {
            (
                &mut *(base as *mut ProcessParameters<usize>),
                core::slice::from_raw_parts_mut(
                    (base + size_of::<ProcessParameters<usize>>()) as *mut u8,
                    strings.room(),
                ),
            )
        };
        params::lay_out(header, tail, &strings, environment);
        *out = header;
        STATUS_SUCCESS
    })
}

/// RtlNormalizeProcessParams: the block at `parameters` normalized in place, each string's offset
/// from the block made its address (`rtl::params`); a block already normalized is left as it is.
/// The block (null for null).
///
/// # Safety
///
/// `parameters` is null or a writable process parameters block.
#[unsafe(export_name = "f2k_export_RtlNormalizeProcessParams")]
pub unsafe extern "system" fn rtl_normalize_process_params(
    parameters: *mut ProcessParameters<usize>,
) -> *mut ProcessParameters<usize> {
    // SAFETY: the caller's block.
    if let Some(block) = unsafe { parameters.as_mut() } {
        block.normalize(parameters as usize);
    }
    parameters
}

/// RtlDeNormalizeProcessParams: the block at `parameters` denormalized in place, each string's
/// address made its offset from the block (`rtl::params`); a block already denormalized is left as
/// it is. The block (null for null).
///
/// # Safety
///
/// `parameters` is null or a writable process parameters block.
#[unsafe(export_name = "f2k_export_RtlDeNormalizeProcessParams")]
pub unsafe extern "system" fn rtl_denormalize_process_params(
    parameters: *mut ProcessParameters<usize>,
) -> *mut ProcessParameters<usize> {
    // SAFETY: the caller's block.
    if let Some(block) = unsafe { parameters.as_mut() } {
        block.denormalize(parameters as usize);
    }
    parameters
}

/// The process's own block normalized, as Windows 2000's loader does first thing in a process's
/// initialization: kernel32's CreateProcess writes a new process's block denormalized; the kernel
/// writes a boot program's already normalized, which this leaves as it is.
pub fn normalize_own_parameters() {
    // SAFETY: the PEB's ProcessParameters, null or the process's block, mapped and writable; the
    // process's first thread is the only one running.
    unsafe { rtl_normalize_process_params(sys::process_parameters()) };
}

/// RtlDestroyProcessParameters: the block RtlCreateProcessParameters made, released
/// (NtFreeVirtualMemory); the release's status.
#[unsafe(export_name = "f2k_export_RtlDestroyProcessParameters")]
pub extern "system" fn rtl_destroy_process_parameters(parameters: usize) -> u32 {
    sys::release_virtual_memory(parameters)
}
