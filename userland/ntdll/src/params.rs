//! The process parameters a new process starts with: RtlCreateProcessParameters builds the block
//! kernel32's CreateProcess hands the new process, RtlDestroyProcessParameters frees it. The block
//! is one allocation of virtual memory (NtAllocateVirtualMemory), laid out by `rtl::params`:
//! denormalized, its strings' buffers offsets from its start, so that it reads the same wherever it
//! is copied. What the caller leaves out comes from the calling process's own block, under the PEB
//! lock: its DLL search path and current directory, its environment; the command line defaults to
//! the image's path. The new process normalizes the block it was handed early in its
//! initialization ([`normalize_own_parameters`], RtlNormalizeProcessParams: the offsets made
//! addresses); RtlDeNormalizeProcessParams does the reverse.

use core::mem::size_of;

use rtl::params::{self, CountedString, ProcessParameters, Strings};
use rtl::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use rtl::string::UnicodeString;
use rtl::sys;

/// The virtual-memory calls' constants.
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;

/// The calling process's own block.
fn own_parameters() -> &'static ProcessParameters<usize> {
    // SAFETY: the PEB's ProcessParameters points at the process's block, mapped for its whole life
    // and normalized (its strings' buffers addresses); its fields change only under the PEB lock,
    // which the callers hold while they read it.
    unsafe { &*sys::process_parameters() }
}

/// A string of the process's own (normalized) block, as bytes.
fn own_string(string: &CountedString<usize>) -> &'static [u8] {
    if string.buffer == 0 || string.length == 0 {
        return &[];
    }
    // SAFETY: a normalized block's string: its buffer, inside the block's pages, holds its length.
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
    crate::process::peb_lock().with(&sys::Native, || {
        let own = own_parameters();
        let strings = Strings {
            current_directory: current_directory
                .unwrap_or_else(|| own_string(&own.current_directory.dos_path)),
            dll_path: dll_path.unwrap_or_else(|| own_string(&own.dll_path)),
            image_path_name,
            command_line: command_line.unwrap_or(image_path_name),
            window_title,
            desktop_info,
            shell_info,
            runtime_data,
        };
        let environment = if environment == 0 {
            own.environment
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
