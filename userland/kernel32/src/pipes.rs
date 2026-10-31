//! Anonymous pipes: CreatePipe, a named pipe with a name of its own made of the named-pipe file
//! system's services, and PeekNamedPipe over its peek (FSCTL_PIPE_PEEK), as Windows 2000's kernel32
//! makes them (its imports: NtCreateNamedPipeFile, NtOpenFile, NtFsControlFile).

use core::sync::atomic::{AtomicU32, Ordering};

use crate::base::{current_process_id, SecurityAttributes, OBJ_CASE_INSENSITIVE, OBJ_INHERIT};
use crate::edge::{In, Out, OutBuf};
use crate::error::{bool_answer, Failure};
use crate::heap::{HeapArray, Owned};
use crate::nt::{ObjectAttributes, UnicodeString};
use crate::ntcall::{self, NamedPipe};

/// The access each end is opened with: the read end GENERIC_READ, with FILE_WRITE_ATTRIBUTES and
/// SYNCHRONIZE (the capture's granted 0x120189), the write end GENERIC_WRITE and SYNCHRONIZE
/// (0x120116).
const READ_END_ACCESS: u32 = GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE;
const WRITE_END_ACCESS: u32 = GENERIC_WRITE | SYNCHRONIZE;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// The share access: the pipe goes both ways (FILE_SHARE_READ and FILE_SHARE_WRITE make its
/// configuration); the write end shares reading.
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;

/// The dispositions and options: the read end made (FILE_CREATE), the write end opened, both for
/// synchronous I/O, the write end no directory.
const FILE_CREATE: u32 = 2;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;

/// A byte-stream pipe, read as bytes, its calls queued (waiting): FILE_PIPE_BYTE_STREAM_TYPE,
/// FILE_PIPE_BYTE_STREAM_MODE, FILE_PIPE_QUEUE_OPERATION; one instance.
const FILE_PIPE_BYTE_STREAM: u32 = 0;
const FILE_PIPE_QUEUE_OPERATION: u32 = 0;

/// The default timeout a client's wait for the pipe would take: 120 seconds, relative.
const DEFAULT_TIMEOUT: i64 = -120 * 10_000_000;

/// FSCTL_PIPE_PEEK: CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA).
const FSCTL_PIPE_PEEK: u32 = 0x0011_400C;

/// FILE_PIPE_PEEK_BUFFER's fixed part, before the data.
const PEEK_HEADER: usize = core::mem::size_of::<rtl::nt::FilePipePeekBuffer>();

/// The anonymous pipes' serial number, one up for each CreatePipe of the process (Windows 2000's
/// kernel32 counts its PipeSerialNumber so).
static SERIAL: AtomicU32 = AtomicU32::new(0);

/// The name's prefix.
const PREFIX: &[u8] = b"\\Device\\NamedPipe\\Win32Pipes.";

/// The units of `\Device\NamedPipe\Win32Pipes.<pid>.<serial>`, each number eight lowercase hex
/// digits (the capture's name, its digits masked): the public sources' `Win32Pipes.%08x.%08x`.
fn pipe_name(process_id: u32, serial: u32) -> [u16; PIPE_NAME] {
    let mut name = [0u16; PIPE_NAME];
    for (unit, &byte) in name.iter_mut().zip(PREFIX) {
        *unit = u16::from(byte);
    }
    let digits = |value: u32, out: &mut [u16]| {
        for (index, unit) in out.iter_mut().enumerate() {
            let nibble = (value >> (28 - 4 * index)) & 0xF;
            *unit = u16::from(b"0123456789abcdef"[nibble as usize]);
        }
    };
    let at = PREFIX.len();
    digits(process_id, &mut name[at..at + 8]);
    name[at + 8] = u16::from(b'.');
    digits(serial, &mut name[at + 9..]);
    name
}

/// The name's length in units.
const PIPE_NAME: usize = PREFIX.len() + 17;

/// CreatePipe: an anonymous pipe, a named pipe with a name of its own
/// (`\Device\NamedPipe\Win32Pipes.<pid>.<serial>`): its read end made with NtCreateNamedPipeFile
/// (a byte stream of one instance, `size` the quota both ways, 0 the file system's default), its
/// write end an open of the same name with NtOpenFile; both inheritable when the security
/// attributes ask, both for synchronous I/O. A failure sets the status's error (the read end
/// closed when the write end's open fails) and stores no handle.
///
/// # Safety
///
/// `read` and `write` point at dwords; `attributes` is null or a SECURITY_ATTRIBUTES.
#[unsafe(export_name = "f2k_export_CreatePipe")]
pub unsafe extern "system" fn create_pipe(
    read: *mut u32,
    write: *mut u32,
    attributes: *const SecurityAttributes,
    size: u32,
) -> u32 {
    // SAFETY: the caller's handle slots, and its security attributes when given (the contract).
    let (read, write, attributes) =
        unsafe { (Out::new(read), Out::new(write), In::optional(attributes)) };
    bool_answer(make_pipe(read, write, attributes, size))
}

/// CreatePipe's work.
fn make_pipe(
    mut read: Out<'_, u32>,
    mut write: Out<'_, u32>,
    attributes: Option<In<'_, SecurityAttributes>>,
    size: u32,
) -> Result<(), Failure> {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed) + 1;
    let units = pipe_name(current_process_id(), serial);
    let name = UnicodeString::from_units(&units).expect("a pipe's name is short");
    let (inherit, descriptor) = match attributes.map(|attributes| attributes.read()) {
        Some(security) => (security.inherit_handle != 0, security.security_descriptor),
        None => (false, core::ptr::null()),
    };
    let object_attributes = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: &name,
        attributes: OBJ_CASE_INSENSITIVE | if inherit { OBJ_INHERIT } else { 0 },
        security_descriptor: descriptor,
        security_quality_of_service: core::ptr::null(),
    };
    let pipe = NamedPipe {
        pipe_type: FILE_PIPE_BYTE_STREAM,
        read_mode: FILE_PIPE_BYTE_STREAM,
        completion_mode: FILE_PIPE_QUEUE_OPERATION,
        maximum_instances: 1,
        inbound_quota: size,
        outbound_quota: size,
        default_timeout: Some(DEFAULT_TIMEOUT),
    };
    let read_end = ntcall::create_named_pipe_file(
        READ_END_ACCESS,
        &object_attributes,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT,
        &pipe,
    )
    .map_err(Failure::Status)?;
    // Closed again should the write end's open fail.
    let read_end = Owned(read_end);
    let write_end = ntcall::open_file(
        WRITE_END_ACCESS,
        &object_attributes,
        FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
    )
    .map_err(Failure::Status)?;
    read.set(read_end.into_raw());
    write.set(write_end);
    Ok(())
}

/// PeekNamedPipe: what the pipe holds, unread, through its peek (NtFsControlFile's
/// FSCTL_PIPE_PEEK into a block of kernel32's: FILE_PIPE_PEEK_BUFFER's header and `size` bytes):
/// as many of its bytes as `buffer` holds copied there, and when asked, the count copied, the
/// total the pipe holds, and what is left of the message (its length less the count: a byte-mode
/// pipe's 0 less it, the capture's 4294967292 for 4 bytes). A peek cut to the buffer
/// (STATUS_BUFFER_OVERFLOW) is a success; any failure sets the status's error (the capture: 5
/// through the write end, 109 once the writer is gone and the pipe drained),
/// ERROR_NOT_ENOUGH_MEMORY when the block cannot be had.
///
/// # Safety
///
/// `buffer` is null or holds `size` bytes; `read`, `total` and `left` are each null or point at a
/// dword.
#[unsafe(export_name = "f2k_export_PeekNamedPipe")]
pub unsafe extern "system" fn peek_named_pipe(
    pipe: u32,
    buffer: *mut u8,
    size: u32,
    read: *mut u32,
    total: *mut u32,
    left: *mut u32,
) -> u32 {
    // SAFETY: the caller's buffer and dwords, when given (the contract).
    let (buffer, read, total, left) = unsafe {
        (
            OutBuf::optional(buffer, size as usize),
            Out::optional(read),
            Out::optional(total),
            Out::optional(left),
        )
    };
    bool_answer(peek(pipe, size, buffer, read, total, left))
}

/// PeekNamedPipe's work.
fn peek(
    pipe: u32,
    size: u32,
    buffer: Option<OutBuf<'_, u8>>,
    read: Option<Out<'_, u32>>,
    total: Option<Out<'_, u32>>,
    left: Option<Out<'_, u32>>,
) -> Result<(), Failure> {
    let length = PEEK_HEADER
        .checked_add(size as usize)
        .ok_or(Failure::Error(crate::heap::OutOfMemory.error()))?;
    let mut block = HeapArray::<u8>::new(length).map_err(|full| Failure::Error(full.error()))?;
    let io_status =
        ntcall::fs_control_file(pipe, FSCTL_PIPE_PEEK, &[], &mut block).map_err(Failure::Status)?;
    let word = |at: usize| crate::files::word(&block, at);
    let available = word(4);
    let message_length = word(12);
    let copied = (io_status.information as usize).saturating_sub(PEEK_HEADER);
    if let Some(mut total) = total {
        total.set(available);
    }
    if let Some(mut read) = read {
        read.set(copied as u32);
    }
    if let Some(mut buffer) = buffer {
        if copied > 0 {
            buffer.put(&block[PEEK_HEADER..PEEK_HEADER + copied]);
        }
    }
    if let Some(mut left) = left {
        left.set(message_length.wrapping_sub(copied as u32));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name: the device's prefix, then the process id and the serial, eight lowercase hex
    /// digits each.
    #[test]
    fn the_name_is_win32pipes_pid_serial() {
        let name = std::string::String::from_utf16(&pipe_name(0x1c, 0xab)).unwrap();
        assert_eq!(name, "\\Device\\NamedPipe\\Win32Pipes.0000001c.000000ab");
        assert_eq!(PIPE_NAME, name.len());
    }
}
