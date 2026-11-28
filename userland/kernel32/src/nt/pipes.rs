//! The host tests' named-pipe services: NtCreateNamedPipeFile recorded and answered with
//! [`PIPE_READ`], NtFsControlFile's peek answered from the stand-in pipe ([`PIPE`]); the client
//! end's open is the file stand-in's NtOpenFile ([`super::files`]).

use std::cell::RefCell;
use std::string::String;
use std::vec::Vec;

use super::host::FAIL_NEXT;
use super::{IoStatus, ObjectAttributes, UnicodeString};

/// The read end's handle NtCreateNamedPipeFile answers.
pub const PIPE_READ: u32 = 0x60;
use rtl::status::{STATUS_BUFFER_OVERFLOW, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

/// A named-pipe call, as the stand-in took it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PipeCall {
    /// NtCreateNamedPipeFile: the access, the name, the attributes' flags, the share, the
    /// disposition, the options, the type, read mode and completion mode, the instances, the
    /// quotas and the default timeout.
    Create {
        access: u32,
        name: String,
        attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        modes: [u32; 3],
        instances: u32,
        quotas: [u32; 2],
        timeout: Option<i64>,
    },
    /// NtFsControlFile: the handle, the code, the output buffer's length.
    Control {
        handle: u32,
        code: u32,
        output_length: u32,
    },
}

/// The stand-in pipe a peek reads: its state, and the bytes it holds.
pub struct Pipe {
    pub state: u32,
    pub bytes: Vec<u8>,
}

std::thread_local! {
    pub static PIPE_CALLS: RefCell<Vec<PipeCall>> = const { RefCell::new(Vec::new()) };
    pub static PIPE: RefCell<Pipe> = const { RefCell::new(Pipe { state: 3, bytes: Vec::new() }) };
    /// The status the service after a successful NtCreateNamedPipeFile fails with (0: none):
    /// the client end's open, in CreatePipe.
    pub static FAIL_AFTER_CREATE: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// The calls taken since the last look.
pub fn pipe_calls() -> Vec<PipeCall> {
    PIPE_CALLS.with(|calls| std::mem::take(&mut *calls.borrow_mut()))
}

fn record(call: PipeCall) {
    PIPE_CALLS.with(|calls| calls.borrow_mut().push(call));
}

fn failure() -> Option<u32> {
    let status = FAIL_NEXT.with(|cell| cell.replace(0));
    (status != 0).then_some(status)
}

unsafe fn text(string: *const UnicodeString) -> String {
    // SAFETY: the caller's string, its buffer holding its length.
    String::from_utf16_lossy(unsafe { (*string).units() })
}

pub unsafe extern "system" fn NtCreateNamedPipeFile(
    handle: *mut u32,
    access: u32,
    attributes: *const ObjectAttributes,
    io_status: *mut IoStatus,
    share: u32,
    disposition: u32,
    options: u32,
    pipe_type: u32,
    read_mode: u32,
    completion_mode: u32,
    maximum_instances: u32,
    inbound_quota: u32,
    outbound_quota: u32,
    default_timeout: *const i64,
) -> u32 {
    // SAFETY: the caller's attributes, their name, and its timeout when given.
    let (name, flags, timeout) = unsafe {
        (
            text((*attributes).object_name),
            (*attributes).attributes,
            (!default_timeout.is_null()).then(|| *default_timeout),
        )
    };
    record(PipeCall::Create {
        access,
        name,
        attributes: flags,
        share,
        disposition,
        options,
        modes: [pipe_type, read_mode, completion_mode],
        instances: maximum_instances,
        quotas: [inbound_quota, outbound_quota],
        timeout,
    });
    if let Some(status) = failure() {
        return status;
    }
    // SAFETY: the caller's slots.
    unsafe {
        handle.write(PIPE_READ);
        io_status.write(IoStatus {
            status: 0,
            information: 2,
        });
    }
    FAIL_NEXT.with(|next| next.set(FAIL_AFTER_CREATE.with(|after| after.replace(0))));
    0
}

/// A device's control request: the stand-ins' handles name no driver's device.
pub unsafe extern "system" fn NtDeviceIoControlFile(
    _handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    _io_status: *mut IoStatus,
    _code: u32,
    _input: *const u8,
    _input_length: u32,
    _output: *mut u8,
    _output_length: u32,
) -> u32 {
    STATUS_INVALID_HANDLE
}

/// The peek, as the named-pipe file system answers it: FILE_PIPE_PEEK_BUFFER's header, then
/// what of the stand-in pipe's bytes fits (STATUS_BUFFER_OVERFLOW when not all do); a buffer
/// shorter than the header STATUS_INVALID_PARAMETER.
pub unsafe extern "system" fn NtFsControlFile(
    handle: u32,
    _event: u32,
    _routine: usize,
    _context: usize,
    io_status: *mut IoStatus,
    code: u32,
    _input: *const u8,
    _input_length: u32,
    output: *mut u8,
    output_length: u32,
) -> u32 {
    record(PipeCall::Control {
        handle,
        code,
        output_length,
    });
    if let Some(status) = failure() {
        return status;
    }
    if handle != PIPE_READ {
        return STATUS_INVALID_HANDLE;
    }
    if output_length < 16 {
        return STATUS_INVALID_PARAMETER;
    }
    PIPE.with(|pipe| {
        let pipe = pipe.borrow();
        let room = output_length as usize - 16;
        let copied = pipe.bytes.len().min(room);
        let header = [pipe.state, pipe.bytes.len() as u32, 0, 0];
        let status = if copied < pipe.bytes.len() {
            STATUS_BUFFER_OVERFLOW
        } else {
            0
        };
        // SAFETY: the caller's output buffer of `output_length` bytes, and its I/O status.
        unsafe {
            for (index, word) in header.iter().enumerate() {
                output
                    .add(4 * index)
                    .copy_from_nonoverlapping(word.to_le_bytes().as_ptr(), 4);
            }
            output
                .add(16)
                .copy_from_nonoverlapping(pipe.bytes.as_ptr(), copied);
            io_status.write(IoStatus {
                status,
                information: 16 + copied as u32,
            });
        }
        status
    })
}
