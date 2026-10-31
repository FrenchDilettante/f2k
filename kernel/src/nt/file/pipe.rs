//! The named-pipe file system's services: NtCreateNamedPipeFile (a pipe's server end), a pipe's
//! client end through NtCreateFile and NtOpenFile, and NtFsControlFile (FSCTL_PIPE_PEEK). The I/O
//! manager's checks first, then [`crate::fs::pipes`] makes, connects or peeks the pipe, and the
//! I/O manager's half of an open ([`io::insert`]) makes the end's file object and its handle.
//!
//! Byte-mode pipes of one instance, whose calls wait for the other end: a message-mode pipe, a
//! non-blocking one, a second instance of a name, and the file system controls other than the peek
//! are the stub path (STATUS_NOT_IMPLEMENTED).

use super::super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};
use super::common::{complete, completion_event, deliver, file_object, named, signal, Named};
use super::create::{
    FILE_CREATE,
    FILE_CREATED,
    FILE_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_OPENED,
    FILE_OPEN_IF,
    FILE_SYNCHRONOUS_IO_ALERT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use crate::fs::file::{rights, Context};
use crate::fs::io;
use crate::fs::pipes::{self, PipeEnd, PipeName};
use crate::status::*;

/// The create options a server's create takes (FILE_VALID_PIPE_OPTION_FLAGS, wdm.h): the
/// synchronous modes and write-through.
const FILE_VALID_PIPE_OPTION_FLAGS: u32 = 0x32;

/// The share bits: FILE_SHARE_READ and FILE_SHARE_WRITE make a pipe's configuration;
/// FILE_SHARE_DELETE no pipe takes.
const FILE_SHARE_READ_WRITE: u32 = 3;
const FILE_SHARE_DELETE: u32 = 4;

/// The pipe types, read modes and completion modes (ntifs.h's FILE_PIPE_*): byte streams that wait
/// are served, messages and non-blocking calls are the stub path.
const FILE_PIPE_BYTE_STREAM: u32 = 0;
const FILE_PIPE_MESSAGE: u32 = 1;
const FILE_PIPE_QUEUE_OPERATION: u32 = 0;
const FILE_PIPE_COMPLETE_OPERATION: u32 = 1;

/// FSCTL_PIPE_PEEK: CTL_CODE(FILE_DEVICE_NAMED_PIPE, 3, METHOD_BUFFERED, FILE_READ_DATA).
const FSCTL_PIPE_PEEK: u32 = 0x0011_400C;

/// A file system control code's required access (its bits 14 and 15): FILE_READ_ACCESS asks
/// FILE_READ_DATA of the handle, FILE_WRITE_ACCESS FILE_WRITE_DATA.
fn control_rights(code: u32) -> u32 {
    let mut needs = 0;
    if code & 0x4000 != 0 {
        needs |= rights::FILE_READ_DATA;
    }
    if code & 0x8000 != 0 {
        needs |= rights::FILE_WRITE_DATA;
    }
    needs
}

/// Whether `granted` holds every right of `needs`; STATUS_ACCESS_DENIED otherwise.
fn check_all(granted: u32, needs: u32) -> Result<(), NtStatus> {
    if granted & needs != needs {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

/// Whether a create's options ask synchronous I/O (the object then keeps a position).
fn synchronous(options: u32) -> bool {
    options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0
}

/// What a create or open of a pipe's name asks: the rights (mapped), the share, the disposition,
/// the options and the handle's inheritance.
pub struct ClientOpen {
    pub granted: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub inherit: bool,
}

/// Make `end`'s file object and its handle in the calling process, the slot and the I/O status
/// answered (`information` what the create did); the end abandoned when no object comes of it.
fn publish(
    end: PipeEnd,
    open: &io::Open,
    slot: UserPtr<u32>,
    io_status: UserAddr,
    information: u32,
) -> NtResult {
    let process = crate::user::args::calling_process();
    let access = rights::share_access(open.granted);
    let handle = io::insert(process, Context::Pipe(end), access, open, || {
        pipes::abandon(end)
    })?;
    deliver(slot, handle)?;
    complete(io_status, STATUS_SUCCESS, information);
    Ok(STATUS_SUCCESS)
}

/// A create or open of a pipe's name (NtCreateFile, NtOpenFile): the client end of the pipe
/// connected (see [`pipes::connect`]: STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PIPE_NOT_AVAILABLE,
/// STATUS_ACCESS_DENIED), the I/O status's Information FILE_OPENED. Only an open's dispositions
/// (FILE_OPEN, FILE_OPEN_IF) are served on a pipe; a directory asked for is
/// STATUS_NOT_A_DIRECTORY; a full handle table STATUS_INSUFFICIENT_RESOURCES.
pub fn open_client(
    name: &PipeName,
    open: &ClientOpen,
    slot: UserPtr<u32>,
    io_status: UserAddr,
) -> NtResult {
    if !matches!(open.disposition, FILE_OPEN | FILE_OPEN_IF) {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    if open.options & FILE_DIRECTORY_FILE != 0 {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    if crate::user::args::calling_process().handles_full() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let end = pipes::connect(name, open.granted)?;
    let object = io::Open {
        granted: open.granted,
        share: open.share as u8,
        inherit: open.inherit,
        synchronous: synchronous(open.options),
        delete_on_close: false,
    };
    publish(end, &object, slot, io_status, FILE_OPENED)
}

/// NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess,
/// CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances,
/// InboundQuota, OutboundQuota, DefaultTimeout): a new pipe named under `\Device\NamedPipe\`, its
/// server end's handle written back, the I/O status's Information FILE_CREATED. The share access
/// is the pipe's configuration (FILE_SHARE_WRITE: clients write, FILE_SHARE_READ: clients read),
/// the quotas its queues' (0: the default; see [`pipes::quota`]); the default timeout, optional, is
/// read and not consulted (no WaitNamedPipe yet).
///
/// The I/O manager's checks first, each STATUS_INVALID_PARAMETER: a pipe type, read mode or
/// completion mode past the defined ones, FILE_SHARE_DELETE or no share at all, a disposition other
/// than FILE_CREATE, FILE_OPEN or FILE_OPEN_IF, an option past FILE_VALID_PIPE_OPTION_FLAGS, both
/// synchronous modes or one without SYNCHRONIZE, no instance allowed, and a byte stream read as
/// messages. Then the name: a disk path is no pipe's (STATUS_INVALID_DEVICE_REQUEST, the answer a
/// file system without pipes gives). A name already a pipe's is STATUS_ACCESS_DENIED for
/// FILE_CREATE (CreateNamedPipe's FILE_FLAG_FIRST_PIPE_INSTANCE), and FILE_OPEN of a missing one
/// STATUS_OBJECT_NAME_NOT_FOUND; a full pool or handle table STATUS_INSUFFICIENT_RESOURCES.
#[allow(clippy::too_many_arguments)]
pub fn create_named_pipe_file(
    _call: &mut NtCall,
    slot: UserPtr<u32>,
    access: u32,
    attributes: UserAddr,
    io_status: UserAddr,
    share: u32,
    disposition: u32,
    options: u32,
    pipe_type: u32,
    read_mode: u32,
    completion_mode: u32,
    max_instances: u32,
    inbound_quota: u32,
    outbound_quota: u32,
    timeout: UserPtr<u64>,
) -> NtResult {
    let both = FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT;
    let invalid = pipe_type > FILE_PIPE_MESSAGE
        || read_mode > FILE_PIPE_MESSAGE
        || completion_mode > FILE_PIPE_COMPLETE_OPERATION
        || share & !FILE_SHARE_READ_WRITE != 0
        || share == 0
        || !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)
        || options & !FILE_VALID_PIPE_OPTION_FLAGS != 0
        || options & both == both
        || (synchronous(options) && access & rights::SYNCHRONIZE == 0)
        || max_instances == 0
        || (pipe_type == FILE_PIPE_BYTE_STREAM && read_mode == FILE_PIPE_MESSAGE);
    if invalid {
        return Err(STATUS_INVALID_PARAMETER);
    }
    debug_assert_eq!(share & FILE_SHARE_DELETE, 0);
    if pipe_type != FILE_PIPE_BYTE_STREAM || completion_mode != FILE_PIPE_QUEUE_OPERATION {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    if !timeout.is_null() {
        timeout.read()?;
    }
    let (name, inherit) = match named(attributes)? {
        Named::Pipe { name, inherit } => (name, inherit),
        Named::Disk(_) => return Err(STATUS_INVALID_DEVICE_REQUEST),
    };
    slot.addr().probe(4)?;
    io_status.probe(8)?;
    if crate::user::args::calling_process().handles_full() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    if disposition == FILE_OPEN {
        // Opening another instance of a pipe that exists is not served yet.
        return Err(if pipes::exists(&name) {
            STATUS_NOT_IMPLEMENTED
        } else {
            STATUS_OBJECT_NAME_NOT_FOUND
        });
    }
    let granted = rights::mapped(access);
    let end = match pipes::create(&name, share, granted, inbound_quota, outbound_quota) {
        Ok(end) => end,
        Err(Some(status)) => return Err(status),
        Err(None) if disposition == FILE_CREATE => return Err(STATUS_ACCESS_DENIED),
        Err(None) => return Err(STATUS_NOT_IMPLEMENTED),
    };
    let object = io::Open {
        granted,
        share: share as u8,
        inherit,
        synchronous: synchronous(options),
        delete_on_close: false,
    };
    publish(end, &object, slot, io_status, FILE_CREATED)
}

/// NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode,
/// InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength): the I/O manager's checks —
/// the handle, the access the code asks (FSCTL_PIPE_PEEK's FILE_READ_DATA: the capture's write end
/// gets STATUS_ACCESS_DENIED, its I/O status untouched), the I/O status block, an APC routine (not
/// supported), the output buffer, the event (reset) — then the object's device: a pipe's end
/// answers FSCTL_PIPE_PEEK (see [`pipes::peek`]) under the object's lock, the I/O status and the
/// event as a read's; STATUS_BUFFER_OVERFLOW, a warning, reports the bytes written as a success
/// does. Every other code, and every other device, is the stub path.
#[allow(clippy::too_many_arguments)]
pub fn fs_control_file(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    code: u32,
    _input: UserAddr,
    _input_length: u32,
    output: UserAddr,
    output_length: u32,
) -> NtResult {
    let object = file_object(handle.raw())?;
    check_all(object.granted, control_rights(code))?;
    io_status.probe(8)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    output.probe(output_length)?;
    let end = match (object.context, code) {
        (Context::Pipe(end), FSCTL_PIPE_PEEK) => end,
        _ => return Err(STATUS_NOT_IMPLEMENTED),
    };
    let event = completion_event(event.raw())?;
    let (status, information) =
        io::serialized_interruptible(&object, |_| pipes::peek(end, output, output_length))
            .and_then(|peeked| peeked)?;
    complete(io_status, status, information);
    signal(event);
    if status == STATUS_SUCCESS {
        Ok(status)
    } else {
        Err(status)
    }
}
