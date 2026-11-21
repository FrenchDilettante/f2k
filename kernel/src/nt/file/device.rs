//! NtDeviceIoControlFile: a device control request, for a device a loaded driver made, carried to
//! its driver as IRP_MJ_DEVICE_CONTROL by the I/O manager ([`crate::dev::io::device_control`]).
//!
//! The I/O manager's checks come first, as for NtFsControlFile: the handle, the access the code
//! asks (its RequiredAccess bits: FILE_READ_DATA, FILE_WRITE_DATA), the I/O status block, an APC
//! routine (not supported), the event (reset). Then METHOD_BUFFERED's system buffer, a block of
//! the larger of the two lengths holding the input, the driver's answer copied back into the
//! output buffer (as many bytes as the I/O status's Information says, at most the buffer's
//! length) unless the request failed. The service's status is the dispatch routine's; the I/O
//! status block takes the IRP's, unless it is an error. The other methods, and the file systems'
//! own devices (the disk's, the pipes', the null device's), are the stub path.
//!
//! NtReadFile, NtWriteFile and NtFlushBuffersFile on a driver's device ([`read_write`],
//! [`flush`]) go down as IRP_MJ_READ, IRP_MJ_WRITE and IRP_MJ_FLUSH_BUFFERS, the caller's buffer
//! reached as the device asks: through a system buffer for DO_BUFFERED_IO, as the IRP's UserBuffer
//! for neither (DO_DIRECT_IO's MDL is the stub path). A driver that never set the major function
//! answers through the I/O manager's STATUS_INVALID_DEVICE_REQUEST (ERROR_INVALID_FUNCTION, as
//! the `drvload` capture's `unknown` block shows).

use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{complete, completion_event, file_object, signal};
use super::{buffered_lengths, check_all, control_rights, copied_back, METHOD_BUFFERED};
use crate::dev::io::{DeviceFile, Transfer};
use crate::dev::ntddk::{DO_BUFFERED_IO, DO_DIRECT_IO};
use crate::fs::file::Context;
use crate::status::*;

/// NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
/// IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength).
#[allow(clippy::too_many_arguments)]
pub fn device_io_control_file(
    _call: &mut NtCall,
    handle: Handle,
    event: Handle,
    routine: UserAddr,
    _context: UserAddr,
    io_status: UserAddr,
    code: u32,
    input: UserAddr,
    input_length: u32,
    output: UserAddr,
    output_length: u32,
) -> NtResult {
    let object = file_object(handle.raw())?;
    check_all(object.granted, control_rights(code))?;
    io_status.probe(8)?;
    if !routine.is_null() {
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let Context::Device(file) = object.context else {
        return Err(super::common::device_request("NtDeviceIoControlFile"));
    };
    if code & 3 != METHOD_BUFFERED {
        crate::dbgprint::unhandled(
            "ntdll",
            "NtDeviceIoControlFile",
            format_args!("IoControlCode={code:#010x}"),
            format_args!(
                "METHOD_IN_DIRECT, METHOD_OUT_DIRECT and METHOD_NEITHER are not yet implemented"
            ),
        );
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    let (input_length, output_length, size) = buffered_lengths(
        (!input.is_null()).then_some(input_length),
        (!output.is_null()).then_some(output_length),
    );
    output.probe(output_length)?;
    let event = completion_event(event.raw())?;
    let system = if size > 0 {
        let mut block = crate::mem::pool::allocate(size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        input.read(&mut block.as_mut()[..input_length as usize])?;
        Some(block)
    } else {
        None
    };
    // The system buffer is the IRP's while the driver holds it, handed back with the outcome.
    let (outcome, system) = crate::dev::io::device_control(
        file,
        code,
        system,
        input_length,
        output_length,
        output.raw(),
    )?;
    if let Some(count) = copied_back(outcome.status, outcome.information, output_length) {
        if let Some(block) = &system {
            output.write(&block.as_ref()[..count as usize])?;
        }
        complete(io_status, outcome.status, outcome.information);
        signal(event);
    }
    drop(system);
    if outcome.returned.is_success() {
        Ok(outcome.returned)
    } else {
        Err(outcome.returned)
    }
}

/// A read (`write` false) or a write of `length` bytes at `buffer` on a driver's device, at
/// `offset` (none for the file object's position): the count the driver moved, or the IRP's
/// error.
pub fn read_write(
    file: DeviceFile,
    write: bool,
    buffer: UserAddr,
    length: u32,
    offset: Option<u64>,
) -> Result<u32, NtStatus> {
    let flags = crate::dev::io::device_flags(file);
    let service = if write { "NtWriteFile" } else { "NtReadFile" };
    if flags & DO_DIRECT_IO != 0 {
        crate::dbgprint::unhandled(
            "ntdll",
            service,
            format_args!("FileHandle=<a DO_DIRECT_IO device>"),
            format_args!("a direct I/O transfer's MDL is not yet implemented"),
        );
        return Err(STATUS_NOT_IMPLEMENTED);
    }
    buffer.probe(length)?;
    let system = if flags & DO_BUFFERED_IO != 0 && length > 0 {
        let mut block =
            crate::mem::pool::allocate(length as usize).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        if write {
            buffer.read(&mut block.as_mut()[..length as usize])?;
        }
        Some(block)
    } else {
        None
    };
    let major = if write {
        crate::dev::irp::IRP_MJ_WRITE
    } else {
        crate::dev::irp::IRP_MJ_READ
    };
    // The system buffer is the IRP's while the driver holds it, handed back with the outcome.
    let (outcome, system) = crate::dev::io::read_write(
        file,
        major,
        Transfer {
            system,
            user_buffer: buffer.raw(),
            length,
            offset,
        },
    )?;
    let count = copied_back(outcome.status, outcome.information, length).ok_or(outcome.status)?;
    if let (false, Some(block)) = (write, &system) {
        buffer.write(&block.as_ref()[..count as usize])?;
    }
    Ok(count)
}

/// A flush of a driver's device: the IRP's error, if any.
pub fn flush(file: DeviceFile) -> Result<(), NtStatus> {
    let outcome = crate::dev::io::flush(file)?;
    if crate::dev::io::nt_error(outcome.status) {
        return Err(outcome.status);
    }
    Ok(())
}
