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

use super::super::call::{Handle, NtCall, NtResult, UserAddr};
use super::common::{complete, completion_event, file_object, signal};
use super::pipe::{check_all, control_rights};
use crate::fs::file::Context;
use crate::status::*;

/// The transfer method in an I/O control code's low two bits.
const METHOD_BUFFERED: u32 = 0;

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
    let input_length = if input.is_null() { 0 } else { input_length };
    let output_length = if output.is_null() { 0 } else { output_length };
    output.probe(output_length)?;
    let event = completion_event(event.raw())?;
    let size = input_length.max(output_length) as usize;
    let mut system = if size > 0 {
        Some(crate::mem::pool::allocate(size).ok_or(STATUS_INSUFFICIENT_RESOURCES)?)
    } else {
        None
    };
    let address = match system.as_mut() {
        Some(block) => {
            input.read(&mut block.as_mut()[..input_length as usize])?;
            block.as_mut().as_mut_ptr() as u32
        }
        None => 0,
    };
    let outcome = crate::dev::io::device_control(
        file,
        code,
        address,
        input_length,
        output_length,
        output.raw(),
    )?;
    if !crate::dev::io::nt_error(outcome.status) {
        if let Some(block) = &system {
            let count = (outcome.information as usize).min(output_length as usize);
            output.write(&block.as_ref()[..count])?;
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
