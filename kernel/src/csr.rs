//! The client-server runtime's stand-in: the console server kernel32's console calls reach.
//!
//! Windows 2000's kernel32 sends its console work to csrss, whose console server owns each
//! process's console handles, through ntdll's CsrClientCallServer (an LPC request on the process's
//! CSR port). F2K has no csrss (a known gap): ntdll's CsrClientCallServer raises the internal
//! service [`SYS_CSR_CALL`](crate::user::syscall::SYS_CSR_CALL) instead, and this module serves
//! the message — its header, the console API's data after it — with the
//! rules `rtl::console` holds (shared with kernel32's host tests), over the calling process's
//! console handles. The console's screen is the serial line (COM1), as the kernel's console has
//! always been. Console handles stay outside the kernel's handle table, as on Windows 2000.

use rtl::console::{header, Handles, Screen, DATA_WORDS, MESSAGE_BYTES};

use crate::nt::call::{NtResult, Status, UserAddr, STATUS_INVALID_PARAMETER};
use crate::user::syscall::ServiceFn;

/// STATUS_INVALID_USER_BUFFER: a buffer that passed the probe but could not be read.
const STATUS_INVALID_USER_BUFFER: u32 = 0xC000_00E8;

/// The service the dispatcher raises SYS_CSR_CALL into: its four dword arguments, and its body.
pub const SERVICE: (u32, ServiceFn) = (16, service);

/// SYS_CSR_CALL's service: CsrClientCallServer(message, capture buffer, API number, data length),
/// answered for the calling process.
#[cfg(target_arch = "x86")]
fn service(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let mut call = crate::nt::call::NtCall::new(frame);
    let handles = call.process().console_mut();
    let result = client_call_server(
        handles,
        &mut Serial,
        UserAddr(args[0]),
        UserAddr(args[1]),
        args[2],
        args[3],
    );
    call.finish(result);
}

/// Host builds compile the dispatch but never raise it.
#[cfg(not(target_arch = "x86"))]
fn service(_frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    unreachable!("the gate is the target's");
}

/// Serve one message: its header and `length` bytes of API data read from the caller's memory,
/// the API served over `handles`, and the answer written back — the capture buffer and API number
/// as the call named them, the status as the message's ReturnValue, the data as the server left it
/// (CsrClientCallServer's writes and the server's reply, as Windows 2000's port carries them). The
/// status is the answer too. Data longer than the largest API's, or not whole dwords, is
/// STATUS_INVALID_PARAMETER; a message the caller cannot name STATUS_ACCESS_VIOLATION.
pub fn client_call_server(
    handles: &mut Handles,
    screen: &mut impl Screen,
    message: UserAddr,
    capture: UserAddr,
    api: u32,
    length: u32,
) -> NtResult {
    let length = length as usize;
    if length > 4 * DATA_WORDS || length % 4 != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = header::DATA + length;
    let mut bytes = [0u8; MESSAGE_BYTES];
    message.read(&mut bytes[..size])?;
    let mut data = [0usize; DATA_WORDS];
    for (word, raw) in data
        .iter_mut()
        .zip(bytes[header::DATA..size].chunks_exact(4))
    {
        *word = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    }
    let status = rtl::console::serve(handles, screen, api, &mut data[..length / 4]);
    let mut put = |at: usize, value: u32| bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    put(header::CAPTURE_BUFFER, capture.raw());
    put(header::API_NUMBER, api);
    put(header::RETURN_VALUE, status);
    for (index, &word) in data[..length / 4].iter().enumerate() {
        put(header::DATA + 4 * index, word as u32);
    }
    message
        .offset(header::CAPTURE_BUFFER as u32)
        .write(&bytes[header::CAPTURE_BUFFER..size])?;
    if status >> 30 >= 2 {
        Err(Status(status))
    } else {
        Ok(status)
    }
}

/// The console's screen: the serial line, the client's bytes read through a kernel chunk.
struct Serial;

impl Screen for Serial {
    /// A buffer the caller cannot name is refused before a byte reaches the screen
    /// (STATUS_ACCESS_VIOLATION, ERROR_NOACCESS to the caller); one that passed the probe but cannot
    /// be read is an invalid user buffer (ERROR_INVALID_USER_BUFFER), what was read before it shown
    /// — the two answers the bare/badptr fixture's console writes capture.
    fn write(&mut self, buffer: usize, count: usize) -> Result<(), u32> {
        let (buffer, count) = (buffer as u32, count as u32);
        crate::user::syscall::probe_user_range(buffer, count)?;
        let mut chunk = [0u8; 256];
        let mut done = 0u32;
        while done < count {
            let take = (count - done).min(chunk.len() as u32) as usize;
            UserAddr(buffer.wrapping_add(done))
                .read(&mut chunk[..take])
                .map_err(|_| STATUS_INVALID_USER_BUFFER)?;
            for &byte in &chunk[..take] {
                screen_byte(byte);
            }
            done += take as u32;
        }
        Ok(())
    }
}

/// One byte to the screen: COM1.
#[cfg(target_arch = "x86")]
fn screen_byte(byte: u8) {
    crate::hw::serial::write_byte_blocking(byte);
}

/// Host builds have no serial line.
#[cfg(not(target_arch = "x86"))]
fn screen_byte(_byte: u8) {}

#[cfg(test)]
mod tests {
    use rtl::console::api;

    use super::*;

    /// The host's user memory refuses every transfer (the gate is the target's): a message the
    /// caller cannot name fails before the server is asked.
    #[test]
    fn the_message_must_be_readable_and_its_data_whole_dwords() {
        let mut handles = Handles::standard();
        let call = |handles: &mut Handles, length| {
            client_call_server(
                handles,
                &mut Serial,
                UserAddr(0x40_0000),
                UserAddr(0),
                api::CLOSE_HANDLE,
                length,
            )
        };
        assert_eq!(call(&mut handles, 4), Err(Status(0xC000_0005)));
        assert_eq!(handles, Handles::standard(), "nothing served");
        assert_eq!(call(&mut handles, 6), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            call(&mut handles, 4 * DATA_WORDS as u32 + 4),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    /// The process parameters' standard handles are the ones the console server opens a process
    /// with.
    #[test]
    fn the_parameters_name_the_servers_standard_handles() {
        use crate::user::params::{STD_ERROR, STD_INPUT, STD_OUTPUT};
        assert_eq!(
            [STD_INPUT, STD_OUTPUT, STD_ERROR],
            rtl::console::STANDARD_HANDLES
        );
    }
}
