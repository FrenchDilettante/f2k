//! The client-server runtime's stand-in: the console server kernel32's console calls reach.
//!
//! Windows 2000's kernel32 sends its console work to csrss, whose console server owns each
//! process's console handles, through ntdll's CsrClientCallServer (an LPC request on the process's
//! CSR port). F2K has no csrss (a known gap): ntdll's CsrClientCallServer raises the internal
//! service [`SYS_CSR_CALL`](crate::user::syscall::SYS_CSR_CALL) instead, and this module serves
//! the message — its header, the console API's data after it — with the
//! rules `rtl::console` holds (shared with kernel32's host tests), over the calling process's
//! console handles and the one console every process shares ([`Console`]: its modes, its screen
//! buffer, its title). Console handles stay outside the kernel's handle table, as on Windows 2000.
//!
//! What a client writes reaches two places, in order: each byte goes to the serial line (COM1)
//! unchanged, as the kernel's console always has (the suite reads program output there), then
//! through the screen buffer's renderer. After each call the rows it changed are copied to the
//! VGA text screen and the hardware cursor follows the buffer's.
//!
//! The keyboard's bytes reach the same console from the keyboard driver's DPC ([`key_byte`]): the
//! console's producer turns them into key event records, appended to its input buffer for the
//! input APIs to serve.

use rtl::console::screen::ScreenBuffer;
use rtl::console::{header, Client, Console, Handles, DATA_WORDS, MESSAGE_BYTES};

use crate::hw::portio::Io;
use crate::hw::vga::{CellMemory, TextScreen};
use crate::nt::call::{NtResult, Status, UserAddr, STATUS_INVALID_PARAMETER};
use crate::user::syscall::ServiceFn;

/// STATUS_INVALID_USER_BUFFER: a buffer that passed the probe but could not be read.
const STATUS_INVALID_USER_BUFFER: u32 = 0xC000_00E8;

/// The service the dispatcher raises SYS_CSR_CALL into: its four dword arguments, and its body.
pub const SERVICE: (u32, ServiceFn) = (16, service);

/// The console: one, shared by every process.
#[cfg(target_arch = "x86")]
static mut CONSOLE: Console = Console::new();

/// The console's state, borrowed for one service call, one keyboard byte, or the boot's first
/// look.
///
/// # Safety
///
/// A single CPU, interrupts off across the system service: the borrow is the console's only one.
/// The keyboard's DPC borrows it too, at the dispatch level: DPCs drain only on an interrupt's
/// exit and in the idle loop, neither of which can run inside the service, and no thread is
/// switched to while a DPC runs, so no service starts inside one. The DPC queue runs one routine
/// at a time.
#[cfg(target_arch = "x86")]
unsafe fn console() -> &'static mut Console {
    // SAFETY: the caller's.
    unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) }
}

/// The boot's step: the text screen shows the fresh console's screen buffer (whatever the firmware
/// and loader left there cleared), the hardware cursor at its cursor.
#[cfg(target_arch = "x86")]
pub fn init() {
    // SAFETY: the boot context, before any process runs.
    let screen = &mut unsafe { console() }.screen;
    let mut vga = crate::hw::vga::screen();
    vga.clear(rtl::console::screen::DEFAULT_ATTRIBUTE);
    vga.put_grid(screen.cells());
    let (row, column) = screen.cursor();
    vga.set_cursor(row, column);
    screen.take_damage();
}

/// SYS_CSR_CALL's service: CsrClientCallServer(message, capture buffer, API number, data length),
/// answered for the calling process.
#[cfg(target_arch = "x86")]
fn service(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let mut call = crate::nt::call::NtCall::new(frame);
    let handles = call.process().console_mut();
    // SAFETY: a system service: one CPU, interrupts off.
    let console = unsafe { console() };
    let result = client_call_server(
        console,
        handles,
        &mut Dual,
        UserAddr(args[0]),
        UserAddr(args[1]),
        args[2],
        args[3],
    );
    present(&mut console.screen, &mut crate::hw::vga::screen());
    call.finish(result);
}

/// The keyboard DPC's step: one key byte into the console's producer, each record it completes
/// appended to the input buffer, the lights a toggle changes shown through `lights`. A record the
/// full buffer cannot take is reported on COM1; the `kbd-smoke` diagnostic boot reports every
/// record as the buffer holds it.
#[cfg(target_arch = "x86")]
pub fn key_byte(byte: u8, lights: &mut impl rtl::console::input::Lights) {
    use rtl::console::input::Append;
    // SAFETY: the keyboard's DPC, at the dispatch level (see `console`): SYS_CSR_CALL's service
    // runs with interrupts masked from its gate to its return, so no DPC drains inside it.
    let console = unsafe { console() };
    console.key_byte(byte, lights, &mut |outcome, record| {
        if outcome == Append::Dropped {
            crate::serial_println!("F2K: kbd: input buffer full: a key event dropped");
        }
        #[cfg(feature = "kbd-smoke")]
        crate::serial_println!(
            "F2K: kbd: record {} vk={:#04x} scan={:#04x} char={:#06x} state={:#06x} repeat={}{}",
            if record.key_down != 0 { "down" } else { "up" },
            record.virtual_key_code,
            record.virtual_scan_code,
            record.char,
            record.control_key_state,
            record.repeat_count,
            match outcome {
                Append::Stored => "",
                Append::Coalesced => " (coalesced)",
                Append::Filtered => " (filtered)",
                Append::Dropped => " (dropped)",
            }
        );
        #[cfg(not(feature = "kbd-smoke"))]
        let _ = record;
    });
}

/// Copy what the screen buffer changed since the last look to the text screen: the rows it
/// touched, then the hardware cursor.
fn present<M: CellMemory, P: Io>(screen: &mut ScreenBuffer, vga: &mut TextScreen<M, P>) {
    let Some(rows) = screen.take_damage() else {
        return;
    };
    for row in rows {
        vga.put_row(row, &screen.cells()[row]);
    }
    let (row, column) = screen.cursor();
    vga.set_cursor(row, column);
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
    console: &mut Console,
    handles: &mut Handles,
    client: &mut impl Client,
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
    let status = rtl::console::serve(console, handles, client, api, &mut data[..length / 4]);
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

/// The calling client: its bytes read through a kernel chunk, each chunk to the serial line, then
/// to the screen buffer.
struct Dual;

impl Client for Dual {
    /// A buffer the caller cannot name is refused before a byte reaches the screen
    /// (STATUS_ACCESS_VIOLATION, ERROR_NOACCESS to the caller); one that passed the probe but
    /// cannot be read is an invalid user buffer (ERROR_INVALID_USER_BUFFER), what was read
    /// before it shown — the two answers the bare/badptr fixture's console writes capture.
    fn show(&mut self, screen: &mut ScreenBuffer, buffer: usize, count: usize) -> Result<(), u32> {
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
                serial_byte(byte);
            }
            screen.render(&chunk[..take]);
            done += take as u32;
        }
        Ok(())
    }

    /// The caller's memory, refused as the services refuse it: STATUS_ACCESS_VIOLATION.
    fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32> {
        crate::user::syscall::probe_user_range(buffer as u32, into.len() as u32)?;
        UserAddr(buffer as u32)
            .read(into)
            .map_err(|fault| Status::from(fault).0)
    }

    fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32> {
        crate::user::syscall::probe_user_range(buffer as u32, bytes.len() as u32)?;
        UserAddr(buffer as u32)
            .write(bytes)
            .map_err(|fault| Status::from(fault).0)
    }
}

/// One byte to the serial line: COM1.
#[cfg(target_arch = "x86")]
fn serial_byte(byte: u8) {
    crate::hw::serial::write_byte_blocking(byte);
}

/// Host builds have no serial line.
#[cfg(not(target_arch = "x86"))]
fn serial_byte(_byte: u8) {}

#[cfg(test)]
mod tests {
    use rtl::console::api;

    use super::*;

    /// The host's user memory refuses every transfer (the gate is the target's): a message the
    /// caller cannot name fails before the server is asked.
    #[test]
    fn the_message_must_be_readable_and_its_data_whole_dwords() {
        let mut handles = Handles::standard();
        let mut console = Console::new();
        let mut call = |handles: &mut Handles, length| {
            client_call_server(
                &mut console,
                handles,
                &mut Dual,
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

    /// After a call, the text screen gets the rows the screen buffer changed and its cursor;
    /// nothing at all when nothing changed.
    #[test]
    fn the_text_screen_gets_the_changed_rows_and_the_cursor() {
        use std::vec::Vec;

        use rtl::console::screen::{Cell, HEIGHT, WIDTH};

        struct Memory(Vec<u16>);
        impl CellMemory for Memory {
            fn store(&mut self, index: usize, word: u16) {
                self.0[index] = word;
            }
        }
        #[derive(Default)]
        struct Ports(Vec<(u16, u8)>);
        impl Io for Ports {
            fn out(&mut self, port: u16, byte: u8) {
                self.0.push((port, byte));
            }

            fn read(&mut self, _port: u16) -> u8 {
                0
            }

            fn read_word(&mut self, _port: u16) -> u16 {
                0
            }
        }

        use crate::hw::vga::{COLUMNS, ROWS};
        let mut vga = TextScreen::new(Memory(std::vec![0; COLUMNS * ROWS]), Ports::default());
        let mut screen = ScreenBuffer::new();
        screen.take_damage();
        present(&mut screen, &mut vga);
        let (memory, ports) = vga.parts();
        assert!(
            memory.0.iter().all(|&word| word == 0) && ports.0.is_empty(),
            "nothing changed"
        );
        screen.set_cursor(2, 0);
        screen.write_bytes(b"ok");
        present(&mut screen, &mut vga);
        let (memory, ports) = vga.parts();
        let row = |row: usize| &memory.0[row * COLUMNS..row * COLUMNS + WIDTH.min(COLUMNS)];
        assert_eq!(row(2)[..3], [0x076F, 0x076B, 0x0720]);
        assert!(
            row(0)
                .iter()
                .chain(row(HEIGHT.min(ROWS) - 1))
                .all(|&word| word == 0),
            "only row 2"
        );
        let location = 2 * COLUMNS as u16 + 2;
        assert_eq!(
            ports.0,
            [
                (0x3D4, 0x0E),
                (0x3D5, (location >> 8) as u8),
                (0x3D4, 0x0F),
                (0x3D5, location as u8)
            ]
        );
        assert_eq!(
            screen.cell(2, 0),
            Cell {
                character: b'o',
                attribute: 0x07
            }
        );
    }
}
