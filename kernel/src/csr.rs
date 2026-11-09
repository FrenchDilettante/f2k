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
//! through the screen buffer's renderer. Only the standard handles' writes reach the serial line
//! (`rtl::console::Handles`): it stands for the file a capture redirects standard output to, and a
//! screen buffer opened by name (CONOUT$) writes to the screen alone. Under the kernel option
//! `redirected` (the harness's runs of the corpus) the standard handles' writes reach the serial
//! line alone, as the capture's redirected output never reaches the real machine's screen. After
//! each call the window's rows it changed are copied to the VGA text screen and the hardware
//! cursor follows the buffer's.
//!
//! The keyboard's bytes reach the same console from the keyboard driver's DPC ([`key_byte`]): the
//! console's producer turns them into key event records, appended to its input buffer for the
//! input APIs to serve.
//!
//! The console's input-wait event is a notification event the server makes for the process that
//! first asks for it (kernel32, the first time it must wait on the console) and hands to it as a
//! handle; the process's handle keeps it, and it goes with the process. After each call and each
//! keyboard byte it shows whether the input buffer holds records: a read the server answered
//! STATUS_PENDING waits on it.
//!
//! The console's control events — Ctrl+C and Ctrl+Break, from the keyboard or
//! GenerateConsoleCtrlEvent — are [`ctrl`]'s: the console's processes, and the control thread that
//! delivers each event to them. The base server's APIs F2K serves (`rtl::console::base`) come
//! through the same service: kernel32's announcement of a process it created, which puts the
//! process in its process group, and the process's shutdown level and flags, which the server
//! keeps with its entry for the session's end. So does the user server's one API
//! (`rtl::console::user`), user32's ExitWindowsEx: the request for the session's end, which the
//! control thread carries out ([`crate::session`]).

pub mod ctrl;

use core::mem::offset_of;

use rtl::console::screen::{ScreenBuffer, DEFAULT_ATTRIBUTE};
use rtl::console::{Client, Console, CsrApiMsg, Handles, DATA_WORDS};
use rtl::pod::Pod;

use self::ctrl::Control;
use crate::hal::Io;
#[cfg(target_arch = "x86")]
use crate::hal::{Hal, PLATFORM};
use crate::hw::vga::{CellMemory, TextScreen};
#[cfg(target_arch = "x86")]
use crate::level::{At, Dispatch, LevelCell, Passive};
use crate::nt::call::{NtResult, UserAddr};
#[cfg(target_arch = "x86")]
use crate::ob::ObjectId;
#[cfg(target_arch = "x86")]
use crate::sched::wait::WaitableId;
use crate::status::*;
use crate::user::syscall::ServiceFn;

/// The service the dispatcher raises SYS_CSR_CALL into: its four dword arguments, and its body.
pub const SERVICE: (u32, ServiceFn) = (16, service);

/// The console server's state: the one console every process shares, and its input-wait event
/// (Windows 2000's CONSOLE_INFORMATION.InputEvent).
#[cfg(target_arch = "x86")]
struct ConsoleServer {
    console: Console,
    /// The console's processes and the control events raised for them (see [`ctrl`]).
    ctrl: Control,
    /// The console's input-wait event, once a process asked for it: the object, which the server
    /// holds a reference on until no process is left.
    input_event: Option<ObjectId>,
    /// Whether the console has its first program's name for its title.
    named: bool,
    /// The writes a call made into its caller's stack guard page, kept for the caller to copy out
    /// below the server's level (see [`Staged`]).
    staged: Staged,
}

/// The room for a call's staged writes: the most one call writes to its caller (a whole input
/// buffer's records, 7680 bytes; a Unicode title, 2050), with room to spare.
const STAGED_BYTES: usize = 8 * 1024;

const _: () = assert!(
    rtl::console::input::INPUT_BUFFER_RECORDS * rtl::console::input::INPUT_RECORD_BYTES
        < STAGED_BYTES
);

/// A call's writes into its caller's stack guard page, held for the copy into the caller's memory
/// below the server's level, where the fault on the guard page grows the stack as any fault on it
/// does (a fault at the server's level cannot be resolved). This is Windows 2000's shape: csrss
/// answers into the message's capture buffer, and kernel32 copies the answer into the caller's
/// buffer itself, in user mode. One contiguous run of bytes, written by one call at a time.
struct Staged {
    /// The thread whose call staged the bytes, until it has copied them out; none when free.
    owner: Option<crate::sched::thread::ThreadId>,
    /// Where the bytes go in the caller's memory.
    address: u32,
    length: usize,
    bytes: [u8; STAGED_BYTES],
}

impl Staged {
    const fn new() -> Self {
        Staged {
            owner: None,
            address: 0,
            length: 0,
            bytes: [0; STAGED_BYTES],
        }
    }

    /// Take `bytes`, bound for `address`, after what is staged already when they follow it (a
    /// write made in pieces); false, nothing taken, when another thread's bytes wait to be copied
    /// out, the bytes do not follow, or there is no room.
    fn stage(&mut self, address: u32, bytes: &[u8]) -> bool {
        if self.owner.is_some() {
            return false;
        }
        if self.length == 0 {
            self.address = address;
        } else if self.address.wrapping_add(self.length as u32) != address {
            return false;
        }
        let Some(room) = self.bytes.get_mut(self.length..self.length + bytes.len()) else {
            return false;
        };
        room.copy_from_slice(bytes);
        self.length += bytes.len();
        true
    }
}

/// The console server, at the dispatch level: the keyboard's DPC feeds it there, and the system
/// service raises there to serve a call. The dispatch token keeps the two apart: no DPC runs while
/// the service holds it, and no service starts inside a DPC.
#[cfg(target_arch = "x86")]
static SERVER: LevelCell<Dispatch, ConsoleServer> = LevelCell::new(ConsoleServer {
    console: Console::new(),
    ctrl: Control::new(),
    input_event: None,
    named: false,
    staged: Staged::new(),
});

/// The kernel option under which the standard handles stand for a file ([`Console::redirect`]):
/// the test harness's runs of the corpus, as capture.bat redirects each program's standard output
/// and error to a file on the real machine.
pub const REDIRECTED: &[u8] = b"redirected";

/// The console's title, from the first program the boot loads into it: its image path (see
/// [`Console::name`]); and, under the kernel option [`REDIRECTED`], its standard handles standing
/// for a file. The programs after it share the console, its title and its standard handles'
/// redirection.
#[cfg(target_arch = "x86")]
pub fn name_console(image_path: &[u8]) {
    use crate::boot::cmdline::{kernel_command_line, kernel_option};
    let redirected = kernel_option(kernel_command_line(), REDIRECTED);
    crate::level::raised::<Dispatch, _>(|dispatch| {
        let server = SERVER.get(dispatch);
        if !core::mem::replace(&mut server.named, true) {
            server.console.name(image_path);
            if redirected {
                server.console.redirect();
            }
        }
    });
}

/// The boot's step: the text screen shows the fresh console's window (whatever the firmware and
/// loader left there cleared), the hardware cursor at its cursor.
///
/// The boot runs with interrupts masked and the interrupt controllers not set up yet, so it does
/// not raise to the server's level (a raise below the clock level enables interrupts). Nor does it
/// need to look at the server: its console is a fresh one, whose window is blank in the default
/// attribute with the cursor home, and whose screen buffer holds no change for the first call's
/// look to copy.
#[cfg(target_arch = "x86")]
pub fn init() {
    show_fresh(&mut crate::hw::vga::screen());
}

/// Show what a fresh console's window holds: every cell blank in the default attribute, the
/// cursor home.
fn show_fresh<M: CellMemory, P: Io>(vga: &mut TextScreen<M, P>) {
    vga.clear(DEFAULT_ATTRIBUTE);
    vga.set_cursor(0, 0);
}

/// SYS_CSR_CALL's service: CsrClientCallServer(message, capture buffer, API number, data length),
/// answered for the calling process.
#[cfg(target_arch = "x86")]
fn service(frame: &mut crate::user::TrapFrame, args: &[u32], passive: &mut At<Passive>) {
    let mut call = crate::nt::call::NtCall::new(frame, passive);
    let other = match args[2] >> 16 {
        rtl::console::base::BASE_SERVER => Some(base_call_server as OtherServer),
        rtl::console::user::USER_SERVER => Some(user_call_server as OtherServer),
        _ => None,
    };
    if let Some(serve) = other {
        let result = serve_message(
            UserAddr(args[0]),
            UserAddr(args[1]),
            args[2],
            args[3],
            serve,
        );
        call.finish(result);
        return;
    }
    // Who calls, as the console holds its processes: its object and its process group (read
    // before the call holds the process's state).
    let calling = crate::user::args::calling_process();
    let caller = Caller {
        process: calling.object(),
        group: calling.process_group(),
    };
    // The input-wait handle is an object's: made (or opened) here, below the server's level,
    // where objects are made, and handed to the call that asks for it.
    let mut prepared = (args[2] == rtl::console::Api::GetInputWaitHandle.into())
        .then(|| prepare_input_wait_handle(call.passive()));
    let guard = stack_guard_page();
    let process = crate::user::args::calling_process();
    let program = process.name();
    // The process's console handles are held for the call (its lock is the process's state
    // lock), and the call is served at the server's level, raised from the lock's.
    let (mut result, staged) = process.with_console(|handles| {
        crate::level::raised::<Dispatch, _>(|dispatch| {
            // Nothing below waits: a fault in a user-memory copy resolves in place (a
            // copy-on-write page) or fails the copy; a write into the caller's stack guard page,
            // whose fault would grow the stack, is staged instead.
            let server = SERVER.get(dispatch);
            let result = client_call_server(
                &mut server.console,
                handles,
                &mut Dual {
                    input_wait_handle: &mut prepared,
                    guard: guard.map(|page| (page, &mut server.staged)),
                    caller: Some((caller, &mut server.ctrl)),
                    program,
                },
                UserAddr(args[0]),
                UserAddr(args[1]),
                args[2],
                args[3],
            );
            // The text screen shows the console until the graphics mode is set; from then on the
            // VGA text page is not on the screen (and in a VBE mode the legacy window may reach
            // video memory), so its cells and cursor are left alone and the changes dropped.
            if PLATFORM.graphics_mode_set() {
                server.console.screen.take_damage();
            } else {
                present(&mut server.console.screen, &mut crate::hw::vga::screen());
            }
            let staged = server.staged.length != 0 && server.staged.owner.is_none();
            if staged {
                server.staged.owner = Some(crate::sched::current_thread());
            }
            let input = server.input_state();
            let raised = server.ctrl.has_pending();
            show_input(dispatch, input);
            if raised {
                ctrl::wake(crate::sched::DISPATCHER.get(dispatch));
            }
            (result, staged)
        })
    });
    if staged && copy_out_staged(call.passive()).is_err() {
        result = Err(STATUS_ACCESS_VIOLATION);
    }
    // A call refused before it reached the handle (its message unreadable) leaves it unopened.
    if let Some(Ok(handle)) = prepared {
        call.process().close_handle(handle);
    }
    call.finish(result);
}

/// The calling thread's stack guard page: the page below its TEB's StackLimit, the one whose fault
/// grows its stack. None for a thread without a TEB.
#[cfg(target_arch = "x86")]
fn stack_guard_page() -> Option<u32> {
    use crate::user::teb::teb_field;
    let thread = crate::sched::current_thread();
    let teb = crate::level::raised::<Dispatch, _>(|dispatch| {
        crate::sched::DISPATCHER
            .get(dispatch)
            .thread(thread)
            .teb_va()
    });
    if teb == 0 {
        return None;
    }
    let limit = teb_field!(stack_limit).of(teb).read().ok()?;
    limit.checked_sub(crate::mem::paging::PAGE_SIZE)
}

/// Copy the calling thread's staged writes into its memory, below the server's level, a chunk at a
/// time (a fault on the guard page grows its stack, as the thread's own touch would); the staging
/// is free again after. The copy's refusal is the call's answer then.
#[cfg(target_arch = "x86")]
fn copy_out_staged(passive: &mut At<Passive>) -> Result<(), NtStatus> {
    let mut chunk = [0u8; 256];
    let mut done = 0;
    let mut copied = Ok(());
    loop {
        let (address, take) = {
            let mut dispatch = passive.raise::<Dispatch>();
            let staged = &SERVER.get(&mut dispatch).staged;
            let take = (staged.length - done).min(chunk.len());
            chunk[..take].copy_from_slice(&staged.bytes[done..done + take]);
            (staged.address.wrapping_add(done as u32), take)
        };
        if take == 0 || copied.is_err() {
            break;
        }
        copied = UserAddr(address).write(&chunk[..take]);
        done += take;
    }
    let mut dispatch = passive.raise::<Dispatch>();
    let staged = &mut SERVER.get(&mut dispatch).staged;
    staged.owner = None;
    staged.length = 0;
    copied.map_err(NtStatus::from)
}

/// The calling process's handle to the console's input-wait event, for the call about to ask for
/// it: a new handle on the event the server's slot holds, or on a fresh one made for the slot;
/// STATUS_INSUFFICIENT_RESOURCES when neither can be had. The slot is read and written at the
/// server's level, the object made and the handle inserted below it. The event is the console's,
/// as Windows 2000's console keeps its own handle to it: its creator's reference is the server's,
/// kept until no process is left ([`release_input_event`]).
#[cfg(target_arch = "x86")]
fn prepare_input_wait_handle(passive: &mut At<Passive>) -> Result<u32, NtStatus> {
    use crate::ob::{self, EVENT_ALL_ACCESS};
    use crate::sched::event::EventKind;
    let held = SERVER.get(&mut passive.raise::<Dispatch>()).input_event;
    let id = match held {
        Some(id) => id,
        None => {
            let made = ob::lock(passive)
                .create_event(EventKind::Notification, false)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            // Another call may have made one meanwhile (holding the directory opens interrupts):
            // the first one kept is the console's, and a second goes again.
            let kept = *SERVER
                .get(&mut passive.raise::<Dispatch>())
                .input_event
                .get_or_insert(made);
            if kept != made {
                ob::release(made);
            }
            kept
        }
    };
    ob::open(
        crate::user::args::calling_process(),
        id,
        EVENT_ALL_ACCESS,
        false,
    )
    .map(core::num::NonZeroU32::get)
    .ok_or(STATUS_INSUFFICIENT_RESOURCES)
}

#[cfg(target_arch = "x86")]
impl ConsoleServer {
    /// What the input-wait event must show, when there is one: its body, and whether the console's
    /// input buffer holds records. The server holds a reference on the event (see
    /// [`prepare_input_wait_handle`]), so its body is named without the object directory, which
    /// neither the service at this level nor the keyboard DPC may take.
    fn input_state(&self) -> Option<(WaitableId, bool)> {
        let event = self.input_event?.waitable()?;
        Some((event, self.console.input_waiting()))
    }
}

/// The console has no process attached any more (the system is quiescent): the server's
/// reference on its input-wait event goes, and the event with it (the next process to ask for the
/// handle gets a fresh one), as Windows 2000's console goes with its last process.
#[cfg(target_arch = "x86")]
pub fn release_input_event() {
    let event =
        crate::level::raised::<Dispatch, _>(|dispatch| SERVER.get(dispatch).input_event.take());
    if let Some(id) = event {
        crate::ob::release(id);
    }
}

/// Set the input-wait event to show whether the console's input buffer holds records, as
/// [`ConsoleServer::input_state`] read them; nothing when no event lives.
#[cfg(target_arch = "x86")]
fn show_input(dispatch: &mut At<Dispatch>, state: Option<(WaitableId, bool)>) {
    let Some((event, waiting)) = state else {
        return;
    };
    let dispatcher = crate::sched::DISPATCHER.get(dispatch);
    if !waiting {
        dispatcher.reset_event(event);
    } else if dispatcher.waitable(event).signal_state() <= 0 {
        dispatcher.set_event(event, crate::sched::event::EVENT_WAKE_INCREMENT);
    }
}

/// The keyboard DPC's step: one key byte into the console's producer, each record it completes
/// appended to the input buffer, the lights a toggle changes asked of `lights`. A record the full
/// buffer cannot take is reported on COM1; the `kbd-smoke` diagnostic boot reports every record as
/// the buffer holds it.
#[cfg(target_arch = "x86")]
pub fn key_byte(
    dispatch: &mut At<Dispatch>,
    byte: u8,
    lights: &mut impl rtl::console::input::Lights,
) {
    use rtl::console::input::Append;
    let server = SERVER.get(dispatch);
    let raised = server
        .console
        .key_byte(byte, lights, &mut |outcome, record| {
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
    // A control key's event goes to every process of the console, group 0.
    if let Some(event) = raised {
        if !server.ctrl.raise(event, 0) {
            crate::serial_println!("F2K: kbd: control events queue full: an event dropped");
        }
    }
    let input = server.input_state();
    let raised = server.ctrl.has_pending();
    show_input(dispatch, input);
    if raised {
        ctrl::wake(crate::sched::DISPATCHER.get(dispatch));
    }
}

/// Start the console's control thread (see [`ctrl`]): once, at boot, before the first process.
#[cfg(target_arch = "x86")]
pub fn start_control_thread() {
    ctrl::start();
}

/// The server's step at a process's end: it leaves the console, and no control event nor the
/// session's end reaches it from then on, as Windows 2000's csrss takes a process off its console
/// and forgets it when it ends. Its group leads nothing any more (GenerateConsoleCtrlEvent refuses
/// it).
#[cfg(target_arch = "x86")]
pub fn disconnect(process: ObjectId) {
    crate::level::raised::<Dispatch, _>(|dispatch| SERVER.get(dispatch).ctrl.disconnect(process));
}

/// The server learns of `process` (see [`ctrl`]), at its first win32k service: from then on the
/// session's end reaches it, through its windows, whether or not the console holds it. Windows
/// 2000's user32 connects each process that loads it to csrss's user server; F2K's user32 makes
/// no connection of its own, so its first service stands for it.
#[cfg(target_arch = "x86")]
pub fn know(process: ObjectId) {
    crate::level::raised::<Dispatch, _>(|dispatch| {
        SERVER.get(dispatch).ctrl.know(process);
    });
}

/// Copy what the screen buffer changed since the last look to the text screen: the window's rows
/// it touched, then the hardware cursor.
fn present<M: CellMemory, P: Io>(screen: &mut ScreenBuffer, vga: &mut TextScreen<M, P>) {
    let Some(rows) = screen.take_damage() else {
        return;
    };
    let window = screen.window();
    for row in rows.start.max(window.start)..rows.end.min(window.end) {
        vga.put_row(row - window.start, &screen.cells()[row]);
    }
    if let Some((row, column)) = screen.window_cursor() {
        vga.set_cursor(row, column);
    }
}

/// Host builds compile the dispatch but never raise it.
#[cfg(not(target_arch = "x86"))]
fn service(
    _frame: &mut crate::user::TrapFrame,
    _args: &[u32],
    _passive: &mut crate::level::At<crate::level::Passive>,
) {
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
    if length > 4 * DATA_WORDS || !length.is_multiple_of(4) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // The message as far as the call's data goes, as Windows 2000's port copies a message's own
    // length: the rest stays zeros here, and the caller's is neither read nor written. The server
    // decodes the data as the API's message and answers it in place.
    let size = offset_of!(CsrApiMsg, data) + length;
    let mut msg = CsrApiMsg::zeroed();
    message.read(&mut msg.as_bytes_mut()[..size])?;
    let status = NtStatus(rtl::console::serve(
        console,
        handles,
        client,
        api,
        &mut msg.data,
        length,
    ));
    msg.capture_buffer = capture.raw();
    msg.api_number = api;
    msg.return_value = status.0;
    // Everything after the LPC header, which the server leaves as the caller wrote it.
    let answer = offset_of!(CsrApiMsg, capture_buffer);
    message
        .offset(answer as u32)
        .write(&msg.as_bytes()[answer..size])?;
    if status.is_success() {
        Ok(status)
    } else {
        Err(status)
    }
}

/// A server's API beside the console's: the API number, and the message's data as far as the
/// call's length goes, answered in place; the status.
#[cfg(target_arch = "x86")]
type OtherServer = fn(u32, &mut [u8]) -> NtStatus;

/// Serve one message of a server beside the console's, read and answered as [`client_call_server`]
/// reads and answers the console's: the data handed to `serve`, which answers it in place, then
/// the capture buffer, the API number, the status and the data written back.
#[cfg(target_arch = "x86")]
fn serve_message(
    message: UserAddr,
    capture: UserAddr,
    api: u32,
    length: u32,
    serve: OtherServer,
) -> NtResult {
    let length = length as usize;
    if length > 4 * DATA_WORDS || !length.is_multiple_of(4) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = offset_of!(CsrApiMsg, data) + length;
    let mut msg = CsrApiMsg::zeroed();
    message.read(&mut msg.as_bytes_mut()[..size])?;
    let status = serve(api, &mut msg.data.as_bytes_mut()[..length]);
    msg.capture_buffer = capture.raw();
    msg.api_number = api;
    msg.return_value = status.0;
    let answer = offset_of!(CsrApiMsg, capture_buffer);
    message
        .offset(answer as u32)
        .write(&msg.as_bytes()[answer..size])?;
    if status.is_success() {
        Ok(status)
    } else {
        Err(status)
    }
}

/// The base server's APIs F2K serves (`rtl::console::base`), for the calling process:
/// BasepCreateProcess (see [`announce_process`]), and BasepSetProcessShutdownParam and
/// BasepGetProcessShutdownParam (see [`set_shutdown_parameters`] and [`get_shutdown_parameters`]).
/// Any other API is STATUS_ILLEGAL_FUNCTION; data too short for the message
/// STATUS_INVALID_PARAMETER.
#[cfg(target_arch = "x86")]
fn base_call_server(api: u32, data: &mut [u8]) -> NtStatus {
    use rtl::console::base::{
        CREATE_PROCESS,
        GET_PROCESS_SHUTDOWN_PARAM,
        SET_PROCESS_SHUTDOWN_PARAM,
    };
    match api {
        CREATE_PROCESS => announce_process(data),
        SET_PROCESS_SHUTDOWN_PARAM => set_shutdown_parameters(data),
        GET_PROCESS_SHUTDOWN_PARAM => get_shutdown_parameters(data),
        _ => NtStatus(rtl::console::STATUS_ILLEGAL_FUNCTION),
    }
}

/// BasepSetProcessShutdownParam: the calling process's shutdown level and flags, kept with its
/// entry, where the session's end reads them ([`Control::next_to_end`]). Any level is kept; flags
/// holding any bit but SHUTDOWN_NORETRY leave the parameters as they were
/// (`rtl::console::base::shutdown_parameters_kept`), and either way the answer is a success, as
/// Windows 2000's caller sees it. Windows 2000's csrss keeps them for every process it knows, and
/// so does F2K's server: a process the console does not hold (a program with windows and no
/// console) is known from its call on, and the session's end reaches it at its level.
#[cfg(target_arch = "x86")]
fn set_shutdown_parameters(data: &mut [u8]) -> NtStatus {
    use rtl::console::base::{shutdown_parameters_kept, ShutdownParameters};
    let Some(request) = ShutdownParameters::<u32>::from_bytes(data) else {
        return STATUS_INVALID_PARAMETER;
    };
    if !shutdown_parameters_kept(request.flags) {
        return STATUS_SUCCESS;
    }
    let caller = crate::user::args::calling_process().object();
    crate::level::raised::<Dispatch, _>(|dispatch| {
        SERVER
            .get(dispatch)
            .ctrl
            .set_shutdown_parameters(caller, request.level, request.flags)
    });
    STATUS_SUCCESS
}

/// BasepGetProcessShutdownParam: the calling process's shutdown level and flags, answered in the
/// message (the defaults, 0x280 and none, until it sets its own).
#[cfg(target_arch = "x86")]
fn get_shutdown_parameters(data: &mut [u8]) -> NtStatus {
    use rtl::console::base::ShutdownParameters;
    let Some(answer) = data.get_mut(..core::mem::size_of::<ShutdownParameters<u32>>()) else {
        return STATUS_INVALID_PARAMETER;
    };
    let caller = crate::user::args::calling_process().object();
    let (level, flags) = crate::level::raised::<Dispatch, _>(|dispatch| {
        SERVER.get(dispatch).ctrl.shutdown_parameters(caller)
    });
    answer.copy_from_slice(ShutdownParameters { level, flags }.as_bytes());
    STATUS_SUCCESS
}

/// BasepCreateProcess, the creator's announcement of a process it made: the process (the
/// creator's handle to it names it) put in the creator's process group, or in a group of its own
/// for CREATE_NEW_PROCESS_GROUP, as Windows 2000's base server decides. A handle that names no
/// process is refused as the process services refuse it.
#[cfg(target_arch = "x86")]
fn announce_process(data: &mut [u8]) -> NtStatus {
    use rtl::console::base::{CreateProcess, CREATE_NEW_PROCESS_GROUP};
    let Some(request) = CreateProcess::<u32>::from_bytes(data) else {
        return STATUS_INVALID_PARAMETER;
    };
    let announced = crate::nt::object::reference_process(request.process, 0).map(|made| {
        let group = if request.creation_flags & CREATE_NEW_PROCESS_GROUP != 0 {
            made.record().id()
        } else {
            crate::user::args::calling_process().process_group()
        };
        made.record().set_process_group(group);
    });
    announced.map_or_else(|status| status, |()| STATUS_SUCCESS)
}

/// The user server's one API (`rtl::console::user`), for the calling process: UserpExitWindowsEx,
/// the request for the session's end, its flags checked as Windows 2000 checks them before its
/// privilege check (a bit it does not know is STATUS_ACCESS_DENIED), then taken for the control
/// thread, which ends the session once the call has returned ([`crate::session`]). A request made
/// while the session ends already changes nothing, and is answered as taken. Any other API is
/// STATUS_ILLEGAL_FUNCTION; data too short for the message STATUS_INVALID_PARAMETER.
#[cfg(target_arch = "x86")]
fn user_call_server(api: u32, data: &mut [u8]) -> NtStatus {
    use rtl::console::user::{check_flags, ExitWindowsEx, EXIT_WINDOWS_EX};
    if api != EXIT_WINDOWS_EX {
        return NtStatus(rtl::console::STATUS_ILLEGAL_FUNCTION);
    }
    let Some(request) = ExitWindowsEx::<u32>::from_bytes(data) else {
        return STATUS_INVALID_PARAMETER;
    };
    if let Err(status) = check_flags(request.flags) {
        return NtStatus(status);
    }
    // Windows 2000 refuses every action but EWX_LOGOFF here unless the caller's token holds
    // SeShutdownPrivilege enabled (ERROR_PRIVILEGE_NOT_HELD, the exitwin capture). F2K checks no
    // privilege: a known deviation, the owner's decision while F2K has no security.
    request_session_end(ctrl::SessionRequest {
        flags: request.flags,
        caller: crate::user::args::calling_process().object(),
    });
    STATUS_SUCCESS
}

/// Take `request` for the control thread, and wake it.
#[cfg(target_arch = "x86")]
fn request_session_end(request: ctrl::SessionRequest) {
    crate::level::raised::<Dispatch, _>(|dispatch| {
        let control = &mut SERVER.get(dispatch).ctrl;
        control.request_session_end(request);
        let pending = control.has_pending();
        if pending {
            ctrl::wake(crate::sched::DISPATCHER.get(dispatch));
        }
    });
}

/// The session's end's step (see [`crate::session`]): the next of the server's processes to ask
/// to end, with its CtrlRoutine when it is one of the console's (see [`Control::next_to_end`]).
#[cfg(target_arch = "x86")]
pub fn next_to_end(caller: ObjectId) -> Option<(ObjectId, Option<u32>)> {
    crate::level::raised::<Dispatch, _>(|dispatch| SERVER.get(dispatch).ctrl.next_to_end(caller))
}

/// The session's end is done: another may be asked for.
#[cfg(target_arch = "x86")]
pub fn session_ended() {
    crate::level::raised::<Dispatch, _>(|dispatch| SERVER.get(dispatch).ctrl.session_ended());
}

/// The calling client: its bytes read through a kernel chunk, each chunk to the serial line, then
/// to the screen buffer; and the console's input-wait event, which the client asks a handle to.
struct Dual<'a> {
    /// The input-wait handle prepared for a call that asks for it, taken by that call (the
    /// target's: the host never serves that call).
    #[cfg_attr(not(target_arch = "x86"), allow(dead_code))]
    input_wait_handle: &'a mut Option<Result<u32, NtStatus>>,
    /// The caller's stack guard page and the staging its writes go to (see [`Staged`]); none for
    /// a caller without one.
    guard: Option<(u32, &'a mut Staged)>,
    /// Who calls, and the console's control-event side it connects to or raises events through;
    /// none where nothing calls (the host's tests).
    caller: Option<(Caller, &'a mut Control)>,
    /// The calling process's name: its program's, the key of its command history. Windows
    /// 2000's kernel32 names the program when it connects to the console; F2K's server takes the
    /// name the kernel keeps for the process.
    program: crate::process::ProcessName,
}

/// The calling process, as the console holds its processes: its object, and its process group.
#[derive(Clone, Copy)]
struct Caller {
    process: crate::ob::ObjectId,
    group: u32,
}

impl Client for Dual<'_> {
    /// A buffer the caller cannot name is refused before a byte reaches the screen
    /// (STATUS_ACCESS_VIOLATION, ERROR_NOACCESS to the caller); one that passed the probe but
    /// cannot be read is an invalid user buffer (ERROR_INVALID_USER_BUFFER), what was read
    /// before it shown — the two answers the bare/badptr fixture's console writes capture.
    fn show(
        &mut self,
        mut screen: Option<&mut ScreenBuffer>,
        buffer: usize,
        count: usize,
        logged: bool,
    ) -> Result<(), u32> {
        let (buffer, count) = (buffer as u32, count as u32);
        crate::user::syscall::probe_user_range(buffer, count).map_err(|status| status.0)?;
        let mut chunk = [0u8; 256];
        let mut done = 0u32;
        while done < count {
            let take = (count - done).min(chunk.len() as u32) as usize;
            UserAddr(buffer.wrapping_add(done))
                .read(&mut chunk[..take])
                .map_err(|_| STATUS_INVALID_USER_BUFFER.0)?;
            if logged {
                for &byte in &chunk[..take] {
                    serial_byte(byte);
                }
            }
            if let Some(screen) = screen.as_deref_mut() {
                screen.render(&chunk[..take]);
            }
            done += take as u32;
        }
        Ok(())
    }

    /// The server's bytes (a Unicode write's), to the serial line, then to the screen buffer.
    fn print(&mut self, screen: Option<&mut ScreenBuffer>, bytes: &[u8], logged: bool) {
        if logged {
            for &byte in bytes {
                serial_byte(byte);
            }
        }
        if let Some(screen) = screen {
            screen.render(bytes);
        }
    }

    /// The caller's memory, refused as the services refuse it: STATUS_ACCESS_VIOLATION.
    fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32> {
        crate::user::syscall::probe_user_range(buffer as u32, into.len() as u32)
            .map_err(|status| status.0)?;
        UserAddr(buffer as u32)
            .read(into)
            .map_err(|fault| NtStatus::from(fault).0)
    }

    /// A write into the caller's stack guard page — or following one staged — is staged (see
    /// [`Staged`]); any other goes to the caller's memory at once.
    fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32> {
        crate::user::syscall::probe_user_range(buffer as u32, bytes.len() as u32)
            .map_err(|status| status.0)?;
        if let Some((guard, staged)) = &mut self.guard {
            let (start, end) = (buffer as u32, buffer as u32 + bytes.len() as u32);
            let page = *guard..guard.wrapping_add(crate::mem::paging::PAGE_SIZE);
            let touches = start < page.end && end > page.start;
            if (touches || staged.length != 0) && staged.stage(start, bytes) {
                return Ok(());
            }
        }
        UserAddr(buffer as u32)
            .write(bytes)
            .map_err(|fault| NtStatus::from(fault).0)
    }

    fn input_wait_handle(&mut self) -> Result<u32, u32> {
        self.input_wait_handle
            .take()
            .expect("the input-wait handle is prepared for the call that asks for it")
            .map_err(|status| status.0)
    }

    /// The caller joins the console's processes with its CtrlRoutine and its group.
    fn connect_ctrl(&mut self, routine: usize) -> Result<(), u32> {
        let (caller, control) = self.caller.as_mut().ok_or(STATUS_INVALID_PARAMETER.0)?;
        if control.connect(caller.process, caller.group, routine as u32) {
            Ok(())
        } else {
            Err(STATUS_NO_MEMORY.0)
        }
    }

    /// The event raised for the group; under the kernel option `end-session`, the boot's first
    /// one is taken instead for a request for the session's end from the caller (see
    /// [`crate::session`]).
    fn generate_ctrl_event(&mut self, event: u32, group: u32) -> Result<(), u32> {
        let (caller, control) = self.caller.as_mut().ok_or(STATUS_INVALID_PARAMETER.0)?;
        if let Some(flags) = crate::session::option_flags() {
            if control.divert() {
                control.request_session_end(ctrl::SessionRequest {
                    flags,
                    caller: caller.process,
                });
                return Ok(());
            }
        }
        control.generate(event, group)
    }

    fn program(&self) -> &[u8] {
        self.program.as_str().as_bytes()
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
    use rtl::console::Api;

    use super::*;

    /// A call's writes into its caller's guard page are staged in one run: a piece that follows
    /// the last is taken, one elsewhere or past the room is not, and nothing is taken while
    /// another thread's bytes wait to be copied out.
    #[test]
    fn staged_writes_make_one_run() {
        let mut staged = Box::new(Staged::new());
        assert!(staged.stage(0x1000, b"abc"));
        assert!(staged.stage(0x1003, b"de"));
        assert!(!staged.stage(0x2000, b"x"), "not following");
        assert_eq!(
            (staged.address, &staged.bytes[..staged.length]),
            (0x1000, &b"abcde"[..])
        );
        assert!(!staged.stage(0x1005, &[0; STAGED_BYTES]), "past the room");
        staged.owner = Some(crate::sched::thread::ThreadId(0));
        assert!(!staged.stage(0x1005, b"f"), "another thread's bytes wait");
    }

    /// The host's user memory refuses every transfer (the gate is the target's): a message the
    /// caller cannot name fails before the server is asked.
    #[test]
    fn the_message_must_be_readable_and_its_data_whole_dwords() {
        let mut handles = Handles::standard();
        let mut console = Console::new();
        let mut input_wait_handle = None;
        let mut call = |handles: &mut Handles, length| {
            client_call_server(
                &mut console,
                handles,
                &mut Dual {
                    input_wait_handle: &mut input_wait_handle,
                    guard: None,
                    caller: None,
                    program: crate::process::ProcessName::new(b"fixture"),
                },
                UserAddr(0x40_0000),
                UserAddr(0),
                Api::CloseHandle.into(),
                length,
            )
        };
        assert_eq!(call(&mut handles, 4), Err(STATUS_ACCESS_VIOLATION));
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

    /// The text screen's cell memory, for the host.
    struct Memory(std::vec::Vec<u16>);

    impl CellMemory for Memory {
        fn store(&mut self, index: usize, word: u16) {
            self.0[index] = word;
        }
    }

    /// The text screen's ports, for the host: what was written to them.
    #[derive(Default)]
    struct Ports(std::vec::Vec<(u16, u8)>);

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

    /// A text screen over the host's fakes, every cell holding `word`.
    fn text_screen(word: u16) -> TextScreen<Memory, Ports> {
        use crate::hw::vga::{COLUMNS, ROWS};
        TextScreen::new(Memory(std::vec![word; COLUMNS * ROWS]), Ports::default())
    }

    /// The boot's step shows what a fresh console's window holds without looking at it: the screen
    /// cleared, then the window's cells and its cursor, over whatever the screen held; and a fresh
    /// console holds no change for the first call's look to copy.
    #[test]
    fn the_boot_shows_a_fresh_console() {
        let mut console = Console::new();
        let screen = &mut console.screen;
        let mut drawn = text_screen(0x4E41);
        drawn.clear(DEFAULT_ATTRIBUTE);
        drawn.put_grid(screen.window_cells());
        let (row, column) = screen.window_cursor().expect("the cursor is in the window");
        drawn.set_cursor(row, column);
        let mut shown = text_screen(0x4E41);
        show_fresh(&mut shown);
        let (drawn, shown) = (drawn.parts(), shown.parts());
        assert!(drawn.0 .0 == shown.0 .0, "the same cells");
        assert_eq!(drawn.1 .0, shown.1 .0, "the same cursor");
        assert_eq!(screen.take_damage(), None);
    }

    /// After a call, the text screen gets the rows the screen buffer changed and its cursor;
    /// nothing at all when nothing changed.
    #[test]
    fn the_text_screen_gets_the_changed_rows_and_the_cursor() {
        use rtl::console::screen::{Cell, HEIGHT, WIDTH};

        use crate::hw::vga::{COLUMNS, ROWS};
        let mut vga = text_screen(0);
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
