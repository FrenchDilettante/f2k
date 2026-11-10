//! The host tests' imports: stand-ins with the imports' shapes, recording what they were given.
//!
//! win32k's window services are served by a window manager of the stand-ins' own ([`Wm`]): classes,
//! windows, the calling thread's queue (its sent and posted messages and its WM_QUIT), the update
//! regions, the DCs and the display, each with the kernel's rules as far as the tests reach them,
//! and the kernel's statuses. The window procedures and callbacks the tests register are host
//! functions, named by small numbers ([`procedure`], [`monitor_procedure`]) as a 32-bit program's
//! addresses name them.

use core::mem::size_of;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::vec::Vec;

use rtl::display::*;
use rtl::gdi::Rect;
use rtl::pod::Pod;
use rtl::status::*;
use rtl::user::*;
use rtl::window::*;

use crate::class::WndClassExW;

std::thread_local! {
    /// The calling thread's last error, as SetLastError left it.
    pub static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
    /// The text each DbgPrint printed, in order.
    pub static DEBUG_PRINTS: RefCell<std::vec::Vec<std::string::String>> = const { RefCell::new(std::vec::Vec::new()) };
    /// The window station handle, the desktop handle and the thread the services know, as the
    /// kernel answers them.
    pub static WINDOW_STATION: Cell<u32> = const { Cell::new(0x18) };
    pub static DESKTOP: Cell<u32> = const { Cell::new(0x1C) };
    pub static THREAD_ID: Cell<u32> = const { Cell::new(0x10) };
    /// How many win32k services were called.
    pub static SERVICES: Cell<u32> = const { Cell::new(0) };
    /// The messages CsrClientCallServer was given (the API number and the data words the
    /// length names), and the status the server answers.
    pub static SERVER_CALLS: RefCell<std::vec::Vec<(u32, std::vec::Vec<u32>)>> = const { RefCell::new(std::vec::Vec::new()) };
    pub static SERVER_ANSWER: Cell<u32> = const { Cell::new(0) };
    /// What NtUserChangeDisplaySettings was last given (the name's units, the DEVMODEW as far
    /// as its dmSize goes, the window, the flags, the parameter), and what it answers.
    pub static DISPLAY_CHANGES: RefCell<std::vec::Vec<DisplayChange>> = const { RefCell::new(std::vec::Vec::new()) };
    pub static DISPLAY_ANSWER: Cell<i32> = const { Cell::new(0) };
}

/// One NtUserChangeDisplaySettings call, as the stand-in read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayChange {
    pub device: Option<std::vec::Vec<u16>>,
    pub dev_mode: Option<rtl::display::DevModeW>,
    pub window: usize,
    pub flags: u32,
    pub param: usize,
}

pub unsafe extern "system" fn SetLastError(code: u32) {
    LAST_ERROR.with(|error| error.set(code));
}

// --- The resources -------------------------------------------------------------------------------

/// The module NULL names in the resource calls: the program's.
pub const PROGRAM: usize = 0x0040_0000;

/// One resource of the stand-ins' modules: its module (never NULL), numbered type and name, and
/// data (leaked: a module's image outlives the calls).
pub struct HostResource {
    pub module: usize,
    pub kind: u16,
    pub name: u16,
    pub data: &'static [u8],
}

std::thread_local! {
    /// The resources FindResourceExW finds, and the languages it was asked for, in order.
    pub static RESOURCES: RefCell<Vec<HostResource>> = const { RefCell::new(Vec::new()) };
    pub static RESOURCE_LANGUAGES: RefCell<Vec<u32>> = const { RefCell::new(Vec::new()) };
}

/// A resource added to the module `module`'s, its data `data`; its data's address.
pub fn add_resource(module: usize, kind: u16, name: u16, data: &[u8]) -> usize {
    let data: &'static [u8] = std::boxed::Box::leak(data.to_vec().into_boxed_slice());
    RESOURCES.with(|resources| {
        resources.borrow_mut().push(HostResource {
            module,
            kind,
            name,
            data,
        })
    });
    data.as_ptr() as usize
}

/// FindResourceExW over [`RESOURCES`], for numbered types and names, whatever the language: an
/// HRSRC of the stand-in's (the resource's index plus one); kernel32's level errors otherwise,
/// ERROR_RESOURCE_TYPE_NOT_FOUND (1813) and ERROR_RESOURCE_NAME_NOT_FOUND (1814).
pub unsafe extern "system" fn FindResourceExW(
    module: usize,
    kind: *const u16,
    name: *const u16,
    language: u32,
) -> usize {
    let module = if module == 0 { PROGRAM } else { module };
    let (kind, name) = (kind as usize, name as usize);
    assert!(
        kind >> 16 == 0 && name >> 16 == 0,
        "the stand-in serves numbers"
    );
    RESOURCE_LANGUAGES.with(|languages| languages.borrow_mut().push(language));
    RESOURCES.with(|resources| {
        let resources = resources.borrow();
        let mine = |r: &&HostResource| r.module == module && r.kind as usize == kind;
        if !resources.iter().any(|r| mine(&r)) {
            LAST_ERROR.with(|error| error.set(1813));
            return 0;
        }
        match resources
            .iter()
            .position(|r| mine(&r) && r.name as usize == name)
        {
            Some(index) => index + 1,
            None => {
                LAST_ERROR.with(|error| error.set(1814));
                0
            }
        }
    })
}

/// LoadResource: the data's address, as kernel32's handle is.
pub unsafe extern "system" fn LoadResource(_module: usize, resource: usize) -> usize {
    RESOURCES.with(|resources| resources.borrow()[resource - 1].data.as_ptr() as usize)
}

pub unsafe extern "system" fn SizeofResource(_module: usize, resource: usize) -> u32 {
    RESOURCES.with(|resources| resources.borrow()[resource - 1].data.len() as u32)
}

pub unsafe extern "system" fn LockResource(data: usize) -> usize {
    data
}

/// DbgPrint, as the stub routine calls it: `"%s"` and the text (the stand-in serves that
/// format alone), kept.
pub unsafe extern "C" fn DbgPrint(format: *const u8, text: *const core::ffi::c_char) -> u32 {
    // SAFETY: the caller's NUL-terminated format and text.
    let (format, text) = unsafe {
        (
            core::ffi::CStr::from_ptr(format.cast()).to_bytes(),
            core::ffi::CStr::from_ptr(text.cast()),
        )
    };
    assert_eq!(format, b"%s", "the stand-in serves \"%s\" alone");
    DEBUG_PRINTS.with(|prints| {
        prints
            .borrow_mut()
            .push(text.to_string_lossy().into_owned())
    });
    0
}

/// CsrClientCallServer: the message kept, answered with [`SERVER_ANSWER`] as the server
/// answers it (its ReturnValue, the API number and capture buffer as the call named them).
pub unsafe extern "system" fn CsrClientCallServer(
    message: *mut rtl::console::CsrApiMsg,
    capture_buffer: *mut u8,
    api: u32,
    length: u32,
) -> u32 {
    // SAFETY: the caller's message.
    let message = unsafe { &mut *message };
    let words = message.data[..length as usize / 4].to_vec();
    SERVER_CALLS.with(|calls| calls.borrow_mut().push((api, words)));
    let status = SERVER_ANSWER.with(Cell::get);
    message.capture_buffer = capture_buffer as usize as u32;
    message.api_number = api;
    message.return_value = status;
    status
}

pub unsafe extern "system" fn RtlNtStatusToDosError(status: u32) -> u32 {
    rtl::status::dos_error(status)
}

/// The heap: the host's allocator, a block zeroed, its size kept before it.
pub unsafe extern "system" fn RtlAllocateHeap(_heap: usize, _flags: u32, size: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(size + 8, 8).unwrap();
    // SAFETY: a non-zero layout; the size goes in the first word.
    unsafe {
        let block = std::alloc::alloc_zeroed(layout);
        (block as *mut usize).write(size);
        block.add(8)
    }
}

pub unsafe extern "system" fn RtlFreeHeap(_heap: usize, _flags: u32, block: *mut u8) -> u32 {
    // SAFETY: a block RtlAllocateHeap made.
    unsafe {
        let start = block.sub(8);
        let size = (start as *const usize).read();
        std::alloc::dealloc(
            start,
            std::alloc::Layout::from_size_align(size + 8, 8).unwrap(),
        );
    }
    1
}

pub unsafe extern "system" fn RtlMultiByteToUnicodeN(
    unicode: *mut u16,
    max_bytes: u32,
    bytes_written: *mut u32,
    multi_byte: *const u8,
    multi_byte_bytes: u32,
) -> u32 {
    // SAFETY: the caller's buffers, of the sizes given.
    let written = unsafe {
        rtl::string::multi_byte_to_unicode(
            core::slice::from_raw_parts_mut(unicode, max_bytes as usize / 2),
            core::slice::from_raw_parts(multi_byte, multi_byte_bytes as usize),
        )
    };
    if !bytes_written.is_null() {
        // SAFETY: the caller's count.
        unsafe { bytes_written.write(2 * written as u32) };
    }
    0
}

/// The kernel's reads, as the service makes them: the name to its NUL, the DEVMODEW as far as
/// its dmSize goes; the answer is [`DISPLAY_ANSWER`].
pub unsafe extern "system" fn NtUserChangeDisplaySettings(
    device: *const u16,
    dev_mode: *const rtl::display::DevModeW,
    window: usize,
    flags: u32,
    param: usize,
) -> i32 {
    use rtl::pod::Pod;
    SERVICES.with(|count| count.set(count.get() + 1));
    // SAFETY: the tests' own name, NUL-terminated.
    let device =
        (!device.is_null()).then(|| unsafe { rtl::cstr::units_until_nul(device) }.to_vec());
    let dev_mode = (!dev_mode.is_null()).then(|| {
        // SAFETY: the tests' own DEVMODEW, at least as long as its dmSize says (capped).
        let size = unsafe { (*dev_mode).size } as usize;
        let mut copy = rtl::display::DevModeW::zeroed();
        let length = size.min(core::mem::size_of::<rtl::display::DevModeW>());
        // SAFETY: as above.
        let bytes = unsafe { core::slice::from_raw_parts(dev_mode.cast::<u8>(), length) };
        copy.as_bytes_mut()[..length].copy_from_slice(bytes);
        copy
    });
    DISPLAY_CHANGES.with(|changes| {
        changes.borrow_mut().push(DisplayChange {
            device,
            dev_mode,
            window,
            flags,
            param,
        })
    });
    DISPLAY_ANSWER.with(Cell::get)
}

pub unsafe extern "system" fn RtlUnicodeToMultiByteN(
    multi_byte: *mut u8,
    max_bytes: u32,
    bytes_written: *mut u32,
    unicode: *const u16,
    unicode_bytes: u32,
) -> u32 {
    // SAFETY: the caller's buffers, of the sizes given.
    let written = unsafe {
        rtl::string::unicode_to_multi_byte(
            core::slice::from_raw_parts_mut(multi_byte, max_bytes as usize),
            core::slice::from_raw_parts(unicode, unicode_bytes as usize / 2),
        )
    };
    if !bytes_written.is_null() {
        // SAFETY: the caller's count.
        unsafe { bytes_written.write(written as u32) };
    }
    0
}

pub unsafe extern "system" fn NtUserGetProcessWindowStation(window_station: *mut u32) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    // SAFETY: the caller's out-pointer.
    unsafe { window_station.write(WINDOW_STATION.with(Cell::get)) };
    0
}

pub unsafe extern "system" fn NtUserGetThreadDesktop(thread_id: u32, desktop: *mut u32) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    if thread_id != THREAD_ID.with(Cell::get) {
        return 0xC000_000D;
    }
    // SAFETY: the caller's out-pointer.
    unsafe { desktop.write(DESKTOP.with(Cell::get)) };
    0
}

/// The kernel's answers for the stand-ins' window station: its name, its type's name and its
/// flags (WSF_VISIBLE), with the kernel's lengths and statuses.
pub unsafe extern "system" fn NtUserGetObjectInformation(
    object: usize,
    index: u32,
    information: *mut u8,
    length: u32,
    needed: *mut u32,
) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    let answer: std::vec::Vec<u8> = match index {
        _ if object != WINDOW_STATION.with(Cell::get) as usize => {
            // SAFETY: the caller's out-pointer.
            unsafe { needed.write(u32::MAX) };
            return 0xC000_0008;
        }
        1 => [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0].to_vec(),
        2 | 3 => {
            let text = if index == 2 {
                "WinSta0"
            } else {
                "WindowStation"
            };
            text.encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        }
        _ => {
            // SAFETY: the caller's out-pointer.
            unsafe { needed.write(0) };
            return 0xC000_000D;
        }
    };
    // SAFETY: the caller's out-pointer and buffer, of the length given.
    unsafe {
        needed.write(answer.len() as u32);
        if (length as usize) < answer.len() {
            return 0xC000_0023;
        }
        core::ptr::copy_nonoverlapping(answer.as_ptr(), information, answer.len());
    }
    0
}

pub fn process_heap() -> usize {
    0x0014_0000
}

/// The host process's memory: every address the tests hand over is their own.
pub struct Probed;

impl rtl::stub::Memory for Probed {
    fn readable(&self, _address: usize) -> bool {
        true
    }
}

// --- The procedures
// --------------------------------------------------------------------------------

/// A window procedure, as the tests write one.
pub type WndProc = fn(u32, u32, u32, i32) -> i32;
/// A MonitorEnumProc, as the tests write one (the rectangle by value).
pub type MonitorProc = fn(u32, usize, Rect, usize) -> u32;

/// The first number a registered procedure is named by.
const FIRST_PROC: u32 = 0x0040_1000;

std::thread_local! {
    static PROCS: RefCell<Vec<WndProc>> = const { RefCell::new(Vec::new()) };
    static MONITOR_PROCS: RefCell<Vec<MonitorProc>> = const { RefCell::new(Vec::new()) };
}

/// `proc` registered: the number that names it, as a class's lpfnWndProc holds it.
pub fn procedure(proc: WndProc) -> u32 {
    PROCS.with(|procs| {
        procs.borrow_mut().push(proc);
        FIRST_PROC + 4 * (procs.borrow().len() as u32 - 1)
    })
}

/// `proc` registered: the number that names it.
pub fn monitor_procedure(proc: MonitorProc) -> u32 {
    MONITOR_PROCS.with(|procs| {
        procs.borrow_mut().push(proc);
        FIRST_PROC + 4 * (procs.borrow().len() as u32 - 1)
    })
}

/// The window procedure `proc` names, called.
pub unsafe fn call_procedure(
    proc: u32,
    window: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> i32 {
    let proc = PROCS.with(|procs| procs.borrow()[((proc - FIRST_PROC) / 4) as usize]);
    proc(window, message, wparam, lparam)
}

/// The MonitorEnumProc `proc` names, called.
pub unsafe fn call_monitor_procedure(
    proc: u32,
    monitor: u32,
    dc: usize,
    rect: *const Rect,
    data: usize,
) -> u32 {
    let proc = MONITOR_PROCS.with(|procs| procs.borrow()[((proc - FIRST_PROC) / 4) as usize]);
    // SAFETY: the caller's rectangle.
    proc(monitor, dc, unsafe { rect.read() }, data)
}

// --- The window manager
// -----------------------------------------------------------------------------

/// The desktop window's handle and class atom, and the message window's, as the boot makes them.
pub const DESKTOP_WINDOW: u32 = 0x8;
pub const DESKTOP_ATOM: u16 = 0x8001;
pub const MESSAGE_WINDOW: u32 = 0x4;
/// The screen, the work area and a listed mode of the stand-ins' display.
pub const SCREEN: Rect = Rect {
    left: 0,
    top: 0,
    right: 640,
    bottom: 480,
};
pub const LISTED_MODE: (u32, u32) = (800, 600);
/// STATUS_INFO_LENGTH_MISMATCH and STATUS_INVALID_INFO_CLASS, the query service's refusals.
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;

/// A class the window manager holds.
#[derive(Clone, Debug)]
pub struct HostClass {
    pub atom: u16,
    pub name: Vec<u16>,
    pub class: WndClassExW,
    /// The menu name's units, when it is a string.
    pub menu: Option<Vec<u16>>,
    pub windows: u32,
    /// Registered through a narrow call: its procedure takes the narrow forms of the messages.
    pub ansi: bool,
}

/// A window the window manager holds.
#[derive(Clone, Debug, Default)]
pub struct HostWindow {
    pub handle: u32,
    pub atom: u16,
    pub proc: u32,
    pub rect: Rect,
    pub style: u32,
    pub ex_style: u32,
    /// The parent's handle: the desktop window for a top-level window, 0 for the boot's.
    pub parent: u32,
    pub visible: bool,
    pub alive: bool,
    /// The update region's box and whether its erase is pending.
    pub update: Option<(Rect, bool)>,
    /// The procedure takes the narrow forms of the messages.
    pub ansi: bool,
    /// GWL_ID, GWL_USERDATA, GWL_HINSTANCE.
    pub id: u32,
    pub user_data: u32,
    pub instance: u32,
    /// The extra bytes (the class's cbWndExtra of them).
    pub extra: Vec<u8>,
    /// The text, as DefWindowProc set it.
    pub text: Vec<u16>,
}

/// A creation, as NtUserCreateWindowEx was given it: the class (its units, or its atom), the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Created {
    pub ex_style: u32,
    pub class: Result<Vec<u16>, u16>,
    pub name: Option<Vec<u16>>,
    pub version: u32,
}

/// A sent message on its way to the calling thread.
#[derive(Clone, Copy, Debug)]
pub struct HostSent {
    pub hwnd: u32,
    pub message: u32,
    pub wparam: u32,
    pub lparam: i32,
    pub proc: u32,
    pub create: Option<CreateStructW>,
}

/// The stand-ins' window manager.
#[derive(Debug, Default)]
pub struct Wm {
    pub classes: Vec<HostClass>,
    pub next_atom: u16,
    pub windows: Vec<HostWindow>,
    pub created: Vec<Created>,
    pub sent: VecDeque<HostSent>,
    /// The messages handed out and not answered yet, innermost last.
    pub receiving: Vec<u32>,
    /// The answers the procedures gave, by message, in order.
    pub answers: Vec<(u32, i32)>,
    pub posted: VecDeque<Msg>,
    pub quit: Option<u32>,
    pub dcs: Vec<u32>,
    /// The system colors SetSysColors set, in order.
    pub colors: Vec<(u32, u32)>,
    /// The calling thread's focus window and active window, and the foreground window (0 for
    /// none).
    pub focus: u32,
    pub active: u32,
    pub foreground: u32,
}

std::thread_local! {
    pub static WM: RefCell<Wm> = RefCell::new(Wm::boot());
}

impl Wm {
    /// The boot's window manager: the message window and the desktop window, nothing else.
    fn boot() -> Wm {
        let mut wm = Wm {
            next_atom: 0xC010,
            ..Wm::default()
        };
        for (handle, atom) in [(MESSAGE_WINDOW, 0xC000), (DESKTOP_WINDOW, DESKTOP_ATOM)] {
            wm.windows.push(HostWindow {
                handle,
                atom,
                proc: 0,
                rect: SCREEN,
                style: 0x8000_0000,
                ex_style: 0,
                parent: 0,
                visible: handle == DESKTOP_WINDOW,
                alive: true,
                update: None,
                ..HostWindow::default()
            });
        }
        wm
    }

    fn window(&mut self, handle: usize) -> Result<&mut HostWindow, u32> {
        self.windows
            .iter_mut()
            .find(|w| w.alive && w.handle as usize == handle && handle != 0)
            .ok_or(STATUS_INVALID_HANDLE)
    }

    /// A message with no payload sent to `hwnd`'s procedure.
    fn send(&mut self, hwnd: u32, message: u32, wparam: u32, lparam: i32) {
        let proc = self.window(hwnd as usize).map_or(0, |w| w.proc);
        self.sent.push_back(HostSent {
            hwnd,
            message,
            wparam,
            lparam,
            proc,
            create: None,
        });
    }

    /// The focus to `new`: WM_KILLFOCUS to the window that had it, WM_SETFOCUS to `new`.
    fn move_focus(&mut self, new: u32) {
        let old = self.focus;
        if old == new {
            return;
        }
        self.focus = new;
        if old != 0 {
            self.send(old, WM_KILLFOCUS, new, 0);
        }
        if new != 0 {
            self.send(new, WM_SETFOCUS, old, 0);
        }
    }

    /// `new` made the active window: WM_NCACTIVATE and WM_ACTIVATE to the window that was and to
    /// `new`, as the kernel sends them.
    fn activate(&mut self, new: u32) {
        let old = self.active;
        if old == new {
            return;
        }
        if old != 0 {
            self.send(old, WM_NCACTIVATE, 0, 0);
            self.send(old, WM_ACTIVATE, WA_INACTIVE, new as i32);
        }
        self.active = new;
        self.foreground = new;
        if new != 0 {
            self.send(new, WM_NCACTIVATE, 1, 0);
            self.send(new, WM_ACTIVATE, WA_ACTIVE, old as i32);
        }
    }

    fn class(&mut self, name: &Result<Vec<u16>, u16>) -> Option<&mut HostClass> {
        self.classes.iter_mut().find(|c| match name {
            Ok(units) => same_name(&c.name, units),
            Err(atom) => c.atom == *atom,
        })
    }

    /// A new DC's handle: unique among the tests' threads, which share user32's table of the DCs
    /// it handed out.
    fn new_dc(&mut self) -> u32 {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x100);
        let dc = NEXT.fetch_add(4, std::sync::atomic::Ordering::Relaxed) + 4;
        self.dcs.push(dc);
        dc
    }
}

/// Run `f` on the window manager.
pub fn wm<R>(f: impl FnOnce(&mut Wm) -> R) -> R {
    SERVICES.with(|count| count.set(count.get() + 1));
    WM.with(|wm| f(&mut wm.borrow_mut()))
}

/// Whether two class names are the same, without regard to ASCII case (atom names are not).
fn same_name(a: &[u16], b: &[u16]) -> bool {
    let fold = |unit: u16| {
        if (0x61..=0x7A).contains(&unit) {
            unit - 0x20
        } else {
            unit
        }
    };
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| fold(x) == fold(y))
}

/// A name argument: a string's units (read to its NUL), or an integer atom.
fn name_at(raw: usize) -> Result<Vec<u16>, u16> {
    if raw >> 16 == 0 {
        return Err(raw as u16);
    }
    // SAFETY: the tests' own NUL-terminated string.
    Ok(unsafe { rtl::cstr::units_until_nul(raw as *const u16) }.to_vec())
}

/// The status of a stand-in's answer.
fn status(answer: Result<(), u32>) -> u32 {
    answer.err().unwrap_or(STATUS_SUCCESS)
}

pub unsafe extern "system" fn NtClose(handle: usize) -> u32 {
    wm(
        |wm| match wm.dcs.iter().position(|&dc| dc as usize == handle) {
            Some(at) => {
                wm.dcs.remove(at);
                STATUS_SUCCESS
            }
            None => STATUS_INVALID_HANDLE,
        },
    )
}

pub unsafe extern "system" fn NtUserRegisterClassExWOW(
    class: *const WndClassExW,
    name: usize,
    flags: u32,
    atom: *mut u32,
    wow: *mut u32,
) -> u32 {
    // SAFETY: the caller's structure.
    let class = unsafe { class.read() };
    let name = name_at(name);
    let menu = (class.menu_name >> 16 != 0).then(|| {
        // SAFETY: the caller's NUL-terminated menu name.
        unsafe { rtl::cstr::units_until_nul(class.menu_name as usize as *const u16) }.to_vec()
    });
    wm(|wm| {
        if wm.class(&name).is_some() {
            return STATUS_OBJECT_NAME_EXISTS;
        }
        // The stand-ins hold no cursor: a 4.0-compatible registration naming one is refused.
        if class.cursor != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let value = match &name {
            Ok(_) => {
                wm.next_atom += 1;
                wm.next_atom
            }
            Err(atom) => *atom,
        };
        wm.classes.push(HostClass {
            atom: value,
            name: name
                .clone()
                .unwrap_or_else(|atom| format!("#{atom}").encode_utf16().collect()),
            class,
            menu,
            windows: 0,
            ansi: flags & crate::class::REGISTER_ANSI_PROC != 0,
        });
        // SAFETY: the caller's out-pointers.
        unsafe {
            atom.write(value as u32);
            wow.write(0);
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserUnregisterClass(name: usize, _instance: usize) -> u32 {
    let name = name_at(name);
    wm(|wm| {
        let Some(at) = wm.classes.iter().position(|c| match &name {
            Ok(units) => same_name(&c.name, units),
            Err(atom) => c.atom == *atom,
        }) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if wm.classes[at].windows != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        wm.classes.remove(at);
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserGetClassInfo(
    _instance: usize,
    name: usize,
    out: *mut WndClassExW,
) -> u32 {
    let name = name_at(name);
    wm(|wm| {
        let Some(class) = wm.class(&name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        let mut answer = class.class;
        answer.cb_size = 48;
        answer.class_name = 0;
        // SAFETY: the caller's structure.
        unsafe { out.write(answer) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserGetClassName(
    window: usize,
    buffer: *mut u8,
    max: u32,
    copied: *mut u32,
) -> u32 {
    wm(|wm| {
        let atom = match wm.window(window) {
            Ok(w) => w.atom,
            Err(status) => return status,
        };
        let name = wm.class(&Err(atom)).map_or(Vec::new(), |c| c.name.clone());
        let count = name.len().min((max as usize).saturating_sub(1));
        // SAFETY: the caller's buffer of `max` units, and its count.
        unsafe {
            if max != 0 {
                let units = buffer.cast::<u16>();
                for (at, &unit) in name[..count].iter().enumerate() {
                    units.add(at).write_unaligned(unit);
                }
                units.add(count).write_unaligned(0);
            }
            copied.write(count as u32);
        }
        STATUS_SUCCESS
    })
}

#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn NtUserCreateWindowEx(
    ex_style: u32,
    class: usize,
    name: usize,
    style: u32,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    parent: usize,
    menu: usize,
    instance: usize,
    param: usize,
    version: u32,
    window: *mut u32,
) -> u32 {
    let class_name = name_at(class);
    let text = (name != 0).then(|| {
        // SAFETY: the caller's NUL-terminated name.
        unsafe { rtl::cstr::units_until_nul(name as *const u16) }.to_vec()
    });
    // SAFETY: the caller's out-pointer.
    unsafe { window.write(0) };
    wm(|wm| {
        wm.created.push(Created {
            ex_style,
            class: class_name.clone(),
            name: text,
            version,
        });
        let Some(class) = wm.class(&class_name) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        class.windows += 1;
        let (atom, proc, ansi) = (class.atom, class.class.wnd_proc as u32, class.ansi);
        let extra = std::vec![0u8; class.class.cb_wnd_extra.max(0) as usize];
        let handle = 0x20 + 4 * wm.windows.len() as u32;
        let (x, y) = if x == i32::MIN { (0, 0) } else { (x, y) };
        wm.windows.push(HostWindow {
            handle,
            atom,
            proc,
            rect: Rect {
                left: x,
                top: y,
                right: x + cx,
                bottom: y + cy,
            },
            style: style & !WS_VISIBLE_BIT,
            ex_style: ex_style & !0x8000_0000,
            parent: if parent == 0 {
                DESKTOP_WINDOW
            } else {
                parent as u32
            },
            visible: style & WS_VISIBLE_BIT != 0,
            alive: true,
            update: None,
            ansi,
            id: menu as u32,
            instance: instance as u32,
            extra,
            ..HostWindow::default()
        });
        let create = CreateStructW {
            create_params: param as u32,
            instance: instance as u32,
            menu: menu as u32,
            parent: parent as u32,
            cy,
            cx,
            y,
            x,
            style,
            name: 0,
            class: atom as u32,
            ex_style,
        };
        for message in [WM_NCCREATE, WM_CREATE] {
            wm.sent.push_back(HostSent {
                hwnd: handle,
                message,
                wparam: 0,
                lparam: 0,
                proc,
                create: Some(create),
            });
        }
        // SAFETY: the caller's out-pointer.
        unsafe { window.write(handle) };
        STATUS_SUCCESS
    })
}

/// WS_VISIBLE.
const WS_VISIBLE_BIT: u32 = 0x1000_0000;

pub unsafe extern "system" fn NtUserDestroyWindow(window: usize) -> u32 {
    wm(|wm| {
        let (atom, proc, handle) = match wm.window(window) {
            Ok(w) if w.proc == 0 => return STATUS_ACCESS_DENIED,
            Ok(w) => {
                w.alive = false;
                w.update = None;
                (w.atom, w.proc, w.handle)
            }
            Err(status) => return status,
        };
        if let Some(class) = wm.class(&Err(atom)) {
            class.windows -= 1;
        }
        for message in [WM_DESTROY, WM_NCDESTROY] {
            wm.sent.push_back(HostSent {
                hwnd: handle,
                message,
                wparam: 0,
                lparam: 0,
                proc,
                create: None,
            });
        }
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserQueryWindow(
    window: usize,
    index: u32,
    answer: *mut u8,
    length: u32,
) -> u32 {
    let fits = match index {
        QUERY_WINDOW_INFO => length as usize == size_of::<WindowInfo>(),
        QUERY_WINDOW_VISIBLE | QUERY_WINDOW_PARENT => length == 4,
        QUERY_WINDOW_DATA => length as usize == size_of::<WindowData>(),
        QUERY_WINDOW_TEXT => length as usize == size_of::<WindowText>(),
        index if index & QUERY_WINDOW_EXTRA != 0 => length == 2 || length == 4,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if !fits {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    wm(|wm| {
        let w = match wm.window(window) {
            Ok(w) => w.clone(),
            Err(status) => return status,
        };
        let bytes: Vec<u8> = if index & QUERY_WINDOW_EXTRA != 0 {
            let offset = (index & !QUERY_WINDOW_EXTRA) as usize;
            match w.extra.get(offset..offset + length as usize) {
                Some(bytes) => bytes.to_vec(),
                None => return STATUS_INVALID_INFO_CLASS,
            }
        } else if index == QUERY_WINDOW_DATA {
            WindowData {
                style: w.style,
                ex_style: w.ex_style,
                id: w.id,
                user_data: w.user_data,
                instance: w.instance,
                proc: w.proc,
                flags: if w.ansi { WINDOW_ANSI_PROC } else { 0 },
                extra: w.extra.len() as u32,
                ..WindowData::default()
            }
            .as_bytes()
            .to_vec()
        } else if index == QUERY_WINDOW_TEXT {
            let mut text = WindowText::default();
            let length = w.text.len().min(WINDOW_TEXT_UNITS);
            text.units[..length].copy_from_slice(&w.text[..length]);
            text.length = length as u32;
            text.as_bytes().to_vec()
        } else if index == QUERY_WINDOW_INFO {
            WindowInfo {
                size: 60,
                window: w.rect,
                client: w.rect,
                style: w.style | if w.visible { WS_VISIBLE_BIT } else { 0 },
                ex_style: w.ex_style,
                atom_window_type: w.atom,
                creator_version: 0x0400,
                ..WindowInfo::default()
            }
            .as_bytes()
            .to_vec()
        } else if index == QUERY_WINDOW_PARENT {
            w.parent.to_le_bytes().to_vec()
        } else {
            (w.visible as u32).to_le_bytes().to_vec()
        };
        // SAFETY: the caller's buffer of the answer's length.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), answer, bytes.len()) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserSetWindowLong(
    window: usize,
    index: i32,
    value: u32,
    ansi: u32,
    previous: *mut u32,
    previous_ansi: *mut u32,
) -> u32 {
    let answer = wm(|wm| {
        let w = wm.window(window)?;
        if index >= 0 {
            let offset = index as usize;
            let bytes = w
                .extra
                .get_mut(offset..offset + 4)
                .ok_or(STATUS_INVALID_INFO_CLASS)?;
            let old = u32::from_le_bytes(bytes.try_into().unwrap());
            bytes.copy_from_slice(&value.to_le_bytes());
            return Ok((old, false));
        }
        let field = match index {
            GWL_STYLE => &mut w.style,
            GWL_EXSTYLE => &mut w.ex_style,
            GWL_ID => &mut w.id,
            GWL_USERDATA => &mut w.user_data,
            GWL_HINSTANCE => &mut w.instance,
            GWL_WNDPROC => {
                let old = (w.proc, w.ansi);
                w.proc = value;
                w.ansi = ansi != 0;
                return Ok(old);
            }
            _ => return Err(STATUS_INVALID_INFO_CLASS),
        };
        Ok((core::mem::replace(field, value), false))
    });
    match answer {
        Ok((old, old_ansi)) => {
            // SAFETY: the caller's out-pointers.
            unsafe {
                previous.write(old);
                previous_ansi.write(old_ansi as u32);
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserSetWindowWord(
    window: usize,
    index: i32,
    value: u32,
    previous: *mut u32,
) -> u32 {
    let answer = wm(|wm| {
        let w = wm.window(window)?;
        let offset = usize::try_from(index).map_err(|_| STATUS_INVALID_INFO_CLASS)?;
        let bytes = w
            .extra
            .get_mut(offset..offset + 2)
            .ok_or(STATUS_INVALID_INFO_CLASS)?;
        let old = u16::from_le_bytes(bytes.try_into().unwrap());
        bytes.copy_from_slice(&(value as u16).to_le_bytes());
        Ok(old)
    });
    match answer {
        Ok(old) => {
            // SAFETY: the caller's out-pointer.
            unsafe { previous.write(old as u32) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserDefSetText(window: usize, text: usize) -> u32 {
    let units = if text == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's NUL-terminated text.
        unsafe { rtl::cstr::units_until_nul(text as *const u16) }.to_vec()
    };
    wm(|wm| {
        status(wm.window(window).map(|w| {
            w.text = units;
            w.text.truncate(WINDOW_TEXT_UNITS);
        }))
    })
}

pub unsafe extern "system" fn NtUserSetWindowPos(
    window: usize,
    _insert_after: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    flags: u32,
) -> u32 {
    wm(|wm| {
        status(wm.window(window).map(|w| {
            if flags & 0x2 == 0 {
                let (width, height) = (w.rect.right - w.rect.left, w.rect.bottom - w.rect.top);
                w.rect = Rect {
                    left: x,
                    top: y,
                    right: x + width,
                    bottom: y + height,
                };
            }
            if flags & 0x1 == 0 {
                w.rect.right = w.rect.left + cx;
                w.rect.bottom = w.rect.top + cy;
            }
        }))
    })
}

pub unsafe extern "system" fn NtUserMoveWindow(
    window: usize,
    x: i32,
    y: i32,
    cx: i32,
    cy: i32,
    _repaint: u32,
) -> u32 {
    wm(|wm| {
        status(wm.window(window).map(|w| {
            w.rect = Rect {
                left: x,
                top: y,
                right: x + cx,
                bottom: y + cy,
            }
        }))
    })
}

pub unsafe extern "system" fn NtUserShowWindow(
    window: usize,
    command: i32,
    previous: *mut u32,
) -> u32 {
    let answer = wm(|wm| {
        wm.window(window).map(|w| {
            let was = w.visible;
            w.visible = command != 0;
            if was {
                16
            } else {
                0
            }
        })
    });
    match answer {
        Ok(was) => {
            // SAFETY: the caller's out-pointer.
            unsafe { previous.write(was) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserShowWindowAsync(window: usize, command: i32) -> u32 {
    wm(|wm| status(wm.window(window).map(|w| w.visible = command != 0)))
}

/// The window itself for a point inside it, none outside: the stand-ins' windows have no children
/// to find.
pub unsafe extern "system" fn NtUserChildWindowFromPointEx(
    parent: usize,
    x: i32,
    y: i32,
    _flags: u32,
    child: *mut u32,
) -> u32 {
    let rect = wm(|wm| {
        wm.windows
            .iter()
            .find(|w| w.alive && w.handle as usize == parent && parent != 0)
            .map(|w| w.rect)
    });
    let Some(rect) = rect else {
        return STATUS_INVALID_HANDLE;
    };
    let inside = x >= 0 && y >= 0 && x < rect.right - rect.left && y < rect.bottom - rect.top;
    // SAFETY: the caller's out-pointer.
    unsafe { child.write(if inside { parent as u32 } else { 0 }) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserPostMessage(
    window: usize,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    wm(|wm| {
        if window != 0 {
            if let Err(status) = wm.window(window) {
                return status;
            }
        }
        wm.posted.push_back(Msg {
            hwnd: window as u32,
            message,
            wparam,
            lparam,
            ..Msg::default()
        });
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserPostThreadMessage(
    thread: u32,
    message: u32,
    wparam: u32,
    lparam: i32,
) -> u32 {
    if thread != THREAD_ID.with(Cell::get) {
        return STATUS_INVALID_CID;
    }
    // SAFETY: no pointers.
    unsafe { NtUserPostMessage(0, message, wparam, lparam) }
}

/// GetMessage's and PeekMessage's read, into the receipt: the sent messages first, then the posted
/// ones the filter takes, WM_QUIT, WM_PAINT.
fn take(receipt: *mut Receipt, window: usize, min: u32, max: u32, flags: u32) -> u32 {
    let remove = flags & PM_REMOVE != 0;
    let kinds = flags >> 16;
    let takes = |msg: &Msg| {
        (window == 0 || msg.hwnd as usize == window)
            && ((min == 0 && max == 0) || (min <= msg.message && msg.message <= max))
    };
    let mut answer = Receipt::zeroed();
    let base = receipt as usize;
    wm(|wm| {
        if window != 0 && wm.window(window).is_err() {
            return Err(STATUS_INVALID_HANDLE);
        }
        if let Some(sent) = wm.sent.pop_front() {
            wm.receiving.push(sent.message);
            answer.kind = RECEIVED_SENT;
            answer.proc = sent.proc;
            answer.msg = Msg {
                hwnd: sent.hwnd,
                message: sent.message,
                wparam: sent.wparam,
                lparam: sent.lparam,
                ..Msg::default()
            };
            if let Some(create) = sent.create {
                // The structure is in the receipt, as the kernel writes it; its address is the
                // lParam where it fits one (a 64-bit host's seldom does, and its procedures then
                // get none to read).
                answer.create = create;
                let at = base + core::mem::offset_of!(Receipt, create);
                answer.msg.lparam = i32::try_from(at).unwrap_or(0);
            }
            return Ok(());
        }
        answer.kind = RECEIVED_NONE;
        if kinds == QS_SENDMESSAGE {
            return Ok(());
        }
        if let Some(at) = wm.posted.iter().position(takes) {
            answer.kind = RECEIVED_MESSAGE;
            answer.msg = wm.posted[at];
            if remove {
                wm.posted.remove(at);
            }
        } else if let Some(code) = wm.quit {
            answer.kind = RECEIVED_QUIT;
            answer.msg = Msg {
                message: WM_QUIT,
                wparam: code,
                ..Msg::default()
            };
            if remove {
                wm.quit = None;
            }
        } else if let Some(w) = wm
            .windows
            .iter()
            .find(|w| w.alive && w.update.is_some() && (window == 0 || w.handle as usize == window))
        {
            answer.kind = RECEIVED_MESSAGE;
            answer.msg = Msg {
                hwnd: w.handle,
                message: WM_PAINT,
                ..Msg::default()
            };
        }
        Ok(())
    })
    .map(|()| {
        // SAFETY: the caller's receipt.
        unsafe { receipt.write(answer) };
        STATUS_SUCCESS
    })
    .unwrap_or_else(|status| status)
}

pub unsafe extern "system" fn NtUserGetMessage(
    receipt: *mut Receipt,
    window: usize,
    min: u32,
    max: u32,
) -> u32 {
    let status = take(receipt, window, min, max, PM_REMOVE);
    // SAFETY: the caller's receipt, written above when the status is a success.
    if status == STATUS_SUCCESS && unsafe { (*receipt).kind } == RECEIVED_NONE {
        panic!("GetMessage would wait: the stand-ins' queue is empty");
    }
    status
}

pub unsafe extern "system" fn NtUserPeekMessage(
    receipt: *mut Receipt,
    window: usize,
    min: u32,
    max: u32,
    flags: u32,
) -> u32 {
    take(receipt, window, min, max, flags)
}

pub unsafe extern "system" fn NtUserMessageCall(
    window: usize,
    _message: u32,
    _wparam: u32,
    _lparam: i32,
    proc: *mut u32,
    result: *mut i32,
) -> u32 {
    let found = wm(|wm| wm.window(window).map(|w| w.proc));
    match found {
        Ok(target) => {
            // SAFETY: the caller's out-pointers.
            unsafe {
                proc.write(target);
                result.write(0);
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserDispatchMessage(msg: *const Msg, proc: *mut u32) -> u32 {
    // SAFETY: the caller's message.
    let msg = unsafe { msg.read() };
    let target = if msg.message == WM_TIMER && msg.lparam != 0 {
        Ok(msg.lparam as u32)
    } else if msg.hwnd == 0 {
        Ok(0)
    } else {
        wm(|wm| wm.window(msg.hwnd as usize).map(|w| w.proc))
    };
    match target {
        Ok(target) => {
            // SAFETY: the caller's out-pointer.
            unsafe { proc.write(target) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserCallOneParam(
    param: u32,
    routine: u32,
    result: *mut u32,
) -> u32 {
    let answer = wm(|wm| match routine {
        ONE_PARAM_POST_QUIT_MESSAGE => {
            wm.quit = Some(param);
            Ok(0)
        }
        ONE_PARAM_REPLY_MESSAGE => Ok(0),
        ONE_PARAM_END_SENT_MESSAGE => Ok(match wm.receiving.pop() {
            Some(message) => {
                wm.answers.push((message, param as i32));
                1
            }
            None => 0,
        }),
        _ => Err(STATUS_INVALID_PARAMETER),
    });
    match answer {
        Ok(value) => {
            // SAFETY: the caller's out-pointer.
            unsafe { result.write(value) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserCallHwndLock(window: usize, routine: u32) -> u32 {
    wm(|wm| {
        let (update, handle, proc) = match wm.window(window) {
            Ok(w) => (w.update.is_some(), w.handle, w.proc),
            Err(status) => return status,
        };
        match routine {
            HWND_LOCK_UPDATE_WINDOW => {}
            HWND_LOCK_SET_FOREGROUND_WINDOW => {
                wm.activate(handle);
                return STATUS_SUCCESS;
            }
            HWND_LOCK_ACTIVATE_FOCUS => {
                if wm.active == handle {
                    wm.move_focus(handle);
                }
                return STATUS_SUCCESS;
            }
            _ => return STATUS_INVALID_PARAMETER,
        }
        if update {
            wm.sent.push_back(HostSent {
                hwnd: handle,
                message: WM_PAINT,
                wparam: 0,
                lparam: 0,
                proc,
                create: None,
            });
        }
        STATUS_SUCCESS
    })
}

/// WS_DISABLED.
const WS_DISABLED_BIT: u32 = 0x0800_0000;

/// The window a focus or activation service names: 0 for none, a live window's handle, or
/// STATUS_INVALID_HANDLE.
fn named(wm: &mut Wm, window: usize) -> Result<u32, u32> {
    if window == 0 {
        return Ok(0);
    }
    wm.window(window).map(|w| w.handle)
}

pub unsafe extern "system" fn NtUserSetFocus(window: usize, previous: *mut u32) -> u32 {
    wm(|wm| {
        let handle = match named(wm, window) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        let disabled = handle != 0
            && wm
                .window(window)
                .is_ok_and(|w| w.style & WS_DISABLED_BIT != 0);
        let answer = if disabled {
            0
        } else {
            let old = wm.focus;
            wm.move_focus(handle);
            old
        };
        // SAFETY: the caller's out-pointer.
        unsafe { previous.write(answer) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserSetActiveWindow(window: usize, previous: *mut u32) -> u32 {
    wm(|wm| {
        let handle = match named(wm, window) {
            Ok(handle) => handle,
            Err(status) => return status,
        };
        let old = wm.active;
        wm.activate(handle);
        // SAFETY: the caller's out-pointer.
        unsafe { previous.write(old) };
        STATUS_SUCCESS
    })
}

pub unsafe extern "system" fn NtUserGetForegroundWindow(window: *mut u32) -> u32 {
    let answer = wm(|wm| wm.foreground);
    // SAFETY: the caller's out-pointer.
    unsafe { window.write(answer) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetThreadState(routine: u32, result: *mut u32) -> u32 {
    let answer = wm(|wm| match routine {
        THREAD_STATE_FOCUS_WINDOW => Ok(wm.focus),
        THREAD_STATE_ACTIVE_WINDOW => Ok(wm.active),
        _ => Err(STATUS_INVALID_PARAMETER),
    });
    match answer {
        Ok(value) => {
            // SAFETY: the caller's out-pointer.
            unsafe { result.write(value) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserCallHwndParamLock(
    window: usize,
    param: u32,
    routine: u32,
    result: *mut u32,
) -> u32 {
    wm(|wm| {
        if routine != HWND_PARAM_LOCK_ENABLE_WINDOW {
            return STATUS_INVALID_PARAMETER;
        }
        let (handle, was) = match wm.window(window) {
            Ok(w) => (w.handle, w.style & WS_DISABLED_BIT != 0),
            Err(status) => return status,
        };
        if param == 0 {
            wm.send(handle, WM_CANCELMODE, 0, 0);
            if wm.focus == handle {
                wm.move_focus(0);
            }
        }
        if was == (param != 0) {
            if let Ok(w) = wm.window(window) {
                w.style ^= WS_DISABLED_BIT;
            }
            wm.send(handle, WM_ENABLE, param, 0);
        }
        // SAFETY: the caller's out-pointer.
        unsafe { result.write(if was { 8 } else { 0 }) };
        STATUS_SUCCESS
    })
}

/// The rectangle at `rect`, or none.
fn rect_at(rect: usize) -> Option<Rect> {
    // SAFETY: the tests' own rectangle.
    (rect != 0).then(|| unsafe { (rect as *const Rect).read_unaligned() })
}

pub unsafe extern "system" fn NtUserInvalidateRect(window: usize, rect: usize, erase: u32) -> u32 {
    let rect = rect_at(rect);
    wm(|wm| {
        status(wm.window(window).map(|w| {
            if !w.visible {
                return;
            }
            let client = Rect {
                left: 0,
                top: 0,
                right: w.rect.right - w.rect.left,
                bottom: w.rect.bottom - w.rect.top,
            };
            let added = rect.unwrap_or(client);
            w.update = Some(match w.update {
                None => (added, erase != 0),
                Some((old, pending)) => (
                    Rect {
                        left: old.left.min(added.left),
                        top: old.top.min(added.top),
                        right: old.right.max(added.right),
                        bottom: old.bottom.max(added.bottom),
                    },
                    pending || erase != 0,
                ),
            });
        }))
    })
}

pub unsafe extern "system" fn NtUserValidateRect(window: usize, _rect: usize) -> u32 {
    wm(|wm| status(wm.window(window).map(|w| w.update = None)))
}

pub unsafe extern "system" fn NtUserGetUpdateRect(
    window: usize,
    rect: usize,
    erase: u32,
    result: *mut u32,
) -> u32 {
    let answer = wm(|wm| {
        wm.window(window).map(|w| match &mut w.update {
            None => (Rect::default(), 0),
            Some((update, pending)) => {
                let bits = if erase != 0 && *pending {
                    *pending = false;
                    UPDATE_NOT_EMPTY | UPDATE_ERASE
                } else {
                    UPDATE_NOT_EMPTY
                };
                (*update, bits)
            }
        })
    });
    match answer {
        Ok((update, bits)) => {
            // SAFETY: the caller's rectangle (or none) and out-pointer.
            unsafe {
                if rect != 0 {
                    (rect as *mut Rect).write_unaligned(update);
                }
                result.write(bits);
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserBeginPaint(window: usize, paint: usize) -> u32 {
    let answer = wm(|wm| {
        let (rect, erase) = match wm.window(window) {
            Ok(w) => w.update.take().unwrap_or_default(),
            Err(status) => return Err(status),
        };
        if paint == 0 {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        Ok(PaintStruct {
            hdc: wm.new_dc(),
            erase: erase as i32,
            paint: rect,
            ..PaintStruct::default()
        })
    });
    match answer {
        Ok(answer) => {
            // SAFETY: the caller's structure.
            unsafe { (paint as *mut PaintStruct).write_unaligned(answer) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

pub unsafe extern "system" fn NtUserEndPaint(window: usize, paint: usize) -> u32 {
    if let Err(status) = wm(|wm| wm.window(window).map(|_| ())) {
        return status;
    }
    if paint == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    // SAFETY: the caller's structure.
    let hdc = unsafe { (paint as *const PaintStruct).read_unaligned() }.hdc;
    // SAFETY: no pointers.
    unsafe { NtClose(hdc as usize) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetDC(_window: usize, dc: *mut u32) -> u32 {
    let handle = wm(Wm::new_dc);
    // SAFETY: the caller's out-pointer.
    unsafe { dc.write(handle) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserGetDCEx(
    window: usize,
    _region: usize,
    _flags: u32,
    dc: *mut u32,
) -> u32 {
    // SAFETY: the caller's out-pointer.
    unsafe { NtUserGetDC(window, dc) }
}

pub unsafe extern "system" fn NtUserGetWindowDC(window: usize, dc: *mut u32) -> u32 {
    // SAFETY: the caller's out-pointer.
    unsafe { NtUserGetDC(window, dc) }
}

pub unsafe extern "system" fn NtUserEnumDisplaySettings(
    device: usize,
    mode: u32,
    dev_mode: usize,
    _flags: u32,
) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    if device != 0 {
        // SAFETY: the tests' own NUL-terminated name.
        let name = unsafe { rtl::cstr::units_until_nul(device as *const u16) };
        if name != "\\\\.\\DISPLAY1".encode_utf16().collect::<Vec<_>>() {
            return STATUS_INVALID_PARAMETER;
        }
    }
    // SAFETY: the caller's DEVMODEW, as long as its dmSize says.
    let size = unsafe { ((dev_mode + DEV_MODE_W_SIZE) as *const u16).read_unaligned() };
    if (size as usize) < DISPLAY_FIELDS_END_W {
        return STATUS_INVALID_PARAMETER;
    }
    let (width, height, current) = match mode {
        ENUM_CURRENT_SETTINGS => (SCREEN.right as u32, SCREEN.bottom as u32, true),
        0 => (LISTED_MODE.0, LISTED_MODE.1, false),
        _ => return STATUS_NO_MORE_ENTRIES,
    };
    // As win32k's: the description in its own version, the DEVMODEW ending at dmDisplayFrequency,
    // whatever the caller's dmSize; the caller's bytes past it untouched.
    let mut described = DevModeW::zeroed();
    described.spec_version = DM_SPECVERSION;
    described.size = DISPLAY_FIELDS_END_W as u16;
    described.fields =
        DM_BITSPERPEL | DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFLAGS | DM_DISPLAYFREQUENCY;
    if current {
        described.fields |= DM_POSITION | DM_LOGPIXELS;
    }
    described.log_pixels = 96;
    described.bits_per_pel = 32;
    described.pels_width = width;
    described.pels_height = height;
    described.display_frequency = 1;
    // SAFETY: the caller's DEVMODEW, at least DISPLAY_FIELDS_END_W long (its dmSize, checked).
    unsafe {
        core::ptr::copy_nonoverlapping(
            described.as_bytes().as_ptr(),
            dev_mode as *mut u8,
            DISPLAY_FIELDS_END_W,
        )
    };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserEnumDisplayDevices(
    device: usize,
    number: u32,
    out: usize,
    _flags: u32,
) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    if device != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's structure's cb.
    let cb = unsafe { (out as *const u32).read_unaligned() } as usize;
    if cb < DISPLAY_DEVICE_STATE_END_W {
        return STATUS_INVALID_PARAMETER;
    }
    let (name, string, state) = match number {
        0 => (
            "\\\\.\\DISPLAY1",
            "VBE Display Adapter",
            DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE,
        ),
        1 => (
            "\\\\.\\DISPLAY2",
            "VGA Text Display",
            DISPLAY_DEVICE_VGA_COMPATIBLE,
        ),
        _ => return STATUS_NO_MORE_ENTRIES,
    };
    let mut device = DisplayDeviceW::zeroed();
    device.cb = cb as u32;
    for (unit, value) in device.device_name.iter_mut().zip(name.encode_utf16()) {
        *unit = value;
    }
    for (unit, value) in device.device_string.iter_mut().zip(string.encode_utf16()) {
        *unit = value;
    }
    device.state_flags = state;
    let length = cb.min(size_of::<DisplayDeviceW>());
    // SAFETY: the caller's structure, as long as its cb says.
    unsafe { core::ptr::copy_nonoverlapping(device.as_bytes().as_ptr(), out as *mut u8, length) };
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserEnumDisplayMonitors(
    _dc: usize,
    clip: usize,
    monitors: *mut u32,
    rects: *mut Rect,
    count: u32,
    found: *mut u32,
) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    let part = match rect_at(clip) {
        None => SCREEN,
        Some(clip) => Rect {
            left: clip.left.max(0),
            top: clip.top.max(0),
            right: clip.right.min(SCREEN.right),
            bottom: clip.bottom.min(SCREEN.bottom),
        },
    };
    let total = (part.left < part.right && part.top < part.bottom) as u32;
    // SAFETY: the caller's arrays of `count` entries, and its count.
    unsafe {
        if total != 0 && count != 0 {
            monitors.write(PRIMARY_MONITOR_HANDLE);
            rects.write(part);
        }
        found.write(total);
    }
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserSetSysColors(
    count: u32,
    indexes: usize,
    colors: usize,
    _flags: u32,
) -> u32 {
    // SAFETY: the caller's arrays of `count` entries.
    let (indexes, colors) = unsafe {
        (
            core::slice::from_raw_parts(indexes as *const u32, count as usize),
            core::slice::from_raw_parts(colors as *const u32, count as usize),
        )
    };
    if indexes.iter().any(|&index| index as usize >= SYSTEM_COLORS) {
        return STATUS_INVALID_PARAMETER;
    }
    wm(|wm| {
        wm.colors
            .extend(indexes.iter().copied().zip(colors.iter().copied()))
    });
    STATUS_SUCCESS
}

pub unsafe extern "system" fn NtUserSystemParametersInfo(
    action: u32,
    _ui_param: u32,
    param: usize,
    _win_ini: u32,
) -> u32 {
    SERVICES.with(|count| count.set(count.get() + 1));
    if action != SPI_GETWORKAREA {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's RECT.
    unsafe { (param as *mut Rect).write_unaligned(SCREEN) };
    STATUS_SUCCESS
}
