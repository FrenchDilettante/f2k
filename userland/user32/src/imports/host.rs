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
use rtl::window::{WindowInfo, QUERY_WINDOW_INFO, QUERY_WINDOW_VISIBLE};

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
}

/// A window the window manager holds.
#[derive(Clone, Debug)]
pub struct HostWindow {
    pub handle: u32,
    pub atom: u16,
    pub proc: u32,
    pub rect: Rect,
    pub style: u32,
    pub ex_style: u32,
    pub visible: bool,
    pub alive: bool,
    /// The update region's box and whether its erase is pending.
    pub update: Option<(Rect, bool)>,
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
                visible: handle == DESKTOP_WINDOW,
                alive: true,
                update: None,
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
    _flags: u32,
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
        let (atom, proc) = (class.atom, class.class.wnd_proc as u32);
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
            visible: style & WS_VISIBLE_BIT != 0,
            alive: true,
            update: None,
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
    let expected = match index {
        QUERY_WINDOW_INFO => size_of::<WindowInfo>(),
        QUERY_WINDOW_VISIBLE => 4,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if length as usize != expected {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    wm(|wm| {
        let w = match wm.window(window) {
            Ok(w) => w.clone(),
            Err(status) => return status,
        };
        let bytes: Vec<u8> = if index == QUERY_WINDOW_INFO {
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
        } else {
            (w.visible as u32).to_le_bytes().to_vec()
        };
        // SAFETY: the caller's buffer of the answer's length.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), answer, bytes.len()) };
        STATUS_SUCCESS
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
                answer.create = create;
                answer.msg.lparam = (base + core::mem::offset_of!(Receipt, create)) as i32;
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
        if routine != HWND_LOCK_UPDATE_WINDOW {
            return STATUS_INVALID_PARAMETER;
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
