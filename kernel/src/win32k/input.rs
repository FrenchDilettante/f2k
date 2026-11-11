//! Keyboard input: the path a keystroke takes to a window, as Windows 2000's raw input thread
//! takes it, the key states, and TranslateMessage.
//!
//! A keystroke comes from the PS/2 keyboard or from SendInput. The keyboard's bytes reach win32k
//! only while a GUI thread is in the foreground ([`takes_keyboard`]); otherwise they go to the
//! console, as before any program had a window. The keyboard driver's DPC hands them to the raw
//! input thread ([`raw_byte`]), a system thread of win32k's, as Windows 2000's raw input thread
//! is, which decodes them with the console's own decoder and layout (`rtl::console::input`'s
//! [`Decoder`], `rtl::console::layout`'s US tables: one set of scan-code tables for both) and runs
//! each keystroke under the window manager's lock. SendInput's keystrokes run in the caller's
//! service, synchronously. Each keystroke ([`key_event`]):
//!
//! - becomes a virtual key: SendInput names it, or its scan code does through the layout (the
//!   extended flag picks the E0 table; Num Lock and the modifiers convert the keypad's keys). A
//!   generic Shift, Ctrl or Alt is made the side's key: right Shift by its scan code (0x36), the
//!   right Ctrl and Alt by the extended flag;
//! - moves the system's key state, the asynchronous one ([`RawInput`]): the key down or up, its
//!   toggle flipped on a key going down from up, the generic key following its two sides;
//! - is posted to the foreground thread's focus window, or, with no focus window, to its active
//!   window as a system key, as an input message ([`super::queue::post_input`]): WM_SYSKEYDOWN and
//!   WM_SYSKEYUP while Alt is down without Ctrl, for F10, and for Alt's release when no other key
//!   went down since Alt did (the capture: Alt alone is WM_SYSKEYDOWN then WM_SYSKEYUP, Alt+F's Alt
//!   released is a WM_KEYUP); WM_KEYDOWN and WM_KEYUP otherwise. wParam is the generic key, lParam
//!   the repeat count (1), the scan code, the extended bit, the context bit (Alt down), the
//!   previous state (the key was down; always 1 for a release) and the transition (a release).
//!
//! Each thread has a key state of its own ([`KeyState`], in its record beside its focus and active
//! window), which GetKeyState reads: a key message the thread reads out of its queue moves it
//! ([`read`]), so it is the state as of the thread's last message, and SetKeyboardState sets it.
//! GetAsyncKeyState reads the system's. TranslateMessage ([`translate`]) reads the thread's: the
//! character a key-down makes through the layout, under the thread's Shift, Ctrl and Caps Lock, is
//! posted as WM_CHAR (WM_SYSCHAR for a system key-down, whose character is the key's without Alt),
//! with the key-down's lParam.
//!
//! The services, user32's calls (F2K's argument lists, see [`crate::win32k`]; Windows 2000's
//! numbers):
//!
//! - NtUserSendInput (0x11E1): `Count` INPUT records at `Inputs`, each `Size` bytes (an INPUT's,
//!   28, or STATUS_INVALID_PARAMETER); the keyboard's run, the count run into `Sent`. The first
//!   that is not a keyboard event (the mouse's, deferred) stops the run;
//! - NtUserGetKeyState (0x1195) and NtUserGetAsyncKeyState (0x1175): a key's state, the thread's or
//!   the system's, as GetKeyState and GetAsyncKeyState answer it, into `State`;
//! - NtUserGetKeyboardState (0x1193) and NtUserSetKeyboardState (0x11F7): the thread's state of the
//!   256 keys, a byte each (0x80 down, 0x01 toggled), out of or into the caller's array;
//! - NtUserTranslateMessage (0x1224): the MSG at `Msg` translated ([`translate`]); whether a
//!   character was posted, into `Translated`.

use core::sync::atomic::{AtomicBool, Ordering};

use rtl::accel::Modifiers;
use rtl::console::input::{Decoder, Key};
use rtl::console::layout::{
    Origin,
    ALT,
    CAPS_LOCK,
    CTRL,
    NUM_LOCK,
    SCROLL_LOCK,
    SHIFT,
    US,
    VK_CAPITAL,
    VK_CONTROL,
    VK_F10,
    VK_LCONTROL,
    VK_LMENU,
    VK_LSHIFT,
    VK_MENU,
    VK_NUMLOCK,
    VK_RCONTROL,
    VK_RMENU,
    VK_RSHIFT,
    VK_SCROLL,
    VK_SHIFT,
};
use rtl::user::{
    Input,
    Msg,
    Point,
    KEYEVENTF_EXTENDEDKEY,
    KEYEVENTF_KEYUP,
    KEYEVENTF_SCANCODE,
    KEYEVENTF_UNICODE,
    WM_CHAR,
    WM_KEYDOWN,
    WM_KEYUP,
    WM_SYSCHAR,
    WM_SYSKEYDOWN,
    WM_SYSKEYUP,
};

use super::window::{WindowId, Windows};
use crate::sched::thread::ThreadId;
use crate::status::*;

/// The virtual key of a character SendInput carries in place of a key (KEYEVENTF_UNICODE): its
/// key message's wParam holds the character in its high word.
pub const VK_PACKET: u8 = 0xE7;

/// The make code of the right Shift key, which tells a generic Shift's side.
const RIGHT_SHIFT_SCAN: u8 = 0x36;

// --- The key states ------------------------------------------------------------------------------

/// A key state: for each of the 256 virtual keys, whether it is down and its toggle (which flips
/// each time the key goes down from up: Caps Lock's, Num Lock's and Scroll Lock's are their
/// lights).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyState {
    down: [u32; 8],
    toggled: [u32; 8],
}

impl KeyState {
    /// No key down, no toggle on.
    pub const EMPTY: Self = KeyState {
        down: [0; 8],
        toggled: [0; 8],
    };

    fn bit(bits: &[u32; 8], vk: u8) -> bool {
        bits[vk as usize / 32] & (1 << (vk % 32)) != 0
    }

    fn set(bits: &mut [u32; 8], vk: u8, on: bool) {
        if on {
            bits[vk as usize / 32] |= 1 << (vk % 32);
        } else {
            bits[vk as usize / 32] &= !(1 << (vk % 32));
        }
    }

    pub fn is_down(&self, vk: u8) -> bool {
        Self::bit(&self.down, vk)
    }

    pub fn is_toggled(&self, vk: u8) -> bool {
        Self::bit(&self.toggled, vk)
    }

    /// The key `vk` down or up, its toggle flipped when it goes down from up.
    fn update(&mut self, vk: u8, down: bool) {
        if down && !self.is_down(vk) {
            let toggled = self.is_toggled(vk);
            Self::set(&mut self.toggled, vk, !toggled);
        }
        Self::set(&mut self.down, vk, down);
    }

    /// The key `vk` goes down or up, as a keystroke or a key message moves it: a side's Shift,
    /// Ctrl or Alt takes the generic key with it, down while either side's is.
    pub fn press(&mut self, vk: u8, down: bool) {
        self.update(vk, down);
        if let Some((generic, left, right)) = sides(vk) {
            let either = self.is_down(left) || self.is_down(right);
            self.update(generic, either);
        }
    }

    /// The key's byte, as GetKeyboardState lays it: 0x80 down, 0x01 toggled.
    pub fn byte(&self, vk: u8) -> u8 {
        (if self.is_down(vk) { 0x80 } else { 0 }) | u8::from(self.is_toggled(vk))
    }

    /// The key's state from its byte, as SetKeyboardState takes it (the other bits ignored).
    pub fn set_byte(&mut self, vk: u8, byte: u8) {
        Self::set(&mut self.down, vk, byte & 0x80 != 0);
        Self::set(&mut self.toggled, vk, byte & 0x01 != 0);
    }

    /// GetKeyState's answer for the key: the high byte all ones while it is down (a negative
    /// SHORT, 0xFF80), the low bit its toggle.
    pub fn key_state(&self, vk: u8) -> u16 {
        (if self.is_down(vk) { 0xFF80 } else { 0 }) | u16::from(self.is_toggled(vk))
    }

    /// The modifiers down, by the generic keys: TranslateAccelerator's.
    pub fn modifiers(&self) -> Modifiers {
        Modifiers {
            shift: self.is_down(VK_SHIFT),
            control: self.is_down(VK_CONTROL),
            alt: self.is_down(VK_MENU),
        }
    }

    /// The layout's modifier bits (from the generic keys) and toggle bits the state holds.
    fn layout_bits(&self) -> (u8, u8) {
        let modifiers = self.modifiers();
        let mods = [
            (modifiers.shift, SHIFT),
            (modifiers.control, CTRL),
            (modifiers.alt, ALT),
        ];
        let toggles = [
            (VK_CAPITAL, CAPS_LOCK),
            (VK_NUMLOCK, NUM_LOCK),
            (VK_SCROLL, SCROLL_LOCK),
        ];
        (
            mods.iter()
                .filter(|&&(on, _)| on)
                .fold(0, |bits, &(_, bit)| bits | bit),
            toggles
                .iter()
                .filter(|&&(vk, _)| self.is_toggled(vk))
                .fold(0, |bits, &(_, bit)| bits | bit),
        )
    }

    /// The lights the toggles show (the layout's toggle bits).
    pub fn toggles(&self) -> u8 {
        self.layout_bits().1
    }
}

/// A side's modifier key: its generic key and the two sides' keys.
fn sides(vk: u8) -> Option<(u8, u8, u8)> {
    match vk {
        VK_LSHIFT | VK_RSHIFT => Some((VK_SHIFT, VK_LSHIFT, VK_RSHIFT)),
        VK_LCONTROL | VK_RCONTROL => Some((VK_CONTROL, VK_LCONTROL, VK_RCONTROL)),
        VK_LMENU | VK_RMENU => Some((VK_MENU, VK_LMENU, VK_RMENU)),
        _ => None,
    }
}

/// The key a message names for the side's key `vk`: the generic Shift, Ctrl or Alt.
fn generic(vk: u8) -> u8 {
    sides(vk).map_or(vk, |(generic, _, _)| generic)
}

/// The system's input state: the asynchronous key state, the keys pressed since GetAsyncKeyState
/// last answered for them, whether Alt went down with no other key since, and the decode of the
/// keyboard's bytes. The window registry's, behind the window manager's lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawInput {
    pub keys: KeyState,
    recent: [u32; 8],
    alt_alone: bool,
    decoder: Decoder,
}

impl RawInput {
    pub const EMPTY: Self = RawInput {
        keys: KeyState::EMPTY,
        recent: [0; 8],
        alt_alone: false,
        decoder: Decoder::new(),
    };

    /// GetAsyncKeyState's answer for the key: 0x8000 while it is down, the low bit when it went
    /// down since the last answer for it, which clears that.
    pub fn async_key_state(&mut self, vk: u8) -> u16 {
        let recent = KeyState::bit(&self.recent, vk);
        KeyState::set(&mut self.recent, vk, false);
        (if self.keys.is_down(vk) { 0x8000 } else { 0 }) | u16::from(recent)
    }
}

// --- The keystrokes ------------------------------------------------------------------------------

/// One keystroke on its way to a window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keystroke {
    /// The virtual key, the side's for Shift, Ctrl and Alt.
    pub vk: u8,
    pub scan: u8,
    pub extended: bool,
    pub up: bool,
    /// The character a VK_PACKET carries.
    pub character: u16,
}

impl Keystroke {
    /// SendInput's keyboard event as a keystroke, under the system's key state `keys` (a scan
    /// code's conversions read it); none for a scan code or virtual key that names no key.
    pub fn of_input(input: &Input, keys: &KeyState) -> Option<Keystroke> {
        let extended = input.flags & KEYEVENTF_EXTENDEDKEY != 0;
        let up = input.flags & KEYEVENTF_KEYUP != 0;
        let scan = input.scan as u8;
        if input.flags & KEYEVENTF_UNICODE != 0 {
            return Some(Keystroke {
                vk: VK_PACKET,
                scan: 0,
                extended: false,
                up,
                character: input.scan,
            });
        }
        let vk = if input.flags & KEYEVENTF_SCANCODE != 0 {
            let origin = if extended { Origin::E0 } else { Origin::Base };
            scan_key(origin, scan & 0x7F, keys)?
        } else {
            match u8::try_from(input.vk) {
                Ok(0) | Err(_) => return None,
                Ok(vk) => side(vk, scan, extended),
            }
        };
        Some(Keystroke {
            vk,
            scan,
            extended,
            up,
            character: 0,
        })
    }

    /// The keyboard's key, as its bytes decoded, a keystroke under the system's key state `keys`.
    pub fn of_key(key: &Key, keys: &KeyState) -> Option<Keystroke> {
        let (mods, toggles) = keys.layout_bits();
        let vk = US.virtual_key(key.origin, key.vk, mods, toggles);
        (vk != 0).then_some(Keystroke {
            vk,
            scan: key.make,
            extended: key.origin == Origin::E0,
            up: !key.down,
            character: 0,
        })
    }
}

/// The virtual key a make code from `origin` reports under the key state `keys`; none for a code
/// the layout's tables do not name.
fn scan_key(origin: Origin, make: u8, keys: &KeyState) -> Option<u8> {
    let physical = match origin {
        Origin::Base => US.scan[make as usize],
        Origin::E0 => US.e0_key(make)?,
    };
    let (mods, toggles) = keys.layout_bits();
    let vk = US.virtual_key(origin, physical, mods, toggles);
    (vk != 0).then_some(vk)
}

/// The side's key a generic Shift, Ctrl or Alt names: right Shift by its scan code, the right Ctrl
/// and Alt by the extended flag; any other key as it is.
fn side(vk: u8, scan: u8, extended: bool) -> u8 {
    match vk {
        VK_SHIFT if scan == RIGHT_SHIFT_SCAN => VK_RSHIFT,
        VK_SHIFT => VK_LSHIFT,
        VK_CONTROL if extended => VK_RCONTROL,
        VK_CONTROL => VK_LCONTROL,
        VK_MENU if extended => VK_RMENU,
        VK_MENU => VK_LMENU,
        other => other,
    }
}

/// The window the keystrokes go to: the foreground thread's focus window, or its active window
/// when it has no focus window (the keystrokes then system keys).
fn target(windows: &Windows) -> Option<(WindowId, bool)> {
    let thread = windows.foreground_thread?;
    if !windows.thread(thread).live {
        return None;
    }
    super::focus::focus_window(windows, thread)
        .map(|window| (window, false))
        .or_else(|| super::focus::active_window(windows, thread).map(|window| (window, true)))
}

/// A keystroke, stamped `time`: the system's key state moved, and its key message posted to the
/// window the keystrokes go to (see the module's description); nothing is posted when there is
/// none. The toggles, when the keystroke changed them (a toggle key going down), for the lights.
pub fn key_event(windows: &mut Windows, stroke: Keystroke, time: u32) -> Option<u8> {
    let input = &mut windows.input;
    let vk = stroke.vk;
    let was_down = input.keys.is_down(vk);
    let toggles = input.keys.toggles();
    input.keys.press(vk, !stroke.up);
    let is_alt = matches!(vk, VK_LMENU | VK_RMENU);
    let alt_alone = input.alt_alone;
    if stroke.up {
        if is_alt {
            input.alt_alone = false;
        }
    } else {
        KeyState::set(&mut input.recent, vk, true);
        KeyState::set(&mut input.recent, generic(vk), true);
        if is_alt {
            if !was_down {
                input.alt_alone = true;
            }
        } else {
            input.alt_alone = false;
        }
    }
    let alt = input.keys.is_down(VK_MENU);
    let ctrl = input.keys.is_down(VK_CONTROL);
    let changed = (input.keys.toggles() != toggles).then(|| input.keys.toggles());

    let Some((window, inactive)) = target(windows) else {
        return changed;
    };
    let system = inactive
        || if is_alt && stroke.up {
            alt_alone && !ctrl
        } else {
            (alt && !ctrl) || vk == VK_F10
        };
    let message = match (system, stroke.up) {
        (false, false) => WM_KEYDOWN,
        (false, true) => WM_KEYUP,
        (true, false) => WM_SYSKEYDOWN,
        (true, true) => WM_SYSKEYUP,
    };
    let previous = stroke.up || was_down;
    let lparam = 1
        | u32::from(stroke.scan) << 16
        | u32::from(stroke.extended) << 24
        | u32::from(alt) << 29
        | u32::from(previous) << 30
        | u32::from(stroke.up) << 31;
    let msg = Msg {
        hwnd: windows.handle_of(window),
        message,
        wparam: u32::from(generic(vk)) | u32::from(stroke.character) << 16,
        lparam: lparam as i32,
        time,
        pt: Point::default(),
    };
    let thread = windows.window_thread(window);
    super::queue::post_input(windows, thread, msg, vk, !stroke.up && was_down);
    changed
}

/// One of the keyboard's bytes, stamped `time`: the keystroke it completes, if it completes one
/// ([`key_event`]). The toggles when the keystroke changed them, for the lights.
pub fn key_byte(windows: &mut Windows, byte: u8, time: u32) -> Option<u8> {
    let key = windows.input.decoder.byte(&US, byte)?;
    let stroke = Keystroke::of_key(&key, &windows.input.keys)?;
    key_event(windows, stroke, time)
}

/// The thread `thread` read the input message `msg` out of its queue, of the key `key` (the
/// side's, for a modifier): its key state moves with it.
pub fn read(windows: &mut Windows, thread: ThreadId, msg: &Msg, key: u8) {
    let down = matches!(msg.message, WM_KEYDOWN | WM_SYSKEYDOWN);
    if matches!(
        msg.message,
        WM_KEYDOWN | WM_KEYUP | WM_SYSKEYDOWN | WM_SYSKEYUP
    ) {
        windows.thread_mut(thread).keys.press(key, down);
    }
}

/// TranslateMessage for the thread `thread`: the character a key-down message makes, under the
/// thread's key state, posted to the message's window as WM_CHAR (WM_SYSCHAR for a
/// WM_SYSKEYDOWN, its character the key's without Alt), with the key-down's lParam, stamped
/// `time`. Whether a character was posted: none for another message, or a key that makes none.
pub fn translate(
    windows: &mut Windows,
    thread: ThreadId,
    msg: &Msg,
    time: u32,
) -> Result<bool, NtStatus> {
    let (message, system) = match msg.message {
        WM_KEYDOWN => (WM_CHAR, false),
        WM_SYSKEYDOWN => (WM_SYSCHAR, true),
        _ => return Ok(false),
    };
    let vk = msg.wparam as u8;
    let character = if vk == VK_PACKET {
        (msg.wparam >> 16) as u16
    } else if msg.wparam > 0xFF {
        0
    } else {
        let (mut mods, toggles) = windows.thread(thread).keys.layout_bits();
        if system {
            mods &= !ALT;
        }
        US.character(vk, mods, toggles)
    };
    if character == 0 {
        return Ok(false);
    }
    super::queue::post(
        windows,
        thread,
        msg.hwnd,
        message,
        u32::from(character),
        msg.lparam,
        time,
    )?;
    Ok(true)
}

// --- Where the keyboard's bytes go ---------------------------------------------------------------

/// Whether a GUI thread is in the foreground (it has an active window), so the keyboard's bytes go
/// to win32k: the window manager's state, published for the keyboard's DPC, which cannot take the
/// lock, each time the lock is let go ([`publish`]).
static TAKES_KEYBOARD: AtomicBool = AtomicBool::new(false);

/// Publish whether the keyboard's bytes go to win32k: the window manager's bridges' last step,
/// under its lock.
pub fn publish(windows: &Windows) {
    TAKES_KEYBOARD.store(
        super::focus::foreground_window(windows).is_some(),
        Ordering::SeqCst,
    );
}

/// Whether the keyboard's bytes go to win32k (a GUI thread is in the foreground), as the window
/// manager last published it; to the console otherwise.
pub fn takes_keyboard() -> bool {
    TAKES_KEYBOARD.load(Ordering::SeqCst)
}

#[cfg(target_arch = "x86")]
mod target {
    use core::cell::UnsafeCell;
    use core::ptr::NonNull;

    use crate::hw::kbd::ByteRing;
    use crate::level::{At, Dispatch};
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::wait::{WaitReason, WaitableId};

    /// The raw input thread's priority: Windows 2000's, LOW_REALTIME_PRIORITY + 3, above every
    /// program's thread, so a keystroke reaches its queue before the program reads on.
    const PRIORITY: i8 = 19;

    /// The keyboard's bytes for the raw input thread, in arrival order: the DPC puts them, the
    /// thread takes them.
    static RAW: ByteRing = ByteRing::new();

    /// The raw input thread's work event: a synchronization event, set by the DPC for each byte,
    /// waited on by the thread alone. Named by its address in the dispatcher database
    /// ([`WaitableId::Embedded`]), and reached only through the dispatcher once named.
    struct WorkEvent(UnsafeCell<Event>);

    // SAFETY: one processor. The event is touched directly once, by `start` at boot, before the
    // thread exists and before the keyboard's bytes can reach it; from then on only the
    // dispatcher reaches its header, by its address, serialized at the dispatch level.
    unsafe impl Sync for WorkEvent {}

    static WORK: WorkEvent = WorkEvent(UnsafeCell::new(Event::new(
        EventKind::Synchronization,
        false,
    )));

    impl WorkEvent {
        /// The event's name: its header's address. No reference to the event is formed.
        fn id(&self) -> WaitableId {
            // SAFETY: a projection inside the static's own cell: it computes the header's address
            // and reads nothing.
            let header = unsafe { core::ptr::addr_of_mut!((*self.0.get()).waitable) };
            WaitableId::Embedded(NonNull::new(header).expect("a static is not null"))
        }
    }

    /// Start the raw input thread: once, at boot, before the first process.
    pub fn start() {
        {
            let _masked = crate::pcr::pcr().mask_guard();
            // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing waits on
            // it or sets it yet, and interrupts are masked for the reference's life.
            unsafe { (*WORK.0.get()).init() };
        }
        crate::sched::idle::start_system_thread(
            crate::sched::database::RAW_INPUT_THREAD,
            raw_input_thread,
            PRIORITY,
        );
    }

    /// The keyboard DPC's hand-over of a byte for win32k: kept for the raw input thread, which is
    /// woken. A byte that finds the ring full is lost.
    pub fn raw_byte(dispatch: &mut At<Dispatch>, byte: u8) {
        if !RAW.push(byte) {
            crate::serial_println!("F2K: kbd: raw input ring full: a byte dropped");
        }
        crate::sched::DISPATCHER
            .get(dispatch)
            .set_event(WORK.id(), EVENT_WAKE_INCREMENT);
    }

    /// The raw input thread's routine: wait for bytes, run each one's keystroke under the window
    /// manager's lock, show the toggles it changed on the lights, again. Never returns.
    extern "C" fn raw_input_thread(_start: u32, _context: u32) -> ! {
        loop {
            crate::sched::wait::wait_current_for(WORK.id(), WaitReason::Executive, None);
            while let Some(byte) = RAW.pop() {
                let time = crate::win32k::queue::millis(crate::win32k::queue::now());
                let lights =
                    crate::win32k::queue::locked(|m| super::key_byte(&mut m.windows, byte, time));
                if let Some(toggles) = lights {
                    crate::hw::kbd::show_toggles(toggles);
                }
            }
        }
    }
}

#[cfg(target_arch = "x86")]
pub use target::{raw_byte, start};

#[cfg(target_arch = "x86")]
mod services {
    use super::*;
    use crate::nt::call::{NtCall, NtResult, UserAddr, UserPtr};
    use crate::win32k::queue::{millis, now, with_manager};
    use crate::win32k::winsta::gui_thread;

    /// The keys a keyboard state holds: GetKeyboardState's and SetKeyboardState's array.
    const KEYS: usize = 256;

    /// NtUserSendInput(Count, Inputs, Size, Sent): the INPUT records' keystrokes run in order (see
    /// [`key_event`]), until one that is not a keyboard event; how many ran into `sent`.
    /// STATUS_INVALID_PARAMETER for a size other than an INPUT's.
    pub fn send_input(
        call: &mut NtCall,
        count: u32,
        inputs: UserAddr,
        size: i32,
        sent: UserPtr<u32>,
    ) -> NtResult {
        gui_thread(call)?;
        if size as usize != core::mem::size_of::<Input>() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut done = 0;
        while done < count {
            let input = inputs
                .offset(done.wrapping_mul(size as u32))
                .cast::<Input>()
                .read()?;
            if input.kind != rtl::user::INPUT_KEYBOARD {
                break;
            }
            let time = millis(now());
            let lights = with_manager(call.passive(), |m| {
                let stroke = Keystroke::of_input(&input, &m.windows.input.keys)?;
                key_event(&mut m.windows, stroke, time)
            });
            if let Some(toggles) = lights {
                crate::hw::kbd::show_toggles(toggles);
            }
            done += 1;
        }
        sent.write(done)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetKeyState(VirtKey, State): the calling thread's state of the key, as GetKeyState
    /// answers it (0 for a key past 255).
    pub fn get_key_state(call: &mut NtCall, vk: i32, state: UserPtr<u32>) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let answer = with_manager(call.passive(), |m| {
            u8::try_from(vk).map_or(0, |vk| m.windows.thread(caller).keys.key_state(vk))
        });
        state.write(u32::from(answer))?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetAsyncKeyState(VirtKey, State): the system's state of the key, as GetAsyncKeyState
    /// answers it (0 for a key past 255).
    pub fn get_async_key_state(call: &mut NtCall, vk: i32, state: UserPtr<u32>) -> NtResult {
        gui_thread(call)?;
        let answer = with_manager(call.passive(), |m| {
            u8::try_from(vk).map_or(0, |vk| m.windows.input.async_key_state(vk))
        });
        state.write(u32::from(answer))?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserGetKeyboardState(KeyState): the calling thread's key state, a byte a key, into the
    /// caller's 256-byte array.
    pub fn get_keyboard_state(call: &mut NtCall, keys: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let mut bytes = [0u8; KEYS];
        with_manager(call.passive(), |m| {
            let state = &m.windows.thread(caller).keys;
            for (vk, byte) in bytes.iter_mut().enumerate() {
                *byte = state.byte(vk as u8);
            }
        });
        keys.write(&bytes)?;
        Ok(STATUS_SUCCESS)
    }

    /// NtUserSetKeyboardState(KeyState): the calling thread's key state from the caller's 256-byte
    /// array (the system's is left as it is).
    pub fn set_keyboard_state(call: &mut NtCall, keys: UserAddr) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let mut bytes = [0u8; KEYS];
        keys.read(&mut bytes)?;
        with_manager(call.passive(), |m| {
            let state = &mut m.windows.thread_mut(caller).keys;
            for (vk, &byte) in bytes.iter().enumerate() {
                state.set_byte(vk as u8, byte);
            }
        });
        Ok(STATUS_SUCCESS)
    }

    /// NtUserTranslateMessage(Msg, Flags, Translated): the MSG at `msg` translated for the calling
    /// thread ([`translate`]); whether a character was posted, into `translated`. `Flags` is
    /// TranslateMessageEx's, 0 from TranslateMessage.
    pub fn translate_message(
        call: &mut NtCall,
        msg: UserAddr,
        _flags: u32,
        translated: UserPtr<u32>,
    ) -> NtResult {
        let caller = gui_thread(call)?.thread;
        let msg = msg.cast::<Msg>().read()?;
        let time = millis(now());
        let posted = with_manager(call.passive(), |m| {
            translate(&mut m.windows, caller, &msg, time)
        })?;
        translated.write(u32::from(posted))?;
        Ok(STATUS_SUCCESS)
    }
}

// The host builds have no processes and no user memory: the services answer nothing (the host
// tests drive the keystrokes and the translation themselves).
#[cfg(not(target_arch = "x86"))]
mod services {
    use super::*;
    use crate::nt::call::{NtCall, NtResult, UserAddr, UserPtr};

    pub fn send_input(_: &mut NtCall, _: u32, _: UserAddr, _: i32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_key_state(_: &mut NtCall, _: i32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_async_key_state(_: &mut NtCall, _: i32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn get_keyboard_state(_: &mut NtCall, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn set_keyboard_state(_: &mut NtCall, _: UserAddr) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }

    pub fn translate_message(_: &mut NtCall, _: UserAddr, _: u32, _: UserPtr<u32>) -> NtResult {
        Err(STATUS_NOT_IMPLEMENTED)
    }
}

pub use services::{
    get_async_key_state,
    get_key_state,
    get_keyboard_state,
    send_input,
    set_keyboard_state,
    translate_message,
};

#[cfg(test)]
mod tests;
