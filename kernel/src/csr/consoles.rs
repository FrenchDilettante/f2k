//! The server's consoles, and which console each process is attached to, as Windows 2000's csrss
//! holds a console per window and each process's console in its process data.
//!
//! The boot's console ([`BOOT`]) is the first program's, which every program the boot starts
//! shares; it lives for the whole boot. The others are made for a program that asks for one of its
//! own — AllocConsole, or the connection of a process CreateProcess gave a new console
//! (CREATE_NEW_CONSOLE, or a console program whose creator has none) — and go with the last process
//! attached to them, as Windows 2000's console goes with its last process. The server holds
//! [`CONSOLES`] at once: past them, AllocConsole is refused (ERROR_NOT_ENOUGH_MEMORY).
//!
//! A process is attached to its creator's console when NtCreateProcess makes it ([`inherit`]),
//! taken off it when its creator announces it DETACHED_PROCESS or CREATE_NEW_CONSOLE, attached to
//! the console made for it, taken off by FreeConsole, and forgotten at its end. A process the
//! server never heard of is one of the boot's own programs, which no creator made: it shares the
//! boot's console.
//!
//! F2K has one screen. It shows one console, the foreground one, and the keyboard types into that
//! console, as a single-screen system's would: the console made last that is still live and not
//! hidden (a console made SW_HIDE never comes to the screen, as its window never shows); the boot's
//! once no other is. A console's making brings it to the screen, its end gives the screen back.
//! The others' screen buffers change as their programs write, unseen.
//!
//! A console's window (GetConsoleWindow) is a value that names the console: F2K's window manager
//! has no window for a console (no console window class, no thread of the server's to own one), so
//! the value is a window handle's shape — even, its low word past the user handle table's slots,
//! the count of consoles made in its high word — that names no window: user32's calls take it for
//! a destroyed window's handle. It is distinct for each console and stays its console's.
//!
//! [`inherit`]: super::inherit

use rtl::console::Console;

use super::ctrl::SERVER_PROCESSES;
use crate::ob::ObjectId;
use crate::status::*;

/// How many consoles the server holds at once: the boot's, and three made for programs.
pub const CONSOLES: usize = 4;

/// The boot's console.
pub const BOOT: usize = 0;

/// A console window's low word, past the user handle table's last slot (1024 slots, the handle
/// the slot shifted left two), with the console's index above its three low bits.
const WINDOW_BASE: u32 = 0xE000;

/// One of the server's consoles: the console, and what the server keeps beside it.
pub struct Slot {
    pub console: Console,
    /// Whether the slot holds a console now (the boot's always does).
    live: bool,
    /// The console's input-wait event, once a process asked for it (Windows 2000's
    /// CONSOLE_INFORMATION.InputEvent): the object, which the server holds a reference on until
    /// the console goes.
    pub input_event: Option<ObjectId>,
    /// Its window's value (see the module's notes).
    window: u32,
    /// Whether it was made hidden (SW_HIDE): it never comes to the screen.
    hidden: bool,
    /// When it was made: the server's count of consoles made then (the boot's 0).
    made: u32,
}

impl Slot {
    /// A slot's console, fresh. Its console makes it large: it is evaluated where it is kept, at
    /// compile time (the server is a static), never on a kernel stack.
    #[allow(clippy::large_unopt_stack_frames)]
    const fn new(live: bool, index: usize) -> Self {
        Slot {
            console: Console::new(),
            live,
            input_event: None,
            window: window(index, 0),
            hidden: false,
            made: 0,
        }
    }
}

/// The window of the console at `index`, the `made`th made.
const fn window(index: usize, made: u32) -> u32 {
    ((made & 0x7FFF) << 16) | WINDOW_BASE | ((index as u32) << 3)
}

/// What a new console is made of: its title, its screen buffer's size and attribute, whether it is
/// hidden.
#[derive(Clone, Copy, Debug)]
pub struct Making<'a> {
    pub title: &'a [u16],
    pub width: usize,
    pub height: usize,
    pub attribute: u16,
    pub hidden: bool,
}

/// The consoles, the processes' attachments, and the console the screen shows.
pub struct Consoles {
    slots: [Slot; CONSOLES],
    /// The processes the server attached to a console, or took off one: each with its console's
    /// index, none for no console.
    attached: [Option<(ObjectId, Option<u8>)>; SERVER_PROCESSES],
    /// The console the screen shows and the keyboard types into.
    foreground: usize,
    /// How many consoles were made.
    made: u32,
}

impl Consoles {
    /// The boot's console alone, on the screen; no process attached. Evaluated at compile time,
    /// as [`Slot::new`] is.
    #[allow(clippy::large_unopt_stack_frames)]
    pub const fn new() -> Self {
        let mut slots = [const { Slot::new(false, BOOT) }; CONSOLES];
        let mut index = 0;
        while index < CONSOLES {
            slots[index] = Slot::new(index == BOOT, index);
            index += 1;
        }
        Consoles {
            slots,
            attached: [None; SERVER_PROCESSES],
            foreground: BOOT,
            made: 0,
        }
    }

    /// The console at `index`.
    pub fn slot(&mut self, index: usize) -> &mut Slot {
        &mut self.slots[index]
    }

    /// Every console's slot, live or not.
    pub fn slots(&mut self) -> impl Iterator<Item = &mut Slot> {
        self.slots.iter_mut()
    }

    /// The console the screen shows.
    pub fn foreground(&self) -> usize {
        self.foreground
    }

    /// The console `process` is attached to; none when it has none.
    pub fn console_of(&self, process: ObjectId) -> Option<usize> {
        match self.entry(process) {
            Some(entry) => self.attached[entry].and_then(|(_, console)| console.map(usize::from)),
            None => Some(BOOT),
        }
    }

    /// The window of the console at `index`.
    pub fn window(&self, index: usize) -> u32 {
        self.slots[index].window
    }

    /// The entry holding `process`.
    fn entry(&self, process: ObjectId) -> Option<usize> {
        self.attached
            .iter()
            .position(|held| held.is_some_and(|(held, _)| held == process))
    }

    /// Attach `process` to the console at `console` (none: no console); false, nothing changed,
    /// when the server has no room for it.
    pub fn attach(&mut self, process: ObjectId, console: Option<usize>) -> bool {
        let Some(entry) = self
            .entry(process)
            .or_else(|| self.attached.iter().position(Option::is_none))
        else {
            return false;
        };
        self.attached[entry] = Some((process, console.map(|index| index as u8)));
        true
    }

    /// Forget `process` (its end): the console it was attached to, if any.
    pub fn forget(&mut self, process: ObjectId) -> Option<usize> {
        let console = self.console_of(process);
        if let Some(entry) = self.entry(process) {
            self.attached[entry] = None;
        }
        console
    }

    /// Whether a process is attached to the console at `index` (the boot's always counts: its
    /// programs need no attachment).
    fn in_use(&self, index: usize) -> bool {
        index == BOOT
            || self
                .attached
                .iter()
                .flatten()
                .any(|&(_, console)| console == Some(index as u8))
    }

    /// AllocConsole's work for `process`: a console made as `making` says, `process` attached to
    /// it, and on the screen unless hidden; its index. STATUS_ACCESS_DENIED for a process attached
    /// to a console already, STATUS_NO_MEMORY when the server holds as many consoles as it can (or
    /// has no room for the process).
    pub fn allocate(&mut self, process: ObjectId, making: &Making) -> Result<usize, NtStatus> {
        if self.console_of(process).is_some() {
            return Err(STATUS_ACCESS_DENIED);
        }
        let index = (0..CONSOLES)
            .find(|&index| !self.slots[index].live)
            .ok_or(STATUS_NO_MEMORY)?;
        if !self.attach(process, Some(index)) {
            return Err(STATUS_NO_MEMORY);
        }
        self.made = self.made.wrapping_add(1);
        let slot = &mut self.slots[index];
        slot.console
            .make_fresh(making.title, making.width, making.height, making.attribute);
        slot.live = true;
        slot.hidden = making.hidden;
        slot.made = self.made;
        slot.window = window(index, self.made);
        if !making.hidden {
            self.foreground = index;
        }
        Ok(index)
    }

    /// FreeConsole's work for `process`: taken off its console; the console's index.
    /// STATUS_INVALID_PARAMETER for a process with no console, STATUS_NO_MEMORY when the server
    /// has no room to record it.
    pub fn detach(&mut self, process: ObjectId) -> Result<usize, NtStatus> {
        let index = self.console_of(process).ok_or(STATUS_INVALID_PARAMETER)?;
        if !self.attach(process, None) {
            return Err(STATUS_NO_MEMORY);
        }
        Ok(index)
    }

    /// The console at `index` goes when no process is attached to it any more (never the boot's),
    /// the screen going to the foreground console left; its input-wait event, which the caller
    /// releases (below the server's level).
    pub fn release_unused(&mut self, index: usize) -> Option<ObjectId> {
        if self.in_use(index) || !self.slots[index].live {
            return None;
        }
        let slot = &mut self.slots[index];
        slot.live = false;
        let event = slot.input_event.take();
        if self.foreground == index {
            self.foreground = (0..CONSOLES)
                .filter(|&index| self.slots[index].live && !self.slots[index].hidden)
                .max_by_key(|&index| self.slots[index].made)
                .unwrap_or(BOOT);
        }
        event
    }
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use super::*;
    use crate::ob::ObjectType;

    fn process(index: u16) -> ObjectId {
        ObjectId {
            kind: ObjectType::Process,
            index,
            generation: 1,
        }
    }

    /// Fresh consoles on the heap, copied there from fresh ones in the image: they are too large
    /// for a test thread's stack.
    fn fresh() -> Box<Consoles> {
        static FRESH: Consoles = Consoles::new();
        let mut copy = Box::<Consoles>::new_uninit();
        // SAFETY: a bitwise copy of the consoles (plain data, owning nothing, so the copy is a
        // clone of them), into the box's room for them.
        unsafe {
            core::ptr::copy_nonoverlapping(&FRESH, copy.as_mut_ptr(), 1);
            copy.assume_init()
        }
    }

    fn making(hidden: bool) -> Making<'static> {
        Making {
            title: &[0x61, 0x62],
            width: 100,
            height: 200,
            attribute: 0x1E,
            hidden,
        }
    }

    /// A process the server never heard of shares the boot's console; a console made for a
    /// process takes it alone, comes to the screen, and goes with its last process, the screen
    /// going back.
    #[test]
    fn a_console_made_for_a_process_goes_with_its_last_process() {
        let mut consoles = fresh();
        assert_eq!(consoles.console_of(process(1)), Some(BOOT));
        assert_eq!(
            consoles.allocate(process(1), &making(false)),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(consoles.detach(process(1)), Ok(BOOT));
        assert_eq!(consoles.console_of(process(1)), None);
        assert_eq!(consoles.detach(process(1)), Err(STATUS_INVALID_PARAMETER));
        let index = consoles.allocate(process(1), &making(false)).unwrap();
        assert_ne!(index, BOOT);
        assert_eq!(consoles.foreground(), index);
        assert_ne!(consoles.window(index), consoles.window(BOOT));
        let console = &consoles.slot(index).console;
        assert_eq!(console.title(), [0x61, 0x62]);
        assert_eq!(console.screen.size(), (100, 200));
        assert_eq!(console.screen.attribute(), 0x1E);
        // A child shares it; the console stays while either is attached.
        assert!(consoles.attach(process(2), consoles.console_of(process(1))));
        assert_eq!(consoles.forget(process(1)), Some(index));
        assert_eq!(consoles.release_unused(index), None);
        assert_eq!(consoles.foreground(), index);
        assert_eq!(consoles.forget(process(2)), Some(index));
        assert_eq!(consoles.release_unused(index), None);
        assert_eq!(consoles.foreground(), BOOT);
        assert_eq!(consoles.release_unused(BOOT), None);
        assert_eq!(consoles.console_of(process(2)), Some(BOOT), "forgotten");
    }

    /// A hidden console never comes to the screen; the screen goes back to the latest console
    /// shown once the one it shows goes; the server holds so many consoles and refuses the next.
    #[test]
    fn the_screen_shows_the_latest_console_shown() {
        let mut consoles = fresh();
        for index in 1..4 {
            consoles.detach(process(index)).unwrap();
        }
        let first = consoles.allocate(process(1), &making(false)).unwrap();
        let hidden = consoles.allocate(process(2), &making(true)).unwrap();
        assert_eq!(consoles.foreground(), first);
        let last = consoles.allocate(process(3), &making(false)).unwrap();
        assert_eq!(consoles.foreground(), last);
        consoles.detach(process(4)).unwrap();
        assert_eq!(
            consoles.allocate(process(4), &making(false)),
            Err(STATUS_NO_MEMORY)
        );
        consoles.detach(process(3)).unwrap();
        consoles.release_unused(last);
        assert_eq!(consoles.foreground(), first);
        consoles.forget(process(1));
        consoles.release_unused(first);
        assert_eq!(consoles.foreground(), BOOT);
        assert_eq!(consoles.console_of(process(2)), Some(hidden));
        let again = consoles.allocate(process(4), &making(false)).unwrap();
        assert_eq!(
            consoles.window(again) & 0xFFFF,
            0xE000 | (again as u32) << 3
        );
        assert_ne!(consoles.window(again), window(again, 0));
    }
}
