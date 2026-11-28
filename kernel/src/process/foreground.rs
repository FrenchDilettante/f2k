//! The foreground process and its stretched quantum: Windows 2000's priority separation.
//!
//! Windows 2000 gives the threads of the foreground process a longer quantum than the others'. The
//! registry's `HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl\Win32PrioritySeparation`
//! (read at boot into PsRawPrioritySeparation) picks a table of three quanta, PspForegroundQuantum
//! (PsChangeQuantumTable), and how far into it the foreground process reaches,
//! PsPrioritySeparation:
//!
//! - bits 0-1, the separation: the index of the foreground process's quantum (3 reads as 2); the
//!   background processes take index 0;
//! - bits 2-3, variable (1) or fixed (2) quanta; 0 is the product's default, variable on
//!   Professional and fixed on Server;
//! - bits 4-5, long (1) or short (2) quanta; 0 is the product's default, short on Professional and
//!   long on Server.
//!
//! The tables, in quantum units (three a clock tick, so 6 is the two-tick base, THREAD_QUANTUM):
//! variable short 6, 12, 18; variable long 12, 24, 36; fixed short 18, 18, 18; fixed long 36, 36,
//! 36. Professional's default, 2, is variable short quanta with the foreground three times the
//! background's: 18 against 6. A fixed table stretches nothing, whatever the separation.
//!
//! A process's quantum is set when it changes between the foreground and the background
//! (PsSetProcessPriorityByClass, [`super::Process::set_priority_by_class`]): its scheduling
//! record's thread quantum, the value each of its threads' quanta reset to, becomes the table's
//! entry at the separation for the foreground, at 0 for the background, and THREAD_QUANTUM whatever
//! its state for a process of the idle priority class. The process's base priority is then set
//! again (KeSetPriorityProcess), which hands each of its threads a fresh quantum of the new length.
//!
//! Which process is the foreground one is the window manager's and the console server's to say. On
//! Windows 2000 win32k marks the process of the thread that takes the foreground
//! (SetForegroundWindow and the activations) foreground and the one that loses it background; csrss
//! marks the processes of a console whose window takes the focus foreground (and those of one that
//! loses it background), and a process connecting to the focused console foreground. F2K's console
//! has no window (see `crate::csr::consoles`): its one screen shows the foreground console, and the
//! keyboard types into it unless a GUI thread has the foreground (`win32k::input::takes_keyboard`).
//! So F2K's foreground processes follow the keyboard: the process of the window manager's
//! foreground window's thread while there is one, otherwise every process attached to the
//! foreground console ([`wanted`]).
//!
//! The window manager publishes its foreground process each time its lock goes ([`publish_gui`]),
//! and the console server notes each change to its consoles and their processes
//! ([`console_changed`]), as does the making of a process. Either marks the foreground stale, and
//! the next settle point — a console call's end, a window-manager session's end, a process's
//! creation — walks the processes and moves each one whose state changed ([`sync`]). A settle point
//! is a service at the passive level; one reached on the idle thread (the reap) leaves the walk to
//! the next.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::sched::QUANTUM_RESET;

/// Win32PrioritySeparation's default on Windows 2000 Professional: variable short quanta, the
/// foreground's three times the background's.
pub const DEFAULT_PRIORITY_SEPARATION: u32 = 2;

/// The separation's bits: the foreground process's index into the table.
const SEPARATION_MASK: u32 = 0x3;
/// The most the separation reaches (a separation of 3 reads as this).
const SEPARATION_MAX: u8 = 2;
/// The variable-or-fixed bits, and their values.
const VARIABLE_MASK: u32 = 0xC;
const VARIABLE_VALUE: u32 = 0x4;
const FIXED_VALUE: u32 = 0x8;
/// The long-or-short bits, and their values.
const LONG_MASK: u32 = 0x30;
const LONG_VALUE: u32 = 0x10;
const SHORT_VALUE: u32 = 0x20;

/// The two-tick base quantum (THREAD_QUANTUM).
const BASE: i8 = QUANTUM_RESET;

/// PspVariableQuantums: short (1x, 2x, 3x), then long (2x, 4x, 6x).
const VARIABLE_QUANTA: [i8; 6] = [BASE, 2 * BASE, 3 * BASE, 2 * BASE, 4 * BASE, 6 * BASE];
/// PspFixedQuantums: short (3x thrice), then long (6x thrice).
const FIXED_QUANTA: [i8; 6] = [3 * BASE, 3 * BASE, 3 * BASE, 6 * BASE, 6 * BASE, 6 * BASE];

/// Whether F2K answers as Windows 2000 Server (MmIsThisAnNtAsSystem): never, it is Professional.
const SERVER: bool = false;

/// The quantum table a Win32PrioritySeparation value selects (PsChangeQuantumTable): the
/// separation and the three quanta.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QuantumTable {
    separation: u8,
    quanta: [i8; 3],
}

impl QuantumTable {
    /// The table `raw` selects, on Server or Professional (the defaults of its zero fields).
    pub const fn new(raw: u32, server: bool) -> Self {
        let separation = match raw & SEPARATION_MASK {
            3 => SEPARATION_MAX,
            separation => separation as u8,
        };
        let fixed = match raw & VARIABLE_MASK {
            VARIABLE_VALUE => false,
            FIXED_VALUE => true,
            _ => server,
        };
        let long = match raw & LONG_MASK {
            LONG_VALUE => true,
            SHORT_VALUE => false,
            _ => server,
        };
        let table = if fixed { FIXED_QUANTA } else { VARIABLE_QUANTA };
        let at = if long { 3 } else { 0 };
        QuantumTable {
            separation,
            quanta: [table[at], table[at + 1], table[at + 2]],
        }
    }

    /// PsPrioritySeparation: the foreground's index.
    #[cfg(test)]
    pub const fn separation(&self) -> u8 {
        self.separation
    }

    /// PspForegroundQuantum.
    #[cfg(test)]
    pub const fn quanta(&self) -> [i8; 3] {
        self.quanta
    }

    /// The thread quantum of a process in the foreground or the background, of the idle priority
    /// class or another (PsSetProcessPriorityByClass's).
    pub const fn thread_quantum(&self, foreground: bool, idle_class: bool) -> i8 {
        if idle_class {
            return BASE;
        }
        let index = if foreground { self.separation } else { 0 };
        self.quanta[index as usize]
    }
}

/// The Win32PrioritySeparation the system runs with: the registry's, read at boot.
static RAW: AtomicU32 = AtomicU32::new(DEFAULT_PRIORITY_SEPARATION);

/// The quantum table the system runs with.
pub fn table() -> QuantumTable {
    QuantumTable::new(RAW.load(Ordering::Relaxed), SERVER)
}

/// Take the registry's Win32PrioritySeparation: at boot, before the first process.
pub fn set_priority_separation(raw: u32) {
    RAW.store(raw, Ordering::Relaxed);
}

/// The priority class whose processes keep the base quantum (PROCESS_PRIORITY_CLASS_IDLE).
pub const IDLE_PRIORITY_CLASS: u8 = 1;

/// The thread quantum of a process in the foreground or not, of the priority class `class`.
pub fn thread_quantum(foreground: bool, class: u8) -> i8 {
    table().thread_quantum(foreground, class == IDLE_PRIORITY_CLASS)
}

/// Whether the process at pool index `index` belongs in the foreground: the window manager's
/// foreground process (`gui`) alone while it has one, otherwise each process attached to the
/// foreground console.
pub fn wanted(gui: Option<u16>, index: u16, on_foreground_console: bool) -> bool {
    match gui {
        Some(owner) => owner == index,
        None => on_foreground_console,
    }
}

/// No foreground window.
const NO_GUI: u32 = u32::MAX;

/// What the walk reads: the window manager's foreground process as last published, and whether
/// the foreground may have changed since the last walk.
struct Published {
    /// The foreground window's thread's process's pool index, [`NO_GUI`] for none.
    gui: AtomicU32,
    stale: AtomicBool,
}

impl Published {
    const fn new() -> Self {
        Published {
            gui: AtomicU32::new(NO_GUI),
            stale: AtomicBool::new(false),
        }
    }

    /// Publish the window manager's foreground process: a change marks the foreground stale.
    fn publish_gui(&self, owner: Option<u16>) {
        let value = owner.map_or(NO_GUI, u32::from);
        if self.gui.swap(value, Ordering::SeqCst) != value {
            self.stale.store(true, Ordering::SeqCst);
        }
    }

    fn gui(&self) -> Option<u16> {
        match self.gui.load(Ordering::SeqCst) {
            NO_GUI => None,
            index => Some(index as u16),
        }
    }

    fn mark_stale(&self) {
        self.stale.store(true, Ordering::SeqCst);
    }

    /// Whether the foreground was stale, now not.
    fn take_stale(&self) -> bool {
        self.stale.swap(false, Ordering::SeqCst)
    }
}

static PUBLISHED: Published = Published::new();

/// The window manager's foreground process (the pool index of its foreground window's thread's
/// process), published under its lock; a change marks the foreground stale.
pub fn publish_gui(owner: Option<u16>) {
    PUBLISHED.publish_gui(owner);
}

/// The console server's consoles or their processes changed, or a process was made: the
/// foreground is stale.
pub fn console_changed() {
    PUBLISHED.mark_stale();
}

/// A settle point: when the foreground is stale, move every process whose state changed. Left
/// stale on the idle thread, which cannot wait for the locks the walk takes.
#[cfg(target_arch = "x86")]
pub fn sync() {
    let threads = &crate::pcr::pcr().threads;
    if threads.current().is_none() || threads.current() == threads.idle() {
        return;
    }
    if PUBLISHED.take_stale() {
        refresh();
    }
}

/// The walk: each live process that has not ended, set in the foreground or the background as
/// [`wanted`] says, where that is not its state already.
#[cfg(target_arch = "x86")]
fn refresh() {
    let gui = PUBLISHED.gui();
    for process in super::pool::listed() {
        let on_console = crate::csr::on_foreground_console(process.object());
        let foreground = wanted(gui, process.object().index, on_console);
        if foreground != process.foreground() {
            process.set_priority_by_class(foreground, None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Professional's default, 2: variable short quanta, the foreground's three times the
    /// background's two ticks.
    #[test]
    fn the_professional_default_stretches_the_foreground_threefold() {
        let table = QuantumTable::new(DEFAULT_PRIORITY_SEPARATION, false);
        assert_eq!(table.separation(), 2);
        assert_eq!(table.quanta(), [6, 12, 18]);
        assert_eq!(table.thread_quantum(true, false), 18);
        assert_eq!(table.thread_quantum(false, false), 6);
    }

    /// The separation picks the foreground's entry: 0 none, 1 twice, 2 and 3 three times.
    #[test]
    fn the_separation_indexes_the_table() {
        let quantum = |raw| QuantumTable::new(raw, false).thread_quantum(true, false);
        assert_eq!(
            [quantum(0), quantum(1), quantum(2), quantum(3)],
            [6, 12, 18, 18]
        );
        // The background takes entry 0 whatever the separation.
        assert_eq!(QuantumTable::new(1, false).thread_quantum(false, false), 6);
    }

    /// The four tables, by their bits, and the defaults of Professional and Server.
    #[test]
    fn the_tables() {
        let quanta = |raw, server| QuantumTable::new(raw, server).quanta();
        assert_eq!(quanta(0x24, false), [6, 12, 18]);
        assert_eq!(quanta(0x14, false), [12, 24, 36]);
        assert_eq!(quanta(0x28, false), [18, 18, 18]);
        assert_eq!(quanta(0x18, false), [36, 36, 36]);
        // Server's defaults: long fixed quanta, nothing stretched.
        assert_eq!(quanta(2, true), [36, 36, 36]);
        // Its zero fields overridden: short variable, as Professional's.
        assert_eq!(quanta(0x26, true), [6, 12, 18]);
        // Win32PrioritySeparation 0x26, "programs" on Server's performance options.
        assert_eq!(
            QuantumTable::new(0x26, true).thread_quantum(true, false),
            18
        );
        // A value of 3 in either two-bit field is no choice: the default.
        assert_eq!(quanta(0x3E, false), [6, 12, 18]);
    }

    /// A process of the idle priority class keeps the base quantum, foreground or not.
    #[test]
    fn the_idle_class_is_never_stretched() {
        let table = QuantumTable::new(DEFAULT_PRIORITY_SEPARATION, false);
        assert_eq!(table.thread_quantum(true, true), 6);
        assert_eq!(table.thread_quantum(false, true), 6);
        assert_eq!(thread_quantum(true, IDLE_PRIORITY_CLASS), 6);
        assert_eq!(
            thread_quantum(true, crate::process::NORMAL_PRIORITY_CLASS),
            18
        );
    }

    /// The window manager's foreground process is the one foreground process while there is one;
    /// otherwise the foreground console's processes are.
    #[test]
    fn the_foreground_follows_the_keyboard() {
        assert!(wanted(Some(4), 4, false));
        assert!(!wanted(Some(4), 5, true));
        assert!(wanted(None, 5, true));
        assert!(!wanted(None, 5, false));
    }

    /// A change of the published foreground process marks the foreground stale; the same one
    /// again does not.
    #[test]
    fn publishing_a_change_marks_the_foreground_stale() {
        let published = Published::new();
        published.publish_gui(Some(7));
        assert!(published.take_stale());
        published.publish_gui(Some(7));
        assert!(!published.take_stale());
        assert_eq!(published.gui(), Some(7));
        published.publish_gui(None);
        assert!(published.take_stale());
        assert_eq!(published.gui(), None);
        published.mark_stale();
        assert!(published.take_stale());
    }
}
