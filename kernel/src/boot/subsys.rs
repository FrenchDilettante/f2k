//! The subsystem table: each kernel subsystem the boot starts, as a descriptor (its name, its start
//! type, its boot phase, the subsystems it depends on, and the teardown hooks it owns), and the
//! started flags the rest of the kernel can ask.
//!
//! `kmain` starts the table's subsystems in its order ([`State::start`] each), phase by phase, the
//! diagnostic boots at the phases' ends (`boot::start_subsystems`). The table is listed in the
//! boot's order, and the build checks that the order is a dependency order ([`check`], at compile
//! time): every dependency is in the table, the dependencies have no cycle, a subsystem comes after
//! everything it depends on, and the phases do not go back. The subsystem's start itself, the
//! descriptor's init, is `boot::init`'s arm for it (the target's code, which the host tests do not
//! build).
//!
//! The start types mirror Windows 2000's driver and service start types (the registry's `Start`
//! value: SERVICE_BOOT_START 0, SERVICE_SYSTEM_START 1, SERVICE_AUTO_START 2, SERVICE_DEMAND_START
//! 3). Every Boot row starts at every boot (the base profile). The others are the boot's selection
//! when the kernel command line's `subsys=` names them or a row that depends on them ([`parse`],
//! [`selection`]), and all of them without a `subsys=`; a row the selection leaves out stands as
//! a SERVICE_DISABLED service does, never started. A selected System or Auto row starts at the
//! boot; a selected Demand row at its first use ([`State::start_on_demand`]: win32k's window
//! station and fonts at the first win32k service, `user::syscall`), or never. A call into a
//! subsystem the boot left out fails loudly, never quietly differently: a kernel-internal reach
//! panics ([`require`]); a program's win32k service is refused with STATUS_INVALID_SYSTEM_SERVICE
//! and a COM1 line (`user::syscall`).

use core::sync::atomic::{AtomicU32, Ordering};

/// A kernel subsystem the boot starts. Its value is its bit in the started flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Subsystem {
    /// COM1, the serial line the boot reports on (and the POST code before it).
    Com1,
    /// The CPU tables (GDT, IDT, TSS) and the floating-point unit.
    Cpu,
    /// The loader's hand-off, the frame database and the kernel's own page tables.
    Memory,
    /// The console server's text screen (the in-kernel csrss).
    Console,
    /// The configuration manager: the registry in kernel memory.
    Registry,
    /// The scheduler's quantum table, from the registry's priority separation (PspInitPhase0).
    Quantum,
    /// The I/O manager for the drivers NtLoadDriver loads, and PsInitialSystemProcess.
    Io,
    /// The interrupt core: the interrupt controllers, the interval timer and clock, the wall
    /// clock, the shared data page.
    Interrupts,
    /// The scheduler's resting state: the dispatcher and the idle thread.
    Scheduler,
    /// win32k's interactive window station, WinSta0, its Default desktop and its windows.
    WinSta,
    /// The PCI bus scan.
    Pci,
    /// The device tree: the PCI functions as nodes, their interrupt pins routed.
    DevTree,
    /// The RAM disk over the boot loader's disk module.
    RamDisk,
    /// The IDE disk (primary master).
    Ide,
    /// The PS/2 keyboard.
    Keyboard,
    /// The block device registry: the disks and their partitions.
    Block,
    /// The boot volume, mounted as FAT32.
    BootVolume,
    /// The paging file on the boot volume, and the commit limit it sets.
    PagingFile,
    /// win32k's boot fonts, from the boot volume.
    Fonts,
    /// ntdll's pages, which every process maps.
    SystemDlls,
}

impl Subsystem {
    /// How many subsystems there are.
    pub const COUNT: usize = Subsystem::SystemDlls as usize + 1;

    /// The subsystem's bit in a set of subsystems.
    pub const fn bit(self) -> u32 {
        1 << self as u32
    }
}

// A set of subsystems is a `u32`.
const _: () = assert!(Subsystem::COUNT <= 32);

/// When a subsystem starts, after Windows 2000's driver and service start types: a Boot row at
/// every boot; a System or Auto row at the boot when the boot-time selection (`subsys=`, or none:
/// every row) holds it; a Demand row at its first use when the selection holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartType {
    /// SERVICE_BOOT_START (0): the kernel's core, in every boot (the base profile).
    Boot,
    /// SERVICE_SYSTEM_START (1): a hardware driver the kernel starts at its Phase 1
    /// (IoInitSystem's drivers): the buses and devices a boot can do without.
    System,
    /// SERVICE_AUTO_START (2): started at the boot when selected, though the boot's own work does
    /// not need it. None now: the session's pieces (win32k's window station, the fonts) were
    /// these until they became Demand rows.
    #[allow(dead_code)] // A row's start type, should one be Auto again.
    Auto,
    /// SERVICE_DEMAND_START (3): started at its first use, when the selection holds it
    /// ([`State::start_on_demand`]): win32k's window station and fonts, at the first win32k
    /// service (Windows 2000's session manager loads win32k and its window station at the
    /// session's start, and the fonts come at logon: F2K, with no session manager, makes them when
    /// a program first needs them). Nothing a Boot, System or Auto row needs is a Demand row
    /// ([`demand_rows_stand_alone`]).
    Demand,
}

/// The boot's phases, in order, as Windows 2000's initialization runs its Phase 0 (the processor,
/// memory, the executive's tables) and its Phase 1 (interrupts, the scheduler, the drivers) before
/// its first process. A phase's diagnostic boot runs once its subsystems are started.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// The processor: COM1, the CPU tables, the floating-point unit.
    Processor,
    /// The loader's hand-off and physical memory.
    Memory,
    /// The executive's tables: the console, the registry, the I/O manager.
    Executive,
    /// Interrupts and the scheduler, then the interactive window station.
    Interrupts,
    /// The devices and the boot volume.
    Devices,
    /// What reads the boot volume (the paging file, the fonts) and the system DLLs.
    Late,
}

impl Phase {
    /// The phases in the boot's order.
    pub const ALL: [Phase; 6] = [
        Phase::Processor,
        Phase::Memory,
        Phase::Executive,
        Phase::Interrupts,
        Phase::Devices,
        Phase::Late,
    ];
}

/// A teardown hook a subsystem owns: a step a process's, a thread's or the system's end takes on
/// the subsystem's state, which a boot that never started the subsystem has no state for. The hooks
/// are called from where they are today; the descriptors only name their owners. Each runs only
/// over what started: the shutdown's are Boot rows'; the process's and the thread's are the Demand
/// rows' (win32k's), run only for a process connected to win32k, and a connection comes after the
/// win32k start on demand (`user::syscall`), so it implies the start (the hooks assert it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Teardown {
    /// A process's end (`process::release_process`'s win32k steps: GDI objects, windows and
    /// classes, queues, private fonts).
    ProcessEnd,
    /// A thread's end (`process::threads`: the thread's win32k queue).
    ThreadEnd,
    /// The shutdown's close of the boot volume to changes and its flush (`nt::shutdown`).
    VolumeFlush,
    /// The shutdown's flush of the boot volume's disk's write cache (`nt::shutdown`).
    DiskCacheFlush,
    /// The shutdown's flush of the registry's hives (`nt::shutdown`).
    RegistryFlush,
}

impl Teardown {
    /// Every hook.
    #[cfg_attr(not(test), allow(dead_code))] // The host tests'.
    pub const ALL: [Teardown; 5] = [
        Teardown::ProcessEnd,
        Teardown::ThreadEnd,
        Teardown::VolumeFlush,
        Teardown::DiskCacheFlush,
        Teardown::RegistryFlush,
    ];
}

/// A subsystem's descriptor: its row of the table.
#[derive(Clone, Copy, Debug)]
pub struct Descriptor {
    /// The subsystem.
    pub id: Subsystem,
    /// Its name, as the kernel command line and the boot's report name it.
    pub name: &'static str,
    /// Its start type.
    pub start: StartType,
    /// The boot phase it starts in.
    pub phase: Phase,
    /// The subsystems it needs started before its own start, and while it runs.
    pub depends: &'static [Subsystem],
    /// The teardown hooks it owns.
    #[cfg_attr(not(test), allow(dead_code))] // The host tests'.
    pub teardown: &'static [Teardown],
}

/// A descriptor, briefly.
const fn subsystem(
    id: Subsystem,
    name: &'static str,
    start: StartType,
    phase: Phase,
    depends: &'static [Subsystem],
    teardown: &'static [Teardown],
) -> Descriptor {
    Descriptor {
        id,
        name,
        start,
        phase,
        depends,
        teardown,
    }
}

use Phase as P;
use StartType as T;
use Subsystem as S;

/// The kernel's subsystems, in the boot's order.
pub static SUBSYSTEMS: [Descriptor; Subsystem::COUNT] = TABLE;

/// [`SUBSYSTEMS`] as a constant, for the build's check.
const TABLE: [Descriptor; Subsystem::COUNT] = [
    subsystem(S::Com1, "com1", T::Boot, P::Processor, &[], &[]),
    // The CPU tables' report goes to COM1.
    subsystem(S::Cpu, "cpu", T::Boot, P::Processor, &[S::Com1], &[]),
    // The page tables' rebuild runs with the CPU tables' fault reports in place.
    subsystem(S::Memory, "memory", T::Boot, P::Memory, &[S::Cpu], &[]),
    // The text screen, through the kernel window the memory's page tables map.
    subsystem(
        S::Console,
        "console",
        T::Boot,
        P::Executive,
        &[S::Memory],
        &[],
    ),
    // Its chunks come from the nonpaged pool.
    subsystem(
        S::Registry,
        "registry",
        T::Boot,
        P::Executive,
        &[S::Memory],
        &[Teardown::RegistryFlush],
    ),
    // Reads the registry's priority separation.
    subsystem(
        S::Quantum,
        "quantum",
        T::Boot,
        P::Executive,
        &[S::Registry],
        &[],
    ),
    // Its arena comes from the nonpaged pool.
    subsystem(S::Io, "io", T::Boot, P::Executive, &[S::Memory], &[]),
    // The IDT's hardware vectors; the shared data page.
    subsystem(
        S::Interrupts,
        "interrupts",
        T::Boot,
        P::Interrupts,
        &[S::Cpu, S::Memory],
        &[],
    ),
    // The idle thread's install raises to the dispatch level, which enables interrupts.
    subsystem(
        S::Scheduler,
        "scheduler",
        T::Boot,
        P::Interrupts,
        &[S::Interrupts],
        &[],
    ),
    // Made under the object directory's lock, whose raise enables interrupts.
    subsystem(
        S::WinSta,
        "winsta",
        T::Demand,
        P::Interrupts,
        &[S::Interrupts],
        &[Teardown::ProcessEnd, Teardown::ThreadEnd],
    ),
    subsystem(S::Pci, "pci", T::System, P::Devices, &[S::Memory], &[]),
    // The scan's functions.
    subsystem(S::DevTree, "devtree", T::System, P::Devices, &[S::Pci], &[]),
    // Over the frames the boot memory plan withheld.
    subsystem(
        S::RamDisk,
        "ramdisk",
        T::Boot,
        P::Devices,
        &[S::Memory],
        &[],
    ),
    // Its reads complete through IRQ 14 and wait on an event; its bus master is a PCI function.
    subsystem(
        S::Ide,
        "ide",
        T::System,
        P::Devices,
        &[S::Interrupts, S::Scheduler, S::Pci],
        &[],
    ),
    // IRQ 1; its bring-up waits read the tick; its bytes go to the console's input.
    subsystem(
        S::Keyboard,
        "keyboard",
        T::System,
        P::Devices,
        &[S::Interrupts, S::Console],
        &[],
    ),
    // The RAM disk's partitions (and the IDE disk's, when it is started: it comes first in the
    // table, being optional here).
    subsystem(
        S::Block,
        "block",
        T::Boot,
        P::Devices,
        &[S::RamDisk],
        &[Teardown::DiskCacheFlush],
    ),
    subsystem(
        S::BootVolume,
        "bootvol",
        T::Boot,
        P::Devices,
        &[S::Block],
        &[Teardown::VolumeFlush],
    ),
    // Windows 2000's session manager creates it (MmCreatePagingFile); in the base profile all the
    // same, its commit limit being visible to every program.
    subsystem(
        S::PagingFile,
        "pagingfile",
        T::Boot,
        P::Late,
        &[S::BootVolume],
        &[],
    ),
    subsystem(
        S::Fonts,
        "fonts",
        T::Demand,
        P::Late,
        &[S::BootVolume],
        &[Teardown::ProcessEnd],
    ),
    // Staged from the embedded file into frames of the kernel's.
    subsystem(S::SystemDlls, "ntdll", T::Boot, P::Late, &[S::Memory], &[]),
];

// The build refuses a table that is no dependency order of the whole kernel.
const _: () = match check(&TABLE) {
    Ok(()) => assert!(
        TABLE.len() == Subsystem::COUNT,
        "every subsystem has a descriptor"
    ),
    Err(TableError::Duplicate(_)) => panic!("subsystem table: a subsystem listed twice"),
    Err(TableError::MissingDependency { .. }) => {
        panic!("subsystem table: a dependency not in the table")
    }
    Err(TableError::Cycle(_)) => panic!("subsystem table: a dependency cycle"),
    Err(TableError::OutOfOrder { .. }) => {
        panic!("subsystem table: a subsystem listed before a dependency")
    }
    Err(TableError::PhaseOrder(_)) => panic!("subsystem table: a phase goes back"),
};

/// What makes a table no dependency order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    /// The subsystem has two descriptors.
    Duplicate(Subsystem),
    /// The subsystem depends on one the table does not list.
    MissingDependency {
        subsystem: Subsystem,
        dependency: Subsystem,
    },
    /// The subsystem's dependencies lead back to it (the first of the cycle's subsystems, or of
    /// those that depend on one, in the table's order).
    Cycle(Subsystem),
    /// The subsystem is listed before one it depends on.
    OutOfOrder {
        subsystem: Subsystem,
        dependency: Subsystem,
    },
    /// The subsystem's phase is earlier than the one listed before it.
    PhaseOrder(Subsystem),
}

/// The set of a table's subsystems.
pub const fn listed(table: &[Descriptor]) -> u32 {
    let mut set = 0;
    let mut i = 0;
    while i < table.len() {
        set |= table[i].id.bit();
        i += 1;
    }
    set
}

/// The set of a descriptor's dependencies.
const fn dependencies(descriptor: &Descriptor) -> u32 {
    let mut set = 0;
    let mut i = 0;
    while i < descriptor.depends.len() {
        set |= descriptor.depends[i].bit();
        i += 1;
    }
    set
}

/// Check that `table` is a dependency order: no subsystem twice, every dependency listed, no
/// cycle, every subsystem after its dependencies, and the phases in order. A `const fn`: the build
/// checks [`SUBSYSTEMS`] with it.
pub const fn check(table: &[Descriptor]) -> Result<(), TableError> {
    // No subsystem twice.
    let mut i = 0;
    while i < table.len() {
        let mut j = 0;
        while j < i {
            if table[j].id as u8 == table[i].id as u8 {
                return Err(TableError::Duplicate(table[i].id));
            }
            j += 1;
        }
        i += 1;
    }
    // Every dependency listed.
    let present = listed(table);
    let mut i = 0;
    while i < table.len() {
        let mut d = 0;
        while d < table[i].depends.len() {
            let dependency = table[i].depends[d];
            if present & dependency.bit() == 0 {
                return Err(TableError::MissingDependency {
                    subsystem: table[i].id,
                    dependency,
                });
            }
            d += 1;
        }
        i += 1;
    }
    // No cycle: a topological sort (Kahn's), each round placing the first subsystem in the table
    // whose dependencies are all placed; a round that places none leaves the cycles and what
    // depends on them.
    let mut placed = 0u32;
    let mut count = 0;
    while count < table.len() {
        let mut found = false;
        let mut i = 0;
        while i < table.len() {
            let id = table[i].id;
            if placed & id.bit() == 0 && dependencies(&table[i]) & !placed == 0 {
                placed |= id.bit();
                found = true;
                break;
            }
            i += 1;
        }
        if !found {
            let mut i = 0;
            while placed & table[i].id.bit() != 0 {
                i += 1;
            }
            return Err(TableError::Cycle(table[i].id));
        }
        count += 1;
    }
    // Every subsystem after its dependencies, and the phases in order.
    let mut before = 0u32;
    let mut i = 0;
    while i < table.len() {
        let mut d = 0;
        while d < table[i].depends.len() {
            let dependency = table[i].depends[d];
            if before & dependency.bit() == 0 {
                return Err(TableError::OutOfOrder {
                    subsystem: table[i].id,
                    dependency,
                });
            }
            d += 1;
        }
        if i > 0 && (table[i].phase as u8) < (table[i - 1].phase as u8) {
            return Err(TableError::PhaseOrder(table[i].id));
        }
        before |= table[i].id.bit();
        i += 1;
    }
    Ok(())
}

/// The descriptor of `id` in `table`.
pub fn descriptor(table: &[Descriptor], id: Subsystem) -> Option<&Descriptor> {
    table.iter().find(|descriptor| descriptor.id == id)
}

/// The subsystems `selected` needs: the set and every subsystem it depends on, transitively (the
/// set a boot-time selection starts). Over a checked table.
pub fn closure(table: &[Descriptor], selected: u32) -> u32 {
    let mut set = selected;
    // A checked table lists every dependency before its dependents: one backward pass closes it.
    for descriptor in table.iter().rev() {
        if set & descriptor.id.bit() != 0 {
            set |= dependencies(descriptor);
        }
    }
    set
}

/// The subsystems of `set`, in the order a boot starts them (the table's).
#[cfg_attr(not(test), allow(dead_code))] // The boot-time selection's.
pub fn start_order(table: &[Descriptor], set: u32) -> impl Iterator<Item = Subsystem> + '_ {
    table
        .iter()
        .map(|descriptor| descriptor.id)
        .filter(move |id| set & id.bit() != 0)
}

/// The started flags: which subsystems the boot selected, which have started, and which are
/// starting.
pub struct State {
    /// The selected subsystems' bits: those the boot may start, at the boot or on demand.
    selected: AtomicU32,
    /// The started subsystems' bits.
    started: AtomicU32,
    /// The bits of the subsystems whose start is under way (their dependencies' or their own).
    starting: AtomicU32,
}

impl State {
    /// No subsystem selected or started.
    pub const fn new() -> Self {
        Self {
            selected: AtomicU32::new(0),
            started: AtomicU32::new(0),
            starting: AtomicU32::new(0),
        }
    }

    /// Record the boot's selection: the subsystems it may start ([`selection`], or every row).
    pub fn select(&self, set: u32) {
        self.selected.store(set, Ordering::Release);
    }

    /// The selected subsystems' set.
    pub fn selected_set(&self) -> u32 {
        self.selected.load(Ordering::Acquire)
    }

    /// Whether `id` has started.
    pub fn started(&self, id: Subsystem) -> bool {
        self.started.load(Ordering::Acquire) & id.bit() != 0
    }

    /// The started subsystems' set.
    pub fn started_set(&self) -> u32 {
        self.started.load(Ordering::Acquire)
    }

    /// Start `id`, once: its dependencies first (each once, in the same way), then its own start,
    /// `init(id)`. A subsystem already started is left as it is, so a start is idempotent.
    ///
    /// # Panics
    ///
    /// `id`, or one of its dependencies, has no descriptor in `table`, or a start re-enters a
    /// subsystem whose start is under way (a dependency cycle: [`check`] refuses those tables).
    pub fn start(&self, table: &[Descriptor], id: Subsystem, init: &mut dyn FnMut(Subsystem)) {
        if self.started(id) {
            return;
        }
        let descriptor =
            descriptor(table, id).unwrap_or_else(|| panic!("subsystem {id:?} has no descriptor"));
        let previous = self.starting.fetch_or(id.bit(), Ordering::AcqRel);
        assert!(
            previous & id.bit() == 0,
            "subsystem {}: its start re-entered (a dependency cycle)",
            descriptor.name
        );
        for &dependency in descriptor.depends {
            self.start(table, dependency, init);
        }
        init(id);
        self.started.fetch_or(id.bit(), Ordering::AcqRel);
        self.starting.fetch_and(!id.bit(), Ordering::AcqRel);
    }

    /// Start the subsystems of `needs` that have not started, at their first use: each, and what
    /// it depends on, once ([`State::start`]), in the table's order. Returns the set this call
    /// started (none when `needs` had all started); or, starting nothing, `needs`' subsystems the
    /// boot did not select, which never start.
    ///
    /// Not safe against a concurrent caller on its own: two threads making their first use at
    /// once would both run a start (or the second would find it under way and panic). The
    /// kernel's callers hold one lock across it (`boot::start_on_demand`); the check of the
    /// started flags before the lock is the fast path, and is repeated here, under it.
    pub fn start_on_demand(
        &self,
        table: &[Descriptor],
        needs: u32,
        init: &mut dyn FnMut(Subsystem),
    ) -> Result<u32, u32> {
        let left_out = needs & !self.selected_set();
        if left_out != 0 {
            return Err(left_out);
        }
        let before = self.started_set();
        for id in start_order(table, needs & !before) {
            self.start(table, id, init);
        }
        Ok(self.started_set() & !before)
    }
}

/// The kernel's started flags.
pub static STATE: State = State::new();

/// Whether the kernel has started `id`.
pub fn started(id: Subsystem) -> bool {
    STATE.started(id)
}

/// The rows of `table` whose start type is `start`.
fn rows_of(table: &[Descriptor], start: StartType) -> u32 {
    table
        .iter()
        .filter(|descriptor| descriptor.start == start)
        .fold(0, |set, descriptor| set | descriptor.id.bit())
}

/// The base profile: the Boot rows of `table`, which every boot starts.
pub fn boot_rows(table: &[Descriptor]) -> u32 {
    rows_of(table, StartType::Boot)
}

/// The Demand rows of `table`: started at their first use, never by the boot itself.
pub fn demand_rows(table: &[Descriptor]) -> u32 {
    rows_of(table, StartType::Demand)
}

/// The subsystems the boot itself starts of its `selected` ones: all but the Demand rows, which
/// wait for their first use.
pub fn boot_starts(table: &[Descriptor], selected: u32) -> u32 {
    selected & !demand_rows(table)
}

/// Whether no row the boot starts depends on a Demand row (a Demand row some other row needs would
/// start with it, at the boot, and its first use would come too late to matter). Over a checked
/// table.
#[cfg_attr(not(test), allow(dead_code))] // The host tests'.
pub fn demand_rows_stand_alone(table: &[Descriptor]) -> bool {
    let demand = demand_rows(table);
    table
        .iter()
        .filter(|descriptor| descriptor.start != StartType::Demand)
        .all(|descriptor| dependencies(descriptor) & demand == 0)
}

/// The names `subsys=` takes beside the rows' own: `gui`, win32k's whole (its window station and
/// its fonts, the two its services need: `user::syscall`'s gate).
pub const ALIASES: [(&str, u32); 1] = [("gui", Subsystem::WinSta.bit() | Subsystem::Fonts.bit())];

/// The subsystems a `subsys=` value names: its comma-separated words, each a row's `name` in
/// `table` or an [`ALIASES`] name (an empty word, as in `subsys=` alone, names nothing). The first
/// word that names nothing is the error.
pub fn parse<'a>(table: &[Descriptor], value: &'a [u8]) -> Result<u32, &'a [u8]> {
    let mut set = 0;
    for word in value
        .split(|&byte| byte == b',')
        .filter(|word| !word.is_empty())
    {
        let row = table
            .iter()
            .find(|descriptor| descriptor.name.as_bytes() == word)
            .map(|descriptor| descriptor.id.bit());
        let alias = || {
            ALIASES
                .iter()
                .find(|(name, _)| name.as_bytes() == word)
                .map(|&(_, set)| set)
        };
        set |= row.or_else(alias).ok_or(word)?;
    }
    Ok(set)
}

/// The set a boot starts for the `named` subsystems: every Boot row, the named, and everything
/// they depend on ([`closure`]).
pub fn selection(table: &[Descriptor], named: u32) -> u32 {
    closure(table, boot_rows(table) | named)
}

/// The names of `set`'s subsystems, in the table's order.
pub fn names(table: &[Descriptor], set: u32) -> impl Iterator<Item = &'static str> + '_ {
    table
        .iter()
        .filter(move |descriptor| set & descriptor.id.bit() != 0)
        .map(|descriptor| descriptor.name)
}

/// A set's names, comma-separated, in the table's order (the boot's report).
pub struct Names<'a>(pub &'a [Descriptor], pub u32);

impl core::fmt::Display for Names<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, name) in names(self.0, self.1).enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

/// Check that the boot started `id` before `site` reaches into it: a kernel-internal reach into a
/// subsystem the boot left out (the command line's `subsys=`) is a kernel bug, never a quiet
/// difference, so it stops the kernel as Windows 2000's bug checks do.
///
/// # Panics
///
/// `id` has not started.
#[track_caller]
pub fn require(id: Subsystem, site: &str) {
    if !started(id) {
        not_started(id, site);
    }
}

#[cold]
#[track_caller]
fn not_started(id: Subsystem, site: &str) -> ! {
    let name = descriptor(&SUBSYSTEMS, id).map_or("?", |descriptor| descriptor.name);
    panic!(
        "SUBSYSTEM_NOT_STARTED: {site} needs subsystem {name}, which this boot's subsys= left out"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(id: Subsystem, phase: Phase, depends: &'static [Subsystem]) -> Descriptor {
        subsystem(id, "test", StartType::Boot, phase, depends, &[])
    }

    #[test]
    fn the_kernel_table_is_a_dependency_order() {
        assert_eq!(check(&SUBSYSTEMS), Ok(()));
        assert_eq!(SUBSYSTEMS.len(), Subsystem::COUNT);
        assert_eq!(listed(&SUBSYSTEMS), (1 << Subsystem::COUNT) - 1);
    }

    #[test]
    fn the_kernel_table_keeps_the_boot_order() {
        let order: Vec<Subsystem> = start_order(&SUBSYSTEMS, u32::MAX).collect();
        assert_eq!(
            order,
            [
                S::Com1,
                S::Cpu,
                S::Memory,
                S::Console,
                S::Registry,
                S::Quantum,
                S::Io,
                S::Interrupts,
                S::Scheduler,
                S::WinSta,
                S::Pci,
                S::DevTree,
                S::RamDisk,
                S::Ide,
                S::Keyboard,
                S::Block,
                S::BootVolume,
                S::PagingFile,
                S::Fonts,
                S::SystemDlls,
            ]
        );
    }

    #[test]
    fn names_are_unique_and_every_teardown_has_an_owner() {
        for (i, a) in SUBSYSTEMS.iter().enumerate() {
            assert!(!a.name.is_empty());
            for b in &SUBSYSTEMS[..i] {
                assert_ne!(a.name, b.name);
            }
        }
        for hook in Teardown::ALL {
            assert!(
                SUBSYSTEMS.iter().any(|d| d.teardown.contains(&hook)),
                "{hook:?} has no owner"
            );
        }
    }

    #[test]
    fn a_cycle_is_refused() {
        let table = [
            d(S::Com1, P::Processor, &[]),
            d(S::Cpu, P::Processor, &[S::Memory]),
            d(S::Memory, P::Memory, &[S::Cpu]),
            d(S::Console, P::Executive, &[S::Memory]),
        ];
        assert_eq!(check(&table), Err(TableError::Cycle(S::Cpu)));
        // A subsystem depending on itself is the shortest cycle.
        let table = [d(S::Com1, P::Processor, &[S::Com1])];
        assert_eq!(check(&table), Err(TableError::Cycle(S::Com1)));
    }

    #[test]
    fn a_missing_dependency_is_refused() {
        let table = [
            d(S::Com1, P::Processor, &[]),
            d(S::Ide, P::Devices, &[S::Com1, S::Pci]),
        ];
        assert_eq!(
            check(&table),
            Err(TableError::MissingDependency {
                subsystem: S::Ide,
                dependency: S::Pci,
            })
        );
    }

    #[test]
    fn a_dependency_listed_late_is_refused() {
        let table = [
            d(S::Com1, P::Processor, &[]),
            d(S::Ide, P::Devices, &[S::Pci]),
            d(S::Pci, P::Devices, &[S::Com1]),
        ];
        assert_eq!(
            check(&table),
            Err(TableError::OutOfOrder {
                subsystem: S::Ide,
                dependency: S::Pci,
            })
        );
    }

    #[test]
    fn a_duplicate_and_a_phase_going_back_are_refused() {
        let table = [d(S::Com1, P::Processor, &[]), d(S::Com1, P::Processor, &[])];
        assert_eq!(check(&table), Err(TableError::Duplicate(S::Com1)));
        let table = [d(S::Com1, P::Memory, &[]), d(S::Cpu, P::Processor, &[])];
        assert_eq!(check(&table), Err(TableError::PhaseOrder(S::Cpu)));
    }

    #[test]
    fn a_selection_closes_over_its_dependencies_in_boot_order() {
        let set = closure(&SUBSYSTEMS, S::Ide.bit() | S::Fonts.bit());
        let order: Vec<Subsystem> = start_order(&SUBSYSTEMS, set).collect();
        assert_eq!(
            order,
            [
                S::Com1,
                S::Cpu,
                S::Memory,
                S::Interrupts,
                S::Scheduler,
                S::Pci,
                S::RamDisk,
                S::Ide,
                S::Block,
                S::BootVolume,
                S::Fonts,
            ]
        );
    }

    #[test]
    fn a_start_runs_the_dependencies_first_and_once() {
        let state = State::new();
        let mut started = Vec::new();
        state.start(&SUBSYSTEMS, S::Ide, &mut |id| started.push(id));
        assert_eq!(
            started,
            [
                S::Com1,
                S::Cpu,
                S::Memory,
                S::Interrupts,
                S::Scheduler,
                S::Pci,
                S::Ide
            ]
        );
        assert!(state.started(S::Ide) && state.started(S::Pci));
        assert!(!state.started(S::Keyboard));
        // Started already: nothing runs again.
        started.clear();
        state.start(&SUBSYSTEMS, S::Ide, &mut |id| started.push(id));
        state.start(&SUBSYSTEMS, S::Keyboard, &mut |id| started.push(id));
        assert_eq!(started, [S::Console, S::Keyboard]);
    }

    #[test]
    fn the_whole_table_starts_in_its_order() {
        let state = State::new();
        let mut started = Vec::new();
        for descriptor in &SUBSYSTEMS {
            state.start(&SUBSYSTEMS, descriptor.id, &mut |id| started.push(id));
        }
        let order: Vec<Subsystem> = start_order(&SUBSYSTEMS, u32::MAX).collect();
        assert_eq!(started, order);
        assert_eq!(state.started_set(), listed(&SUBSYSTEMS));
    }

    #[test]
    fn the_base_profile_is_closed_and_starts_before_the_command_line() {
        let base = boot_rows(&SUBSYSTEMS);
        // A Boot row needs only Boot rows: the base profile is a set of its own.
        assert_eq!(closure(&SUBSYSTEMS, base), base);
        assert_eq!(
            names(&SUBSYSTEMS, base).collect::<Vec<_>>(),
            [
                "com1",
                "cpu",
                "memory",
                "console",
                "registry",
                "quantum",
                "io",
                "interrupts",
                "scheduler",
                "ramdisk",
                "block",
                "bootvol",
                "pagingfile",
                "ntdll",
            ]
        );
        // The command line is read in the memory phase: every row up to it is a Boot row, so the
        // selection is known before the first row it can leave out.
        for descriptor in SUBSYSTEMS.iter().filter(|d| d.phase <= Phase::Memory) {
            assert_eq!(descriptor.start, StartType::Boot, "{}", descriptor.name);
        }
    }

    #[test]
    fn a_subsys_value_names_rows_and_aliases() {
        assert_eq!(parse(&SUBSYSTEMS, b""), Ok(0));
        assert_eq!(parse(&SUBSYSTEMS, b","), Ok(0));
        assert_eq!(parse(&SUBSYSTEMS, b"ide"), Ok(S::Ide.bit()));
        assert_eq!(
            parse(&SUBSYSTEMS, b"keyboard,,fonts,"),
            Ok(S::Keyboard.bit() | S::Fonts.bit())
        );
        assert_eq!(
            parse(&SUBSYSTEMS, b"gui"),
            Ok(S::WinSta.bit() | S::Fonts.bit())
        );
        // Names are the rows' own, exactly: no case folding, no prefix.
        assert_eq!(parse(&SUBSYSTEMS, b"pci,IDE"), Err(&b"IDE"[..]));
        assert_eq!(parse(&SUBSYSTEMS, b"win"), Err(&b"win"[..]));
        assert_eq!(parse(&SUBSYSTEMS, b"ide pci"), Err(&b"ide pci"[..]));
        // Every row's name parses to the row.
        for descriptor in &SUBSYSTEMS {
            assert_eq!(
                parse(&SUBSYSTEMS, descriptor.name.as_bytes()),
                Ok(descriptor.id.bit())
            );
        }
    }

    #[test]
    fn a_selection_adds_the_base_profile_and_the_dependencies() {
        let base = boot_rows(&SUBSYSTEMS);
        assert_eq!(selection(&SUBSYSTEMS, 0), base);
        assert_eq!(selection(&SUBSYSTEMS, S::Com1.bit()), base);
        // ide pulls in pci, not devtree or the keyboard.
        assert_eq!(
            selection(&SUBSYSTEMS, S::Ide.bit()),
            base | S::Ide.bit() | S::Pci.bit()
        );
        assert_eq!(
            selection(&SUBSYSTEMS, S::DevTree.bit()),
            base | S::DevTree.bit() | S::Pci.bit()
        );
        // The owner's choices: fonts need only the boot volume, not the window station.
        assert_eq!(
            selection(&SUBSYSTEMS, S::Fonts.bit()),
            base | S::Fonts.bit()
        );
        assert_eq!(
            selection(&SUBSYSTEMS, S::WinSta.bit()),
            base | S::WinSta.bit()
        );
        // Everything named: the whole table, as a boot without subsys= starts.
        assert_eq!(
            selection(&SUBSYSTEMS, listed(&SUBSYSTEMS)),
            listed(&SUBSYSTEMS)
        );
        let all = parse(&SUBSYSTEMS, b"winsta,pci,devtree,ide,keyboard,fonts").unwrap();
        assert_eq!(selection(&SUBSYSTEMS, all), listed(&SUBSYSTEMS));
    }

    #[test]
    fn a_set_is_reported_by_its_names() {
        let set = S::Com1.bit() | S::Ide.bit() | S::Cpu.bit();
        assert_eq!(Names(&SUBSYSTEMS, set).to_string(), "com1,cpu,ide");
        assert_eq!(Names(&SUBSYSTEMS, 0).to_string(), "");
    }

    #[test]
    fn the_session_pieces_start_on_demand_and_nothing_at_boot_needs_them() {
        assert_eq!(demand_rows(&SUBSYSTEMS), S::WinSta.bit() | S::Fonts.bit());
        assert!(demand_rows_stand_alone(&SUBSYSTEMS));
        // win32k's alias names exactly the Demand rows.
        assert_eq!(parse(&SUBSYSTEMS, b"gui"), Ok(demand_rows(&SUBSYSTEMS)));
        // A Boot row needing a Demand row would start it at the boot.
        let table = [
            subsystem(S::Com1, "a", StartType::Demand, P::Processor, &[], &[]),
            d(S::Cpu, P::Processor, &[S::Com1]),
        ];
        assert_eq!(check(&table), Ok(()));
        assert!(!demand_rows_stand_alone(&table));
        // The hooks a boot may reach before the Demand rows start are none of theirs: theirs are
        // the win32k connection's, which comes after the start.
        for descriptor in &SUBSYSTEMS {
            let win32k_hooks = descriptor
                .teardown
                .iter()
                .any(|hook| matches!(hook, Teardown::ProcessEnd | Teardown::ThreadEnd));
            assert_eq!(
                win32k_hooks,
                descriptor.start == StartType::Demand,
                "{}",
                descriptor.name
            );
        }
    }

    #[test]
    fn the_boot_starts_its_selection_but_the_demand_rows() {
        let all = listed(&SUBSYSTEMS);
        let demand = S::WinSta.bit() | S::Fonts.bit();
        // No subsys=: every row selected, all but win32k's started by the boot.
        assert_eq!(boot_starts(&SUBSYSTEMS, all), all & !demand);
        // subsys=gui: the base profile at the boot, win32k's two selected for later.
        let gui = selection(&SUBSYSTEMS, parse(&SUBSYSTEMS, b"gui").unwrap());
        assert_eq!(gui, boot_rows(&SUBSYSTEMS) | demand);
        assert_eq!(boot_starts(&SUBSYSTEMS, gui), boot_rows(&SUBSYSTEMS));
        // subsys= and subsys=ide: as before, nothing on demand.
        let base = selection(&SUBSYSTEMS, 0);
        assert_eq!(boot_starts(&SUBSYSTEMS, base), base);
        let ide = selection(&SUBSYSTEMS, S::Ide.bit());
        assert_eq!(boot_starts(&SUBSYSTEMS, ide), ide);
    }

    /// The boot's half and the first use's, as the kernel runs them: the boot's rows started in
    /// the table's order, then the Demand rows when asked.
    fn boot(state: &State, selected: u32) {
        state.select(selected);
        for id in start_order(&SUBSYSTEMS, boot_starts(&SUBSYSTEMS, selected)) {
            state.start(&SUBSYSTEMS, id, &mut |_| {});
        }
    }

    #[test]
    fn a_demand_start_runs_once_at_the_first_use() {
        let state = State::new();
        boot(&state, listed(&SUBSYSTEMS));
        let win32k = S::WinSta.bit() | S::Fonts.bit();
        assert_eq!(state.started_set(), listed(&SUBSYSTEMS) & !win32k);
        let mut started = Vec::new();
        assert_eq!(
            state.start_on_demand(&SUBSYSTEMS, win32k, &mut |id| started.push(id)),
            Ok(win32k)
        );
        // In the table's order, their dependencies (the boot's) not again.
        assert_eq!(started, [S::WinSta, S::Fonts]);
        assert_eq!(state.started_set(), listed(&SUBSYSTEMS));
        // The second use finds them started.
        started.clear();
        assert_eq!(
            state.start_on_demand(&SUBSYSTEMS, win32k, &mut |id| started.push(id)),
            Ok(0)
        );
        assert!(started.is_empty());
    }

    #[test]
    fn a_demand_start_the_selection_left_out_is_refused_whole() {
        // subsys=winsta (the toolhelp fixture's): the fonts were left out, so win32k's services
        // start nothing, the window station neither.
        let state = State::new();
        let selected = selection(&SUBSYSTEMS, S::WinSta.bit());
        boot(&state, selected);
        let win32k = S::WinSta.bit() | S::Fonts.bit();
        let mut started = Vec::new();
        assert_eq!(
            state.start_on_demand(&SUBSYSTEMS, win32k, &mut |id| started.push(id)),
            Err(S::Fonts.bit())
        );
        assert!(started.is_empty());
        assert!(!state.started(S::WinSta));
        // The base profile: both left out.
        let state = State::new();
        boot(&state, selection(&SUBSYSTEMS, 0));
        assert_eq!(
            state.start_on_demand(&SUBSYSTEMS, win32k, &mut |_| {}),
            Err(win32k)
        );
        // Nothing selected for it to need: a use of the boot's own rows starts nothing.
        assert_eq!(
            state.start_on_demand(&SUBSYSTEMS, S::Memory.bit(), &mut |_| panic!()),
            Ok(0)
        );
    }

    #[test]
    fn concurrent_first_uses_under_one_lock_start_each_row_once() {
        // The kernel's rule: the started flags checked first, without the lock (the fast path),
        // then the start under one lock, which re-checks them. Threads racing to their first use
        // start each row once, and every one of them returns only once the rows have started.
        use std::sync::atomic::AtomicUsize;
        use std::sync::{Arc, Barrier, Mutex};
        let state = Arc::new(State::new());
        boot(&state, listed(&SUBSYSTEMS));
        let lock = Arc::new(Mutex::new(()));
        let runs: Arc<[AtomicUsize; Subsystem::COUNT]> =
            Arc::new(core::array::from_fn(|_| AtomicUsize::new(0)));
        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));
        let win32k = S::WinSta.bit() | S::Fonts.bit();
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let (state, lock, runs, barrier) =
                    (state.clone(), lock.clone(), runs.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    if state.started_set() & win32k != win32k {
                        let _held = lock.lock().unwrap();
                        state
                            .start_on_demand(&SUBSYSTEMS, win32k, &mut |id| {
                                runs[id as usize].fetch_add(1, Ordering::SeqCst);
                                // A start that takes a while, as the fonts' disk reads do.
                                std::thread::sleep(std::time::Duration::from_millis(2));
                            })
                            .unwrap();
                    }
                    assert_eq!(state.started_set() & win32k, win32k);
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(runs[S::WinSta as usize].load(Ordering::SeqCst), 1);
        assert_eq!(runs[S::Fonts as usize].load(Ordering::SeqCst), 1);
        assert_eq!(state.started_set(), listed(&SUBSYSTEMS));
    }

    #[test]
    #[should_panic(expected = "SUBSYSTEM_NOT_STARTED: a test needs subsystem pci")]
    fn a_reach_into_a_subsystem_not_started_panics() {
        // The host tests start nothing in the kernel's flags.
        require(S::Pci, "a test");
    }

    #[test]
    #[should_panic(expected = "re-entered")]
    fn a_start_re_entering_a_cycle_panics() {
        // An unchecked table: the start's own guard catches the cycle.
        let table = [
            d(S::Com1, P::Processor, &[S::Cpu]),
            d(S::Cpu, P::Processor, &[S::Com1]),
        ];
        State::new().start(&table, S::Com1, &mut |_| {});
    }

    #[test]
    #[should_panic(expected = "no descriptor")]
    fn a_start_of_an_unlisted_subsystem_panics() {
        let table = [d(S::Com1, P::Processor, &[])];
        State::new().start(&table, S::Cpu, &mut |_| {});
    }
}
