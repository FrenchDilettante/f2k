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
//! 3). Today they only document the subsystem's class: every subsystem starts at every boot.

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

/// When a subsystem starts, after Windows 2000's driver and service start types. Every subsystem
/// starts at every boot today; the types are the classes the boot-time selection (`subsys=`) and
/// the lazy start will act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartType {
    /// SERVICE_BOOT_START (0): the kernel's core, in every boot (the base profile).
    Boot,
    /// SERVICE_SYSTEM_START (1): a hardware driver the kernel starts at its Phase 1
    /// (IoInitSystem's drivers): the buses and devices a boot can do without.
    System,
    /// SERVICE_AUTO_START (2): the session's pieces Windows 2000's session manager starts (win32k
    /// and its window station, the fonts).
    Auto,
    /// SERVICE_DEMAND_START (3): started at its first use. None yet.
    #[cfg_attr(not(test), allow(dead_code))] // The lazy start's.
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
/// are called from where they are today; the descriptors only name their owners.
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
    #[cfg_attr(not(test), allow(dead_code))] // The boot-time selection's.
    pub start: StartType,
    /// The boot phase it starts in.
    pub phase: Phase,
    /// The subsystems it needs started before its own start, and while it runs.
    pub depends: &'static [Subsystem],
    /// The teardown hooks it owns.
    #[cfg_attr(not(test), allow(dead_code))] // The lazy start's.
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
        T::Auto,
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
        T::Auto,
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
#[cfg_attr(not(test), allow(dead_code))] // The boot-time selection's.
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

/// The started flags: which subsystems have started, and which are starting.
pub struct State {
    /// The started subsystems' bits.
    started: AtomicU32,
    /// The bits of the subsystems whose start is under way (their dependencies' or their own).
    starting: AtomicU32,
}

impl State {
    /// No subsystem started.
    pub const fn new() -> Self {
        Self {
            started: AtomicU32::new(0),
            starting: AtomicU32::new(0),
        }
    }

    /// Whether `id` has started.
    pub fn started(&self, id: Subsystem) -> bool {
        self.started.load(Ordering::Acquire) & id.bit() != 0
    }

    /// The started subsystems' set.
    #[cfg_attr(not(test), allow(dead_code))] // The boot's report of what it used.
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
}

/// The kernel's started flags.
pub static STATE: State = State::new();

/// Whether the kernel has started `id`.
pub fn started(id: Subsystem) -> bool {
    STATE.started(id)
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
