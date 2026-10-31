//! The console's control events: Ctrl+C and Ctrl+Break, delivered to the console's processes as
//! Windows 2000's console delivers them.
//!
//! The console keeps its processes ([`Control`]), as Windows 2000's console keeps each process
//! attached to it: one connects at its start (kernel32's ConnectCtrl, the server's API 27), handing
//! over its CtrlRoutine — kernel32's routine that runs the process's handlers — and the console
//! records it with the process's group (see `Process::process_group`); its end disconnects it. An
//! event names a group: a key's goes to group 0, every process of the console;
//! GenerateConsoleCtrlEvent names one, refused (STATUS_INVALID_PARAMETER) when no process of the
//! console is in it.
//!
//! Events are raised at the server's level — the keyboard's DPC raises a key's, the system service
//! GenerateConsoleCtrlEvent's — and queued there for the console's control thread, which the raise
//! wakes. The control thread delivers each at the passive level, in the order raised: for each of
//! the console's processes in the event's group, a new thread of the process, started at its
//! CtrlRoutine with the event as its argument. That is the thread Windows 2000's csrss makes with
//! RtlCreateUserThread, and the kernel does the same work: it attaches to the process, reserves
//! and commits a stack of the sizes the process's image asks for (its guard page below), puts the
//! argument on it under a null return address, as RtlInitializeContext does, and creates and
//! readies the thread; the CtrlRoutine ends it itself (ExitThread), or ends the process. The
//! thread goes through ntdll's thread initialization first, as every thread does.
//!
//! The control thread is the kernel's first worker thread, the stand-in for csrss's input thread
//! (a system thread of the kernel's own process, see `crate::sched::idle::start_system_thread`):
//! it waits on its work event, a synchronization event the raise sets, and delivers whatever is
//! queued each time it wakes. A DPC cannot make a thread — making one waits for locks, and maps
//! and writes another process's memory — so the keyboard's events wait for it.

use crate::ob::ObjectId;
use crate::status::STATUS_INVALID_PARAMETER;

/// How many processes the console holds: any process can be one of its.
pub const CONSOLE_PROCESSES: usize = crate::process::MAX_PROCESSES;

/// How many raised events wait for the control thread at most (one more is dropped).
const PENDING_EVENTS: usize = 16;

/// One of the console's processes: its object, the group it belongs to, and its CtrlRoutine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleProcess {
    pub process: ObjectId,
    pub group: u32,
    pub routine: u32,
}

/// An event to deliver, and the processes it goes to (each with its CtrlRoutine), as the console
/// held them when the control thread took the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Delivery {
    pub event: u32,
    pub targets: [Option<(ObjectId, u32)>; CONSOLE_PROCESSES],
}

/// The console's side of its control events, at the server's level: its processes, and the
/// events raised and not yet taken by the control thread, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    processes: [Option<ConsoleProcess>; CONSOLE_PROCESSES],
    /// The raised events, each with its group: a ring, `first` the oldest, `count` of them.
    pending: [(u32, u32); PENDING_EVENTS],
    first: usize,
    count: usize,
}

impl Control {
    /// A console with no process and no event.
    pub const fn new() -> Self {
        Control {
            processes: [None; CONSOLE_PROCESSES],
            pending: [(0, 0); PENDING_EVENTS],
            first: 0,
            count: 0,
        }
    }

    /// Connect `process`, of group `group`, its CtrlRoutine `routine`: a connection it made before
    /// is replaced. False when the console has no room for it.
    pub fn connect(&mut self, process: ObjectId, group: u32, routine: u32) -> bool {
        let entry = ConsoleProcess {
            process,
            group,
            routine,
        };
        let slot = match self.slot_of(process) {
            Some(slot) => Some(slot),
            None => self.processes.iter().position(Option::is_none),
        };
        match slot {
            Some(slot) => {
                self.processes[slot] = Some(entry);
                true
            }
            None => false,
        }
    }

    /// Disconnect `process` (its end): no event reaches it from now on. Nothing for a process the
    /// console does not hold.
    pub fn disconnect(&mut self, process: ObjectId) {
        if let Some(slot) = self.slot_of(process) {
            self.processes[slot] = None;
        }
    }

    /// The slot holding `process`'s connection.
    fn slot_of(&self, process: ObjectId) -> Option<usize> {
        self.processes
            .iter()
            .position(|held| held.is_some_and(|held| held.process == process))
    }

    /// The console's processes in `group`, every one for group 0.
    fn in_group(&self, group: u32) -> impl Iterator<Item = ConsoleProcess> + '_ {
        self.processes
            .iter()
            .flatten()
            .copied()
            .filter(move |held| group == 0 || held.group == group)
    }

    /// GenerateConsoleCtrlEvent's work: `event` raised for group `group`; STATUS_INVALID_PARAMETER,
    /// nothing raised, when no process of the console is in the group — a group no process leads
    /// any more, a process's id that leads none, a process of another console.
    pub fn generate(&mut self, event: u32, group: u32) -> Result<(), u32> {
        if self.in_group(group).next().is_none() {
            return Err(STATUS_INVALID_PARAMETER.0);
        }
        self.raise(event, group);
        Ok(())
    }

    /// Queue `event` for group `group`, for the control thread; false, nothing queued, when the
    /// queue is full.
    pub fn raise(&mut self, event: u32, group: u32) -> bool {
        if self.count == PENDING_EVENTS {
            return false;
        }
        self.pending[(self.first + self.count) % PENDING_EVENTS] = (event, group);
        self.count += 1;
        true
    }

    /// Whether events wait for the control thread.
    pub fn has_pending(&self) -> bool {
        self.count != 0
    }

    /// The oldest event waiting, taken, with the processes it goes to now.
    pub fn take(&mut self) -> Option<Delivery> {
        if self.count == 0 {
            return None;
        }
        let (event, group) = self.pending[self.first];
        self.first = (self.first + 1) % PENDING_EVENTS;
        self.count -= 1;
        let mut targets = [None; CONSOLE_PROCESSES];
        for (target, held) in targets.iter_mut().zip(self.in_group(group)) {
            *target = Some((held.process, held.routine));
        }
        Some(Delivery { event, targets })
    }
}

impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use core::cell::UnsafeCell;
    use core::ptr::NonNull;

    use super::Delivery;
    use crate::level::{raised, Dispatch};
    use crate::mem::paging::PAGE_SIZE;
    use crate::nt::call::UserAddr;
    use crate::ob::ObjectId;
    use crate::sched::event::{Event, EventKind, EVENT_WAKE_INCREMENT};
    use crate::sched::wait::{WaitReason, WaitableId};
    use crate::sched::DISPATCHER;
    use crate::status::*;
    use crate::user::args::UserPtr;

    /// The control thread's priority: csrss's console input thread's (THREAD_PRIORITY_HIGHEST in
    /// csrss's high priority class), the top of the variable range.
    const PRIORITY: i8 = 15;

    /// The control thread's work event: a synchronization event, set by each raise, waited on by
    /// the control thread alone. It is named by its address in the dispatcher database
    /// ([`WaitableId::Embedded`]), and reached only through the dispatcher once named.
    struct WorkEvent(UnsafeCell<Event>);

    // SAFETY: one processor. The event is touched directly once, by `init` at boot, before the
    // control thread exists and before anything raises an event; from then on only the
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

    /// Start the control thread: its work event named, then the thread (see
    /// `crate::sched::idle::start_system_thread`). Once, at boot, before the first process.
    pub fn start() {
        {
            let _masked = crate::pcr::pcr().mask_guard();
            // SAFETY: the one direct reach into the event (see the `Sync` impl): nothing waits on
            // it or signals it yet, and interrupts are masked for the reference's life.
            unsafe { (*WORK.0.get()).init() };
        }
        crate::sched::idle::start_system_thread(
            crate::sched::database::CONSOLE_CONTROL_THREAD,
            control_thread,
            PRIORITY,
        );
    }

    /// Wake the control thread: events wait for it.
    pub fn wake(dispatcher: &mut crate::sched::dispatcher::Dispatcher) {
        dispatcher.set_event(WORK.id(), EVENT_WAKE_INCREMENT);
    }

    /// The control thread's routine: wait for work, deliver every event waiting, again. Never
    /// returns.
    extern "C" fn control_thread(_start: u32, _context: u32) -> ! {
        loop {
            crate::sched::wait::wait_current_for(WORK.id(), WaitReason::Executive, None);
            while let Some(delivery) =
                raised::<Dispatch, _>(|dispatch| super::super::SERVER.get(dispatch).ctrl.take())
            {
                deliver(&delivery);
            }
        }
    }

    /// Deliver an event: a thread at the CtrlRoutine of each process it goes to. A process that
    /// ended meanwhile, or cannot take the thread, goes without.
    fn deliver(delivery: &Delivery) {
        for &(process, routine) in delivery.targets.iter().flatten() {
            let _ = start_ctrl_thread(process, routine, delivery.event);
        }
    }

    /// A process's stack sizes, as its image's headers ask (SizeOfStackReserve and
    /// SizeOfStackCommit, read from the image the PEB names, in the live address space) and as
    /// RtlCreateUserThread rounds them (BaseCreateStack's rounding: the commit to pages, the
    /// reservation to the allocation granularity, a commit reaching the reservation taking a
    /// reservation of whole MiBs). The default reservation and one page for an image that cannot
    /// be read.
    fn stack_sizes() -> (u32, u32) {
        const GRANULARITY: u32 = 0x1_0000;
        const MIB: u32 = 0x10_0000;
        let image = || -> Option<(u32, u32)> {
            use core::mem::offset_of;
            let peb =
                crate::user::PEB_PAGE + offset_of!(rtl::peb::Peb<u32>, image_base_address) as u32;
            let base = UserPtr::<u32>::at(peb).read().ok()?;
            let dos = UserPtr::<rtl::image::ImageDosHeader>::at(base)
                .read()
                .ok()?;
            let nt =
                UserPtr::<rtl::image::ImageNtHeaders32>::at(base.wrapping_add(dos.e_lfanew as u32))
                    .read()
                    .ok()?;
            let optional = nt.optional_header;
            Some((
                optional.size_of_stack_reserve,
                optional.size_of_stack_commit,
            ))
        };
        let (reserve, commit) = image().unwrap_or((MIB, PAGE_SIZE));
        let commit = commit.max(PAGE_SIZE).next_multiple_of(PAGE_SIZE);
        let reserve = match reserve {
            0 => MIB,
            size => size.next_multiple_of(GRANULARITY),
        };
        if commit >= reserve {
            (commit.next_multiple_of(MIB), commit)
        } else {
            (reserve, commit)
        }
    }

    /// The new thread's stack in `process`, the live address space: reserved, its top committed
    /// and a guard page below that (when the reservation has room for one), the CtrlRoutine's
    /// argument at its top under a null return address. The stack, and the stack pointer the
    /// thread starts with.
    fn make_stack(
        process: &crate::process::Process,
        event: u32,
    ) -> Result<(crate::sched::startup::InitialStack, u32), NtStatus> {
        use crate::mem::vm::{CurrentPages, Kind, PAGE_READWRITE};
        let (reserve, commit) = stack_sizes();
        let base = process
            .with_space(|space| space.reserve(None, reserve, PAGE_READWRITE, Kind::Private))
            .map_err(|_| STATUS_NO_MEMORY)?;
        let top = base + reserve;
        let limit = top - commit;
        let made = process.with_space(|space| {
            space.commit(&mut CurrentPages, limit, commit, PAGE_READWRITE)?;
            if limit > base {
                crate::user::stack::plant_guard(space, limit - PAGE_SIZE);
            }
            Ok::<_, crate::mem::vm::VmError>(())
        });
        // The argument, then the null return address under it: the routine is entered as if
        // called (stdcall: its own return pops the argument).
        let esp = top - 8;
        let written = made.ok().and_then(|()| {
            let mut words = [0u8; 8];
            words[4..].copy_from_slice(&event.to_le_bytes());
            UserAddr(esp).write(&words).ok()
        });
        if written.is_none() {
            release_stack(process, base);
            return Err(STATUS_NO_MEMORY);
        }
        let stack = crate::sched::startup::InitialStack {
            base: top,
            limit,
            allocation_base: base,
        };
        Ok((stack, esp))
    }

    /// A stack whose thread was never made goes back whole.
    fn release_stack(process: &crate::process::Process, base: u32) {
        use crate::mem::vm::CurrentPages;
        let _ = process.with_space(|space| space.release(&mut CurrentPages, base));
    }

    /// RtlCreateUserThread's work for the console: a thread of the process `id` names, started at
    /// `routine` with `event` as its argument, and readied. The process's own failures refuse it:
    /// it has ended or is ending, its address space has no room, it can take no thread.
    fn start_ctrl_thread(id: ObjectId, routine: u32, event: u32) -> Result<(), NtStatus> {
        // The process's object held for the delivery: its record stays the process's.
        let _reference = crate::ob::reference(id).ok_or(STATUS_INVALID_HANDLE)?;
        let process = crate::process::pool::of_object(id).ok_or(STATUS_INVALID_HANDLE)?;
        if process.end().is_some() || process.terminating() {
            return Err(STATUS_PROCESS_IS_TERMINATING);
        }
        let thread = {
            // The process's teardown waits for the attach's end.
            let _attached = process.attach();
            let (stack, esp) = make_stack(process, event)?;
            let user = crate::sched::startup::UserStart {
                eip: routine,
                esp,
                ..Default::default()
            };
            match crate::process::threads::create(process, user, stack) {
                Ok((_object, thread, _id)) => thread,
                Err(status) => {
                    release_stack(process, stack.allocation_base);
                    return Err(status);
                }
            }
        };
        // No handle names the thread: its own reference keeps it until its end, as csrss closes
        // its handle once the thread runs.
        raised::<Dispatch, _>(|dispatch| DISPATCHER.get(dispatch).make_ready(thread));
        Ok(())
    }
}

#[cfg(target_arch = "x86")]
pub use target::{start, wake};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ob::ObjectType;

    fn process(index: u16) -> ObjectId {
        ObjectId {
            kind: ObjectType::Process,
            index,
            generation: 0,
        }
    }

    /// The console's processes: a connection made twice is replaced, a disconnection forgets it;
    /// an event goes to the processes of its group, every one for group 0, each with its
    /// CtrlRoutine.
    #[test]
    fn events_go_to_their_groups_processes() {
        let mut control = Control::new();
        assert!(control.connect(process(1), 8, 0x1000));
        assert!(control.connect(process(2), 12, 0x2000));
        assert!(control.connect(process(3), 12, 0x3000));
        assert!(control.connect(process(1), 8, 0x1100));
        assert!(control.raise(1, 12));
        assert!(control.raise(0, 0));
        let targets = |delivery: Delivery| {
            delivery
                .targets
                .iter()
                .flatten()
                .copied()
                .collect::<std::vec::Vec<_>>()
        };
        let first = control.take().unwrap();
        assert_eq!(first.event, 1);
        assert_eq!(targets(first), [(process(2), 0x2000), (process(3), 0x3000)]);
        control.disconnect(process(2));
        let second = control.take().unwrap();
        assert_eq!(second.event, 0);
        assert_eq!(
            targets(second),
            [(process(1), 0x1100), (process(3), 0x3000)]
        );
        assert_eq!(control.take(), None);
        assert!(!control.has_pending());
    }

    /// GenerateConsoleCtrlEvent's group: one the console's processes are in, or 0; any other is
    /// refused, nothing raised. The queue holds a bounded number of events.
    #[test]
    fn a_generated_event_needs_a_process_in_its_group() {
        let mut control = Control::new();
        assert_eq!(control.generate(1, 0), Err(STATUS_INVALID_PARAMETER.0));
        assert!(control.connect(process(1), 8, 0x1000));
        assert_eq!(control.generate(1, 12), Err(STATUS_INVALID_PARAMETER.0));
        assert!(!control.has_pending());
        assert_eq!(control.generate(1, 8), Ok(()));
        assert_eq!(control.generate(0, 0), Ok(()));
        control.disconnect(process(1));
        assert_eq!(control.generate(1, 8), Err(STATUS_INVALID_PARAMETER.0));
        while control.raise(1, 8) {}
        assert_eq!(
            core::iter::from_fn(|| control.take()).count(),
            PENDING_EVENTS
        );
    }
}
