//! The console's control events: Ctrl+C and Ctrl+Break, delivered to the console's processes as
//! Windows 2000's console delivers them.
//!
//! The server keeps the consoles' processes ([`Control`]), as Windows 2000's console keeps each
//! process attached to it: one connects at its start (kernel32's ConnectCtrl, the server's API 27,
//! or the making of a console of its own, AllocConsole's), handing over its CtrlRoutine —
//! kernel32's routine that runs the process's handlers — and the server records it with the
//! process's group (see `Process::process_group`) and its console; leaving the console
//! (FreeConsole) or its end disconnects it. An event names a console and a group: a key's goes to
//! group 0 of the console the keyboard types into, every process of it; GenerateConsoleCtrlEvent
//! names one of the caller's console, refused (STATUS_INVALID_PARAMETER) when no process of that
//! console is in it — a process of another console leads no group of the caller's.
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
//! (a system thread of the System process, see `crate::sched::idle::start_system_thread`):
//! it waits on its work event, a synchronization event the raise sets, and delivers whatever is
//! queued each time it wakes. A DPC cannot make a thread — making one waits for locks, and maps
//! and writes another process's memory — so the keyboard's events wait for it.
//!
//! The session's end goes through the same server ([`crate::session`]): a request
//! (ExitWindowsEx's, through the user server) waits here for the control thread, as an event does,
//! and the control thread then asks each process the server knows to end in turn, and marks each
//! process the session's end has reached. It asks them by their shutdown level, the highest first
//! (SetProcessShutdownParameters, through the base server: Windows 2000's csrss keeps each
//! process's level and flags with the process, and F2K's server keeps them with its entry).
//!
//! The server knows more processes than the console's, as Windows 2000's csrss knows the session's
//! processes, not only those attached to a console: one that enters win32k (at its first service,
//! where Windows 2000's user32 has connected to csrss's user server already), one that sets its
//! shutdown parameters, and the one that asks for the session's end are held too, without a
//! CtrlRoutine until they connect to the console. No control event reaches such a process; the
//! session's end does, through its windows ([`crate::session`]).

use crate::ob::ObjectId;
use crate::slots::{entries_per_page, Record, SideTable, KERNEL_PAGES};
use crate::status::STATUS_INVALID_PARAMETER;

/// What the server keeps for one process, at its process object's index: the process, and the
/// server's record of it; none for no process.
#[derive(Clone, Copy)]
pub struct Held<T>(Option<(ObjectId, T)>);

// SAFETY: writes a whole record.
unsafe impl<T> Record for Held<T> {
    unsafe fn write_fresh(at: *mut Self, _: u32) {
        // SAFETY: the caller's contract.
        unsafe { at.write(Held(None)) };
    }
}

/// The server's records of the processes it holds, by process object index, as Windows 2000's
/// csrss keeps its CSR_PROCESS for each process it knows: any process can be one of its. A side
/// table ([`SideTable`]) made a page at a time at the server's first sight of a process at an
/// index, and kept; `PER` records to a chunk ([`entries_per_page`] of [`Held`]`<T>`). A record
/// names its process by id, so a later process at the index finds none of its predecessor's. The
/// walks go in index order.
pub struct ByProcess<T: Copy, const PER: usize> {
    table: SideTable<Held<T>, PER>,
    /// One past the highest index made: the walks stop there.
    end: u32,
}

impl<T: Copy, const PER: usize> ByProcess<T, PER> {
    /// No process held, no page taken.
    pub const fn new() -> Self {
        ByProcess {
            table: SideTable::new(),
            end: 0,
        }
    }

    /// The record of `process`, if the server holds one.
    pub fn get(&self, process: ObjectId) -> Option<&T> {
        match &self.table.get(process.index.into())?.0 {
            Some((held, value)) if *held == process => Some(value),
            _ => None,
        }
    }

    /// The record of `process`, to change.
    pub fn get_mut(&mut self, process: ObjectId) -> Option<&mut T> {
        match &mut self.table.get_mut(process.index.into())?.0 {
            Some((held, value)) if *held == process => Some(value),
            _ => None,
        }
    }

    /// Hold `value` for `process`, replacing what the server held for it or a process before it
    /// at its index: false, nothing changed, when no page is left for the record.
    pub fn insert(&mut self, process: ObjectId, value: T) -> bool {
        let index = u32::from(process.index);
        if self.table.ensure(index, &KERNEL_PAGES).is_err() {
            return false;
        }
        self.end = self.end.max(index + 1);
        let record = self.table.get_mut(index).expect("made just now");
        record.0 = Some((process, value));
        true
    }

    /// Forget `process`: its record, if the server held one.
    pub fn remove(&mut self, process: ObjectId) -> Option<T> {
        let record = self.table.get_mut(process.index.into())?;
        match record.0 {
            Some((held, value)) if held == process => {
                record.0 = None;
                Some(value)
            }
            _ => None,
        }
    }

    /// Every process held, with its record, in index order.
    pub fn iter(&self) -> impl Iterator<Item = (ObjectId, &T)> + '_ {
        (0..self.end).filter_map(|index| {
            let (process, value) = self.table.get(index)?.0.as_ref()?;
            Some((*process, value))
        })
    }

    /// Every process held, with its record to change, in index order.
    pub fn for_each_mut(&mut self, mut f: impl FnMut(ObjectId, &mut T)) {
        for index in 0..self.end {
            if let Some(Some((process, value))) =
                self.table.get_mut(index).map(|record| record.0.as_mut())
            {
                f(*process, value);
            }
        }
    }
}

impl<T: Copy, const PER: usize> Default for ByProcess<T, PER> {
    fn default() -> Self {
        Self::new()
    }
}

/// How many raised events wait for the control thread at most (one more is dropped).
const PENDING_EVENTS: usize = 16;

/// A process the server knows: its object; the group it belongs to, its console (the server's
/// slot) and its CtrlRoutine once it is one of a console's (none for a process no console holds);
/// its shutdown level and flags (SetProcessShutdownParameters'); whether the session's end under
/// way has reached it; and the CtrlRoutine the event the control thread is delivering still goes
/// to, as the process held it when the event was taken (none: no thread of it to make).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerProcess {
    pub process: ObjectId,
    pub group: u32,
    pub console: usize,
    pub routine: Option<u32>,
    pub shutdown_level: u32,
    pub shutdown_flags: u32,
    pub reached: bool,
    delivery: Option<u32>,
}

/// The server's processes to a chunk of their table: a page's worth.
const PROCESSES_PER_CHUNK: usize = entries_per_page::<Held<ServerProcess>>();

impl ServerProcess {
    /// `process`, off the console, at the default shutdown level with no shutdown flag.
    fn known(process: ObjectId) -> Self {
        ServerProcess {
            process,
            group: 0,
            console: 0,
            routine: None,
            shutdown_level: rtl::console::base::DEFAULT_SHUTDOWN_LEVEL,
            shutdown_flags: 0,
            reached: false,
            delivery: None,
        }
    }
}

/// A request for the session's end: ExitWindowsEx's flags, and the process that asked (ended
/// last).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRequest {
    pub flags: u32,
    pub caller: ObjectId,
}

/// Where the session's end stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Session {
    /// No end asked for, or the last one done.
    Running,
    /// Asked for, waiting for the control thread.
    Requested(SessionRequest),
    /// Under way on the control thread.
    Ending,
}

/// The console's side of its control events and the session's end, at the server's level: the
/// processes the server knows, and the events raised and not yet taken by the control thread,
/// oldest first.
pub struct Control {
    processes: ByProcess<ServerProcess, PROCESSES_PER_CHUNK>,
    /// The raised events, each with its group and its console: a ring, `first` the oldest, `count`
    /// of them.
    pending: [(u32, u32, usize); PENDING_EVENTS],
    first: usize,
    count: usize,
    session: Session,
    /// Whether a program's control event has been taken for a request for the session's end, as
    /// the kernel option `end-session` asks (see [`crate::session`]): once a boot.
    diverted: bool,
}

impl Control {
    /// A server that knows no process, with no event.
    pub const fn new() -> Self {
        Control {
            processes: ByProcess::new(),
            pending: [(0, 0, 0); PENDING_EVENTS],
            first: 0,
            count: 0,
            session: Session::Running,
            diverted: false,
        }
    }

    /// Connect `process`, of group `group`, its CtrlRoutine `routine`, to console `console`, at
    /// the default shutdown level with no shutdown flag: a connection it made before, or what the
    /// server knew of it, is replaced, its shutdown level and flags kept (and an event being
    /// delivered to it still is). False when the server has no room for it (no page).
    pub fn connect(&mut self, process: ObjectId, group: u32, routine: u32, console: usize) -> bool {
        let mut entry = ServerProcess {
            group,
            console,
            routine: Some(routine),
            ..ServerProcess::known(process)
        };
        if let Some(held) = self.processes.get(process) {
            entry.shutdown_level = held.shutdown_level;
            entry.shutdown_flags = held.shutdown_flags;
            entry.delivery = held.delivery;
        }
        self.processes.insert(process, entry)
    }

    /// The server learns of `process`: held from now on, off the console, at the default shutdown
    /// level with no shutdown flag, unless it is held already (and stays as it is). False when the
    /// server has no room for it (no page).
    pub fn know(&mut self, process: ObjectId) -> bool {
        self.processes.get(process).is_some()
            || self
                .processes
                .insert(process, ServerProcess::known(process))
    }

    /// SetProcessShutdownParameters' work for `process`, its flags taken already (any level is
    /// kept, as Windows 2000 keeps it), the server learning of it if it had not: false, nothing
    /// kept, only when the server has no room for it.
    pub fn set_shutdown_parameters(&mut self, process: ObjectId, level: u32, flags: u32) -> bool {
        if !self.know(process) {
            return false;
        }
        let Some(held) = self.processes.get_mut(process) else {
            return false;
        };
        held.shutdown_level = level;
        held.shutdown_flags = flags;
        true
    }

    /// GetProcessShutdownParameters' work: `process`'s shutdown level and flags, the defaults for
    /// a process the server does not know.
    pub fn shutdown_parameters(&self, process: ObjectId) -> (u32, u32) {
        self.processes
            .get(process)
            .map_or((rtl::console::base::DEFAULT_SHUTDOWN_LEVEL, 0), |held| {
                (held.shutdown_level, held.shutdown_flags)
            })
    }

    /// `process` leaves its console (FreeConsole): no event reaches it until it connects again;
    /// the server still knows it.
    pub fn leave(&mut self, process: ObjectId) {
        if let Some(held) = self.processes.get_mut(process) {
            held.routine = None;
        }
    }

    /// Forget `process` (its end): no event, nor the session's end, reaches it from now on, and its
    /// shutdown parameters go. Nothing for a process the server does not know.
    pub fn disconnect(&mut self, process: ObjectId) {
        self.processes.remove(process);
    }

    /// Whether `held`, a process the server knows, is one of console `console`'s in `group`
    /// (every one for group 0) that an event reaches: its CtrlRoutine, if so.
    fn in_group(held: &ServerProcess, group: u32, console: usize) -> Option<u32> {
        if held.console == console && (group == 0 || held.group == group) {
            held.routine
        } else {
            None
        }
    }

    /// GenerateConsoleCtrlEvent's work: `event` raised for group `group` of console `console`
    /// (the caller's); STATUS_INVALID_PARAMETER, nothing raised, when no process of the console is
    /// in the group — a group no process leads any more, a process's id that leads none, a process
    /// of another console.
    pub fn generate(&mut self, event: u32, group: u32, console: usize) -> Result<(), u32> {
        if !self
            .processes
            .iter()
            .any(|(_, held)| Self::in_group(held, group, console).is_some())
        {
            return Err(STATUS_INVALID_PARAMETER.0);
        }
        self.raise(event, group, console);
        Ok(())
    }

    /// Queue `event` for group `group` of console `console`, for the control thread; false,
    /// nothing queued, when the queue is full.
    pub fn raise(&mut self, event: u32, group: u32, console: usize) -> bool {
        if self.count == PENDING_EVENTS {
            return false;
        }
        self.pending[(self.first + self.count) % PENDING_EVENTS] = (event, group, console);
        self.count += 1;
        true
    }

    /// Whether events, or a request for the session's end, wait for the control thread.
    pub fn has_pending(&self) -> bool {
        self.count != 0 || matches!(self.session, Session::Requested(_))
    }

    /// The oldest event waiting, taken: the processes it goes to now are marked, each with its
    /// CtrlRoutine, for [`Control::next_target`] to hand out (the marks of an event before it
    /// dropped: the control thread delivers one event at a time).
    pub fn take(&mut self) -> Option<u32> {
        if self.count == 0 {
            return None;
        }
        let (event, group, console) = self.pending[self.first];
        self.first = (self.first + 1) % PENDING_EVENTS;
        self.count -= 1;
        self.processes.for_each_mut(|_, held| {
            held.delivery = Self::in_group(held, group, console);
        });
        Some(event)
    }

    /// The next process the event taken last goes to, with its CtrlRoutine as it held it then,
    /// its mark dropped: in the server's order, none once every one has been handed out. A
    /// process that ended meanwhile is gone from the server, and goes without.
    pub fn next_target(&mut self) -> Option<(ObjectId, u32)> {
        let mut found = None;
        self.processes.for_each_mut(|process, held| {
            if found.is_none() {
                found = held.delivery.take().map(|routine| (process, routine));
            }
        });
        found
    }

    /// A request for the session's end, for the control thread to take, the server learning of
    /// its caller if it had not (ExitWindowsEx's documentation: a logoff ends every process of the
    /// session, so the caller's too). One already waiting or under way stays the one: the session
    /// ends once, as first asked, and the request is answered all the same (true when it was
    /// taken).
    pub fn request_session_end(&mut self, request: SessionRequest) -> bool {
        if self.session != Session::Running {
            return false;
        }
        self.know(request.caller);
        self.session = Session::Requested(request);
        true
    }

    /// The kernel option `end-session`'s step (see [`crate::session`]): whether this control event
    /// a program generates is the one taken for a request for the session's end instead — the
    /// first of the boot.
    pub fn divert(&mut self) -> bool {
        !core::mem::replace(&mut self.diverted, true)
    }

    /// The control thread's step: the request for the session's end waiting, taken, the session
    /// now ending; none reached by it yet.
    pub fn take_session_end(&mut self) -> Option<SessionRequest> {
        let Session::Requested(request) = self.session else {
            return None;
        };
        self.session = Session::Ending;
        self.processes.for_each_mut(|_, held| held.reached = false);
        Some(request)
    }

    /// The next process the session's end asks to end, marked reached, with its CtrlRoutine when
    /// it is one of the console's: of those the server knows that the end has not reached, the one
    /// with the highest shutdown level, the first in the server's order among equals; the caller
    /// once no other is left, whatever its level. A process the server learns of while the session
    /// ends, or that changes its level meanwhile, is reached in its turn. None once every process
    /// has been reached.
    ///
    /// That is Windows 2000's order: the highest level first, the caller last, every process
    /// starting at 0x280 until it changes its own with SetProcessShutdownParameters. Its flag,
    /// SHUTDOWN_NORETRY, changes nothing here: Windows ends such a process without its "End
    /// Program" dialog once the wait has passed, and F2K, which has no dialog, ends every process
    /// that way.
    pub fn next_to_end(&mut self, caller: ObjectId) -> Option<(ObjectId, Option<u32>)> {
        let others = self
            .processes
            .iter()
            .filter(|&(process, held)| !held.reached && process != caller)
            .max_by_key(|&(process, held)| (held.shutdown_level, core::cmp::Reverse(process.index)))
            .map(|(process, _)| process);
        let process = others.or_else(|| {
            self.processes
                .get(caller)
                .filter(|held| !held.reached)
                .map(|_| caller)
        })?;
        let held = self.processes.get_mut(process)?;
        held.reached = true;
        Some((held.process, held.routine))
    }

    /// The session's end is done: another may be asked for.
    pub fn session_ended(&mut self) {
        self.session = Session::Running;
    }
}

impl Default for Control {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86")]
mod target {
    use crate::level::{raised, Dispatch};
    use crate::mem::paging::PAGE_SIZE;
    use crate::nt::call::UserAddr;
    use crate::ob::ObjectId;
    use crate::sched::event::{WorkEvent, EVENT_WAKE_INCREMENT};
    use crate::sched::wait::WaitReason;
    use crate::sched::DISPATCHER;
    use crate::status::*;
    use crate::user::args::UserPtr;

    /// The control thread's priority: csrss's console input thread's (THREAD_PRIORITY_HIGHEST in
    /// csrss's high priority class), the top of the variable range.
    const PRIORITY: i8 = 15;

    /// The control thread's work event, set by each raise.
    static WORK: WorkEvent = WorkEvent::new();

    /// Start the control thread: its work event named, then the thread (see
    /// `crate::sched::idle::start_system_thread`). Once, at boot, before the first process.
    pub fn start() {
        WORK.init();
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

    /// The control thread's routine: wait for work, deliver every event waiting, then end the
    /// session when that was asked for (see [`crate::session`]), again. Events raised while the
    /// session ends wait for its end. Never returns.
    extern "C" fn control_thread(_start: u32, _context: u32) -> ! {
        loop {
            crate::sched::wait::wait_current_for(WORK.id(), WaitReason::Executive, None);
            loop {
                while let Some(event) =
                    raised::<Dispatch, _>(|dispatch| super::super::SERVER.get(dispatch).ctrl.take())
                {
                    deliver(event);
                }
                let request = raised::<Dispatch, _>(|dispatch| {
                    super::super::SERVER.get(dispatch).ctrl.take_session_end()
                });
                match request {
                    Some(request) => crate::session::end(request),
                    None => break,
                }
            }
        }
    }

    /// Deliver the event just taken: a thread at the CtrlRoutine of each process it goes to, one
    /// at a time. A process that ended meanwhile, or cannot take the thread, goes without.
    fn deliver(event: u32) {
        while let Some((process, routine)) =
            raised::<Dispatch, _>(|dispatch| super::super::SERVER.get(dispatch).ctrl.next_target())
        {
            let _ = start_ctrl_thread(process, routine, event);
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
    pub fn start_ctrl_thread(id: ObjectId, routine: u32, event: u32) -> Result<(), NtStatus> {
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
pub use target::{start, start_ctrl_thread, wake};

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

    /// The processes the event taken last goes to, handed out in turn.
    fn targets(control: &mut Control) -> std::vec::Vec<(ObjectId, u32)> {
        core::iter::from_fn(|| control.next_target()).collect()
    }

    /// The event's processes are the ones it found at its take: one that leaves its console or
    /// changes its routine meanwhile still has its thread, at the routine it had; one that ends
    /// goes without, and a process held at the same index after it is no target.
    #[test]
    fn an_event_goes_to_the_processes_it_found() {
        let mut control = Control::new();
        for index in 1..=3 {
            assert!(control.connect(process(index), 8, 0x1000 * index as u32, 0));
        }
        assert!(control.raise(0, 0, 0));
        assert_eq!(control.take(), Some(0));
        control.leave(process(1));
        assert!(control.connect(process(2), 8, 0x2200, 0));
        control.disconnect(process(3));
        let after = ObjectId {
            generation: 1,
            ..process(3)
        };
        assert!(control.connect(after, 8, 0x3300, 0));
        assert!(control.connect(process(4), 8, 0x4000, 0));
        assert_eq!(
            targets(&mut control),
            [(process(1), 0x1000), (process(2), 0x2000)]
        );
    }

    /// The server's processes grow past the old 64-process table, by index; a record at a high
    /// index is found by the walks and gone with its process.
    #[test]
    fn the_server_holds_processes_past_the_old_table() {
        let mut control = Control::new();
        for index in (1..=300).rev() {
            assert!(control.connect(process(index), 8, u32::from(index), 0));
        }
        assert!(control.raise(0, 0, 0));
        assert_eq!(control.take(), Some(0));
        let all = targets(&mut control);
        assert_eq!(all.len(), 300);
        assert_eq!(all[0], (process(1), 1), "in index order");
        assert_eq!(all[299], (process(300), 300));
        control.disconnect(process(300));
        assert_eq!(control.generate(0, 0, 0), Ok(()));
        assert_eq!(control.take(), Some(0));
        let left = targets(&mut control);
        assert_eq!((left.len(), left.last()), (299, Some(&(process(299), 299))));
    }

    /// The console's processes: a connection made twice is replaced, a disconnection forgets it;
    /// an event goes to the processes of its group, every one for group 0, each with its
    /// CtrlRoutine.
    #[test]
    fn events_go_to_their_groups_processes() {
        let mut control = Control::new();
        assert!(control.connect(process(1), 8, 0x1000, 0));
        assert!(control.connect(process(2), 12, 0x2000, 0));
        assert!(control.connect(process(3), 12, 0x3000, 0));
        assert!(control.connect(process(1), 8, 0x1100, 0));
        assert!(control.raise(1, 12, 0));
        assert!(control.raise(0, 0, 0));
        assert_eq!(control.take(), Some(1));
        assert_eq!(
            targets(&mut control),
            [(process(2), 0x2000), (process(3), 0x3000)]
        );
        control.disconnect(process(2));
        assert_eq!(control.take(), Some(0));
        assert_eq!(
            targets(&mut control),
            [(process(1), 0x1100), (process(3), 0x3000)]
        );
        assert_eq!(control.take(), None);
        assert!(!control.has_pending());
    }

    /// The session's end asks the server's processes in turn, in the server's order, the caller
    /// last; a process that connects meanwhile in its turn, one that disconnects never.
    #[test]
    fn the_session_ends_with_the_caller_last() {
        let mut control = Control::new();
        for index in 1..=4 {
            assert!(control.connect(process(index), 8, 0x1000 * index as u32, 0));
        }
        let caller = process(2);
        assert!(control.request_session_end(SessionRequest { flags: 1, caller }));
        assert!(control.has_pending());
        assert!(
            !control.request_session_end(SessionRequest { flags: 2, caller }),
            "the first request stands"
        );
        assert_eq!(
            control.take_session_end(),
            Some(SessionRequest { flags: 1, caller })
        );
        assert!(!control.has_pending());
        assert_eq!(
            control.next_to_end(caller),
            Some((process(1), Some(0x1000)))
        );
        assert!(control.connect(process(5), 8, 0x5000, 0));
        control.disconnect(process(1));
        assert_eq!(
            control.next_to_end(caller),
            Some((process(3), Some(0x3000)))
        );
        control.disconnect(process(4));
        assert_eq!(
            control.next_to_end(caller),
            Some((process(5), Some(0x5000)))
        );
        assert_eq!(
            control.next_to_end(caller),
            Some((process(2), Some(0x2000)))
        );
        assert_eq!(control.next_to_end(caller), None);
        assert!(
            !control.request_session_end(SessionRequest { flags: 0, caller }),
            "still ending"
        );
        control.session_ended();
        // Another session's end reaches every process again; a caller that is not the console's
        // is known from its request on, and reached last, with no CtrlRoutine.
        assert!(control.request_session_end(SessionRequest {
            flags: 0,
            caller: process(9)
        }));
        control.take_session_end();
        let reached =
            core::iter::from_fn(|| control.next_to_end(process(9))).collect::<std::vec::Vec<_>>();
        assert_eq!(
            reached,
            [
                (process(2), Some(0x2000)),
                (process(3), Some(0x3000)),
                (process(5), Some(0x5000)),
                (process(9), None)
            ]
        );
    }

    /// The server knows processes the console does not hold: off the console, no event reaches
    /// them and GenerateConsoleCtrlEvent finds none in their group, but the session's end does, in
    /// their turn by level, with no CtrlRoutine. Knowing a process twice changes nothing; its
    /// connection to the console keeps its parameters and gives it its routine; its end forgets
    /// it.
    #[test]
    fn the_server_knows_processes_off_the_console() {
        let mut control = Control::new();
        assert!(control.connect(process(1), 8, 0x1000, 0));
        assert!(control.know(process(2)));
        assert!(control.set_shutdown_parameters(process(3), 0x300, 0));
        assert!(control.know(process(3)));
        assert_eq!(control.shutdown_parameters(process(3)), (0x300, 0));
        assert_eq!(
            control.generate(0, process(2).index as u32, 0),
            Err(STATUS_INVALID_PARAMETER.0)
        );
        assert!(control.raise(0, 0, 0));
        assert_eq!(control.take(), Some(0));
        assert_eq!(targets(&mut control), [(process(1), 0x1000)]);
        let caller = process(1);
        assert!(control.request_session_end(SessionRequest { flags: 1, caller }));
        control.take_session_end();
        assert_eq!(control.next_to_end(caller), Some((process(3), None)));
        assert!(control.connect(process(2), 8, 0x2000, 0));
        assert_eq!(
            control.next_to_end(caller),
            Some((process(2), Some(0x2000)))
        );
        assert_eq!(
            control.next_to_end(caller),
            Some((process(1), Some(0x1000)))
        );
        assert_eq!(control.next_to_end(caller), None);
        control.session_ended();
        assert!(control.connect(process(3), 12, 0x3000, 0));
        assert_eq!(control.shutdown_parameters(process(3)), (0x300, 0));
        control.disconnect(process(3));
        assert_eq!(
            control.shutdown_parameters(process(3)),
            (rtl::console::base::DEFAULT_SHUTDOWN_LEVEL, 0)
        );
    }

    /// Each process starts at the default shutdown level with no flag, and keeps what it set
    /// across a second connection; one the console does not hold is known from its call on and
    /// keeps what it set until its end. The session's end asks the highest level first, levels
    /// outside the applications' 0x100-0x3FF included, the server's order among equals, and the
    /// caller last whatever its level.
    #[test]
    fn the_session_ends_by_shutdown_level() {
        use rtl::console::base::{DEFAULT_SHUTDOWN_LEVEL, SHUTDOWN_NORETRY};
        let mut control = Control::new();
        for index in 1..=5 {
            assert!(control.connect(process(index), 8, 0x1000 * index as u32, 0));
        }
        assert_eq!(
            control.shutdown_parameters(process(1)),
            (DEFAULT_SHUTDOWN_LEVEL, 0)
        );
        assert!(control.set_shutdown_parameters(process(4), 0x3FF, SHUTDOWN_NORETRY));
        assert!(control.set_shutdown_parameters(process(2), 0x100, 0));
        assert!(control.set_shutdown_parameters(process(5), 0x3FF, 0));
        assert!(control.set_shutdown_parameters(process(1), 0x0, 0));
        assert!(control.set_shutdown_parameters(process(3), 0xFFFF_FFFF, 0));
        assert!(control.connect(process(4), 8, 0x4100, 0));
        assert_eq!(
            control.shutdown_parameters(process(4)),
            (0x3FF, SHUTDOWN_NORETRY)
        );
        assert!(control.set_shutdown_parameters(process(9), 0x300, 0));
        assert_eq!(control.shutdown_parameters(process(9)), (0x300, 0));
        control.disconnect(process(9));
        assert_eq!(
            control.shutdown_parameters(process(9)),
            (DEFAULT_SHUTDOWN_LEVEL, 0)
        );
        // The caller, process 5, at 0x3FF, is asked last all the same, after process 1 at 0x000.
        let caller = process(5);
        assert!(control.request_session_end(SessionRequest { flags: 1, caller }));
        control.take_session_end();
        assert_eq!(
            control.next_to_end(caller),
            Some((process(3), Some(0x3000)))
        );
        assert_eq!(
            control.next_to_end(caller),
            Some((process(4), Some(0x4100)))
        );
        // A level changed while the session ends counts from then on.
        assert!(control.set_shutdown_parameters(process(2), 0x301, 0));
        assert_eq!(
            control.next_to_end(caller),
            Some((process(2), Some(0x2000)))
        );
        assert_eq!(
            control.next_to_end(caller),
            Some((process(1), Some(0x1000)))
        );
        assert_eq!(
            control.next_to_end(caller),
            Some((process(5), Some(0x5000)))
        );
        assert_eq!(control.next_to_end(caller), None);
        control.session_ended();
        // A process that disconnects and connects again starts over at the default level.
        control.disconnect(process(4));
        assert!(control.connect(process(4), 8, 0x4000, 0));
        assert_eq!(
            control.shutdown_parameters(process(4)),
            (DEFAULT_SHUTDOWN_LEVEL, 0)
        );
    }

    /// An event goes to its console's processes alone: a group of another console's is no group
    /// of the caller's, group 0 is every process of the console it names, and a process that left
    /// its console takes no event until it connects again.
    #[test]
    fn events_stay_in_their_console() {
        let mut control = Control::new();
        assert!(control.connect(process(1), 0, 0x1000, 0));
        assert!(control.connect(process(2), 0, 0x2000, 1));
        assert!(control.connect(process(3), 30, 0x3000, 1));
        assert_eq!(control.generate(1, 30, 0), Err(STATUS_INVALID_PARAMETER.0));
        assert_eq!(control.generate(0, 0, 1), Ok(()));
        assert_eq!(control.take(), Some(0));
        assert_eq!(
            targets(&mut control),
            [(process(2), 0x2000), (process(3), 0x3000)]
        );
        control.leave(process(2));
        assert_eq!(control.generate(1, 0, 1), Ok(()));
        assert_eq!(control.take(), Some(1));
        assert_eq!(targets(&mut control), [(process(3), 0x3000)]);
        control.leave(process(3));
        assert_eq!(control.generate(1, 0, 1), Err(STATUS_INVALID_PARAMETER.0));
        assert!(control.connect(process(3), 30, 0x3000, 2));
        assert_eq!(control.generate(1, 30, 2), Ok(()));
    }

    /// The `end-session` option takes one control event a boot.
    #[test]
    fn one_event_is_diverted() {
        let mut control = Control::new();
        assert!(control.divert());
        assert!(!control.divert());
    }

    /// GenerateConsoleCtrlEvent's group: one the console's processes are in, or 0; any other is
    /// refused, nothing raised. The queue holds a bounded number of events.
    #[test]
    fn a_generated_event_needs_a_process_in_its_group() {
        let mut control = Control::new();
        assert_eq!(control.generate(1, 0, 0), Err(STATUS_INVALID_PARAMETER.0));
        assert!(control.connect(process(1), 8, 0x1000, 0));
        assert_eq!(control.generate(1, 12, 0), Err(STATUS_INVALID_PARAMETER.0));
        assert!(!control.has_pending());
        assert_eq!(control.generate(1, 8, 0), Ok(()));
        assert_eq!(control.generate(0, 0, 0), Ok(()));
        control.disconnect(process(1));
        assert_eq!(control.generate(1, 8, 0), Err(STATUS_INVALID_PARAMETER.0));
        while control.raise(1, 8, 0) {}
        assert_eq!(
            core::iter::from_fn(|| control.take()).count(),
            PENDING_EVENTS
        );
    }
}
