//! Critical sections: the RtlInitializeCriticalSection family, as Windows 2000's ntdll runs it —
//! entirely in user mode, over the RTL_CRITICAL_SECTION programs allocate and read.
//!
//! The layout, 24 bytes: DebugInfo, LockCount, RecursionCount, OwningThread (the owner's thread
//! id), LockSemaphore (an auto-reset event's handle, made on the first contention unless
//! preallocated), SpinCount. LockCount is -1 when free and goes up by one for every entry — the
//! owner's recursive ones and each waiter's — so after a leave it is nonnegative exactly when
//! someone waits. Programs read RecursionCount and OwningThread directly.
//!
//! The kernel is entered only under contention, and only for the event ([`System`]): an enter
//! that finds another owner waits on it, and a leave that finds a waiter counted signals it. The
//! release hands the section over: the leave clears the owner and leaves the waiter's count
//! standing, and the woken waiter takes the section directly — no other entrant slips in, since
//! LockCount stays nonnegative and every entrant then waits.

use core::sync::atomic::Ordering::{Relaxed, SeqCst};
use core::sync::atomic::{AtomicI32, AtomicU32};

/// An RTL_CRITICAL_SECTION, as user code lays it out.
#[repr(C)]
pub struct CriticalSection {
    pub debug_info: AtomicU32,
    pub lock_count: AtomicI32,
    pub recursion_count: AtomicI32,
    pub owning_thread: AtomicU32,
    pub lock_semaphore: AtomicU32,
    pub spin_count: AtomicU32,
}

impl Default for CriticalSection {
    fn default() -> Self {
        Self::new()
    }
}

/// What the critical sections need of the system: the calling thread, the processor count, and
/// the event the kernel keeps for a contended section.
pub trait System {
    /// The calling thread's id (its TEB's ClientId.UniqueThread): what a section records as its
    /// owner.
    fn thread_id(&self) -> u32;
    /// The processors the process runs on (its PEB's NumberOfProcessors).
    fn processors(&self) -> u32;
    /// A fresh unnamed auto-reset event, nonsignaled: its handle, or 0 when none can be made.
    fn create_event(&self) -> u32;
    /// Wait on the event, forever.
    fn wait(&self, event: u32);
    /// Signal the event.
    fn set(&self, event: u32);
    /// Close the handle.
    fn close(&self, handle: u32);
    /// Raise `status` as a noncontinuable exception (RtlRaiseStatus).
    fn raise(&self, status: u32) -> !;
}

/// STATUS_SUCCESS.
pub const STATUS_SUCCESS: u32 = 0;
/// What an initialization asked to preallocate the event answers when none can be made.
pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
/// What a contended enter or leave raises when no event can be made for the section: Windows
/// 2000's EnterCriticalSection raises in low memory (its documentation names
/// STATUS_INVALID_HANDLE).
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// The spin count's high bit, at initialization: make the event now, so a later contention cannot
/// fail for want of one (InitializeCriticalSectionAndSpinCount on Windows 2000).
pub const PREALLOCATE_EVENT: u32 = 0x8000_0000;

impl CriticalSection {
    /// A section's storage, all zero, as a DLL's data holds one before its initialization (ntdll's
    /// own locks, which its process initialization initializes before anything takes them).
    pub const fn new() -> Self {
        Self {
            debug_info: AtomicU32::new(0),
            lock_count: AtomicI32::new(0),
            recursion_count: AtomicI32::new(0),
            owning_thread: AtomicU32::new(0),
            lock_semaphore: AtomicU32::new(0),
            spin_count: AtomicU32::new(0),
        }
    }

    /// RtlInitializeCriticalSectionAndSpinCount: free, owned by nobody, no event unless the spin
    /// count's high bit asks for one now. A uniprocessor ignores the spin count (it stores 0);
    /// otherwise the count is stored without the high bit. No debug information is kept (DebugInfo
    /// stays NULL). STATUS_NO_MEMORY when the preallocated event cannot be made.
    pub fn initialize(&self, system: &impl System, spin_count: u32) -> Result<(), u32> {
        self.debug_info.store(0, Relaxed);
        self.lock_count.store(-1, Relaxed);
        self.recursion_count.store(0, Relaxed);
        self.owning_thread.store(0, Relaxed);
        self.lock_semaphore.store(0, Relaxed);
        let spin = if system.processors() > 1 {
            spin_count & !PREALLOCATE_EVENT
        } else {
            0
        };
        self.spin_count.store(spin, Relaxed);
        if spin_count & PREALLOCATE_EVENT != 0 {
            let event = system.create_event();
            if event == 0 {
                return Err(STATUS_NO_MEMORY);
            }
            self.lock_semaphore.store(event, SeqCst);
        }
        Ok(())
    }

    /// RtlEnterCriticalSection: count the entry; the first acquires, the owner's re-enters, anyone
    /// else's waits on the event until a leave hands the section over, then takes it.
    pub fn enter(&self, system: &impl System) {
        let thread = system.thread_id();
        if self.lock_count.fetch_add(1, SeqCst) == -1 {
            return self.take(thread);
        }
        if self.owning_thread.load(Relaxed) == thread {
            self.recursion_count.fetch_add(1, Relaxed);
            return;
        }
        let event = self.event(system);
        system.wait(event);
        self.take(thread);
    }

    /// RtlTryEnterCriticalSection: acquire a free section (LockCount -1 to 0 in one
    /// compare-exchange), re-enter an owned one, or fail leaving no trace. It never enters the
    /// kernel.
    pub fn try_enter(&self, system: &impl System) -> bool {
        let thread = system.thread_id();
        if self
            .lock_count
            .compare_exchange(-1, 0, SeqCst, SeqCst)
            .is_ok()
        {
            self.take(thread);
            return true;
        }
        if self.owning_thread.load(Relaxed) == thread {
            self.lock_count.fetch_add(1, SeqCst);
            self.recursion_count.fetch_add(1, Relaxed);
            return true;
        }
        false
    }

    /// RtlLeaveCriticalSection: drop one entry; the last clears the owner, and signals the event
    /// when a waiter is counted. As on Windows, the caller's ownership is not checked.
    pub fn leave(&self, system: &impl System) {
        if self.recursion_count.fetch_sub(1, Relaxed) != 1 {
            self.lock_count.fetch_sub(1, SeqCst);
            return;
        }
        self.owning_thread.store(0, Relaxed);
        if self.lock_count.fetch_sub(1, SeqCst) >= 1 {
            system.set(self.event(system));
        }
    }

    /// Run `body` with the section entered, and answer what it answers: entered first, left when
    /// `body` returns or unwinds.
    pub fn with<R>(&self, system: &impl System, body: impl FnOnce() -> R) -> R {
        self.enter(system);
        let _entered = Entered {
            section: self,
            system,
        };
        body()
    }

    /// RtlDeleteCriticalSection: close the section's event, if it ever got one. The other fields
    /// are left as they are.
    pub fn delete(&self, system: &impl System) {
        let event = self.lock_semaphore.swap(0, SeqCst);
        if event != 0 {
            system.close(event);
        }
    }

    /// RtlSetCriticalSectionSpinCount: store a new spin count (0 on a uniprocessor), answering
    /// the previous one.
    pub fn set_spin_count(&self, system: &impl System, spin_count: u32) -> u32 {
        let spin = if system.processors() > 1 {
            spin_count
        } else {
            0
        };
        self.spin_count.swap(spin, Relaxed)
    }

    /// The section passes to `thread`, entered once.
    fn take(&self, thread: u32) {
        self.owning_thread.store(thread, Relaxed);
        self.recursion_count.store(1, Relaxed);
    }

    /// The section's event, made on first need: of two contenders making one at once, the first
    /// to store its handle wins and the other closes its own. With none to be made, the status
    /// Windows 2000 raises.
    fn event(&self, system: &impl System) -> u32 {
        let event = self.lock_semaphore.load(SeqCst);
        if event != 0 {
            return event;
        }
        let made = system.create_event();
        if made == 0 {
            system.raise(STATUS_INVALID_HANDLE);
        }
        match self
            .lock_semaphore
            .compare_exchange(0, made, SeqCst, SeqCst)
        {
            Ok(_) => made,
            Err(existing) => {
                system.close(made);
                existing
            }
        }
    }
}

/// Leaves the section once when dropped ([`CriticalSection::with`]).
struct Entered<'a, S: System> {
    section: &'a CriticalSection,
    system: &'a S,
}

impl<S: System> Drop for Entered<'_, S> {
    fn drop(&mut self) {
        self.section.leave(self.system);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    /// What a scripted system saw.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Call {
        Create(u32),
        Wait(u32),
        Set(u32),
        Close(u32),
    }

    /// Something another thread does while the caller waits (or makes an event).
    type Step<'a> = Box<dyn FnOnce(&Scripted<'a>) + 'a>;

    /// A system with one runnable thread at a time: the test sets whose turn it is, and what the
    /// others do while it blocks.
    struct Scripted<'a> {
        thread: Cell<u32>,
        processors: u32,
        next_handle: Cell<u32>,
        creatable: Cell<bool>,
        signaled: RefCell<Vec<u32>>,
        calls: RefCell<Vec<Call>>,
        while_waiting: RefCell<Vec<Step<'a>>>,
        while_creating: RefCell<Vec<Step<'a>>>,
    }

    impl<'a> Scripted<'a> {
        fn new(processors: u32) -> Self {
            Scripted {
                thread: Cell::new(8),
                processors,
                next_handle: Cell::new(0x44),
                creatable: Cell::new(true),
                signaled: RefCell::new(Vec::new()),
                calls: RefCell::new(Vec::new()),
                while_waiting: RefCell::new(Vec::new()),
                while_creating: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }

        fn as_thread(&self, thread: u32, step: impl FnOnce()) {
            let caller = self.thread.replace(thread);
            step();
            self.thread.set(caller);
        }
    }

    impl System for Scripted<'_> {
        fn thread_id(&self) -> u32 {
            self.thread.get()
        }

        fn processors(&self) -> u32 {
            self.processors
        }

        fn create_event(&self) -> u32 {
            let step = self.while_creating.borrow_mut().pop();
            if let Some(step) = step {
                step(self);
            }
            if !self.creatable.get() {
                return 0;
            }
            let handle = self.next_handle.get();
            self.next_handle.set(handle + 4);
            self.calls.borrow_mut().push(Call::Create(handle));
            handle
        }

        fn wait(&self, event: u32) {
            self.calls.borrow_mut().push(Call::Wait(event));
            let step = self.while_waiting.borrow_mut().pop();
            if let Some(step) = step {
                step(self);
            }
            let mut signaled = self.signaled.borrow_mut();
            let at = signaled
                .iter()
                .position(|&e| e == event)
                .expect("the wait would block forever");
            signaled.remove(at);
        }

        fn set(&self, event: u32) {
            self.calls.borrow_mut().push(Call::Set(event));
            self.signaled.borrow_mut().push(event);
        }

        fn close(&self, handle: u32) {
            self.calls.borrow_mut().push(Call::Close(handle));
        }

        fn raise(&self, status: u32) -> ! {
            panic!("raised {status:#010x}")
        }
    }

    fn fields(section: &CriticalSection) -> (u32, i32, i32, u32, u32, u32) {
        (
            section.debug_info.load(SeqCst),
            section.lock_count.load(SeqCst),
            section.recursion_count.load(SeqCst),
            section.owning_thread.load(SeqCst),
            section.lock_semaphore.load(SeqCst),
            section.spin_count.load(SeqCst),
        )
    }

    /// A section full of junk, as user memory hands it to InitializeCriticalSection.
    fn junk() -> CriticalSection {
        CriticalSection {
            debug_info: AtomicU32::new(0xDEAD),
            lock_count: AtomicI32::new(7),
            recursion_count: AtomicI32::new(7),
            owning_thread: AtomicU32::new(7),
            lock_semaphore: AtomicU32::new(7),
            spin_count: AtomicU32::new(7),
        }
    }

    fn initialized(system: &impl System) -> CriticalSection {
        let section = junk();
        section.initialize(system, 0).unwrap();
        section
    }

    /// The layout user code reads: 24 bytes, the fields at Windows 2000's offsets.
    #[test]
    fn the_layout_is_the_platforms() {
        assert_eq!(core::mem::size_of::<CriticalSection>(), 24);
        assert_eq!(core::mem::offset_of!(CriticalSection, lock_count), 4);
        assert_eq!(core::mem::offset_of!(CriticalSection, recursion_count), 8);
        assert_eq!(core::mem::offset_of!(CriticalSection, owning_thread), 0xC);
        assert_eq!(core::mem::offset_of!(CriticalSection, lock_semaphore), 0x10);
        assert_eq!(core::mem::offset_of!(CriticalSection, spin_count), 0x14);
    }

    /// `with` runs its body with the section entered, recursively within another entry, and
    /// leaves it after, as an unwinding body does too.
    #[test]
    fn with_enters_for_the_body_only() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        let answer = section.with(&system, || {
            let (_, lock_count, recursion_count, owner, _, _) = fields(&section);
            assert_eq!((lock_count, recursion_count, owner), (0, 1, 8));
            section.with(&system, || fields(&section).2)
        });
        assert_eq!(answer, 2);
        assert_eq!(fields(&section), (0, -1, 0, 0, 0, 0));
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            section.with(&system, || panic!("the body fails"))
        }));
        assert!(unwound.is_err());
        assert_eq!(fields(&section), (0, -1, 0, 0, 0, 0));
        assert!(system.calls().is_empty());
    }

    /// Initialization: free, no owner, no event, no debug information; a uniprocessor stores no
    /// spin count, a multiprocessor the count without the high bit.
    #[test]
    fn initialization_is_the_free_state() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        assert_eq!(fields(&section), (0, -1, 0, 0, 0, 0));
        section.initialize(&system, 4000).unwrap();
        assert_eq!(
            fields(&section).5,
            0,
            "a uniprocessor ignores the spin count"
        );
        let system = Scripted::new(2);
        section.initialize(&system, 4000).unwrap();
        assert_eq!(fields(&section).5, 4000);
        assert_eq!(system.calls(), []);
    }

    /// The spin count's high bit makes the event at initialization; when none can be made, the
    /// initialization fails with STATUS_NO_MEMORY.
    #[test]
    fn the_high_bit_preallocates_the_event() {
        let system = Scripted::new(2);
        let section = initialized(&system);
        section
            .initialize(&system, PREALLOCATE_EVENT | 100)
            .unwrap();
        assert_eq!(fields(&section), (0, -1, 0, 0, 0x44, 100));
        assert_eq!(system.calls(), [Call::Create(0x44)]);
        system.creatable.set(false);
        assert_eq!(
            section.initialize(&system, PREALLOCATE_EVENT),
            Err(STATUS_NO_MEMORY)
        );
    }

    /// Recursive entries count up and leave in turn; the last leave frees the section, with no
    /// waiter to signal and no kernel call.
    #[test]
    fn recursion() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        section.enter(&system);
        section.enter(&system);
        assert!(section.try_enter(&system));
        assert_eq!(fields(&section), (0, 2, 3, 8, 0, 0));
        section.leave(&system);
        section.leave(&system);
        section.leave(&system);
        assert_eq!(fields(&section), (0, -1, 0, 0, 0, 0));
        assert_eq!(system.calls(), []);
    }

    /// Another thread's try fails and leaves no trace; its enter is counted as a waiter, makes the
    /// event and waits; the owner's leave signals and hands over; the woken waiter takes the
    /// section, and the next contention reuses the event.
    #[test]
    fn contention_hands_the_section_over() {
        let section = junk();
        let system = Scripted::new(1);
        section.initialize(&system, 0).unwrap();
        let section = &section;
        section.enter(&system);
        system.as_thread(12, || assert!(!section.try_enter(&system)));
        assert_eq!(fields(&section).1, 0, "the try left no trace");
        system
            .while_waiting
            .borrow_mut()
            .push(Box::new(move |system: &Scripted| {
                system.as_thread(8, || section.leave(system));
                assert_eq!(fields(&section).3, 0, "handed over: owned by nobody yet");
            }));
        system.as_thread(12, || section.enter(&system));
        assert_eq!(fields(&section), (0, 0, 1, 12, 0x44, 0));
        assert_eq!(
            system.calls(),
            [Call::Create(0x44), Call::Wait(0x44), Call::Set(0x44)]
        );
        system
            .while_waiting
            .borrow_mut()
            .push(Box::new(move |system: &Scripted| {
                system.as_thread(12, || section.leave(system));
            }));
        system.as_thread(16, || section.enter(&system));
        assert_eq!(fields(&section), (0, 0, 1, 16, 0x44, 0));
        assert_eq!(
            system.calls()[3..],
            [Call::Wait(0x44), Call::Set(0x44)],
            "one event, reused"
        );
        system.as_thread(16, || section.leave(&system));
        assert_eq!(fields(&section), (0, -1, 0, 0, 0x44, 0));
    }

    /// A leave that finds a waiter counted before the waiter made the event makes it itself; the
    /// waiter then finds it and its signal.
    #[test]
    fn the_leave_can_make_the_event_first() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        section.enter(&system);
        // The waiter is counted (its enter's increment), then the owner leaves before it gets on.
        section.lock_count.fetch_add(1, SeqCst);
        section.leave(&system);
        assert_eq!(system.calls(), [Call::Create(0x44), Call::Set(0x44)]);
        system.as_thread(12, || {
            let event = section.event(&system);
            system.wait(event);
            section.take(12);
        });
        assert_eq!(fields(&section), (0, 0, 1, 12, 0x44, 0));
    }

    /// Between the leave and the woken waiter's take nobody slips in: the section reads unowned,
    /// but a try fails and an entrant is counted as one more waiter.
    #[test]
    fn no_entrant_slips_into_a_handover() {
        let section = junk();
        let system = Scripted::new(1);
        section.initialize(&system, 0).unwrap();
        let section = &section;
        section.enter(&system);
        system
            .while_waiting
            .borrow_mut()
            .push(Box::new(move |system: &Scripted| {
                system.as_thread(8, || section.leave(system));
                system.as_thread(16, || assert!(!section.try_enter(system), "the try fails"));
                // 16's enter is counted and waits; 12, signaled, takes the section and later
                // leaves.
                system
                    .while_waiting
                    .borrow_mut()
                    .push(Box::new(move |system: &Scripted| {
                        system.as_thread(12, || section.leave(system));
                    }));
            }));
        system.as_thread(12, || section.enter(&system));
        assert_eq!(fields(&section).3, 12);
        system.as_thread(16, || section.enter(&system));
        assert_eq!(fields(&section), (0, 0, 1, 16, 0x44, 0));
        system.as_thread(16, || section.leave(&system));
        assert_eq!(fields(&section).1, -1);
    }

    /// Two contenders making the event at once: the first to store its handle wins, the other
    /// closes its own and waits on the winner's.
    #[test]
    fn a_lost_event_race_closes_the_loser() {
        let section = junk();
        let system = Scripted::new(1);
        section.initialize(&system, 0).unwrap();
        let section = &section;
        section.enter(&system);
        system
            .while_creating
            .borrow_mut()
            .push(Box::new(move |_: &Scripted| {
                section.lock_semaphore.store(0x80, SeqCst);
            }));
        system
            .while_waiting
            .borrow_mut()
            .push(Box::new(move |system: &Scripted| {
                system.as_thread(8, || section.leave(system));
            }));
        system.as_thread(12, || section.enter(&system));
        assert_eq!(
            system.calls(),
            [
                Call::Create(0x44),
                Call::Close(0x44),
                Call::Wait(0x80),
                Call::Set(0x80)
            ]
        );
        assert_eq!(fields(&section).4, 0x80);
    }

    /// A contended enter with no event to be made raises STATUS_INVALID_HANDLE (Windows 2000's
    /// low-memory exception); an uncontended one never needs one.
    #[test]
    #[should_panic(expected = "raised 0xc0000008")]
    fn a_contended_enter_without_an_event_raises() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        system.creatable.set(false);
        section.enter(&system);
        section.leave(&system);
        section.enter(&system);
        system.as_thread(12, || section.enter(&system));
    }

    /// Delete closes the event, if any, and clears its handle; nothing else changes.
    #[test]
    fn delete_closes_the_event() {
        let system = Scripted::new(1);
        let section = initialized(&system);
        section.delete(&system);
        assert_eq!(system.calls(), []);
        section.initialize(&system, PREALLOCATE_EVENT).unwrap();
        section.delete(&system);
        assert_eq!(system.calls(), [Call::Create(0x44), Call::Close(0x44)]);
        assert_eq!(fields(&section), (0, -1, 0, 0, 0, 0));
    }

    /// Setting the spin count answers the previous one; a uniprocessor stores 0.
    #[test]
    fn the_spin_count_swaps() {
        let system = Scripted::new(2);
        let section = initialized(&system);
        assert_eq!(section.set_spin_count(&system, 4000), 0);
        assert_eq!(section.set_spin_count(&system, 10), 4000);
        let system = Scripted::new(1);
        assert_eq!(section.set_spin_count(&system, 4000), 10);
        assert_eq!(fields(&section).5, 0);
    }

    /// Real threads: the sync fixture's shape (4 threads × 100000 increments of a plain counter
    /// under the section) totals exactly, the contended enters waiting on one event.
    #[test]
    fn real_threads_exclude_each_other() {
        use std::sync::atomic::AtomicU32 as Next;
        use std::sync::{Condvar, Mutex};

        struct Threads {
            next: Next,
            signaled: Mutex<Vec<u32>>,
            ready: Condvar,
        }
        std::thread_local!(static ID: Cell<u32> = const { Cell::new(0) });
        impl System for Threads {
            fn thread_id(&self) -> u32 {
                ID.with(Cell::get)
            }

            fn processors(&self) -> u32 {
                4
            }

            fn create_event(&self) -> u32 {
                self.next.fetch_add(4, SeqCst)
            }

            fn wait(&self, event: u32) {
                let mut signaled = self.signaled.lock().unwrap();
                loop {
                    if let Some(at) = signaled.iter().position(|&e| e == event) {
                        signaled.remove(at);
                        return;
                    }
                    signaled = self.ready.wait(signaled).unwrap();
                }
            }

            fn set(&self, event: u32) {
                self.signaled.lock().unwrap().push(event);
                self.ready.notify_all();
            }

            fn close(&self, _: u32) {}

            fn raise(&self, status: u32) -> ! {
                panic!("raised {status:#010x}")
            }
        }

        struct Counter(std::cell::UnsafeCell<u64>);
        // SAFETY: the counter is only touched by the section's owner.
        unsafe impl Sync for Counter {}

        let system = Threads {
            next: Next::new(0x44),
            signaled: Mutex::new(Vec::new()),
            ready: Condvar::new(),
        };
        let section = initialized(&system);
        let counter = Counter(std::cell::UnsafeCell::new(0));
        std::thread::scope(|scope| {
            for id in 1..=4u32 {
                let (system, section, counter) = (&system, &section, &counter);
                scope.spawn(move || {
                    ID.with(|cell| cell.set(id * 4));
                    for _ in 0..100_000 {
                        section.enter(system);
                        // SAFETY: the section is held.
                        unsafe { *counter.0.get() += 1 };
                        section.leave(system);
                    }
                });
            }
        });
        // SAFETY: the scope joined every thread that wrote the counter; none touches it now.
        assert_eq!(unsafe { *counter.0.get() }, 400_000);
        assert_eq!(fields(&section).1, -1);
        assert_eq!(fields(&section).3, 0);
    }
}
