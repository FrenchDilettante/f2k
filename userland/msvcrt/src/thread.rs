//! The C runtime's per-thread data and its locks, and the threads it starts (_beginthreadex and
//! _endthreadex).
//!
//! Each thread has its own `errno`, `_doserrno`, rand seed, `struct tm` (gmtime's and
//! localtime's) and wcstok position, as the multithreaded C runtime keeps them: a block from the C
//! runtime's heap, found through a TLS slot the DLL allocates when it is loaded, made on the
//! thread's first need and freed at its DLL_THREAD_DETACH. Finding it keeps the thread's last error
//! as it was (TlsGetValue clears it), so a C runtime call never disturbs a program's GetLastError.
//!
//! As process's capture shows them: a thread _beginthreadex starts ends with its routine's answer
//! or `_endthreadex`'s code (the code after it never run), read through the handle the C runtime
//! leaves open for its caller to close, and has an errno of its own.
//!
//! The process-wide state is split by lock, as Windows 2000's msvcrt splits it: each stream has a
//! lock of its own ([`crate::stdio`]), each descriptor one beside the descriptor table's
//! ([`crate::lowio`]), and the exit functions, the environment ([`crate::startup`]), the locale
//! ([`crate::ctype`]), the console input ([`crate::conio`]) and the time zone ([`crate::utility`])
//! one each. A lock is a critical section entered through kernel32 ([`Lock`]); the state it guards
//! is an `rtl::sync::Locked` value, reached only inside its `with`. A thread waiting on one stream
//! or descriptor (stdin, reading the console) holds that one's locks alone, so another thread's
//! output goes on.
//!
//! The locks a call holds while it reads or writes its caller's memory (a stream's and the buffer
//! it is lent, a descriptor's across its reads and writes, the exit functions') are let go when an
//! exception unwinds out of the call ([`UnwindLock`], [`Lock::holding`], over [`crate::unwind`]): a
//! fault in the caller's memory that the program's `__except` takes leaves no lock held, as
//! Windows 2000's `__finally` blocks leave none.
//!
//! The locks nest in one order, outermost first: a stream's, then the buffer it is lent for a call;
//! a descriptor's (two at once in ascending order); the descriptor table's. The exit functions',
//! the environment's, the locale's, the console input's and the time zone's take none of the C
//! runtime's locks inside them.

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize};

use rtl::critsec::CriticalSection;
use rtl::sync::RawLock;

use crate::{kernel32, unwind};

/// A thread's own C runtime state. Its fields are atomics: a thread's block is its own, but the
/// [`FALLBACK`] is shared by every thread the slot or the heap fails.
#[repr(C)]
pub struct ThreadData {
    /// `errno`.
    pub errno: AtomicI32,
    /// `_doserrno`: the Win32 error behind the last `errno` a system call set.
    pub doserrno: AtomicU32,
    /// rand's seed (srand's), 1 until the thread seeds it.
    pub seed: AtomicU32,
    /// The `struct tm` gmtime, localtime and mktime answer through (time.h's nine ints): one per
    /// thread, as the multithreaded C runtime keeps it.
    pub tm: [AtomicI32; 9],
    /// set_terminate's handler, which terminate calls (0 for none): the thread's own, as the
    /// multithreaded C runtime keeps it.
    pub terminate: AtomicUsize,
    /// The innermost catch block running on the thread: its guard, on the stack of the C++
    /// exception handling that called it (`crate::eh`), 0 for none.
    pub catches: AtomicUsize,
    /// Where wcstok goes on when it is called with NULL: the unit after the last token's end, in
    /// the string the thread last started (0 before its first): each thread's own, as wide's
    /// capture shows.
    pub wcstok: AtomicUsize,
}

/// The TLS slot holding each thread's [`ThreadData`] (TLS_OUT_OF_INDEXES before the DLL's
/// initialization), set once by the DLL's process attach. Host tests never run the DLL's attach
/// and run on many threads at once: they start with the slot the host TlsAlloc stand-in hands out,
/// so each test thread has its own data, as each thread does on target (the shared [`FALLBACK`]
/// would let one test's errno leak into another's).
static SLOT: AtomicU32 = AtomicU32::new(if cfg!(test) { HOST_SLOT } else { u32::MAX });

/// The slot the host TlsAlloc stand-in answers (`imports`' host stand-ins).
#[cfg(test)]
const HOST_SLOT: u32 = 1;
#[cfg(not(test))]
const HOST_SLOT: u32 = u32::MAX;

/// A thread's data while the slot or the heap fails it: errno and the seed still have a home.
static FALLBACK: ThreadData = ThreadData {
    errno: AtomicI32::new(0),
    doserrno: AtomicU32::new(0),
    seed: AtomicU32::new(1),
    tm: [const { AtomicI32::new(0) }; 9],
    terminate: AtomicUsize::new(0),
    catches: AtomicUsize::new(0),
    wcstok: AtomicUsize::new(0),
};

/// The lock of the C runtime's locks: held while one of them is initialized on its first use (a
/// [`Lock`] is, as Windows 2000's msvcrt initializes its locks on demand). The DLL's process attach
/// initializes it.
static ROOT: CriticalSection = unprepared();

/// The DLL's process attach: the TLS slot and the lock of the locks. False when the slot cannot be
/// had.
pub fn initialize() -> bool {
    kernel32::initialize_critical_section(&ROOT);
    let slot = kernel32::tls_alloc();
    SLOT.store(slot, Relaxed);
    slot != u32::MAX
}

/// `body` run over the calling thread's data, made on its first need.
pub fn with_data<R>(body: impl FnOnce(&ThreadData) -> R) -> R {
    let slot = SLOT.load(Relaxed);
    if slot == u32::MAX {
        return body(&FALLBACK);
    }
    let error = kernel32::last_error();
    let mut block = kernel32::tls_get(slot) as *const ThreadData;
    let fresh = block.is_null();
    if fresh {
        block = crate::heap::allocate(core::mem::size_of::<ThreadData>(), true).cast();
        if block.is_null() || kernel32::tls_set(slot, block as usize).is_err() {
            kernel32::set_last_error(error);
            return body(&FALLBACK);
        }
    }
    kernel32::set_last_error(error);
    // SAFETY: the block is the calling thread's (its TLS slot's value): allocated zeroed from the C
    // runtime's heap, whose blocks are 8-aligned (zero is a valid ThreadData: its fields are
    // atomics), and freed only at this thread's DLL_THREAD_DETACH. The borrow ends with `body`, on
    // this thread.
    let data = unsafe { &*block };
    if fresh {
        data.seed.store(1, Relaxed);
    }
    body(data)
}

/// A thread's DLL_THREAD_DETACH: its data given back.
pub fn detach_thread() {
    let slot = SLOT.load(Relaxed);
    if slot == u32::MAX {
        return;
    }
    let data = kernel32::tls_get(slot) as *mut u8;
    if !data.is_null() {
        let _ = kernel32::tls_set(slot, 0);
        // SAFETY: the thread's block, of the C runtime's heap: the thread's alone, and the thread
        // runs no more C runtime code that reaches it.
        unsafe { crate::heap::release(data) };
    }
}

/// A thread routine of `_beginthreadex`'s: a stdcall function of one argument, answering the
/// thread's exit code.
pub type ThreadRoutine = unsafe extern "system" fn(usize) -> u32;

/// What a thread _beginthreadex starts runs: the program's routine and its argument, in a block
/// of the C runtime's heap that the new thread takes and frees.
#[repr(C)]
struct Start {
    routine: ThreadRoutine,
    parameter: usize,
}

/// The start routine of the threads _beginthreadex makes: the program's routine called with its
/// argument, its answer the thread's exit code, as `_endthreadex` ends it.
///
/// # Safety
///
/// `block` is a [`Start`] of the C runtime's heap, the thread's alone.
unsafe extern "system" fn thread_start(block: usize) -> u32 {
    let block = block as *mut Start;
    // SAFETY: the caller's contract: a Start _beginthreadex wrote, handed to this thread alone,
    // read once and given back.
    let start = unsafe {
        let start = block.read();
        crate::heap::release(block.cast());
        start
    };
    // SAFETY: the program's routine, called with the argument it was given for it.
    let code = unsafe { (start.routine)(start.parameter) };
    endthreadex(code)
}

/// _beginthreadex: a thread that runs `routine(parameter)`, made with the caller's security
/// attributes, stack size and creation flags (CREATE_SUSPENDED: it waits for ResumeThread): its
/// handle, which the caller closes (the C runtime keeps none), its id stored at `id` when it is
/// given. The routine's answer is the thread's exit code, as `_endthreadex` gives it. 0 on
/// failure, errno and _doserrno set from the last error (EINVAL for no routine).
///
/// # Safety
///
/// `routine` is null or a thread routine that may be called with `parameter` on the new thread;
/// `security` is null or a SECURITY_ATTRIBUTES; `id` is null or a dword's storage.
#[unsafe(export_name = "f2k_export__beginthreadex")]
pub unsafe extern "C" fn beginthreadex(
    security: usize,
    stack_size: u32,
    routine: Option<ThreadRoutine>,
    parameter: usize,
    flags: u32,
    id: *mut u32,
) -> usize {
    /// ERROR_NOT_ENOUGH_MEMORY.
    const NOT_ENOUGH_MEMORY: u32 = 8;
    let Some(routine) = routine else {
        set_errno(EINVAL);
        return 0;
    };
    let block = crate::heap::allocate(core::mem::size_of::<Start>(), false).cast::<Start>();
    if block.is_null() {
        set_dos_error(NOT_ENOUGH_MEMORY);
        return 0;
    }
    // SAFETY: a fresh block of the C runtime's heap, a Start's size (its blocks are 8-aligned).
    unsafe { block.write(Start { routine, parameter }) };
    // SAFETY: thread_start takes the block, which holds the program's routine and its argument;
    // the security attributes are the caller's, which kernel32 reads.
    let made = unsafe {
        kernel32::create_thread(
            security,
            stack_size as usize,
            thread_start,
            block as usize,
            flags,
        )
    };
    match made {
        Ok((thread, thread_id)) => {
            if !id.is_null() {
                // SAFETY: the caller's dword.
                unsafe { id.write_unaligned(thread_id) };
            }
            thread
        }
        Err(error) => {
            // SAFETY: the block the thread never got, given back.
            unsafe { crate::heap::release(block.cast()) };
            set_dos_error(error.0);
            0
        }
    }
}

/// _endthreadex: the calling thread ends with `code` (ExitThread); its C runtime data is given
/// back at its DLL_THREAD_DETACH. The thread's handle stays open: its creator closes it.
#[unsafe(export_name = "f2k_export__endthreadex")]
pub extern "C" fn endthreadex(code: u32) -> ! {
    kernel32::exit_thread(code)
}

/// errno's values (errno.h).
pub const ENOENT: i32 = 2;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EEXIST: i32 = 17;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const EILSEQ: i32 = 42;

/// The calling thread's errno.
pub fn errno() -> i32 {
    with_data(|data| data.errno.load(Relaxed))
}

/// The calling thread's errno set.
pub fn set_errno(value: i32) {
    with_data(|data| data.errno.store(value, Relaxed));
}

/// The calling thread's _doserrno set.
pub fn set_doserrno(value: u32) {
    with_data(|data| data.doserrno.store(value, Relaxed));
}

/// The calling thread's errno and _doserrno set:`doserrno` and the errno a C program sees for it.
/// A system call's failure maps the Win32 error the way errno.h's values read: the files and paths
/// not found to ENOENT, too many open files to EMFILE, access denied to EACCES, a bad handle to
/// EBADF, no memory to ENOMEM, an existing file to EEXIST, a broken pipe to EPIPE, a full disk to
/// ENOSPC, a file that is no program to ENOEXEC (spawn's capture: _spawnl of a text file is errno
/// 8, _doserrno 193), anything else to EINVAL.
pub fn set_dos_error(doserrno: u32) {
    let errno = match doserrno {
        2 | 3 | 15 | 18 => ENOENT,
        4 => EMFILE,
        5 | 19 | 32 | 33 | 82 => EACCES,
        6 => EBADF,
        8 | 14 => ENOMEM,
        80 | 183 => EEXIST,
        109 => EPIPE,
        112 => ENOSPC,
        193 => ENOEXEC,
        _ => EINVAL,
    };
    with_data(|data| {
        data.errno.store(errno, Relaxed);
        data.doserrno.store(doserrno, Relaxed);
    });
}

/// _errno: the address of the calling thread's errno (errno.h's `errno` is `(*_errno())`).
#[unsafe(export_name = "f2k_export__errno")]
pub extern "C" fn errno_address() -> *mut i32 {
    with_data(|data| data.errno.as_ptr())
}

/// __doserrno: the address of the calling thread's _doserrno (stdlib.h's `_doserrno` is
/// `(*__doserrno())`).
#[unsafe(export_name = "f2k_export___doserrno")]
pub extern "C" fn doserrno_address() -> *mut u32 {
    with_data(|data| data.doserrno.as_ptr())
}

/// A lock of the C runtime's: a critical section, entered through kernel32's EnterCriticalSection
/// (msvcrt imports kernel32 alone, as Windows 2000's does). It is recursive: its holder may take it
/// again. kernel32's InitializeCriticalSection prepares it on its first use, under the lock of the
/// locks ([`ROOT`]).
pub struct Lock {
    section: CriticalSection,
    /// Whether InitializeCriticalSection has run on the section: set once, after it has.
    ready: AtomicBool,
}

impl Lock {
    pub const fn new() -> Lock {
        Lock {
            section: unprepared(),
            ready: AtomicBool::new(false),
        }
    }

    /// The lock taken, until the guard is dropped: for a lock that guards no value of its own (a
    /// descriptor's, held across its reads and writes).
    pub fn hold(&self) -> Held<'_> {
        self.lock();
        Held(self)
    }

    /// `body` run with the lock taken, which is let go when `body` returns or when an exception
    /// unwinds out of it: for a lock held while the caller's memory is read or written.
    pub fn holding<R>(&self, body: impl FnOnce() -> R) -> R {
        self.lock();
        let answer = unwind::on_unwind(&|| self.unlock(), body);
        self.unlock();
        answer
    }

    /// The section initialized, once, before its first enter.
    fn prepare(&self) {
        if self.ready.load(Acquire) {
            return;
        }
        kernel32::enter_critical_section(&ROOT);
        if !self.ready.load(Relaxed) {
            kernel32::initialize_critical_section(&self.section);
            self.ready.store(true, Release);
        }
        kernel32::leave_critical_section(&ROOT);
    }
}

impl Default for Lock {
    fn default() -> Lock {
        Lock::new()
    }
}

// SAFETY: EnterCriticalSection returns once the calling thread owns the section, which no other
// thread owns until the owner's last LeaveCriticalSection (each enter matched by a leave), and its
// interlocked operations order one owner's accesses before the next's. `prepare` initializes the
// section before the first enter, publishing it (Release, read with Acquire) to every thread.
unsafe impl RawLock for Lock {
    fn lock(&self) {
        self.prepare();
        kernel32::enter_critical_section(&self.section);
    }

    fn unlock(&self) {
        kernel32::leave_critical_section(&self.section);
    }
}

/// A taking of a [`Lock`], let go when dropped.
pub struct Held<'a>(&'a Lock);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        self.0.unlock();
    }
}

/// A lock of the C runtime's for state a call holds while it reads or writes its caller's memory:
/// a [`Lock`] whose `rtl::sync::Locked` value is let go, the lock with it, when an exception
/// unwinds out of the closure ([`crate::unwind`]).
pub struct UnwindLock(Lock);

impl UnwindLock {
    pub const fn new() -> UnwindLock {
        UnwindLock(Lock::new())
    }
}

impl Default for UnwindLock {
    fn default() -> UnwindLock {
        UnwindLock::new()
    }
}

// SAFETY: `Lock`'s, for taking and letting go. `on_unwind` runs `body` once, and calls `release`
// only from its registration's handler, while an exception's unwind passes the call: `body`'s
// frames are then being abandoned, never to resume (the host tests' panic stands in for it, and
// its drops find the value given back already).
unsafe impl RawLock for UnwindLock {
    fn lock(&self) {
        self.0.lock();
    }

    fn unlock(&self) {
        self.0.unlock();
    }

    fn on_abandon<R>(&self, release: &dyn Fn(), body: impl FnOnce() -> R) -> R {
        unwind::on_unwind(release, body)
    }
}

/// A CRITICAL_SECTION's storage before InitializeCriticalSection: zero.
const fn unprepared() -> CriticalSection {
    CriticalSection {
        debug_info: AtomicU32::new(0),
        lock_count: AtomicI32::new(0),
        recursion_count: AtomicI32::new(0),
        owning_thread: AtomicU32::new(0),
        lock_semaphore: AtomicU32::new(0),
        spin_count: AtomicU32::new(0),
    }
}

#[cfg(test)]
mod tests {
    use rtl::sync::Locked;

    use super::*;

    /// __doserrno and _errno address the calling thread's data: _doserrno beside errno, where
    /// set_dos_error writes it.
    #[test]
    fn doserrno_is_beside_errno() {
        with_data(|data| {
            assert_eq!(errno_address(), data.errno.as_ptr());
            assert_eq!(doserrno_address(), data.doserrno.as_ptr());
        });
        assert_eq!(
            doserrno_address() as usize - errno_address() as usize,
            4,
            "the second dword"
        );
    }

    /// An exception unwinding out of the closure of a value behind an [`UnwindLock`] (a panic, on
    /// the host) lets the lock go and the value with it: the same thread takes it again at once,
    /// and so does another.
    #[test]
    fn an_unwind_lets_a_guarded_value_go() {
        static STATE: Locked<u32, UnwindLock> = Locked::new(UnwindLock::new(), 0);
        let unwound = std::panic::catch_unwind(|| {
            STATE.with(|value| {
                *value = 7;
                panic!("a fault in the caller's memory");
            })
        });
        assert!(unwound.is_err());
        assert_eq!(
            STATE.with(|value| *value),
            7,
            "taken again, the busy flag clear"
        );
        let other = std::thread::spawn(|| STATE.with(|value| *value + 1));
        assert_eq!(other.join().unwrap(), 8, "let go: another thread takes it");
        assert!(!crate::imports::host::holds_a_section());
    }

    /// The same for a lock held across the caller's memory.
    #[test]
    fn an_unwind_lets_a_held_lock_go() {
        static LOCK: Lock = Lock::new();
        let unwound = std::panic::catch_unwind(|| LOCK.holding(|| panic!("a fault")));
        assert!(unwound.is_err());
        assert!(!crate::imports::host::section_held(&LOCK.section));
        assert_eq!(LOCK.holding(|| 5), 5);
        assert!(!crate::imports::host::section_held(&LOCK.section));
    }

    /// A lock is recursive, and taken by one thread at a time.
    #[test]
    fn a_lock_is_recursive_and_exclusive() {
        use std::sync::atomic::AtomicU32;
        static LOCK: Lock = Lock::new();
        static INSIDE: AtomicU32 = AtomicU32::new(0);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..200 {
                        let _outer = LOCK.hold();
                        let _inner = LOCK.hold();
                        assert_eq!(INSIDE.fetch_add(1, Relaxed), 0);
                        std::thread::yield_now();
                        INSIDE.fetch_sub(1, Relaxed);
                    }
                });
            }
        });
    }
}
