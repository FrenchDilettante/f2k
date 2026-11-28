//! The host tests' process and threads: a PEB, process parameters and TEB laid out as the kernel
//! lays them out, and the thread and process information services over a small model of the
//! kernel's records (the rules `kernel/src/nt/thread.rs` and `nt/process.rs` apply).

use std::cell::{Cell, RefCell};

use super::host::{failure, VIRTUAL_SIZE};

/// The pseudo-handles: the current process (-1) and the current thread (-2).
pub const CURRENT_PROCESS: u32 = 0xFFFF_FFFF;
pub const CURRENT_THREAD: u32 = 0xFFFF_FFFE;
/// A second thread's handle, and one naming an ended thread.
pub const THREAD: u32 = 0x48;
pub const ENDED_THREAD: u32 = 0x4C;

/// The process's stand-in blocks, rtl's (what `rtl::sys` reads on the host).
pub use rtl::host::{counted, process, COMMAND_LINE, IMAGE_BASE, IMAGE_PATH};
use rtl::status::{
    STATUS_INFO_LENGTH_MISMATCH,
    STATUS_INVALID_HANDLE,
    STATUS_INVALID_INFO_CLASS,
    STATUS_INVALID_PARAMETER,
    STATUS_SUSPEND_COUNT_EXCEEDED,
    STATUS_THREAD_IS_TERMINATING,
    STATUS_UNSUCCESSFUL,
};

/// A thread as the stand-ins keep it.
#[derive(Clone, Copy, Debug)]
pub struct HostThread {
    pub exit_status: u32,
    pub priority: i32,
    /// The base priority's increment, the saturation value (±16) when pinned.
    pub base: i32,
    pub disable_boost: bool,
    pub suspend_count: u32,
    pub ended: bool,
}

const LIVE: HostThread = HostThread {
    exit_status: 259,
    priority: 8,
    base: 0,
    disable_boost: false,
    suspend_count: 0,
    ended: false,
};

std::thread_local! {
    /// The threads, by handle: the current one, another, and one that ended with 7.
    pub static THREADS: RefCell<std::vec::Vec<(u32, HostThread)>> = RefCell::new(std::vec![
        (CURRENT_THREAD, LIVE),
        (THREAD, LIVE),
        (ENDED_THREAD, HostThread { exit_status: 7, ended: true, ..LIVE }),
    ]);
    /// The process's hard-error mode (1 at its start) and priority class (2, normal).
    pub static HARD_ERROR_MODE: Cell<u32> = const { Cell::new(1) };
    pub static PRIORITY_CLASS: Cell<u8> = const { Cell::new(2) };
    /// The TLS indexes ThreadZeroTlsCell was asked to clear.
    pub static ZEROED_TLS: RefCell<std::vec::Vec<u32>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// The thread `handle` names, changed by `change`; STATUS_INVALID_HANDLE for no thread.
fn with_thread<R>(handle: u32, change: impl FnOnce(&mut HostThread) -> R) -> Result<R, u32> {
    THREADS.with(|threads| {
        let mut threads = threads.borrow_mut();
        let thread = threads
            .iter_mut()
            .find(|(h, _)| *h == handle)
            .ok_or(STATUS_INVALID_HANDLE)?;
        Ok(change(&mut thread.1))
    })
}

/// A stand-in's answer: its status, or the arranged failure.
fn answer(result: Result<(), u32>) -> u32 {
    result.err().unwrap_or(0)
}

/// A thread NtCreateThread made: its access, whether its handle is inheritable, its process,
/// its CONTEXT's words, its stack, and whether it was made suspended.
#[derive(Clone, Debug)]
pub struct Created {
    pub access: u32,
    pub inherit: bool,
    pub process: u32,
    pub context: std::vec::Vec<u32>,
    pub stack: crate::thread::InitialTeb,
    pub suspended: bool,
}

/// The process's own id.
pub const PROCESS_ID: usize = 8;
/// The handle and thread id the next created thread gets.
pub const CREATED_THREAD: u32 = 0x60;
pub const CREATED_ID: usize = 0x24;

std::thread_local! {
    /// The threads NtCreateThread made.
    pub static CREATED: RefCell<std::vec::Vec<Created>> = const { RefCell::new(std::vec::Vec::new()) };
    /// The NtTerminateThread and NtTerminateProcess calls: the handle and the status.
    pub static TERMINATED: RefCell<std::vec::Vec<(&'static str, u32, u32)>> = const { RefCell::new(std::vec::Vec::new()) };
    /// The status the next NtCreateThread fails with (0: it succeeds).
    pub static CREATE_FAILS: Cell<u32> = const { Cell::new(0) };
}

/// NtCreateThread: the thread recorded (a created-suspended one with its suspend count), its
/// handle and client id written back.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "system" fn NtCreateThread(
    handle: *mut u32,
    access: u32,
    attributes: *const super::ObjectAttributes,
    process: u32,
    client_id: *mut usize,
    context: *const u32,
    initial_teb: *const crate::thread::InitialTeb,
    create_suspended: u32,
) -> u32 {
    if let Some(status) = failure()
        .or(Some(CREATE_FAILS.with(|fails| fails.replace(0))).filter(|&status| status != 0))
    {
        return status;
    }
    // SAFETY: the caller's structures.
    let (inherit, context, stack) = unsafe {
        (
            attributes
                .as_ref()
                .is_some_and(|attributes| attributes.attributes & 2 != 0),
            std::slice::from_raw_parts(context, crate::thread::CONTEXT_WORDS).to_vec(),
            *initial_teb,
        )
    };
    let suspended = create_suspended != 0;
    CREATED.with(|created| {
        created.borrow_mut().push(Created {
            access,
            inherit,
            process,
            context,
            stack,
            suspended,
        })
    });
    THREADS.with(|threads| {
        threads.borrow_mut().push((
            CREATED_THREAD,
            HostThread {
                suspend_count: u32::from(suspended),
                ..LIVE
            },
        ))
    });
    // SAFETY: the caller's out values.
    unsafe {
        handle.write(CREATED_THREAD);
        client_id.write(if process == super::children::CHILD_PROCESS {
            super::children::CHILD_ID
        } else {
            PROCESS_ID
        });
        client_id.add(1).write(CREATED_ID);
    }
    0
}

/// NtTerminateThread: recorded; an ended thread is STATUS_INVALID_PARAMETER, a handle naming
/// no thread STATUS_INVALID_HANDLE (a null handle, the caller, is taken).
pub unsafe extern "system" fn NtTerminateThread(thread: u32, status: u32) -> u32 {
    TERMINATED.with(|terminated| terminated.borrow_mut().push(("thread", thread, status)));
    if thread == 0 {
        return 0;
    }
    answer(
        with_thread(thread, |thread| {
            if thread.ended {
                return Err(STATUS_INVALID_PARAMETER);
            }
            thread.ended = true;
            thread.exit_status = status;
            Ok(())
        })
        .and_then(|result| result),
    )
}

/// NtTerminateProcess: recorded; the current process (or a null handle) and a child
/// ([`super::children`]: ended with the status) are reachable.
pub unsafe extern "system" fn NtTerminateProcess(process: u32, status: u32) -> u32 {
    TERMINATED.with(|terminated| terminated.borrow_mut().push(("process", process, status)));
    if process == 0 || process == CURRENT_PROCESS {
        0
    } else if super::children::is_child(process) {
        super::children::terminate(status)
    } else {
        STATUS_INVALID_HANDLE
    }
}

pub unsafe extern "system" fn LdrShutdownThread() -> u32 {
    0
}

pub unsafe extern "system" fn LdrShutdownProcess() -> u32 {
    0
}

std::thread_local! {
    /// Each thread's CONTEXT as NtSetContextThread last left it (all zero before), by handle.
    pub static CONTEXTS: RefCell<std::vec::Vec<(u32, rtl::seh::Context)>> =
        const { RefCell::new(std::vec::Vec::new()) };
}

/// The stand-in's thread context services: a thread that has ended has no context
/// (STATUS_UNSUCCESSFUL), a handle naming no thread none either (STATUS_INVALID_HANDLE).
fn live_thread(thread: u32) -> Result<(), u32> {
    with_thread(thread, |thread| thread.ended).and_then(|ended| {
        if ended {
            Err(STATUS_UNSUCCESSFUL)
        } else {
            Ok(())
        }
    })
}

pub unsafe extern "system" fn NtGetContextThread(thread: u32, context: *mut u8) -> u32 {
    use rtl::pod::Pod;
    if let Some(status) = failure() {
        return status;
    }
    answer(live_thread(thread).map(|()| {
        // SAFETY: the caller's CONTEXT.
        let context = unsafe { &mut *context.cast::<rtl::seh::Context>() };
        let flags = context.context_flags;
        *context = CONTEXTS.with(|contexts| {
            let contexts = contexts.borrow();
            contexts
                .iter()
                .find(|(handle, _)| *handle == thread)
                .map_or_else(rtl::seh::Context::zeroed, |&(_, context)| context)
        });
        context.context_flags = flags;
    }))
}

pub unsafe extern "system" fn NtSetContextThread(thread: u32, context: *const u8) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    answer(live_thread(thread).map(|()| {
        // SAFETY: the caller's CONTEXT.
        let context = unsafe { *context.cast::<rtl::seh::Context>() };
        CONTEXTS.with(|contexts| {
            let mut contexts = contexts.borrow_mut();
            contexts.retain(|(handle, _)| *handle != thread);
            contexts.push((thread, context));
        });
    }))
}

pub unsafe extern "system" fn NtSuspendThread(thread: u32, previous: *mut u32) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    answer(
        with_thread(thread, |thread| {
            if thread.ended {
                return Err(STATUS_THREAD_IS_TERMINATING);
            }
            if thread.suspend_count == 127 {
                return Err(STATUS_SUSPEND_COUNT_EXCEEDED);
            }
            // SAFETY: the caller's count, when given.
            unsafe {
                previous
                    .as_mut()
                    .map(|previous| *previous = thread.suspend_count)
            };
            thread.suspend_count += 1;
            Ok(())
        })
        .and_then(|result| result),
    )
}

pub unsafe extern "system" fn NtResumeThread(thread: u32, previous: *mut u32) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    answer(with_thread(thread, |thread| {
        // SAFETY: the caller's count, when given.
        unsafe {
            previous
                .as_mut()
                .map(|previous| *previous = thread.suspend_count)
        };
        thread.suspend_count = thread.suspend_count.saturating_sub(1);
    }))
}

pub unsafe extern "system" fn NtQueryInformationThread(
    thread: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    _returned: *mut u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    let size = match class {
        0 => 28,
        1 => 32,
        14 => 4,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if length != size {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    answer(with_thread(thread, |thread| {
        let words: &[u32] = match class {
            0 => &[
                thread.exit_status,
                process().teb as usize as u32,
                8,
                12,
                1,
                thread.priority as u32,
                thread.base as u32,
            ],
            // The times: created at 1, not ended, a tick of kernel time and two of user time.
            1 => &[1, 0, 0, 0, 100_144, 0, 200_288, 0],
            _ => &[u32::from(thread.disable_boost)],
        };
        for (at, word) in words.iter().enumerate() {
            // SAFETY: the caller's structure, `length` bytes.
            unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
        }
    }))
}

pub unsafe extern "system" fn NtSetInformationThread(
    thread: u32,
    class: u32,
    information: *const u8,
    length: u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    if ![2, 3, 4, 10, 14].contains(&class) {
        return STATUS_INVALID_INFO_CLASS;
    }
    if length != 4 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: the caller's value.
    let value = unsafe { (information as *const u32).read_unaligned() };
    match class {
        3 => {
            if !matches!(value as i32, -2..=2 | 16 | -16) {
                return STATUS_INVALID_PARAMETER;
            }
            answer(with_thread(thread, |thread| thread.base = value as i32))
        }
        10 => {
            if thread != CURRENT_THREAD || value >= 1088 {
                return STATUS_INVALID_PARAMETER;
            }
            ZEROED_TLS.with(|zeroed| zeroed.borrow_mut().push(value));
            if value < 64 {
                crate::base::set_tls_slot(value as usize, 0);
            } else {
                let expansion = crate::base::tls_expansion_slots();
                if !expansion.is_null() {
                    // SAFETY: the stand-in thread's expansion slots, 1024 of them.
                    unsafe { expansion.add(value as usize - 64).write(0) };
                }
            }
            0
        }
        14 => answer(with_thread(thread, |thread| {
            thread.disable_boost = value != 0
        })),
        _ => answer(with_thread(thread, |_| ())),
    }
}

pub unsafe extern "system" fn NtQueryInformationProcess(
    process: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    _returned: *mut u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    if super::children::is_child(process) {
        // SAFETY: the caller's structure, `length` bytes.
        return unsafe { super::children::query(class, information, length) };
    }
    if process != CURRENT_PROCESS {
        return STATUS_INVALID_HANDLE;
    }
    let words: std::vec::Vec<u32> = match (class, length) {
        (0, 24) => std::vec![
            259,
            self::process().peb as usize as u32,
            1,
            8,
            PROCESS_ID as u32,
            4
        ],
        (3, 44) => {
            let mut counters = std::vec![0; 11];
            counters[..2].copy_from_slice(&[VIRTUAL_SIZE, VIRTUAL_SIZE]);
            counters
        }
        (12, 4) => std::vec![HARD_ERROR_MODE.with(Cell::get)],
        (18, 2) => {
            // SAFETY: the caller's PROCESS_PRIORITY_CLASS.
            unsafe {
                information
                    .cast::<[u8; 2]>()
                    .write([0, PRIORITY_CLASS.with(Cell::get)])
            };
            return 0;
        }
        (0 | 3 | 12 | 18, _) => return STATUS_INFO_LENGTH_MISMATCH,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    for (at, word) in words.iter().enumerate() {
        // SAFETY: the caller's structure, `length` bytes.
        unsafe { (information as *mut u32).add(at).write_unaligned(*word) };
    }
    0
}

pub unsafe extern "system" fn NtSetInformationProcess(
    process: u32,
    class: u32,
    information: *const u8,
    length: u32,
) -> u32 {
    if let Some(status) = failure() {
        return status;
    }
    let size = match class {
        12 | 21 => 4,
        18 => 2,
        _ => return STATUS_INVALID_INFO_CLASS,
    };
    if length != size {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: the caller's value, `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(information, length as usize) };
    if super::children::is_child(process) {
        return super::children::set(class, bytes);
    }
    if process != CURRENT_PROCESS {
        return STATUS_INVALID_HANDLE;
    }
    match class {
        12 => HARD_ERROR_MODE.with(|mode| mode.set(u32::from_le_bytes(bytes.try_into().unwrap()))),
        18 if (1..=6).contains(&bytes[1]) => PRIORITY_CLASS.with(|class| class.set(bytes[1])),
        21 if bytes == [1, 0, 0, 0] => {}
        _ => return STATUS_INVALID_PARAMETER,
    }
    0
}
