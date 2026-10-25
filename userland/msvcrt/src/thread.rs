//! The C runtime's per-thread data and its lock.
//!
//! Each thread has its own `errno`, `_doserrno` and rand seed, as the multithreaded C runtime keeps
//! them: a block from the C runtime's heap, found through a TLS slot the DLL allocates when it is
//! loaded, made on the thread's first need and freed at its DLL_THREAD_DETACH. Finding it keeps the
//! thread's last error as it was (TlsGetValue clears it), so a C runtime call never disturbs a
//! program's GetLastError.
//!
//! One critical section serializes the process-wide state: the descriptor table, the streams, the
//! exit-function table and the locale.

use crate::data::Global;
use crate::imports;

/// A thread's own C runtime state.
#[repr(C)]
pub struct ThreadData {
    /// `errno`.
    pub errno: i32,
    /// `_doserrno`: the Win32 error behind the last `errno` a system call set.
    pub doserrno: u32,
    /// rand's seed (srand's), 1 until the thread seeds it.
    pub seed: u32,
}

/// The TLS slot holding each thread's [`ThreadData`] (TLS_OUT_OF_INDEXES before the DLL's
/// initialization). Host tests never run the DLL's attach and run on many threads at once: they
/// start with the slot the host TlsAlloc stand-in hands out, so each test thread has its own data,
/// as each thread does on target (the shared [`FALLBACK`] would let one test's errno leak into
/// another's).
static SLOT: Global<u32> = Global::new(if cfg!(test) { HOST_SLOT } else { u32::MAX });

/// The slot the host TlsAlloc stand-in answers (`imports`' host stand-ins).
#[cfg(test)]
const HOST_SLOT: u32 = 1;
#[cfg(not(test))]
const HOST_SLOT: u32 = u32::MAX;

/// A thread's data while the slot or the heap fails it: errno and the seed still have a home.
static FALLBACK: Global<ThreadData> = Global::new(ThreadData {
    errno: 0,
    doserrno: 0,
    seed: 1,
});

/// The C runtime's lock: a CRITICAL_SECTION (24 bytes), initialized with the DLL.
static LOCK: Global<[usize; 8]> = Global::new([0; 8]);

/// The DLL's process attach: the TLS slot and the lock. False when the slot cannot be had.
pub fn initialize() -> bool {
    // SAFETY: kernel32's exports; the lock's storage is the DLL's own.
    unsafe {
        imports::InitializeCriticalSection(LOCK.get().cast());
        let slot = imports::TlsAlloc();
        SLOT.write(slot);
        slot != u32::MAX
    }
}

/// The calling thread's data, made on its first need.
pub fn data() -> *mut ThreadData {
    let slot = SLOT.read();
    if slot == u32::MAX {
        return FALLBACK.get();
    }
    // SAFETY: kernel32's exports; the block, the thread's own, from the C runtime's heap.
    unsafe {
        let error = imports::GetLastError();
        let mut data = imports::TlsGetValue(slot) as *mut ThreadData;
        if data.is_null() {
            data = crate::heap::allocate(core::mem::size_of::<ThreadData>(), true).cast();
            if data.is_null() || imports::TlsSetValue(slot, data as usize) == 0 {
                imports::SetLastError(error);
                return FALLBACK.get();
            }
            (*data).seed = 1;
        }
        imports::SetLastError(error);
        data
    }
}

/// A thread's DLL_THREAD_DETACH: its data given back.
pub fn detach_thread() {
    let slot = SLOT.read();
    if slot == u32::MAX {
        return;
    }
    // SAFETY: kernel32's exports; the block was the thread's alone.
    unsafe {
        let data = imports::TlsGetValue(slot) as *mut u8;
        if !data.is_null() {
            imports::TlsSetValue(slot, 0);
            crate::heap::release(data);
        }
    }
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
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
pub const EPIPE: i32 = 32;
pub const ERANGE: i32 = 34;

/// The calling thread's errno set.
pub fn set_errno(value: i32) {
    // SAFETY: the thread's own data.
    unsafe { (*data()).errno = value };
}

/// The calling thread's _doserrno set.
pub fn set_doserrno(value: u32) {
    // SAFETY: the thread's own data.
    unsafe { (*data()).doserrno = value };
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
    // SAFETY: the thread's own data.
    unsafe {
        let data = data();
        (*data).errno = errno;
        (*data).doserrno = doserrno;
    }
}

/// _errno: the address of the calling thread's errno (errno.h's `errno` is `(*_errno())`).
#[unsafe(export_name = "f2k_export__errno")]
pub extern "C" fn errno_address() -> *mut i32 {
    // SAFETY: the thread's own data; errno is its first field.
    unsafe { core::ptr::addr_of_mut!((*data()).errno) }
}

/// __doserrno: the address of the calling thread's _doserrno (stdlib.h's `_doserrno` is
/// `(*__doserrno())`).
#[unsafe(export_name = "f2k_export___doserrno")]
pub extern "C" fn doserrno_address() -> *mut u32 {
    // SAFETY: the thread's own data.
    unsafe { core::ptr::addr_of_mut!((*data()).doserrno) }
}

/// The C runtime's lock, held for the guard's life (it is recursive: a thread may take it again).
pub struct Locked(());

impl Locked {
    pub fn take() -> Locked {
        // SAFETY: kernel32's export, over the DLL's own critical section.
        unsafe { imports::EnterCriticalSection(LOCK.get().cast()) };
        Locked(())
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: as above; the guard took it.
        unsafe { imports::LeaveCriticalSection(LOCK.get().cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// __doserrno and _errno address the calling thread's data: _doserrno beside errno, where
    /// set_dos_error writes it.
    #[test]
    fn doserrno_is_beside_errno() {
        let data = data();
        // SAFETY: the thread's own data.
        unsafe {
            assert_eq!(errno_address(), core::ptr::addr_of_mut!((*data).errno));
            assert_eq!(
                doserrno_address(),
                core::ptr::addr_of_mut!((*data).doserrno)
            );
        }
        assert_eq!(
            doserrno_address() as usize - errno_address() as usize,
            4,
            "the second dword"
        );
    }
}
