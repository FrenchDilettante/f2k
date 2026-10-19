//! kernel32's kernel-served exports: the transitional Win32 services behind kernel32.dll's stubs.
//!
//! kernel32.dll is a real DLL (userland/kernel32, mapped into every process: `exec::modules`). Its
//! exports are generated service stubs, each raising the gate on its service number with the
//! caller's arguments; this module holds the services they reach, the registry the gate dispatches
//! through ([`SERVICES`], generated from the export specs, userland/<dll>/exports.toml), and the
//! replays they answer from. The heap group answers from a genuine allocator (`userheap`),
//! never-called imports from safe minimal floors. Each increment moves a group to user mode and
//! deletes its services here (the console and the start-up calls are kernel32's own code now, over
//! the console server, `crate::csr`, and the PEB, `user::teb`; the locale group, the clocks and the
//! system messages too, over `rtl::codepage` and the shared data page, `user::shared`).

use crate::fs::file::SeekMethod;
use crate::user::syscall::{read_user, write_user, ServiceFn};
use crate::user::PARAMS_PAGE;

// --- Replay data (captured on a real Windows 2000 SP4 machine) ------

const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;
/// SetFilePointer's failure return.
const INVALID_SET_FILE_POINTER: u32 = 0xFFFF_FFFF;
/// CreateFileA's read access right.
const GENERIC_READ: u32 = 0x8000_0000;
/// CreateFileA's open-an-existing-file disposition.
const OPEN_EXISTING: u32 = 3;
/// CreateFileA's overlapped-I/O flag.
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// The ANSI path limit, terminator included.
const MAX_PATH: usize = 260;

// --- Services -------------------------------------------------------

/// ExitProcess: end the process, carrying the exit code.
fn svc_exit_process(_frame: &mut crate::user::TrapFrame, args: &[u32]) {
    crate::user::process_exited(args[0])
}

/// Whether `handle` is a console handle: Windows 2000 kernel32's `CONSOLE_HANDLE` test (low two
/// bits set, bit 28 clear — so INVALID_HANDLE_VALUE is not one). Console handles are routed to the
/// console, never decoded as object-table handles: the table ignores the low tag bits, so without
/// this rule stdout would name a table slot.
fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
}

/// The object `handle` names when it is of `kind`, referenced for the caller's scope; none for a
/// console handle, a handle naming nothing or another kind of object, or an open file (Windows
/// reports them alike, an invalid handle).
#[cfg(target_arch = "x86")]
fn referenced(handle: u32, kind: crate::ob::ObjectType) -> Option<crate::ob::ObRef> {
    if is_console_handle(handle) {
        return None;
    }
    crate::ob::reference_by_handle(handle, Some(kind))
}

/// The thread a handle names, referenced for the caller's scope.
#[cfg(target_arch = "x86")]
fn thread_of(handle: u32) -> Option<crate::ob::Referenced<crate::sched::thread::Thread>> {
    let reference = referenced(handle, crate::ob::ObjectType::Thread)?;
    let record = reference.thread();
    Some(crate::ob::Referenced::new(reference, record))
}

/// GetEnvironmentStringsW: a pointer to the (empty) wide environment block the process parameters
/// point at (`user::params::ENVIRONMENT_BUFFER`).
fn svc_get_environment_strings_w(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = PARAMS_PAGE + crate::user::params::ENVIRONMENT_BUFFER;
}

/// GetEnvironmentStrings (A variant): report failure. The CRT calls the W variant first and never
/// needs this fallback.
fn svc_get_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

/// FreeEnvironmentStringsA/W: nothing to free, report success. Quirk: the CRT frees the W block
/// through the A entry.
fn svc_free_environment_strings(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 1;
}

// Heap services: the genuine allocator lives in `userheap`.

/// HeapCreate: reset and report the heap handle. Flags and sizes are recorded by nothing — the CRT
/// trusts the handle.
fn svc_heap_create(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = crate::user::userheap::create();
}

/// HeapAlloc: serve (or zero-serve) from the heap region.
fn svc_heap_alloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::alloc(args[1], args[2] as usize);
}

/// HeapFree: validate and coalesce.
fn svc_heap_free(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::free(args[2]);
}

/// HeapReAlloc: grow by allocate-copy-free, zeroing the extension when asked.
fn svc_heap_realloc(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] != crate::user::userheap::HEAP_HANDLE {
        frame.eax = 0;
        return;
    }
    frame.eax = crate::user::userheap::realloc(args[2], args[1], args[3] as usize);
}

/// HeapDestroy: accept the handle, reset the region.
fn svc_heap_destroy(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = crate::user::userheap::destroy(args[0]);
}

/// INFINITE: the documented forever timeout.
const INFINITE: u32 = 0xFFFF_FFFF;

/// CREATE_SUSPENDED: the creation flag that starts the thread with a suspend count of one.
const CREATE_SUSPENDED: u32 = 0x0000_0004;

/// The sleep interval conversion: INFINITE is not a wait at all but the longest relative interval
/// the ABI can name — the delay parks for a due time on the far side of the clock. Every other
/// value is milliseconds to 100 ns units.
fn sleep_interval(milliseconds: u32) -> i64 {
    if milliseconds == INFINITE {
        i64::MIN
    } else {
        milliseconds as i64 * 10_000
    }
}

/// The SetThreadPriority value conversion: the five band values (-2..2) are base-priority
/// increments and pass straight through; the two edge specials name the class saturation pins
/// instead. Any other value is not a documented priority, and the call fails.
fn thread_priority_increment(value: i32) -> Option<i32> {
    const TIME_CRITICAL: i32 = 15;
    const IDLE: i32 = -15;
    const SATURATION: i32 = 16;
    match value {
        -2..=2 => Some(value),
        TIME_CRITICAL => Some(SATURATION),
        IDLE => Some(-SATURATION),
        _ => None,
    }
}

/// Sleep: park the calling thread for the requested milliseconds — the delay discipline on the
/// caller's own timer, in the timer table. Zero is the pure yield (the immediate test); INFINITE
/// parks for the longest interval the ABI names. The return is void; the delay's resume-side
/// conversion makes a timed-out sleep a successful one, and 0 rides in `eax`.
fn svc_sleep(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let interval = sleep_interval(args[0]);
        // The delay runs through the shared blocking entry: a kernel APC breaks the sleep and the
        // entry replays it with the remaining time — the wake time never slips.
        let status = crate::sched::wait::wait_current_with(|dispatcher, thread, stamp, replay| {
            let interval = if replay {
                crate::sched::wait::replay_interval(thread.timer.due_time, stamp.interrupt_time)
            } else {
                interval
            };
            dispatcher.delay(
                thread,
                crate::sched::wait::WaitMode::User,
                false,
                interval,
                stamp,
            )
        });
        frame.eax = crate::sched::dispatcher::Dispatcher::delay_completed(status) as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// CreateThread: a child thread on the current process. The start address and parameter are
/// honored, and CREATE_SUSPENDED starts the thread suspended (a ResumeThread lets it run); the
/// attributes, stack size (the per-thread default), and every other creation flag are ignored. The
/// identifier is written back only when the caller asked for it. The handle exists before the
/// thread is made schedulable, so the creator can always wait on what it created.
fn svc_create_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (_attributes, stack_size, start, parameter, flags, thread_id_out) =
            (args[0], args[1], args[2], args[3], args[4], args[5]);
        // Every refusal comes before the spawn: once a thread record is attached to the process
        // and its stacks are mapped, there is no unwinding it, so the create must not fail after.
        // A full handle table, or an identifier pointer the probe refuses, fails it here. (A
        // pointer that passes the probe but names no page faults in the write below, which
        // ends the whole process: nothing is left half-created for it to observe.)
        let process = crate::process::current_mut();
        if process.handles().is_full()
            || (thread_id_out != 0
                && crate::user::syscall::probe_user_range(thread_id_out, 4).is_err())
        {
            frame.eax = 0;
            return;
        }
        let Some((object, thread, id)) = crate::process::threads::spawn(process, start, parameter, stack_size)
        else {
            frame.eax = 0;
            return;
        };
        // The handle joins the thread's own reference (which its end releases).
        let handle = crate::ob::open(process, object, crate::ob::THREAD_ALL_ACCESS, false);
        assert_ne!(handle, 0, "the table had a free slot before the spawn");
        if thread_id_out != 0 {
            let written = crate::user::syscall::write_user(thread_id_out, &id.to_le_bytes());
            assert!(written.is_ok(), "the identifier pointer passed the probe");
        }
        let dispatcher = crate::sched::idle::dispatcher();
        if flags & CREATE_SUSPENDED != 0 {
            // The suspend APC queues on the never-run thread; its startup delivers it before the
            // first user instruction, parking it until a resume. A fresh thread is never at the
            // count's maximum nor terminating, so the suspend cannot be refused.
            // SAFETY: the created thread, live and exclusive here.
            let suspended = dispatcher.suspend_thread(unsafe { &mut *thread });
            assert_eq!(suspended, Ok(0), "a fresh thread suspends");
        }
        // The handle exists; the thread becomes schedulable now.
        // SAFETY: the created thread, live and exclusive here.
        dispatcher.make_ready(unsafe { &mut *thread });
        frame.eax = handle;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetThreadPriority: set a thread's base-priority increment from its process's base. The handle
/// must name a thread; the value is the increment conversion (the band values, or one of the two
/// saturation specials). The kernel's base-priority machinery requeues, boosts, or preempts as the
/// thread's state requires — a raised Ready thread requests the processor, and the service boundary
/// delivers the request before the caller returns. The return is the documented success boolean.
fn svc_set_thread_priority(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let (handle, value) = (args[0], args[1] as i32);
        let Some(increment) = thread_priority_increment(value) else {
            frame.eax = 0;
            return;
        };
        let Some(mut thread) = thread_of(handle) else {
            frame.eax = 0;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        dispatcher.set_base_priority(&mut thread, increment);
        frame.eax = 1;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = 0;
    }
}

/// SetFilePointer: move a file handle's position `lDistanceToMove` (signed) bytes from the start,
/// the current position, or the end, and return the new position. Past the end is legal; a target
/// before the start, a bad move method, and any handle that names no open file return
/// INVALID_SET_FILE_POINTER. The high-word pointer is accepted and ignored: positions are 32-bit.
fn svc_set_file_pointer(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, distance, _distance_high, method) = (args[0], args[1] as i32, args[2], args[3]);
    frame.eax = match (SeekMethod::from_raw(method), open_file(handle)) {
        (Some(method), Some(file)) => file
            .seek(distance, method)
            .unwrap_or(INVALID_SET_FILE_POINTER),
        _ => INVALID_SET_FILE_POINTER,
    };
}

/// Count a NUL-terminated user string, terminator included; None on a bad range or a missing
/// terminator (capped).
fn walk_narrow(src: u32) -> Option<u32> {
    let mut len = 0u32;
    while len < 0x1_0000 {
        let mut byte = [0u8; 1];
        read_user(src + len, &mut byte).ok()?;
        if byte[0] == 0 {
            return Some(len + 1);
        }
        len += 1;
    }
    None
}

/// The open file a handle names in the current process; none for a console handle or any handle
/// that names no file.
#[cfg(target_arch = "x86")]
fn open_file(handle: u32) -> Option<&'static mut crate::fs::file::OpenFile> {
    if is_console_handle(handle) {
        return None;
    }
    crate::process::current_mut().file_mut(handle)
}

/// Host builds have no process: no handle names an open file.
#[cfg(not(target_arch = "x86"))]
fn open_file(_handle: u32) -> Option<&'static mut crate::fs::file::OpenFile> {
    None
}

/// Whether CreateFileA's request is one this read-only surface serves: read access to an existing
/// file, not overlapped. The share mode is not enforced, and the attribute bits matter only to a
/// creation, which is never one.
fn is_supported_open(access: u32, disposition: u32, flags: u32) -> bool {
    access == GENERIC_READ && disposition == OPEN_EXISTING && flags & FILE_FLAG_OVERLAPPED == 0
}

/// CreateFileA: open an existing file on the boot volume for reading. The path resolves as the
/// loader's does: root-relative, 8.3, case-folded, a drive prefix and leading backslashes dropped
/// (the boot volume is the only volume: GetModuleFileNameA's `C:\...` names the image). A new handle on success; INVALID_HANDLE_VALUE for
/// any other request, a path that does not resolve or names a directory, or a full table.
fn svc_create_file_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (name, access, _share, _security, disposition, flags, _template) = (
        args[0], args[1], args[2], args[3], args[4], args[5], args[6],
    );
    frame.eax = INVALID_HANDLE_VALUE;
    if !is_supported_open(access, disposition, flags) {
        return;
    }
    // The path is copied out of user memory before the volume is taken: a fault in the copy ends
    // the process, which must not happen while it holds the volume.
    let mut path = [0u8; MAX_PATH];
    let Some(length) = walk_narrow(name).map(|length| length as usize - 1) else {
        return;
    };
    if length >= MAX_PATH || read_user(name, &mut path[..length]).is_err() {
        return;
    }
    #[cfg(target_arch = "x86")]
    {
        let found = crate::fs::fat32::volume::with_boot_volume(|volume| {
            crate::fs::fat32::lookup::lookup(volume, crate::user::volume_path(&path[..length]))
        });
        if let Some(Ok(file)) = found {
            if !file.directory {
                let handle = crate::process::current_mut().open_file(file);
                if handle != 0 {
                    frame.eax = handle;
                }
            }
        }
    }
    #[cfg(not(target_arch = "x86"))]
    let _ = path;
}

/// The bounce chunk ReadFile moves file bytes through: read off the volume into the kernel, then
/// copied out to the caller once the volume is released.
const READ_CHUNK: usize = 512;

/// ReadFile: read from a file handle's position into the caller's buffer — what remains before the
/// end, at most the request — store the count moved, and advance the position. A read at or past
/// the end moves nothing and succeeds. Overlapped requests and every handle that names no open file
/// fail; a bad buffer or count pointer ends the process, not the kernel.
fn svc_read_file(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (handle, buffer, count, read_out, overlapped) =
        (args[0], args[1], args[2], args[3], args[4]);
    frame.eax = 0; // FALSE until the read completes
    if overlapped != 0 {
        return;
    }
    // A copy: the volume read blocks, and the record is not held across it.
    let Some(start) = open_file(handle).map(|open| *open) else {
        return;
    };
    let wanted = start.available(count);
    let mut moved = 0u32;
    while moved < wanted {
        let take = (wanted - moved).min(READ_CHUNK as u32) as usize;
        let mut chunk = [0u8; READ_CHUNK];
        let Some(got) = read_volume(&start.file, start.position + moved, &mut chunk[..take]) else {
            break;
        };
        if write_user(buffer.wrapping_add(moved), &chunk[..got]).is_err() {
            break;
        }
        moved += got as u32;
    }
    // The position advances by what reached the caller, so a failed read leaves it after the bytes
    // delivered. A handle closed meanwhile has no position left to advance.
    if let Some(open) = open_file(handle) {
        open.position = start.position + moved;
    }
    if read_out != 0 && write_user(read_out, &moved.to_le_bytes()).is_err() {
        return;
    }
    if moved == wanted {
        frame.eax = 1;
    }
}

/// Read `out.len()` bytes of `file` from `offset` off the boot volume; none when the volume is
/// missing or the read fails, or when it comes up short (the size said the bytes were there).
#[cfg(target_arch = "x86")]
fn read_volume(
    file: &crate::fs::fat32::lookup::File,
    offset: u32,
    out: &mut [u8],
) -> Option<usize> {
    let read = crate::fs::fat32::volume::with_boot_volume(|volume| {
        crate::fs::fat32::read::read_at(volume, file, offset, out)
    })?;
    read.ok().filter(|&got| got == out.len())
}

/// Host builds have no boot volume.
#[cfg(not(target_arch = "x86"))]
fn read_volume(
    _file: &crate::fs::fat32::lookup::File,
    _offset: u32,
    _out: &mut [u8],
) -> Option<usize> {
    None
}

/// SuspendThread: bump the target thread's suspend count and arm its builtin suspend APC — the
/// APC's delivery parks the thread on its suspend semaphore. The return is the previous suspend
/// count, or (DWORD)-1 for every refusal: a bad handle, a non-thread slot, an exited thread, or
/// the documented count maximum.
fn svc_suspend_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let Some(mut thread) = thread_of(args[0]) else {
            frame.eax = u32::MAX;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            frame.eax = u32::MAX;
            return;
        }
        match dispatcher.suspend_thread(&mut thread) {
            Ok(previous) => frame.eax = previous as u32,
            Err(_) => frame.eax = u32::MAX,
        }
        // A self-suspend's APC delivers at the service boundary below — the caller never reaches
        // user mode before its suspend APC runs.
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = u32::MAX;
    }
}

/// ResumeThread: release the suspend the count table decides — at one outstanding suspend the
/// semaphore releases and the parked thread wakes. The return is the previous suspend count (zero
/// for a thread nobody suspended), or (DWORD)-1 on the same refusal shape as SuspendThread.
fn svc_resume_thread(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    #[cfg(target_arch = "x86")]
    {
        let Some(mut thread) = thread_of(args[0]) else {
            frame.eax = u32::MAX;
            return;
        };
        let dispatcher = crate::sched::idle::dispatcher();
        if thread.state() == crate::sched::thread::ThreadState::Terminated {
            frame.eax = u32::MAX;
            return;
        }
        frame.eax = dispatcher.resume_thread(&mut thread) as u32;
    }
    #[cfg(not(target_arch = "x86"))]
    {
        let _ = args;
        frame.eax = u32::MAX;
    }
}

/// Floor for the never-called imports: zero, no side effects. (The export spec's floor kind; no
/// export is one.)
#[allow(dead_code)]
fn svc_floor_zero(frame: &mut crate::user::TrapFrame, _args: &[u32]) {
    frame.eax = 0;
}

// --- The registry ----------------------------------------------------

// The service registry: `WIN32_SERVICE_BASE`, and `SERVICES`, one (export, argument bytes,
// handler) entry per kernel-served export, in service-number order, generated from the export specs
// (userland/<dll>/exports.toml) by the build script. A floor's handler is `svc_floor_zero`; a
// legacy handler's path resolves in this module's scope.
include!(concat!(env!("OUT_DIR"), "/kernel32_services.rs"));

/// An export's service number (the base plus its registry position plus one), at build time: the
/// hand-assembled fault-test stubs patch theirs from here. A name the registry does not hold fails
/// the build.
pub const fn service_number(name: &str) -> u32 {
    let mut index = 0;
    while index < SERVICES.len() {
        if same_name(SERVICES[index].0.as_bytes(), name.as_bytes()) {
            return WIN32_SERVICE_BASE + index as u32 + 1;
        }
        index += 1;
    }
    panic!("no such export in the registry");
}

/// Byte equality, usable at build time.
const fn same_name(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut index = 0;
    while index < a.len() {
        if a[index] != b[index] {
            return false;
        }
        index += 1;
    }
    true
}

/// Look a transitional Win32 service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    let position = number.checked_sub(WIN32_SERVICE_BASE + 1)? as usize;
    let &(_, arg_bytes, service) = SERVICES.get(position)?;
    Some((arg_bytes, service))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry's numbering: ExitProcess is the first service (SYS_EXIT), the others follow it
    /// from the base; numbers outside the registry name no service; the names are unique.
    #[test]
    fn the_registry_numbers_from_its_base() {
        assert_eq!(
            SERVICES.len(),
            20,
            "kernel32's served surface, less its natives (the last error, the current process, \
             the console and start-up calls, the locale group and clock, the exception filter, \
             the virtual memory, the events and waits) and ntdll's RtlUnwind"
        );
        assert_eq!(WIN32_SERVICE_BASE, 0x2000);
        assert_eq!(SERVICES[0].0, "ExitProcess");
        assert_eq!(crate::user::syscall::SYS_EXIT, WIN32_SERVICE_BASE + 1);
        assert_eq!(
            service_number("ExitProcess"),
            crate::user::syscall::SYS_EXIT
        );
        for (i, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            let number = WIN32_SERVICE_BASE + i as u32 + 1;
            assert_eq!(service_number(name), number, "{name}");
            assert_eq!(lookup_service(number).map(|(b, _)| b), Some(arg_bytes));
            assert!(SERVICES[i + 1..].iter().all(|&(other, ..)| other != name));
        }
        for number in [
            0,
            1,
            51,
            WIN32_SERVICE_BASE,
            WIN32_SERVICE_BASE + 52,
            u32::MAX,
        ] {
            assert_eq!(lookup_service(number).map(|(b, _)| b), None, "{number:#x}");
        }
    }

    /// The registry keeps its order discipline: ExitProcess first, the rest alphabetical (ASCII
    /// case-insensitively, as the names were placed).
    #[test]
    fn the_registry_is_alphabetical_after_exit_process() {
        let names: Vec<String> = SERVICES
            .iter()
            .skip(1)
            .map(|&(name, ..)| name.to_ascii_lowercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
        let arg_bytes = |name: &str| SERVICES.iter().find(|&&(n, ..)| n == name).unwrap().1;
        assert_eq!(arg_bytes("CreateFileA"), 28);
        assert_eq!(arg_bytes("ReadFile"), 20);
    }

    /// CreateFileA serves exactly read access to an existing file, synchronously: another access
    /// mode, any other disposition, and an overlapped open are refused; the attribute bits pass.
    #[test]
    fn only_read_opens_of_existing_files_are_served() {
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const CREATE_ALWAYS: u32 = 2;
        const OPEN_ALWAYS: u32 = 4;
        const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
        assert!(is_supported_open(GENERIC_READ, OPEN_EXISTING, 0));
        assert!(is_supported_open(
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL
        ));
        assert!(!is_supported_open(GENERIC_WRITE, OPEN_EXISTING, 0));
        assert!(!is_supported_open(
            GENERIC_READ | GENERIC_WRITE,
            OPEN_EXISTING,
            0
        ));
        assert!(!is_supported_open(0, OPEN_EXISTING, 0));
        assert!(!is_supported_open(GENERIC_READ, CREATE_ALWAYS, 0));
        assert!(!is_supported_open(GENERIC_READ, OPEN_ALWAYS, 0));
        assert!(!is_supported_open(
            GENERIC_READ,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED
        ));
    }

    /// The file services' host-testable refusal shapes (the opens and reads themselves run on
    /// target): an unsupported open is INVALID_HANDLE_VALUE before the path is touched; a read is
    /// FALSE on an overlapped request or a handle naming no open file — console handles included;
    /// a seek on such a handle, or with a bad move method, is INVALID_SET_FILE_POINTER.
    #[test]
    fn file_service_refusal_shapes() {
        let mut frame = zero_frame();
        svc_create_file_a(
            &mut frame,
            &[0x0040_0000, 0x4000_0000, 1, 0, OPEN_EXISTING, 0, 0],
        );
        assert_eq!(frame.eax, INVALID_HANDLE_VALUE);
        frame.eax = 0;
        svc_create_file_a(&mut frame, &[0x0040_0000, GENERIC_READ, 1, 0, 2, 0, 0]);
        assert_eq!(frame.eax, INVALID_HANDLE_VALUE);

        frame.eax = 1;
        svc_read_file(&mut frame, &[4, 0x0040_0000, 2, 0, 0x0050_0000]);
        assert_eq!(frame.eax, 0, "overlapped");
        for handle in [4, 3, 7, INVALID_HANDLE_VALUE, 0] {
            frame.eax = 1;
            svc_read_file(&mut frame, &[handle, 0x0040_0000, 2, 0, 0]);
            assert_eq!(frame.eax, 0, "{handle:#x}");
            frame.eax = 0;
            svc_set_file_pointer(&mut frame, &[handle, 0x3C, 0, 0]);
            assert_eq!(frame.eax, INVALID_SET_FILE_POINTER, "{handle:#x}");
        }
        frame.eax = 0;
        svc_set_file_pointer(&mut frame, &[4, 0, 0, 3]);
        assert_eq!(frame.eax, INVALID_SET_FILE_POINTER, "bad move method");
    }

    /// The sleep interval conversion: milliseconds to 100 ns units, exact; INFINITE is the longest
    /// relative interval the ABI names, not a special kernel value.
    #[test]
    fn sleep_intervals_convert_exactly() {
        assert_eq!(sleep_interval(200), 2_000_000);
        assert_eq!(sleep_interval(100), 1_000_000);
        assert_eq!(sleep_interval(5), 50_000);
        assert_eq!(sleep_interval(0), 0);
        assert_eq!(sleep_interval(INFINITE), i64::MIN);
    }

    /// The SetThreadPriority value conversion: the five band values are increments and pass
    /// straight through; the two edge specials name the class saturation pins instead; every other
    /// value — the extremes included, which would overflow the increment arithmetic — is refused.
    #[test]
    fn thread_priority_values_convert_to_increments() {
        assert_eq!(thread_priority_increment(0), Some(0));
        assert_eq!(thread_priority_increment(1), Some(1));
        assert_eq!(thread_priority_increment(-1), Some(-1));
        assert_eq!(thread_priority_increment(2), Some(2));
        assert_eq!(thread_priority_increment(-2), Some(-2));
        assert_eq!(thread_priority_increment(15), Some(16));
        assert_eq!(thread_priority_increment(-15), Some(-16));
        for refused in [3, -3, 7, 14, 16, -16, i32::MAX, i32::MIN] {
            assert_eq!(thread_priority_increment(refused), None, "{refused}");
        }
    }

    /// The environment's replay pointer is the process parameters' empty block; the A variant
    /// reports failure; the W/A free pair succeeds.
    #[test]
    fn the_environment_replays_the_parameters_block() {
        let mut frame = zero_frame();
        svc_get_environment_strings_w(&mut frame, &[]);
        assert_eq!(
            frame.eax,
            PARAMS_PAGE + crate::user::params::ENVIRONMENT_BUFFER
        );
        svc_get_environment_strings(&mut frame, &[]);
        assert_eq!(frame.eax, 0);
        svc_free_environment_strings(&mut frame, &[0x0032_0040]);
        assert_eq!(frame.eax, 1);
    }

    /// The served shapes no path the corpus takes reaches answer with their decided values, and no
    /// export is a floor any more (UnhandledExceptionFilter is kernel32's code and RtlUnwind
    /// ntdll's).
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        let floor = |name: &str| SERVICES.iter().find(|&&(n, ..)| n == name).unwrap().2;
        assert!(SERVICES
            .iter()
            .all(|&(_, _, handler)| handler as usize != svc_floor_zero as usize));
        assert_eq!(
            floor("SetFilePointer") as usize,
            svc_set_file_pointer as usize
        );
        let mut frame = zero_frame();
        // A seek on a handle that names no open file fails honestly.
        svc_set_file_pointer(&mut frame, &[0; 4]);
        assert_eq!(frame.eax, 0xFFFF_FFFF); // INVALID_SET_FILE_POINTER

        // The floors report zero without side effects.
        svc_floor_zero(&mut frame, &[]);
        assert_eq!(frame.eax, 0);
    }

    /// The console tag: every replayed std handle carries it and object handles (multiples of four)
    /// never do, so the object services can route on it; INVALID_HANDLE_VALUE is not a console
    /// handle (the bit-28 mask).
    #[test]
    fn console_handles_are_told_apart_from_object_handles() {
        for handle in [3, 7, 0xB] {
            assert!(is_console_handle(handle), "{handle:#x}");
        }
        for handle in [4, 8, 12, 0x3C] {
            assert!(!is_console_handle(handle), "{handle:#x}");
        }
        assert!(!is_console_handle(INVALID_HANDLE_VALUE));
        assert!(!is_console_handle(0));
    }

    fn zero_frame() -> crate::user::TrapFrame {
        crate::user::TrapFrame {
            edi: 0,
            esi: 0,
            ebp: 0,
            esp: 0,
            ebx: 0,
            edx: 0,
            ecx: 0,
            eax: 0,
            vector: 0,
            error_code: 0,
            eip: 0,
            cs: 0,
            eflags: 0,
            user_esp: 0,
            user_ss: 0,
        }
    }
}
