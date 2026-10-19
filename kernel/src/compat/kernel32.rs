//! kernel32's kernel-served exports: the transitional Win32 services behind kernel32.dll's stubs.
//!
//! kernel32.dll is a real DLL (userland/kernel32, mapped into every process: `exec::modules`). Its
//! exports are generated service stubs, each raising the gate on its service number with the
//! caller's arguments; this module holds the services they reach, the registry the gate dispatches
//! through ([`SERVICES`], generated from the export specs, userland/<dll>/exports.toml), and the
//! replays they answer from. Each increment moves a group to user mode and deletes its services
//! here (the console and the start-up calls are kernel32's own code now, over the console server,
//! `crate::csr`, and the PEB, `user::teb`; the locale group, the clocks and the system messages
//! too, over `rtl::codepage` and the shared data page, `user::shared`; the heaps, Local/Global
//! memory and the environment are ntdll's and kernel32's user code over the process's own memory;
//! the threads and the process's end kernel32's code over ntdll's thread and process services; the
//! files' read side kernel32's over the NT file services, `nt::file`; the modules kernel32's over
//! ntdll's loader and the PEB's module lists, `user::ldr`). No export is served any more: the
//! registry is empty, its deletion to follow.

use crate::user::syscall::ServiceFn;

#[cfg(test)]
const INVALID_HANDLE_VALUE: u32 = 0xFFFF_FFFF;

// --- Services -------------------------------------------------------

/// Whether `handle` is a console handle: Windows 2000 kernel32's `CONSOLE_HANDLE` test (low two
/// bits set, bit 28 clear — so INVALID_HANDLE_VALUE is not one). Console handles are routed to the
/// console, never decoded as object-table handles: the table ignores the low tag bits, so without
/// this rule stdout would name a table slot.
#[cfg(test)]
fn is_console_handle(handle: u32) -> bool {
    handle & 0x1000_0003 == 0x3
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

/// Look a transitional Win32 service up by number: its argument block size and handler.
pub fn lookup_service(number: u32) -> Option<(u32, ServiceFn)> {
    let position = number.checked_sub(WIN32_SERVICE_BASE + 1)? as usize;
    let &(_, arg_bytes, service) = SERVICES.get(position)?;
    Some((arg_bytes, service))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry's numbering: the services follow the base; numbers outside the registry name no
    /// service; the names are unique.
    #[test]
    fn the_registry_numbers_from_its_base() {
        assert_eq!(
            SERVICES.len(),
            0,
            "the served surface, less kernel32's natives (the last error, the current process, \
             the console and start-up calls, the locale group and clock, the exception filter, \
             the virtual memory, the events and waits, Sleep, the heaps and environment, \
             the threads and the process's end, the files, the modules) and ntdll's RtlUnwind"
        );
        assert_eq!(WIN32_SERVICE_BASE, 0x2000);
        for (i, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
            let number = WIN32_SERVICE_BASE + i as u32 + 1;
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

    /// The registry keeps its order discipline: alphabetical (ASCII case-insensitively, as the names
    /// were placed; ExitProcess, which the generator would place first, is kernel32's own code
    /// now).
    #[test]
    fn the_registry_is_alphabetical() {
        let names: Vec<String> = SERVICES
            .iter()
            .map(|&(name, ..)| name.to_ascii_lowercase())
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    /// The served shapes no path the corpus takes reaches answer with their decided values, and no
    /// export is a floor any more (UnhandledExceptionFilter is kernel32's code and RtlUnwind
    /// ntdll's).
    #[test]
    fn never_called_shapes_resolve_to_their_floors() {
        assert!(SERVICES
            .iter()
            .all(|&(_, _, handler)| handler as usize != svc_floor_zero as usize));
        let mut frame = zero_frame();

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
