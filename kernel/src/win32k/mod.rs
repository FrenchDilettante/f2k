//! win32k: the window manager's kernel side, as far as F2K has one: window stations and desktops
//! ([`winsta`]), and the second service table their services come through.
//!
//! On Windows 2000, user32 and gdi32 enter the kernel themselves, not through ntdll: their own
//! `NtUser*` and `NtGdi*` stubs raise the gate with win32k's numbers, table 1 in the number's bits
//! 12-13 (numbers from 0x1000; ntoskrnl's services are table 0), and the dispatcher routes them
//! here by those bits (`user::syscall`). The table is generated from user32's export spec (its
//! `internal` `impl = { syscall = ... }` records, through tools/exportgen), by Windows 2000's
//! numbers (userland/user32/w2k-services.txt): [`WIN32K_SERVICES`], each entry a wrapper that
//! decodes the argument block by the spec's kinds and calls the typed handler,
//! `fn(&mut NtCall, <arguments>) -> NtResult`, as the NT services' do.
//!
//! The services' argument lists are F2K's own: Windows 2000 documents none of them, and only F2K's
//! user32 calls them. They answer as the NT services do, an NTSTATUS in EAX and the results through
//! the caller's pointers, never touching the last error: user32 maps a failure through ntdll's
//! RtlNtStatusToDosError. (Windows 2000's win32k answers with the Win32 result and sets the last
//! error itself.)

pub mod winsta;

use crate::user::syscall::ServiceFn;

/// The first number of win32k's table: table 1 in the number's bits 12-13.
pub const WIN32K_BASE: u32 = 0x1000;

// `WIN32K_SERVICE_LIMIT` and `WIN32K_SERVICES`, from user32's export spec (kernel/build.rs).
include!(concat!(env!("OUT_DIR"), "/win32k_services.rs"));

/// The service at `index` in win32k's table (the number's low 12 bits), if F2K serves it: its
/// argument block's size and its handler.
pub fn lookup(index: u32) -> Option<(u32, ServiceFn)> {
    let number = WIN32K_BASE | index;
    WIN32K_SERVICES
        .binary_search_by_key(&number, |&(n, _, _, _)| n)
        .ok()
        .map(|at| (WIN32K_SERVICES[at].2, WIN32K_SERVICES[at].3))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is in number order, within Windows 2000's win32k table, each entry's argument
    /// block within the gate's copy budget.
    #[test]
    fn the_table_is_windows_2000s_numbering() {
        assert_eq!(WIN32K_SERVICE_LIMIT, 640);
        assert!(WIN32K_SERVICES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for &(number, name, bytes, _) in &WIN32K_SERVICES {
            assert!(
                (WIN32K_BASE..WIN32K_BASE + WIN32K_SERVICE_LIMIT).contains(&number),
                "{name}"
            );
            assert!(
                bytes as usize <= crate::user::syscall::MAX_ARG_BYTES,
                "{name}"
            );
        }
        let entry = |name: &str| {
            WIN32K_SERVICES
                .iter()
                .find(|entry| entry.1 == name)
                .map(|entry| (entry.0, entry.2))
        };
        assert_eq!(entry("NtUserGetObjectInformation"), Some((0x119C, 20)));
        assert_eq!(entry("NtUserGetProcessWindowStation"), Some((0x119F, 4)));
        assert_eq!(entry("NtUserGetThreadDesktop"), Some((0x11A2, 8)));
        assert_eq!(lookup(0x19C).map(|(bytes, _)| bytes), Some(20));
        assert!(lookup(0).is_none(), "NtGdiAbortDoc: not served");
    }

    /// user32 enters win32k through its own stubs, Windows 2000's shape: mov eax,number /
    /// lea edx,[esp+4] / int 2Eh / ret imm16, one per service, none exported. A DLL built from
    /// another version of the spec fails here.
    #[test]
    fn user32s_stubs_raise_windows_2000s_numbers() {
        use crate::exec::modules::USER32;
        for &(number, name, bytes, _) in &WIN32K_SERVICES {
            let mut stub = std::vec![0xB8];
            stub.extend_from_slice(&number.to_le_bytes());
            stub.extend_from_slice(&[0x8D, 0x54, 0x24, 0x04, 0xCD, 0x2E]);
            if bytes == 0 {
                stub.push(0xC3);
            } else {
                stub.push(0xC2);
                stub.extend_from_slice(&(bytes as u16).to_le_bytes());
            }
            let found = USER32
                .file
                .windows(stub.len())
                .filter(|window| *window == &stub[..])
                .count();
            assert_eq!(found, 1, "{name}'s stub");
            assert!(
                crate::exec::modules::resolve_in(&USER32, name, 0).is_err(),
                "{name} is user32's internal call, not an export"
            );
        }
    }
}
