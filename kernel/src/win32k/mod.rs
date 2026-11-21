//! win32k: the window manager's and GDI's kernel side, as far as F2K has them: window classes
//! ([`class`]), windows ([`window`]) and their properties ([`prop`]), their focus, enabling and
//! activation ([`focus`]), the
//! threads' message queues ([`queue`]), their timers ([`timer`]) and the windows' painting
//! ([`paint`]), their carets ([`caret`]), menus ([`menu`]), keyboard accelerators ([`accel`]),
//! cursors and icons ([`icon`]), the one handle table every one of those user objects' handles
//! names a slot of ([`handle`]), window stations and desktops ([`winsta`]), keyboard input
//! ([`input`]), the display settings ([`display`]), device contexts ([`dc`]), the brushes they fill
//! with ([`brush`]), the bitmaps memory DCs draw on and the blits between DCs ([`bitmap`],
//! [`blit`]) and what is drawn through them ([`raster`], in the built-in font, [`font`], or a
//! TrueType font, [`fonts`], which holds the faces loaded and the font objects too), the clipboard
//! ([`clipboard`]), the windows' texts ([`text`]), and the second service table their services come
//! through.
//!
//! On Windows 2000, user32 and gdi32 enter the kernel themselves, not through ntdll: their own
//! `NtUser*` and `NtGdi*` stubs raise the gate with win32k's numbers, table 1 in the number's bits
//! 12-13 (numbers from 0x1000; ntoskrnl's services are table 0), and the dispatcher routes them
//! here by those bits (`user::syscall`). The table is generated from user32's and gdi32's export
//! specs (their `internal` `impl = { syscall = ... }` records, through tools/exportgen), by Windows
//! 2000's numbers (userland/user32/w2k-services.txt): [`WIN32K_SERVICES`], each entry a wrapper
//! that decodes the argument block by the spec's kinds and calls the typed handler,
//! `fn(&mut NtCall, <arguments>) -> NtResult`, as the NT services' do.
//!
//! The services' argument lists are F2K's own: Windows 2000 documents none of them, and only F2K's
//! user32 and gdi32 call them. They answer as the NT services do, an NTSTATUS in EAX and the
//! results through the caller's pointers, never touching the last error: user32 maps a failure
//! through ntdll's RtlNtStatusToDosError, gdi32 through rtl's table (Windows 2000's gdi32 imports
//! no RtlNtStatusToDosError). (Windows 2000's win32k answers with the Win32 result and sets the
//! last error itself.) A USER decision whose Win32 error has no NTSTATUS of its own (a window
//! class there is none of, a menu handle naming no menu, the clipboard not open...) answers that
//! error itself, in a FACILITY_NTWIN32 status (`NtStatus::from_win32`, 0xC007xxxx), which the
//! mapping hands back as it is: each module's `Failure::status`. One answers as Windows 2000's
//! does: NtUserChangeDisplaySettings, whose answer is ChangeDisplaySettingsEx's own DISP_CHANGE
//! code, which sets no last error ([`display`]).

pub mod accel;
pub mod bitmap;
pub mod blit;
pub mod brush;
pub mod caret;
pub mod class;
pub mod clipboard;
pub mod dc;
pub mod display;
pub mod focus;
pub mod font;
pub mod fonts;
pub mod handle;
pub mod icon;
pub mod input;
pub mod menu;
pub mod paint;
pub mod posted;
pub mod prop;
pub mod queue;
pub mod raster;
pub mod text;
pub mod timer;
pub mod window;
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

    /// Each USER refusal answers its Win32 error itself, which ntdll's mapping hands back as it
    /// is: no two decisions share a status user32 would have to guess the error back from.
    #[test]
    fn the_refusals_carry_their_win32_errors() {
        use rtl::status::dos_error;
        use window::Failure as W;
        for failure in [
            W::AccessDenied,
            W::OutOfMemory,
            W::InvalidParameter,
            W::InvalidWindowHandle,
            W::InvalidIndex,
            W::TlwWithWsChild,
            W::CannotFindWindowClass,
        ] {
            assert_eq!(dos_error(failure.status().0), failure.code(), "{failure:?}");
        }
        use class::Failure as C;
        for failure in [
            C::AccessDenied,
            C::OutOfMemory,
            C::InvalidParameter,
            C::InvalidCursorHandle,
            C::CannotFindWindowClass,
            C::ClassAlreadyExists,
            C::ClassDoesNotExist,
            C::ClassHasWindows,
            C::InvalidIndex,
            C::InvalidIconHandle,
        ] {
            assert_eq!(dos_error(failure.status().0), failure.code(), "{failure:?}");
        }
        use menu::Failure as M;
        for (failure, error) in [
            (M::NotEnoughMemory, 8),
            (M::InvalidWindowHandle, 1400),
            (M::InvalidMenuHandle, 1401),
            (M::ChildWindowMenu, 1436),
            (M::ItemNotFound, 1456),
        ] {
            assert_eq!(dos_error(failure.status().0), error, "{failure:?}");
        }
        use accel::Failure as A;
        for (failure, error) in [
            (A::NotEnoughMemory, 8),
            (A::InvalidParameter, 87),
            (A::InvalidWindowHandle, 1400),
            (A::InvalidAccelHandle, 1403),
        ] {
            assert_eq!(dos_error(failure.status().0), error, "{failure:?}");
        }
        use clipboard::Refusal as R;
        for (refusal, error) in [
            (R::NotOpen, 1418),
            (R::AccessDenied, 5),
            (R::InvalidParameter, 87),
            (R::NoMemory, 8),
        ] {
            assert_eq!(dos_error(refusal.status().0), error, "{refusal:?}");
        }
        for (status, error) in [
            (icon::INVALID_CURSOR_HANDLE, 1402),
            (queue::MESSAGE_SYNC_ONLY, 1159),
            (queue::INVALID_THREAD_ID, 1444),
        ] {
            assert_eq!(dos_error(status.0), error);
        }
    }

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
        assert_eq!(entry("NtGdiExtTextOutW"), Some((0x108E, 32)));
        assert_eq!(entry("NtGdiEngTextOut"), Some((0x1257, 32)));
        assert_eq!(entry("NtUserGetDC"), Some((0x1186, 8)));
        assert_eq!(entry("NtGdiSetPixel"), Some((0x1110, 20)));
        assert_eq!(entry("NtUserSetWindowPos"), Some((0x120F, 28)));
        assert_eq!(entry("NtUserMoveWindow"), Some((0x11C1, 24)));
        assert_eq!(entry("NtUserShowWindow"), Some((0x1218, 12)));
        assert_eq!(entry("NtUserShowWindowAsync"), Some((0x1219, 8)));
        assert_eq!(entry("NtUserQueryWindow"), Some((0x11D2, 16)));
        assert_eq!(entry("NtUserEnumDisplaySettings"), Some((0x116B, 16)));
        assert_eq!(entry("NtUserEnumDisplayDevices"), Some((0x1169, 16)));
        assert_eq!(entry("NtUserEnumDisplayMonitors"), Some((0x116A, 24)));
        assert_eq!(entry("NtUserSetSysColors"), Some((0x1204, 16)));
        assert_eq!(entry("NtUserSystemParametersInfo"), Some((0x121C, 16)));
        assert_eq!(entry("NtUserSendInput"), Some((0x11E1, 16)));
        assert_eq!(entry("NtUserGetKeyState"), Some((0x1195, 8)));
        assert_eq!(entry("NtUserTranslateMessage"), Some((0x1224, 12)));
        assert_eq!(lookup(0x19C).map(|(bytes, _)| bytes), Some(20));
        assert!(lookup(0).is_none(), "NtGdiAbortDoc: not served");
    }

    /// user32 and gdi32 enter win32k through their own stubs, Windows 2000's shape: mov
    /// eax,number / lea edx,[esp+4] / int 2Eh / ret imm16, one per service (an `NtUser*` in
    /// user32, an `NtGdi*` in gdi32), none exported. A DLL built from another version of the spec
    /// fails here.
    #[test]
    fn the_clients_stubs_raise_windows_2000s_numbers() {
        use crate::exec::modules::{GDI32, USER32};
        for &(number, name, bytes, _) in &WIN32K_SERVICES {
            let dll = if name.starts_with("NtGdi") {
                &GDI32
            } else {
                &USER32
            };
            let mut stub = std::vec![0xB8];
            stub.extend_from_slice(&number.to_le_bytes());
            stub.extend_from_slice(&[0x8D, 0x54, 0x24, 0x04, 0xCD, 0x2E]);
            if bytes == 0 {
                stub.push(0xC3);
            } else {
                stub.push(0xC2);
                stub.extend_from_slice(&(bytes as u16).to_le_bytes());
            }
            let found = dll
                .file
                .windows(stub.len())
                .filter(|window| *window == &stub[..])
                .count();
            assert_eq!(found, 1, "{name}'s stub");
            assert!(
                crate::exec::modules::resolve_in(dll, name, 0).is_err(),
                "{name} is {}'s internal call, not an export",
                dll.file_name
            );
        }
    }
}
