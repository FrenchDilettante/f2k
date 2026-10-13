//! The kernel-synthesized kernel32 export surface.
//!
//! No real kernel32.dll image exists yet: the kernel publishes an
//! export table (name -> syscall service) and maps one user page of
//! thunk stubs. Each stub points EDX at the caller's stack arguments
//! (the Win32 stdcall convention: first argument at `[esp+4]`),
//! loads its service number into EAX, and raises the syscall gate;
//! the PE loader snaps IAT slots to the stub addresses.
//!
//! Kernel pages are supervisor-only and unreachable from ring 3, so
//! the stubs must live in user memory. Tiny user-mode stub pages are
//! the interim shape; a full ntdll-like user-mode layer remains the
//! end state (the plan's open question).

use crate::syscall::{SYS_EXIT, SYSCALL_VECTOR};

/// The module name imports resolve against; the PE import descriptor
/// must name it (ASCII-case-insensitively).
pub const MODULE_NAME: &str = "KERNEL32.dll";

/// The user page the thunk stubs live in: above the largest image the
/// loader maps (an image spans up to the fixed base plus
/// [`crate::pe::MAX_IMAGE_SIZE`]), in its own 4 MiB window away from
/// the user stack (0x300000).
pub const THUNK_PAGE: u32 = crate::pe::IMAGE_BASE + crate::pe::MAX_IMAGE_SIZE;

/// Bytes of one thunk stub (see the module doc).
const STUB_LEN: usize = 12;

/// Offset between consecutive stubs in the thunk page: every stub
/// starts 16 bytes in after the previous one.
const STUB_STRIDE: u32 = 16;

/// The export table: names as they appear in hint/name entries,
/// paired with the syscall service each one raises.
const EXPORTS: &[(&str, u32)] = &[("ExitProcess", SYS_EXIT)];

/// The bytes of one stub: point EDX at the caller's first argument,
/// request the service, raise the gate, and a never-reached return
/// (ExitProcess ends the process inside the service).
fn stub_bytes(service: u32) -> [u8; STUB_LEN] {
    let mut stub = [
        0x8D, 0x54, 0x24, 0x04, // lea edx, [esp+4]
        0xB8, 0, 0, 0, 0, // mov eax, service
        0xCD, SYSCALL_VECTOR as u8, // int 0x2E
        0xC3, // ret
    ];
    stub[5..9].copy_from_slice(&service.to_le_bytes());
    stub
}

/// Resolve an export name to its thunk address (the value snapped into
/// an IAT slot). Exact-match for now; the reference's export lookup is
/// case-insensitive and grows in with the real surface.
pub fn resolve(name: &str) -> Option<u32> {
    EXPORTS
        .iter()
        .position(|&(export, _)| export == name)
        .map(|index| THUNK_PAGE + index as u32 * STUB_STRIDE)
}

/// Map the thunk stubs into user space: one frame, zeroed and seeded
/// with the first stub, patched with the rest, then mapped readable
/// and user-accessible (the stubs execute; nothing writes the page).
#[cfg(target_arch = "x86")]
pub fn init() {
    let frame = crate::mem::paging::allocate_frame_phys();
    crate::mem::paging::init_frame(frame, 0, &stub_bytes(EXPORTS[0].1));
    for (index, &(_, service)) in EXPORTS.iter().enumerate().skip(1) {
        crate::mem::paging::write_frame(
            frame,
            (index as u32 * STUB_STRIDE) as usize,
            &stub_bytes(service),
        );
    }
    crate::mem::paging::map_user_page(THUNK_PAGE, frame, false);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::paging::KERNEL_BASE;
    use crate::pe::IMAGE_BASE;

    /// The stub bytes are the documented encoding: lea /r with the
    /// [esp+4] displacement (8D 54 24 04), mov eax with an imm32
    /// (B8 + service, little-endian), the syscall gate (CD 2E), and
    /// the never-reached return (C3).
    #[test]
    fn stub_bytes_match_their_encoding() {
        for &(_, service) in EXPORTS {
            let stub = stub_bytes(service);
            assert_eq!(&stub[..4], &[0x8D, 0x54, 0x24, 0x04]);
            assert_eq!(stub[4], 0xB8);
            assert_eq!(&stub[5..9], &service.to_le_bytes());
            assert_eq!(stub[9], 0xCD);
            assert_eq!(stub[10], SYSCALL_VECTOR as u8);
            assert_eq!(stub[11], 0xC3);
        }
    }

    /// The exit stub requests the exit service.
    #[test]
    fn exit_process_raises_the_exit_service() {
        assert!(EXPORTS.contains(&("ExitProcess", SYS_EXIT)));
    }

    /// Names are unique and every service number is nonzero (0 is not
    /// a service).
    #[test]
    fn exports_are_table_consistent() {
        for (i, &(name, service)) in EXPORTS.iter().enumerate() {
            assert!(!name.is_empty());
            assert!(service > 0);
            for &(other, _) in EXPORTS.iter().skip(i + 1) {
                assert_ne!(name, other);
            }
        }
    }

    /// Resolution: known names map to their stub's address, stride
    /// apart, inside the thunk page; unknown names do not resolve.
    #[test]
    fn resolve_addresses_the_stubs() {
        assert_eq!(resolve("ExitProcess"), Some(THUNK_PAGE));
        assert_eq!(resolve("exitprocess"), None);
        assert_eq!(resolve("VirtualAlloc"), None);
        for (i, &(name, _)) in EXPORTS.iter().enumerate() {
            let va = resolve(name).expect("export resolves");
            assert_eq!(va, THUNK_PAGE + i as u32 * STUB_STRIDE);
            assert!(va >= THUNK_PAGE && (va as usize) + STUB_LEN <= (THUNK_PAGE + 4096) as usize);
        }
    }

    /// The thunk page sits in user space, page-aligned, clear of every
    /// image the loader can map (at or past the fixed base plus the
    /// size cap), and all stubs fit inside the page.
    #[test]
    fn thunk_page_layout_is_consistent() {
        assert_eq!(THUNK_PAGE % 4096, 0);
        assert!(THUNK_PAGE < KERNEL_BASE);
        assert!(THUNK_PAGE >= IMAGE_BASE + crate::pe::MAX_IMAGE_SIZE);
        assert!(THUNK_PAGE + 4096 < KERNEL_BASE);
        let last = (EXPORTS.len() - 1) as u32;
        assert!((last * STUB_STRIDE) as usize + STUB_LEN <= 4096);
    }

    /// The module name matches the fixtures' import descriptors
    /// ("KERNEL32.dll").
    #[test]
    fn module_name_is_kernel32() {
        assert_eq!(MODULE_NAME, "KERNEL32.dll");
    }
}
