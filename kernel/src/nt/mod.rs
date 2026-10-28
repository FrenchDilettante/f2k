//! The NT system services: Windows 2000's `Nt*` calls, which ntdll's stubs enter the kernel through
//! with Windows 2000's own service numbers.
//!
//! The services speak NT, not Win32: handles, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, LARGE_INTEGER
//! timeouts, and an NTSTATUS in EAX. They never touch the calling thread's last error: kernel32's
//! user-mode code maps a failure through ntdll's RtlNtStatusToDosError, as Windows 2000's does.
//! They sit directly on the object manager (`ob`), and, as later work adds them, the file system
//! (`fs`) and the address space (`mem::vm`).
//!
//! The service table is generated from ntdll's export spec (userland/ntdll/exports.toml, the
//! `impl = { syscall = ... }` exports, through tools/exportgen): [`NT_SERVICES`], each entry a
//! wrapper that decodes the argument block by the spec's kinds and calls the typed handler here,
//! `fn(&mut NtCall, <arguments>) -> NtResult` (see [`call`]). The first is NtClose ([`object`]).

/// The host builds' stand-ins for the services that run on the target's dispatcher, object manager
/// and address space: the table names them; each fails with STATUS_NOT_IMPLEMENTED (the host tests
/// exercise their pure parts). An area whose handlers are target-only lists them in an
/// `unserved! { name(Arg, ...); ... }` block in its host module, so the host build compiles.
#[cfg(not(target_arch = "x86"))]
#[allow(unused_macros)]
macro_rules! unserved {
    ($($name:ident($($arg:ty),*);)*) => {$(
        pub fn $name(_: &mut NtCall, $(_: $arg),*) -> NtResult {
            Err($crate::status::STATUS_NOT_IMPLEMENTED)
        }
    )*};
}

pub mod attributes;
pub mod call;
pub mod exception;
pub mod file;
pub mod key;
pub mod memory;
pub mod object;
pub mod process;
pub mod section;
#[cfg(target_arch = "x86")]
pub mod sync;
pub mod system;
pub mod thread;

/// The host builds' synchronization services (see [`unserved`]).
#[cfg(not(target_arch = "x86"))]
pub mod sync {
    use super::call::{Handle, NtCall, NtResult, UserAddr, UserPtr};

    unserved! {
        open_directory_object(UserPtr<u32>, u32, UserAddr);
        create_event(UserPtr<u32>, u32, UserAddr, u32, bool);
        open_event(UserPtr<u32>, u32, UserAddr);
        set_event(Handle, UserPtr<i32>);
        reset_event(Handle, UserPtr<i32>);
        clear_event(Handle);
        pulse_event(Handle, UserPtr<i32>);
        create_mutant(UserPtr<u32>, u32, UserAddr, bool);
        open_mutant(UserPtr<u32>, u32, UserAddr);
        release_mutant(Handle, UserPtr<i32>);
        create_semaphore(UserPtr<u32>, u32, UserAddr, i32, i32);
        open_semaphore(UserPtr<u32>, u32, UserAddr);
        release_semaphore(Handle, i32, UserPtr<i32>);
        wait_for_single_object(Handle, bool, UserPtr<u64>);
        wait_for_multiple_objects(u32, UserAddr, u32, bool, UserPtr<u64>);
        signal_and_wait_for_single_object(Handle, Handle, bool, UserPtr<u64>);
        create_timer(UserPtr<u32>, u32, UserAddr, u32);
        open_timer(UserPtr<u32>, u32, UserAddr);
        set_timer(Handle, UserPtr<u64>, UserAddr, UserAddr, bool, i32, UserAddr);
        cancel_timer(Handle, UserAddr);
        delay_execution(bool, UserPtr<u64>);
        yield_execution();
        duplicate_object(Handle, Handle, Handle, UserPtr<u32>, u32, u32, u32);
        queue_apc_thread(Handle, UserAddr, UserAddr, UserAddr, UserAddr);
    }
}

use crate::user::syscall::ServiceFn;

// `NT_SERVICE_LIMIT` and `NT_SERVICES`, from ntdll's export spec (kernel/build.rs).
include!(concat!(env!("OUT_DIR"), "/nt_services.rs"));

/// The system service EAX numbers, if F2K serves it: its argument block's size and its handler.
pub fn lookup(number: u32) -> Option<(u32, ServiceFn)> {
    NT_SERVICES
        .binary_search_by_key(&number, |&(n, _, _, _)| n)
        .ok()
        .map(|index| (NT_SERVICES[index].2, NT_SERVICES[index].3))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table is in number order, below Windows 2000's limit, each entry's argument block within
    /// the gate's copy budget.
    #[test]
    fn the_table_is_windows_2000s_numbering() {
        assert_eq!(NT_SERVICE_LIMIT, 248);
        assert!(NT_SERVICES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for &(number, name, bytes, _) in &NT_SERVICES {
            assert!(number < NT_SERVICE_LIMIT, "{name}");
            assert!(
                bytes as usize <= crate::user::syscall::MAX_ARG_BYTES,
                "{name}"
            );
        }
        let close = NT_SERVICES
            .iter()
            .find(|entry| entry.1 == "NtClose")
            .unwrap();
        assert_eq!(close.0, 0x18, "NtClose is Windows 2000's service 0x18");
        assert!(lookup(0x18).is_some() && lookup(0x00).is_none());
        assert_eq!(lookup(0x18).map(|(bytes, _)| bytes), Some(4));
    }

    /// ntdll exports every system service under its Nt and its Zw name, at one stub that raises the
    /// gate on the service's Windows 2000 number as Windows 2000's own stubs do: mov eax,number /
    /// lea edx,[esp+4] / int 2Eh / ret imm16 (a plain ret without arguments). A DLL built from
    /// another version of the spec fails here.
    #[test]
    fn ntdll_stubs_raise_windows_2000s_numbers() {
        use crate::exec::modules::{resolve, NTDLL};
        let dll = &NTDLL;
        for &(number, name, bytes, _) in &NT_SERVICES {
            let address =
                resolve("ntdll.dll", name).unwrap_or_else(|_| panic!("ntdll exports no {name}"));
            let zw = std::format!("Zw{}", &name[2..]);
            assert_eq!(
                resolve("ntdll.dll", &zw),
                Ok(address),
                "{zw} is {name}'s stub"
            );
            let mut stub = std::vec![0xB8];
            stub.extend_from_slice(&number.to_le_bytes());
            stub.extend_from_slice(&[0x8D, 0x54, 0x24, 0x04, 0xCD, 0x2E]);
            if bytes == 0 {
                stub.push(0xC3);
            } else {
                stub.push(0xC2);
                stub.extend_from_slice(&(bytes as u16).to_le_bytes());
            }
            let at = (address - dll.base) as usize;
            assert_eq!(&dll.file[at..at + stub.len()], &stub[..], "{name}");
        }
    }

    /// The generated wrapper decodes the argument block and puts the handler's NTSTATUS in EAX:
    /// NtClose of a handle the host has no table for is STATUS_INVALID_HANDLE.
    #[test]
    fn the_wrapper_answers_with_the_status() {
        // SAFETY: a trap frame is plain dwords; all zeros is a valid one.
        let mut frame: crate::user::TrapFrame = unsafe { core::mem::zeroed() };
        let (_, service) = lookup(0x18).unwrap();
        service(&mut frame, &[0x44], &mut crate::level::passive_for_test());
        assert_eq!(frame.eax, 0xC000_0008);
    }
}
