//! The system DLLs as the kernel embeds them: the module table's images and resolution, the built
//! DLLs against the export specs (every served export's stub, the natives, the forwarders), and the
//! import surface of the corpus binaries the kernel runs.

use super::*;
use crate::compat::kernel32::{SERVICES, WIN32_SERVICE_BASE};

// `NATIVE_EXPORTS`: kernel32's native exports (its user-mode code), (export, argument bytes), as the
// spec declares them.
include!(concat!(env!("OUT_DIR"), "/kernel32_natives.rs"));

// `DLL_EXPORTS`: every export kernel32's table carries, from its export spec.
include!(concat!(env!("OUT_DIR"), "/kernel32_exports.rs"));

/// The embedded system DLLs: i386 DLL images at their bases, clear of each other and of kernel
/// space, with file offsets equal to RVAs (the export reads rely on it: the file is the mapped
/// image, its zero tail aside), and no entry point (no DllMain runs).
#[test]
fn the_system_dlls_are_images_at_their_bases() {
    let sizes = [NTDLL_SIZE, KERNEL32_SIZE];
    for (dll, size) in SYSTEM_DLLS.iter().zip(sizes) {
        let image = dll.image();
        assert!(image.is_dll(), "{}", dll.file_name);
        assert_eq!(image.image_base, dll.base, "{}", dll.file_name);
        assert_eq!(image.size_of_image, size, "{}", dll.file_name);
        assert!(dll.base as u64 + size as u64 <= crate::mem::paging::KERNEL_BASE as u64);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(dll.file, &mut mapped);
        let shared = dll.file.len().min(mapped.len());
        assert!(
            mapped[..shared] == dll.file[..shared],
            "{}: the file is its mapped image",
            dll.file_name
        );
        assert_eq!(
            image.entry_va(),
            dll.base,
            "{}: no entry point",
            dll.file_name
        );
    }
    assert!(NTDLL_BASE + NTDLL_SIZE <= KERNEL32_BASE);
}

/// Exports resolve by exact name, kernel32's forwarder lands in ntdll, unknown names and modules
/// do not resolve, and the kernel's internal entry point exists (in ntdll only: kernel32's surface
/// carries Windows 2000's names alone).
#[test]
fn exports_resolve_through_the_module_table() {
    let exit = resolve("KERNEL32.dll", "ExitProcess").unwrap();
    assert!((KERNEL32_BASE..KERNEL32_BASE + KERNEL32_SIZE).contains(&exit));
    assert_eq!(resolve("kernel32", "ExitProcess"), Ok(exit));
    assert_eq!(kernel32_export("ExitProcess"), Some(exit));
    assert_eq!(
        resolve("KERNEL32.dll", "exitprocess"),
        Err(Unresolved::NoEntry)
    );
    assert_eq!(
        resolve("USER32.dll", "MessageBoxA"),
        Err(Unresolved::NoModule)
    );
    let unwind = resolve("KERNEL32.dll", "RtlUnwind").unwrap();
    assert_eq!(resolve("ntdll.dll", "RtlUnwind"), Ok(unwind));
    assert!(
        (NTDLL_BASE..NTDLL_BASE + NTDLL_SIZE).contains(&unwind),
        "the forwarder resolves in ntdll"
    );
    // The thread-exit trampoline is gone: every thread's start routine returns into kernel32's
    // start frame, which calls ExitThread.
    assert_eq!(
        resolve("ntdll", "F2kThreadExitTrampoline"),
        Err(Unresolved::NoEntry)
    );
    assert_eq!(
        Some(ldr_initialize_thunk()),
        resolve("ntdll", "LdrInitializeThunk").ok(),
        "the cache holds the export"
    );
}

/// The bytes at `address` in the system DLL holding it, as the embedded file holds them.
fn bytes_at(address: u32) -> &'static [u8] {
    let dll = SYSTEM_DLLS
        .iter()
        .find(|dll| address >= dll.base && ((address - dll.base) as usize) < dll.file.len())
        .unwrap_or_else(|| panic!("{address:#x} lies in no system DLL"));
    &dll.file[(address - dll.base) as usize..]
}

/// Every service the registry holds is a system DLL export (kernel32's, or ntdll's that kernel32
/// forwards to) whose stub raises the gate on its number and returns popping its argument block:
/// lea edx,[esp+4] / mov eax,service (WIN32_SERVICE_BASE + its position + 1) / int 0x2E / ret
/// imm16 (the stdcall cleanup; `ret` for an empty block). Every export has its own code. A DLL
/// built from another version of the specs fails here.
#[test]
fn the_system_dlls_serve_the_registry() {
    let mut addresses = Vec::new();
    for (index, &(name, arg_bytes, _)) in SERVICES.iter().enumerate() {
        let mut stub = vec![0x8D, 0x54, 0x24, 0x04, 0xB8];
        stub.extend_from_slice(&(WIN32_SERVICE_BASE + index as u32 + 1).to_le_bytes());
        stub.extend_from_slice(&[0xCD, crate::user::syscall::SYSCALL_VECTOR as u8]);
        if arg_bytes == 0 {
            stub.push(0xC3);
        } else {
            stub.push(0xC2);
            stub.extend_from_slice(&(arg_bytes as u16).to_le_bytes());
        }
        let address = kernel32_export(name).unwrap_or_else(|| panic!("kernel32 exports no {name}"));
        let found = bytes_at(address);
        assert!(
            found.starts_with(&stub),
            "{name}: {:02x?}",
            &found[..stub.len()]
        );
        addresses.push(address);
    }
    // The corpus's argument-block shapes, looked up by name so a renumbering cannot silently skew
    // the pins.
    for (name, arg_bytes) in [("GetProcAddress", 8), ("LoadLibraryA", 4)] {
        let &(_, found, _) = SERVICES
            .iter()
            .find(|&&(export, ..)| export == name)
            .unwrap();
        assert_eq!(found, arg_bytes, "{name}");
    }
    // The natives: kernel32's own code (the trivial ones, the exception filter and the pointer
    // probes its assembly, the TLS slots' reads and writes; the console, start-up, locale, clock,
    // virtual-memory, mapping, synchronization, timer, sleep, APC, affinity, TLS-index,
    // environment, file (the write side's included) and current-directory calls and RaiseException
    // its Rust, the heap and Local/Global calls its own over ntdll's heap).
    // The internal start thunks are not among them.
    assert_eq!(NATIVE_EXPORTS.len(), 171);
    for &(name, _) in &NATIVE_EXPORTS {
        let address = kernel32_export(name).unwrap_or_else(|| panic!("kernel32 exports no {name}"));
        addresses.push(address);
    }
    for thunk in ["BaseProcessStartThunk", "BaseThreadStartThunk"] {
        addresses.push(kernel32_export(thunk).unwrap_or_else(|| panic!("kernel32 exports no {thunk}")));
    }
    addresses.sort_unstable();
    addresses.dedup();
    assert_eq!(
        addresses.len(),
        SERVICES.len() + NATIVE_EXPORTS.len() + 2,
        "every export has its own code"
    );
}

/// The entry points the kernel sends user code to keep their protocols: ntdll's exception
/// dispatcher calls its body with the two pointers the kernel left on top (it never returns: a
/// `ud2` follows), its APC dispatcher calls the routine the kernel left on top, then resumes the
/// context above it, and its LdrInitializeThunk runs its body, then resumes the same; kernel32's
/// start thunks clear EBP and push their registers (the main thread's entry point; a child's
/// parameter, then its start address) under a zero return address, then jump to their bodies. The exception-filter natives address the top-level filter's slot in the
/// PEB page.
#[test]
fn the_entry_points_keep_their_protocols() {
    let dispatcher = bytes_at(exception_dispatcher());
    assert_eq!(dispatcher[0], 0xE8, "KiUserExceptionDispatcher: a call");
    assert_eq!(
        &dispatcher[5..7],
        &[0x0F, 0x0B],
        "KiUserExceptionDispatcher: then ud2"
    );
    assert_eq!(
        Some(exception_dispatcher()),
        resolve("ntdll.dll", "KiUserExceptionDispatcher").ok()
    );
    // The APC dispatcher keeps the context's address (past the four-word call frame) in EDI, pops
    // and calls the routine, then NtContinue(context, TRUE); a failed one's status is raised.
    let apc = bytes_at(apc_dispatcher());
    assert_eq!(
        &apc[..10],
        &[0x8D, 0x7C, 0x24, 0x10, 0x58, 0xFF, 0xD0, 0x6A, 0x01, 0x57],
        "KiUserApcDispatcher"
    );
    assert_eq!(apc[10], 0xE8, "KiUserApcDispatcher: NtContinue's call");
    assert_eq!(apc[15], 0x50, "KiUserApcDispatcher: then the status pushed");
    assert_eq!(crate::user::apc::CALL_WORDS * 4, 0x10);
    // LdrInitializeThunk keeps the context's address (past the same call frame) in EDI across its
    // body's call, then NtContinue(context, TRUE).
    let ldr = bytes_at(ldr_initialize_thunk());
    assert_eq!(&ldr[..4], &[0x8D, 0x7C, 0x24, 0x10], "LdrInitializeThunk");
    assert_eq!(ldr[4], 0xE8, "LdrInitializeThunk: its body's call");
    assert_eq!(&ldr[9..12], &[0x6A, 0x01, 0x57], "LdrInitializeThunk: NtContinue(context, TRUE)");
    assert_eq!(ldr[12], 0xE8, "LdrInitializeThunk: NtContinue's call");
    assert_eq!(
        Some(ldr_initialize_thunk()),
        resolve("ntdll.dll", "LdrInitializeThunk").ok()
    );
    let thunk = bytes_at(process_start_thunk());
    assert_eq!(
        &thunk[..5],
        &[0x31, 0xED, 0x50, 0x6A, 0x00],
        "BaseProcessStartThunk"
    );
    assert!(
        matches!(thunk[5], 0xE9 | 0xEB),
        "BaseProcessStartThunk: a jump"
    );
    assert_eq!(
        Some(process_start_thunk()),
        kernel32_export("BaseProcessStartThunk")
    );
    let thunk = bytes_at(kernel32_export("BaseThreadStartThunk").unwrap());
    assert_eq!(
        &thunk[..6],
        &[0x31, 0xED, 0x53, 0x50, 0x6A, 0x00],
        "BaseThreadStartThunk"
    );
    assert!(
        matches!(thunk[6], 0xE9 | 0xEB),
        "BaseThreadStartThunk: a jump"
    );
    let slot = crate::user::teb::peb_offset::TOP_LEVEL_FILTER.to_le_bytes();
    for name in ["SetUnhandledExceptionFilter", "UnhandledExceptionFilter"] {
        let body = bytes_at(kernel32_export(name).unwrap());
        assert!(body[..32].windows(4).any(|w| w == slot), "{name}");
    }
}

/// Every unimplemented export has its own generated body: the last error set to
/// ERROR_CALL_NOT_IMPLEMENTED through FS (mov dword ptr fs:[34h], 120), the spec's failure value
/// in EAX, then the stdcall return popping its argument block.
#[test]
fn unimplemented_exports_fail_the_call() {
    // (export, its failure value, its argument block), as the spec declares them.
    for (name, fails, arg_bytes) in [
        ("FreeLibrary", 0u32, 4u16),
    ] {
        let mut stub = vec![0x64, 0xC7, 0x05, 0x34, 0, 0, 0, 120, 0, 0, 0, 0xB8];
        stub.extend_from_slice(&fails.to_le_bytes());
        stub.push(0xC2);
        stub.extend_from_slice(&arg_bytes.to_le_bytes());
        let found = bytes_at(kernel32_export(name).unwrap_or_else(|| panic!("no {name}")));
        assert!(
            found.starts_with(&stub),
            "{name}: {:02x?}",
            &found[..stub.len()]
        );
    }
}

/// The corpus binaries (the smokes in the root directory, the sectioned fixtures in \CORPUS): the
/// import surface kernel32 exports.
const CORPUS: [(&str, &[u8]); 11] = [
    ("bare", include_bytes!("../../../../tests/bare/bare.exe")),
    ("files", include_bytes!("../../../../tests/files/files.exe")),
    (
        "fswrite",
        include_bytes!("../../../../tests/fswrite/fswrite.exe"),
    ),
    (
        "memory",
        include_bytes!("../../../../tests/memory/memory.exe"),
    ),
    (
        "runtime",
        include_bytes!("../../../../tests/runtime/runtime.exe"),
    ),
    ("sched", include_bytes!("../../../../tests/sched/sched.exe")),
    ("sync", include_bytes!("../../../../tests/sync/sync.exe")),
    (
        "threads",
        include_bytes!("../../../../tests/threads/threads.exe"),
    ),
    ("exit0", include_bytes!("../../../../tests/exit0/exit0.exe")),
    ("ret0", include_bytes!("../../../../tests/ret0/ret0.exe")),
    ("hello", include_bytes!("../../../../tests/hello/hello.exe")),
];

/// A binary's imports, as (module, name), read through the loader's own import walk.
fn imports_of(file: &[u8]) -> Vec<(String, String)> {
    let image = Image::parse(file).expect("the fixture parses");
    let mut mapped = vec![0u8; image.size_of_image as usize];
    image.map_into(file, &mut mapped);
    let mut imports = Vec::new();
    image.snap_imports(file, &mut mapped, |module, name| {
        imports.push((module.to_string(), name.to_string()));
        Ok(0)
    });
    imports
}

/// kernel32 exports exactly what the corpus binaries import: every import of every corpus binary
/// resolves, and every export is imported by some corpus binary. The export names are unique.
#[test]
fn the_surface_is_the_corpus_import_surface() {
    let names: Vec<&str> = DLL_EXPORTS.iter().map(|&(name, _)| name).collect();
    assert_eq!(names.len(), 184, "the corpus's import surface");
    for (i, name) in names.iter().enumerate() {
        assert!(!names[i + 1..].contains(name), "{name} listed twice");
        assert!(
            kernel32_export(name).is_some(),
            "kernel32.dll does not export {name}"
        );
    }
    let mut imported: Vec<String> = Vec::new();
    for (fixture, file) in CORPUS {
        for (module, name) in imports_of(file) {
            assert!(
                module.eq_ignore_ascii_case(KERNEL32_NAME),
                "{fixture} imports {module}"
            );
            assert!(
                kernel32_export(&name).is_some(),
                "{fixture} imports {name}, which is not exported"
            );
            imported.push(name);
        }
    }
    for name in names {
        assert!(
            imported.iter().any(|import| import == name),
            "{name} is exported but no corpus binary imports it"
        );
    }
}

/// Each corpus binary snaps every import through the module table: the counts are each binary's
/// import surface (ret0's 35, hello's 40 — ret0's plus the console-stdio group).
#[test]
fn the_corpus_snaps_fully_against_the_module_table() {
    for (fixture, thunks) in [("ret0", 35), ("hello", 40)] {
        let (_, file) = CORPUS.iter().find(|(name, _)| *name == fixture).unwrap();
        let image = Image::parse(file).expect("the fixture parses");
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let result = image.snap_imports(file, &mut mapped, crate::exec::loader::resolve_import);
        assert_eq!(result.thunks, thunks, "{fixture}");
    }
}

/// Module names: each system DLL by any case, with or without `.dll`, through a path; nothing else.
/// Module handles: the DLLs' bases.
#[test]
fn modules_answer_to_their_names_and_handles() {
    for name in [
        &b"kernel32.dll"[..],
        b"KERNEL32",
        b"Kernel32.Dll",
        b"C:\\WINNT\\system32\\kernel32.dll",
        b"system32/KERNEL32.DLL",
    ] {
        assert_eq!(
            module_named(name),
            Some(KERNEL32),
            "{:?}",
            core::str::from_utf8(name)
        );
    }
    for name in [
        &b"ntdll.dll"[..],
        b"NTDLL",
        b"C:\\WINNT\\system32\\NTDLL.DLL",
    ] {
        assert_eq!(
            module_named(name),
            Some(NTDLL),
            "{:?}",
            core::str::from_utf8(name)
        );
    }
    for name in [
        &b"nosuch.dll"[..],
        b"kernel32.exe",
        b"kernel32.",
        b"",
        b"C:\\",
    ] {
        assert_eq!(module_named(name), None, "{:?}", core::str::from_utf8(name));
    }
    assert_eq!(module_of(KERNEL32_BASE), Some(KERNEL32));
    assert_eq!(module_of(NTDLL_BASE), Some(NTDLL));
    for handle in [0, 0x0040_0000, KERNEL32_BASE + 0x1000, 0x1234_0000] {
        assert_eq!(module_of(handle), None, "{handle:#x}");
    }
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
        eax: 0xDEAD,
        vector: 0,
        error_code: 0,
        eip: 0,
        cs: 0,
        eflags: 0,
        user_esp: 0,
        user_ss: 0,
    }
}

/// GetProcAddress and LoadLibraryA refuse (NULL) before they read the caller's name: a handle
/// naming no system DLL (the image exports nothing), an ordinal, a NULL name; an unreadable name
/// (here past the probe limit) is refused too. Their lookups are the module table's, pinned above.
#[test]
fn the_module_services_refuse_what_names_no_module() {
    let kernel_name = crate::user::syscall::USER_PROBE_LIMIT;
    for args in [
        [0x0040_0000, kernel_name],
        [0, kernel_name],
        [KERNEL32_BASE, 0],
        [KERNEL32_BASE, 0xFFFF],
        [NTDLL_BASE, kernel_name],
    ] {
        let mut frame = zero_frame();
        svc_get_proc_address(&mut frame, &args);
        assert_eq!(frame.eax, 0, "{args:x?}");
    }
    for name in [0, kernel_name] {
        let mut frame = zero_frame();
        svc_load_library_a(&mut frame, &[name]);
        assert_eq!(frame.eax, 0, "{name:#x}");
    }
}

/// The module name matches the corpus's import descriptors.
#[test]
fn module_name_is_kernel32() {
    assert_eq!(KERNEL32_NAME, "KERNEL32.dll");
}
