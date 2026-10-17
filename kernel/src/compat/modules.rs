//! Modules: the two a process has — its own image and kernel32 — and the services that name them.
//!
//! kernel32 is the kernel's surface, not a loaded DLL, but programs expect a module: a handle that
//! is the image's base, headers there to read, a file name, exports to look up. The surface keeps a
//! header page for it at the capture machine's kernel32 base (tests/hello/trace.txt measured it): a
//! DOS header, the PE signature, and optional headers naming that base. Its exports are the registry's — GetProcAddress hands back the
//! address the loader snaps an import to, so a call through the pointer is a call through the
//! import. Names compare as the platform compares them: module names without regard to case (a name
//! without an extension is taken as `.dll`), export names exactly.
//!
//! No other DLL exists: loading one fails with ERROR_MOD_NOT_FOUND. Loading kernel32 (or the image
//! itself) hands back its handle; freeing it succeeds and changes nothing.

/// kernel32's module handle: its image base, the header page's address.
pub const KERNEL32_BASE: u32 = 0x7C4E_0000;

/// kernel32's file name, as GetModuleFileNameA reports it.
pub const KERNEL32_PATH: &[u8] = b"C:\\WINNT\\system32\\KERNEL32.DLL";

/// The image's module handle: its base, as the PEB records it.
#[cfg(target_arch = "x86")]
pub fn image_base() -> u32 {
    let mut base = [0u8; 4];
    let peb_image_base = crate::user::PEB_PAGE + crate::user::teb::peb_offset::IMAGE_BASE_ADDRESS;
    match crate::user::syscall::read_user(peb_image_base, &mut base) {
        Ok(()) => u32::from_le_bytes(base),
        Err(_) => 0,
    }
}

/// Host builds have no process: the conventional image base.
#[cfg(not(target_arch = "x86"))]
pub fn image_base() -> u32 {
    0x0040_0000
}

/// kernel32's header page: a DOS header pointing at a PE header for a DLL at [`KERNEL32_BASE`].
pub fn header_page() -> [u8; 0x200] {
    let mut page = [0u8; 0x200];
    let put16 = |page: &mut [u8; 0x200], at: usize, v: u16| page[at..at + 2].copy_from_slice(&v.to_le_bytes());
    page[0..2].copy_from_slice(b"MZ");
    page[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    page[0x80..0x84].copy_from_slice(b"PE\0\0");
    // The file header: i386, no sections, the optional header's size, a 32-bit executable DLL.
    put16(&mut page, 0x84, 0x014C);
    put16(&mut page, 0x94, 0x00E0);
    put16(&mut page, 0x96, 0x2102);
    // The optional header: PE32, the image base, alignments, Windows 5.0, the image and header
    // sizes, the console subsystem's neighbour (a DLL: GUI), sixteen directories.
    let opt = 0x98;
    put16(&mut page, opt, 0x010B);
    let put32 = |page: &mut [u8; 0x200], at: usize, v: u32| page[at..at + 4].copy_from_slice(&v.to_le_bytes());
    put32(&mut page, opt + 28, KERNEL32_BASE);
    put32(&mut page, opt + 32, 0x1000);
    put32(&mut page, opt + 36, 0x200);
    put16(&mut page, opt + 40, 5);
    put16(&mut page, opt + 48, 5);
    put32(&mut page, opt + 56, 0x1000);
    put32(&mut page, opt + 60, 0x200);
    put16(&mut page, opt + 68, 2);
    put32(&mut page, opt + 92, 16);
    page
}

/// Which module a name names: kernel32, the image (by its file name), or none.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Module {
    Kernel32,
    Image,
}

/// The module `name` (a path or a bare file name, any case; no extension means `.dll`) names, given
/// the image's own file name.
pub fn module_named(name: &[u8], image_file: &[u8]) -> Option<Module> {
    let file = &name[name.iter().rposition(|&b| b == b'\\' || b == b'/').map_or(0, |i| i + 1)..];
    let has_extension = file.contains(&b'.');
    let matches = |candidate: &[u8]| {
        if has_extension {
            file.eq_ignore_ascii_case(candidate)
        } else {
            candidate.len() == file.len() + 4
                && candidate[..file.len()].eq_ignore_ascii_case(file)
                && candidate[file.len()..].eq_ignore_ascii_case(b".dll")
        }
    };
    if matches(b"kernel32.dll") {
        Some(Module::Kernel32)
    } else if !image_file.is_empty() && matches(image_file) {
        Some(Module::Image)
    } else {
        None
    }
}

/// The module a handle is: kernel32's base, the image's base.
pub fn module_of(handle: u32) -> Option<Module> {
    match handle {
        KERNEL32_BASE => Some(Module::Kernel32),
        _ if handle != 0 && handle == image_base() => Some(Module::Image),
        _ => None,
    }
}

/// A module's handle.
pub fn handle(module: Module) -> u32 {
    match module {
        Module::Kernel32 => KERNEL32_BASE,
        Module::Image => image_base(),
    }
}

// --- Services --------------------------------------------------------------------------------------

use crate::compat::error::{ERROR_MOD_NOT_FOUND, ERROR_NOACCESS, ERROR_PROC_NOT_FOUND};
use crate::user::teb::set_last_error;

/// A module-name argument: its bytes (up to MAX_PATH), or ERROR_NOACCESS.
fn name_arg(pointer: u32, out: &mut [u8; 260]) -> Result<usize, u32> {
    let mut len = 0;
    loop {
        let mut byte = [0u8];
        crate::user::syscall::read_user(pointer + len as u32, &mut byte).map_err(|_| ERROR_NOACCESS)?;
        if byte[0] == 0 || len == out.len() {
            return Ok(len);
        }
        out[len] = byte[0];
        len += 1;
    }
}

/// The image's file name (the staged module name's last component).
fn image_file(out: &mut [u8; 260]) -> usize {
    let mut path = [0u8; 260];
    let len = crate::compat::kernel32::module_path(&mut path);
    let start = path[..len].iter().rposition(|&b| b == b'\\').map_or(0, |i| i + 1);
    out[..len - start].copy_from_slice(&path[start..len]);
    len - start
}

/// The module a name argument names, or ERROR_MOD_NOT_FOUND.
fn find_module(pointer: u32) -> Result<Module, u32> {
    let mut name = [0u8; 260];
    let len = name_arg(pointer, &mut name)?;
    let mut file = [0u8; 260];
    let file_len = image_file(&mut file);
    module_named(&name[..len], &file[..file_len]).ok_or(ERROR_MOD_NOT_FOUND)
}

/// GetModuleHandleA: the image's handle for null, else the named module's; ERROR_MOD_NOT_FOUND for
/// any other name.
pub fn svc_get_module_handle_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    if args[0] == 0 {
        frame.eax = image_base();
        return;
    }
    frame.eax = match find_module(args[0]) {
        Ok(module) => handle(module),
        Err(error) => {
            set_last_error(error);
            0
        }
    };
}

/// LoadLibraryA: an already-present module's handle (kernel32, the image); no other module loads
/// (ERROR_MOD_NOT_FOUND).
pub fn svc_load_library_a(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    svc_get_module_handle_a(frame, args);
    if args[0] == 0 {
        frame.eax = 0;
        set_last_error(crate::compat::error::ERROR_INVALID_PARAMETER);
    }
}

/// FreeLibrary: kernel32 and the image stay; freeing either succeeds. Any other handle is
/// ERROR_INVALID_HANDLE.
pub fn svc_free_library(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    frame.eax = match module_of(args[0]) {
        Some(_) => 1,
        None => {
            set_last_error(crate::compat::error::ERROR_INVALID_HANDLE);
            0
        }
    };
}

/// GetProcAddress: a kernel32 export's address, by its exact name (an ordinal finds nothing);
/// ERROR_PROC_NOT_FOUND for a name it does not export, as for the image (which exports nothing);
/// ERROR_MOD_NOT_FOUND for a handle naming no module.
pub fn svc_get_proc_address(frame: &mut crate::user::TrapFrame, args: &[u32]) {
    let (module, name) = (args[0], args[1]);
    frame.eax = 0;
    let module = if module == 0 { Some(Module::Image) } else { module_of(module) };
    let Some(module) = module else {
        return set_last_error(ERROR_MOD_NOT_FOUND);
    };
    if module == Module::Image || name < 0x1_0000 {
        return set_last_error(ERROR_PROC_NOT_FOUND);
    }
    let mut bytes = [0u8; 260];
    let len = match name_arg(name, &mut bytes) {
        Ok(len) => len,
        Err(error) => return set_last_error(error),
    };
    let found = core::str::from_utf8(&bytes[..len])
        .ok()
        .and_then(crate::compat::kernel32::resolve);
    match found {
        Some(address) => frame.eax = address,
        None => set_last_error(ERROR_PROC_NOT_FOUND),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Module names: kernel32 by any case, with or without `.dll`, through a path; the image by its
    /// file name; nothing else.
    #[test]
    fn modules_answer_to_their_names() {
        let image = b"RUNTIME.EXE";
        for name in [&b"kernel32.dll"[..], b"KERNEL32", b"Kernel32.Dll", b"C:\\WINNT\\system32\\kernel32.dll"] {
            assert_eq!(module_named(name, image), Some(Module::Kernel32), "{:?}", core::str::from_utf8(name));
        }
        assert_eq!(module_named(b"runtime.exe", image), Some(Module::Image));
        assert_eq!(module_named(b"nosuch.dll", image), None);
        assert_eq!(module_named(b"kernel32.exe", image), None);
        assert_eq!(module_named(b"runtime", image), None, "no extension means .dll");
    }

    /// The header page: MZ, the PE signature at e_lfanew, the image base in the optional header.
    #[test]
    fn the_header_page_is_a_dll_image() {
        let page = header_page();
        assert_eq!(&page[..2], b"MZ");
        let lfanew = u32::from_le_bytes(page[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(&page[lfanew..lfanew + 4], b"PE\0\0");
        let base = u32::from_le_bytes(page[lfanew + 24 + 28..lfanew + 24 + 32].try_into().unwrap());
        assert_eq!(base, KERNEL32_BASE);
    }
}
