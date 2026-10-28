//! process.h's process calls: the _spawn family (`_spawnl`, `_spawnle`, `_spawnlp`, `_spawnv`,
//! `_spawnve`, `_spawnvp`), `_cwait` and `system`, over kernel32's CreateProcessA, as MSDN
//! documents MSVC 6's C runtime (its _spawn, _exec, _cwait and system pages) and spawn's capture
//! pins them:
//!
//! - The program: a name with an extension is looked for as it is; one without is tried with
//!   `.com`, `.exe`, `.bat` and `.cmd` in turn (one ending in a period as it is, the period
//!   dropped). The p forms then look in each of PATH's directories (the C runtime's environment,
//!   which `_putenv` edits) when the name has no path of its own; the others never search. Found
//!   nowhere: -1, errno ENOENT, `_doserrno` the attributes' error.
//! - The command line: the arguments joined with single spaces, never quoted (an argument holding a
//!   space is two in the child: the capture's `"a b"`); past 1024 bytes, E2BIG.
//! - The environment: the e forms' array as a block, in its order; the others the process's own.
//! - The open descriptors go to the child in STARTUPINFO's C runtime block
//!   ([`crate::lowio::inheritance_length`]), the handles inherited (bInheritHandles TRUE).
//! - The modes: `_P_WAIT` waits and answers the exit code; `_P_NOWAIT` and `_P_NOWAITO` answer the
//!   process handle for `_cwait`; `_P_DETACH` starts it detached (DETACHED_PROCESS) and answers 0;
//!   `_P_OVERLAY` ends the caller once the child is started (`_exit(0)`, as an _exec does); any
//!   other mode is EINVAL with `_doserrno` 0, nothing started.
//! - CreateProcessA's failure is -1, its error the `_doserrno` and errno mapped from it
//!   (ERROR_BAD_EXE_FORMAT is ENOEXEC).
//! - `_cwait` waits for the process, writes its exit code where asked, closes its handle and
//!   answers it; a handle that names no process (one `_cwait` closed already) is -1, errno ECHILD,
//!   the status -1.
//! - `system` runs `%COMSPEC% /c command`, through PATH's `cmd.exe` when COMSPEC is unset or cannot
//!   be run, and answers its exit code (-1, errno ENOENT, when no command processor starts);
//!   `system(NULL)` answers whether COMSPEC names a file (0 with ENOENT when not). F2K has no
//!   cmd.exe on its disk.

use core::ptr::NonNull;

use crate::imports::{self, ProcessInformation, StartupInfoA};
use crate::thread::{
    set_dos_error,
    set_doserrno,
    set_errno,
    Locked,
    E2BIG,
    EACCES,
    ECHILD,
    EINVAL,
    ENOENT,
    ENOMEM,
};

/// The modes (process.h).
pub const P_WAIT: i32 = 0;
pub const P_NOWAIT: i32 = 1;
pub const P_OVERLAY: i32 = 2;
pub const P_NOWAITO: i32 = 3;
pub const P_DETACH: i32 = 4;

/// The longest command line the family makes, its NUL included.
const MAX_COMMAND_LINE: usize = 1024;

/// What the search tries after a name without an extension.
const EXTENSIONS: [&[u8]; 4] = [b".com", b".exe", b".bat", b".cmd"];

/// CreateProcessA's DETACHED_PROCESS; the waits' INFINITE and WAIT_OBJECT_0; GetFileAttributesA's
/// failure; ERROR_INVALID_HANDLE and ERROR_FILE_NOT_FOUND.
const DETACHED_PROCESS: u32 = 0x8;
const INFINITE: u32 = 0xFFFF_FFFF;
const WAIT_OBJECT_0: u32 = 0;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_FILE_NOT_FOUND: u32 = 2;

/// Bytes of the C runtime's heap, freed when dropped.
struct Buffer {
    block: NonNull<u8>,
    length: usize,
}

impl Buffer {
    /// `length` zeroed bytes; none (errno ENOMEM) when the heap has no room.
    fn new(length: usize) -> Option<Buffer> {
        let block = NonNull::new(crate::heap::allocate(length.max(1), true));
        if block.is_none() {
            set_errno(ENOMEM);
        }
        Some(Buffer {
            block: block?,
            length,
        })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the block holds `length` initialized bytes, ours until dropped.
        unsafe { core::slice::from_raw_parts(self.block.as_ptr(), self.length) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as above, borrowed mutably.
        unsafe { core::slice::from_raw_parts_mut(self.block.as_ptr(), self.length) }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: the block the C runtime's heap made, not used again.
        unsafe { crate::heap::release(self.block.as_ptr()) };
    }
}

/// A NULL-terminated array of NUL-terminated strings, as argv and envp are.
#[derive(Clone, Copy)]
pub struct Strings {
    array: *const *const u8,
}

impl Strings {
    /// The caller's array.
    ///
    /// # Safety
    ///
    /// `array` points at NUL-terminated strings, a null pointer after the last, all live as long as
    /// the value is used.
    pub unsafe fn new(array: *const *const u8) -> Strings {
        Strings { array }
    }

    /// The strings, in order.
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> + Clone + '_ {
        let array = self.array;
        (0..)
            // SAFETY: the array's contract: entries up to its null one.
            .map(move |at| unsafe { *array.add(at) })
            .take_while(|string| !string.is_null())
            // SAFETY: as above: each entry is NUL-terminated.
            .map(|string| unsafe { crate::string::narrow(string) })
    }
}

/// The arguments joined with single spaces into `out` (when given), NUL-terminated: the bytes the
/// command line takes, its NUL included.
pub fn join<'a>(arguments: impl Iterator<Item = &'a [u8]>, mut out: Option<&mut [u8]>) -> usize {
    let mut at = 0;
    for argument in arguments {
        if at != 0 {
            if let Some(out) = out.as_deref_mut() {
                out[at] = b' ';
            }
            at += 1;
        }
        if let Some(out) = out.as_deref_mut() {
            out[at..at + argument.len()].copy_from_slice(argument);
        }
        at += argument.len();
    }
    if let Some(out) = out {
        out[at] = 0;
    }
    at + 1
}

/// The entries as an environment block into `out` (when given): each NUL-terminated, a NUL after
/// the last (two NULs for none); the bytes it takes.
pub fn environment_block<'a>(
    entries: impl Iterator<Item = &'a [u8]>,
    mut out: Option<&mut [u8]>,
) -> usize {
    let mut at = 0;
    for entry in entries {
        if let Some(out) = out.as_deref_mut() {
            out[at..at + entry.len()].copy_from_slice(entry);
            out[at + entry.len()] = 0;
        }
        at += entry.len() + 1;
    }
    let end = if at == 0 { 2 } else { at + 1 };
    if let Some(out) = out {
        out[at..end].fill(0);
    }
    end
}

/// The kernel32 calls the family makes, each a safe call over its import.
mod calls {
    use super::*;

    /// The calling thread's last error.
    pub fn last_error() -> u32 {
        // SAFETY: kernel32's export.
        unsafe { imports::GetLastError() }
    }

    /// Whether the NUL-terminated `name` names a file or directory (GetFileAttributesA).
    pub fn exists(name: &[u8]) -> bool {
        debug_assert_eq!(name.last(), Some(&0));
        // SAFETY: kernel32's export, over the terminated name.
        unsafe { imports::GetFileAttributesA(name.as_ptr()) != INVALID_FILE_ATTRIBUTES }
    }

    /// CreateProcessA of the program `application` (NUL-terminated) with the command line, the
    /// handles inherited, the flags, the environment block (none: the process's own) and the C
    /// runtime's block; its handles and ids, or the error.
    pub fn create_process(
        application: &[u8],
        command_line: &mut [u8],
        flags: u32,
        environment: Option<&[u8]>,
        runtime_data: &[u8],
    ) -> Result<ProcessInformation, u32> {
        debug_assert_eq!(application.last(), Some(&0));
        let mut startup = StartupInfoA::new();
        startup.reserved2_length = runtime_data.len() as u16;
        startup.reserved2 = runtime_data.as_ptr();
        let mut information = ProcessInformation::default();
        // SAFETY: kernel32's export, over the terminated strings, the block and the structures.
        let created = unsafe {
            imports::CreateProcessA(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                0,
                0,
                1,
                flags,
                environment.map_or(core::ptr::null(), <[u8]>::as_ptr),
                core::ptr::null(),
                &startup,
                &mut information,
            )
        };
        if created == 0 {
            return Err(last_error());
        }
        Ok(information)
    }

    /// The process's end waited for, and its exit code; none when the handle names no process.
    pub fn wait_for(process: usize) -> Option<u32> {
        let mut code = 0;
        // SAFETY: kernel32's exports, over the local above.
        let ended = unsafe {
            imports::WaitForSingleObject(process, INFINITE) == WAIT_OBJECT_0
                && imports::GetExitCodeProcess(process, &mut code) != 0
        };
        ended.then_some(code)
    }

    /// CloseHandle.
    pub fn close(handle: usize) {
        // SAFETY: kernel32's export.
        unsafe { imports::CloseHandle(handle) };
    }
}

/// The NUL-terminated path at `out` made of `parts`, if it names a file.
fn found(parts: &[&[u8]], out: &mut [u8; 260]) -> bool {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    if length >= out.len() {
        return false;
    }
    let mut at = 0;
    for part in parts {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    out[at] = 0;
    calls::exists(&out[..=at])
}

/// The program `name` names (see the module doc), at `directory` (none: as given): with its
/// extension, as given; without one, each of [`EXTENSIONS`] added; ending in a period, as given
/// without it. Its NUL-terminated path in `out`.
fn find_in(directory: Option<&[u8]>, name: &[u8], out: &mut [u8; 260]) -> bool {
    let separator: &[u8] = match directory {
        Some(directory) if !directory.ends_with(b"\\") && !directory.ends_with(b"/") => b"\\",
        _ => b"",
    };
    let directory = directory.unwrap_or(b"");
    let file = name
        .iter()
        .rposition(|&byte| matches!(byte, b'\\' | b'/' | b':'))
        .map_or(name, |at| &name[at + 1..]);
    if let Some(stem) = name.strip_suffix(b".") {
        return found(&[directory, separator, stem], out);
    }
    if file.contains(&b'.') {
        return found(&[directory, separator, name], out);
    }
    EXTENSIONS
        .iter()
        .any(|extension| found(&[directory, separator, name, extension], out))
}

/// The program `name` names, looked for where the family looks (for the p forms, PATH's
/// directories `path` too): its NUL-terminated path in `out`; none with errno ENOENT and
/// `_doserrno` the last look's error.
fn locate(name: &[u8], path: Option<&[u8]>, out: &mut [u8; 260]) -> bool {
    if find_in(None, name, out) {
        return true;
    }
    let has_path = name.iter().any(|&byte| matches!(byte, b'\\' | b'/' | b':'));
    if let Some(path) = path.filter(|_| !has_path) {
        let directories = path.split(|&byte| byte == b';');
        for directory in directories.filter(|directory| !directory.is_empty()) {
            if find_in(Some(directory), name, out) {
                return true;
            }
        }
    }
    let error = match calls::last_error() {
        0 => ERROR_FILE_NOT_FOUND,
        error => error,
    };
    set_errno(ENOENT);
    set_doserrno(error);
    false
}

/// The family's work: `name`'s program started with `arguments` as its command line, `environment`
/// as its environment (none: the process's own), the open descriptors handed on, as `mode` says
/// (see the module doc).
pub fn spawn(
    mode: i32,
    name: &[u8],
    arguments: Strings,
    environment: Option<Strings>,
    search_path: bool,
) -> isize {
    if !matches!(mode, P_WAIT | P_NOWAIT | P_OVERLAY | P_NOWAITO | P_DETACH) {
        set_errno(EINVAL);
        set_doserrno(0);
        return -1;
    }
    let length = join(arguments.iter(), None);
    if arguments.iter().next().is_none() {
        set_errno(EINVAL);
        set_doserrno(0);
        return -1;
    }
    if length > MAX_COMMAND_LINE {
        set_errno(E2BIG);
        set_doserrno(0);
        return -1;
    }
    let mut path_variable = [0u8; 1024];
    let directories = search_path.then(|| {
        crate::startup::environment_value(b"PATH", &mut path_variable)
            .map_or(&b""[..], |length| &path_variable[..length])
    });
    let mut path = [0u8; 260];
    if !locate(name, directories, &mut path) {
        return -1;
    }
    let path_length = path.iter().position(|&byte| byte == 0).unwrap_or(0);
    let Some(mut command_line) = Buffer::new(length) else {
        return -1;
    };
    join(arguments.iter(), Some(command_line.bytes_mut()));
    let block = match environment {
        Some(entries) => {
            let Some(mut block) = Buffer::new(environment_block(entries.iter(), None)) else {
                return -1;
            };
            environment_block(entries.iter(), Some(block.bytes_mut()));
            Some(block)
        }
        None => None,
    };
    let created = {
        let _lock = Locked::take();
        let descriptors = crate::lowio::inheritance_count();
        let Some(mut runtime_data) = Buffer::new(crate::lowio::inheritance_length(descriptors))
        else {
            return -1;
        };
        crate::lowio::write_inheritance(runtime_data.bytes_mut());
        calls::create_process(
            &path[..=path_length],
            command_line.bytes_mut(),
            if mode == P_DETACH {
                DETACHED_PROCESS
            } else {
                0
            },
            block.as_ref().map(Buffer::bytes),
            runtime_data.bytes(),
        )
    };
    let process = match created {
        Ok(process) => process,
        Err(error) => {
            set_dos_error(error);
            return -1;
        }
    };
    calls::close(process.thread);
    match mode {
        P_WAIT => {
            let code = calls::wait_for(process.process);
            calls::close(process.process);
            code.map_or(-1, |code| code as i32 as isize)
        }
        P_NOWAIT | P_NOWAITO => process.process as isize,
        P_DETACH => {
            calls::close(process.process);
            0
        }
        _ => {
            calls::close(process.process);
            crate::startup::quick_exit(0)
        }
    }
}

/// `_spawnv(mode, cmdname, argv)`, `_spawnve` and `_spawnvp`'s work: the caller's strings read.
///
/// # Safety
///
/// `name` is NUL-terminated; `argv` (and `envp` when not null) are NULL-terminated arrays of
/// NUL-terminated strings.
unsafe fn spawn_arrays(
    mode: i32,
    name: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
    search_path: bool,
) -> isize {
    // SAFETY: the caller's contract.
    let (name, arguments, environment) = unsafe {
        (
            crate::string::narrow(name),
            Strings::new(argv),
            (!envp.is_null()).then(|| Strings::new(envp)),
        )
    };
    spawn(mode, name, arguments, environment, search_path)
}

/// _spawnv: the program started with the arguments, the process's environment.
///
/// # Safety
///
/// `name` is NUL-terminated; `argv` a NULL-terminated array of NUL-terminated strings.
#[unsafe(export_name = "f2k_export__spawnv")]
pub unsafe extern "C" fn spawnv(mode: i32, name: *const u8, argv: *const *const u8) -> isize {
    // SAFETY: the caller's contract.
    unsafe { spawn_arrays(mode, name, argv, core::ptr::null(), false) }
}

/// _spawnve: as _spawnv, the environment `envp`'s (the process's own for NULL).
///
/// # Safety
///
/// As _spawnv's; `envp` null or a NULL-terminated array of NUL-terminated strings.
#[unsafe(export_name = "f2k_export__spawnve")]
pub unsafe extern "C" fn spawnve(
    mode: i32,
    name: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> isize {
    // SAFETY: the caller's contract.
    unsafe { spawn_arrays(mode, name, argv, envp, false) }
}

/// _spawnvp: as _spawnv, the program looked for in PATH's directories too.
///
/// # Safety
///
/// As _spawnv's.
#[unsafe(export_name = "f2k_export__spawnvp")]
pub unsafe extern "C" fn spawnvp(mode: i32, name: *const u8, argv: *const *const u8) -> isize {
    // SAFETY: the caller's contract.
    unsafe { spawn_arrays(mode, name, argv, core::ptr::null(), true) }
}

/// _spawnl's body: `arguments` the address of its first variable argument, where the caller
/// pushed arg0, arg1, ... NULL (cdecl: an argv array).
///
/// # Safety
///
/// As _spawnv's, `arguments` the array.
pub unsafe extern "C" fn spawnl_va(
    mode: i32,
    name: *const u8,
    arguments: *const *const u8,
) -> isize {
    // SAFETY: the caller's contract.
    unsafe { spawn_arrays(mode, name, arguments, core::ptr::null(), false) }
}

/// _spawnlp's body (as _spawnl's, PATH searched).
///
/// # Safety
///
/// As _spawnl_va's.
pub unsafe extern "C" fn spawnlp_va(
    mode: i32,
    name: *const u8,
    arguments: *const *const u8,
) -> isize {
    // SAFETY: the caller's contract.
    unsafe { spawn_arrays(mode, name, arguments, core::ptr::null(), true) }
}

/// _spawnle's body (as _spawnl's): the envp pointer follows the arguments' NULL.
///
/// # Safety
///
/// As _spawnl_va's, an envp array (or NULL) after the NULL.
pub unsafe extern "C" fn spawnle_va(
    mode: i32,
    name: *const u8,
    arguments: *const *const u8,
) -> isize {
    // SAFETY: the caller's contract: the arguments up to their NULL, the envp pointer next.
    let envp = unsafe {
        let count = Strings::new(arguments).iter().count();
        *arguments.add(count + 1) as *const *const u8
    };
    // SAFETY: as above.
    unsafe { spawn_arrays(mode, name, arguments, envp, false) }
}

/// The l forms: each hands its mode, its name and the address of its variable arguments (where
/// its caller pushed them, cdecl: an argv array) to its body.
#[cfg(target_arch = "x86")]
mod variadic {
    use super::*;

    /// _spawnl(mode, cmdname, arg0, ..., NULL).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export__spawnl")]
    pub unsafe extern "C" fn spawnl() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym spawnl_va,
        )
    }

    /// _spawnlp(mode, cmdname, arg0, ..., NULL).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export__spawnlp")]
    pub unsafe extern "C" fn spawnlp() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym spawnlp_va,
        )
    }

    /// _spawnle(mode, cmdname, arg0, ..., NULL, envp).
    #[unsafe(naked)]
    #[unsafe(export_name = "f2k_export__spawnle")]
    pub unsafe extern "C" fn spawnle() {
        core::arch::naked_asm!(
            "lea eax, [esp+12]",
            "push eax",
            "push dword ptr [esp+12]",
            "push dword ptr [esp+12]",
            "call {body}",
            "add esp, 12",
            "ret",
            body = sym spawnle_va,
        )
    }
}

/// _cwait: the process waited for (the action ignored, as Windows NT's C runtime ignores it), its
/// exit code into `*status` when asked, its handle closed; answers the handle. A handle naming no
/// process is -1, errno ECHILD (another error is its errno), the status -1.
///
/// # Safety
///
/// `status` is null or writable.
#[unsafe(export_name = "f2k_export__cwait")]
pub unsafe extern "C" fn cwait(status: *mut i32, process: isize, _action: i32) -> isize {
    // SAFETY: the caller's slot.
    let status = unsafe { status.as_mut() };
    let handle = process as usize;
    let (answer, code) = match calls::wait_for(handle) {
        Some(code) => (process, code as i32),
        None => {
            match calls::last_error() {
                ERROR_INVALID_HANDLE => {
                    set_errno(ECHILD);
                    set_doserrno(ERROR_INVALID_HANDLE);
                }
                error => set_dos_error(error),
            }
            (-1, -1)
        }
    };
    calls::close(handle);
    if let Some(status) = status {
        *status = code;
    }
    answer
}

/// system: `command` run by the command processor (see the module doc); for NULL, whether there
/// is one.
///
/// # Safety
///
/// `command` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export_system")]
pub unsafe extern "C" fn system(command: *const u8) -> i32 {
    let mut comspec = [0u8; 260];
    let comspec = crate::startup::environment_value(b"COMSPEC", &mut comspec[..259])
        .map(|length| &comspec[..=length]);
    if command.is_null() {
        let found = comspec.is_some_and(calls::exists);
        if !found {
            set_errno(ENOENT);
        }
        return i32::from(found);
    }
    let processor: &[u8] = b"cmd.exe\0";
    let switch: &[u8] = b"/c\0";
    let mut argv = [
        processor.as_ptr(),
        switch.as_ptr(),
        command,
        core::ptr::null(),
    ];
    if let Some(comspec) = comspec {
        argv[0] = comspec.as_ptr();
        // SAFETY: the array above, of NUL-terminated strings, NULL-terminated.
        let arguments = unsafe { Strings::new(argv.as_ptr()) };
        let answer = spawn(
            P_WAIT,
            &comspec[..comspec.len() - 1],
            arguments,
            None,
            false,
        );
        // SAFETY: the calling thread's errno.
        let errno = unsafe { *crate::thread::errno_address() };
        if answer != -1 || (errno != ENOENT && errno != EACCES) {
            return answer as i32;
        }
        argv[0] = processor.as_ptr();
    }
    // SAFETY: as above.
    let arguments = unsafe { Strings::new(argv.as_ptr()) };
    spawn(P_WAIT, b"cmd.exe", arguments, None, true) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::host::{
        ATTRIBUTES_ASKED,
        CLOSED,
        CREATED,
        CREATE_FAILS,
        EXISTING,
        EXIT_CODE,
        PROCESS,
        THREAD,
    };

    fn errno() -> (i32, u32) {
        // SAFETY: the calling thread's own data.
        unsafe {
            (
                *crate::thread::errno_address(),
                *crate::thread::doserrno_address(),
            )
        }
    }

    fn reset() {
        CREATED.with(|created| created.borrow_mut().clear());
        CLOSED.with(|closed| closed.borrow_mut().clear());
        ATTRIBUTES_ASKED.with(|asked| asked.borrow_mut().clear());
        set_errno(0);
        set_doserrno(0);
    }

    fn existing(paths: &[&str]) {
        EXISTING.with(|existing| {
            *existing.borrow_mut() = paths.iter().map(|path| path.to_string()).collect()
        });
    }

    /// An argv array over the strings (each with its NUL), NULL-terminated.
    fn argv(strings: &[&[u8]]) -> Vec<*const u8> {
        strings
            .iter()
            .map(|string| string.as_ptr())
            .chain([core::ptr::null()])
            .collect()
    }

    fn created() -> crate::imports::host::Created {
        CREATED.with(|created| created.borrow().last().unwrap().clone())
    }

    /// The arguments are joined with single spaces, never quoted: an argument holding a space
    /// splits in the child, as spawn's capture shows (`spawnkid args a b c`).
    #[test]
    fn arguments_join_with_spaces_unquoted() {
        let arguments: [&[u8]; 4] = [b"spawnkid", b"args", b"a b", b"c"];
        let length = join(arguments.iter().copied(), None);
        assert_eq!(length, 20);
        let mut out = [0xCCu8; 20];
        join(arguments.iter().copied(), Some(&mut out));
        assert_eq!(&out, b"spawnkid args a b c\0");
        assert_eq!(join(core::iter::once(&b""[..]), None), 1);
    }

    /// An environment block is the entries in their order, each NUL-terminated, a NUL after the
    /// last; none at all is two NULs.
    #[test]
    fn environment_entries_make_a_block() {
        let entries: [&[u8]; 2] = [b"F2KE=one", b"F2KF=two words"];
        let length = environment_block(entries.iter().copied(), None);
        let mut out = vec![0xCCu8; length];
        environment_block(entries.iter().copied(), Some(&mut out));
        assert_eq!(out, b"F2KE=one\0F2KF=two words\0\0");
        let mut empty = [0xCCu8; 2];
        assert_eq!(environment_block(core::iter::empty(), Some(&mut empty)), 2);
        assert_eq!(empty, [0, 0]);
    }

    /// The C runtime's block: the count, the flags bytes, then the handles, little-endian dwords;
    /// decoding gives them back, no more than the block holds.
    #[test]
    fn the_inherited_descriptors_block_round_trips() {
        use crate::lowio::{decode_inheritance, encode_inheritance, inheritance_length};
        let descriptors = [(0xC1u8, 3u32), (0, u32::MAX), (0x01, 0x44)];
        let mut block = vec![0xCCu8; inheritance_length(3)];
        encode_inheritance(descriptors.iter().copied(), &mut block);
        assert_eq!(
            block,
            [3, 0, 0, 0, 0xC1, 0, 0x01, 3, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0x44, 0, 0, 0]
        );
        assert_eq!(decode_inheritance(&block).collect::<Vec<_>>(), descriptors);
        assert_eq!(decode_inheritance(&block[..10]).count(), 1, "cut short");
        assert_eq!(decode_inheritance(&[]).count(), 0);
    }

    /// _spawnv with _P_WAIT: a name without an extension tried with .com then .exe; CreateProcessA
    /// handed the path found, the arguments joined, the handles inherited and the descriptors'
    /// block; the thread's and process's handles closed; the exit code answered.
    #[test]
    fn spawn_wait_runs_and_answers_the_exit_code() {
        reset();
        existing(&["spawnkid.exe"]);
        EXIT_CODE.with(|code| code.set(5));
        let arguments = argv(&[b"spawnkid\0", b"exit\0", b"5\0"]);
        // SAFETY: a NUL-terminated name; `argv` makes a NULL-terminated array of NUL-terminated
        // strings, alive for the call.
        let answer = unsafe { spawnv(P_WAIT, b"spawnkid\0".as_ptr(), arguments.as_ptr()) };
        assert_eq!(answer, 5);
        ATTRIBUTES_ASKED
            .with(|asked| assert_eq!(*asked.borrow(), ["spawnkid.com", "spawnkid.exe"]));
        let made = created();
        assert_eq!(
            (
                made.application_name.as_str(),
                made.command_line.as_str(),
                made.inherit_handles,
                made.flags,
                made.environment
            ),
            ("spawnkid.exe", "spawnkid exit 5", true, 0, None)
        );
        assert_eq!(
            made.runtime_data.len() % 5,
            4,
            "a count and five bytes a descriptor"
        );
        CLOSED.with(|closed| assert_eq!(*closed.borrow(), [THREAD, PROCESS]));
        assert_eq!(errno(), (0, 0));
    }

    /// _P_NOWAIT answers the process handle; _cwait waits for it, writes its exit code, closes it
    /// and answers it; a second _cwait on the closed handle is -1, ECHILD, the status -1.
    #[test]
    fn nowait_and_cwait() {
        reset();
        existing(&["C:\\CORPUS\\SPAWNKID.EXE"]);
        EXIT_CODE.with(|code| code.set(9));
        let arguments = argv(&[b"spawnkid\0", b"exit\0", b"9\0"]);
        let name = b"C:\\CORPUS\\SPAWNKID.EXE\0";
        // SAFETY: a NUL-terminated name; `argv` makes a NULL-terminated array of NUL-terminated
        // strings, alive for the call.
        let handle = unsafe { spawnv(P_NOWAIT, name.as_ptr(), arguments.as_ptr()) };
        assert_eq!(handle, PROCESS as isize);
        let mut status = 0xF2F2;
        // SAFETY: `status` is a writable local.
        assert_eq!(unsafe { cwait(&mut status, handle, 0) }, handle);
        assert_eq!(status, 9);
        // SAFETY: as above.
        assert_eq!(unsafe { cwait(&mut status, handle, 0) }, -1);
        assert_eq!((status, errno()), (-1, (ECHILD, 6)));
        // SAFETY: a null status, which _cwait leaves unwritten.
        assert_eq!(unsafe { cwait(core::ptr::null_mut(), handle, 0) }, -1);
    }

    /// The program: the name as given first, then (the p forms) each of PATH's directories; a
    /// name with an extension tried alone, one ending in a period without it. A name found
    /// nowhere is ENOENT, `_doserrno` 2 (the search without PATH: _spawnv's); a name with a path
    /// of its own is not looked for in PATH.
    #[test]
    fn the_program_is_looked_for() {
        let mut out = [0u8; 260];
        let found = |out: &[u8; 260]| {
            let length = out.iter().position(|&byte| byte == 0).unwrap();
            String::from_utf8(out[..length].to_vec()).unwrap()
        };
        let path = Some(&b"C:\\TOOLS;;C:\\OTHER\\"[..]);
        reset();
        existing(&["C:\\OTHER\\kidcopy.exe"]);
        assert!(locate(b"kidcopy", path, &mut out));
        assert_eq!(found(&out), "C:\\OTHER\\kidcopy.exe");
        let asked = ATTRIBUTES_ASKED.with(|asked| asked.borrow().clone());
        assert_eq!(
            asked[..6],
            [
                "kidcopy.com",
                "kidcopy.exe",
                "kidcopy.bat",
                "kidcopy.cmd",
                "C:\\TOOLS\\kidcopy.com",
                "C:\\TOOLS\\kidcopy.exe"
            ]
        );
        reset();
        assert!(!locate(b"kidcopy", None, &mut out));
        assert_eq!(errno(), (ENOENT, 2));
        assert_eq!(ATTRIBUTES_ASKED.with(|asked| asked.borrow().len()), 4);
        reset();
        assert!(!locate(b"sub\\kidcopy", path, &mut out));
        assert_eq!(ATTRIBUTES_ASKED.with(|asked| asked.borrow().len()), 4);
        reset();
        existing(&["notexe.txt", "dotted"]);
        assert!(locate(b"notexe.txt", path, &mut out));
        assert!(locate(b"dotted.", None, &mut out));
        assert_eq!(found(&out), "dotted");
        ATTRIBUTES_ASKED.with(|asked| assert_eq!(*asked.borrow(), ["notexe.txt", "dotted"]));
    }

    /// The e forms hand the child their environment as a block; a failed CreateProcessA is -1 with
    /// its error mapped (ERROR_BAD_EXE_FORMAT: ENOEXEC); an unknown mode is EINVAL, `_doserrno`
    /// 0, nothing started.
    #[test]
    fn environments_failures_and_modes() {
        reset();
        existing(&["kid.exe", "notexe.txt"]);
        let arguments = argv(&[b"kid\0", b"envall\0"]);
        let envp = argv(&[b"F2KE=one\0", b"F2KF=two words\0"]);
        // SAFETY: a NUL-terminated name; `arguments` and `envp` NULL-terminated arrays of
        // NUL-terminated strings (`argv`'s), alive for the call.
        let answer = unsafe {
            spawnve(
                P_WAIT,
                b"kid.exe\0".as_ptr(),
                arguments.as_ptr(),
                envp.as_ptr(),
            )
        };
        assert_eq!(answer, 0);
        assert_eq!(
            created().environment.as_deref(),
            Some(&b"F2KE=one\0F2KF=two words\0\0"[..])
        );
        reset();
        let mut list = argv(&[b"kid\0", b"envall\0"]);
        list.push(envp.as_ptr().cast());
        // SAFETY: a NUL-terminated name; `list` the arguments, their NULL, then the envp array, as
        // _spawnle's variable arguments lie on the stack, all alive for the call.
        let answer = unsafe { spawnle_va(P_WAIT, b"kid.exe\0".as_ptr(), list.as_ptr()) };
        assert_eq!(answer, 0);
        assert_eq!(
            created().environment.as_deref(),
            Some(&b"F2KE=one\0F2KF=two words\0\0"[..])
        );
        reset();
        CREATE_FAILS.with(|fails| fails.set(193));
        // SAFETY: a NUL-terminated name; `argv` makes a NULL-terminated array of NUL-terminated
        // strings, alive for the call.
        let answer = unsafe { spawnv(P_WAIT, b"notexe.txt\0".as_ptr(), arguments.as_ptr()) };
        assert_eq!((answer, errno()), (-1, (8, 193)));
        reset();
        // SAFETY: as above.
        let answer = unsafe { spawnv(99, b"kid.exe\0".as_ptr(), arguments.as_ptr()) };
        assert_eq!((answer, errno()), (-1, (EINVAL, 0)));
        assert!(CREATED.with(|created| created.borrow().is_empty()));
        reset();
        let long = [b'x'; 1100];
        let mut long = long.to_vec();
        long.push(0);
        let arguments = argv(&[b"kid\0", &long]);
        // SAFETY: as above, the long argument NUL-terminated too.
        let answer = unsafe { spawnv(P_WAIT, b"kid.exe\0".as_ptr(), arguments.as_ptr()) };
        assert_eq!((answer, errno().0), (-1, E2BIG));
    }
}
