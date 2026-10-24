//! Program start-up and exit: what a /MD program's own start-up code (linked into it from
//! msvcrt.lib) calls before and after `main`, and the DLL's own initialization.
//!
//! The start-up code says the program's kind (`__set_app_type`), copies its `_fmode` and
//! `_commode` through `__p__fmode` and `__p__commode`, sets the floating-point precision
//! (`_controlfp`), runs its C initializers (`_initterm` over `.CRT$XI*`), takes argc, argv and envp
//! (`__getmainargs`), runs its C++ constructors (`_initterm` over `.CRT$XC*`), calls `main` under
//! an exception filter (`_XcptFilter`), and ends with `exit` (or `_exit` from its handler). As
//! crt's capture pins it:
//!
//! - argv is the command line split as MSDN's "Parsing C Command-Line Arguments" says (blanks
//!   separate; quotes group, `\"` is a quote, backslashes are literal unless a quote follows, 2n of
//!   them before a quote are n and the quote groups, 2n+1 are n and a literal quote); argv[0] ends
//!   at its closing quote or first blank, backslashes literal. `__argc` is 0 until then.
//! - envp, `_environ` and `__initenv` are one array: the environment block's entries, in order,
//!   less those starting with `=` (cmd.exe's per-drive current directories).
//! - `_fmode` and `_commode` are 0; the start-up's `_controlfp(_PC_53, _MCW_PC)` leaves 0x9001F.
//! - exit runs the `_onexit`/`atexit` functions, last registered first, then flushes the streams,
//!   then ends the process; `_exit` ends it at once (nothing run, nothing flushed).
//! - An exception the program does not handle reaches `_XcptFilter`, which hands it to
//!   UnhandledExceptionFilter; the start-up's handler ends the process with the exception's code.

use crate::data::{Exported, Global, FMODE};
use crate::imports;
use crate::lowio::APP_TYPE;
use crate::thread::Locked;

/// `_commode`: the default commit mode of the streams a program opens (0).
static COMMODE: Exported<i32> = Exported::new(0);
/// `__argc` and `__argv` (`__getmainargs` sets them), `_environ` and `__initenv` (the DLL's
/// initialization does).
static ARGC: Exported<i32> = Exported::new(0);
static ARGV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
static ENVIRON: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
static INITENV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
/// The program's `_matherr` (`__setusermatherr`).
static USER_MATHERR: Global<usize> = Global::new(0);

/// The exit functions: a growable array from the C runtime's heap, in registration order.
struct ExitTable {
    functions: *mut usize,
    count: usize,
    capacity: usize,
}

static EXIT_TABLE: Global<ExitTable> = Global::new(ExitTable {
    functions: core::ptr::null_mut(),
    count: 0,
    capacity: 0,
});

/// Whether exit or _exit has run: the DLL's detach then leaves the process as they did.
static EXITED: Global<bool> = Global::new(false);

/// __set_app_type: the program's kind, 1 a console program, 2 a GUI one.
#[unsafe(export_name = "f2k_export___set_app_type")]
pub extern "C" fn set_app_type(kind: i32) {
    APP_TYPE.write(kind);
}

/// __p__fmode: `_fmode`'s address.
#[unsafe(export_name = "f2k_export___p__fmode")]
pub extern "C" fn p_fmode() -> *mut i32 {
    FMODE.get()
}

/// __p__commode: `_commode`'s address.
#[unsafe(export_name = "f2k_export___p__commode")]
pub extern "C" fn p_commode() -> *mut i32 {
    COMMODE.get()
}

/// __p___argc: `__argc`'s address.
#[unsafe(export_name = "f2k_export___p___argc")]
pub extern "C" fn p_argc() -> *mut i32 {
    ARGC.get()
}

/// __p___argv: `__argv`'s address.
#[unsafe(export_name = "f2k_export___p___argv")]
pub extern "C" fn p_argv() -> *mut *mut *mut u8 {
    ARGV.get()
}

/// __p__environ: `_environ`'s address.
#[unsafe(export_name = "f2k_export___p__environ")]
pub extern "C" fn p_environ() -> *mut *mut *mut u8 {
    ENVIRON.get()
}

/// __p___initenv: `__initenv`'s address (the environment `main` was given).
#[unsafe(export_name = "f2k_export___p___initenv")]
pub extern "C" fn p_initenv() -> *mut *mut *mut u8 {
    INITENV.get()
}

/// __setusermatherr: the program's `_matherr`, kept.
#[unsafe(export_name = "f2k_export___setusermatherr")]
pub extern "C" fn setusermatherr(handler: usize) {
    USER_MATHERR.write(handler);
}

/// float.h's control word, abstract: the exception masks, the infinity, rounding and precision
/// controls.
const EM_INEXACT: u32 = 0x0000_0001;
const EM_UNDERFLOW: u32 = 0x0000_0002;
const EM_OVERFLOW: u32 = 0x0000_0004;
const EM_ZERODIVIDE: u32 = 0x0000_0008;
const EM_INVALID: u32 = 0x0000_0010;
const EM_DENORMAL: u32 = 0x0008_0000;
const MCW_RC: u32 = 0x0000_0300;
const IC_AFFINE: u32 = 0x0004_0000;
const PC_24: u32 = 0x0002_0000;
const PC_53: u32 = 0x0001_0000;

/// The x87 control word's mask bits, each beside its abstract one.
const MASKS: [(u16, u32); 6] = [
    (0x01, EM_INVALID),
    (0x02, EM_DENORMAL),
    (0x04, EM_ZERODIVIDE),
    (0x08, EM_OVERFLOW),
    (0x10, EM_UNDERFLOW),
    (0x20, EM_INEXACT),
];

/// An x87 control word as float.h's.
fn abstract_word(x87: u16) -> u32 {
    let mut word = MASKS
        .iter()
        .filter(|(bit, _)| x87 & bit != 0)
        .fold(0, |word, (_, flag)| word | flag);
    word |= ((x87 >> 2) as u32) & MCW_RC;
    word |= match (x87 >> 8) & 3 {
        0 => PC_24,
        2 => PC_53,
        3 => 0,
        _ => PC_24,
    };
    if x87 & 0x1000 != 0 {
        word |= IC_AFFINE;
    }
    word
}

/// float.h's control word as the x87's (its reserved bits from `old`).
fn x87_word(word: u32, old: u16) -> u16 {
    let mut x87 = old & !0x1F3F;
    x87 |= MASKS
        .iter()
        .filter(|(_, flag)| word & flag != 0)
        .fold(0, |x87, (bit, _)| x87 | bit);
    x87 |= ((word & MCW_RC) << 2) as u16;
    x87 |= match word & (PC_24 | PC_53) {
        PC_24 => 0x000,
        PC_53 => 0x200,
        0 => 0x300,
        _ => 0x000,
    };
    if word & IC_AFFINE != 0 {
        x87 |= 0x1000;
    }
    x87
}

/// The FPU's control word, read and written.
#[cfg(target_arch = "x86")]
mod fpu {
    pub fn read() -> u16 {
        let mut word = 0u16;
        // SAFETY: fnstcw stores the control word.
        unsafe { core::arch::asm!("fnstcw [{}]", in(reg) &mut word, options(nostack)) };
        word
    }

    pub fn write(word: u16) {
        // SAFETY: fldcw loads a control word the C runtime built.
        unsafe { core::arch::asm!("fldcw [{}]", in(reg) &word, options(nostack)) };
    }
}

/// The host's stand-in: the word kept in a variable.
#[cfg(not(target_arch = "x86"))]
mod fpu {
    static WORD: crate::data::Global<u16> = crate::data::Global::new(0x027F);

    pub fn read() -> u16 {
        WORD.read()
    }

    pub fn write(word: u16) {
        WORD.write(word)
    }
}

/// _controlfp: the floating-point control word's `mask` bits set from `new` (the denormal
/// exception's mask left alone, as MSDN documents); the word as it is now.
#[unsafe(export_name = "f2k_export__controlfp")]
pub extern "C" fn controlfp(new: u32, mask: u32) -> u32 {
    let mask = mask & !EM_DENORMAL;
    let old = fpu::read();
    if mask != 0 {
        let word = (new & mask) | (abstract_word(old) & !mask);
        fpu::write(x87_word(word, old));
    }
    abstract_word(fpu::read())
}

/// _initterm: each non-null function of the table `[begin, end)` called, in order.
///
/// # Safety
///
/// The table holds null or callable `void (*)(void)` entries.
#[unsafe(export_name = "f2k_export__initterm")]
pub unsafe extern "C" fn initterm(begin: *const usize, end: *const usize) {
    let mut at = begin;
    while at < end {
        // SAFETY: the caller's table.
        let function = unsafe { at.read() };
        if function != 0 {
            // SAFETY: the caller's initializer.
            unsafe { core::mem::transmute::<usize, extern "C" fn()>(function)() };
        }
        // SAFETY: inside the table.
        at = unsafe { at.add(1) };
    }
}

/// A command line split into arguments, each byte handed to `each` (`None` ends an argument).
pub fn split(line: &[u8], mut each: impl FnMut(Option<u8>)) {
    let blank = |b: u8| b == b' ' || b == b'\t';
    let mut i = 0;
    // argv[0]: to its closing quote, or to a blank.
    if line.first() == Some(&b'"') {
        i = 1;
        while i < line.len() && line[i] != b'"' {
            each(Some(line[i]));
            i += 1;
        }
        i += 1;
    }
    while i < line.len() && !blank(line[i]) {
        each(Some(line[i]));
        i += 1;
    }
    each(None);
    loop {
        while i < line.len() && blank(line[i]) {
            i += 1;
        }
        if i >= line.len() {
            return;
        }
        let mut quoted = false;
        while i < line.len() && (quoted || !blank(line[i])) {
            let mut backslashes = 0;
            while i < line.len() && line[i] == b'\\' {
                backslashes += 1;
                i += 1;
            }
            if i < line.len() && line[i] == b'"' {
                for _ in 0..backslashes / 2 {
                    each(Some(b'\\'));
                }
                if backslashes % 2 == 1 {
                    each(Some(b'"'));
                } else if quoted && line.get(i + 1) == Some(&b'"') {
                    // "" inside quotes: a quote, and the quotes end.
                    each(Some(b'"'));
                    i += 1;
                    quoted = false;
                } else {
                    quoted = !quoted;
                }
                i += 1;
            } else {
                for _ in 0..backslashes {
                    each(Some(b'\\'));
                }
                if i < line.len() && (quoted || !blank(line[i])) {
                    each(Some(line[i]));
                    i += 1;
                }
            }
        }
        each(None);
    }
}

/// The C runtime's copy of a NUL-terminated string array's worth: `count` pointers (and a NULL)
/// followed by `bytes` bytes, in one block.
fn array_block(count: usize, bytes: usize) -> *mut *mut u8 {
    let size = (count + 1) * core::mem::size_of::<usize>() + bytes;
    crate::heap::allocate(size, true).cast()
}

/// __getmainargs: argc, argv and envp for `main`, from the command line and the environment;
/// `__argc` and `__argv` too. 0, or -1 when there is no memory for them. (`dowildcard`, the
/// wildcard expansion setargv.obj asks for, is not served: the arguments stay as given.)
///
/// # Safety
///
/// The pointers are the start-up's storage for argc, argv and envp.
#[unsafe(export_name = "f2k_export___getmainargs")]
pub unsafe extern "C" fn getmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut u8,
    envp: *mut *mut *mut u8,
    _dowildcard: i32,
    _startinfo: *mut i32,
) -> i32 {
    // SAFETY: kernel32's export; the command line, NUL-terminated.
    let line = unsafe { core::ffi::CStr::from_ptr(imports::GetCommandLineA().cast()) }.to_bytes();
    let (mut count, mut bytes) = (0usize, 0usize);
    split(line, |b| {
        bytes += 1;
        if b.is_none() {
            count += 1;
        }
    });
    let block = array_block(count, bytes);
    if block.is_null() {
        return -1;
    }
    // SAFETY: the block holds `count + 1` pointers, then the bytes.
    unsafe {
        let mut text = block.add(count + 1).cast::<u8>();
        let mut index = 0;
        *block = text;
        split(line, |b| match b {
            Some(byte) => {
                text.write(byte);
                text = text.add(1);
            }
            None => {
                text.write(0);
                text = text.add(1);
                index += 1;
                *block.add(index) = if index < count {
                    text
                } else {
                    core::ptr::null_mut()
                };
            }
        });
        *ARGC.get() = count as i32;
        *ARGV.get() = block;
        *INITENV.get() = *ENVIRON.get();
        argc.write(count as i32);
        argv.write(block);
        envp.write(*ENVIRON.get());
    }
    0
}

/// The DLL's process attach: `_environ` from the environment block, less its `=` entries.
pub fn initialize_environment() -> bool {
    // SAFETY: kernel32's exports; the block, double-NUL-terminated, read then given back.
    unsafe {
        let block = imports::GetEnvironmentStrings();
        if block.is_null() {
            return false;
        }
        let entries = || {
            let mut at = block;
            core::iter::from_fn(move || {
                let entry = core::ffi::CStr::from_ptr(at.cast()).to_bytes();
                if entry.is_empty() {
                    return None;
                }
                at = at.add(entry.len() + 1);
                Some(entry)
            })
            .filter(|entry| entry[0] != b'=')
        };
        let count = entries().count();
        let bytes: usize = entries().map(|entry| entry.len() + 1).sum();
        let array = array_block(count, bytes);
        if array.is_null() {
            imports::FreeEnvironmentStringsA(block);
            return false;
        }
        let mut text = array.add(count + 1).cast::<u8>();
        for (i, entry) in entries().enumerate() {
            *array.add(i) = text;
            core::ptr::copy_nonoverlapping(entry.as_ptr(), text, entry.len());
            text = text.add(entry.len());
            text.write(0);
            text = text.add(1);
        }
        *ENVIRON.get() = array;
        *INITENV.get() = array;
        imports::FreeEnvironmentStringsA(block);
        true
    }
}

/// A function appended to a table that grows in the C runtime's heap: its array and its count.
///
/// # Safety
///
/// `functions` is null or a block of the C runtime's heap holding `count` entries.
unsafe fn append(
    functions: *mut usize,
    count: usize,
    capacity: usize,
    function: usize,
) -> Option<(*mut usize, usize)> {
    let (functions, capacity) = if count < capacity {
        (functions, capacity)
    } else {
        let capacity = (capacity * 2).max(32);
        let bytes = capacity * core::mem::size_of::<usize>();
        let grown = if functions.is_null() {
            crate::heap::allocate(bytes, false)
        } else {
            // SAFETY: the caller's block.
            unsafe { crate::heap::resize(functions.cast(), bytes) }
        };
        if grown.is_null() {
            return None;
        }
        (grown.cast(), capacity)
    };
    // SAFETY: inside the (grown) table.
    unsafe { functions.add(count).write(function) };
    Some((functions, capacity))
}

/// _onexit: `function` registered for exit, which calls them last registered first; answers it, or
/// NULL when the table cannot grow (atexit's -1).
#[unsafe(export_name = "f2k_export__onexit")]
pub extern "C" fn onexit(function: usize) -> usize {
    let _lock = Locked::take();
    // SAFETY: the exit table, under the lock.
    unsafe {
        let table = &mut *EXIT_TABLE.get();
        match append(table.functions, table.count, table.capacity, function) {
            Some((functions, capacity)) => {
                table.functions = functions;
                table.capacity = capacity;
                table.count += 1;
                function
            }
            None => 0,
        }
    }
}

/// __dllonexit: `function` appended to a DLL's own exit table, `*begin` to `*end` (a block of the
/// C runtime's heap, grown as needed); answers it, or NULL.
///
/// # Safety
///
/// `begin` and `end` hold the table's bounds, the table a block from malloc.
#[unsafe(export_name = "f2k_export___dllonexit")]
pub unsafe extern "C" fn dllonexit(
    function: usize,
    begin: *mut *mut usize,
    end: *mut *mut usize,
) -> usize {
    let _lock = Locked::take();
    // SAFETY: the caller's table.
    unsafe {
        let functions = *begin;
        let count = if functions.is_null() {
            0
        } else {
            (*end).offset_from(functions) as usize
        };
        let capacity = if functions.is_null() {
            0
        } else {
            crate::heap::size_of(functions.cast()) / core::mem::size_of::<usize>()
        };
        match append(functions, count, capacity, function) {
            Some((functions, _)) => {
                *begin = functions;
                *end = functions.add(count + 1);
                function
            }
            None => 0,
        }
    }
}

/// The exit functions run, last registered first (one that registers another has it run too).
fn run_exit_functions() {
    loop {
        let function = {
            let _lock = Locked::take();
            // SAFETY: the exit table, under the lock.
            let table = unsafe { &mut *EXIT_TABLE.get() };
            if table.count == 0 {
                break;
            }
            table.count -= 1;
            // SAFETY: inside the table.
            unsafe { table.functions.add(table.count).read() }
        };
        if function != 0 {
            // SAFETY: a function the program registered.
            unsafe { core::mem::transmute::<usize, extern "C" fn()>(function)() };
        }
    }
}

/// exit: the exit functions run, the streams flushed, the process ended with `status`.
#[unsafe(export_name = "f2k_export_exit")]
pub extern "C" fn exit(status: i32) -> ! {
    run_exit_functions();
    crate::stdio::flush_all();
    EXITED.write(true);
    // SAFETY: kernel32's export.
    unsafe { imports::ExitProcess(status as u32) }
}

/// _exit: the process ended with `status` at once.
#[unsafe(export_name = "f2k_export__exit")]
pub extern "C" fn quick_exit(status: i32) -> ! {
    EXITED.write(true);
    // SAFETY: kernel32's export.
    unsafe { imports::ExitProcess(status as u32) }
}

/// The DLL's detach as the process ends without exit or _exit (ExitProcess straight from the
/// program): the exit functions run and the streams flushed, as exit would.
pub fn detach_process() {
    if !EXITED.read() {
        EXITED.write(true);
        run_exit_functions();
        crate::stdio::flush_all();
    }
}

/// _XcptFilter: the start-up's filter of an exception `main` did not handle: the process's
/// unhandled-exception filter decides (no signal handler is installed through this DLL).
///
/// # Safety
///
/// `pointers` is the exception's EXCEPTION_POINTERS.
#[unsafe(export_name = "f2k_export__XcptFilter")]
pub unsafe extern "C" fn xcpt_filter(_code: u32, pointers: usize) -> i32 {
    // SAFETY: kernel32's export, over the dispatcher's pointers.
    unsafe { imports::UnhandledExceptionFilter(pointers) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(line: &[u8]) -> Vec<String> {
        let mut out = vec![String::new()];
        split(line, |b| match b {
            Some(byte) => out.last_mut().unwrap().push(byte as char),
            None => out.push(String::new()),
        });
        out.pop();
        out
    }

    /// crt's args block: its command line, split as captured.
    #[test]
    fn the_command_line_as_captured() {
        assert_eq!(
            arguments(
                br#"crt.exe args one "two words" back\slash "tail\\" a\\\"b "q\"uote" "" x"y z"w"#
            ),
            [
                "crt.exe",
                "args",
                "one",
                "two words",
                r"back\slash",
                r"tail\",
                r#"a\"b"#,
                r#"q"uote"#,
                "",
                "xy zw"
            ]
        );
        assert_eq!(
            arguments(br#""C:\Program Files\a.exe" x"#),
            [r"C:\Program Files\a.exe", "x"]
        );
        assert_eq!(arguments(b"a.exe  \t "), ["a.exe"]);
        assert_eq!(arguments(br#"a "x""y z"#), ["a", "x\"y", "z"]);
    }

    /// crt's modes block: the start-up's precision, the fields, a change and its restoring.
    #[test]
    fn controlfp_as_captured() {
        controlfp(PC_53, 0x3_0000);
        let initial = controlfp(0, 0);
        assert_eq!(initial, 0x0009_001F);
        assert_eq!(controlfp(PC_24, 0x3_0000), 0x000A_001F);
        assert_eq!(controlfp(0x300, MCW_RC), 0x000A_031F);
        assert_eq!(controlfp(initial, 0x3_0000 | MCW_RC), initial);
        assert_eq!(
            controlfp(0, EM_DENORMAL),
            initial,
            "the denormal mask stays"
        );
    }
}
