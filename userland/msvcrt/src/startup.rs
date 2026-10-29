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
//!   less those starting with `=` (cmd.exe's per-drive current directories). `_putenv` (as MSDN
//!   documents it) changes both `_environ`, a new array each time (envp stays as `main` got it),
//!   and the process environment.
//! - `_fmode` and `_commode` are 0; the start-up's `_controlfp(_PC_53, _MCW_PC)` leaves 0x9001F.
//! - exit runs the `_onexit`/`atexit` functions, last registered first, then flushes the streams,
//!   then ends the process; `_exit` ends it at once (nothing run, nothing flushed).
//! - An exception the program does not handle reaches `_XcptFilter`, which hands it to
//!   UnhandledExceptionFilter; the start-up's handler ends the process with the exception's code.

use core::ffi::CStr;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicUsize};

use rtl::cstr::bytes_until_nul;
use rtl::sync::Locked;

use crate::data::{Exported, FMODE};
use crate::kernel32;
use crate::thread::{Guarded, Lock};

/// `_commode`: the default commit mode of the streams a program opens (0).
static COMMODE: Exported<i32> = Exported::new(0);
/// `__argc` and `__argv` (`__getmainargs` sets them), `_environ` and `__initenv` (the DLL's
/// initialization does). The C runtime reaches them under the environment's lock
/// ([`ENVIRONMENT`]).
static ARGC: Exported<i32> = Exported::new(0);
static ARGV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
static ENVIRON: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
static INITENV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
/// The program's `_matherr` (`__setusermatherr`).
static USER_MATHERR: AtomicUsize = AtomicUsize::new(0);

/// A function registered for exit (`_onexit`, `atexit`, `__dllonexit`): a C `void (*)(void)`, or
/// NULL.
pub type ExitFunction = Option<extern "C" fn()>;

/// The exit functions: a growable array from the C runtime's heap, in registration order.
struct ExitTable {
    functions: *mut ExitFunction,
    count: usize,
    capacity: usize,
}

// SAFETY: the table owns its block of the C runtime's heap (a process-wide heap: any thread may
// grow or free it), and the block holds plain function pointers; it moves between threads only
// under the exit functions' lock.
unsafe impl Send for ExitTable {}

/// The exit functions, behind their lock (Windows 2000's msvcrt has one for its exit list). Each
/// one is taken out under it and called after it is let go, so a function may register another.
/// `__dllonexit` changes its caller's table under it too, so an exception there lets it go.
static EXIT: Guarded<ExitTable> = Guarded::new(ExitTable {
    functions: core::ptr::null_mut(),
    count: 0,
    capacity: 0,
});

/// Whether exit or _exit has run: the DLL's detach then leaves the process as they did.
static EXITED: AtomicBool = AtomicBool::new(false);

/// The environment's lock (Windows 2000's msvcrt has one for its environment), and the access to
/// `_environ` and `__initenv` it guards: the C runtime reads and writes them only through the
/// `&mut Environment` its `with` lends. Programs read them directly.
static ENVIRONMENT: Locked<Environment, Lock> = Locked::new(Lock::new(), Environment(()));

/// The C runtime's way to `_environ` and `__initenv`, lent under the environment's lock.
struct Environment(());

impl Environment {
    /// `_environ`: the environment's array, NULL-terminated, of `NAME=value` strings.
    fn current(&self) -> *mut *mut u8 {
        ENVIRON.read()
    }

    /// `__initenv`: the array `main` was given.
    fn initial(&self) -> *mut *mut u8 {
        INITENV.read()
    }

    fn set_current(&mut self, array: *mut *mut u8) {
        ENVIRON.write(array);
    }

    fn set_initial(&mut self, array: *mut *mut u8) {
        INITENV.write(array);
    }
}

/// __set_app_type: the program's kind, 1 a console program, 2 a GUI one.
#[unsafe(export_name = "f2k_export___set_app_type")]
pub extern "C" fn set_app_type(kind: i32) {
    crate::lowio::set_app_type(kind);
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
    USER_MATHERR.store(handler, Relaxed);
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
    use core::sync::atomic::{AtomicU16, Ordering::Relaxed};

    static WORD: AtomicU16 = AtomicU16::new(0x027F);

    pub fn read() -> u16 {
        WORD.load(Relaxed)
    }

    pub fn write(word: u16) {
        WORD.store(word, Relaxed)
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

/// _initterm: each non-null function of the table `[begin, end)` called, in order (a C
/// `void (*)(void)` each: `Option<extern "C" fn()>` is a nullable function pointer).
///
/// # Safety
///
/// `[begin, end)` is a table, aligned, of null or callable `void (*)(void)` entries that the
/// functions it calls leave unchanged.
#[unsafe(export_name = "f2k_export__initterm")]
pub unsafe extern "C" fn initterm(
    begin: *const Option<extern "C" fn()>,
    end: *const Option<extern "C" fn()>,
) {
    let count =
        (end as usize).saturating_sub(begin as usize) / core::mem::size_of::<ExitFunction>();
    if count == 0 {
        return;
    }
    // SAFETY: the caller's table: `count` entries from `begin`, before `end`.
    let table = unsafe { core::slice::from_raw_parts(begin, count) };
    for function in table.iter().flatten() {
        function();
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

/// A pointer's size: a word.
const WORD: usize = core::mem::size_of::<usize>();

/// The strings of an array [`string_array`] builds, written one after the other: each string's
/// bytes go into the block's pool, and its end records its address in the pointer that is its
/// own.
struct ArrayWriter<'a> {
    /// The pointers not yet written, a word each.
    pointers: core::slice::IterMut<'a, [u8; WORD]>,
    /// The bytes after the pointers, and their address.
    pool: &'a mut [u8],
    base: usize,
    /// Where the next byte goes, and where the current string starts.
    at: usize,
    start: usize,
}

impl ArrayWriter<'_> {
    /// A byte of the current string.
    fn push(&mut self, byte: u8) {
        self.pool[self.at] = byte;
        self.at += 1;
    }

    /// The current string ended: its NUL written, its address its pointer's.
    fn end(&mut self) {
        self.push(0);
        let pointer = self.pointers.next().expect("no more strings than counted");
        *pointer = (self.base + self.start).to_ne_bytes();
        self.start = self.at;
    }

    /// A whole string.
    fn string(&mut self, string: &[u8]) {
        string.iter().for_each(|&byte| self.push(byte));
        self.end();
    }
}

/// A NULL-terminated array of `count` NUL-terminated strings of `bytes` bytes (their NULs
/// included), as argv and `_environ` are, in one block of the C runtime's heap: the pointers and
/// the NULL after them, then the strings, which `fill` writes. Null when the heap has no room.
fn string_array(count: usize, bytes: usize, fill: impl FnOnce(&mut ArrayWriter)) -> *mut *mut u8 {
    let words = count * WORD;
    let size = words + WORD + bytes;
    let block = crate::heap::allocate(size, true);
    if block.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: a fresh, zeroed block of the C runtime's heap of `size` bytes, this function's alone
    // until it answers it.
    let whole = unsafe { core::slice::from_raw_parts_mut(block, size) };
    let (pointers, pool) = whole.split_at_mut(words + WORD);
    let mut writer = ArrayWriter {
        pointers: pointers[..words].as_chunks_mut::<WORD>().0.iter_mut(),
        base: pool.as_ptr() as usize,
        pool,
        at: 0,
        start: 0,
    };
    // The NULL after the pointers is the block's zero.
    fill(&mut writer);
    block.cast()
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
    let line = kernel32::command_line();
    let (mut count, mut bytes) = (0usize, 0usize);
    split(line, |b| {
        bytes += 1;
        if b.is_none() {
            count += 1;
        }
    });
    let block = string_array(count, bytes, |array| {
        split(line, |b| match b {
            Some(byte) => array.push(byte),
            None => array.end(),
        })
    });
    if block.is_null() {
        return -1;
    }
    let environment = ENVIRONMENT.with(|environment| {
        ARGC.write(count as i32);
        ARGV.write(block);
        let current = environment.current();
        environment.set_initial(current);
        current
    });
    // SAFETY: the start-up's storage for argc, argv and envp.
    unsafe {
        argc.write(count as i32);
        argv.write(block);
        envp.write(environment);
    }
    0
}

/// The DLL's process attach: `_environ` from the environment block, less its `=` entries.
pub fn initialize_environment() -> bool {
    let Some(strings) = kernel32::EnvironmentStrings::get() else {
        return false;
    };
    let entries = || strings.entries().filter(|entry| entry[0] != b'=');
    let count = entries().count();
    let bytes: usize = entries().map(|entry| entry.len() + 1).sum();
    let array = string_array(count, bytes, |array| {
        entries().for_each(|entry| array.string(entry))
    });
    if array.is_null() {
        return false;
    }
    ENVIRONMENT.with(|environment| {
        environment.set_current(array);
        environment.set_initial(array);
    });
    true
}

/// A copy of `bytes` with a NUL after them, from the C runtime's heap (null when it has no room).
fn terminated_copy(bytes: &[u8]) -> *mut u8 {
    let copy = crate::heap::allocate(bytes.len() + 1, true);
    if !copy.is_null() {
        // SAFETY: a fresh, zeroed block of the bytes' length and a NUL.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), copy, bytes.len()) };
    }
    copy
}

/// Whether the environment entry `entry` sets the variable `name`: its name, up to its `=`, the
/// same without regard to case (each byte lowered in the LC_CTYPE locale).
fn sets(entry: &[u8], name: &[u8]) -> bool {
    entry.len() > name.len()
        && entry[name.len()] == b'='
        && entry
            .iter()
            .zip(name)
            .all(|(&a, &b)| crate::ctype::byte_lower(a) == crate::ctype::byte_lower(b))
}

/// The C runtime's environment's value of `name` (as getenv reads `_environ`), copied into `out`:
/// its length, none when the variable is unset or its value does not fit. The environment's lock is
/// taken for the read.
pub fn environment_value(name: &[u8], out: &mut [u8]) -> Option<usize> {
    ENVIRONMENT.with(|environment| value_of(environment, name, out))
}

/// `name`'s value in `_environ`, into `out`: [`environment_value`]'s work, under the lock.
fn value_of(environment: &Environment, name: &[u8], out: &mut [u8]) -> Option<usize> {
    let current = environment.current();
    if current.is_null() {
        return None;
    }
    // SAFETY: `_environ` is the C runtime's array of NUL-terminated entries, ended by NULL.
    let entries = (0..)
        .map(|i| unsafe { *current.add(i) })
        .take_while(|entry| !entry.is_null())
        .map(|entry| unsafe { bytes_until_nul(entry) });
    let value = entries
        .into_iter()
        .find(|entry| sets(entry, name))
        .map(|entry| &entry[name.len() + 1..])?;
    let room = out.get_mut(..value.len())?;
    room.copy_from_slice(value);
    Some(value.len())
}

/// `_environ` with `name`'s entry replaced by `entry` (a fresh `NAME=value` of the C runtime's
/// heap), added at its end when the name has none, or removed for none: a new array, the old one
/// freed unless it is `__initenv`'s (main's envp keeps it). A replaced entry's string is kept (a
/// pointer getenv handed out stays readable). False when the heap has no room.
fn edit_environ(environment: &mut Environment, name: &[u8], entry: Option<*mut u8>) -> bool {
    let (current, initial) = (environment.current(), environment.initial());
    let entries: &[*mut u8] = if current.is_null() {
        &[]
    } else {
        // SAFETY: `_environ` is the C runtime's array of NUL-terminated entries, ended by NULL.
        unsafe {
            let count = (0..).take_while(|&i| !(*current.add(i)).is_null()).count();
            core::slice::from_raw_parts(current, count)
        }
    };
    // SAFETY: as above: each entry is NUL-terminated.
    let found = entries
        .iter()
        .position(|&each| sets(unsafe { bytes_until_nul(each) }, name));
    let added = entry.filter(|_| found.is_none());
    let count = entries.len() + usize::from(added.is_some())
        - usize::from(found.is_some() && entry.is_none());
    let array: *mut *mut u8 =
        crate::heap::allocate((count + 1) * core::mem::size_of::<usize>(), true).cast();
    if array.is_null() {
        return false;
    }
    // SAFETY: the fresh, zeroed array: room for `count` entries and the NULL after them.
    let slots = unsafe { core::slice::from_raw_parts_mut(array, count + 1) };
    let kept =
        entries
            .iter()
            .enumerate()
            .filter_map(|(i, &each)| if Some(i) == found { entry } else { Some(each) });
    for (slot, each) in slots.iter_mut().zip(kept.chain(added)) {
        *slot = each;
    }
    if !current.is_null() && current != initial {
        // SAFETY: an array a previous edit made, of the C runtime's heap, no longer `_environ`.
        unsafe { crate::heap::release(current.cast()) };
    }
    environment.set_current(array);
    true
}

/// _putenv: `NAME=value` set in the C runtime's environment (`_environ`, a copy of the string) and
/// the process's (SetEnvironmentVariableA, which the children CreateProcess makes inherit); an
/// empty value (`NAME=`) removes the variable from both. 0, or -1 for a string that names no
/// variable (no `=`, or nothing before it) or when either update fails.
///
/// # Safety
///
/// `string` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export__putenv")]
pub unsafe extern "C" fn putenv(string: *const u8) -> i32 {
    if string.is_null() {
        return -1;
    }
    // SAFETY: the caller's string.
    let string = unsafe { bytes_until_nul(string) };
    let Some(split) = string
        .iter()
        .position(|&byte| byte == b'=')
        .filter(|&at| at > 0)
    else {
        return -1;
    };
    ENVIRONMENT.with(|environment| put(environment, string, split))
}

/// _putenv's work, under the environment's lock: `string`, `NAME=value` with its `=` at `split`,
/// set in both environments.
fn put(environment: &mut Environment, string: &[u8], split: usize) -> i32 {
    let (name, value) = (&string[..split], &string[split + 1..]);
    let entry = if value.is_empty() {
        None
    } else {
        let copy = terminated_copy(string);
        if copy.is_null() {
            return -1;
        }
        Some(copy)
    };
    if !edit_environ(environment, name, entry) {
        if let Some(copy) = entry {
            // SAFETY: the copy made above, used nowhere.
            unsafe { crate::heap::release(copy) };
        }
        return -1;
    }
    let copy = terminated_copy(name);
    if copy.is_null() {
        return -1;
    }
    // SAFETY: the name's copy, NUL-terminated; the entry's copy holds `split + 1` bytes and its
    // value after them, NUL-terminated. Both stay until the call below returns.
    let (name, value) = unsafe {
        (
            CStr::from_ptr(copy.cast()),
            entry.map(|entry| CStr::from_ptr(entry.add(split + 1).cast())),
        )
    };
    let set = kernel32::set_environment_variable(name, value);
    // SAFETY: the name's copy, used no more.
    unsafe { crate::heap::release(copy) };
    if set.is_err() {
        -1
    } else {
        0
    }
}

/// A function appended to a table that grows in the C runtime's heap: its array and its count.
///
/// # Safety
///
/// `functions` is null or a block of the C runtime's heap holding `count` entries.
unsafe fn append(
    functions: *mut ExitFunction,
    count: usize,
    capacity: usize,
    function: ExitFunction,
) -> Option<(*mut ExitFunction, usize)> {
    let (functions, capacity) = if count < capacity {
        (functions, capacity)
    } else {
        let capacity = (capacity * 2).max(32);
        let bytes = capacity * core::mem::size_of::<ExitFunction>();
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
pub extern "C" fn onexit(function: ExitFunction) -> ExitFunction {
    EXIT.with(|table| {
        // SAFETY: the table's own block of the C runtime's heap, holding `count` entries.
        let grown = unsafe { append(table.functions, table.count, table.capacity, function) };
        let (functions, capacity) = grown?;
        table.functions = functions;
        table.capacity = capacity;
        table.count += 1;
        function
    })
}

/// __dllonexit: `function` appended to a DLL's own exit table, `*begin` to `*end` (a block of the
/// C runtime's heap, grown as needed); answers it, or NULL.
///
/// # Safety
///
/// `begin` and `end` hold the table's bounds, the table a block from malloc.
#[unsafe(export_name = "f2k_export___dllonexit")]
pub unsafe extern "C" fn dllonexit(
    function: ExitFunction,
    begin: *mut *mut ExitFunction,
    end: *mut *mut ExitFunction,
) -> ExitFunction {
    // Under the exit functions' lock, as the process's own table is changed.
    EXIT.with(|_| {
        // SAFETY: the caller's table: its bounds at `begin` and `end`, the table null or a block
        // from malloc holding the entries between them.
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
                crate::heap::size_of(functions.cast()) / core::mem::size_of::<ExitFunction>()
            };
            let (functions, _) = append(functions, count, capacity, function)?;
            *begin = functions;
            *end = functions.add(count + 1);
            function
        }
    })
}

/// The exit functions run, last registered first (one that registers another has it run too).
fn run_exit_functions() {
    loop {
        let next = EXIT.with(|table| {
            table.count = table.count.checked_sub(1)?;
            // SAFETY: inside the table's block, which holds the entries below its count.
            Some(unsafe { table.functions.add(table.count).read() })
        });
        match next {
            None => break,
            Some(Some(function)) => function(),
            Some(None) => {}
        }
    }
}

/// exit: the exit functions run, the streams flushed, the process ended with `status`.
#[unsafe(export_name = "f2k_export_exit")]
pub extern "C" fn exit(status: i32) -> ! {
    run_exit_functions();
    crate::stdio::flush_all();
    EXITED.store(true, Relaxed);
    kernel32::exit_process(status as u32)
}

/// _exit: the process ended with `status` at once.
#[unsafe(export_name = "f2k_export__exit")]
pub extern "C" fn quick_exit(status: i32) -> ! {
    EXITED.store(true, Relaxed);
    kernel32::exit_process(status as u32)
}

/// The DLL's detach as the process ends without exit or _exit (ExitProcess straight from the
/// program): the exit functions run and the streams flushed, as exit would.
pub fn detach_process() {
    if !EXITED.swap(true, Relaxed) {
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
    // SAFETY: the caller's contract: the dispatcher's pointers.
    unsafe { kernel32::unhandled_exception_filter(pointers) }
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

    /// The entries of a NULL-terminated environment array.
    fn entries_of(array: *mut *mut u8) -> Vec<String> {
        // SAFETY: an array of NUL-terminated entries, ended by NULL.
        unsafe {
            (0..)
                .map(|i| *array.add(i))
                .take_while(|entry| !entry.is_null())
                .map(|entry| {
                    core::ffi::CStr::from_ptr(entry.cast())
                        .to_string_lossy()
                        .into_owned()
                })
                .collect()
        }
    }

    /// _putenv adds, replaces (in place, whatever the name's case) and removes `_environ`'s
    /// entries, copying the string, and sets the process environment the same; main's envp stays
    /// as it was; a string naming no variable is -1, nothing changed.
    #[test]
    fn putenv_sets_both_environments() {
        use crate::imports::ENVIRONMENT_SETS;
        let initial = [&b"F2KHOME=C:\\CORPUS"[..], b"PATH=C:\\WINNT"];
        let bytes = initial.iter().map(|entry| entry.len() + 1).sum();
        let array = string_array(initial.len(), bytes, |array| {
            initial.iter().for_each(|entry| array.string(entry))
        });
        ENVIRON.write(array);
        INITENV.write(array);
        let environ = || entries_of(ENVIRON.read());
        let sets = || ENVIRONMENT_SETS.with(|sets| std::mem::take(&mut *sets.borrow_mut()));
        let put = |text: &[u8]| {
            let mut owned = text.to_vec();
            owned.push(0);
            // SAFETY: a NUL-terminated string.
            let answer = unsafe { putenv(owned.as_ptr()) };
            owned.fill(b'#');
            answer
        };
        let some = |name: &str, value: &str| (name.to_string(), Some(value.to_string()));

        assert_eq!(put(b"F2KSPAWN=through _putenv"), 0);
        assert_eq!(
            environ(),
            [
                "F2KHOME=C:\\CORPUS",
                "PATH=C:\\WINNT",
                "F2KSPAWN=through _putenv"
            ]
        );
        assert_eq!(sets(), [some("F2KSPAWN", "through _putenv")]);
        assert_eq!(put(b"path=C:\\CORPUS"), 0);
        assert_eq!(
            environ(),
            [
                "F2KHOME=C:\\CORPUS",
                "path=C:\\CORPUS",
                "F2KSPAWN=through _putenv"
            ]
        );
        assert_eq!(sets(), [some("path", "C:\\CORPUS")]);
        assert_eq!(put(b"F2KHOME="), 0);
        assert_eq!(put(b"F2KNONE="), 0);
        assert_eq!(environ(), ["path=C:\\CORPUS", "F2KSPAWN=through _putenv"]);
        assert_eq!(
            sets(),
            [("F2KHOME".to_string(), None), ("F2KNONE".to_string(), None)]
        );
        assert_eq!(put(b"X=a=b"), 0);
        assert_eq!(sets(), [some("X", "a=b")]);
        for refused in [&b"F2KNOEQUALS"[..], b"=C:=C:\\", b""] {
            assert_eq!(put(refused), -1, "{:?}", String::from_utf8_lossy(refused));
        }
        // SAFETY: a null string.
        assert_eq!(unsafe { putenv(core::ptr::null()) }, -1);
        assert!(sets().is_empty());
        assert_eq!(environ().len(), 3);
        assert_eq!(
            entries_of(INITENV.read()),
            ["F2KHOME=C:\\CORPUS", "PATH=C:\\WINNT"],
            "main's envp, as the start-up left it"
        );
    }
}
