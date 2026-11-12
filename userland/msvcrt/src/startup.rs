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
//!   them before a quote are n and the quote groups, 2n+1 are n and a literal quote; `""` inside
//!   quotes is a quote, and ends them). argv[0], the program's name, follows rules of its own,
//!   backslashes literal: quoted, it ends at its closing quote, where the next argument starts
//!   (`"spawn"kid exit 2` is `spawn`, `kid`, `exit`, `2`, as batline's capture shows); unquoted, it
//!   ends at its first blank, a quote in it kept. `__argc` is 0 until then.
//! - envp, `_environ` and `__initenv` are one array: the environment block's entries, in order,
//!   less those starting with `=` (cmd.exe's per-drive current directories). The DLL's
//!   initialization makes `_environ`; `__getmainargs` answers it, and the start-up stores it in
//!   `__initenv` itself (through `__p___initenv`: wmain's capture shows a call of the program's own
//!   leaving `__initenv` as it was). `_putenv` (as MSDN documents it) changes both `_environ`, a
//!   new array each time (envp stays as `main` got it), and the process environment. getenv reads
//!   `_environ` alone (MSDN: it "operates only on the data structures accessible to the run-time
//!   library and not on the environment 'segment' created for the process by the operating
//!   system").
//! - `_acmdln` and `_wcmdln` hold GetCommandLineA's and GetCommandLineW's pointers from the DLL's
//!   load; `__argc` and `__argv` are the variables `__p___argc` and `__p___argv` point at.
//! - `_fmode` and `_commode` are 0; the start-up's `_controlfp(_PC_53, _MCW_PC)` leaves 0x9001F.
//! - exit runs the `_onexit`/`atexit` functions, last registered first, then flushes the streams,
//!   then ends the process; `_exit` ends it at once (nothing run, nothing flushed).
//! - An exception the program does not handle reaches `_XcptFilter`, which hands it to
//!   UnhandledExceptionFilter; the start-up's handler ends the process with the exception's code.
//!
//! A program whose main is `wmain` (cmd.exe's) starts the same way through `__wgetmainargs`, as
//! wmain's capture pins it: argv is GetCommandLineW split by the same rules, made again at each
//! call (`__wargv`); envp is `_wenviron`, `_environ` widened, made on the first call and the same
//! array after it, and the start-up stores it in `__winitenv`. The narrow `_environ` is there in a
//! wide program too, `__argv` and `__initenv` NULL. `_wgetenv` reads `_wenviron`, making it first
//! in a narrow program, and `_putenv` changes it too once it is there.

use core::ffi::CStr;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicBool, AtomicUsize};

use rtl::cstr::bytes_until_nul;
use rtl::sync::Locked;

use crate::data::{Exported, FMODE};
use crate::edge;
use crate::kernel32;
use crate::thread::{Lock, UnwindLock};

/// `_commode`: the default commit mode of the streams a program opens (0).
static COMMODE: Exported<i32> = Exported::new(0);
/// `__argc` and `__argv` (`__getmainargs` sets them), `_environ` and `__initenv` (the DLL's
/// initialization does). The C runtime reaches them under the environment's lock
/// ([`ENVIRONMENT`]). `__argc` and `__argv` are data exports too: the storage `__p___argc` and
/// `__p___argv` answer.
#[unsafe(export_name = "f2k_export___argc")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
static ARGC: Exported<i32> = Exported::new(0);
#[unsafe(export_name = "f2k_export___argv")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
static ARGV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
/// `_acmdln` and `_wcmdln`: the process's command line, kernel32's own copies (GetCommandLineA's
/// and GetCommandLineW's pointers), which the DLL's initialization sets
/// ([`initialize_command_line`]). Data exports, which the C runtime only writes there.
#[unsafe(export_name = "f2k_export__acmdln")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
static ACMDLN: Exported<*const u8> = Exported::new(core::ptr::null());
#[unsafe(export_name = "f2k_export__wcmdln")]
#[cfg_attr(target_arch = "x86", unsafe(link_section = ".data"))]
static WCMDLN: Exported<*const u16> = Exported::new(core::ptr::null());
static ENVIRON: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
static INITENV: Exported<*mut *mut u8> = Exported::new(core::ptr::null_mut());
/// A wide program's `__wargv` (`__wgetmainargs` sets it), `_wenviron` (`__wgetmainargs`, or the
/// first `_wgetenv`, makes it) and `__winitenv` (the start-up sets it, through
/// `__p___winitenv`): `__argv`, `_environ` and `__initenv`'s wide forms, under the same lock.
static WARGV: Exported<*mut *mut u16> = Exported::new(core::ptr::null_mut());
static WENVIRON: Exported<*mut *mut u16> = Exported::new(core::ptr::null_mut());
static WINITENV: Exported<*mut *mut u16> = Exported::new(core::ptr::null_mut());
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
static EXIT: Locked<ExitTable, UnwindLock> = Locked::new(
    UnwindLock::new(),
    ExitTable {
        functions: core::ptr::null_mut(),
        count: 0,
        capacity: 0,
    },
);

/// Whether exit or _exit has run: the DLL's detach then leaves the process as they did.
static EXITED: AtomicBool = AtomicBool::new(false);

/// The environment's lock (Windows 2000's msvcrt has one for its environment), and the access to
/// `_environ` and `__initenv`, and their wide forms, it guards: the C runtime reads and writes them
/// only through the `&mut Environment` its `with` lends. Programs read them directly.
static ENVIRONMENT: Locked<Environment, Lock> = Locked::new(
    Lock::new(),
    Environment {
        edited: false,
        wide_edited: false,
    },
);

/// The C runtime's way to `_environ` and `__initenv`, and `_wenviron` and `__winitenv`, lent under
/// the environment's lock.
struct Environment {
    /// Whether `_environ` is an array _putenv made (its pointers alone, which it gives back when
    /// it replaces them), not the one the DLL's initialization made (its entries in its block).
    edited: bool,
    /// The same for `_wenviron`.
    wide_edited: bool,
}

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

    /// `_wenviron`: the wide environment's array, NULL until it is made.
    fn wide_current(&self) -> *mut *mut u16 {
        WENVIRON.read()
    }

    /// `__winitenv`: the array `wmain` was given.
    fn wide_initial(&self) -> *mut *mut u16 {
        WINITENV.read()
    }

    fn set_wide_current(&mut self, array: *mut *mut u16) {
        WENVIRON.write(array);
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

/// __p___initenv: `__initenv`'s address (the environment `main` was given, which the start-up
/// stores there).
#[unsafe(export_name = "f2k_export___p___initenv")]
pub extern "C" fn p_initenv() -> *mut *mut *mut u8 {
    INITENV.get()
}

/// __p___wargv: `__wargv`'s address.
#[unsafe(export_name = "f2k_export___p___wargv")]
pub extern "C" fn p_wargv() -> *mut *mut *mut u16 {
    WARGV.get()
}

/// __p__wenviron: `_wenviron`'s address.
#[unsafe(export_name = "f2k_export___p__wenviron")]
pub extern "C" fn p_wenviron() -> *mut *mut *mut u16 {
    WENVIRON.get()
}

/// __p___winitenv: `__winitenv`'s address (the environment `wmain` was given, which the start-up
/// stores there).
#[unsafe(export_name = "f2k_export___p___winitenv")]
pub extern "C" fn p_winitenv() -> *mut *mut *mut u16 {
    WINITENV.get()
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

/// A unit of the strings the start-up hands over: a narrow character, or a UTF-16 one for a wide
/// program's. Zero is a valid one (the arrays are made zeroed).
pub trait Unit: Copy + Default + PartialEq + From<u8> + 'static {
    /// The unit lowered in the LC_CTYPE locale, as the environment's names are matched.
    fn lowered(self) -> Self;
}

impl Unit for u8 {
    fn lowered(self) -> u8 {
        crate::ctype::byte_lower(self)
    }
}

impl Unit for u16 {
    fn lowered(self) -> u16 {
        crate::ctype::wide_lower(self)
    }
}

/// The units of the string at `string`, its NUL left out.
///
/// # Safety
///
/// `string` points at a NUL-terminated string of the C runtime's (aligned), unchanged while the
/// units are borrowed.
unsafe fn units_of<'a, U: Unit>(string: *const U) -> &'a [U] {
    // SAFETY: the caller's contract.
    unsafe { core::slice::from_raw_parts(string, rtl::cstr::len_until_nul(string)) }
}

/// A command line split into arguments, each unit handed to `each` (`None` ends an argument): the
/// same rules for a narrow line and a wide one, as crt's and wmain's captures show.
pub fn split<U: Unit>(line: &[U], mut each: impl FnMut(Option<U>)) {
    let [blank, tab, quote, backslash] = b" \t\"\\".map(U::from);
    let is_blank = |unit: U| unit == blank || unit == tab;
    let mut i = 0;
    // argv[0], the program's name: from an opening quote to the next quote (the next argument
    // starts right after it, blank or not), else to the first blank, quotes kept; backslashes are
    // literal either way.
    if line.first() == Some(&quote) {
        i = 1;
        while i < line.len() && line[i] != quote {
            each(Some(line[i]));
            i += 1;
        }
        i += 1;
    } else {
        while i < line.len() && !is_blank(line[i]) {
            each(Some(line[i]));
            i += 1;
        }
    }
    each(None);
    loop {
        while i < line.len() && is_blank(line[i]) {
            i += 1;
        }
        if i >= line.len() {
            return;
        }
        let mut quoted = false;
        while i < line.len() && (quoted || !is_blank(line[i])) {
            let mut backslashes = 0;
            while i < line.len() && line[i] == backslash {
                backslashes += 1;
                i += 1;
            }
            if i < line.len() && line[i] == quote {
                for _ in 0..backslashes / 2 {
                    each(Some(backslash));
                }
                if backslashes % 2 == 1 {
                    each(Some(quote));
                } else if quoted && line.get(i + 1) == Some(&quote) {
                    // "" inside quotes: a quote, and the quotes end.
                    each(Some(quote));
                    i += 1;
                    quoted = false;
                } else {
                    quoted = !quoted;
                }
                i += 1;
            } else {
                for _ in 0..backslashes {
                    each(Some(backslash));
                }
                if i < line.len() && (quoted || !is_blank(line[i])) {
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
/// units go into the block's pool, and its end records its address in the pointer that is its
/// own.
struct ArrayWriter<'a, U> {
    /// The pointers not yet written, a word each.
    pointers: core::slice::IterMut<'a, [u8; WORD]>,
    /// The units after the pointers, and their address.
    pool: &'a mut [U],
    base: usize,
    /// Where the next unit goes, and where the current string starts.
    at: usize,
    start: usize,
}

impl<U: Unit> ArrayWriter<'_, U> {
    /// A unit of the current string.
    fn push(&mut self, unit: U) {
        self.pool[self.at] = unit;
        self.at += 1;
    }

    /// The current string ended: its NUL written, its address its pointer's.
    fn end(&mut self) {
        self.push(U::from(0));
        let pointer = self.pointers.next().expect("no more strings than counted");
        *pointer = (self.base + self.start * core::mem::size_of::<U>()).to_ne_bytes();
        self.start = self.at;
    }

    /// A whole string.
    fn string(&mut self, string: &[U]) {
        string.iter().for_each(|&unit| self.push(unit));
        self.end();
    }
}

/// A NULL-terminated array of `count` NUL-terminated strings of `units` units (their NULs
/// included), as argv and `_environ` are, in one block of the C runtime's heap: the pointers and
/// the NULL after them, then the strings, which `fill` writes. Null when the heap has no room.
fn string_array<U: Unit>(
    count: usize,
    units: usize,
    fill: impl FnOnce(&mut ArrayWriter<U>),
) -> *mut *mut U {
    let words = (count + 1) * WORD;
    let block = crate::heap::allocate(words + units * core::mem::size_of::<U>(), true);
    if block.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: a fresh, zeroed block of the C runtime's heap (8-aligned), this function's alone
    // until it answers it: `count` pointers' words and the NULL's, then `units` units (zero is a
    // valid unit; the words keep their alignment).
    let (pointers, pool) = unsafe {
        (
            core::slice::from_raw_parts_mut(block.cast::<[u8; WORD]>(), count),
            core::slice::from_raw_parts_mut(block.add(words).cast::<U>(), units),
        )
    };
    let mut writer = ArrayWriter {
        pointers: pointers.iter_mut(),
        base: pool.as_ptr() as usize,
        pool,
        at: 0,
        start: 0,
    };
    // The NULL after the pointers is the block's zero.
    fill(&mut writer);
    block.cast()
}

/// argv from a command line: its arguments ([`split`]) in an array of the C runtime's heap, and
/// their count; none when the heap has no room.
fn arguments<U: Unit>(line: &[U]) -> Option<(usize, *mut *mut U)> {
    let (mut count, mut units) = (0usize, 0usize);
    split(line, |unit| {
        units += 1;
        if unit.is_none() {
            count += 1;
        }
    });
    let block = string_array(count, units, |array| {
        split(line, |unit| match unit {
            Some(unit) => array.push(unit),
            None => array.end(),
        })
    });
    (!block.is_null()).then_some((count, block))
}

/// __getmainargs: argc, argv and envp for `main`, from the command line and the environment;
/// `__argc` and `__argv` too. 0, or -1 when there is no memory for them. argv is made again at each
/// call; envp is `_environ` (`__initenv` is the start-up's to set, as wmain's capture shows: a
/// call of the program's own leaves it). (`dowildcard`, the wildcard expansion setargv.obj asks
/// for, is not served: the arguments stay as given.)
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
    let Some((count, block)) = arguments(kernel32::command_line()) else {
        return -1;
    };
    let environment = ENVIRONMENT.with(|environment| {
        ARGC.write(count as i32);
        ARGV.write(block);
        environment.current()
    });
    // SAFETY: the start-up's storage for argc, argv and envp.
    unsafe {
        argc.write(count as i32);
        argv.write(block);
        envp.write(environment);
    }
    0
}

/// `_wenviron`, made on its first need from `make` (none when it cannot be had); under the
/// environment's lock, which `make` runs outside of.
fn wide_environ(make: impl FnOnce() -> *mut *mut u16) -> *mut *mut u16 {
    let current = ENVIRONMENT.with(|environment| environment.wide_current());
    if !current.is_null() {
        return current;
    }
    let made = make();
    ENVIRONMENT.with(|environment| {
        if environment.wide_current().is_null() {
            environment.set_wide_current(made);
            return made;
        }
        if !made.is_null() {
            // SAFETY: the array made above, used nowhere: another thread's came first.
            unsafe { crate::heap::release(made.cast()) };
        }
        environment.wide_current()
    })
}

/// __wgetmainargs: argc, argv and envp for `wmain`, as __getmainargs's for `main` but wide: argv
/// from GetCommandLineW split by the same rules, made again at each call (`__argc` and `__wargv`
/// too), envp `_wenviron`, made on the first call and the same array after it. `_wenviron` is
/// `_environ` widened, not the wide environment block: wmain's capture shows a child's U+03B1
/// reaching envp as the `a` the ANSI code page's best fit makes of it, where its argv keeps it.
/// `__winitenv` is the start-up's to set. 0, or -1 when there is no memory for them.
/// (`dowildcard` is not served, as __getmainargs's.)
///
/// # Safety
///
/// The pointers are the start-up's storage for argc, argv and envp.
#[unsafe(export_name = "f2k_export___wgetmainargs")]
pub unsafe extern "C" fn wgetmainargs(
    argc: *mut i32,
    argv: *mut *mut *mut u16,
    envp: *mut *mut *mut u16,
    _dowildcard: i32,
    _startinfo: *mut i32,
) -> i32 {
    let (_, wide) = kernel32::command_line_pointers();
    // SAFETY: kernel32's wide copy of the command line, NUL-terminated, aligned, never freed.
    let line = unsafe { units_of(wide) };
    let Some((count, block)) = arguments(line) else {
        return -1;
    };
    let environment = wide_environ(widened_environ);
    if environment.is_null() {
        // SAFETY: the argv made above, used nowhere.
        unsafe { crate::heap::release(block.cast()) };
        return -1;
    }
    ENVIRONMENT.with(|_| {
        ARGC.write(count as i32);
        WARGV.write(block);
    });
    // SAFETY: the start-up's storage for argc, argv and envp.
    unsafe {
        argc.write(count as i32);
        argv.write(block);
        envp.write(environment);
    }
    0
}

/// The DLL's process attach: `_environ` from the environment block, less its `=` entries, for
/// a wide program too (wmain's capture: its narrow `_environ` is there before any getenv).
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
    ENVIRONMENT.with(|environment| environment.set_current(array));
    true
}

/// A copy of `units` with a NUL after them, from the C runtime's heap (null when it has no room).
fn terminated_copy<U: Unit>(units: &[U]) -> *mut U {
    let copy =
        crate::heap::allocate((units.len() + 1) * core::mem::size_of::<U>(), true).cast::<U>();
    if !copy.is_null() {
        // SAFETY: a fresh, zeroed block of the units' length and a NUL.
        unsafe { core::ptr::copy_nonoverlapping(units.as_ptr(), copy, units.len()) };
    }
    copy
}

/// Whether the environment entry `entry` sets the variable `name`: its name, up to its `=`, the
/// same without regard to case (each unit lowered in the LC_CTYPE locale).
fn sets<U: Unit>(entry: &[U], name: &[U]) -> bool {
    entry.len() > name.len()
        && entry[name.len()] == U::from(b'=')
        && entry
            .iter()
            .zip(name)
            .all(|(&a, &b)| a.lowered() == b.lowered())
}

/// The C runtime's environment's value of `name` (as getenv reads `_environ`), copied into `out`:
/// its length, none when the variable is unset or its value does not fit. The environment's lock is
/// taken for the read.
pub fn environment_value(name: &[u8], out: &mut [u8]) -> Option<usize> {
    ENVIRONMENT.with(|environment| value_of(environment, name, out))
}

/// `name`'s value in `_environ`, into `out`: [`environment_value`]'s work, under the lock.
fn value_of(environment: &Environment, name: &[u8], out: &mut [u8]) -> Option<usize> {
    let entry = entry_of(environment.current(), name)?;
    // SAFETY: one of `_environ`'s entries, NUL-terminated, `NAME=value`.
    let value = &unsafe { bytes_until_nul(entry) }[name.len() + 1..];
    let room = out.get_mut(..value.len())?;
    room.copy_from_slice(value);
    Some(value.len())
}

/// The entries of an environment array (`_environ` or `_wenviron`), none for a NULL one.
///
/// # Safety
///
/// `array` is null or the C runtime's array of NUL-terminated entries, ended by NULL, unchanged
/// while the entries are borrowed (under the environment's lock).
unsafe fn entries<'a, U: Unit>(array: *mut *mut U) -> &'a [*mut U] {
    if array.is_null() {
        return &[];
    }
    // SAFETY: the caller's contract.
    unsafe {
        let count = (0..).take_while(|&i| !(*array.add(i)).is_null()).count();
        core::slice::from_raw_parts(array, count)
    }
}

/// The entry of the environment array `array` that sets `name`, under the environment's lock.
fn entry_of<U: Unit>(array: *mut *mut U, name: &[U]) -> Option<*mut U> {
    // SAFETY: `_environ` or `_wenviron`, under the environment's lock; each entry NUL-terminated.
    unsafe { entries(array) }
        .iter()
        .copied()
        .find(|&entry| sets(unsafe { units_of(entry) }, name))
}

/// getenv: `name`'s value in the C runtime's environment, its name matched without regard to case:
/// a pointer into its `_environ` entry, just after the `=`; NULL when it is unset. The C runtime's
/// environment is its own copy, which _putenv changes: SetEnvironmentVariable behind its back is
/// not seen.
///
/// # Safety
///
/// `name` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export_getenv")]
pub unsafe extern "C" fn getenv(name: *const u8) -> *mut u8 {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's string.
    let name = unsafe { bytes_until_nul(name) };
    ENVIRONMENT.with(|environment| {
        entry_of(environment.current(), name).map_or(core::ptr::null_mut(), |entry| {
            entry.wrapping_add(name.len() + 1)
        })
    })
}

/// `_wenviron` as it is first made: `_environ` widened, each entry's characters in the LC_CTYPE
/// locale (in a narrow program, on its first `_wgetenv`: MSDN's `_wenviron` is made "on the first
/// call to _wgetenv or _wputenv"). Null when there is no room.
fn widened_environ() -> *mut *mut u16 {
    ENVIRONMENT.with(|environment| {
        // SAFETY: `_environ`, under the environment's lock.
        let entries = unsafe { entries(environment.current()) };
        // SAFETY: each entry NUL-terminated.
        let strings = || {
            entries
                .iter()
                .map(|&entry| unsafe { bytes_until_nul(entry) })
        };
        let units = strings().map(|entry| entry.len() + 1).sum();
        string_array(entries.len(), units, |array| {
            for entry in strings() {
                entry
                    .iter()
                    .for_each(|&byte| array.push(crate::ctype::byte_to_wide(byte)));
                array.end();
            }
        })
    })
}

/// _wgetenv: `name`'s value in the C runtime's wide environment (`_wenviron`), as getenv reads the
/// narrow one: a pointer just after its entry's `=`, its name matched without regard to case;
/// NULL when it is unset. A program that has no `_wenviron` yet (a narrow one) gets one, made from
/// `_environ`.
///
/// # Safety
///
/// `name` is null or NUL-terminated.
#[unsafe(export_name = "f2k_export__wgetenv")]
pub unsafe extern "C" fn wgetenv(name: *const u16) -> *mut u16 {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's string, at any address.
    let name = unsafe { edge::wide(name) };
    wide_environ(widened_environ);
    ENVIRONMENT.with(|environment| {
        // SAFETY: `_wenviron`, under the environment's lock.
        let entries = unsafe { entries(environment.wide_current()) };
        let found = entries.iter().copied().find(|&entry| {
            // SAFETY: each entry NUL-terminated.
            let entry = unsafe { units_of(entry) };
            entry.len() > name.len()
                && entry[name.len()] == u16::from(b'=')
                && entry
                    .iter()
                    .zip(edge::units(name))
                    .all(|(&a, b)| a.lowered() == b.lowered())
        });
        found.map_or(core::ptr::null_mut(), |entry| {
            entry.wrapping_add(name.len() + 1)
        })
    })
}

/// The DLL's process attach: `_acmdln` and `_wcmdln`, kernel32's command line.
pub fn initialize_command_line() {
    let (narrow, wide) = kernel32::command_line_pointers();
    ACMDLN.write(narrow);
    WCMDLN.write(wide);
}

/// The environment array `current` with `name`'s entry replaced by `entry` (a fresh `NAME=value`
/// of the C runtime's heap), added at its end when the name has none, or removed for none: a new
/// array of the C runtime's heap (the entries are the old array's, which stay where they are: a
/// pointer getenv handed out stays readable); none when the heap has no room.
fn edited<U: Unit>(current: *mut *mut U, name: &[U], entry: Option<*mut U>) -> Option<*mut *mut U> {
    // SAFETY: `_environ` or `_wenviron`, under the environment's lock; each entry NUL-terminated.
    let entries = unsafe { entries(current) };
    let found = entries
        .iter()
        .position(|&each| sets(unsafe { units_of(each) }, name));
    let added = entry.filter(|_| found.is_none());
    let count = entries.len() + usize::from(added.is_some())
        - usize::from(found.is_some() && entry.is_none());
    let array: *mut *mut U = crate::heap::allocate((count + 1) * WORD, true).cast();
    if array.is_null() {
        return None;
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
    Some(array)
}

/// An environment array an edit replaced, given back when an edit made it: the arrays the DLL's
/// initialization and the start-up made hold their entries in their own block, which the arrays
/// after them still point into, and `main`'s envp (`initial`) keeps its own.
///
/// # Safety
///
/// `old` is the array the edit replaced: when `edit_made` says so, an array of pointers alone, of
/// the C runtime's heap, used no more.
unsafe fn release_replaced<U>(old: *mut *mut U, initial: *mut *mut U, edit_made: bool) {
    if edit_made && !old.is_null() && old != initial {
        // SAFETY: the caller's contract.
        unsafe { crate::heap::release(old.cast()) };
    }
}

/// _putenv: `NAME=value` set in the C runtime's environment (`_environ`, a copy of the string,
/// and `_wenviron`'s wide copy when the program has one, as MSDN's _putenv says both change) and
/// the process's (SetEnvironmentVariableA, which the children CreateProcess makes inherit); an
/// empty value (`NAME=`) removes the variable from all three. 0, or -1 for a string that names no
/// variable (no `=`, or nothing before it) or when an update fails.
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

/// `name`'s entry in one environment array set to the fresh `entry` (removed for none): the new
/// array (the old one given back when an edit made it), or the entry given back and false when the
/// heap has no room.
fn put_entry<U: Unit>(
    (current, initial, edit_made): (*mut *mut U, *mut *mut U, bool),
    name: &[U],
    entry: Option<*mut U>,
) -> Option<*mut *mut U> {
    let Some(array) = edited(current, name, entry) else {
        if let Some(copy) = entry {
            // SAFETY: the entry made for the edit, used nowhere.
            unsafe { crate::heap::release(copy.cast()) };
        }
        return None;
    };
    // SAFETY: `current` is the array the edit replaced, which an edit made when `edit_made` says.
    unsafe { release_replaced(current, initial, edit_made) };
    Some(array)
}

/// A wide copy of a narrow string, each character widened in the LC_CTYPE locale, NUL-terminated,
/// from the C runtime's heap (null when it has no room).
fn widened_copy(bytes: &[u8]) -> *mut u16 {
    let copy = crate::heap::allocate((bytes.len() + 1) * 2, true).cast::<u16>();
    if !copy.is_null() {
        // SAFETY: a fresh, zeroed block of the units and a NUL, aligned.
        let units = unsafe { core::slice::from_raw_parts_mut(copy, bytes.len()) };
        for (unit, &byte) in units.iter_mut().zip(bytes) {
            *unit = crate::ctype::byte_to_wide(byte);
        }
    }
    copy
}

/// _putenv's work, under the environment's lock: `string`, `NAME=value` with its `=` at `split`,
/// set in every environment.
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
    let narrow = (
        environment.current(),
        environment.initial(),
        environment.edited,
    );
    let Some(array) = put_entry(narrow, name, entry) else {
        return -1;
    };
    environment.set_current(array);
    environment.edited = true;
    if !environment.wide_current().is_null() {
        // The entry widened (`NAME=` alone for a removal, which lends the name and goes after).
        let copy = widened_copy(string);
        if copy.is_null() {
            return -1;
        }
        // SAFETY: the copy's units, the name's first, NUL-terminated after them.
        let wide_name = unsafe { core::slice::from_raw_parts(copy.cast_const(), split) };
        let wide = (
            environment.wide_current(),
            environment.wide_initial(),
            environment.wide_edited,
        );
        let array = put_entry(wide, wide_name, entry.map(|_| copy));
        if entry.is_none() {
            // SAFETY: the copy lent its name, used no more.
            unsafe { crate::heap::release(copy.cast()) };
        }
        let Some(array) = array else {
            return -1;
        };
        environment.set_wide_current(array);
        environment.wide_edited = true;
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

/// A run-time error's message: R6025, a pure virtual function called.
pub const R6025_PURE_VIRTUAL: &[u8] = b"R6025\r\n- pure virtual function call\r\n";

/// A run-time error (_amsg_exit's work): its message written after the banner, the process ended
/// with 255, as crt's capture shows for R6025.
pub fn runtime_error(message: &[u8]) -> ! {
    write_message(&[b"\r\n", b"runtime error ", message]);
    quick_exit(255)
}

/// abort: "abnormal program termination" written, the process ended with 3 (SIGABRT's default
/// action; F2K has no signal handlers), nothing flushed.
#[unsafe(export_name = "f2k_export_abort")]
pub extern "C" fn abort() -> ! {
    write_message(&[b"\r\nabnormal program termination\r\n"]);
    quick_exit(3)
}

/// The C runtime's message on its way out: a console program's to its standard error handle, in
/// pieces. A GUI program's would be a message box, which F2K does not show yet: it is logged.
fn write_message(pieces: &[&[u8]]) {
    if !crate::lowio::console_program() {
        // SAFETY: no arguments are read.
        unsafe {
            crate::stub::logged(
                &crate::spec::abort,
                "a GUI program's run-time error message box",
                &[],
            )
        };
        return;
    }
    /// STD_ERROR_HANDLE.
    const STD_ERROR: u32 = -12i32 as u32;
    let handle = kernel32::std_handle(STD_ERROR);
    for piece in pieces {
        let _ = kernel32::write_file(handle, piece);
    }
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

    /// MSDN's "Parsing C Command-Line Arguments": each of its examples, after a program name.
    #[test]
    fn the_documented_examples() {
        assert_eq!(arguments(br#"p "a b c" d e"#), ["p", "a b c", "d", "e"]);
        assert_eq!(
            arguments(br#"p "ab\"c" "\\" d"#),
            ["p", r#"ab"c"#, r"\", "d"]
        );
        assert_eq!(
            arguments(br#"p a\\\b d"e f"g h"#),
            ["p", r"a\\\b", "de fg", "h"]
        );
        assert_eq!(arguments(br#"p a\\\"b c d"#), ["p", r#"a\"b"#, "c", "d"]);
        assert_eq!(
            arguments(br#"p a\\\\"b c" d e"#),
            ["p", r"a\\b c", "d", "e"]
        );
    }

    /// Each documented rule on its own: blanks (spaces and tabs) separate, runs of them as one;
    /// quotes group and may sit inside an argument; backslashes are literal unless a quote follows;
    /// before a quote, 2n are n and the quote groups, 2n+1 are n and a literal quote; `""` inside
    /// quotes is a literal quote that ends them, and an unclosed quote runs to the line's end.
    #[test]
    fn the_documented_rules() {
        assert_eq!(arguments(b"p a\t b  \t c"), ["p", "a", "b", "c"]);
        assert_eq!(arguments(br#"p x"a b"y"#), ["p", "xa by"]);
        assert_eq!(arguments(br"p \a\\b\ c\\"), ["p", r"\a\\b\", r"c\\"]);
        assert_eq!(arguments(br#"p \" \\" x""#), ["p", "\"", r"\ x"]);
        assert_eq!(
            arguments(br#"p \\\\" a" \\\\\"b"#),
            ["p", r"\\ a", r#"\\"b"#]
        );
        assert_eq!(arguments(br#"p "a""b c""#), ["p", "a\"b", "c"]);
        assert_eq!(arguments(br#"p """a""" b"#), ["p", "\"a\"", "b"]);
        assert_eq!(arguments(br#"p a""b"#), ["p", "ab"]);
        assert_eq!(arguments(br#"p "" """#), ["p", "", ""]);
        assert_eq!(arguments(br#"p "a b"#), ["p", "a b"]);
        assert_eq!(arguments(b"p"), ["p"]);
    }

    /// The program's name: quoted, it ends at its closing quote and the next argument starts right
    /// after it (batline's `"spawn"kid exit 2` reaches spawnkid as `spawn`, `kid`: an unknown
    /// mode); unquoted, it ends at a blank and keeps any quote; backslashes are literal in both.
    #[test]
    fn the_program_name() {
        assert_eq!(
            arguments(br#""spawn"kid exit 2"#),
            ["spawn", "kid", "exit", "2"]
        );
        assert_eq!(
            arguments(br#""spawnkid" exit 3"#),
            ["spawnkid", "exit", "3"]
        );
        assert_eq!(arguments(br#""C:\dir\"x"#), [r"C:\dir\", "x"]);
        assert_eq!(arguments(br#""a\"b c"#), [r"a\", "b", "c"]);
        assert_eq!(arguments(br#"a"b c" d"#), [r#"a"b"#, "c d"]);
        assert_eq!(arguments(br#"C:\a\\"b x"#), [r#"C:\a\\"b"#, "x"]);
        assert_eq!(arguments(br#""no end"#), ["no end"]);
        assert_eq!(arguments(br#""" x"#), ["", "x"]);
        assert_eq!(arguments(b"\tp x"), ["", "p", "x"]);
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

        // process's getenv block: a pointer into `_environ`'s entry, just after its `=`, whatever
        // the name's case; NULL for a name no entry sets, the empty name, a name holding `=`, and
        // after _putenv's removal.
        let get = |name: &[u8]| {
            let mut owned = name.to_vec();
            owned.push(0);
            // SAFETY: a NUL-terminated name.
            unsafe { getenv(owned.as_ptr()) }
        };
        assert_eq!(put(b"F2KT_A=one"), 0);
        let upper = get(b"F2KT_A");
        // SAFETY: getenv's answer, inside a NUL-terminated entry.
        assert_eq!(unsafe { CStr::from_ptr(upper.cast()) }, c"one");
        assert_eq!(get(b"f2kt_a"), upper);
        // SAFETY: `_environ`, an array of NUL-terminated entries ended by NULL.
        let entry = unsafe {
            (0..)
                .map(|i| *ENVIRON.read().add(i))
                .find(|&entry| CStr::from_ptr(entry.cast()) == c"F2KT_A=one")
                .unwrap()
        };
        assert_eq!(upper, entry.wrapping_add(7));
        for missing in [&b"F2KT_MISSING"[..], b"", b"F2KT_A=x", b"F2KT_A=one"] {
            assert!(get(missing).is_null(), "{missing:?}");
        }
        // SAFETY: a null name.
        assert!(unsafe { getenv(core::ptr::null()) }.is_null());
        assert_eq!(put(b"F2KT_A="), 0);
        assert!(get(b"F2KT_A").is_null());
        sets();

        // A narrow program's first _wgetenv makes `_wenviron` from `_environ`; _putenv then
        // changes both, and the narrow `__initenv` stays as the start-up left it.
        let wide_get = |name: &str| {
            let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
            // SAFETY: a NUL-terminated name.
            let value = unsafe { wgetenv(name.as_ptr()) };
            // SAFETY: wgetenv's answer, inside a NUL-terminated entry.
            (!value.is_null()).then(|| String::from_utf16(unsafe { units_of(value) }).unwrap())
        };
        assert!(WENVIRON.read().is_null());
        assert_eq!(put(b"F2KW=\xE9t\xE9"), 0);
        assert_eq!(wide_get("path").as_deref(), Some("C:\\CORPUS"));
        assert_eq!(wide_get("f2kw").as_deref(), Some("\u{E9}t\u{E9}"));
        assert_eq!(wide_get("F2KT_A"), None);
        let made = WENVIRON.read();
        assert!(!made.is_null());
        assert_eq!(put(b"F2KW=two"), 0);
        assert_eq!(wide_get("F2KW").as_deref(), Some("two"));
        assert_ne!(WENVIRON.read(), made, "a new array");
        assert_eq!(put(b"F2KNEW=x"), 0);
        assert_eq!(wide_get("F2KNEW").as_deref(), Some("x"));
        assert_eq!(put(b"F2KW="), 0);
        assert_eq!(wide_get("F2KW"), None);
        assert!(!get(b"F2KNEW").is_null());
        // SAFETY: a null name.
        assert!(unsafe { wgetenv(core::ptr::null()) }.is_null());
        assert_eq!(
            entries_of(INITENV.read()),
            ["F2KHOME=C:\\CORPUS", "PATH=C:\\WINNT"]
        );
        sets();
    }

    /// wmain's args block: the child's wide command line, split by the narrow line's rules.
    #[test]
    fn the_wide_command_line_as_captured() {
        let line: Vec<u16> = concat!(
            r#"wmain.exe kid args one "two words" back\slash "tail\\" a\\\"b "q\"uote" "" "#,
            "x\"y z\"w \u{E9}\u{3B1}"
        )
        .encode_utf16()
        .collect();
        let mut out = vec![Vec::new()];
        split(&line[..], |unit| match unit {
            Some(unit) => out.last_mut().unwrap().push(unit),
            None => out.push(Vec::new()),
        });
        out.pop();
        let out: Vec<String> = out
            .iter()
            .map(|arg| String::from_utf16(arg).unwrap())
            .collect();
        assert_eq!(
            out,
            [
                "wmain.exe",
                "kid",
                "args",
                "one",
                "two words",
                r"back\slash",
                r"tail\",
                r#"a\"b"#,
                r#"q"uote"#,
                "",
                "xy zw",
                "\u{E9}\u{3B1}",
            ]
        );
    }
}
