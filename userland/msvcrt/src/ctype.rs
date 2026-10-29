//! The locale and the character functions: setlocale, the `isw*` classes, the `tow*` mappings and
//! toupper, and the conversions between a narrow character and a wide one the formatter and the
//! scanner use.
//!
//! As wide's capture shows them:
//!
//! - A program starts in the "C" locale. setlocale(LC_ALL, "") selects the user's locale, named
//!   `<language>_<country>.<code page>` from its English names (`English_United States.1252`); a
//!   category set alone makes LC_ALL's name the composite
//!   `LC_COLLATE=…;LC_CTYPE=…;LC_MONETARY=…;LC_NUMERIC=…;LC_TIME=…`; a name that names no locale
//!   answers NULL and changes nothing.
//! - A character below U+0100 is classified by the LC_CTYPE locale's table: the "C" locale's knows
//!   ASCII alone (a letter is `_UPPER` or `_LOWER`, without the `_ALPHA` bit), another locale's is
//!   its code page's CT_CTYPE1 flags (GetStringTypeA, whose bits are ctype.h's). One from U+0100 up
//!   is GetStringTypeW's, in any locale.
//! - The "C" locale maps the case of ASCII letters alone; another locale maps every character's
//!   through LCMapStringW.
//! - The "C" locale converts a byte to the wide character of the same value (and back, below
//!   U+0100); another locale converts through its ANSI code page.
//!
//! The character functions read LC_CTYPE's tables without a lock, as Windows 2000's do through
//! `_pctype` (an exported pointer to the classification table, which setlocale points at another):
//! the tables are published whole through one pointer ([`CTYPE`]), and never changed or freed once
//! published. setlocale makes a locale's tables once and keeps them, under the locale's lock, which
//! also guards the categories' names and its answer.

use core::sync::atomic::{AtomicPtr, Ordering::Acquire, Ordering::Release};

use rtl::sync::Locked;

use crate::imports;
use crate::thread::Lock;

/// setlocale's categories (locale.h).
pub const LC_ALL: i32 = 0;
pub const LC_CTYPE: i32 = 2;
const LC_MAX: usize = 5;
/// The categories' names, as LC_ALL's composite name spells them.
const CATEGORY_NAMES: [&[u8]; LC_MAX + 1] = [
    b"LC_ALL",
    b"LC_COLLATE",
    b"LC_CTYPE",
    b"LC_MONETARY",
    b"LC_NUMERIC",
    b"LC_TIME",
];

/// ctype.h's classes.
pub const UPPER: u16 = 0x0001;
pub const LOWER: u16 = 0x0002;
pub const DIGIT: u16 = 0x0004;
pub const SPACE: u16 = 0x0008;
pub const PUNCT: u16 = 0x0010;
pub const CONTROL: u16 = 0x0020;
pub const BLANK: u16 = 0x0040;
pub const HEX: u16 = 0x0080;
pub const ALPHA: u16 = 0x0100 | UPPER | LOWER;

/// WEOF: the wide end of file.
pub const WEOF: u16 = 0xFFFF;

/// The NLS calls' constants.
const CT_CTYPE1: u32 = 1;
const LCMAP_LOWERCASE: u32 = 0x0100;
const LCMAP_UPPERCASE: u32 = 0x0200;
const LOCALE_SABBREVLANGNAME: u32 = 0x03;
const LOCALE_SABBREVCTRYNAME: u32 = 0x07;
const LOCALE_IDEFAULTCODEPAGE: u32 = 0x0B;
const LOCALE_SENGLANGUAGE: u32 = 0x1001;
const LOCALE_SENGCOUNTRY: u32 = 0x1002;
const LOCALE_IDEFAULTANSICODEPAGE: u32 = 0x1004;

/// The "C" locale's table: ASCII's classes, nothing above.
const C_TABLE: [u16; 256] = {
    let mut table = [0u16; 256];
    let mut c = 0;
    while c < 128 {
        table[c] = match c as u8 {
            b' ' => SPACE | BLANK,
            0x09..=0x0D => SPACE | CONTROL,
            0x00..=0x1F | 0x7F => CONTROL,
            b'0'..=b'9' => DIGIT | HEX,
            b'A'..=b'F' => UPPER | HEX,
            b'G'..=b'Z' => UPPER,
            b'a'..=b'f' => LOWER | HEX,
            b'g'..=b'z' => LOWER,
            _ => PUNCT,
        };
        c += 1;
    }
    table
};

/// A locale's name, as setlocale answers it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Name {
    bytes: [u8; 64],
    length: usize,
}

impl Name {
    const C: Name = Name::of(b"C");

    const fn of(text: &[u8]) -> Name {
        let mut bytes = [0; 64];
        let mut i = 0;
        while i < text.len() {
            bytes[i] = text[i];
            i += 1;
        }
        Name {
            bytes,
            length: text.len(),
        }
    }

    fn text(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    fn push(&mut self, text: &[u8]) {
        let room = self.bytes.len() - 1 - self.length;
        let take = text.len().min(room);
        self.bytes[self.length..self.length + take].copy_from_slice(&text[..take]);
        self.length += take;
    }
}

/// A locale setlocale can select: its LCID (0 for "C"), its ANSI code page, its name.
#[derive(Clone, Copy)]
struct Resolved {
    lcid: u32,
    page: u32,
    name: Name,
}

/// LC_CTYPE's tables: its locale (its LCID, 0 for "C", and its ANSI code page), and the classes
/// and case mappings of the 256 narrow characters in it. Once published they never change.
struct Tables {
    lcid: u32,
    page: u32,
    class: [u16; 256],
    lower: [u8; 256],
    upper: [u8; 256],
    /// The tables setlocale made before these (none for the "C" locale's): the ones it may reuse.
    next: Option<&'static Tables>,
}

/// The "C" locale's tables.
static C_TABLES: Tables = Tables {
    lcid: 0,
    page: 0,
    class: C_TABLE,
    lower: ascii_case(false),
    upper: ascii_case(true),
    next: None,
};

/// LC_CTYPE's tables: the "C" locale's, or tables setlocale made, published here whole (Release,
/// read with Acquire) and never freed. Only setlocale changes it, under the locale's lock.
static CTYPE: AtomicPtr<Tables> = AtomicPtr::new(core::ptr::addr_of!(C_TABLES).cast_mut());

/// LC_CTYPE's tables, as setlocale last published them.
fn tables() -> &'static Tables {
    // SAFETY: CTYPE holds C_TABLES, or tables `make_tables` made: filled in before setlocale's
    // Release store published them (this Acquire load sees them whole), and never changed or
    // freed after, so a shared reference to them is valid for the process's life.
    unsafe { &*CTYPE.load(Acquire) }
}

/// The locale's state, behind its lock: each category's name, the tables setlocale made (the
/// newest first), and setlocale's answer.
struct Locale {
    names: [Name; LC_MAX + 1],
    made: Option<&'static Tables>,
    /// setlocale's answer: its own storage, overwritten by the next call (as the C runtime's
    /// contract has it).
    answer: [u8; 512],
}

static STATE: Locked<Locale, Lock> = Locked::new(
    Lock::new(),
    Locale {
        names: [Name::C; LC_MAX + 1],
        made: None,
        answer: [0; 512],
    },
);

const fn ascii_case(upper: bool) -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut c = 0;
    while c < 256 {
        table[c] = match c as u8 {
            b'A'..=b'Z' if !upper => c as u8 + 32,
            b'a'..=b'z' if upper => c as u8 - 32,
            _ => c as u8,
        };
        c += 1;
    }
    table
}

/// Whether LC_CTYPE is the "C" locale.
pub fn is_c_locale() -> bool {
    tables().lcid == 0
}

/// The classes of a narrow character in the LC_CTYPE locale.
pub fn byte_class(byte: u8) -> u16 {
    tables().class[byte as usize]
}

/// iswctype: whether `c` is in any of the `mask` classes (the classes found, masked).
pub fn wide_class(c: u16, mask: u16) -> u16 {
    if c == WEOF {
        return 0;
    }
    if c < 0x100 {
        return byte_class(c as u8) & mask;
    }
    let mut types = 0u16;
    // SAFETY: kernel32's export, over one unit and one type word.
    unsafe { imports::GetStringTypeW(CT_CTYPE1, &c, 1, &mut types) };
    types & mask
}

/// A wide character's case mapped, in the LC_CTYPE locale.
fn map_wide(c: u16, upper: bool) -> u16 {
    if c == WEOF {
        return c;
    }
    let state = tables();
    if state.lcid == 0 {
        return match c {
            0x41..=0x5A if !upper => c + 0x20,
            0x61..=0x7A if upper => c - 0x20,
            _ => c,
        };
    }
    let flags = if upper {
        LCMAP_UPPERCASE
    } else {
        LCMAP_LOWERCASE
    };
    let mut mapped = 0u16;
    // SAFETY: kernel32's export, over one unit each way.
    match unsafe { imports::LCMapStringW(state.lcid, flags, &c, 1, &mut mapped, 1) } {
        0 => c,
        _ => mapped,
    }
}

pub fn wide_lower(c: u16) -> u16 {
    map_wide(c, false)
}

pub fn wide_upper(c: u16) -> u16 {
    map_wide(c, true)
}

/// A narrow character lowered, in the LC_CTYPE locale.
pub fn byte_lower(byte: u8) -> u8 {
    tables().lower[byte as usize]
}

/// A narrow character raised, in the LC_CTYPE locale.
pub fn byte_upper(byte: u8) -> u8 {
    tables().upper[byte as usize]
}

/// A narrow character as a wide one (mbtowc), in the LC_CTYPE locale.
pub fn byte_to_wide(byte: u8) -> u16 {
    let state = tables();
    if state.lcid == 0 {
        return byte as u16;
    }
    let mut wide = 0u16;
    // SAFETY: kernel32's export, over one byte and one unit.
    match unsafe { imports::MultiByteToWideChar(state.page, 0, &byte, 1, &mut wide, 1) } {
        0 => byte as u16,
        _ => wide,
    }
}

/// A wide character as a narrow one (wctomb), in the LC_CTYPE locale; none when the locale's code
/// page has no character for it.
pub fn wide_to_byte(c: u16) -> Option<u8> {
    let state = tables();
    if state.lcid == 0 {
        return (c < 0x100).then_some(c as u8);
    }
    let (mut byte, mut defaulted) = (0u8, 0u32);
    // SAFETY: kernel32's export, over one unit and one byte.
    let written = unsafe {
        imports::WideCharToMultiByte(
            state.page,
            0,
            &c,
            1,
            &mut byte,
            1,
            core::ptr::null(),
            &mut defaulted,
        )
    };
    (written == 1 && defaulted == 0).then_some(byte)
}

/// A string locale value of `lcid` (GetLocaleInfoA), into `out`; its length.
fn locale_info(lcid: u32, lctype: u32, out: &mut [u8; 64]) -> usize {
    // SAFETY: kernel32's export, over the buffer.
    let length =
        unsafe { imports::GetLocaleInfoA(lcid, lctype, out.as_mut_ptr(), out.len() as i32) };
    (length as usize).saturating_sub(1)
}

/// A numeric locale value of `lcid`.
fn locale_number(lcid: u32, lctype: u32) -> u32 {
    let mut text = [0u8; 64];
    let length = locale_info(lcid, lctype, &mut text);
    text[..length]
        .iter()
        .take_while(|b| b.is_ascii_digit())
        .fold(0, |value, &b| value * 10 + (b - b'0') as u32)
}

fn equal_ignoring_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// The locale a setlocale name selects: "C", "" (the user's), or
/// `language[_country][.code_page]` / `.code_page` naming the user's locale (kernel32 knows that
/// one alone) by its English or abbreviated names, its code page its ANSI one (or "ACP"), or its
/// OEM one (or "OCP").
fn resolve(text: &[u8]) -> Option<Resolved> {
    if text == b"C" {
        return Some(Resolved {
            lcid: 0,
            page: 0,
            name: Name::C,
        });
    }
    // SAFETY: kernel32's export.
    let lcid = unsafe { imports::GetUserDefaultLCID() };
    let ansi = locale_number(lcid, LOCALE_IDEFAULTANSICODEPAGE);
    let mut page = ansi;
    if !text.is_empty() {
        let (names, code_page) = match text.iter().position(|&b| b == b'.') {
            Some(dot) => (&text[..dot], Some(&text[dot + 1..])),
            None => (text, None),
        };
        let (language, country) = match names.iter().position(|&b| b == b'_') {
            Some(underscore) => (&names[..underscore], Some(&names[underscore + 1..])),
            None => (names, None),
        };
        let matches = |given: &[u8], lctypes: &[u32], aliases: &[&[u8]]| {
            lctypes.iter().any(|&lctype| {
                let mut value = [0u8; 64];
                let length = locale_info(lcid, lctype, &mut value);
                equal_ignoring_case(given, &value[..length])
            }) || aliases
                .iter()
                .any(|alias| equal_ignoring_case(given, alias))
        };
        if !language.is_empty()
            && !matches(
                language,
                &[LOCALE_SENGLANGUAGE, LOCALE_SABBREVLANGNAME],
                &[
                    b"american",
                    b"american english",
                    b"american-english",
                    b"english-american",
                    b"english-us",
                    b"english-usa",
                ],
            )
        {
            return None;
        }
        if language.is_empty() && code_page.is_none() {
            return None;
        }
        if let Some(country) = country {
            if !matches(
                country,
                &[LOCALE_SENGCOUNTRY, LOCALE_SABBREVCTRYNAME],
                &[b"america", b"united-states", b"us"],
            ) {
                return None;
            }
        }
        if let Some(code_page) = code_page {
            let oem = locale_number(lcid, LOCALE_IDEFAULTCODEPAGE);
            page = if equal_ignoring_case(code_page, b"ACP") {
                ansi
            } else if equal_ignoring_case(code_page, b"OCP") {
                oem
            } else if !code_page.is_empty() && code_page.iter().all(u8::is_ascii_digit) {
                code_page.iter().fold(0u32, |value, &b| {
                    value.saturating_mul(10).saturating_add((b - b'0') as u32)
                })
            } else {
                return None;
            };
            if page != ansi && page != oem {
                return None;
            }
        }
    }
    let mut name = Name::of(b"");
    let mut value = [0u8; 64];
    let length = locale_info(lcid, LOCALE_SENGLANGUAGE, &mut value);
    name.push(&value[..length]);
    name.push(b"_");
    let length = locale_info(lcid, LOCALE_SENGCOUNTRY, &mut value);
    name.push(&value[..length]);
    name.push(b".");
    let mut digits = [0u8; 10];
    let mut count = 0;
    let mut rest = page;
    loop {
        digits[count] = b'0' + (rest % 10) as u8;
        count += 1;
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    digits[..count].reverse();
    name.push(&digits[..count]);
    Some(Resolved { lcid, page, name })
}

/// New LC_CTYPE tables for `locale` (not the "C" locale), from the C runtime's heap, `next` after
/// them; none when the heap has no room. They are never freed: a reader may hold them at any time.
fn make_tables(locale: &Resolved, next: Option<&'static Tables>) -> Option<&'static Tables> {
    let block = crate::heap::allocate(core::mem::size_of::<Tables>(), true).cast::<Tables>();
    if block.is_null() {
        return None;
    }
    debug_assert!(block.is_aligned());
    // SAFETY: a fresh, zeroed block of the C runtime's heap of a Tables' size, aligned (the heap's
    // blocks are 8-aligned), and all zero is a valid Tables (numbers, and `next` none). It is never
    // freed, and nothing else reaches it until it is published.
    let tables: &'static mut Tables = unsafe { &mut *block };
    tables.lcid = locale.lcid;
    tables.page = locale.page;
    tables.next = next;
    let mut bytes = [0u8; 256];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = i as u8;
    }
    // SAFETY: kernel32's exports, over the 256 bytes and the tables of 256 entries.
    unsafe {
        imports::GetStringTypeA(
            locale.lcid,
            CT_CTYPE1,
            bytes.as_ptr(),
            256,
            tables.class.as_mut_ptr(),
        );
        imports::LCMapStringA(
            locale.lcid,
            LCMAP_LOWERCASE,
            bytes.as_ptr(),
            256,
            tables.lower.as_mut_ptr(),
            256,
        );
        imports::LCMapStringA(
            locale.lcid,
            LCMAP_UPPERCASE,
            bytes.as_ptr(),
            256,
            tables.upper.as_mut_ptr(),
            256,
        );
    }
    Some(tables)
}

impl Locale {
    /// LC_CTYPE's tables for `locale`: the "C" locale's, those made before for its LCID and code
    /// page, or new ones; none when the heap has no room for them.
    fn tables_for(&mut self, locale: &Resolved) -> Option<&'static Tables> {
        if locale.lcid == 0 {
            return Some(&C_TABLES);
        }
        let mut made = self.made;
        while let Some(tables) = made {
            if (tables.lcid, tables.page) == (locale.lcid, locale.page) {
                return Some(tables);
            }
            made = tables.next;
        }
        let tables = make_tables(locale, self.made)?;
        self.made = Some(tables);
        Some(tables)
    }

    /// The name setlocale answers for `category`, into its answer storage: the storage's address.
    /// It stays valid for the process's life; the next setlocale overwrites it, as the C runtime's
    /// contract says.
    fn answer(&mut self, category: usize) -> *const u8 {
        let names = &self.names;
        let storage = &mut self.answer;
        let mut length = 0;
        let mut push = |text: &[u8]| {
            let take = text.len().min(storage.len() - 1 - length);
            storage[length..length + take].copy_from_slice(&text[..take]);
            length += take;
        };
        if category == 0 && names[1..].iter().any(|name| *name != names[1]) {
            for c in 1..=LC_MAX {
                if c > 1 {
                    push(b";");
                }
                push(CATEGORY_NAMES[c]);
                push(b"=");
                push(names[c].text());
            }
        } else {
            push(names[category.max(1)].text());
        }
        storage[length] = 0;
        storage.as_ptr()
    }

    /// setlocale's work, under the locale's lock: `category` set to the locale `text` names, or
    /// asked (none); the answer's address, or none when `text` names no locale or the heap has no
    /// room for its tables (nothing changes then).
    fn set(&mut self, category: usize, text: Option<&[u8]>) -> Option<*const u8> {
        if let Some(text) = text {
            let mut chosen = [None; LC_MAX + 1];
            if category == 0 && text.contains(&b'=') {
                chosen = resolve_composite(text)?;
            } else {
                let resolved = resolve(text)?;
                if category == 0 {
                    chosen[1..].fill(Some(resolved));
                } else {
                    chosen[category] = Some(resolved);
                }
            }
            let ctype = match &chosen[LC_CTYPE as usize] {
                Some(locale) => Some(self.tables_for(locale)?),
                None => None,
            };
            for (name, locale) in self.names.iter_mut().zip(&chosen) {
                if let Some(locale) = locale {
                    *name = locale.name;
                }
            }
            if let Some(tables) = ctype {
                CTYPE.store(core::ptr::from_ref(tables).cast_mut(), Release);
            }
        }
        Some(self.answer(category))
    }
}

/// A composite LC_ALL name's categories (`LC_X=name;…`) resolved, each in its place; none when
/// one names no category or no locale.
fn resolve_composite(text: &[u8]) -> Option<[Option<Resolved>; LC_MAX + 1]> {
    let mut resolved = [None; LC_MAX + 1];
    for part in text.split(|&b| b == b';') {
        let equals = part.iter().position(|&b| b == b'=')?;
        let category = (1..=LC_MAX).find(|&c| CATEGORY_NAMES[c] == &part[..equals])?;
        resolved[category] = Some(resolve(&part[equals + 1..])?);
    }
    Some(resolved)
}

/// setlocale: `category`'s locale set to the one `locale` names, or asked (NULL); answers its name
/// (LC_ALL's composite when its categories differ), or NULL when `locale` names none (nothing
/// changes) or the category is unknown.
///
/// # Safety
///
/// `locale` is null or a NUL-terminated string.
#[unsafe(export_name = "f2k_export_setlocale")]
pub unsafe extern "C" fn setlocale(category: i32, locale: *const u8) -> *const u8 {
    if !(0..=LC_MAX as i32).contains(&category) {
        return core::ptr::null();
    }
    let category = category as usize;
    // SAFETY: the caller's string.
    let text =
        (!locale.is_null()).then(|| unsafe { core::ffi::CStr::from_ptr(locale.cast()) }.to_bytes());
    STATE
        .with(|state| state.set(category, text))
        .unwrap_or(core::ptr::null())
}

/// iswalpha: a letter (`_ALPHA`'s classes).
#[unsafe(export_name = "f2k_export_iswalpha")]
pub extern "C" fn iswalpha(c: u32) -> i32 {
    wide_class(c as u16, ALPHA) as i32
}

/// iswdigit: a decimal digit.
#[unsafe(export_name = "f2k_export_iswdigit")]
pub extern "C" fn iswdigit(c: u32) -> i32 {
    wide_class(c as u16, DIGIT) as i32
}

/// iswspace: a space character.
#[unsafe(export_name = "f2k_export_iswspace")]
pub extern "C" fn iswspace(c: u32) -> i32 {
    wide_class(c as u16, SPACE) as i32
}

/// iswxdigit: a hexadecimal digit.
#[unsafe(export_name = "f2k_export_iswxdigit")]
pub extern "C" fn iswxdigit(c: u32) -> i32 {
    wide_class(c as u16, HEX) as i32
}

/// towlower: `c`'s small letter, in the LC_CTYPE locale.
#[unsafe(export_name = "f2k_export_towlower")]
pub extern "C" fn towlower(c: u32) -> u32 {
    wide_lower(c as u16) as u32
}

/// towupper: `c`'s capital letter, in the LC_CTYPE locale.
#[unsafe(export_name = "f2k_export_towupper")]
pub extern "C" fn towupper(c: u32) -> u32 {
    wide_upper(c as u16) as u32
}

/// toupper: `c`'s capital letter, in the LC_CTYPE locale (the "C" locale's ASCII letters alone);
/// a value that is not an unsigned char's (EOF among them) unchanged.
#[unsafe(export_name = "f2k_export_toupper")]
pub extern "C" fn toupper(c: i32) -> i32 {
    match u8::try_from(c) {
        Ok(byte) => byte_upper(byte) as i32,
        Err(_) => c,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The host tests share the process's locale: those that change it hold this.
    pub static LOCALE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn set(category: i32, name: &[u8]) -> Option<String> {
        let mut text = name.to_vec();
        text.push(0);
        // SAFETY: a NUL-terminated name.
        let answer = unsafe { setlocale(category, text.as_ptr()) };
        name_of(answer)
    }

    fn ask(category: i32) -> Option<String> {
        // SAFETY: a query.
        name_of(unsafe { setlocale(category, core::ptr::null()) })
    }

    fn name_of(answer: *const u8) -> Option<String> {
        // SAFETY: setlocale's NUL-terminated answer.
        (!answer.is_null()).then(|| unsafe {
            core::ffi::CStr::from_ptr(answer.cast())
                .to_string_lossy()
                .into_owned()
        })
    }

    /// wide's locale block.
    #[test]
    fn setlocale_as_captured() {
        let _locale = LOCALE.lock().unwrap();
        let user = Some("English_United States.1252".to_string());
        assert_eq!(ask(LC_ALL).as_deref(), Some("C"));
        assert_eq!(set(LC_ALL, b""), user);
        assert_eq!(ask(LC_CTYPE), user);
        assert_eq!(set(LC_ALL, b"C").as_deref(), Some("C"));
        assert_eq!(set(LC_ALL, b"zz-not-a-locale"), None);
        assert_eq!(ask(LC_ALL).as_deref(), Some("C"));
        assert_eq!(set(4, b""), user);
        assert_eq!(
            ask(LC_ALL).as_deref(),
            Some("LC_COLLATE=C;LC_CTYPE=C;LC_MONETARY=C;LC_NUMERIC=English_United States.1252;LC_TIME=C")
        );
        let composite = ask(LC_ALL).unwrap();
        assert_eq!(set(LC_ALL, b"C").as_deref(), Some("C"));
        assert_eq!(set(LC_ALL, composite.as_bytes()), Some(composite));
        assert_eq!(set(LC_ALL, b"english_usa.1252"), user);
        assert_eq!(set(LC_ALL, b".ACP"), user);
        assert_eq!(set(LC_ALL, b"German"), None);
        assert_eq!(set(6, b"C"), None);
        assert_eq!(set(LC_ALL, b"C").as_deref(), Some("C"));
    }

    /// wide's ctype block, in both locales: the classes and the case mappings of each code point.
    #[test]
    fn classes_as_captured() {
        let _locale = LOCALE.lock().unwrap();
        // (code point, alpha, digit, space, xdigit, lower, upper) in "C", then in "".
        let c_locale: &[(u32, i32, i32, i32, i32, u32, u32)] = &[
            (0x0009, 0, 0, 8, 0, 0x0009, 0x0009),
            (0x0030, 0, 4, 0, 0x80, 0x0030, 0x0030),
            (0x0041, 1, 0, 0, 0x80, 0x0061, 0x0041),
            (0x0047, 1, 0, 0, 0, 0x0067, 0x0047),
            (0x005F, 0, 0, 0, 0, 0x005F, 0x005F),
            (0x0061, 2, 0, 0, 0x80, 0x0061, 0x0041),
            (0x007F, 0, 0, 0, 0, 0x007F, 0x007F),
            (0x00A0, 0, 0, 0, 0, 0x00A0, 0x00A0),
            (0x00C9, 0, 0, 0, 0, 0x00C9, 0x00C9),
            (0x00FF, 0, 0, 0, 0, 0x00FF, 0x00FF),
            (0x0100, 0x101, 0, 0, 0, 0x0100, 0x0100),
            (0x03B1, 0x102, 0, 0, 0, 0x03B1, 0x03B1),
            (0x0660, 0, 4, 0, 0, 0x0660, 0x0660),
            (0x2028, 0, 0, 0, 0, 0x2028, 0x2028),
            (0x3000, 0, 0, 8, 0, 0x3000, 0x3000),
            (0x4E00, 0x100, 0, 0, 0, 0x4E00, 0x4E00),
            (0xFEFF, 0, 0, 8, 0, 0xFEFF, 0xFEFF),
            (0xFF10, 0, 4, 0, 0x80, 0xFF10, 0xFF10),
            (0xFF21, 0x101, 0, 0, 0x80, 0xFF21, 0xFF21),
        ];
        let user_locale: &[(u32, i32, i32, i32, i32, u32, u32)] = &[
            (0x0041, 0x101, 0, 0, 0x80, 0x0061, 0x0041),
            (0x0061, 0x102, 0, 0, 0x80, 0x0061, 0x0041),
            (0x00A0, 0, 0, 8, 0, 0x00A0, 0x00A0),
            (0x00AA, 0, 0, 0, 0, 0x00AA, 0x00AA),
            (0x00B2, 0, 4, 0, 0, 0x00B2, 0x00B2),
            (0x00B5, 0, 0, 0, 0, 0x00B5, 0x00B5),
            (0x00C9, 0x101, 0, 0, 0, 0x00E9, 0x00C9),
            (0x00DF, 0x102, 0, 0, 0, 0x00DF, 0x00DF),
            (0x00FF, 0x102, 0, 0, 0, 0x00FF, 0x0178),
            (0x0100, 0x101, 0, 0, 0, 0x0101, 0x0100),
            (0x0178, 0x101, 0, 0, 0, 0x00FF, 0x0178),
            (0x0391, 0x101, 0, 0, 0, 0x03B1, 0x0391),
            (0x0436, 0x102, 0, 0, 0, 0x0436, 0x0416),
            (0xFF21, 0x101, 0, 0, 0x80, 0xFF41, 0xFF21),
            (0xFF41, 0x102, 0, 0, 0x80, 0xFF41, 0xFF21),
        ];
        let check = |table: &[(u32, i32, i32, i32, i32, u32, u32)]| {
            for &(c, alpha, digit, space, xdigit, lower, upper) in table {
                assert_eq!(
                    (
                        iswalpha(c),
                        iswdigit(c),
                        iswspace(c),
                        iswxdigit(c),
                        towlower(c),
                        towupper(c)
                    ),
                    (alpha, digit, space, xdigit, lower, upper),
                    "U+{c:04X}"
                );
            }
        };
        set(LC_ALL, b"C");
        check(c_locale);
        set(LC_ALL, b"");
        check(user_locale);
        set(LC_ALL, b"C");
    }

    /// toupper raises the "C" locale's ASCII letters alone, the user locale's code page 1252
    /// letters too; a value outside an unsigned char's passes unchanged.
    #[test]
    fn toupper_raises_in_the_locale() {
        let _locale = LOCALE.lock().unwrap();
        set(LC_ALL, b"C");
        assert_eq!(
            [b'a', b'z', b'A', b'1', b'{', 0xE9].map(|c| toupper(c as i32)),
            [b'A', b'Z', b'A', b'1', b'{', 0xE9].map(i32::from)
        );
        assert_eq!([-1, 0x161, -23].map(|c| toupper(c)), [-1, 0x161, -23]);
        set(LC_ALL, b"");
        assert_eq!(toupper(0xE9), 0xC9);
        assert_eq!(toupper(b'q' as i32), b'Q' as i32);
        set(LC_ALL, b"C");
    }
}
