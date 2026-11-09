//! The resources: FindResourceA/W and FindResourceExA/W over ntdll's LdrFindResource_U, and
//! LoadResource, SizeofResource, LockResource and FreeResource over LdrAccessResource. The stand-in
//! ntdll holds the program's resources as the resource fixture's script lays them out, and
//! kernel32's message table (`crate::nt::resources`); it records each path kernel32 hands it.

use super::last_error;
use crate::base::set_last_error;
use crate::nt::{PathElement, IMAGE_BASE, KERNEL32, NTDLL, RESOURCE_PATHS, RT_RCDATA};
use crate::resource::{
    find_resource_a,
    find_resource_ex_a,
    find_resource_ex_w,
    find_resource_w,
    free_resource,
    load_resource,
    lock_resource,
    sizeof_resource,
};

const IMAGE: usize = IMAGE_BASE as usize;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_RESOURCE_DATA_NOT_FOUND: u32 = 1812;
const ERROR_RESOURCE_TYPE_NOT_FOUND: u32 = 1813;
const ERROR_RESOURCE_NAME_NOT_FOUND: u32 = 1814;
const ERROR_RESOURCE_LANG_NOT_FOUND: u32 = 1815;
/// A last error no call sets: one still there after a call was left untouched.
const UNTOUCHED: u32 = 0x0F2F_2F2F;

/// A NUL-terminated UTF-16 copy of `text`.
fn w(text: &str) -> std::vec::Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A NUL-terminated copy of `text`'s bytes.
fn a(text: &[u8]) -> std::vec::Vec<u8> {
    text.iter().copied().chain([0]).collect()
}

/// MAKEINTRESOURCEW and MAKEINTRESOURCEA.
fn id_w(id: u16) -> *const u16 {
    usize::from(id) as *const u16
}

fn id_a(id: u16) -> *const u8 {
    usize::from(id) as *const u8
}

/// The path the last lookup handed ntdll.
fn last_path() -> std::vec::Vec<PathElement> {
    RESOURCE_PATHS.with(|paths| paths.borrow().last().cloned().unwrap())
}

fn name(text: &str) -> PathElement {
    PathElement::Name(text.into())
}

/// A resource's data, through LoadResource and SizeofResource, as bytes.
fn data(module: usize, resource: usize) -> std::vec::Vec<u8> {
    let at = load_resource(module, resource);
    let size = sizeof_resource(module, resource) as usize;
    assert_ne!(at, 0);
    // SAFETY: the stand-in's data, `size` bytes at the address LoadResource answered.
    unsafe { core::slice::from_raw_parts(at as *const u8, size) }.to_vec()
}

/// A number is handed to ntdll as it is, and `#` with decimal digits stands for the same number:
/// both find the same resource, through the same path; FindResource asks for language 0.
///
/// Pins: kernel32.FindResourceW, kernel32.FindResourceA
#[test]
fn numbers_and_hash_strings_find_the_same_resource() {
    let rcdata = id_w(RT_RCDATA as u16);
    let by_number = unsafe { find_resource_w(IMAGE, id_w(101), rcdata) };
    assert_ne!(by_number, 0);
    assert_eq!(
        last_path(),
        [
            PathElement::Id(10),
            PathElement::Id(101),
            PathElement::Id(0)
        ]
    );
    for text in ["#101", "#0101"] {
        assert_eq!(
            unsafe { find_resource_w(IMAGE, w(text).as_ptr(), rcdata) },
            by_number,
            "{text}"
        );
        assert_eq!(last_path()[1], PathElement::Id(101));
    }
    assert_eq!(
        unsafe { find_resource_w(IMAGE, w("#101").as_ptr(), w("#10").as_ptr()) },
        by_number
    );
    assert_eq!(
        unsafe { find_resource_a(IMAGE, a(b"#101").as_ptr(), a(b"#10").as_ptr()) },
        by_number
    );
    assert_eq!(
        last_path()[..2],
        [PathElement::Id(10), PathElement::Id(101)]
    );
}

/// Whatever follows `#` is the number ntdll's RtlUnicodeStringToInteger reads there: its digits up
/// to the first that is not one, none being 0 ("#abc" is 0, a number no resource has, which Windows
/// 2000 answers with ERROR_RESOURCE_NAME_NOT_FOUND too). A number past a word fails the call with
/// ERROR_INVALID_PARAMETER before any lookup.
///
/// Pins: kernel32.FindResourceW, kernel32.FindResourceA
#[test]
fn hash_strings_are_read_by_ntdll() {
    let rcdata = id_w(RT_RCDATA as u16);
    for (text, number) in [("#abc", 0), ("#", 0), ("#1a", 1), ("# 7", 7)] {
        set_last_error(0);
        assert_eq!(
            unsafe { find_resource_w(IMAGE, w(text).as_ptr(), rcdata) },
            0
        );
        assert_eq!(last_error(), ERROR_RESOURCE_NAME_NOT_FOUND, "{text}");
        assert_eq!(last_path()[1], PathElement::Id(number), "{text}");
    }
    assert_ne!(
        unsafe { find_resource_a(IMAGE, a(b"#101abc").as_ptr(), a(b"#10").as_ptr()) },
        0
    );
    let lookups = RESOURCE_PATHS.with(|paths| paths.borrow().len());
    set_last_error(0);
    assert_eq!(
        unsafe { find_resource_w(IMAGE, w("#70000").as_ptr(), rcdata) },
        0
    );
    assert_eq!(last_error(), ERROR_INVALID_PARAMETER);
    assert_eq!(
        RESOURCE_PATHS.with(|paths| paths.borrow().len()),
        lookups,
        "no lookup"
    );
}

/// The empty string is a name: no resource has it.
///
/// Pins: kernel32.FindResourceA
#[test]
fn the_empty_string_is_a_name() {
    set_last_error(0);
    assert_eq!(
        unsafe { find_resource_a(IMAGE, a(b"").as_ptr(), id_a(RT_RCDATA as u16)) },
        0
    );
    assert_eq!(last_error(), ERROR_RESOURCE_NAME_NOT_FOUND);
    assert_eq!(last_path()[1], name(""));
}

/// Names and types are matched without regard to case: kernel32 hands ntdll each upper-cased (by
/// ntdll's RtlUpcaseUnicodeString), as the resource compiler stores them; an A call's converted
/// through the ANSI code page first.
///
/// Pins: kernel32.FindResourceW, kernel32.FindResourceA
#[test]
fn names_are_upper_cased() {
    let rcdata = id_w(RT_RCDATA as u16);
    let upper = unsafe { find_resource_w(IMAGE, w("MIXEDNAME").as_ptr(), rcdata) };
    assert_ne!(upper, 0);
    for text in ["mixedname", "MixedName", "mixedNAME"] {
        assert_eq!(
            unsafe { find_resource_w(IMAGE, w(text).as_ptr(), rcdata) },
            upper
        );
        assert_eq!(last_path()[1], name("MIXEDNAME"));
    }
    let item = unsafe { find_resource_a(IMAGE, a(b"item").as_ptr(), a(b"MyType").as_ptr()) };
    assert_ne!(item, 0);
    assert_eq!(
        last_path(),
        [name("MYTYPE"), name("ITEM"), PathElement::Id(0)]
    );
    assert_eq!(data(IMAGE, item), b"custom type");
    // Code page 1252's e acute (0xE9) is U+00E9, upper-cased to U+00C9.
    set_last_error(0);
    assert_eq!(
        unsafe { find_resource_a(IMAGE, a(b"caf\xE9").as_ptr(), id_a(10)) },
        0
    );
    assert_eq!(last_path()[1], name("CAF\u{C9}"));
    assert_eq!(last_error(), ERROR_RESOURCE_NAME_NOT_FOUND);
}

/// A NULL module is the program's own image, for the lookups and for the data.
///
/// Pins: kernel32.FindResourceW, kernel32.FindResourceExA, kernel32.LoadResource,
/// kernel32.SizeofResource
#[test]
fn a_null_module_is_the_program() {
    let rcdata = id_w(RT_RCDATA as u16);
    let found = unsafe { find_resource_w(IMAGE, id_w(101), rcdata) };
    assert_eq!(unsafe { find_resource_w(0, id_w(101), rcdata) }, found);
    assert_eq!(
        unsafe { find_resource_ex_a(0, id_a(10), id_a(101), 0x0409) },
        found
    );
    assert_eq!(load_resource(0, found), load_resource(IMAGE, found));
    assert_eq!(sizeof_resource(0, found), 11);
}

/// Each level's lookup not found has its own error, mapped from ntdll's status; a module without
/// resources is ERROR_RESOURCE_DATA_NOT_FOUND.
///
/// Pins: kernel32.FindResourceW, kernel32.FindResourceA, kernel32.FindResourceExW
#[test]
fn each_level_not_found_has_its_error() {
    /// The call fails (NULL) with `error`.
    fn fails_with(what: &str, call: impl FnOnce() -> usize, error: u32) {
        set_last_error(0);
        assert_eq!(call(), 0, "{what}");
        assert_eq!(last_error(), error, "{what}");
    }
    let rcdata = id_w(RT_RCDATA as u16);
    let no_type = w("NOSUCHTYPE");
    fails_with(
        "type",
        || unsafe { find_resource_w(IMAGE, id_w(101), no_type.as_ptr()) },
        ERROR_RESOURCE_TYPE_NOT_FOUND,
    );
    fails_with(
        "name",
        || unsafe { find_resource_w(IMAGE, id_w(999), rcdata) },
        ERROR_RESOURCE_NAME_NOT_FOUND,
    );
    fails_with(
        "language",
        || unsafe { find_resource_ex_w(IMAGE, rcdata, id_w(200), 0x0407) },
        ERROR_RESOURCE_LANG_NOT_FOUND,
    );
    let my_type = a(b"MYTYPE");
    fails_with(
        "kernel32's type",
        || unsafe { find_resource_a(KERNEL32 as usize, id_a(1), my_type.as_ptr()) },
        ERROR_RESOURCE_TYPE_NOT_FOUND,
    );
    fails_with(
        "the arguments swapped",
        || unsafe { find_resource_ex_w(IMAGE, id_w(101), rcdata, 0x0409) },
        ERROR_RESOURCE_TYPE_NOT_FOUND,
    );
    fails_with(
        "ntdll",
        || unsafe { find_resource_w(NTDLL as usize, id_w(1), rcdata) },
        ERROR_RESOURCE_DATA_NOT_FOUND,
    );
}

/// FindResourceEx takes the type before the name and asks for the language given, which finds the
/// neutral language's resource when it has none of its own, never another sublanguage's;
/// FindResource asks for language 0, which finds US English, F2K's locale, among two.
///
/// Pins: kernel32.FindResourceExW, kernel32.FindResourceExA, kernel32.FindResourceW
#[test]
fn the_languages() {
    let rcdata = id_w(RT_RCDATA as u16);
    let english = unsafe { find_resource_ex_w(IMAGE, rcdata, id_w(200), 0x0409) };
    let french = unsafe { find_resource_ex_w(IMAGE, rcdata, id_w(200), 0x040C) };
    assert_eq!(
        last_path(),
        [
            PathElement::Id(10),
            PathElement::Id(200),
            PathElement::Id(0x040C)
        ]
    );
    assert_eq!(data(IMAGE, english), b"english");
    assert_eq!(data(IMAGE, french), b"francais");
    assert_eq!(
        unsafe { find_resource_w(IMAGE, id_w(200), rcdata) },
        english
    );
    // LANG_NEUTRAL with SUBLANG_DEFAULT: the user's default language. The language is a WORD:
    // its dword's high half is not part of it.
    assert_eq!(
        unsafe { find_resource_ex_a(IMAGE, id_a(10), id_a(200), 0xFFFF_0400) },
        english
    );
    assert_eq!(last_path()[2], PathElement::Id(0x0400));
    let neutral = unsafe { find_resource_w(IMAGE, id_w(201), rcdata) };
    assert_eq!(data(IMAGE, neutral), b"neutral");
    for language in [0x0409, 0] {
        assert_eq!(
            unsafe { find_resource_ex_w(IMAGE, rcdata, id_w(201), language) },
            neutral,
            "{language:#06x}"
        );
    }
    for language in [0x0809, 0x0407] {
        set_last_error(0);
        assert_eq!(
            unsafe { find_resource_ex_w(IMAGE, rcdata, id_w(200), language) },
            0
        );
        assert_eq!(last_error(), ERROR_RESOURCE_LANG_NOT_FOUND);
    }
}

/// LoadResource answers the data's address and LockResource hands it back; SizeofResource its size;
/// FreeResource is FALSE, the last error untouched. A NULL HRSRC fails both calls with
/// ERROR_RESOURCE_DATA_NOT_FOUND, as on Windows 2000.
///
/// Pins: kernel32.LoadResource, kernel32.SizeofResource, kernel32.LockResource,
/// kernel32.FreeResource
#[test]
fn the_data() {
    let found = unsafe { find_resource_w(IMAGE, id_w(101), id_w(10)) };
    let loaded = load_resource(IMAGE, found);
    assert_eq!(lock_resource(loaded), loaded);
    assert_eq!(sizeof_resource(IMAGE, found), 11);
    assert_eq!(data(IMAGE, found), b"id 101 data");
    set_last_error(UNTOUCHED);
    assert_eq!(free_resource(loaded), 0);
    assert_eq!(free_resource(0), 0);
    assert_eq!(last_error(), UNTOUCHED);
    assert_eq!(lock_resource(0), 0);
    set_last_error(0);
    assert_eq!(load_resource(IMAGE, 0), 0);
    assert_eq!(last_error(), ERROR_RESOURCE_DATA_NOT_FOUND);
    set_last_error(0);
    assert_eq!(sizeof_resource(IMAGE, 0), 0);
    assert_eq!(last_error(), ERROR_RESOURCE_DATA_NOT_FOUND);
    // Another module's HRSRC is not one of kernel32's resources there.
    set_last_error(0);
    assert_eq!(load_resource(KERNEL32 as usize, found), 0);
    assert_eq!(last_error(), ERROR_RESOURCE_DATA_NOT_FOUND);
}
