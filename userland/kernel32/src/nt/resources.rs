//! The host tests' resources: a model of the modules' resource directories ([`RESOURCE_MODEL`]),
//! and LdrFindResource_U and LdrAccessResource over it, recording each path they were given
//! ([`RESOURCE_PATHS`]). The walk itself is `rtl::resource`'s, tested there: the stand-in matches
//! as it does (numbers, names exactly, languages in `rtl::resource::languages`' order).

use std::cell::RefCell;

use rtl::resource::{self, Defaults};

use super::modules::KERNEL32;
use super::threads::IMAGE_BASE;

/// A type or a name, as the model holds one: a number, or a name as the resource compiler
/// stores it (in upper case).
#[derive(Clone, Copy, Debug)]
pub enum ResourceKey {
    Id(u32),
    Name(&'static str),
}

/// One resource of the model: its module, type, name, language and data.
pub struct ModelResource {
    pub module: u32,
    pub kind: ResourceKey,
    pub name: ResourceKey,
    pub language: u16,
    pub data: &'static [u8],
}

/// RT_STRING and RT_RCDATA.
pub const RT_STRING: u32 = 6;
pub const RT_RCDATA: u32 = 10;

/// The modules' resources: the image's, as the resource fixture's script lays them out, and
/// kernel32's message table. ntdll has none. A data entry's address is its record's here.
pub static RESOURCE_MODEL: [ModelResource; 8] = [
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(RT_RCDATA),
        name: ResourceKey::Id(101),
        language: 0x0409,
        data: b"id 101 data",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(RT_RCDATA),
        name: ResourceKey::Name("MIXEDNAME"),
        language: 0x0409,
        data: b"named data",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Name("MYTYPE"),
        name: ResourceKey::Name("ITEM"),
        language: 0x0409,
        data: b"custom type",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(300),
        name: ResourceKey::Id(7),
        language: 0x0409,
        data: b"type 300",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(RT_RCDATA),
        name: ResourceKey::Id(200),
        language: 0x040C,
        data: b"francais",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(RT_RCDATA),
        name: ResourceKey::Id(200),
        language: 0x0409,
        data: b"english",
    },
    ModelResource {
        module: IMAGE_BASE,
        kind: ResourceKey::Id(RT_RCDATA),
        name: ResourceKey::Id(201),
        language: 0,
        data: b"neutral",
    },
    ModelResource {
        module: KERNEL32,
        kind: ResourceKey::Id(resource::RT_MESSAGETABLE),
        name: ResourceKey::Id(resource::MESSAGE_TABLE_NAME),
        language: 0x0409,
        data: b"\0\0\0\0",
    },
];

/// A path element as LdrFindResource_U was handed it: a number, or the name it pointed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathElement {
    Id(u32),
    Name(std::string::String),
}

std::thread_local! {
    /// The paths LdrFindResource_U was given, in order.
    pub static RESOURCE_PATHS: RefCell<std::vec::Vec<std::vec::Vec<PathElement>>> = const { RefCell::new(std::vec::Vec::new()) };
}

/// An element as the path holds it: a number when its high word is zero, else a
/// NUL-terminated UTF-16 name's address (read to its terminator).
fn element(value: usize) -> PathElement {
    if value >> 16 == 0 {
        return PathElement::Id(value as u32);
    }
    let mut units = std::vec::Vec::new();
    // SAFETY: the caller's name, read to its NUL.
    while let unit @ 1.. = unsafe { (value as *const u16).add(units.len()).read_unaligned() } {
        units.push(unit);
    }
    PathElement::Name(std::string::String::from_utf16(&units).unwrap())
}

/// Whether the model's key is the element, exactly.
fn matches(key: ResourceKey, element: &PathElement) -> bool {
    match (key, element) {
        (ResourceKey::Id(id), PathElement::Id(value)) => id == *value,
        (ResourceKey::Name(name), PathElement::Name(value)) => name == value,
        _ => false,
    }
}

/// LdrFindResource_U over the model, for the three-element paths kernel32 hands it:
/// STATUS_RESOURCE_DATA_NOT_FOUND for a module without resources, then the level's status for
/// a type, a name or a language not found.
pub unsafe extern "system" fn LdrFindResource_U(
    module: usize,
    path: *const usize,
    length: u32,
    entry: *mut usize,
) -> u32 {
    assert_eq!(length, 3);
    // SAFETY: the caller's three elements.
    let path: std::vec::Vec<PathElement> = unsafe { core::slice::from_raw_parts(path, 3) }
        .iter()
        .map(|&value| element(value))
        .collect();
    RESOURCE_PATHS.with(|paths| paths.borrow_mut().push(path.clone()));
    let PathElement::Id(language) = path[2] else {
        panic!("a language is a number");
    };
    let of_module: std::vec::Vec<&ModelResource> = RESOURCE_MODEL
        .iter()
        .filter(|found| found.module as usize == module)
        .collect();
    if of_module.is_empty() {
        return rtl::status::STATUS_RESOURCE_DATA_NOT_FOUND;
    }
    let of_type: std::vec::Vec<_> = of_module
        .into_iter()
        .filter(|found| matches(found.kind, &path[0]))
        .collect();
    if of_type.is_empty() {
        return rtl::status::STATUS_RESOURCE_TYPE_NOT_FOUND;
    }
    let named: std::vec::Vec<_> = of_type
        .into_iter()
        .filter(|found| matches(found.name, &path[1]))
        .collect();
    if named.is_empty() {
        return rtl::status::STATUS_RESOURCE_NAME_NOT_FOUND;
    }
    let (languages, count, any) = resource::languages(language as u16, Defaults::F2K);
    let found = languages[..count]
        .iter()
        .find_map(|&language| named.iter().find(|found| found.language == language))
        .or_else(|| any.then(|| named.first()).flatten());
    match found {
        Some(found) => {
            // SAFETY: the caller's place.
            unsafe { entry.write(core::ptr::from_ref::<ModelResource>(found) as usize) };
            0
        }
        None => rtl::status::STATUS_RESOURCE_LANG_NOT_FOUND,
    }
}

/// LdrAccessResource over the model: the data of the module's resource whose record `entry`
/// is, its address and size where asked; STATUS_RESOURCE_DATA_NOT_FOUND for any other entry.
pub unsafe extern "system" fn LdrAccessResource(
    module: usize,
    entry: usize,
    address: *mut usize,
    size: *mut u32,
) -> u32 {
    let Some(found) = RESOURCE_MODEL.iter().find(|found| {
        core::ptr::from_ref(*found) as usize == entry && found.module as usize == module
    }) else {
        return rtl::status::STATUS_RESOURCE_DATA_NOT_FOUND;
    };
    // SAFETY: the caller's places, when given.
    unsafe {
        if !address.is_null() {
            address.write(found.data.as_ptr() as usize);
        }
        if !size.is_null() {
            size.write(found.data.len() as u32);
        }
    }
    0
}
