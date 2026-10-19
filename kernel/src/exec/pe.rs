//! PE32 image parsing, export lookup and import resolution for the image loader.
//!
//! Pure logic over a byte slice, with no kernel state: [`Image::parse`] validates a PE32 image's
//! headers and section table — a program or a DLL, told apart by the file header's DLL flag —
//! [`Image::map_into`] builds the in-memory image under the eager mapping rule (headers verbatim,
//! then each section's raw bytes, zero-fill to the section extent), [`Image::exports`] reads the
//! export directory of a mapped image, and [`Image::snap_imports`] resolves the import directory
//! module by module through a caller-supplied resolver, writing addresses into the IAT slots.
//!
//! Every image maps at its own preferred base (no relocation machinery exists): the base must be a
//! 64 KiB multiple and the image must fit below the kernel window.
//!
//! Failure discipline: questions of identity ("is this an image we load?") come back as
//! [`Reject`]s, a header that would read past its bytes or a section whose raw data lies past the
//! file's end among them ([`Reject::Truncated`]: any file a program names is parsed); malformed
//! bytes past the parse (an export or import table reading out of the image), and violations of
//! the load contract, panic naming the violated contract. A run-to-completion program must
//! have at least one live import, so a snap that resolves nothing is a contract violation, not
//! a success.

/// The DOS-header magic ("MZ").
const DOS_MAGIC: u16 = 0x5A4D;

/// The NT-header signature ("PE\0\0").
const PE_SIGNATURE: u32 = 0x0000_4550;

/// The only machine type this loader accepts: i386.
const MACHINE_I386: u16 = 0x014C;

/// The only optional-header layout this loader accepts: PE32 (not PE32+).
const OPT_MAGIC_PE32: u16 = 0x010B;

/// The only subsystem this loader accepts for a program: console. A DLL's subsystem field is not
/// consulted (the system DLLs carry either value).
const SUBSYSTEM_CUI: u16 = 3;

/// The file-header characteristic that makes an image a DLL.
const FILE_DLL: u16 = 0x2000;

/// The granularity a preferred base must be a multiple of (the format's 64 KiB rule).
const IMAGE_BASE_ALIGNMENT: u32 = 0x1_0000;

/// The end of user space: an image must end at or below it.
pub const USER_SPACE_END: u32 = crate::mem::paging::KERNEL_BASE;

/// The largest image this loader will map.
pub const MAX_IMAGE_SIZE: u32 = 0x0100_0000;

/// The section-count cap.
const MAX_SECTIONS: usize = 96;

/// The data-directory array cap (the format's maximum).
const MAX_DIRECTORIES: usize = 16;

/// Data-directory indices the loader consumes.
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_IAT: usize = 12;

/// The high bit of a thunk marks an import by ordinal, not by name.
const ORDINAL_FLAG: u32 = 0x8000_0000;

/// Section-characteristic bits the loader maps to page protection.
const SCN_EXECUTE: u32 = 0x2000_0000;
const SCN_READ: u32 = 0x4000_0000;
const SCN_WRITE: u32 = 0x8000_0000;

// Header geometry: offsets and sizes within the file image.
const OFF_E_LFANEW: usize = 0x3C;
const SIZE_DOS_HEADER: usize = 0x40;
const SIZE_NT_SIGNATURE: usize = 4;
const SIZE_FILE_HEADER: usize = 20;
const SIZE_SECTION_HEADER: usize = 40;
/// The optional header's standard fields, before the directory array.
const SIZE_OPT_STANDARD: usize = 96;
const SIZE_DIRECTORY_ENTRY: usize = 8;
/// One import descriptor: five dwords, terminated by an all-zero one.
const SIZE_IMPORT_DESCRIPTOR: usize = 20;
/// The export directory's fixed part (its arrays and strings live elsewhere in the image).
const SIZE_EXPORT_DIRECTORY: usize = 40;

/// Why an image is not loadable. Identity questions only: bytes that merely do not describe a
/// loadable PE32 image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No DOS-header magic.
    NotDos,
    /// No PE signature at the NT-header offset.
    NotPe,
    /// Not an i386 image.
    WrongMachine,
    /// Not a PE32 (32-bit) optional header.
    NotPe32,
    /// More data directories than the format allows.
    TooManyDirectories,
    /// The optional header is too small to hold its directories.
    OptionalHeaderTooSmall,
    /// No sections.
    NoSections,
    /// More sections than the loader accepts.
    TooManySections,
    /// The section table does not fit inside the header region.
    TableOutsideHeaders,
    /// The header region does not fit inside the image.
    HeadersOutsideImage,
    /// The alignment bundle is violated.
    BadAlignment,
    /// SizeOfImage does not match the section layout.
    SizeOfImageMismatch,
    /// The preferred base is not a 64 KiB multiple (zero included).
    ImageBaseUnaligned,
    /// The image does not fit below the end of user space at its preferred base.
    ImageOutsideUserSpace,
    /// A program that is not a console image.
    WrongSubsystem,
    /// A program without an entry point (a DLL may have none).
    NoEntryPoint,
    /// A DLL where a program was asked for.
    NotAProgram,
    /// The entry point is not inside an executable section.
    EntryNotExecutable,
    /// Sections are not contiguous and ordered.
    SectionDiscontiguous,
    /// A section's raw data reaches past its mapped extent.
    RawBeyondExtent,
    /// A section occupies no address space.
    ZeroExtent,
    /// The image exceeds the loader's size cap.
    ImageTooLarge,
    /// A header, the section table or a section's raw data lies past the bytes (or the file).
    Truncated,
}

/// One data-directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    pub rva: u32,
    pub size: u32,
}

/// One section-table row, with the zero-raw-size fix applied (a section with no raw data has no
/// meaningful raw offset either).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
    pub characteristics: u32,
}

impl Section {
    /// The section name; an 8-byte name has no terminator, by format.
    #[cfg(test)]
    pub fn name_str(&self) -> &str {
        let len = self.name.iter().position(|&b| b == 0).unwrap_or(8);
        core::str::from_utf8(&self.name[..len]).unwrap_or_else(|_| {
            panic!("section name is not valid UTF-8");
        })
    }

    /// The size that counts for mapping: the virtual size, or the raw size when the virtual size is
    /// zero.
    fn effective_vsize(&self) -> u32 {
        if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        }
    }

    /// The section's footprint in the image, rounded up to the section alignment.
    fn extent(&self, section_alignment: u32) -> u32 {
        round_up(self.effective_vsize().max(self.raw_size), section_alignment)
    }

    /// How many raw bytes the mapping copies for this section: the raw data, capped at the
    /// rounded-up virtual size.
    fn copy_len(&self, section_alignment: u32) -> u32 {
        self.raw_size
            .min(round_up(self.effective_vsize(), section_alignment))
    }

    /// The (read, write, execute) protection this section maps with.
    pub fn protection(&self) -> (bool, bool, bool) {
        (
            self.characteristics & SCN_READ != 0,
            self.characteristics & SCN_WRITE != 0,
            self.characteristics & SCN_EXECUTE != 0,
        )
    }
}

/// A parsed PE32 image: the fields the loader needs, plus the section table. Borrows nothing:
/// everything is copied out at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image {
    pub entry_rva: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub subsystem: u16,
    /// The subsystem version the image was linked for (major, minor).
    pub subsystem_version: (u16, u16),
    /// The file header's characteristics (the DLL flag among them).
    pub characteristics: u16,
    /// The file header's TimeDateStamp (the loader's module lists record it).
    pub time_date_stamp: u32,
    directories: [DataDirectory; MAX_DIRECTORIES],
    num_directories: usize,
    sections: [Section; MAX_SECTIONS],
    num_sections: usize,
}

/// The outcome of an import snap: descriptors walked and IAT slots written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapResult {
    pub descriptors: usize,
    pub thunks: usize,
}

/// Why an import did not resolve: the resolver has no module by that name, or the module has no
/// such entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unresolved {
    NoModule,
    NoEntry,
}

/// What an export slot holds: an address in the exporting image (an RVA), or a forwarder — the
/// export lives in another module, named by a "MODULE.Name" or "MODULE.#ordinal" string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Export<'a> {
    Address(u32),
    Forwarder(&'a str),
}

/// A forwarder's target entry point: by name, or by ordinal ("MODULE.#ordinal").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardTarget<'a> {
    Name(&'a str),
    Ordinal(u32),
}

/// Split a forwarder string into its module and target. The module part is everything before the
/// first dot and carries no extension (".dll" is implied, see [`same_module`]); the target is
/// everything after it, dots included. `None` for a string without a dot or with an empty part —
/// malformed exports are the caller's to report.
pub fn split_forwarder(forwarder: &str) -> Option<(&str, ForwardTarget<'_>)> {
    let (module, entry) = forwarder.split_once('.')?;
    if module.is_empty() || entry.is_empty() {
        return None;
    }
    match entry.strip_prefix('#') {
        Some(digits) => Some((module, ForwardTarget::Ordinal(digits.parse().ok()?))),
        None => Some((module, ForwardTarget::Name(entry))),
    }
}

/// Whether two module names designate the same module: ASCII-case-insensitively, with a missing
/// extension standing for ".dll" (a forwarder names "NTDLL" for NTDLL.dll; an import descriptor
/// spells the extension out).
pub fn same_module(a: &str, b: &str) -> bool {
    // `full` spelled with an extension, `bare` without: equal when `full` is `bare` plus ".dll".
    fn implied_dll(full: &[u8], bare: &[u8]) -> bool {
        full.len() == bare.len() + 4
            && full[..bare.len()].eq_ignore_ascii_case(bare)
            && full[bare.len()..].eq_ignore_ascii_case(b".dll")
    }
    match (a.contains('.'), b.contains('.')) {
        (true, false) => implied_dll(a.as_bytes(), b.as_bytes()),
        (false, true) => implied_dll(b.as_bytes(), a.as_bytes()),
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// An image's export directory, as read from the mapped image: where its three arrays live and how
/// they are numbered. Lookups read the arrays from the same mapped bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exports {
    /// The directory's own range: a function RVA inside it is a forwarder string.
    directory_rva: u32,
    directory_size: u32,
    /// The ordinal of the address table's first slot.
    pub ordinal_base: u32,
    pub num_functions: u32,
    pub num_names: u32,
    functions_rva: u32,
    names_rva: u32,
    name_ordinals_rva: u32,
}

impl Exports {
    /// The export directory at `rva` (`size` bytes) of the mapped image `mapped`, its arrays checked
    /// to lie inside the image.
    fn read(mapped: &[u8], rva: u32, size: u32) -> Exports {
        let at = rva as usize;
        need(mapped, at, SIZE_EXPORT_DIRECTORY, "export directory");
        let exports = Exports {
            directory_rva: rva,
            directory_size: size,
            ordinal_base: read_u32(mapped, at + 16, "export directory"),
            num_functions: read_u32(mapped, at + 20, "export directory"),
            num_names: read_u32(mapped, at + 24, "export directory"),
            functions_rva: read_u32(mapped, at + 28, "export directory"),
            names_rva: read_u32(mapped, at + 32, "export directory"),
            name_ordinals_rva: read_u32(mapped, at + 36, "export directory"),
        };
        // The arrays must lie inside the image: every lookup indexes them.
        let array = |rva: u32, count: u32, width: usize, what: &str| {
            let len = (count as usize).checked_mul(width).unwrap_or_else(|| {
                panic!("{what} of {count} entries wraps");
            });
            need(mapped, rva as usize, len, what);
        };
        array(
            exports.functions_rva,
            exports.num_functions,
            4,
            "export address table",
        );
        array(exports.names_rva, exports.num_names, 4, "export name table");
        array(
            exports.name_ordinals_rva,
            exports.num_names,
            2,
            "export name-ordinal table",
        );
        exports
    }

    /// The export directory of a PE32 image `mapped` (a file whose offsets are its RVAs, or the
    /// mapped image), read straight from its headers, if it has one. For lookups on a small stack:
    /// a parsed [`Image`] takes several KiB, too much for a system service's gate stack. The image
    /// must be one [`Image::parse`] accepts (the system DLLs are, pinned by their tests).
    pub fn in_headers(mapped: &[u8]) -> Option<Exports> {
        let nt = read_u32(mapped, OFF_E_LFANEW, "e_lfanew") as usize;
        let opt = nt + SIZE_NT_SIGNATURE + SIZE_FILE_HEADER;
        let directories = read_u32(mapped, opt + SIZE_OPT_STANDARD - 4, "NumberOfRvaAndSizes");
        if directories as usize <= DIR_EXPORT {
            return None;
        }
        let entry = opt + SIZE_OPT_STANDARD + DIR_EXPORT * SIZE_DIRECTORY_ENTRY;
        let rva = read_u32(mapped, entry, "export directory entry");
        let size = read_u32(mapped, entry + 4, "export directory entry");
        (rva != 0).then(|| Exports::read(mapped, rva, size))
    }

    /// Every exported name, in the name table's order.
    #[cfg(test)]
    pub fn names<'a>(&self, mapped: &'a [u8]) -> impl Iterator<Item = &'a str> + 'a {
        let names_rva = self.names_rva as usize;
        (0..self.num_names as usize).map(move |index| {
            let name_rva = read_u32(mapped, names_rva + index * 4, "export name");
            read_cstr(mapped, name_rva as usize, "export name")
        })
    }

    /// The export with this name. Names compare exactly (export names are case-sensitive); the name
    /// table is walked in full, so its sort order is not relied on.
    pub fn by_name<'a>(&self, mapped: &'a [u8], name: &str) -> Option<Export<'a>> {
        for index in 0..self.num_names as usize {
            let name_rva = read_u32(mapped, self.names_rva as usize + index * 4, "export name");
            if read_cstr(mapped, name_rva as usize, "export name") == name {
                let slot = read_u16(
                    mapped,
                    self.name_ordinals_rva as usize + index * 2,
                    "export name ordinal",
                );
                // The name-ordinal table holds address-table indexes, not biased ordinals.
                assert!(
                    (slot as u32) < self.num_functions,
                    "export '{name}' names slot {slot} of a {}-slot address table",
                    self.num_functions
                );
                return self.slot(mapped, slot as u32);
            }
        }
        None
    }

    /// The export with this ordinal (biased by the directory's ordinal base).
    pub fn by_ordinal<'a>(&self, mapped: &'a [u8], ordinal: u32) -> Option<Export<'a>> {
        let slot = ordinal.checked_sub(self.ordinal_base)?;
        if slot >= self.num_functions {
            return None;
        }
        self.slot(mapped, slot)
    }

    /// Address-table slot `slot`: an unused slot (zero) exports nothing.
    fn slot<'a>(&self, mapped: &'a [u8], slot: u32) -> Option<Export<'a>> {
        let rva = read_u32(
            mapped,
            self.functions_rva as usize + slot as usize * 4,
            "export address",
        );
        if rva == 0 {
            return None;
        }
        if rva >= self.directory_rva && rva - self.directory_rva < self.directory_size {
            return Some(Export::Forwarder(read_cstr(
                mapped,
                rva as usize,
                "export forwarder",
            )));
        }
        assert!(
            rva < mapped.len() as u32,
            "export RVA 0x{rva:x} is outside the image 0x{:x}",
            mapped.len()
        );
        Some(Export::Address(rva))
    }
}

/// Bounds-check a read: `what` at `[off, off + len)` must fit inside `bytes`. Violations are
/// malformed-image bounds, so they panic naming what was being read.
fn need(bytes: &[u8], off: usize, len: usize, what: &str) {
    let end = off.checked_add(len).unwrap_or_else(|| {
        panic!("{what} at 0x{off:x} wraps");
    });
    assert!(
        end <= bytes.len(),
        "{what} at [0x{off:x}, 0x{end:x}) exceeds the buffer size 0x{:x}",
        bytes.len()
    );
}

fn read_u16(bytes: &[u8], off: usize, what: &str) -> u16 {
    need(bytes, off, 2, what);
    u16::from_le_bytes([bytes[off], bytes[off + 1]])
}

fn read_u32(bytes: &[u8], off: usize, what: &str) -> u32 {
    need(bytes, off, 4, what);
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

fn write_u32(bytes: &mut [u8], off: usize, value: u32, what: &str) {
    need(bytes, off, 4, what);
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// A NUL-terminated string at `off`. An unterminated string is malformed bytes, so it panics; so
/// does a non-UTF-8 one.
fn read_cstr<'a>(bytes: &'a [u8], off: usize, what: &str) -> &'a str {
    need(bytes, off, 1, what);
    let end = bytes[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or_else(|| panic!("{what} at 0x{off:x} is not NUL-terminated"));
    core::str::from_utf8(&bytes[off..off + end])
        .unwrap_or_else(|_| panic!("{what} is not valid UTF-8"))
}

/// Whether `[off, off + len)` lies inside `bytes`: a header range that does not is a truncated image.
fn fits(bytes: &[u8], off: usize, len: usize) -> Result<(), Reject> {
    match off.checked_add(len) {
        Some(end) if end <= bytes.len() => Ok(()),
        _ => Err(Reject::Truncated),
    }
}

/// Round `v` up to a multiple of `align` (which must be nonzero).
fn round_up(v: u32, align: u32) -> u32 {
    let bumped = v
        .checked_add(align - 1)
        .unwrap_or_else(|| panic!("0x{v:x} does not round up to 0x{align:x}"));
    (bumped / align) * align
}

impl Image {
    /// Parse and validate a PE32 executable.
    ///
    /// `Err` means the bytes are not an image this loader accepts, a truncated one included.
    pub fn parse(file: &[u8]) -> Result<Image, Reject> {
        Image::parse_headers(file, file.len())
    }

    /// Parse and validate a PE32 image from its first bytes, `headers` (the header region at
    /// least: the DOS and NT headers and the section table), the whole file being `file_len`
    /// bytes long: its sections' raw data must lie inside the file, not inside `headers`.
    pub fn parse_headers(headers: &[u8], file_len: usize) -> Result<Image, Reject> {
        let file = headers;
        // DOS header.
        fits(file, 0, SIZE_DOS_HEADER)?;
        if read_u16(file, 0, "DOS magic") != DOS_MAGIC {
            return Err(Reject::NotDos);
        }
        let nt = read_u32(file, OFF_E_LFANEW, "e_lfanew") as usize;
        fits(file, nt, SIZE_NT_SIGNATURE + SIZE_FILE_HEADER)?;
        if read_u32(file, nt, "PE signature") != PE_SIGNATURE {
            return Err(Reject::NotPe);
        }

        // File header.
        let machine = read_u16(file, nt + 4, "machine");
        let num_sections = read_u16(file, nt + 6, "section count") as usize;
        let size_optional = read_u16(file, nt + 20, "SizeOfOptionalHeader") as usize;
        let characteristics = read_u16(file, nt + 22, "Characteristics");
        let time_date_stamp = read_u32(file, nt + 8, "TimeDateStamp");
        let opt = nt + SIZE_NT_SIGNATURE + SIZE_FILE_HEADER;

        if machine != MACHINE_I386 {
            return Err(Reject::WrongMachine);
        }

        // Optional header.
        fits(file, opt, SIZE_OPT_STANDARD)?;
        let magic = read_u16(file, opt, "optional-header magic");
        if magic != OPT_MAGIC_PE32 {
            return Err(Reject::NotPe32);
        }
        let num_directories = read_u32(file, opt + 92, "NumberOfRvaAndSizes") as usize;
        if num_directories > MAX_DIRECTORIES {
            return Err(Reject::TooManyDirectories);
        }
        if SIZE_OPT_STANDARD + num_directories * SIZE_DIRECTORY_ENTRY > size_optional {
            return Err(Reject::OptionalHeaderTooSmall);
        }
        fits(file, opt, size_optional)?;

        let entry_rva = read_u32(file, opt + 16, "AddressOfEntryPoint");
        let image_base = read_u32(file, opt + 28, "ImageBase");
        let section_alignment = read_u32(file, opt + 32, "SectionAlignment");
        let file_alignment = read_u32(file, opt + 36, "FileAlignment");
        let size_of_image = read_u32(file, opt + 56, "SizeOfImage");
        let size_of_headers = read_u32(file, opt + 60, "SizeOfHeaders");
        let subsystem = read_u16(file, opt + 68, "Subsystem");
        let subsystem_version = (
            read_u16(file, opt + 48, "MajorSubsystemVersion"),
            read_u16(file, opt + 50, "MinorSubsystemVersion"),
        );

        let mut directories = [DataDirectory { rva: 0, size: 0 }; MAX_DIRECTORIES];
        for i in 0..num_directories {
            let at = opt + SIZE_OPT_STANDARD + i * SIZE_DIRECTORY_ENTRY;
            directories[i] = DataDirectory {
                rva: read_u32(file, at, "data directory"),
                size: read_u32(file, at + 4, "data directory"),
            };
        }

        // Identity contracts. A program must be a console image with an entry point; a DLL may be
        // either subsystem and may have no entry point (nothing to call at attach).
        let dll = characteristics & FILE_DLL != 0;
        if num_sections == 0 {
            return Err(Reject::NoSections);
        }
        if image_base == 0 || !image_base.is_multiple_of(IMAGE_BASE_ALIGNMENT) {
            return Err(Reject::ImageBaseUnaligned);
        }
        if !dll && subsystem != SUBSYSTEM_CUI {
            return Err(Reject::WrongSubsystem);
        }
        if !dll && entry_rva == 0 {
            return Err(Reject::NoEntryPoint);
        }
        if size_of_image > MAX_IMAGE_SIZE {
            return Err(Reject::ImageTooLarge);
        }
        if image_base
            .checked_add(size_of_image)
            .is_none_or(|end| end > USER_SPACE_END)
        {
            return Err(Reject::ImageOutsideUserSpace);
        }

        // The alignment bundle.
        if file_alignment == 0 {
            return Err(Reject::BadAlignment);
        }
        if file_alignment % 512 != 0 && file_alignment != section_alignment {
            return Err(Reject::BadAlignment);
        }
        if file_alignment & (file_alignment - 1) != 0 {
            return Err(Reject::BadAlignment);
        }
        if section_alignment < file_alignment {
            return Err(Reject::BadAlignment);
        }

        // Section table: it lives inside the header region, which lives inside the image.
        let table = opt + size_optional;
        fits(file, table, num_sections * SIZE_SECTION_HEADER)?;
        if num_sections > MAX_SECTIONS {
            return Err(Reject::TooManySections);
        }
        let table_end = table + num_sections * SIZE_SECTION_HEADER;
        if table_end > size_of_headers as usize {
            return Err(Reject::TableOutsideHeaders);
        }
        if size_of_headers >= size_of_image {
            return Err(Reject::HeadersOutsideImage);
        }
        if size_of_headers as usize > file_len {
            return Err(Reject::Truncated);
        }

        // Sections and their mapping plan.
        let mut sections = [Section {
            name: [0; 8],
            virtual_size: 0,
            virtual_address: 0,
            raw_size: 0,
            raw_offset: 0,
            characteristics: 0,
        }; MAX_SECTIONS];
        // The header region ends at the first section; sections must tile the image from there,
        // contiguously and in order.
        let mut running_va = round_up(size_of_headers, section_alignment) as u64;
        for i in 0..num_sections {
            let at = table + i * SIZE_SECTION_HEADER;
            let mut name = [0u8; 8];
            name.copy_from_slice(&file[at..at + 8]);
            let mut section = Section {
                name,
                virtual_size: read_u32(file, at + 8, "section header"),
                virtual_address: read_u32(file, at + 12, "section header"),
                raw_size: read_u32(file, at + 16, "section header"),
                raw_offset: read_u32(file, at + 20, "section header"),
                characteristics: read_u32(file, at + 36, "section header"),
            };
            // A section with no raw data has no meaningful raw offset.
            if section.raw_size == 0 {
                section.raw_offset = 0;
            }
            // The raw range must not wrap and must exist in the file.
            match section.raw_offset.checked_add(section.raw_size) {
                Some(end) if end as usize <= file_len => {}
                _ => return Err(Reject::Truncated),
            }
            let extent = section.extent(section_alignment);
            if extent == 0 {
                return Err(Reject::ZeroExtent);
            }
            if round_up(section.effective_vsize(), section_alignment) < section.raw_size {
                return Err(Reject::RawBeyondExtent);
            }
            if section.virtual_address as u64 != running_va {
                return Err(Reject::SectionDiscontiguous);
            }
            running_va += extent as u64;
            sections[i] = section;
        }

        // SizeOfImage is the rounded-up end of the last section.
        if size_of_image % section_alignment != 0 {
            return Err(Reject::SizeOfImageMismatch);
        }
        if running_va != size_of_image as u64 {
            return Err(Reject::SizeOfImageMismatch);
        }

        // The entry point, when there is one, must be inside an executable section.
        let entry_covered = entry_rva == 0
            || (0..num_sections).any(|i| {
                let s = &sections[i];
                entry_rva >= s.virtual_address
                    && entry_rva < s.virtual_address + s.extent(section_alignment)
                    && s.characteristics & SCN_EXECUTE != 0
            });
        if !entry_covered {
            return Err(Reject::EntryNotExecutable);
        }

        // An image without an import directory is legal: it imports nothing and must end by fault
        // (the fault-containment fixture) — the loader snaps zero imports.
        Ok(Image {
            entry_rva,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            subsystem,
            subsystem_version,
            characteristics,
            time_date_stamp,
            directories,
            num_directories,
            sections,
            num_sections,
        })
    }

    /// Parse an image that must be a program: a DLL is refused.
    pub fn parse_program(file: &[u8]) -> Result<Image, Reject> {
        let image = Image::parse(file)?;
        if image.is_dll() {
            return Err(Reject::NotAProgram);
        }
        Ok(image)
    }

    /// Whether the image is a DLL (the file header's DLL flag, not the subsystem, decides).
    pub fn is_dll(&self) -> bool {
        self.characteristics & FILE_DLL != 0
    }

    /// The export directory of the mapped image `mapped`, if the image has one. The kernel's own
    /// lookups read it from the headers alone ([`Exports::in_headers`]); the tests hold the two
    /// to agree.
    #[cfg(test)]
    pub fn exports(&self, mapped: &[u8]) -> Option<Exports> {
        let (rva, size) = self.directory(DIR_EXPORT)?;
        Some(Exports::read(mapped, rva, size))
    }

    pub fn section(&self, index: usize) -> &Section {
        &self.sections[index]
    }

    pub fn num_sections(&self) -> usize {
        self.num_sections
    }

    /// The section whose raw data backs `rva`, if any. The bound is the raw size: file-mode lookups
    /// can only find bytes that exist in the file.
    pub fn section_for_rva(&self, rva: u32) -> Option<usize> {
        (0..self.num_sections).find(|&i| {
            let s = &self.sections[i];
            rva >= s.virtual_address && rva < s.virtual_address + s.raw_size
        })
    }

    /// File-mode RVA to file offset: header-region RVAs resolve directly, others through the
    /// section table.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.size_of_headers {
            return Some(rva as usize);
        }
        let i = self.section_for_rva(rva)?;
        let s = &self.sections[i];
        Some((rva - s.virtual_address + s.raw_offset) as usize)
    }

    /// A data directory, if the image has it. A directory whose RVA points outside the image is
    /// malformed bytes, not an absent directory.
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        if index >= self.num_directories {
            return None;
        }
        let d = self.directories[index];
        if d.rva == 0 {
            return None;
        }
        assert!(
            d.rva < self.size_of_image,
            "directory {index} RVA 0x{:x} is outside the image 0x{:x}",
            d.rva,
            self.size_of_image
        );
        Some((d.rva, d.size))
    }

    /// The section's footprint in the image.
    pub fn section_extent(&self, index: usize) -> u32 {
        self.sections[index].extent(self.section_alignment)
    }

    /// How many raw bytes the mapping copies for the section.
    pub fn section_copy_len(&self, index: usize) -> u32 {
        self.sections[index].copy_len(self.section_alignment)
    }

    /// The entry point's virtual address.
    pub fn entry_va(&self) -> u32 {
        self.image_base + self.entry_rva
    }

    /// Build the in-memory image: headers verbatim, then each section's raw bytes, zero-filled to
    /// the section extent. `out` must be at least `size_of_image` bytes.
    pub fn map_into(&self, file: &[u8], out: &mut [u8]) {
        assert!(
            out.len() >= self.size_of_image as usize,
            "destination 0x{:x} is smaller than the image 0x{:x}",
            out.len(),
            self.size_of_image
        );
        assert!(
            self.size_of_headers as usize <= file.len(),
            "SizeOfHeaders 0x{:x} exceeds the file length 0x{:x}",
            self.size_of_headers,
            file.len()
        );
        let headers = self.size_of_headers as usize;
        out[..headers].copy_from_slice(&file[..headers]);
        for i in 0..self.num_sections {
            let s = &self.sections[i];
            let dst = s.virtual_address as usize;
            let copy_len = s.copy_len(self.section_alignment) as usize;
            if copy_len > 0 {
                need(file, s.raw_offset as usize, copy_len, "section raw data");
                need(out, dst, copy_len, "section mapping");
                out[dst..dst + copy_len].copy_from_slice(
                    &file[s.raw_offset as usize..s.raw_offset as usize + copy_len],
                );
            }
            let extent = s.extent(self.section_alignment) as usize;
            if extent > copy_len {
                need(out, dst + copy_len, extent - copy_len, "section mapping");
                out[dst + copy_len..dst + extent].fill(0);
            }
        }
    }

    /// One page of the in-memory image as [`Image::map_into`] builds it — the headers verbatim, each
    /// section's raw bytes, zeros elsewhere — the page at `page_rva` into `out` (one page), its
    /// bytes read from the file by `read` (a file offset and the bytes to fill there). False when a
    /// read fails. For a mapping made page by page, without the file or the image in memory.
    pub fn map_page(
        &self,
        page_rva: u32,
        out: &mut [u8],
        mut read: impl FnMut(u32, &mut [u8]) -> bool,
    ) -> bool {
        out.fill(0);
        let page_end = page_rva as u64 + out.len() as u64;
        // (RVA, bytes copied, file offset) for the headers, then each section.
        let pieces = core::iter::once((0, self.size_of_headers, 0)).chain(
            self.sections[..self.num_sections].iter().map(|s| {
                (s.virtual_address, s.copy_len(self.section_alignment), s.raw_offset)
            }),
        );
        for (rva, len, offset) in pieces {
            let start = (rva as u64).max(page_rva as u64);
            let end = (rva as u64 + len as u64).min(page_end);
            if start >= end {
                continue;
            }
            let into = &mut out[(start - page_rva as u64) as usize..(end - page_rva as u64) as usize];
            if !read(offset + (start - rva as u64) as u32, into) {
                return false;
            }
        }
        true
    }

    /// The IAT region: the IAT directory when the linker emitted one, else the whole raw extent of
    /// the section holding the import directory. Call only when an import directory exists (the
    /// zero-import image never reaches here).
    fn iat_region(&self) -> (u32, u32) {
        if let Some((rva, size)) = self.directory(DIR_IAT) {
            return (rva, size);
        }
        let (import_rva, _) = self
            .directory(DIR_IMPORT)
            .expect("the caller checked for an import directory");
        for i in 0..self.num_sections {
            let s = &self.sections[i];
            if import_rva >= s.virtual_address && import_rva < s.virtual_address + s.raw_size {
                let size = if s.virtual_size == 0 {
                    s.raw_size
                } else {
                    s.virtual_size
                };
                return (s.virtual_address, size);
            }
        }
        panic!("unable to locate the IAT region");
    }

    /// Read one import's name out of the file bytes. The name must live in file-backed bytes: the
    /// zero tail cannot hold names. The hint is read but never authoritative. Ordinal imports are not
    /// served: the resolver is name-keyed (the system DLLs' ordinals are not Windows 2000's yet).
    fn import_name<'a>(&self, file: &'a [u8], thunk: u32) -> &'a str {
        if thunk & ORDINAL_FLAG != 0 {
            panic!(
                "ordinal import 0x{:04x} against the kernel export table",
                thunk & 0xFFFF
            );
        }
        assert!(
            thunk < self.size_of_image,
            "import name RVA 0x{thunk:x} is outside the image 0x{:x}",
            self.size_of_image
        );
        let off = self.rva_to_offset(thunk).unwrap_or_else(|| {
            panic!("import name RVA 0x{thunk:x} is not backed by file data");
        });
        need(file, off, 2, "hint/name entry");
        let _hint = read_u16(file, off, "hint/name entry");
        read_cstr(file, off + 2, "import name")
    }

    /// A NUL-terminated string at `rva`, read out of the file bytes: it must lie inside the image
    /// and be file-backed.
    fn file_cstr<'a>(&self, file: &'a [u8], rva: u32, what: &str) -> &'a str {
        assert!(
            rva < self.size_of_image,
            "{what} RVA 0x{rva:x} is outside the image 0x{:x}",
            self.size_of_image
        );
        let off = self.rva_to_offset(rva).unwrap_or_else(|| {
            panic!("{what} RVA 0x{rva:x} is not backed by file data");
        });
        read_cstr(file, off, what)
    }

    /// Resolve the import directory: `resolve` maps a (module, entry point) pair — the module as the
    /// descriptor spells it — to the address the IAT slot receives. Each IAT slot is written; the
    /// original thunk array is left untouched, and whatever the IAT held before (lookup values, or
    /// addresses a bind step wrote against some other build of the module) is never trusted.
    /// Descriptor and thunk reads come from the mapped image (what the loader actually walks);
    /// module and entry-point names come from the file bytes (they must be file-backed).
    pub fn snap_imports(
        &self,
        file: &[u8],
        image: &mut [u8],
        mut resolve: impl FnMut(&str, &str) -> Result<u32, Unresolved>,
    ) -> SnapResult {
        let Some((import_rva, _)) = self.directory(DIR_IMPORT) else {
            // No import directory: nothing to snap (an importless program must end by fault).
            return SnapResult::default();
        };
        let (iat_base, iat_size) = self.iat_region();
        let mut result = SnapResult::default();
        let mut off = import_rva as usize;
        loop {
            need(image, off, SIZE_IMPORT_DESCRIPTOR, "import descriptor");
            let original_first_thunk = read_u32(image, off, "import descriptor");
            let name_rva = read_u32(image, off + 12, "import descriptor");
            let first_thunk = read_u32(image, off + 16, "import descriptor");
            // The all-zero descriptor ends the array.
            if name_rva == 0 || first_thunk == 0 {
                break;
            }
            result.descriptors += 1;
            let module = self.file_cstr(file, name_rva, "import module name");
            // An import with no live references is skipped.
            if read_u32(image, first_thunk as usize, "thunk slot") == 0 {
                off += SIZE_IMPORT_DESCRIPTOR;
                continue;
            }
            // A thunk array pointer that does not point inside the image is bogus; the first-thunk
            // array is walked in place instead.
            let lookup = if original_first_thunk < self.size_of_headers
                || original_first_thunk >= self.size_of_image
            {
                first_thunk
            } else {
                original_first_thunk
            };
            let mut lookup_off = lookup as usize;
            let mut slot_off = first_thunk as usize;
            loop {
                let thunk = read_u32(image, lookup_off, "thunk slot");
                // The zero slot ends the array.
                if thunk == 0 {
                    break;
                }
                let name = self.import_name(file, thunk);
                let address = match resolve(module, name) {
                    Ok(address) => address,
                    Err(Unresolved::NoModule) => panic!("import module '{module}' is not loaded"),
                    Err(Unresolved::NoEntry) => {
                        panic!("entry point '{name}' not found in {module}")
                    }
                };
                need(image, slot_off, 4, "IAT slot");
                write_u32(image, slot_off, address, "IAT slot");
                assert!(
                    slot_off >= iat_base as usize
                        && slot_off + 4 <= iat_base as usize + iat_size as usize,
                    "IAT slot at RVA 0x{slot_off:x} lies outside the IAT region [0x{iat_base:x}, 0x{:x})",
                    iat_base + iat_size
                );
                result.thunks += 1;
                lookup_off += 4;
                slot_off += 4;
            }
            off += SIZE_IMPORT_DESCRIPTOR;
        }
        // A run-to-completion program must resolve at least one import: its exit path. A DLL may
        // import nothing.
        assert!(
            result.thunks > 0 || self.is_dll(),
            "image has no live imports (run-to-completion contract)"
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT0: &[u8] = include_bytes!("../../../tests/exit0/exit0.exe");
    const RET0: &[u8] = include_bytes!("../../../tests/ret0/ret0.exe");

    // exit0: NT at 0xb8, optional header at 0xd0, section table at 0x1b0; ret0: NT at 0xc8,
    // optional header at 0xe0, section table at 0x1c0. Import surfaces: exit0 has one import
    // (KERNEL32.dll!ExitProcess, hint/name at 0x2038, IL at 0x2030, IAT at 0x2000, module name at
    // 0x2046); ret0 has 35 (IL at 0x441c, IAT at 0x4000, module name at 0x4708).

    /// The ret0 import order, as the linker emitted it.
    const RET0_IMPORTS: [&str; 35] = [
        "VirtualFree",
        "GetVersion",
        "ExitProcess",
        "TerminateProcess",
        "GetCurrentProcess",
        "UnhandledExceptionFilter",
        "GetModuleFileNameA",
        "FreeEnvironmentStringsA",
        "FreeEnvironmentStringsW",
        "WideCharToMultiByte",
        "GetEnvironmentStrings",
        "GetEnvironmentStringsW",
        "SetHandleCount",
        "GetStdHandle",
        "GetFileType",
        "GetStartupInfoA",
        "HeapDestroy",
        "HeapCreate",
        "GetCommandLineA",
        "HeapFree",
        "RtlUnwind",
        "WriteFile",
        "HeapAlloc",
        "GetCPInfo",
        "GetACP",
        "GetOEMCP",
        "VirtualAlloc",
        "HeapReAlloc",
        "GetProcAddress",
        "LoadLibraryA",
        "MultiByteToWideChar",
        "LCMapStringA",
        "LCMapStringW",
        "GetStringTypeA",
        "GetStringTypeW",
    ];

    fn r16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }

    fn r32(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
    }

    fn w16(b: &mut [u8], off: usize, v: u16) {
        b[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn w32(b: &mut [u8], off: usize, v: u32) {
        b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn patched(src: &[u8], f: impl FnOnce(&mut [u8])) -> Vec<u8> {
        let mut v = src.to_vec();
        f(&mut v);
        v
    }

    // Header offsets, computed the way the parser computes them.
    fn off_nt(b: &[u8]) -> usize {
        r32(b, 0x3c) as usize
    }
    fn off_opt(b: &[u8]) -> usize {
        off_nt(b) + 24
    }
    fn off_table(b: &[u8]) -> usize {
        off_nt(b) + 4 + 20 + r16(b, off_nt(b) + 20) as usize
    }
    fn off_dir(b: &[u8], i: usize) -> usize {
        off_opt(b) + 96 + 8 * i
    }
    fn off_sec(b: &[u8], i: usize) -> usize {
        off_table(b) + 40 * i
    }

    // Section-header field offsets.
    const S_NAME: usize = 0;
    const S_VSIZE: usize = 8;
    const S_VADDR: usize = 12;
    const S_RAWSIZE: usize = 16;
    const S_RAWOFF: usize = 20;
    const S_CHARS: usize = 36;

    fn parse_ok(file: &[u8]) -> Image {
        Image::parse(file).expect("fixture parses")
    }

    /// Map a fixture (or a mutated copy) and snap its imports against `table`, recording every name
    /// the resolver saw.
    fn snap(file: &[u8], table: &[(&str, u32)]) -> (Image, Vec<u8>, SnapResult, Vec<String>) {
        let image = parse_ok(file);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let mut seen: Vec<String> = Vec::new();
        let result = image.snap_imports(file, &mut mapped, |module: &str, name: &str| {
            if !same_module(module, "KERNEL32.dll") {
                return Err(Unresolved::NoModule);
            }
            seen.push(name.to_string());
            table
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, a)| *a)
                .ok_or(Unresolved::NoEntry)
        });
        (image, mapped, result, seen)
    }

    fn snap_default(file: &[u8]) -> (Image, Vec<u8>, SnapResult, Vec<String>) {
        // A full kernel32 stand-in covering both fixtures; the ret0 list contains ExitProcess
        // (index 2).
        let table: Vec<(&str, u32)> = RET0_IMPORTS
            .iter()
            .enumerate()
            .map(|(i, n)| (*n, 0x5000_0000 + i as u32))
            .collect();
        snap(file, &table)
    }

    // ---- header identity ----

    #[test]
    fn fixtures_parse_with_expected_headers() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.entry_rva, 0x1000);
        assert_eq!(e.image_base, 0x400000);
        assert_eq!(e.section_alignment, 0x1000);
        assert_eq!(e.file_alignment, 0x1000);
        assert_eq!(e.size_of_image, 0x3000);
        assert_eq!(e.size_of_headers, 0x1000);
        assert_eq!(e.subsystem, 3);
        assert_eq!(e.subsystem_version, (4, 0), "MSVC 6's link default");
        assert_eq!(e.num_sections(), 2);
        assert_eq!(e.entry_va(), 0x401000);

        let r = parse_ok(RET0);
        assert_eq!(r.entry_rva, 0x1007);
        assert_eq!(r.image_base, 0x400000);
        assert_eq!(r.section_alignment, 0x1000);
        assert_eq!(r.file_alignment, 0x1000);
        assert_eq!(r.size_of_image, 0x6000);
        assert_eq!(r.size_of_headers, 0x1000);
        assert_eq!(r.subsystem, 3);
        assert_eq!(r.num_sections(), 3);
        assert_eq!(r.entry_va(), 0x401007);
    }

    #[test]
    fn dos_magic_rejects() {
        for src in [EXIT0, RET0] {
            let bad = patched(src, |b| b[0] = 0x4e);
            assert_eq!(Image::parse(&bad), Err(Reject::NotDos));
        }
    }

    #[test]
    fn lfanew_straddling_eof_is_truncated() {
        let bad = patched(EXIT0, |b| w32(b, 0x3c, (b.len() - 1) as u32));
        assert_eq!(Image::parse(&bad), Err(Reject::Truncated));
    }

    #[test]
    fn lfanew_wrapping_is_truncated() {
        let bad = patched(EXIT0, |b| w32(b, 0x3c, 0xffff_fff0));
        assert_eq!(Image::parse(&bad), Err(Reject::Truncated));
    }

    #[test]
    fn lfanew_without_signature_rejects() {
        // 0x100 is inside the file but in the DOS stub: the offset is readable, the content is not
        // a PE signature. A clean reject, not a bounds panic.
        let bad = patched(EXIT0, |b| w32(b, 0x3c, 0x100));
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe));
    }

    #[test]
    fn pe_signature_rejects() {
        let bad = patched(EXIT0, |b| b[off_nt(b) + 3] = 1);
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe));
    }

    #[test]
    fn non_i386_machine_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 4, 0x8664));
        assert_eq!(Image::parse(&bad), Err(Reject::WrongMachine));
    }

    #[test]
    fn pe32plus_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_opt(b), 0x20b));
        assert_eq!(Image::parse(&bad), Err(Reject::NotPe32));
    }

    #[test]
    fn section_table_offset_is_honored() {
        // The table follows SizeOfOptionalHeader, not a fixed offset: exit0 0x1b0, ret0 0x1c0, each
        // starting with ".text".
        let e = parse_ok(EXIT0);
        assert_eq!(e.section(0).name_str(), ".text");
        assert_eq!(off_table(EXIT0), 0x1b0);
        let r = parse_ok(RET0);
        assert_eq!(r.section(0).name_str(), ".text");
        assert_eq!(off_table(RET0), 0x1c0);
    }

    #[test]
    fn no_sections_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 0));
        assert_eq!(Image::parse(&bad), Err(Reject::NoSections));
    }

    #[test]
    fn section_table_beyond_file_is_truncated() {
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 0x200));
        assert_eq!(Image::parse(&bad), Err(Reject::Truncated));
    }

    #[test]
    fn section_table_outside_headers_rejects() {
        // 96 sections still fit the file, but not the header region.
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 6, 96));
        assert_eq!(Image::parse(&bad), Err(Reject::TableOutsideHeaders));
    }

    #[test]
    fn optional_header_too_small_rejects() {
        // 0xd8 cannot hold the standard fields plus 16 directories.
        let bad = patched(EXIT0, |b| w16(b, off_nt(b) + 20, 0xd8));
        assert_eq!(Image::parse(&bad), Err(Reject::OptionalHeaderTooSmall));
    }

    // ---- optional-header contracts ----

    #[test]
    fn zero_entry_point_rejects() {
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 16, 0));
        assert_eq!(Image::parse(&bad), Err(Reject::NoEntryPoint));
    }

    #[test]
    fn entry_point_outside_image_rejects() {
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 16, 0x3000));
        assert_eq!(Image::parse(&bad), Err(Reject::EntryNotExecutable));
    }

    #[test]
    fn the_preferred_base_is_the_mapping_base() {
        // cmd.exe's preferred base: a program linked anywhere in user space parses there.
        let moved = patched(EXIT0, |b| w32(b, off_opt(b) + 28, 0x4AD0_0000));
        let image = parse_ok(&moved);
        assert_eq!(image.image_base, 0x4AD0_0000);
        assert_eq!(image.entry_va(), 0x4AD0_1000);
    }

    #[test]
    fn unaligned_image_base_rejects() {
        for base in [0, 0x0040_1000, 0x0040_8000] {
            let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 28, base));
            assert_eq!(
                Image::parse(&bad),
                Err(Reject::ImageBaseUnaligned),
                "{base:#x}"
            );
        }
    }

    #[test]
    fn image_past_user_space_rejects() {
        // exit0 spans 0x3000 bytes: at 0x7FFF0000 it still fits, one unit higher it reaches into
        // the kernel window, and near the top of the address space its end wraps.
        let fits = patched(EXIT0, |b| w32(b, off_opt(b) + 28, 0x7FFF_0000));
        assert_eq!(parse_ok(&fits).image_base, 0x7FFF_0000);
        for base in [USER_SPACE_END, 0xFFFF_0000] {
            let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 28, base));
            assert_eq!(
                Image::parse(&bad),
                Err(Reject::ImageOutsideUserSpace),
                "{base:#x}"
            );
        }
    }

    #[test]
    fn bad_alignment_bundle_rejects() {
        let not_pow2 = patched(EXIT0, |b| w32(b, off_opt(b) + 36, 0x801));
        assert_eq!(Image::parse(&not_pow2), Err(Reject::BadAlignment));
        let zero = patched(EXIT0, |b| w32(b, off_opt(b) + 36, 0));
        assert_eq!(Image::parse(&zero), Err(Reject::BadAlignment));
        let small = patched(EXIT0, |b| w32(b, off_opt(b) + 32, 0x200));
        assert_eq!(Image::parse(&small), Err(Reject::BadAlignment));
    }

    #[test]
    fn size_of_image_mismatch_rejects() {
        let shrunk = patched(EXIT0, |b| w32(b, off_opt(b) + 56, 0x2000));
        assert_eq!(Image::parse(&shrunk), Err(Reject::SizeOfImageMismatch));
        let unaligned = patched(EXIT0, |b| w32(b, off_opt(b) + 56, 0x3001));
        assert_eq!(Image::parse(&unaligned), Err(Reject::SizeOfImageMismatch));
    }

    #[test]
    fn headers_region_contract_rejects() {
        let small = patched(EXIT0, |b| w32(b, off_opt(b) + 60, 0x100));
        assert_eq!(Image::parse(&small), Err(Reject::TableOutsideHeaders));
        let huge = patched(EXIT0, |b| w32(b, off_opt(b) + 60, 0x3000));
        assert_eq!(Image::parse(&huge), Err(Reject::HeadersOutsideImage));
    }

    #[test]
    fn non_console_subsystem_rejects() {
        let bad = patched(EXIT0, |b| w16(b, off_opt(b) + 68, 5));
        assert_eq!(Image::parse(&bad), Err(Reject::WrongSubsystem));
    }

    // ---- program or DLL ----

    /// `src` with the file header's DLL flag set.
    fn as_dll(src: &[u8]) -> Vec<u8> {
        patched(src, |b| {
            let at = off_nt(b) + 22;
            w16(b, at, r16(b, at) | FILE_DLL);
        })
    }

    #[test]
    fn the_fixtures_are_programs() {
        for src in [EXIT0, RET0] {
            let image = Image::parse_program(src).expect("fixture parses as a program");
            assert!(!image.is_dll());
            assert_eq!(image.characteristics & FILE_DLL, 0);
        }
    }

    #[test]
    fn the_dll_flag_makes_a_dll() {
        let dll = as_dll(EXIT0);
        assert!(parse_ok(&dll).is_dll());
        assert_eq!(Image::parse_program(&dll), Err(Reject::NotAProgram));
    }

    #[test]
    fn a_dll_carries_either_subsystem() {
        // The subsystem field does not tell a DLL apart: GUI-subsystem DLLs exist (msvcrt.dll).
        for subsystem in [2, 3] {
            let dll = patched(&as_dll(EXIT0), |b| w16(b, off_opt(b) + 68, subsystem));
            assert!(parse_ok(&dll).is_dll(), "subsystem {subsystem}");
        }
    }

    #[test]
    fn a_dll_may_have_no_entry_point() {
        let dll = patched(&as_dll(EXIT0), |b| w32(b, off_opt(b) + 16, 0));
        assert_eq!(parse_ok(&dll).entry_rva, 0);
        // A DLL's entry point, when it has one, is held to the executable-section rule.
        let outside = patched(&as_dll(EXIT0), |b| w32(b, off_opt(b) + 16, 0x2000));
        assert_eq!(Image::parse(&outside), Err(Reject::EntryNotExecutable));
    }

    // ---- section table and mapping plan ----

    #[test]
    fn section_fields_parse() {
        let e = parse_ok(EXIT0);
        let text = e.section(0);
        assert_eq!(text.name_str(), ".text");
        assert_eq!(text.virtual_size, 0xd);
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.raw_size, 0x1000);
        assert_eq!(text.raw_offset, 0x1000);
        assert_eq!(text.characteristics, 0x6000_0020);
        let rdata = e.section(1);
        assert_eq!(rdata.name_str(), ".rdata");
        assert_eq!(rdata.virtual_size, 0x54);
        assert_eq!(rdata.virtual_address, 0x2000);
        assert_eq!(rdata.raw_size, 0x1000);
        assert_eq!(rdata.raw_offset, 0x2000);
        assert_eq!(rdata.characteristics, 0x4000_0040);

        let r = parse_ok(RET0);
        let text = r.section(0);
        assert_eq!(text.name_str(), ".text");
        assert_eq!(text.virtual_size, 0x27ce);
        assert_eq!(text.virtual_address, 0x1000);
        assert_eq!(text.raw_size, 0x3000);
        assert_eq!(text.raw_offset, 0x1000);
        assert_eq!(text.characteristics, 0x6000_0020);
        let rdata = r.section(1);
        assert_eq!(rdata.name_str(), ".rdata");
        assert_eq!(rdata.virtual_size, 0x716);
        assert_eq!(rdata.virtual_address, 0x4000);
        assert_eq!(rdata.raw_size, 0x1000);
        assert_eq!(rdata.raw_offset, 0x4000);
        assert_eq!(rdata.characteristics, 0x4000_0040);
        let data = r.section(2);
        assert_eq!(data.name_str(), ".data");
        assert_eq!(data.virtual_size, 0x79c);
        assert_eq!(data.virtual_address, 0x5000);
        assert_eq!(data.raw_size, 0x1000);
        assert_eq!(data.raw_offset, 0x5000);
        assert_eq!(data.characteristics, 0xc000_0040);
    }

    #[test]
    fn eight_byte_section_name_has_no_terminator() {
        let bad = patched(EXIT0, |b| {
            let at = off_sec(b, 0) + S_NAME;
            b[at..at + 8].copy_from_slice(b"longtext");
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section(0).name_str(), "longtext");
    }

    #[test]
    fn section_extents_and_copy_lengths() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section_extent(0), 0x1000);
        assert_eq!(e.section_copy_len(0), 0x1000);
        assert_eq!(e.section_extent(1), 0x1000);
        assert_eq!(e.section_copy_len(1), 0x1000);

        let r = parse_ok(RET0);
        assert_eq!(r.section_extent(0), 0x3000);
        assert_eq!(r.section_copy_len(0), 0x3000);
        assert_eq!(r.section_extent(1), 0x1000);
        assert_eq!(r.section_copy_len(1), 0x1000);
        assert_eq!(r.section_extent(2), 0x1000);
        assert_eq!(r.section_copy_len(2), 0x1000);
    }

    #[test]
    fn zero_only_section_maps_zeroes() {
        // .rdata loses its raw data: the mapping plan shows a full zero extent. The import surface
        // then has no file-backed bytes, which the snap enforces.
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 1) + S_RAWSIZE, 0));
        let image = parse_ok(&bad);
        assert_eq!(image.section_copy_len(1), 0);
        assert_eq!(image.section_extent(1), 0x1000);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert!(mapped[0x2000..0x3000].iter().all(|&b| b == 0));
    }

    #[test]
    fn tail_bytes_between_vsize_and_raw_come_from_the_file() {
        let e = parse_ok(EXIT0);
        let mut mapped = vec![0u8; e.size_of_image as usize];
        e.map_into(EXIT0, &mut mapped);
        // .text holds 0xd live bytes; the rest of the page is the file's own padding, mapped as-is.
        assert_eq!(&mapped[0x1000..0x100d], &EXIT0[0x1000..0x100d]);
        assert_eq!(&mapped[0x100d..0x2000], &EXIT0[0x100d..0x2000]);
    }

    #[test]
    fn zero_tail_when_vsize_exceeds_raw() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section_extent(1), 0x2000);
        assert_eq!(image.section_copy_len(1), 0x1000);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert_eq!(&mapped[0x2000..0x3000], &EXIT0[0x2000..0x3000]);
        assert!(mapped[0x3000..0x4000].iter().all(|&b| b == 0));
    }

    #[test]
    fn zero_vsize_maps_the_raw_size() {
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 0) + S_VSIZE, 0));
        let image = parse_ok(&bad);
        assert_eq!(image.section_extent(0), 0x1000);
        assert_eq!(image.section_copy_len(0), 0x1000);
    }

    #[test]
    fn section_order_swap_rejects() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 0) + S_VADDR, 0x2000);
            w32(b, off_sec(b, 1) + S_VADDR, 0x1000);
        });
        assert_eq!(Image::parse(&bad), Err(Reject::SectionDiscontiguous));
    }

    /// Page by page, the image is the one `map_into` builds (the corpus, and a DLL); a read that
    /// fails fails the page.
    #[test]
    fn pages_map_as_the_whole_image_does() {
        const PAGE: usize = 0x1000;
        for src in [EXIT0, RET0, &as_dll(EXIT0)[..]] {
            let image = parse_ok(src);
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(src, &mut mapped);
            let mut page = vec![0xAAu8; PAGE];
            for (index, expected) in mapped.chunks(PAGE).enumerate() {
                let read = |offset: u32, out: &mut [u8]| {
                    out.copy_from_slice(&src[offset as usize..offset as usize + out.len()]);
                    true
                };
                assert!(image.map_page((index * PAGE) as u32, &mut page, read));
                assert_eq!(&page[..], expected, "page {index}");
            }
            assert!(!image.map_page(0, &mut page, |_, _| false), "a failed read fails the page");
        }
    }

    /// The parse from the headers alone, given the file's length: the same image; a file shorter
    /// than its headers or its sections' raw data is truncated.
    #[test]
    fn the_headers_parse_alone() {
        for src in [EXIT0, RET0] {
            assert_eq!(Image::parse_headers(&src[..0x1000], src.len()), Image::parse(src));
            assert_eq!(Image::parse_headers(&src[..0x1000], 0xFFF), Err(Reject::Truncated));
        }
        // exit0's last section's raw data ends the file.
        assert_eq!(Image::parse_headers(&EXIT0[..0x1000], EXIT0.len() - 1), Err(Reject::Truncated));
    }

    #[test]
    fn headers_map_verbatim() {
        for src in [EXIT0, RET0] {
            let image = parse_ok(src);
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(src, &mut mapped);
            assert_eq!(&mapped[..0x1000], &src[..0x1000]);
        }
    }

    #[test]
    fn raw_range_wrap_is_truncated() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 0) + S_RAWOFF, 0xffff_f000);
        });
        assert_eq!(Image::parse(&bad), Err(Reject::Truncated));
    }

    #[test]
    fn raw_data_past_eof_is_truncated() {
        let bad = patched(EXIT0, |b| w32(b, off_sec(b, 1) + S_RAWSIZE, 0x2000));
        assert_eq!(Image::parse(&bad), Err(Reject::Truncated));
    }

    #[test]
    fn raw_data_beyond_extent_rejects() {
        let bad = patched(RET0, |b| w32(b, off_sec(b, 0) + S_VSIZE, 0x2000));
        assert_eq!(Image::parse(&bad), Err(Reject::RawBeyondExtent));
    }

    #[test]
    fn protections_follow_characteristics() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section(0).protection(), (true, false, true));
        assert_eq!(e.section(1).protection(), (true, false, false));
        let r = parse_ok(RET0);
        assert_eq!(r.section(2).protection(), (true, true, false));
    }

    #[test]
    fn discardable_bit_does_not_change_the_plan() {
        let bad = patched(EXIT0, |b| {
            let chars = r32(b, off_sec(b, 0) + S_CHARS);
            w32(b, off_sec(b, 0) + S_CHARS, chars | 0x0200_0000);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.section_copy_len(0), 0x1000);
    }

    // ---- RVA mapping ----

    #[test]
    fn section_lookup_by_rva() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.section_for_rva(0x1000), Some(0));
        assert_eq!(e.section_for_rva(0x2008), Some(1));
        assert_eq!(e.section_for_rva(0x2030), Some(1));
        assert_eq!(e.section_for_rva(0x2fff), Some(1));
        assert_eq!(e.section_for_rva(0x3000), None);

        let r = parse_ok(RET0);
        assert_eq!(r.section_for_rva(0x1007), Some(0));
        assert_eq!(r.section_for_rva(0x43f4), Some(1));
        assert_eq!(r.section_for_rva(0x441c), Some(1));
        assert_eq!(r.section_for_rva(0x4000), Some(1));
        assert_eq!(r.section_for_rva(0x5000), Some(2));
        assert_eq!(r.section_for_rva(0x6000), None);
        assert_eq!(r.section_for_rva(0x5fff), Some(2));
    }

    #[test]
    fn header_region_rvas_resolve_directly() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x100), Some(0x100));
        // 0xfff is below the first section: no section backs it, but the header region resolves it
        // directly.
        assert_eq!(e.section_for_rva(0xfff), None);
        assert_eq!(e.rva_to_offset(0xfff), Some(0xfff));
    }

    #[test]
    fn section_rvas_resolve_through_the_table() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x2008), Some(0x2008));
        assert_eq!(e.rva_to_offset(0x2038), Some(0x2038));
        let r = parse_ok(RET0);
        assert_eq!(r.rva_to_offset(0x441c), Some(0x441c));
        assert_eq!(r.rva_to_offset(0x4708), Some(0x4708));
    }

    #[test]
    fn raw_tail_rva_resolves_file_mode() {
        // 0x100d is past .text's virtual size but inside its raw data: the file-mode bound is the
        // raw size.
        let e = parse_ok(EXIT0);
        assert_eq!(e.rva_to_offset(0x100d), Some(0x100d));
    }

    #[test]
    fn zero_tail_rva_has_no_file_backing() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
        });
        let image = parse_ok(&bad);
        // 0x3000 is inside the section extent but past the raw data: valid zero memory in the
        // image, no file backing.
        assert_eq!(image.section_for_rva(0x3000), None);
        assert_eq!(image.rva_to_offset(0x3000), None);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        assert!(mapped[0x3000..0x4000].iter().all(|&b| b == 0));
    }

    // ---- data directories ----

    #[test]
    fn directories_parse() {
        let e = parse_ok(EXIT0);
        assert_eq!(e.directory(DIR_IMPORT), Some((0x2008, 0x28)));
        assert_eq!(e.directory(DIR_IAT), Some((0x2000, 8)));
        assert_eq!(e.directory(DIR_BASERELOC), None);
        let r = parse_ok(RET0);
        assert_eq!(r.directory(DIR_IMPORT), Some((0x43f4, 0x28)));
        assert_eq!(r.directory(DIR_IAT), Some((0x4000, 0x90)));
        assert_eq!(r.directory(DIR_BASERELOC), None);
    }

    #[test]
    fn fixtures_have_no_reloc_section() {
        for src in [EXIT0, RET0] {
            let image = parse_ok(src);
            for i in 0..image.num_sections() {
                assert_ne!(image.section(i).name_str(), ".reloc");
            }
        }
    }

    #[test]
    fn directory_count_bounds_lookups() {
        // Twelve directories: the IAT slot (index 12) reads as absent even though its bytes are
        // still in the file.
        let bad = patched(EXIT0, |b| w32(b, off_opt(b) + 92, 12));
        let image = parse_ok(&bad);
        assert_eq!(image.directory(DIR_IAT), None);
        assert_eq!(image.directory(DIR_IMPORT), Some((0x2008, 0x28)));
    }

    #[test]
    fn absent_import_directory_snaps_zero_imports() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0));
        let image = parse_ok(&bad);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(&bad, &mut mapped);
        // Nothing to snap: the image imports nothing and must end by fault.
        assert_eq!(
            image.snap_imports(&bad, &mut mapped, |_, _| Err(Unresolved::NoModule)),
            SnapResult::default()
        );
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn import_directory_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x5000));
        let image = parse_ok(&bad);
        let _ = image.directory(DIR_IMPORT);
    }

    #[test]
    fn header_region_directory_resolves_directly() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x200));
        let image = parse_ok(&bad);
        assert_eq!(image.directory(DIR_IMPORT), Some((0x200, 0x28)));
        assert_eq!(image.rva_to_offset(0x200), Some(0x200));
    }

    #[test]
    fn unconsumed_directories_are_enumerated_but_not_interpreted() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_dir(b, 10), 0x2100);
            w32(b, off_dir(b, 10) + 4, 0x40);
        });
        let image = parse_ok(&bad);
        assert_eq!(image.directory(10), Some((0x2100, 0x40)));
    }

    // ---- import walk and IAT snap ----

    #[test]
    fn exit0_snaps_its_single_import() {
        let (image, mapped, result, seen) = snap_default(EXIT0);
        assert_eq!(result.descriptors, 1);
        assert_eq!(result.thunks, 1);
        assert_eq!(seen, vec!["ExitProcess"]);
        // ExitProcess sits at index 2 of the stand-in table.
        assert_eq!(r32(&mapped, 0x2000), 0x5000_0002);
        // The terminator slot stays zero.
        assert_eq!(r32(&mapped, 0x2004), 0);
        assert_eq!(image.directory(DIR_IAT), Some((0x2000, 8)));
    }

    #[test]
    fn ret0_snaps_its_crt_startup_surface() {
        let (image, mapped, result, seen) = snap_default(RET0);
        assert_eq!(result.descriptors, 1);
        assert_eq!(result.thunks, 35);
        assert_eq!(seen.len(), 35);
        for (i, name) in RET0_IMPORTS.iter().enumerate() {
            assert_eq!(seen[i], *name);
            assert_eq!(r32(&mapped, 0x4000 + 4 * i), 0x5000_0000 + i as u32);
        }
        // The terminator slot stays zero.
        assert_eq!(r32(&mapped, 0x4000 + 4 * 35), 0);
        assert_eq!(image.directory(DIR_IAT), Some((0x4000, 0x90)));
    }

    #[test]
    fn lookup_array_is_preserved_by_the_snap() {
        for (src, il_rva, count) in [(EXIT0, 0x2030usize, 1usize), (RET0, 0x441c, 35)] {
            let (_, mapped, _, _) = snap_default(src);
            for i in 0..=count {
                let original = r32(src, il_rva + 4 * i);
                assert_eq!(r32(&mapped, il_rva + 4 * i), original);
            }
        }
    }

    #[test]
    fn iat_holds_lookup_values_before_the_snap() {
        let image = parse_ok(EXIT0);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(EXIT0, &mut mapped);
        assert_eq!(r32(&mapped, 0x2000), 0x2038);
        assert_eq!(r32(&mapped, 0x2030), 0x2038);
    }

    #[test]
    fn bogus_lookup_pointer_falls_back_to_the_iat() {
        for oft in [0u32, 0x3000] {
            let bad = patched(EXIT0, |b| w32(b, 0x2008, oft));
            let (_, _, result, seen) = snap(&bad, &[("ExitProcess", 0x5000_1000)]);
            assert_eq!(result.thunks, 1);
            assert_eq!(seen, vec!["ExitProcess"]);
        }
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn terminator_slot_is_not_assumed() {
        // The walk stops at the zero slot, not at a count: a nonzero value where the terminator
        // should be is walked as an import and fails on the bogus name.
        let bad = patched(EXIT0, |b| w32(b, 0x2034, 0x0000_beef));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "ordinal import 0x2038")]
    fn ordinal_import_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2030, 0x8000_2038));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "no live imports")]
    fn import_with_no_references_has_no_live_thunks() {
        let bad = patched(EXIT0, |b| w32(b, 0x2000, 0));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "no live imports")]
    fn lookup_pointer_into_padding_yields_no_imports() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008, 0x2ff0));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn lookup_pointer_at_image_end_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008, 0x2ffd));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "import module name RVA 0x5000 is outside the image")]
    fn module_name_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2008 + 12, 0x5000));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "not NUL-terminated")]
    fn unterminated_module_name_panics() {
        // Point the module name at a tail with no NUL before the image ends.
        let bad = patched(EXIT0, |b| {
            w32(b, 0x2008 + 12, 0x2ff8);
            b[0x2ff8..0x3000].fill(0xaa);
        });
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "exceeds the buffer size")]
    fn descriptor_at_image_end_panics() {
        let bad = patched(EXIT0, |b| w32(b, off_dir(b, DIR_IMPORT), 0x2ff8));
        let _ = snap_default(&bad);
    }

    #[test]
    fn hint_is_never_authoritative() {
        let wrong_hint = patched(EXIT0, |b| w16(b, 0x2038, 1));
        let (_, _, result, _) = snap(&wrong_hint, &[("ExitProcess", 0x5000_1000)]);
        assert_eq!(result.thunks, 1);
    }

    #[test]
    #[should_panic(expected = "not found in KERNEL32.dll")]
    fn renamed_export_misses() {
        let renamed = patched(EXIT0, |b| {
            b[0x203a..0x203a + 4].copy_from_slice(b"XitP");
        });
        let _ = snap_default(&renamed);
    }

    #[test]
    #[should_panic(expected = "not found in KERNEL32.dll")]
    fn missing_export_panics() {
        let _ = snap(EXIT0, &[("SomethingElse", 1)]);
    }

    #[test]
    #[should_panic(expected = "import module 'USER32.dll' is not loaded")]
    fn foreign_module_panics() {
        let bad = patched(EXIT0, |b| {
            b[0x2046..0x2046 + 11].copy_from_slice(b"USER32.dll\0");
        });
        let _ = snap_default(&bad);
    }

    #[test]
    fn the_resolver_sees_the_module_as_spelled() {
        let image = parse_ok(EXIT0);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(EXIT0, &mut mapped);
        let mut asked: Vec<(String, String)> = Vec::new();
        image.snap_imports(EXIT0, &mut mapped, |module, name| {
            asked.push((module.to_string(), name.to_string()));
            Ok(0x5000_1000)
        });
        assert_eq!(
            asked,
            vec![("KERNEL32.dll".to_string(), "ExitProcess".to_string())]
        );
    }

    #[test]
    fn bound_iat_values_are_overwritten() {
        // A bind step pre-fills the IAT with addresses inside some build of the module and stamps
        // the descriptor's time-date field: the snap still resolves by name from the lookup array
        // and overwrites the slot.
        let bound = patched(EXIT0, |b| {
            w32(b, 0x2000, 0x7C4E_1234);
            w32(b, 0x2008 + 4, 0xFFFF_FFFF);
        });
        let (_, mapped, result, seen) = snap(&bound, &[("ExitProcess", 0x5000_1000)]);
        assert_eq!(result.thunks, 1);
        assert_eq!(seen, vec!["ExitProcess"]);
        assert_eq!(r32(&mapped, 0x2000), 0x5000_1000);
    }

    #[test]
    fn a_dll_may_import_nothing() {
        let bad = patched(EXIT0, |b| {
            w32(b, 0x2000, 0);
            let at = off_nt(b) + 22;
            w16(b, at, r16(b, at) | FILE_DLL);
        });
        let (_, _, result, _) = snap_default(&bad);
        assert_eq!(result.thunks, 0);
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn import_name_outside_image_panics() {
        let bad = patched(EXIT0, |b| w32(b, 0x2030, 0x9000));
        let _ = snap_default(&bad);
    }

    #[test]
    #[should_panic(expected = "not backed by file data")]
    fn import_name_in_the_zero_tail_panics() {
        let bad = patched(EXIT0, |b| {
            w32(b, off_sec(b, 1) + S_VSIZE, 0x2000);
            w32(b, off_opt(b) + 56, 0x4000);
            w32(b, 0x2030, 0x3000);
        });
        let _ = snap_default(&bad);
    }

    // ---- exports ----
    //
    // No DLL fixture exists yet: the export directory is synthesized into exit0's .rdata padding
    // (0x2100.., past the import surface's last byte at 0x2054), flagged as a DLL.

    /// One address-table slot of a synthesized export directory.
    #[derive(Clone, Copy)]
    enum Slot<'a> {
        Code(u32),
        Unused,
        Forward(&'a str),
    }

    /// Where the synthesized directory and its pieces live.
    const EXPORT_DIR: usize = 0x2100;
    const EXPORT_FUNCTIONS: usize = 0x2140;
    const EXPORT_NAMES: usize = 0x2200;
    const EXPORT_ORDINALS: usize = 0x2280;
    const EXPORT_STRINGS: usize = 0x2300;
    /// Forwarder strings must lie inside the directory's range: the range covers them.
    const EXPORT_FORWARDERS: usize = 0x2400;
    const EXPORT_DIR_SIZE: u32 = 0x400;

    /// exit0 as a DLL exporting `slots` from ordinal `base`, with `names` naming address-table
    /// slots. Names are written in the order given (a real linker sorts them).
    fn with_exports(base: u32, slots: &[Slot], names: &[(&str, u16)]) -> Vec<u8> {
        /// Write `s` NUL-terminated at `*at`, advance past it, and return its RVA.
        fn put_str(b: &mut [u8], at: &mut usize, s: &str) -> u32 {
            let rva = *at as u32;
            b[*at..*at + s.len()].copy_from_slice(s.as_bytes());
            b[*at + s.len()] = 0;
            *at += s.len() + 1;
            rva
        }
        patched(&as_dll(EXIT0), |b| {
            w32(b, off_dir(b, DIR_EXPORT), EXPORT_DIR as u32);
            w32(b, off_dir(b, DIR_EXPORT) + 4, EXPORT_DIR_SIZE);
            let mut strings = EXPORT_STRINGS;
            let module = put_str(b, &mut strings, "SYNTH.dll");
            w32(b, EXPORT_DIR + 12, module);
            w32(b, EXPORT_DIR + 16, base);
            w32(b, EXPORT_DIR + 20, slots.len() as u32);
            w32(b, EXPORT_DIR + 24, names.len() as u32);
            w32(b, EXPORT_DIR + 28, EXPORT_FUNCTIONS as u32);
            w32(b, EXPORT_DIR + 32, EXPORT_NAMES as u32);
            w32(b, EXPORT_DIR + 36, EXPORT_ORDINALS as u32);
            let mut forwarders = EXPORT_FORWARDERS;
            for (i, slot) in slots.iter().enumerate() {
                let value = match *slot {
                    Slot::Code(rva) => rva,
                    Slot::Unused => 0,
                    Slot::Forward(target) => put_str(b, &mut forwarders, target),
                };
                w32(b, EXPORT_FUNCTIONS + 4 * i, value);
            }
            for (i, (name, slot)) in names.iter().enumerate() {
                let rva = put_str(b, &mut strings, name);
                w32(b, EXPORT_NAMES + 4 * i, rva);
                w16(b, EXPORT_ORDINALS + 2 * i, *slot);
            }
        })
    }

    /// Map `file` and read its export directory.
    fn exports_of(file: &[u8]) -> (Vec<u8>, Exports) {
        let image = parse_ok(file);
        let mut mapped = vec![0u8; image.size_of_image as usize];
        image.map_into(file, &mut mapped);
        let exports = image.exports(&mapped).expect("export directory present");
        assert_eq!(
            Exports::in_headers(&mapped),
            Some(exports),
            "the headers' reading agrees"
        );
        (mapped, exports)
    }

    /// A small export surface: ordinals 5..=8, slot 2 unused, slot 3 forwarded, one slot exported
    /// by ordinal only.
    fn synth() -> Vec<u8> {
        with_exports(
            5,
            &[
                Slot::Code(0x1000),
                Slot::Code(0x1008),
                Slot::Unused,
                Slot::Forward("NTDLL.RtlAllocateHeap"),
            ],
            &[("Alpha", 0), ("Forwarded", 3), ("Gamma", 1)],
        )
    }

    #[test]
    fn the_fixtures_export_nothing() {
        for src in [EXIT0, RET0] {
            let image = parse_ok(src);
            let mut mapped = vec![0u8; image.size_of_image as usize];
            image.map_into(src, &mut mapped);
            assert_eq!(image.exports(&mapped), None);
            assert_eq!(Exports::in_headers(&mapped), None);
        }
    }

    #[test]
    fn export_directory_fields_parse() {
        let (_, exports) = exports_of(&synth());
        assert_eq!(exports.ordinal_base, 5);
        assert_eq!(exports.num_functions, 4);
        assert_eq!(exports.num_names, 3);
    }

    #[test]
    fn exports_resolve_by_name() {
        let (mapped, exports) = exports_of(&synth());
        assert_eq!(
            exports.by_name(&mapped, "Alpha"),
            Some(Export::Address(0x1000))
        );
        assert_eq!(
            exports.by_name(&mapped, "Gamma"),
            Some(Export::Address(0x1008))
        );
        // Export names are case-sensitive, and a missing name is no export.
        assert_eq!(exports.by_name(&mapped, "alpha"), None);
        assert_eq!(exports.by_name(&mapped, "Delta"), None);
    }

    #[test]
    fn exports_resolve_by_ordinal() {
        let (mapped, exports) = exports_of(&synth());
        assert_eq!(
            exports.by_ordinal(&mapped, 5),
            Some(Export::Address(0x1000))
        );
        assert_eq!(
            exports.by_ordinal(&mapped, 6),
            Some(Export::Address(0x1008))
        );
        // The unused slot exports nothing; ordinals outside [base, base + count) are no exports.
        assert_eq!(exports.by_ordinal(&mapped, 7), None);
        assert_eq!(exports.by_ordinal(&mapped, 4), None);
        assert_eq!(exports.by_ordinal(&mapped, 9), None);
    }

    #[test]
    fn a_slot_inside_the_directory_is_a_forwarder() {
        let (mapped, exports) = exports_of(&synth());
        let forwarded = Some(Export::Forwarder("NTDLL.RtlAllocateHeap"));
        assert_eq!(exports.by_name(&mapped, "Forwarded"), forwarded);
        assert_eq!(exports.by_ordinal(&mapped, 8), forwarded);
    }

    #[test]
    fn the_name_table_order_is_not_relied_on() {
        let unsorted = with_exports(
            1,
            &[Slot::Code(0x1000), Slot::Code(0x1004)],
            &[("Zulu", 0), ("Alpha", 1)],
        );
        let (mapped, exports) = exports_of(&unsorted);
        assert_eq!(
            exports.by_name(&mapped, "Alpha"),
            Some(Export::Address(0x1004))
        );
        assert_eq!(
            exports.by_name(&mapped, "Zulu"),
            Some(Export::Address(0x1000))
        );
    }

    #[test]
    #[should_panic(expected = "names slot 4 of a 4-slot address table")]
    fn a_name_past_the_address_table_panics() {
        let bad = with_exports(5, &[Slot::Code(0x1000); 4], &[("Alpha", 4)]);
        let (mapped, exports) = exports_of(&bad);
        let _ = exports.by_name(&mapped, "Alpha");
    }

    #[test]
    #[should_panic(expected = "export address table")]
    fn an_address_table_past_the_image_panics() {
        let bad = patched(&synth(), |b| w32(b, EXPORT_DIR + 20, 0x1000));
        let _ = exports_of(&bad);
    }

    #[test]
    #[should_panic(expected = "outside the image")]
    fn an_export_rva_past_the_image_panics() {
        let bad = with_exports(1, &[Slot::Code(0x9000)], &[("Far", 0)]);
        let (mapped, exports) = exports_of(&bad);
        let _ = exports.by_name(&mapped, "Far");
    }

    #[test]
    fn forwarders_split_into_module_and_target() {
        assert_eq!(
            split_forwarder("NTDLL.RtlAllocateHeap"),
            Some(("NTDLL", ForwardTarget::Name("RtlAllocateHeap")))
        );
        assert_eq!(
            split_forwarder("NTDLL.#12"),
            Some(("NTDLL", ForwardTarget::Ordinal(12)))
        );
        // The first dot splits: everything after it is the entry, dots and all.
        assert_eq!(
            split_forwarder("API.MS.Entry"),
            Some(("API", ForwardTarget::Name("MS.Entry")))
        );
        assert_eq!(
            split_forwarder("NTDLL.#12.x"),
            None,
            "an ordinal target is digits alone"
        );
        for bad in ["NTDLL", ".Entry", "NTDLL.", "NTDLL.#", "NTDLL.#x1"] {
            assert_eq!(split_forwarder(bad), None, "{bad}");
        }
    }

    #[test]
    fn module_names_match_with_an_implied_dll_extension() {
        assert!(same_module("KERNEL32.dll", "kernel32.DLL"));
        assert!(same_module("NTDLL", "ntdll.dll"));
        assert!(same_module("ntdll.dll", "NTDLL"));
        assert!(same_module("NTDLL", "ntdll"));
        assert!(!same_module("NTDLL", "NTDLL.EXE"));
        assert!(!same_module("KERNEL32.dll", "KERNEL.dll"));
        assert!(!same_module("KERNEL", "KERNEL32.dll"));
    }

    // ---- malformed files ----

    #[test]
    fn file_cut_to_headers_is_truncated() {
        assert_eq!(Image::parse(&EXIT0[..0x1000]), Err(Reject::Truncated));
    }

    #[test]
    fn file_cut_to_dos_header_is_truncated() {
        assert_eq!(Image::parse(&EXIT0[..0x40]), Err(Reject::Truncated));
    }

    #[test]
    fn file_missing_last_raw_byte_is_truncated() {
        assert_eq!(Image::parse(&EXIT0[..EXIT0.len() - 1]), Err(Reject::Truncated));
    }

    #[test]
    fn cross_field_contract_holds_on_fixtures() {
        for src in [EXIT0, RET0] {
            let (image, _, result, _) = snap_default(src);
            // The IAT directory covers every slot the walk writes, terminator included.
            let (iat_rva, iat_size) = image.directory(DIR_IAT).unwrap();
            let ft = r32(src, image.directory(DIR_IMPORT).unwrap().0 as usize + 16);
            assert!(ft >= iat_rva);
            assert!(ft + (result.thunks as u32 + 1) * 4 <= iat_rva + iat_size);
            // The entry point lies inside the executable section.
            assert_eq!(image.section(0).name_str(), ".text");
            assert!(image.entry_rva >= image.section(0).virtual_address);
            assert!(image.entry_rva < image.section(0).virtual_address + image.section_extent(0));
        }
    }
}
