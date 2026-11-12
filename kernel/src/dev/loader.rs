//! The kernel-side `.sys` loader, in minimal form: map a PE32 kernel module into the reserved
//! [`layout::MODULES`] region, apply its base relocations, resolve its imports against the
//! kernel's own export surface (ntoskrnl.exe's export directory, built from `kernel/exports.toml`,
//! and the HAL's kept table, from `kernel/hal_exports.toml`), and call its `DriverEntry`.
//!
//! The pure core runs over bytes and seams, host-tested against a synthetic PE image:
//! [`load_staged`] parses the image as a kernel module ([`Image::parse_kernel_module`]), stages
//! the in-memory image into a buffer ([`Image::map_into`]), applies the base relocations
//! ([`apply_relocations`]) for the move from the preferred base to the chosen one, and snaps the
//! import directory ([`snap_imports`]) through a caller-supplied resolver, writing the resolved
//! addresses into the IAT slots of the staged image.
//!
//! On target the `target` module does the mapping: it reserves a run of the modules region, stages
//! the image in a pool block, then maps the staged pages frame by frame into the region's shared
//! tables, so the module is reachable from every address space. Its resolver is
//! [`resolve_import`]: hal.dll by name through the generated HAL table, ntoskrnl.exe by name or
//! ordinal through the kernel image's own export directory (forwarders followed, depth-limited).
//! It then creates the module's [`DriverObject`], calls the entry point, and registers the driver
//! in the global table on success.
//!
//! Recorded seams: nothing calls the loader at boot yet (the first image is the FAT32 driver's,
//! loaded as a boot module); the registry path passed to `DriverEntry` is null; modules are never
//! unloaded; an image linked /FIXED (no relocation directory) can only load at its preferred
//! base.

// The target half is not wired into the boot yet (the first .sys image comes with the FAT32
// driver slice), so the target build sees no caller for it.
#![cfg_attr(not(test), allow(dead_code))]

use crate::exec::pe::{Image, Reject, Unresolved};
use rtl::image::{data_directory, DIRECTORY_BASERELOC, DIRECTORY_IMPORT};

/// The image's data directory `index`, when the image has one and it lies inside the image: a
/// directory pointing outside is malformed bytes, treated as absent (the callers' walks are
/// bounded by the image anyway).
fn directory(image: &Image, index: usize) -> Option<(u32, u32)> {
    let d = data_directory(image.nt_headers(), index)?;
    if d.size == 0
        || d.virtual_address >= image.size_of_image()
        || u64::from(d.virtual_address) + u64::from(d.size) > u64::from(image.size_of_image())
    {
        return None;
    }
    Some((d.virtual_address, d.size))
}

// --- The load's errors -----------------------------------------------------------------------

/// Why a `.sys` image did not load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    /// The bytes are not a kernel module this loader accepts.
    NotAnImage(Reject),
    /// A directory or entry read outside the staged image: malformed bytes past the parse.
    Malformed,
    /// The image moves from its preferred base but carries no relocation directory (linked
    /// /FIXED).
    NoRelocations,
    /// A relocation entry of a type this loader does not apply.
    UnsupportedRelocation(u16),
    /// The resolver had no module by the descriptor's name, or no such entry point.
    Unresolved,
    /// The modules region has no free run for the image (target).
    OutOfRegion,
    /// The frame database ran out mid-mapping (target).
    OutOfFrames,
    /// The global driver table is full (target).
    DriverTableFull,
    /// DriverEntry returned a failure status (target).
    DriverEntry(crate::status::NtStatus),
}

// --- One import's name -----------------------------------------------------------------------

/// An import's entry point as the thunk spells it: by name, or by ordinal (the thunk's high bit
/// set, the low 16 bits the ordinal, biased by the module's ordinal base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportName<'a> {
    Name(&'a str),
    Ordinal(u32),
}

// --- Base relocations ------------------------------------------------------------------------

/// The relocation entry types: 0 is padding, 3 (HIGHLOW) adds the delta to the dword at the
/// entry's address.
const RELOC_ABSOLUTE: u16 = 0;
const RELOC_HIGHLOW: u16 = 3;

/// Apply the image's base relocations in `staged` (the in-memory image [`Image::map_into` built,
/// so RVAs are offsets into it) for its move from the preferred base to `base`. A zero delta
/// changes nothing; a nonzero delta with no relocation directory is [`LoadError::NoRelocations`].
pub fn apply_relocations(image: &Image, staged: &mut [u8], base: u32) -> Result<(), LoadError> {
    let delta = base.wrapping_sub(image.image_base());
    if delta == 0 {
        return Ok(());
    }
    let Some((rva, size)) = directory(image, DIRECTORY_BASERELOC) else {
        return Err(LoadError::NoRelocations);
    };
    if size == 0 {
        return Err(LoadError::NoRelocations);
    }
    let end = rva as usize + size as usize;
    if end > staged.len() {
        return Err(LoadError::Malformed);
    }
    let mut off = rva as usize;
    while off + 8 <= end {
        let page_rva = read_u32(staged, off).ok_or(LoadError::Malformed)?;
        let block_size = read_u32(staged, off + 4).ok_or(LoadError::Malformed)? as usize;
        // A zero block ends the directory (the linker pads the directory's tail with them).
        if block_size == 0 {
            break;
        }
        if block_size < 8 || off + block_size > end {
            return Err(LoadError::Malformed);
        }
        let mut entry_off = off + 8;
        while entry_off + 2 <= off + block_size {
            let entry = read_u16(staged, entry_off).ok_or(LoadError::Malformed)?;
            match entry >> 12 {
                RELOC_ABSOLUTE => {}
                RELOC_HIGHLOW => {
                    let at = (page_rva + u32::from(entry & 0xFFF)) as usize;
                    let slot = read_u32(staged, at).ok_or(LoadError::Malformed)?;
                    write_u32(staged, at, slot.wrapping_add(delta));
                }
                other => return Err(LoadError::UnsupportedRelocation(other)),
            }
            entry_off += 2;
        }
        off += block_size;
    }
    Ok(())
}

// --- Import resolution -----------------------------------------------------------------------

/// The import snap's outcome: descriptors walked, thunks resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snap {
    pub descriptors: usize,
    pub thunks: usize,
}

/// Resolve the staged image's import directory: walk the descriptors in `staged`, resolve each
/// (module, entry) through `resolve` — the module as the descriptor spells it, the entry as
/// [`ImportName`] — and write the address into the IAT slot. The names come from `staged` (the
/// module is fully staged by then). An unresolved (module, entry) fails the load with
/// [`LoadError::Unresolved`]. An image with no import directory snaps nothing.
pub fn snap_imports(
    image: &Image,
    staged: &mut [u8],
    mut resolve: impl FnMut(&str, ImportName) -> Result<u32, Unresolved>,
) -> Result<Snap, LoadError> {
    let Some((import_rva, _)) = directory(image, DIRECTORY_IMPORT) else {
        return Ok(Snap::default());
    };
    let mut result = Snap::default();
    let mut off = import_rva as usize;
    loop {
        if off + 20 > staged.len() {
            return Err(LoadError::Malformed);
        }
        let original_first_thunk = read_u32(staged, off).ok_or(LoadError::Malformed)?;
        let name_rva = read_u32(staged, off + 12).ok_or(LoadError::Malformed)?;
        let first_thunk = read_u32(staged, off + 16).ok_or(LoadError::Malformed)?;
        // The all-zero descriptor ends the array.
        if name_rva == 0 || first_thunk == 0 {
            break;
        }
        off += 20;
        result.descriptors += 1;
        let module_off = name_rva as usize;
        // The lookup array: the original thunk when the descriptor carries one, else the IAT
        // itself (the linker's bound image reads it from either).
        let lookup = if original_first_thunk == 0 {
            first_thunk
        } else {
            original_first_thunk
        };
        let mut lookup_off = lookup as usize;
        let mut slot_off = first_thunk as usize;
        loop {
            let thunk = read_u32(staged, lookup_off).ok_or(LoadError::Malformed)?;
            if thunk == 0 {
                break;
            }
            let name = if thunk & 0x8000_0000 != 0 {
                ImportName::Ordinal(thunk & 0xFFFF)
            } else {
                // The hint word precedes the name and is never authoritative.
                ImportName::Name(cstr(staged, thunk as usize + 2).ok_or(LoadError::Malformed)?)
            };
            // Read fresh per thunk so the borrow ends at the resolve, before the IAT write.
            let module = cstr(staged, module_off).ok_or(LoadError::Malformed)?;
            let address = resolve(module, name).map_err(|_| LoadError::Unresolved)?;
            write_u32(staged, slot_off, address);
            result.thunks += 1;
            lookup_off += 4;
            slot_off += 4;
        }
    }
    Ok(result)
}

// --- The staged load -------------------------------------------------------------------------

/// A module staged into a buffer: where it will map, its size, its entry point's address, and
/// the import snap's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedModule {
    pub base: u32,
    pub size: u32,
    pub entry_va: u32,
    pub snap: Snap,
}

/// The load over a staging buffer: parse as a kernel module, stage the in-memory image into
/// `staged` (which must hold `size_of_image`), relocate to `base`, snap the imports through
/// `resolve`. Mapping the staged pages into kernel space is the target half's job.
pub fn load_staged(
    file: &[u8],
    base: u32,
    staged: &mut [u8],
    resolve: impl FnMut(&str, ImportName) -> Result<u32, Unresolved>,
) -> Result<StagedModule, LoadError> {
    let image = Image::parse_kernel_module(file).map_err(LoadError::NotAnImage)?;
    if staged.len() < image.size_of_image() as usize {
        return Err(LoadError::NotAnImage(Reject::Truncated));
    }
    image.map_into(file, staged).map_err(LoadError::NotAnImage)?;
    apply_relocations(&image, staged, base)?;
    let snap = snap_imports(&image, staged, resolve)?;
    Ok(StagedModule {
        base,
        size: image.size_of_image(),
        entry_va: base + image.entry_rva(),
        snap,
    })
}

// --- Small byte readers (the staged image is the whole address space of the walk) -------------

/// The `u32` at `off` in `bytes`, if it lies inside them.
fn read_u32(bytes: &[u8], off: usize) -> Option<u32> {
    bytes
        .get(off..off + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

/// The `u16` at `off`.
fn read_u16(bytes: &[u8], off: usize) -> Option<u16> {
    bytes
        .get(off..off + 2)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

/// Write `value` as the `u32` at `off`.
fn write_u32(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// The NUL-terminated string at `off`, if there is one.
fn cstr(bytes: &[u8], off: usize) -> Option<&str> {
    let tail = bytes.get(off..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    core::str::from_utf8(&tail[..end]).ok()
}

// --- On target: map into the modules region, resolve against the kernel's surfaces -----------

// Nothing calls the target half at boot yet, so its re-exports read as unused there.
#[cfg(target_arch = "x86")]
#[cfg_attr(not(test), allow(unused_imports))]
pub use target::*;

#[cfg(target_arch = "x86")]
mod target {
    use super::*;
    use crate::dev::{self, DriverObject, MatchSpec};
    use crate::exec::pe;
    use crate::hal::exports as hal_exports;
    use crate::level::{self, High, LevelCell};
    use crate::mem::{dma, layout, paging, pool};
    use crate::status::NtStatus;

    /// A loaded driver: its image's record and the driver object its DriverEntry filled in.
    pub struct LoadedDriver {
        pub base: u32,
        pub size: u32,
        pub entry_va: u32,
        pub driver: &'static DriverObject,
        pub driver_id: dev::DriverId,
    }

    /// The modules region's page allocator, at the high level like the DMA state's. Mapping the
    /// pages runs outside this lock (each step takes the memory manager's database).
    static REGION: LevelCell<High, dma::MmioMappings> =
        LevelCell::new(dma::MmioMappings::new(layout::MODULES));

    /// The kernel image's own export directory, read from its mapped image: ntoskrnl.exe imports
    /// resolve through it (`kernel/exports.toml` is what the image's export directory is built
    /// from). Returns the directory and the mapped bytes its lookups read.
    fn kernel_exports() -> Option<(pe::Exports, &'static [u8])> {
        let base = layout::NTOSKRNL_BASE as usize;
        let end = layout::KERNEL_IMAGE.end() as usize;
        // SAFETY: the kernel image window maps physical [0, 16 MiB) at KERNEL_BASE on, and the
        // kernel's image sits at NTOSKRNL_BASE within it, so the slice covers the whole image.
        let mapped = unsafe { core::slice::from_raw_parts(base as *const u8, end - base) };
        pe::exports_of_mapped(mapped).map(|exports| (exports, mapped))
    }

    /// Resolve one import of a loaded module: hal.dll by name through the generated HAL table
    /// (`kernel/hal_exports.toml`), ntoskrnl.exe by name or ordinal through the kernel image's
    /// export directory, forwarders followed (depth-limited). Anything else is no module.
    pub fn resolve_import(module: &str, name: ImportName) -> Result<u32, Unresolved> {
        resolve_import_depth(module, name, 0)
    }

    fn resolve_import_depth(
        module: &str,
        name: ImportName,
        depth: u32,
    ) -> Result<u32, Unresolved> {
        if depth > 4 {
            return Err(Unresolved::NoEntry);
        }
        if pe::same_module(module, "hal.dll") {
            let ImportName::Name(name) = name else {
                return Err(Unresolved::NoEntry);
            };
            return hal_exports::export_address(name)
                .map(|address| address as u32)
                .ok_or(Unresolved::NoEntry);
        }
        if pe::same_module(module, "ntoskrnl.exe") {
            let (exports, mapped) = kernel_exports().ok_or(Unresolved::NoModule)?;
            let export = match name {
                ImportName::Name(name) => exports.by_name(mapped, name),
                ImportName::Ordinal(ordinal) => exports.by_ordinal(mapped, ordinal),
            };
            return match export {
                Some(pe::Export::Address(rva)) => Ok(layout::NTOSKRNL_BASE + rva),
                Some(pe::Export::Forwarder(forwarder)) => {
                    let (target_module, target) =
                        pe::split_forwarder(forwarder).ok_or(Unresolved::NoEntry)?;
                    let target_name = match target {
                        pe::ForwardTarget::Name(name) => ImportName::Name(name),
                        pe::ForwardTarget::Ordinal(ordinal) => ImportName::Ordinal(ordinal),
                    };
                    resolve_import_depth(target_module, target_name, depth + 1)
                }
                None => Err(Unresolved::NoEntry),
            };
        }
        Err(Unresolved::NoModule)
    }

    /// Load a `.sys` image into the modules region and call its DriverEntry: reserve a run of the
    /// region, stage the image in a pool block (parse, map, relocate, snap against
    /// [`resolve_import`]), map the staged pages frame by frame into the region's shared tables,
    /// then enter at the image's entry point with a fresh driver object and register it on
    /// success. The registry path is null (a recorded seam).
    pub fn load_driver_image(file: &[u8], name: &'static str) -> Result<LoadedDriver, LoadError> {
        let image = Image::parse_kernel_module(file).map_err(LoadError::NotAnImage)?;
        let size = image.size_of_image() as usize;
        let pages = size.div_ceil(paging::PAGE_SIZE as usize);

        // Reserve the run first: the base the relocations target is the run's start.
        let first = level::raised::<High, _>(|high| REGION.get(high).reserve_pages(pages))
            .ok_or(LoadError::OutOfRegion)?;
        let base = layout::MODULES.start + first as u32 * paging::PAGE_SIZE;

        // Stage the image in a pool block, relocated to the base and with its imports snapped.
        let mut staging = pool::allocate(size).ok_or(LoadError::OutOfFrames)?;
        let module = match load_staged(file, base, staging.as_mut(), resolve_import) {
            Ok(module) => module,
            Err(error) => {
                level::raised::<High, _>(|high| REGION.get(high).unreserve_pages(first, pages));
                return Err(error);
            }
        };

        // Map the staged pages frame by frame into the region's shared tables.
        let mut mapped = 0usize;
        let mut map_error = None;
        for page in 0..pages {
            match map_staged_page(staging.as_ref(), base, page) {
                Ok(()) => mapped += 1,
                Err(error) => {
                    map_error = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = map_error {
            for page in 0..mapped {
                let frame = paging::unmap_kernel_page(base + page as u32 * paging::PAGE_SIZE);
                paging::release_frame_phys(frame);
            }
            level::raised::<High, _>(|high| REGION.get(high).unreserve_pages(first, pages));
            return Err(error);
        }
        drop(staging);

        // The module's driver object: a pool block the driver keeps for the system's lifetime.
        let mut object_block = pool::allocate(core::mem::size_of::<DriverObject>())
            .ok_or(LoadError::OutOfFrames)?;
        let driver: &'static mut DriverObject = {
            let bytes = object_block.as_mut();
            assert!(bytes.len() >= core::mem::size_of::<DriverObject>());
            let slot = bytes.as_mut_ptr().cast::<DriverObject>();
            // SAFETY: the block is page-aligned (so aligned for a DriverObject) and holds at
            // least its size, checked above; the block is forgotten below, so the reference is
            // the object's only owner for the rest of the run.
            unsafe {
                slot.write(DriverObject::new(
                    name,
                    [None; dev::irp::IRP_MJ_MAX],
                    None,
                    MatchSpec::any(),
                ));
                &mut *slot
            }
        };
        core::mem::forget(object_block);

        // DriverEntry(DriverObject, RegistryPath): enter at the image's entry point. The
        // registry path is null (a recorded seam).
        let entry: extern "stdcall" fn(*mut DriverObject, *const core::ffi::c_void) -> i32 =
            // SAFETY: the entry point is the image's AddressOfEntryPoint, mapped at
            // module.entry_va; its signature is the documented DriverEntry's.
            unsafe { core::mem::transmute(module.entry_va) };
        let status = NtStatus(entry(driver, core::ptr::null()) as u32);
        if !status.is_success() {
            return Err(LoadError::DriverEntry(status));
        }
        let driver_id = dev::register_driver(&*driver).ok_or(LoadError::DriverTableFull)?;
        Ok(LoadedDriver {
            base: module.base,
            size: module.size,
            entry_va: module.entry_va,
            driver: &*driver,
            driver_id,
        })
    }

    /// Copy staged page `page` into a fresh frame and map it at the module's page: the frame is
    /// zero-filled and filled through the scratch window, then mapped in the region's shared
    /// tables (so in every address space).
    fn map_staged_page(staging: &[u8], base: u32, page: usize) -> Result<(), LoadError> {
        let frame = paging::try_allocate_frame_phys().ok_or(LoadError::OutOfFrames)?;
        let start = page * paging::PAGE_SIZE as usize;
        paging::init_frame(
            frame,
            0,
            &staging[start..start + paging::PAGE_SIZE as usize],
        );
        paging::map_kernel_page(base + page as u32 * paging::PAGE_SIZE, frame);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    // --- A synthetic .sys image ---------------------------------------------------------------
    //
    // 0x800 bytes: DOS header (e_lfanew 0x80), NT headers at 0x80 (optional at 0x98, section
    // table at 0x178), three sections — .text at RVA 0x1000 (file 0x200), .idata at 0x2000
    // (file 0x400), .reloc at 0x3000 (file 0x700). The import directory walks two descriptors
    // (hal.dll, ntoskrnl.exe); the reloc block patches the dword at RVA 0x1010.

    const PREFERRED: u32 = 0xC400_0000;

    fn w16(file: &mut [u8], off: usize, value: u16) {
        file[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn w32(file: &mut [u8], off: usize, value: u32) {
        file[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn cstr_at(file: &mut [u8], off: usize, text: &str) {
        file[off..off + text.len()].copy_from_slice(text.as_bytes());
        file[off + text.len()] = 0;
    }

    /// Build the synthetic image: `dll` sets the file-header DLL flag, `reloc` emits the
    /// relocation directory, `ordinal` makes the ntoskrnl import by ordinal instead of name.
    fn synthetic_sys(dll: bool, reloc: bool, ordinal: bool) -> Vec<u8> {
        let mut file = vec![0u8; 0x800];
        w16(&mut file, 0x00, 0x5A4D); // DOS magic
        w32(&mut file, 0x3C, 0x80); // e_lfanew
        w32(&mut file, 0x80, 0x4550); // PE signature
        w16(&mut file, 0x84, 0x014C); // machine i386
        w16(&mut file, 0x86, 3); // three sections
        w16(&mut file, 0x94, 0xE0); // size of optional header
        w16(&mut file, 0x96, if dll { 0x2102 } else { 0x0102 }); // DLL | 32-bit | executable
        let opt = 0x98;
        w16(&mut file, opt, 0x10B); // PE32 magic
        w32(&mut file, opt + 0x10, 0x1000); // entry point RVA (.text)
        w32(&mut file, opt + 0x1C, PREFERRED); // image base
        w32(&mut file, opt + 0x20, 0x1000); // section alignment
        w32(&mut file, opt + 0x24, 0x200); // file alignment
        w32(&mut file, opt + 0x38, 0x4000); // size of image
        w32(&mut file, opt + 0x3C, 0x200); // size of headers
        w16(&mut file, opt + 0x44, 1); // subsystem: native
        w32(&mut file, opt + 0x5C, 16); // data directories
        let dirs = opt + 0x60;
        w32(&mut file, dirs + 1 * 8, 0x2000); // import directory RVA
        w32(&mut file, dirs + 1 * 8 + 4, 0x300); // ... size
        if reloc {
            w32(&mut file, dirs + 5 * 8, 0x3000); // reloc directory RVA
            w32(&mut file, dirs + 5 * 8 + 4, 0x100); // ... size
        }
        // Section table at 0x178: .text, .idata, .reloc.
        let table = 0x178;
        let section = |file: &mut [u8], row: usize, name: &str, vsize: u32, va: u32, raw: u32, raw_at: u32, chars: u32| {
            let at = table + row * 40;
            file[at..at + name.len()].copy_from_slice(name.as_bytes());
            w32(file, at + 8, vsize);
            w32(file, at + 12, va);
            w32(file, at + 16, raw);
            w32(file, at + 20, raw_at);
            w32(file, at + 36, chars);
        };
        section(&mut file, 0, ".text", 0x200, 0x1000, 0x200, 0x200, 0x6000_0020);
        section(&mut file, 1, ".idata", 0x300, 0x2000, 0x300, 0x400, 0xC000_0040);
        section(&mut file, 2, ".reloc", 0x100, 0x3000, 0x100, 0x700, 0x4200_0040);

        // .text: entry code, and the dword the relocation patches (RVA 0x1010 = file 0x210).
        file[0x200] = 0xC3; // ret
        w32(&mut file, 0x210, PREFERRED + 0x1234);

        // .idata (RVA 0x2000 = file 0x400): two descriptors, thunk arrays, names, IAT.
        w32(&mut file, 0x400, 0x2100); // descriptor 0: original first thunk
        w32(&mut file, 0x400 + 12, 0x2180); // ... name RVA ("hal.dll")
        w32(&mut file, 0x400 + 16, 0x2200); // ... first thunk (IAT)
        w32(&mut file, 0x414, 0x2108); // descriptor 1: original first thunk
        w32(&mut file, 0x414 + 12, 0x2190); // ... name RVA ("ntoskrnl.exe")
        w32(&mut file, 0x414 + 16, 0x2208); // ... first thunk (IAT)
        // descriptor 2 at 0x428 stays zero: the array's end.
        w32(&mut file, 0x500, 0x21A0); // thunk array 0: hint/name RVA
        w32(&mut file, 0x504, 0); // ... end
        if ordinal {
            w32(&mut file, 0x508, 0x8000_0000 | 7); // thunk array 1: by ordinal 7
        } else {
            w32(&mut file, 0x508, 0x21C0); // thunk array 1: hint/name RVA
        }
        w32(&mut file, 0x50C, 0); // ... end
        cstr_at(&mut file, 0x580, "hal.dll"); // RVA 0x2180
        cstr_at(&mut file, 0x590, "ntoskrnl.exe"); // RVA 0x2190
        cstr_at(&mut file, 0x5A2, "HalGetDmaAlignmentRequirement"); // RVA 0x21A0 (hint at 0x5A0)
        cstr_at(&mut file, 0x5C2, "IoCreateDevice"); // RVA 0x21C0 (hint at 0x5C0)
        // IAT at RVA 0x2200 (file 0x600) stays zero: the snap writes it.

        // .reloc (RVA 0x3000 = file 0x700): one block patching RVA 0x1010.
        if reloc {
            w32(&mut file, 0x700, 0x1000); // page RVA
            w32(&mut file, 0x704, 12); // block size
            w16(&mut file, 0x708, 0x3010); // HIGHLOW at offset 0x10
            w16(&mut file, 0x70A, 0x0000); // ABSOLUTE padding
        }
        file
    }

    fn u32_at(bytes: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
    }

    /// The fake export tables the loader's resolver walks: the (module, entry) pairs it was
    /// asked for land in `log` (ordinals as "#<n>"), and the known entries resolve.
    fn fake_resolve(
        log: &mut Vec<(String, String)>,
    ) -> impl FnMut(&str, ImportName) -> Result<u32, Unresolved> + '_ {
        move |module, name| {
            let result = match (module, name) {
                ("hal.dll", ImportName::Name("HalGetDmaAlignmentRequirement")) => Ok(0xDEAD_0000),
                ("ntoskrnl.exe", ImportName::Name("IoCreateDevice")) => Ok(0xBEEF_0000),
                ("ntoskrnl.exe", ImportName::Ordinal(7)) => Ok(0xCAFE_0000),
                _ => Err(Unresolved::NoEntry),
            };
            let entry = match &name {
                ImportName::Name(name) => name.to_string(),
                ImportName::Ordinal(ordinal) => format!("#{ordinal}"),
            };
            log.push((module.to_string(), entry));
            result
        }
    }

    /// A module stages, relocates to the chosen base, and snaps its imports against the fake
    /// tables: the IAT slots hold the resolved addresses, the relocation patched the dword, and
    /// the entry point is the base plus its RVA.
    #[test]
    fn a_module_stages_relocates_and_snaps_over_the_seams() {
        let file = synthetic_sys(true, true, false);
        let base = 0xC680_0000;
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        let module = load_staged(&file, base, &mut staged, fake_resolve(&mut log)).unwrap();

        assert_eq!(module.base, base);
        assert_eq!(module.size, 0x4000);
        assert_eq!(module.entry_va, base + 0x1000);
        assert_eq!(
            module.snap,
            Snap {
                descriptors: 2,
                thunks: 2
            }
        );
        // The IAT slots were written in the staged image.
        assert_eq!(u32_at(&staged, 0x2200), 0xDEAD_0000);
        assert_eq!(u32_at(&staged, 0x2208), 0xBEEF_0000);
        // The relocation added the delta to the dword at RVA 0x1010.
        assert_eq!(u32_at(&staged, 0x1010), base + 0x1234);
        // The resolver saw the module names as spelled and the entry names by name.
        assert_eq!(
            log,
            [
                ("hal.dll".to_string(), "HalGetDmaAlignmentRequirement".to_string()),
                ("ntoskrnl.exe".to_string(), "IoCreateDevice".to_string()),
            ]
        );

        // The same image at its preferred base needs no relocations and changes nothing.
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        let module = load_staged(&file, PREFERRED, &mut staged, fake_resolve(&mut log)).unwrap();
        assert_eq!(module.entry_va, PREFERRED + 0x1000);
        assert_eq!(u32_at(&staged, 0x1010), PREFERRED + 0x1234, "delta zero");
    }

    /// An import by ordinal reaches the resolver as an ordinal.
    #[test]
    fn an_import_by_ordinal_reaches_the_resolver_as_one() {
        let file = synthetic_sys(true, true, true);
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        let module = load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap();
        assert_eq!(module.snap.thunks, 2);
        assert_eq!(u32_at(&staged, 0x2208), 0xCAFE_0000);
        assert_eq!(log[1].1, "#7");
    }

    /// An unresolved import fails the load; a /FIXED image cannot move; a non-DLL or a
    /// user-space base is refused at the parse; a truncated file is refused.
    #[test]
    fn the_load_refuses_what_it_cannot_serve() {
        // An import the fake tables do not have.
        let mut file = synthetic_sys(true, true, false);
        cstr_at(&mut file, 0x5A2, "NoSuchEntry");
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        let error = load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err();
        assert_eq!(error, LoadError::Unresolved);
        assert_eq!(log[0].1, "NoSuchEntry");

        // No relocation directory, moved from the preferred base: refused; at the preferred
        // base: fine.
        let file = synthetic_sys(true, false, false);
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err(),
            LoadError::NoRelocations
        );
        let mut log = Vec::new();
        assert!(load_staged(&file, PREFERRED, &mut staged, fake_resolve(&mut log)).is_ok());

        // A program (no DLL flag) is not a kernel module.
        let file = synthetic_sys(false, true, false);
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err(),
            LoadError::NotAnImage(Reject::NotADll)
        );

        // A preferred base in user space is not a module's base.
        let mut file = synthetic_sys(true, true, false);
        w32(&mut file, 0x98 + 0x1C, 0x0040_0000);
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err(),
            LoadError::NotAnImage(Reject::ImageOutsideKernelSpace)
        );

        // A truncated file.
        let file = synthetic_sys(true, true, false);
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file[..0x100], 0xC680_0000, &mut staged, fake_resolve(&mut log))
                .unwrap_err(),
            LoadError::NotAnImage(Reject::Truncated)
        );

        // A staging buffer too small for the image.
        let file = synthetic_sys(true, true, false);
        let mut small = vec![0u8; 0x1000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut small, fake_resolve(&mut log)).unwrap_err(),
            LoadError::NotAnImage(Reject::Truncated)
        );
    }

    /// A relocation entry of an unsupported type is refused, and a block reading past the
    /// directory is malformed.
    #[test]
    fn relocation_blocks_are_walked_and_checked() {
        let mut file = synthetic_sys(true, true, false);
        w16(&mut file, 0x708, 0xA010); // type 0xA at offset 0x10
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err(),
            LoadError::UnsupportedRelocation(0xA)
        );

        // A block whose size runs past the directory's end.
        let mut file = synthetic_sys(true, true, false);
        w32(&mut file, 0x704, 0x200);
        let mut staged = vec![0u8; 0x4000];
        let mut log = Vec::new();
        assert_eq!(
            load_staged(&file, 0xC680_0000, &mut staged, fake_resolve(&mut log)).unwrap_err(),
            LoadError::Malformed
        );
    }
}
