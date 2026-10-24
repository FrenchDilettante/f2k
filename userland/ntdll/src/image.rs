//! RtlImageNtHeader: a mapped image's NT headers, found from its base as `rtl::image` finds them.

use rtl::image::{self, ImageDosHeader, ImageNtHeaders32, NT_SIGNATURE};

/// RtlImageNtHeader: the NT headers of the image mapped at `base` (its DOS header's e_lfanew from
/// the base), or null when `base` is null or -1, the image has no MZ signature, or its headers have
/// no PE signature. An image whose headers are not mapped faults the caller, as on Windows 2000.
#[unsafe(export_name = "f2k_export_RtlImageNtHeader")]
pub extern "system" fn rtl_image_nt_header(base: usize) -> *const ImageNtHeaders32 {
    if base == 0 || base == usize::MAX {
        return core::ptr::null();
    }
    // SAFETY: the caller's image, its headers mapped; read unaligned, a base promising nothing.
    let dos = unsafe { core::ptr::read_unaligned(base as *const ImageDosHeader) };
    let Some(headers) = image::nt_headers_offset(&dos)
        .and_then(|offset| base.checked_add(offset))
        .map(|at| at as *const ImageNtHeaders32)
    else {
        return core::ptr::null();
    };
    // SAFETY: as above: the signature e_lfanew points at.
    let signature = unsafe { core::ptr::addr_of!((*headers).signature).read_unaligned() };
    if signature == NT_SIGNATURE {
        headers
    } else {
        core::ptr::null()
    }
}
