//! Regions: CreateRectRgn, CreateRectRgnIndirect and CreatePolygonRgn, CombineRgn, SetRectRgn,
//! OffsetRgn, GetRgnBox, EqualRgn, PtInRegion, GetRegionData and FillRgn, each over its win32k
//! service ([`imports`]); the region objects and their algebra are the kernel's
//! (kernel/src/win32k/region.rs describes them).
//!
//! DeleteObject of a region does not enter the kernel: it queues the deletion in the calling
//! thread's GDI batch ([`delete_region`]), which win32k runs on the thread's next win32k service,
//! as Windows 2000's gdi32 does, so the region lives until then. Windows 2000's gdi32 answers
//! GetRgnBox and PtInRegion of a simple or empty region from the region's attributes in user
//! memory, without entering the kernel; F2K keeps no such attributes, but the batch's command
//! holds what they would (the region's complexity and box as it was queued), and these two answer
//! from it for a region whose deletion waits there: the regions capture's GetRgnBox of a region
//! just deleted reads its box, where the next call (EqualRgn, which enters the kernel) finds it
//! gone. Every other call on such a region enters the kernel, which runs the batch first.
//!
//! The last error, as the regions capture shows it: PtInRegion and CombineRgn of a handle naming
//! no region set ERROR_INVALID_HANDLE, CombineRgn of a mode that is none and GetRegionData of a
//! buffer too small ERROR_INVALID_PARAMETER, CreatePolygonRgn of fewer than two points
//! ERROR_INVALID_PARAMETER; GetRgnBox, EqualRgn, OffsetRgn, SetRectRgn and FillRgn fail without
//! touching it, as CreatePolygonRgn of a fill mode that is none does.

use rtl::edge::Out;
use rtl::gdi::*;

use crate::imports::{self, Caller};
use crate::{answered, failed, ERROR_INVALID_PARAMETER};

/// The command the calling thread's GDI batch holds for `region`'s deletion, if it holds one.
fn pending(region: usize) -> Option<BatchCommand> {
    let count = rtl::sys::gdi_batch_count().min(GDI_BATCH_LIMIT) as usize;
    (0..count)
        .map(rtl::sys::gdi_batch_command)
        .find(|command| command.command == BATCH_DELETE_REGION && command.handle == region as u32)
}

/// The complexity and box a region whose deletion waits in the batch answers without the kernel:
/// a simple or empty one's (see the module notes).
fn pending_simple(region: usize) -> Option<(i32, Rect)> {
    pending(region)
        .filter(|command| command.complexity == NULLREGION || command.complexity == SIMPLEREGION)
        .map(|command| (command.complexity, command.bounds))
}

/// DeleteObject of a region: its deletion queued in the calling thread's GDI batch with its
/// complexity and box (a region whose deletion is queued already is queued again, as Windows
/// 2000's is); TRUE. A handle that names no region goes to NtGdiDeleteObjectApp, which fails.
pub fn delete_region(region: usize) -> u32 {
    let (complexity, bounds) = match pending(region) {
        Some(command) => (command.complexity, command.bounds),
        None => match imports::rgn_box(region) {
            Ok(answer) => answer,
            Err(_) => return answered(imports::delete_object(region)).map_or(0, |()| 1),
        },
    };
    if rtl::sys::gdi_batch_count() >= GDI_BATCH_LIMIT {
        imports::flush();
    }
    rtl::sys::push_gdi_batch_command(BatchCommand {
        command: BATCH_DELETE_REGION,
        handle: region as u32,
        complexity,
        bounds,
    });
    1
}

/// GetObjectType of a region's handle: OBJ_REGION while it names one (its deletion still queued
/// too), 0 otherwise.
pub fn object_type(region: usize) -> u32 {
    if pending(region).is_some() || imports::rgn_box(region).is_ok() {
        OBJ_REGION
    } else {
        0
    }
}

/// GdiFlush's step: the calling thread's GDI batch run, when it holds anything.
pub fn flush_batch() {
    if rtl::sys::gdi_batch_count() != 0 {
        imports::flush();
    }
}

/// CreateRectRgn: a region of the rectangle, its edges put in order (an empty one is the empty
/// region); NULL with the last error when the kernel has no room for it.
#[unsafe(export_name = "f2k_export_CreateRectRgn")]
pub extern "system" fn create_rect_rgn(left: i32, top: i32, right: i32, bottom: i32) -> usize {
    answered(imports::create_rect_rgn(left, top, right, bottom)).map_or(0, |region| region as usize)
}

/// CreateRectRgnIndirect: CreateRectRgn of the RECT at `rect`; NULL with ERROR_INVALID_PARAMETER
/// for none.
///
/// # Safety
///
/// `rect`, when not null, is a RECT.
#[unsafe(export_name = "f2k_export_CreateRectRgnIndirect")]
pub unsafe extern "system" fn create_rect_rgn_indirect(rect: *const Rect) -> usize {
    if rect.is_null() {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    // SAFETY: the caller's RECT.
    let rect = unsafe { rect.read_unaligned() };
    create_rect_rgn(rect.left, rect.top, rect.right, rect.bottom)
}

/// CreatePolygonRgn: a region of the polygon of the `count` points at `points`, under the fill
/// mode (ALTERNATE or WINDING); NULL with ERROR_INVALID_PARAMETER for fewer than two points, NULL
/// alone for a fill mode that is none.
#[unsafe(export_name = "f2k_export_CreatePolygonRgn")]
pub extern "system" fn create_polygon_rgn(points: usize, count: i32, mode: u32) -> usize {
    if count < 2 {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(0);
    }
    if mode != ALTERNATE && mode != WINDING {
        return 0;
    }
    let counts = [count as u32];
    answered(imports::create_poly_polygon_rgn(
        Caller(points),
        &counts,
        mode,
    ))
    .map_or(0, |region| region as usize)
}

/// CombineRgn: `dest` made the combination of the sources in `mode` (RGN_COPY: the first's); its
/// complexity, ERROR with ERROR_INVALID_PARAMETER for a mode that is none (`dest` untouched), with
/// ERROR_INVALID_HANDLE for a handle that names no region.
#[unsafe(export_name = "f2k_export_CombineRgn")]
pub extern "system" fn combine_rgn(dest: usize, first: usize, second: usize, mode: i32) -> i32 {
    if !(RGN_AND as i32..=RGN_COPY as i32).contains(&mode) {
        return failed(ERROR_INVALID_PARAMETER).unwrap_or(ERROR);
    }
    answered(imports::combine_rgn(dest, first, second, mode as u32)).unwrap_or(ERROR)
}

/// SetRectRgn: the region made the rectangle (its edges put in order); FALSE for a handle that
/// names no region.
#[unsafe(export_name = "f2k_export_SetRectRgn")]
pub extern "system" fn set_rect_rgn(
    region: usize,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> u32 {
    imports::set_rect_rgn(region, left, top, right, bottom).is_ok() as u32
}

/// OffsetRgn: the region moved; its complexity, ERROR for a handle that names no region.
#[unsafe(export_name = "f2k_export_OffsetRgn")]
pub extern "system" fn offset_rgn(region: usize, x: i32, y: i32) -> i32 {
    imports::offset_rgn(region, x, y).unwrap_or(ERROR)
}

/// GetRgnBox: the region's box into the RECT at `rect` (the empty rectangle for the empty
/// region); its complexity, ERROR for a handle that names no region (the RECT untouched).
///
/// # Safety
///
/// `rect`, when not null, is a RECT to write.
#[unsafe(export_name = "f2k_export_GetRgnBox")]
pub unsafe extern "system" fn get_rgn_box(region: usize, rect: *mut Rect) -> i32 {
    let answer = match pending_simple(region) {
        Some(answer) => answer,
        None => match imports::rgn_box(region) {
            Ok(answer) => answer,
            Err(_) => return ERROR,
        },
    };
    // SAFETY: the caller's RECT.
    if let Some(mut out) = unsafe { Out::optional(rect) } {
        out.set(answer.1);
    }
    answer.0
}

/// EqualRgn: whether the regions hold the same rectangles; ERROR (0) for a handle that names no
/// region.
#[unsafe(export_name = "f2k_export_EqualRgn")]
pub extern "system" fn equal_rgn(first: usize, second: usize) -> u32 {
    imports::equal_rgn(first, second).map_or(0, u32::from)
}

/// PtInRegion: whether the point lies in the region; FALSE with ERROR_INVALID_HANDLE for a
/// handle that names no region.
#[unsafe(export_name = "f2k_export_PtInRegion")]
pub extern "system" fn pt_in_region(region: usize, x: i32, y: i32) -> u32 {
    if let Some((_, bounds)) = pending_simple(region) {
        return bounds.contains(x, y) as u32;
    }
    answered(imports::pt_in_region(region, x, y)).map_or(0, u32::from)
}

/// GetRegionData: the region's RGNDATA (its header, then its rectangles) into the `count` bytes
/// at `data`; its size, the size alone for no buffer; 0 with ERROR_INVALID_PARAMETER for a buffer
/// too small, with ERROR_INVALID_HANDLE for a handle that names no region.
#[unsafe(export_name = "f2k_export_GetRegionData")]
pub extern "system" fn get_region_data(region: usize, count: u32, data: usize) -> u32 {
    answered(imports::region_data(region, count, Caller(data))).unwrap_or(0)
}

/// FillRgn: the region painted with the brush; FALSE for the null brush, which paints nothing,
/// and for a DC, a region or a brush that is none.
#[unsafe(export_name = "f2k_export_FillRgn")]
pub extern "system" fn fill_rgn(dc: usize, region: usize, brush: usize) -> u32 {
    imports::fill_rgn(dc, region, brush).map_or(0, u32::from)
}
