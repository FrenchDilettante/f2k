//! drawdemo.exe: a window of user32's drawing calls (src/lib.rs lays the sheet out). Run under
//! FiSH, which sets the graphics mode: `fish.exe \WINNT\system32\drawdemo.exe`. The window paints
//! once, in its WM_PAINT, through BeginPaint's DC, one sample through GetDC's, then quits; the
//! screen keeps the drawing for its screenshot.

#![no_std]
#![no_main]

use drawdemo::*;
use exe::winuser::{
    BF_ADJUST,
    BF_MIDDLE,
    BF_RECT,
    BF_SOFT,
    COLOR_3DFACE,
    COLOR_3DSHADOW,
    COLOR_WINDOW,
    DT_CALCRECT,
    DT_CENTER,
    DT_EXPANDTABS,
    DT_SINGLELINE,
    DT_VCENTER,
    DT_WORDBREAK,
    EDGE_RAISED,
    EDGE_SUNKEN,
    SW_SHOW,
    WM_PAINT,
    WS_POPUP,
};

exe::entry!(main);

/// The window's procedure, its class's name, and the messages it reads (winuser.h).
const CLASS: &[u8] = b"F2KDrawDemo\0";
/// The system colors and stock objects the sheet paints with (winuser.h, wingdi.h).
const BLACK_BRUSH: i32 = 4;
const TRANSPARENT: i32 = 1;

/// The calls the sheet makes, as user32 exports them: the shared ones, and its own.
mod ffi {
    pub use common::ffi::*;
    use drawdemo::Rect;

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn ShowWindow(window: usize, command: i32) -> i32;
        pub fn GetDC(window: usize) -> usize;
        pub fn ReleaseDC(window: usize, dc: usize) -> i32;
        pub fn GetSysColorBrush(index: i32) -> usize;
        pub fn FillRect(dc: usize, rect: *const Rect, brush: usize) -> i32;
        pub fn FrameRect(dc: usize, rect: *const Rect, brush: usize) -> i32;
        pub fn InvertRect(dc: usize, rect: *const Rect) -> i32;
        pub fn DrawFocusRect(dc: usize, rect: *const Rect) -> i32;
        pub fn DrawEdge(dc: usize, rect: *mut Rect, edge: u32, flags: u32) -> i32;
        pub fn DrawTextA(
            dc: usize,
            text: *const u8,
            count: i32,
            rect: *mut Rect,
            format: u32,
        ) -> i32;
    }
}

/// The calls over a DC, each wrapped once: the sheet's own rectangles and strings, which live for
/// the call, are all they are handed.
struct Dc(usize);

impl Dc {
    fn fill(&self, area: Rect, brush: usize) {
        // SAFETY: the sheet's own RECT.
        unsafe { ffi::FillRect(self.0, &area, brush) };
    }

    fn frame(&self, area: Rect, brush: usize) {
        // SAFETY: the sheet's own RECT.
        unsafe { ffi::FrameRect(self.0, &area, brush) };
    }

    fn invert(&self, area: Rect) {
        // SAFETY: the sheet's own RECT.
        unsafe { ffi::InvertRect(self.0, &area) };
    }

    fn focus(&self, area: Rect) {
        // SAFETY: the sheet's own RECT.
        unsafe { ffi::DrawFocusRect(self.0, &area) };
    }

    /// The edge drawn; the rectangle it leaves.
    fn edge(&self, area: Rect, edge: u32, flags: u32) -> Rect {
        let mut area = area;
        // SAFETY: the sheet's own RECT, which BF_ADJUST writes.
        unsafe { ffi::DrawEdge(self.0, &mut area, edge, flags | BF_ADJUST) };
        area
    }

    /// The text drawn; the rectangle as DT_CALCRECT leaves it.
    fn text(&self, text: &[u8], area: Rect, format: u32) -> Rect {
        let mut area = area;
        // SAFETY: the sheet's own string, of its length, and RECT.
        unsafe { ffi::DrawTextA(self.0, text.as_ptr(), text.len() as i32, &mut area, format) };
        area
    }

    fn transparent(&self) {
        // SAFETY: no pointers.
        unsafe { ffi::SetBkMode(self.0, TRANSPARENT) };
    }
}

/// `area` moved in by `by` on every side.
fn inset(area: Rect, by: i32) -> Rect {
    rect(
        area.left + by,
        area.top + by,
        area.right - by,
        area.bottom - by,
    )
}

/// A solid brush of `color`, deleted when it drops.
struct Brush(usize);

impl Brush {
    fn solid(color: u32) -> Self {
        // SAFETY: no pointers.
        Brush(unsafe { ffi::CreateSolidBrush(color) })
    }
}

impl Drop for Brush {
    fn drop(&mut self) {
        // SAFETY: no pointers; the brush is ours.
        unsafe { ffi::DeleteObject(self.0) };
    }
}

/// The sheet, drawn through BeginPaint's DC.
fn paint(dc: &Dc) {
    dc.fill(CLIENT, COLOR_3DFACE + 1);
    dc.transparent();
    let centered = DT_SINGLELINE | DT_CENTER | DT_VCENTER;
    for sample in &EDGES {
        let inside = dc.edge(sample.area, sample.edge, BF_RECT | BF_MIDDLE | sample.flags);
        dc.text(sample.label, inside, centered);
    }

    for &(area, color) in &FILLS {
        let brush = Brush::solid(color);
        dc.fill(area, brush.0);
    }
    dc.invert(INVERTED);
    // SAFETY: no pointers.
    let (black, shadow) = unsafe {
        (
            ffi::GetStockObject(BLACK_BRUSH),
            ffi::GetSysColorBrush(COLOR_3DSHADOW as i32),
        )
    };
    dc.frame(FRAME, black);
    dc.frame(INNER_FRAME, shadow);

    dc.text(b"&Focus", FOCUS, centered);
    dc.focus(inset(FOCUS, 4));

    dc.frame(ALIGNED, black);
    for &(text, format) in &ALIGNMENTS {
        dc.text(text, inset(ALIGNED, 4), DT_SINGLELINE | format);
    }

    let inside = dc.edge(WRAPPED, EDGE_SUNKEN, BF_RECT);
    dc.fill(inside, COLOR_WINDOW + 1);
    dc.text(PARAGRAPH, inset(inside, 4), DT_WORDBREAK);

    let inside = dc.edge(TABBED, EDGE_SUNKEN, BF_RECT);
    dc.fill(inside, COLOR_WINDOW + 1);
    dc.text(TABS, inset(inside, 2), DT_EXPANDTABS);

    let bound = dc.text(CALCULATED, CALCULATED_AT, DT_SINGLELINE | DT_CALCRECT);
    dc.text(CALCULATED, bound, DT_SINGLELINE);
    dc.frame(inset(bound, -2), black);

    dc.frame(DEFAULT_BUTTON, black);
    let face = dc.edge(
        inset(DEFAULT_BUTTON, 1),
        EDGE_RAISED,
        BF_RECT | BF_SOFT | BF_MIDDLE,
    );
    dc.text(b"OK", face, centered);
    dc.focus(inset(face, 2));
    let face = dc.edge(BUTTON, EDGE_RAISED, BF_RECT | BF_SOFT | BF_MIDDLE);
    dc.text(b"Cancel", face, centered);
}

/// The sample GetDC's DC draws: the window's client area outside the paint.
fn paint_through_get_dc(window: usize) {
    // SAFETY: no pointers.
    let dc = Dc(unsafe { ffi::GetDC(window) });
    dc.transparent();
    dc.text(
        b"GetDC",
        GETDC_FOCUS,
        DT_SINGLELINE | DT_CENTER | DT_VCENTER,
    );
    dc.focus(inset(GETDC_FOCUS, 4));
    // SAFETY: no pointers; the DC GetDC handed out.
    unsafe { ffi::ReleaseDC(window, dc.0) };
}

/// The window's procedure: WM_PAINT paints the sheet and quits; the rest is DefWindowProc's.
extern "system" fn window_proc(window: usize, message: u32, wparam: usize, lparam: isize) -> isize {
    if message != WM_PAINT {
        // SAFETY: the message as it came.
        return unsafe { ffi::DefWindowProcA(window, message, wparam, lparam) };
    }
    let mut ps = ffi::PaintStruct::default();
    // SAFETY: our own PAINTSTRUCT.
    let dc = Dc(unsafe { ffi::BeginPaint(window, &mut ps) });
    paint(&dc);
    // SAFETY: the PAINTSTRUCT BeginPaint filled.
    unsafe { ffi::EndPaint(window, &ps) };
    paint_through_get_dc(window);
    // SAFETY: no pointers.
    unsafe { ffi::PostQuitMessage(0) };
    0
}

fn main() -> u32 {
    let Some(instance) = common::register_class_a(CLASS, window_proc, COLOR_3DFACE + 1) else {
        let _ = exe::stderr().print(format_args!("drawdemo: the class cannot be registered\r\n"));
        return 1;
    };
    let (width, height) = (WINDOW.right - WINDOW.left, WINDOW.bottom - WINDOW.top);
    // SAFETY: the class's name and the window's, NUL-terminated.
    let window = unsafe {
        ffi::CreateWindowExA(
            0,
            CLASS.as_ptr(),
            c"drawdemo".as_ptr().cast(),
            WS_POPUP,
            WINDOW.left,
            WINDOW.top,
            width,
            height,
            0,
            0,
            instance,
            0,
        )
    };
    if window == 0 {
        let _ = exe::stderr().print(format_args!("drawdemo: the window cannot be made\r\n"));
        return 1;
    }
    // SAFETY: no pointers.
    unsafe {
        ffi::ShowWindow(window, SW_SHOW);
        ffi::UpdateWindow(window);
    }
    let mut msg = ffi::Msg::default();
    // SAFETY: our own MSG.
    while unsafe { ffi::GetMessageA(&mut msg, 0, 0, 0) } > 0 {
        // SAFETY: the MSG GetMessageA filled.
        unsafe { ffi::DispatchMessageA(&msg) };
    }
    msg.wparam as u32
}
