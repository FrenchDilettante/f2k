//! drawdemo.exe: a window of user32's drawing calls (src/lib.rs lays the sheet out). Run under
//! FiSH, which sets the graphics mode: `fish.exe \WINNT\system32\drawdemo.exe`. The window paints
//! once, in its WM_PAINT, through BeginPaint's DC, one sample through GetDC's, then quits; the
//! screen keeps the drawing for its screenshot.

#![no_std]
#![no_main]

use drawdemo::*;

exe::entry!(main);

/// The window's procedure, its class's name, and the messages it reads (winuser.h).
const CLASS: &[u8] = b"F2KDrawDemo\0";
const WM_PAINT: u32 = 0x000F;
const WS_POPUP: u32 = 0x8000_0000;
const SW_SHOW: i32 = 5;
/// The system colors and stock objects the sheet paints with (winuser.h, wingdi.h).
const COLOR_WINDOW: usize = 5;
const COLOR_3DFACE: usize = 15;
const COLOR_3DSHADOW: i32 = 16;
const BLACK_BRUSH: i32 = 4;
const TRANSPARENT: i32 = 1;

/// The calls the sheet makes, as user32, gdi32 and kernel32 export them.
mod ffi {
    use drawdemo::Rect;

    /// WNDCLASSEXA (48 bytes).
    #[repr(C)]
    pub struct WndClassExA {
        pub size: u32,
        pub style: u32,
        pub proc: extern "system" fn(usize, u32, usize, isize) -> isize,
        pub class_extra: i32,
        pub window_extra: i32,
        pub instance: usize,
        pub icon: usize,
        pub cursor: usize,
        pub background: usize,
        pub menu_name: *const u8,
        pub class_name: *const u8,
        pub small_icon: usize,
    }

    /// MSG (28 bytes).
    #[repr(C)]
    #[derive(Default)]
    pub struct Msg {
        pub window: usize,
        pub message: u32,
        pub wparam: usize,
        pub lparam: isize,
        pub time: u32,
        pub x: i32,
        pub y: i32,
    }

    /// PAINTSTRUCT (64 bytes).
    #[repr(C)]
    #[derive(Default)]
    pub struct PaintStruct {
        pub dc: usize,
        pub erase: i32,
        pub paint: Rect,
        pub restore: i32,
        pub inc_update: i32,
        pub reserved: [u8; 32],
    }

    #[link(
        name = "kernel32",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )]
    unsafe extern "system" {
        pub fn GetModuleHandleA(name: *const u8) -> usize;
    }

    #[link(name = "user32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn RegisterClassExA(class: *const WndClassExA) -> u16;
        #[allow(clippy::too_many_arguments)]
        pub fn CreateWindowExA(
            ex_style: u32,
            class: *const u8,
            name: *const u8,
            style: u32,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            parent: usize,
            menu: usize,
            instance: usize,
            param: usize,
        ) -> usize;
        pub fn ShowWindow(window: usize, command: i32) -> i32;
        pub fn UpdateWindow(window: usize) -> i32;
        pub fn GetMessageA(msg: *mut Msg, window: usize, first: u32, last: u32) -> i32;
        pub fn DispatchMessageA(msg: *const Msg) -> isize;
        pub fn DefWindowProcA(window: usize, message: u32, wparam: usize, lparam: isize) -> isize;
        pub fn PostQuitMessage(code: i32);
        pub fn BeginPaint(window: usize, paint: *mut PaintStruct) -> usize;
        pub fn EndPaint(window: usize, paint: *const PaintStruct) -> i32;
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

    #[link(name = "gdi32", kind = "raw-dylib", import_name_type = "undecorated")]
    unsafe extern "system" {
        pub fn CreateSolidBrush(color: u32) -> usize;
        pub fn DeleteObject(object: usize) -> i32;
        pub fn GetStockObject(index: i32) -> usize;
        pub fn SetBkMode(dc: usize, mode: i32) -> i32;
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
            ffi::GetSysColorBrush(COLOR_3DSHADOW),
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
    // SAFETY: the program's own module.
    let instance = unsafe { ffi::GetModuleHandleA(core::ptr::null()) };
    let class = ffi::WndClassExA {
        size: core::mem::size_of::<ffi::WndClassExA>() as u32,
        style: 0,
        proc: window_proc,
        class_extra: 0,
        window_extra: 0,
        instance,
        icon: 0,
        cursor: 0,
        background: COLOR_3DFACE + 1,
        menu_name: core::ptr::null(),
        class_name: CLASS.as_ptr(),
        small_icon: 0,
    };
    // SAFETY: the class's structure and name, which live for the call.
    if unsafe { ffi::RegisterClassExA(&class) } == 0 {
        let _ = exe::stderr().print(format_args!("drawdemo: the class cannot be registered\r\n"));
        return 1;
    }
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
