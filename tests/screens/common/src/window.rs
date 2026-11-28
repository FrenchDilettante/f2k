//! A test program's top-level window: its class and its making ([`TopLevel`]), its children
//! ([`Window::child`]), its painting ([`paint`]) and the procedure that ends the program with it
//! ([`procedure`]), the message loop ([`pump`], [`pump_ready`]), and an object selected while a
//! DC draws with it ([`with`]); the ANSI class of the programs that make theirs with
//! RegisterClassExA ([`register_class_a`]).

use exe::winuser::{PM_NOREMOVE, SM_CXSCREEN, SM_CYSCREEN, WM_DESTROY, WS_CHILD, WS_VISIBLE};

use crate::ffi::{self, WindowProc};
use crate::Wide;

/// A top-level window of a class of its own (WNDCLASSW: no class style, icon or cursor), its
/// client area `client` wide and high, centred on the screen.
pub struct TopLevel<'a> {
    /// The class's name.
    pub class: &'a str,
    /// The window's title.
    pub title: &'a str,
    /// The class's procedure.
    pub procedure: WindowProc,
    /// The class's background brush (a COLOR_* + 1, or 0 for none).
    pub background: usize,
    /// The window's styles.
    pub style: u32,
    /// The client area's width and height.
    pub client: (i32, i32),
    /// The window's menu bar, 0 for none.
    pub menu: usize,
}

/// A window made by [`TopLevel::create`], and the program's module, which its children name.
#[derive(Clone, Copy)]
pub struct Window {
    pub handle: usize,
    pub instance: usize,
}

impl TopLevel<'_> {
    /// The class registered and the window made: its frame (AdjustWindowRectEx, a menu bar
    /// counted when it has one) around the client area, centred on the screen. None when the class
    /// cannot be registered or the window cannot be made.
    pub fn create(&self) -> Option<Window> {
        let class_name = Wide::of(self.class);
        let title = Wide::of(self.title);
        // SAFETY: the program's own module, class, strings and RECT, which live for each call.
        let (handle, instance) = unsafe {
            let instance = ffi::GetModuleHandleA(core::ptr::null());
            let class = ffi::WndClassW {
                style: 0,
                proc: self.procedure,
                class_extra: 0,
                window_extra: 0,
                instance,
                icon: 0,
                cursor: 0,
                background: self.background,
                menu_name: core::ptr::null(),
                class_name: class_name.as_ptr(),
            };
            if ffi::RegisterClassW(&class) == 0 {
                return None;
            }
            let mut rect = ffi::Rect {
                left: 0,
                top: 0,
                right: self.client.0,
                bottom: self.client.1,
            };
            ffi::AdjustWindowRectEx(&mut rect, self.style, (self.menu != 0).into(), 0);
            let (cx, cy) = (rect.right - rect.left, rect.bottom - rect.top);
            let x = (ffi::GetSystemMetrics(SM_CXSCREEN) - cx) / 2;
            let y = (ffi::GetSystemMetrics(SM_CYSCREEN) - cy) / 2;
            let handle = ffi::CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                self.style,
                x,
                y,
                cx,
                cy,
                0,
                self.menu,
                instance,
                0,
            );
            (handle, instance)
        };
        (handle != 0).then_some(Window { handle, instance })
    }
}

impl Window {
    /// A child of the window, of the class `class`, with `ex_style` and `style` (WS_CHILD and
    /// WS_VISIBLE added), its text `text`, at (`x`, `y`), `cx` by `cy`, its id `id`; 0 when it
    /// cannot be made.
    pub fn child(
        &self,
        class: &str,
        ex_style: u32,
        style: u32,
        text: &str,
        (x, y, cx, cy): (i32, i32, i32, i32),
        id: usize,
    ) -> usize {
        let class = Wide::of(class);
        let text = Wide::of(text);
        // SAFETY: the program's own window, class name and text, which live for the call.
        unsafe {
            ffi::CreateWindowExW(
                ex_style,
                class.as_ptr(),
                text.as_ptr(),
                WS_CHILD | WS_VISIBLE | style,
                x,
                y,
                cx,
                cy,
                self.handle,
                id,
                self.instance,
                0,
            )
        }
    }

    /// The window made the foreground window.
    pub fn to_foreground(&self) {
        // SAFETY: no pointers.
        unsafe { ffi::SetForegroundWindow(self.handle) };
    }
}

/// The procedure of a window that only ends the program: its WM_DESTROY ends the message loop;
/// the rest is DefWindowProcW's. A program's own procedure hands it what it does not answer.
pub extern "system" fn procedure(
    window: usize,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match message {
        WM_DESTROY => {
            // SAFETY: no pointers.
            unsafe { ffi::PostQuitMessage(0) };
            0
        }
        // SAFETY: the message as the window manager handed it over.
        _ => unsafe { ffi::DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// A WM_PAINT of `window`: `draw` handed BeginPaint's DC (when it has one), then EndPaint.
pub fn paint(window: usize, draw: impl FnOnce(usize)) {
    let mut paint = ffi::PaintStruct::default();
    // SAFETY: the window's own PAINTSTRUCT.
    let dc = unsafe { ffi::BeginPaint(window, &mut paint) };
    if dc != 0 {
        draw(dc);
    }
    // SAFETY: as above.
    unsafe { ffi::EndPaint(window, &paint) };
}

/// The thread's message loop, until WM_QUIT: each message translated and dispatched. Whenever the
/// queue is empty `idle` is called first; when it answers true the queue is looked at again
/// instead of waited on (it has posted or caused something).
pub fn pump(mut idle: impl FnMut() -> bool) {
    let mut msg = ffi::Msg::default();
    loop {
        // SAFETY: the loop's own MSG.
        let empty = unsafe { ffi::PeekMessageW(&mut msg, 0, 0, 0, PM_NOREMOVE) } == 0;
        if empty && idle() {
            continue;
        }
        // SAFETY: as above.
        if unsafe { ffi::GetMessageW(&mut msg, 0, 0, 0) } <= 0 {
            break;
        }
        // SAFETY: as above.
        unsafe {
            ffi::TranslateMessage(&msg);
            ffi::DispatchMessageW(&msg);
        }
    }
}

/// The message loop ([`pump`]), the line `ready` printed the first time the queue is idle.
pub fn pump_ready(ready: &str) {
    let mut said = false;
    pump(|| {
        if !said {
            said = true;
            let _ = exe::stdout().print(format_args!("{ready}\r\n"));
        }
        false
    });
}

/// `object` selected into `dc` while `f` draws, then the previous one back and `object` deleted.
///
/// # Safety
///
/// `dc` a DC of the program's; `object` a pen or brush it made (or a stock object).
pub unsafe fn with(dc: usize, object: usize, f: impl FnOnce()) {
    // SAFETY: the caller's DC and object.
    unsafe {
        let old = ffi::SelectObject(dc, object);
        f();
        ffi::SelectObject(dc, old);
        ffi::DeleteObject(object);
    }
}

/// The ANSI class `name` (NUL-terminated) registered with RegisterClassExA: `procedure`, the
/// background brush `background` (a COLOR_* + 1, or 0 for none), no class style, icon or cursor.
/// The program's module, which its windows name; None when the class cannot be registered.
pub fn register_class_a(
    name: &'static [u8],
    procedure: WindowProc,
    background: usize,
) -> Option<usize> {
    debug_assert_eq!(name.last(), Some(&0), "the class name is NUL-terminated");
    // SAFETY: the program's own module.
    let instance = unsafe { ffi::GetModuleHandleA(core::ptr::null()) };
    let class = ffi::WndClassExA {
        size: core::mem::size_of::<ffi::WndClassExA>() as u32,
        style: 0,
        proc: procedure,
        class_extra: 0,
        window_extra: 0,
        instance,
        icon: 0,
        cursor: 0,
        background,
        menu_name: core::ptr::null(),
        class_name: name.as_ptr(),
        small_icon: 0,
    };
    // SAFETY: the class's structure and name, which live for the call.
    (unsafe { ffi::RegisterClassExA(&class) } != 0).then_some(instance)
}
