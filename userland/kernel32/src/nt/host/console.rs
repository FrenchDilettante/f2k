//! The console server's stand-in (CsrClientCallServer) and what it showed.

use std::cell::Cell;

use super::{CONSOLE, CONSOLE_HANDLES, CONSOLE_STATE, HANDLE, SHUTDOWN_PARAMETERS};

/// The writes the console showed since the last look.
pub fn console_writes() -> std::vec::Vec<(u32, std::vec::Vec<u8>)> {
    CONSOLE.with(|console| std::mem::take(&mut *console.borrow_mut()))
}

/// The host's client: what a write shows is recorded with its handle and rendered; an address
/// at or above 0x8000_0000 is refused as the kernel's probe refuses it, 0x10 as an unmapped
/// page.
struct Client(u32);

impl Client {
    fn check(buffer: usize) -> Result<(), u32> {
        match buffer {
            0x8000_0000..=0xFFFF_FFFF => Err(rtl::status::STATUS_ACCESS_VIOLATION),
            0x10 => Err(0xC000_00E8),
            _ => Ok(()),
        }
    }
}

impl rtl::console::Client for Client {
    fn show(
        &mut self,
        screen: Option<&mut rtl::console::screen::ScreenBuffer>,
        buffer: usize,
        count: usize,
        _logged: bool,
    ) -> Result<(), u32> {
        Self::check(buffer)?;
        // SAFETY: the test's buffer of `count` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, count) };
        if let Some(screen) = screen {
            screen.render(bytes);
        }
        CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes.to_vec())));
        Ok(())
    }

    fn print(
        &mut self,
        screen: Option<&mut rtl::console::screen::ScreenBuffer>,
        bytes: &[u8],
        _logged: bool,
    ) {
        if let Some(screen) = screen {
            screen.render(bytes);
        }
        CONSOLE.with(|console| console.borrow_mut().push((self.0, bytes.to_vec())));
    }

    fn read(&mut self, buffer: usize, into: &mut [u8]) -> Result<(), u32> {
        Self::check(buffer)?;
        // SAFETY: the test's buffer of `into.len()` bytes.
        let bytes = unsafe { core::slice::from_raw_parts(buffer as *const u8, into.len()) };
        into.copy_from_slice(bytes);
        Ok(())
    }

    fn write(&mut self, buffer: usize, bytes: &[u8]) -> Result<(), u32> {
        Self::check(buffer)?;
        // SAFETY: the test's buffer of `bytes.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, bytes.len()) };
        Ok(())
    }

    /// The stand-in's one handle stands for the input-wait event.
    fn input_wait_handle(&mut self) -> Result<u32, u32> {
        Ok(HANDLE)
    }
}

/// CsrClientCallServer over `rtl::console`'s rules, as the kernel serves them: the data words
/// the length names answered in place, the ReturnValue returned. Of the base server's calls
/// (`rtl::console::base`), a new process's announcement is accepted and the shutdown level and
/// flags are kept (or left) as the kernel's server keeps them.
pub unsafe extern "system" fn CsrClientCallServer(
    message: *mut crate::nt::ApiMessage,
    capture_buffer: *mut u8,
    api: u32,
    length: u32,
) -> u32 {
    use rtl::console::base;
    // SAFETY: the caller's message.
    let message = unsafe { &mut *message };
    if api >> 16 == base::BASE_SERVER {
        let [level, flags, ..] = &mut message.data;
        let status = match api {
            base::SET_PROCESS_SHUTDOWN_PARAM => {
                let (level, flags) = (*level as u32, *flags as u32);
                if base::shutdown_parameters_kept(flags) {
                    SHUTDOWN_PARAMETERS.with(|kept| kept.set((level, flags)));
                }
                0
            }
            base::GET_PROCESS_SHUTDOWN_PARAM => {
                let (kept_level, kept_flags) = SHUTDOWN_PARAMETERS.with(Cell::get);
                (*level, *flags) = (kept_level as _, kept_flags as _);
                0
            }
            _ => 0,
        };
        message.capture_buffer = capture_buffer as usize;
        message.api_number = api;
        message.return_value = status;
        return status;
    }
    let mut handles = CONSOLE_HANDLES.with(Cell::get);
    let status = CONSOLE_STATE.with(|console| {
        rtl::console::serve(
            &mut console.borrow_mut(),
            &mut handles,
            &mut Client(message.data[0] as u32),
            api,
            &mut message.data,
            length as usize,
        )
    });
    CONSOLE_HANDLES.with(|cell| cell.set(handles));
    message.capture_buffer = capture_buffer as usize;
    message.api_number = api;
    message.return_value = status;
    status
}
