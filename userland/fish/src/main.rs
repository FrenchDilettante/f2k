//! fish.exe (FiSH, the Fine SHell): sets the graphics mode through user32's
//! ChangeDisplaySettingsA, then runs the program its command line names and ends with that
//! program's exit code, so a GUI test's boot runs `fish.exe <program>` and its exit-code line
//! reports the program.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

exe::entry!(main);

fn main() -> u32 {
    let Some(child) = fish::child_command_line(exe::command_line_a()) else {
        let _ = exe::stderr().print(format_args!("fish: usage: fish.exe <program>\r\n"));
        return fish::USAGE;
    };
    // The child's command line, NUL-terminated in a buffer CreateProcess may write.
    let mut buffer = [0u8; exe::MAX_PATH];
    let Some(mut line) = exe::CommandLine::new(&mut buffer, child) else {
        let _ = exe::stderr().print(format_args!("fish: the command line is too long\r\n"));
        return fish::USAGE;
    };
    // The graphics mode, as a Windows 2000 program asks for one.
    let (width, height, bits) = fish::MODE;
    if let Err(code) = exe::change_display_mode(width, height, bits) {
        let _ = exe::stderr().print(format_args!(
            "fish: the graphics mode cannot be set (DISP_CHANGE {code})\r\n"
        ));
        return fish::NO_GRAPHICS;
    }
    let name = core::str::from_utf8(child).unwrap_or("(not ASCII)");
    let child = match exe::create_child(&mut line) {
        Ok(child) => child,
        Err(error) => {
            let _ =
                exe::stderr().print(format_args!("fish: {name} cannot be started ({error})\r\n"));
            return fish::NO_CHILD;
        }
    };
    match child.wait_exit_code() {
        Ok(code) => fish::exit_code(code),
        Err(error) => {
            let _ = exe::stderr().print(format_args!("fish: the child's exit code: {error}\r\n"));
            fish::NO_CHILD
        }
    }
}
