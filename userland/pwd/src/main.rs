//! pwd.exe: prints the current directory, then CR LF, and ends with 0. When the directory cannot
//! be read or the line cannot be written, it says so on the standard error and ends with
//! [`pwd::FAILED`], the standard output left empty.

#![no_std]
#![no_main]
#![forbid(unsafe_code)]

exe::entry!(main);

fn main() -> u32 {
    let mut buffer = [0; exe::MAX_PATH];
    let directory = match exe::current_directory(&mut buffer) {
        Ok(directory) => directory,
        Err(error) => {
            let _ = exe::stderr().print(format_args!(
                "pwd: the current directory cannot be read ({error})\r\n"
            ));
            return pwd::FAILED;
        }
    };
    if let Err(error) = exe::stdout().print(format_args!("{}", pwd::Line(directory))) {
        let _ = exe::stderr().print(format_args!(
            "pwd: the standard output cannot be written ({error})\r\n"
        ));
        return pwd::FAILED;
    }
    0
}
