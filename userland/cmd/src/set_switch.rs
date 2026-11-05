//! `set /a` and `set /p` run, as cmd::arith reads them: the expression evaluated over the
//! environment's variables, and a line read into a variable from the standard input (the
//! console's line, or a file's or a pipe's).

use cmd::arith::{self, Switch};
use cmd::batch::LineReader;

/// `set`'s `argument` run when it starts with `/a` or `/p`: whether it did (otherwise it is one of
/// `set`'s other forms). `in_batch` when its line comes from a batch file, where `set /a` prints
/// nothing.
pub fn run(argument: &[u16], state: &mut cmd::State, in_batch: bool) -> bool {
    match arith::switch(argument) {
        None => return false,
        Some(Switch::Arithmetic(expression)) => arithmetic(expression, state, in_batch),
        Some(Switch::Prompt { name, prompt }) => prompt_for(name, prompt, state),
        Some(Switch::Incorrect) => {
            let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
            state.failed();
        }
    }
    true
}

/// The environment's variables, as `set /a` reads and assigns them.
struct Environment;

impl arith::Variables for Environment {
    /// The variable's value read as a number; one too long to read is 0, as no number is that
    /// long.
    #[inline(never)]
    fn value(&mut self, name: &[u16]) -> i32 {
        let mut value = [0; cmd::LINE];
        match exe::environment_variable(name, &mut value) {
            Ok(Some(value)) => arith::number_in(value),
            _ => 0,
        }
    }

    fn assign(&mut self, name: &[u16], value: i32) -> Result<(), u32> {
        let mut buffer = [0; 11];
        exe::set_environment_variable(name, Some(arith::decimal(value, &mut buffer)))
            .map_err(|exe::Error(code)| code)
    }
}

/// `set /a expression`: evaluated, its assignments made; its value printed, without a line
/// break, unless the line comes from a batch file (`set /?`: only at the command line). An
/// expression that cannot be evaluated prints why on the standard error, and leaves the
/// ERRORLEVEL its error has.
#[inline(never)]
fn arithmetic(expression: &[u16], state: &mut cmd::State, in_batch: bool) {
    match arith::evaluate(expression, &mut Environment) {
        Ok(value) => {
            if !in_batch {
                let _ = exe::stdout().print(format_args!("{value}"));
            }
        }
        Err(arith::Error::Environment(code)) => {
            report(exe::Error(code));
            state.failed();
        }
        Err(error) => {
            if let Some(text) = error.text() {
                let _ = exe::stderr().print(format_args!("{text}"));
            }
            state.ended(error.errorlevel());
        }
    }
}

/// `set /p name=prompt`: the prompt printed as it is, with no line break, then a line read from
/// the standard input into the variable, its line break dropped. An empty line, or none (the
/// input's end, or Ctrl+C at the console), leaves the variable as it is and fails, the
/// ERRORLEVEL 1.
#[inline(never)]
fn prompt_for(name: &[u16], prompt: &[u16], state: &mut cmd::State) {
    let _ = exe::stdout().print(format_args!("{}", cmd::Text(prompt)));
    let mut units = [0; cmd::LINE];
    match answer(&mut units) {
        Ok([]) => state.failed(),
        Ok(value) => {
            if let Err(error) = exe::set_environment_variable(name, Some(value)) {
                report(error);
                state.failed();
            }
        }
        Err(error) => {
            report(error);
            state.failed();
        }
    }
}

/// The line the standard input gives, without its line break, in `units`: the console's line, or
/// a file's or a pipe's (OEM bytes up to LF, a CR before it dropped), read a byte at a time so that
/// what follows the line stays for the shell, or a program, to read. Empty when there is none.
fn answer(units: &mut [u16]) -> Result<&[u16], exe::Error> {
    if exe::standard_input_is_console() {
        return match exe::read_line(units)? {
            exe::Input::Line(line) => Ok(cmd::without_break(line)),
            exe::Input::Aborted => {
                // The console leaves the abandoned line as it echoed it: what follows goes below.
                let _ = exe::stdout().print(format_args!("\r\n"));
                Ok(&[])
            }
            exe::Input::End => Ok(&[]),
        };
    }
    let mut reader = LineReader::default();
    let mut bytes = [0; cmd::MAX_LINE];
    let mut read = |buffer: &mut [u8]| {
        let byte = buffer.len().min(1);
        exe::read_standard_input(&mut buffer[..byte])
    };
    match reader.next_line(&mut read, &mut bytes)? {
        Some(line) => exe::oem_to_wide(line, units),
        None => Ok(&[]),
    }
}

/// A Win32 error, on the standard error: Windows 2000's text when the shell has one.
fn report(exe::Error(code): exe::Error) {
    let _ = match cmd::message(code) {
        Some(text) => exe::stderr().print(format_args!("{text}")),
        None => exe::stderr().print(format_args!("cmd: error {code}\r\n")),
    };
}
