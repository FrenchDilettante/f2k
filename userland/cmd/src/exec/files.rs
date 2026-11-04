//! The file built-ins run: `del`, `md`, `rd`, `copy`, `ren` and `move`, over kernel32's file calls
//! (exe's src/files.rs). Each helper holds the path buffers it needs and is not inlined, so that a
//! directory walk's frames stay small.

use cmd::builtins::files::{
    self as rules,
    Answer,
    AreYouSure,
    Attributes,
    CopyFile,
    CouldNotFind,
    DeleteFile,
    DeleteSwitches,
    Deleted,
    Mode,
    RemoveSwitches,
    Tokens,
    DIRECTORY,
    ERROR_ALREADY_EXISTS,
    ERROR_FILENAME_EXCED_RANGE,
    ERROR_FILE_EXISTS,
    ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND,
    READONLY,
};
use cmd::Text;
use exe::MAX_PATH;

use super::{ask, ask_overwrite, report, wide};

/// FILE_ATTRIBUTE_NORMAL: the attributes of a file left with none.
const NORMAL: u32 = 0x80;

/// The pattern that matches every file of a directory.
const STAR: &[u16] = &[b'*' as u16];

/// The error a path too long for a buffer is.
const TOO_LONG: exe::Error = exe::Error(ERROR_FILENAME_EXCED_RANGE);

/// `name` without its quotes, in `out`.
fn unquoted<'a>(name: &[u16], out: &'a mut [u16; MAX_PATH]) -> Result<&'a [u16], exe::Error> {
    cmd::program_name(name, out).ok_or(TOO_LONG)
}

/// `directory` and `name` joined, in `out`.
fn joined<'a>(
    directory: &[u16],
    name: &[u16],
    out: &'a mut [u16; MAX_PATH],
) -> Result<&'a [u16], exe::Error> {
    rules::join(directory, name, out).ok_or(TOO_LONG)
}

/// Whether `path` names a directory: it says so itself (`sub\`, `..`), or a directory goes by it.
fn is_directory(path: &[u16]) -> bool {
    rules::names_directory(path)
        || exe::attributes(path).is_ok_and(|attributes| attributes & DIRECTORY != 0)
}

/// Whether a file (not a directory) goes by `path`.
fn file_exists(path: &[u16]) -> bool {
    exe::attributes(path).is_ok_and(|attributes| attributes & DIRECTORY == 0)
}

/// The standard error's line for a path, then the error met on it (a file `del` could not delete).
fn report_on(path: &[u16], error: exe::Error) {
    let _ = exe::stderr().print(format_args!("{}\r\n", Text(path)));
    report(error);
}

// --- del -----------------------------------------------------------------------------------------

/// `del` (or `erase`): the files each name matches deleted (see [`delete_name`]). Without a name,
/// or with a switch it does not take, it fails. Otherwise it sets the ERRORLEVEL to 0, and returns
/// 1 when a name matched nothing or a file stayed.
pub fn delete(argument: &[u16], state: &mut cmd::State) {
    let switches = match rules::delete_switches(argument) {
        Ok(switches) => switches,
        Err(invalid) => {
            let _ = exe::stderr().print(format_args!("{invalid}"));
            return state.failed();
        }
    };
    let mut any = false;
    let mut failed = false;
    for name in Tokens::new(argument, false).names() {
        any = true;
        if !delete_name(name, &switches) {
            failed = true;
        }
    }
    if !any {
        let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
        return state.failed();
    }
    state.errorlevel = 0;
    if failed {
        state.return_code = 1;
    }
}

/// The files `name` matches deleted: a directory's every file (`dir` is `dir\*`), else the files
/// its last component matches, wildcards and all, through the subdirectories with `/S`. Before
/// deleting every file of a directory, `del` asks, unless `/Q`; a name that matches nothing prints
/// `Could Not Find` and its full path. Whether every file it matched was deleted.
#[inline(never)]
fn delete_name(name: &[u16], switches: &DeleteSwitches) -> bool {
    let mut buffer = [0; MAX_PATH];
    let mut every_file = [0; MAX_PATH];
    let path = match unquoted(name, &mut buffer) {
        Ok(path) => path,
        Err(error) => {
            report(error);
            return false;
        }
    };
    let whole_directory = !rules::has_wildcards(path) && is_directory(path);
    let pattern = if whole_directory {
        match joined(path, STAR, &mut every_file) {
            Ok(pattern) => pattern,
            Err(error) => {
                report(error);
                return false;
            }
        }
    } else {
        path
    };
    let (directory, file) = rules::split(pattern);
    let mut full = [0; MAX_PATH];
    let full = exe::full_path(pattern, &mut full).unwrap_or(pattern);
    if !switches.quiet && (whole_directory || rules::matches_all(file)) && !ask(AreYouSure(full)) {
        return true;
    }
    let mut found = false;
    let deleted = if switches.subdirectories {
        delete_tree(directory, file, switches, &mut found)
    } else {
        delete_in(directory, file, switches, &mut found)
    };
    if !found {
        let _ = exe::stderr().print(format_args!("{}", CouldNotFind(full)));
        return false;
    }
    deleted
}

/// The files in `directory` that `file` matches, and that the attributes select, deleted; `found`
/// set when there is one. Whether each was.
#[inline(never)]
fn delete_in(directory: &[u16], file: &[u16], switches: &DeleteSwitches, found: &mut bool) -> bool {
    let mut buffer = [0; MAX_PATH];
    let files = match joined(directory, file, &mut buffer).map(exe::find) {
        Ok(Ok(files)) => files,
        // Nothing matches here.
        Ok(Err(_)) => return true,
        Err(error) => {
            report(error);
            return false;
        }
    };
    let mut deleted = true;
    for entry in files {
        if !switches.attributes.selects(entry.attributes) {
            continue;
        }
        *found = true;
        if !delete_one(directory, entry.name(), entry.attributes, switches) {
            deleted = false;
        }
    }
    deleted
}

/// [`delete_in`] in `directory`, then in each of its subdirectories, theirs, and so on (`/S`).
#[inline(never)]
fn delete_tree(
    directory: &[u16],
    file: &[u16],
    switches: &DeleteSwitches,
    found: &mut bool,
) -> bool {
    let mut deleted = delete_in(directory, file, switches, found);
    let mut buffer = [0; MAX_PATH];
    let Ok(Ok(entries)) = joined(directory, STAR, &mut buffer).map(exe::find) else {
        return deleted;
    };
    for entry in entries {
        if entry.attributes & DIRECTORY == 0 || rules::is_dots(entry.name()) {
            continue;
        }
        let mut sub = [0; MAX_PATH];
        let walked = joined(directory, entry.name(), &mut sub)
            .map(|sub| delete_tree(sub, file, switches, found));
        if walked != Ok(true) {
            deleted = false;
        }
    }
    deleted
}

/// The file `name` in `directory` deleted: asked about first with `/P`; refused when it is
/// read-only, unless `/F`; printed once deleted with `/S`. Whether it was deleted (or left by the
/// answer N).
#[inline(never)]
fn delete_one(directory: &[u16], name: &[u16], attributes: u32, switches: &DeleteSwitches) -> bool {
    let mut buffer = [0; MAX_PATH];
    let path = match joined(directory, name, &mut buffer) {
        Ok(path) => path,
        Err(error) => {
            report(error);
            return false;
        }
    };
    let mut full = [0; MAX_PATH];
    let full = exe::full_path(path, &mut full).unwrap_or(path);
    if switches.prompt && !ask(DeleteFile(full)) {
        return true;
    }
    if attributes & READONLY != 0 {
        if !switches.force {
            report_on(full, exe::Error(5));
            return false;
        }
        let kept = attributes & !(READONLY | DIRECTORY);
        if let Err(error) = exe::set_attributes(path, if kept == 0 { NORMAL } else { kept }) {
            report_on(full, error);
            return false;
        }
    }
    match exe::delete_file(path) {
        Ok(()) => {
            if switches.subdirectories {
                let _ = exe::stdout().print(format_args!("{}", Deleted(full)));
            }
            true
        }
        Err(error) => {
            report_on(full, error);
            false
        }
    }
}

// --- md ------------------------------------------------------------------------------------------

/// `md` (or `mkdir`): a directory created for each name, with the directories above it that do
/// not exist (command extensions). A name already taken prints `A subdirectory or file ... already
/// exists.`; any failure fails the command.
pub fn make_directories(argument: &[u16], state: &mut cmd::State) {
    if let Err(invalid) = rules::no_switches(argument) {
        let _ = exe::stderr().print(format_args!("{invalid}"));
        return state.failed();
    }
    let mut any = false;
    for name in Tokens::new(argument, false).names() {
        any = true;
        if !make_directory(name) {
            state.failed();
        }
    }
    if !any {
        let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
        state.failed();
    }
}

/// Whether `unit` separates a path's directories.
fn is_slash(unit: u16) -> bool {
    unit == u16::from(b'\\') || unit == u16::from(b'/')
}

/// The directory `name` names created, with the directories above it: whether it was.
#[inline(never)]
fn make_directory(name: &[u16]) -> bool {
    let mut buffer = [0; MAX_PATH];
    let path = match unquoted(name, &mut buffer) {
        Ok(path) => path,
        Err(error) => {
            report(error);
            return false;
        }
    };
    // A trailing separator names the same directory (a root's stays).
    let mut path = path;
    while path.len() > 1
        && path.last().copied().is_some_and(is_slash)
        && path[path.len() - 2] != u16::from(b':')
    {
        path = &path[..path.len() - 1];
    }
    let mut result = exe::create_directory(path);
    if result == Err(exe::Error(ERROR_PATH_NOT_FOUND)) {
        // Each directory above it, from the top, created when it is missing; a failure shows as
        // the last one's.
        for (index, _) in path.iter().enumerate().filter(|&(index, &unit)| {
            index > 0
                && is_slash(unit)
                && path[index - 1] != u16::from(b':')
                && !is_slash(path[index - 1])
        }) {
            let _ = exe::create_directory(&path[..index]);
        }
        result = exe::create_directory(path);
    }
    match result {
        Ok(()) => true,
        Err(exe::Error(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS)) => {
            let _ = exe::stderr().print(format_args!("{}", rules::AlreadyExists(path)));
            false
        }
        Err(error) => {
            report(error);
            false
        }
    }
}

// --- rd ------------------------------------------------------------------------------------------

/// `rd` (or `rmdir`): each directory named removed, with what it holds with `/S` (after asking,
/// unless `/Q`). Any failure fails the command.
pub fn remove_directories(argument: &[u16], state: &mut cmd::State) {
    let switches = match rules::remove_switches(argument) {
        Ok(switches) => switches,
        Err(invalid) => {
            let _ = exe::stderr().print(format_args!("{invalid}"));
            return state.failed();
        }
    };
    let mut any = false;
    for name in Tokens::new(argument, false).names() {
        any = true;
        if !remove_directory(name, &switches) {
            state.failed();
        }
    }
    if !any {
        let _ = exe::stderr().print(format_args!("{}", cmd::SYNTAX));
        state.failed();
    }
}

/// The directory `name` names removed: whether it was (or kept by the answer N).
#[inline(never)]
fn remove_directory(name: &[u16], switches: &RemoveSwitches) -> bool {
    let mut buffer = [0; MAX_PATH];
    let path = match unquoted(name, &mut buffer) {
        Ok(path) => path,
        Err(error) => {
            report(error);
            return false;
        }
    };
    if switches.tree {
        if !switches.quiet && !ask(AreYouSure(path)) {
            return true;
        }
        return remove_tree(path, true);
    }
    match exe::remove_directory(path) {
        Ok(()) => true,
        Err(error) => {
            report(error);
            false
        }
    }
}

/// The directory `path` removed with everything in it, read-only files included: whether it was.
/// Each failure is reported, the directory's own only when `report_self` and nothing in it failed.
#[inline(never)]
fn remove_tree(path: &[u16], report_self: bool) -> bool {
    let mut removed = true;
    let mut buffer = [0; MAX_PATH];
    if let Ok(Ok(entries)) = joined(path, STAR, &mut buffer).map(exe::find) {
        for entry in entries {
            if rules::is_dots(entry.name()) {
                continue;
            }
            let mut child = [0; MAX_PATH];
            let child = match joined(path, entry.name(), &mut child) {
                Ok(child) => child,
                Err(error) => {
                    report(error);
                    removed = false;
                    continue;
                }
            };
            if entry.attributes & DIRECTORY != 0 {
                removed &= remove_tree(child, true);
                continue;
            }
            if entry.attributes & READONLY != 0 {
                let _ = exe::set_attributes(child, NORMAL);
            }
            if let Err(error) = exe::delete_file(child) {
                report(error);
                removed = false;
            }
        }
    }
    if let Err(error) = exe::remove_directory(path) {
        if removed && report_self {
            report(error);
        }
        return false;
    }
    removed
}

// --- copy ----------------------------------------------------------------------------------------

/// Whether `copy` or `move` asks before replacing a file: `/Y` or `/-Y` say, else the COPYCMD
/// variable's, else it asks at the prompt and not in a batch file (`copy /?`).
#[inline(never)]
fn asks(overwrite: Option<bool>, in_batch: bool) -> bool {
    let preset = overwrite.or_else(|| {
        let mut name = [0; 7];
        let mut value = [0; cmd::LINE];
        match exe::environment_variable(wide("COPYCMD", &mut name), &mut value) {
            Ok(Some(value)) => rules::copycmd(value),
            _ => None,
        }
    });
    !preset.unwrap_or(in_batch)
}

/// What a `copy` has done so far.
struct Copying {
    /// Whether to replace files without asking: no question, or All answered.
    replace_all: bool,
    /// The files written.
    copied: usize,
    /// Whether anything failed.
    failed: bool,
}

/// `copy`: each source copied to its destination, or the sources joined into one file, as
/// `copy /?` says (see [`rules::copy`]). The files written are counted (`N file(s) copied.`);
/// anything that fails fails the command.
pub fn copy(argument: &[u16], state: &mut cmd::State, in_batch: bool) {
    let parsed = match rules::copy(argument) {
        Ok(parsed) => parsed,
        Err(invalid) => {
            let _ = exe::stderr().print(format_args!("{invalid}"));
            return state.failed();
        }
    };
    let mut copying = Copying {
        replace_all: !asks(parsed.overwrite, in_batch),
        copied: 0,
        failed: false,
    };
    copy_files(&parsed, &mut copying);
    let _ = exe::stdout().print(format_args!("{}", rules::Copied(copying.copied)));
    if copying.failed {
        state.failed();
    }
}

/// [`copy`]'s work: its destination found (the current directory without one, or, for joined
/// sources, the first source), then each file copied, or the files joined.
#[inline(never)]
fn copy_files(parsed: &rules::Copy<'_>, copying: &mut Copying) {
    let first = parsed.sources()[0];
    let mut source = [0; MAX_PATH];
    let mut destination = [0; MAX_PATH];
    let paths = unquoted(first.name, &mut source).and_then(|source| {
        let destination = match parsed.destination {
            Some(file) => unquoted(file.name, &mut destination)?,
            None if parsed.joined => source,
            None => wide(".", &mut destination),
        };
        Ok((source, destination))
    });
    let (source, destination) = match paths {
        Ok(paths) => paths,
        Err(error) => {
            report(error);
            copying.failed = true;
            return;
        }
    };
    let to_directory = is_directory(destination);
    let destination_mode = parsed.destination.and_then(|file| file.mode);
    if parsed.joined {
        let mut target = [0; MAX_PATH];
        let target = if to_directory {
            joined(destination, rules::split(source).1, &mut target)
        } else {
            Ok(destination)
        };
        match target {
            Ok(target) => join_files(parsed.sources(), target, destination_mode, copying),
            Err(error) => {
                report(error);
                copying.failed = true;
            }
        }
        return;
    }
    // A directory's files: `copy dir x` is `copy dir\* x`.
    let mut pattern = [0; MAX_PATH];
    let (pattern, wildcards) = if !rules::has_wildcards(source) && is_directory(source) {
        match joined(source, STAR, &mut pattern) {
            Ok(pattern) => (pattern, true),
            Err(error) => {
                report(error);
                copying.failed = true;
                return;
            }
        }
    } else {
        (source, rules::has_wildcards(source))
    };
    if wildcards && !to_directory && !rules::has_wildcards(destination) {
        // Several files into one: joined.
        let file = CopyFile {
            name: pattern,
            mode: first.mode,
        };
        return join_files(
            core::slice::from_ref(&file),
            destination,
            destination_mode,
            copying,
        );
    }
    let modes = (first.mode(false), destination_mode.unwrap_or(Mode::Binary));
    copy_each(
        pattern,
        wildcards,
        destination,
        to_directory,
        modes,
        copying,
    );
}

/// Each file `pattern` matches copied: into the directory `destination` under its own name, or to
/// the name `destination`'s wildcards give it, or to `destination` itself. With `wildcards`, each
/// file's name is printed before it is copied.
#[inline(never)]
fn copy_each(
    pattern: &[u16],
    wildcards: bool,
    destination: &[u16],
    to_directory: bool,
    modes: (Mode, Mode),
    copying: &mut Copying,
) {
    let (directory, _) = rules::split(pattern);
    let files = match exe::find(pattern) {
        Ok(files) => files,
        Err(error) => {
            report(not_found(error));
            copying.failed = true;
            return;
        }
    };
    let mut any = false;
    for entry in files {
        if !Attributes::DEFAULT.selects(entry.attributes) {
            continue;
        }
        any = true;
        let mut from = [0; MAX_PATH];
        let mut to = [0; MAX_PATH];
        let mut renamed = [0; MAX_PATH];
        let paths = joined(directory, entry.name(), &mut from).and_then(|from| {
            let to = if to_directory {
                joined(destination, entry.name(), &mut to)?
            } else if rules::has_wildcards(destination) {
                let (into, mask) = rules::split(destination);
                let name =
                    rules::rename_target(entry.name(), mask, &mut renamed).ok_or(TOO_LONG)?;
                joined(into, name, &mut to)?
            } else {
                destination
            };
            Ok((from, to))
        });
        match paths {
            Ok((from, to)) => {
                if wildcards {
                    let _ = exe::stdout().print(format_args!("{}\r\n", Text(from)));
                }
                copy_one(from, to, modes, copying);
            }
            Err(error) => {
                report(error);
                copying.failed = true;
            }
        }
    }
    if !any {
        report(exe::Error(ERROR_FILE_NOT_FOUND));
        copying.failed = true;
    }
}

/// FindFirstFileW's errors for a name matching nothing, as `copy` reports them: a file not found.
fn not_found(error: exe::Error) -> exe::Error {
    match error.0 {
        rules::ERROR_NO_MORE_FILES => exe::Error(ERROR_FILE_NOT_FOUND),
        _ => error,
    }
}

/// The file `from` copied to `to`, in the modes given (the source's, the destination's): refused
/// when it is the file itself, asked about when `to` exists (unless every file is replaced).
#[inline(never)]
fn copy_one(from: &[u16], to: &[u16], (from_mode, to_mode): (Mode, Mode), copying: &mut Copying) {
    let mut full_from = [0; MAX_PATH];
    let mut full_to = [0; MAX_PATH];
    let full_from = exe::full_path(from, &mut full_from).unwrap_or(from);
    let full_to = exe::full_path(to, &mut full_to).unwrap_or(to);
    if rules::same_path(full_from, full_to) {
        let _ = exe::stderr().print(format_args!("{}", rules::ONTO_ITSELF));
        copying.failed = true;
        return;
    }
    if !copying.replace_all && file_exists(to) {
        match ask_overwrite(full_to) {
            Answer::No => return,
            Answer::All => copying.replace_all = true,
            Answer::Yes => {}
        }
    }
    let copied = if (from_mode, to_mode) == (Mode::Binary, Mode::Binary) {
        exe::copy_file(from, to, false)
    } else {
        exe::create_file(to, false).and_then(|output| {
            append(from, from_mode, &output)?;
            end(&output, to_mode)
        })
    };
    match copied {
        Ok(()) => copying.copied += 1,
        Err(error) => {
            report(error);
            copying.failed = true;
        }
    }
}

/// The file `from`'s bytes written to `output`: in ASCII mode, those before its first Ctrl+Z.
#[inline(never)]
fn append(from: &[u16], mode: Mode, output: &exe::OutputFile) -> Result<(), exe::Error> {
    let file = exe::open_file(from)?;
    let mut buffer = [0u8; 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        let bytes = &buffer[..read];
        if mode == Mode::Ascii {
            if let Some(end) = bytes.iter().position(|&byte| byte == rules::END_OF_FILE) {
                return output.write(&bytes[..end]);
            }
        }
        output.write(bytes)?;
    }
}

/// A destination written in ASCII mode ended with a Ctrl+Z.
fn end(output: &exe::OutputFile, mode: Mode) -> Result<(), exe::Error> {
    match mode {
        Mode::Ascii => output.write(&[rules::END_OF_FILE]),
        Mode::Binary => Ok(()),
    }
}

/// The files each of `sources` matches joined into `target`, each one's name printed: one file
/// written. The first source, when it is the target itself (`copy a+b`), is appended to; any other
/// source that is the target is skipped. Asked about when the target exists, unless every file is
/// replaced. A source mode defaults to ASCII, and so does the target's.
#[inline(never)]
fn join_files(
    sources: &[CopyFile<'_>],
    target: &[u16],
    target_mode: Option<Mode>,
    copying: &mut Copying,
) {
    let mut full_target = [0; MAX_PATH];
    let full_target = exe::full_path(target, &mut full_target).unwrap_or(target);
    let mut output: Option<exe::OutputFile> = None;
    for (index, source) in sources.iter().enumerate() {
        let mut path = [0; MAX_PATH];
        let path = match unquoted(source.name, &mut path) {
            Ok(path) => path,
            Err(error) => {
                report(error);
                copying.failed = true;
                continue;
            }
        };
        let (directory, _) = rules::split(path);
        let Ok(files) = exe::find(path) else {
            continue;
        };
        for entry in files {
            if !Attributes::DEFAULT.selects(entry.attributes) {
                continue;
            }
            let mut from = [0; MAX_PATH];
            let Ok(from) = joined(directory, entry.name(), &mut from) else {
                report(TOO_LONG);
                copying.failed = true;
                continue;
            };
            let mut full_from = [0; MAX_PATH];
            let full_from = exe::full_path(from, &mut full_from).unwrap_or(from);
            let itself = rules::same_path(full_from, full_target);
            if itself && (index > 0 || output.is_some()) {
                continue;
            }
            let _ = exe::stdout().print(format_args!("{}\r\n", Text(from)));
            if itself {
                match exe::create_file(target, true) {
                    Ok(file) => output = Some(file),
                    Err(error) => return failed(error, copying),
                }
                continue;
            }
            if output.is_none() {
                if !copying.replace_all && file_exists(target) {
                    match ask_overwrite(full_target) {
                        Answer::No => return,
                        Answer::All => copying.replace_all = true,
                        Answer::Yes => {}
                    }
                }
                match exe::create_file(target, false) {
                    Ok(file) => output = Some(file),
                    Err(error) => return failed(error, copying),
                }
            }
            if let Some(output) = &output {
                if let Err(error) = append(from, source.mode(true), output) {
                    report(error);
                    copying.failed = true;
                }
            }
        }
    }
    let Some(output) = output else {
        report(exe::Error(ERROR_FILE_NOT_FOUND));
        copying.failed = true;
        return;
    };
    match end(&output, target_mode.unwrap_or(Mode::Ascii)) {
        Ok(()) => copying.copied += 1,
        Err(error) => failed(error, copying),
    }
}

/// An error that stops a copy: reported, the copy failed.
fn failed(error: exe::Error, copying: &mut Copying) {
    report(error);
    copying.failed = true;
}

// --- ren -----------------------------------------------------------------------------------------

/// `ren` (or `rename`): each file or directory the first name matches renamed in its directory, to
/// the second name, or to the name its wildcards give (see [`rules::rename_target`]). A first name
/// matching nothing prints that the file cannot be found; a new name taken prints `A duplicate
/// file name exists, or the file cannot be found.`. Any failure fails the command.
#[inline(never)]
pub fn rename(argument: &[u16], state: &mut cmd::State) {
    let (from, to) = match rules::rename(argument) {
        Ok(names) => names,
        Err(invalid) => {
            let _ = exe::stderr().print(format_args!("{invalid}"));
            return state.failed();
        }
    };
    let mut source = [0; MAX_PATH];
    let mut mask = [0; MAX_PATH];
    let (source, mask) = match unquoted(from, &mut source)
        .and_then(|source| Ok((source, unquoted(to, &mut mask)?)))
    {
        Ok(names) => names,
        Err(error) => {
            report(error);
            return state.failed();
        }
    };
    let files = match exe::find(source) {
        Ok(files) => files,
        Err(error) => {
            report(not_found(error));
            return state.failed();
        }
    };
    let (directory, _) = rules::split(source);
    for entry in files {
        if rules::is_dots(entry.name()) {
            continue;
        }
        if !rename_one(directory, entry.name(), mask) {
            state.failed();
        }
    }
}

/// The file `name` in `directory` renamed to what `mask` gives it: whether it was.
#[inline(never)]
fn rename_one(directory: &[u16], name: &[u16], mask: &[u16]) -> bool {
    let mut new_name = [0; MAX_PATH];
    let mut from = [0; MAX_PATH];
    let mut to = [0; MAX_PATH];
    let paths = joined(directory, name, &mut from).and_then(|from| {
        let new_name = if rules::has_wildcards(mask) {
            rules::rename_target(name, mask, &mut new_name).ok_or(TOO_LONG)?
        } else {
            mask
        };
        Ok((from, joined(directory, new_name, &mut to)?))
    });
    let result = paths.and_then(|(from, to)| exe::move_file(from, to, false));
    match result {
        Ok(()) => true,
        Err(exe::Error(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS)) => {
            let _ = exe::stderr().print(format_args!("{}", rules::DUPLICATE));
            false
        }
        Err(error) => {
            report(error);
            false
        }
    }
}

// --- move ----------------------------------------------------------------------------------------

/// `move`: each file or directory the sources name moved into the destination directory, or
/// renamed to the destination; a file it would replace asked about first unless `/Y` (or in a
/// batch file). With wildcards, which move files alone, each file's full path is printed once
/// moved. Any failure fails the command.
pub fn move_files(argument: &[u16], state: &mut cmd::State, in_batch: bool) {
    let parsed = match rules::move_arguments(argument) {
        Ok(parsed) => parsed,
        Err(invalid) => {
            let _ = exe::stderr().print(format_args!("{invalid}"));
            return state.failed();
        }
    };
    let mut replace_all = !asks(parsed.overwrite, in_batch);
    let mut destination = [0; MAX_PATH];
    let destination = match unquoted(parsed.destination(), &mut destination) {
        Ok(destination) => destination,
        Err(error) => {
            report(error);
            return state.failed();
        }
    };
    let to_directory = is_directory(destination);
    for source in parsed.sources() {
        if !move_source(source, destination, to_directory, &mut replace_all) {
            state.failed();
        }
    }
}

/// The files and directories `source` matches moved (see [`move_files`]): whether each was.
#[inline(never)]
fn move_source(
    source: &[u16],
    destination: &[u16],
    to_directory: bool,
    replace_all: &mut bool,
) -> bool {
    let mut path = [0; MAX_PATH];
    let found = unquoted(source, &mut path).and_then(|path| Ok((path, exe::find(path)?)));
    let (path, files) = match found {
        Ok(found) => found,
        Err(error) => {
            report(not_found(error));
            return false;
        }
    };
    let wildcards = rules::has_wildcards(path);
    let (directory, _) = rules::split(path);
    let mut moved = 0;
    let mut all_moved = true;
    for entry in files {
        if rules::is_dots(entry.name()) || wildcards && entry.attributes & DIRECTORY != 0 {
            continue;
        }
        if moved > 0 && !to_directory {
            let _ = exe::stderr().print(format_args!("{}", rules::MULTIPLE));
            return false;
        }
        match move_one(
            directory,
            entry.name(),
            destination,
            to_directory,
            wildcards,
            replace_all,
        ) {
            Some(true) => moved += 1,
            Some(false) => {}
            None => all_moved = false,
        }
    }
    all_moved
}

/// The file `name` in `directory` moved: Some(true) when it was, Some(false) when the answer No
/// kept it, None when it failed.
#[inline(never)]
fn move_one(
    directory: &[u16],
    name: &[u16],
    destination: &[u16],
    to_directory: bool,
    print: bool,
    replace_all: &mut bool,
) -> Option<bool> {
    let mut from = [0; MAX_PATH];
    let mut to = [0; MAX_PATH];
    let paths = joined(directory, name, &mut from).and_then(|from| {
        let to = if to_directory {
            joined(destination, name, &mut to)?
        } else {
            destination
        };
        Ok((from, to))
    });
    let (from, to) = match paths {
        Ok(paths) => paths,
        Err(error) => {
            report(error);
            return None;
        }
    };
    let replace = file_exists(to);
    if replace && !*replace_all {
        let mut full = [0; MAX_PATH];
        match ask_overwrite(exe::full_path(to, &mut full).unwrap_or(to)) {
            Answer::No => return Some(false),
            Answer::All => *replace_all = true,
            Answer::Yes => {}
        }
    }
    if let Err(error) = exe::move_file(from, to, replace) {
        report(error);
        return None;
    }
    if print {
        let mut full = [0; MAX_PATH];
        let shown = exe::full_path(from, &mut full).unwrap_or(from);
        let _ = exe::stdout().print(format_args!("{}\r\n", Text(shown)));
    }
    Some(true)
}
