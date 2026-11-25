//! The control flow's host tests: lines run against a fake shell ([`Shell`]) that records each
//! simple command as it would run (its escapes resolved, its redirections taken out, its loop
//! variables replaced). The expectations are Windows 2000's, from the captures of
//! tests/cmd/batflow, batforq and batops (their `%%` single here, as a batch file's line reads
//! once expanded).

use std::collections::BTreeMap;

use super::{run_line, Flow, Host, BLOCK};
use crate::flow::repeat::{self, Scope};
use crate::syntax::{self, Redirections, Syntax};
use crate::testing::{narrow, wide};
use crate::{State, Variables};

/// The current directory of [`crate::flow::tests::Fake`].
const CURRENT: &str = "C:\\F2K";

/// A fake shell. A simple command's text is recorded in `ran`; its first word says what it does:
/// `code N` returns N (a program exiting with it), `goto` goes to a label, `exitb` ends the batch
/// file, anything else returns 0.
struct Shell {
    environment: crate::flow::tests::Fake,
    ran: Vec<String>,
    echoed: Vec<String>,
    printed: String,
    reported: String,
    /// The directories' entries: a directory's full path, a name, its attributes.
    entries: Vec<(String, String, u32)>,
    /// `for /f`'s files, by their name upper-cased, and the lines of each.
    files: BTreeMap<String, Vec<String>>,
    /// The lines each command `for /f` runs writes.
    commands: BTreeMap<String, Vec<String>>,
    /// The pass at which Ctrl+C is pressed, counted from 0.
    interrupt: Option<usize>,
    passes: usize,
}

impl Shell {
    fn new() -> Shell {
        Shell {
            environment: crate::flow::tests::Fake::new(&[("BATFLOWN", "xxx")], &[]),
            ran: Vec::new(),
            echoed: Vec::new(),
            printed: String::new(),
            reported: String::new(),
            entries: Vec::new(),
            files: BTreeMap::new(),
            commands: BTreeMap::new(),
            interrupt: None,
            passes: 0,
        }
    }

    /// A file (or with `attributes`' 0x10, a directory) at `path`, relative to the current
    /// directory unless it starts with a drive.
    fn entry(mut self, path: &str, attributes: u32) -> Shell {
        let full = full(path);
        let (directory, name) = full.rsplit_once('\\').unwrap();
        self.entries
            .push((directory.to_string(), name.to_string(), attributes));
        self
    }

    fn file(mut self, name: &str, lines: &[&str]) -> Shell {
        self.files.insert(
            name.to_uppercase(),
            lines.iter().map(|line| line.to_string()).collect(),
        );
        self
    }

    fn command(mut self, command: &str, lines: &[&str]) -> Shell {
        self.commands.insert(
            command.to_string(),
            lines.iter().map(|line| line.to_string()).collect(),
        );
        self
    }

    /// `line` run as typed (no batch file around it), echo off.
    fn run(&mut self, line: &str) -> Flow {
        let mut state = State {
            echo: false,
            ..State::default()
        };
        self.run_in(line, &mut state)
    }

    fn run_in(&mut self, line: &str, state: &mut State) -> Flow {
        run_line(&wide(line), state, self, None)
    }
}

/// `path`'s full path, as the fake's current directory makes it.
fn full(path: &str) -> String {
    let path = path.trim_end_matches('\\');
    if path.get(1..2) == Some(":") {
        path.to_string()
    } else if path.is_empty() {
        CURRENT.to_string()
    } else {
        format!("{CURRENT}\\{path}")
    }
}

/// Whether `name` matches the wildcard `mask` (`*` and `?`), whatever the case.
fn matches(mask: &[char], name: &[char]) -> bool {
    match mask.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|at| matches(rest, &name[at..])),
        Some(('?', rest)) => !name.is_empty() && matches(rest, &name[1..]),
        Some((unit, rest)) => name
            .split_first()
            .is_some_and(|(first, after)| first.eq_ignore_ascii_case(unit) && matches(rest, after)),
    }
}

impl Host for Shell {
    fn variables(&mut self) -> &mut dyn Variables {
        &mut self.environment
    }

    fn simple(&mut self, text: &[u16], state: &mut State, scope: Option<&Scope<'_>>) -> Flow {
        let mut buffer = vec![0; crate::LINE];
        let mut list = Redirections::default();
        let line = syntax::simple(text, &mut buffer, &mut list).expect("a command that fits");
        let mut bound = vec![0; BLOCK];
        let line = repeat::bind(line, scope, &mut self.environment, &mut bound).unwrap();
        // Blanks and `@`s before the command are the command's own to skip (cmd::parse's).
        let line = narrow(line)
            .trim_start_matches([' ', '\t', '\n', '@'])
            .to_string();
        let mut words = line.split_whitespace();
        let flow = match words.next() {
            Some("code") => {
                state.ended(words.next().unwrap().parse().unwrap());
                Flow::Next
            }
            Some("goto") => Flow::Goto,
            Some("exitb") => Flow::EndBatch,
            _ => {
                state.return_code = 0;
                Flow::Next
            }
        };
        self.ran.push(line);
        flow
    }

    fn pipeline(&mut self, text: &[u16], _state: &mut State, _scope: Option<&Scope<'_>>) -> Flow {
        self.ran.push(format!("pipeline: {}", narrow(text)));
        Flow::Next
    }

    fn group(
        &mut self,
        inner: &[u16],
        redirections: &[u16],
        state: &mut State,
        scope: Option<&Scope<'_>>,
    ) -> Flow {
        if !crate::trim(redirections).is_empty() {
            self.ran
                .push(format!("group redirected: {}", narrow(redirections).trim()));
        }
        run_line(inner, state, self, scope)
    }

    /// As in a batch file: the error reported, every batch file ended.
    fn malformed(&mut self, error: Syntax<'_>, _state: &mut State) -> Flow {
        self.reported.push_str(&error.to_string());
        Flow::Abort
    }

    fn echo(&mut self, command: &[u16], _spaced: bool) {
        self.echoed.push(narrow(command));
    }

    fn print(&mut self, text: std::fmt::Arguments<'_>) {
        self.printed.push_str(&text.to_string());
    }

    fn report(&mut self, text: std::fmt::Arguments<'_>) {
        self.reported.push_str(&text.to_string());
    }

    fn interrupted(&mut self) -> bool {
        let pass = self.passes;
        self.passes += 1;
        self.interrupt == Some(pass)
    }

    fn exists(&mut self, name: &[u16]) -> bool {
        let full = full(&narrow(name)).to_uppercase();
        self.entries
            .iter()
            .any(|(directory, entry, _)| format!("{directory}\\{entry}").to_uppercase() == full)
    }

    fn defined(&mut self, name: &[u16]) -> bool {
        let mut value = [0; 1];
        !matches!(self.environment.get(name, &mut value), Ok(None))
    }

    fn find(
        &mut self,
        pattern: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16], u32) -> Flow,
    ) -> Flow {
        let pattern = narrow(pattern);
        let (directory, mask) = pattern.rsplit_once('\\').unwrap_or(("", &pattern));
        let directory = full(directory).to_uppercase();
        let mask: Vec<char> = mask.chars().collect();
        let found: Vec<(String, u32)> = self
            .entries
            .iter()
            .filter(|(within, name, _)| {
                within.to_uppercase() == directory
                    && matches(&mask, &name.chars().collect::<Vec<_>>())
            })
            .map(|(_, name, attributes)| (name.clone(), *attributes))
            .collect();
        for (name, attributes) in found {
            match each(self, &wide(&name), attributes) {
                Flow::Next => {}
                flow => return flow,
            }
        }
        Flow::Next
    }

    fn directory<'b>(
        &mut self,
        root: &[u16],
        buffer: &'b mut [u16; super::MAX_PATH],
    ) -> Option<&'b [u16]> {
        let path = wide(&full(&narrow(root)));
        buffer[..path.len()].copy_from_slice(&path);
        Some(&buffer[..path.len()])
    }

    fn file_lines(
        &mut self,
        name: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16]) -> Flow,
    ) -> Option<Flow> {
        let lines = self.files.get(&narrow(name).to_uppercase())?.clone();
        for line in lines {
            match each(self, &wide(&line)) {
                Flow::Next => {}
                flow => return Some(flow),
            }
        }
        Some(Flow::Next)
    }

    fn command_lines(
        &mut self,
        command: &[u16],
        each: &mut dyn FnMut(&mut Self, &[u16]) -> Flow,
    ) -> Flow {
        let lines = self
            .commands
            .get(&narrow(command))
            .cloned()
            .unwrap_or_default();
        for line in lines {
            match each(self, &wide(&line)) {
                Flow::Next => {}
                flow => return flow,
            }
        }
        Flow::Next
    }
}

/// What `line` runs in a fresh shell.
fn ran(line: &str) -> Vec<String> {
    let mut shell = Shell::new();
    assert_eq!(shell.run(line), Flow::Next);
    shell.ran
}

// The operators (batops).

#[test]
fn and_then_runs_after_success_only() {
    assert_eq!(
        ran("code 0 && echo and-then after exit 0"),
        ["code 0 ", "echo and-then after exit 0"]
    );
    assert_eq!(ran("code 3 && echo and-then after exit 3"), ["code 3 "]);
}

#[test]
fn or_else_runs_after_failure_only() {
    assert_eq!(
        ran("code 3 || echo or-else after exit 3"),
        ["code 3 ", "echo or-else after exit 3"]
    );
    assert_eq!(ran("code 0 || echo or-else after exit 0"), ["code 0 "]);
}

#[test]
fn or_else_binds_looser_than_and_then() {
    // batops: `spawnkid exit 3 && echo ... || echo or-else after the and-then`.
    assert_eq!(
        ran("code 3 && echo and-then || echo or-else after the and-then"),
        ["code 3 ", "echo or-else after the and-then"]
    );
}

#[test]
fn always_runs_the_next_command_whatever_the_first_returned() {
    let mut shell = Shell::new();
    let mut state = State::default();
    state.echo = false;
    shell.run_in("code 3 & echo always", &mut state);
    assert_eq!(shell.ran, ["code 3 ", "echo always"]);
    assert_eq!(state.errorlevel, 3);
    assert_eq!(state.return_code, 0);
}

#[test]
fn a_pipeline_is_handed_whole_to_the_shell() {
    assert_eq!(
        ran("code 3 | code 5 & echo after"),
        ["pipeline: code 3 | code 5 ", "echo after"]
    );
}

#[test]
fn escaped_operators_are_text() {
    assert_eq!(
        ran("echo a ^& b ^| c ^> d ^< e"),
        ["echo a & b | c > d < e"]
    );
    assert_eq!(ran("echo caret ^^"), ["echo caret ^"]);
    assert_eq!(ran("echo \"a ^& b\""), ["echo \"a ^& b\""]);
}

// Groups (batflow's `echo )`).

#[test]
fn a_group_runs_its_commands_and_a_caret_keeps_its_parenthesis() {
    assert_eq!(
        ran("(echo one line & echo ^))"),
        ["echo one line ", "echo )"]
    );
    assert_eq!(
        ran("(\necho inside a block\necho ^)\n)"),
        ["echo inside a block", "echo )"]
    );
}

#[test]
fn a_parenthesis_outside_a_group_is_text() {
    assert_eq!(ran("echo )"), ["echo )"]);
    assert_eq!(ran("echo a ) b"), ["echo a ) b"]);
}

#[test]
fn a_group_s_redirections_apply_to_it() {
    assert_eq!(
        ran("(echo a & echo b) > out.txt"),
        ["group redirected: > out.txt", "echo a ", "echo b"]
    );
}

// if (batflow).

#[test]
fn if_s_command_takes_the_rest_of_the_line() {
    assert_eq!(ran("if a==a echo x & echo y"), ["echo x ", "echo y"]);
    assert_eq!(ran("if a==b echo x & echo y"), Vec::<String>::new());
}

#[test]
fn if_exist_with_else() {
    let line = "if exist batflow.cmd (echo exists) else echo missing";
    let mut shell = Shell::new().entry("batflow.cmd", 0x20);
    shell.run(line);
    assert_eq!(shell.ran, ["echo exists"]);
    assert_eq!(ran(line), ["echo missing"]);
}

#[test]
fn if_not_exist_with_blocks_over_several_lines() {
    assert_eq!(
        ran("if not exist batflow-nope.cmd (\n  echo not there\n\n  echo two lines\n) else (\n  echo never\n)"),
        ["echo not there", "echo two lines"]
    );
}

#[test]
fn if_nested_with_i_and_gtr() {
    assert_eq!(
        ran("if /i ABC==abc if 10 GTR 9 echo nested"),
        ["echo nested"]
    );
}

#[test]
fn if_defined_with_else() {
    assert_eq!(
        ran("if defined BATFLOWN (echo defined) else echo undefined"),
        ["echo defined"]
    );
    assert_eq!(
        ran("if defined BATFLOWZ (echo defined) else echo undefined"),
        ["echo undefined"]
    );
}

#[test]
fn if_errorlevel_reads_the_shell_s_errorlevel() {
    // batflow: after `exit /b 4`, `if errorlevel 4 echo four or more` prints.
    let mut shell = Shell::new();
    let mut state = State {
        echo: false,
        errorlevel: 4,
        ..State::default()
    };
    shell.run_in("if errorlevel 4 echo four or more", &mut state);
    state.errorlevel = 3;
    shell.run_in("if errorlevel 4 echo never", &mut state);
    assert_eq!(shell.ran, ["echo four or more"]);
}

#[test]
fn if_cmdextversion() {
    assert_eq!(
        ran("if cmdextversion 2 echo extensions"),
        ["echo extensions"]
    );
}

#[test]
fn an_if_in_parentheses_takes_its_else_after_the_group() {
    assert_eq!(
        ran("if 1==1 (echo in an if: ^)) else echo never"),
        ["echo in an if: )"]
    );
}

#[test]
fn a_help_switch_prints_the_help_and_returns_1() {
    let mut shell = Shell::new();
    let mut state = State {
        echo: false,
        errorlevel: 5,
        ..State::default()
    };
    shell.run_in("if /?", &mut state);
    assert!(shell.printed.contains("IF [NOT] ERRORLEVEL number command"));
    assert_eq!((state.return_code, state.errorlevel), (1, 5));
    assert!(shell.ran.is_empty());
}

#[test]
fn a_header_that_cannot_be_read_is_malformed() {
    let mut shell = Shell::new();
    assert_eq!(shell.run("if a echo x"), Flow::Abort);
    assert!(shell.ran.is_empty());
    assert!(!shell.reported.is_empty());
}

// for (batflow).

#[test]
fn for_over_a_list_runs_its_command_once_for_each_item() {
    assert_eq!(
        ran("for %a in (a b) do call :sub %a"),
        ["call :sub a", "call :sub b"]
    );
}

#[test]
fn for_s_items_are_separated_as_a_command_s_arguments_are() {
    // `for /?`: the set's items are separated by blanks, commas, semicolons and equal signs; a
    // quoted item keeps them.
    assert_eq!(
        ran("for %a in (a,b;c=d \"e f\") do echo [%a]"),
        [
            "echo [a]",
            "echo [b]",
            "echo [c]",
            "echo [d]",
            "echo [\"e f\"]"
        ]
    );
    assert!(ran("for %a in () do echo never").is_empty());
}

#[test]
fn for_s_command_takes_the_operators_after_it() {
    // batflow: `cmd /c for %%a in (1 2) do @echo %%a ^& echo end`.
    assert_eq!(
        ran("for %a in (1 2) do @echo %a & echo end"),
        ["echo 1 ", "echo end", "echo 2 ", "echo end"]
    );
}

#[test]
fn for_l_counts_by_its_step() {
    assert_eq!(
        ran("for /l %i in (1,2,5) do echo l%i"),
        ["echo l1", "echo l3", "echo l5"]
    );
    assert_eq!(
        ran("for /l %i in (3,-2,-3) do echo %i"),
        ["echo 3", "echo 1", "echo -1", "echo -3"]
    );
}

#[test]
fn for_f_over_a_string_cuts_its_tokens() {
    assert_eq!(
        ran("for /f \"tokens=1,3* delims=,\" %a in (\"x,y,z,w,v\") do echo f [%a] [%b] [%c]"),
        ["echo f [x] [z] [w,v]"]
    );
}

#[test]
fn for_s_variable_takes_path_modifiers() {
    assert_eq!(
        ran("for %f in (batflow.cmd) do echo %~nxf %~xf"),
        ["echo batflow.cmd .cmd"]
    );
}

#[test]
fn for_f_over_a_command_s_output() {
    let mut shell = Shell::new().command("echo piped out", &["piped out"]);
    shell.run("for /f %v in ('echo piped out') do echo command [%v]");
    assert_eq!(shell.ran, ["echo command [piped]"]);
}

/// batflow's `batflow.d`: two files, and a directory holding one.
fn names() -> Shell {
    Shell::new()
        .entry("batflow.d\\.", 0x10)
        .entry("batflow.d\\..", 0x10)
        .entry("batflow.d\\one.txt", 0x20)
        .entry("batflow.d\\three.dat", 0x20)
        .entry("batflow.d\\sub", 0x10)
        .entry("batflow.d\\sub\\two.txt", 0x20)
}

fn ran_over_names(line: &str) -> Vec<String> {
    let mut shell = names();
    shell.run(line);
    shell.ran
}

#[test]
fn for_over_wildcards() {
    assert_eq!(
        ran_over_names("for %f in (batflow.d\\*.txt) do echo wildcard [%f]"),
        ["echo wildcard [batflow.d\\one.txt]"]
    );
    assert!(ran_over_names("for %f in (batflow.d\\*.none) do echo never: [%f]").is_empty());
    assert_eq!(
        ran_over_names("for %f in (batflow.d\\nosuch.txt) do echo no wildcard [%f]"),
        ["echo no wildcard [batflow.d\\nosuch.txt]"]
    );
    assert_eq!(
        ran_over_names("for %f in (batflow.d\\*.txt;batflow.d\\*.dat) do echo two patterns [%f]"),
        [
            "echo two patterns [batflow.d\\one.txt]",
            "echo two patterns [batflow.d\\three.dat]"
        ]
    );
}

#[test]
fn for_leaves_out_hidden_and_system_files() {
    let mut shell = Shell::new()
        .entry("h.txt", 0x22)
        .entry("s.txt", 0x24)
        .entry("v.txt", 0x20);
    shell.run("for %f in (*.txt) do echo [%f]");
    assert_eq!(shell.ran, ["echo [v.txt]"]);
}

#[test]
fn for_d_matches_directories_only() {
    assert_eq!(
        ran_over_names("for /d %d in (batflow.d\\s*) do echo directory [%d]"),
        ["echo directory [batflow.d\\sub]"]
    );
    assert!(ran_over_names("for /d %d in (batflow.d\\*.txt) do echo never: [%d]").is_empty());
    assert!(ran_over_names("for /d %d in (batflow.d\\.*) do echo never: [%d]").is_empty());
}

#[test]
fn for_r_walks_a_directory_before_those_below_it() {
    assert_eq!(
        ran_over_names("for /r batflow.d %f in (*.txt) do echo recursive [%~nxf]"),
        ["echo recursive [one.txt]", "echo recursive [two.txt]"]
    );
    assert_eq!(
        ran_over_names(
            "for /r batflow.d %f in (two.txt) do if exist \"%f\" (echo [%~nxf]: exists) else echo [%~nxf]: missing"
        ),
        ["echo [two.txt]: missing", "echo [two.txt]: exists"]
    );
}

/// batflow's `batflow.txt`.
fn batflow_txt() -> Shell {
    let lines = [
        "header line",
        "#a comment",
        "one two",
        "",
        ";semicolon",
        "three",
    ];
    Shell::new()
        .file("batflow.txt", &lines)
        .file("batflow d.txt", &lines)
        .command("echo back quoted", &["back quoted"])
}

fn ran_over_lines(line: &str) -> Vec<String> {
    let mut shell = batflow_txt();
    shell.run(line);
    shell.ran
}

#[test]
fn for_f_over_a_file() {
    assert_eq!(
        ran_over_lines("for /f %a in (batflow.txt) do echo default [%a]"),
        [
            "echo default [header]",
            "echo default [#a]",
            "echo default [one]",
            "echo default [three]"
        ]
    );
    assert_eq!(
        ran_over_lines("for /f \"skip=1\" %a in (batflow.txt) do echo skip=1 [%a]"),
        [
            "echo skip=1 [#a]",
            "echo skip=1 [one]",
            "echo skip=1 [three]"
        ]
    );
    assert_eq!(
        ran_over_lines("for /f \"eol=# tokens=*\" %a in (batflow.txt) do echo eol=# [%a]"),
        [
            "echo eol=# [header line]",
            "echo eol=# [one two]",
            "echo eol=# [;semicolon]",
            "echo eol=# [three]"
        ]
    );
    assert_eq!(
        ran_over_lines("for /f \"tokens=2\" %a in (batflow.txt) do echo tokens=2 [%a]"),
        [
            "echo tokens=2 [line]",
            "echo tokens=2 [comment]",
            "echo tokens=2 [two]"
        ]
    );
}

#[test]
fn for_f_usebackq() {
    assert_eq!(
        ran_over_lines(
            "for /f \"usebackq skip=2\" %a in (\"batflow d.txt\") do echo usebackq file [%a]"
        ),
        ["echo usebackq file [one]", "echo usebackq file [three]"]
    );
    assert_eq!(
        ran_over_lines(
            "for /f \"usebackq\" %a in (`echo back quoted`) do echo usebackq command [%a]"
        ),
        ["echo usebackq command [back]"]
    );
    assert_eq!(
        ran_over_lines(
            "for /f \"usebackq\" %a in ('a literal string') do echo usebackq string [%a]"
        ),
        ["echo usebackq string [a]"]
    );
}

#[test]
fn for_f_over_a_file_that_does_not_exist_reports_it_twice_and_keeps_the_errorlevel() {
    let mut shell = batflow_txt();
    let mut state = State {
        echo: false,
        errorlevel: 7,
        ..State::default()
    };
    shell.run_in(
        "for /f %a in (batflow-nope.txt) do echo never: [%a]",
        &mut state,
    );
    assert!(shell.ran.is_empty());
    assert_eq!(
        shell.reported,
        "The system cannot find the file ??.\r\nThe system cannot find the file batflow-nope.txt.\r\n"
    );
    assert_eq!(state.errorlevel, 7);
}

// A for's values are text, never syntax (batforq).

#[test]
fn file_names_holding_operators_are_text() {
    let mut shell = Shell::new()
        .entry("a&b.txt", 0x20)
        .entry("c (1).txt", 0x20)
        .entry("d^e.txt", 0x20)
        .entry("f%g.txt", 0x20);
    shell.run("for %f in (a*.txt) do echo [%f]");
    shell.run("for %f in (c*.txt) do echo [%f]");
    shell.run("for %f in (d*.txt) do echo [%f]");
    shell.run("for %f in (f*.txt) do echo [%f]");
    shell.run("for %f in (c*.txt) do (echo [%f])");
    shell.run("for %f in (a*.txt) do (echo [%f] & echo [%~nf] [%~xf])");
    shell.run("for %f in (c*.txt) do if exist %f echo exists: [%f]");
    shell.run("for %f in (a*.txt) do if exist \"%f\" (echo exists: [%f]) else echo missing: [%f]");
    assert_eq!(
        shell.ran,
        [
            "echo [a&b.txt]",
            "echo [c (1).txt]",
            "echo [d^e.txt]",
            "echo [f%g.txt]",
            "echo [c (1).txt]",
            "echo [a&b.txt] ",
            "echo [a&b] [.txt]",
            "echo exists: [c (1).txt]",
            "echo exists: [a&b.txt]",
        ]
    );
}

#[test]
fn a_redirection_in_for_s_command_is_its_own() {
    let mut shell = Shell::new().entry("a.txt", 0x20).entry("b.txt", 0x20);
    shell.run("for %f in (*.txt) do set /a BATFORQN+=1 > nul");
    assert_eq!(shell.ran, ["set /a BATFORQN+=1 ", "set /a BATFORQN+=1 "]);
}

/// batforq's `batforq.txt`: lines holding the operators.
const INJECTING: [&str; 8] = [
    "a & echo INJECTED",
    "b | echo INJECTED",
    "c > batforq.out",
    "d < batforq.txt",
    "e (f) g )",
    "h ^ i ^& echo INJECTED",
    "\")\" j & echo INJECTED",
    "k %PATH% l",
];

#[test]
fn lines_holding_operators_are_text() {
    let mut shell = Shell::new()
        .file("batforq.txt", &INJECTING)
        .command("type batforq.txt", &INJECTING);
    shell.run("for /f \"delims=\" %a in (batforq.txt) do echo [%a]");
    shell.run("for /f \"delims=\" %a in (batforq.txt) do (echo [%a])");
    shell.run("for /f \"delims=\" %a in ('type batforq.txt') do echo [%a]");
    let once: Vec<String> = INJECTING
        .iter()
        .map(|line| format!("echo [{line}]"))
        .collect();
    assert_eq!(shell.ran, [once.clone(), once.clone(), once].concat());
}

#[test]
fn fields_holding_operators_are_text() {
    let mut shell = Shell::new().file(
        "batforq.csv",
        &[
            "a & echo INJECTED,b | echo INJECTED",
            "(c),d)",
            "e > batforq.out,f ^ g",
            "\"h & i\",j & echo INJECTED",
        ],
    );
    shell.run("for /f \"tokens=1,2 delims=,\" %a in (batforq.csv) do echo [%a] [%b]");
    shell.run("for /f \"tokens=1* delims=&\" %a in (\"x & echo INJECTED & y\") do echo [%a] [%b]");
    assert_eq!(
        shell.ran,
        [
            "echo [a & echo INJECTED] [b | echo INJECTED]",
            "echo [(c)] [d)]",
            "echo [e > batforq.out] [f ^ g]",
            "echo [\"h & i\"] [j & echo INJECTED]",
            "echo [x ] [ echo INJECTED & y]",
        ]
    );
}

#[test]
fn a_nested_for_s_set_is_bound_to_the_outer_loop() {
    assert_eq!(
        ran("for %a in (\"x y\") do for %b in (%~a) do echo nested: [%b]"),
        ["echo nested: [x]", "echo nested: [y]"]
    );
}

#[test]
fn a_nested_for_s_command_sees_both_loops_variables() {
    assert_eq!(
        ran("for %a in (1 2) do for %b in (x y) do echo %a%b"),
        ["echo 1x", "echo 1y", "echo 2x", "echo 2y"]
    );
}

#[test]
fn an_if_reads_its_words_before_the_values_replace_them() {
    // batforq's ifempty, ifblank and ifamp (shallow-gui-cmd finding 20's example).
    assert_eq!(
        ran("for %a in (\"\") do if not %~a==x echo an empty value: not x"),
        ["echo an empty value: not x"]
    );
    assert_eq!(
        ran("for /f \"delims=\" %a in (\"a b\") do if %a==x (echo a b: x) else echo a b: not x"),
        ["echo a b: not x"]
    );
    assert_eq!(
        ran("for /f \"delims=\" %a in (\"a & b\") do if \"%a\"==\"a & b\" echo quoted: equal"),
        ["echo quoted: equal"]
    );
    assert_eq!(
        ran("for /f \"delims=\" %a in (\"a & b\") do if %a==x (echo unquoted: x) else echo unquoted: not x"),
        ["echo unquoted: not x"]
    );
}

// How a loop ends, and what it echoes.

#[test]
fn goto_in_a_for_s_command_leaves_the_loop() {
    let mut shell = Shell::new();
    assert_eq!(shell.run("for %a in (a b c) do goto %a"), Flow::Goto);
    assert_eq!(shell.ran, ["goto a"]);
}

#[test]
fn exit_b_in_a_for_f_s_command_ends_the_batch_file() {
    let mut shell = Shell::new().file("x.txt", &["1", "2"]);
    assert_eq!(
        shell.run("for /f %a in (x.txt) do exitb %a & echo never"),
        Flow::EndBatch
    );
    assert_eq!(shell.ran, ["exitb 1 "]);
}

#[test]
fn ctrl_c_ends_the_loop_before_its_next_pass() {
    let mut shell = Shell::new();
    shell.interrupt = Some(1);
    assert_eq!(shell.run("for /l %i in (1,1,5) do echo %i"), Flow::Abort);
    assert_eq!(shell.ran, ["echo 1"]);
}

#[test]
fn the_loop_returns_its_last_command_s_code() {
    let mut shell = Shell::new();
    let mut state = State {
        echo: false,
        ..State::default()
    };
    shell.run_in("for %a in (0 3) do code %a", &mut state);
    assert_eq!((state.return_code, state.errorlevel), (3, 3));
}

#[test]
fn each_pass_is_echoed_with_its_values_while_echo_is_on() {
    let mut shell = Shell::new();
    let mut state = State::default();
    shell.run_in("for %a in (1 2) do echo [%a]", &mut state);
    assert_eq!(shell.echoed, ["echo [1]", "echo [2]"]);
    assert_eq!(shell.ran, ["echo [1]", "echo [2]"]);
}
