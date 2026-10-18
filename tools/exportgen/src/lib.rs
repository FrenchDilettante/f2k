//! exportgen: the system DLLs' export specs, and everything generated from them.
//!
//! Each system DLL's exports are declared once, in `userland/<dll>/exports.toml` (the file's own
//! header documents its records). This crate reads a spec ([`load`]), checks it, and emits what
//! derives from it ([`emit`]):
//!
//! - for the kernel (through its build script): the service dispatch table, and the native exports'
//!   and the DLL's exports' argument blocks (the kernel's tests check the built DLLs against them);
//! - for the system DLL builds (userland/build-support/stubs.rs): each DLL's service stubs (the
//!   gate-raising bodies of the exports the kernel serves), its module-definition (`.def`) file,
//!   and the kernel ABI constants its assembly uses ([`abi`]).
//!
//! The kernel-served exports are the transitional Win32 services (the kernel's kernel32 surface,
//! which later work moves to user mode group by group), numbered from [`WIN32_SERVICE_BASE`], a
//! service table Windows 2000 does not have (its table index 2): ExitProcess is the base plus 1;
//! the other served exports follow in case-insensitive name order. Both the kernel's registry and
//! the stubs come from here, so the two sides agree by construction.
//!
//! The specs are TOML read through [`toml`], a strict reader for the subset they are written in.

pub mod abi;
pub mod emit;
pub mod toml;

use std::path::Path;

use toml::{Table, Value};

/// One DLL's spec.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    /// The API groups, in file order.
    pub groups: Vec<Group>,
    /// The exports, in file order.
    pub exports: Vec<Export>,
}

/// An API group: the unit the ledger reports by.
#[derive(Clone, Debug, PartialEq)]
pub struct Group {
    pub key: String,
    pub title: String,
}

/// One export.
#[derive(Clone, Debug, PartialEq)]
pub struct Export {
    pub name: String,
    pub group: String,
    /// The prototype's arguments, first (lowest address) first.
    pub args: Vec<Arg>,
    pub implementation: Implementation,
    /// The export ordinal, once known from the platform's own table.
    pub ordinal: Option<u16>,
    /// The failure return value (`0`, `FALSE`, `INVALID_HANDLE_VALUE`, `-1`).
    pub fails: Option<String>,
    /// A fact worth keeping beside the export.
    pub note: Option<String>,
    /// The fixture blocks pinning the export's behavior: `<fixture>/<section>`, or `<fixture>/*`
    /// for every block of the fixture.
    pub pinned_by: Vec<String>,
    /// The host scenarios pinning it (test function names).
    pub scenarios: Vec<String>,
    /// Why an implemented export has no evidence yet (the report lists it as unpinned).
    pub unpinned: Option<String>,
    /// An F2K-internal entry point (the kernel's own calls into user mode), not a Windows 2000
    /// export: the ledger leaves it out of the platform's counts.
    pub internal: bool,
}

/// One prototype argument.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg {
    pub kind: ArgKind,
    pub name: String,
}

/// An argument's kind: what the caller pushes (the argument block derives from it), and what the
/// argument is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// A dword value: a count, flags, a code address (`u32`).
    U32,
    /// A signed dword: a count where -1 means "up to the terminator" (`i32`).
    I32,
    /// A Win32 BOOL: nonzero is true (`bool`).
    Bool,
    /// A handle value (`handle`).
    Handle,
    /// A pointer into caller memory, untyped (`ptr`).
    Ptr,
    /// A pointer to one value of `Pointee` in caller memory (`ptr<u32>`).
    PtrTo(Pointee),
    /// A quadword passed by value (two dwords, low first) (`u64`).
    U64,
    /// A NUL-terminated string the call reads: narrow (`strA`) or wide (`strW`), NULL allowed
    /// when optional (`strA?`), and the platform's limit on its length in units, the terminator
    /// included, when it has one (`strA[260]`). Without a limit the string is bounded only by the
    /// caller's memory.
    Str {
        wide: bool,
        optional: bool,
        limit: Option<u32>,
    },
}

/// What a typed pointer points to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pointee {
    U8,
    U16,
    U32,
    I32,
    U64,
}

impl Pointee {
    fn word(self) -> &'static str {
        match self {
            Pointee::U8 => "u8",
            Pointee::U16 => "u16",
            Pointee::U32 => "u32",
            Pointee::I32 => "i32",
            Pointee::U64 => "u64",
        }
    }

    fn parse(word: &str) -> Option<Pointee> {
        Some(match word {
            "u8" => Pointee::U8,
            "u16" => Pointee::U16,
            "u32" => Pointee::U32,
            "i32" => Pointee::I32,
            "u64" => Pointee::U64,
            _ => return None,
        })
    }
}

impl ArgKind {
    /// The bytes the caller pushes.
    pub fn bytes(self) -> u32 {
        match self {
            ArgKind::U64 => 8,
            _ => 4,
        }
    }

    /// Parse the kind word of an argument: `u32`, `i32`, `bool`, `handle`, `ptr`, `ptr<T>`, `u64`,
    /// or a string `strA`/`strW` with an optional `?` and an optional `[limit]`.
    pub fn parse(word: &str) -> Option<ArgKind> {
        Some(match word {
            "u32" => ArgKind::U32,
            "i32" => ArgKind::I32,
            "bool" => ArgKind::Bool,
            "handle" => ArgKind::Handle,
            "ptr" => ArgKind::Ptr,
            "u64" => ArgKind::U64,
            _ => {
                if let Some(inner) = word.strip_prefix("ptr<").and_then(|w| w.strip_suffix('>')) {
                    return Pointee::parse(inner).map(ArgKind::PtrTo);
                }
                let wide = match word.get(..4) {
                    Some("strA") => false,
                    Some("strW") => true,
                    _ => return None,
                };
                let mut rest = &word[4..];
                let optional = rest.starts_with('?');
                if optional {
                    rest = &rest[1..];
                }
                let limit = if rest.is_empty() {
                    None
                } else {
                    let digits = rest.strip_prefix('[')?.strip_suffix(']')?;
                    let limit: u32 = digits.parse().ok()?;
                    if limit == 0 {
                        return None;
                    }
                    Some(limit)
                };
                ArgKind::Str {
                    wide,
                    optional,
                    limit,
                }
            }
        })
    }

    fn word(self) -> String {
        match self {
            ArgKind::U32 => "u32".into(),
            ArgKind::I32 => "i32".into(),
            ArgKind::Bool => "bool".into(),
            ArgKind::Handle => "handle".into(),
            ArgKind::Ptr => "ptr".into(),
            ArgKind::PtrTo(pointee) => format!("ptr<{}>", pointee.word()),
            ArgKind::U64 => "u64".into(),
            ArgKind::Str {
                wide,
                optional,
                limit,
            } => format!(
                "str{}{}{}",
                if wide { "W" } else { "A" },
                if optional { "?" } else { "" },
                limit.map(|n| format!("[{n}]")).unwrap_or_default()
            ),
        }
    }
}

/// The first transitional Win32 service's number, less one: the services Windows 2000 does not have,
/// in the gate's table index 2 (`(EAX >> 12) & 3`), which Windows 2000 leaves empty.
pub const WIN32_SERVICE_BASE: u32 = 0x2000;

/// How an export is implemented.
#[derive(Clone, Debug, PartialEq)]
pub enum Implementation {
    /// Served by the kernel through a handler on the raw argument block, `fn(&mut TrapFrame,
    /// &[u32])` (its path in `compat::kernel32`'s scope): one of the kernel's served exports, until
    /// its group moves to user mode.
    Legacy(String),
    /// Runs in user mode: the body's name.
    Native(String),
    /// Forwarded to another module's export (`NTDLL.RtlUnwind`).
    Forward(String),
    /// A deliberate fixed answer (zero, from the kernel's shared floor handler), and why.
    Floor(String),
    /// Not implemented, and why it is listed: the DLL does not export it yet.
    Unimplemented(String),
}

impl Implementation {
    /// Whether the kernel serves the export as a transitional Win32 service (it has a number from
    /// [`WIN32_SERVICE_BASE`]).
    pub fn is_served(&self) -> bool {
        matches!(self, Implementation::Legacy(_) | Implementation::Floor(_))
    }
}

/// The handler the floors share.
pub const FLOOR_HANDLER: &str = "svc_floor_zero";

impl Export {
    /// The argument block the export's callers push and its body pops (stdcall).
    pub fn arg_bytes(&self) -> u32 {
        self.args.iter().map(|arg| arg.kind.bytes()).sum()
    }

    /// The kernel handler its registry entry names, for a served export: its legacy handler, or the
    /// floors' handler.
    pub fn handler(&self) -> Option<String> {
        match &self.implementation {
            Implementation::Legacy(path) => Some(path.clone()),
            Implementation::Floor(_) => Some(FLOOR_HANDLER.to_string()),
            _ => None,
        }
    }

    /// The value it returns on failure (`fails`), as a dword.
    pub fn fail_value(&self) -> Option<u32> {
        self.fails
            .as_deref()
            .map(|text| fail_value(text).expect("a loaded spec's fails values parse"))
    }
}

/// A `fails` value: an integer (decimal, `-1`, or `0x` hex), one of the platform's named failure
/// returns, or `void` / `never` (the function returns nothing / cannot fail; the register is 0).
pub fn fail_value(text: &str) -> Option<u32> {
    Some(match text {
        "FALSE" | "NULL" | "void" | "never" => 0,
        "INVALID_HANDLE_VALUE"
        | "WAIT_FAILED"
        | "INVALID_FILE_SIZE"
        | "INVALID_SET_FILE_POINTER"
        | "INVALID_FILE_ATTRIBUTES"
        | "TLS_OUT_OF_INDEXES" => 0xFFFF_FFFF,
        _ => {
            if let Some(hex) = text.strip_prefix("0x") {
                u32::from_str_radix(&hex.replace('_', ""), 16).ok()?
            } else if let Some(negative) = text.strip_prefix('-') {
                negative.parse::<u32>().ok()?.wrapping_neg()
            } else {
                text.parse().ok()?
            }
        }
    })
}

/// The kernel's transitional service registry over every DLL's spec: the served exports in
/// service-number order (number = [`WIN32_SERVICE_BASE`] + position + 1; ExitProcess first, then
/// case-insensitive name order).
pub fn registry<'a>(specs: &[&'a Spec]) -> Vec<&'a Export> {
    let mut served: Vec<&Export> = specs
        .iter()
        .flat_map(|spec| spec.exports.iter())
        .filter(|e| e.implementation.is_served())
        .collect();
    served.sort_by_key(|e| (e.name != "ExitProcess", e.name.to_ascii_lowercase()));
    served
}

/// The system DLLs' specs, checked together: `(dll, spec)` pairs, the DLL named as its module
/// (`kernel32`, `ntdll`). A served export is served once across them (the registry names it once),
/// and a forward names an export of a listed DLL with the same prototype.
pub fn check_together(specs: &[(&str, &Spec)]) -> Result<(), String> {
    let mut served: Vec<&str> = Vec::new();
    for (dll, spec) in specs {
        for export in &spec.exports {
            if export.implementation.is_served() {
                if served.contains(&export.name.as_str()) {
                    return Err(format!("{dll}/{}: served by two DLLs", export.name));
                }
                served.push(&export.name);
            }
            if let Implementation::Forward(target) = &export.implementation {
                let (module, name) = target
                    .split_once('.')
                    .expect("a forward names MODULE.Export");
                let Some((_, owner)) = specs.iter().find(|(d, _)| d.eq_ignore_ascii_case(module))
                else {
                    return Err(format!(
                        "{dll}/{}: forwards to {module}, which has no spec",
                        export.name
                    ));
                };
                let Some(found) = owner.export(name) else {
                    return Err(format!(
                        "{dll}/{}: forwards to {target}, which {module} does not export",
                        export.name
                    ));
                };
                if found.args != export.args {
                    return Err(format!(
                        "{dll}/{}: its prototype differs from {target}'s",
                        export.name
                    ));
                }
            }
        }
    }
    Ok(())
}

impl Spec {
    /// This spec's served exports in service-number order (the registry of this spec alone; see
    /// [`registry`] for the system DLLs together).
    pub fn services(&self) -> Vec<&Export> {
        registry(&[self])
    }

    /// The native exports, in file order.
    pub fn natives(&self) -> Vec<&Export> {
        self.exports
            .iter()
            .filter(|e| matches!(e.implementation, Implementation::Native(_)))
            .collect()
    }

    /// The members of group `key`, in file order.
    pub fn members(&self, key: &str) -> Vec<&Export> {
        self.exports.iter().filter(|e| e.group == key).collect()
    }

    /// The export named `name`.
    pub fn export(&self, name: &str) -> Option<&Export> {
        self.exports.iter().find(|e| e.name == name)
    }
}

/// Read and check the spec at `path`.
pub fn load(path: &Path) -> Result<Spec, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_spec(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read and check a spec's text.
pub fn parse_spec(text: &str) -> Result<Spec, String> {
    let root = toml::parse(text).map_err(|e| e.to_string())?;
    if let Some(key) = root.keys().find(|key| *key != "group" && *key != "export") {
        return Err(format!(
            "unknown top-level key {key:?} (a spec holds [[group]] and [[export]] records)"
        ));
    }
    let mut groups: Vec<Group> = Vec::new();
    for (index, table) in tables(&root, "group")?.into_iter().enumerate() {
        let context = format!("group #{}", index + 1);
        allow(table, &["key", "title"], &context)?;
        let key = string(table, "key", &context)?;
        if groups.iter().any(|g| g.key == key) {
            return Err(format!("{context}: group {key:?} declared twice"));
        }
        groups.push(Group {
            title: string(table, "title", &context)?,
            key,
        });
    }
    let mut exports: Vec<Export> = Vec::new();
    for (index, table) in tables(&root, "export")?.into_iter().enumerate() {
        let export = read_export(table, index, &groups)?;
        if exports.iter().any(|e| e.name == export.name) {
            return Err(format!("export {:?} declared twice", export.name));
        }
        if let Some(ordinal) = export.ordinal {
            if let Some(other) = exports.iter().find(|e| e.ordinal == Some(ordinal)) {
                return Err(format!(
                    "exports {:?} and {:?} share ordinal {ordinal}",
                    other.name, export.name
                ));
            }
        }
        exports.push(export);
    }
    Ok(Spec { groups, exports })
}

fn read_export(table: &Table, index: usize, groups: &[Group]) -> Result<Export, String> {
    let context = match table.get("name") {
        Some(Value::String(name)) => format!("export {name:?}"),
        _ => format!("export #{}", index + 1),
    };
    allow(
        table,
        &[
            "name",
            "group",
            "args",
            "impl",
            "ordinal",
            "fails",
            "note",
            "pinned_by",
            "scenarios",
            "unpinned",
            "internal",
        ],
        &context,
    )?;
    let name = string(table, "name", &context)?;
    if !is_identifier(&name) {
        return Err(format!("{context}: the name must be an identifier"));
    }
    let group = string(table, "group", &context)?;
    if !groups.iter().any(|g| g.key == group) {
        return Err(format!("{context}: unknown group {group:?}"));
    }
    let args = strings(table, "args", &context)?
        .into_iter()
        .map(|text| {
            let (kind, arg) = text
                .split_once(' ')
                .ok_or_else(|| format!("{context}: argument {text:?} is not \"<kind> <name>\""))?;
            let kind = ArgKind::parse(kind).ok_or_else(|| {
                format!(
                    "{context}: argument kind {kind:?} (u32, i32, bool, handle, ptr, ptr<T>, u64, \
                     strA, strW, with ? and [limit] for strings)"
                )
            })?;
            if !is_identifier(arg) {
                return Err(format!(
                    "{context}: argument name {arg:?} must be an identifier"
                ));
            }
            Ok(Arg {
                kind,
                name: arg.to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let implementation = match table.get("impl") {
        Some(Value::Table(spec)) if spec.entries.len() == 1 => {
            let (kind, value) = &spec.entries[0];
            let Value::String(value) = value else {
                return Err(format!("{context}: impl.{kind} must be a string"));
            };
            match kind.as_str() {
                "legacy" => Implementation::Legacy(value.clone()),
                "native" => Implementation::Native(value.clone()),
                "forward" => {
                    let valid = value.split_once('.').is_some_and(|(module, export)| {
                        is_identifier(module) && (is_identifier(export) || export.starts_with('#'))
                    });
                    if !valid {
                        return Err(format!(
                            "{context}: a forward names MODULE.Export, not {value:?}"
                        ));
                    }
                    Implementation::Forward(value.clone())
                }
                "floor" => Implementation::Floor(value.clone()),
                "unimplemented" => Implementation::Unimplemented(value.clone()),
                _ => {
                    return Err(format!(
                        "{context}: impl kind {kind:?} (legacy, native, forward, floor, \
                         unimplemented)"
                    ))
                }
            }
        }
        Some(_) => return Err(format!("{context}: impl is an inline table with one key")),
        None => return Err(format!("{context}: missing impl")),
    };
    let ordinal = match table.get("ordinal") {
        None => None,
        Some(Value::Integer(n)) if (1..=0xFFFF).contains(n) => Some(*n as u16),
        Some(other) => {
            return Err(format!(
                "{context}: ordinal must be an integer in 1..=65535, not {}",
                other.kind()
            ))
        }
    };
    let pinned_by = optional_strings(table, "pinned_by", &context)?;
    for block in &pinned_by {
        let valid = block.split_once('/').is_some_and(|(fixture, section)| {
            is_identifier(fixture) && !section.is_empty() && !section.contains(char::is_whitespace)
        });
        if !valid {
            return Err(format!(
                "{context}: pinned_by entry {block:?} is not <fixture>/<section>"
            ));
        }
    }
    let scenarios = optional_strings(table, "scenarios", &context)?;
    if let Some(bad) = scenarios.iter().find(|s| !is_identifier(s)) {
        return Err(format!(
            "{context}: scenario {bad:?} is not a test function name"
        ));
    }
    let fails = optional_string(table, "fails", &context)?;
    if let Some(text) = &fails {
        if fail_value(text).is_none() {
            return Err(format!(
                "{context}: fails {text:?} is not a failure value (an integer, a named one such \
                 as INVALID_HANDLE_VALUE, void or never)"
            ));
        }
    }
    Ok(Export {
        name,
        group,
        args,
        implementation,
        ordinal,
        fails,
        note: optional_string(table, "note", &context)?,
        pinned_by,
        scenarios,
        unpinned: optional_string(table, "unpinned", &context)?,
        internal: match table.get("internal") {
            None => false,
            Some(Value::Boolean(flag)) => *flag,
            Some(other) => {
                return Err(format!(
                    "{context}: internal must be a boolean, not {}",
                    other.kind()
                ))
            }
        },
    })
}

pub(crate) fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The tables of the array of tables `key` (none when absent).
pub(crate) fn tables<'a>(root: &'a Table, key: &str) -> Result<Vec<&'a Table>, String> {
    match root.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Table(table) => Ok(table),
                _ => Err(format!("{key} must be an array of tables ([[{key}]])")),
            })
            .collect(),
        Some(_) => Err(format!("{key} must be an array of tables ([[{key}]])")),
    }
}

pub(crate) fn allow(table: &Table, keys: &[&str], context: &str) -> Result<(), String> {
    match table.keys().find(|key| !keys.contains(key)) {
        Some(key) => Err(format!("{context}: unknown key {key:?}")),
        None => Ok(()),
    }
}

pub(crate) fn string(table: &Table, key: &str, context: &str) -> Result<String, String> {
    optional_string(table, key, context)?.ok_or_else(|| format!("{context}: missing {key}"))
}

pub(crate) fn optional_string(
    table: &Table,
    key: &str,
    context: &str,
) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(Some(text.clone())),
        Some(Value::String(_)) => Err(format!("{context}: {key} must not be empty")),
        Some(other) => Err(format!(
            "{context}: {key} must be a string, not {}",
            other.kind()
        )),
    }
}

pub(crate) fn strings(table: &Table, key: &str, context: &str) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Err(format!("{context}: missing {key}")),
        Some(_) => optional_strings(table, key, context),
    }
}

pub(crate) fn optional_strings(
    table: &Table,
    key: &str,
    context: &str,
) -> Result<Vec<String>, String> {
    match table.get(key) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(format!(
                    "{context}: {key} holds {}, not strings",
                    other.kind()
                )),
            })
            .collect(),
        Some(other) => Err(format!(
            "{context}: {key} must be an array of strings, not {}",
            other.kind()
        )),
    }
}

impl std::fmt::Display for Arg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.kind.word(), self.name)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SPEC: &str = r#"
[[group]]
key = "termination"
title = "termination"

[[export]]
name = "GetVersion"
group = "termination"
args = []
impl = { legacy = "svc_get_version" }

[[export]]
name = "ExitProcess"
group = "termination"
args = ["u32 uExitCode"]
impl = { legacy = "svc_exit_process" }
pinned_by = ["bare/*"]

[[export]]
name = "GetLastError"
group = "termination"
args = []
impl = { native = "GetLastError" }

[[export]]
name = "SetStdHandle"
group = "termination"
args = ["u32 nStdHandle", "u32 hHandle"]
impl = { floor = "never called" }

[[export]]
name = "HeapAlloc"
group = "termination"
args = ["u32 hHeap", "u32 dwFlags", "u32 dwBytes"]
impl = { forward = "NTDLL.RtlAllocateHeap" }
ordinal = 0x10
"#;

    /// Every argument kind, with the argument block and the words it reads back as.
    #[test]
    fn reads_every_argument_kind() {
        let text = SPEC.replacen(
            "args = []\nimpl = { legacy = \"svc_get_version\" }",
            "args = [\"u32 a\", \"i32 b\", \"bool c\", \"handle d\", \"ptr e\", \"ptr<u32> f\", \
             \"u64 g\", \"strA h\", \"strW?[260] i\"]\nimpl = { legacy = \"svc_get_version\" }\n\
             fails = \"INVALID_HANDLE_VALUE\"",
            1,
        );
        assert_ne!(text, SPEC);
        let spec = parse_spec(&text).unwrap();
        let version = spec.export("GetVersion").unwrap();
        assert_eq!(version.handler().as_deref(), Some("svc_get_version"));
        assert_eq!(version.fail_value(), Some(0xFFFF_FFFF));
        assert_eq!(version.arg_bytes(), 40);
        assert_eq!(version.args[5].kind, ArgKind::PtrTo(Pointee::U32));
        assert_eq!(
            version.args[8].kind,
            ArgKind::Str {
                wide: true,
                optional: true,
                limit: Some(260)
            }
        );
        let words: Vec<String> = version.args.iter().map(|a| a.to_string()).collect();
        assert_eq!(
            words,
            [
                "u32 a",
                "i32 b",
                "bool c",
                "handle d",
                "ptr e",
                "ptr<u32> f",
                "u64 g",
                "strA h",
                "strW?[260] i"
            ]
        );
        for (from, to, message) in [
            (
                "fails = \"INVALID_HANDLE_VALUE\"",
                "fails = \"sometimes\"",
                "not a failure value",
            ),
            ("\"strW?[260] i\"", "\"strW[0] i\"", "argument kind"),
            ("\"ptr<u32> f\"", "\"ptr<char> f\"", "argument kind"),
        ] {
            let changed = text.replacen(from, to, 1);
            assert_ne!(changed, text, "the change applies: {from:?}");
            let error = parse_spec(&changed).unwrap_err();
            assert!(error.contains(message), "{error}");
        }
    }

    /// The kinds a spec no longer takes: the typed services and the system services are later
    /// increments' (an unknown kind is refused, not misread).
    #[test]
    fn refuses_unknown_impl_kinds() {
        for kind in ["service", "syscall", "native2"] {
            let text = SPEC.replacen(
                "{ legacy = \"svc_get_version\" }",
                &format!("{{ {kind} = \"x\" }}"),
                1,
            );
            let error = parse_spec(&text).unwrap_err();
            assert!(error.contains("impl kind"), "{kind}: {error}");
        }
    }

    #[test]
    fn reads_a_spec() {
        let spec = parse_spec(SPEC).unwrap();
        assert_eq!(spec.exports.len(), 5);
        let exit = spec.export("ExitProcess").unwrap();
        assert_eq!(exit.arg_bytes(), 4);
        assert_eq!(exit.pinned_by, ["bare/*"]);
        assert_eq!(spec.export("HeapAlloc").unwrap().ordinal, Some(16));
        assert_eq!(
            spec.export("SetStdHandle").unwrap().handler().as_deref(),
            Some(FLOOR_HANDLER)
        );
        assert_eq!(spec.export("GetLastError").unwrap().handler(), None);
    }

    #[test]
    fn fail_values_read_as_dwords() {
        for (text, value) in [
            ("0", 0),
            ("FALSE", 0),
            ("void", 0),
            ("-1", 0xFFFF_FFFF),
            ("0xFFFF_FFFF", 0xFFFF_FFFF),
            ("WAIT_FAILED", 0xFFFF_FFFF),
            ("258", 258),
        ] {
            assert_eq!(fail_value(text), Some(value), "{text}");
        }
        assert_eq!(fail_value("maybe"), None);
    }

    #[test]
    fn exit_process_is_service_one_then_names_in_case_insensitive_order() {
        let spec = parse_spec(SPEC).unwrap();
        let order: Vec<&str> = spec.services().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(order, ["ExitProcess", "GetVersion", "SetStdHandle"]);
    }

    #[test]
    fn refuses_bad_records() {
        for (from, to, message) in [
            ("args = []", "args = [\"dword x\"]", "argument kind"),
            (
                "impl = { native = \"GetLastError\" }",
                "impl = { native = \"A\", floor = \"B\" }",
                "one key",
            ),
            (
                "group = \"termination\"\nargs = []\nimpl = { legacy",
                "group = \"other\"\nargs = []\nimpl = { legacy",
                "unknown group",
            ),
            (
                "pinned_by = [\"bare/*\"]",
                "pinned_by = [\"bare\"]",
                "pinned_by",
            ),
            ("ordinal = 0x10", "ordinal = 0x10\nextra = 1", "unknown key"),
            (
                "forward = \"NTDLL.RtlAllocateHeap\"",
                "forward = \"RtlAllocateHeap\"",
                "MODULE.Export",
            ),
        ] {
            let text = SPEC.replacen(from, to, 1);
            assert_ne!(text, SPEC, "the change applies: {from:?}");
            let error = parse_spec(&text).unwrap_err();
            assert!(error.contains(message), "{error}");
        }
        let twice = format!(
            "{SPEC}\n[[export]]\nname = \"GetVersion\"\ngroup = \"termination\"\nargs = []\nimpl = {{ native = \"x\" }}\n"
        );
        assert!(parse_spec(&twice).unwrap_err().contains("declared twice"));
    }
}
