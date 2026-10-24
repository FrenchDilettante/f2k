//! exportgen: the system DLLs' export specs, and everything generated from them.
//!
//! Each system DLL's exports are declared once, in `userland/<dll>/exports.toml` (the file's own
//! header documents its records). This crate reads a spec ([`load`]), checks it, and emits what
//! derives from it ([`emit`]):
//!
//! - for the kernel (through its build script): its two service tables (ntoskrnl's NT services and
//!   win32k's), and the native exports' and the DLL's exports' argument blocks (the kernel's tests
//!   check the built DLLs against them);
//! - for the system DLL builds (userland/build-support/stubs.rs): each DLL's system-service stubs,
//!   its module-definition (`.def`) file, and the kernel ABI constants its assembly uses ([`abi`]).
//!
//! Three DLLs enter the kernel, as on Windows 2000, each through its own stubs and by Windows
//! 2000's own numbers ([`w2k`]): ntdll, through ntoskrnl's `Nt*` services (exported, under their
//! `Zw` names too), and user32 and gdi32, through win32k's `NtUser*` and `NtGdi*` services (their
//! internal calls, exported by neither). Both are `impl = { syscall = ... }` records; the kernel's
//! tables and the DLLs' stubs both come from here, so the two sides agree by construction. Every
//! other export is user-mode code: a native body, or a forwarder to another DLL's export.
//!
//! The specs are TOML read through [`toml`], a strict reader for the subset they are written in.

pub mod abi;
pub mod emit;
pub mod toml;
pub mod w2k;

use std::path::Path;

use toml::{Table, Value};

/// One DLL's spec.
#[derive(Clone, Debug, PartialEq)]
pub struct Spec {
    /// The calling convention of every export the DLL implements (its top-level `convention`;
    /// stdcall when absent).
    pub convention: Convention,
    /// The API groups, in file order.
    pub groups: Vec<Group>,
    /// The exports, in file order.
    pub exports: Vec<Export>,
    /// The platform's exports F2K does not implement yet (the records without an `impl`), in file
    /// order: nothing is generated for them.
    pub catalogued: Vec<Catalogued>,
}

/// One of the platform's exports F2K does not implement yet: catalogued from the platform's own
/// export table.
#[derive(Clone, Debug, PartialEq)]
pub struct Catalogued {
    pub name: String,
    /// The export ordinal, from the platform's own table.
    pub ordinal: u16,
    /// A variable, not a function (an export in a section without code).
    pub data: bool,
    /// A fact worth keeping beside the export.
    pub note: Option<String>,
}

/// A DLL's calling convention: who pops an export's arguments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Convention {
    /// The callee pops them (`ret N`): WINAPI, the system DLLs' own (`stdcall`).
    #[default]
    Stdcall,
    /// The caller pops them: the C library's functions (`cdecl`). An export with variable
    /// arguments is cdecl whatever its DLL's convention.
    Cdecl,
}

/// An API group: the unit the compatibility report groups by.
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
    /// The export ordinal, from the platform's own table (none for an F2K-internal entry point).
    pub ordinal: Option<u16>,
    /// A system service's `Zw` alias's ordinal, from the platform's own table.
    pub zw_ordinal: Option<u16>,
    /// The failure return value (`0`, `FALSE`, `INVALID_HANDLE_VALUE`, `-1`).
    pub fails: Option<String>,
    /// A fact worth keeping beside the export.
    pub note: Option<String>,
    /// Not a Windows 2000 export, so the compatibility report leaves it out: an F2K-internal entry
    /// point (the kernel's own calls into user mode), or one of win32k's services, which the DLL's
    /// own code calls through its stub and the `.def` does not export.
    pub internal: bool,
    /// A variable, not a function: the DLL's own storage (a native, `f2k_export_<Name>`), which
    /// the `.def` exports as DATA (an importer reaches it through its import address table).
    pub data: bool,
}

/// One prototype argument.
#[derive(Clone, Debug, PartialEq)]
pub struct Arg {
    pub kind: ArgKind,
    pub name: String,
}

/// An argument's kind: what the caller pushes (the argument block derives from it), and, for a
/// system service, what its handler receives (see [`emit::nt_services`]).
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
    /// A cdecl export's variable arguments (`...`, the last argument, without a name): the caller
    /// pushes them and pops them; the block counts none of them.
    Varargs,
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
    /// The Rust type the handler sees it as.
    pub fn rust(self) -> &'static str {
        self.word()
    }

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
            ArgKind::Varargs => 0,
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
            ArgKind::Varargs => "...".into(),
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

/// How an export is implemented.
#[derive(Clone, Debug, PartialEq)]
pub enum Implementation {
    /// A Windows 2000 system service: the DLL's stub raises the gate on its Windows 2000 number
    /// ([`w2k`]), and the kernel's service table for it serves it through a typed handler (its
    /// path from the crate root), `fn(&mut NtCall, <the arguments by kind>) -> NtResult`, the
    /// NTSTATUS in EAX. One of ntoskrnl's (ntdll's `Nt*`) is exported under its `Zw` name too,
    /// at the same stub; one of win32k's (user32's `NtUser*`, gdi32's `NtGdi*`) is `internal`:
    /// the DLL's own code calls its stub, and nothing exports it.
    Syscall(String),
    /// Runs in user mode: the body's name.
    Native(String),
    /// Forwarded to another module's export (`NTDLL.RtlUnwind`).
    Forward(String),
    /// Not written yet: a generated body logs the call, every argument, and the reason (what is
    /// missing: `not yet implemented`), then fails as the export fails (its `fails` value, the
    /// last error ERROR_CALL_NOT_IMPLEMENTED); one that returns nothing (`void`) returns,
    /// having no failure to report, and one that cannot fail (`never`) raises.
    Stub(String),
}

impl Implementation {
    /// Whether the export is a Windows 2000 system service.
    pub fn is_syscall(&self) -> bool {
        matches!(self, Implementation::Syscall(_))
    }
}

impl Export {
    /// The argument block the export's callers push (and its body pops, when it is stdcall).
    pub fn arg_bytes(&self) -> u32 {
        self.args.iter().map(|arg| arg.kind.bytes()).sum()
    }

    /// Its calling convention in a DLL whose convention is `dll`: cdecl when it takes variable
    /// arguments (`...`), the DLL's otherwise.
    pub fn convention(&self, dll: Convention) -> Convention {
        if self.args.iter().any(|arg| arg.kind == ArgKind::Varargs) {
            Convention::Cdecl
        } else {
            dll
        }
    }

    /// A system service's generated wrapper: its service table's entry for it.
    pub fn nt_wrapper(&self) -> String {
        format!("nt_{}", self.name)
    }

    /// A system service's Windows 2000 number, in whichever table holds it (ntoskrnl's from 0,
    /// win32k's from 0x1000).
    pub fn syscall_number(&self) -> Option<u32> {
        self.implementation
            .is_syscall()
            .then(|| {
                w2k::service_number(&self.name).or_else(|| w2k::win32k_service_number(&self.name))
            })
            .flatten()
    }

    /// Whether it is one of ntoskrnl's services (ntdll's `Nt*`, exported with its `Zw` alias).
    pub fn is_nt_service(&self) -> bool {
        self.implementation.is_syscall() && w2k::service_number(&self.name).is_some()
    }

    /// Whether it is one of win32k's services (user32's `NtUser*`, gdi32's `NtGdi*`: their own
    /// code's calls, not exported).
    pub fn is_win32k_service(&self) -> bool {
        self.implementation.is_syscall() && w2k::win32k_service_number(&self.name).is_some()
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

/// The DLLs whose own code enters win32k's services, as on Windows 2000.
pub const WIN32K_CLIENTS: [&str; 2] = ["user32", "gdi32"];

/// The system DLLs' specs, checked together: `(dll, spec)` pairs, the DLL named as its module
/// (`kernel32`, `ntdll`). A forward names an export of a listed DLL with the same prototype (not
/// one of win32k's services, which no DLL exports); ntoskrnl's services are ntdll's, and win32k's
/// user32's or gdi32's ([`WIN32K_CLIENTS`]).
pub fn check_together(specs: &[(&str, &Spec)]) -> Result<(), String> {
    for (dll, spec) in specs {
        for export in &spec.exports {
            // Which DLL enters which table: ntdll ntoskrnl's, user32 and gdi32 win32k's.
            if export.is_nt_service() && *dll != "ntdll" {
                return Err(format!(
                    "{dll}/{}: one of ntoskrnl's services is ntdll's alone",
                    export.name
                ));
            }
            if export.is_win32k_service() && !WIN32K_CLIENTS.contains(dll) {
                return Err(format!(
                    "{dll}/{}: one of win32k's services is user32's or gdi32's alone",
                    export.name
                ));
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
                let Some(found) = owner
                    .export(name)
                    .filter(|found| !found.is_win32k_service())
                else {
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
    /// The native exports, in file order.
    pub fn natives(&self) -> Vec<&Export> {
        self.exports
            .iter()
            .filter(|e| matches!(e.implementation, Implementation::Native(_)))
            .collect()
    }

    /// The variables (data exports) the DLL implements, in file order.
    pub fn data(&self) -> Vec<&Export> {
        self.exports.iter().filter(|e| e.data).collect()
    }

    /// The stubbed exports, in file order.
    pub fn stubs(&self) -> Vec<&Export> {
        self.exports
            .iter()
            .filter(|e| matches!(e.implementation, Implementation::Stub(_)))
            .collect()
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
    if let Some(key) = root
        .keys()
        .find(|key| !["convention", "group", "export"].contains(key))
    {
        return Err(format!(
            "unknown top-level key {key:?} (a spec holds its convention, [[group]] and [[export]] \
             records)"
        ));
    }
    let convention = match root.get("convention") {
        None => Convention::Stdcall,
        Some(Value::String(word)) if word == "stdcall" => Convention::Stdcall,
        Some(Value::String(word)) if word == "cdecl" => Convention::Cdecl,
        Some(Value::String(word)) => {
            return Err(format!(
                "convention is \"stdcall\" or \"cdecl\", not {word:?}"
            ))
        }
        Some(other) => return Err(format!("convention must be a string, not {}", other.kind())),
    };
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
    let mut catalogued: Vec<Catalogued> = Vec::new();
    // Every name and ordinal the records claim (a system service's Zw alias's among them).
    let mut names: Vec<String> = Vec::new();
    let mut ordinals: Vec<(u16, String)> = Vec::new();
    for (index, table) in tables(&root, "export")?.into_iter().enumerate() {
        let (name, claimed) = if table.get("impl").is_some() {
            let export = read_export(table, index, &groups)?;
            let mut claimed: Vec<(u16, String)> = export
                .ordinal
                .map(|o| (o, export.name.clone()))
                .into_iter()
                .collect();
            if let Some(zw) = export.zw_ordinal {
                claimed.push((zw, w2k::zw_alias(&export.name)));
            }
            let name = export.name.clone();
            exports.push(export);
            (name, claimed)
        } else {
            let record = read_catalogued(table, index)?;
            let claimed = vec![(record.ordinal, record.name.clone())];
            let name = record.name.clone();
            catalogued.push(record);
            (name, claimed)
        };
        if names.contains(&name) {
            return Err(format!("export {name:?} declared twice"));
        }
        names.push(name);
        for (ordinal, name) in claimed {
            if let Some((_, other)) = ordinals.iter().find(|(o, _)| *o == ordinal) {
                return Err(format!(
                    "exports {other:?} and {name:?} share ordinal {ordinal}"
                ));
            }
            ordinals.push((ordinal, name));
        }
    }
    // A system service's Zw alias is the service's own export: not catalogued apart.
    for export in exports.iter().filter(|e| e.is_nt_service()) {
        let zw = w2k::zw_alias(&export.name);
        if catalogued.iter().any(|c| c.name == zw) {
            return Err(format!(
                "{zw} is {}'s alias: drop its record, its ordinal is {}'s zw_ordinal",
                export.name, export.name
            ));
        }
    }
    if convention == Convention::Cdecl {
        if let Some(service) = exports.iter().find(|e| e.implementation.is_syscall()) {
            return Err(format!(
                "export {:?}: a system service is stdcall, and the spec's convention is cdecl",
                service.name
            ));
        }
    }
    Ok(Spec {
        convention,
        groups,
        exports,
        catalogued,
    })
}

/// A record without an `impl`: one of the platform's exports F2K does not implement yet.
fn read_catalogued(table: &Table, index: usize) -> Result<Catalogued, String> {
    let context = match table.get("name") {
        Some(Value::String(name)) => format!("export {name:?}"),
        _ => format!("export #{}", index + 1),
    };
    allow(table, &["name", "ordinal", "data", "note"], &context).map_err(|e| {
        format!("{e} (an export without an impl is catalogued: name, ordinal, data, note)")
    })?;
    let name = string(table, "name", &context)?;
    // The platform's names, decorated C++ ones among them (msvcrt's `??0exception@@QAE@XZ`).
    if !name.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "{context}: the name must be printable ASCII, without spaces"
        ));
    }
    Ok(Catalogued {
        ordinal: ordinal_field(table, "ordinal", &context)?
            .ok_or_else(|| format!("{context}: a catalogued export has its platform ordinal"))?,
        data: boolean(table, "data", &context)?,
        note: optional_string(table, "note", &context)?,
        name,
    })
}

/// An optional ordinal field: an integer in 1..=65535.
fn ordinal_field(table: &Table, key: &str, context: &str) -> Result<Option<u16>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(Value::Integer(n)) if (1..=0xFFFF).contains(n) => Ok(Some(*n as u16)),
        Some(other) => Err(format!(
            "{context}: {key} must be an integer in 1..=65535, not {}",
            other.kind()
        )),
    }
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
            "zw_ordinal",
            "fails",
            "note",
            "internal",
            "data",
        ],
        &context,
    )?;
    let data = boolean(table, "data", &context)?;
    let name = string(table, "name", &context)?;
    if !is_identifier(&name) {
        return Err(format!("{context}: the name must be an identifier"));
    }
    let group = string(table, "group", &context)?;
    if !groups.iter().any(|g| g.key == group) {
        return Err(format!("{context}: unknown group {group:?}"));
    }
    // A variable has no prototype: its record may leave the arguments out.
    let args = if data && table.get("args").is_none() {
        Vec::new()
    } else {
        strings(table, "args", &context)?
    };
    let args = args
        .into_iter()
        .map(|text| {
            if text == "..." {
                return Ok(Arg {
                    kind: ArgKind::Varargs,
                    name: String::new(),
                });
            }
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
    if let Some(at) = args.iter().position(|a| a.kind == ArgKind::Varargs) {
        if at + 1 != args.len() {
            return Err(format!(
                "{context}: the variable arguments (\"...\") come last"
            ));
        }
    }
    let implementation = match table.get("impl") {
        Some(Value::Table(spec)) if spec.entries.len() == 1 => {
            let (kind, value) = &spec.entries[0];
            let Value::String(value) = value else {
                return Err(format!("{context}: impl.{kind} must be a string"));
            };
            match kind.as_str() {
                "syscall" => {
                    if w2k::service_number(&name).is_none()
                        && w2k::win32k_service_number(&name).is_none()
                    {
                        return Err(format!(
                            "{context}: a syscall is a Windows 2000 system service (ntoskrnl's Nt* \
                             or win32k's NtUser* and NtGdi*), and {name} is not one"
                        ));
                    }
                    Implementation::Syscall(value.clone())
                }
                "native" => Implementation::Native(value.clone()),
                "stub" => {
                    if value.trim().is_empty() {
                        return Err(format!(
                            "{context}: a stub gives its reason (\"not yet implemented\")"
                        ));
                    }
                    Implementation::Stub(value.clone())
                }
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
                _ => {
                    return Err(format!(
                        "{context}: impl kind {kind:?} (syscall, native, forward, stub)"
                    ))
                }
            }
        }
        Some(_) => return Err(format!("{context}: impl is an inline table with one key")),
        None => return Err(format!("{context}: missing impl")),
    };
    let ordinal = ordinal_field(table, "ordinal", &context)?;
    let zw_ordinal = ordinal_field(table, "zw_ordinal", &context)?;
    let internal = boolean(table, "internal", &context)?;
    let win32k = implementation.is_syscall() && w2k::win32k_service_number(&name).is_some();
    if zw_ordinal.is_some() && (!implementation.is_syscall() || win32k) {
        return Err(format!(
            "{context}: only one of ntoskrnl's system services has a Zw alias (zw_ordinal)"
        ));
    }
    // win32k's services are the DLL's own calls, as on Windows 2000: never exported.
    if win32k && (!internal || ordinal.is_some()) {
        return Err(format!(
            "{context}: one of win32k's services is the DLL's internal call: internal = true, no \
             ordinal (Windows 2000's user32 and gdi32 export none)"
        ));
    }
    if implementation.is_syscall() && !win32k && internal {
        return Err(format!(
            "{context}: one of ntoskrnl's system services is ntdll's export, not internal"
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
    if implementation.is_syscall() && fails.is_some() {
        return Err(format!(
            "{context}: a syscall returns its NTSTATUS: it declares no failure return (fails)"
        ));
    }
    if matches!(implementation, Implementation::Stub(_)) && fails.is_none() {
        return Err(format!(
            "{context}: a stub fails as the export fails: it declares its failure return (fails; \
             void or never when it has none)"
        ));
    }
    if implementation.is_syscall() && args.iter().any(|a| a.kind == ArgKind::Varargs) {
        return Err(format!("{context}: a syscall takes no variable arguments"));
    }
    if implementation.is_syscall() && args.iter().any(|a| matches!(a.kind, ArgKind::Str { .. })) {
        return Err(format!(
            "{context}: a syscall takes no strA or strW (NT's strings are UNICODE_STRINGs behind \
             pointers)"
        ));
    }
    if data {
        if !matches!(implementation, Implementation::Native(_)) {
            return Err(format!(
                "{context}: a variable is the DLL's own storage: impl = {{ native = \"<Name>\" }}"
            ));
        }
        if !args.is_empty() || fails.is_some() {
            return Err(format!(
                "{context}: a variable takes no arguments and has no failure return (args, fails)"
            ));
        }
    }
    Ok(Export {
        name,
        group,
        args,
        implementation,
        ordinal,
        zw_ordinal,
        fails,
        note: optional_string(table, "note", &context)?,
        internal,
        data,
    })
}

/// An optional boolean field: false when absent.
fn boolean(table: &Table, key: &str, context: &str) -> Result<bool, String> {
    match table.get(key) {
        None => Ok(false),
        Some(Value::Boolean(flag)) => Ok(*flag),
        Some(other) => Err(format!(
            "{context}: {key} must be a boolean, not {}",
            other.kind()
        )),
    }
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
        if self.kind == ArgKind::Varargs {
            return f.write_str("...");
        }
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
impl = { native = "GetVersion" }

[[export]]
name = "ExitProcess"
group = "termination"
args = ["u32 uExitCode"]
impl = { native = "ExitProcess" }

[[export]]
name = "GetLastError"
group = "termination"
args = []
impl = { native = "GetLastError" }

[[export]]
name = "SetStdHandle"
group = "termination"
args = ["u32 nStdHandle", "u32 hHandle"]
impl = { native = "SetStdHandle" }

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
            "args = []\nimpl = { native = \"GetVersion\" }",
            "args = [\"u32 a\", \"i32 b\", \"bool c\", \"handle d\", \"ptr e\", \"ptr<u32> f\", \
             \"u64 g\", \"strA h\", \"strW?[260] i\"]\nimpl = { native = \"GetVersion\" }\n\
             fails = \"INVALID_HANDLE_VALUE\"",
            1,
        );
        assert_ne!(text, SPEC);
        let spec = parse_spec(&text).unwrap();
        let version = spec.export("GetVersion").unwrap();
        assert_eq!(
            version.implementation,
            Implementation::Native("GetVersion".into())
        );
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

    /// The Win32 service kinds are gone: nothing enters the kernel but Windows 2000's system
    /// services, and every export the spec lists is built (an unknown kind is refused, not
    /// misread).
    #[test]
    fn the_win32_service_kinds_are_gone() {
        for kind in ["service", "legacy", "floor", "unimplemented", "native2"] {
            let text = SPEC.replacen(
                "{ native = \"GetVersion\" }",
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
        assert_eq!(spec.export("HeapAlloc").unwrap().ordinal, Some(16));
        assert_eq!(
            spec.export("HeapAlloc").unwrap().implementation,
            Implementation::Forward("NTDLL.RtlAllocateHeap".into())
        );
        assert_eq!(spec.natives().len(), 4);
    }

    /// A spec's convention: stdcall unless it says cdecl, any other word refused; a cdecl DLL has
    /// no system services; a variadic export is cdecl in either.
    #[test]
    fn reads_the_convention() {
        let spec = parse_spec(SPEC).unwrap();
        assert_eq!(spec.convention, Convention::Stdcall);
        let exit = spec.export("ExitProcess").unwrap();
        assert_eq!(exit.convention(spec.convention), Convention::Stdcall);
        let cdecl = parse_spec(&format!("convention = \"cdecl\"\n{SPEC}")).unwrap();
        assert_eq!(cdecl.convention, Convention::Cdecl);
        assert_eq!(
            cdecl
                .export("ExitProcess")
                .unwrap()
                .convention(cdecl.convention),
            Convention::Cdecl
        );
        let variadic = parse_spec(&SPEC.replacen(
            "args = [\"u32 uExitCode\"]",
            "args = [\"u32 uExitCode\", \"...\"]",
            1,
        ))
        .unwrap();
        assert_eq!(
            variadic
                .export("ExitProcess")
                .unwrap()
                .convention(Convention::Stdcall),
            Convention::Cdecl
        );
        for (head, message) in [
            ("convention = \"fastcall\"\n", "\"stdcall\" or \"cdecl\""),
            ("convention = 1\n", "must be a string"),
            ("calling = \"cdecl\"\n", "unknown top-level key"),
        ] {
            let error = parse_spec(&format!("{head}{SPEC}")).unwrap_err();
            assert!(error.contains(message), "{head}: {error}");
        }
        let service =
            "convention = \"cdecl\"\n[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\n\
                       name = \"NtClose\"\ngroup = \"nt\"\nargs = [\"handle Handle\"]\n\
                       impl = { syscall = \"x\" }\n";
        assert!(parse_spec(service).unwrap_err().contains("stdcall"));
    }

    /// A variable: the DLL's own storage (a native), without arguments or a failure return.
    #[test]
    fn reads_variables() {
        let text = format!(
            "{SPEC}\n[[export]]\nname = \"_iob\"\ngroup = \"termination\"\ndata = true\n\
             impl = {{ native = \"_iob\" }}\nordinal = 0x20\n"
        );
        let spec = parse_spec(&text).unwrap();
        let iob = spec.export("_iob").unwrap();
        assert!(iob.data && iob.args.is_empty());
        assert_eq!(spec.data().len(), 1);
        assert!(spec.natives().contains(&iob), "a variable is the DLL's own");
        assert!(!spec.export("ExitProcess").unwrap().data);
        for (from, to, message) in [
            ("native = \"_iob\"", "forward = \"NTDLL.x\"", "own storage"),
            (
                "data = true",
                "data = true\nargs = [\"u32 x\"]",
                "no arguments",
            ),
            ("data = true", "data = true\nfails = \"0\"", "no arguments"),
            ("data = true", "data = 1", "must be a boolean"),
        ] {
            let changed = text.replacen(from, to, 1);
            assert_ne!(changed, text, "the change applies: {from:?}");
            let error = parse_spec(&changed).unwrap_err();
            assert!(error.contains(message), "{to}: {error}");
        }
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
    fn syscalls_take_windows_2000s_numbers() {
        let spec = parse_spec(
            "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\ngroup = \"nt\"\n\
             args = [\"handle Handle\"]\nimpl = { syscall = \"crate::nt::object::close\" }\n",
        )
        .unwrap();
        let close = spec.export("NtClose").unwrap();
        assert_eq!(close.syscall_number(), Some(0x18));
        assert_eq!(close.nt_wrapper(), "nt_NtClose");
        let text = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtNoSuch\"\n\
                    group = \"nt\"\nargs = []\nimpl = { syscall = \"x\" }\n";
        assert!(parse_spec(text).unwrap_err().contains("not one"));
        let text = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\n\
                    group = \"nt\"\nargs = []\nimpl = { syscall = \"x\" }\nfails = \"0\"\n";
        assert!(parse_spec(text).unwrap_err().contains("NTSTATUS"));
        let text = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\n\
                    group = \"nt\"\nargs = [\"strA x\"]\nimpl = { syscall = \"x\" }\n";
        assert!(parse_spec(text).unwrap_err().contains("UNICODE_STRING"));
        let text = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\n\
                    group = \"nt\"\nargs = []\nimpl = { syscall = \"x\" }\ninternal = true\n";
        assert!(parse_spec(text).unwrap_err().contains("not internal"));
    }

    /// One of win32k's services: its number from the second table, internal, without an ordinal
    /// or a Zw alias; user32's or gdi32's alone, and no forward's target.
    #[test]
    fn win32k_services_are_internal_calls() {
        let record = "[[group]]\nkey = \"winsta\"\ntitle = \"winsta\"\n\n[[export]]\n\
                      name = \"NtUserGetThreadDesktop\"\ngroup = \"winsta\"\n\
                      args = [\"u32 ThreadId\", \"ptr<u32> Desktop\"]\n\
                      impl = { syscall = \"crate::win32k::x\" }\ninternal = true\n";
        let spec = parse_spec(record).unwrap();
        let service = spec.export("NtUserGetThreadDesktop").unwrap();
        assert_eq!(service.syscall_number(), Some(0x11A2));
        assert!(service.is_win32k_service() && !service.is_nt_service());
        for (from, to, message) in [
            ("internal = true\n", "", "internal = true"),
            (
                "internal = true\n",
                "internal = true\nordinal = 5\n",
                "no ordinal",
            ),
            (
                "internal = true\n",
                "internal = true\nzw_ordinal = 5\n",
                "Zw alias",
            ),
            ("NtUserGetThreadDesktop", "NtUserNoSuch", "not one"),
        ] {
            let changed = record.replacen(from, to, 1);
            assert_ne!(changed, record, "the change applies: {from:?}");
            let error = parse_spec(&changed).unwrap_err();
            assert!(error.contains(message), "{to}: {error}");
        }
        check_together(&[("user32", &spec)]).unwrap();
        check_together(&[("gdi32", &spec)]).unwrap();
        let error = check_together(&[("ntdll", &spec)]).unwrap_err();
        assert!(error.contains("user32's or gdi32's"), "{error}");
        let nt = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\n\
                  group = \"nt\"\nargs = [\"handle Handle\"]\nimpl = { syscall = \"x\" }\n";
        let error = check_together(&[("user32", &parse_spec(nt).unwrap())]).unwrap_err();
        assert!(error.contains("ntdll's alone"), "{error}");
        let forward = "[[group]]\nkey = \"winsta\"\ntitle = \"winsta\"\n\n[[export]]\n\
                       name = \"GetThreadDesktop\"\ngroup = \"winsta\"\n\
                       args = [\"u32 ThreadId\", \"ptr<u32> Desktop\"]\n\
                       impl = { forward = \"USER32.NtUserGetThreadDesktop\" }\n";
        let forward = parse_spec(forward).unwrap();
        let error = check_together(&[("kernel32", &forward), ("user32", &spec)]).unwrap_err();
        assert!(error.contains("does not export"), "{error}");
    }

    #[test]
    fn refuses_bad_records() {
        for (from, to, message) in [
            ("args = []", "args = [\"dword x\"]", "argument kind"),
            (
                "impl = { native = \"GetLastError\" }",
                "impl = { native = \"A\", forward = \"B\" }",
                "one key",
            ),
            (
                "group = \"termination\"\nargs = []\nimpl = { native = \"GetVersion",
                "group = \"other\"\nargs = []\nimpl = { native = \"GetVersion",
                "unknown group",
            ),
            (
                "impl = { native = \"ExitProcess\" }",
                "impl = { native = \"ExitProcess\" }\npinned_by = [\"bare/*\"]",
                "unknown key",
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
        // The catalogued records: name, ordinal, data and note only; their names and ordinals
        // are the spec's like any other's; a system service's Zw alias is not catalogued apart.
        for (record, message) in [
            ("name = \"AddAtomA\"", "platform ordinal"),
            (
                "name = \"AddAtomA\"\nordinal = 1\ngroup = \"termination\"",
                "unknown key",
            ),
            ("name = \"AddAtomA\"\nordinal = 0x10", "share ordinal 16"),
            ("name = \"GetVersion\"\nordinal = 2", "declared twice"),
            ("name = \"Add Atom\"\nordinal = 2", "printable ASCII"),
        ] {
            let text = format!("{SPEC}\n[[export]]\n{record}\n");
            let error = parse_spec(&text).unwrap_err();
            assert!(error.contains(message), "{record}: {error}");
        }
        let zw = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\ngroup = \"nt\"\n\
                  args = [\"handle Handle\"]\nimpl = { syscall = \"x\" }\nzw_ordinal = 3\n";
        assert_eq!(
            parse_spec(zw)
                .unwrap()
                .export("NtClose")
                .unwrap()
                .zw_ordinal,
            Some(3)
        );
        let decorated =
            format!("{SPEC}\n[[export]]\nname = \"??0exception@@QAE@XZ\"\nordinal = 2\n");
        assert_eq!(parse_spec(&decorated).unwrap().catalogued.len(), 1);
        let apart = format!("{zw}\n[[export]]\nname = \"ZwClose\"\nordinal = 4\n");
        assert!(parse_spec(&apart).unwrap_err().contains("alias"));
        let clash = format!("{zw}\n[[export]]\nname = \"NtYieldExecution\"\nordinal = 3\n");
        assert!(parse_spec(&clash).unwrap_err().contains("share ordinal 3"));
        let not_a_service = SPEC.replacen("ordinal = 0x10", "ordinal = 0x10\nzw_ordinal = 3", 1);
        assert!(parse_spec(&not_a_service)
            .unwrap_err()
            .contains("zw_ordinal"));
        let twice = format!(
            "{SPEC}\n[[export]]\nname = \"GetVersion\"\ngroup = \"termination\"\nargs = []\nimpl = {{ native = \"x\" }}\n"
        );
        assert!(parse_spec(&twice).unwrap_err().contains("declared twice"));
        // A stub gives its reason and its failure return; the variable arguments come last.
        for (record, message) in [
            (
                "args = []\nimpl = { stub = \"\" }\nfails = \"FALSE\"",
                "its reason",
            ),
            (
                "args = []\nimpl = { stub = \"not yet implemented\" }",
                "failure return",
            ),
            (
                "args = [\"...\", \"u32 x\"]\nimpl = { native = \"x\" }",
                "come last",
            ),
        ] {
            let text = format!(
                "{SPEC}\n[[export]]\nname = \"Stubbed\"\ngroup = \"termination\"\n{record}\n"
            );
            let error = parse_spec(&text).unwrap_err();
            assert!(error.contains(message), "{record}: {error}");
        }
        let syscall = "[[group]]\nkey = \"nt\"\ntitle = \"nt\"\n\n[[export]]\nname = \"NtClose\"\n\
                       group = \"nt\"\nargs = [\"handle x\", \"...\"]\nimpl = { syscall = \"x\" }\n";
        assert!(parse_spec(syscall)
            .unwrap_err()
            .contains("variable arguments"));
        let stub = format!(
            "{SPEC}\n[[export]]\nname = \"Stubbed\"\ngroup = \"termination\"\nargs = [\"strA f\", \"...\"]\n\
             impl = {{ stub = \"not yet implemented\" }}\nfails = \"void\"\n"
        );
        let spec = parse_spec(&stub).unwrap();
        let stubbed = spec.export("Stubbed").unwrap();
        assert_eq!(
            stubbed.implementation,
            Implementation::Stub("not yet implemented".into())
        );
        assert_eq!(stubbed.arg_bytes(), 4);
        assert_eq!(stubbed.args[1].to_string(), "...");
        assert_eq!(spec.stubs().len(), 1);
    }
}
