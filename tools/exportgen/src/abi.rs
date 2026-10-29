//! The kernel ABI constants the system DLLs' assembly uses: the gate vector and the internal
//! service numbers (kernel/src/user/syscall.rs), read off the kernel's sources so the two sides
//! cannot disagree.

use std::fmt::Write;
use std::path::Path;

/// `pub const <NAME>: <integer type> = <literal>;` lines of `text` whose name `wanted` accepts, in
/// file order.
fn constants(text: &str, wanted: impl Fn(&str) -> bool) -> Vec<(String, u32)> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("pub const ")?;
            let (name, rest) = rest.split_once(':')?;
            let (kind, value) = rest.split_once('=')?;
            let kind = kind.trim();
            if !wanted(name) || !(kind.starts_with('u') || kind == "usize") {
                return None;
            }
            let value = value.trim().strip_suffix(';')?.replace('_', "");
            let value = match value.strip_prefix("0x") {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => value.parse().ok()?,
            };
            Some((name.to_string(), value))
        })
        .collect()
}

/// The constants, from the kernel's sources under `repo`: the syscall module's `SYS_*` and
/// `SYSCALL_VECTOR`.
pub fn kernel_constants(repo: &Path) -> Result<Vec<(String, u32)>, String> {
    let read = |relative: &str| {
        std::fs::read_to_string(repo.join(relative)).map_err(|e| format!("{relative}: {e}"))
    };
    let found = constants(&read("kernel/src/user/syscall.rs")?, |name| {
        name.starts_with("SYS_") || name == "SYSCALL_VECTOR"
    });
    if !found.iter().any(|(name, _)| name == "SYSCALL_VECTOR") {
        return Err("kernel/src/user/syscall.rs: no SYSCALL_VECTOR".to_string());
    }
    Ok(found)
}

/// The constants as assembler `.set` lines.
pub fn consts_s(constants: &[(String, u32)]) -> String {
    let mut out = String::new();
    for (name, value) in constants {
        writeln!(out, ".set {name}, {value:#x}").unwrap();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_integer_constants_in_file_order() {
        let text = "pub const SYS_EXIT: u32 = 1;\n  pub const SYSCALL_VECTOR: u8 = 0x2E;\n\
                    pub const SYS_THREAD_EXIT: u32 = 0x8000_0000;\npub const OTHER: u32 = 3;\n\
                    pub const SYS_NAME: &str = \"x\";\n";
        let found = constants(text, |n| n.starts_with("SYS"));
        assert_eq!(
            found,
            [
                ("SYS_EXIT".into(), 1),
                ("SYSCALL_VECTOR".into(), 0x2E),
                ("SYS_THREAD_EXIT".into(), 0x8000_0000)
            ]
        );
        assert_eq!(consts_s(&found[..1]), ".set SYS_EXIT, 0x1\n");
    }
}
