// Included by a system DLL's build script beside stubs.rs (kernel32's): a DLL's resources, written
// as a .res file the linker takes as an input (rust-lld in its MSVC mode converts it into the
// image's resource directory), so no resource compiler is needed.
//
// The formats are public. A .res file is a run of resources, each a RESOURCEHEADER (DataSize,
// HeaderSize, the type and the name — numbered ones as 0xFFFF and the number —, DataVersion,
// MemoryFlags, LanguageId, Version, Characteristics) then its data, padded to a dword; it starts
// with an empty one (32 bytes, every field zero but HeaderSize and the 0xFFFF markers). A message
// table (RT_MESSAGETABLE) is winnt.h's MESSAGE_RESOURCE_DATA: the count of blocks, the blocks (the
// first and last identifier of a run of consecutive ones, and the offset of its records), then the
// records (MESSAGE_RESOURCE_ENTRY: its length, its flags — 1, the text is UTF-16 —, the text,
// NUL-terminated and padded to a dword).

/// RT_MESSAGETABLE.
const RT_MESSAGETABLE: u16 = 11;

/// The messages of a messages file (see userland/kernel32/messages.txt): (code, text), in code
/// order, each text ending in CR LF. Panics on a malformed line or a code given twice.
fn messages(source: &str) -> Vec<(u32, String)> {
    let mut messages: Vec<(u32, String)> = source
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (code, text) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("a message is its code, a blank and its text: {line}"));
            let code = code
                .parse()
                .unwrap_or_else(|e| panic!("{code}: not a decimal code: {e}"));
            (code, format!("{text}\r\n"))
        })
        .collect();
    messages.sort_by_key(|&(code, _)| code);
    if let Some(pair) = messages.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        panic!("message {} is given twice", pair[0].0);
    }
    messages
}

/// The MESSAGE_RESOURCE_DATA of `messages` (in code order): one block per run of consecutive codes,
/// every text UTF-16.
fn message_table(messages: &[(u32, String)]) -> Vec<u8> {
    let mut runs: Vec<&[(u32, String)]> = Vec::new();
    let mut start = 0;
    for at in 1..=messages.len() {
        if at == messages.len() || messages[at].0 != messages[at - 1].0 + 1 {
            runs.push(&messages[start..at]);
            start = at;
        }
    }
    let mut records = Vec::new();
    let mut blocks = Vec::new();
    let first_record = 4 + 12 * runs.len();
    for run in &runs {
        blocks.push((run[0].0, run[run.len() - 1].0, first_record + records.len()));
        for (_, text) in run.iter() {
            let mut bytes: Vec<u8> = text
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect();
            bytes.resize(bytes.len().next_multiple_of(4), 0);
            let length = u16::try_from(4 + bytes.len()).expect("a message fits its record");
            records.extend_from_slice(&length.to_le_bytes());
            records.extend_from_slice(&1u16.to_le_bytes());
            records.extend_from_slice(&bytes);
        }
    }
    let mut table = (runs.len() as u32).to_le_bytes().to_vec();
    for (low, high, offset) in blocks {
        for value in [low, high, offset as u32] {
            table.extend_from_slice(&value.to_le_bytes());
        }
    }
    table.extend_from_slice(&records);
    table
}

/// A RESOURCEHEADER for a numbered type and name, `size` bytes of data following.
fn resource_header(size: u32, type_id: u16, name_id: u16, language: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(&size.to_le_bytes());
    header.extend_from_slice(&32u32.to_le_bytes());
    for id in [type_id, name_id] {
        header.extend_from_slice(&0xFFFFu16.to_le_bytes());
        header.extend_from_slice(&id.to_le_bytes());
    }
    header.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    // MemoryFlags: MOVEABLE, PURE and DISCARDABLE, what the resource compiler gives a message
    // table; ignored in a Win32 image.
    let flags: u16 = if size == 0 { 0 } else { 0x1030 };
    header.extend_from_slice(&flags.to_le_bytes());
    header.extend_from_slice(&language.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // Version
    header.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    header
}

/// A .res file holding one resource: a numbered type and name in `language`.
fn res_file(type_id: u16, name_id: u16, language: u16, data: &[u8]) -> Vec<u8> {
    let mut file = resource_header(0, 0, 0, 0);
    file.extend_from_slice(&resource_header(
        data.len() as u32,
        type_id,
        name_id,
        language,
    ));
    file.extend_from_slice(data);
    file.resize(file.len().next_multiple_of(4), 0);
    file
}

/// Link the messages file `source` (relative to the crate) into the DLL as its message table
/// (RT_MESSAGETABLE, name 1, in `language`): `<dll>.res` in OUT_DIR, given to the linker, beside
/// `messages.bin`, the table alone (the host tests' stand-in for RtlFindMessage reads it).
fn link_message_table(dll: &str, source: &str, language: u16) {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=../build-support/resources.rs");
    let path = manifest.join(source);
    println!("cargo:rerun-if-changed={}", path.display());
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let table = message_table(&messages(&text));
    std::fs::write(out.join("messages.bin"), &table).unwrap();
    let res = out.join(format!("{dll}.res"));
    std::fs::write(&res, res_file(RT_MESSAGETABLE, 1, language, &table)).unwrap();
    println!("cargo:rustc-link-arg-bins={}", res.display());
}
