//! kernel32.dll's build: its .def from the export specs (see build-support/stubs.rs), and its
//! system messages (messages.txt) as its message-table resource (see build-support/resources.rs).
include!("../build-support/stubs.rs");
include!("../build-support/resources.rs");

fn main() {
    build_dll(
        "kernel32",
        0x7C4E_0000,
        None,
        &[
            "src/natives.s",
            "src/start.s",
            "src/probe.s",
            "src/critsec.s",
            "src/memory.s",
        ],
    );
    // US English, the language of Windows 2000's own English kernel32.dll's message table.
    link_message_table("kernel32", "messages.txt", 0x0409);
}
