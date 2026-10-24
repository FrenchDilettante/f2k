//! msvcrt.dll's build: its .def and its stubs' bodies from the export specs (see
//! build-support/stubs.rs), linked at Windows 2000's base for it, with its entry point and its
//! assembly exports (src/seh.s).
include!("../build-support/stubs.rs");

fn main() {
    build_dll("msvcrt", 0x7800_0000, Some("DllMain"), &["src/seh.s"]);
}
