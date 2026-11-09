//! shell32.dll's build: its .def and its stubs' bodies from the export specs (see
//! build-support/stubs.rs), linked at Windows 2000's base for it, with its entry point.
include!("../build-support/stubs.rs");

fn main() {
    build_dll("shell32", 0x782F_0000, Some("DllMain"), &[]);
}
