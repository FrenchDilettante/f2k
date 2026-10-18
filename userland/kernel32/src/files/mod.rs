//! The file calls: kernel32's handle-level file exports ([`handle`]). Their console branches are
//! here now; their file halves come with the NT file services (B8, B9).

pub mod handle;
