mod inode;
mod pipe;
mod stdio;

use crate::mm::UserBuffer;
use crate::security::IpcObject;

pub trait File: Send + Sync {
    fn readable(&self) -> bool;
    fn writable(&self) -> bool;
    fn read(&self, buf: UserBuffer) -> usize;
    fn write(&self, buf: UserBuffer) -> usize;
    /// IPC files expose stable audit metadata; ordinary files use `None`.
    fn ipc_object(&self) -> Option<IpcObject> {
        None
    }
}

pub use inode::{OpenFlags, list_apps, open_file};
pub use pipe::make_pipe;
pub use stdio::{Stdin, Stdout};
