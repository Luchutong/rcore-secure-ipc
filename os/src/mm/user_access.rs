//! Compatibility boundary for safe user-memory access.
//!
//! All user pointers are validated before dereference; a bad pointer
//! yields `IpcError::InvalidAddress` instead of panicking the kernel.

use super::{try_translated_ref, try_translated_refmut};
use crate::security::{IpcError, IpcResult};

/// Copy a plain value from user memory.
pub fn copy_from_user<T: Copy + 'static>(token: usize, src: *const T) -> IpcResult<T> {
    match try_translated_ref(token, src) {
        Some(r) => Ok(*r),
        None => Err(IpcError::InvalidAddress),
    }
}

/// Copy a plain value to user memory.
pub fn copy_to_user<T: Copy + 'static>(token: usize, dst: *mut T, value: &T) -> IpcResult<()> {
    match try_translated_refmut(token, dst) {
        Some(r) => {
            *r = *value;
            Ok(())
        }
        None => Err(IpcError::InvalidAddress),
    }
}
