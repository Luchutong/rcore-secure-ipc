//! Compatibility boundary for safe user-memory access.
//!
//! The current adapters preserve baseline behavior while giving the user
//! access feature branch stable call sites to harden.

use super::{translated_ref, translated_refmut};
use crate::security::IpcResult;

/// Copy a plain value from user memory.
pub fn copy_from_user<T: Copy>(token: usize, src: *const T) -> IpcResult<T> {
    Ok(*translated_ref(token, src))
}

/// Copy a plain value to user memory.
pub fn copy_to_user<T: Copy>(token: usize, dst: *mut T, value: &T) -> IpcResult<()> {
    *translated_refmut(token, dst) = *value;
    Ok(())
}
