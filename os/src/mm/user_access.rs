//! Compatibility boundary for safe user-memory access.
//!
//! All user pointers are validated before dereference; a bad pointer
//! yields `IpcError::InvalidAddress` instead of panicking the kernel.

use core::mem::{MaybeUninit, size_of};

use super::try_translated_byte_buffer;
use crate::security::{IpcError, IpcResult};

/// Copy a plain value from user memory.
pub fn copy_from_user<T: Copy + 'static>(token: usize, src: *const T) -> IpcResult<T> {
    let size = size_of::<T>();
    if size == 0 {
        return Err(IpcError::InvalidArgument);
    }

    let buffers = try_translated_byte_buffer(token, src.cast::<u8>(), size, false)
        .ok_or(IpcError::InvalidAddress)?;
    let mut value = MaybeUninit::<T>::uninit();
    let destination =
        unsafe { core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), size) };
    let mut offset = 0;
    for buffer in buffers {
        let end = offset + buffer.len();
        destination[offset..end].copy_from_slice(buffer);
        offset = end;
    }
    debug_assert_eq!(offset, size);
    Ok(unsafe { value.assume_init() })
}

/// Copy a plain value to user memory.
pub fn copy_to_user<T: Copy + 'static>(token: usize, dst: *mut T, value: &T) -> IpcResult<()> {
    let size = size_of::<T>();
    if size == 0 {
        return Err(IpcError::InvalidArgument);
    }

    let buffers = try_translated_byte_buffer(token, dst.cast::<u8>(), size, true)
        .ok_or(IpcError::InvalidAddress)?;
    let source = unsafe { core::slice::from_raw_parts((value as *const T).cast::<u8>(), size) };
    let mut offset = 0;
    for buffer in buffers {
        let end = offset + buffer.len();
        buffer.copy_from_slice(&source[offset..end]);
        offset = end;
    }
    debug_assert_eq!(offset, size);
    Ok(())
}
