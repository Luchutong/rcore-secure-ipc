use crate::fs::{OpenFlags, make_pipe, open_file};
use crate::mm::{UserBuffer, translated_byte_buffer, translated_str};
use crate::task::{current_task, current_user_token};
use alloc::sync::Arc;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.write(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    if let Some(file) = &inner.fd_table[fd] {
        let file = file.clone();
        if !file.readable() {
            return -1;
        }
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        file.read(UserBuffer::new(translated_byte_buffer(token, buf, len))) as isize
    } else {
        -1
    }
}

fn ipc_error_to_ret(error: crate::security::IpcError) -> isize {
    match error {
        crate::security::IpcError::PermissionDenied => -1, // EPERM
        crate::security::IpcError::InvalidAddress => -14,  // EFAULT
        crate::security::IpcError::InvalidArgument => -22, // EINVAL
        crate::security::IpcError::ProcessNotFound => -3,  // ESRCH
        crate::security::IpcError::TooManyFiles => -24,    // EMFILE
        crate::security::IpcError::ResourceExhausted => -28, // ENOSPC
        crate::security::IpcError::TryAgain => -11,        // EAGAIN
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);

    if let Some(inode) = open_file(path.as_str(), OpenFlags::from_bits(flags).unwrap()) {
        let mut inner = task.inner_exclusive_access();

        if let Err(error) = crate::security::reserve_file_fd(&mut inner.security) {
            return ipc_error_to_ret(error);
        }

        let fd = inner.alloc_fd();
        inner.fd_table[fd] = Some(inode);
        fd as isize
    } else {
        -1
    }
}

pub fn sys_close(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();

    if fd >= inner.fd_table.len() {
        return -1;
    }

    if inner.fd_table[fd].is_none() {
        return -1;
    }

    inner.fd_table[fd].take();
    crate::security::release_fd(&mut inner.security, fd);

    0
}

pub fn sys_pipe(pipe: *mut usize) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let pid = task.getpid();

    // Preflight reserves two total FD slots and two pipe endpoint slots.
    let (permit, read_fd, write_fd) = {
        let mut inner = task.inner_exclusive_access();

        let credentials = inner.security.credentials;

        let request = crate::security::IpcRequest {
            subject: crate::security::IpcSubject {
                pid,
                uid: credentials.uid,
                capabilities: credentials.capabilities,
            },
            object: crate::security::IpcObject {
                // A newly-created pipe has no pre-existing target object.
                id: 0,
                owner_uid: credentials.uid,
            },
            operation: crate::security::IpcOperation::PipeCreate,
            amount: 2,
        };

        let permit = match crate::security::preflight(&mut inner.security, request) {
            Ok(permit) => permit,
            Err(error) => return ipc_error_to_ret(error),
        };

        let (pipe_read, pipe_write) = make_pipe();

        let read_fd = inner.alloc_fd();
        inner.fd_table[read_fd] = Some(pipe_read);

        let write_fd = inner.alloc_fd();
        inner.fd_table[write_fd] = Some(pipe_write);

        (permit, read_fd, write_fd)
    };

    // Do not hold the task's inner state while touching user memory.
    let copy_result = crate::mm::copy_to_user(token, pipe, &read_fd)
        .and_then(|_| crate::mm::copy_to_user(token, pipe.wrapping_add(1), &write_fd));

    let mut inner = task.inner_exclusive_access();

    match copy_result {
        Ok(()) => {
            // Descriptor numbers become committed pipe endpoints only after
            // the result has been successfully copied back to user space.
            crate::security::register_pipe_fd(&mut inner.security, read_fd);
            crate::security::register_pipe_fd(&mut inner.security, write_fd);

            match crate::security::complete(&mut inner.security, permit, Ok(0)) {
                Ok(value) => value as isize,
                Err(error) => ipc_error_to_ret(error),
            }
        }
        Err(error) => {
            // Remove the concrete descriptors first. They have not yet been
            // registered in the pipe bitmap, so quota rollback belongs to
            // `complete(..., Err(...))`.
            if read_fd < inner.fd_table.len() {
                inner.fd_table[read_fd].take();
            }

            if write_fd < inner.fd_table.len() {
                inner.fd_table[write_fd].take();
            }

            match crate::security::complete(&mut inner.security, permit, Err(error)) {
                Ok(value) => value as isize,
                Err(error) => ipc_error_to_ret(error),
            }
        }
    }
}

pub fn sys_dup(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();

    if fd >= inner.fd_table.len() {
        return -1;
    }

    if inner.fd_table[fd].is_none() {
        return -1;
    }

    let file = Arc::clone(inner.fd_table[fd].as_ref().unwrap());

    let source_is_pipe = match crate::security::reserve_dup_fd(&mut inner.security, fd) {
        Ok(is_pipe) => is_pipe,
        Err(error) => return ipc_error_to_ret(error),
    };

    let new_fd = inner.alloc_fd();
    inner.fd_table[new_fd] = Some(file);

    if source_is_pipe {
        crate::security::register_pipe_fd(&mut inner.security, new_fd);
    }

    new_fd as isize
}
