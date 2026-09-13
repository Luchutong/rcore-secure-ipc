use crate::fs::{OpenFlags, make_pipe, open_file};
use crate::mm::{
    MAX_STR_LEN, UserBuffer, copy_bytes_from_user, try_translated_byte_buffer, try_translated_str,
};
use crate::task::{current_task, current_user_token};
use alloc::sync::Arc;

pub fn sys_write(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    let Some(file) = &inner.fd_table[fd] else {
        return -1;
    };
    if !file.writable() {
        return -1;
    }
    let file = file.clone();
    let request = file.ipc_object().map(|object| {
        let credentials = inner.security.credentials;
        crate::security::IpcRequest {
            subject: crate::security::IpcSubject {
                pid: task.getpid(),
                uid: credentials.uid,
                capabilities: credentials.capabilities,
            },
            object,
            operation: crate::security::IpcOperation::PipeWrite,
            amount: len,
        }
    });
    drop(inner);

    // B+C+D order: validate user memory, authorize, perform I/O, then audit outcome.
    let user_buffer = match copy_bytes_from_user(token, buf, len) {
        Ok(buffer) => buffer,
        Err(error) => {
            if let Some(request) = &request {
                crate::security::record_failure(request, error);
            }
            return ipc_error_to_ret(error);
        }
    };
    let Some(request) = request else {
        return if len == 0 {
            0
        } else {
            file.write(user_buffer) as isize
        };
    };
    let permit = {
        let mut inner = task.inner_exclusive_access();
        match crate::security::preflight(&mut inner.security, request) {
            Ok(permit) => permit,
            Err(error) => return ipc_error_to_ret(error),
        }
    };
    let written = if len == 0 { 0 } else { file.write(user_buffer) };
    let mut inner = task.inner_exclusive_access();
    match crate::security::complete(&mut inner.security, permit, Ok(written)) {
        Ok(value) => value as isize,
        Err(error) => ipc_error_to_ret(error),
    }
}

pub fn sys_read(fd: usize, buf: *const u8, len: usize) -> isize {
    let token = current_user_token();
    let task = current_task().unwrap();
    let inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    let Some(file) = &inner.fd_table[fd] else {
        return -1;
    };
    let file = file.clone();
    if !file.readable() {
        return -1;
    }
    let request = file.ipc_object().map(|object| {
        let credentials = inner.security.credentials;
        crate::security::IpcRequest {
            subject: crate::security::IpcSubject {
                pid: task.getpid(),
                uid: credentials.uid,
                capabilities: credentials.capabilities,
            },
            object,
            operation: crate::security::IpcOperation::PipeRead,
            amount: len,
        }
    });
    drop(inner);

    let Some(buffers) = try_translated_byte_buffer(token, buf, len, true) else {
        if let Some(request) = &request {
            crate::security::record_failure(request, crate::security::IpcError::InvalidAddress);
        }
        return ipc_error_to_ret(crate::security::IpcError::InvalidAddress);
    };
    let Some(request) = request else {
        return if len == 0 {
            0
        } else {
            file.read(UserBuffer::new(buffers)) as isize
        };
    };
    let permit = {
        let mut inner = task.inner_exclusive_access();
        match crate::security::preflight(&mut inner.security, request) {
            Ok(permit) => permit,
            Err(error) => return ipc_error_to_ret(error),
        }
    };
    let read = if len == 0 {
        0
    } else {
        file.read(UserBuffer::new(buffers))
    };
    let mut inner = task.inner_exclusive_access();
    match crate::security::complete(&mut inner.security, permit, Ok(read)) {
        Ok(value) => value as isize,
        Err(error) => ipc_error_to_ret(error),
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
    // 校验路径字符串：非法指针或超长返回 EFAULT，不 panic。
    let Some(path) = try_translated_str(token, path, MAX_STR_LEN) else {
        return ipc_error_to_ret(crate::security::IpcError::InvalidAddress);
    };
    // 校验用户传入的打开标志：非法位组合返回 EINVAL，不 panic。
    let Some(open_flags) = OpenFlags::from_bits(flags) else {
        return ipc_error_to_ret(crate::security::IpcError::InvalidArgument);
    };
    if let Some(inode) = open_file(path.as_str(), open_flags) {
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
            // Audit ABI counts one pipe creation. quota::reserve separately
            // charges the two file-descriptor endpoints.
            amount: 1,
        };

        let permit = match crate::security::preflight(&mut inner.security, request) {
            Ok(permit) => permit,
            Err(error) => return ipc_error_to_ret(error),
        };

        let (pipe_read, pipe_write) = match make_pipe(credentials.uid) {
            Ok(pipe) => pipe,
            Err(error) => {
                return match crate::security::complete(&mut inner.security, permit, Err(error)) {
                    Ok(value) => value as isize,
                    Err(error) => ipc_error_to_ret(error),
                };
            }
        };

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
