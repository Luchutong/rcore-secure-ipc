use crate::fs::{OpenFlags, make_pipe, open_file};
use crate::mm::{UserBuffer, copy_to_user, translated_byte_buffer, translated_str};
use crate::security::{self, IpcObject, IpcOperation, IpcRequest, IpcSubject};
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

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    let path = translated_str(token, path);
    let Some(flags) = OpenFlags::from_bits(flags) else {
        return -1;
    };

    {
        let mut inner = task.inner_exclusive_access();
        if inner.security.quota.reserve_files(1).is_err() {
            return -1;
        }
    }

    let Some(inode) = open_file(path.as_str(), flags) else {
        task.inner_exclusive_access()
            .security
            .quota
            .release_files(1);
        return -1;
    };

    let mut inner = task.inner_exclusive_access();
    let fd = inner.alloc_fd();
    inner.fd_table[fd] = Some(inode);
    fd as isize
}

fn pipe_create_request() -> Option<IpcRequest> {
    let task = current_task()?;
    let inner = task.inner_exclusive_access();
    let credentials = inner.security.credentials;

    Some(IpcRequest {
        subject: IpcSubject {
            pid: task.getpid(),
            uid: credentials.uid,
            capabilities: credentials.capabilities,
        },
        object: IpcObject {
            id: 0,
            owner_uid: credentials.uid,
        },
        operation: IpcOperation::PipeCreate,
        // The audit ABI counts one pipe creation operation. Quota accounting
        // independently reserves its two endpoint descriptors.
        amount: 1,
    })
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
    inner.security.quota.release_fd(fd);
    0
}

pub fn sys_pipe(pipe: *mut usize) -> isize {
    let Some(request) = pipe_create_request() else {
        return -1;
    };
    let permit = match security::preflight(request) {
        Ok(permit) => permit,
        Err(_) => return -1,
    };

    let task = current_task().unwrap();
    let token = current_user_token();
    let (pipe_read, pipe_write) = make_pipe();
    let (read_fd, write_fd) = {
        let mut inner = task.inner_exclusive_access();
        let read_fd = inner.alloc_fd();
        inner.fd_table[read_fd] = Some(pipe_read);
        let write_fd = inner.alloc_fd();
        inner.fd_table[write_fd] = Some(pipe_write);
        (read_fd, write_fd)
    };

    let pipe_fds = [read_fd, write_fd];
    if let Err(error) = copy_to_user(token, pipe.cast::<[usize; 2]>(), &pipe_fds) {
        let mut inner = task.inner_exclusive_access();
        inner.fd_table[read_fd].take();
        inner.fd_table[write_fd].take();
        drop(inner);
        let _ = security::complete(permit, Err(error));
        return -1;
    }

    {
        let mut inner = task.inner_exclusive_access();
        inner.security.quota.register_pipe_fd(read_fd);
        inner.security.quota.register_pipe_fd(write_fd);
    }

    match security::complete(permit, Ok(0)) {
        Ok(result) => result as isize,
        Err(_) => -1,
    }
}

pub fn sys_dup(fd: usize) -> isize {
    let task = current_task().unwrap();
    let mut inner = task.inner_exclusive_access();
    if fd >= inner.fd_table.len() {
        return -1;
    }
    let Some(file) = inner.fd_table[fd].as_ref().cloned() else {
        return -1;
    };
    let is_pipe = inner.security.quota.is_pipe_fd(fd);
    let reservation = if is_pipe {
        inner.security.quota.reserve_pipe_fds(1)
    } else {
        inner.security.quota.reserve_files(1)
    };
    if reservation.is_err() {
        return -1;
    }

    let new_fd = inner.alloc_fd();
    inner.fd_table[new_fd] = Some(Arc::clone(&file));
    if is_pipe {
        inner.security.quota.register_pipe_fd(new_fd);
    }
    new_fd as isize
}
