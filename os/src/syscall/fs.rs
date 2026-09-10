use crate::fs::{OpenFlags, make_pipe, open_file};
use crate::mm::{
    MAX_STR_LEN, UserBuffer, try_translated_byte_buffer, try_translated_refmut, try_translated_str,
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
    if let Some(file) = &inner.fd_table[fd] {
        if !file.writable() {
            return -1;
        }
        let file = file.clone();
        // release current task TCB manually to avoid multi-borrow
        drop(inner);
        // 内核从用户缓冲区读取数据：要求用户页可读
        let Some(buffers) = try_translated_byte_buffer(token, buf, len, false) else {
            return -1;
        };
        file.write(UserBuffer::new(buffers)) as isize
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
        // 内核向用户缓冲区写入数据：要求用户页可写
        let Some(buffers) = try_translated_byte_buffer(token, buf, len, true) else {
            return -1;
        };
        file.read(UserBuffer::new(buffers)) as isize
    } else {
        -1
    }
}

pub fn sys_open(path: *const u8, flags: u32) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    // 校验路径字符串：非法指针或超长返回 -1，不 panic
    let Some(path) = try_translated_str(token, path, MAX_STR_LEN) else {
        return -1;
    };
    // 校验用户传入的打开标志：非法位组合返回 -1，不 panic
    let Some(open_flags) = OpenFlags::from_bits(flags) else {
        return -1;
    };
    if let Some(inode) = open_file(path.as_str(), open_flags) {
        let mut inner = task.inner_exclusive_access();
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
    0
}

pub fn sys_pipe(pipe: *mut usize) -> isize {
    let task = current_task().unwrap();
    let token = current_user_token();
    // 先校验两个用户指针，全部合法后才分配 fd，避免中途失败泄漏 fd
    let Some(read_slot) = try_translated_refmut(token, pipe) else {
        return -1;
    };
    let Some(write_slot) = try_translated_refmut(token, unsafe { pipe.add(1) }) else {
        return -1;
    };
    let mut inner = task.inner_exclusive_access();
    let (pipe_read, pipe_write) = make_pipe();
    let read_fd = inner.alloc_fd();
    inner.fd_table[read_fd] = Some(pipe_read);
    let write_fd = inner.alloc_fd();
    inner.fd_table[write_fd] = Some(pipe_write);
    *read_slot = read_fd;
    *write_slot = write_fd;
    0
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
    let new_fd = inner.alloc_fd();
    inner.fd_table[new_fd] = Some(Arc::clone(inner.fd_table[fd].as_ref().unwrap()));
    new_fd as isize
}
