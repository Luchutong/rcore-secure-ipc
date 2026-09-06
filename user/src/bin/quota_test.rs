#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{close, dup, pipe};

const MAX_OPEN_FILES: usize = 32;
const STDIO_FILES: usize = 3;
const MAX_PIPE_FDS: usize = 16;

fn test_fd_limit_and_reuse() {
    let mut duplicates = [0usize; MAX_OPEN_FILES - STDIO_FILES];

    for slot in duplicates.iter_mut() {
        let fd = dup(0);
        assert!(fd >= 0);
        *slot = fd as usize;
    }
    assert_eq!(dup(0), -1);

    for fd in duplicates {
        assert_eq!(close(fd), 0);
    }

    let reused = dup(0);
    assert!(reused >= 0);
    assert_eq!(close(reused as usize), 0);
}

fn test_pipe_limit_and_rollback() {
    let mut pipes = [[0usize; 2]; MAX_PIPE_FDS / 2];

    for pipe_fds in pipes.iter_mut() {
        assert_eq!(pipe(pipe_fds), 0);
    }

    let mut rejected = [usize::MAX; 2];
    assert_eq!(pipe(&mut rejected), -1);
    assert_eq!(rejected, [usize::MAX; 2]);

    // One free endpoint is insufficient for an atomic two-endpoint pipe.
    assert_eq!(close(pipes[0][0]), 0);
    assert_eq!(pipe(&mut rejected), -1);

    // Duplicating a pipe endpoint consumes pipe quota, and closing the
    // duplicate releases it again.
    let duplicated_pipe_fd = dup(pipes[1][0]);
    assert!(duplicated_pipe_fd >= 0);
    assert_eq!(pipe(&mut rejected), -1);
    assert_eq!(close(duplicated_pipe_fd as usize), 0);
    assert_eq!(pipe(&mut rejected), -1);

    // Once both endpoints are released, a complete pipe can be created.
    assert_eq!(close(pipes[0][1]), 0);
    assert_eq!(pipe(&mut rejected), 0);
    assert_eq!(close(rejected[0]), 0);
    assert_eq!(close(rejected[1]), 0);

    for pipe_fds in pipes.iter().skip(1) {
        assert_eq!(close(pipe_fds[0]), 0);
        assert_eq!(close(pipe_fds[1]), 0);
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    test_fd_limit_and_reuse();
    test_pipe_limit_and_rollback();
    println!("quota_test passed!");
    0
}
