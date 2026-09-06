#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{OpenFlags, close, dup, exit, fork, open, pipe, waitpid};

const EMFILE: isize = -24;
const ENOSPC: isize = -28;

const MAX_OPEN_FILES: usize = 32;
const MAX_OPEN_PIPE_FDS: usize = 16;
const INITIAL_FDS: usize = 3;

fn close_pair(pair: &[usize; 2]) {
    assert_eq!(close(pair[0]), 0);
    assert_eq!(close(pair[1]), 0);
}

/// Verify that ordinary open() calls are limited by MAX_OPEN_FILES and that
/// closing one descriptor immediately makes quota available again.
fn test_open_fd_limit_and_recovery() {
    println!("[quota] open FD exhaustion + recovery");

    // Create the test file once, then release the descriptor again.
    let seed = open("quota_fd_test\0", OpenFlags::CREATE | OpenFlags::RDWR);
    assert!(seed >= 0);
    assert_eq!(close(seed as usize), 0);

    // stdin/stdout/stderr already consume three descriptors, so 29 more
    // descriptors should exactly reach MAX_OPEN_FILES == 32.
    let mut fds = [0usize; MAX_OPEN_FILES - INITIAL_FDS];

    for slot in fds.iter_mut() {
        let fd = open("quota_fd_test\0", OpenFlags::RDONLY);
        assert!(fd >= 0);
        *slot = fd as usize;
    }

    // The next open must fail with EMFILE.
    assert_eq!(open("quota_fd_test\0", OpenFlags::RDONLY), EMFILE);

    // Release one slot and verify that it can immediately be reused.
    assert_eq!(close(fds[0]), 0);

    let recovered = open("quota_fd_test\0", OpenFlags::RDONLY);
    assert!(recovered >= 0);
    assert_eq!(close(recovered as usize), 0);

    for fd in fds.iter().skip(1) {
        assert_eq!(close(*fd), 0);
    }

    println!("[quota] open FD exhaustion + recovery passed");
}

/// Verify the ordinary-file branch of dup() quota accounting.
fn test_dup_fd_limit_and_recovery() {
    println!("[quota] dup FD exhaustion + recovery");

    let mut fds = [0usize; MAX_OPEN_FILES - INITIAL_FDS];

    for slot in fds.iter_mut() {
        let fd = dup(1);
        assert!(fd >= 0);
        *slot = fd as usize;
    }

    assert_eq!(dup(1), EMFILE);

    assert_eq!(close(fds[0]), 0);

    let recovered = dup(1);
    assert!(recovered >= 0);
    assert_eq!(close(recovered as usize), 0);

    for fd in fds.iter().skip(1) {
        assert_eq!(close(*fd), 0);
    }

    println!("[quota] dup FD exhaustion + recovery passed");
}

/// Eight pipes consume sixteen pipe endpoint descriptors. The ninth pipe must
/// fail with ENOSPC. Closing one complete pipe must allow another pipe.
fn test_pipe_limit_and_recovery() {
    println!("[quota] pipe exhaustion + recovery");

    const PIPE_COUNT: usize = MAX_OPEN_PIPE_FDS / 2;

    let mut pipes = [[0usize; 2]; PIPE_COUNT];

    for pair in pipes.iter_mut() {
        assert_eq!(pipe(pair), 0);
    }

    let mut extra = [0usize; 2];

    // Pipe-specific quota is exhausted before the total FD limit.
    assert_eq!(pipe(&mut extra), ENOSPC);

    // Free two pipe endpoints.
    close_pair(&pipes[0]);

    // Exactly one pipe should now fit again.
    assert_eq!(pipe(&mut extra), 0);
    close_pair(&extra);

    for pair in pipes.iter().skip(1) {
        close_pair(pair);
    }

    println!("[quota] pipe exhaustion + recovery passed");
}

/// Verify that total FD exhaustion takes precedence over the pipe-specific
/// limit when pipe() cannot reserve two total FD slots.
fn test_pipe_emfile_and_rollback() {
    println!("[quota] pipe EMFILE + rollback");

    // Leave exactly one total FD slot free:
    // 3 initial + 28 duplicates = 31.
    let mut fds = [0usize; MAX_OPEN_FILES - INITIAL_FDS - 1];

    for slot in fds.iter_mut() {
        let fd = dup(1);
        assert!(fd >= 0);
        *slot = fd as usize;
    }

    let mut pair = [0usize; 2];

    // pipe() requires two descriptors, so this must be EMFILE.
    assert_eq!(pipe(&mut pair), EMFILE);

    // The failed reservation must not leak quota. Freeing one descriptor
    // leaves exactly two slots, so pipe() must now succeed.
    assert_eq!(close(fds[0]), 0);
    assert_eq!(pipe(&mut pair), 0);

    close_pair(&pair);

    for fd in fds.iter().skip(1) {
        assert_eq!(close(*fd), 0);
    }

    println!("[quota] pipe EMFILE + rollback passed");
}

/// Verify that dup(pipe_fd) consumes pipe quota as well as ordinary FD quota.
fn test_pipe_dup_quota() {
    println!("[quota] dup(pipe_fd) accounting");

    let mut pair = [0usize; 2];
    assert_eq!(pipe(&mut pair), 0);

    // The original pipe already consumes two pipe endpoint slots.
    let mut duplicates = [0usize; MAX_OPEN_PIPE_FDS - 2];

    for slot in duplicates.iter_mut() {
        let fd = dup(pair[0]);
        assert!(fd >= 0);
        *slot = fd as usize;
    }

    // We now have sixteen pipe endpoint FDs.
    assert_eq!(dup(pair[0]), ENOSPC);

    // Closing one duplicated pipe FD must release one pipe quota slot.
    assert_eq!(close(duplicates[0]), 0);

    let recovered = dup(pair[0]);
    assert!(recovered >= 0);
    assert_eq!(close(recovered as usize), 0);

    for fd in duplicates.iter().skip(1) {
        assert_eq!(close(*fd), 0);
    }

    close_pair(&pair);

    println!("[quota] dup(pipe_fd) accounting passed");
}

/// Verify that fork copies quota state, but the parent's and child's later
/// quota accounting remain independent.
fn test_fork_quota_isolation() {
    println!("[quota] fork inheritance + isolation");

    // Parent starts with fourteen pipe endpoint descriptors.
    let mut inherited = [[0usize; 2]; 7];

    for pair in inherited.iter_mut() {
        assert_eq!(pipe(pair), 0);
    }

    let pid = fork();
    assert!(pid >= 0);

    if pid == 0 {
        // Child inherited open_pipes == 14.
        // Release two inherited endpoints in the child only.
        close_pair(&inherited[0]);

        // Child now has twelve endpoints, so two more pipes fit.
        let mut child_a = [0usize; 2];
        let mut child_b = [0usize; 2];
        let mut child_fail = [0usize; 2];

        assert_eq!(pipe(&mut child_a), 0);
        assert_eq!(pipe(&mut child_b), 0);
        assert_eq!(pipe(&mut child_fail), ENOSPC);

        exit(0);
    }

    let mut exit_code = -1;
    assert_eq!(waitpid(pid as usize, &mut exit_code), pid);
    assert_eq!(exit_code, 0);

    // The child's close/create operations must not change the parent's
    // open_pipes == 14 state. Therefore exactly one more pipe fits.
    let mut parent_extra = [0usize; 2];
    let mut parent_fail = [0usize; 2];

    assert_eq!(pipe(&mut parent_extra), 0);
    assert_eq!(pipe(&mut parent_fail), ENOSPC);

    close_pair(&parent_extra);

    for pair in inherited.iter() {
        close_pair(pair);
    }

    println!("[quota] fork inheritance + isolation passed");
}

fn churn_pipes(rounds: usize) {
    for _ in 0..rounds {
        let mut pair = [0usize; 2];
        assert_eq!(pipe(&mut pair), 0);
        close_pair(&pair);
    }
}

/// Stress repeated create/close from two processes so descriptor reuse and
/// quota release are exercised repeatedly.
fn test_concurrent_create_close() {
    println!("[quota] concurrent create/close");

    let pid = fork();
    assert!(pid >= 0);

    if pid == 0 {
        churn_pipes(32);
        exit(0);
    }

    churn_pipes(32);

    let mut exit_code = -1;
    assert_eq!(waitpid(pid as usize, &mut exit_code), pid);
    assert_eq!(exit_code, 0);

    println!("[quota] concurrent create/close passed");
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    println!("========== quota_test ==========");

    test_open_fd_limit_and_recovery();
    test_dup_fd_limit_and_recovery();
    test_pipe_limit_and_recovery();
    test_pipe_emfile_and_rollback();
    test_pipe_dup_quota();
    test_fork_quota_isolation();
    test_concurrent_create_close();

    println!("quota_test passed!");
    0
}
