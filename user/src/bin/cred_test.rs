//! IPC security test: kill authorization matrix.
//!
//! Tests that signal sending respects UID-based authorization:
//! - Same-UID kill is allowed
//! - Cross-UID kill without KILL capability is denied (EPERM)
//! - Root can kill any process
//!
//! Run inside rCore user shell: `cred_test`

#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

use user_lib::{fork, getpid, getuid, setuid, kill, wait, yield_};

const SIGUSR1: i32 = 10;

#[unsafe(no_mangle)]
fn main() -> i32 {
    println!("=== credential kill authorization test ===");

    // -------------------------------------------------------
    // Test 1: root identity check
    // -------------------------------------------------------
    println!("[test 1] root identity check");
    let uid = getuid();
    println!("  uid={}", uid);
    assert_eq!(uid, 0, "init should be root");
    println!("  PASS: init process has uid=0");

    // -------------------------------------------------------
    // Test 2: root kills same-UID child (should succeed)
    // -------------------------------------------------------
    println!("[test 2] root kills same-uid child");
    let child = fork();
    if child == 0 {
        // Child: spin and wait to be killed.
        let mut slept = 0;
        while slept < 50 {
            yield_();
            slept += 1;
        }
        return 99; // timeout — wasn't killed
    }
    // Parent: send SIGUSR1 to child (same UID=0).
    let ret = kill(child as usize, SIGUSR1);
    assert_eq!(ret, 0, "same-uid kill should succeed");
    println!("  PASS: same-uid kill returned 0");

    let mut exit_code: i32 = 0;
    wait(&mut exit_code);
    println!("  child exit_code={}", exit_code);

    // -------------------------------------------------------
    // Test 3: cross-UID kill denied (EPERM)
    //   child_a drops to uid=1, tries to kill parent (uid=0)
    // -------------------------------------------------------
    println!("[test 3] cross-uid kill denied");
    let parent_pid = getpid() as usize;
    let child = fork();
    if child == 0 {
        // Drop to uid=1.
        setuid(1);
        let uid = getuid();
        if uid != 1 {
            println!("  FAIL: uid should be 1, got {}", uid);
            return -1;
        }
        // Try to kill parent (uid=0). Should be denied.
        let ret = kill(parent_pid, SIGUSR1);
        if ret == -1 {
            println!("  PASS: cross-uid kill returned -1 (EPERM)");
            return 0;
        } else {
            println!("  FAIL: cross-uid kill returned {} (expected -1)", ret);
            return -1;
        }
    }
    let mut ec: i32 = 0;
    wait(&mut ec);
    println!("  child_a exit_code={}", ec);

    // -------------------------------------------------------
    // Test 4: root kills non-privileged process (should succeed)
    // -------------------------------------------------------
    println!("[test 4] root kills non-privileged process");
    let child = fork();
    if child == 0 {
        // Child: drop to uid=1, then wait.
        setuid(1);
        let uid = getuid();
        println!("  child uid={}", uid);
        let mut slept = 0;
        while slept < 50 {
            yield_();
            slept += 1;
        }
        return 99; // timeout
    }
    // Parent (uid=0) kills child (uid=1) — should succeed.
    let ret = kill(child as usize, SIGUSR1);
    assert_eq!(ret, 0, "root kill non-priv should succeed");
    println!("  PASS: root kill non-priv returned 0");
    let mut ec: i32 = 0;
    wait(&mut ec);

    // -------------------------------------------------------
    // Test 5: non-privileged same-UID kill (should succeed)
    //   child_a (uid=1) forks child_b (uid=1), kills child_b
    // -------------------------------------------------------
    println!("[test 5] non-priv same-uid kill");
    let child = fork();
    if child == 0 {
        // Drop to uid=1.
        setuid(1);

        // Fork a grandchild (also uid=1).
        let grandchild = fork();
        if grandchild == 0 {
            // Grandchild: wait.
            let mut slept = 0;
            while slept < 50 {
                yield_();
                slept += 1;
            }
            return 99; // timeout
        }

        // Kill grandchild (same uid=1) — should succeed.
        let ret = kill(grandchild as usize, SIGUSR1);
        if ret == 0 {
            println!("  PASS: non-priv same-uid kill returned 0");
        } else {
            println!("  FAIL: non-priv same-uid kill returned {}", ret);
        }
        let mut ec: i32 = 0;
        wait(&mut ec);
        return 0;
    }
    let mut ec: i32 = 0;
    wait(&mut ec);

    println!("=== all credential tests done ===");
    0
}
