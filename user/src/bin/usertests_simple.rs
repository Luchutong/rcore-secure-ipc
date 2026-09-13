#![no_std]
#![no_main]

#[macro_use]
extern crate user_lib;

static TESTS: &[&str] = &[
    "exit\0",
    "fantastic_text\0",
    "forktest\0",
    "forktest2\0",
    "forktest_simple\0",
    "hello_world\0",
    "matrix\0",
    "sleep\0",
    "sleep_simple\0",
    "stack_overflow\0",
    "yield\0",
];

use user_lib::{exec, fork, waitpid};

/// 每个子测试的预期退出码：
/// stack_overflow 本就应触发 SIGSEGV(=11)，按信号杀死时退出码为 -11，属预期；
/// 其余测试正常结束，退出码应为 0。
fn expected_code(test: &str) -> i32 {
    if test.trim_end_matches('\0') == "stack_overflow" {
        -11
    } else {
        0
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let mut passed = 0usize;
    let mut failed = 0usize;
    for test in TESTS {
        println!("Usertests: Running {}", test);
        let pid = fork();
        if pid == 0 {
            exec(*test, &[core::ptr::null::<u8>()]);
            panic!("unreachable!");
        } else {
            let mut exit_code: i32 = Default::default();
            let wait_pid = waitpid(pid as usize, &mut exit_code);
            let expect = expected_code(test);
            if wait_pid == pid && exit_code == expect {
                passed += 1;
                println!(
                    "\x1b[32m[PASS] {} exited with code {}\x1b[0m",
                    test, exit_code
                );
            } else {
                failed += 1;
                println!(
                    "\x1b[31m[FAIL] {} wait_pid={} exit_code={} (expected {})\x1b[0m",
                    test, wait_pid, exit_code, expect
                );
            }
        }
    }
    println!("---------- usertests summary ----------");
    println!(
        "total = {}, PASS = {}, FAIL = {}",
        TESTS.len(),
        passed,
        failed
    );
    if failed == 0 {
        println!("Usertests passed!");
        0
    } else {
        println!("Usertests FAILED!");
        1
    }
}
