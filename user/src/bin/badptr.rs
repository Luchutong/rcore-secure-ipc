#![no_std]
#![no_main]

//! 恶意用户指针回归测试。直接发起系统调用，避免先在 Rust 用户态构造
//! 不满足语言约束的切片或字符串；内核必须返回 EFAULT 且保持可运行。

#[macro_use]
extern crate user_lib;

use core::arch::asm;

const EFAULT: isize = 14;
const SYSCALL_OPEN: usize = 56;
const SYSCALL_PIPE: usize = 59;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;

fn raw_syscall(id: usize, args: [usize; 3]) -> isize {
    let mut result: isize;
    unsafe {
        asm!(
            "ecall",
            inlateout("x10") args[0] => result,
            in("x11") args[1],
            in("x12") args[2],
            in("x17") id,
        );
    }
    result
}

fn check(name: &str, result: isize) -> bool {
    if result == -EFAULT {
        println!("badptr [PASS] {} rejected with EFAULT", name);
        true
    } else {
        println!(
            "badptr [FAIL] {} returned {} (expected -EFAULT)",
            name, result
        );
        false
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let local = [0u8; 8];
    let results = [
        check("write null", raw_syscall(SYSCALL_WRITE, [1, 0, 16])),
        check(
            "write kernel-addr",
            raw_syscall(SYSCALL_WRITE, [1, 0x8020_0000, 16]),
        ),
        check(
            "write high-addr",
            raw_syscall(SYSCALL_WRITE, [1, 0xffff_ffff_ffff_f000, 16]),
        ),
        check(
            "write overflow-len",
            raw_syscall(SYSCALL_WRITE, [1, local.as_ptr() as usize, usize::MAX]),
        ),
        check(
            "open kernel-addr",
            raw_syscall(SYSCALL_OPEN, [0x8020_0000, 0, 0]),
        ),
        check("open null", raw_syscall(SYSCALL_OPEN, [0, 0, 0])),
        check(
            "pipe kernel-addr",
            raw_syscall(SYSCALL_PIPE, [0x8020_0000, 0, 0]),
        ),
        check(
            "read kernel-addr",
            raw_syscall(SYSCALL_READ, [0, 0x8020_0000, 16]),
        ),
    ];
    let passed = results.iter().filter(|ok| **ok).count();
    println!("badptr summary: {}/{} passed", passed, results.len());
    if passed == results.len() { 0 } else { 1 }
}
