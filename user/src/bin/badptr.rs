#![no_std]
#![no_main]

//! 恶意用户指针回归测试。直接发起系统调用，避免先在 Rust 用户态构造
//! 不满足语言约束的切片或字符串；内核必须返回 EFAULT 且保持可运行。

#[macro_use]
extern crate user_lib;

use core::arch::asm;

const EFAULT: isize = 14;
const SYSCALL_READ: usize = 63;
const SYSCALL_WRITE: usize = 64;
const PAGE_SIZE: usize = 4096;

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
        println!("badptr [PASS] {} -> EFAULT", name);
        true
    } else {
        println!(
            "badptr [FAIL] {} returned {} (expected -EFAULT)",
            name, result
        );
        false
    }
}

fn stack_pointer() -> usize {
    let value: usize;
    unsafe {
        asm!("mv {}, sp", out(reg) value);
    }
    value
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let local = [0u8; 8];
    // The linker loads user programs at 0x10000, so 0x4000 is a non-null,
    // unmapped user address. The two-page user stack ends at the first page
    // boundary above the current SP; crossing that boundary reaches an
    // unmapped page. Code pages are readable/executable but never writable.
    let unmapped_page = 0x4000usize;
    let stack_top = (stack_pointer() + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let cross_page_missing = stack_top - 8;
    let read_only_output = main as *const () as usize;
    let read_only_page_end = (read_only_output & !(PAGE_SIZE - 1)) + PAGE_SIZE;
    let cross_page_read_only = read_only_page_end - 8;
    let results = [
        check("NULL", raw_syscall(SYSCALL_WRITE, [1, 0, 16])),
        check(
            "Kernel Address",
            raw_syscall(SYSCALL_WRITE, [1, 0x8020_0000, 16]),
        ),
        check(
            "High Address",
            raw_syscall(SYSCALL_WRITE, [1, 0xffff_ffff_ffff_f000, 16]),
        ),
        check(
            "Length Overflow",
            raw_syscall(SYSCALL_WRITE, [1, local.as_ptr() as usize, usize::MAX]),
        ),
        check(
            "Unmapped Page",
            raw_syscall(SYSCALL_WRITE, [1, unmapped_page, 16]),
        ),
        check(
            "Cross-page Missing",
            raw_syscall(SYSCALL_WRITE, [1, cross_page_missing, 16]),
        ),
        check(
            "Read-only Output",
            raw_syscall(SYSCALL_READ, [0, read_only_output, 1]),
        ),
        check(
            "Cross-page Read-only",
            raw_syscall(SYSCALL_READ, [0, cross_page_read_only, 16]),
        ),
    ];
    let passed = results.iter().filter(|ok| **ok).count();
    println!("badptr summary: {}/{} passed", passed, results.len());
    if passed == results.len() {
        println!("badptr kernel: alive");
        0
    } else {
        1
    }
}
