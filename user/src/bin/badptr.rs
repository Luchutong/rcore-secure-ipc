#![no_std]
#![no_main]

//! 恶意用户指针安全测试：向各系统调用传入空指针 / 内核地址 /
//! 越界地址 / 溢出长度，内核必须返回 -1 且绝不能 panic。
//!
//! 注：所有恶意地址都经 black_box 处理，避免编译器在编译期把
//! “空指针构造切片”判定为 UB；这些指针在用户态绝不会被解引用，
//! 只把数值通过 ecall 传给内核，由内核的用户指针校验拒绝。

#[macro_use]
extern crate user_lib;

use user_lib::{OpenFlags, open, pipe, read, write};

fn bad_ptr(addr: usize) -> *const u8 {
    core::hint::black_box(addr) as *const u8
}
fn bad_mut_ptr(addr: usize) -> *mut u8 {
    core::hint::black_box(addr) as *mut u8
}
fn bad_len(len: usize) -> usize {
    core::hint::black_box(len)
}

/// 返回 true 表示该攻击被内核正确拒绝（PASS）
fn check(name: &str, ret: isize) -> bool {
    if ret == -1 {
        println!("badptr [PASS] {} rejected with -1", name);
        true
    } else {
        println!("badptr [FAIL] {} returned {} (expected -1)", name, ret);
        false
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let results = [
        // 1. write: NULL 缓冲区
        check("write null", unsafe {
            write(1, core::slice::from_raw_parts(bad_ptr(0), 16))
        }),
        // 2. write: 内核物理地址 0x80200000
        check("write kernel-addr", unsafe {
            write(1, core::slice::from_raw_parts(bad_ptr(0x8020_0000), 16))
        }),
        // 3. write: 顶端越界地址
        check("write high-addr", unsafe {
            write(
                1,
                core::slice::from_raw_parts(bad_ptr(0xffff_ffff_ffff_f000), 16),
            )
        }),
        // 4. write: 合法地址 + 溢出长度
        check("write overflow-len", unsafe {
            let local = [0u8; 8];
            write(
                1,
                core::slice::from_raw_parts(local.as_ptr(), bad_len(usize::MAX)),
            )
        }),
        // 5. open: 内核地址路径
        check("open kernel-addr", unsafe {
            let s = core::slice::from_raw_parts(bad_ptr(0x8020_0000), 8);
            open(core::str::from_utf8_unchecked(s), OpenFlags::RDONLY)
        }),
        // 6. open: NULL 路径
        check("open null", unsafe {
            let s = core::slice::from_raw_parts(bad_ptr(0), 4);
            open(core::str::from_utf8_unchecked(s), OpenFlags::RDONLY)
        }),
        // 7. pipe: 输出数组位于内核地址
        check("pipe kernel-addr", unsafe {
            pipe(core::slice::from_raw_parts_mut(
                0x8020_0000 as *mut usize,
                2,
            ))
        }),
        // 8. read: 向内核地址写入
        check("read kernel-addr", unsafe {
            read(
                0,
                core::slice::from_raw_parts_mut(bad_mut_ptr(0x8020_0000), 16),
            )
        }),
    ];
    let total = results.len();
    let passed = results.iter().filter(|ok| **ok).count();
    let failed = total - passed;
    println!("---------- badptr summary ----------");
    println!("total = {}, PASS = {}, FAIL = {}", total, passed, failed);
    if failed == 0 {
        println!("badptr finished: kernel survived every bad user pointer!");
        0
    } else {
        println!("badptr FAILED: some bad pointers were not rejected!");
        1
    }
}
