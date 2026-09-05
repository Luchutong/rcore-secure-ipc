//! QEMU 端到端测试：exec 真实 auditctl，经管道逐行检查输出。

#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::String;
use user_lib::audit::{self, IpcStatsV1};
use user_lib::{close, dup, exec, exit, fork, pipe, println, read, waitpid};

#[derive(Default)]
struct Output {
    records: usize,
    last_sequence: u64,
    stat: bool,
    usage: bool,
    gap: bool,
    empty: bool,
    ipc_stat_error: bool,
    summary: bool,
}

impl Output {
    fn line(&mut self, line: &str) {
        if let Some(rest) = line.strip_prefix("seq=") {
            let sequence = rest.split_whitespace().next().unwrap().parse().unwrap();
            assert!(sequence > self.last_sequence);
            self.last_sequence = sequence;
            self.records += 1;
        }
        self.stat |= line.starts_with("capacity=") && line.contains("retained=");
        self.usage |= line.starts_with("Usage: auditctl");
        self.gap |= line.contains("GAP_BEFORE");
        self.empty |= line.starts_with("auditctl: records=0 ");
        self.summary |= line.starts_with("auditctl: records=");
        self.ipc_stat_error |= line.contains("op=ipc_stat(6)") && line.contains("errno=22(EINVAL)");
    }
}

fn run_tool(args: &[&str], expected_exit: i32) -> Output {
    let mut fds = [0usize; 2];
    assert_eq!(pipe(&mut fds), 0);
    let pid = fork();
    assert!(pid >= 0);
    if pid == 0 {
        close(fds[0]);
        close(1);
        assert_eq!(dup(fds[1]), 1);
        close(fds[1]);
        // args 是带结尾 NUL 的参数；最多三个参数，第四槽作为结束指针。
        let mut pointers = [core::ptr::null::<u8>(); 4];
        for (index, arg) in args.iter().enumerate() {
            pointers[index] = arg.as_ptr();
        }
        exec("auditctl\0", &pointers);
        exit(127);
    }

    close(fds[1]);
    let mut output = Output::default();
    let mut chunk = [0u8; 128];
    let mut line = String::new();
    // 边读边消费，避免管道写满死锁，也不把 256 条输出塞进 32 KiB 用户堆。
    loop {
        let count = read(fds[0], &mut chunk);
        assert!(count >= 0);
        if count == 0 {
            break;
        }
        for byte in &chunk[..count as usize] {
            if *byte == b'\n' {
                output.line(&line);
                line.clear();
            } else {
                assert!(line.len() < 512);
                line.push(*byte as char); // auditctl 目前输出 ASCII
            }
        }
    }
    if !line.is_empty() {
        output.line(&line);
    }
    close(fds[0]);
    let mut exit_code = 0;
    assert_eq!(waitpid(pid as usize, &mut exit_code), pid);
    assert_eq!(exit_code, expected_exit);
    output
}

fn stats() -> IpcStatsV1 {
    let mut stats = IpcStatsV1::default();
    assert_eq!(audit::stat(&mut stats), 0);
    stats
}

fn emit_failures(count: u64) {
    let mut unused = IpcStatsV1::default();
    for _ in 0..count {
        // flags=1 在内核复制用户地址前被拒绝，不依赖 B 的恶意指针防护。
        let result = unsafe { audit::raw::ipc_stat(&mut unused, 80, 1) };
        assert_eq!(result, -(audit::EINVAL as isize));
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    assert!(run_tool(&["auditctl\0", "help\0"], 0).usage);
    assert!(run_tool(&["auditctl\0", "read\0", "-1\0"], 2).usage);
    assert!(run_tool(&["auditctl\0", "stat\0"], 0).stat);

    let before = stats();
    let cursor = alloc::format!("{}\0", before.next_sequence - 1);
    assert!(run_tool(&["auditctl\0", "read\0", &cursor], 0).empty);

    emit_failures(35);
    let output = run_tool(&["auditctl\0", "read\0", &cursor], 0);
    assert_eq!(output.records, 35);
    assert!(output.ipc_stat_error && output.summary);
    let after = stats();
    assert_eq!(after.total_events, before.total_events + 35);
    assert_eq!(after.failed_events, before.failed_events + 35);

    let tail = alloc::format!("{}\0", output.last_sequence);
    assert!(run_tool(&["auditctl\0", "read\0", &tail], 0).empty);
    assert_eq!(stats().total_events, after.total_events);

    emit_failures(after.capacity + 1);
    let full = stats();
    assert!(full.overwritten_events > after.overwritten_events);
    let output = run_tool(&["auditctl\0", "read\0", &tail], 0);
    assert!(output.gap && output.summary);
    assert_eq!(output.records as u64, full.retained);
    assert_eq!(output.last_sequence, full.next_sequence - 1);
    assert_eq!(stats().total_events, full.total_events);
    println!("auditctl_test passed: stat, pagination, cursor, overflow, no feedback");
    0
}
