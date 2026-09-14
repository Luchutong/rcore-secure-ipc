//! 审计查看工具：只使用用户库的安全 read/stat 接口。
//! 主机测试直接编译本文件；no_std 与入口符号仅用于真实裸机目标。

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

use user_lib::audit::{
    self, AUDIT_ABI_VERSION, AUDIT_RECORD_V1_SIZE, AUDIT_UID_UNKNOWN, AuditRecordV1,
    IPC_STATS_V1_SIZE, IpcStatsV1,
};
use user_lib::{print, println};

/// 批次大小与内核容量无关，固定占用 32 × 80 = 2560 字节。
const BATCH_SIZE: usize = 32;
const EXIT_ERROR: i32 = 1;
const EXIT_USAGE: i32 = 2;

fn usage() {
    println!("Usage: auditctl stat | read [after_sequence] | help");
    println!("  stat: show audit buffer statistics");
    println!("  read: read through the initial log tail (default cursor: 0)");
    println!("  after_sequence: last processed sequence, unsigned decimal u64");
    println!("  Requires UID 0 or AUDIT_READ capability; time_ms is kernel time.");
}

fn errno_name(errno: u64) -> &'static str {
    match errno {
        1 => "EPERM",
        3 => "ESRCH",
        11 => "EAGAIN",
        14 => "EFAULT",
        22 => "EINVAL",
        24 => "EMFILE",
        28 => "ENOSPC",
        _ => "UNKNOWN",
    }
}

fn syscall_error(call: &str, result: isize) -> i32 {
    // unsigned_abs 也能表达 isize::MIN，诊断异常返回值时不发生取负溢出。
    let errno = result.unsigned_abs() as u64;
    println!(
        "auditctl: {} failed: {} (errno={}, return={})",
        call,
        errno_name(errno),
        errno,
        result
    );
    EXIT_ERROR
}

fn load_stats() -> Result<IpcStatsV1, i32> {
    let mut stats = IpcStatsV1::default();
    let result = audit::stat(&mut stats);
    if result < 0 {
        return Err(syscall_error("ipc_stat", result));
    }
    if result != 0 {
        println!("auditctl: invalid ipc_stat return value: {}", result);
        return Err(EXIT_ERROR);
    }
    // 先检查布局，再解释计数；未来的未知 ABI 不能按 v1 静默显示。
    if stats.abi_version != AUDIT_ABI_VERSION || stats.struct_size != IPC_STATS_V1_SIZE {
        println!(
            "auditctl: incompatible stats ABI: version={}, size={}",
            stats.abi_version, stats.struct_size
        );
        return Err(EXIT_ERROR);
    }
    if stats.retained > stats.capacity
        || stats.successful_events.checked_add(stats.failed_events) != Some(stats.total_events)
        || stats.first_sequence == 0
        || stats.next_sequence.checked_sub(stats.first_sequence) != Some(stats.retained)
    {
        println!("auditctl: inconsistent audit statistics");
        return Err(EXIT_ERROR);
    }
    Ok(stats)
}

fn show_stats() -> i32 {
    let stats = match load_stats() {
        Ok(stats) => stats,
        Err(code) => return code,
    };
    println!("capacity={} retained={}", stats.capacity, stats.retained);
    println!(
        "total_events={} successful_events={} failed_events={} overwritten_events={}",
        stats.total_events, stats.successful_events, stats.failed_events, stats.overwritten_events
    );
    println!(
        "first_sequence={} next_sequence={}",
        stats.first_sequence, stats.next_sequence
    );
    0
}

fn show_record(record: &AuditRecordV1) {
    print!(
        "seq={} time_ms={} pid={} uid={} op={}({}) object_id={} owner_uid=",
        record.sequence,
        record.timestamp_ms,
        record.subject_pid,
        record.subject_uid,
        audit::operation_name(record.operation).unwrap_or("unknown"),
        record.operation,
        record.object_id
    );
    if record.object_owner_uid == AUDIT_UID_UNKNOWN {
        print!("unknown");
    } else {
        print!("{}", record.object_owner_uid);
    }
    print!(" requested={}", record.requested_amount);
    if record.succeeded() {
        println!(" result={} status=OK", record.result_value);
    } else {
        println!(
            " status=ERROR errno={}({})",
            record.errno,
            errno_name(record.errno as u64)
        );
    }
}

fn read_records(mut cursor: u64) -> i32 {
    let stats = match load_stats() {
        Ok(stats) => stats,
        Err(code) => return code,
    };
    // 一次 read 命令只追到启动时的尾部。后续新增事件留给下一次命令。
    // load_stats 已验证 next_sequence >= first_sequence >= 1。
    let through = stats.next_sequence - 1;
    let mut records = [AuditRecordV1::default(); BATCH_SIZE];
    let mut displayed = 0u64;

    'read: while cursor < through {
        let result = audit::read(&mut records, cursor);
        if result < 0 {
            // 内核可能已复制前缀；整批失败时不能显示它或推进游标。
            syscall_error("audit_read", result);
            println!("auditctl: retry with: auditctl read {}", cursor);
            return EXIT_ERROR;
        }
        if result == 0 {
            break;
        }
        let count = result as usize;
        if count > records.len() {
            println!("auditctl: invalid audit_read count: {}", count);
            return EXIT_ERROR;
        }

        // 整批验证后再显示，避免重复/倒序序号导致游标不前进或无限循环。
        let mut previous = cursor;
        for (index, record) in records[..count].iter().enumerate() {
            if record.abi_version != AUDIT_ABI_VERSION
                || record.record_size != AUDIT_RECORD_V1_SIZE
                || record.sequence <= previous
                || record.errno < 0
                || (index != 0 && record.has_gap_before())
            {
                println!(
                    "auditctl: invalid audit record at batch index {}; cursor={}",
                    index, cursor
                );
                return EXIT_ERROR;
            }
            previous = record.sequence;
        }

        for record in &records[..count] {
            // 即使初始范围已全部被覆盖，也要在停止前报告这个缺口。
            if record.has_gap_before() {
                println!(
                    "auditctl: warning: GAP_BEFORE before sequence {}; records were overwritten",
                    record.sequence
                );
            }
            if record.sequence > through {
                break 'read;
            }
            show_record(record);
            cursor = record.sequence;
            displayed += 1;
        }
        // 不以 count < BATCH_SIZE 判断结束；内核可以返回更小的批次。
    }
    println!(
        "auditctl: records={} cursor={} through={}",
        displayed, cursor, through
    );
    0
}

#[cfg_attr(target_os = "none", unsafe(no_mangle))]
pub fn main(_argc: usize, argv: &[&str]) -> i32 {
    match argv.get(1..).unwrap_or(&[]) {
        ["help" | "--help" | "-h"] => {
            usage();
            0
        }
        ["stat"] => show_stats(),
        ["read"] => read_records(0),
        ["read", after] => {
            // 只接受十进制非负整数，拒绝符号、空串、非数字和 u64 溢出。
            if !after.is_empty() && after.bytes().all(|byte| byte.is_ascii_digit()) {
                if let Ok(cursor) = after.parse::<u64>() {
                    return read_records(cursor);
                }
            }
            println!("auditctl: invalid after_sequence");
            usage();
            EXIT_USAGE
        }
        _ => {
            usage();
            EXIT_USAGE
        }
    }
}
