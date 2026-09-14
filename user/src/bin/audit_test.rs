//! 独立审计回归：游标、覆盖、统计。用例编号见 docs/AUDIT_TEST_DESIGN.md。
//! 通过非法 ipc_stat flags 生成事件，不依赖信号/管道实现；测量期间不输出。

#![no_std]
#![no_main]

use core::mem::{offset_of, size_of};
use core::ptr::addr_of_mut;
use user_lib::audit::{self, AuditRecordV1, IpcStatsV1};
use user_lib::{exit, getpid, println};

const PAGE_SIZE: usize = 4096;
const READ_LIMIT: usize = 32;
const RECORD_SLOTS: usize = READ_LIMIT + 2;
const MAX_INJECTIONS: u64 = 4096;
const GUARD: u8 = 0xa5;

// 明确初始化所有字段；哨兵比较逐字段进行，不读取填充字节。
const RECORD_SENTINEL: AuditRecordV1 = AuditRecordV1 {
    abi_version: 0xa5a5,
    record_size: 0xa5a5,
    operation: 0xa5a5,
    flags: 0xa5a5,
    errno: -12345,
    subject_uid: u32::MAX,
    object_owner_uid: 12345,
    reserved0: 12345,
    sequence: u64::MAX,
    timestamp_ms: u64::MAX,
    subject_pid: u64::MAX,
    object_id: u64::MAX,
    requested_amount: u64::MAX,
    result_value: u64::MAX,
    reserved1: u64::MAX,
};

const STATS_SENTINEL: IpcStatsV1 = IpcStatsV1 {
    abi_version: 0xa5a5,
    struct_size: 0xa5a5,
    flags: u32::MAX,
    capacity: u64::MAX,
    retained: u64::MAX,
    first_sequence: u64::MAX,
    next_sequence: u64::MAX,
    total_events: u64::MAX,
    successful_events: u64::MAX,
    failed_events: u64::MAX,
    overwritten_events: u64::MAX,
    reserved0: u64::MAX,
};

#[repr(C, align(4096))]
struct RecordPage {
    records: [AuditRecordV1; RECORD_SLOTS],
}

#[repr(C, align(4096))]
struct StatsPage {
    value: IpcStatsV1,
    guard: [u8; 16],
}

// B 的复制接口尚未加固：每个输出区域放在一个有效页内，也不占用 8 KiB 用户栈。
static mut RECORD_PAGE: RecordPage = RecordPage {
    records: [RECORD_SENTINEL; RECORD_SLOTS],
};
static mut STATS_PAGE: StatsPage = StatsPage {
    value: STATS_SENTINEL,
    guard: [GUARD; 16],
};

const _: [(); 80] = [(); size_of::<AuditRecordV1>()];
const _: [(); 80] = [(); size_of::<IpcStatsV1>()];
const _: [(); PAGE_SIZE] = [(); size_of::<RecordPage>()];
const _: [(); PAGE_SIZE] = [(); size_of::<StatsPage>()];
const _: [(); 80] = [(); offset_of!(StatsPage, guard)];

// 用 exit(1) 传播失败，不依赖用户 panic 路径中的 kill 或 A 的信号权限。
macro_rules! require {
    ($case:expr, $condition:expr, $($message:tt)+) => {
        if !$condition {
            println!("[audit_test][{}] FAIL {}", $case, core::format_args!($($message)+));
            exit(1);
        }
    };
}

macro_rules! equal {
    ($case:expr, $actual:expr, $expected:expr) => {{
        let actual = $actual;
        let expected = $expected;
        require!(
            $case,
            actual == expected,
            "{}: expected={:?} actual={:?}",
            stringify!($actual),
            expected,
            actual
        );
    }};
}

fn add(case: &str, left: u64, right: u64) -> u64 {
    match left.checked_add(right) {
        Some(value) => value,
        None => {
            println!("[audit_test][{}] FAIL counter/sequence overflow", case);
            exit(1);
        }
    }
}

fn record_fields(r: &AuditRecordV1) -> [u64; 15] {
    [
        r.abi_version as u64,
        r.record_size as u64,
        r.operation as u64,
        r.flags as u64,
        r.errno as i64 as u64,
        r.subject_uid as u64,
        r.object_owner_uid as u64,
        r.reserved0 as u64,
        r.sequence,
        r.timestamp_ms,
        r.subject_pid,
        r.object_id,
        r.requested_amount,
        r.result_value,
        r.reserved1,
    ]
}

fn stats_fields(s: &IpcStatsV1) -> [u64; 12] {
    [
        s.abi_version as u64,
        s.struct_size as u64,
        s.flags as u64,
        s.capacity,
        s.retained,
        s.first_sequence,
        s.next_sequence,
        s.total_events,
        s.successful_events,
        s.failed_events,
        s.overwritten_events,
        s.reserved0,
    ]
}

fn same_stats(case: &str, expected: &IpcStatsV1, actual: &IpcStatsV1) {
    require!(
        case,
        stats_fields(expected) == stats_fields(actual),
        "statistics mismatch: expected={:?} actual={:?}",
        expected,
        actual
    );
}

fn check_stats(case: &str, s: &IpcStatsV1) {
    equal!(case, s.abi_version, audit::AUDIT_ABI_VERSION);
    equal!(case, s.struct_size, 80);
    equal!(case, s.flags, 0);
    equal!(case, s.reserved0, 0);
    require!(
        case,
        s.capacity > READ_LIMIT as u64,
        "capacity={} cannot test pagination",
        s.capacity
    );
    require!(
        case,
        s.retained <= s.capacity,
        "retained exceeds capacity: {:?}",
        s
    );
    equal!(
        case,
        s.total_events,
        add(case, s.successful_events, s.failed_events)
    );
    equal!(
        case,
        s.total_events,
        add(case, s.retained, s.overwritten_events)
    );
    equal!(case, s.next_sequence, add(case, s.total_events, 1));
    require!(
        case,
        s.first_sequence >= 1 && s.next_sequence >= s.first_sequence,
        "invalid sequence bounds: {:?}",
        s
    );
    equal!(case, s.next_sequence - s.first_sequence, s.retained);
}

/// 数学模型只关心追加总量与保留容量，不复写内核的环形下标算法。
fn failure_delta(case: &str, before: &IpcStatsV1, after: &IpcStatsV1, count: u64) {
    let occupied = add(case, before.retained, count);
    let mut expected = *before;
    expected.retained = occupied.min(before.capacity);
    expected.total_events = add(case, before.total_events, count);
    expected.failed_events = add(case, before.failed_events, count);
    expected.overwritten_events = add(
        case,
        before.overwritten_events,
        occupied.saturating_sub(before.capacity),
    );
    expected.next_sequence = add(case, before.next_sequence, count);
    expected.first_sequence = expected.next_sequence - expected.retained;
    same_stats(case, &expected, after);
}

struct Fixture {
    records: &'static mut RecordPage,
    stats: &'static mut StatsPage,
    pid: u64,
    // 从第一条受控事件取得身份，后续事件须一致；真实 UID/权限由 A 联合测试验证。
    uid: Option<u32>,
}

impl Fixture {
    fn check_layout(&self) {
        equal!("S02", size_of::<AuditRecordV1>(), 80);
        equal!("S02", size_of::<IpcStatsV1>(), 80);
        let record_address = self.records.records.as_ptr() as usize;
        let stats_address = core::ptr::addr_of!(self.stats.value) as usize;
        equal!("S02", record_address % PAGE_SIZE, 0);
        equal!("S02", stats_address % PAGE_SIZE, 0);
        require!(
            "S02",
            size_of::<[AuditRecordV1; RECORD_SLOTS]>() <= PAGE_SIZE,
            "record output crosses a page"
        );
        require!(
            "S02",
            size_of::<IpcStatsV1>() + self.stats.guard.len() <= PAGE_SIZE,
            "stats output crosses a page"
        );
    }

    fn reset_stats(&mut self) {
        self.stats.value = STATS_SENTINEL;
        self.stats.guard.fill(GUARD);
    }

    fn load_stats(&mut self, case: &str) -> IpcStatsV1 {
        self.reset_stats();
        let ret = audit::stat(&mut self.stats.value);
        equal!(case, ret, 0); // 包括 EPERM 在内的错误都不能当成有效快照。
        equal!(case, self.stats.guard, [GUARD; 16]);
        check_stats(case, &self.stats.value);
        self.stats.value
    }

    fn invalid_stat(&mut self, case: &str, out_size: usize, flags: usize) {
        self.reset_stats();
        // 指针指向有效独占输出；仅故意违反 flags/长度约定，检查参数失败先于复制。
        let ret = unsafe { audit::raw::ipc_stat(&mut self.stats.value, out_size, flags) };
        equal!(case, ret, -(audit::EINVAL as isize));
        same_stats(case, &STATS_SENTINEL, &self.stats.value);
        equal!(case, self.stats.guard, [GUARD; 16]);
    }

    fn inject(&mut self, case: &str, count: u64) -> (IpcStatsV1, IpcStatsV1) {
        require!(
            case,
            count <= MAX_INJECTIONS,
            "injection budget exceeded: {}",
            count
        );
        let before = self.load_stats(case);
        for _ in 0..count {
            self.invalid_stat(case, 80, 1);
        }
        let after = self.load_stats(case);
        failure_delta(case, &before, &after, count);
        (before, after)
    }

    fn injected_record(&mut self, case: &str, r: &AuditRecordV1) {
        equal!(case, r.operation, audit::AUDIT_OP_IPC_STAT);
        equal!(case, r.errno, audit::EINVAL);
        equal!(case, r.subject_pid, self.pid);
        if let Some(uid) = self.uid {
            equal!(case, r.subject_uid, uid);
        } else {
            self.uid = Some(r.subject_uid);
        }
        equal!(case, r.object_id, audit::AUDIT_OBJECT_NONE);
        equal!(case, r.object_owner_uid, audit::AUDIT_UID_UNKNOWN);
        equal!(case, r.requested_amount, 0);
        equal!(case, r.result_value, 0);
    }

    /// 输出先填哨兵，再对照 [first, next) 的逻辑集合逐条验证。
    fn read_batch(
        &mut self,
        case: &str,
        cursor: u64,
        capacity: usize,
        view: &IpcStatsV1,
        own_events: bool,
    ) -> usize {
        require!(
            case,
            capacity < RECORD_SLOTS,
            "test output capacity too large"
        );
        self.records.records.fill(RECORD_SENTINEL);
        let ret = audit::read(&mut self.records.records[..capacity], cursor);
        require!(
            case,
            ret >= 0,
            "audit_read cursor={} returned {}",
            cursor,
            ret
        );
        require!(
            case,
            ret as usize <= capacity && ret as usize <= READ_LIMIT,
            "audit_read cursor={} capacity={} returned {}",
            cursor,
            capacity,
            ret
        );
        let count = ret as usize;
        let start = cursor.checked_add(1).map(|n| n.max(view.first_sequence));
        let expected = start.map_or(0, |n| {
            view.next_sequence
                .saturating_sub(n)
                .min(capacity.min(READ_LIMIT) as u64)
        }) as usize;
        require!(
            case,
            count == expected,
            "cursor={} capacity={} view={:?} expected_count={} actual_count={}",
            cursor,
            capacity,
            view,
            expected,
            count
        );

        let gap = cursor
            .checked_add(1)
            .is_some_and(|n| n < view.first_sequence);
        let mut previous_time = 0;
        for index in 0..count {
            let r = self.records.records[index];
            equal!(case, r.abi_version, audit::AUDIT_ABI_VERSION);
            equal!(case, r.record_size, 80);
            equal!(case, r.reserved0, 0);
            equal!(case, r.reserved1, 0);
            equal!(case, r.sequence, add(case, start.unwrap(), index as u64));
            equal!(case, r.has_gap_before(), index == 0 && gap);
            require!(
                case,
                r.errno >= 0,
                "negative record errno at sequence={}",
                r.sequence
            );
            require!(
                case,
                r.timestamp_ms >= previous_time,
                "timestamps decreased at sequence={}",
                r.sequence
            );
            previous_time = r.timestamp_ms;
            if own_events {
                self.injected_record(case, &r);
            }
        }
        for index in count..RECORD_SLOTS {
            equal!(
                case,
                record_fields(&self.records.records[index]),
                record_fields(&RECORD_SENTINEL)
            );
        }
        count
    }

    /// 固定目标尾部、有界循环；最后再读一次验证空尾部，不用短批次作为结束条件。
    fn drain(&mut self, case: &str, mut cursor: u64, capacity: usize, view: &IpcStatsV1) -> u64 {
        let mut total = 0;
        let mut previous_time = 0;
        for _ in 0..=view.capacity {
            let count = self.read_batch(case, cursor, capacity, view, true);
            if count == 0 {
                equal!(case, cursor, view.next_sequence - 1);
                return total;
            }
            require!(
                case,
                self.records.records[0].timestamp_ms >= previous_time,
                "timestamps decreased across batches"
            );
            let last = self.records.records[count - 1];
            require!(
                case,
                last.sequence > cursor,
                "cursor did not advance: {}",
                cursor
            );
            previous_time = last.timestamp_ms;
            cursor = last.sequence;
            total = add(case, total, count as u64);
        }
        println!("[audit_test][{}] FAIL pagination budget exhausted", case);
        exit(1);
    }

    fn cursors(&mut self, capacity: u64) {
        let initial = self.load_stats("C01");
        self.read_batch(
            "C01",
            initial.next_sequence - 1,
            READ_LIMIT,
            &initial,
            false,
        );
        same_stats("C01", &initial, &self.load_stats("C01"));

        let k = capacity.min(2 * READ_LIMIT as u64 + 1);
        let (before, view) = self.inject("S03/cursor", k);
        let c0 = before.next_sequence - 1;
        self.read_batch("C02", c0, 7, &view, true);
        let mut first = [RECORD_SENTINEL; 7];
        first.copy_from_slice(&self.records.records[..7]);
        self.read_batch("C02", c0, 7, &view, true);
        for (index, saved) in first.iter().enumerate() {
            equal!(
                "C02",
                record_fields(&self.records.records[index]),
                record_fields(saved)
            );
        }
        equal!("C03", self.drain("C03", c0, 7, &view), k);

        let mut reader_a = c0;
        for _ in 0..2 {
            let count = self.read_batch("C04/A", reader_a, 7, &view, true);
            reader_a = self.records.records[count - 1].sequence;
        }
        // A 已经读过两批；B 仍从相同起点读到第一批，两者没有内核共享游标。
        self.read_batch("C04/B", c0, 7, &view, true);
        for (index, saved) in first.iter().enumerate() {
            equal!(
                "C04/B",
                record_fields(&self.records.records[index]),
                record_fields(saved)
            );
        }
        equal!("C04/B", self.drain("C04/B", c0, 7, &view), k);
        equal!("C04/A", self.drain("C04/A", reader_a, 7, &view), k - 14);

        for request in [0, 1, 31, 32, 33] {
            self.read_batch("C05", c0, request, &view, true);
        }
        for cursor in [view.next_sequence - 1, view.next_sequence, u64::MAX] {
            self.read_batch("C06", cursor, READ_LIMIT, &view, true);
        }
        same_stats("C02-C06", &view, &self.load_stats("C02-C06"));

        let (before, after) = self.inject("C07", 1);
        self.read_batch("C07", before.next_sequence - 1, READ_LIMIT, &after, true);
        self.read_batch("C07", after.next_sequence - 1, READ_LIMIT, &after, true);
        same_stats("C07", &after, &self.load_stats("C07"));
    }

    fn no_feedback(&mut self) {
        let before = self.load_stats("S06");
        for _ in 0..8 {
            same_stats("S06/stat", &before, &self.load_stats("S06/stat"));
            self.read_batch(
                "S06/nonempty",
                before.next_sequence - 2,
                READ_LIMIT,
                &before,
                true,
            );
            self.read_batch(
                "S06/tail",
                before.next_sequence - 1,
                READ_LIMIT,
                &before,
                true,
            );
            self.read_batch("S06/zero", before.next_sequence - 2, 0, &before, true);
        }
        // 授权后的零容量不触碰指针，独立于 B 的真实无效页检查。
        let ret = unsafe { audit::raw::audit_read(core::ptr::null_mut(), 0, 0) };
        equal!("S06/zero-null", ret, 0);
        same_stats("S06", &before, &self.load_stats("S06"));
    }

    fn overflow(&mut self, capacity: u64) {
        let before = self.load_stats("O02");
        let (_, full) = self.inject("O02/fill", capacity - before.retained);
        equal!("O02", full.retained, capacity);
        equal!("O02", full.overwritten_events, before.overwritten_events);
        let (_, one_more) = self.inject("O02/first-overwrite", 1);
        equal!(
            "O02",
            one_more.first_sequence,
            add("O02", full.first_sequence, 1)
        );
        self.read_batch("O02", one_more.next_sequence - 2, 1, &one_more, true);
        same_stats("O02", &one_more, &self.load_stats("O02"));

        let (before, view) = self.inject("O03", add("O03", capacity, 1));
        let c0 = before.next_sequence - 1;
        equal!(
            "O03",
            view.first_sequence,
            add("O03", before.next_sequence, 1)
        );
        equal!("O03", self.drain("O03", c0, READ_LIMIT, &view), capacity);

        for cursor in [
            view.first_sequence - 2,
            view.first_sequence - 1,
            view.first_sequence,
            0,
        ] {
            self.read_batch("O04", cursor, READ_LIMIT, &view, true);
        }
        for _ in 0..2 {
            self.read_batch("O05/stale", c0, READ_LIMIT, &view, true);
            let mut flagged = self.records.records[0];
            require!(
                "O05",
                flagged.has_gap_before(),
                "stale cursor lost gap flag"
            );
            self.read_batch(
                "O05/boundary",
                view.first_sequence - 1,
                READ_LIMIT,
                &view,
                true,
            );
            flagged.flags &= !audit::AUDIT_RECORD_F_GAP_BEFORE;
            equal!(
                "O05",
                record_fields(&self.records.records[0]),
                record_fields(&flagged)
            );
        }
        same_stats("O03-O05", &view, &self.load_stats("O03-O05"));

        let m = add("O06", add("O06", capacity, capacity), 3);
        let (before, view) = self.inject("O06", m);
        equal!(
            "O06",
            self.drain("O06", before.next_sequence - 1, 31, &view),
            capacity
        );
        same_stats("O06", &view, &self.load_stats("O06"));

        let (before, view) = self.inject("O07/setup", capacity.min(65));
        let count = self.read_batch("O07/first", before.next_sequence - 1, 7, &view, true);
        let cursor = self.records.records[count - 1].sequence;
        let (_, changed) = self.inject("O07/between-batches", add("O07", capacity, 1));
        require!(
            "O07",
            add("O07", cursor, 1) < changed.first_sequence,
            "fixture failed to overwrite the reader's next record"
        );
        equal!(
            "O07",
            self.drain("O07", cursor, READ_LIMIT, &changed),
            capacity
        );
        same_stats("O07", &changed, &self.load_stats("O07"));
    }

    fn stats_parameters(&mut self) {
        let before = self.load_stats("S07");
        for size in [80, 96] {
            self.reset_stats();
            // 96 字节全部位于 StatsPage；内核只能改写其中前 80 字节。
            let ret = unsafe { audit::raw::ipc_stat(&mut self.stats.value, size, 0) };
            equal!("S07", ret, 0);
            equal!("S07", self.stats.guard, [GUARD; 16]);
            same_stats("S07", &before, &self.stats.value);
        }
        same_stats("S07/success", &before, &self.load_stats("S07/success"));
        self.invalid_stat("S07/size79", 79, 0);
        let after = self.load_stats("S07/size79");
        failure_delta("S07/size79", &before, &after, 1);
        self.read_batch(
            "S07/size79",
            before.next_sequence - 1,
            READ_LIMIT,
            &after,
            true,
        );
        same_stats("S07/final", &after, &self.load_stats("S07/final"));
    }
}

#[unsafe(no_mangle)]
pub fn main() -> i32 {
    let pid = getpid();
    require!("setup", pid >= 0, "getpid returned {}", pid);
    // 单线程 main 中各建立唯一引用，此后只经 Fixture 使用静态区，不再访问静态名字。
    let mut fixture = Fixture {
        records: unsafe { &mut *addr_of_mut!(RECORD_PAGE) },
        stats: unsafe { &mut *addr_of_mut!(STATS_PAGE) },
        pid: pid as u64,
        uid: None,
    };
    fixture.check_layout();
    let initial = fixture.load_stats("S02/setup");
    let capacity = initial.capacity;
    require!(
        "setup",
        add("setup", add("setup", capacity, capacity), 3) <= MAX_INJECTIONS,
        "capacity={} exceeds test injection budget",
        capacity
    );

    let (before, after) = fixture.inject("S01", 1);
    fixture.read_batch("S01", before.next_sequence - 1, 1, &after, true);
    same_stats("S01", &after, &fixture.load_stats("S01"));
    fixture.cursors(capacity);
    fixture.no_feedback();
    fixture.overflow(capacity);
    fixture.stats_parameters();
    fixture.no_feedback();
    let final_stats = fixture.load_stats("S02/final");

    // 到这里才输出，保持所有统计测量区间无测试自身的输出写入。
    for case in [
        "C01", "C02", "C03", "C04", "C05", "C06", "C07", "O02", "O03", "O04", "O05", "O06", "O07",
        "S01", "S02", "S03", "S06", "S07",
    ] {
        println!("[audit_test][{}] PASS", case);
    }
    println!(
        "[audit_test] capacity={} initial_total={} final_total={}",
        capacity, initial.total_events, final_stats.total_events
    );
    println!("audit_test passed!");
    0
}
