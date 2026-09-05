# auditctl 工具设计与使用

实现：[user/src/bin/auditctl.rs](../user/src/bin/auditctl.rs)。
依赖：[用户态审计 API](USER_AUDIT_API.md) 与 [审计 ABI v1](AUDIT_ABI_V1.md)。

状态：工具、602/603 内核路由和真实用户态回归测试已实现。

## 1. 如何使用

在宿主机终端启动系统：

```bash
cd /home/luchitong/work/rcore-secure-ipc
make -C os run
```

进入 `Rust user shell` 后执行：

```text
auditctl help
auditctl stat
auditctl read
auditctl read 100
```

`auditctl` 是 rCore 用户程序，在 QEMU 内运行；宿主机 Bash 不能直接执行这个 RV64 ELF。
`user/Makefile` 自动编译 `src/bin/*.rs`，文件系统打包器也会自动收录它，无须手动注册应用名。

| 命令 | 含义 |
| --- | --- |
| `auditctl stat` | 查询容量、保留数、累计成功/失败/覆盖数以及序号边界 |
| `auditctl read` | 游标从 0 开始，输出当前仍保留的记录 |
| `auditctl read 100` | 表示已处理到 100，从严格大于 100 的序号开始 |
| `auditctl help` / `--help` / `-h` | 显示帮助，不调用审计系统调用 |

游标只接受十进制 `u64`；负数、加号、十六进制、溢出及多余参数返回用法错误。
无参数也显示用法并返回 2。统计和读取要求 UID 0 或 `AUDIT_READ` capability。

## 2. 在 rCore 中的位置

```text
auditctl main：解析参数、显示输出、维护游标
    ↓
user_lib::audit::{stat, read}：安全引用/切片封装
    ↓
user/src/syscall.rs：a7=603/602，a0～a2 传参，ecall
    ↓
os/src/syscall/mod.rs：登记并分发 603/602
    ↓
os/src/syscall/security.rs：权限校验、生成快照、复制用户地址
    ↓
security::audit：有界环形缓冲区
```

工具只使用安全封装，不调用 `audit::raw`，也不在工具内重复实现权限、页表或审计写入。
本次接线使用已冻结的 602/603 编号和现有内核函数，未改变系统调用参数或 ABI 布局。

## 3. 统计输出

以下为格式示例，数值并非固定测试结果：

```text
capacity=256 retained=35
total_events=35 successful_events=0 failed_events=35 overwritten_events=0
first_sequence=1 next_sequence=36
```

`load_stats()` 先检查系统调用返回 0，再检查版本 1 和结构大小 80，最后核对：

- `retained <= capacity`；
- `successful_events + failed_events == total_events`，使用 `checked_add` 防止溢出；
- `first_sequence >= 1`；
- `next_sequence - first_sequence == retained`，使用 `checked_sub` 防止回绕。

字段来自同一次内核快照。工具不硬编码环形容量，也不会在失败时展示初始化为 0 的伪统计。

## 4. 分批读取与结束条件

每条 ABI 记录是 80 字节，工具使用一个 32 条数组，记录缓冲区固定占用 2560 字节。
整个读取过程复用数组，不把日志积累到 `Vec`，也不按环形容量分配内存。

开始读取时，先取一次统计并保存 `through = next_sequence - 1`。这个序号表示本次命令
打算读取到的尾部。随后反复调用 `audit::read(&mut records, cursor)`：

1. 返回负数：本批失败，不显示前缀数据，不推进游标，输出重试命令并退出。
2. 返回 0：结束。
3. 返回正数：确认未超过数组长度，并对整批记录检查 ABI、序号严格递增和非负 errno。
4. 逐条显示不超过 `through` 的记录，处理成功后才将其 `sequence` 保存为新游标。
5. 到达 `through`，或遇到更晚的事件时结束；否则继续读取下一批。

例如开始时日志尾部为 70：前两批各返回 32 条，第三批返回 6 条，即可显示全部 70 条。
即使内核只返回 1 条，也继续读取，不能把“小于 32 条”当成日志结束。

固定尾部能使一次命令有明确终点。若其他进程持续制造事件，或者工具输出被重定向到
将来会记录写入事件的管道，本次命令仍然只处理启动时确定的范围。新事件由下一次命令读取。
这属于工具的读取策略，没有改变内核每次调用的快照语义。

最终输出例如：

```text
auditctl: records=70 cursor=70 through=70
```

`records` 是本次显示数量，`cursor` 是最后成功显示的序号，`through` 是本次目标尾部。
再次运行 `auditctl read 70` 可以继续。相同游标重复查询不会删除日志。
空日志或游标已到尾部时输出 `records=0`。最大 `u64` 游标也可安全处理。
游标只在本次内核启动中有效，系统重启后应重新从 0 开始。

## 5. 覆盖提示与字段显示

记录输出采用单行 `key=value` 格式，便于阅读和逐行测试。例如：

```text
seq=11 time_ms=1234 pid=7 uid=42 op=pipe_read(3) object_id=99 owner_uid=unknown requested=100 result=60 status=OK
seq=12 time_ms=1235 pid=7 uid=42 op=ipc_stat(6) object_id=0 owner_uid=unknown requested=0 status=ERROR errno=22(EINVAL)
```

时间按 ABI 表示内核时钟毫秒值，不转换为日历时间。成功显示实际结果数量；失败显示正 errno
及名称，不把错误码当作结果数量。`object_id` 只作数值资源编号显示，未知所有者显示 `unknown`。

未知操作如 77 显示 `op=unknown(77)`；未知错误如 99 显示 `errno=99(UNKNOWN)`。
未知记录标志位被忽略，只检查已知的 `GAP_BEFORE` 位。

当游标落后于最旧保留记录时，工具显示：

```text
auditctl: warning: GAP_BEFORE before sequence 101; records were overwritten
```

随后继续处理仍保留的记录。不能用“游标加返回数量”计算新游标，因为序号可能已经跳过
一段被覆盖的区间。缺口是正常的有界日志行为，命令提示后仍可成功退出。

固定尾部不等于整个命令拥有一个不变快照；各批之间仍可能发生覆盖。若初始目标范围已经
全部被覆盖、首条返回记录比 `through` 更晚，工具先报告缺口再退出，不显示范围外的记录。
此时最终 `cursor` 仍是上次成功显示的位置；它可能小于 `through`，不能把它当作“完整导出”。

工具不获取或打印用户载荷、页表 token、缓冲区地址；内核负责保证资源 ID 不是内核指针。

## 6. 错误如何传播

| 退出码 | 含义 |
| ---: | --- |
| 0 | 操作完成，包括空结果、帮助及已提示的覆盖缺口 |
| 1 | 系统调用失败，或返回的统计/记录不符合 ABI |
| 2 | 命令行参数错误 |

收到 `-EFAULT` 等负值时，先判断符号才转换记录数量。内核可能已写入前缀，但本批整体失败，
所以工具不会显示它，并给出使用上一成功游标的重试命令。未知负 errno 原样保留数值。
工具还拒绝超长返回数、重复/倒序序号或不兼容布局，防止越界索引、误读和读取循环不前进。

当前遵循用户库终端输出方式，结果和诊断都输出到标准输出；重定向后的消费者可以依据
`seq=` 和 `auditctl:` 前缀区分记录与提示，不应假定每一行都是事件。

## 7. 验证与边界

从仓库根目录执行：

```bash
cargo test --manifest-path tests/audit-host/Cargo.toml -- --test-threads=1
make -C os run TEST=1
```

[主机测试](../tests/audit-host/auditctl.rs) 直接编译真实工具和用户 API，仅替换系统调用
与输出，共 12 项：参数、统计、空尾部、最大游标、超过 32 条和短批次、固定尾部、覆盖、
未知编号、失败前缀丢弃、ABI 不兼容及异常返回等。原有 16 项内核审计主机测试也保留。

[auditctl_test](../user/src/bin/auditctl_test.rs) 是真实 rCore 用户程序，已加入 `SUCC_TESTS`。
它通过 `fork/exec` 启动工具，父进程同时从管道消费输出，检查子进程退出码。输出逐行处理，
避免大量记录耗尽 32 KiB 用户堆，避免父进程只等待退出而让子进程阻塞在满管道上。

该测试先验证帮助、非法游标和统计，再用合法地址、非法 603 标志制造 35 条失败事件，验证
多批读取和尾部续读；之后再制造 `capacity + 1` 条事件，检查覆盖提示和保留记录。它使用
统计增量检查成功工具调用不制造事件，不依赖累计计数从 0 开始。

2026-09-05 自动验证：28 项主机测试通过；QEMU 中 `auditctl_test` 通过，原有
21 个正常/4 个预期异常用例继续通过，总计 22 个正常、4 个预期异常。
内核和用户库的格式检查、`cargo doc --no-deps` 均通过。

QEMU 测试目前针对 D 分支：A/C 还没有给信号和管道完整接入事件，因此测试可以精确核对
失败事件的增量。未来接入后，测试自身的管道、进程活动也可能制造事件，须改成按 PID/操作
筛选并重新核对覆盖断言。B 的真实不可写、跨页、未映射地址防护仍属于后续联合验收；主机
模拟复制失败通过，不代表这些真实内存边界已经完成。

如果运行过 `TEST=1` 后普通 `make run` 仍进入自动测试，这是现有构建规则把 `usertests`
复制到 `initproc` 产物造成的。可在 `user/` 下执行 `cargo clean -p user_lib` 后重新
`make -C ../os run`，以重新生成正常启动程序。
