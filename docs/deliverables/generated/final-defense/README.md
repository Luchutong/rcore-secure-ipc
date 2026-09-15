# 最终答辩综合验证：可复核原始证据包

本目录为答辩 PPT 的“综合验证”页提供可追溯证据。`images/` 中的 PNG **不是手工
制作的终端截图，也不是由 Markdown 结果重新绘制的示意图**：它们由
[`tools/render_verbatim.py`](tools/render_verbatim.py) 从本目录保存的真实 PTY 运行记录，或
仓库既存的最终性能原始日志中，截取连续文本后逐字渲染而成。这样既保留可读的 16:9
白底/北洋蓝版式，也能由原文、命令和 SHA-256 完整复核。

渲染程序不保存任何测试结果字符串；每张图的开始和结束标记、输入文件哈希及 PNG 哈希均在
[`VERIFICATION_INDEX.json`](VERIFICATION_INDEX.json) 中记录。图片不带伪造的终端窗口边框或
人工补写的时间、结果和统计数字。

## 本次实际执行

以下两项由本工作区在 `2026-09-15` 实际执行，并由 Unix `script` 以 PTY 格式原样保存。各
`.typescript` 文件开头含有时间、命令、TTY 和退出码；命令成功均为 `COMMAND_EXIT_CODE="0"`。

| 证据源 | 实际命令 | 可复核结果 |
| --- | --- | --- |
| [`raw/qemu-usertests-20260915.typescript`](raw/qemu-usertests-20260915.typescript) | `cd os && make run TEST=1` | QEMU 8.2.2；28/28 预期成功、4/4 预期异常、总计 32/32；包含坏指针、配额与审计压力程序。 |
| [`raw/host-audit-20260915.typescript`](raw/host-audit-20260915.typescript) | `cargo test --manifest-path tests/audit-host/Cargo.toml -- --test-threads=1` | `audit_host_tests` 7/7、`auditctl` 12/12、`syscalls` 9/9。 |
| [`raw/qemu-summary-filter-20260915.typescript`](raw/qemu-summary-filter-20260915.typescript) | 对上述 QEMU PTY 文件执行 `grep -E`，只筛选总计行 | 这是对同一原始 QEMU 文件的实际命令输出，便于在一张图中连续展示 28/28、4/4 与 32/32。 |

运行时所在分支为 `deliverables/final-kit`；其内核实现基线是 `v1.0.0` 的代码提交
`b626d923736149873286734966cfba13a06a1b01`。`v1.0.0` 标签提交
`c202b1764c63ae70006edabe8af3f892c82bad72` 在此前者之上只归档文档和验收材料，未改变内核
实现。

## 最终性能证据的来源说明

[`images/08-final-performance-log-verbatim.png`](images/08-final-performance-log-verbatim.png) 来自仓库
已有的最终性能原始记录 [`../../logs/final-performance.log`](../../logs/final-performance.log)，并非本次
重新测出的单次数据。该记录明确标注最终代码提交 `main@b626d923…`、QEMU 8.2.2、5 次
`ipc_bench 20000` 样本，以及中位数 `746 ms` 相对原始基线 `647 ms` 的 `+15.3%`。

保留该原始最终日志是为了避免以一次新运行覆盖或混合基线样本；PPT 中应表述为“最终性能日志
记录显示”，而不是“本次会话重新跑得”。

## 图片与原文对应关系

| PNG（1600×900） | 原文来源 | PPT 可支持的结论 |
| --- | --- | --- |
| [`01-qemu-suite-summary-verbatim.png`](images/01-qemu-suite-summary-verbatim.png) | QEMU 汇总筛选 PTY | QEMU 用户测试 28/28 + 4/4，合计 32/32。 |
| [`02-qemu-badptr-verbatim.png`](images/02-qemu-badptr-verbatim.png) | QEMU PTY 的 `badptr` 连续区段 | 八类坏指针均返回 `EFAULT`；测试进程和内核继续运行。 |
| [`03-qemu-quota-verbatim.png`](images/03-qemu-quota-verbatim.png) | QEMU PTY 的 `quota_test` 连续区段 | 到达上限、`close` 后恢复、失败回滚与生命周期一致性均通过。 |
| [`04-qemu-audit-stress-verbatim.png`](images/04-qemu-audit-stress-verbatim.png) | QEMU PTY 的 `audit_stress_test` 连续区段 | 6×128=768 事件，保留 256 条；程序退出 0。 |
| [`05-host-audit-lib-verbatim.png`](images/05-host-audit-lib-verbatim.png) | 宿主 PTY 的库测试连续区段 | 审计 ABI、转换、环形缓冲计数等 7/7。 |
| [`06-host-auditctl-verbatim.png`](images/06-host-auditctl-verbatim.png) | 宿主 PTY 的 `auditctl` 测试连续区段 | 游标、分页、异常统计等 12/12。 |
| [`07-host-syscalls-verbatim.png`](images/07-host-syscalls-verbatim.png) | 宿主 PTY 的 syscall 测试连续区段 | `EFAULT`、参数检查、权限优先级、快照等 9/9。 |
| [`08-final-performance-log-verbatim.png`](images/08-final-performance-log-verbatim.png) | 最终性能原始日志 | 5 次样本中位数 746 ms，对基线 +15.3%，无数量级回退。 |

## 复核与复现渲染

在仓库根目录运行：

```bash
python3 docs/deliverables/generated/final-defense/tools/verify_evidence.py
```

该检查会验证每个源文件与图片的 SHA-256、PNG 尺寸，并在临时目录从源文本重新渲染；只有逐字
重建出的 PNG 哈希完全一致才通过。若要在同一环境中更新图片和索引，可运行：

```bash
python3 docs/deliverables/generated/final-defense/tools/render_verbatim.py
python3 docs/deliverables/generated/final-defense/tools/verify_evidence.py
```

图片在 PPT 中建议以“原始运行记录（逐字渲染）”或“最终性能原始日志（逐字渲染）”标注，避免
误称为终端应用窗口截图。
