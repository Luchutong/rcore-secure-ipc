# 运行截图与测试日志操作手册

## 1. 两类证据必须区分

1. **原始运行截图**：直接截取终端或 GitHub Actions 页面，证明程序确实运行。
2. **论文数据图**：根据原始日志整理的图表，便于阅读和比较。

报告建议每类关键结果使用“1 张简洁数据图 + 1 个日志文件/链接”，不应堆放十几张终端截图。
本目录 `figures/` 是第二类，`logs/` 是可复核原始文本。组员若自行截屏，应按本手册保持简洁。

## 2. 已提供图片

| 文件 | 建议用途 | 推荐图题 |
| --- | --- | --- |
| `fig-01-ci-summary` | 报告测试总览、PPT 第 7 页 | 图 7-1 最终测试通过情况 |
| `fig-02-security-matrix` | 报告测试设计、PPT 第 7 页备选 | 图 7-2 安全模块用户态测试矩阵 |
| `fig-03-audit-stress` | 报告压力测试、PPT 第 8 页 | 图 7-3 审计压力与有界内存结果 |
| `fig-04-performance` | 报告性能分析、PPT 第 8 页 | 图 7-4 管道创建关闭基准中位耗时 |
| `fig-05-audit-output` | 报告审计工具、PPT 第 6 页 | 图 7-5 auditctl 审计读取实例 |
| `fig-06-architecture` | 报告总体设计、PPT 第 4 页 | 图 4-1 安全 IPC 统一调用链 |

每张图均有 SVG 和 PNG：

- Word/WPS 支持 SVG 时优先 SVG；
- PPT 使用 PNG 最稳妥；
- 不拉伸变形，不删除图内来源说明；
- 不添加阴影、发光、三维柱状图或大面积渐变。

## 3. 原始终端截图规范

### 3.1 终端设置

- 分辨率至少 1600×900，缩放 100%。
- 字体使用等宽字体，字号 16～20 pt。
- 建议浅色背景或纯黑背景，不使用透明、壁纸或花哨主题。
- 截图前执行 `clear`，一张图只呈现一个结论。
- 命令和结果必须同时可见；隐藏用户名可裁掉提示符左侧，但不能裁掉测试名和汇总。
- 不在截图中显示访问令牌、私有邮箱、密钥、完整家目录或其他无关个人信息。

### 3.2 推荐截图清单

| 编号 | 命令/页面 | 必须可见内容 | 负责人 |
| --- | --- | --- | --- |
| S01 | `make run TEST=1` | 28/28、4/4、32/32、Usertests passed | D |
| S02 | `badptr`，随后运行 `hello_world` | 八行 EFAULT、8/8、kernel alive，以及后续程序成功输出 | B |
| S03 | `quota_test` | 七类 passed 与总结 | C |
| S04 | `cred_test` | 两次 SIGKILL 和 `cred_test passed!` | A |
| S05 | `auditctl stat` + `read` | capacity、序号、操作、status | D |
| S06 | `audit_stress_test` | children、total、retained、elapsed | D |
| S07 | 五次 `ipc_bench 20000` | 五条 BENCH 原始输出 | C |
| S08 | GitHub Actions 最终 run | 三个 job 为绿色成功，commit 对应最终 main | D |

报告正文通常选择 S01、S02、S05、S07 四张即可；其余放附录或答辩备用页。

模块 B 已提供两张可直接插入的 16:9 图片：

- `figures/module-b-badptr-summary.png`：第 7 页主图，左侧八类输入，右侧 8/8、EFAULT、Alive。
- `figures/module-b-badptr-qemu-evidence.png`：原始测试证据页，包含逐项输出及攻击后运行
  `hello_world` 的存活证明。

模块 C 已提供三张可直接插入的 16:9 图片：

- `figures/module-c-quota-performance-summary.png`：第 9 页主图，配额正确性与性能数据合并展示。
- `figures/module-c-quota-qemu-evidence.png`：七组 `quota_test` 通过和 32/32 回归证据。
- `figures/module-c-performance-evidence.png`：五次性能样本、中位数与 +15.3% 计算证据。

## 4. 日志采集命令

### 4.1 自动测试日志

推荐使用 `script` 保留 ANSI 终端输出：

```bash
mkdir -p delivery-logs
script -q -c 'cd os && make run TEST=1' delivery-logs/qemu-usertests.typescript
```

若学校只接受纯文本，可去除颜色码：

```bash
sed -E 's/\x1B\[[0-9;]*[mK]//g' \
  delivery-logs/qemu-usertests.typescript \
  > delivery-logs/qemu-usertests.log
```

### 4.2 宿主测试日志

```bash
script -q -c 'cd tests/audit-host && cargo test' delivery-logs/host-audit.typescript
```

### 4.3 环境清单

```bash
{
  date -Iseconds
  git rev-parse HEAD
  git describe --tags --always
  rustc --version
  cargo --version
  qemu-system-riscv64 --version | head -1
} | tee delivery-logs/environment.txt
```

如果使用 Windows PowerShell，不熟悉 `script` 时可用终端“全部选择→复制”保存 UTF-8 文本；
必须检查换行和中文是否正常。

### 4.4 GitHub Actions 日志

```bash
gh run view 34799749443 --log > delivery-logs/main-ci-34799749443.log
gh run view 34799749443 \
  --json status,conclusion,headSha,url,jobs \
  > delivery-logs/main-ci-34799749443.json
```

仓库已提供摘要 `logs/main-ci-34799749443.log`。答辩被追问时可打开完整 GitHub 链接核验。

## 5. 性能数据处理

只使用原始五次数据：

```text
778, 746, 737, 746, 727 ms
```

人工核算：

```text
排序：727, 737, 746, 746, 778
中位数：746 ms
原始基线：647 ms
差值：746 - 647 = 99 ms
比例：(746 - 647) / 647 × 100% ≈ 15.3%
```

图表规范：

- 纵轴从 0 开始，避免夸大差异；
- 明确单位 ms 和工作量 20,000 轮；
- 标注提交或测试日期；
- 图下注明不同日期、QEMU 调度和宿主负载是威胁因素；
- 不画趋势线，不写“提升”或“优化”，正确表述为“开销增加约 15.3%”。

## 6. 审计压力图解释

图中 768 与 256 不是“通过数/失败数”：

- 768：所有子进程实际生成并被统计的失败事件总数；
- 256：环形缓冲区在任一时刻最多保留的最新记录数；
- 更旧记录被覆盖，`overwritten_events` 和 `GAP_BEFORE` 让消费者识别缺口；
- 该设计用有限可观测性换取确定内存上限，避免审计自身成为 DoS 来源。

## 7. 图片命名与图注

建议最终命名：

```text
图4-1_安全IPC统一调用链.png
图7-1_最终测试通过情况.png
图7-2_安全模块用户态测试矩阵.png
图7-3_审计压力与有界内存结果.png
图7-4_管道创建关闭基准中位耗时.png
图7-5_auditctl审计读取实例.png
附图A-1_QEMU完整测试原始截图.png
```

标准图注示例：

> 图 7-4 给出了相同 20,000 轮工作量下的 QEMU 端到端中位耗时。最终安全版本中位数为
> 746 ms，较原始基线增加约 15.3%。由于实验跨日期且使用毫秒时钟，该结果用于排除数量级
> 回退，不作为硬件级精确开销。

## 8. 严禁事项

- 不使用伪造终端、手工把 FAIL 改成 PASS 或删除不利数据。
- 不从中期 PPT 复制已经过期的 30/30、2.3% 等阶段性结论作为最终结果。
- 不把 `overwritten_events` 翻译为“丢失写入”；写入已计数，只是旧记录不再保留。
- 不把日志截图当作唯一证据；同时保留文本日志和提交号。
- 不使用复杂 CSS、网页仪表盘、3D 图、装饰性图标或无法打印辨认的深色渐变。
- 不截取只显示绿色对勾却看不到项目、commit 或测试名的图片。
