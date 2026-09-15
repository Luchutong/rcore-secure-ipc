# rCore Secure IPC 成果交付包

本目录用于把最终成果拆分给四位组员完成排版、复核和答辩准备。所有结论统一以
`v1.0.0`（`main@c202b17`）及最终 CI #34799749443 为准，不再引用中期阶段的“尚待集成”
表述。

远端材料分支：`deliverables/final-kit`。组员获取方式：

```bash
git fetch origin deliverables/final-kit
git switch --track origin/deliverables/final-kit
```

只想查看材料而不切换当前工作区时，也可使用独立 worktree：

```bash
git worktree add ../rcore-secure-ipc-deliverables origin/deliverables/final-kit
```

## 1. 交付物索引

| 交付物 | 主文件 | 用途 |
| --- | --- | --- |
| 组员任务单 | [TEAM_ASSIGNMENTS.md](TEAM_ASSIGNMENTS.md) | 明确四人负责章节、程序、图片和复核项 |
| 用户态测试程序说明 | [USER_TEST_PROGRAMS.md](USER_TEST_PROGRAMS.md) | 说明测试入口、覆盖点、运行命令和预期输出 |
| 完整课程设计报告草稿 | [COURSE_REPORT.md](COURSE_REPORT.md) / [可编辑 DOCX](generated/rcore-secure-ipc-course-report-draft.docx) | 可直接套用学校 Word 模板继续排版 |
| 截图与日志操作手册 | [SCREENSHOT_AND_LOG_GUIDE.md](SCREENSHOT_AND_LOG_GUIDE.md) | 统一截图、命名、图注、日志和复现实验方法 |
| 答辩 PPT 正式方案 | [DEFENSE_PPT_10MIN_4PERSON.md](DEFENSE_PPT_10MIN_4PERSON.md) | 12 页、约 10 分钟；D 主讲统筹，A/B/C 分模块接力 |
| 答辩 PPT 压缩备用 | [DEFENSE_PPT.md](DEFENSE_PPT.md) | 现场临时限时 5 分钟时使用，不与正式稿混讲 |
| D 模块答辩问答手册 | [DEFENSE_QA_MODULE_D.md](DEFENSE_QA_MODULE_D.md) | 围绕模块 D 与项目整体的分级问答、统一数据口径和易错表述 |
| 最终交付检查表 | [FINAL_CHECKLIST.md](FINAL_CHECKLIST.md) | 汇总前的逐项验收和文件命名规则 |
| 最终答辩综合验证原始证据 | [generated/final-defense/README.md](generated/final-defense/README.md) | 本次实际 QEMU/宿主测试 PTY 记录、性能原始日志及可重建 PNG |
| 原始日志 | [logs/](logs/) | CI、宿主测试、独立安全程序和性能原始输出 |
| 论文式图片 | [figures/](figures/) | 同时提供 SVG 与 1600×900 PNG |

## 2. 统一项目口径

- 中文标题：**基于 rCore 的安全进程间通信机制设计与实现**。
- 项目基线：rCore-Tutorial-v3 第七章，提交 `af89aff`。
- 最终版本：`v1.0.0`，提交 `c202b1764c63ae70006edabe8af3f892c82bad72`。
- 核心模块：A 凭据与授权、B 用户地址安全、C IPC 资源治理、D 审计与测试。
- 集成顺序：B → A → C → D。
- 宿主测试：28/28 通过。
- QEMU 用户测试：28 个预期成功 + 4 个预期异常，共 32/32 通过。
- 压力测试：6×128=768 个事件，缓冲区最多保留 256 条。
- 性能：20,000 轮管道创建/关闭，中位数由 647 ms 变为 746 ms，观测增加约 15.3%，
  未出现数量级回退。

## 3. 图片使用原则

本目录图片采用白底、单一灰蓝配色、无渐变和无复杂 CSS，适合论文、打印和 PPT：

- 报告优先插入 SVG，保持文字和线条清晰；学校模板不支持 SVG 时使用同名 PNG。
- PPT 使用 PNG，推荐宽 25～28 cm，保持原始 16:9 比例，不裁切数据来源和注释。
- 图题放在图下，格式为“图 X-X ……”，正文必须先引用图片再放图。
- 图中的数字必须能够在 `logs/` 或 GitHub Actions 链接中找到原始证据。
- 不将人工整理图称为“终端原始截图”；`fig-05` 是根据真实日志排版的展示图，原始文本见
  `logs/qemu-security-programs.log`。

## 4. 推荐交付目录

```text
成果提交包/
├── 01-课程设计报告/
│   ├── 基于rCore的安全进程间通信机制设计与实现.docx
│   └── 基于rCore的安全进程间通信机制设计与实现.pdf
├── 02-源代码/
│   ├── rcore-secure-ipc-v1.0.0.zip
│   └── README.txt
├── 03-测试程序与日志/
│   ├── 用户态测试程序说明.pdf
│   ├── logs/
│   └── figures/
├── 04-答辩PPT/
│   ├── rCore安全IPC答辩.pptx
│   └── rCore安全IPC答辩.pdf
└── 05-分工与AI使用记录/
    ├── 四人分工说明.pdf
    └── AI_USAGE.pdf
```

## 5. 组员开始工作前

1. 每人先阅读本页及自己的任务单，不自行修改统一数字。
2. 需要补充姓名、学号、课程、教师和学院的地方统一使用真实信息替换 `[待填写]`。
3. 所有新增实验必须记录提交号、QEMU 版本、命令、时间和完整输出。
4. 修改报告结论时同步检查 PPT、图注和答辩讲稿，避免同一指标出现不同版本。
5. 最终由一人按照 [FINAL_CHECKLIST.md](FINAL_CHECKLIST.md) 汇总，不接受四份格式各异的材料。
