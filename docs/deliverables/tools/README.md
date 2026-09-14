# 可编辑报告生成工具

脚本根据仓库内 Markdown 与 PNG 生成可继续编辑的 Word 报告草稿。生成结果不是最终学校格式，
组员仍需填写身份信息、套用学校封面和目录格式并导出 PDF。答辩 PPT 由组员根据
`DEFENSE_PPT.md` 的逐页材料自行制作。

## 依赖

```bash
python3 -m venv /tmp/rcore-delivery-venv
/tmp/rcore-delivery-venv/bin/pip install python-docx
```

## 生成

```bash
/tmp/rcore-delivery-venv/bin/python \
  docs/deliverables/tools/generate_docx.py

```

输出：

- `generated/rcore-secure-ipc-course-report-draft.docx`

PPT 页序、每页文字、讲稿、配图和五分钟时间分配见 `../DEFENSE_PPT.md`。

## 校验交付包

```bash
python3 docs/deliverables/tools/verify_delivery.py
```

校验器检查必需材料、用户程序、图片尺寸与简洁风格、日志关键数字、报告一致性、DOCX 完整性
和本地 Markdown 链接。成功时最后输出 `ALL DELIVERY CHECKS PASSED`。
