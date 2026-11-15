> 中文 | [English](README.md)

# zerot

> Detect dangerous Unicode characters hiding in your source code.

[![CI](https://github.com/YikunWei-dev/zerot/actions/workflows/ci.yml/badge.svg)](https://github.com/YikunWei-dev/zerot/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/zerot.svg)](https://pypi.org/project/zerot/)
[![Python](https://img.shields.io/pypi/pyversions/zerot.svg)](https://pypi.org/project/zerot/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-blue.svg)](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support)

`zerot` scans code for the Unicode tricks that silently break, spoof, or
backdoor software:

| 类别 (Category) | 危害 | 严重度 |
|---|---|---|
| **Zero-width** (`U+200B` 等) | 不可见字符，能藏匿/篡改代码逻辑 | high |
| **Bidirectional override** (`U+202A`–`U+202E`, `U+2066`–`U+2069`) | 让代码**显示顺序**与**执行顺序**不同 —— 经典 *Trojan Source* 攻击 | critical |
| **Unbalanced bidi** | 方向控制未正确闭合 | critical |
| **Confusable / homoglyph** | 视觉上像 ASCII 字母，实则是另一码点（西里尔、希腊、全角等） | high |
| **Fullwidth / compatibility** | 全角/兼容形式字符 | medium |
| **Compatibility masquerade** | NFKC 归一化后塌缩成单个 ASCII 字符（如数学粗体/带圈字母） | medium |
| **Suspicious whitespace** | 看起来像空格但不是 | medium |
| **Control character** | 不可打印的控制字符 | high |
| **Noncharacter** | Unicode 永久保留的非字符码点 | medium |
| **Mixed-script token** | 标识符同时混用 ASCII 与非 ASCII 脚本（如 `арр = 1` 里的西里尔 а/р） | high |

`zerot` 以 **Markdown 报告** 形式列出所有问题，并标注行号、列号、码点、类别与“看起来像谁”。

---

## 两种模式

### 1. 轻量模式 (Lite) — 免安装，单文件即用

`zerot_lite.py` 是**完全自包含**的单文件脚本（仅依赖 Python 标准库），可以直接丢进任意仓库运行，无需 `pip install`。

```bash
# 扫描当前目录（递归）
python3 zerot_lite.py scan .

# 扫描指定文件
python3 zerot_lite.py scan src/app.py

# 生成 Markdown 报告
python3 zerot_lite.py scan . --md report.md

# 只扫描特定扩展名、排除目录
python3 zerot_lite.py scan . --include "*.py" --exclude "*.min.js" --no-recursive
```

退出码：`0` = 未发现风险，`1` = 发现风险（可用于 CI），`2` = 用法错误。

### 2. 软件模式 (Software) — 安装后功能更全

```bash
pip install .            # 或: pip install zerot
```

安装后获得：

- 一个 `zerot` 命令（不必再敲 `python3 zerot_lite.py`）
- 更丰富的选项：JSON / 文本 / Markdown 多格式输出
- 配置文件 `.zerot.json`（提交到仓库，团队共享扫描策略）
- `zerot check` 子命令，专为 CI 设计（有风险即非零退出）

```bash
# 生成 Markdown 报告到文件
zerot scan . --format md -o report.md

# 输出 JSON 给其它工具消费
zerot scan . --format json -o report.json

# CI：发现 high/critical 即失败（默认）
zerot check .

# 仅当达到某严重度才失败
zerot check . --fail-on critical

# 用配置文件
zerot scan . --config .zerot.json
```

#### 配置文件示例 (`.zerot.json`)

```json
{
  "exclude": ["vendor", "*.min.js"],
  "include": ["*.py", "*.js", "*.go", "*.c", "*.rs"],
  "max_size": 2097152,
  "fail_on": "high",
  "format": "md"
}
```

---

## 检测能力详解

### Trojan Source（方向控制攻击）
`zerot` 不仅找出 `U+202E` (RTL Override) 等方向控制字符，还会**跟踪其栈式配对**：
若文件结尾时仍有未闭合的嵌入/隔离控制，会额外报告 `bidi_unbalanced`，并在报告顶部打出醒目警告横幅。

### 同形字符 / 域名欺骗（Homoglyphs）
内置西里尔、希腊、全角等大量“长得像 ASCII”的字符表，每条命中都会标注“看起来像 `a` / `e` / `o` ...”。
对**混合脚本标识符**（同一 token 内同时出现 ASCII 字母与非 ASCII 字母）额外高亮，这类最危险（肉眼几乎无法分辨）。

### 零宽字符
覆盖 `U+200B/200C/200D/2060/FEFF` 等一整套零宽/不可见字符（含变体选择符 VS-1..VS-32）。

---

## 在 CI 中使用

### 作为 GitHub Action（推荐，输出进 Security 面板）

zerot 自带 `action.yml`，可直接在 workflows 中使用，并把结果以 **SARIF** 形式上传到
GitHub 代码扫描（Security 标签页）：

```yaml
# .github/workflows/zerot.yml
name: Zerot
on: [push, pull_request]
jobs:
  unicode-scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: YikunWei-dev/zerot@v1        # 或 pin 到具体 commit
        with:
          targets: "src tests"
          fail-on: high
```

### 作为命令行（任意 CI）

```yaml
# 软件模式
- name: Scan for Unicode tricks
  run: |
    pip install .
    zerot check . --fail-on critical
```

或免安装直接用单文件：

```yaml
- name: Scan with zerot lite
  run: python3 zerot_lite.py scan . --no-recursive
```

---

## 报告格式

默认输出 **Markdown** 报告。还支持：

- `--format json` — 给其它工具消费的结构化数据。
- `--format text` — 紧凑的终端视图（自动上色，可用 `--no-color` 关闭）。
- `--format sarif` — **SARIF 2.1.0**，可直接上传到 GitHub 代码扫描：

```bash
zerot scan . --format sarif -o zerot.sarif
# 然后在 GitHub Actions 里用 github/codeql-action/upload-sarif 上传
```

---

## 作为 pre-commit 钩子

本项目提供 pre-commit 钩子（见 `.pre-commit-hooks.yaml`）。在仓库的
`.pre-commit-config.yaml` 中添加：

```yaml
repos:
  - repo: https://github.com/YikunWei-dev/zerot
    rev: v1.0.0
    hooks:
      - id: zerot            # 需要 pip install zerot
      # - id: zerot-lite     # 无需安装，直接跑单文件 zerot_lite.py
```

提交代码时会自动扫描改动文件，发现 high/critical 即阻断提交。

---

## 配置（`.zerot.json`）

```json
{
  "exclude": ["vendor", "*.min.js"],
  "include": ["*.py", "*.js", "*.go", "*.c", "*.rs"],
  "ignore":  ["tests/fixtures/known_bad.py"],
  "skip_strings": true,
  "max_size": 2097152,
  "fail_on": "high",
  "format": "md"
}
```

| 键 | 说明 |
|---|---|
| `exclude` | 跳过的文件/目录（fnmatch，可重复） |
| `include` | 仅扫描匹配的文件 |
| `ignore` | 忽略命中路径匹配的文件中的**发现**（白名单） |
| `skip_strings` | 是否跳过注释与字符串字面量（默认 `true`） |
| `max_size` | 超过该字节数的文件跳过 |
| `fail_on` | 达到该严重度即非零退出（`low/medium/high/critical`） |
| `format` | 默认报告格式 |

---

## 默认跳过注释与字符串（不影响程序运行）

zerot 是**只读**工具：它只会生成报告，**绝不会修改你的源文件**（有些“可疑字符”可能是你刻意设计的，例如带圈字母做品牌名）。

此外，对代码而言，真正危险的是**写在代码逻辑里的**字符；注释和字符串字面量（比如 C 语言 `printf("…")`、`# 注释`）里的内容只是数据，不影响程序如何执行，通常是有意为之。因此 zerot **默认不扫描**注释与字符串内容：

```bash
# 默认：跳过注释 / 字符串，只扫代码
zerot scan .

# 连注释和字符串里的内容也一起扫（--scan-strings）
zerot scan . --scan-strings
```

支持的语言：C/C++/C#/Java/JS/TS/Go/Rust/Swift/Kotlin/PHP/Objective-C 等使用 `//`、`/* */`、引号字符串；Python/Ruby/Shell/YAML/TOML 等使用 `#` 注释与三重引号字符串。其它扩展名的文件会按纯文本整体扫描。

---

## 项目结构

```
zerot/
├── pyproject.toml
├── action.yml              # GitHub Action（composite）
├── .pre-commit-hooks.yaml  # pre-commit 钩子定义
├── zerot_lite.py           # 轻量模式：单文件、零依赖
├── src/zerot/              # 软件模式包源码
│   ├── catalog.py          # 危险码点目录（唯一数据源）
│   ├── engine.py           # 扫描引擎
│   ├── report.py           # Markdown / JSON / 文本 / SARIF 报告
│   ├── cli.py              # 命令行接口
│   ├── config.py           # 配置文件加载
│   └── __main__.py
├── tests/                  # pytest 测试 + 样本
├── examples/               # 示例报告
└── README_zh.md            # 本文件（中文）
```

## 许可证

MIT © zerot contributors
