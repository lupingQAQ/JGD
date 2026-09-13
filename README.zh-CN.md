# ⚡ JGD

### JavaGadgetDigger — 解决反序列化漏洞挖掘的最后一公里

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-11%20%7C%2017-orange?logo=java&logoColor=white)](https://openjdk.org)

🌐 **[English](README.md)**

---

## 什么是 JGD？

一个**自主挖掘 agent**：输入任意 JAR 目录，输出：
1. **已知公开链** — 四态判定（在场 / 版本 / 可组装 / 可点火）
2. **未公开新链** — 静态+动态分析 + 对抗式 LLM 审计发现
3. **武器化 PoC** — 序列化载荷 + RCE 闭环演示（良性标记文件）

全部决策已内化：`jar 进 → 链子出`，零中间用户交互。

```
┌─────────────────────────────────────────────────────────────────┐
│  输入: 任意 JAR 目录                输出: 链 + PoC               │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   │
│  │ 公开链   │──▶│ 桥发现   │──▶│ 链配对   │──▶│ PoC      │   │
│  │ 判定     │   │ (静态)   │   │ (动态)   │   │ 武器化   │   │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘   │
│    签名+版本门    字节码+CHA图    契约合成       良性载荷       │
│                   +分派边        +三载体       +点火测试      │
└─────────────────────────────────────────────────────────────────┘
```

## 🆕 已发现新链

### T1 — 新入口（ds 确认：所有公开语料中无记录）

| 链 | 桥接类 | 载体 | JDK | 状态 |
|---|-------|------|-----|------|
| **objlongpair-hashmap** | `org.apache.activemq.artemis.api.core.ObjLongPair` | HashMap rehash | 17+ | ✅ RCE已闭环 |

```
HashMap.readObject() → rehash → hash(key)
  → ObjLongPair.hashCode() → Objects.hash(first, second)
    → Arrays.hashCode() → first.hashCode()     [Object 字段 — isInstance 恒真]
      → EqualsBean.hashCode() → beanHashCode()
        → ObjectBean.toString() → ToStringBean.toString()
          → Templates.getOutputProperties() → TemplatesImpl.newTransformer()
            → TemplatesImpl.defineClass() → payload 静态块 → RCE
```

> **新颖性**：入口侧经对抗审计确认 T1 —— 未见于 ysoserial、GadgetInspector
> 及全部公开 CVE writeup。与所有已知 ROME 入口范式正交（直接 ROME key /
> BAVE / HotSwappableTargetSource / XString）。

### T2 — 新载体（ds 确认 CONFIRM）

| 链 | 桥接类 | 依赖库 | 载体 | JDK | 状态 |
|---|-------|--------|------|-----|------|
| **mutableobj-bave** | `cn.hutool.core.lang.mutable.MutableObj` | hutool-core | BAVE toString | ≤11 | ✅ RCE已闭环 |
| **antlr4-pair-bave** | `org.antlr.v4.runtime.misc.Pair` | antlr4-runtime | BAVE toString | ≤11 | ✅ RCE已闭环 |
| **federationconfiguration** | `FederationConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE已闭环 |
| **federationaddresspolicy** | `FederationAddressPolicyConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE已闭环 |
| **federationqueuepolicy** | `FederationQueuePolicyConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE已闭环 |
| **broadcastgroupconfiguration** | `BroadcastGroupConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE已闭环 |

### T3 — 变体

| 链 | 桥接类 | 依赖库 | 备注 |
|---|-------|--------|------|
| **ewah-hashmap** | `EWAHCompressedBitmap` | JavaEWAH (Lucene/ES) | 浅分派，价值有限 |

<details>
<summary>📊 完整分派栈（点击展开）</summary>

**ObjLongPair (T1, JDK 17):**
```
HashMap.put → HashMap.hash
  → ObjLongPair.hashCode(ObjLongPair.java:55)
    → Objects.hash → Arrays.hashCode
      → EqualsBean.hashCode → EqualsBean.beanHashCode
        → ObjectBean.toString → ToStringBean.toString → Method.invoke
          → TemplatesImpl.defineClass → payload static block
```

**MutableObj (T2, JDK 11):**
```
BAVE.readObject → val.toString()
  → MutableObj.toString → value.toString()
    → ObjectBean.toString → ToStringBean.toString
      → Templates.getOutputProperties → newTransformer → defineClass → RCE
```
</details>

## 🚀 快速开始

### CLI 模式（批量审计）

```bash
# 环境要求: Python 3.10+, JDK 11 与 17, ECJ 编译器
pip install chromadb  # 可选, RAG 持久化

# 指向任意 JAR 目录, 自动产出链 + PoC
python3 audit_target.py --target /path/to/jars --name "你的产品"
```

### TUI 模式（交互式可视化）

```bash
python3 tui.py                    # English
python3 tui.py --lang zh          # 中文
```

### TUI 按键

| 按键 | 功能 |
|------|------|
| `↑` `↓` / `j` `k` | 导航链 |
| `Enter` | 切换详情视图 |
| `t` | 切换语言（中/英） |
| `q` | 退出 |

## 📁 项目结构

```
jgd/
├── audit_target.py          # 产品 CLI 入口
├── tui.py                   # 交互式 TUI
├── jgd/            # 核心 agent 模块 (25 个)
│   ├── verify_agent.py      # 桥发现 + ds 对抗审计
│   ├── chain_complete.py    # 链配对 + 穷尽证明
│   ├── poc_gen.py           # 武器化 PoC 生成
│   ├── known_chains.py      # 公开链四态判定
│   ├── matrix_agent.py      # 多 JDK 探针编排
│   ├── bcdisasm.py          # 纯 Python 字节码反汇编器
│   ├── bridge_fix.py        # 操作数栈符号执行
│   ├── chroma_store.py      # RAG（按语料指纹分域）
│   ├── llm.py               # 双模型（GLM × DeepSeek）
│   ├── scope.py             # 语料指纹隔离
│   ├── profiler.py          # 节点级性能画像
│   ├── conductor.py         # 验收门控终局
│   └── ...
├── examples/
│   ├── chains.json          # 全部已发现链（机器可读）
│   └── chains.md            # 人类可读链目录
├── tests/
│   └── test_smoke.py        # 可第三方复现测试
├── ARCHITECTURE.md          # 25 模块图 + 设计裁决
├── CHANGELOG.md             # 设计决策史 (R6-R52)
├── SECURITY.md              # 授权使用 + 负责任披露
├── CONTRIBUTING.md          # 五项开发原则
└── LICENSE                  # MIT
```

## 🔬 工作原理

### 1. 公开链判定（必能）
- 精选签名库类匹配
- 版本门控（CC 3.2.2 阻断 functor、CC4 4.6 NotSerializable、BAVE JDK17 收窄 val 为 String 等实证截止点）
- 用目标自己的 JAR 动态组装 + 点火复验

### 2. 未公开链发现（声明域内穷尽）
- **静态**：操作数栈符号执行检测接收者桥 + 参数桥
- **图**：语料指纹门控实时建图 + CHA 分派边
- **动态**：批处理并行 JVM 探针（三载体 × 字段契约合成 × 多 JDK）
- **可观测性**：标记物可达性 + 异常栈帧 + 标记物调用者栈捕获

### 3. 对抗式审计
- **发现者 ≠ 验证者**：GLM 选候选，DeepSeek 独立审计
- **DSH 验收门控**：终局判定被拒收则自动延长轮次继续挖
- **"声明 ≠ 证据"标准**：每项修复须有测量证据

### 4. 武器化 PoC 生成
- 链从挖掘产物自动派生（`derive_chains`）
- 字段类型感知桥装配（`make_bridge` 支持 Object/接口-Proxy）
- 尾巴候选循环至 RCE 闭环（`R42 完整性循环`）
- 良性载荷：仅写 `/tmp` 标记文件

## ⚡ 性能

| 指标 | 数值 |
|------|------|
| 全管线（31 jars） | ~90s 端到端 |
| 配对吞吐 | 1500+ 对 / 9 分钟（批处理 + 4 并行） |
| PoC 生成（3 链） | 20.3s（并行加速 2.7×） |
| 单 JVM 内存 | ≤ 256 MB（-Xmx256m, 余量 28%） |
| 全语料 OOM | 0 |

## 🛡️ 诚实能力边界

| 主张 | 状态 |
|------|------|
| 公开链：必能检测 | ✅ 机械判定（有限签名集） |
| 未公开链：声明域内穷尽 | ✅ 覆盖账本可复算 |
| 未公开链：全域穷尽 | ❌ 不可判定（Rice 定理） |
| PoC：永远完整产出 | ✅ 尾巴候选循环至 RCE 闭环 |

## 📖 文档

- [ARCHITECTURE.md](ARCHITECTURE.md) — 25 模块图, 设计裁决
- [CHANGELOG.md](CHANGELOG.md) — 47 轮演化史（R6-R52）
- [examples/chains.md](examples/chains.md) — 人类可读链目录
- [SECURITY.md](SECURITY.md) — 授权使用政策, 负责任披露

## ⚠️ 免责声明

**仅用于合法安全研究、教育和授权渗透测试。**
所有 PoC 载荷仅写良性标记文件（`/tmp/jgd_poc_fired`）—— 无破坏动作。

## 📄 许可证

[MIT](LICENSE) — Copyright (c) 2026 JGD Contributors
