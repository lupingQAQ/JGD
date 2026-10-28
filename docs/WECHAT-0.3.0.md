# JGD 0.3.0 发布｜让代码审计 Agent 接得上、跑得快、判得准

> **Agent 集成 · 性能提升 · 核心 Bug 修复**

这不是一个“又多了一条链”的版本。

0.3.0 的目标很明确：**把 JGD 变成一个其他代码审计 Agent 可以直接调用的领域能力，同时把速度和质量补上来。**

---

## 01｜可接入：JGD 不再是一个孤立的 CLI

过去的 JGD 更像一个“自己跑”的工具。  
0.3.0 开始，它可以被其他代码审计 Agent、平台和工作流直接编排。

### 三种接入方式

**① CLI + JSON / SARIF**

- `jgd audit`、`jgd poc`、`jgd index`、`jgd db`、`jgd doctor`、`jgd serve`
- 机器可读的 `run.json`
- SARIF 2.1.0，方便接入代码审计平台
- 稳定退出码：`0 / 10 / 20 / 30 / 40`

**② MCP stdio**

提供 5 个工具：

- `jgd_audit`
- `jgd_poc`
- `jgd_get_run`
- `jgd_list_findings`
- `jgd_cancel`

**③ A2A JSON-RPC / SSE**

- Agent Card
- `SendMessage`
- `SendStreamingMessage`
- `GetTask`
- `ListTasks`
- `CancelTask`
- 可选 Bearer Token

> **边界很重要：控制面在外，领域内核在内。**
>
> 外部 Agent 只需要提供目标、授权、profile 和预算；桥发现、链配对、动态验证、PoC 终止仍然由 JGD 内部完成。

同时，终态裁决继续由 **确定性 verifier** 拥有。  
LLM 可以参与分析和建议，但不能把一条链“判成 confirmed”。

---

## 02｜更快：索引 + JVM 批处理

0.3.0 的速度优化，不是单纯加机器，而是减少重复工作。

### ① 字节码数据库索引

JGD 使用 SQLite 建立字节码语义索引，支持增量构建：未变化的 JAR 直接跳过。

实测数据：

- **828 个 JAR 热查询：0.038s**
- 旧路径：2.56s
- 提升约 **67 倍**

### ② 动态探针批量复用 JVM

同一 classpath 上的多个 bridge，不再每个都启动一次 JVM。  
`DynamicProbe.probe_many` 会把它们合并成一个批次执行。

### ③ 完整 target classpath

动态探针不再只挂载 bridge 所在的 JAR，而是使用整个目标 classpath。

Spring Boot 的嵌套结构也会被处理：

- `BOOT-INF/lib/*.jar`
- `BOOT-INF/classes`

在安全提取后加入探针 classpath。

### ④ 热索引覆盖统计修复

增量构建时，覆盖数据不再显示成 `jars=0 / classes=0`，  
而是返回完整的目标统计。

---

## 03｜更准：修掉几个会误导结论的问题

### ① 修正 CC3 链构造

`ChainedTransformer` 现在使用真实的 `Transformer[]` 构造函数，  
并采用标准的：

```text
getMethod → invoke → exec
```

不再因为错误的构造签名导致链无法组装。

### ② `hmz:` 延迟触发载体

普通 `HashMap.put()` 会在**构建或序列化阶段**触发 bridge，  
这只能证明“构建期有效果”，不能证明反序列化闭链。

0.3.0 新增 `hmz:` 载体：

- 反射写入 `HashMap$Node`
- 构建和序列化阶段不触发 `hashCode`
- 只有 `HashMap.readObject()` 重哈希时才触发
- `fired_at_deser=true` 才记为 `CHAIN_CONFIRMED`

> **构建期触发 ≠ 反序列化闭链。**

### ③ 移除 LLM 终态把关

旧路径中残留的 LLM acceptance gate 已删除。  
终态只由证据、覆盖、预算和策略决定。

### ④ 嵌套 fat JAR 递归索引

Spring Boot / WAR 的 `BOOT-INF/lib`、`WEB-INF/lib` 不再被静默漏扫。

### ⑤ 版本门更保守

无法验证的版本条件返回：

```text
UNVERIFIED
```

而不是误报为：

```text
APPLICABLE
```

### ⑥ 压缩比限制只作用于 `.class`

避免正常资源文件因为压缩比检查被误拒。

---

## 04｜实测：五个高 star 开源产品

所有动态验证都在隔离 Linux VM 内完成，未在 Windows 主机执行目标代码。

- **Hutool 5.8.48**：4 个 `DESER_OK`，包含 `DynaBean`
- **RocketMQ 5.5.1**：8 个 `NOT_SERIALIZABLE`，2 个依赖错误
- **Jenkins 2.587**：6 个 `NOT_SERIALIZABLE`，4 个 NPE
- **Nacos 3.2.4**：10 个 `NOT_SERIALIZABLE`
- **SkyWalking 11.0.0**：10 个 `DESER_OK`（内置 Nacos API 类）

其中，Hutool `DynaBean` + Commons Collections 3.2.1 完成了确定性闭链：

```text
RCE_DEMO_FIRED
fired_at_build=false
fired_at_deser=true
```

自动审计路径也在 43.1s 内产出：

```text
coverage.poc=2
2 × CHAIN_CONFIRMED
```

---

## 05｜怎么开始

```bash
# 静态审计：JSON / SARIF / Markdown
python -m jgd audit \
  --target /path/to/jars \
  --profile standard \
  --format json,sarif,md \
  --out runs/demo

# 启动 MCP stdio
python -m jgd serve mcp

# 启动 A2A
python -m jgd serve a2a \
  --host 127.0.0.1 \
  --port 8080
```

A2A Agent Card：

```text
http://127.0.0.1:8080/.well-known/agent-card.json
```

---

## 06｜边界说明

- Hutool 单独 JAR **不包含** Commons Collections；本次闭链是 **Hutool bridge + 公共 tail classpath**，不是单 JAR Hutool 零日。
- Jenkins 内置 Commons Collections 3.2.2，默认序列化 guard 会阻止 `InvokerTransformer`。
- 未获得授权商业产品语料，因此没有伪造商业链结论。
- PoC 必须在隔离 Linux VM 中运行，并显式传入 `--unsafe-host`。
- LLM 输出只作为分析建议，不拥有终态裁决权。

---

## 最后

0.3.0 的核心不是“炫技”。

它做的是三件事：

**让 JGD 能被其他代码审计 Agent 调得动。**  
**让索引和动态验证跑得更快。**  
**让链判定不再被构建期假触发和旧 LLM 把关误导。**

---

### 发布信息

- GitHub：https://github.com/lupingQAQ/JGD
- Release：https://github.com/lupingQAQ/JGD/releases/tag/v0.3.0
- Version：`0.3.0`
- Release tag：`v0.3.0`
- 状态：Latest

> **JGD 0.3.0 — Agent integration, performance, and correctness.**
