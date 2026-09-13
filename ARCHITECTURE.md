# JGD 架构（Architecture）

> 输入任意 jar 目录 → 输出：公开链四态判定 + 未公开链（对抗审计过的）+ 武器化良性 PoC。
> 单命令、零中间决策、全部判定内化、终局经 dsh 验收。

## 模块图（25 个存活模块，唯一真相源）

```
audit_target.py ──────────── 产品 CLI（--target <jar目录> --name <产品>）
  │  一次性终局: known_chains → verify → chains → poc, rc 收敛 0
  ▼
┌─────────────────── 核心管线（4 层 agent）───────────────────┐
│                                                              │
│  ① known_chains.py     公开链四态判定 (PRESENT/VERSION/     │
│      └ chains_2026.py    ASSEMBLE/FIRE) — 签名库+版本门      │
│                                                              │
│  ② verify_agent.py     桥发现（接收者桥+参数桥）→ 分级 →     │
│      └ matrix_agent.py  层次取证(抽象/子类) → 动态验证 →      │
│         └ staticagent     ds 对抗审计 + glm 辩护 → RAG        │
│                                                              │
│  ③ evolve_v2.py        候选池(5源) → PV 注入探针 →           │
│                        FIELD_FORWARD → CV 链 PoC             │
│                                                              │
│  ④ chain_complete.py   链完成/穷尽回路                        │
│      ├ ensure_graph      指纹门控实时建图 + CHA 分派边        │
│      ├ scan_receivers    sink 种子(经典+产品自有+反射API)     │
│      │                   反向≤3跳 + 具体可序列化              │
│      ├ 批处理配对         一个JVM/桥×全接收者, 双/三载体       │
│      │                   (BAVE|HASHMAP|HASHMAP_EQ)           │
│      ├ 字段契约合成       survival(): 全字段存活值注入         │
│      ├ 观测三通道         hop2标记物(唯一可达论证)+异常栈帧     │
│      │                   +标记物调用者栈 + -Xlog:class+load   │
│      └ 失败9分类          每对证据入账, 穷尽语义 ds 验收        │
│                                                              │
│  ⑤ poc_gen.py          链→武器化 PoC（默认产出）              │
│      ├ derive_chains    从挖掘产物自动派生链清单              │
│      ├ make_bridge      字段类型感知装配(Object/接口Proxy)    │
│      └ R42 完整性循环    尾巴候选迭代至 RCE_DEMO_FIRED         │
└──────────────────────────────────────────────────────────────┘

┌─────────────────── 基础设施 ───────────────────┐
│ chroma_store.py  RAG（collection 按语料指纹分域）│
│ llm.py           双模型: glm(编排/辩护) × ds(对抗审计/验收) │
│ scope.py         语料分域工具（状态/审计/PoC 全隔离）│
│ profiler.py      节点级 wall/CPU/peakRSS 采样     │
│ bcdisasm.py      纯 Python class 反汇编器        │
│ bridge_fix.py    操作数栈符号模拟（接收者桥+参数桥）│
└─────────────────────────────────────────────────┘

┌─────────────────── 质量回路（内化）──────────────┐
│ conductor.py     ds 验收门控终局, 拒收自动延长轮次 │
│ dsh_cross.py     profile+发现 → 优化优先级         │
│ dsh_final.py     终验（声明≠证据 标准）            │
│ evidence_r52.py  测量证据采集                      │
└─────────────────────────────────────────────────┘
```

## 关键设计裁决（历史沉淀的原因）

| 裁决 | 原因 |
|---|---|
| 图指纹门控实时重建 | 图必须对应当前语料（防陈旧图污染） |
| hop2 可达性判定 | 标记物唯一可达路径=载体→桥→接收者→字段；无异常≠无链 |
| 双载体+equals载体 | BAVE 只触发 toString(JDK≤11)；hashCode/equals 桥需要 HashMap 族 |
| 字段契约合成 | 空状态 NPE 是 90% 假阴性根源（carrier_fail 6926→清零） |
| 发现者≠验证者 | ds 审计与 glm 辩护分离, 翻供阈值抗 LLM 非确定性 |
| 语料分域(scope.py) | 跨语料状态污染是实测事故（apache2026 实验暴露） |
| 声明≠证据 | dsh 终验标准: 每项修复须有测量证据 |

## 目录

```
jgd_v0/
├── audit_target.py      # 产品入口
├── run_agents.sh        # 研究入口(conductor)
├── *.py                 # 25 存活模块(见上图)
├── *_state*.json        # 运行状态(语料分域, 断点续跑)
├── pocs/<fp8>/          # PoC 产物(载荷/报告/验收)
├── audit_report/        # 审计报告
└── archive/             # 历史版本归档(code/logs/docs, 只读)
```
