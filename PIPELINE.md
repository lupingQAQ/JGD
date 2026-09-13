# JGD Agent 挖掘流水线（R7-R21 修订后实际形态）

## 运行流水线

```
run_agents.sh                      唯一入口: 重试循环, 直到 ds-accepted 终局
└─ conductor.py                    调度 + 继续/终止判定 (状态驱动, 可断点续跑)
   │
   ├─[1] verify_agent.py           验证回路
   │    ├ fixed_scan               bcdisasm+bridge_fix: 接收者桥(R6)+参数桥(R13)
   │    ├ local_grade              字段类型分级(INTERESTING/TRIVIAL) + 公开链语料比对
   │    ├ enrich_with_hierarchy    抽象类→具体可序列化子类搜索(R7, 带缓存+预算)
   │    ├ dynamic_verify           多JDK探针(抽象候选改探子类, FAIL/ERROR 分账)
   │    ├ ds_cross_audit           verifier 对抗审计(发现者≠验证者)
   │    ├ glm_defense              ds 否决时 glm 辩护, 分歧→DISPUTED
   │    └ persist                  RAG(chroma) + verify_state.json
   │
   ├─[2] evolve_v2.py              挖掘回路
   │    ├ build_candidate_pool     5源: 调用图≤3跳 / RAG / novel_paths /
   │    │                          jar_scan / verify审计存活者(DISPUTED=-9优先)
   │    ├ probe_batch (PV)         注入探针: final可写(R7)+接口Proxy分派(R7)+
   │    │                          抽象Unsafe分配(R7) → FIELD_FORWARD
   │    ├ assemble_chain (CV)      BAVE链PoC, JDK11(BAVE.val在17已收窄String)
   │    ├ retry_chains             修复后免重探复验
   │    └ RAG + evolve_v2_state.json
   │
   ├─[3] verify_agent --audit-chains  链发现回灌 ds 审计
   │    └ 合并+翻供阈值(R12): 单轮翻供不推翻 CONFIRM(抗ds非确定性)
   │
   └─[4] chain_complete.py         链完成/穷尽回路
        ├ ensure_graph             语料指纹校验, 不符实时重建(R10, 990K节点)
        ├ add_dispatch_edges       CHA分派边(接口→实现, R16)
        ├ load_bridges             桥池 = CONFIRM ∪ 链PoC TRIGGERED ∪ verify存活者
        │                          ∪ 全部INTERESTING(R20) ∪ DEPTH2接收者链延伸(R21)
        ├ scan_receivers           sink种子(430方法节点)+反向≤3跳(含CHA)+具体可序列化
        ├ run_full_chain (CC)      BAVE→桥→接收者:
        │                          hop2标记物(唯一可达路径论证R18) + 写侧清除
        │                          + String canary值流(R21) + 异常栈帧佐证
        │                          + 接收者钩子审计(R19) + 失败9分类(R17)
        ├ audit_chain              DEPTH2/SINK/VALUE_FLOW/HOP1 → ds 审计定级
        ├ reclassify               判定语义修正后重判存量(R18)
        ├ reflect_with_ds          联合反思: 可达性漏洞/盲区/下一步
        └ jgd_chain_state.json
           终局: conductor._ds_acceptance — ds 拒收 → 延长轮次继续挖(R15)

状态/知识底座:
  RAG(chroma_store)     全部结论沉淀, 候选池来源2消费
  verify_state.json / evolve_v2_state.json / jgd_chain_state.json
  jgd_graph_live.db (指纹门控 + CHA边)
```

## 整体反思：流程与思路的演化

**架构层(用户三次纠正后定型)**：验证/挖掘逻辑全部在 agent 内，主循环只启动+汇报。
曾犯：修正检测器、交叉验证、抽象类诊断都先写成了主循环临时脚本。

**检测层**：方法名白名单(R6前, 大量假阳) → 操作数栈模拟接收者桥(R6) →
参数进静态助手也算桥(R13, 修复 antlr4 Pair 漏检)。open_fields 从"排除final"
(方向反了)改为排除 static+transient。

**图层**：陈旧DB直接用 → 指纹门控+实时重建(R10, 用户裁决"图必须实时构造") →
CHA 分派边(R16) —— 无分派边的反向可达在多态边界系统性断裂，而反序列化链
的本质就是接口分派。

**观测层(教训最深)**：标记物4方法 → +异常栈帧(R17, **回归**：把证据当必要
条件，18对完整链被判 NOT_FIRED —— 与4月错链同构) → hop2 可达性论证+写侧
清除(R18) + String canary 值流(R21)。教训：**观测升级不能改变判定语义的
充分条件集，只能增加证据种类**。

**判定纪律**：verdict 残留导致零尝试事故(R14)、污染数据归档重跑、ds 验收
门控终局(R15)、审计非确定性翻供阈值(R12)。教训：**终局判定必须被对抗审计
接受才有效，且数字口径要能自证**。

**当前瓶颈(ds 联合反思结论)**：no_dispatch 占绝对多数 → 入口命中率是瓶颈,
不是链构造; 值可达性(sink参数)与链延伸(深度3+)是 R21 正在补的面。

## 结果现状

- 36 条 CHAIN_DEPTH2(机制完整链, 读侧复验+无自赋值钩子), ds 全判非新颖
  (MutableObj/Pair→ROME 家族 = 已知范式变体)
- 配对覆盖 1509+/~1900, HOP1 5条(链延伸产生), VALUE_FLOW 层刚上线
- 用户裁决: 存在至少一条未公开新链 —— 循环不终局, 继续挖
