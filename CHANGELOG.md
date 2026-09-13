# Changelog（设计裁决编号史 R6-R52）

历史轮次的全部修复与裁决, 按主题归组。编号保留可追溯性; 详细上下文见
git-less 档案 `archive/docs/` 与各模块内的行级注释。

## 检测语义
- **R6** 桥检测接收者感知（操作数栈模拟）; open_fields 修正（final 可写, 排 static+transient）
- **R13** 参数桥: 字段作为参数流入静态助手也算桥（修复 antlr4 Pair 漏检）
- **R16** 图补 CHA 分派边（接口→实现）, 反向可达不再断在多态边界
- **R47** 反射 API 节点进 sink 种子; equals 载体(HASHMAP_EQ); 类型化 canary(URL/URI); 深度4链延伸; -Xlog:class+load 观测

## 观测与判定
- **R17→R18** hop2 可达性判定修正（把异常栈帧当必要条件是回归, 18 对完整链被误判）
- **R21** 标记物调用者栈（dispatch_stack 直接证据）; DEPTH2 接收者进化为桥(链延伸)
- **R29** 标记物记录自身调用者栈（不依赖异常）
- **R31** 字段契约合成（survival(): carrier_fail 90% 根治）
- **R42** PoC 完整性循环: 尾巴候选迭代至 RCE_DEMO_FIRED（agent 默认产出）
- **R44** payload 静态块自打印全链栈

## 载体与环境
- **R8** BAVE 载体 JDK≤11 约束（17 起 val 收窄 String）
- **R23** HashMap 载体（hashCode 触发, 跨 JDK）
- **R27/R28** 按桥类版本选 JDK; 单对复跑同规则（ObjLongPair 事故）
- **R30** 最小 classpath + NCDFE 回退

## 性能
- **R24/R25/R26** 批处理+并行+dispatch 池缓存+最小CP（合计 12×: 126→1500 对/9min）
- **R33/R34** 每批落盘; 审计回填
- **R50(F9)** 审计 8 线程并行 + md5 缓存
- **R51(D5)** PoC 链间 3 并行（54.4s→20.3s, 2.7×, dsh 采信）
- **R52** -Xmx256m（OOM=0, 单JVM 184MB 余量28%）; sha1 取数校验 3/3

## 正确性与工程
- **R10** 图指纹门控（语料变更实时重建）
- **R12** 链审计合并+翻供阈值（抗 ds 非确定性）
- **R14/R15** verdict 残留清除; ds 验收门控终局
- **R49** 状态按语料指纹隔离（apache2026 跨语料污染事故）
- **R50(D3)** 全产物分域(scope.py): jgd_chain_audit/evolve/jgd_entry_audit/pocs/RAG
- **R51(D1/D2/D4)** 账本每批增量; 缓存键统一; JDK-only 链运行时在场

## 产品化
- **R40** --target 任意 jar; 产品自有 sink 发现; 尾巴自动选型; JEP290 姿态
- **R45** 链清单自动派生（derive_chains）+ make_bridge 字段类型感知泛化
- **R50** 一次性终局入口（零中间决策, rc 收敛 0）
- **R52** 终验标准: 声明≠证据（四轮对抗至 PASS）

## 已知边界（登记, 非阻断）
- JVMPOOL: 常驻池未实现（缓解=链间并行 2.7×, 有回归数据）
- 并发8 需主机内存实测（当前并发5×256m 预估安全）
- env_blocked 80 对（antlr3 runtime 缺失）: 目标环境补齐需重跑
- 非 CHA 可见接收者/非插桩观测: 声明域边界（终局报告显式声明）
