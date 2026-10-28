# Security Policy / 安全策略

## 适用边界（Authorized Use Only）

JGD 是**防御性安全研究工具**：用于在自有/授权代码库上发现反序列化
gadget 链，先于攻击者完成修复评估。

**禁止**将本工具用于：
- 未经书面授权的目标系统
- 实际入侵、数据窃取、破坏
- 武器化用途（生成的 PoC 均为良性演示：payload 仅写标记文件）

## 负责任披露（Responsible Disclosure）

通过本工具发现新链/漏洞时：
1. 先向受影响供应商安全邮箱披露（给 90 天修复窗口）
2. 未经许可不得公开未修复细节
3. 里程碑类发现建议同步 CVE/编号机构

## 报告安全问题

对本工具自身的安全issue（如注入、路径穿越）：开 private security advisory。

## 工具内置防护（2026-10 hardening）

- Plan 1 静态扫描器不执行目标代码：`SafeJar` 只读校验，`bcdisasm` 只解析字节码。
- 动态探针通过 `jgd.security.sandbox`；`HostSandbox` 需要显式 `--unsafe-host`，仅用于可信 lab 语料；生产使用 Docker/WSL2。WSL 功能已启用但需要重启后生效。
- A2A 支持 Bearer token（`--token`）；MCP stdio 只继承本地信任；任务只启动 JGD run，不执行任意命令。
- PoC 策略默认开启，但硬化 CLI 尚未接入沙箱化 PoC 执行；旧 `poc_gen` 仍是研究路径，不在默认 CLI 调用。任何 PoC 只允许良性 marker。
- LLM 默认开启但只做 advisory；生产路径的 LLM 把关（`ds_acceptance`/`accepted`）已删除。
- 详细威胁模型与测试映射见 [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)。


