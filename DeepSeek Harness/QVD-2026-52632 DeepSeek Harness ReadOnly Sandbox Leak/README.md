# QVD-2026-52632 — DeepSeek Harness 只读沙箱信息泄露

> 系列归属：**DeepSeek Harness（DSH）** 上线 11 天内被奇安信披露的 5 个漏洞之一（开源当天 4 个中的第 2 个）。

## 漏洞速览

| 项 | 内容 |
|---|---|
| 漏洞编号 | **QVD-2026-52632**（奇安信 CERT 验证，暂无 CVE） |
| 产品 | DeepSeek Harness（`deepseek-ai/deepseek-harness`） |
| 漏洞类型 | 只读沙箱信息泄露（read-only sandbox reads entire host FS） |
| 危害等级 | **CVSS 7.5（中危/高危边界）** |
| 影响版本 | v0.1 开发者预览版（PoC 验证于 0.1.0-rc.5） |
| 披露时间 | 2026-08-13（奇安信 CERT） |
| 利用条件 | 在 read-only 模式下处理不可信仓库/内容（最常见使用场景） |

## 受影响范围

- 所有以 `read-only` 权限模式部署、让模型处理不可信仓库/代码评审/被 fetch 文档的 DSH 实例。
- 该模式被市场宣传为“安全承诺”，但实际只拦写不拦读。

## 根因分析

`read-only` 模式**只对写操作做 fence，对读操作完全不设防**：

1. 进程内 fence（`packages/fs/fs-sandbox/src/index.ts:7,91,112`）只包裹 `writeText` / `editText`，`readText` 原样继承、无任何检查；
2. 进程级 bwrap 配置为 `--ro-bind / /`（`packages/sandbox/sandbox-local/src/profiles.ts:17`）——**整个宿主文件系统以只读方式挂载进沙箱**；
3. `read-only` 模式的可写 root 是空集，但这意味着模型可以读 `~/.ssh/*`、项目 `.env`、credentials 凭据文件（credentials 系统自身用 `0600` 保护这些文件，说明威胁模型里它们就是秘密）；
4. 动态插件 `inject` 无 allowlist（`cordis-host-runner/src/lifecycle.ts:56` 唯一检查是“服务是否存在”），`inject: ['fs','web']` 即可“读 secret + 外发”，一步到位；
5. 默认组合里没有任何 host 侧插件对工具调用弹 `ask`——`tool-bash` 里还留着 `TODO(permissions)`（`tool-bash/src/index.ts:6-7`）。即“只读安全模式”下模型读凭据是**零审批**的。

## 利用机制

受害者切到 read-only 模式处理不可信项目 → AI 仍能读取工作区外的文件（SSH 私钥、环境变量里的密码/密钥等）→ 内容经 `web` 工具发往攻击者服务器。脚本演示：“读密钥成功、写文件被拦”。

## PoC 分析

`exploit/poc-v2-readonly-reads.ts`（来自 `zzszmyf/dsh-security-pocs`）启动真实的 `SandboxPolicyService` + `SandboxedFileSystem`（`read-only`），读取 workspace 外的 secret：

```ts
const secret = await fs.readText(await fs.resolve(secretPath))   // secret 在 workspace 外
// => [V2] read of a secret OUTSIDE the workspace under read-only mode: "apiKey: dsh-poc-secret-value\n"
await fs.writeText(...)  // 同模式写 => [V2] contrast — write denied with code: FS_SANDBOX_DENIED
```

对比鲜明：读穿全盘成功，写被拒——证明“只读”只防写不防读。

## 复现步骤

前置：DeepSeek Harness 源码 checkout + Node ≥ 22.3 + pnpm。

```sh
DSH_CHECKOUT=/path/to/deepseek-harness pnpm exec tsx /path/to/dsh-security-pocs/poc-v2-readonly-reads.ts
```

预期输出：`[V2] read of a secret OUTSIDE the workspace ...: "apiKey: dsh-poc-secret-value\n"` / `[V2] contrast — write ... denied with code: FS_SANDBOX_DENIED`。

## 修复方案

- 密钥/凭据不要放进 Agent 可读取的目录；
- 从 read-only 模式中排除 secret 目录（官方 P1 建议：allowlist 动态插件 inject、把 secret 目录排除出 read-only 模式）。

## 检测排查

- 检查会话日志中模型是否读取了 `~/.ssh/`、`*.env`、`credentials*` 等敏感路径；
- 监控来自 Agent 宿主的出站连接（凭据外发）。

## 时间线

- 2026-08-13：奇安信 CERT 披露并验证（QVD-2026-52632）。
- 2026-08-17：安天发布漏洞风险提示。

## 参考资料

- 奇安信 CERT 披露（2026-08-13，QVD-2026-52632）
- PoC 仓库：https://github.com/zzszmyf/dsh-security-pocs （`poc-v2-readonly-reads.ts`）
- 分析长文：《插件、沙箱与一个总钥匙：DeepSeek Harness 四个安全漏洞的发现与利用实录》

## 免责声明

本资料仅供授权安全研究与防御目的。请勿对已不拥有的系统运行相关 PoC。
