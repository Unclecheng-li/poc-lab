# QVD-2026-52631 — DeepSeek Harness 配置加载任意代码执行

> 系列归属：**DeepSeek Harness（DSH）** 上线 11 天内被奇安信披露的 5 个漏洞之一（开源当天 4 个中的第 1 个）。

## 漏洞速览

| 项 | 内容 |
|---|---|
| 漏洞编号 | **QVD-2026-52631**（奇安信 CERT 验证，暂无 CVE） |
| 产品 | DeepSeek Harness（`deepseek-ai/deepseek-harness`） |
| 漏洞类型 | 配置文件加载期任意代码执行（YAML `!!js` 表达式求值） |
| 危害等级 | **CVSS 7.8（高危）** |
| 影响版本 | v0.1 开发者预览版（PoC 验证于 0.1.0-rc.5） |
| 披露时间 | 2026-08-13（奇安信 CERT） |
| 利用条件 | 加载一份含恶意 `!!js` 的配置（无认证、无用户交互） |

## 受影响范围

- 所有加载外部/不可信 `cordis.yml`、`cordis.patch.yml` 的 DeepSeek Harness 部署。
- 特别地，“自修改 / self-modification” 部署（官方 demo `cordis` 即此场景）、把 `workspaceRoot` 指向 home、或把 profile 目录放进工作区的配置，链条会静默闭合，可被用于持久化后门。

## 根因分析

DSH 的 Cordis 配置系统支持 `!!js` 标签。Loader 在**挂载每个配置行**时通过 `internal/config` 瀑布流对值做插值（`vendor/loader/src/index.ts:92-101`），其核心是：

```ts
// vendor/loader/src/config/utils.ts:5-9
evaluate = new Function('ctx', 'expr', 'with (ctx) { return eval(expr) }')
```

表达式在 `with(ctx)` 作用域链内被直接 `eval`，而 `process` 在 `ctx` 上查不到时，会沿作用域链落到 **Node.js 全局对象**。仓库 `engines` 范围为 `^22.19 || >=24`，而 **Node 22.3+ 提供 `process.getBuiltinModule()`**，可同步取得任意内建模块——无需 `import`/`require`。于是：

> 一条 `!!js` 配置 = 一段**加载期的、同步的、任意代码执行**，且执行时机极早——沙箱与审批都还没初始化，任何防护都不生效。

更危险的是：
- `PROFILE_PATCH_TEMPLATE` 的注释主动告诉用户 “`!!js expressions allowed`”（`app-boot/src/profile.ts:127-131`）；
- `app-boot` 用 HMR 监听 patch 文件（`app-boot/src/index.ts:213`）——**写入即执行，每次 boot 重放**，可直接做持久化后门。

## 利用机制

1. 攻击者将恶意 `!!js` 藏入配置文件（如诱导受害者“从网上抄一份别人分享的配置直接加载”）。
2. DSH 启动时配置加载即执行该代码，以 harness 进程权限运行任意逻辑（读写文件、反弹 shell、植入后门）。
3. 在 self-modification 部署下，patch 文件被 HMR 反复重放 → 持久化后门。

## PoC 分析

`exploit/poc-v1-js-config-exec.ts`（来自 `zzszmyf/dsh-security-pocs`）走**真实 Loader 挂载路径**触发：

```ts
const payload = `process.getBuiltinModule('node:fs').writeFileSync(${JSON.stringify(marker)}, 'executed-at-config-load')`
await ctx.loader.create({
  name: '@deepseek-ai/cordis-plugin-timer',
  config: { probe: { __jsExpr: payload } },   // 任意 cordis.yml 行都可携带 __jsExpr
})
// => [V1] marker written at config-load time: true
```

它证明了“配置加载那一刻就已执行任意代码”，且唯一防线是沙箱写边界（默认 `workspace-write` = workspace root + 主机临时目录），而没有任何 boot 期检查保证“已加载配置目录 ∉ 可写 root”。

## 复现步骤

前置：DeepSeek Harness 源码 checkout + Node ≥ 22.3 + pnpm。

```sh
git clone https://github.com/deepseek-ai/deepseek-harness.git
cd deepseek-harness && pnpm install
# 将 dsh-security-pocs 作为兄弟目录，或设置 DSH_CHECKOUT
DSH_CHECKOUT=/path/to/deepseek-harness pnpm exec tsx /path/to/dsh-security-pocs/poc-v1-js-config-exec.ts
```

预期输出：`[V1] marker written at config-load time: true` / `[V1] marker content: "executed-at-config-load"`。

## 修复方案

- 截至披露，官方未见明确安全补丁（rc.7/rc.8/0.1.1 更新说明多为加功能或崩溃修复）。
- 防御建议：不要加载来源不明的配置；将 profile 目录移出可写 root；boot 期校验“已加载配置目录 ∉ 可写 roots，重叠即失败”（官方 P2 建议）。

## 检测排查

- 检查 `~/.dsh/` 下 profile 目录是否出现可疑 `cordis.patch.yml` 改动（尤其是含 `!!js` 的行）。
- 审查会话日志中是否有模型执行了非预期的工具调用。

## 时间线

- 2026-08-13：奇安信 CERT 披露并验证（QAX Verified），PoC 公开、技术细节公开。
- 2026-08-17：安天发布漏洞风险提示，确认影响 v0.1 开发者预览版。
- 2026-08-20：官方发布 v0.1.0-rc.8。

## 参考资料

- 奇安信 CERT 披露（2026-08-13，QVD-2026-52631）
- PoC 仓库：https://github.com/zzszmyf/dsh-security-pocs （`poc-v1-js-config-exec.ts`）
- 分析长文：《插件、沙箱与一个总钥匙：DeepSeek Harness 四个安全漏洞的发现与利用实录》

## 免责声明

本资料仅供授权安全研究与防御目的。请勿对已不拥有的系统运行相关 PoC。
