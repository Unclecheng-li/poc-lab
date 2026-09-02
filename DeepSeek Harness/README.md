# DeepSeek Harness (DSH) 漏洞集合

> 本目录收录 **DeepSeek Harness（DSH）** 相关的全部漏洞复现与 PoC。
> DSH 是 DeepSeek 开源的 AI Agent 运行时框架（"万物皆插件"，基于 Cordis 插件体系，TypeScript 实现，约 2026-08-13 开源），Agent = Model + Harness，Web UI 默认监听 `127.0.0.1:3080`。
> 2026 年 8 月，DSH 在 11 天内集中披露 5 个 QVD 漏洞（含 1 个 CVSS 10.0 与 1 个 9.8 的未授权 RCE）；另有 1 个无 CVE 编号的 macOS 本地提权（DesktopServicesHelper 组件名同为 DSH）一并归入本集合。

## 漏洞总览

| 目录 | 漏洞 | 类型 | 严重度 | PoC |
|------|------|------|--------|-----|
| [QVD-2026-52631 DeepSeek Harness Config Load RCE](QVD-2026-52631%20DeepSeek%20Harness%20Config%20Load%20RCE/README.md) | 配置加载任意代码执行 | YAML `!!js` 表达式执行 | CVSS 7.8 | `poc-v1-js-config-exec.ts` |
| [QVD-2026-52632 DeepSeek Harness ReadOnly Sandbox Leak](QVD-2026-52632%20DeepSeek%20Harness%20ReadOnly%20Sandbox%20Leak/README.md) | 只读沙箱信息泄露 | 读栅栏只包写不包读，`inject:['fs','web']` 零审批读密钥 | CVSS 7.5 | `poc-v2-readonly-reads.ts` |
| [QVD-2026-52644 DeepSeek Harness VM Sandbox Escape](QVD-2026-52644%20DeepSeek%20Harness%20VM%20Sandbox%20Escape/README.md) | 动态插件 VM 沙箱逃逸 | `execute(args,exec)` 把宿主 `exec` 透传进 vm realm | 高危 | `poc-v4-exec-escape.ts` |
| [QVD-2026-52646 DeepSeek Harness Chained Sandbox Escape RCE](QVD-2026-52646%20DeepSeek%20Harness%20Chained%20Sandbox%20Escape%20RCE/README.md) | 链式沙箱逃逸 → RCE | exec 逃逸后 `subprocess.spawn()` 起无约束宿主进程 | CVSS 10.0 | `poc-v4b-exec-escape-to-rce.ts` |
| [QVD-2026-57410 DeepSeek Harness Host Header Unauth RCE](QVD-2026-57410%20DeepSeek%20Harness%20Host%20Header%20Unauth%20RCE/README.md) | 未授权 RCE（Host 头伪造） | 管理 RPC 信任 `Host: localhost` 字面量、无真实 remoteAddress 校验/无鉴权 | CVSS 9.8 | `dsh2shell.py` |
| [macOS_DSH_LPE](macOS_DSH_LPE/README.md) | macOS 本地提权 (LPE) | DesktopServicesHelper chown 原语 + `auth.db` 劫持 | 高危（无 CVE） | `lpe.sh` |

## 时间线速览

- **2026-07-18** — `macOS_DSH_LPE` 由 Lyutoon 自主 Agent 端到端发现并报告 Apple（Apple 拒发 CVE）。
- **2026-08-13 前后** — DeepSeek Harness 开源。
- **披露首日（约 2026-08-13）** — 奇安信 CERT 一口气披露 4 个 QVD：`52631` / `52632` / `52644` / `52646`。
- **2026-08-24** — 第 5 个 QVD `57410`（CVSS 9.8 未授权 RCE）披露。

## 利用链递进关系

```
配置加载 RCE (52631, 7.8)          ← 静态配置即可触发
   │
只读沙箱泄露 (52632, 7.5)          ← 沙箱读栅栏缺陷，零审批读密钥
   │
VM 沙箱逃逸 (52644, 高危)          ← 动态插件把宿主 exec 透传进 vm realm
   │
链式沙箱逃逸 RCE (52646, 10.0)     ← exec 逃逸 → subprocess.spawn 起无约束宿主进程
   │
未授权 RCE (57410, 9.8)            ← 无需任何前置，伪造 Host 头直打管理 RPC
```

## PoC 来源

- `QVD-2026-52631 / 52632 / 52644 / 52646`：<https://github.com/zzszmyf/dsh-security-pocs>（`.ts`，需 DSH 源码 checkout + Node ≥ 22.3 + pnpm + `tsx`）。
- `QVD-2026-57410`：<https://github.com/ChaoMixian/dsh2shell>（Python3 标准库，`dsh2shell.py` 独立可用）。
- `macOS_DSH_LPE`：<https://github.com/Lyutoon/macOS_DSH_LPE>（`lpe.sh` 自包含）。

## 免责声明

本目录内容仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
