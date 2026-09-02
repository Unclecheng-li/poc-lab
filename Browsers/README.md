# Browsers 漏洞集合

> 浏览器（Chrome / Firefox / Chromium 系）漏洞集中收纳目录。多为渲染进程内存破坏，需配合沙箱逃逸链使用。

| 目录 | 漏洞 / 浏览器 | 类型 | 严重度 |
|------|--------------|------|--------|
| [CVE-2026-2441 Chrome CSSFontFeatureValuesMap UAF](CVE-2026-2441%20Chrome%20CSSFontFeatureValuesMap%20UAF/README.md) | Chrome / Chromium：迭代器持 HashMap 悬垂指针 → 渲染进程 UAF（已在野利用，可接沙箱逃逸） | 渲染进程 UAF | CVSS 8.8 |
| [CVE-2026-10702 IonStack Firefox JIT](CVE-2026-10702%20IonStack%20Firefox%20JIT/README.md) | Firefox（Android / 桌面）：IonStack JIT 类型混淆 → RCE（攻击链第 1 环，配 `Linux Kernel` 的 GhostLock 逃逸） | JIT 类型混淆 | CVSS 4.3 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
