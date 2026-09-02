# Web Servers & Protocols 漏洞集合

> Web 服务器与网络协议层漏洞集中收纳目录（基础设施层）。Web 应用 / 面板 / CMS 漏洞见 `Web Applications`。

| 目录 | 漏洞 / 产品 | 类型 | 严重度 |
|------|------------|------|--------|
| [CVE-2026-42945 NGINX Rift](CVE-2026-42945%20NGINX%20Rift/README.md) | NGINX rewrite 模块：分配按原文长度 / 复制按转义展开 → 远程堆溢出 | 堆溢出 DoS / RCE | 官方 medium（第三方 9.2） |
| [CVE-2026-49975 HTTP2 Bomb](CVE-2026-49975%20HTTP2%20Bomb/README.md) | HTTP/2 协议：HPACK 索引放大 + `WINDOW_UPDATE` 停滞 → 多服务器（nginx / Apache / IIS / Envoy / Pingora）DoS | 协议级 DoS | 无 CVSS |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
