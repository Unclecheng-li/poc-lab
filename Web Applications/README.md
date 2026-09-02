# Web Applications 漏洞集合

> Web 应用 / 管理面板 / CMS 相关漏洞集中收纳目录（服务端应用层）。Web 服务器与协议层漏洞见 `Web Servers & Protocols`。

| 目录 | 漏洞 / 产品 | 类型 | 严重度 |
|------|------------|------|--------|
| [CVE-2026-29205 cPanel2Shell-Scanner](CVE-2026-29205%20cPanel2Shell-Scanner/README.md) | cPanel / WHM `cpdavd`：CalDAV 附件路径穿越 → 预认证 root 任意文件读（`/etc/shadow`） | 路径穿越 + root 任意读 | 无 CVSS |
| [CVE-2026-53519 Nezha Monitoring](CVE-2026-53519%20Nezha%20Monitoring/README.md) | 哪吒监控 dashboard：前缀误配路径遍历 + JWT 伪造 → 接管面板 | 路径遍历 + 认证绕过 | CVSS 9.1 |
| [CVE-2026-63030 wp2shell](CVE-2026-63030%20wp2shell/README.md) | WordPress：批处理路由错位 × SQLi × changeset 借权 → 预认证 RCE（建管理员） | Pre-auth RCE | CVSS 9.8 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
