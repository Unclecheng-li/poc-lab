# Databases 漏洞集合

> 数据库 / KV 存储相关漏洞集中收纳目录。

| 目录 | 漏洞 / 产品 | 类型 | 严重度 |
|------|------------|------|--------|
| [CVE-2026-25243 Redis RESTORE RCE](CVE-2026-25243%20Invalid%20Memory%20Access%20in%20Redis%20RESTORE%20Command%20May%20Lead%20to%20Remote%20Code%20Execution/README.md) | Redis / Valkey：`RESTORE` 反序列化 zipmap 长度前缀步长不一致 → 堆越界（需认证，理论可 RCE） | 反序列化堆越界 | CVSS 7.7 |
| [CVE-2026-27623 Valkey RESP DoS](CVE-2026-27623%20Pre-Authentication%20DOS%20from%20malformed%20RESP%20request/README.md) | Valkey：畸形 RESP 请求（`*0\r\nPING`）触发断言 → 预认证进程崩溃 | Pre-auth DoS | CVSS 7.5 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
