# AI Infrastructure 漏洞集合

> AI 基础设施（LLM 网关 / Agent 框架等）漏洞集中收纳目录。
> 注：`DeepSeek Harness/`（根目录，含 6 个 DSH 漏洞）同属此类，暂独立存放，可按需并入本目录。

| 目录 | 漏洞 / 产品 | 类型 | 严重度 |
|------|------------|------|--------|
| [CVE-2026-47101 LiteLLM](CVE-2026-47101%20LiteLLM/README.md) | LiteLLM（AI 网关）：`internal_user` 经 `/key/generate` 建通配符 key + `/user/update` 自提权 → `proxy_admin`（受影响 < 1.83.14） | 授权链失效提权 | CVSS 8.8 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
