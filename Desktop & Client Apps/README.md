# Desktop & Client Apps 漏洞集合

> 桌面 / 客户端应用与媒体库漏洞集中收纳目录。

| 目录 | 漏洞 / 产品 | 类型 | 严重度 |
|------|------------|------|--------|
| [CVE-2026-48778 Notepad++ RCE](CVE-2026-48778%20Notepad%2B%2B%20RCE/README.md) | Notepad++（Windows）：`config.xml` 污染解释器路径 → 命令注入 / 任意执行（需用户操作触发） | 配置注入 RCE | CVSS 7.8 |
| [CVE-2026-8461 PixelSmash](CVE-2026-8461%20PixelSmash/README.md) | FFmpeg（跨平台）：MagicYUV 解码器色度平面高度舍入不一致 → 堆越界写（可升 RCE） | 解码器堆越界写 | CVSS 8.8 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
