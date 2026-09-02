<div align="center">

<h1>poc-lab</h1>

<p><strong>近期高危漏洞 PoC 复现实验室</strong> — Linux 内核 · KVM · Web 应用 · 数据库 · 浏览器 · AI 基础设施</p>

<p>每个漏洞一条可复现链：根因 → PoC → 修复。</p>

<p>
  <a href="https://github.com/Unclecheng-li/poc-lab/stargazers"><img src="https://img.shields.io/github/stars/Unclecheng-li/poc-lab?style=social" alt="Stars"></a>
  <a href="https://github.com/Unclecheng-li/poc-lab/forks"><img src="https://img.shields.io/github/forks/Unclecheng-li/poc-lab?style=social" alt="Forks"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Unclecheng-li/poc-lab?color=blue" alt="License"></a>
  <img src="https://img.shields.io/badge/PoCs-32-2ea44f" alt="PoCs">
  <img src="https://img.shields.io/badge/Linux%20Kernel-LPE%20Series-CC0000" alt="Linux Kernel LPE Series">
</p>

**English version**: [`README_EN.md`](README_EN.md)

</div>

---

> ## 快速上手
>
> ```bash
> git clone https://github.com/Unclecheng-li/poc-lab.git && cd poc-lab
> cd "Linux Kernel"                 # 选一个分类
> cat "CVE-2026-31431 Copy Fail"/README.md   # 先读复现指南
> python3 "CVE-2026-31431 Copy Fail"/exploit/exp.py   # 再跑 PoC
> ```

---

## poc-lab 是什么？

一个按**主题分类**收纳高危漏洞 PoC 的复现仓库。每个 CVE 来自安全公告与公开披露（NVD / 厂商公告 / 奇安信 QVD 等），入库自带完整中文分析：根因、利用链、PoC 与修复，方便快速复现、代码审计与二次研究。

### 目录结构

```
poc-lab/
├── DeepSeek Harness/            # DSH AI Agent 框架系列 (6)
├── Linux Kernel/                # Linux 内核 (14)
│   ├── 脏牛系 · 页缓存污染提权   # CopyFail / DirtyFrag / DirtyCBC / ...
│   ├── 独立 LPE · 堆利用         # PinTheft / GhostLock / CIFSwitch / ...
│   └── KVM 虚拟化逃逸           # Januscape / Zapscape
├── Web Applications/            # Web 面板 / CMS / 应用 (3)
├── Databases/                   # 数据库 / KV 存储 (2)
├── Web Servers & Protocols/     # Web 服务器与网络协议 (2)
├── Browsers/                    # Chrome / Firefox 浏览器 (2)
├── AI Infrastructure/           # AI 基础设施 (1)
├── Desktop & Client Apps/       # 桌面 / 客户端应用与媒体库 (2)
│
└── 单个漏洞目录/                 # 见下方「标准布局」
    ├── README.md
    ├── exploit/
    ├── build/
    └── env/
```

### 分类索引

| 分类 | 数量 | 内容 |
|------|-----:|------|
| [`DeepSeek Harness/`](./DeepSeek%20Harness/README.md) | 6 | DeepSeek Harness（AI Agent 框架）系列：配置加载 RCE / 只读沙箱泄露 / VM 沙箱逃逸 / 链式逃逸 RCE / Host 头未授权 RCE / macOS LPE |
| [`Linux Kernel/`](./Linux%20Kernel/README.md) | 14 | 脏牛系页缓存污染提权（CopyFail / Dirty Frag / DirtyCBC / DirtyDecrypt / Fragnesia / act_pedit）、独立 LPE / 堆利用（Slab Cross-Cache / PinTheft / GhostLock / CIFSwitch / SSH Keysign）、KVM 逃逸（Januscape / Zapscape） |
| [`Web Applications/`](./Web%20Applications/README.md) | 3 | cPanel2Shell / Nezha Monitoring / wp2shell（WordPress） |
| [`Databases/`](./Databases/README.md) | 2 | Redis RESTORE RCE / Valkey RESP DoS |
| [`Web Servers & Protocols/`](./Web%20Servers%20%26%20Protocols/README.md) | 2 | NGINX Rift / HTTP2 Bomb |
| [`Browsers/`](./Browsers/README.md) | 2 | Chrome CSSFontFeatureValuesMap UAF / Firefox IonStack JIT |
| [`AI Infrastructure/`](./AI%20Infrastructure/README.md) | 1 | LiteLLM 授权链提权 |
| [`Desktop & Client Apps/`](./Desktop%20%26%20Client%20Apps/README.md) | 2 | Notepad++ RCE / PixelSmash（FFmpeg MagicYUV） |

## 每个漏洞目录的标准布局

仓库遵循统一的「CopyFail 模板」——每个 CVE 一个目录，结构一致：

| 文件 / 目录 | 用途 |
|------------|------|
| `README.md` | 11 节完整分析：漏洞速览 / 受影响范围 / 根因分析 / 利用机制 / PoC 分析 / 复现步骤 / 修复方案 / 检测排查 / 时间线 / 参考资料 / 免责声明 |
| `exploit/` | PoC 脚本（`exp.py` / `exp.c` / `exp.html` / `lpe.sh` …） |
| `build/` | 内核类漏洞的编译产物 |
| `env/` | Web 类漏洞的 `docker-compose.yml` 复现环境 |

## 新增漏洞

新披露的 CVE 落库遵循固定流程：

1. 按 CopyFail 模板新建 `<CVE-编号 名称>/` 目录；
2. 写 `README.md`（上述 11 节）+ `exploit/` PoC（尽量附一手来源链接）；
3. 推送远端 `main`。

## 相关项目

- [VulnClaw](https://github.com/Unclecheng-li/VulnClaw) — AI 驱动的渗透测试框架
- [DeepSec](https://github.com/Unclecheng-li/DeepSec) — AI 安全攻防一体平台（Shield 代码审计 + Spear 授权渗透测试）

## 免责声明

本仓库仅用于**安全研究与教育目的**。

- 请勿对不属于你、或未经明确授权测试的任意系统运行这些 PoC。
- 作者对滥用行为不承担任何法律责任。
- 请始终遵循负责任的披露规范。

## License

MIT
