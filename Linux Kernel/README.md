# Linux Kernel 漏洞集合

> Linux 内核相关漏洞（提权 / 逃逸 / DoS）集中收纳目录。按利用方式分为三组：**脏牛系（页缓存污染）**、**独立 LPE / 堆利用**、**KVM 虚拟化逃逸**。
> PoC 主要针对各发行版内核，复现前请核对 README 内受影响版本。

## ① 脏牛系 · 页缓存污染提权（Dirty-style）

| 目录 | 漏洞 / 根因 | 严重度 |
|------|------------|--------|
| [CVE-2026-31431 Copy Fail](CVE-2026-31431%20Copy%20Fail/README.md) | `splice` + `algif_aead`/`authencesn` 写只读页缓存 → LPE + 容器逃逸 | CVSS 7.8 |
| [CVE-2026-43284 Dirty Frag](CVE-2026-43284%20Dirty%20Frag/README.md) | xfrm-ESP：UDP splice 未标 `SKBFL_SHARED_FRAG` → 页缓存污染 LPE | CVSS 8.8 / 7.8 |
| [CVE-2026-43500 Dirty Frag](CVE-2026-43500%20Dirty%20Frag/README.md) | RxRPC/rxkad：原地解密写只读页缓存（Dirty Frag 变体） | CVSS 7.8 |
| [CVE-2026-31635 DirtyCBC](CVE-2026-31635%20DirtyCBC/README.md) | rxrpc/rxgk：`auth_len` 边界检查写反 → 页缓存污染 LPE（DoS 成因视角） | CVSS 7.5 |
| [CVE-2026-31635 DirtyDecrypt](CVE-2026-31635%20DirtyDecrypt/README.md) | rxrpc/rxgk：krb5enc 先解密后校验、无 COW（同 CVE-2026-31635，LPE 利用视角） | CVSS 7.5 |
| [CVE-2026-46300 Fragnesia](CVE-2026-46300%20Fragnesia/README.md) | ESP-in-TCP：coalesce 原地解密 → 页缓存替换 LPE | 暂无 |
| [CVE-2026-46331 act_pedit](CVE-2026-46331%20act_pedit/README.md) | net/sched：`tcf_pedit_act` COW 范围算错 → 页缓存污染 LPE | 无 CVSS |

## ② 独立 LPE / 堆利用 / 逻辑提权

| 目录 | 漏洞 / 根因 | 严重度 |
|------|------------|--------|
| [CVE-2026-31429 Slab Cross-Cache](CVE-2026-31429%20Slab%20Cross-Cache/README.md) | KFENCE 精确 ksize 致 skb head 释放错桶 → 跨缓存释放 DoS / 潜在提权 | CVSS 5.5 |
| [CVE-2026-43494 PinTheft](CVE-2026-43494%20PinTheft/README.md) | RDS zcopy double-free / 偷 pin 引用 + io_uring 悬垂页 → 页缓存覆写 LPE | 无 CVSS |
| [CVE-2026-43499 GhostLock](CVE-2026-43499%20GhostLock/README.md) | rtmutex `remove_waiter` 回滚路径错误 → 栈 UAF LPE + 容器逃逸（与 IonStack 同链） | CVSS 7.8 |
| [CVE-2026-46243 CIFSwitch](CVE-2026-46243%20CIFSwitch/README.md) | CIFS/spnego：`cifs.upcall` 来源校验缺失 → 身份混淆逻辑 LPE | CVSS 7.8 |
| [CVE-2026-46333 SSH Keysign pwn](CVE-2026-46333%20SSH%20Keysign%20pwn/README.md) | pidfd 权限检查缺陷：`pidfd_getfd` 窃 root fd（触发 ssh-keysign）→ 本地信息泄露 | 无 CVSS |

## ③ KVM 虚拟化逃逸

| 目录 | 漏洞 / 根因 | 严重度 |
|------|------------|--------|
| [CVE-2026-53359 Januscape](CVE-2026-53359%20Januscape/README.md) | KVM/x86 shadow MMU：影子页复用只比 gfn 不比 role → UAF 客逃主 + LPE | CVSS 7.5~9.3 |
| [CVE-2026-64561 Zapscape](CVE-2026-64561%20Zapscape/README.md) | KVM/x86 shadow MMU：stale 检查与 quota reclaim 顺序错 → UAF 虚拟机逃逸 | CVSS 7.0 |

## 免责声明

仅供**安全研究与授权测试**用途。请勿对未授权系统运行任何 PoC；始终遵循负责任的披露实践。
