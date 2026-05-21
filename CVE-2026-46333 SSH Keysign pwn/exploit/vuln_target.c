/* Setuid target that opens /etc/shadow before dropping. Install as
 * setuid root; exploit with exploit_vuln_target.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	int fd = open("/etc/shadow", O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }

	if (setuid(getuid()) < 0) { perror("setuid"); return 1; }

	if (argc > 1 && !strcmp(argv[1], "exit-now"))
		return 0;
	pause();
	return 0;
}
