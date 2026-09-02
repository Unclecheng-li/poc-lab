# CVE-2026-46331 -- net/sched act_pedit partial-COW page-cache corruption.
#
#   make                 build both binaries
#   make test_cve        the api_fd_write() primitive + 10-call testcase
#   make packet_edit_meme  the unprivileged-user -> root exploit
#   make clean           remove binaries
#
# Static x86_64 binaries; override CC / CFLAGS to retarget. Both link
# pedit_primitive.c. test_cve overwrites an O_RDONLY /tmp file via the page cache
# (expects 10/10). packet_edit_meme must be launched as an unprivileged user (it
# refuses root) and overwrites the cached ELF entry of setuid-root su -> root shell.

ifeq ($(origin CC),default)
CC := x86_64-linux-gnu-gcc
endif
CFLAGS ?= -O2 -Wall -static

BINS = test_cve packet_edit_meme

all: $(BINS)

test_cve: test_cve.c pedit_primitive.c pedit_primitive.h
	$(CC) $(CFLAGS) test_cve.c pedit_primitive.c -o $@

packet_edit_meme: packet_edit_meme.c pedit_primitive.c pedit_primitive.h
	$(CC) $(CFLAGS) packet_edit_meme.c pedit_primitive.c -o $@

clean:
	rm -f $(BINS)

.PHONY: all clean
