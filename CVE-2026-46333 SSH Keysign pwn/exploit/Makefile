CFLAGS ?= -O2 -Wall

ALL = sshkeysign_pwn chage_pwn vuln_target exploit_vuln_target

all: $(ALL)

sshkeysign_pwn: sshkeysign_pwn.c
	$(CC) $(CFLAGS) -o $@ $<

chage_pwn: chage_pwn.c
	$(CC) $(CFLAGS) -o $@ $<

vuln_target: vuln_target.c
	$(CC) $(CFLAGS) -o $@ $<

exploit_vuln_target: exploit_vuln_target.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(ALL)

.PHONY: all clean
