"""Shared utilities for php2shell exploits."""
import socket
import ssl


def connect(host, port, tls=False, timeout=15):
    """Create a TCP connection, optionally wrapped with TLS."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def send_raw(host, port, data, tls=False, timeout=15):
    """Send raw bytes and return the full response."""
    s = connect(host, port, tls=tls, timeout=timeout)
    s.sendall(data)
    s.settimeout(timeout)
    resp = b""
    while True:
        try:
            d = s.recv(65536)
            if not d:
                break
            resp += d
        except (socket.timeout, ConnectionResetError, ssl.SSLError):
            break
    s.close()
    return resp


def parse_target(target):
    """Parse a URL like http://host:port or https://host into (host, port, tls)."""
    from urllib.parse import urlparse
    u = urlparse(target)
    tls = u.scheme == "https"
    host = u.hostname
    port = u.port or (443 if tls else 80)
    return host, port, tls
