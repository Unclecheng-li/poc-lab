#!/usr/bin/env python3
"""Simple HTTP backend with configurable delay via X-Delay header."""
import http.server
import time
import socketserver

class BackendHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'backend ok\n')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        delay = float(self.headers.get('X-Delay', '5'))
        time.sleep(delay)
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'backend ok\n')

    def log_message(self, format, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", 19323), BackendHandler) as httpd:
    print("Backend on :19323")
    httpd.serve_forever()
