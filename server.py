"""
bare http server to receive files from device
curl -T /dev/mtdblock0 http://$HOST:8000/mtdblock0.bin

warning: path traversal and partial reads possible; no chunk extensions support
for safer alternatives, sideload statically compiled dropbear
"""

import socket
from http.server import BaseHTTPRequestHandler, HTTPServer

TIMEOUT = 10.0
PORT = 8000
HOST = "0.0.0.0"


class StoreHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        print(f"receiving: {self.path}")
        self.connection.settimeout(TIMEOUT)
        content_length = self.headers.get("Content-Length")
        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower()

        try:
            with open(self.path.strip("/"), "wb") as f:
                if "chunked" in transfer_encoding:
                    total_decoded = 0
                    while True:
                        size_line = self.rfile.readline()
                        if not size_line:
                            break
                        try:
                            chunk_size = int(size_line.strip(), 16)
                        except ValueError:
                            print(f"invalid chunk size: {size_line}")
                            break
                        if chunk_size == 0:  # final chunk
                            break
                        chunk_data = self.rfile.read(chunk_size)
                        f.write(chunk_data)
                        total_decoded += len(chunk_data)

                        self.rfile.read(2)  # trailing \r\n
                    print(f"decoded {total_decoded} bytes from chunked encoding")
                elif content_length:
                    remaining = int(content_length)
                    while remaining > 0:
                        chunk = self.rfile.read(min(65536, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                    print(f"received {int(content_length)} bytes")
                else:  # read until EOF or timeout
                    total = 0
                    while True:
                        try:
                            chunk = self.rfile.read(65536)
                            if not chunk:
                                break
                            f.write(chunk)
                            total += len(chunk)
                        except socket.timeout:
                            print(f"watchdog: saving {self.path}")
                            break
                    print(f"received {total} bytes (no content-length)")

        except Exception as e:
            print(f"error during write: {e}")
            import traceback

            traceback.print_exc()

        try:
            self.send_response(201)
            self.end_headers()
        except Exception:
            pass

        print(f"terminated: {self.path}")


print(f"http server starting on {HOST}:{PORT}...")
HTTPServer((HOST, PORT), StoreHandler).serve_forever()
