#!/usr/bin/env python3
"""Static release origin with one deliberate fault mode.

Paths under /short/ send a correct Content-Length header but only half of the
body, which is how an interrupted download is reproduced without any network
manipulation.
"""
import http.server
import os
import sys

ROOT = sys.argv[1]
PORT = int(sys.argv[2])


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.path, fmt % args))

    def do_GET(self):
        if self.path.startswith("/short/"):
            fp = os.path.join(ROOT, self.path.lstrip("/"))
            with open(fp, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(data[: len(data) // 2])
            self.wfile.flush()
            return
        super().do_GET()


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
