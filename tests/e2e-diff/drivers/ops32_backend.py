#!/usr/bin/env python3
"""OPS-32 marker backend.

Every GET is answered with the marker passed on the command line, so the
client transcript can tell which upstream peer produced the body. One line per
request is appended to the shared request log:

    <epoch>  <marker>  <request path>

Usage:
    python3 ops32_backend.py <marker> <port> <request-log>
"""

import http.server
import sys
import time

marker = sys.argv[1]
port = int(sys.argv[2])
request_log = sys.argv[3]


class Handler(http.server.BaseHTTPRequestHandler):
    # HTTP/1.0 closes the connection after every response, so a kept-alive
    # upgrade request can never leave a second request unanswered.
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = marker.encode()
        with open(request_log, "a", encoding="utf-8") as fh:
            fh.write("%.3f\t%s\t%s\n" % (time.time(), marker, self.path))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
