"""lane-demo is a status page with misconfigurations stage 07 can see.

The values on /.env are placeholders for the scan. They are not credentials.
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>lane-demo</title></head>
<body>
<h1>lane-demo</h1>
<p>Demo service for a live API check.</p>
</body>
</html>
"""

ENV_FILE = "DEMO_MODE=true\nDEBUG=true\n"


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "lane-demo/0.1.0"

    def do_HEAD(self):
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            self._send(200, HOME, "text/html; charset=utf-8")
        elif path == "/.env":
            self._send(200, ENV_FILE, "text/plain; charset=utf-8")
        elif path == "/debug":
            self._send(200, '{"debug":true,"service":"lane-demo"}\n', "application/json")
        elif path == "/server-status":
            self._send(200, "service: lane-demo\nstate: up\n", "text/plain; charset=utf-8")
        else:
            self._send(404, "not found\n", "text/plain; charset=utf-8")

    def _send(self, status, body, content_type):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if not getattr(self, "_head_only", False):
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
