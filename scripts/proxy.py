import http.client
import os
import socketserver
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

FLASK_PORT = 8080
STREAMLIT_PORT = 8501
PROXY_PORT = int(os.environ.get("PORT", 7860))


class ProxyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")

    def do_PUT(self):
        self._proxy("PUT")

    def do_DELETE(self):
        self._proxy("DELETE")

    def do_PATCH(self):
        self._proxy("PATCH")

    def _proxy(self, method):
        if self.path.startswith("/webhooks/") or self.path == "/webhook":
            target_port = FLASK_PORT
        else:
            target_port = STREAMLIT_PORT

        body = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)

        conn = http.client.HTTPConnection("127.0.0.1", target_port, timeout=30)
        try:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "transfer-encoding")}
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", len(resp_body))
            self.end_headers()
            self.wfile.write(resp_body)
        finally:
            conn.close()

    def log_message(self, format, *args):
        print(f"[proxy] {args[0]} {args[1]} -> {FLASK_PORT if self.path.startswith('/webhooks') or self.path == '/webhook' else STREAMLIT_PORT}")


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler)
    print(f"[proxy] Listening on {PROXY_PORT}, Flask={FLASK_PORT}, Streamlit={STREAMLIT_PORT}")
    server.serve_forever()
