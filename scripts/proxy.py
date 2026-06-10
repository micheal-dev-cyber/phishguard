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
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PUT(self):
        self._route("PUT")

    def do_DELETE(self):
        self._route("DELETE")

    def do_PATCH(self):
        self._route("PATCH")

    def _route(self, method):
        # Simple health check for debugging
        if self.path == "/proxy-test":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"proxy alive")
            return

        is_webhook = self.path.startswith("/webhooks/") or self.path == "/webhook"
        target_port = FLASK_PORT if is_webhook else STREAMLIT_PORT
        print(f"[proxy] {method} {self.path} -> port {target_port}")

        body = None
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            print(f"[proxy] body ({content_length} bytes): {body[:200]}")

        conn = http.client.HTTPConnection("127.0.0.1", target_port, timeout=30)
        try:
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "transfer-encoding")}
            conn.request(method, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            print(f"[proxy] response {resp.status} from port {target_port}")

            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                    self.send_header(k, v)
            self.send_header("Content-Length", len(resp_body))
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception as e:
            print(f"[proxy] ERROR: {e}")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"proxy error: {e}".encode())
        finally:
            conn.close()

    def log_message(self, format, *args):
        pass  # we log ourselves


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler)
    print(f"[proxy] Listening on {PROXY_PORT}, Flask={FLASK_PORT}, Streamlit={STREAMLIT_PORT}")
    server.serve_forever()
