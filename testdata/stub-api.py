#!/usr/bin/env python3
"""A stub of the ArtefactFlow endpoints this action calls.

It exists so the action can be exercised end to end — the container, the input
plumbing, and $GITHUB_OUTPUT — without an ArtefactFlow instance and without any
secret, which is what lets the smoke test run on pull requests from forks too.

It is deliberately strict about the things the action could get wrong silently:
the token endpoint checks the credentials, the write endpoints reject a request
that does not present the minted token, the create body is checked for the
provenance the action is supposed to derive from the workflow context, creating
the same version twice returns 409, and vulnerabilities cannot be uploaded for a
version that was never created. Each of those would otherwise pass unnoticed.

    python3 testdata/stub-api.py [port]
"""

import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLIENT_ID = "507f191e810c19729de860ed"
CLIENT_SECRET = "afsa_stub-client-secret"
MINTED_TOKEN = "stub-minted-jwt"

ARTEFACT_ID = "0123456789abcdef01234567"
ARTEFACT_NAME = "acme-payment-service"

CREATE_PATH = re.compile(rf"^/v1/artefacts/{ARTEFACT_ID}/versions$")
VULNS_PATH = re.compile(rf"^/v1/artefacts/{ARTEFACT_ID}/versions/([^/]+)/vulnerabilities$")

# Fields the action must always derive from the workflow context, whether or not the workflow set them explicitly.
REQUIRED_CREATE_FIELDS = ("version", "commit_sha", "build_id", "pipeline_id", "builder")

# Creating this version succeeds but uploading its vulnerabilities always fails, so the smoke test can exercise the one failure the action must report unambiguously: the version exists, only the upload needs re-running.
UPLOAD_FAILS_FOR_VERSION = "9.9.9"

created_versions = set()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        # Each request re-arms the drain guard; the body of one request must never be mistaken for the body of the next.
        self._drained = False
        self._raw = b""
        super().handle_one_request()

    def log_message(self, fmt, *args):
        # One line per request, on stderr, without the noisy default prefix.
        sys.stderr.write("stub-api: " + fmt % args + "\n")

    def _send(self, status, payload, headers=None):
        # Drain the request body first. With keep-alive on, replying to a request whose body is still unread leaves those bytes in the stream, where they are parsed as the next request line — turning every early-return error path into a confusing 501 on the *following* call.
        self._drain()
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _error(self, status, code, message):
        self._send(status, {"code": code, "message": message, "logid": "stub-log-id"})

    def _drain(self):
        """Read and discard any unread request body. Safe to call more than once."""
        if getattr(self, "_drained", False):
            return
        self._drained = True
        length = int(self.headers.get("Content-Length") or 0)
        if length > 0:
            self._raw = self.rfile.read(length)

    def _body(self):
        self._drain()
        try:
            return json.loads(getattr(self, "_raw", b"") or b"{}")
        except json.JSONDecodeError:
            self._error(400, "GEN00001", "Malformed JSON body")
            return None

    def _authorised(self):
        # Only the token this stub minted is accepted. The action has no other way to
        # authenticate, so anything else means the credentials flow is broken.
        header = self.headers.get("Authorization", "")
        if header == f"Bearer {MINTED_TOKEN}":
            return True
        self._error(401, "AUTH00002", f"Unexpected Authorization header: {header!r}")
        return False

    def do_POST(self):
        path = self.path.split("?", 1)[0]

        if path == "/v1/auth/token":
            body = self._body()
            if body is None:
                return
            if body.get("client_id") != CLIENT_ID or body.get("client_secret") != CLIENT_SECRET:
                # The real API does not distinguish an unknown id from a wrong secret.
                self._error(401, "AUTH00001", "Invalid credentials")
                return
            self._send(200, {"access_token": MINTED_TOKEN, "expire_in": 300, "token_type": "Bearer"})
            return

        if CREATE_PATH.match(path):
            if not self._authorised():
                return
            body = self._body()
            if body is None:
                return

            missing = [f for f in REQUIRED_CREATE_FIELDS if not body.get(f)]
            if missing:
                self._error(422, "VERSION00422", f"Create body is missing {', '.join(missing)}")
                return
            if body["builder"] != "github-actions":
                self._error(422, "VERSION00422", f"Unexpected builder {body['builder']!r}")
                return

            version = body["version"]
            if version in created_versions:
                self._error(409, "VERSION00409", "A version with that value already exists")
                return
            created_versions.add(version)

            self._send(
                201,
                {"id": "6a49227d9e270d46c3526074", "artefact_id": ARTEFACT_ID, "version": version},
                {"Location": f"/v1/artefacts/{ARTEFACT_ID}/versions/{version}"},
            )
            return

        self._error(404, "GEN00404", "No such endpoint")

    def do_PUT(self):
        path = self.path.split("?", 1)[0]

        match = VULNS_PATH.match(path)
        if not match:
            self._error(404, "GEN00404", "No such endpoint")
            return
        if not self._authorised():
            return

        version = match.group(1)
        if version == UPLOAD_FAILS_FOR_VERSION:
            self._error(500, "VULN00500", "Deliberate upload failure, so the smoke test can check what the action reports")
            return
        if version not in created_versions:
            # Vulnerabilities are keyed by the version's SemVer string, so uploading for a
            # version that does not exist means the action sequenced the two calls wrongly.
            self._error(404, "VERSION00404", "No such version; it must be created first")
            return

        body = self._body()
        if body is None:
            return
        vulns = body.get("vulnerabilities")
        if not isinstance(vulns, list):
            # A full replace with a missing or null list would silently clear the set.
            self._error(422, "VULN00422", "`vulnerabilities` must be an array")
            return
        self._send(200, {"metadata": {"total_records": len(vulns)}, "vulnerabilities": vulns})

    def do_GET(self):
        path, _, query = self.path.partition("?")

        if path == "/v1/artefacts/resolve":
            if not self._authorised():
                return
            name = ""
            for pair in query.split("&"):
                key, _, value = pair.partition("=")
                if key == "name":
                    name = value
            if name != ARTEFACT_NAME:
                self._error(404, "ARTEFACT00509", "Artefact not found")
                return
            self._send(200, {"id": ARTEFACT_ID, "name": ARTEFACT_NAME})
            return

        self._error(404, "GEN00404", "No such endpoint")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    # Threaded on purpose. With keep-alive connections a single-threaded server accepts no new connection while an idle one is open, so a client that opens a second connection — a retry, or a client built with its own transport — would hang until it timed out.
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
