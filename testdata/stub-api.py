#!/usr/bin/env python3
"""A stub of the ArtefactFlow endpoints this action calls.

It exists so the action can be exercised end to end (the container, the input
plumbing, and $GITHUB_OUTPUT) without an ArtefactFlow instance and without any
secret, which is what lets the smoke test run on pull requests from forks too.

It is deliberately strict about the things the action could get wrong silently:
the token endpoint checks the credentials, the write endpoints reject a request
that does not present the minted token, the create body is checked for the
provenance the action is supposed to derive from the workflow context, creating
the same version twice returns 409, a scan report cannot be imported onto a
version that was never created, and the import must arrive as multipart form
data with JSON parts. Each of those would otherwise pass unnoticed.

It does not convert reports: that is ArtefactFlow's job, tested there. It only
recognises a report's format and lists the identifiers in it, which is enough
for the action's own behaviour (the dry run, the converted file, the summary in
the step log) to be exercised. It recognises Trivy, Grype, CycloneDX and native
reports only; a SARIF, OSV-Scanner, GitLab or Snyk report is refused here even
though ArtefactFlow reads it. Like ArtefactFlow it refuses a VEX document sent
beside a native report, and it echoes `producer` and `producer_version`.

It never answers 413 or 429: the size limit and the import gate's
`Retry-After` are covered by the Go unit tests, not by the smoke test.

    python3 testdata/stub-api.py [port]
"""

import json
import re
import sys
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

CLIENT_ID = "0198e2c3-9a21-7b8e-90f5-6c1d4e2a83b0"
CLIENT_SECRET = "afsa_stub-client-secret"
MINTED_TOKEN = "stub-minted-jwt"

ARTEFACT_ID = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
ARTEFACT_NAME = "acme-payment-service"

CREATE_PATH = re.compile(rf"^/v1/artefacts/{ARTEFACT_ID}/versions$")
IMPORT_PATH = re.compile(rf"^/v1/artefacts/{ARTEFACT_ID}/versions/([^/]+)/vulnerabilities/import$")

# Fields the action must always derive from the workflow context, whether or not the workflow set them explicitly.
REQUIRED_CREATE_FIELDS = ("version", "commit_sha", "build_id", "pipeline_id", "builder")

# Creating this version succeeds but importing its scan report always fails, so the smoke test can exercise the one failure the action must report unambiguously: the version exists, only the upload needs re-running. The failure is a 500, which the action retries (three attempts with backoff) before it gives up and fails the step.
UPLOAD_FAILS_FOR_VERSION = "9.9.9"

created_versions = set()


def multipart_parts(content_type, body):
    """The parts of a multipart/form-data body, as {name: (content type, bytes)}."""
    message = BytesParser(policy=policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    )
    if not message.is_multipart():
        return None
    parts = {}
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        parts[name] = (part.get_content_type(), part.get_payload(decode=True))
    return parts


def report_findings(report):
    """The report's format and the identifiers it names, or (None, None) for a document of no known format."""
    if isinstance(report, list):
        return "native", [v.get("id") for v in report]
    if not isinstance(report, dict):
        return None, None
    if "SchemaVersion" in report and "Results" in report:
        ids = [v.get("VulnerabilityID") for r in report.get("Results") or [] for v in r.get("Vulnerabilities") or []]
        return "trivy", ids
    if "matches" in report:
        return "grype", [m.get("vulnerability", {}).get("id") for m in report.get("matches") or []]
    if "bomFormat" in report:
        return "cyclonedx", [v.get("id") for v in report.get("vulnerabilities") or []]
    if "vulnerabilities" in report:
        return "native", [v.get("id") for v in report.get("vulnerabilities") or []]
    return None, None


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
        # Drain the request body first. With keep-alive on, replying to a request whose body is still unread leaves those bytes in the stream, where they are parsed as the next request line, turning every early-return error path into a confusing 501 on the *following* call.
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
        self._send(status, {"code": code, "message": message, "log_id": "stub-log-id"})

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

        match = IMPORT_PATH.match(path)
        if match:
            self._import(match.group(1))
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
                {"id": "0199a1b2-d5e6-7f80-9a1b-2c3d4e5f6a7b", "artefact_id": ARTEFACT_ID, "version": version},
                {"Location": f"/v1/artefacts/{ARTEFACT_ID}/versions/{version}"},
            )
            return

        self._error(404, "GEN00404", "No such endpoint")

    def _import(self, version):
        if not self._authorised():
            return
        if version == UPLOAD_FAILS_FOR_VERSION:
            # A 500 is retryable, so the action sends this import three times before failing; the smoke test checks only the outcome after the last one.
            self._error(500, "VULN00500", "Deliberate import failure, so the smoke test can check what the action reports")
            return
        if version not in created_versions:
            # The import addresses the version by its SemVer string, so importing onto one that does not exist means the action sequenced the two calls wrongly.
            self._error(404, "VERSION00404", "No such version; it must be created first")
            return

        self._drain()
        parts = multipart_parts(self.headers.get("Content-Type", ""), self._raw)
        if parts is None or "report" not in parts:
            self._error(400, "VULN00001", "The import takes multipart form data with a `report` part")
            return
        documents = {}
        for name, (content_type, content) in parts.items():
            if content_type != "application/json":
                self._error(400, "VULN00001", f"Part `{name}` is {content_type}, want application/json")
                return
            try:
                documents[name] = json.loads(content)
            except json.JSONDecodeError:
                self._error(400, "VULN00001", f"Part `{name}` is not JSON")
                return

        query = parse_qs(self.path.partition("?")[2])
        fmt, ids = report_findings(documents["report"])
        if fmt is None or (query.get("format") and query["format"][0] != fmt):
            self._error(400, "VULN00001", "The report's format was not recognised")
            return
        if fmt == "native" and "vex" in documents:
            # As ArtefactFlow does: a native report carries its analysis inline, so a VEX document beside one is a mistake to name, not an overlay to apply.
            self._error(400, "VULN00001", "A native report carries its analysis inline and takes no `vex` part")
            return
        ids = sorted({i for i in ids if i})
        vex_ids = {v.get("id") for v in (documents.get("vex") or {}).get("vulnerabilities") or []}
        summary = {"format": fmt, "vex_matched": len(vex_ids & set(ids))}
        unmatched = sorted(i for i in vex_ids - set(ids) if i)
        if unmatched:
            summary["vex_unmatched"] = unmatched
        producer = (query.get("producer") or [fmt])[0]
        producer_version = (query.get("producer_version") or [""])[0]
        findings = [{"id": i, "source": {"name": "NVD"}} for i in ids]
        for finding in findings:
            if finding["id"] in vex_ids:
                finding["analysis"] = {"state": "not_affected"}

        if (query.get("dry_run") or ["false"])[0] == "true":
            preview = {"producer": producer, "vulnerabilities": findings, "import": summary}
            if producer_version:
                preview["producer_version"] = producer_version
            self._send(200, preview)
            return
        recorded_producer = {"name": producer}
        if producer_version:
            recorded_producer["version"] = producer_version
        self._send(200, {
            "metadata": {"total_records": len(findings)},
            "vulnerabilities": [dict(f, producers=[producer]) for f in findings[:10]],
            "producer": recorded_producer,
            "import": summary,
        })

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
    # Threaded on purpose. With keep-alive connections a single-threaded server accepts no new connection while an idle one is open, so a client that opens a second connection (a retry, or a client built with its own transport) would hang until it timed out.
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
