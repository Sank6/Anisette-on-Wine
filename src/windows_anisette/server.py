from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import ssl
from typing import Any, Protocol

from . import __version__
from .tokens import ProvisioningTokens, TokenError, decode_identifier
from .websocket import WebSocket, WebSocketError


class HeaderProvider(Protocol):
    def headers(self) -> dict[str, str]: ...

    def probe(self) -> dict[str, Any]: ...


class ServiceError(RuntimeError):
    pass


def require_loopback(host: str) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ServiceError("bind address must be a numeric loopback address") from exc
    if not address.is_loopback:
        raise ServiceError("refusing to bind anisette data outside loopback")


class AnisetteHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        provider: HeaderProvider,
        tokens: ProvisioningTokens,
        client_info: str,
        user_agent: str,
    ):
        require_loopback(address[0])
        self.address_family = socket.AF_INET6 if ipaddress.ip_address(address[0]).version == 6 else socket.AF_INET
        self.provider = provider
        self.tokens = tokens
        self.client_info = client_info
        self.user_agent = user_agent
        super().__init__(address, AnisetteRequestHandler)


class AnisetteRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"anisette-on-wine/{__version__}"
    sys_version = ""
    MAX_BODY = 16 * 1024

    @property
    def anisette_server(self) -> AnisetteHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format_string: str, *args: object) -> None:
        # Deliberately omit request bodies, query strings, and generated headers.
        clean_path = self.path.split("?", 1)[0]
        print(f'{self.client_address[0]} - {self.command} {clean_path} - {args[1] if len(args) > 1 else "-"}')

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Implementation-Version", self.server_version)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, result: str, message: str) -> None:
        self._json(status, {"result": result, "message": message})

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path == "/":
            try:
                self._json(200, self.anisette_server.provider.headers())
            except Exception:
                self._error(503, "GetHeadersError", "Windows ADI is unavailable")
            return
        if path == "/healthz":
            try:
                self.anisette_server.provider.probe()
            except Exception:
                self._json(503, {"status": "unavailable", "backend": "wine-aoskit"})
            else:
                self._json(200, {"status": "ok", "backend": "wine-aoskit"})
            return
        if path == "/v3/client_info":
            self._json(
                200,
                {
                    "client_info": self.anisette_server.client_info,
                    "user_agent": self.anisette_server.user_agent,
                },
            )
            return
        if path == "/v3/provisioning_session":
            self._provisioning_session()
            return
        self._error(404, "NotFound", "route not found")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        path = self.path.split("?", 1)[0]
        if path != "/v3/get_headers":
            self._error(404, "NotFound", "route not found")
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._error(415, "InvalidRequest", "Content-Type must be application/json")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._error(411, "InvalidRequest", "a valid Content-Length is required")
            return
        if length < 2 or length > self.MAX_BODY:
            self._error(413, "InvalidRequest", "request body size is invalid")
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
            identifier = decode_identifier(payload.get("identifier"))
            self.anisette_server.tokens.verify(identifier, payload.get("adi_pb"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TokenError):
            self._error(400, "InvalidRequest", "invalid identifier or provisioning handle")
            return
        try:
            headers = self.anisette_server.provider.headers()
        except Exception:
            self._error(503, "GetHeadersError", "Windows ADI is unavailable")
            return
        self._json(
            200,
            {
                "result": "Headers",
                "X-Apple-I-MD": headers["X-Apple-I-MD"],
                "X-Apple-I-MD-M": headers["X-Apple-I-MD-M"],
                "X-Apple-I-MD-RINFO": headers["X-Apple-I-MD-RINFO"],
            },
        )

    def _provisioning_session(self) -> None:
        if self.headers.get("Upgrade", "").lower() != "websocket":
            self._error(426, "UpgradeRequired", "a WebSocket upgrade is required")
            return
        if self.headers.get("Sec-WebSocket-Version") != "13":
            self._error(400, "InvalidWebSocket", "WebSocket version 13 is required")
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        try:
            decoded_key = base64.b64decode(key, validate=True)
        except (ValueError, base64.binascii.Error):
            decoded_key = b""
        if len(decoded_key) != 16:
            self._error(400, "InvalidWebSocket", "invalid WebSocket key")
            return
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        socket = WebSocket(self.connection)
        try:
            socket.send_json({"result": "GiveIdentifier"})
            request = socket.receive_json()
            identifier = decode_identifier(request.get("identifier"))
            handle = self.anisette_server.tokens.issue(identifier)
            socket.send_json({"result": "ProvisioningSuccess", "adi_pb": handle})
            socket.close()
        except (WebSocketError, TokenError, OSError):
            try:
                socket.send_json({"result": "InvalidIdentifier"})
                socket.close(1002)
            except (WebSocketError, OSError):
                pass


def serve(
    host: str,
    port: int,
    provider: HeaderProvider,
    tokens: ProvisioningTokens,
    client_info: str,
    user_agent: str,
    tls_cert: str | None = None,
    tls_key: str | None = None,
) -> None:
    server = AnisetteHTTPServer((host, port), provider, tokens, client_info, user_agent)
    if bool(tls_cert) != bool(tls_key):
        server.server_close()
        raise ServiceError("--tls-cert and --tls-key must be supplied together")
    if tls_cert and tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(tls_cert, tls_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        scheme = "https" if tls_cert else "http"
        print(f"Serving anisette on {scheme}://{host}:{port}")
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
