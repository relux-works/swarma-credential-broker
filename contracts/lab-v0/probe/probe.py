import argparse
import datetime
import hashlib
import re
import http.server
import json
import os
from pathlib import Path
import socketserver
import subprocess
import threading
import time
import urllib.parse


ROOT = Path(__file__).resolve().parent
EXPECTED_BINARY = "a982d38030b97e750848add2cbb2df6d9a70d5544a22ca9b216a349ba25865e8"
AUTH_ROWS = {
    "oauth-ssh": {"CLAUDE_CODE_OAUTH_TOKEN": "ssh-placeholder"},
    "apikey-ssh": {"ANTHROPIC_API_KEY": "ssh-placeholder"},
    "oauth-other": {"CLAUDE_CODE_OAUTH_TOKEN": "another-placeholder"},
    "auth-token": {"ANTHROPIC_AUTH_TOKEN": "placeholder"},
}
SELECTED_HEADERS = ("authorization", "x-api-key", "anthropic-beta", "anthropic-version", "user-agent")


def message_events(mode):
    message = {
        "id": "msg_lab", "type": "message", "role": "assistant",
        "model": "claude-sonnet-4-6", "content": [], "stop_reason": None,
        "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0},
    }
    events = [
        ("message_start", {"type": "message_start", "message": message}),
        ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
        ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ok"}}),
        ("content_block_stop", {"type": "content_block_stop", "index": 0}),
        ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 1}}),
        ("message_stop", {"type": "message_stop"}),
    ]
    if mode == "minimal":
        events[0][1]["message"].pop("stop_reason")
        events[0][1]["message"].pop("stop_sequence")
        events[4][1]["delta"].pop("stop_sequence")
    if mode == "without-stop":
        events = events[:-1]
    return b"".join(f"event: {name}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode() for name, data in events)


def request_shape(document):
    paths = set()
    caches = []
    def visit(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = path + "." + key if path else key
                paths.add(child_path)
                if key == "cache_control" and isinstance(child, dict):
                    caches.append({name: child[name] for name in ("type", "scope", "ttl") if name in child})
                visit(child, child_path)
        elif isinstance(value, list):
            for child in value:
                visit(child, path + "[]")
    visit(document, "")
    allowed = {"thinking": ({"type": "adaptive", "display": "omitted"},),
               "output_config": ({"effort": "medium"},),
               "context_management": ({"edits": [{"type": "clear_thinking_20251015", "keep": "all"}]},),
               "model": ("claude-opus-5-5",), "max_tokens": (128000,)}
    for name, choices in allowed.items():
        if name in document and document[name] not in choices:
            raise ValueError("unreviewed structural enum")
    for cache in caches:
        if any(value not in {"ephemeral", "global", "1h", "5m"} for value in cache.values()):
            raise ValueError("unreviewed cache enum")
    return {"paths": sorted(paths), "cache_controls": caches,
            "thinking": document.get("thinking"), "output_config": document.get("output_config"),
            "context_management": document.get("context_management"),
            "model": document.get("model"), "max_tokens": document.get("max_tokens")}


class RecordingServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


class RecordingHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        import socket
        self.request.settimeout(6)
        self.transport_tls = False
        prefix = self.request.recv(8, socket.MSG_PEEK)
        if prefix.startswith(b"\x16\x03") and getattr(self.server, "tls_context", None):
            self.request = self.server.tls_context.wrap_socket(self.request, server_side=True)
            self.transport_tls = True
        super().setup()

    def handle(self):
        import socket
        self.connection.settimeout(6)
        try:
            prefix = self.connection.recv(8, socket.MSG_PEEK) if not self.transport_tls else b"GET "
        except (TimeoutError, ConnectionResetError):
            prefix = b""
        kind = "tls-client-hello" if prefix.startswith(b"\x16\x03") else "http1" if prefix.startswith((b"GET ", b"POST ", b"CONNECT ", b"HEAD ")) else "empty-or-other"
        if self.transport_tls:
            kind = "tls-http1"
        with self.server.log_lock:
            with self.server.log_path.with_name("transport.jsonl").open("a") as output:
                output.write(json.dumps({"kind": kind, "elapsed_seconds": round(time.monotonic() - self.server.started, 3)}) + "\n")
        if kind in ("http1", "tls-http1"):
            try:
                super().handle()
            except (TimeoutError, ConnectionResetError):
                pass

    def do_CONNECT(self):
        self.respond()

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        length = int(self.headers.get("Content-Length", "0"))
        request_body = self.rfile.read(length) if length else b""
        stream_requested = None
        body_shape = None
        if request_body:
            try:
                document = json.loads(request_body)
                stream_requested = document.get("stream") if isinstance(document, dict) else None
                body_shape = request_shape(document) if isinstance(document, dict) else None
            except (ValueError, UnicodeDecodeError):
                pass
        del request_body
        configuration = self.server.configuration
        record = {
            "elapsed_seconds": round(time.monotonic() - self.server.started, 3),
            "method": self.command, "path": self.path,
            "headers": {name: self.headers.get(name) for name in SELECTED_HEADERS},
            "stream_requested": stream_requested, "body_shape": body_shape,
        }
        if record["headers"]["x-api-key"] not in (None, "ssh-placeholder") or record["headers"]["authorization"] not in (None, "Bearer ssh-placeholder", "Bearer another-placeholder", "Bearer placeholder", "Bearer swarma-ph-test1"):
            raise ValueError("non-synthetic header refused")
        path = urllib.parse.urlsplit(self.path).path
        status = 200
        content_type = "application/json"
        if path == "/api/claude_code/policy_limits":
            body = json.dumps(configuration["policy"]).encode()
        elif path == "/api/claude_code/settings":
            body = json.dumps(configuration["settings"]).encode()
        elif path in ("/api/oauth/profile", "/api/claude_code/profile"):
            body = json.dumps(configuration["profile"]).encode()
        elif path == "/v1/messages":
            if configuration["messages"] == "error":
                status = 400
                body = b'{"type":"error","error":{"type":"invalid_request_error","message":"synthetic negative control"}}'
            elif stream_requested:
                content_type = "text/event-stream"
                body = message_events(configuration["messages"])
            else:
                body = json.dumps({"id": "msg_lab", "type": "message", "role": "assistant", "model": "claude-sonnet-4-6", "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}}).encode()
        elif path == "/v1/messages/count_tokens":
            body = b'{"input_tokens":1}'
        else:
            status = 404
            body = b'{"type":"error","error":{"type":"not_found_error","message":"unconfigured local probe path"}}'
        record["response_status"] = status
        record["response_content_type"] = content_type
        with self.server.log_lock:
            with self.server.log_path.open("a") as output:
                output.write(json.dumps(record) + "\n")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if configuration["request_id"]:
            self.send_header("request-id", "req_synthetic_local")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True


def synthetic_extra_environment(assignments):
    result = {}
    for assignment in assignments:
        name, value = assignment.split("=", 1)
        if name not in {"ANTHROPIC_BASE_URL", "API_TIMEOUT_MS", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"}:
            raise ValueError("extra environment variable is not allowlisted")
        if name in {"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"} and value not in {"ssh-placeholder", "another-placeholder", "placeholder", "swarma-ph-test1"}:
            raise ValueError("only explicitly synthetic credential placeholders are admitted")
        result[name] = value
    return result


def run_probe(arguments):
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,60}", arguments.name):
        raise ValueError("run name must be a bounded lowercase slug")
    binary = Path(arguments.binary).resolve(strict=True)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != EXPECTED_BINARY:
        raise ValueError("unapproved executable digest")
    scratch = Path(arguments.scratch)
    if not scratch.is_absolute():
        raise ValueError("scratch must be absolute")
    scratch = scratch.resolve(strict=True)
    extra_environment = synthetic_extra_environment(arguments.extra_env)
    run_directory = scratch / arguments.name
    run_directory.mkdir(parents=True, exist_ok=False)
    for directory in ("home", "work", "tmp", "cache", "config", "state", "managed"):
        (run_directory / directory).mkdir()
    socket_path = run_directory / "api.sock"
    configuration = {
        "policy": json.loads(arguments.policy), "settings": json.loads(arguments.settings),
        "profile": json.loads(arguments.profile), "messages": arguments.messages,
        "request_id": not arguments.no_request_id,
    }
    environment = {
        "HOME": str(run_directory / "home"), "USERPROFILE": str(run_directory / "home"),
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": "dumb",
        "TMPDIR": str(run_directory / "tmp"), "TMP": str(run_directory / "tmp"), "TEMP": str(run_directory / "tmp"),
        "XDG_CONFIG_HOME": str(run_directory / "config"), "XDG_CACHE_HOME": str(run_directory / "cache"),
        "XDG_STATE_HOME": str(run_directory / "state"),
        "CLAUDE_CONFIG_DIR": str(run_directory / "home" / ".claude"),
        "CLAUDE_CODE_MANAGED_SETTINGS_PATH": str(run_directory / "managed"),
        "CLAUDE_CODE_TMPDIR": str(run_directory / "tmp"),
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1", "DISABLE_AUTOUPDATER": "1", "DISABLE_UPDATES": "1",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false",
        "ANTHROPIC_UNIX_SOCKET": str(socket_path),
        **AUTH_ROWS[arguments.row],
    }
    if arguments.tls_cert:
        environment["NODE_EXTRA_CA_CERTS"] = str(Path(arguments.tls_cert).resolve())
    environment.update(extra_environment)
    command = [
        "/usr/bin/env", "-i", *[f"{name}={value}" for name, value in environment.items()],
        "/usr/bin/timeout", "--signal=TERM", "--kill-after=5s", f"{arguments.timeout}s",
        "/usr/bin/strace", "-f", "-qq", "-s", "160", "-e", "trace=socket,connect,io_uring_setup,io_uring_enter,io_uring_register",
        "-o", str(run_directory / "network.strace"),
        "/usr/bin/python3", str(ROOT / "socket_only.py"), str(binary),
    ]
    if arguments.version:
        command += ["--version"]
    else:
        command += ["-p", "say ok", "--max-turns", "1", "--no-session-persistence", "--setting-sources", "", "--strict-mcp-config", "--tools", "", "--disable-slash-commands", "--output-format", "json"]
    with RecordingServer(str(socket_path), RecordingHandler) as server:
        if arguments.tls_cert:
            import ssl
            server.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server.tls_context.load_cert_chain(arguments.tls_cert, arguments.tls_key)
        server.configuration = configuration
        server.log_path = run_directory / "requests.jsonl"
        server.log_path.touch()
        server.log_lock = threading.Lock()
        server.started = time.monotonic()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        metadata = {"name": arguments.name, "row": arguments.row, "configuration": configuration, "command": command, "cwd": str(run_directory / "work"), "initial_home_entries": list((run_directory / "home").iterdir()), "server_pid": os.getpid()}
        metadata["initial_home_entries"] = [str(entry) for entry in metadata["initial_home_entries"]]
        metadata["started_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        metadata["stdin"] = "/dev/null"
        metadata["source_sha256"] = {}
        for source in (binary, ROOT / "probe.py", ROOT / "socket_only.py"):
            with source.open("rb") as input_file:
                metadata["source_sha256"][str(source)] = hashlib.file_digest(input_file, "sha256").hexdigest()
        (run_directory / "run.json").write_text(json.dumps(metadata, indent=2))
        try:
            with (run_directory / "stdout.log").open("wb") as stdout, (run_directory / "stderr.log").open("wb") as stderr:
                process = subprocess.Popen(command, cwd=run_directory / "work", env={}, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, close_fds=True)
                metadata["process_pid"] = process.pid
                metadata["exit_code"] = process.wait(timeout=arguments.timeout + 15)
        finally:
            server.shutdown()
            thread.join(timeout=3)
        metadata["elapsed_seconds"] = round(time.monotonic() - server.started, 3)
        (run_directory / "run.json").write_text(json.dumps(metadata, indent=2))
    summary = {"name": arguments.name, "exit_code": metadata["exit_code"], "elapsed_seconds": metadata["elapsed_seconds"], "requests": [json.loads(line) for line in (run_directory / "requests.jsonl").read_text().splitlines()], "stdout": (run_directory / "stdout.log").read_text(errors="replace")[:2500], "stderr": (run_directory / "stderr.log").read_text(errors="replace")[:2500]}
    print(json.dumps(summary, indent=2))
    return metadata["exit_code"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--row", choices=AUTH_ROWS, default="apikey-ssh")
    parser.add_argument("--timeout", type=int, default=35)
    parser.add_argument("--policy", default='{"restrictions":{}}')
    parser.add_argument("--settings", default='{"settings":{}}')
    parser.add_argument("--profile", default='{}')
    parser.add_argument("--messages", choices=("sse", "minimal", "without-stop", "error"), default="sse")
    parser.add_argument("--no-request-id", action="store_true")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--extra-env", action="append", default=[])
    return run_probe(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
