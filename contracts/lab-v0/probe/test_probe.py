import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lab_probe", ROOT / "probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
audit_spec = importlib.util.spec_from_file_location("lab_verify", ROOT / "verify_run.py")
audit = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(audit)


class ProbeTests(unittest.TestCase):
    # Claim: the filter permits Unix sockets and refuses IPv4/IPv6/io_uring before exec; the unfiltered creation control distinguishes host denial.
    def test_unix_valid_and_network_refused(self):
        with socket.socket(socket.AF_INET):
            pass
        source = """
import ctypes, errno, socket
with socket.socket(socket.AF_UNIX):
    pass
for family in (socket.AF_INET, socket.AF_INET6):
    try:
        socket.socket(family)
    except OSError as error:
        assert error.errno == errno.EPERM
    else:
        raise AssertionError('network socket admitted')
library = ctypes.CDLL(None, use_errno=True)
assert library.syscall(425, 1, 0) == -1
assert ctypes.get_errno() == errno.EPERM
print('unix valid; network and io_uring refused')
"""
        result = subprocess.run([sys.executable, str(ROOT / "socket_only.py"), sys.executable, "-c", source], capture_output=True, text=True, timeout=10, close_fds=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unix valid", result.stdout)

    # Claim: reconstructed body fields match the measured profile without retaining prompt strings; an unreviewed enum is rejected, not logged.
    def test_structural_projection_pair(self):
        fixture_path = ROOT.parent / "wire-fixtures.json"
        document = json.loads(fixture_path.read_text())["cases"][0]["request"]["body"]
        observation = json.loads((ROOT / "observed.json").read_text())["requests"][1]["body_shape"]
        shape = probe.request_shape(document)
        for projection in (shape, observation):
            projection["cache_controls"].sort(key=lambda cache: json.dumps(cache, sort_keys=True))
        self.assertEqual(shape, observation)
        self.assertNotIn("PUBLIC SYNTHETIC", json.dumps(shape))
        document["thinking"]["display"] = "PUBLIC-DO-NOT-RECORD"
        with self.assertRaisesRegex(ValueError, "unreviewed structural enum"):
            probe.request_shape(document)

    # Claim: a filtered local Unix HTTP request gets SSE without prompt content in recorder output, while the error control remains HTTP 400.
    def test_local_http_and_error_pair(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as scratch:
            scratch = Path(scratch)
            for mode, status in (("sse", 200), ("error", 400)):
                with probe.RecordingServer(str(scratch / (mode + ".sock")), probe.RecordingHandler) as server:
                    server.configuration = {"messages": mode, "policy": {"restrictions": {}}, "request_id": False}
                    server.log_path = scratch / (mode + ".jsonl")
                    server.log_lock = threading.Lock()
                    server.started = probe.time.monotonic()
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    source = """
import socket, sys
body = b'{"stream":true,"sentinel":"PUBLIC-DO-NOT-RECORD"}'
with socket.socket(socket.AF_UNIX) as client:
    client.connect(sys.argv[1])
    client.sendall(b'POST /v1/messages?beta=true HTTP/1.1\\r\\nHost: api.anthropic.com\\r\\nx-api-key: ssh-placeholder\\r\\nContent-Length: '+str(len(body)).encode()+b'\\r\\n\\r\\n'+body)
    reply = b''
    while True:
        piece = client.recv(65536)
        if not piece: break
        reply += piece
    assert reply.startswith(('HTTP/1.1 '+sys.argv[2]).encode())
"""
                    try:
                        result = subprocess.run([sys.executable, str(ROOT / "socket_only.py"), sys.executable, "-c", source, str(scratch / (mode + ".sock")), str(status)], capture_output=True, text=True, timeout=10, close_fds=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                    finally:
                        server.shutdown()
                        thread.join(timeout=3)
                    record = server.log_path.read_text()
                    self.assertNotIn("PUBLIC-DO-NOT-RECORD", record)
                    self.assertEqual(json.loads(record)["response_status"], status)

    # Claim: owned successful Unix connects pass, while successful IPv4/foreign Unix and incomplete trace plants fail without generating traffic.
    def test_trace_audit_pairs(self):
        valid = '1 socket(AF_UNIX, SOCK_STREAM, 0) = 3\n1 connect(3, {sa_family=AF_UNIX, sun_path="/tmp/fixture.sock"}, 110) = 0\n' * 2
        self.assertTrue(audit.trace_is_local(valid, "/tmp/fixture.sock"))
        for plant in ('1 socket(AF_INET, SOCK_STREAM, 0) = 4\n', '1 connect(4, {sa_family=AF_UNIX, sun_path="/tmp/foreign.sock"}, 110) = 0\n', '1 connect(3, <unfinished ...>\n'):
            self.assertFalse(audit.trace_is_local(valid + plant, "/tmp/fixture.sock"))
        self.assertFalse(audit.trace_is_local("", "/tmp/fixture.sock"))

    # Claim: the evidence checker distinguishes an exact valid profile from unqualified error retries, and refuses changed authentication on the initial model attempt.
    def test_evidence_profile_pairs(self):
        import hashlib
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as scratch:
            scratch = Path(scratch)
            observed = json.loads((ROOT / "observed.json").read_text())["requests"]
            metadata = {"exit_code": 0, "row": "apikey-ssh", "initial_home_entries": [],
                        "source_sha256": {str(ROOT / name): hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in ("probe.py", "socket_only.py")}}
            metadata["source_sha256"]["fixture-binary"] = probe.EXPECTED_BINARY
            (scratch / "run.json").write_text(json.dumps(metadata))
            trace = f'1 socket(AF_UNIX, SOCK_STREAM, 0) = 3\n1 connect(3, {{sa_family=AF_UNIX, sun_path="{scratch / "api.sock"}"}}, 110) = 0\n'
            (scratch / "network.strace").write_text(trace * 2)
            (scratch / "requests.jsonl").write_text("".join(json.dumps(request)+"\n" for request in observed))
            self.assertEqual(audit.verify(scratch, 0)["unqualified_retries"], 0)
            observed[1]["headers"]["authorization"] = "Bearer ssh-placeholder"
            (scratch / "requests.jsonl").write_text("".join(json.dumps(request)+"\n" for request in observed))
            with self.assertRaisesRegex(ValueError, "wire/profile mismatch"):
                audit.verify(scratch, 0)
            negative = json.loads((ROOT / "error-observed.json").read_text())["requests"]
            metadata["exit_code"] = 1
            (scratch / "run.json").write_text(json.dumps(metadata))
            (scratch / "requests.jsonl").write_text("".join(json.dumps(request)+"\n" for request in negative))
            self.assertEqual(audit.verify(scratch, 1)["unqualified_retries"], 2)

    # Claim: the recorder refuses a wrong executable digest before creating any run directory, beside the fixed approved digest declaration.
    def test_wrong_binary_refused(self):
        self.assertEqual(probe.EXPECTED_BINARY, json.loads((ROOT / "client.json").read_text())["binary_sha256"])
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as scratch:
            arguments = type("Arguments", (), {"name": "negative", "binary": sys.executable, "scratch": scratch})()
            with self.assertRaisesRegex(ValueError, "unapproved executable digest"):
                probe.run_probe(arguments)
            self.assertEqual(list(Path(scratch).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
