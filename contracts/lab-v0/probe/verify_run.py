import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent


def trace_is_local(text, socket_path):
    connects = 0
    if not text.strip():
        return False
    for line in text.splitlines():
        if "unfinished" in line or "resumed" in line:
            return False
        if "socket(" in line and "socket(AF_UNIX," not in line:
            if "= -1 EPERM " not in line:
                return False
        if "io_uring_" in line and "= -1 EPERM " not in line:
            return False
        if "connect(" in line:
            if "= -1 ENOENT " in line and 'sun_path="/var/run/nscd/socket"' in line:
                continue
            if f'sun_path="{socket_path}"' not in line or not re.search(r" = 0$", line):
                return False
            connects += 1
    return connects >= 2


def verify(directory, expected_exit):
    directory = Path(directory).resolve(strict=True)
    metadata = json.loads((directory / "run.json").read_text())
    client = json.loads((ROOT / "client.json").read_text())
    if metadata["exit_code"] != expected_exit or metadata["row"] != "apikey-ssh" or metadata["initial_home_entries"]:
        raise ValueError("exit/mode/isolation mismatch")
    for name in ("probe.py", "socket_only.py"):
        expected = hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        if metadata["source_sha256"].get(str(ROOT / name)) != expected:
            raise ValueError("harness pin mismatch")
    if client["binary_sha256"] not in metadata["source_sha256"].values():
        raise ValueError("executable pin mismatch")
    if not trace_is_local((directory / "network.strace").read_text(), directory / "api.sock"):
        raise ValueError("nonlocal or incomplete syscall evidence")
    observed = json.loads((ROOT / "observed.json").read_text())["requests"]
    actual = [json.loads(line) for line in (directory / "requests.jsonl").read_text().splitlines()]
    if not actual or actual[0]["path"] != observed[0]["path"]:
        raise ValueError("missing policy request")
    if expected_exit == 0 and len(actual) != 2:
        raise ValueError("unbounded valid request sequence")
    if expected_exit == 1 and not 2 <= len(actual) <= 4:
        raise ValueError("unbounded error retry sequence")
    unqualified_retries = 0
    for position, request in enumerate(actual):
        request.pop("elapsed_seconds", None)
        reference = observed[0] if position == 0 else observed[1]
        for name in ("method", "path"):
            if request[name] != reference[name]:
                raise ValueError("wire/profile mismatch")
        exact = all(request[name] == reference[name] for name in ("headers", "stream_requested", "body_shape"))
        if not exact:
            if expected_exit == 0 or position < 2:
                raise ValueError("wire/profile mismatch")
            for name in ("authorization", "x-api-key", "anthropic-version", "user-agent"):
                if request["headers"][name] != reference["headers"][name]:
                    raise ValueError("retry authentication drift")
            beta = request["headers"]["anthropic-beta"].split(",")
            allowed = reference["headers"]["anthropic-beta"].split(",")
            if len(beta) != len(set(beta)) or not set(beta) <= set(allowed):
                raise ValueError("unknown retry beta")
            unqualified_retries += 1
        required = 200 if position == 0 or expected_exit == 0 else 400
        if request["response_status"] != required:
            raise ValueError("wrong stub response")
    return {"synthetic_only": True, "exit_code": expected_exit, "requests": len(actual), "local_trace": True,
            "unqualified_retries": unqualified_retries}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--expected-exit", type=int, choices=(0, 1), default=0)
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.directory, arguments.expected_exit), sort_keys=True))


if __name__ == "__main__":
    main()
