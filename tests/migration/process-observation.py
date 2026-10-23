#!/usr/bin/env python3
"""Exercise real process metadata failures at the public Bash entry point."""
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

script, fixture, error = sys.argv[1:]
root = Path(os.environ["MIGRATION_FIXTURE"])
processes = root / "processes.jsonl"
# Adopt only descendants of this test so a deliberately faulty script cannot
# leave its abandoned fixture producer for the host's init process to reap.
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, "subreaper unavailable"


def launch(argv, **kwargs):
    p = subprocess.Popen(argv, **kwargs)
    with processes.open("a") as log:
        log.write(json.dumps(dict(pid=p.pid, command=argv)) + "\n")
    return p


def run_case(directory, injection=None):
    directory.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["MIGRATION_FIXTURE"] = str(directory)
    env["PATH"] = str(directory / "bin") + ":" + env["PATH"]

    def ctl(*args):
        assert launch(["python3", fixture, *args], env=env).wait() == 0

    ctl("init")
    with (directory / "prepare.out").open("w") as out:
        assert launch(["bash", script, "close-admission", str(directory / "config")],
                      env=env, stdout=out, stderr=subprocess.STDOUT).wait() == 0
    ctl("confirm")
    ctl("fault", json.dumps(dict(command="platform:final", mode="expected", status=0,
                                 producer=dict(record="nul", ignore_term=True))))
    trace = directory / "process.trace"
    argv = ["strace", "-qq", "-s", "256", "-e", "trace=openat,wait4,kill", "-o", str(trace)]
    if injection is not None:
        argv += ["-e", f"inject=openat:error={error}:when={injection}"]
    argv += ["bash", script, "migrate", str(directory / "config")]
    producer = None
    p = None
    evidence = dict(error=error if injection else "control")
    try:
        with (directory / "stdout").open("w") as out, (directory / "stderr").open("w") as err:
            p = launch(argv, env=env, stdout=out, stderr=err)
            ready = directory / "producer-ready.json"
            until = time.monotonic() + 20
            while not ready.exists() and p.poll() is None and time.monotonic() < until:
                time.sleep(.01)
            assert ready.exists(), "fixture producer was not reached"
            evidence.update(json.loads(ready.read_text()))
            producer = evidence["pid"]
            # Invalid bytes after open-new must allow bounded reclose even if
            # the actual owned child's metadata read fails with EACCES/EIO.
            code = p.wait(timeout=max(.01, evidence["started"] + 2.5 - time.monotonic()))
        evidence.update(exit=code, elapsed=round(time.monotonic() - evidence["started"], 3))
        opens = [line for line in trace.read_text().splitlines() if line.startswith("openat(")]
        hits = [(i + 1, line) for i, line in enumerate(opens)
                if f'"/proc/{producer}/stat"' in line]
        assert hits, "no owned-child metadata lookup"
        evidence["lookup_index"], evidence["lookup_line"] = hits[0]
        if injection is not None:
            assert evidence["lookup_index"] == injection, "injection missed owned child"
            assert f"= -1 {error}" in hits[0][1] and "(INJECTED)" in hits[0][1], "fault not applied"
        assert code == 75, ("unexpected migration exit", code)
        db = json.loads((directory / "fixture.json").read_text())
        opened = next(i for i, call in enumerate(db["calls"]) if call[:2] == ["platform", "open-new"])
        evidence["reclose_attempted"] = any(call[:2] == ["platform", "close"]
                                          for call in db["calls"][opened + 1:])
        evidence["producer_gone"] = not Path(f"/proc/{producer}").exists()
        assert evidence["reclose_attempted"] and not db["new_open"], "safety reclose was postponed"
        # This checks the faulty inference, not just a fast exit: a single
        # transient read error cannot discard a still-live producer identity.
        assert evidence["producer_gone"], "metadata failure discarded live producer"
        for claim in ("fault-used", "closed", "unknown"):
            ctl("assert", claim)
        evidence["passed"] = True
        return evidence["lookup_index"]
    finally:
        (directory / "producer-release").touch()
        if producer is not None and Path(f"/proc/{producer}").exists():
            # Only the fixture-recorded owned child may be signaled here.
            try:
                os.kill(producer, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if p is not None and p.poll() is None:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if producer is not None:
            until = time.monotonic() + 2
            while Path(f"/proc/{producer}").exists() and time.monotonic() < until:
                try:
                    os.waitpid(producer, os.WNOHANG)
                except ChildProcessError:
                    pass
                time.sleep(.01)
        evidence["producer_gone_after_cleanup"] = producer is None or not Path(f"/proc/{producer}").exists()
        (directory / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")


# Calibrate on a matching ordinary run, then require the trace to prove that
# the one injected syscall was the owned producer's lookup, not a setup error.
index = run_case(root / "control")
run_case(root / "fault", index)
