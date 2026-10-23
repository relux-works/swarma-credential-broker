#!/usr/bin/env python3
"""Bounded live-producer cases, using only the existing synthetic fixture."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

script, fixture, phase, record, status, ignore_term = sys.argv[1:7]
unconfirmed = sys.argv[7:] == ["unconfirmed"]
reader_evidence = sys.argv[7:] == ["reader-evidence"]
root = Path(os.environ["MIGRATION_FIXTURE"])
processes = root / "producer-processes.jsonl"


def launch(argv, **kwargs):
    p = subprocess.Popen(argv, **kwargs)
    with processes.open("a") as f:
        f.write(json.dumps(dict(pid=p.pid, command=argv)) + "\n")
    return p


fault = dict(command="platform:" + ("inventory" if phase == "close-admission" else "final"),
             mode="expected", status=int(status),
             producer=dict(record=record, ignore_term=ignore_term == "yes"))
assert launch(["python3", fixture, "fault", json.dumps(fault)]).wait() == 0
env = os.environ.copy()
env["PATH"] = str(root / "bin") + ":" + env["PATH"]
p = None
producer = None
try:
    with (root / "stdout").open("w") as out, (root / "stderr").open("w") as err:
        p = launch(["bash", script, phase, str(root / "config")], env=env, stdout=out, stderr=err)
        ready = root / "producer-ready.json"
        until = time.monotonic() + 20
        while not ready.exists() and p.poll() is None and time.monotonic() < until:
            time.sleep(.01)
        assert ready.exists(), "fixture producer was not reached"
        evidence = json.loads(ready.read_text())
        producer = evidence["pid"]
        invalid = record in ("nul", "oversize", "closed-invalid")
        if invalid:
            # A known-invalid live record must not postpone refusal/recovery.
            # The deadline starts at that fixture's write, excluding setup.
            try:
                code = p.wait(timeout=max(.01, evidence["started"] + 2.5 - time.monotonic()))
            except subprocess.TimeoutExpired:
                db = json.loads((root / "fixture.json").read_text())
                evidence.update(blocked=True, new_open=db["new_open"])
                raise AssertionError("known-invalid producer blocked refusal/recovery")
            expected = 75 if unconfirmed or phase == "migrate" else 69
            assert code == expected, (code, expected)
        else:
            # Valid fragments and valid EOF retain no observation deadline;
            # even after the shutdown grace interval, status must be awaited.
            time.sleep(1.25)
            assert p.poll() is None, "valid producer was timed out or accepted early"
            assert Path(f"/proc/{producer}").exists(), "valid producer was stopped"
            if reader_evidence:
                # Only a live valid producer is expected to retain fd 1.
                # Invalid producers below have already been stopped/reaped.
                pipe = os.readlink(f"/proc/{producer}/fd/1")
                links = []
                for fd in Path(f"/proc/{p.pid}/fd").iterdir():
                    try:
                        links.append(os.readlink(fd))
                    except FileNotFoundError:
                        pass
                evidence["reader_open"] = pipe in links
                assert evidence["reader_open"], "valid incomplete observation lost its reader"
            (root / "producer-release").touch()
            code = p.wait(timeout=10)
            expected = (69 if phase == "close-admission" else 75) if int(status) else 0
            assert code == expected, (code, expected)
        evidence.update(exit=code, elapsed=round(time.monotonic() - evidence["started"], 3))
        assert not Path(f"/proc/{producer}").exists(), "producer was not reaped"
        assert evidence["parent"] == p.pid, "captured PID must directly own the producer"
        if reader_evidence and invalid:
            # Absence after successful stop is evidence, not an fd-read error.
            db = json.loads((root / "fixture.json").read_text())
            opened = next(i for i, c in enumerate(db["calls"]) if c[:2] == ["platform", "open-new"])
            evidence["reclose_attempted"] = any(c[:2] == ["platform", "close"] for c in db["calls"][opened + 1:])
            assert evidence["reclose_attempted"] and not db["new_open"]
        if unconfirmed:
            diagnostics = (root / "stderr").read_text()
            assert f"unconfirmed observation producer pid={producer}" in diagnostics
            assert "incomplete/unknown" in diagnostics
            assert "verified target cleanup" not in diagnostics
        claims = ["fault-used"]
        if phase == "close-admission":
            claims += ["no-mutation"] if code else ["closed"]
        else:
            claims += ["closed", "unknown"] if code else ["success"]
        for claim in claims:
            assert launch(["python3", fixture, "assert", claim]).wait() == 0, claim
finally:
    # Only fixture-recorded processes are released/signaled; the script owns
    # and reaps its direct producer. No pattern or process-group kills.
    (root / "producer-release").touch()
    if producer is not None and Path(f"/proc/{producer}").exists():
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
        evidence["producer_gone_after_cleanup"] = not Path(f"/proc/{producer}").exists()
        (root / "producer-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
