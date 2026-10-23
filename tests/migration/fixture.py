#!/usr/bin/env python3
"""Metadata-only command doubles and fault controller; never used by deployment.

Python's standard library supplies durable JSON call records, real lstat/inode
checks and timestamp observations without installing a test dependency. Account,
manager, ownership and mount operations are simulated; payload files are not read.
"""
import json
import os
from pathlib import Path
import signal
import stat
import sys

ROOT = Path(os.environ["MIGRATION_FIXTURE"])
DB = ROOT / "fixture.json"
COMMANDS = ("id", "stat", "mountpoint", "getent", "find", "cat", "sha256sum",
            "flock", "sync", "groupadd", "useradd", "mkdir", "mv", "chown",
            "chmod", "rmdir", "userdel", "groupdel", "platform")
INVENTORY = "a" * 64
SERIALIZATION = "b" * 64
EVIDENCE = "c" * 64
CANARY = "SYNTHETIC_CREDENTIAL_DO_NOT_READ_7b329"


def load():
    return json.loads(DB.read_text())


def save(db):
    DB.write_text(json.dumps(db, sort_keys=True))


def init():
    for name in ("bin", "parent", "old", "state", "source", "unrelated"):
        (ROOT / name).mkdir(mode=0o700)
    (ROOT / "parent").chmod(0o755)
    (ROOT / "state/lock").touch(mode=0o600)
    (ROOT / "source/records").mkdir(mode=0o700)
    for name in ("credential.fixture", "records/attempt.fixture", "records/outcome.fixture"):
        p = ROOT / "source" / name
        p.write_text(CANARY if name == "credential.fixture" else "retained synthetic record")
        p.chmod(0o600)
        os.utime(p, ns=(1_000_000_000, p.stat().st_mtime_ns))
    driver = ROOT / "bin/platform"
    for name in COMMANDS:
        (ROOT / "bin" / name).symlink_to(Path(__file__).resolve())
    shell = ROOT / "nologin"
    shell.touch(mode=0o700)
    cfg = dict(old_user="former", old_uid="21001", old_gid="21001", user="service",
               uid="21002", group="service", gid="21002", home=str(ROOT / "parent/new"),
               parent=str(ROOT / "parent"), source=str(ROOT / "source"),
               destination=str(ROOT / "parent/new/data"), state=str(ROOT / "state"),
               driver=str(driver), shell=str(shell))
    (ROOT / "config").write_text("\n".join(f"{k}={v}" for k, v in cfg.items()) + "\n")
    (ROOT / "config").chmod(0o600)
    old = f"former:x:21001:21001:::{shell}"
    metadata = {}
    for p in [ROOT / "source", *(ROOT / "source").rglob("*")]:
        metadata[str(p)] = {"uid": 21001, "gid": 21001}
    atimes = {str(p): p.stat().st_atime_ns for p in (ROOT / "source").rglob("*") if p.is_file()}
    save(dict(passwd={"former": old}, group={}, metadata=metadata, calls=[], counts={},
              faults=[], mounts=[], old_closed=False, new_open=False, old_disabled=False,
              installed=False, started=False, evidence=True, serialization=True, cfg=cfg,
              original_atimes=atimes, unrelated_id=(ROOT / "unrelated").stat().st_ino))


def arguments_without_options(args):
    return args[args.index("--") + 1:] if "--" in args else args


def stat_line(db, p):
    s = os.lstat(p)
    md = db["metadata"].get(str(p), {})
    mode = md.get("mode", stat.S_IMODE(s.st_mode))
    # Fixture roots and their actual host ancestors model protected root-owned
    # ancestry. No operation changes real ownership or host metadata.
    uid, gid = md.get("uid", 0), md.get("gid", 0)
    dev = md.get("dev", s.st_dev)
    raw_mode = stat.S_IFMT(s.st_mode) | mode
    if Path(p) in [ROOT, ROOT.parent] or ROOT not in Path(p).parents:
        mode = 0o755
        raw_mode = stat.S_IFMT(s.st_mode) | mode
    return f"{dev}:{s.st_ino}:{uid}:{gid}:{mode:o}:{s.st_nlink}:{raw_mode:x}:{s.st_size}:{int(s.st_mtime)}:{int(s.st_ctime)}"


def effect(db, cmd, args):
    if cmd == "id":
        return "0\n", 0
    if cmd == "stat":
        p = Path(args[-1])
        # The platform double is a real symlink in PATH, but the configured
        # protected driver is modeled as the executable regular file it names.
        if p == ROOT / "bin/platform":
            s = os.stat(p)
            return f"{s.st_dev}:{s.st_ino}:0:0:755:1:81ed:{s.st_size}:{int(s.st_mtime)}:{int(s.st_ctime)}", 0
        return stat_line(db, p), 0
    if cmd == "mountpoint":
        return "", 0 if args[-1] in db["mounts"] else 32
    if cmd == "getent":
        which, key = args
        for name, entry in db[which].items():
            if name == key or entry.split(":")[2] == key:
                return entry + "\n", 0
        return "", 2
    if cmd == "find":
        base = Path(args[0])
        if not base.is_dir():
            return "", 1
        fmt = args[-1]
        if "-name" in args:
            name = args[args.index("-name") + 1]
            return name if os.path.lexists(base / name) else "", 0
        entries = [base]
        for current, dirs, files in os.walk(base, followlinks=False):
            entries.extend(Path(current) / n for n in dirs + files)
        if fmt == ".":
            return "." * len(entries), 0
        return "".join(str(p.relative_to(base)) .replace(".", "", 1) + "\n" if p == base
                       else str(p.relative_to(base)) + "\n" for p in entries), 0
    if cmd == "cat":
        p = Path(args[-1])
        if ROOT / "source" == p or ROOT / "source" in p.parents or ROOT / "parent/new/data" in p.parents:
            db["forbidden_read"] = True
            return "", 99
        return p.read_text(), 0
    if cmd == "sha256sum":
        import hashlib
        if args:
            p = Path(args[-1])
            if p != ROOT / "config":
                db["forbidden_read"] = True
                return "", 99
            content = p.read_bytes()
        else:
            content = sys.stdin.buffer.read()
        return hashlib.sha256(content).hexdigest() + "  -\n", 0
    if cmd in ("flock", "sync"):
        return "", 0
    if cmd == "groupadd":
        name = args[-1]
        gid = args[args.index("--gid") + 1]
        db["group"][name] = f"{name}:x:{gid}:"
    elif cmd == "useradd":
        name = args[-1]
        uid = args[args.index("--uid") + 1]
        gid = args[args.index("--gid") + 1]
        home = args[args.index("--home-dir") + 1]
        shell = args[args.index("--shell") + 1]
        db["passwd"][name] = f"{name}:x:{uid}:{gid}::{home}:{shell}"
    elif cmd == "mkdir":
        Path(args[-1]).mkdir(mode=0o700)
    elif cmd == "mv":
        if "--no-copy" not in args or "--no-clobber" not in args or "-T" not in args:
            return "", 99
        a, b = map(Path, arguments_without_options(args))
        if os.path.lexists(b):
            return "", 1
        os.rename(a, b)
        for name, md in list(db["metadata"].items()):
            if name == str(a) or name.startswith(str(a) + "/"):
                db["metadata"][str(b) + name[len(str(a)):]] = db["metadata"].pop(name)
    elif cmd == "chown":
        owner, p = arguments_without_options(args)
        uid, gid = map(int, owner.split(":"))
        db["metadata"].setdefault(p, {}).update(uid=uid, gid=gid)
    elif cmd == "chmod":
        mode, p = arguments_without_options(args)
        db["metadata"].setdefault(p, {})["mode"] = int(mode, 8)
    elif cmd == "rmdir":
        Path(args[-1]).rmdir()
    elif cmd == "userdel":
        del db["passwd"][args[-1]]
    elif cmd == "groupdel":
        del db["group"][args[-1]]
    elif cmd == "platform":
        action = args[0]
        if action == "inventory":
            return f"inventory:{INVENTORY}:serialized:{SERIALIZATION}", 0 if db["serialization"] else 1
        if action == "close":
            db.update(old_closed=True, new_open=False, old_disabled=True, started=False)
        elif action == "closed":
            return f"closed:{INVENTORY}:old-inactive:old-disabled:new-disabled", 0 if db["old_closed"] and not db["new_open"] and db["old_disabled"] else 1
        elif action == "evidence":
            return f"reconciled:{EVIDENCE}:original-manager:complete-absence:durable-outcomes", 0 if db["evidence"] else 1
        elif action == "install-and-repin":
            db["installed"] = True
        elif action == "installed":
            return f"installed:{INVENTORY}:uid=21002:leases-invalidated:clients-repinned", 0 if db["installed"] else 1
        elif action == "prestart":
            return f"ready:{INVENTORY}:containment:store-outcomes:policy:qualification:admission-closed", 0 if db["installed"] and not db["new_open"] else 1
        elif action == "start-new":
            db["started"] = True
        elif action == "readiness":
            return f"ready:{INVENTORY}:new-active:old-disabled:admission-closed", 0 if db["started"] and not db["new_open"] else 1
        elif action == "open-new":
            db["new_open"] = True
        elif action == "final":
            return f"active:{INVENTORY}:new-open:old-disabled", 0 if db["new_open"] else 1
        else:
            return "", 99
    else:
        return "", 99
    return "", 0


def run_command(cmd, args):
    db = load()
    key = cmd + (":" + args[0] if cmd == "platform" else "")
    db["counts"][key] = db["counts"].get(key, 0) + 1
    db["calls"].append([cmd, *args])
    expected_intents = dict(groupadd="create-group", useradd="create-user", mkdir="create-home",
                            mv=("move-store", "restore-store"), chown=("normalize-owner:", "restore-owner:", "home-owner"),
                            chmod=("normalize-mode:", "restore-mode:"), rmdir="remove-home", userdel="remove-user", groupdel="remove-group")
    expected = expected_intents.get(cmd)
    if cmd == "platform" and args[0] in ("close", "install-and-repin", "start-new", "open-new"):
        expected = ("close-admission", "recovery-close") if args[0] == "close" else args[0]
    if expected:
        journal = ROOT / "state/journal"
        intents = [x.removeprefix("intent:") for x in journal.read_text().splitlines() if x.startswith("intent:")] if journal.exists() else []
        expected = (expected,) if isinstance(expected, str) else expected
        if not intents or not any(intents[-1].startswith(x) for x in expected):
            db["missing_intent"] = True
            save(db)
            return 98
    fault = None
    for f in db["faults"]:
        if f.get("used"):
            continue
        if f.get("after_command") and not db["counts"].get(f["after_command"], 0):
            continue
        if f["command"] != key or f.get("nth", db["counts"][key]) != db["counts"][key]:
            continue
        if f.get("contains") and f["contains"] not in " ".join(args):
            continue
        fault = f
        fault["used"] = True
        break
    if fault and fault["mode"] == "before":
        out, code = fault.get("output", ""), fault.get("status", 1)
    else:
        try:
            out, code = effect(db, cmd, args)
        except (OSError, KeyError, ValueError):
            out, code = "", 1
        if fault:
            if fault.get("reappear"):
                p = ROOT / "source"
                p.mkdir(mode=0o700)
                (p / "unrelated").write_text("unrelated")
            if fault.get("replace_home"):
                db["metadata"][str(ROOT / "parent/new")] = {"uid": 29000, "gid": 29000}
            if fault["mode"] in ("after", "expected"):
                code = fault.get("status", 1)
    save(db)
    if fault and fault["mode"] == "term":
        # State is committed, but no output/exit bookkeeping reached the shell.
        os.kill(os.getppid(), signal.SIGTERM)
    sys.stdout.write(out)
    return code


def control(args):
    action = args[0]
    if action == "init":
        init()
    elif action == "fault":
        db = load()
        db["faults"].append(json.loads(args[1]))
        save(db)
    elif action == "confirm":
        db = load()
        fingerprint = (ROOT / "state/closed").read_text().strip().split(":")[-1]
        p = ROOT / "state/confirmation"
        p.write_text("I_HAVE_RECONCILED_ALL_WRITERS_AND_DURABLE_OUTCOMES:" + fingerprint + ":" + EVIDENCE + "\n")
        p.chmod(0o600)
    elif action == "scenario":
        db = load()
        which = args[1]
        if which == "user":
            db["passwd"]["service"] = "service:x:21002:21002:unrelated:/unrelated:/unrelated"
        elif which == "group":
            db["group"]["service"] = "service:x:21002:unrelated"
        elif which == "home":
            (ROOT / "parent/new").mkdir()
        elif which == "destination":
            (ROOT / "parent/new/data").mkdir(parents=True)
        elif which == "device":
            db["metadata"][str(ROOT / "source")]["dev"] = 9999999
        elif which == "symlink":
            (ROOT / "source/link").symlink_to(ROOT / "unrelated")
            db["metadata"][str(ROOT / "source/link")] = {"uid": 21001, "gid": 21001}
        elif which == "hardlink":
            os.link(ROOT / "source/credential.fixture", ROOT / "source/hardlink")
            db["metadata"][str(ROOT / "source/hardlink")] = {"uid": 21001, "gid": 21001}
        elif which == "mount":
            db["mounts"].append(str(ROOT / "source/records"))
        elif which == "evidence":
            db["evidence"] = False
        elif which == "stale":
            p = ROOT / "state/confirmation"
            p.write_text(p.read_text().replace(EVIDENCE, "d" * 64))
        elif which == "stale-store":
            (ROOT / "source/records/new.fixture").touch(mode=0o600)
            db["metadata"][str(ROOT / "source/records/new.fixture")] = {"uid": 21001, "gid": 21001}
        else:
            raise AssertionError(which)
        save(db)
    elif action == "assert":
        db = load()
        claim = args[1]
        mutations = {"groupadd", "useradd", "mkdir", "mv", "chown", "chmod", "rmdir", "userdel", "groupdel"}
        target_calls = [c for c in db["calls"] if c[0] in mutations or (c[0] == "platform" and c[1] in ("close", "install-and-repin", "start-new", "open-new"))]
        if claim == "no-mutation":
            assert not target_calls, target_calls
        elif claim == "no-migration":
            assert not any(c[0] in mutations or c[:2] == ["platform", "install-and-repin"] for c in target_calls)
        elif claim == "closed":
            assert db["old_closed"] and db["old_disabled"] and not db["new_open"]
        elif claim == "success":
            assert db["new_open"] and db["old_disabled"] and db["installed"]
            assert not (ROOT / "source").exists()
            assert (ROOT / "parent/new/data/credential.fixture").is_file()
            assert (ROOT / "state/result").read_text().startswith("verified:")
            assert not any(c[0] in ("userdel", "groupdel", "rmdir") for c in db["calls"])
        elif claim == "restored":
            assert (ROOT / "source/credential.fixture").is_file()
            assert not (ROOT / "parent/new").exists()
            assert "service" not in db["passwd"] and "service" not in db["group"]
            assert "recovery:verified-target-cleanup" in (ROOT / "state/journal").read_text()
        elif claim == "unknown":
            assert "recovery:verified-target-cleanup" not in (ROOT / "state/journal").read_text()
            assert "incomplete/unknown" in (ROOT / "stderr").read_text()
        elif claim == "reappeared":
            assert (ROOT / "source/unrelated").read_text() == "unrelated"
            assert (ROOT / "parent/new/data/credential.fixture").is_file()
        elif claim == "partial-group":
            assert "service" in db["group"]
            assert not any(c[0] == "groupdel" for c in db["calls"])
        elif claim == "no-open":
            assert not any(c[:2] == ["platform", "open-new"] for c in db["calls"])
        elif claim == "fault-used":
            assert db["faults"] and all(f.get("used") for f in db["faults"]), db["faults"]
        else:
            raise AssertionError(claim)
        # Every assertion also checks the stable unrelated identity, the lack of
        # credential-bearing command reads and payload atimes, and clean output.
        assert (ROOT / "unrelated").stat().st_ino == db["unrelated_id"]
        assert not db.get("forbidden_read")
        assert not db.get("missing_intent")
        for name, atime in db["original_atimes"].items():
            p = Path(name)
            if not p.exists():
                p = ROOT / "parent/new/data" / p.relative_to(ROOT / "source")
            assert p.stat().st_atime_ns == atime, p
        for name in ("stdout", "stderr", "state/journal", "state/preflight", "state/result"):
            p = ROOT / name
            if p.exists():
                assert CANARY not in p.read_text()
    else:
        raise AssertionError(action)


if __name__ == "__main__":
    name = Path(sys.argv[0]).name
    if name in COMMANDS:
        sys.exit(run_command(name, sys.argv[1:]))
    control(sys.argv[1:])
