"""Replay bounded B2 source overlays; never modify the tested checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


MUTANTS = [
    ("format", "internal/labtimev0/records_linux.go", "if text != grammar[1:] {", "if false {", "./internal/labcontractv0", "TestLabB2CatalogueGrammarPairs", "A01", "closed singleton format"),
    ("owner-role", "internal/labtimev0/continuity_linux.go", "!role.Accepted || roles[role.Role]", "roles[role.Role]", "./internal/labtimev0", "TestLabCOpening", "A06", "every named owner role accepts"),
    ("fence-replay", "internal/labtimev0/continuity_linux.go", "|| fence.Consumed ||", "||", "./internal/labtimev0", "TestLabStartJoins", "A06", "consumed fence cannot authorize another start"),
    ("exact-heads", "internal/labtimev0/continuity_linux.go", "|| fence.Heads != pins.Heads", "", "./internal/labtimev0", "TestLabStartJoins", "A06", "off-VM and fence heads equal independent pins"),
    ("off-home", "internal/labtimev0/fence_linux.go", "return path != home && !strings.HasPrefix(path, home+\"/\") && !strings.HasPrefix(home, filepath.Dir(path)+\"/\") && filepath.Dir(path) != home", "return true", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "even a regular protected fence inside home refuses"),
    ("fence-mode", "internal/labtimev0/fence_linux.go", "before.Mode != unix.S_IFREG|0644", "before.Mode & unix.S_IFMT != unix.S_IFREG", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "fence mode must be exactly 0644"),
    ("fence-group", "internal/labtimev0/fence_linux.go", "|| before.Gid != group", "", "./internal/labtimev0", "TestLabRootFenceOneUse", "A06", "fence group must match the protected root group"),
    ("watermark", "internal/labtimev0/continuity_linux.go", "!instant(next.Lower).After(instant(old.Watermark))", "instant(next.Lower).Before(instant(old.Watermark))", "./internal/labtimev0", "TestLabCheckpointContinuity", "A06", "lower bound must strictly exceed retained W"),
    ("manager-prefix", "internal/labtimev0/continuity_linux.go", "genjournal.Floor{Seq: int64(prior.Sequence), Hash: strings.TrimPrefix(prior.SHA256, \"sha256:\")}", "genjournal.Floor{Seq: 0, Hash: strings.TrimPrefix(\"sha256:\"+genjournal.ZeroHash, \"sha256:\")}", "./internal/labtimev0", "TestLabManagerPrefix", "A06", "well-formed alternate history is not an extension"),
    ("floor-prefix", "internal/labtimev0/continuity_linux.go", "|| next.Previous != old.Manager", "", "./internal/labtimev0", "TestLabFloorContinuity", "A06", "publication retains the prior verified prefix"),
    ("witness-cas", "timeconf/lab_linux.go", "|| current != old ||", "|| current.Generation < old.Generation ||", "./timeconf", "TestLabWitnessDurableCAS", "A06", "CAS compares the exact old durable head"),
    ("floor-sync", "timeconf/lab_linux.go", "|| session.sync(session.dir, \"lab-floor-current\") != nil", "", "./timeconf", "TestLabFloorDurabilityFaults", "A06", "receipt release executes the directory sync boundary"),
    ("nts-only", "timeconf/provider.go", "!e.Sources.AllNTS ||", "", "./timeconf", "TestLabConsumerAuthenticatedNTS", "A06", "plain NTP cannot supply an authenticated settlement"),
    ("sticky-floor", "timeconf/lab_linux.go", "floor.Holds, floor.Checkpoint = append([]string(nil), checkpoint.Holds...), sum(checkpointRaw)", "floor.Checkpoint = sum(checkpointRaw)", "./timeconf", "TestLabConsumerStickyRestart", "A06", "C0 incident publication retains the sticky hold"),
    ("burned-reopen", "timeconf/lab_linux.go", "\"lab-burned\", &stat", "\"lab-no-burn\", &stat", "./timeconf", "TestLabBurnPersists", "A06", "durable burn closes reconstructed consumers"),
    ("start-burn", "timeconf/lab_linux.go", "floor.Manager != expected.Manager {\n\t\tlab.burn(ctx)", "floor.Manager != expected.Manager {\n\t\tlab.failed = true", "./timeconf", "TestLabStartContinuityBurn", "A06", "restore/head mismatch durably burns even with missing old metadata"),
    ("c1-hold-reset", "internal/labtimev0/continuity_linux.go", "|| !slices.Contains([]string{\"restore\", \"clone\", \"regression\"}, recovery.Reason)", "", "./internal/labtimev0", "TestLabBurnedRecovery", "A06", "C1 is not an ordinary hold reset route"),
    ("qualification-expiry", "internal/labtimev0/continuity_linux.go", "|| !instant(checkpoint.Watermark).Before(bound)", "", "./internal/labtimev0", "TestLabQualificationDeadline", "A07", "settled W must be strictly below exclusive expiry"),
    ("build-graph", "internal/assemblyv0/importgraph_test.go", "if !allowed {", "if false && !allowed {", "./internal/assemblyv0", "TestInactiveImportGraphBuildTagControlsLabTime", "A01", "graph instrument detects a planted default import"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    work = Path.cwd().resolve()
    out = args.out.resolve()
    root = work.parent
    if work.name != "work" or root.name != ".temp" or not out.is_relative_to(root):
        parser.error("run from physical task .temp/work; outputs must be inside that .temp")
    for name in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR"):
        value = Path(os.environ.get(name, ""))
        if not value.is_absolute() or not value.resolve().is_relative_to(root):
            parser.error(name + " must be an absolute task-local path")
    out.mkdir(parents=True, exist_ok=False)
    results = []
    for name, relative, old, new, package, test, row, bound in MUTANTS:
        directory = out / name
        directory.mkdir()
        original = work / relative
        source = original.read_text()
        count = source.count(old)
        expected = 2 if name == "burned-reopen" else 1
        if count != expected:
            raise RuntimeError(name + ": source anchor count " + str(count))
        replacement = directory / original.name
        replacement.write_text(source.replace(old, new))
        overlay = directory / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(original): str(replacement)}}))
        command = [os.environ.get("GO", "go"), "test", "-count=1", "-tags", "broker_lab", "-overlay", str(overlay), package, "-run", "^" + test + "$"]
        with (directory / "test.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            (directory / "pid").write_text(str(process.pid) + "\n")
            exit_code = process.wait()
        text = (directory / "test.log").read_text(errors="replace")
        named = "--- FAIL: " + test + " " in text
        invalid = any(marker in text for marker in ("[build failed]", "[setup failed]", "panic:", "fatal error:"))
        verdict = "KILLED" if exit_code != 0 and named and not invalid else "SURVIVED_OR_INVALID"
        result = dict(mutant=name, row=row, bound=bound, test=test, exit=exit_code, verdict=verdict,
                      command=command, source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                      overlay_sha256=hashlib.sha256(replacement.read_bytes()).hexdigest())
        (directory / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")
        results.append(result)
        print(name, verdict, "exit=" + str(exit_code), test, flush=True)
    (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    lines = ["| Mutant | Row | Gate narrowed to | Named failing test | Exit | Verdict |", "|---|---|---|---|---|---|"]
    lines.extend("| {mutant} | {row} | {bound} | `{test}` | {exit} | {verdict} |".format(**result) for result in results)
    (out / "results.md").write_text("\n".join(lines) + "\n")
    return 0 if all(result["verdict"] == "KILLED" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
