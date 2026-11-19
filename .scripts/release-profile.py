#!/usr/bin/env python3
"""Main-owned optional native cgo builds and exact release-set collection."""
import json
import os
import pathlib
import platform
import re
import runpy
import shutil
import subprocess
import sys
import tempfile


ARCHITECTURES = {"amd64": ("x86_64", "x86_64-linux-gnu"), "arm64": ("aarch64", "aarch64-linux-gnu")}
GO_FLAGS = ["-trimpath", "-buildvcs=false", "-ldflags=-buildid= -linkmode=external -extldflags=-Wl,--build-id=none"]
C_FLAGS = {"CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_FFLAGS", "CGO_LDFLAGS"}
METADATA = {"SHA256SUMS", "provenance.json", "release-set.json"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def lines(path, optional=False):
    require(not path.is_symlink(), "symlinked-release-policy")
    if optional and not path.exists():
        return []
    content = path.read_text(encoding="ascii")
    values = content.splitlines()
    require(not content or content == "".join(value + "\n" for value in values), "noncanonical-release-policy")
    require(values == sorted(set(values)) and all(values), "noncanonical-release-policy")
    return values


def policy(root):
    packages = lines(root / ".github/release/cgo-packages", optional=True)
    expected = lines(root / ".github/release/expected-artifacts")
    require(expected and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*_linux_(amd64|arm64)", name) for name in expected),
            "invalid-expected-artifacts")
    require(all(re.fullmatch(r"\./cmd/(?:[A-Za-z0-9][A-Za-z0-9_+-]*/)*[A-Za-z0-9][A-Za-z0-9_+-]*", package)
                for package in packages), "invalid-cgo-package-policy")
    require(len({package.rsplit("/", 1)[1] for package in packages}) == len(packages), "duplicate-cgo-command-name")
    selected = {f"{pathlib.PurePosixPath(package).name}_linux_{arch}" for package in packages for arch in ARCHITECTURES}
    require(selected <= set(expected), "cgo-artifact-not-expected")
    return packages, set(expected), selected


def toolchain(root):
    path = root / ".github/release/cgo-toolchain.json"
    require(not path.is_symlink(), "symlinked-release-policy")
    pin = json.loads(path.read_text(encoding="ascii"))
    require(set(pin) == C_FLAGS | {"compiler_version", "libc_version", "image"}, "invalid-cgo-toolchain-policy")
    require(all(isinstance(value, str) and not any(ord(char) < 32 for char in value) for value in pin.values()),
            "invalid-cgo-toolchain-policy")
    require(re.fullmatch(r"gcc:[0-9.]+-bookworm@sha256:[0-9a-f]{64}", pin["image"]), "unpinned-cgo-image")
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pin["compiler_version"]), "unpinned-cgo-compiler")
    require(re.fullmatch(r"glibc [0-9]+\.[0-9]+", pin["libc_version"]), "unpinned-cgo-libc")
    require(pin["CGO_LDFLAGS"] == "-Wl,--build-id=none", "cgo-linker-build-id-not-disabled")
    return pin


def output(command, **kwargs):
    return subprocess.check_output(command, text=True, **kwargs).strip()


def metadata(root):
    return runpy.run_path(str(root / ".scripts/release-metadata.py"))


def exact_files(directory, names):
    require(directory.is_dir() and not directory.is_symlink(), "invalid-artifact-directory")
    require({path.name for path in directory.iterdir()} == set(names), "unexpected-artifact-set")
    require(all(path.is_file() and not path.is_symlink() for path in directory.iterdir()), "missing-or-symlinked-artifact")


def check(directory, root, pure=False):
    packages, expected, selected = policy(root)
    exact_files(directory, (expected - selected if pure else expected) | METADATA)
    subprocess.run([sys.executable, str(root / ".scripts/release-metadata.py"), "check", str(directory)], check=True)


def build(directory, root, source, arch):
    packages, expected, selected = policy(root)
    require(packages, "empty-cgo-policy")
    require(arch in ARCHITECTURES, "unsupported-cgo-architecture")
    machine, target = ARCHITECTURES[arch]
    require(platform.system() == "Linux" and platform.machine() == machine, "native-cgo-runner-required")
    require(not directory.exists(), "new-output-directory-required")
    require(not output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source), "dirty-build-source")
    commit = output(["git", "rev-parse", "HEAD"], cwd=source)
    epoch = output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=source)
    go = shutil.which(os.environ.get("GO", "go"))
    require(go, "go1.26.10-required")
    pin = toolchain(root)
    compiler = shutil.which("gcc")
    cxx = shutil.which("g++")
    require(compiler and cxx, "pinned-cgo-compiler-required")
    require(output([compiler, "-dumpfullversion"]) == pin["compiler_version"] and
            output([cxx, "-dumpfullversion"]) == pin["compiler_version"], "cgo-compiler-version-mismatch")
    require(output([compiler, "-dumpmachine"]) == target, "native-cgo-compiler-required")
    require(output(["getconf", "GNU_LIBC_VERSION"]) == pin["libc_version"], "cgo-libc-version-mismatch")
    tools = {"image": pin["image"], "compiler_version": pin["compiler_version"],
             "compiler": output([compiler, "--version"]).splitlines()[0], "target": target,
             "libc_version": pin["libc_version"], "linker": output(["ld", "--version"]).splitlines()[0]}
    c_environment = {key: pin[key] for key in sorted(C_FLAGS)}
    c_environment.update({"CGO_ENABLED": "1", "CC": "gcc", "CXX": "g++"})
    scratch_parent = pathlib.Path(os.environ["TMPDIR"])
    require(scratch_parent.is_absolute() and scratch_parent.is_dir(), "absolute-private-tmpdir-required")
    work = pathlib.Path(tempfile.mkdtemp(prefix="release-cgo.", dir=scratch_parent)).resolve()
    print(f"Native cgo two-build evidence: {work}", flush=True)
    for attempt in ("first", "second"):
        attempt_root = work / attempt
        for name in ("home", "config", "cache", "tmp", "go-build", "go-mod", "go-path", "dist"):
            (attempt_root / name).mkdir(parents=True, exist_ok=True)
        checkout = attempt_root / "source"
        subprocess.run(["git", "clone", "--quiet", "--no-local", "--no-checkout", str(source), str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", commit], check=True)
        environment = os.environ.copy()
        for name in ("GOTELEMETRYDIR", "CGO_CFLAGS_ALLOW", "CGO_CFLAGS_DISALLOW", "CGO_CPPFLAGS_ALLOW",
                     "CGO_CPPFLAGS_DISALLOW", "CGO_CXXFLAGS_ALLOW", "CGO_CXXFLAGS_DISALLOW",
                     "CGO_LDFLAGS_ALLOW", "CGO_LDFLAGS_DISALLOW", "CGO_FFLAGS_ALLOW", "CGO_FFLAGS_DISALLOW",
                     "PKG_CONFIG_PATH", "PKG_CONFIG_LIBDIR", "PKG_CONFIG_SYSROOT_DIR", "LIBRARY_PATH",
                     "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH"):
            environment.pop(name, None)
        environment.update({"HOME": str(attempt_root / "home"), "USERPROFILE": str(attempt_root / "home"),
                            "XDG_CONFIG_HOME": str(attempt_root / "config"), "XDG_CACHE_HOME": str(attempt_root / "cache"),
                            "TMPDIR": str(attempt_root / "tmp"), "GOTMPDIR": str(attempt_root / "tmp"),
                            "TMP": str(attempt_root / "tmp"), "TEMP": str(attempt_root / "tmp"),
                            "GOCACHE": str(attempt_root / "go-build"), "GOMODCACHE": str(attempt_root / "go-mod"),
                            "GOPATH": str(attempt_root / "go-path"), "GOTOOLCHAIN": "local", "GOWORK": "off",
                            "GOENV": "off", "GOTELEMETRY": "off", "GOOS": "linux", "GOARCH": arch,
                            "GOAMD64": "v1", "GOARM64": "v8.0", "GOEXPERIMENT": "",
                            "GOFLAGS": "-mod=readonly -p=2", "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": epoch})
        environment.update(c_environment)
        require(output([go, "env", "GOVERSION"], env=environment) == "go1.26.10", "go1.26.10-required")
        for package in packages:
            require(output([go, "list", "-f", "{{.Name}}", package], cwd=checkout, env=environment) == "main",
                    "cgo-main-package-required")
            binary = attempt_root / "dist" / f"{pathlib.PurePosixPath(package).name}_linux_{arch}"
            subprocess.run([go, "build", *GO_FLAGS, "-o", str(binary), package], cwd=checkout, env=environment, check=True)
    helpers = metadata(root)
    names = sorted(name for name in selected if name.endswith("_" + arch))
    hashes = {name: helpers["digest"](work / "first/dist" / name) for name in names}
    require(all(helpers["digest"](work / "second/dist" / name) == hashes[name] for name in names),
            "cgo-reproducibility-mismatch")
    receipt = {"architecture": arch, "commit": commit, "go_version": "go1.26.10", "SOURCE_DATE_EPOCH": int(epoch),
               "packages": packages, "toolchain": tools, "environment": c_environment,
               "flags": GO_FLAGS, "reproducibility": {"independent_builds": 2, "sha256": hashes}}
    directory.mkdir()
    for name in names:
        shutil.copy2(work / "first/dist" / name, directory / name)
    (directory / f"cgo_linux_{arch}.json").write_bytes(helpers["canonical"](receipt))


def native_receipt(directory, root, commit, epoch, arch):
    packages, expected, selected = policy(root)
    names = {name for name in selected if name.endswith("_" + arch)}
    receipt_name = f"cgo_linux_{arch}.json"
    exact_files(directory, names | {receipt_name})
    helpers = metadata(root)
    data = (directory / receipt_name).read_bytes()
    receipt = json.loads(data)
    require(data == helpers["canonical"](receipt), "noncanonical-cgo-receipt")
    require(set(receipt) == {"architecture", "commit", "go_version", "SOURCE_DATE_EPOCH", "packages", "toolchain",
                             "environment", "flags", "reproducibility"}, "invalid-cgo-receipt")
    require(receipt["architecture"] == arch and receipt["commit"] == commit and receipt["SOURCE_DATE_EPOCH"] == epoch
            and receipt["go_version"] == "go1.26.10" and receipt["packages"] == packages and receipt["flags"] == GO_FLAGS,
            "cgo-receipt-input-mismatch")
    pin = toolchain(root)
    tools = receipt["toolchain"]
    require(set(tools) == {"image", "compiler_version", "compiler", "target", "libc_version", "linker"},
            "invalid-cgo-toolchain-receipt")
    require(all(tools[key] == pin[key] for key in ("image", "compiler_version", "libc_version")) and
            tools["target"] == ARCHITECTURES[arch][1] and tools["compiler"] and tools["linker"], "cgo-toolchain-receipt-mismatch")
    environment = {key: pin[key] for key in C_FLAGS}
    environment.update({"CGO_ENABLED": "1", "CC": "gcc", "CXX": "g++"})
    require(receipt["environment"] == environment, "cgo-environment-receipt-mismatch")
    require(receipt["reproducibility"] == {"independent_builds": 2,
            "sha256": {name: helpers["digest"](directory / name) for name in sorted(names)}}, "cgo-receipt-digest-mismatch")
    return receipt


def collect(directory, root, commit, pure, native):
    packages, expected, selected = policy(root)
    require(not directory.exists(), "new-output-directory-required")
    check(pure, root, pure=True)
    provenance = json.loads((pure / "provenance.json").read_bytes())
    helpers = metadata(root)
    require(re.fullmatch(r"[0-9a-f]{40,64}", commit), "invalid-build-inputs")
    epoch = output(["git", "show", "-s", "--format=%ct", commit], cwd=root)
    require(provenance == helpers["build_provenance"](commit, "go1.26.10", epoch), "pure-provenance-input-mismatch")
    require(len(native) == (2 if packages else 0), "native-cgo-artifacts-required")
    profiles = [native_receipt(path, root, commit, provenance["SOURCE_DATE_EPOCH"], arch)
                for path, arch in zip(native, ARCHITECTURES)]
    directory.mkdir()
    for source in [pure, *native]:
        for path in source.iterdir():
            if path.name in expected:
                require(not (directory / path.name).exists(), "duplicate-artifact")
                shutil.copy2(path, directory / path.name)
    helpers["create"](directory, commit, "go1.26.10", provenance["SOURCE_DATE_EPOCH"], profiles)
    check(directory, root)


def run():
    mode, *arguments = sys.argv[1:]
    if mode in ("packages", "info"):
        root = pathlib.Path(arguments[0]).resolve()
        packages, expected, selected = policy(root)
        if mode == "packages":
            if packages:
                print("\n".join(packages))
        else:
            print("cgo=" + ("true" if packages else "false"))
            if packages:
                print("cgo_image=" + toolchain(root)["image"])
    else:
        require(len(arguments) >= 2 and all(pathlib.Path(value).is_absolute() for value in arguments[:2]),
                "absolute-output-and-policy-required")
        directory, root = map(pathlib.Path, arguments[:2])
        if mode == "build":
            source = pathlib.Path(arguments[2])
            require(source.is_absolute(), "absolute-source-directory-required")
            build(directory, root, source.resolve(), arguments[3])
        elif mode in ("check", "pure-check"):
            check(directory, root, pure=mode == "pure-check")
        elif mode == "collect":
            require(all(pathlib.Path(value).is_absolute() for value in arguments[3:]), "absolute-input-directories-required")
            collect(directory, root, arguments[2], pathlib.Path(arguments[3]), [pathlib.Path(value) for value in arguments[4:]])
        else:
            raise ValueError("unknown-mode")


if __name__ == "__main__":
    try:
        run()
    except (ValueError, OSError, KeyError, IndexError, TypeError, subprocess.CalledProcessError) as error:
        print(f"release profile: {error}", file=sys.stderr)
        sys.exit(1)
