"""Drive only the installed test product through its public commands."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src" / "sysdiff"))
from inventory import capture, command, digest, output


def require_runner():
    required = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "ETD_G2_CI": "1"}
    if any(os.environ.get(key) != value for key, value in required.items()):
        raise RuntimeError("tier 3 requires a disposable GitHub-hosted runner")
    if os.name != "nt" and os.geteuid() != 0:
        raise RuntimeError("tier 3 requires the elevated CI step")


def eventually(description, read, accept, timeout=75):
    end = time.monotonic() + timeout
    while True:
        last = read()
        if accept(last):
            return last
        if time.monotonic() >= end:
            raise AssertionError(f"timed out waiting for {description}: {last}")
        time.sleep(0.4)


class Service:
    def __init__(self):
        require_runner()
        binaries = Path(os.environ["ETD_G2_BIN"])
        ext = ".exe" if os.name == "nt" else ""
        self.installer = binaries / ("etd-host" + ext)
        self.client = binaries / ("etd-ctl" + ext)
        if sys.platform == "win32":
            base = Path(os.environ["ProgramFiles"]) / "EasyTierDesk"
            self.state = Path(os.environ["ProgramData"]) / "EasyTierDesk"
        elif sys.platform == "darwin":
            base = Path("/Library/Application Support/easytier-desk")
            self.state = base / "state"
        else:
            base = Path("/usr/local/lib/easytier-desk")
            self.state = Path("/var/lib/easytier-desk")
        self.host = base / self.installer.name
        self.cores = base / "cores"
        self.core = self.cores / os.environ["ETD_G2_SHA"] / ("easytier-core" + ext)
        self.runtime = self.state / "run"

    @contextmanager
    def installed(self):
        if self.state.exists() or self.host.exists():
            raise RuntimeError("test needs a fresh service installation")
        self.call(self.installer, "install")
        try:
            assert digest(self.core) == os.environ["ETD_G2_SHA"], "installed core digest"
            status = self.ctl("status")
            assert status["host"]["mode"] == "service" and status["host"]["role"] == "admin"
            assert status["default_core_version"] == "2.7.1", status
            yield self
        finally:
            # Shared driver candidates can legitimately prevent uninstall;
            # retain the native report, never delete drivers to pass cleanup.
            result = command(self.installer, "uninstall", check=False)
            if result.returncode:
                print(f"test service uninstall exited {result.returncode}: {result.stderr.strip()}")
                if sys.exc_info()[0] is None:
                    raise RuntimeError("test service uninstall incomplete")

    @staticmethod
    def call(*args):
        result = command(*args, check=False)
        if result.returncode:
            raise RuntimeError(f"{Path(args[0]).name} {args[1]} exited {result.returncode}: "
                               f"{result.stderr.strip()}")
        return result.stdout

    def ctl(self, *args):
        return json.loads(self.call(self.client, "--json", *args))

    def apply(self, spec, instance, request, revision, check=True):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(spec), encoding="utf-8")
            args = [self.client, "--json", "apply", "--start", "-f", path,
                    "--instance", instance, "--request-id", request, "--expected-revision", revision]
            if check:
                return json.loads(self.call(*args))
            return command(*args, check=False)

    def effects(self):
        # A fresh read transaction, never a second ledger writer.
        uri = (self.state / "ledger.sqlite3").as_uri() + "?mode=ro"
        db = sqlite3.connect(uri, uri=True)
        try:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM effects")]
        finally:
            db.close()

    def receipt(self, tag):
        uri = (self.state / "ledger.sqlite3").as_uri() + "?mode=ro"
        db = sqlite3.connect(uri, uri=True)
        try:
            row = db.execute("SELECT payload FROM requests WHERE id = ?", (tag,)).fetchone()
            return json.loads(row[0])["receipt"] if row else None
        finally:
            db.close()

    def view(self, instance):
        result = command(self.client, "--json", "--timeout", "2", "status", instance, check=False)
        if result.returncode == 3:
            return {}
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)["instances"][0]["status"] or {}

    def ready(self, instance, after=0):
        return eventually("new ready generation", lambda: self.view(instance),
                          lambda s: s.get("state") in ("ready_basic", "ready_full")
                          and s["epoch"] > after)

    def inventory(self, extra=()):
        return capture(self.runtime, [self.host, self.cores, *extra])

    def crash_installed(self, image):
        if image not in (self.host, self.core):
            raise ValueError("expected an installed test image")
        # psutil pins process creation time in kill() and checks PID reuse.
        import psutil
        matches = []
        for proc in psutil.process_iter(["pid", "exe"], ad_value=None):
            exe = proc.info["exe"]
            if exe and Path(exe) == image:
                matches.append(proc)
        assert len(matches) == 1, f"expected one process running {image}, found {len(matches)}"
        target = matches[0]
        target.kill()
        target.wait(15)
        if image == self.host and os.name == "nt":
            eventually("SCM stopped", lambda: output("sc.exe", "query", "easytier-desk-host"),
                       lambda text: "STOPPED" in text)
            self.call("sc.exe", "start", "easytier-desk-host")
        return target.pid


class Desktop:
    def __init__(self, instance, request, revision, directory):
        self.env = dict(os.environ, ETD_G2_INSTANCE=instance, ETD_G2_REQUEST=request,
                        ETD_G2_REVISION=revision)
        self.directory = Path(directory)

    def args(self, action):
        path = self.directory / action
        path.unlink(missing_ok=True)
        return ([os.environ["ETD_G2_TEST_IMAGE"], "--exact", "desktop::peer", "--nocapture"],
                dict(self.env, ETD_G2_DESKTOP=action, ETD_G2_REPLY=str(path)), path)

    @contextmanager
    def connected(self, action):
        args, env, path = self.args(action)
        proc = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            if action == "hold":
                eventually("desktop handshake", path.exists, bool)
            yield
            assert proc.poll() is None, "desktop exited before the simulated UI crash"
        finally:
            proc.kill()
            proc.wait(timeout=10)

    def read(self, action):
        args, env, path = self.args(action)
        result = command(*args, env=env, check=False)
        if result.returncode:
            raise AssertionError(f"desktop {action} failed: {result.stderr}")
        return json.loads(path.read_bytes())
