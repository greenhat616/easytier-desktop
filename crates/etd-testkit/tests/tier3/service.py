"""Drive only the installed test product through its public commands."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
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
        self.retained_drivers = set()

    def verify_bundle(self):
        expected = {self.core.name: os.environ["ETD_G2_SHA"]}
        if os.name == "nt":
            source = self.installer.parent / "cores" / "2.7.1"
            for name in ("Packet.dll", "wintun.dll", "WinDivert64.sys"):
                expected[name] = digest(source / name)
        actual = {}
        for entry in self.core.parent.iterdir():
            assert entry.is_file() and not entry.is_symlink(), entry.name
            actual[entry.name] = digest(entry)
        assert actual == expected, f"installed bundle differs: {sorted(actual)}"
        print(f"installed bundle SHA-256 verified: {sorted(actual.items())}", flush=True)

    def report_effects(self, instance):
        state = self.view(instance)
        print(f"instance epoch={state.get('epoch')} state={state.get('state')}", flush=True)
        for row in self.effects():
            print(f"{row['kind']} {row['state']}: {row.get('last_error') or ''}", flush=True)

    def uninstall(self):
        # SCM and the product reclaimer may still be servicing the outstanding
        # lifecycle request. Read the durable phase even on a subprocess timeout.
        try:
            result = command(self.installer, "uninstall", check=False,
                             timeout=240 if os.name == "nt" else 60)
        except subprocess.TimeoutExpired as error:
            for label, data in (("stdout", error.stdout), ("stderr", error.stderr)):
                print(f"uninstall {label}: {(data or b'').decode('utf-8', 'replace').strip()}")
            self.report_uninstall_phase()
            raise
        if result.returncode:
            print(f"uninstall exited {result.returncode}; stdout={result.stdout.strip()} "
                  f"stderr={result.stderr.strip()}")
            self.report_uninstall_phase()
        return result

    def report_uninstall_phase(self):
        status = command(self.installer, "uninstall", "--status", check=False)
        print(f"uninstall --status ({status.returncode}): "
              f"{status.stdout.strip()} {status.stderr.strip()}", flush=True)

    @contextmanager
    def installed(self):
        if self.state.exists() or self.host.exists():
            raise RuntimeError("test needs a fresh service installation")
        self.call(self.installer, "install")
        try:
            self.verify_bundle()
            status = eventually("installed service self-check", lambda: self.ctl("status"),
                                lambda body: body["host"]["phase"] == "serving")
            assert status["host"]["mode"] == "service" and status["host"]["role"] == "admin"
            assert status["default_core_version"] == "2.7.1", status
            yield self
        finally:
            # Shared driver candidates can legitimately prevent uninstall;
            # retain the native report, never delete drivers to pass cleanup.
            result = self.uninstall()
            if result.returncode:
                if sys.exc_info()[0] is None:
                    pending = [r for r in self.effects() if r["state"] != "reclaimed"]
                    if not self.retained_drivers or not all(
                            r["kind"] == "driver" and r["scope"] == "product"
                            and r["state"] in ("candidate", "conflict") for r in pending):
                        raise RuntimeError("test service uninstall incomplete")
                    assert {r["key"]["name"].lower() for r in pending} == self.retained_drivers

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
        result = command(self.client, "--json", "--timeout", "2", "status", check=False)
        if result.returncode == 3:
            return {}
        if result.returncode:
            raise RuntimeError(result.stderr)
        body = json.loads(result.stdout)
        return next((row["status"] or {} for row in body["instances"]
                     if row["instance_id"] == instance), {})

    def ready(self, instance, after=0):
        def ready_or_failed(status):
            if status.get("state") in ("quarantined", "gave_up", "cut_unconfirmed"):
                raise AssertionError(f"recovery stopped: {status}")
            return status.get("state") in ("ready_basic", "ready_full") and status["epoch"] > after
        try:
            return eventually("new ready generation", lambda: self.view(instance), ready_or_failed,
                              timeout=240 if os.name == "nt" else 75)
        except AssertionError:
            self.report_effects(instance)
            logs = command(self.client, "--json", "logs", instance, "--tail", "100", check=False)
            for line in logs.stdout.splitlines():
                entry = json.loads(line)
                text = entry.get("text", "")
                if (re.search(r"error|fail|denied|invalid|panic|not found|unsupported", text, re.I)
                        and not re.search(r"secret|password|token|key[ =]|g2-log-probe", text, re.I)):
                    print(f"{entry.get('source')}: {text[:500]}")
            raise

    def inventory(self, extra=(), other_run_dirs=()):
        return capture(self.runtime, [self.host, self.cores, *extra], other_run_dirs)

    def stop(self):
        if os.name == "nt":
            self.call("sc.exe", "stop", "easytier-desk-host")
            eventually("SCM stopped", lambda: output("sc.exe", "query", "easytier-desk-host"),
                       lambda text: "STOPPED" in text)
        elif sys.platform == "darwin":
            self.call("launchctl", "bootout", "system/easytier-desk-host")
        else:
            self.call("systemctl", "stop", "easytier-desk-host.service")

    def start(self):
        if os.name == "nt":
            self.call("sc.exe", "start", "easytier-desk-host")
        elif sys.platform == "darwin":
            self.call("launchctl", "bootstrap", "system",
                      "/Library/LaunchDaemons/easytier-desk-host.plist")
        else:
            self.call("systemctl", "start", "easytier-desk-host.service")

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
            self.start()
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
