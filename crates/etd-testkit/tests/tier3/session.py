"""Elevated session host acceptance (ES5, doc#13#wbs, topic#51 msg#2183) on the
disposable Windows privileged runner: the portable layout (etd-host.exe with
its bundled kernels in a user-writable directory), driven only through its
public commands. This test image, copied beside the host as etd-ui.exe,
holds the lease the way the UI does."""

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

from service import command, eventually, require_runner
from consistency import (
    adapter_defaults, check_closed, managed_service_changes, record_windows_adapter, runner_noise, scope,
    system_policy_changes, tun_created,
)
from inventory import assert_exited, capture

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
EXIT_SERVICE_INSTALLED = 3
EXIT_NOT_CONFORMING = 4
SHARED_DRIVERS = ("wintun", "windivert")


def spec():
    return {"display_name": "ES5 session", "network_name": "es5-ci",
            "ipv4_cidr": "192.0.2.57/28", "no_listener": True,
            "flags": {"disable_ipv6": True, "disable_udp_hole_punching": True}}


def current_sid():
    line = command("whoami", "/user", "/fo", "csv", "/nh").stdout.strip()
    return line.rsplit(",", 1)[-1].strip('"')


class Session:
    def __init__(self, stack):
        require_runner()
        binaries = Path(os.environ["ETD_G2_BIN"])
        self.dir = Path(stack.enter_context(
            tempfile.TemporaryDirectory(prefix="etd-es5-", dir=os.environ["RUNNER_TEMP"],
                                        ignore_cleanup_errors=True)))
        for name in ("etd-host.exe", "etd-ctl.exe"):
            shutil.copy2(binaries / name, self.dir / name)
        shutil.copytree(binaries / "cores", self.dir / "cores")
        shutil.copy2(os.environ["ETD_G2_TEST_IMAGE"], self.dir / "etd-ui.exe")
        self.host = self.dir / "etd-host.exe"
        self.client = self.dir / "etd-ctl.exe"
        self.ui = self.dir / "etd-ui.exe"
        self.root = Path(os.environ["ProgramData"]) / "EasyTierDesk.session" / current_sid()
        self.state = self.root / "state"
        self.runtime = self.root / "run"
        self.cores = self.root / "cores"
        self.core = self.cores / os.environ["ETD_G2_SHA"] / "easytier-core.exe"
        self.process = None
        self.lease = None
        self.log = self.dir / "host-stderr.log"
        self.adapter_indices = {}
        stack.callback(self.teardown)

    # -- the host and the UI's lease ------------------------------------
    def run(self, *args):
        return command(self.host, *args, check=False, timeout=180)

    def start(self):
        with self.log.open("ab") as log:
            self.process = subprocess.Popen([self.host, "run", "--mode", "elevated-session"],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=log, creationflags=NO_WINDOW)
        reply = self.dir / "lease-reply"
        reply.unlink(missing_ok=True)
        env = dict(os.environ, ETD_G2_DESKTOP="hold", ETD_G2_SESSION_DIR=str(self.dir),
                   ETD_G2_INSTANCE="lease", ETD_G2_REQUEST="lease", ETD_G2_REVISION="0",
                   ETD_G2_REPLY=str(reply))
        self.lease = subprocess.Popen([self.ui, "--exact", "desktop::peer", "--nocapture"],
                                      env=env, stdin=subprocess.DEVNULL, creationflags=NO_WINDOW)
        try:
            eventually("UI lease connection", lambda: reply.exists() or self.process.poll() is not None,
                       bool, timeout=120)
        except AssertionError:
            self.report_log()
            raise
        if self.process.poll() is not None:
            self.report_log()
            raise AssertionError(f"session host exited {self.process.returncode} at start")
        status = eventually("session host serving", lambda: self.ctl("status"),
                            lambda body: body["host"]["phase"] == "serving")
        assert status["host"]["mode"] == "elevated_session", status["host"]
        assert status["host"]["role"] == "admin", status["host"]
        return status

    def drop_lease(self):
        if self.lease is not None:
            self.lease.kill()
            self.lease.wait(timeout=10)
            self.lease = None

    def release(self):
        """The UI goes away: the host stops its kernels and exits after the
        30 s lease grace."""
        self.drop_lease()
        code = self.process.wait(timeout=180)
        assert code == 0, f"session host exited {code} after the lease grace"
        self.process = None

    def teardown(self):
        self.drop_lease()
        if self.process is not None and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=30)
        self.report_log()

    def report_log(self):
        if self.log.exists():
            text = self.log.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                print(f"session host stderr (last 2000 chars):\n{text[-2000:]}", flush=True)

    # -- public commands -----------------------------------------------
    def ctl_raw(self, *args, timeout_arg=None):
        extra = ["--timeout", str(timeout_arg)] if timeout_arg else []
        return command(self.client, "--host", "elevated-session", "--host-dir", self.dir, "--json",
                       *extra, *args, check=False)

    def ctl(self, *args):
        result = self.ctl_raw(*args)
        if result.returncode:
            raise RuntimeError(f"etd-ctl {args[0]} exited {result.returncode}: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def apply(self, body, instance, request, revision):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(body), encoding="utf-8")
            return self.ctl("apply", "--start", "-f", path, "--instance", instance,
                            "--request-id", request, "--expected-revision", revision)

    def view(self, instance):
        result = self.ctl_raw("status", timeout_arg=2)
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
                              timeout=240)
        except AssertionError:
            for row in self.effects():
                print(f"{row['kind']} {row['state']}: {row.get('last_error') or ''}", flush=True)
            raise

    def track_adapter(self, baseline, instance, view):
        """Record the running generation's adapter, whose default values
        Windows keeps after it goes away (consistency.adapter_defaults)."""
        live = self.inventory()
        tuns = [r for r in self.effects() if r["kind"] == "win.tun"
                and r["scope"] == scope(instance, view["epoch"]) and r["state"] != "reclaimed"]
        assert len(tuns) == 1, "expected a single adapter record for the running generation"
        record_windows_adapter(baseline, live, tuns[0]["key"], view["interface_name"], self.adapter_indices)

    def purge(self):
        """Purge the session root. A root a shared driver's registration
        still references is retained, and the command says so."""
        # Only --all-users removes the roots (cli-and-install.md, reclaim);
        # an elevated administrator may run it.
        result = self.run("reclaim", "--mode", "elevated-session", "--all-users", "--all", "--purge")
        print(f"purge: exit {result.returncode}: {result.stdout.strip()} {result.stderr.strip()}", flush=True)
        assert result.returncode == 0, f"purge exited {result.returncode}: {result.stderr}"
        if self.root.exists():
            remaining = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
            print(f"purge output: {result.stdout.strip()} {result.stderr.strip()}", flush=True)
            print(f"retained session root entries: {remaining}", flush=True)
            assert "retained" in (result.stdout + result.stderr).lower(),                 "the purge left the session root without saying why"
        return result

    def effects(self):
        ledger = self.state / "ledger.sqlite3"
        if not ledger.exists():
            return []
        db = sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True)
        try:
            return [json.loads(row[0]) for row in db.execute("SELECT payload FROM effects")]
        finally:
            db.close()

    def inventory(self):
        return capture(self.runtime, [self.dir, self.cores])

    def crash(self, image):
        import psutil
        matches = [p for p in psutil.process_iter(["pid", "exe"], ad_value=None)
                   if p.info["exe"] and Path(p.info["exe"]) == image]
        assert len(matches) == 1, f"expected one process running {image}, found {len(matches)}"
        matches[0].kill()
        matches[0].wait(15)
        return matches[0].pid

    def kernels(self):
        import psutil
        psutil.process_iter.cache_clear()
        return [p for p in psutil.process_iter(["pid", "exe"], ad_value=None)
                if p.info["exe"] and Path(p.info["exe"]).name.lower() == "easytier-core.exe"]


def machine_delta(before, after, adapter_indices):
    delta = before.delta(after) - managed_service_changes(before, after)
    delta -= runner_noise(before, after) | tun_created(before, after)
    delta -= adapter_defaults(before, after, adapter_indices)
    delta -= system_policy_changes(before, after, "uninstalled")
    # The shared drivers are re-ensured by every host and never deleted.
    for name in SHARED_DRIVERS:
        key = ("service", name)
        if key not in before.rows and key in after.rows:
            delta.discard(key)
    return delta


def recovery():
    """Start, kill the kernel, kill the host, then the next start's
    self-check reclaims; the lease grace ends the host; the purge leaves the
    machine as before (doc#13#wbs ES5, first item)."""
    with ExitStack() as stack:
        session = Session(stack)
        before = session.inventory()
        status = session.start()
        instance, request = str(uuid.uuid4()), str(uuid.uuid4())
        session.apply(spec(), instance, request, str(status["revision"]))
        first = session.ready(instance)
        session.track_adapter(before, instance, first)
        print(f"session kernel ready: {first['state']} epoch={first['epoch']}", flush=True)
        assert session.core.is_file(), "the kernel runs from the protected session store"

        old = first["epoch"]
        session.crash(session.core)
        first = session.ready(instance, after=old)
        session.track_adapter(before, instance, first)
        check_closed(session, instance, old)
        print(f"after the kernel crash: epoch {first['epoch']}", flush=True)

        old = first["epoch"]
        kernels = {(p.pid, p.create_time()) for p in session.kernels()}
        host_pid = session.crash(session.host)
        session.process = None
        session.drop_lease()
        open_records = [r for r in session.effects() if r["state"] != "reclaimed"]
        assert open_records, "a crashed host leaves open records for the next start"
        session.start()
        first = session.ready(instance, after=old)
        session.track_adapter(before, instance, first)
        check_closed(session, instance, old)
        assert_exited(kernels, timeout=30)
        print(f"after the host crash ({host_pid}): the self-check reclaimed epoch {old}, "
              f"now epoch {first['epoch']}", flush=True)

        session.ctl("stop", instance)
        eventually("stopped instance", lambda: session.view(instance),
                   lambda body: body.get("state") == "stopped", timeout=240)
        check_closed(session, instance, first["epoch"])
        session.release()
        assert not session.kernels(), "no kernel outlives the session host"

        session.purge()
        after = session.inventory()
        delta = machine_delta(before, after, session.adapter_indices)
        assert not delta, f"session start to purge differences: {sorted(delta)}"


def exclusion():
    """The service and the session exclude each other, and install drains a
    crashed session's ledger before it registers the service."""
    with ExitStack() as stack:
        session = Session(stack)
        before = session.inventory()
        status = session.start()
        instance, request = str(uuid.uuid4()), str(uuid.uuid4())
        session.apply(spec(), instance, request, str(status["revision"]))
        session.track_adapter(before, instance, session.ready(instance))
        refused = session.run("install")
        assert refused.returncode != 0, "install while the session host runs"
        assert command("sc.exe", "query", "easytier-desk-host", check=False).returncode != 0, \
            "a refused install registers nothing"
        session.crash(session.host)
        session.process = None
        session.drop_lease()
        assert any(r["state"] != "reclaimed" for r in session.effects())

        installed = session.run("install")
        assert installed.returncode == 0, f"install exited {installed.returncode}: {installed.stderr}"
        try:
            pending = [(r["kind"], r["state"]) for r in session.effects() if r["state"] != "reclaimed"]
            assert not pending, f"install left the session ledger open: {pending}"
            started = session.run("run", "--mode", "elevated-session")
            assert started.returncode == EXIT_SERVICE_INSTALLED, \
                f"session start with the service registered exited {started.returncode}"
        finally:
            removed = session.run("uninstall")
            assert removed.returncode == 0, f"uninstall exited {removed.returncode}: {removed.stderr}"
        session.purge()
        after = session.inventory()
        delta = machine_delta(before, after, session.adapter_indices)
        assert not delta, f"session start to uninstall differences: {sorted(delta)}"


# Copies of system DLLs etd-host imports that are not KnownDLLs, planted
# beside the portable host: none may be loaded from there.
PLANTED = ("iphlpapi.dll", "fwpuclnt.dll", "pdh.dll", "powrprof.dll", "cfgmgr32.dll", "version.dll",
           "dbghelp.dll", "winhttp.dll", "userenv.dll", "wtsapi32.dll")

CONNECT = r"""
$ErrorActionPreference = 'Continue'
$label = ((whoami /groups) -match 'Mandatory Label') -replace '\s+', ' '
$s = [Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork, [Net.Sockets.SocketType]::Stream, [Net.Sockets.ProtocolType]::Tcp)
try { $s.Connect('127.0.0.1', __PORT__); $verdict = 'connected' }
catch { $e = $_.Exception; while ($e.InnerException) { $e = $e.InnerException }; $verdict = "error $($e.NativeErrorCode) $($e.SocketErrorCode)" }
finally { $s.Dispose() }
"$(whoami) | $label | $verdict"
"""


def encoded(script):
    import base64
    return base64.b64encode(script.encode("utf-16-le")).decode()


def kernel_port(session):
    [kernel] = session.kernels()
    argv = kernel.cmdline()
    address = argv[argv.index("--rpc-portal") + 1]
    host, port = address.rsplit(":", 1)
    assert host == "127.0.0.1", address
    return int(port)


def low_copy(directory):
    """A copy of Windows PowerShell labelled Low: a process started from it
    runs at Low integrity (the file's label caps the new token)."""
    powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    copy = directory / "low-powershell.exe"
    shutil.copy2(powershell, copy)
    command("icacls", copy, "/setintegritylevel", "low")
    return copy


def own_low_connect(port, directory):
    result = command(low_copy(directory), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                     encoded(CONNECT.replace("__PORT__", str(port))), check=False)
    return result.stdout.strip() or result.stderr.strip()


SECOND_ACCOUNT = r"""
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $env:ES5_PROBE_SECRET -AsPlainText -Force
$cred = [pscredential]::new("$env:COMPUTERNAME\__NAME__", $secure)
try {
  $p = Start-Process -FilePath '__EXE__' -Credential $cred -WorkingDirectory '__DIR__' -RedirectStandardOutput '__OUT__' -PassThru -Wait -ArgumentList '-NoLogo','-NoProfile','-NonInteractive','-EncodedCommand','__SCRIPT__'
  "exit $($p.ExitCode)"
} catch { "launch failed: $($_.Exception.GetType().FullName): $($_.Exception.Message)" }
"""


def second_account_connects(port):
    """A temporary standard account (random password, never printed)
    connects through the secondary logon at Medium and, from a Low-labelled
    copy, at Low integrity; the account is removed afterwards."""
    name = "es5probe"
    # At most 14 characters: net user asks for confirmation beyond that.
    password = uuid.uuid4().hex[:10] + "Aa1!"
    exchange = Path("C:/es5-probe")
    exchange.mkdir(exist_ok=True)
    command("icacls", exchange, "/grant", "*S-1-1-0:(OI)(CI)F")
    images = {"Medium": Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
              "Low": low_copy(exchange)}
    command("net", "user", name, password, "/add")
    verdicts = {}
    try:
        for level, image in images.items():
            out = exchange / f"connect-{level}.txt"
            out.unlink(missing_ok=True)
            launcher = (SECOND_ACCOUNT.replace("__NAME__", name).replace("__EXE__", str(image))
                        .replace("__DIR__", str(exchange)).replace("__OUT__", str(out))
                        .replace("__SCRIPT__", encoded(CONNECT.replace("__PORT__", str(port)))))
            # Windows PowerShell with its own module path, not pwsh 7's
            # (inherited from the runner), so its cmdlets load.
            env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
            result = command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                             encoded(launcher), check=False, env=dict(env, ES5_PROBE_SECRET=password))
            if not out.exists():
                raise AssertionError(f"second account probe ({level}) did not run: {result.stdout} {result.stderr}")
            verdicts[level] = out.read_text(encoding="utf-8", errors="replace").strip()
    finally:
        command("net", "user", name, "/delete", check=False)
        shutil.rmtree(exchange, ignore_errors=True)
    return verdicts


def identities():
    """The real kernel's management port under the session fence refuses a
    second standard account at Medium and at Low integrity, while the
    elevated user connects (a non-elevated copy of the user's own token is
    refused by the host's own probe on every kernel start, ES2); DLLs planted beside the portable host are
    not loaded, and the kernel loads only from its store and Windows
    (doc#13#wbs ES5)."""
    import psutil
    import socket
    with ExitStack() as stack:
        session = Session(stack)
        system32 = Path(os.environ["SystemRoot"]) / "System32"
        for name in PLANTED:
            shutil.copy2(system32 / name, session.dir / name)
        status = session.start()
        instance, request = str(uuid.uuid4()), str(uuid.uuid4())
        session.apply(spec(), instance, request, str(status["revision"]))
        session.ready(instance)
        port = kernel_port(session)
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            print(f"elevated user: connected to the kernel port {port}", flush=True)
        others = second_account_connects(port)
        for level, verdict in others.items():
            print(f"second account at {level}: {verdict}", flush=True)
            assert f"{level} Mandatory Level" in verdict, verdict
            assert verdict.endswith("error 10013 AccessDenied"), verdict
        # Reported, not judged: a Low copy of the elevated token keeps
        # Administrators enabled, and the fence admits elevated
        # administrators by group (only an elevated parent can make one).
        print(f"elevated token lowered to Low (report only): {own_low_connect(port, session.dir)}", flush=True)

        portable = session.dir.resolve()
        planted = {name.lower() for name in PLANTED}
        host_modules = [m.path for m in psutil.Process(session.process.pid).memory_maps(grouped=True)
                        if m.path and Path(m.path).resolve().parent == portable
                        and Path(m.path).name.lower() in planted]
        assert not host_modules, f"etd-host loaded planted modules: {host_modules}"
        [kernel] = session.kernels()
        store = Path(kernel.info["exe"]).resolve().parent
        windows = Path(os.environ["SystemRoot"]).resolve()
        foreign = [m.path for m in kernel.memory_maps(grouped=True)
                   if m.path and m.path.lower().endswith(".dll")
                   and Path(m.path).resolve().parent != store
                   and not Path(m.path).resolve().is_relative_to(windows)]
        assert not foreign, f"the kernel loaded modules from outside its store and Windows: {foreign}"
        print(f"etd-host loaded none of the {len(PLANTED)} planted modules; "
              f"the kernel loads only from its store and Windows", flush=True)

        session.ctl("stop", instance)
        eventually("stopped instance", lambda: session.view(instance),
                   lambda body: body.get("state") == "stopped", timeout=240)
        session.release()
        session.purge()


CASES = {"session_recovery": recovery, "session_exclusion": exclusion, "session_identities": identities}

if __name__ == "__main__":
    CASES[sys.argv[1]]()
