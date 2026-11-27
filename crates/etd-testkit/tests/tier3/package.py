"""The Windows MSI on a disposable runner (PK3, doc#16).

privileged.yml builds three MSIs with `cargo xtask dist` from this build:
ETD_MSI_A (0.1.0), ETD_MSI_B (0.1.1) and ETD_MSI_C (0.1.2), each with a
distinct etd-host image. Their etd-host carries ci-test-fixtures, so a CI
fault can make an upgrade fail; release packages never do.

The case walks one machine through:
1. a first install that fails (a foreign Program Files\\EasyTierDesk):
   Windows Installer and etd-host leave nothing behind;
2. a first install (A) with ETD_ALLOW_USER: payload, Start menu shortcut,
   App Paths, and a serving service whose image is the payload's;
3. a major upgrade (B): the service runs B's image and keeps its install
   id, install key, ledger settings (allow list) and state;
4. an upgrade (C) whose new host never serves: etd-host rolls the service
   back, Windows Installer rolls the payload back; B stays installed;
5. with a WinDivert driver loaded from a store-length path, a process
   without SeDebugPrivilege reads complete loaded-driver paths from the
   kernel module list (driver_probe.py), the fallback etd-host uses where
   Windows Installer custom actions run (msg#1764);
6. a full uninstall, whose driver reference check runs under the Windows
   Installer service's token, without SeDebugPrivilege: Service.installed
   compares the machine with before step 2, and no payload, shortcut, App
   Paths entry or product remains.
"""

import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time
import winreg

from service import Service, command, eventually, require_runner
from inventory import digest

PAYLOAD = Path(os.environ["ProgramFiles"]) / "EasyTier Desktop"
MENU = Path(os.environ["ProgramData"]) / r"Microsoft\Windows\Start Menu\Programs\EasyTier Desktop"
MAINTENANCE = Path(os.environ["ProgramData"]) / "EasyTierDesk.maintenance"
APP_PATHS = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\etd-ctl.exe"
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
SERVICE = "easytier-desk-host"
# A well-formed SID enrolled through ETD_ALLOW_USER; no account needs it.
ALLOWED = "S-1-5-21-1111111111-2222222222-3333333333-4242"
LOGS = Path(os.environ.get("RUNNER_TEMP", ".")) / "msi-logs"


def products():
    """(product code, version) of every installed EasyTier Desktop."""
    found = []
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, UNINSTALL, 0,
                        winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
        for index in range(winreg.QueryInfoKey(root)[0]):
            code = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, code) as key:
                try:
                    name = winreg.QueryValueEx(key, "DisplayName")[0]
                except FileNotFoundError:
                    continue
                if name == "EasyTier Desktop":
                    found.append((code, winreg.QueryValueEx(key, "DisplayVersion")[0]))
    return sorted(found)


def app_path():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, APP_PATHS, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            return winreg.QueryValueEx(key, "")[0], winreg.QueryValueEx(key, "Path")[0]
    except FileNotFoundError:
        return None


def msiexec(action, target, name, *properties):
    LOGS.mkdir(parents=True, exist_ok=True)
    log = LOGS / f"{name}.log"
    started = time.monotonic()
    result = command("msiexec.exe", action, target, "/qn", "/norestart", "/l*v", log, *properties,
                     check=False, timeout=900)
    print(f"msiexec {action} {Path(target).name} ({name}): exit {result.returncode} "
          f"after {time.monotonic() - started:.1f}s", flush=True)
    # What the custom actions ran and printed, and where the script failed.
    raw = log.read_bytes() if log.exists() else b""
    text = raw.decode("utf-16" if raw.startswith(b"\xff\xfe") else "mbcs", errors="replace")
    for line in text.splitlines():
        if "WixQuietExec" in line or "Return value 3" in line or "Product: EasyTier Desktop" in line:
            print(f"  {line.strip()[:400]}", flush=True)
    return result


def service_registered():
    return command("sc.exe", "query", SERVICE, check=False).returncode != 1060


def journal():
    return json.loads((MAINTENANCE / "lifecycle.json").read_text(encoding="utf-8"))


def settings(service):
    """The ledger's settings row (allow list included), as stored."""
    db = sqlite3.connect((service.state / "ledger.sqlite3").as_uri() + "?mode=ro", uri=True)
    try:
        payload = db.execute("SELECT payload FROM settings WHERE singleton = 1").fetchone()[0]
    finally:
        db.close()
    return payload.encode() if isinstance(payload, str) else bytes(payload)


def serving(service, what):
    status = eventually(what, lambda: service.ctl("status"),
                        lambda body: body["host"]["phase"] == "serving")
    assert status["host"]["mode"] == "service", status
    assert status["default_core_version"] == "2.7.1", status
    return status


def payload_image(msi):
    return Path(msi).parent / "payload" / "etd-host.exe"


def no_backups(service):
    for leftover in (service.host.with_suffix(".prev"), service.host.with_suffix(".new")):
        assert not leftover.exists(), f"upgrade left {leftover}"


def module_path(raw):
    path = raw.removeprefix("\\??\\")
    if path.lower().startswith("\\systemroot\\"):
        return Path(os.environ["SystemRoot"]) / path[len("\\systemroot\\"):]
    return Path(path)


def probe_loaded_driver_paths(service):
    """A WinDivert driver loaded from a path as long as the protected store's
    is reported completely to a process without SeDebugPrivilege."""
    root = Path(os.environ["ProgramFiles"]) / "EasyTierDesk-driver-probe"
    store = service.cores / os.environ["ETD_G2_SHA"]
    directory = root / "cores" / os.environ["ETD_G2_SHA"]
    directory.mkdir(parents=True)
    driver = directory / "WinDivert64.sys"
    shutil.copy2(store / "WinDivert64.sys", driver)
    name = "etd-driver-probe"
    command("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", driver)
    try:
        command("sc.exe", "start", name)
        result = command(sys.executable, "-B", "-I", Path(__file__).with_name("driver_probe.py"))
        report = json.loads(result.stdout)
        found = [raw for raw in report["modules"]
                 if raw.lower().endswith("\\windivert64.sys") and module_path(raw).exists()
                 and module_path(raw).samefile(driver)]
        print(f"driver probe on Windows {report['display_version']} build {report['build']}: "
              f"SeDebugPrivilege removed={report['debug_privilege_removed']}, "
              f"enable refused={report['debug_privilege_enable_refused']}; "
              f"EnumDeviceDrivers {report['enum_count']} entries, {report['enum_null_bases']} with hidden bases; "
              f"SystemModuleInformation {report['module_count']} entries, problems={report['problems']}; "
              f"WinDivert: {found}", flush=True)
        assert report["debug_privilege_removed"] and report["debug_privilege_enable_refused"], report
        assert not report["problems"], report["problems"]
        assert report["module_count"] == report["enum_count"] == len(report["modules"]), report
        assert found, f"no complete path for {driver} in {report['modules']}"
    finally:
        command("sc.exe", "stop", name, check=False)
        command("sc.exe", "delete", name, check=False)
        eventually("probe driver service removed", lambda: command("sc.exe", "query", name, check=False).returncode,
                   lambda code: code == 1060, timeout=30)
        shutil.rmtree(root)


def failed_first_install(service, msi):
    """A refused first install: etd-host install fails, Windows Installer
    rolls back, a foreign directory stays as it was."""
    foreign = service.host.parent
    assert not foreign.exists() and not products()
    foreign.mkdir()
    marker = foreign / "foreign.txt"
    marker.write_text("not ours", encoding="utf-8")
    try:
        result = msiexec("/i", msi, "install-refused")
        assert result.returncode == 1603, f"msiexec exited {result.returncode}"
        assert marker.read_text(encoding="utf-8") == "not ours"
        assert sorted(p.name for p in foreign.iterdir()) == ["foreign.txt"], list(foreign.iterdir())
        assert not products(), products()
        assert not PAYLOAD.exists(), f"rollback left {PAYLOAD}"
        assert not MENU.exists() and app_path() is None
        assert not service_registered(), "a refused install registered the service"
        assert not service.state.exists(), f"a refused install created {service.state}"
    finally:
        shutil.rmtree(foreign)
    print("refused first install: msiexec 1603, no payload, product, service or state; "
          "the foreign directory untouched", flush=True)


def msi_lifecycle():
    service = Service()
    a, b, c = (Path(os.environ[name]) for name in ("ETD_MSI_A", "ETD_MSI_B", "ETD_MSI_C"))
    images = {msi: digest(payload_image(msi)) for msi in (a, b, c)}
    assert len(set(images.values())) == 3, "the three packages must carry distinct images"
    failed_first_install(service, a)

    def install():
        result = msiexec("/i", a, "install", f"ETD_ALLOW_USER={ALLOWED}")
        assert result.returncode == 0, f"msiexec exited {result.returncode}"

    def uninstall():
        # Whatever is installed, even after an earlier failure; the version
        # is checked once the uninstall has run.
        result = None
        for code, version in products():
            removed.append(version)
            result = msiexec("/x", code, f"uninstall-{version}")
        assert result is not None, "no EasyTier Desktop product to uninstall"
        return result

    removed = []

    with service.installed(install=install, uninstall=uninstall):
        # 2. First install.
        [(code_a, version)] = products()
        assert version == "0.1.0", version
        for name in ("etd-ui.exe", "etd-host.exe", "etd-ctl.exe", r"cores\2.7.1\easytier-core.exe"):
            assert (PAYLOAD / name).is_file(), f"payload misses {name}"
        assert (MENU / "EasyTier Desktop.lnk").is_file(), "no Start menu shortcut"
        assert app_path() == (str(PAYLOAD / "etd-ctl.exe"), str(PAYLOAD) + "\\"), app_path()
        assert digest(service.host) == images[a], "the service image is not the payload's"
        assert ALLOWED.encode() in settings(service), "ETD_ALLOW_USER did not reach the allow list"
        install_id = journal()["install_id"]
        key = digest(service.state / "repair-index.json")
        kept = settings(service)
        print(f"installed 0.1.0 ({code_a}): service serving from the payload image, "
              f"{ALLOWED} enrolled", flush=True)

        # 3. Major upgrade.
        result = msiexec("/i", b, "upgrade")
        assert result.returncode == 0, f"msiexec exited {result.returncode}"
        [(code_b, version)] = products()
        assert version == "0.1.1" and code_b != code_a, products()
        serving(service, "upgraded service self-check")
        assert digest(service.host) == digest(PAYLOAD / "etd-host.exe") == images[b]
        record = journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        assert digest(service.state / "repair-index.json") == key, "the install key changed"
        assert settings(service) == kept, "the ledger settings (allow list) changed"
        no_backups(service)
        print(f"upgraded to 0.1.1 ({code_b}): the service runs its image; install id, install key "
              f"and settings kept", flush=True)

        # 4. An upgrade whose new host never serves.
        fault = MAINTENANCE / "ci-upgrade-fault"
        fault.write_text("new-host-unready", encoding="utf-8")
        try:
            result = msiexec("/i", c, "upgrade-refused")
        finally:
            fault.unlink()
        assert result.returncode == 1603, f"msiexec exited {result.returncode}"
        assert products() == [(code_b, "0.1.1")], products()
        serving(service, "previous service after the failed upgrade")
        assert digest(PAYLOAD / "etd-host.exe") == images[b], "the payload was not rolled back"
        assert digest(service.host) == images[b], "the service image was not restored"
        record = journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        assert settings(service) == kept
        no_backups(service)
        print("failed upgrade to 0.1.2: msiexec 1603; etd-host restored and restarted 0.1.1, "
              "Windows Installer restored its payload", flush=True)

        # 5. Loaded-driver paths without SeDebugPrivilege.
        probe_loaded_driver_paths(service)

    # 6. Full uninstall (Service.installed compared the machine).
    assert removed == ["0.1.1"], f"uninstalled {removed}"
    assert not PAYLOAD.exists(), f"uninstall left {PAYLOAD}"
    assert not MENU.exists(), f"uninstall left {MENU}"
    assert app_path() is None, "uninstall left the App Paths entry"
    assert not products(), products()
    assert not service_registered()
    print("uninstalled: no payload, shortcut, App Paths entry, product or service", flush=True)


if __name__ == "__main__":
    require_runner()
    assert sys.platform == "win32", "the MSI case runs on Windows"
    {"msi_lifecycle": msi_lifecycle}[sys.argv[1]]()
