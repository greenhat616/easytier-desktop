"""The Debian package on a disposable Ubuntu runner (PK4, doc#16).

privileged.yml builds three packages with `cargo xtask dist
--allow-test-fixtures` from this build: ETD_DEB_A (0.1.0), ETD_DEB_B (0.1.1)
and ETD_DEB_C (0.1.2), each with a distinct etd-host image. Their etd-host
carries ci-test-fixtures, so a CI fault can make an upgrade fail; dist
refuses that in release packages. The workflow installs the packages'
dependencies first, so apt adds nothing else to the machine.

The case walks one machine through:
1. a service installed with the CLI: the package's preinst refuses before
   anything is unpacked, and the service keeps running untouched;
2. a first install (A): payload, /usr/bin links, desktop entry, icons, and a
   serving service whose image is the payload's, recorded as owned by the
   package;
3. an upgrade (B): the service runs B's image and keeps its install id,
   install key, ledger settings and state;
4. an upgrade (C) whose new host never serves: etd-host rolls the service
   back and B keeps serving; dpkg leaves C unpacked but half-configured
   (postinst failed) and does not restore B's files. Once the fault is gone,
   `dpkg --configure -a` reruns the postinst and completes the upgrade;
5. `apt-get purge`: Service.installed compares the machine with before
   step 2, and no payload, link, desktop entry, icon or package remains.
"""

import json
import os
from pathlib import Path
import sqlite3
import sys

from service import Service, command, eventually, require_runner
from inventory import digest

PACKAGE = "easytier-desktop"
PAYLOAD = Path("/usr/lib/easytier-desktop")
LINKS = {Path("/usr/bin/easytier-desktop"): PAYLOAD / "etd-ui",
         Path("/usr/bin/etd-ctl"): PAYLOAD / "etd-ctl"}
DESKTOP = Path("/usr/share/applications/easytier-desktop.desktop")
ICONS = [Path(f"/usr/share/icons/hicolor/{size}/apps/easytier-desktop.png")
         for size in ("16x16", "24x24", "32x32", "48x48", "64x64", "128x128", "256x256")]
ICONS.append(Path("/usr/share/icons/hicolor/scalable/apps/easytier-desktop.svg"))
UNIT = Path("/etc/systemd/system/easytier-desk-host.service")
MAINTENANCE = Path("/var/lib/easytier-desk-maintenance")
OWNER = "easytier-desktop-package"
APT = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}


def run(*args, name):
    """A package manager command; prints what the hooks said."""
    result = command(*args, check=False, timeout=900, env=APT)
    print(f"{name}: {' '.join(str(a) for a in args)} -> exit {result.returncode}", flush=True)
    for line in (result.stdout + result.stderr).splitlines():
        if "easytier-desktop:" in line or "etd-host" in line or "dpkg:" in line or line.startswith("E:"):
            print(f"  {line.strip()[:300]}", flush=True)
    return result


def apt_install(deb, name):
    return run("apt-get", "install", "-y", "--no-install-recommends", deb, name=name)


def status():
    """dpkg's two-letter state, desired then current (`ii` installed, `iF`
    half-configured, `in` wanted but not installed), or None when dpkg does
    not know the package."""
    result = command("dpkg-query", "-W", "-f=${db:Status-Abbrev}", PACKAGE, check=False)
    return result.stdout.strip() or None if result.returncode == 0 else None


def not_installed():
    state = status()
    return state is None or state[1:2] == "n"


def version():
    return command("dpkg-query", "-W", "-f=${Version}", PACKAGE).stdout.strip()


def journal():
    return json.loads((MAINTENANCE / "lifecycle.json").read_text(encoding="utf-8"))


def settings(service):
    db = sqlite3.connect((service.state / "ledger.sqlite3").as_uri() + "?mode=ro", uri=True)
    try:
        payload = db.execute("SELECT payload FROM settings WHERE singleton = 1").fetchone()[0]
    finally:
        db.close()
    return payload.encode() if isinstance(payload, str) else bytes(payload)


def serving(service, what):
    body = eventually(what, lambda: service.ctl("status"),
                      lambda status: status["host"]["phase"] == "serving")
    assert body["host"]["mode"] == "service", body
    return body


def payload_image(deb):
    return Path(deb).parent / "payload" / "etd-host"


def no_backups(service):
    for leftover in (service.host.with_suffix(".prev"), service.host.with_suffix(".new")):
        assert not leftover.exists(), f"upgrade left {leftover}"


def package_files_present():
    for name in ("etd-ui", "etd-host", "etd-ctl", "cores/2.7.1/easytier-core"):
        assert (PAYLOAD / name).is_file(), f"payload misses {name}"
    for link, target in LINKS.items():
        assert link.is_symlink() and link.resolve() == target, f"{link} -> {os.readlink(link)}"
    assert DESKTOP.is_file(), "no desktop entry"
    assert all(icon.is_file() for icon in ICONS), [str(i) for i in ICONS if not i.is_file()]


def package_files_absent():
    leftovers = [str(p) for p in [PAYLOAD, DESKTOP, *LINKS, *ICONS] if p.exists() or p.is_symlink()]
    assert not leftovers, f"package files remain: {leftovers}"


def refused_over_cli_install(service, deb):
    """preinst refuses before anything is unpacked: the service another
    installer made keeps running untouched."""
    host = payload_image(deb)  # staged next to its kernel bundle, as installed
    command(host, "install", timeout=300)
    try:
        serving(service, "CLI-installed service")
        before = journal()
        assert "owner" not in before, before
        kept = settings(service)
        result = apt_install(deb, "install-over-cli")
        assert result.returncode != 0, "apt installed over a CLI-installed service"
        assert "remove it first" in result.stdout + result.stderr
        assert not_installed(), f"dpkg state {status()}"
        package_files_absent()
        serving(service, "CLI-installed service after the refused package")
        assert journal() == before, "the refused package changed the installation"
        assert settings(service) == kept
    finally:
        command(host, "uninstall", timeout=300)
    assert not UNIT.exists(), "the CLI uninstall left the unit"
    print(f"package over a CLI-installed service: preinst refused, dpkg state {status()}; "
          "the service kept serving with its install id and settings", flush=True)


def deb_lifecycle():
    service = Service()
    a, b, c = (Path(os.environ[name]) for name in ("ETD_DEB_A", "ETD_DEB_B", "ETD_DEB_C"))
    images = {deb: digest(payload_image(deb)) for deb in (a, b, c)}
    assert len(set(images.values())) == 3, "the packages must carry distinct images"
    refused_over_cli_install(service, a)

    def install():
        result = apt_install(a, "install")
        assert result.returncode == 0, f"apt-get exited {result.returncode}"

    def purge():
        return run("apt-get", "purge", "-y", PACKAGE, name="purge")

    with service.installed(install=install, uninstall=purge):
        # 2. First install.
        assert status() == "ii" and version() == "0.1.0-1", (status(), version())
        package_files_present()
        assert digest(service.host) == images[a], "the service image is not the payload's"
        record = journal()
        assert record.get("owner") == OWNER, record
        install_id = record["install_id"]
        key = digest(service.state / "repair-index.json")
        kept = settings(service)
        print("installed 0.1.0: payload, links, desktop entry and icons in place; the service "
              f"serves from the payload image, owned by {OWNER}", flush=True)

        # 3. Upgrade.
        result = apt_install(b, "upgrade")
        assert result.returncode == 0, f"apt-get exited {result.returncode}"
        assert status() == "ii" and version() == "0.1.1-1", (status(), version())
        serving(service, "upgraded service self-check")
        assert digest(service.host) == digest(PAYLOAD / "etd-host") == images[b]
        record = journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        assert digest(service.state / "repair-index.json") == key, "the install key changed"
        assert settings(service) == kept, "the ledger settings changed"
        no_backups(service)
        print("upgraded to 0.1.1: the service runs its image; install id, install key and "
              "settings kept", flush=True)

        # 4. An upgrade whose new host never serves.
        fault = MAINTENANCE / "ci-upgrade-fault"
        fault.write_text("new-host-unready", encoding="utf-8")
        try:
            result = apt_install(c, "upgrade-refused")
        finally:
            fault.unlink()
        assert result.returncode != 0, "the faulted upgrade succeeded"
        state = status()
        assert state == "iF" and version() == "0.1.2-1", (state, version())
        serving(service, "previous service after the failed upgrade")
        assert digest(service.host) == images[b], "the service image was not restored"
        assert digest(PAYLOAD / "etd-host") == images[c], "dpkg restored the payload unexpectedly"
        record = journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        assert settings(service) == kept
        no_backups(service)
        print(f"failed upgrade to 0.1.2: apt-get exit {result.returncode}; etd-host restored and "
              f"restarted 0.1.1; dpkg state {state} (0.1.2 unpacked, postinst failed)", flush=True)
        result = run("dpkg", "--configure", "-a", name="configure")
        assert result.returncode == 0, f"dpkg --configure exited {result.returncode}"
        assert status() == "ii", status()
        serving(service, "service after dpkg --configure")
        assert digest(service.host) == images[c]
        assert journal()["install_id"] == install_id and settings(service) == kept
        no_backups(service)
        print("dpkg --configure -a reran the postinst: the upgrade to 0.1.2 completed", flush=True)

    # 5. Purge (Service.installed compared the machine).
    assert not_installed(), f"dpkg state {status()}"
    package_files_absent()
    assert not UNIT.exists(), "purge left the unit"
    print("purged: no payload, link, desktop entry, icon, unit or package", flush=True)


if __name__ == "__main__":
    require_runner()
    assert sys.platform == "linux", "the Debian case runs on Linux"
    {"deb_lifecycle": deb_lifecycle}[sys.argv[1]]()
