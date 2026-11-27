"""Smoke test of the release packages on a fresh hosted runner (PK5, doc#16).

release-package.yml runs this file directly (not through the tier3 test
binary) on the packages it is about to publish:

- ETD_RELEASE: the release package (.msi on Windows, .deb on Linux), byte
  for byte what the release carries;
- ETD_RELEASE_NEXT: the same build packaged as the next patch version with
  bytes appended to etd-host, so the upgrade replaces the service image. It
  is a test artifact and never published.

ETD_G2_BIN names the release package's payload extracted to a folder that
outlives the uninstall (its etd-ctl talks to the service, its etd-host reads
the uninstall status) and ETD_G2_SHA the digest of its kernel. Each case installs the
release package, checks the service serves from the payload image as owned
by the package, upgrades to the next version keeping the install id, install
key and ledger settings, and removes the package; Service.installed compares
the machine with before the install (zero drift but the maintenance lock).
"""

import os
from pathlib import Path
import sys

from service import Service, require_runner
from inventory import digest


def msi_release():
    import package as msi

    service = Service()
    release, next_ = Path(os.environ["ETD_RELEASE"]), Path(os.environ["ETD_RELEASE_NEXT"])
    removed = []

    def install():
        result = msi.msiexec("/i", release, "install")
        assert result.returncode == 0, f"msiexec exited {result.returncode}"

    def uninstall():
        result = None
        for code, version in msi.products():
            removed.append(version)
            result = msi.msiexec("/x", code, f"uninstall-{version}")
        assert result is not None, "no EasyTier Desktop product to uninstall"
        return result

    with service.installed(install=install, uninstall=uninstall):
        [(code, version)] = msi.products()
        for name in ("etd-ui.exe", "etd-host.exe", "etd-ctl.exe", r"cores\2.7.1\easytier-core.exe"):
            assert (msi.PAYLOAD / name).is_file(), f"payload misses {name}"
        assert (msi.MENU / "EasyTier Desktop.lnk").is_file(), "no Start menu shortcut"
        assert digest(service.host) == digest(msi.PAYLOAD / "etd-host.exe")
        record = msi.journal()
        assert record.get("owner") == code, record
        install_id = record["install_id"]
        key = digest(service.state / "repair-index.json")
        kept = msi.settings(service)
        print(f"installed {version} ({code}): the service serves from the payload image, "
              "owned by its ProductCode", flush=True)

        result = msi.msiexec("/i", next_, "upgrade")
        assert result.returncode == 0, f"msiexec exited {result.returncode}"
        [(code_next, version_next)] = msi.products()
        assert code_next != code and version_next != version, msi.products()
        msi.serving(service, "upgraded service")
        assert digest(service.host) == digest(msi.PAYLOAD / "etd-host.exe")
        record = msi.journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        # The owner is the product that installed the service; an upgrade
        # keeps it (the next uninstall removes the service whatever it is).
        assert record.get("owner") == code, record
        assert digest(service.state / "repair-index.json") == key, "the install key changed"
        assert msi.settings(service) == kept, "the ledger settings changed"
        msi.no_backups(service)
        print(f"upgraded to {version_next} ({code_next}): install id, install key and settings "
              "kept", flush=True)
    assert removed == [version_next], removed
    assert not msi.products() and not msi.PAYLOAD.exists() and not msi.MENU.exists()
    assert not msi.service_registered(), "the service is still registered"
    print("uninstalled: no product, payload, shortcut or service", flush=True)


def deb_release():
    import deb

    service = Service()
    release, next_ = Path(os.environ["ETD_RELEASE"]), Path(os.environ["ETD_RELEASE_NEXT"])

    def install():
        result = deb.apt_install(release, "install")
        assert result.returncode == 0, f"apt-get exited {result.returncode}"

    def purge():
        return deb.run("apt-get", "purge", "-y", deb.PACKAGE, name="purge")

    with service.installed(install=install, uninstall=purge):
        assert deb.status() == "ii", deb.status()
        version = deb.version()
        deb.package_files_present()
        assert digest(service.host) == digest(deb.PAYLOAD / "etd-host")
        record = deb.journal()
        assert record.get("owner") == deb.OWNER, record
        install_id = record["install_id"]
        key = digest(service.state / "repair-index.json")
        kept = deb.settings(service)
        print(f"installed {version}: the service serves from the payload image, owned by "
              f"{deb.OWNER}", flush=True)

        result = deb.apt_install(next_, "upgrade")
        assert result.returncode == 0, f"apt-get exited {result.returncode}"
        version_next = deb.version()
        assert deb.status() == "ii" and version_next != version, (deb.status(), version_next)
        deb.serving(service, "upgraded service")
        assert digest(service.host) == digest(deb.PAYLOAD / "etd-host")
        record = deb.journal()
        assert record["install_id"] == install_id and "upgrade" not in record, record
        assert digest(service.state / "repair-index.json") == key, "the install key changed"
        assert deb.settings(service) == kept, "the ledger settings changed"
        deb.no_backups(service)
        print(f"upgraded to {version_next}: install id, install key and settings kept", flush=True)
    assert deb.not_installed(), deb.status()
    deb.package_files_absent()
    assert not deb.UNIT.exists(), "purge left the unit"
    print("purged: no payload, link, desktop entry, icon, unit or package", flush=True)


if __name__ == "__main__":
    require_runner()
    cases = {"msi_release": msi_release, "deb_release": deb_release}
    cases[sys.argv[1]]()
