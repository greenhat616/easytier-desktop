"""End-to-end regressions for an installed, unmodified service image."""

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

from service import Desktop, Service, command, eventually, require_runner
from consistency import check_closed, check_generation, installed_image
from inventory import file_identity
import foreign


def spec():
    return {"display_name": "G2 service regression", "network_name": "g2-ci",
            "ipv4_cidr": "192.0.2.41/28", "no_listener": True,
            "flags": {"disable_ipv6": True, "disable_udp_hole_punching": True}}


@contextmanager
def foreign_runtime(service):
    with tempfile.TemporaryDirectory(prefix="etd-g2-", dir=service.runtime) as root:
        path = Path(root) / "42"
        path.mkdir()
        marker = path / "marker"
        marker.write_bytes(uuid.uuid4().bytes)
        ident = file_identity(marker)
        yield
        assert file_identity(marker) == ident, "foreign runtime file changed"


@contextmanager
def foreign_linux():
    # Fixtures exist before the generation. They never bind its endpoint or
    # acquire its interface identity, and none carries a product credential.
    device = "etd-g2-foreign"
    table = "etd_f_g2_foreign"
    with ExitStack() as stack:
        command("ip", "link", "add", device, "type", "dummy")
        stack.callback(command, "ip", "link", "del", device)
        command("ip", "link", "set", device, "up")
        command("ip", "route", "add", "198.51.100.241/32", "dev", device)
        command("resolvectl", "dns", device, "192.0.2.53")
        command("resolvectl", "domain", device, "~g2.invalid")
        command("nft", "add", "table", "inet", table)
        stack.callback(command, "nft", "delete", "table", "inet", table)
        unit = Path("/etc/systemd/system/easytier-desk-g2-foreign.service")
        stack.callback(command, "systemctl", "daemon-reload")
        with unit.open("x") as stream:
            stream.write("[Unit]\nDescription=G2 foreign fixture\n[Service]\nExecStart=/usr/bin/true\n")
        stack.callback(unit.unlink)
        command("systemctl", "daemon-reload")
        before = file_identity(unit)
        yield {("interface", device), ("route", device), ("resolver", device),
               ("firewall", "inet/" + table), ("service", unit.name)}
        assert file_identity(unit) == before


def assert_foreign(base, other, keys):
    for key in keys:
        assert key in base.rows, f"foreign fixture was never observed: {key}"
        assert other.rows.get(key) == base.rows[key], f"foreign fixture changed: {key}"


def recovery():
    service = Service()
    instance = str(uuid.uuid4())
    request = str(uuid.uuid4())
    with service.installed(), ExitStack() as stack:
        stack.enter_context(foreign_runtime(service))
        natives = {"linux": foreign_linux, "darwin": foreign.macos, "win32": foreign.windows}
        keys = stack.enter_context(natives[sys.platform]())
        foreign_image, process_key = stack.enter_context(foreign.idle_process())
        keys.add(process_key)
        def inventory():
            return service.inventory([foreign_image])
        baseline = inventory()
        keys.update(key for key in baseline.rows if key[0] == "runtime")
        revision = str(service.ctl("status")["revision"])
        desktop = Desktop(instance, request, revision, stack.enter_context(tempfile.TemporaryDirectory()))
        with desktop.connected("apply"):
            receipt = eventually("durable commit", lambda: service.receipt(request), bool)
        # Abrupt desktop exit after the durable request does not cancel launch.
        first = service.ready(instance)
        before = inventory()
        check_generation(baseline, before, service.effects(), instance, first)
        assert_foreign(baseline, before, keys)
        with desktop.connected("hold"):
            assert desktop.read("logs") > 0
        time.sleep(31)
        assert service.ready(instance)["epoch"] == first["epoch"], "client exit restarted service core"
        for image in (service.core, service.host):
            old_epoch = first["epoch"]
            old_dir = service.runtime / instance / str(old_epoch)
            old_pid = service.crash_installed(image)
            first = service.ready(instance, after=old_epoch)
            after = inventory()
            check_closed(service, instance, old_epoch)
            assert ("process", str(old_pid)) not in after.rows, "killed process remains"
            assert not old_dir.exists(), f"old generation directory remains: {old_dir}"
            assert_foreign(baseline, after, keys)
            # A replacement host has a different pid. Compare generation
            # effects against the same prelaunch baseline at the new host pid.
            if image == service.host:
                prior = [k for k,v in baseline.rows.items()
                         if k[0] == "process" and installed_image(v) == service.host]
                current = [k for k,v in after.rows.items()
                           if k[0] == "process" and installed_image(v) == service.host]
                assert len(prior) == len(current) == 1 and prior != current
                del baseline.rows[prior[0]]
                baseline.rows[current[0]] = after.rows[current[0]]
            check_generation(baseline, after, service.effects(), instance, first)
            # Replay the very first request across both restarts. Ticket,
            # revision and acceptance time must still be identical.
            assert desktop.read("receipt") == desktop.read("replay") == receipt
            status = service.ctl("status")
            assert len(status["instances"]) == 1 and status["revision"] == receipt["revision"]
        service.ctl("stop", instance)
        eventually("stopped instance", lambda: service.view(instance),
                   lambda status: status.get("state") == "stopped")
        check_closed(service, instance, first["epoch"])
        stopped = inventory()
        assert_foreign(baseline, stopped, keys)
        remaining = baseline.delta(stopped)
        if os.name == "nt":
            records = service.effects()
            for key in remaining.copy():
                if key[0] == "service" and key[1] in ("wintun", "windivert"):
                    assert any(r["scope"] == "product" and r["state"] != "reclaimed"
                               and r["key"].get("name", "").lower() == key[1] for r in records)
                    remaining.remove(key)
                elif key[0] == "firewall" and key[1].startswith("policy/"):
                    name = stopped.rows[key][0]
                    assert any("core_binary" in r["scope"] and r["state"] != "reclaimed"
                               and r["key"].get("name") == name for r in records)
                    remaining.remove(key)
        assert not remaining, f"unreclaimed native objects or changed baseline: {sorted(remaining)}"


def magic_dns():
    service = Service()
    with service.installed(), ExitStack() as stack:
        directory = Path("/etc/resolver")
        if not directory.exists():
            directory.mkdir()
            stack.callback(directory.rmdir)
        for name in ("et.net", "etd-g2-foreign"):
            path = directory / name
            with path.open("xb") as file:
                file.write(b"# G2 foreign resolver\nnameserver 192.0.2.53\n")
            stack.callback(path.unlink)
        before = service.inventory()
        config = {**spec(), "magic_dns": True}
        result = service.apply(config, str(uuid.uuid4()), str(uuid.uuid4()),
                               str(service.ctl("status")["revision"]), check=False)
        assert result.returncode == 8, f"expected product refusal; got {result.returncode} {result.stderr}"
        detail = json.loads(result.stderr)["error"]
        assert detail["error_code"] == "feature_rejected" and "magic_dns" in detail["features"], detail
        after = service.inventory()
        assert_foreign(before, after, {k for k in before.rows if k[0] == "resolver"})
        assert not service.ctl("status")["instances"], "rejected config created an instance"
        print("Installed service rejected magic_dns; resolver bytes, device and inode preserved")


if __name__ == "__main__":
    require_runner()
    {"recovery": recovery, "magic_dns": magic_dns}[sys.argv[1]]()
