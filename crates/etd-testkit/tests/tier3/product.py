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
from consistency import UnpredictedChanges, check_closed, check_generation, installed_image
from inventory import capture, file_identity
import foreign


def spec():
    return {"display_name": "G2 service regression", "network_name": "g2-ci",
            "ipv4_cidr": "192.0.2.41/28", "no_listener": True,
            "flags": {"disable_ipv6": True, "disable_udp_hole_punching": True}}


@contextmanager
def foreign_runtime(service, instance):
    # The service owns its private runtime container and can sweep orphans
    # inside it. Give another installation its own adjacent state root and
    # the *same* instance/epoch path and retain its directory/file identity.
    parent = service.host.parent.parent if sys.platform == "darwin" else service.state.parent
    with tempfile.TemporaryDirectory(prefix="easytier-desk-g2-", dir=parent) as root:
        runtime = Path(root) / "run"
        path = runtime / instance / "1"
        path.mkdir(parents=True)
        marker = path / "marker"
        marker.write_bytes(uuid.uuid4().bytes)
        ident = file_identity(marker)
        yield runtime
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


def inventory_case():
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        root = Path(directory)
        before = capture(root, [])
        epoch = root / "etd-g2-foreign" / "42"
        epoch.mkdir(parents=True)
        natives = {"linux": foreign_linux, "darwin": foreign.macos, "win32": foreign.windows}
        keys = stack.enter_context(natives[sys.platform]())
        image, process_key = stack.enter_context(foreign.idle_process())
        keys.update({("runtime", str(epoch)), process_key})
        observed = capture(root, [image])
        assert keys <= before.delta(observed), f"fixture invisible to inventory: {keys - before.delta(observed)}"
        assert_foreign(observed, capture(root, [image]), keys)
        for kind, count in observed.counts().items():
            print(f"{kind}: {count} native entries, {sum(key[0] == kind for key in keys)} stable fixtures")


def recovery():
    service = Service()
    instance = str(uuid.uuid4())
    request = str(uuid.uuid4())
    with service.installed(), ExitStack() as stack:
        other_runtime = stack.enter_context(foreign_runtime(service, instance))
        natives = {"linux": foreign_linux, "darwin": foreign.macos, "win32": foreign.windows}
        keys = stack.enter_context(natives[sys.platform]())
        foreign_image, process_key = stack.enter_context(foreign.idle_process())
        keys.add(process_key)
        def inventory():
            return service.inventory([foreign_image], [other_runtime])
        baseline = inventory()
        differences = []
        def verify_generation(snapshot, view):
            import re
            entries = service.call(service.client, "--json", "logs", instance, "--tail", "1000")
            sources = {"core_stdout": 0, "core_stderr": 0}
            hits = 0
            errors = 0
            for raw in entries.splitlines():
                line = json.loads(raw)
                if line["epoch"] != view["epoch"] or line["source"] not in sources:
                    continue
                sources[line["source"]] += 1
                message = line["text"]
                if re.search(r"\b(?:HOME|TMPDIR|TEMPDIR|temp(?:orary)?(?:[ _-]?director(?:y|ies))?)\b|/tmp/", message, re.I):
                    hits += 1
                    errors += bool(re.search(r"\berror\b|\bfailed\b|not found|denied|unavailable", message, re.I))
                    if not re.search(r"secret|password|bearer|token|authorization|g2-log-probe|private[ _-]?key", message, re.I):
                        print(f"MF kernel {line['source']} epoch={view['epoch']}: {message[:360]}", flush=True)
            print(f"MF actual kernel log epoch={view['epoch']} streams={sources} "
                  f"HOME/TMPDIR/temp matches={hits} error matches={errors}", flush=True)
            assert sum(sources.values()), "no actual kernel log entries available in this epoch"
            try:
                check_generation(baseline, snapshot, service.effects(), instance, view)
            except UnpredictedChanges as err:
                # Finish both crash observations and final cleanup even when a
                # fully observed epoch changed an extra object. Fail below.
                message = f"epoch {view['epoch']}: {err}"
                print(message, flush=True)
                differences.append(message)
        keys.update(key for key in baseline.rows if key[0] == "runtime")
        revision = str(service.ctl("status")["revision"])
        desktop = Desktop(instance, request, revision, stack.enter_context(tempfile.TemporaryDirectory()))
        with desktop.connected("apply"):
            receipt = eventually("durable commit", lambda: service.receipt(request), bool)
        # Abrupt desktop exit after the durable request does not cancel launch.
        first = service.ready(instance)
        print(f"installed kernel ready: {first['state']} epoch={first['epoch']}", flush=True)
        before = inventory()
        verify_generation(before, first)
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
            service.verify_bundle()
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
            verify_generation(after, first)
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
        if remaining:
            message = f"unreclaimed native objects or changed baseline: {sorted(remaining)}"
            print(message, flush=True)
            differences.append(message)
        if os.name == "nt":
            verify_shared_driver_purge(service, baseline, stopped)
        assert not differences, "\n".join(differences)


def verify_shared_driver_purge(service, baseline, stopped):
    names = {name for name in ("wintun", "windivert")
             if ("service", name) not in baseline.rows and ("service", name) in stopped.rows}
    assert "wintun" in names, "the real kernel did not load its TUN driver"
    service.stop()
    result = command(service.installer, "reclaim", "--all", "--purge", check=False)
    records = service.effects()
    retained = {r["key"]["name"].lower() for r in records if r["scope"] == "product"
                and r["kind"] == "driver" and r["state"] == "candidate"}
    assert retained == names, f"expected shared driver candidates {names}, got {retained}"
    assert result.returncode and "candidates" in result.stdout and "reclaim incomplete" in result.stderr
    after = service.inventory()
    assert_foreign(stopped, after, {("service", name) for name in names})
    service.retained_drivers = names


def driver_conflict():
    service = Service()
    with service.installed(), ExitStack() as stack:
        names = {"wintun", "windivert"}
        base = service.inventory()
        for name in names:
            assert ("service", name) not in base.rows, f"runner already owns {name}"
            # Disabled SCM metadata only: no driver file is supplied or loaded.
            missing = Path(os.environ["RUNNER_TEMP"]) / ("absent-g2-" + name + ".sys")
            assert not missing.exists()
            command("sc.exe", "create", name, "type=", "kernel", "start=", "disabled",
                    "binPath=", missing)
            stack.callback(command, "sc.exe", "delete", name)
        foreign_state = service.inventory()
        for name in sorted(names):
            native = foreign_state.rows.get(("service", name))
            print(f"pre-existing driver {name}: {native}", flush=True)
            assert native and "DISABLED" in native and f"absent-g2-{name}.sys" in native, name
        instance = str(uuid.uuid4())
        service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
        def conflicts():
            return {r["key"]["name"].lower() for r in service.effects()
                    if r["kind"] == "driver" and r["state"] == "conflict" and r["scope"] == "product"}
        try:
            eventually("pre-existing driver conflicts", conflicts, lambda found: found == names,
                       timeout=240)
        except AssertionError:
            service.report_effects(instance)
            raise
        service.ctl("stop", instance)
        service.stop()
        assert_foreign(foreign_state, service.inventory(), {("service", n) for n in names})
        service.retained_drivers = names


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
    {"recovery": recovery, "magic_dns": magic_dns, "inventory": inventory_case,
     "driver_conflict": driver_conflict}[sys.argv[1]]()
