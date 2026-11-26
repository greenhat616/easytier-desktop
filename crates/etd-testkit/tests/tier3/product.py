"""End-to-end regressions for an installed, unmodified service image."""

from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

from service import Desktop, Service, assert_driver_notice, command, eventually, require_runner
from consistency import (
    FirewallReadbackPending, UnpredictedChanges, adapter_defaults, check_closed, check_generation, installed_image,
    managed_service_changes, runner_noise, scope, system_policy_changes, tun_created,
)
from inventory import assert_exited, capture, file_identity, native_application_id
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


def wait_for_firewall_readback(service, instance, epoch):
    if os.name != "nt":
        return
    # Program rules are read back asynchronously after basic readiness.
    # Wait for the ledger, then check each credential against the native rule.
    expected_scopes = (scope(instance, epoch), {"core_binary": {"sha256": os.environ["ETD_G2_SHA"]}})
    kinds = {"win.firewall_rule", "win.program_firewall_rule"}
    def read():
        return [(r["kind"], r["state"], bool((r.get("observation") or {}).get("credential")))
                for r in service.effects() if r["scope"] in expected_scopes and r["kind"] in kinds]
    def settled(rows):
        if any(state in ("conflict", "candidate", "quarantined") for _, state, _ in rows):
            raise AssertionError(f"firewall credential readback stopped: {rows}")
        return {kind for kind, _, _ in rows} == kinds and all(
            state == "applied" and credential for _, state, credential in rows)
    eventually("firewall rule credentials", read, settled, timeout=240)


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
            snapshot = service.inventory([foreign_image], [other_runtime])
            marker = other_runtime / instance / "1" / "marker"
            if marker.is_file():
                snapshot.put("runtime", marker, file_identity(marker))
            return snapshot
        baseline = inventory()
        differences = []
        generation_processes = set()
        def verify_generation(snapshot, view):
            end = time.monotonic() + 240
            while True:
                cores = [(int(k[1]), value[1]) for k, value in snapshot.rows.items()
                         if k[0] == "process" and installed_image(value) == service.core]
                assert len(cores) == 1, "expected exactly one installed kernel"
                pid, born = cores[0]
                generation_processes.add((pid, born))
                generation_processes.update(snapshot.descendants[pid])
                try:
                    check_generation(baseline, snapshot, service.effects(), instance, view, service.adapter_guids)
                except FirewallReadbackPending:
                    # A shared Applied record can still carry the preceding
                    # epoch's rule ID while the fresh native policy is visible.
                    if time.monotonic() >= end:
                        raise
                    time.sleep(2)
                    snapshot = inventory()
                    continue
                except UnpredictedChanges as err:
                    # Finish both crashes; the accumulated difference fails below.
                    message = f"epoch {view['epoch']}: {err}"
                    print(message, flush=True)
                    differences.append(message)
                return snapshot
        keys.update(key for key in baseline.rows if key[0] == "runtime")
        revision = str(service.ctl("status")["revision"])
        desktop = Desktop(instance, request, revision, stack.enter_context(tempfile.TemporaryDirectory()))
        with desktop.connected("apply"):
            receipt = eventually("durable commit", lambda: service.receipt(request), bool)
        # Abrupt desktop exit after the durable request does not cancel launch.
        first = service.ready(instance)
        print(f"installed kernel ready: {first['state']} epoch={first['epoch']}", flush=True)
        wait_for_firewall_readback(service, instance, first["epoch"])
        before = inventory()
        before = verify_generation(before, first)
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
            wait_for_firewall_readback(service, instance, first["epoch"])
            after = inventory()
            check_closed(service, instance, old_epoch)
            assert_exited(generation_processes)
            generation_processes.clear()
            assert not old_dir.exists(), f"old generation directory remains: {old_dir}"
            # Verify the old host identity exited even if its PID was reused.
            # Compare the next generation against the replacement host.
            if image == service.host:
                prior = [k for k,v in baseline.rows.items()
                         if k[0] == "process" and installed_image(v) == service.host]
                current = [k for k,v in after.rows.items()
                           if k[0] == "process" and installed_image(v) == service.host]
                assert len(prior) == len(current) == 1
                assert_exited({(old_pid, baseline.rows[prior[0]][1])})
                del baseline.rows[prior[0]]
                baseline.rows[current[0]] = after.rows[current[0]]
                assert int(prior[0][1]) == old_pid
            after = verify_generation(after, first)
            assert_foreign(baseline, after, keys)
            # Replay the very first request across both restarts. Ticket,
            # revision and acceptance time must still be identical.
            assert desktop.read("receipt") == desktop.read("replay") == receipt
            status = service.ctl("status")
            assert len(status["instances"]) == 1 and status["revision"] == receipt["revision"]
        service.ctl("stop", instance)
        eventually("stopped instance", lambda: service.view(instance),
                   lambda status: status.get("state") == "stopped",
                   timeout=240 if os.name == "nt" else 75)
        check_closed(service, instance, first["epoch"])
        stopped = inventory()
        assert_exited(generation_processes)
        assert_foreign(baseline, stopped, keys)
        remaining = baseline.delta(stopped) - managed_service_changes(baseline, stopped)
        remaining -= runner_noise(baseline, stopped) | tun_created(baseline, stopped)
        remaining -= adapter_defaults(baseline, stopped, service.adapter_guids)
        if os.name == "nt":
            records = service.effects()
            program_rules = {("firewall", "policy/" + json.loads(r["observation"]["credential"]["value"])["id"])
                             for r in records if "core_binary" in r["scope"]
                             and r["kind"] == "win.program_firewall_rule" and r["state"] == "applied"}
            assert len(program_rules) == 2 and program_rules <= remaining
            # The last active snapshot verified the two native IDs, programs,
            # directions and rule groups against this installed core's ledger.
            assert_foreign(after, stopped, program_rules)
            directions = set()
            for key in program_rules:
                _, group, direction, action, enabled, image, _ = stopped.rows[key]
                assert group == "EasyTier" and enabled == "True" and action == "Allow"
                assert Path(image).samefile(service.core)
                directions.add(direction)
            assert directions == {"Inbound", "Outbound"}
            remaining -= program_rules
            remaining -= system_policy_changes(baseline, stopped, "stopped", native_application_id(service.core))
            for key in remaining.copy():
                if key[0] == "service" and key[1] in ("wintun", "windivert"):
                    assert any(r["scope"] == "product" and r["state"] != "reclaimed"
                               and r["key"].get("name", "").lower() == key[1] for r in records)
                    remaining.remove(key)
        if remaining:
            message = f"unreclaimed native objects or changed baseline: {sorted(remaining)}"
            print(message, flush=True)
            differences.append(message)
        if os.name == "nt":
            verify_shared_driver_purge(service, baseline, stopped, inventory, keys, program_rules)
        assert not differences, "\n".join(differences)


def verify_shared_driver_purge(service, baseline, stopped, inventory, foreign_keys, program_rules):
    names = {name for name in ("wintun", "windivert")
             if ("service", name) not in baseline.rows and ("service", name) in stopped.rows}
    assert "wintun" in names, "the real kernel did not load its TUN driver"
    service.stop()
    result = command(service.installer, "reclaim", "--all", "--purge", check=False, timeout=240)
    records = service.effects()
    retained = {r["key"]["name"].lower() for r in records if r["scope"] == "product"
                and r["kind"] == "driver" and r["state"] == "candidate"}
    assert retained == names, f"expected shared driver candidates {names}, got {retained}"
    assert f"0 generations, {len(names)} candidates, 0 conflicts" in result.stdout
    assert result.returncode == 0, f"standalone purge exited {result.returncode}"
    after = inventory()
    service.retained_drivers = {name: stopped.rows["service", name] for name in names}
    assert_driver_notice(result.stdout, service.retained_drivers)
    assert_foreign(stopped, after, {("service", name) for name in names})
    assert_foreign(baseline, after, foreign_keys)
    assert not program_rules & after.rows.keys(), "CoreBinary firewall rules survived purge"
    delta = baseline.delta(after) - managed_service_changes(baseline, after)
    delta -= runner_noise(baseline, after) | {("service", name) for name in names}
    delta -= adapter_defaults(baseline, after, service.adapter_guids)
    delta -= system_policy_changes(baseline, after, "purged")
    # The installed baseline included a running host. Purge is an offline
    # command, so that exact host identity must now have exited.
    hosts = [k for k, v in baseline.rows.items() if k[0] == "process" and installed_image(v) == service.host]
    assert len(hosts) == 1 and hosts[0] not in after.rows
    delta.remove(hosts[0])
    assert not delta, f"post-purge native differences: {sorted(delta)}"


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
        print(f"SCM preflight conflicts recorded for {sorted(names)}", flush=True)
        service.ctl("stop", instance)
        service.stop()
        assert_foreign(foreign_state, service.inventory(), {("service", n) for n in names})


def program_rule_conflict():
    service = Service()
    instance = str(uuid.uuid4())
    with service.installed(), ExitStack() as stack:
        rule_id = "G2-" + str(uuid.uuid4())
        display_name = f"EasyTier {service.core} (Inbound)"
        env = dict(os.environ, G2_RULE_ID=rule_id, G2_DISPLAY=display_name, G2_PROGRAM=str(service.core))
        def policy(script):
            command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                    "$ErrorActionPreference='Stop'; " + script, env=env)
        # A disabled rule has no packet-handling effect. Its ID belongs to
        # this fixture, and there is no prior product ownership record.
        policy("New-NetFirewallRule -Name $env:G2_RULE_ID -DisplayName $env:G2_DISPLAY "
               "-Group EasyTier -Direction Inbound -Action Block -Enabled False "
               "-Program $env:G2_PROGRAM | Out-Null")
        stack.callback(policy, "Remove-NetFirewallRule -Name $env:G2_RULE_ID")
        key = ("firewall", "policy/" + rule_id)
        baseline = service.inventory()
        assert key in baseline.rows and baseline.rows[key][0] == display_name
        service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
        refused = eventually("pre-existing program rule refusal", lambda: service.view(instance),
                             lambda v: v.get("state") == "gave_up", timeout=240)
        assert display_name.casefold() in refused["message"].casefold(), refused["message"]
        assert all(not r.get("observation") for r in service.effects() if r["kind"] == "process")
        after = service.inventory()
        assert_foreign(baseline, after, {key})
        assert not any(installed_image(v) == service.core for k, v in after.rows.items() if k[0] == "process")
        print("Installed host refused the unowned program rule; native rule configuration preserved.")


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
     "driver_conflict": driver_conflict, "program_rule_conflict": program_rule_conflict}[sys.argv[1]]()
