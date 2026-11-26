"""Real takeover attempts against an installed, unmodified service (doc#7).

A test-owned impostor process (impostor.py) takes the kernel's loopback
management port, or a released macOS utun. The product must never connect
to the impostor, must keep its fence, must leave the impostor's object alone
and must recover once the impostor exits. Every running generation is
compared with an independent native inventory; Service.installed compares
the machine before install with the machine after uninstall.
"""

from contextlib import contextmanager, ExitStack
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

from service import Service, eventually, require_runner
from consistency import (
    FirewallReadbackPending, UnpredictedChanges, check_closed, check_generation, installed_image,
    management_processes, runner_noise, scope, tun_created, adapter_defaults, managed_service_changes,
)
from product import assert_foreign, spec, wait_for_firewall_readback

FENCE_KINDS = {"linux.fence_rule", "macos.fence_rule", "win.fence_filter"}
READY = ("ready_basic", "ready_full")
TIMEOUT = 240 if os.name == "nt" else 75


class Impostor:
    def __init__(self, proc, status, stop):
        self.proc, self.status, self.stop = proc, status, stop

    def read(self):
        try:
            return json.loads(self.status.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}

    def wait(self, description, accept, timeout=60):
        def read():
            body = self.read()
            if self.proc.poll() is not None and not accept(body):
                raise AssertionError(f"impostor exited ({self.proc.returncode}) before {description}: {body}")
            return body
        return eventually(description, read, accept, timeout=timeout)

    def silent(self, where):
        body = self.read()
        assert body.get("connections", 0) == 0 and body.get("bytes", 0) == 0, \
            f"the product reached the impostor {where}: {body}"
        return body

    def release(self):
        self.stop.touch()
        self.proc.wait(timeout=30)
        assert self.proc.returncode == 0, f"impostor exited {self.proc.returncode}"
        return self.read()


@contextmanager
def impostor(mode, *args):
    with tempfile.TemporaryDirectory(prefix="g2-takeover-") as directory:
        status, stop = Path(directory) / "status.json", Path(directory) / "stop"
        script = Path(__file__).with_name("impostor.py")
        proc = subprocess.Popen(
            [sys.executable, "-B", "-u", str(script), mode, *map(str, args),
             "--status", str(status), "--stop", str(stop)],
            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            yield Impostor(proc, status, stop)
        finally:
            stop.touch()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)


def fence_port(service, instance, epoch):
    ports = {r["key"]["port"] for r in service.effects()
             if r["kind"] in FENCE_KINDS and r["scope"] == scope(instance, epoch)}
    assert len(ports) == 1, f"expected one fenced management port for epoch {epoch}: {ports}"
    return ports.pop()


def kernel_listener(service, port):
    """The installed kernel's PID and creation time listening on 127.0.0.1:port."""
    import psutil
    holders = {c.pid for c in psutil.net_connections(kind="tcp")
               if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == port}
    assert len(holders) == 1, f"expected one listener on management port {port}: {holders}"
    process = psutil.Process(holders.pop())
    assert installed_image([process.exe()]) == service.core, f"port {port} is held by {process.exe()}"
    return process.pid, process.create_time()


def kernels(service):
    import psutil
    found = []
    for proc in psutil.process_iter(["pid", "exe"], ad_value=None):
        if proc.info["exe"] and Path(proc.info["exe"]) == service.core:
            found.append(proc.info["pid"])
    return found


def full_ready(service, instance, after=0):
    """A new generation with its fence verified and the management session attached."""
    basic = service.ready(instance, after=after)
    def attached(view):
        if view.get("epoch") != basic["epoch"]:
            raise AssertionError(f"generation {basic['epoch']} ended before full readiness: {view}")
        if view.get("state") not in READY:
            raise AssertionError(f"generation {basic['epoch']} left readiness: {view}")
        return view["state"] == "ready_full" and view.get("management") == "available"
    return eventually("verified fence and attached management", lambda: service.view(instance), attached,
                      timeout=240)


def verify(service, baseline, instance, view, differences):
    """Every open intent of the generation natively present, nothing else changed."""
    wait_for_firewall_readback(service, instance, view["epoch"])
    end = time.monotonic() + 240
    while True:
        snapshot = service.inventory()
        workers = management_processes(baseline, snapshot, service.host)
        service.workers_seen.update(workers)
        try:
            check_generation(baseline, snapshot, service.effects(), instance, view, service.adapter_indices,
                             {("process", str(pid)) for pid, _ in workers})
        except FirewallReadbackPending:
            if time.monotonic() >= end:
                raise
            time.sleep(2)
            continue
        except UnpredictedChanges as err:
            message = f"epoch {view['epoch']}: {err}"
            print(message, flush=True)
            differences.append(message)
        return snapshot


def hold(service, instance, view, impostor_process, seconds, where):
    """The generation stays ready and the impostor stays silent for a while,
    long enough for the 30 s health check and any management reconnect."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        current = service.view(instance)
        assert current.get("epoch") == view["epoch"] and current.get("state") in READY, \
            f"generation {view['epoch']} changed while the impostor ran: {current}"
        if impostor_process:
            impostor_process.silent(where)
        time.sleep(1)


def stop_instance(service, instance, epoch):
    service.ctl("stop", instance)
    eventually("stopped instance", lambda: service.view(instance),
               lambda status: status.get("state") == "stopped", timeout=TIMEOUT)
    check_closed(service, instance, epoch)


def retain_shared_drivers(service, baseline):
    # The kernel's Wintun / WinDivert registrations outlive uninstall by
    # design; Service.installed verifies the notice for exactly these.
    if os.name == "nt":
        stopped = service.inventory()
        service.retained_drivers = {
            name: stopped.rows["service", name] for name in ("wintun", "windivert")
            if ("service", name) not in baseline.rows and ("service", name) in stopped.rows
        }


def management_port():
    service = Service()
    instance = str(uuid.uuid4())
    differences = []
    with service.installed():
        baseline = service.inventory()
        service.settle_workers(baseline, baseline)
        service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
        first = full_ready(service, instance)
        verify(service, baseline, instance, first, differences)
        old_port = fence_port(service, instance, first["epoch"])
        pid, born = kernel_listener(service, old_port)
        print(f"epoch {first['epoch']}: kernel {pid} serves management on 127.0.0.1:{old_port}", flush=True)

        # A. The crashed kernel's port, taken in the window before the restart.
        with impostor("squat", "--port", old_port, "--holder-pid", pid, "--holder-born", born) as squatter:
            armed = squatter.wait("armed impostor", lambda s: s.get("state") in ("waiting", "bound", "error"))
            assert armed["state"] == "waiting" and armed["holder_alive"], f"kernel did not hold its port: {armed}"
            killed = service.crash_installed(service.core)
            assert killed == pid
            taken = squatter.wait("impostor on the crashed kernel's port",
                                  lambda s: s.get("state") in ("bound", "timeout", "error"))
            assert taken["state"] == "bound", f"impostor could not take port {old_port}: {taken}"
            print(f"impostor {taken['pid']} holds 127.0.0.1:{old_port} after {taken['attempts']} attempts "
                  f"(SO_REUSEADDR={taken['reuse']})", flush=True)
            second = full_ready(service, instance, after=first["epoch"])
            check_closed(service, instance, first["epoch"])
            new_port = fence_port(service, instance, second["epoch"])
            assert new_port != old_port, f"epoch {second['epoch']} reused the impostor's port {old_port}"
            kernel_listener(service, new_port)
            verify(service, baseline, instance, second, differences)
            squatter.silent("after the restart")
            hold(service, instance, second, squatter, 35, "while it held the old port")
            final = squatter.release()
            assert final.get("connections") == 0 and final.get("bytes") == 0, final
            print(f"epoch {second['epoch']} serves 127.0.0.1:{new_port}; the impostor on {old_port} "
                  f"received {final['connections']} connections and {final['bytes']} bytes", flush=True)
        hold(service, instance, second, None, 5, "after it exited")

        # B. The next generation's port, taken between plan and kernel bind.
        current = second
        ledger = service.state / "ledger.sqlite3"
        for attempt in range(1, 5):
            stop_instance(service, instance, current["epoch"])
            with impostor("race", "--ledger", ledger, "--instance", instance, "--after", current["epoch"]) as racer:
                racer.wait("ledger watch", lambda s: s.get("state") == "watching")
                service.ctl("start", instance)
                outcome = racer.wait("the fenced port of the next generation",
                                     lambda s: s.get("state") in ("bound", "lost", "timeout"), timeout=TIMEOUT)
                print(f"race {attempt}: {outcome['state']} port={outcome.get('port')} epoch={outcome.get('epoch')} "
                      f"record={outcome.get('record_state')}", flush=True)
                assert outcome["state"] != "timeout", outcome
                if outcome["state"] == "lost":
                    current = full_ready(service, instance, after=current["epoch"])
                    continue
                epoch, port = outcome["epoch"], outcome["port"]
                def settled(view):
                    if view.get("epoch") == epoch and view.get("state") in READY:
                        raise AssertionError(f"the generation behind the impostor became ready: {view}")
                    if view.get("state") in ("quarantined", "cut_unconfirmed"):
                        raise AssertionError(f"impostor left the instance stuck: {view}")
                    return view.get("state") == "gave_up" or (view.get("state") in READY and view["epoch"] > epoch)
                result = eventually("refusal of the generation behind the impostor",
                                    lambda: service.view(instance), settled, timeout=TIMEOUT)
                print(f"epoch {epoch} refused: now {result['state']} epoch={result['epoch']} "
                      f"management={result.get('management')} message={result.get('message')!r}", flush=True)
                check_closed(service, instance, epoch)
                racer.silent("behind the refused generation")
                if result["state"] == "gave_up":
                    # Deny-all is unverified for the pinned kernel, so no
                    # privileged generation starts after a fence failure.
                    assert not kernels(service), "a kernel runs after the host gave up"
                    time.sleep(10)
                    assert service.view(instance).get("state") == "gave_up"
                else:
                    restarted = fence_port(service, instance, result["epoch"])
                    assert restarted != port
                    kernel_listener(service, restarted)
                    hold(service, instance, result, racer, 35, "behind the restarted generation")
                final = racer.release()
                assert final.get("connections") == 0 and final.get("bytes") == 0, final
                print(f"impostor on {port} received {final['connections']} connections and "
                      f"{final['bytes']} bytes", flush=True)
            break
        else:
            raise AssertionError("the impostor never took a planned port before the kernel in 4 attempts")

        # Recovery once the impostor has gone.
        if result["state"] == "gave_up":
            service.ctl("start", instance, "--retry")
        recovered = full_ready(service, instance, after=epoch) if result["state"] == "gave_up" else result
        verify(service, baseline, instance, recovered, differences)
        recovered_port = fence_port(service, instance, recovered["epoch"])
        assert recovered_port != port
        kernel_listener(service, recovered_port)
        print(f"recovered: epoch {recovered['epoch']} {recovered['state']} on 127.0.0.1:{recovered_port}", flush=True)
        stop_instance(service, instance, recovered["epoch"])
        service.settle_workers(baseline, service.inventory())
        retain_shared_drivers(service, baseline)
        assert not differences, "\n".join(differences)


def utun_name(base, live, view):
    name = view.get("interface_name")
    if name and ("interface", name) in live.rows:
        return name
    names = [key for kind, key in base.delta(live) if kind == "interface" and key.startswith("utun")
             and ("interface", key) in live.rows]
    assert len(names) == 1, f"missing or ambiguous system-assigned utun: {names}"
    return names[0]


def interface_keys(snapshot, name):
    keys = {key for key in (("interface", name), ("route", name)) if key in snapshot.rows}
    assert ("interface", name) in keys, f"{name} is not in the native inventory"
    return keys


def utun_reuse():
    assert sys.platform == "darwin"
    service = Service()
    instance = str(uuid.uuid4())
    differences = []
    with service.installed(), ExitStack() as stack:
        baseline = service.inventory()
        service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
        first = service.ready(instance)
        live = verify(service, baseline, instance, first, differences)
        first_name = utun_name(baseline, live, first)
        stop_instance(service, instance, first["epoch"])
        eventually(f"{first_name} released", service.inventory,
                   lambda snapshot: ("interface", first_name) not in snapshot.rows)

        # A. The reclaimed generation's utun, reopened before the next start.
        owner_a = stack.enter_context(impostor("utun", "--unit", first_name.removeprefix("utun"),
                                               "--address", "198.51.100.161", "--peer", "198.51.100.162"))
        held_a = owner_a.wait("impostor utun", lambda s: s.get("state") in ("held", "timeout", "error"))
        assert held_a["state"] == "held" and held_a["name"] == first_name, held_a
        held = service.inventory()
        keys_a = interface_keys(held, first_name)
        print(f"impostor {held_a['pid']} holds {first_name} (index {held_a['index']}): {sorted(keys_a)}", flush=True)
        service.ctl("start", instance)
        second = service.ready(instance, after=first["epoch"])
        live = verify(service, held, instance, second, differences)
        second_name = utun_name(held, live, second)
        assert second_name != first_name
        assert_foreign(held, live, keys_a)
        print(f"epoch {second['epoch']} uses {second_name}; {first_name} untouched", flush=True)

        # B. The running generation's utun, taken the moment its kernel dies.
        owner_b = stack.enter_context(impostor("utun", "--unit", second_name.removeprefix("utun"),
                                               "--address", "198.51.100.165", "--peer", "198.51.100.166",
                                               "--retry-for", 60))
        armed = owner_b.wait("armed utun impostor", lambda s: s.get("state") in ("waiting", "held", "error"))
        assert armed["state"] == "waiting", f"{second_name} was not held by the kernel: {armed}"
        service.crash_installed(service.core)
        held_b = owner_b.wait("impostor on the crashed kernel's utun",
                              lambda s: s.get("state") in ("held", "timeout", "error"), timeout=90)
        assert held_b["state"] == "held" and held_b["name"] == second_name, held_b
        grabbed = service.inventory()
        keys_b = interface_keys(grabbed, second_name)
        print(f"impostor {held_b['pid']} holds {second_name} (index {held_b['index']}) after "
              f"{held_b['attempts']} attempts: {sorted(keys_b)}", flush=True)
        third = service.ready(instance, after=second["epoch"])
        check_closed(service, instance, second["epoch"])
        base = copy.deepcopy(held)
        for key in keys_b:
            base.rows[key] = grabbed.rows[key]
        live = verify(service, base, instance, third, differences)
        third_name = utun_name(base, live, third)
        assert third_name not in (first_name, second_name)
        assert_foreign(held, live, keys_a)
        assert_foreign(grabbed, live, keys_b)
        print(f"epoch {third['epoch']} uses {third_name}; {first_name} and {second_name} untouched", flush=True)

        stop_instance(service, instance, third["epoch"])
        stopped = service.inventory()
        assert_foreign(held, stopped, keys_a)
        assert_foreign(grabbed, stopped, keys_b)
        remaining = base.delta(stopped) - managed_service_changes(base, stopped)
        remaining -= runner_noise(base, stopped) | tun_created(base, stopped)
        remaining -= adapter_defaults(base, stopped, service.adapter_indices)
        assert not remaining, f"stop left native differences: {sorted(remaining)}"
        for owner, name in ((owner_a, first_name), (owner_b, second_name)):
            final = owner.release()
            assert final["name_at_release"] == name and final["index_at_release"] == final["index"], final
        assert not differences, "\n".join(differences)


if __name__ == "__main__":
    require_runner()
    {"management_port": management_port, "utun_reuse": utun_reuse}[sys.argv[1]]()
