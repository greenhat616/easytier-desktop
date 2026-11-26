"""Sample two service start settings without opening WFP or starting a service."""
from contextlib import ExitStack
from pathlib import Path
import os
import tempfile
import threading
import time
import uuid
import winreg

from service import Service
from product import foreign_runtime, spec
import foreign

def settings():
    values = []
    for name in ("IKEEXT", "BITS"):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" + name) as key:
            values.append(winreg.QueryValueEx(key, "Start")[0])
    return tuple(values)

service = Service()
case = os.environ["G2_COMPARISON"]
phase = "before install"
stop = threading.Event()
start = time.monotonic()

def watch():
    previous = None
    while not stop.is_set():
        value = settings()
        if value != previous:
            print(f"{case} t={time.monotonic()-start:.1f}s phase={phase} IKEEXT/BITS={value}", flush=True)
        previous = value
        stop.wait(0.5)

watcher = threading.Thread(target=watch)
watcher.start()
try:
    with service.installed(), ExitStack() as stack:
        phase = "create sibling fixtures"
        instance = str(uuid.uuid4())
        sibling = stack.enter_context(foreign_runtime(service, instance))
        stack.enter_context(foreign.windows())
        image, _ = stack.enter_context(foreign.idle_process())
        phase = "baseline native inventory"
        service.inventory([image], [sibling])
        baseline = settings()
        end = time.monotonic() + 150
        print(f"{case} before launch interval: {baseline}", flush=True)
        if case == "started":
            phase = "apply network until ready"
            service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
            ready = service.ready(instance)
            print(f"{case} {ready['state']} epoch={ready['epoch']}", flush=True)
        phase = "matched observation interval"
        time.sleep(max(0, end - time.monotonic()))
        phase = "second native inventory"
        service.inventory([image], [sibling])
        after = settings()
        phase = "fixture cleanup and uninstall"
        print(f"{case} final IKEEXT/BITS: {baseline} -> {after}", flush=True)
        assert after == baseline, f"{case} service Start changed: {baseline} -> {after}"
finally:
    stop.set()
    watcher.join()
